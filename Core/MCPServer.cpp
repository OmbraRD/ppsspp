// Copyright (c) 2025- PPSSPP Project.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0 or later versions.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License 2.0 for more details.

// A copy of the GPL 2.0 should have been included with the program.
// If not, see http://www.gnu.org/licenses/

// Official git repository and contact information can be found at
// https://github.com/hrydgard/ppsspp and http://www.ppsspp.org/.

#include <algorithm>
#include <cstring>
#include <future>
#include <mutex>
#include <thread>
#include <string>
#include <functional>
#include <map>
#include <sstream>

#include "Common/Log.h"
#include "Common/Net/HTTPServer.h"
#include "Common/Net/Sinks.h"
#include "Common/Data/Format/JSONReader.h"
#include "Common/Data/Format/JSONWriter.h"
#include "Common/Data/Encoding/Base64.h"
#include "Common/StringUtils.h"
#include "Common/Thread/ThreadUtil.h"
#include "Common/System/OSD.h"
#include "Core/MCPServer.h"
#include "Core/Config.h"
#include "Common/TimeUtil.h"
#include "Core/Core.h"
#include "Core/System.h"
#include "Core/MemMap.h"
#include "Core/MIPS/MIPSAsm.h"
#include "Core/MIPS/MIPSCodeUtils.h"
#include "Core/MIPS/MIPSDebugInterface.h"
#include "Core/MIPS/MIPSTables.h"
#include "Core/Debugger/Breakpoints.h"
#include "Core/Debugger/DisassemblyManager.h"
#include "Core/Debugger/SymbolMap.h"
#include "Core/ELF/ParamSFO.h"
#include "Core/HLE/sceKernel.h"
#include "Core/HLE/sceKernelModule.h"
#include "Core/HLE/sceKernelThread.h"
#include "Core/HLE/HLE.h"
#include "Core/Screenshot.h"
#include "GPU/GPU.h"
#include "GPU/Common/GPUDebugInterface.h"
#include "GPU/Common/FramebufferManagerCommon.h"
#include "GPU/Debugger/Stepping.h"
#include "GPU/Debugger/Breakpoints.h"
#include "GPU/Debugger/State.h"
#include "GPU/Debugger/Debugger.h"
#include "GPU/GeDisasm.h"
#include "Core/Util/PathUtil.h"
#include "Common/File/FileUtil.h"

using json::JsonWriter;
using json::JsonReader;
using json::JsonGet;

static std::thread mcpThread;
static std::mutex mcpLock;
static bool mcpRunning = false;
static int mcpPort = 0;

static constexpr int kJsonRpcParseError = -32700;
static constexpr int kJsonRpcInvalidRequest = -32600;
static constexpr int kJsonRpcMethodNotFound = -32601;
static constexpr int kJsonRpcInvalidParams = -32602;
static constexpr int kJsonRpcInternalError = -32603;

static std::string MakeJsonRpcResult(const std::string &idRaw, const std::string &resultJson) {
	JsonWriter j;
	j.begin();
	j.writeString("jsonrpc", "2.0");
	j.writeRaw("id", idRaw);
	j.writeRaw("result", resultJson);
	j.end();
	return j.str();
}

static std::string MakeJsonRpcError(const std::string &idRaw, int code, const std::string &message) {
	JsonWriter j;
	j.begin();
	j.writeString("jsonrpc", "2.0");
	j.writeRaw("id", idRaw);
	j.pushDict("error");
	j.writeInt("code", code);
	j.writeString("message", message);
	j.pop();
	j.end();
	return j.str();
}

struct MCPToolParam {
	const char *name;
	const char *type;
	const char *description;
	bool required;
};

struct MCPToolDef {
	const char *name;
	const char *description;
	std::vector<MCPToolParam> params;
};

static std::string BuildInputSchema(const MCPToolDef &tool) {
	JsonWriter j;
	j.begin();
	j.writeString("type", "object");
	j.pushDict("properties");
	for (auto &p : tool.params) {
		j.pushDict(p.name);
		j.writeString("type", p.type);
		j.writeString("description", p.description);
		j.pop();
	}
	j.pop(); // properties
	j.pushArray("required");
	for (auto &p : tool.params) {
		if (p.required)
			j.writeString(p.name);
	}
	j.pop(); // required
	j.end();
	return j.str();
}

static std::vector<MCPToolDef> GetToolDefs() {
	return {
		{"get_status", "Get the current emulator status (running, paused, stepping, no game loaded).", {}},
		{"get_game_info", "Get information about the currently loaded game (title, disc ID, version).", {}},
		{"read_memory", "Read bytes from PSP memory. Returns hex string. Memory regions: RAM at 0x08000000 (32MB, or 64MB on Slim), VRAM 2MB at 0x04000000, scratchpad 16KB at 0x00010000. User code starts at 0x08800000.", {
			{"address", "string", "Memory address to read from. Hex with 0x prefix (e.g. \"0x08800000\") or decimal.", true},
			{"size", "number", "Number of bytes to read.", true},
		}},
		{"write_memory", "Write bytes to PSP memory.", {
			{"address", "string", "Memory address to write to. Hex with 0x prefix (e.g. \"0x08800000\") or decimal.", true},
			{"hex", "string", "Hex string of bytes to write (e.g. \"0102AABB\").", true},
		}},
		{"read_registers", "Read CPU registers. Returns all GPR registers, HI, LO, and PC.", {}},
		{"write_register", "Write a value to a CPU register.", {
			{"register", "string", "Register name (r0-r31, or named: zero,at,v0-v1,a0-a3,t0-t9,s0-s7,k0-k1,gp,sp,fp,ra,hi,lo,pc).", true},
			{"value", "number", "Value to write.", true},
		}},
		{"disassemble", "Disassemble MIPS instructions at a given address. Stops at jr ra (function return) by default.", {
			{"address", "string", "Start address to disassemble. Hex with 0x prefix or decimal.", true},
			{"count", "number", "Maximum number of instructions to disassemble (default 16).", false},
			{"stop", "string", "Stop behavior: 'return' (default, stop at jr ra) or 'none' (disassemble exactly count instructions).", false},
		}},
		{"assemble", "Assemble a single MIPS instruction and write it to memory.", {
			{"address", "string", "Address to write the assembled instruction. Hex with 0x prefix or decimal.", true},
			{"instruction", "string", "MIPS assembly instruction (e.g. \"addiu a0, zero, 1\").", true},
		}},
		{"search_memory", "Search PSP memory for a byte pattern within a memory region.", {
			{"hex", "string", "Hex string pattern to search for.", true},
			{"region", "string", "Memory region to search: 'ram' (default, user RAM), 'vram', 'scratchpad', or 'kernel'. Sets default start/end bounds.", false},
			{"start", "string", "Start address override. Hex with 0x prefix or decimal.", false},
			{"end", "string", "End address override. Hex with 0x prefix or decimal.", false},
			{"max_results", "number", "Maximum results to return (default 16, max 256).", false},
		}},
		{"pause", "Pause emulation (break into stepping mode).", {}},
		{"resume", "Resume emulation from paused/stepping state.", {}},
		{"step_into", "Step one instruction (into function calls). Must be paused first.", {}},
		{"list_threads", "List PSP kernel threads with their status and PC.", {}},
		{"set_breakpoint", "Set a CPU execution breakpoint at the given address.", {
			{"address", "string", "Address to set breakpoint at. Hex with 0x prefix or decimal.", true},
			{"enabled", "boolean", "Whether the breakpoint is enabled (default true).", false},
			{"condition", "string", "Expression that must be true for the breakpoint to trigger (e.g. \"a0 == 1\" or \"[sp+0x10] != 0\").", false},
		}},
		{"remove_breakpoint", "Remove a CPU execution breakpoint.", {
			{"address", "string", "Address of breakpoint to remove. Hex with 0x prefix or decimal.", true},
		}},
		{"set_memcheck", "Set a memory watchpoint that triggers on read/write/change to an address range.", {
			{"address", "string", "Start address of memory range. Hex with 0x prefix or decimal.", true},
			{"size", "number", "Size of memory range in bytes.", true},
			{"read", "boolean", "Trigger on memory reads (default false).", false},
			{"write", "boolean", "Trigger on memory writes (default true).", false},
			{"change", "boolean", "Trigger only on writes that change the value (default false).", false},
			{"enabled", "boolean", "Whether the watchpoint is enabled (default true).", false},
			{"condition", "string", "Expression that must be true for the watchpoint to trigger.", false},
		}},
		{"remove_memcheck", "Remove a memory watchpoint.", {
			{"address", "string", "Start address of the watchpoint. Hex with 0x prefix or decimal.", true},
			{"size", "number", "Size of the watchpoint range in bytes.", true},
		}},
		{"list_breakpoints", "List all CPU breakpoints and memory watchpoints.", {}},
		{"lookup_symbol", "Look up a symbol name by address, or an address by symbol name.", {
			{"address", "string", "Address to look up. Hex with 0x prefix or decimal.", false},
			{"name", "string", "Symbol name to look up.", false},
		}},
		{"take_screenshot", "Capture a screenshot of the current PSP display as a PNG image.", {
			{"type", "string", "Screenshot type: 'display' (default, game output) or 'render' (in-progress render).", false},
		}},
		{"list_framebuffers", "List all active virtual framebuffers tracked by the GPU, with VRAM address, dimensions, format, and depth address.", {}},
		{"get_framebuffer", "Dump a framebuffer as a PNG image. Emulator must be paused.", {
			{"address", "string", "VRAM address of the framebuffer to dump. Use list_framebuffers to find addresses. Hex with 0x prefix or decimal.", true},
		}},
		{"list_hle_modules", "List HLE modules and functions imported by the running game.", {}},
		{"ge_list_display_lists", "List active GE (GPU) display lists with their status, PC, and stall address.", {}},
		{"ge_disassemble", "Disassemble GE (GPU) display list commands at a given address. Returns human-readable GPU command descriptions.", {
			{"address", "string", "Start address to disassemble. Hex with 0x prefix or decimal.", true},
			{"count", "number", "Number of GE commands to disassemble (default 32). Stops early at END command.", false},
		}},
		{"get_gpu_state", "Get the current GE (GPU) rendering state. Returns key register values formatted as human-readable strings, organized by category (flags, lighting, texture, settings).", {
			{"category", "string", "Category to return: 'flags', 'lighting', 'texture', 'settings', or 'all' (default 'all').", false},
		}},
		{"get_current_texture", "Dump the currently bound GPU texture as a PNG image. Emulator must be paused.", {
			{"level", "number", "Mipmap level (default 0).", false},
		}},
		{"get_depth_buffer", "Dump the current depth buffer as a PNG image. Emulator must be paused.", {}},
		{"get_stencil_buffer", "Dump the current stencil buffer as a PNG image. Emulator must be paused.", {}},
		{"get_current_clut", "Dump the current CLUT (Color Lookup Table / palette) as a PNG image. Emulator must be paused.", {}},
		{"set_ge_breakpoint", "Set a GE (GPU) breakpoint. Can break on display list address, GE command type, texture address, or render target address.", {
			{"type", "string", "Breakpoint type: 'address' (display list PC), 'cmd' (GE command byte), 'texture' (texture address), or 'rendertarget' (render target address).", true},
			{"value", "string", "The value for the breakpoint: address (hex with 0x prefix or decimal) for address/texture/rendertarget, or command number 0-255 for cmd.", true},
			{"condition", "string", "Expression that must be true for the breakpoint to trigger (address and cmd types only).", false},
		}},
		{"remove_ge_breakpoint", "Remove a GE (GPU) breakpoint.", {
			{"type", "string", "Breakpoint type: 'address', 'cmd', 'texture', or 'rendertarget'.", true},
			{"value", "string", "The value of the breakpoint to remove.", true},
		}},
		{"set_ge_break_on", "Set the GE debugger to break on the next occurrence of a specific event. Emulator must be running.", {
			{"event", "string", "Event to break on: 'op' (next GE command), 'draw' (next draw call), 'tex' (texture command), 'nontex' (non-texture command), 'frame' (frame boundary), 'vsync', 'prim' (primitive draw), 'curve' (bezier/spline), 'blocktransfer'.", true},
			{"count", "number", "Number of events to skip before breaking (default 1).", false},
		}},
		{"get_gpu_stats", "Get GPU rendering statistics for the current/last frame.", {}},
		{"get_current_vertices", "Get the transformed vertices for the current draw call. Must be paused at a GE draw command (use set_ge_break_on with 'draw' or 'prim').", {}},
		{"get_gpu_matrices", "Get GPU transformation matrices.", {
			{"name", "string", "Matrix name: 'world' (4x3), 'view' (4x3), 'projection' (4x4), 'texgen' (4x3), 'bone' (all 8 bone matrices, each 4x3), or 'all' (default).", false},
		}},
	};
}

// Parse an address parameter that may be a JSON number or a string.
// Accepts numbers or strings with auto-detection: 0x prefix for hex, otherwise decimal.
static bool ParseAddress(const JsonGet &args, const char *name, uint32_t *out, uint32_t defaultValue = 0) {
	const JsonNode *node = args.get(name);
	if (!node) {
		*out = defaultValue;
		return false;
	}
	if (node->value.getTag() == JSON_NUMBER) {
		*out = (uint32_t)node->value.toNumber();
		return true;
	}
	if (node->value.getTag() == JSON_STRING) {
		const char *s = node->value.toString();
		if (!s || !*s) {
			*out = defaultValue;
			return false;
		}
		char *end = nullptr;
		*out = (uint32_t)strtoul(s, &end, 0);
		return (end && *end == '\0');
	}
	*out = defaultValue;
	return false;
}

static void WriteHexU32(JsonWriter &j, const std::string &name, uint32_t value) {
	char buf[32];
	snprintf(buf, sizeof(buf), "0x%08X", value);
	j.writeString(name, buf);
}

static std::string ToolResultText(const std::string &text, bool isError = false) {
	JsonWriter j;
	j.begin();
	j.pushArray("content");
	j.pushDict();
	j.writeString("type", "text");
	j.writeString("text", text);
	j.pop();
	j.pop();
	if (isError)
		j.writeBool("isError", true);
	j.end();
	return j.str();
}

static std::string HandleGetStatus(const JsonGet &args) {
	std::string status;
	if (PSP_GetBootState() != BootState::Complete) {
		status = "no_game";
	} else if (Core_IsStepping()) {
		status = "stepping";
	} else if (GetUIState() == UISTATE_PAUSEMENU) {
		status = "paused";
	} else {
		status = "running";
	}

	JsonWriter j;
	j.begin();
	j.writeString("status", status);
	j.writeBool("gameLoaded", PSP_GetBootState() == BootState::Complete);
	j.writeBool("stepping", Core_IsStepping());
	if (PSP_GetBootState() == BootState::Complete && currentDebugMIPS) {
		WriteHexU32(j, "pc", currentDebugMIPS->GetPC());
	}
	j.end();
	return ToolResultText(j.str());
}

static std::string HandleGetGameInfo(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete) {
		return ToolResultText("No game loaded.", true);
	}

	JsonWriter j;
	j.begin();
	j.writeString("id", g_paramSFO.GetDiscID());
	j.writeString("version", g_paramSFO.GetValueString("DISC_VERSION"));
	j.writeString("title", g_paramSFO.GetValueString("TITLE"));
	j.end();
	return ToolResultText(j.str());
}

static std::string HandleReadMemory(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	uint32_t addr;
	if (!ParseAddress(args, "address", &addr))
		return ToolResultText("Missing or invalid 'address' parameter.", true);
	int size = args.getInt("size", 0);
	if (size <= 0)
		return ToolResultText("size must be positive.", true);

	if (!Memory::IsValidRange(addr, size))
		return ToolResultText("Invalid memory address or range.", true);

	const uint8_t *ptr = Memory::GetPointerUnchecked(addr);

	std::string hex;
	hex.reserve(size * 2);
	for (int i = 0; i < size; i++) {
		char buf[3];
		snprintf(buf, sizeof(buf), "%02X", ptr[i]);
		hex += buf;
	}

	std::string ascii;
	int previewLen = std::min(size, 64);
	for (int i = 0; i < previewLen; i++) {
		ascii += (ptr[i] >= 32 && ptr[i] < 127) ? (char)ptr[i] : '.';
	}
	if (size > 64) ascii += "...";

	JsonWriter j;
	j.begin();
	WriteHexU32(j, "address", addr);
	j.writeInt("size", size);
	j.writeString("hex", hex);
	j.writeString("ascii_preview", ascii);
	j.end();
	return ToolResultText(j.str());
}

static std::string HandleWriteMemory(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	uint32_t addr;
	if (!ParseAddress(args, "address", &addr))
		return ToolResultText("Missing or invalid 'address' parameter.", true);
	std::string hex;
	if (!args.getString("hex", &hex) || hex.empty())
		return ToolResultText("Missing or empty 'hex' parameter.", true);

	if (hex.size() % 2 != 0)
		return ToolResultText("Hex string must have even length.", true);

	int size = (int)(hex.size() / 2);
	if (!Memory::IsValidRange(addr, size))
		return ToolResultText("Invalid memory address or range.", true);

	uint8_t *ptr = Memory::GetPointerWriteUnchecked(addr);
	for (int i = 0; i < size; i++) {
		unsigned int byte;
		if (sscanf(hex.c_str() + i * 2, "%02x", &byte) != 1)
			return ToolResultText("Invalid hex string.", true);
		ptr[i] = (uint8_t)byte;
	}

	char msg[128];
	snprintf(msg, sizeof(msg), "Wrote %d bytes to 0x%08X.", size, addr);
	return ToolResultText(msg);
}

static std::string HandleReadRegisters(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !currentDebugMIPS)
		return ToolResultText("No game loaded.", true);

	JsonWriter j;
	j.begin();
	j.pushDict("gpr");
	for (int i = 0; i < 32; i++) {
		WriteHexU32(j, MIPSDebugInterface::GetRegName(0, i), currentDebugMIPS->GetRegValue(0, i));
	}
	j.pop();

	WriteHexU32(j, "hi", currentDebugMIPS->GetHi());
	WriteHexU32(j, "lo", currentDebugMIPS->GetLo());
	WriteHexU32(j, "pc", currentDebugMIPS->GetPC());
	j.end();
	return ToolResultText(j.str());
}

static int ResolveRegisterName(const std::string &name) {
	if (name.size() >= 2 && (name[0] == 'r' || name[0] == 'R')) {
		int n = atoi(name.c_str() + 1);
		if (n >= 0 && n < 32) return n;
	}
	for (int i = 0; i < 32; i++) {
		if (strcasecmp(name.c_str(), MIPSDebugInterface::GetRegName(0, i).c_str()) == 0)
			return i;
	}
	return -1;
}

static std::string HandleWriteRegister(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !currentDebugMIPS)
		return ToolResultText("No game loaded.", true);

	std::string regName;
	if (!args.getString("register", &regName))
		return ToolResultText("Missing 'register' parameter.", true);

	uint32_t value = (uint32_t)args.getFloat("value", 0.0);

	if (strcasecmp(regName.c_str(), "pc") == 0) {
		currentDebugMIPS->SetPC(value);
	} else if (strcasecmp(regName.c_str(), "hi") == 0) {
		currentMIPS->hi = value;
	} else if (strcasecmp(regName.c_str(), "lo") == 0) {
		currentMIPS->lo = value;
	} else {
		int reg = ResolveRegisterName(regName);
		if (reg < 0)
			return ToolResultText("Unknown register name.", true);
		currentDebugMIPS->SetRegValue(0, reg, value);
	}

	char msg[128];
	snprintf(msg, sizeof(msg), "Set %s = 0x%08X.", regName.c_str(), value);
	return ToolResultText(msg);
}

static std::string HandleDisassemble(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !currentDebugMIPS)
		return ToolResultText("No game loaded.", true);

	uint32_t addr;
	if (!ParseAddress(args, "address", &addr))
		return ToolResultText("Missing or invalid 'address' parameter.", true);
	int count = args.getInt("count", 16);
	if (count <= 0) count = 16;

	bool stopAtRet = true;
	std::string stopStr;
	if (args.getString("stop", &stopStr) && stopStr == "none")
		stopAtRet = false;
	int delaySlotCount = 0;

	std::string result;
	for (int i = 0; i < count; i++) {
		uint32_t instrAddr = addr + i * 4;
		if (!Memory::IsValidAddress(instrAddr))
			break;
		uint32_t opcode = Memory::Read_U32(instrAddr);
		char disasm[256];
		MIPSDisAsm(MIPSOpcode(opcode), instrAddr, disasm, sizeof(disasm), true);

		char line[512];
		snprintf(line, sizeof(line), "0x%08X: %08X  %s", instrAddr, opcode, disasm);

		// Check for symbol at this address
		const std::string sym = g_symbolMap->GetLabelString(instrAddr);
		if (!sym.empty()) {
			result += sym + ":\n";
		}
		result += line;
		result += "\n";

		if (!stopAtRet)
			continue;
		// Stop after jr ra + its delay slot.
		if (delaySlotCount > 0)
			break;
		if (opcode == MIPS_MAKE_JR_RA())
			delaySlotCount = 1;
	}

	return ToolResultText(result);
}

static std::string HandleAssemble(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	uint32_t addr;
	if (!ParseAddress(args, "address", &addr))
		return ToolResultText("Missing or invalid 'address' parameter.", true);
	std::string instruction;
	if (!args.getString("instruction", &instruction))
		return ToolResultText("Missing 'instruction' parameter.", true);

	if (!Memory::IsValidAddress(addr))
		return ToolResultText("Invalid memory address.", true);

	std::string errorText;
	if (!MipsAssembleOpcode(instruction, currentDebugMIPS, addr, &errorText)) {
		return ToolResultText("Assembly failed: " + errorText, true);
	}

	char msg[256];
	uint32_t assembled = Memory::Read_U32(addr);
	snprintf(msg, sizeof(msg), "Assembled at 0x%08X: %08X", addr, assembled);
	return ToolResultText(msg);
}

static std::string HandleSearchMemory(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	std::string hex;
	if (!args.getString("hex", &hex) || hex.empty())
		return ToolResultText("Missing 'hex' parameter.", true);
	if (hex.size() % 2 != 0)
		return ToolResultText("Hex string must have even length.", true);

	int patternLen = (int)(hex.size() / 2);
	std::vector<uint8_t> pattern(patternLen);
	for (int i = 0; i < patternLen; i++) {
		unsigned int byte;
		if (sscanf(hex.c_str() + i * 2, "%02x", &byte) != 1)
			return ToolResultText("Invalid hex string.", true);
		pattern[i] = (uint8_t)byte;
	}

	// Determine region defaults.
	uint32_t regionStart = PSP_GetUserMemoryBase();
	uint32_t regionEnd = PSP_GetUserMemoryEnd();
	std::string region;
	if (args.getString("region", &region)) {
		if (region == "ram") {
			regionStart = PSP_GetUserMemoryBase();
			regionEnd = PSP_GetUserMemoryEnd();
		} else if (region == "kernel") {
			regionStart = PSP_GetKernelMemoryBase();
			regionEnd = PSP_GetKernelMemoryEnd();
		} else if (region == "vram") {
			regionStart = PSP_GetVidMemBase();
			regionEnd = PSP_GetVidMemEnd();
		} else if (region == "scratchpad") {
			regionStart = PSP_GetScratchpadMemoryBase();
			regionEnd = PSP_GetScratchpadMemoryEnd();
		} else {
			return ToolResultText("Unknown region. Use 'ram', 'vram', 'scratchpad', or 'kernel'.", true);
		}
	}

	uint32_t start, end;
	ParseAddress(args, "start", &start, regionStart);
	ParseAddress(args, "end", &end, regionEnd);

	// Validate that overrides stay within the region bounds.
	if (start < regionStart || end > regionEnd || start >= end)
		return ToolResultText("start/end out of region bounds.", true);

	int maxResults = args.getInt("max_results", 16);
	if (maxResults > 256) maxResults = 256;

	if (!Memory::IsValidRange(start, end - start))
		return ToolResultText("Invalid search range.", true);

	const uint8_t *base = Memory::GetPointerUnchecked(start);
	uint32_t searchLen = end - start;

	JsonWriter j;
	j.begin();
	j.pushArray("matches");
	int found = 0;
	for (uint32_t offset = 0; offset + patternLen <= searchLen && found < maxResults; offset++) {
		if (memcmp(base + offset, pattern.data(), patternLen) == 0) {
			char addrStr[32];
			snprintf(addrStr, sizeof(addrStr), "0x%08X", start + offset);
			j.writeString(addrStr);
			found++;
		}
	}
	j.pop();
	j.writeInt("count", found);
	j.end();
	return ToolResultText(j.str());
}

static std::string HandlePause(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);
	if (Core_IsStepping())
		return ToolResultText("Already paused.");

	Core_Break(BreakReason::DebugBreak, 0);
	return ToolResultText("Paused.");
}

static std::string HandleResume(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);
	if (!Core_IsStepping())
		return ToolResultText("Not paused.");

	Core_Resume();
	return ToolResultText("Resumed.");
}

static std::string HandleStepInto(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !currentDebugMIPS)
		return ToolResultText("No game loaded.", true);
	if (!Core_IsStepping())
		return ToolResultText("Must be paused to step.", true);

	g_breakpoints.SetSkipFirst(currentMIPS->pc);
	Core_RequestCPUStep(CPUStepType::Into, 1);

	int timeout = 100;
	while (!Core_IsStepping() && timeout > 0) {
		sleep_ms(1, "mcp step");
		timeout--;
	}

	char msg[128];
	snprintf(msg, sizeof(msg), "Stepped to 0x%08X.", currentDebugMIPS->GetPC());
	return ToolResultText(msg);
}

static std::string HandleListThreads(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	auto threads = GetThreadsInfo();
	JsonWriter j;
	j.begin();
	j.pushArray("threads");
	for (auto &t : threads) {
		j.pushDict();
		j.writeString("name", t.name);
		j.writeInt("id", t.id);

		const char *statusStr = "unknown";
		if (t.status & THREADSTATUS_RUNNING) statusStr = "running";
		else if (t.status & THREADSTATUS_READY) statusStr = "ready";
		else if (t.status & THREADSTATUS_WAIT) statusStr = "waiting";
		else if (t.status & THREADSTATUS_DORMANT) statusStr = "dormant";
		else if (t.status & THREADSTATUS_DEAD) statusStr = "dead";
		else if (t.status & THREADSTATUS_SUSPEND) statusStr = "suspended";
		j.writeString("status", statusStr);

		WriteHexU32(j, "pc", t.curPC);
		WriteHexU32(j, "entrypoint", t.entrypoint);

		j.writeInt("priority", t.priority);
		j.writeBool("isCurrent", t.isCurrent);
		j.pop();
	}
	j.pop();
	j.end();
	return ToolResultText(j.str());
}

static std::string HandleSetBreakpoint(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	uint32_t addr;
	if (!ParseAddress(args, "address", &addr))
		return ToolResultText("Missing or invalid 'address' parameter.", true);
	bool enabled = args.getBool("enabled", true);

	g_breakpoints.AddBreakPoint(addr, false);
	if (!enabled)
		g_breakpoints.ChangeBreakPoint(addr, false);

	std::string condition;
	if (args.getString("condition", &condition) && !condition.empty()) {
		PostfixExpression postfix;
		if (!initExpression(currentDebugMIPS, condition.c_str(), postfix))
			return ToolResultText(std::string("Breakpoint set but condition failed to parse: ") + getExpressionError(), true);
		BreakPointCond cond;
		cond.debug = currentDebugMIPS;
		cond.expressionString = condition;
		cond.expression = postfix;
		g_breakpoints.ChangeBreakPointAddCond(addr, cond);
	}

	char msg[256];
	snprintf(msg, sizeof(msg), "Breakpoint set at 0x%08X (%s)%s.", addr,
		enabled ? "enabled" : "disabled",
		condition.empty() ? "" : " with condition");
	return ToolResultText(msg);
}

static std::string HandleRemoveBreakpoint(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	uint32_t addr;
	if (!ParseAddress(args, "address", &addr))
		return ToolResultText("Missing or invalid 'address' parameter.", true);
	g_breakpoints.RemoveBreakPoint(addr);

	char msg[128];
	snprintf(msg, sizeof(msg), "Breakpoint removed at 0x%08X.", addr);
	return ToolResultText(msg);
}

static std::string HandleSetMemcheck(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	uint32_t addr;
	if (!ParseAddress(args, "address", &addr))
		return ToolResultText("Missing or invalid 'address' parameter.", true);
	int size = args.getInt("size", 0);
	if (size <= 0)
		return ToolResultText("size must be positive.", true);
	uint32_t end = addr + size;

	bool read = args.getBool("read", false);
	bool write = args.getBool("write", true);
	bool change = args.getBool("change", false);
	bool enabled = args.getBool("enabled", true);

	int bits = (read ? MEMCHECK_READ : 0) | (write ? MEMCHECK_WRITE : 0) | (change ? MEMCHECK_WRITE_ONCHANGE : 0);
	if (bits == 0)
		return ToolResultText("At least one of read, write, or change must be true.", true);

	BreakAction result = enabled ? BREAK_ACTION_PAUSE : BREAK_ACTION_IGNORE;
	g_breakpoints.AddMemCheck(addr, end, MemCheckCondition(bits), result);

	std::string condition;
	if (args.getString("condition", &condition) && !condition.empty()) {
		PostfixExpression postfix;
		if (!initExpression(currentDebugMIPS, condition.c_str(), postfix))
			return ToolResultText(std::string("Watchpoint set but condition failed to parse: ") + getExpressionError(), true);
		BreakPointCond cond;
		cond.debug = currentDebugMIPS;
		cond.expressionString = condition;
		cond.expression = postfix;
		g_breakpoints.ChangeMemCheckAddCond(addr, end, cond);
	}

	char msg[256];
	snprintf(msg, sizeof(msg), "Watchpoint set at 0x%08X-0x%08X (%s%s%s)%s.", addr, end,
		read ? "read " : "", write ? "write " : "", change ? "change " : "",
		condition.empty() ? "" : " with condition");
	return ToolResultText(msg);
}

static std::string HandleRemoveMemcheck(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	uint32_t addr;
	if (!ParseAddress(args, "address", &addr))
		return ToolResultText("Missing or invalid 'address' parameter.", true);
	int size = args.getInt("size", 0);
	if (size <= 0)
		return ToolResultText("size must be positive.", true);
	uint32_t end = addr + size;

	g_breakpoints.RemoveMemCheck(addr, end);

	char msg[128];
	snprintf(msg, sizeof(msg), "Watchpoint removed at 0x%08X-0x%08X.", addr, end);
	return ToolResultText(msg);
}

static std::string HandleListBreakpoints(const JsonGet &args) {
	auto bps = g_breakpoints.GetBreakpoints();
	auto mcs = g_breakpoints.GetMemChecks();
	JsonWriter j;
	j.begin();
	j.pushArray("breakpoints");
	for (auto &bp : bps) {
		if (bp.temporary)
			continue;
		j.pushDict();
		j.writeString("type", "execute");
		WriteHexU32(j, "address", bp.addr);
		j.writeBool("enabled", bp.IsEnabled());
		if (bp.hasCond)
			j.writeString("condition", bp.cond.expressionString);
		const std::string sym = g_symbolMap->GetLabelString(bp.addr);
		if (!sym.empty())
			j.writeString("symbol", sym);
		j.pop();
	}
	for (auto &mc : mcs) {
		j.pushDict();
		j.writeString("type", "memory");
		WriteHexU32(j, "address", mc.start);
		WriteHexU32(j, "end", mc.end);
		j.writeInt("size", mc.end - mc.start);
		j.writeBool("enabled", mc.IsEnabled());
		j.writeBool("read", (mc.cond & MEMCHECK_READ) != 0);
		j.writeBool("write", (mc.cond & MEMCHECK_WRITE) != 0);
		j.writeBool("change", (mc.cond & MEMCHECK_WRITE_ONCHANGE) != 0);
		if (mc.hasCondition)
			j.writeString("condition", mc.condition.expressionString);
		j.writeInt("hits", mc.numHits);
		j.pop();
	}
	j.pop();
	j.end();
	return ToolResultText(j.str());
}

static std::string HandleLookupSymbol(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	bool hasAddr = args.get("address") != nullptr;
	bool hasName = args.get("name") != nullptr;

	if (!hasAddr && !hasName)
		return ToolResultText("Provide either 'address' or 'name'.", true);

	if (hasAddr) {
		uint32_t addr;
		if (!ParseAddress(args, "address", &addr))
			return ToolResultText("Invalid 'address' parameter.", true);
		const std::string label = g_symbolMap->GetLabelString(addr);
		const std::string desc = g_symbolMap->GetDescription(addr);

		JsonWriter j;
		j.begin();
		WriteHexU32(j, "address", addr);
		j.writeString("label", label.empty() ? "(none)" : label);
		j.writeString("description", desc.empty() ? "(none)" : desc);

		u32 funcStart = g_symbolMap->GetFunctionStart(addr);
		if (funcStart != SymbolMap::INVALID_ADDRESS) {
			WriteHexU32(j, "function_start", funcStart);
			u32 funcSize = g_symbolMap->GetFunctionSize(funcStart);
			j.writeInt("function_size", (int)funcSize);
		}
		j.end();
		return ToolResultText(j.str());
	}

	std::string name;
	args.getString("name", &name);
	u32 addr;
	// Try exact match first, then with zz_ prefix (HLE imports are stored as zz_funcName).
	if (g_symbolMap->GetLabelValue(name.c_str(), addr) ||
		g_symbolMap->GetLabelValue(("zz_" + name).c_str(), addr)) {
		JsonWriter j;
		j.begin();
		j.writeString("name", name);
		WriteHexU32(j, "address", addr);
		j.end();
		return ToolResultText(j.str());
	}

	return ToolResultText("Symbol not found: " + name, true);
}

static std::string ToolResultImage(const std::string &base64Data, const std::string &mimeType) {
	JsonWriter j;
	j.begin();
	j.pushArray("content");
	j.pushDict();
	j.writeString("type", "image");
	j.writeString("data", base64Data);
	j.writeString("mimeType", mimeType);
	j.pop();
	j.pop();
	j.end();
	return j.str();
}

static std::string HandleTakeScreenshot(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	std::string typeStr;
	args.getString("type", &typeStr);
	ScreenshotType type = ScreenshotType::Display;
	if (typeStr == "render")
		type = ScreenshotType::Render;

	Path screenshotDir = GetSysDirectory(DIRECTORY_SCREENSHOT);
	File::CreateDir(screenshotDir);
	Path tempPath = screenshotDir / ".mcp_screenshot.png";

	std::promise<ScreenshotResult> promise;
	std::future<ScreenshotResult> future = promise.get_future();

	ScheduleScreenshot(tempPath, ScreenshotFormat::PNG, type, 1, [&promise](ScreenshotResult result) {
		promise.set_value(result);
	});

	auto status = future.wait_for(std::chrono::seconds(5));
	if (status != std::future_status::ready) {
		return ToolResultText("Screenshot timed out.", true);
	}

	ScreenshotResult result = future.get();
	if (result != ScreenshotResult::Success) {
		return ToolResultText("Screenshot failed.", true);
	}

	size_t fileSize;
	uint8_t *fileData = File::ReadLocalFile(tempPath, &fileSize);
	if (!fileData || fileSize == 0) {
		return ToolResultText("Failed to read screenshot file.", true);
	}

	std::string base64 = Base64Encode(fileData, fileSize);
	delete[] fileData;

	File::Delete(tempPath);

	return ToolResultImage(base64, "image/png");
}

static std::string HandleListFramebuffers(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	auto list = gpuDebug->GetFramebufferList();
	if (list.empty())
		return ToolResultText("No active framebuffers.");

	JsonWriter j;
	j.begin();
	j.pushArray("framebuffers");
	for (const auto *vfb : list) {
		j.pushDict();
		WriteHexU32(j, "fb_address", vfb->fb_address);
		WriteHexU32(j, "z_address", vfb->z_address);
		j.writeInt("width", vfb->width);
		j.writeInt("height", vfb->height);
		j.writeInt("stride", vfb->fb_stride);
		j.writeString("format", GeBufferFormatToString(vfb->fb_format));
		j.writeInt("last_frame_used", vfb->last_frame_used);
		j.writeInt("last_frame_displayed", vfb->last_frame_displayed);
		j.pop();
	}
	j.pop();
	j.end();
	return ToolResultText(j.str());
}

static std::string HandleGetFramebuffer(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	if (coreState != CORE_STEPPING_CPU && !GPUStepping::IsStepping())
		return ToolResultText("Emulator must be paused (use the pause tool first).", true);

	uint32_t addr;
	if (!ParseAddress(args, "address", &addr))
		return ToolResultText("Missing or invalid 'address' parameter.", true);

	// Find the framebuffer at this address.
	auto list = gpuDebug->GetFramebufferList();
	const VirtualFramebuffer *target = nullptr;
	for (const auto *vfb : list) {
		if (vfb->fb_address == addr) {
			target = vfb;
			break;
		}
	}
	if (!target)
		return ToolResultText("No framebuffer found at that address. Use list_framebuffers to see active framebuffers.", true);

	// Get the framebuffer data via the debug interface.
	GPUDebugBuffer buffer;
	if (!gpuDebug->GetFramebufferManagerCommon()->GetFramebuffer(target->fb_address, target->fb_stride, target->fb_format, buffer, 1)) {
		return ToolResultText("Failed to read framebuffer data.", true);
	}

	// Convert to RGB888 and save as PNG to a temp file.
	u8 *flipbuffer = nullptr;
	u32 w = buffer.GetStride();
	u32 h = buffer.GetHeight();
	const u8 *rgb = ConvertBufferToScreenshot(buffer, false, flipbuffer, w, h);
	if (!rgb) {
		return ToolResultText("Failed to convert framebuffer data.", true);
	}

	Path screenshotDir = GetSysDirectory(DIRECTORY_SCREENSHOT);
	File::CreateDir(screenshotDir);
	Path tempPath = screenshotDir / ".mcp_framebuffer.png";

	bool saved = Save888RGBScreenshot(tempPath, ScreenshotFormat::PNG, rgb, w, h);
	delete[] flipbuffer;
	if (!saved)
		return ToolResultText("Failed to save framebuffer as PNG.", true);

	size_t fileSize;
	uint8_t *fileData = File::ReadLocalFile(tempPath, &fileSize);
	if (!fileData || fileSize == 0)
		return ToolResultText("Failed to read framebuffer PNG.", true);

	std::string base64 = Base64Encode(fileData, fileSize);
	delete[] fileData;
	File::Delete(tempPath);

	return ToolResultImage(base64, "image/png");
}

static const char *DisplayListStateToString(DisplayListState state) {
	switch (state) {
	case PSP_GE_DL_STATE_NONE: return "none";
	case PSP_GE_DL_STATE_QUEUED: return "queued";
	case PSP_GE_DL_STATE_RUNNING: return "running";
	case PSP_GE_DL_STATE_COMPLETED: return "completed";
	case PSP_GE_DL_STATE_PAUSED: return "paused";
	default: return "unknown";
	}
}

static std::string HandleListHLEModules(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete)
		return ToolResultText("No game loaded.", true);

	JsonWriter j;
	j.begin();
	j.pushArray("modules");

	kernelObjects.Iterate<PSPModule>([&](SceUID uid, PSPModule *mod) -> bool {
		if (mod->importedFuncs.empty() && mod->exportedFuncs.empty())
			return true;  // Skip modules with no imports/exports.

		j.pushDict();
		j.writeString("name", mod->GetName());
		j.writeInt("uid", uid);
		WriteHexU32(j, "text_addr", mod->nm.text_addr);
		j.writeInt("text_size", mod->nm.text_size);

		if (!mod->impModuleNames.empty()) {
			j.pushDict("imports");
			for (const auto &modName : mod->impModuleNames) {
				j.pushArray(modName.c_str());
				for (const auto &func : mod->importedFuncs) {
					if (func.moduleName == modName) {
						const char *name = GetHLEFuncName(func.moduleName, func.nid);
						j.pushDict();
						j.writeString("name", name ? name : "(unknown)");
						WriteHexU32(j, "nid", func.nid);
						WriteHexU32(j, "stub_addr", func.stubAddr);
						j.pop();
					}
				}
				j.pop();
			}
			j.pop();
		}
		j.pop();
		return true;
	});

	j.pop();
	j.end();
	return ToolResultText(j.str());
}

static std::string HandleGEListDisplayLists(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	auto lists = gpuDebug->ActiveDisplayLists();
	if (lists.empty())
		return ToolResultText("No active display lists.");

	JsonWriter j;
	j.begin();
	j.pushArray("display_lists");
	for (const auto &dl : lists) {
		j.pushDict();
		j.writeInt("id", dl.id);
		j.writeString("state", DisplayListStateToString(dl.state));
		WriteHexU32(j, "start_pc", dl.startpc);
		WriteHexU32(j, "pc", dl.pc);
		WriteHexU32(j, "stall", dl.stall);
		j.writeInt("stack_depth", dl.stackptr);
		j.pop();
	}
	j.pop();
	j.end();
	return ToolResultText(j.str());
}

static std::string HandleGEDisassemble(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	uint32_t addr;
	if (!ParseAddress(args, "address", &addr))
		return ToolResultText("Missing or invalid 'address' parameter.", true);

	int count = args.getInt("count", 32);
	if (count <= 0) count = 32;

	if (!Memory::IsValidAddress(addr))
		return ToolResultText("Invalid memory address.", true);

	std::string result;
	for (int i = 0; i < count; i++) {
		uint32_t cmdAddr = addr + i * 4;
		if (!Memory::IsValidAddress(cmdAddr))
			break;
		uint32_t op = Memory::Read_U32(cmdAddr);
		GPUDebugOp decoded = gpuDebug->DisassembleOp(cmdAddr, op);
		char line[512];
		snprintf(line, sizeof(line), "0x%08X: [%08X] %s\n", cmdAddr, op, decoded.desc.c_str());
		result += line;

		// Stop after END command.
		if (decoded.cmd == GE_CMD_END)
			break;
	}
	return ToolResultText(result);
}

static u8 *ConvertDepthStencilToRGB(const GPUDebugBuffer &buffer, u32 w, u32 h) {
	u8 *rgb = new u8[w * h * 3];
	GPUDebugBufferFormat fmt = buffer.GetFormat();
	bool flipped = buffer.GetFlipped();

	for (u32 y = 0; y < h; y++) {
		u32 srcY = flipped ? (h - 1 - y) : y;
		for (u32 x = 0; x < w; x++) {
			u32 raw = buffer.GetRawPixel(x, srcY);
			u8 val;
			switch (fmt) {
			case GPU_DBG_FORMAT_FLOAT:
			case GPU_DBG_FORMAT_FLOAT_DIV_256: {
				float f;
				memcpy(&f, &raw, sizeof(float));
				if (fmt == GPU_DBG_FORMAT_FLOAT_DIV_256)
					f /= 256.0f;
				val = (u8)(std::min(std::max(f, 0.0f), 1.0f) * 255.0f);
				break;
			}
			case GPU_DBG_FORMAT_24BIT_8X:
			case GPU_DBG_FORMAT_24BIT_8X_DIV_256:
				val = (u8)((raw >> 16) & 0xFF);
				break;
			case GPU_DBG_FORMAT_24X_8BIT:
				val = (u8)(raw & 0xFF);
				break;
			case GPU_DBG_FORMAT_16BIT:
				val = (u8)((raw >> 8) & 0xFF);
				break;
			case GPU_DBG_FORMAT_8BIT:
				val = (u8)(raw & 0xFF);
				break;
			default:
				val = (u8)((raw >> 8) & 0xFF);
				break;
			}
			u8 *dst = &rgb[(y * w + x) * 3];
			dst[0] = dst[1] = dst[2] = val;
		}
	}
	return rgb;
}

static std::string GPUDebugBufferToPNG(const GPUDebugBuffer &buffer) {
	u32 w = buffer.GetStride();
	u32 h = buffer.GetHeight();
	u8 *flipbuffer = nullptr;
	const u8 *rgb = nullptr;

	GPUDebugBufferFormat fmt = buffer.GetFormat();
	if (fmt >= GPU_DBG_FORMAT_FLOAT) {
		flipbuffer = ConvertDepthStencilToRGB(buffer, w, h);
		rgb = flipbuffer;
	} else {
		rgb = ConvertBufferToScreenshot(buffer, false, flipbuffer, w, h);
	}

	if (!rgb) {
		delete[] flipbuffer;
		return ToolResultText("Failed to convert buffer data.", true);
	}

	Path screenshotDir = GetSysDirectory(DIRECTORY_SCREENSHOT);
	File::CreateDir(screenshotDir);
	Path tempPath = screenshotDir / ".mcp_gpubuffer.png";

	bool saved = Save888RGBScreenshot(tempPath, ScreenshotFormat::PNG, rgb, w, h);
	delete[] flipbuffer;
	if (!saved)
		return ToolResultText("Failed to save buffer as PNG.", true);

	size_t fileSize;
	uint8_t *fileData = File::ReadLocalFile(tempPath, &fileSize);
	if (!fileData || fileSize == 0)
		return ToolResultText("Failed to read buffer PNG.", true);

	std::string base64 = Base64Encode(fileData, fileSize);
	delete[] fileData;
	File::Delete(tempPath);

	return ToolResultImage(base64, "image/png");
}

static std::string HandleGetGPUState(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	std::string category;
	args.getString("category", &category);
	if (category.empty()) category = "all";

	struct CategoryInfo {
		const char *name;
		const GECommand *rows;
		size_t count;
	};

	CategoryInfo categories[] = {
		{"flags", g_stateFlagsRows, g_stateFlagsRowsSize},
		{"lighting", g_stateLightingRows, g_stateLightingRowsSize},
		{"texture", g_stateTextureRows, g_stateTextureRowsSize},
		{"settings", g_stateSettingsRows, g_stateSettingsRowsSize},
	};

	const GPUgstate &gstate = gpuDebug->GetGState();

	JsonWriter j;
	j.begin();

	for (auto &cat : categories) {
		if (category != "all" && category != cat.name)
			continue;

		j.pushDict(cat.name);
		for (size_t i = 0; i < cat.count; i++) {
			GECommand cmd = cat.rows[i];
			const GECmdInfo &info = GECmdInfoByCmd(cmd);
			u32 value = gstate.cmdmem[cmd];
			u32 otherValue = info.otherCmd ? gstate.cmdmem[info.otherCmd] : 0;
			u32 otherValue2 = info.otherCmd2 ? gstate.cmdmem[info.otherCmd2] : 0;
			bool enabled = info.enableCmd == 0 || (gstate.cmdmem[info.enableCmd] & 0x01) != 0;

			char formatted[256];
			FormatStateRow(gpuDebug, formatted, sizeof(formatted), info.fmt, value, enabled, otherValue, otherValue2);
			j.writeString(info.name, formatted);
		}
		j.pop();
	}

	j.end();
	return ToolResultText(j.str());
}

static std::string HandleGetCurrentTexture(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	if (coreState != CORE_STEPPING_CPU && !GPUStepping::IsStepping())
		return ToolResultText("Emulator must be paused (use the pause tool first).", true);

	int level = args.getInt("level", 0);
	if (level < 0 || level > 7)
		return ToolResultText("Mipmap level must be 0-7.", true);

	const GPUDebugBuffer *buffer = nullptr;
	bool isFramebuffer = false;
	if (!GPUStepping::GPU_GetCurrentTexture(buffer, level, &isFramebuffer) || !buffer)
		return ToolResultText("Failed to get current texture. Make sure a draw call is in progress.", true);

	return GPUDebugBufferToPNG(*buffer);
}

static std::string HandleGetDepthBuffer(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	if (coreState != CORE_STEPPING_CPU && !GPUStepping::IsStepping())
		return ToolResultText("Emulator must be paused (use the pause tool first).", true);

	const GPUDebugBuffer *buffer = nullptr;
	if (!GPUStepping::GPU_GetCurrentDepthbuffer(buffer) || !buffer)
		return ToolResultText("Failed to get depth buffer.", true);

	return GPUDebugBufferToPNG(*buffer);
}

static std::string HandleGetStencilBuffer(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	if (coreState != CORE_STEPPING_CPU && !GPUStepping::IsStepping())
		return ToolResultText("Emulator must be paused (use the pause tool first).", true);

	const GPUDebugBuffer *buffer = nullptr;
	if (!GPUStepping::GPU_GetCurrentStencilbuffer(buffer) || !buffer)
		return ToolResultText("Failed to get stencil buffer.", true);

	return GPUDebugBufferToPNG(*buffer);
}

static std::string HandleGetCurrentClut(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	if (coreState != CORE_STEPPING_CPU && !GPUStepping::IsStepping())
		return ToolResultText("Emulator must be paused (use the pause tool first).", true);

	const GPUDebugBuffer *buffer = nullptr;
	if (!GPUStepping::GPU_GetCurrentClut(buffer) || !buffer)
		return ToolResultText("Failed to get CLUT.", true);

	return GPUDebugBufferToPNG(*buffer);
}

static std::string HandleSetGEBreakpoint(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	std::string type;
	if (!args.getString("type", &type) || type.empty())
		return ToolResultText("Missing 'type' parameter.", true);

	GPUBreakpoints *bp = gpuDebug->GetBreakpoints();
	if (!bp)
		return ToolResultText("GPU breakpoints not available.", true);

	if (type == "address") {
		uint32_t addr;
		if (!ParseAddress(args, "value", &addr))
			return ToolResultText("Missing or invalid 'value' parameter.", true);
		bp->AddAddressBreakpoint(addr);

		std::string condition;
		if (args.getString("condition", &condition) && !condition.empty()) {
			std::string error;
			if (!bp->SetAddressBreakpointCond(addr, condition, &error))
				return ToolResultText("GE breakpoint set but condition failed: " + error, true);
		}

		char msg[256];
		snprintf(msg, sizeof(msg), "GE address breakpoint set at 0x%08X.", addr);
		return ToolResultText(msg);
	} else if (type == "cmd") {
		uint32_t cmd;
		if (!ParseAddress(args, "value", &cmd))
			return ToolResultText("Missing or invalid 'value' parameter.", true);
		if (cmd > 255)
			return ToolResultText("GE command must be 0-255.", true);
		bp->AddCmdBreakpoint((u8)cmd);

		std::string condition;
		if (args.getString("condition", &condition) && !condition.empty()) {
			std::string error;
			if (!bp->SetCmdBreakpointCond((u8)cmd, condition, &error))
				return ToolResultText("GE breakpoint set but condition failed: " + error, true);
		}

		const GECmdInfo &info = GECmdInfoByCmd((GECommand)cmd);
		char msg[256];
		snprintf(msg, sizeof(msg), "GE command breakpoint set on cmd %d (%s).", cmd, info.name);
		return ToolResultText(msg);
	} else if (type == "texture") {
		uint32_t addr;
		if (!ParseAddress(args, "value", &addr))
			return ToolResultText("Missing or invalid 'value' parameter.", true);
		bp->AddTextureBreakpoint(addr);

		char msg[256];
		snprintf(msg, sizeof(msg), "GE texture breakpoint set at 0x%08X.", addr);
		return ToolResultText(msg);
	} else if (type == "rendertarget") {
		uint32_t addr;
		if (!ParseAddress(args, "value", &addr))
			return ToolResultText("Missing or invalid 'value' parameter.", true);
		bp->AddRenderTargetBreakpoint(addr);

		char msg[256];
		snprintf(msg, sizeof(msg), "GE render target breakpoint set at 0x%08X.", addr);
		return ToolResultText(msg);
	}

	return ToolResultText("Invalid type. Use 'address', 'cmd', 'texture', or 'rendertarget'.", true);
}

static std::string HandleRemoveGEBreakpoint(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	std::string type;
	if (!args.getString("type", &type) || type.empty())
		return ToolResultText("Missing 'type' parameter.", true);

	GPUBreakpoints *bp = gpuDebug->GetBreakpoints();
	if (!bp)
		return ToolResultText("GPU breakpoints not available.", true);

	if (type == "address") {
		uint32_t addr;
		if (!ParseAddress(args, "value", &addr))
			return ToolResultText("Missing or invalid 'value' parameter.", true);
		bp->RemoveAddressBreakpoint(addr);
		char msg[128];
		snprintf(msg, sizeof(msg), "GE address breakpoint removed at 0x%08X.", addr);
		return ToolResultText(msg);
	} else if (type == "cmd") {
		uint32_t cmd;
		if (!ParseAddress(args, "value", &cmd))
			return ToolResultText("Missing or invalid 'value' parameter.", true);
		if (cmd > 255)
			return ToolResultText("GE command must be 0-255.", true);
		bp->RemoveCmdBreakpoint((u8)cmd);
		char msg[128];
		snprintf(msg, sizeof(msg), "GE command breakpoint removed for cmd %d.", cmd);
		return ToolResultText(msg);
	} else if (type == "texture") {
		uint32_t addr;
		if (!ParseAddress(args, "value", &addr))
			return ToolResultText("Missing or invalid 'value' parameter.", true);
		bp->RemoveTextureBreakpoint(addr);
		char msg[128];
		snprintf(msg, sizeof(msg), "GE texture breakpoint removed at 0x%08X.", addr);
		return ToolResultText(msg);
	} else if (type == "rendertarget") {
		uint32_t addr;
		if (!ParseAddress(args, "value", &addr))
			return ToolResultText("Missing or invalid 'value' parameter.", true);
		bp->RemoveRenderTargetBreakpoint(addr);
		char msg[128];
		snprintf(msg, sizeof(msg), "GE render target breakpoint removed at 0x%08X.", addr);
		return ToolResultText(msg);
	}

	return ToolResultText("Invalid type. Use 'address', 'cmd', 'texture', or 'rendertarget'.", true);
}

static std::string HandleSetGEBreakOn(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	std::string event;
	if (!args.getString("event", &event) || event.empty())
		return ToolResultText("Missing 'event' parameter.", true);

	int count = args.getInt("count", 1);
	if (count < 1) count = 1;

	GPUDebug::BreakNext breakNext;
	if (event == "op") breakNext = GPUDebug::BreakNext::OP;
	else if (event == "draw") breakNext = GPUDebug::BreakNext::DRAW;
	else if (event == "tex") breakNext = GPUDebug::BreakNext::TEX;
	else if (event == "nontex") breakNext = GPUDebug::BreakNext::NONTEX;
	else if (event == "frame") breakNext = GPUDebug::BreakNext::FRAME;
	else if (event == "vsync") breakNext = GPUDebug::BreakNext::VSYNC;
	else if (event == "prim") breakNext = GPUDebug::BreakNext::PRIM;
	else if (event == "curve") breakNext = GPUDebug::BreakNext::CURVE;
	else if (event == "blocktransfer") breakNext = GPUDebug::BreakNext::BLOCK_TRANSFER;
	else
		return ToolResultText("Invalid event. Use: op, draw, tex, nontex, frame, vsync, prim, curve, blocktransfer.", true);

	gpuDebug->SetBreakNext(breakNext);
	gpuDebug->SetBreakCount(count);

	char msg[128];
	snprintf(msg, sizeof(msg), "GE will break on next '%s' event (count=%d).", event.c_str(), count);
	return ToolResultText(msg);
}

static std::string HandleGetGPUStats(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	char stats[4096];
	gpuDebug->GetStats(stats, sizeof(stats));

	JsonWriter j;
	j.begin();
	j.writeString("stats", stats);
	j.writeInt("prims_this_frame", gpuDebug->PrimsThisFrame());
	j.writeInt("prims_last_frame", gpuDebug->PrimsLastFrame());
	j.end();
	return ToolResultText(j.str());
}

static std::string HandleGetCurrentVertices(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	if (coreState != CORE_STEPPING_CPU && !GPUStepping::IsStepping())
		return ToolResultText("Emulator must be paused (use the pause tool first).", true);

	int count = gpuDebug->GetCurrentPrimCount();
	if (count <= 0)
		return ToolResultText("No draw call in progress. Break on a draw command first (use set_ge_break_on with 'draw').", true);

	std::vector<GPUDebugVertex> vertices;
	std::vector<u16> indices;
	if (!gpuDebug->GetCurrentDrawAsDebugVertices(count, vertices, indices))
		return ToolResultText("Failed to get vertex data.", true);

	JsonWriter j;
	j.begin();
	j.writeInt("vertex_count", (int)vertices.size());
	j.writeInt("index_count", (int)indices.size());
	j.pushArray("vertices");
	for (const auto &v : vertices) {
		j.pushDict();
		j.writeFloat("x", v.x);
		j.writeFloat("y", v.y);
		j.writeFloat("z", v.z);
		j.writeFloat("u", v.u);
		j.writeFloat("v", v.v);
		j.writeFloat("nx", v.nx);
		j.writeFloat("ny", v.ny);
		j.writeFloat("nz", v.nz);
		char color[16];
		snprintf(color, sizeof(color), "#%02X%02X%02X%02X", v.c[0], v.c[1], v.c[2], v.c[3]);
		j.writeString("color", color);
		j.pop();
	}
	j.pop();
	if (!indices.empty()) {
		j.pushArray("indices");
		for (u16 idx : indices) {
			j.writeInt(idx);
		}
		j.pop();
	}
	j.end();
	return ToolResultText(j.str());
}

static void WriteMatrix(JsonWriter &j, const char *name, const float *m, int rows, int cols) {
	j.pushArray(name);
	for (int r = 0; r < rows; r++) {
		j.pushArray();
		for (int c = 0; c < cols; c++)
			j.writeFloat(m[r * cols + c]);
		j.pop();
	}
	j.pop();
}

static std::string HandleGetGPUMatrices(const JsonGet &args) {
	if (PSP_GetBootState() != BootState::Complete || !gpuDebug)
		return ToolResultText("No game loaded.", true);

	std::string name;
	args.getString("name", &name);
	if (name.empty()) name = "all";

	const GPUgstate &gs = gpuDebug->GetGState();

	JsonWriter j;
	j.begin();
	if (name == "all" || name == "world")
		WriteMatrix(j, "world", gs.worldMatrix, 4, 3);
	if (name == "all" || name == "view")
		WriteMatrix(j, "view", gs.viewMatrix, 4, 3);
	if (name == "all" || name == "projection")
		WriteMatrix(j, "projection", gs.projMatrix, 4, 4);
	if (name == "all" || name == "texgen")
		WriteMatrix(j, "texgen", gs.tgenMatrix, 4, 3);
	if (name == "all" || name == "bone") {
		j.pushDict("bone");
		for (int i = 0; i < 8; i++) {
			char boneName[16];
			snprintf(boneName, sizeof(boneName), "bone%d", i);
			WriteMatrix(j, boneName, &gs.boneMatrix[i * 12], 4, 3);
		}
		j.pop();
	}
	j.end();
	return ToolResultText(j.str());
}

typedef std::string (*ToolHandler)(const JsonGet &args);
static std::map<std::string, ToolHandler> &GetToolHandlers() {
	static std::map<std::string, ToolHandler> handlers = {
		{"get_status", HandleGetStatus},
		{"get_game_info", HandleGetGameInfo},
		{"read_memory", HandleReadMemory},
		{"write_memory", HandleWriteMemory},
		{"read_registers", HandleReadRegisters},
		{"write_register", HandleWriteRegister},
		{"disassemble", HandleDisassemble},
		{"assemble", HandleAssemble},
		{"search_memory", HandleSearchMemory},
		{"pause", HandlePause},
		{"resume", HandleResume},
		{"step_into", HandleStepInto},
		{"list_threads", HandleListThreads},
		{"set_breakpoint", HandleSetBreakpoint},
		{"remove_breakpoint", HandleRemoveBreakpoint},
		{"set_memcheck", HandleSetMemcheck},
		{"remove_memcheck", HandleRemoveMemcheck},
		{"list_breakpoints", HandleListBreakpoints},
		{"lookup_symbol", HandleLookupSymbol},
		{"take_screenshot", HandleTakeScreenshot},
		{"list_framebuffers", HandleListFramebuffers},
		{"get_framebuffer", HandleGetFramebuffer},
		{"list_hle_modules", HandleListHLEModules},
		{"ge_list_display_lists", HandleGEListDisplayLists},
		{"ge_disassemble", HandleGEDisassemble},
		{"get_gpu_state", HandleGetGPUState},
		{"get_current_texture", HandleGetCurrentTexture},
		{"get_depth_buffer", HandleGetDepthBuffer},
		{"get_stencil_buffer", HandleGetStencilBuffer},
		{"get_current_clut", HandleGetCurrentClut},
		{"set_ge_breakpoint", HandleSetGEBreakpoint},
		{"remove_ge_breakpoint", HandleRemoveGEBreakpoint},
		{"set_ge_break_on", HandleSetGEBreakOn},
		{"get_gpu_stats", HandleGetGPUStats},
		{"get_current_vertices", HandleGetCurrentVertices},
		{"get_gpu_matrices", HandleGetGPUMatrices},
	};
	return handlers;
}

static std::string HandleInitialize(const JsonGet &params, const std::string &idRaw) {
	JsonWriter j;
	j.begin();
	j.writeString("protocolVersion", "2024-11-05");
	j.pushDict("capabilities");
	j.pushDict("tools");
	j.pop();
	j.pop();
	j.pushDict("serverInfo");
	j.writeString("name", "ppsspp");
	j.writeString("version", PPSSPP_GIT_VERSION);
	j.pop();
	j.writeString("instructions", "PPSSPP PSP Emulator MCP server. Provides tools for inspecting and controlling the emulated PSP. Memory addresses are in PSP address space (user RAM starts at 0x08800000).");
	j.end();
	return MakeJsonRpcResult(idRaw, j.str());
}

static std::string HandleToolsList(const JsonGet &params, const std::string &idRaw) {
	auto tools = GetToolDefs();

	JsonWriter j;
	j.begin();
	j.pushArray("tools");
	for (auto &tool : tools) {
		j.pushDict();
		j.writeString("name", tool.name);
		j.writeString("description", tool.description);
		j.writeRaw("inputSchema", BuildInputSchema(tool));
		j.pop();
	}
	j.pop();
	j.end();
	return MakeJsonRpcResult(idRaw, j.str());
}

static std::string HandleToolsCall(const JsonGet &params, const std::string &idRaw) {
	const char *toolName = params.getStringOrNull("name");
	if (!toolName) {
		return MakeJsonRpcError(idRaw, kJsonRpcInvalidParams, "Missing tool 'name'.");
	}

	auto &handlers = GetToolHandlers();
	auto it = handlers.find(toolName);
	if (it == handlers.end()) {
		return MakeJsonRpcError(idRaw, kJsonRpcMethodNotFound, std::string("Unknown tool: ") + toolName);
	}

	const JsonNode *argsNode = params.get("arguments");
	JsonGet argsGet = argsNode ? JsonGet(argsNode->value) : JsonGet(JsonValue(JSON_NULL));

	std::string resultJson = it->second(argsGet);
	return MakeJsonRpcResult(idRaw, resultJson);
}

static std::string HandlePing(const JsonGet &params, const std::string &idRaw) {
	return MakeJsonRpcResult(idRaw, "{}");
}

static void HandleMCPRequest(const http::ServerRequest &request) {
	SetCurrentThreadName("MCPHandler");

	if (request.Method() == http::RequestHeader::GET) {
		// SSE stream - not supported
		request.WriteHttpResponseHeader("1.1", 405, -1, "text/plain");
		request.Out()->Push("SSE streams not supported. Use POST.\r\n");
		return;
	}

	if (request.Method() != http::RequestHeader::POST) {
		request.WriteHttpResponseHeader("1.1", 405, -1, "text/plain");
		request.Out()->Push("Method not allowed.\r\n");
		return;
	}

	int contentLength = request.Header().content_length;
	if (contentLength <= 0 || contentLength > 1024 * 1024) {
		request.WriteHttpResponseHeader("1.1", 400, -1, "application/json");
		std::string err = MakeJsonRpcError("null", kJsonRpcParseError, "Invalid or missing Content-Length.");
		request.Out()->Push(err);
		return;
	}

	std::string body(contentLength, '\0');
	if (!request.In()->TakeExact(body.data(), contentLength)) {
		request.WriteHttpResponseHeader("1.1", 400, -1, "application/json");
		std::string err = MakeJsonRpcError("null", kJsonRpcParseError, "Failed to read request body.");
		request.Out()->Push(err);
		return;
	}

	JsonReader reader(body.c_str(), body.size());
	if (!reader.ok()) {
		request.WriteHttpResponseHeader("1.1", 400, -1, "application/json");
		std::string err = MakeJsonRpcError("null", kJsonRpcParseError, "Invalid JSON.");
		request.Out()->Push(err);
		return;
	}

	const JsonGet root = reader.root();
	if (!root) {
		request.WriteHttpResponseHeader("1.1", 400, -1, "application/json");
		std::string err = MakeJsonRpcError("null", kJsonRpcInvalidRequest, "Expected JSON object.");
		request.Out()->Push(err);
		return;
	}

	const char *method = root.getStringOrNull("method");
	if (!method) {
		request.WriteHttpResponseHeader("1.1", 400, -1, "application/json");
		std::string err = MakeJsonRpcError("null", kJsonRpcInvalidRequest, "Missing 'method'.");
		request.Out()->Push(err);
		return;
	}

	std::string idRaw;
	const JsonNode *idNode = root.get("id");
	if (idNode) {
		idRaw = json::json_stringify(idNode);
	}

	bool isNotification = !idNode;

	if (isNotification) {
		// notifications/initialized, notifications/cancelled, etc.
		request.WriteHttpResponseHeader("1.1", 202, 0, "application/json");
		return;
	}

	std::string response;

	const JsonNode *paramsNode = root.get("params");
	JsonGet params = paramsNode ? JsonGet(paramsNode->value) : JsonGet(JsonValue(JSON_NULL));

	if (strcmp(method, "initialize") == 0) {
		response = HandleInitialize(params, idRaw);
	} else if (strcmp(method, "ping") == 0) {
		response = HandlePing(params, idRaw);
	} else if (strcmp(method, "tools/list") == 0) {
		response = HandleToolsList(params, idRaw);
	} else if (strcmp(method, "tools/call") == 0) {
		response = HandleToolsCall(params, idRaw);
	} else {
		response = MakeJsonRpcError(idRaw, kJsonRpcMethodNotFound, std::string("Unknown method: ") + method);
	}

	request.WriteHttpResponseHeader("1.1", 200, response.size(), "application/json");
	request.Out()->Push(response);
}

static void HandleMCPFallback(const http::ServerRequest &request) {
	static const std::string payload = "404 not found\r\n";
	request.WriteHttpResponseHeader("1.1", 404, payload.size(), "text/plain");
	request.Out()->Push(payload);
}

static void MCPServerThread(int port) {
	SetCurrentThreadName("MCPServer");

	auto server = new http::Server(new NewThreadExecutor());
	server->RegisterHandler("/mcp", &HandleMCPRequest);
	server->SetFallbackHandler(&HandleMCPFallback);

	if (!server->Listen(port, "mcp-server")) {
		if (!server->Listen(0, "mcp-server")) {
			ERROR_LOG(Log::HTTP, "MCP server: unable to listen on any port");
			delete server;
			std::lock_guard<std::mutex> guard(mcpLock);
			mcpRunning = false;
			return;
		}
	}

	{
		std::lock_guard<std::mutex> guard(mcpLock);
		mcpPort = server->Port();
		mcpRunning = true;
	}

	INFO_LOG(Log::HTTP, "MCP server listening on port %d", server->Port());
	g_OSD.Show(OSDType::MESSAGE_SUCCESS, StringFromFormat("MCP server started on port %d", server->Port()), 3.0f);

	while (mcpRunning) {
		server->RunSlice(0.25);
	}

	INFO_LOG(Log::HTTP, "MCP server shutting down");
	server->Stop();
	delete server;
}

bool StartMCPServer(int port) {
	std::lock_guard<std::mutex> guard(mcpLock);
	if (mcpRunning)
		return false;

	CPUCore core = (CPUCore)g_Config.iCpuCore;
	if (core == CPUCore::JIT || core == CPUCore::JIT_IR) {
		g_OSD.Show(OSDType::MESSAGE_ERROR,
			"MCP server requires interpreter mode",
			"Change CPU core to Interpreter in Developer Tools settings.",
			5.0f);
		return false;
	}

	mcpRunning = true;
	mcpThread = std::thread(&MCPServerThread, port);
	return true;
}

void ShutdownMCPServer() {
	{
		std::lock_guard<std::mutex> guard(mcpLock);
		if (!mcpRunning)
			return;
		mcpRunning = false;
	}
	if (mcpThread.joinable())
		mcpThread.join();

	g_OSD.Show(OSDType::MESSAGE_INFO, "MCP server stopped", 2.0f);
}

bool MCPServerRunning() {
	std::lock_guard<std::mutex> guard(mcpLock);
	return mcpRunning;
}

int MCPServerPort() {
	std::lock_guard<std::mutex> guard(mcpLock);
	return mcpPort;
}
