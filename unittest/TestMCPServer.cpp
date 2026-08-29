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

#include <cstdio>
#include <string>

#include "Common/Net/HTTPClient.h"
#include "Common/Net/NetBuffer.h"
#include "Common/Net/Resolve.h"
#include "Common/Data/Format/JSONReader.h"
#include "Common/TimeUtil.h"
#include "Core/MCPServer.h"
#include "unittest/UnitTest.h"

using json::JsonReader;
using json::JsonGet;

static bool MCPPost(int port, const std::string &body, std::string *responseBody, int *httpStatus) {
	http::Client client(nullptr);
	if (!client.Resolve("127.0.0.1", port, net::DNSType::IPV4)) {
		printf("  Failed to resolve localhost\n");
		return false;
	}
	if (!client.Connect()) {
		printf("  Failed to connect to MCP server on port %d\n", port);
		return false;
	}

	Buffer output;
	bool cancelled = false;
	net::RequestProgress progress(&cancelled);
	http::RequestParams params("/mcp");
	params.acceptMime = "application/json";
	int status = client.POST(params, body, "application/json", &output, &progress);
	client.Disconnect();

	if (httpStatus)
		*httpStatus = status;
	if (responseBody)
		output.TakeAll(responseBody);
	return status > 0;
}

bool TestMCPServer() {
	net::Init();

	int port = 19737;
	EXPECT_TRUE(StartMCPServer(port));

	sleep_ms(200, "mcp test startup");
	EXPECT_TRUE(MCPServerRunning());
	port = MCPServerPort();
	printf("  MCP server started on port %d\n", port);

	{
		std::string body = R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test"}}})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 200);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();
		EXPECT_TRUE(root);

		EXPECT_EQ_STR(std::string(root.getStringOr("jsonrpc", "")), std::string("2.0"));
		EXPECT_EQ_INT(root.getInt("id"), 1);

		const JsonNode *resultNode = root.get("result");
		EXPECT_TRUE(resultNode != nullptr);
		JsonGet result(resultNode->value);
		EXPECT_EQ_STR(std::string(result.getStringOr("protocolVersion", "")), std::string("2024-11-05"));

		const JsonNode *infoNode = result.get("serverInfo");
		EXPECT_TRUE(infoNode != nullptr);
		JsonGet info(infoNode->value);
		EXPECT_EQ_STR(std::string(info.getStringOr("name", "")), std::string("ppsspp"));

		const JsonNode *capsNode = result.get("capabilities");
		EXPECT_TRUE(capsNode != nullptr);
		JsonGet caps(capsNode->value);
		EXPECT_TRUE(caps.get("tools") != nullptr);

		printf("  [PASS] Initialize handshake\n");
	}

	{
		std::string body = R"({"jsonrpc":"2.0","method":"notifications/initialized"})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 202);
		printf("  [PASS] notifications/initialized returns 202\n");
	}

	{
		std::string body = R"({"jsonrpc":"2.0","id":2,"method":"ping"})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 200);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();
		EXPECT_EQ_INT(root.getInt("id"), 2);

		const JsonNode *resultNode = root.get("result");
		EXPECT_TRUE(resultNode != nullptr);

		printf("  [PASS] ping\n");
	}

	{
		std::string body = R"({"jsonrpc":"2.0","id":3,"method":"tools/list"})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 200);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();
		EXPECT_EQ_INT(root.getInt("id"), 3);

		const JsonNode *resultNode = root.get("result");
		EXPECT_TRUE(resultNode != nullptr);
		JsonGet result(resultNode->value);

		const JsonNode *toolsNode = result.getArray("tools");
		EXPECT_TRUE(toolsNode != nullptr);

		int toolCount = 0;
		bool foundGetStatus = false;
		bool foundReadMemory = false;
		bool foundDisassemble = false;
		bool foundTakeScreenshot = false;

		for (auto tool = toolsNode->value.toNode(); tool != nullptr; tool = tool->next) {
			JsonGet t(tool->value);
			const char *name = t.getStringOrNull("name");
			const char *desc = t.getStringOrNull("description");
			EXPECT_TRUE(name != nullptr);
			EXPECT_TRUE(desc != nullptr);

			const JsonNode *schema = t.get("inputSchema");
			EXPECT_TRUE(schema != nullptr);

			if (name && strcmp(name, "get_status") == 0) foundGetStatus = true;
			if (name && strcmp(name, "read_memory") == 0) foundReadMemory = true;
			if (name && strcmp(name, "disassemble") == 0) foundDisassemble = true;
			if (name && strcmp(name, "take_screenshot") == 0) foundTakeScreenshot = true;
			toolCount++;
		}

		EXPECT_TRUE(toolCount >= 18);
		EXPECT_TRUE(foundGetStatus);
		EXPECT_TRUE(foundReadMemory);
		EXPECT_TRUE(foundDisassemble);
		EXPECT_TRUE(foundTakeScreenshot);

		printf("  [PASS] tools/list (%d tools)\n", toolCount);
	}

	{
		std::string body = R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_status","arguments":{}}})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 200);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();
		EXPECT_EQ_INT(root.getInt("id"), 4);

		const JsonNode *resultNode = root.get("result");
		EXPECT_TRUE(resultNode != nullptr);
		JsonGet result(resultNode->value);

		const JsonNode *contentNode = result.getArray("content");
		EXPECT_TRUE(contentNode != nullptr);

		JsonGet firstContent(contentNode->value.toNode()->value);
		EXPECT_EQ_STR(std::string(firstContent.getStringOr("type", "")), std::string("text"));

		const char *text = firstContent.getStringOrNull("text");
		EXPECT_TRUE(text != nullptr);
		EXPECT_TRUE(strstr(text, "no_game") != nullptr);

		printf("  [PASS] tools/call get_status\n");
	}

	{
		std::string body = R"({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_game_info","arguments":{}}})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 200);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();

		const JsonNode *resultNode = root.get("result");
		EXPECT_TRUE(resultNode != nullptr);
		JsonGet result(resultNode->value);

		EXPECT_TRUE(result.getBoolOr("isError", false));

		printf("  [PASS] tools/call get_game_info (no game = error)\n");
	}

	{
		std::string body = R"({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nonexistent_tool","arguments":{}}})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 200);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();

		const JsonNode *errNode = root.get("error");
		EXPECT_TRUE(errNode != nullptr);
		JsonGet err(errNode->value);
		EXPECT_EQ_INT(err.getInt("code"), -32601); // Method not found

		printf("  [PASS] tools/call unknown tool returns error\n");
	}

	{
		std::string body = R"({"jsonrpc":"2.0","id":7,"method":"resources/list"})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 200);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();

		const JsonNode *errNode = root.get("error");
		EXPECT_TRUE(errNode != nullptr);
		JsonGet err(errNode->value);
		EXPECT_EQ_INT(err.getInt("code"), -32601);

		printf("  [PASS] Unknown method returns error\n");
	}

	{
		std::string body = "this is not json{{{";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 400);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();

		const JsonNode *errNode = root.get("error");
		EXPECT_TRUE(errNode != nullptr);
		JsonGet err(errNode->value);
		EXPECT_EQ_INT(err.getInt("code"), -32700); // Parse error

		printf("  [PASS] Invalid JSON returns parse error\n");
	}

	{
		std::string body = R"({"jsonrpc":"2.0","id":8})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 400);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();

		const JsonNode *errNode = root.get("error");
		EXPECT_TRUE(errNode != nullptr);
		JsonGet err(errNode->value);
		EXPECT_EQ_INT(err.getInt("code"), -32600); // Invalid request

		printf("  [PASS] Missing method returns invalid request error\n");
	}

	{
		std::string body = R"({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"list_breakpoints","arguments":{}}})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 200);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();

		const JsonNode *resultNode = root.get("result");
		EXPECT_TRUE(resultNode != nullptr);
		JsonGet result(resultNode->value);

		const JsonNode *contentNode = result.getArray("content");
		EXPECT_TRUE(contentNode != nullptr);

		printf("  [PASS] tools/call list_breakpoints\n");
	}

	{
		std::string body = R"({"jsonrpc":"2.0","id":"my-string-id","method":"ping"})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 200);

		EXPECT_TRUE(resp.find("\"my-string-id\"") != std::string::npos);

		printf("  [PASS] String id echoed correctly\n");
	}

	{
		std::string body = R"({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"arguments":{}}})";
		std::string resp;
		int status = 0;
		EXPECT_TRUE(MCPPost(port, body, &resp, &status));
		EXPECT_EQ_INT(status, 200);

		JsonReader reader(resp.c_str(), resp.size());
		EXPECT_TRUE(reader.ok());
		JsonGet root = reader.root();

		const JsonNode *errNode = root.get("error");
		EXPECT_TRUE(errNode != nullptr);
		JsonGet err(errNode->value);
		EXPECT_EQ_INT(err.getInt("code"), -32602); // Invalid params

		printf("  [PASS] tools/call missing name returns invalid params\n");
	}

	ShutdownMCPServer();
	EXPECT_FALSE(MCPServerRunning());
	printf("  MCP server stopped\n");

	net::Shutdown();
	return true;
}
