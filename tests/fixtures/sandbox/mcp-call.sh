#!/bin/bash
# mcp-call.sh <tool> <json-arguments>
# One MCP tool call over `agentbox mcp`, from inside a sandbox. Prints the JSON-RPC response.
coproc MCP { agentbox mcp; }

send() { printf '%s\n' "$1" >&"${MCP[1]}"; }

send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized"}'
send "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"

while read -r line <&"${MCP[0]}"; do
  case $line in
    *'"id":2'*) echo "$line"; break ;;
  esac
done

kill "$MCP_PID" 2>/dev/null
