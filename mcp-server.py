#!/usr/bin/env python3
import sys
import os
import json

# Add the current directory to sys.path to allow absolute imports from src
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

def run_fallback():
    """Degraded mode (paramiko missing).

    Answer with real errors, never with an empty tool catalog (T4.1): a model
    seeing zero tools starts inventing them. Parse errors get -32700 instead of
    silence, so a client can never hang waiting for a response.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as exc:
            print(json.dumps({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }), flush=True)
            continue

        method = req.get("method")
        req_id = req.get("id")
        if isinstance(method, str) and method.startswith("notifications/"):
            continue

        if method == "ping":
            print(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}}), flush=True)
        elif method == "initialize":
            res = {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "ssh-mcp-vnext-fallback", "version": "1.0.0"},
                }
            }
            print(json.dumps(res), flush=True)
        elif method in ("tools/list", "tools/call"):
            res = {
                "jsonrpc": "2.0", "id": req_id,
                "error": {
                    "code": -32603,
                    "message": "paramiko library is required. Please install it using: python -m pip install paramiko"
                }
            }
            print(json.dumps(res), flush=True)
        elif req_id is not None:
            res = {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"Method {method} not supported in fallback mode"}
            }
            print(json.dumps(res), flush=True)

if __name__ == "__main__":
    try:
        from src.main import main
        # Try to import paramiko to catch it early before starting the real JSON-RPC loop
        import paramiko
        main()
    except ImportError as e:
        if "paramiko" in str(e):
            print("[SSH-MCP] paramiko is missing - running degraded (tools answer with errors). "
                  "Install it with: python -m pip install paramiko", file=sys.stderr, flush=True)
            print(json.dumps({
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {"type": "error", "message": "paramiko missing. Running in fallback mode."}
            }), flush=True)
            run_fallback()
        else:
            raise
