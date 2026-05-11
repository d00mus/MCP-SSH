#!/usr/bin/env python3
import sys
import os
import json

# Add the current directory to sys.path to allow absolute imports from src
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

def run_fallback():
    # Simple JSON-RPC loop that always returns an error for tools/call
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            method = req.get("method")
            req_id = req.get("id")
            
            if method == "initialize":
                res = {
                    "jsonrpc": "2.0", "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "ssh-mcp-vnext-fallback", "version": "1.0.0"},
                    }
                }
                print(json.dumps(res), flush=True)
            elif method == "tools/list":
                res = {
                    "jsonrpc": "2.0", "id": req_id,
                    "result": {"tools": []}
                }
                print(json.dumps(res), flush=True)
            elif method == "tools/call":
                res = {
                    "jsonrpc": "2.0", "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": "paramiko library is required. Please install it using: python -m pip install paramiko"
                    }
                }
                print(json.dumps(res), flush=True)
            elif method == "notifications/initialized":
                pass
            else:
                if req_id is not None:
                    res = {
                        "jsonrpc": "2.0", "id": req_id,
                        "error": {"code": -32601, "message": f"Method {method} not supported in fallback mode"}
                    }
                    print(json.dumps(res), flush=True)
        except Exception:
            pass

if __name__ == "__main__":
    try:
        from src.main import main
        # Try to import paramiko to catch it early before starting the real JSON-RPC loop
        import paramiko
        main()
    except ImportError as e:
        if "paramiko" in str(e):
            print(json.dumps({
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {"type": "error", "message": "paramiko missing. Running in fallback mode."}
            }), flush=True)
            run_fallback()
        else:
            raise
