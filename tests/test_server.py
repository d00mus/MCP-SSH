import unittest
from unittest.mock import MagicMock, patch
import json

from src.server import project_tool_result, handle_request, tools_list

class TestServer(unittest.TestCase):
    def test_project_tool_result_mcp_level_errors(self):
        # Test non-object return
        res = project_tool_result("run", "not-a-dict")
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "tool returned non-object result")

        # Test success = False (MCP error)
        raw_err = {"success": False, "error": "connection timeout", "session_id": 42}
        res = project_tool_result("run", raw_err)
        self.assertFalse(res["success"])
        self.assertEqual(res["session_id"], 42)
        self.assertEqual(res["error"], "connection timeout")

    def test_project_tool_result_completed_nonzero(self):
        # Non-zero exit status should be wrapped in loud warnings
        raw = {
            "success": True,
            "status": "completed_nonzero",
            "exit_status": 127,
            "output": "bash: command not found",
            "session_id": 1,
            "run_id": 5
        }
        res = project_tool_result("run", raw)
        self.assertEqual(res["session_id"], 1)
        self.assertEqual(res["run_id"], 5)
        self.assertEqual(res["status"], "completed_nonzero")
        self.assertIn("Command failed with exit status 127", res["error"])
        self.assertIn("[WARNING: Command execution failed", res["output"])

    def test_project_tool_result_file_read_download(self):
        # File download action
        raw = {
            "success": True,
            "action": "read",
            "mode": "download",
            "local_path": "/tmp/local.txt",
            "size": 100
        }
        res = project_tool_result("file", raw)
        self.assertIn("Downloaded to /tmp/local.txt", res["message"])
        self.assertEqual(res["size"], 100)

    def test_project_tool_result_file_list(self):
        # File list action
        raw = {
            "success": True,
            "action": "list",
            "files": [{"name": "test.txt", "size": 10, "is_dir": False}]
        }
        res = project_tool_result("file", raw)
        self.assertEqual(len(res["files"]), 1)

    def test_handle_request_initialize(self):
        mock_manager = MagicMock()
        req = {
            "jsonrpc": "2.0",
            "id": 123,
            "method": "initialize",
            "params": {}
        }
        res = handle_request(req, mock_manager)
        self.assertEqual(res["id"], 123)
        self.assertEqual(res["result"]["protocolVersion"], "2024-11-05")
        self.assertTrue(mock_manager.ensure_session.called)

    def test_handle_request_tools_list(self):
        mock_manager = MagicMock()
        req = {
            "jsonrpc": "2.0",
            "id": 456,
            "method": "tools/list",
            "params": {}
        }
        res = handle_request(req, mock_manager)
        self.assertEqual(res["id"], 456)
        self.assertIn("tools", res["result"])

    def test_handle_request_unknown_method(self):
        mock_manager = MagicMock()
        req = {
            "jsonrpc": "2.0",
            "id": 789,
            "method": "unknown_method"
        }
        res = handle_request(req, mock_manager)
        self.assertIn("error", res)
        self.assertEqual(res["error"]["code"], -32601)

    def test_handle_request_tool_session_list(self):
        mock_manager = MagicMock()
        mock_manager.list_sessions.return_value = {
            "success": True,
            "sessions": [{"session_id": 1, "name": "active"}]
        }
        
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "session_list",
                "arguments": {"include_name": True}
            }
        }
        res = handle_request(req, mock_manager)
        text_content = res["result"]["content"][0]["text"]
        self.assertEqual(json.loads(text_content), {
            "sessions": [{"session_id": 1, "name": "active"}]
        })

if __name__ == "__main__":
    unittest.main()
