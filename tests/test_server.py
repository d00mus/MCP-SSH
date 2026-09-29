"""The MCP layer: protocol, tool catalogue, argument handling, the stdio loop."""

import io
import json
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from mcp_ssh_gateway import __version__
from mcp_ssh_gateway.main import build_gateway, build_parser, default_cache_root, load_registry, serve
from mcp_ssh_gateway.server import (
    SERVER_NAME, TOOLS, Gateway, handle_request, is_control_request, to_bool, to_number,
)
from tests.test_manager import ManagerTestCase, servers_json


def request(method, params=None, id=1):
    message = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        message["id"] = id
    if params is not None:
        message["params"] = params
    return message


class ServerTestCase(ManagerTestCase):
    def gateway(self, **settings):
        return Gateway(self.manager(servers_json(web={}), **settings))

    def call(self, gateway, tool, id=1, **arguments):
        response = handle_request(request("tools/call", {"name": tool, "arguments": arguments}, id), gateway)
        result = response["result"]
        return json.loads(result["content"][0]["text"]), bool(result.get("isError"))


class TestProtocol(ServerTestCase):
    def test_initialize_announces_version_tools_and_instructions(self):
        result = handle_request(request("initialize", {"protocolVersion": "2025-06-18"}), self.gateway())["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")
        self.assertEqual(result["serverInfo"], {"name": SERVER_NAME, "version": __version__})
        self.assertIn("server_list", result["instructions"])
        self.assertIn("No session_id = a new shell", result["instructions"])
        self.assertEqual(result["capabilities"], {"tools": {}})

    def test_an_unknown_protocol_version_gets_the_oldest_supported_one(self):
        result = handle_request(request("initialize", {"protocolVersion": "1999-01-01"}), self.gateway())["result"]
        self.assertEqual(result["protocolVersion"], "2024-11-05")

    def test_notifications_get_no_answer(self):
        gateway = self.gateway()
        self.assertIsNone(handle_request(request("notifications/initialized", id=None), gateway))
        self.assertIsNone(handle_request(request("something", id=None), gateway))

    def test_ping_and_unknown_methods(self):
        gateway = self.gateway()
        self.assertEqual(handle_request(request("ping"), gateway)["result"], {})
        self.assertEqual(handle_request(request("nope"), gateway)["error"]["code"], -32601)

    def test_a_message_that_is_not_an_object_is_an_invalid_request(self):
        self.assertEqual(handle_request([1, 2], self.gateway())["error"]["code"], -32600)

    def test_bad_params_are_reported_not_raised(self):
        gateway = self.gateway()
        self.assertEqual(handle_request(request("tools/call", []), gateway)["error"]["code"], -32602)
        self.assertEqual(handle_request(request("tools/call", {"name": "run", "arguments": []}), gateway)["error"]["code"], -32602)
        self.assertEqual(handle_request(request("tools/call", {"name": "nope"}), gateway)["error"]["code"], -32601)


class TestCatalogue(ServerTestCase):
    def listed(self, **settings):
        return handle_request(request("tools/list"), self.gateway(**settings))["result"]["tools"]

    def test_the_default_tool_set_is_small_and_has_no_server_add(self):
        self.assertEqual([t["name"] for t in self.listed()],
                         ["server_list", "run", "read", "signal", "session_close", "file"])

    def test_server_add_appears_only_when_allowed(self):
        self.assertIn("server_add", [t["name"] for t in self.listed(allow_add_server=True)])

    def test_every_parameter_is_described_for_weak_models(self):
        for tool in TOOLS:
            self.assertTrue(tool["description"], tool["name"])
            schema = tool["inputSchema"]
            self.assertFalse(schema["additionalProperties"])
            for name, spec in schema["properties"].items():
                self.assertTrue(spec.get("description") or spec.get("enum"), f"{tool['name']}.{name}")
            self.assertTrue(set(schema["required"]) <= set(schema["properties"]), tool["name"])

    def test_the_file_tool_has_no_knob_that_a_default_or_another_tool_covers(self):
        parameters = set(next(tool for tool in TOOLS if tool["name"] == "file")["inputSchema"]["properties"])
        self.assertLessEqual(len(parameters), 14, sorted(parameters))
        # a size cap (the answers are capped anyway), a backup (cp) and a regex filter (grep) are `run` work
        self.assertEqual(parameters & {"max_chars", "max_bytes", "create_backup", "regex"}, set())

    def test_the_catalogue_stays_within_its_token_budget(self):
        size = len(json.dumps(self.listed(allow_add_server=True), separators=(",", ":")))
        self.assertLess(size, 7500, f"tools/list is {size} characters; every session pays for it")

    def test_only_read_and_server_list_claim_to_be_read_only(self):
        flags = {t["name"]: t["annotations"]["readOnlyHint"] for t in self.listed()}
        self.assertEqual({name for name, flag in flags.items() if flag}, {"server_list", "read"})


class TestToolCalls(ServerTestCase):
    def test_run_returns_the_console_view_and_no_error_flag_for_a_nonzero_exit(self):
        gateway = self.gateway()
        payload, is_error = self.call(gateway, "run", command="false", server="web")
        self.assertFalse(is_error)
        self.assertEqual((payload["status"], payload["exit_code"], payload["session_id"]), ("completed", 1, "web/1"))
        self.assertEqual(payload["output"], "$ false\n")

    def test_the_answer_is_compact_json(self):
        gateway = self.gateway()
        response = handle_request(request("tools/call", {"name": "server_list", "arguments": {}}), gateway)
        text = response["result"]["content"][0]["text"]
        self.assertNotIn(": ", text.split('"host"')[0])
        self.assertEqual(json.loads(text)["servers"][0]["server"], "web")

    def test_arguments_written_as_strings_are_understood(self):
        gateway = self.gateway()
        payload, is_error = self.call(gateway, "run", command="echo hi", wait="5", shell="true", lines="50")
        self.assertFalse(is_error)
        self.assertEqual(payload["output"], "$ echo hi\nhi\n")

    def test_run_without_a_session_id_opens_a_new_shell_and_with_one_continues_it(self):
        gateway = self.gateway()
        first, _ = self.call(gateway, "run", command="true", server="web")
        second, _ = self.call(gateway, "run", command="true", server="web")
        self.assertEqual((first["session_id"], second["session_id"]), ("web/1", "web/2"))
        again, _ = self.call(gateway, "run", command="true", session_id="web/1")
        self.assertEqual(again["session_id"], "web/1")

    def test_there_is_no_new_session_argument_any_more(self):
        payload, is_error = self.call(self.gateway(), "run", command="true", server="web", new_session=True)
        self.assertTrue(is_error)
        self.assertIn("'new_session'", payload["error"])

    def test_a_missing_command_is_a_tool_error_with_a_hint(self):
        payload, is_error = self.call(self.gateway(), "run")
        self.assertTrue(is_error)
        self.assertIn("command", payload["error"])

    def test_an_unknown_argument_is_refused_naming_the_accepted_ones_and_nothing_runs(self):
        gateway = self.gateway()
        payload, is_error = self.call(gateway, "run", command="rm -rf build", server="web", cwd="/srv/app")
        self.assertTrue(is_error)
        self.assertIn("'cwd'", payload["error"])
        self.assertIn("command, server, session_id", payload["error"])
        self.assertIn("cd /path &&", payload["error"])
        self.assertEqual([s for row in gateway.manager.list_servers() for s in row.get("sessions", [])], [])

    def test_every_tool_refuses_arguments_it_does_not_have(self):
        gateway = self.gateway(allow_add_server=True)
        for tool in gateway.tools:
            payload, is_error = self.call(gateway, tool["name"], surprise=1)
            self.assertTrue(is_error, tool["name"])
            self.assertIn("'surprise'", payload["error"], tool["name"])

    def test_the_session_tools_tolerate_server_next_to_the_session_id(self):
        gateway = self.gateway()
        self.call(gateway, "run", command="true", server="web")
        payload, is_error = self.call(gateway, "read", session_id="web/1", server="web")
        self.assertFalse(is_error, payload)
        closed, is_error = self.call(gateway, "session_close", session_id="web/1", server="web")
        self.assertEqual((closed, is_error), ({"closed": "web/1"}, False))

    def test_a_page_size_below_one_is_refused_instead_of_becoming_one_line(self):
        gateway = self.gateway()
        self.call(gateway, "run", command="true", server="web")
        for lines in (0, -5):
            payload, is_error = self.call(gateway, "run", command="seq", server="web", lines=lines)
            self.assertTrue(is_error, lines)
            self.assertIn("'lines'", payload["error"])
        payload, is_error = self.call(gateway, "read", session_id="web/1", lines=0)
        self.assertTrue(is_error)
        self.assertIn("'lines'", payload["error"])
        payload, is_error = self.call(gateway, "read", session_id="web/1", tail=0)
        self.assertTrue(is_error)
        self.assertIn("'tail'", payload["error"])

    def test_an_unknown_server_lists_the_valid_ones(self):
        payload, is_error = self.call(self.gateway(), "run", command="ls", server="nas")
        self.assertTrue(is_error)
        self.assertIn("web", payload["error"])

    def test_read_needs_an_existing_session(self):
        payload, is_error = self.call(self.gateway(), "read", session_id="web/9")
        self.assertTrue(is_error)
        self.assertIn("web/9", payload["error"])

    def test_read_pages_and_scrolls(self):
        gateway = self.gateway()
        self.call(gateway, "run", command="seq", server="web")
        top, _ = self.call(gateway, "read", session_id="web/1", offset=0, lines=1)
        self.assertEqual(top["output"], "$ seq\n")

    def test_signal_ctrl_c_and_session_close(self):
        gateway = self.gateway()
        first, _ = self.call(gateway, "run", command="pause", server="web", wait=0.2)
        self.assertEqual(first["status"], "running")
        stopped, _ = self.call(gateway, "signal", session_id="web/1", action="ctrl_c", wait=5)
        self.assertEqual(stopped["status"], "interrupted")
        closed, is_error = self.call(gateway, "session_close", session_id="web/1")
        self.assertEqual((closed, is_error), ({"closed": "web/1"}, False))

    def test_signal_without_a_running_command_explains_itself(self):
        gateway = self.gateway()
        self.call(gateway, "run", command="true", server="web")
        payload, is_error = self.call(gateway, "signal", session_id="web/1", action="ctrl_c")
        self.assertTrue(is_error)
        self.assertIn("Nothing is running", payload["error"])

    def test_a_crashing_tool_does_not_kill_the_connection(self):
        gateway = self.gateway()
        gateway._handlers["server_list"] = lambda args, request_id: 1 / 0
        payload, is_error = self.call(gateway, "server_list")
        self.assertTrue(is_error)
        self.assertIn("Internal error", payload["error"])
        self.assertEqual(handle_request(request("ping"), gateway)["result"], {})

    def test_cancelling_a_request_stops_its_command(self):
        gateway = self.gateway()
        answers = []
        worker = threading.Thread(
            target=lambda: answers.append(self.call(gateway, "run", id=77, command="pause", server="web", wait=30)))
        worker.start()
        deadline = time.time() + 5
        while time.time() < deadline and not any(
                session["state"] == "busy" for row in gateway.manager.list_servers() for session in row.get("sessions", [])):
            time.sleep(0.02)
        handle_request(request("notifications/cancelled", {"requestId": 77}, id=None), gateway)
        worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(answers[0][0]["status"], "interrupted")

    def test_server_add_saves_the_server(self):
        gateway = self.gateway(allow_add_server=True)
        payload, is_error = self.call(gateway, "server_add", alias="nas", host="10.0.0.5", user="admin", password="x")
        self.assertFalse(is_error, payload)
        self.assertEqual(payload["added"], "nas")
        with open(self.path, encoding="utf-8") as handle:
            self.assertIn("nas", json.load(handle)["servers"])

    def test_server_add_is_unknown_when_not_allowed(self):
        response = handle_request(request("tools/call", {"name": "server_add", "arguments": {"alias": "x"}}),
                                  self.gateway())
        self.assertEqual(response["error"]["code"], -32601)


class TestArguments(unittest.TestCase):
    def test_to_bool(self):
        self.assertIs(to_bool("true"), True)
        self.assertIs(to_bool("False"), False)
        self.assertIs(to_bool(None, True), True)
        self.assertIs(to_bool(0), False)
        self.assertIsNone(to_bool(""))

    def test_to_number_clamps_and_falls_back(self):
        self.assertEqual(to_number("7", 1, 0, 10), 7)
        self.assertEqual(to_number(99, 1, 0, 10), 10)
        self.assertEqual(to_number(-5, 1, 0, 10), 0)
        self.assertEqual(to_number("abc", 3, 0, 10), 3)
        self.assertEqual(to_number(None, 3, 0, 10), 3)


class TestControlRequests(unittest.TestCase):
    def test_stopping_and_closing_skip_the_queue_but_everything_else_waits_its_turn(self):
        def call(name, **arguments):
            return request("tools/call", {"name": name, "arguments": arguments})

        self.assertTrue(is_control_request(call("signal", action="ctrl_c", session_id="a/1")))
        self.assertTrue(is_control_request(call("session_close", session_id="a/1")))
        self.assertFalse(is_control_request(call("signal", action="stdin", session_id="a/1", text="y")))
        self.assertFalse(is_control_request(call("run", command="ls")))
        self.assertFalse(is_control_request(request("ping")))
        self.assertFalse(is_control_request("junk"))


class TestStdioLoop(ServerTestCase):
    def talk(self, gateway, lines):
        out = io.StringIO()
        serve(gateway, io.StringIO("\n".join(lines) + "\n"), out)
        return [json.loads(line) for line in out.getvalue().splitlines()]

    def test_requests_are_answered_and_bad_lines_do_not_stop_the_loop(self):
        gateway = self.gateway()
        answers = self.talk(gateway, [
            json.dumps(request("initialize", {"protocolVersion": "2025-06-18"}, id=1)),
            "{not json",
            "",
            json.dumps(request("notifications/initialized", id=None)),
            json.dumps(request("tools/call", {"name": "run", "arguments": {"command": "echo hi", "server": "web"}}, id=2)),
        ])
        by_id = {a.get("id"): a for a in answers}
        self.assertEqual(by_id[1]["result"]["serverInfo"]["name"], SERVER_NAME)
        self.assertEqual(by_id[None]["error"]["code"], -32700)
        self.assertIn("hi", by_id[2]["result"]["content"][0]["text"])
        self.assertEqual(len(answers), 3)

    def test_ctrl_c_gets_through_while_a_run_occupies_the_workers(self):
        gateway = self.gateway()
        run = request("tools/call", {"name": "run", "arguments": {"command": "pause", "server": "web", "wait": 30}}, id=1)
        stop = request("tools/call", {"name": "signal", "arguments": {"session_id": "web/1", "action": "ctrl_c"}}, id=2)

        def client():
            yield json.dumps(run) + "\n"
            deadline = time.time() + 5
            while time.time() < deadline and not any(
                    session["state"] == "busy" for row in gateway.manager.list_servers() for session in row.get("sessions", [])):
                time.sleep(0.02)
            yield json.dumps(stop) + "\n"

        out = io.StringIO()
        serve(gateway, client(), out)
        answers = {a["id"]: json.loads(a["result"]["content"][0]["text"])
                   for a in map(json.loads, out.getvalue().splitlines())}
        self.assertEqual(answers[1]["status"], "interrupted")


class TestCommandLine(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cache = tmp.name

    def test_defaults(self):
        args = build_parser().parse_args([])
        self.assertEqual((args.log_output, args.read_only, args.allow_add_server), ("meta", False, False))

    def test_inline_json_is_accepted_as_servers_config(self):
        registry, path = load_registry(json.dumps(servers_json(web={})), False)
        self.assertEqual((registry.aliases(), path), (["web"], None))

    def gateway_from(self, argv, env=None):
        args = build_parser().parse_args(["--servers-config", json.dumps(servers_json(web={})),
                                          "--cache-dir", self.cache] + argv)
        with mock.patch.dict(os.environ, env or {}, clear=False):
            gateway = build_gateway(args)
        self.addCleanup(gateway.manager.close_all)
        return gateway.manager.settings

    def test_local_files_are_off_until_a_project_root_is_given(self):
        self.assertIsNone(self.gateway_from([]).project_root)
        self.assertEqual(self.gateway_from(["--project-root", self.cache]).project_root, os.path.abspath(self.cache))

    def test_guardrails_can_come_from_the_environment(self):
        settings = self.gateway_from([], {"SSH_READ_ONLY": "true", "SSH_COMMAND_BLACKLIST": "reboot, dd"})
        self.assertTrue(settings.read_only)
        self.assertEqual(settings.command_blacklist, ["reboot", "dd"])

    def test_flags_win_over_the_environment(self):
        settings = self.gateway_from(["--command-blacklist", "halt"], {"SSH_COMMAND_BLACKLIST": "reboot"})
        self.assertEqual(settings.command_blacklist, ["halt"])

    def test_the_cache_defaults_to_the_user_cache_directory_not_the_working_directory(self):
        with mock.patch.dict(os.environ, {"SSH_MCP_CACHE_DIR": ""}):
            self.assertNotEqual(default_cache_root(), os.path.join(os.getcwd(), ".ssh-cache"))
            self.assertTrue(default_cache_root().endswith("mcp-ssh-gateway"))

    def test_no_servers_is_a_clear_exit(self):
        args = build_parser().parse_args(["--servers-config", "{}"])
        with self.assertRaisesRegex(SystemExit, "No SSH servers"):
            build_gateway(args)


if __name__ == "__main__":
    unittest.main()
