"""The shape of every answer, in one place.

The answers are what the agent works with and most of what it pays for in tokens. A key that appears or
disappears has to be decided here, not slip in somewhere else."""

import unittest

from mcp_ssh_gateway.server import handle_request
from tests.test_server import ServerTestCase, request

ANSWER = {"session_id", "status", "output"}


class TestRunAnswers(ServerTestCase):
    def test_a_finished_command_answers_with_its_exit_code_and_nothing_else(self):
        payload, is_error = self.call(self.gateway(), "run", command="echo hi", server="web")
        self.assertEqual((set(payload), is_error), (ANSWER | {"exit_code"}, False))

    def test_a_failed_command_has_the_same_shape(self):
        payload, is_error = self.call(self.gateway(), "run", command="false", server="web")
        self.assertEqual((set(payload), payload["exit_code"], is_error), (ANSWER | {"exit_code"}, 1, False))

    def test_a_command_still_running_carries_a_hint_and_no_exit_code(self):
        payload, _ = self.call(self.gateway(), "run", command="sleep 30", server="web", wait=0.2)
        self.assertEqual((payload["status"], set(payload)), ("running", ANSWER | {"hint"}))
        self.assertIn("read(session_id='web/1')", payload["hint"])

    def test_a_question_carries_a_hint_that_says_how_to_answer(self):
        payload, _ = self.call(self.gateway(), "run", command="ask", server="web", wait=5)
        self.assertEqual((payload["status"], set(payload)), ("waiting_input", ANSWER | {"hint"}))
        self.assertIn("signal action=stdin", payload["hint"])

    def test_output_beyond_the_page_says_how_many_lines_are_still_unread(self):
        payload, _ = self.call(self.gateway(), "run", command="seq 1 100", server="web", lines=10)
        self.assertEqual(set(payload), ANSWER | {"exit_code", "has_more"})
        self.assertEqual(payload["output"].count("\n"), 10)
        self.assertEqual(payload["has_more"], 1 + 100 - 10)  # the "$ seq 1 100" line and the numbers, less the page

    def test_a_new_command_over_unread_output_reports_how_much_it_passed_over(self):
        gateway = self.gateway()
        first, _ = self.call(gateway, "run", command="seq 1 50", server="web", lines=5)
        second, _ = self.call(gateway, "run", command="echo next", session_id=first["session_id"])
        self.assertEqual(set(second), ANSWER | {"exit_code", "skipped_lines"})
        self.assertEqual(second["skipped_lines"], first["has_more"])

    def test_the_answer_to_a_trivial_command_stays_small(self):
        response = handle_request(request("tools/call", {"name": "run", "arguments": {"command": "echo hi", "server": "web"}}),
                                  self.gateway())
        text = response["result"]["content"][0]["text"]
        self.assertLessEqual(len(text), 100, text)  # it is 84 today; a bigger wrapper is paid for on every call


class TestSessionAnswers(ServerTestCase):
    def test_read_of_a_finished_command_repeats_its_status_and_no_output(self):
        gateway = self.gateway()
        run, _ = self.call(gateway, "run", command="echo hi", server="web")
        payload, _ = self.call(gateway, "read", session_id=run["session_id"])
        self.assertEqual(payload, {"session_id": "web/1", "status": "completed", "output": "", "exit_code": 0})

    def test_ctrl_c_answers_with_the_new_status_and_whether_the_process_stopped(self):
        gateway = self.gateway()
        self.call(gateway, "run", command="sleep 30", server="web", wait=0.2)
        payload, _ = self.call(gateway, "signal", session_id="web/1", action="ctrl_c")
        self.assertEqual(payload["status"], "interrupted")
        self.assertEqual(set(payload), ANSWER | {"process_stopped"})
        self.assertIs(payload["process_stopped"], True)

    def test_closing_a_session_names_it(self):
        gateway = self.gateway()
        self.call(gateway, "run", command="true", server="web")
        payload, _ = self.call(gateway, "session_close", session_id="web/1")
        self.assertEqual(payload, {"closed": "web/1"})

    def test_the_server_list_shows_each_server_and_the_shells_open_on_it(self):
        gateway = self.gateway()
        payload, _ = self.call(gateway, "server_list")
        self.assertEqual(payload, {"servers": [{"server": "web", "host": "web.example:22", "user": "u"}]})
        self.call(gateway, "run", command="true", server="web")
        self.call(gateway, "run", command="sleep 30", server="web", wait=0.2)
        payload, _ = self.call(gateway, "server_list")
        self.assertEqual(payload["servers"][0]["sessions"], [
            {"session_id": "web/1", "state": "idle", "mode": "shell"},
            {"session_id": "web/2", "state": "busy", "mode": "shell", "running": "sleep 30"}])


class TestEnvelope(ServerTestCase):
    def test_a_result_is_one_text_block_and_carries_the_error_flag_only_for_errors(self):
        gateway = self.gateway()
        ok = handle_request(request("tools/call", {"name": "server_list", "arguments": {}}), gateway)["result"]
        bad = handle_request(request("tools/call", {"name": "run", "arguments": {}}), gateway)["result"]
        self.assertEqual((set(ok), [block["type"] for block in ok["content"]]), ({"content"}, ["text"]))
        self.assertEqual((set(bad), bad["isError"]), ({"content", "isError"}, True))

    def test_a_refusal_is_a_single_error_message(self):
        payload, is_error = self.call(self.gateway(), "run")
        self.assertEqual((set(payload), is_error), ({"error"}, True))


if __name__ == "__main__":
    unittest.main()
