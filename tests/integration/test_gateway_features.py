"""Gateway behaviour that needs a real sshd: host keys, hosts without SFTP, guardrails, pitfalls."""

import base64
import hashlib
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from tests.integration.support import Gateway, SshdTestCase, body
from tests.integration.test_linux_hosts import FileScenarios


class DebianFeatures(SshdTestCase):
    flavor = "debian"

    def test_unclosed_quote_is_reported_as_waiting_input_and_recoverable(self):
        first = self.gw.call("run", server="host", command="echo 'oops", wait=3)
        self.assertEqual(first["status"], "waiting_input", first)
        self.assertIn("unclosed", first["hint"])
        stopped = self.gw.call("signal", session_id=first["session_id"], action="ctrl_c")
        self.assertIn(stopped["status"], ("interrupted", "completed"))
        self.assertEqual(body(self.gw.run("echo fine", session_id=first["session_id"])["output"]), "fine")

    def test_a_program_reading_stdin_gets_text_and_ctrl_d(self):
        first = self.gw.call("run", server="host", command="cat", wait=1)
        self.assertEqual(first["status"], "running")
        typed = self.gw.call("signal", session_id=first["session_id"], action="stdin", text="hi", wait=1)
        self.assertIn("hi", typed["output"])
        ended = self.gw.call("signal", session_id=first["session_id"], action="ctrl_d")
        self.assertEqual((ended["status"], ended["exit_code"]), ("completed", 0))

    def test_unicode_output_survives(self):
        self.assertEqual(body(self.gw.run("echo 'привет, мир ✓'")["output"]), "привет, мир ✓")

    def test_two_sessions_run_side_by_side(self):
        slow = self.gw.call("run", server="host", command="sleep 5; echo slow", wait=0.5)
        fast = self.gw.call("run", server="host", command="echo fast")
        self.assertNotEqual(slow["session_id"], fast["session_id"])
        self.assertEqual(body(fast["output"]), "fast")
        self.assertEqual(slow["status"], "running")
        done = self.gw.call("read", session_id=slow["session_id"], wait=10)
        self.assertIn("slow", done["output"])

    def test_a_command_without_session_id_gets_a_fresh_shell_and_with_it_the_same_one(self):
        first = self.gw.call("run", server="host", command="cd /var && pwd")
        elsewhere = self.gw.call("run", server="host", command="pwd")
        again = self.gw.call("run", session_id=first["session_id"], command="pwd")
        self.assertEqual(body(first["output"]), "/var")
        self.assertNotEqual(elsewhere["session_id"], first["session_id"])
        self.assertNotEqual(body(elsewhere["output"]), "/var")
        self.assertEqual(body(again["output"]), "/var")

    def test_huge_output_neither_hangs_nor_grows_without_bound(self):
        started = time.time()
        res = self.gw.call("run", server="host", command="seq 1 300000", wait=30)
        self.assertEqual(res["status"], "completed")
        self.assertLess(time.time() - started, 30)
        tail = self.gw.call("read", session_id=res["session_id"], tail=2, wait=0)
        self.assertEqual(tail["output"].split(), ["299999", "300000"])

    def test_a_shell_started_inside_a_session_is_named_and_can_be_left(self):
        first = self.gw.call("run", server="host", command="bash", wait=3)
        self.assertEqual(first["status"], "running", first)
        self.assertIn("shell started inside this session", first["hint"])
        left = self.gw.call("signal", session_id=first["session_id"], action="stdin", text="exit", wait=5)
        self.assertEqual((left["status"], left["exit_code"]), ("completed", 0), left)
        again = self.gw.call("run", session_id=first["session_id"], command="echo back")
        self.assertEqual(body(again["output"]), "back")

    def test_a_progress_bar_that_rewrites_its_line_is_one_line(self):
        command = 'for i in 10 50 100; do printf "\\r$i%%"; sleep 0.2; done; echo'
        res = self.gw.call("run", server="host", command=command, wait=10)
        self.assertEqual(res["status"], "completed", res)
        self.assertEqual(body(res["output"]), "100%")

    def test_a_tool_that_pages_its_output_on_a_terminal_just_prints_it(self):
        repository = ("rm -rf /tmp/pager && git init -q /tmp/pager && cd /tmp/pager && "
                      "for i in $(seq 1 80); do git -c user.name=t -c user.email=t@t commit -q --allow-empty -m c$i; done")
        self.assertEqual(self.gw.run(repository)["exit_code"], 0)
        log = self.gw.call("run", server="host", command="cd /tmp/pager && git log --oneline", wait=8)
        self.assertEqual(log["status"], "completed", log)
        self.assertEqual(len(log["output"].splitlines()), 81)  # the command line and 80 commits

    def test_commands_see_a_terminal_of_sane_width(self):
        self.assertGreaterEqual(int(body(self.gw.run("tput cols 2>/dev/null || stty size | cut -d' ' -f2")["output"])), 120)

    def test_a_dead_shell_is_replaced_and_said_so(self):
        first = self.gw.run("echo one")
        self.gw.call("run", session_id=first["session_id"], command="exit", wait=3)
        again = self.gw.call("run", session_id=first["session_id"], command="echo two", wait=5)
        self.assertIn("two", again["output"])

    def test_the_server_list_shows_open_sessions(self):
        self.gw.run("true")
        row = self.gw.call("server_list")["servers"][0]
        self.assertEqual(row["server"], "host")
        self.assertEqual(row["sessions"][0]["session_id"], "host/1")


class SessionLimits(SshdTestCase):
    """sshd allows 10 sessions per connection (MaxSessions); the gateway's own default limit stays below that."""
    flavor = "debian"

    def test_a_shell_the_server_refuses_does_not_kill_the_shells_that_are_open(self):
        gw = Gateway(self.container, target_options={"max_sessions": 15})
        self.addCleanup(gw.close)
        first = gw.call("run", server="host", command="cd /tmp && pwd")
        for _ in range(9):
            self.assertEqual(gw.call("run", server="host", command="true")["status"], "completed")
        refused = gw.call_raw("run", server="host", command="true")
        self.assertTrue(refused["is_error"], refused)
        self.assertIn("refused another shell", refused["payload"]["error"])
        again = gw.call("run", session_id=first["session_id"], command="pwd")
        self.assertEqual(body(again["output"]), "/tmp")  # the state of the open shells survived

    def test_the_file_tool_still_gets_its_sftp_channel_when_the_gateway_has_opened_all_the_shells_it_allows(self):
        opened = 0
        while not self.gw.call_raw("run", server="host", command="true")["is_error"]:
            opened += 1
            self.assertLess(opened, 20, "the gateway never refused another shell")
        written = self.gw.call("file", server="host", action="write", path="/tmp/full.txt", content="ok\n")
        self.assertEqual(written.get("via"), "sftp", written)


class LoginShells(SshdTestCase):
    """Accounts whose login shell is not bash: what works as it is and what needs the 'shell' option."""
    flavor = "shells"

    def gateway(self, login, **target_options):
        gw = Gateway(self.container, user=f"user_{login}", target_options=target_options)
        self.addCleanup(gw.close)
        return gw

    def test_zsh_and_dash_logins_work_as_they_are(self):
        for login in ("zsh", "dash"):
            with self.subTest(login=login):
                result = self.gateway(login).run("echo hello; false")
                self.assertEqual(body(result["output"]), "hello")
                self.assertEqual(result["exit_code"], 1)

    def test_fish_and_tcsh_logins_are_refused_at_once_with_the_option_to_set(self):
        for login in ("fish", "tcsh"):
            with self.subTest(login=login):
                started = time.time()
                refused = self.gateway(login).call_raw("run", server="host", command="true")
                self.assertTrue(refused["is_error"], refused)
                self.assertIn('"shell": "bash"', refused["payload"]["error"])
                self.assertLess(time.time() - started, 10)

    def test_the_shell_option_makes_fish_and_tcsh_logins_work(self):
        for login in ("fish", "tcsh"):
            with self.subTest(login=login):
                gw = self.gateway(login, shell="bash")
                first = gw.run('[ -n "$BASH_VERSION" ] && echo bash; cd /tmp')
                self.assertEqual(body(first["output"]), "bash")
                self.assertEqual(body(gw.run("pwd", session_id=first["session_id"])["output"]), "/tmp")


class ReadOnlyGateway(SshdTestCase):
    flavor = "debian"

    def setUp(self):
        self.gw = Gateway(self.container, read_only=True)
        self.addCleanup(self.gw.close)

    def test_writing_commands_are_refused_and_reading_ones_work(self):
        refused = self.gw.call_raw("run", server="host", command="touch /tmp/nope")
        self.assertTrue(refused["is_error"])
        self.assertIn("read-only", refused["payload"]["error"])
        self.assertEqual(body(self.gw.run("echo ok")["output"]), "ok")

    def test_the_file_tool_cannot_write(self):
        refused = self.gw.call_raw("file", server="host", action="write", path="/tmp/x", content="x")
        self.assertTrue(refused["is_error"])


class HostKeyChecking(SshdTestCase):
    flavor = "debian"

    def setUp(self):
        self.gw = Gateway(self.container, verify_host=True)
        self.addCleanup(self.gw.close)
        self.known_hosts = self.gw.settings.known_hosts_path

    def test_first_contact_is_trusted_and_remembered(self):
        self.assertEqual(body(self.gw.run("echo hi")["output"]), "hi")
        with open(self.known_hosts, encoding="utf-8") as handle:
            self.assertIn("ssh-", handle.read())

    def test_a_changed_key_is_refused(self):
        self.gw.run("echo hi")
        with open(self.known_hosts, encoding="utf-8") as handle:
            host = handle.read().split(" ", 1)[0]
        other = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + other

        second = Gateway(self.container, verify_host=True)
        self.addCleanup(second.close)
        os.makedirs(os.path.dirname(second.settings.known_hosts_path), exist_ok=True)
        with open(second.settings.known_hosts_path, "w", encoding="utf-8") as handle:
            handle.write(f"{host} ssh-ed25519 {base64.b64encode(blob).decode()}\n")
        refused = second.call_raw("run", server="host", command="echo hi")
        self.assertTrue(refused["is_error"])
        self.assertIn("CHANGED", refused["payload"]["error"])


class NoSftpHost(FileScenarios, SshdTestCase):
    """The file tool through the shell: the same scenarios as with SFTP, plus what only this path does."""
    flavor = "nosftp"

    def test_file_tool_falls_back_to_the_shell(self):
        written = self.gw.call("file", server="host", action="write", path="/tmp/nf.txt", content="alpha\nbeta\n")
        self.assertEqual(written["via"], "shell", written)
        read = self.gw.call("file", server="host", action="read", path="/tmp/nf.txt")
        self.assertEqual((read["via"], read["content"]), ("shell", "alpha\nbeta\n"))
        edited = self.gw.call("file", server="host", action="edit", path="/tmp/nf.txt",
                              edits=[{"old_text": "beta", "new_text": "gamma"}])
        self.assertTrue(edited["changed"], edited)
        self.assertEqual(self.gw.run("cat /tmp/nf.txt")["output"].splitlines()[1:], ["alpha", "gamma"])

    def test_reading_a_file_that_is_not_there_says_why_it_failed(self):
        refused = self.gw.call_raw("file", server="host", action="read", path="/tmp/not-there.txt")
        self.assertTrue(refused["is_error"], refused)
        self.assertIn("no such file or not readable", refused["payload"]["error"])

    def test_large_and_binary_content_arrives_intact(self):
        payload = bytes(range(256)) * 60
        self.gw.call("file", server="host", action="write", path="/tmp/blob.bin",
                     content=base64.b64encode(payload).decode(), is_base64=True)
        digest = body(self.gw.run("sha256sum /tmp/blob.bin | cut -d' ' -f1")["output"])
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())

    def test_without_a_session_id_the_file_tool_leaves_no_shell_behind(self):
        self.gw.call("file", server="host", action="write", path="/tmp/tmp1.txt", content="x")
        self.assertNotIn("sessions", self.gw.call("server_list")["servers"][0])

    def test_a_shell_named_by_session_id_is_used_and_kept(self):
        session = self.gw.run("echo mine")["session_id"]
        self.gw.call("file", server="host", session_id=session, action="write", path="/tmp/tmp2.txt", content="x")
        kept = self.gw.call("server_list")["servers"][0]["sessions"]
        self.assertEqual([row["session_id"] for row in kept], [session])

    def test_the_file_tool_leaves_the_agents_console_alone(self):
        session = self.gw.run("echo mine")["session_id"]
        self.gw.call("file", server="host", session_id=session, action="write", path="/tmp/q.txt", content="q")
        unread = self.gw.call("read", session_id=session, wait=0)
        self.assertEqual(unread["output"], "")

    def test_paths_with_spaces_and_quotes(self):
        path = "/tmp/it's a dir/file name.txt"
        self.gw.call("file", server="host", action="write", path=path, content="ok\n")
        self.assertEqual(self.gw.call("file", server="host", action="read", path=path)["content"], "ok\n")
