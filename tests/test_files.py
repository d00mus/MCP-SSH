"""The file tool: text handling, both backends and the local sandbox."""

import base64
import hashlib
import io
import os
import re
import tempfile
import unittest
from unittest import mock

from mcp_ssh_gateway import files
from mcp_ssh_gateway.config import ServerTargetConfig, Settings
from mcp_ssh_gateway.files import (
    FileError, FileService, LocalSandbox, apply_edits, filter_lines, window_lines,
)
from mcp_ssh_gateway.session import QuietResult


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeSftp:
    """In-memory stand-in for paramiko.SFTPClient."""

    def __init__(self, files=None, fail_write=False):
        self.files = dict(files or {})
        self.modes = {}
        self.links = {}
        self.dirs = {"/etc": ["b.conf", "a.conf"]}
        self.fail_write = fail_write
        self.closed = False

    def normalize(self, path):
        return self.links.get(path, path)

    class _Handle(io.BytesIO):
        def __init__(self, owner, path, writing):
            super().__init__(owner.files.get(path, b"") if not writing else b"")
            self._owner, self._path, self._writing = owner, path, writing

        def stat(self):
            return type("Attr", (), {"st_size": len(self._owner.files.get(self._path, b""))})()

        def close(self):
            if self._writing:
                self._owner.files[self._path] = self.getvalue()
            super().close()

    def file(self, path, mode="r"):
        if "w" in mode:
            if self.fail_write:
                raise OSError("disk full")
            return self._Handle(self, path, True)
        if path not in self.files:
            raise OSError("No such file")
        return self._Handle(self, path, False)

    def stat(self, path):
        if path not in self.files:
            raise OSError("No such file")
        return type("Attr", (), {"st_mode": self.modes.get(path, 0o100644)})()

    def chmod(self, path, mode):
        self.modes[path] = mode

    def posix_rename(self, source, target):
        self.files[target] = self.files.pop(source)
        if source in self.modes:
            self.modes[target] = self.modes.pop(source)

    def remove(self, path):
        self.files.pop(path, None)

    def listdir_attr(self, path):
        if path not in self.dirs:
            raise OSError("No such directory")
        return [type("E", (), {"filename": name, "__str__": lambda self: f"-rw-r--r-- {self.filename}"})()
                for name in self.dirs[path]]

    def close(self):
        self.closed = True


class FakeManager:
    def __init__(self, sftp=None, read_only=False, session=None):
        self.sftp = sftp
        self.read_only = read_only
        self.session = session
        self.closed_sessions = []

    def server_alias(self, server, session_id):
        return server or (session_id or "web/1").split("/")[0]

    def target(self, alias):
        return ServerTargetConfig(alias=alias, host="h", read_only=self.read_only)

    def connection(self, alias):
        import paramiko
        owner = self

        class Conn:
            def sftp(self):
                if owner.sftp is None:
                    raise paramiko.SSHException("Subsystem request failed")
                return owner.sftp
        return Conn()

    def session_for(self, **kwargs):
        self.session_args = kwargs
        return self.session

    def close_session(self, session_id, server=None):
        self.closed_sessions.append(session_id)
        return session_id


def make_settings(root, **extra):
    return Settings(project_root=root, cache_root=os.path.join(root, ".cache"), **extra)


class WindowAndFilterTests(unittest.TestCase):
    def test_window_reports_position_and_total(self):
        window = window_lines("a\nb\nc\nd\n", 2, 2)
        self.assertEqual((window["text"], window["start"], window["end"], window["total"]), ("b\nc\n", 2, 3, 4))

    def test_window_past_the_end_is_empty(self):
        window = window_lines("a\nb\n", 9, 5)
        self.assertEqual((window["text"], window["start"], window["end"]), ("", 0, 8))

    def test_the_tail_is_taken_from_the_lines_that_contain_the_text(self):
        text = "err 1\nok\nerr 2\nerr 30\nok\n"
        self.assertEqual(filter_lines(text, "err", 2), "err 2\nerr 30\n")

    def test_filter_without_matches_is_empty(self):
        self.assertEqual(filter_lines("a\nb\n", "zzz", None), "")


class ApplyEditsTests(unittest.TestCase):
    def test_single_unique_match_is_replaced(self):
        text, count = apply_edits("a=1\nb=2\n", [{"old_text": "b=2", "new_text": "b=3"}])
        self.assertEqual((text, count), ("a=1\nb=3\n", 1))

    def test_ambiguous_match_lists_the_places(self):
        with self.assertRaisesRegex(FileError, "matches 2 places") as caught:
            apply_edits("x\nfoo\nx\nfoo\n", [{"old_text": "foo", "new_text": "bar"}])
        self.assertIn("2: foo", str(caught.exception))

    def test_replace_all_counts_every_match(self):
        text, count = apply_edits("foo foo", [{"old_text": "foo", "new_text": "bar", "replace_all": True}])
        self.assertEqual((text, count), ("bar bar", 2))

    def test_missing_text_suggests_similar_lines(self):
        with self.assertRaisesRegex(FileError, "(?s)not found.*Similar lines"):
            apply_edits("listen 8080;\n", [{"old_text": "listen 8081;", "new_text": "x"}])

    def test_lf_edit_matches_a_crlf_file(self):
        text, _ = apply_edits("a\r\nb\r\n", [{"old_text": "a\nb", "new_text": "c"}])
        self.assertEqual(text, "c\r\n")

    def test_replacement_is_literal_not_a_regex_template(self):
        text, _ = apply_edits("x", [{"old_text": "x", "new_text": r"\1 \g<0>"}])
        self.assertEqual(text, r"\1 \g<0>")

    def test_empty_old_text_is_refused(self):
        with self.assertRaisesRegex(FileError, "old_text"):
            apply_edits("x", [{"old_text": "", "new_text": "y"}])

    def test_edits_apply_one_after_another(self):
        text, count = apply_edits("a", [{"old_text": "a", "new_text": "b"}, {"old_text": "b", "new_text": "c"}])
        self.assertEqual((text, count), ("c", 2))


class SftpServiceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = os.path.realpath(self._tmp.name)
        self.sftp = FakeSftp({"/etc/app.conf": b"port=1\nmode=a\n"})

    def service(self, **kwargs):
        manager = FakeManager(sftp=self.sftp, read_only=kwargs.pop("read_only", False))
        return FileService(manager, make_settings(self.root, **kwargs))

    def call(self, service, **args):
        args.setdefault("server", "web")
        return service.handle(args)

    def test_list_returns_sorted_text(self):
        result = self.call(self.service(), action="list", path="/etc")
        self.assertEqual(result["listing"].splitlines(), ["-rw-r--r-- a.conf", "-rw-r--r-- b.conf"])
        self.assertEqual((result["via"], result["server"]), ("sftp", "web"))
        self.assertTrue(self.sftp.closed)

    def test_a_long_listing_comes_in_pages_that_say_where_to_continue(self):
        self.sftp.dirs["/many"] = [f"f{number:03d}" for number in range(450)]
        first = self.call(self.service(), action="list", path="/many")
        self.assertEqual(len(first["listing"].splitlines()), 200)
        self.assertEqual((first["total_lines"], first["next_offset_line"]), (450, 201))
        last = self.call(self.service(), action="list", path="/many", offset_line=401)
        self.assertEqual(len(last["listing"].splitlines()), 50)
        self.assertNotIn("next_offset_line", last)

    def test_the_page_size_of_a_listing_is_lines(self):
        self.sftp.dirs["/many"] = [f"f{number:03d}" for number in range(30)]
        page = self.call(self.service(), action="list", path="/many", lines=10)
        self.assertEqual((len(page["listing"].splitlines()), page["next_offset_line"]), (10, 11))

    def test_list_of_a_missing_folder_is_a_file_error(self):
        with self.assertRaisesRegex(FileError, "Cannot list"):
            self.call(self.service(), action="list", path="/nope")

    def test_read_gives_window_and_position(self):
        result = self.call(self.service(), action="read", path="/etc/app.conf", lines=1)
        self.assertEqual((result["content"], result["line_start"], result["line_end"], result["total_lines"]),
                         ("port=1\n", 1, 1, 2))
        self.assertEqual(result["next_offset_line"], 2)

    def test_read_applies_filters(self):
        result = self.call(self.service(), action="read", path="/etc/app.conf", contains="mode")
        self.assertEqual(result["content"], "mode=a\n")

    def test_an_answer_over_the_character_cap_ends_at_a_line_and_says_where_to_go_on(self):
        self.sftp.files["/big"] = (("x" * 300 + "\n") * 3).encode()
        with mock.patch.object(files, "DEFAULT_READ_CHARS", 700):
            result = self.call(self.service(), action="read", path="/big")
        self.assertEqual(result["content"], ("x" * 300 + "\n") * 2)
        self.assertEqual((result["line_start"], result["line_end"], result["total_lines"]), (1, 2, 3))
        self.assertEqual(result["next_offset_line"], 3)
        self.assertIn("700 characters", result["note"])

    def test_a_single_line_over_the_cap_is_cut_and_the_next_line_is_offered(self):
        self.sftp.files["/big"] = ("x" * 300 + "\ny\n").encode()
        with mock.patch.object(files, "DEFAULT_READ_CHARS", 100):
            result = self.call(self.service(), action="read", path="/big")
        self.assertEqual(result["content"], "x" * 100)
        self.assertEqual(result["next_offset_line"], 2)
        self.assertIn("Line 1 is longer than 100 characters", result["note"])

    def test_read_reports_the_hash_that_edit_accepts_as_expected_sha256(self):
        read = self.call(self.service(), action="read", path="/etc/app.conf")
        self.assertEqual(read["sha256"], digest(b"port=1\nmode=a\n"))
        edited = self.call(self.service(), action="edit", path="/etc/app.conf", expected_sha256=read["sha256"],
                           edits=[{"old_text": "port=1", "new_text": "port=2"}])
        self.assertEqual(edited["replacements"], 1)

    def test_a_read_that_stopped_early_has_no_hash_of_the_whole_file(self):
        self.sftp.files["/big"] = b"x\n" * 2000
        with mock.patch.object(files, "DEFAULT_READ_BYTES", 1024):
            result = self.call(self.service(), action="read", path="/big")
        self.assertTrue(result["truncated"])
        self.assertNotIn("sha256", result)
        self.assertIn("run tool", result["note"])

    def test_tail_lines_of_a_big_file_are_the_end_of_the_file(self):
        self.sftp.files["/log"] = "".join(f"line {n}\n" for n in range(1, 1001)).encode()
        with mock.patch.object(files, "DEFAULT_READ_BYTES", 1024):
            result = self.call(self.service(), action="read", path="/log", tail_lines=3)
        self.assertEqual(result["content"], "line 998\nline 999\nline 1000\n")
        self.assertNotIn("truncated", result)

    def test_tail_lines_says_when_the_end_of_the_file_was_not_enough(self):
        self.sftp.files["/log"] = "".join(f"line {n}\n" for n in range(1, 1001)).encode()
        with mock.patch.object(files, "DEFAULT_READ_BYTES", 1024):
            result = self.call(self.service(), action="read", path="/log", tail_lines=500)
        self.assertTrue(result["truncated"])
        self.assertIn("last 1024 bytes", result["note"])
        self.assertTrue(result["content"].endswith("line 1000\n"))
        self.assertTrue(result["content"].startswith("line "))

    def test_read_of_binary_does_not_dump_bytes(self):
        self.sftp.files["/bin"] = b"\x00\x01\x02" * 10
        result = self.call(self.service(), action="read", path="/bin")
        self.assertTrue(result["binary"])
        self.assertNotIn("content", result)

    def test_read_of_a_missing_file_is_a_file_error(self):
        with self.assertRaisesRegex(FileError, "Cannot read"):
            self.call(self.service(), action="read", path="/missing")

    def test_write_creates_file_atomically_and_reports_hash(self):
        result = self.call(self.service(), action="write", path="/new.txt", content="hello")
        self.assertEqual(self.sftp.files["/new.txt"], b"hello")
        self.assertEqual(result["sha256"], digest(b"hello"))
        self.assertEqual([p for p in self.sftp.files if ".mcp_tmp" in p], [])

    def test_a_new_file_is_left_to_the_servers_umask(self):
        self.call(self.service(), action="write", path="/new.txt", content="hello")
        self.assertNotIn("/new.txt", self.sftp.modes)

    def test_write_keeps_the_mode_of_an_existing_file(self):
        self.sftp.modes["/etc/app.conf"] = 0o100640
        self.call(self.service(), action="write", path="/etc/app.conf", content="x")
        self.assertEqual(self.sftp.modes["/etc/app.conf"] & 0o7777, 0o640)

    def test_writing_through_a_symlink_changes_the_target_and_keeps_the_link(self):
        self.sftp.links["/etc/current.conf"] = "/etc/app.conf"
        self.call(self.service(), action="write", path="/etc/current.conf", content="port=9\n")
        self.assertEqual(self.sftp.files["/etc/app.conf"], b"port=9\n")
        self.assertNotIn("/etc/current.conf", self.sftp.files)

    def test_failed_write_leaves_no_temp_file(self):
        self.sftp.fail_write = True
        with self.assertRaisesRegex(FileError, "Cannot write"):
            self.call(self.service(), action="write", path="/etc/app.conf", content="x")
        self.assertEqual(list(self.sftp.files), ["/etc/app.conf"])

    def test_write_base64(self):
        self.call(self.service(), action="write", path="/b", content=base64.b64encode(b"\x00\xff").decode(), is_base64=True)
        self.assertEqual(self.sftp.files["/b"], b"\x00\xff")

    def test_write_needs_content_or_local_path(self):
        with self.assertRaisesRegex(FileError, "content"):
            self.call(self.service(), action="write", path="/x")

    def test_write_uploads_a_local_file(self):
        local = os.path.join(self.root, "up.txt")
        with open(local, "wb") as handle:
            handle.write(b"from local")
        self.call(self.service(), action="write", path="/up", local_path=local)
        self.assertEqual(self.sftp.files["/up"], b"from local")

    def test_read_downloads_to_a_local_file(self):
        local = os.path.join(self.root, "sub", "down.conf")
        result = self.call(self.service(), action="read", path="/etc/app.conf", local_path=local)
        with open(local, "rb") as handle:
            self.assertEqual(handle.read(), b"port=1\nmode=a\n")
        self.assertEqual(result["saved_to"], local)

    def test_a_download_is_not_limited_to_what_is_shown(self):
        self.sftp.files["/big.bin"] = b"x" * 1_500_000
        local = os.path.join(self.root, "big.bin")
        result = self.call(self.service(), action="read", path="/big.bin", local_path=local)
        self.assertEqual((result["size"], result["truncated"]), (1_500_000, False))
        self.assertEqual(os.path.getsize(local), 1_500_000)

    def test_edit_replaces_and_reports_both_hashes(self):
        original = self.sftp.files["/etc/app.conf"]
        result = self.call(self.service(), action="edit", path="/etc/app.conf",
                           edits=[{"old_text": "port=1", "new_text": "port=2"}])
        self.assertEqual(self.sftp.files["/etc/app.conf"], b"port=2\nmode=a\n")
        self.assertEqual((result["sha256_before"], result["replacements"]), (digest(original), 1))
        self.assertEqual(result["sha256_after"], digest(self.sftp.files["/etc/app.conf"]))

    def test_edit_dry_run_changes_nothing(self):
        result = self.call(self.service(), action="edit", path="/etc/app.conf", dry_run=True,
                           edits=[{"old_text": "port=1", "new_text": "port=2"}])
        self.assertTrue(result["dry_run"] and result["changed"])
        self.assertEqual(self.sftp.files["/etc/app.conf"], b"port=1\nmode=a\n")

    def test_edit_refuses_when_the_file_is_not_the_version_the_agent_read(self):
        with self.assertRaisesRegex(FileError, "not the version you read"):
            self.call(self.service(), action="edit", path="/etc/app.conf", expected_sha256="0" * 64,
                      edits=[{"old_text": "port=1", "new_text": "port=2"}])
        self.assertEqual(self.sftp.files["/etc/app.conf"], b"port=1\nmode=a\n")

    def test_stale_hash_is_reported_even_for_a_dry_run(self):
        with self.assertRaisesRegex(FileError, "not the version you read"):
            self.call(self.service(), action="edit", path="/etc/app.conf", expected_sha256="0" * 64, dry_run=True,
                      edits=[{"old_text": "port=1", "new_text": "port=2"}])

    def test_edit_with_expected_hash_of_current_version_succeeds(self):
        self.call(self.service(), action="edit", path="/etc/app.conf",
                  expected_sha256=digest(b"port=1\nmode=a\n"),
                  edits=[{"old_text": "mode=a", "new_text": "mode=b"}])
        self.assertIn(b"mode=b", self.sftp.files["/etc/app.conf"])

    def test_edit_of_binary_file_is_refused(self):
        self.sftp.files["/bin"] = b"\xff\xfe\x00"
        with self.assertRaisesRegex(FileError, "UTF-8"):
            self.call(self.service(), action="edit", path="/bin", edits=[{"old_text": "a", "new_text": "b"}])

    def test_edit_of_too_large_file_is_refused(self):
        self.sftp.files["/big"] = b"a" * 5000
        with mock.patch.object(files, "DEFAULT_EDIT_BYTES", 1024):
            with self.assertRaisesRegex(FileError, r"larger than 1024 bytes.*run tool"):
                self.call(self.service(), action="edit", path="/big", edits=[{"old_text": "a", "new_text": "b"}])

    def test_no_change_edit_does_not_write(self):
        result = self.call(self.service(), action="edit", path="/etc/app.conf",
                           edits=[{"old_text": "port=1", "new_text": "port=1"}])
        self.assertFalse(result["changed"])

    def test_read_only_server_refuses_write_and_edit(self):
        service = self.service(read_only=True)
        for action, extra in (("write", {"content": "x"}), ("edit", {"edits": [{"old_text": "a", "new_text": "b"}]})):
            with self.assertRaisesRegex(FileError, "read-only"):
                self.call(service, action=action, path="/etc/app.conf", **extra)
        self.assertEqual(self.call(service, action="read", path="/etc/app.conf")["total_lines"], 2)

    def test_unknown_action_and_missing_path(self):
        with self.assertRaisesRegex(FileError, "action"):
            self.call(self.service(), action="delete", path="/x")
        with self.assertRaisesRegex(FileError, "path"):
            self.call(self.service(), action="read", path=" ")


class ScriptedSession:
    """A session double that keeps a dict-based 'remote file system' and understands the file commands."""

    sid = "web/7"

    def __init__(self, files=None, fail_on=None):
        self.files = dict(files or {})
        self.links = {}
        self.modes = {}      # existing files: path -> octal mode, as `stat` reports it
        self.chmods = {}     # modes that writes applied: path -> octal mode
        self.commands = []
        self.staging = {}
        self.fail_on = fail_on

    def run_quiet(self, command, timeout=30.0):
        self.commands.append(command)
        if self.fail_on and self.fail_on in command:
            return QuietResult(output="boom", exit_code=1)
        if match := re.match(r"readlink -f -- (\S+) ", command):
            return QuietResult(output=self.links.get(match.group(1), match.group(1)) + "\r\n", exit_code=0)
        if match := re.match(r"stat -c %a (\S+) ", command):
            mode = self.modes.get(match.group(1))
            return QuietResult(output=(mode or "") + "\r\n", exit_code=0 if mode else 1)
        if match := re.match(r"test -f '?([^' ]+)'? && test -r .* && (head|tail) -c (\d+) ", command):
            data = self.files.get(match.group(1))
            if data is None:
                return QuietResult(output="", exit_code=1)
            count = int(match.group(3))
            encoded = base64.b64encode(data[:count] if match.group(2) == "head" else data[-count:]).decode()
            return QuietResult(output="\r\n".join(encoded[i:i + 76] for i in range(0, len(encoded), 76)) + "\r\n", exit_code=0)
        if match := re.match(r"printf %s (\S+) >> '?(\S+?)'?$", command):
            self.staging[match.group(2)] = self.staging.get(match.group(2), "") + match.group(1)
        if ": > " in command:
            self.staging[command.split(": > ")[1].strip("'")] = ""
        if match := re.match(r"base64 -d '?(\S+?)'? > '?(\S+?)'? && (?:chmod (\S+) '?\S+'? && )?mv -f '?\S+'? '?(\S+?)'?$", command):
            self.files[match.group(4)] = base64.b64decode(self.staging[match.group(1)])
            if match.group(3):
                self.chmods[match.group(4)] = match.group(3)
        if command.startswith("ls "):
            return QuietResult(output="total 0\n-rw-r--r-- 1 root root 0 a.conf\n", exit_code=0)
        return QuietResult(output="", exit_code=0)


class ShellFallbackTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.session = ScriptedSession({"/etc/app.conf": b"port=1\nmode=a\n"})
        self.manager = FakeManager(sftp=None, session=self.session)
        self.service = FileService(self.manager, make_settings(os.path.realpath(self._tmp.name)))

    def call(self, **args):
        return self.service.handle({"server": "web", **args})

    def test_without_sftp_a_linux_shell_is_used(self):
        result = self.call(action="read", path="/etc/app.conf")
        self.assertEqual(result["via"], "shell")
        self.assertEqual(result["content"], "port=1\nmode=a\n")
        self.assertIs(self.manager.session_args["shell"], True)

    def test_without_a_session_id_the_shell_is_temporary(self):
        self.call(action="read", path="/etc/app.conf")
        self.assertEqual(self.manager.closed_sessions, ["web/7"])

    def test_a_failed_operation_closes_the_temporary_shell_too(self):
        with self.assertRaises(FileError):
            self.call(action="read", path="/nope")
        self.assertEqual(self.manager.closed_sessions, ["web/7"])

    def test_a_shell_named_by_session_id_stays_open(self):
        self.call(action="read", path="/etc/app.conf", session_id="web/7")
        self.assertEqual(self.manager.closed_sessions, [])

    def test_tail_lines_through_the_shell_reads_the_end_of_the_file(self):
        self.session.files["/log"] = "".join(f"line {n}\n" for n in range(1, 1001)).encode()
        with mock.patch.object(files, "DEFAULT_READ_BYTES", 1024):
            result = self.call(action="read", path="/log", tail_lines=3)
        self.assertEqual(result["content"], "line 998\nline 999\nline 1000\n")
        self.assertIn("tail -c", self.session.commands[-1])

    def test_list_uses_ls(self):
        self.assertIn("a.conf", self.call(action="list", path="/etc")["listing"])

    def test_read_of_missing_file_names_the_problem(self):
        with self.assertRaisesRegex(FileError, "Reading /nope failed"):
            self.call(action="read", path="/nope")

    def test_paths_with_spaces_and_quotes_are_quoted(self):
        self.call(action="list", path="/tmp/it's a dir")
        self.assertIn("'/tmp/it'\"'\"'s a dir'", self.session.commands[-1])

    def test_large_write_is_sent_in_short_lines_and_arrives_intact(self):
        payload = os.urandom(6000)
        self.call(action="write", path="/data.bin", content=base64.b64encode(payload).decode(), is_base64=True)
        self.assertEqual(self.session.files["/data.bin"], payload)
        self.assertLessEqual(max(len(c) for c in self.session.commands), 3200)

    def test_writing_through_a_symlink_changes_the_target_and_keeps_the_link(self):
        self.session.links["/etc/current.conf"] = "/etc/app.conf"
        self.call(action="write", path="/etc/current.conf", content="port=9\n")
        self.assertEqual(self.session.files["/etc/app.conf"], b"port=9\n")
        self.assertNotIn("/etc/current.conf", self.session.files)

    def test_the_shell_write_keeps_the_mode_of_an_existing_file_and_leaves_a_new_one_to_the_umask(self):
        self.session.modes["/etc/app.conf"] = "640"
        self.call(action="write", path="/etc/app.conf", content="x")
        self.call(action="write", path="/etc/new.conf", content="x")
        self.assertEqual(self.session.chmods, {"/etc/app.conf": "640"})

    def test_write_cleans_up_staging_files_even_when_it_fails(self):
        self.session.fail_on = "base64 -d"
        with self.assertRaisesRegex(FileError, "Writing /x failed"):
            self.call(action="write", path="/x", content="data")
        self.assertTrue(self.session.commands[-1].startswith("rm -f"))

    def test_edit_works_through_the_shell(self):
        self.call(action="edit", path="/etc/app.conf", edits=[{"old_text": "port=1", "new_text": "port=9"}])
        self.assertEqual(self.session.files["/etc/app.conf"], b"port=9\nmode=a\n")


class SandboxTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = os.path.realpath(self._tmp.name)
        self.sandbox = LocalSandbox(make_settings(self.root))

    def test_project_files_are_allowed(self):
        path = os.path.join(self.root, "a", "b.txt")
        self.assertEqual(self.sandbox.resolve(path, for_write=True), os.path.realpath(path))

    def test_outside_paths_are_refused(self):
        with self.assertRaisesRegex(FileError, "outside the allowed"):
            self.sandbox.resolve(os.path.join(os.path.dirname(self.root), "elsewhere.txt"), for_write=False)

    def test_dot_dot_escape_is_refused(self):
        with self.assertRaisesRegex(FileError, "outside the allowed"):
            self.sandbox.resolve(os.path.join(self.root, "..", "x"), for_write=False)

    def test_keys_git_and_servers_json_are_protected(self):
        for name in ("id_ed25519", "servers.json", "putty.ppk", os.path.join(".git", "config")):
            with self.assertRaisesRegex(FileError, "protected"):
                self.sandbox.resolve(os.path.join(self.root, name), for_write=False)

    def test_the_configured_servers_file_is_protected_under_any_name(self):
        servers = os.path.join(self.root, "my-hosts.json")
        sandbox = LocalSandbox(make_settings(self.root, servers_path=servers))
        with self.assertRaisesRegex(FileError, "protected"):
            sandbox.resolve(servers, for_write=False)

    def test_without_a_project_root_local_files_are_off(self):
        sandbox = LocalSandbox(Settings(project_root=None, cache_root=os.path.join(self.root, ".cache")))
        for path in (os.path.join(self.root, "a.txt"), os.path.join(self.root, ".cache", "known_hosts")):
            with self.subTest(path=path), self.assertRaisesRegex(FileError, "--project-root"):
                sandbox.resolve(path, for_write=False)

    def test_the_system_temp_flag_alone_opens_the_temp_folder_and_nothing_else(self):
        outside = os.path.join(tempfile.gettempdir(), "mcp-sandbox-probe.txt")
        sandbox = LocalSandbox(Settings(project_root=None, cache_root=os.path.join(self.root, ".cache"),
                                        allow_system_temp=True))
        self.assertEqual(sandbox.resolve(outside, for_write=True), os.path.realpath(outside))
        with self.assertRaisesRegex(FileError, "outside the allowed"):
            sandbox.resolve(os.path.join(os.path.dirname(tempfile.gettempdir()), "elsewhere.txt"), for_write=False)

    def test_system_temp_needs_the_flag(self):
        outside = os.path.join(tempfile.gettempdir(), "mcp-sandbox-probe.txt")
        settings = make_settings(self.root)
        # the temp dir may contain the project root itself on some hosts; only assert when it does not
        if not LocalSandbox._within(outside, self.root):
            with self.assertRaises(FileError):
                LocalSandbox(settings).resolve(outside, for_write=True)
            settings.allow_system_temp = True
            self.assertEqual(LocalSandbox(settings).resolve(outside, for_write=True), os.path.realpath(outside))


if __name__ == "__main__":
    unittest.main()
