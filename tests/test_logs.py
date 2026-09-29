"""Run and session logs: one file per session, one per run, secrets masked, bounded."""

import json
import os
import tempfile
import time
import unittest

from mcp_ssh_gateway.logs import LogStore, mask_secrets


def read_events(path):
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


MASKED = [
    # names that only contain a secret word, not just the bare word
    ("export TOKEN=abc123", "export TOKEN=******"),
    ("GITHUB_TOKEN=ghp_abc123 git push", "GITHUB_TOKEN=****** git push"),
    ("DB_PASSWORD=hunter2 ./run.sh", "DB_PASSWORD=****** ./run.sh"),
    ("PGPASSWORD=hunter2 psql -h db", "PGPASSWORD=****** psql -h db"),
    ("export AWS_SECRET_ACCESS_KEY=abc/def+ghi==", "export AWS_SECRET_ACCESS_KEY=******"),
    # other spellings of an assignment
    ("password: hunter2", "password: ******"),
    ("password='two words' ./run.sh", "password='******' ./run.sh"),
    ("curl -d '{\"password\":\"hunter2\"}' https://x", "curl -d '{\"password\":\"******\"}' https://x"),
    ("curl 'https://x/api?token=abc123&page=2'", "curl 'https://x/api?token=******&page=2'"),
    # flags
    ("tool --password hunter2 --x", "tool --password ****** --x"),
    ("tool --password=hunter2", "tool --password=******"),
    ("tool --api-key abc123", "tool --api-key ******"),
    ("wget --http-password=hunter2 https://x", "wget --http-password=****** https://x"),
    # HTTP credentials
    ("curl -H 'Authorization: Bearer abc.def.ghi' https://x", "curl -H 'Authorization: Bearer ******' https://x"),
    ('curl -H "Authorization: Basic dXNlcjpwYXNz" https://x', 'curl -H "Authorization: Basic ******" https://x'),
    ("curl -H 'X-API-Key: abc123' https://x", "curl -H 'X-API-Key: ******' https://x"),
    ("curl -u admin:s3cret https://x", "curl -u ****** https://x"),
    ("curl -s --user 'admin:s3cret' https://x", "curl -s --user '******' https://x"),
    # addresses with a login
    ("git clone https://user:s3cret@host/repo.git", "git clone https://user:******@host/repo.git"),
    ("git clone https://ghp_abc123@github.com/o/r.git", "git clone https://******@github.com/o/r.git"),
    ("psql postgresql://app:s3cret@db:5432/x", "psql postgresql://app:******@db:5432/x"),
    # clients that take the password as an option
    ("sshpass -p s3cret ssh host", "sshpass -p ****** ssh host"),
    ("sshpass -p 's3 cret' ssh host", "sshpass -p '******' ssh host"),
    ("mysql -u root -ps3cret db", "mysql -u root -p****** db"),
    ("mysqldump -uroot -ps3cret db > x.sql", "mysqldump -uroot -p****** db > x.sql"),
]

UNTOUCHED = [
    "ls -la /var/log",
    "cat /etc/passwd",
    "grep -r 'password' /etc",
    "echo tokenizer",
    "mkdir -p /srv/app",
    "ssh -p 2222 host",
    "mysql -u root -p db",  # a bare -p makes the client ask for the password
    "git clone git@github.com:o/r.git",
    "git clone ssh://git@host/repo.git",  # a login name, not a secret
    "tool --token --verbose",  # the flag has no value: the next flag is not one
    "curl -A x --user-agent y https://x",  # --user-agent is not --user
    "docker run -u 1000:1000 img",  # only curl's -u carries a password
]


class TestMaskSecrets(unittest.TestCase):
    def test_secrets_in_commands_are_hidden(self):
        for command, expected in MASKED:
            with self.subTest(command=command):
                self.assertEqual(mask_secrets(command), expected)

    def test_commands_without_secrets_are_untouched(self):
        for command in UNTOUCHED:
            with self.subTest(command=command):
                self.assertEqual(mask_secrets(command), command)

    def test_masking_twice_changes_nothing(self):
        for command, _ in MASKED:
            with self.subTest(command=command):
                once = mask_secrets(command)
                self.assertEqual(mask_secrets(once), once)

    def test_a_pathological_line_does_not_take_forever(self):
        started = time.time()
        for line in ("password" * 500, "-" + "token" * 800, "a" * 4000, "mysql " + "-x " * 1300, "curl " * 800):
            mask_secrets(line)
        self.assertLess(time.time() - started, 1.0)


class TestLogStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def store(self, policy="meta", **kwargs):
        return LogStore(self.tmp.name, policy=policy, **kwargs)

    def test_sessions_and_runs_go_to_separate_directories(self):
        store = self.store()
        session_log = store.session_log("web", 1)
        run_log = store.run_log("web", 1, 7)
        session_log.event("connected")
        run_log.event("started", command="uptime")
        self.assertEqual(os.path.dirname(session_log.path), os.path.join(self.tmp.name, "sessions"))
        self.assertEqual(os.path.dirname(run_log.path), os.path.join(self.tmp.name, "runs"))
        self.assertIn("web__s1", os.path.basename(session_log.path))
        self.assertIn("web__s1__r7", os.path.basename(run_log.path))

    def test_events_are_json_lines_with_time_and_fields(self):
        log = self.store().run_log("web", 1, 1)
        log.event("started", command="uptime")
        log.event("finished", exit_code=0)
        events = read_events(log.path)
        self.assertEqual([e["event"] for e in events], ["started", "finished"])
        self.assertEqual(events[1]["exit_code"], 0)
        self.assertIn("ts", events[0])

    def test_commands_are_masked_before_they_hit_the_disk(self):
        log = self.store().run_log("web", 1, 1)
        log.event("started", command="deploy --token abcdef")
        with open(log.path, encoding="utf-8") as handle:
            self.assertNotIn("abcdef", handle.read())

    def test_output_is_written_only_when_the_policy_is_full(self):
        meta = self.store("meta").run_log("web", 1, 1)
        meta.output("hello")
        self.assertFalse(os.path.exists(meta.path))
        full = self.store("full").run_log("web", 1, 2)
        full.output("hello")
        self.assertEqual(read_events(full.path)[0]["text"], "hello")

    def test_policy_off_writes_nothing(self):
        log = self.store("off").session_log("web", 1)
        log.event("connected")
        self.assertFalse(os.path.exists(log.path))

    def test_a_full_file_stops_taking_output_but_keeps_taking_events(self):
        log = self.store("full", max_file_bytes=200).run_log("web", 1, 1)
        for _ in range(20):
            log.output("x" * 50)
        size = os.path.getsize(log.path)
        log.event("finished")
        self.assertGreater(os.path.getsize(log.path), size)
        self.assertLess(size, 600)

    def test_unusual_aliases_make_safe_file_names(self):
        log = self.store().session_log("../evil name", 1)
        self.assertEqual(os.path.dirname(log.path), os.path.join(self.tmp.name, "sessions"))


class TestPrune(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = LogStore(self.tmp.name, policy="meta")

    def make(self, kind, name, size, age_seconds):
        directory = os.path.join(self.tmp.name, kind)
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name)
        with open(path, "w") as handle:
            handle.write("x" * size)
        stamp = time.time() - age_seconds
        os.utime(path, (stamp, stamp))
        return path

    def test_files_older_than_the_retention_are_removed(self):
        old = self.make("runs", "old.log", 10, 10 * 86400)
        fresh = self.make("runs", "fresh.log", 10, 60)
        removed = self.store.prune(max_age_seconds=7 * 86400, max_total_bytes=10_000)
        self.assertEqual(removed, 1)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(fresh))

    def test_the_byte_budget_drops_the_oldest_first_across_both_directories(self):
        oldest = self.make("runs", "a.log", 100, 300)
        middle = self.make("sessions", "b.log", 100, 200)
        newest = self.make("runs", "c.log", 100, 100)
        self.store.prune(max_age_seconds=86400, max_total_bytes=200)
        self.assertFalse(os.path.exists(oldest))
        self.assertTrue(os.path.exists(middle))
        self.assertTrue(os.path.exists(newest))

    def test_foreign_files_are_left_alone(self):
        keep = self.make("runs", "notes.txt", 10, 30 * 86400)
        self.store.prune(max_age_seconds=1, max_total_bytes=1)
        self.assertTrue(os.path.exists(keep))


if __name__ == "__main__":
    unittest.main()
