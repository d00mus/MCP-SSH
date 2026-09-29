"""servers.json entries: environment references and defaults."""

import contextlib
import io
import os
import unittest
from unittest import mock

from mcp_ssh_gateway.config import ServerTargetConfig


def target(**fields):
    return ServerTargetConfig.from_dict("web", {"host": "10.0.0.1", "user": "root", **fields})


class TestEnvironmentReferences(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"GW_HOST": "10.9.8.7", "GW_PASS": "s3cret", "GW_KEY": "id_ed25519"})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("GW_MISSING", None)

    def test_a_braced_reference_in_a_field_is_replaced_by_the_variable(self):
        config = target(host="${GW_HOST}", password="${GW_PASS}", key_path="~/.ssh/${GW_KEY}")
        self.assertEqual(config.host, "10.9.8.7")
        self.assertEqual(config.password, "s3cret")
        self.assertEqual(config.key_path, os.path.expanduser("~/.ssh/id_ed25519"))

    def test_a_password_is_kept_as_written_apart_from_braced_references(self):
        os.environ["HOME"] = "/root"
        for password in ("pa$HOME/x", "abc$1", "a$", "$$", "100%GW_KEY%", "pa$GW_PASS"):
            with self.subTest(password=password):
                self.assertEqual(target(password=password).password, password)
        self.assertEqual(target(password="pre${GW_PASS}$HOME").password, "pres3cret$HOME")

    def test_the_passphrase_follows_the_same_rule_as_the_password(self):
        self.assertEqual(target(key_passphrase="x$GW_PASS${GW_PASS}").key_passphrase, "x$GW_PASSs3cret")

    def test_an_unset_variable_in_a_secret_is_an_error_that_names_it(self):
        with self.assertRaisesRegex(ValueError, "GW_MISSING"):
            target(password="${GW_MISSING}")

    def test_an_unset_variable_in_a_plain_field_stays_and_is_reported(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            config = target(host="${GW_MISSING}")
        self.assertEqual(config.host, "${GW_MISSING}")
        self.assertIn("GW_MISSING", stderr.getvalue())


class TestLoginShellOption(unittest.TestCase):
    def test_the_shell_to_switch_to_is_kept_as_written_because_it_is_meant_for_the_host(self):
        self.assertIsNone(target().shell)
        self.assertEqual(target(shell="~/bin/bash").shell, "~/bin/bash")
        self.assertEqual(target(shell="  bash ").shell, "bash")

    def test_the_shell_is_one_line(self):
        with self.assertRaisesRegex(ValueError, "one line"):
            target(shell="bash\nrm -rf /")


class TestDefaults(unittest.TestCase):
    def test_a_server_needs_only_a_host_and_gets_the_usual_defaults(self):
        config = ServerTargetConfig.from_dict("web", {"host": "10.0.0.1"})
        self.assertEqual((config.port, config.verify_host, config.read_only, config.max_sessions),
                         (22, True, False, 8))


if __name__ == "__main__":
    unittest.main()
