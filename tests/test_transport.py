"""Connection set-up: host key policy, error messages, channel opening."""

import base64
import os
import socket
import tempfile
import unittest
from unittest import mock

import paramiko

from mcp_ssh_gateway.config import ServerTargetConfig
from mcp_ssh_gateway.transport import AcceptNewHostKeys, Connection, ConnectionFailed, describe_connect_error


# A real ed25519 blob with its first byte changed: what a half-written or hand-edited file looks like.
_GOOD_KEY = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + bytes(range(0x80, 0xa0))).decode()
DAMAGED_KEY = "B" + _GOOD_KEY[1:]


def target(**kwargs):
    return ServerTargetConfig(alias="web", host="10.0.0.1", user="root", password="pw", **kwargs)


class DescribeErrorTests(unittest.TestCase):
    def describe(self, exc):
        return describe_connect_error(exc, "10.0.0.1", 22)

    def test_bad_host_key_says_it_changed(self):
        key = paramiko.RSAKey.generate(1024)
        self.assertIn("CHANGED", self.describe(paramiko.BadHostKeyException("h", key, key)))

    def test_authentication_failure_points_at_the_credentials(self):
        self.assertIn("authentication failed", self.describe(paramiko.AuthenticationException("bad")))

    def test_unreachable_refused_and_unresolvable_are_told_apart(self):
        self.assertIn("timed out", self.describe(TimeoutError("timed out")))
        self.assertIn("refused", self.describe(ConnectionRefusedError("Connection refused")))
        self.assertIn("does not resolve", self.describe(socket.gaierror("Name or service not known")))

    def test_unknown_errors_still_carry_the_detail(self):
        self.assertIn("weird", self.describe(RuntimeError("weird")))


class HostKeyPolicyTests(unittest.TestCase):
    def test_first_contact_is_remembered_in_the_known_hosts_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "known_hosts")
            client = paramiko.SSHClient()
            key = paramiko.RSAKey.generate(1024)
            AcceptNewHostKeys(path).missing_host_key(client, "10.0.0.1", key)
            reloaded = paramiko.HostKeys(path)
            self.assertEqual(reloaded.lookup("10.0.0.1")["ssh-rsa"], key)

    def test_an_unwritable_file_does_not_break_the_connection(self):
        client = paramiko.SSHClient()
        key = paramiko.RSAKey.generate(1024)
        with mock.patch("os.makedirs", side_effect=OSError("read-only")):
            AcceptNewHostKeys("/nonexistent/known_hosts").missing_host_key(client, "h", key)
        self.assertIsNotNone(client.get_host_keys().lookup("h"))


class ConnectTests(unittest.TestCase):
    def test_a_damaged_known_hosts_file_is_reported_not_crashed_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "known_hosts")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f"10.0.0.1 ssh-ed25519 {DAMAGED_KEY}\n")
            with mock.patch("paramiko.SSHClient.connect", side_effect=ConnectionRefusedError("x")):
                with self.assertRaisesRegex(ConnectionFailed, "known_hosts"):
                    Connection(target(), path).open_channel()

    def test_connect_failures_become_actionable_messages(self):
        with mock.patch("paramiko.SSHClient.connect", side_effect=ConnectionRefusedError("Connection refused")):
            with self.assertRaisesRegex(ConnectionFailed, "refused the connection"):
                Connection(target()).open_channel()

    def test_explicit_credentials_disable_agent_and_key_search(self):
        with mock.patch("paramiko.SSHClient.connect", side_effect=ConnectionRefusedError("x")) as connect:
            with self.assertRaises(ConnectionFailed):
                Connection(target()).open_channel()
        self.assertFalse(connect.call_args.kwargs["allow_agent"])
        self.assertFalse(connect.call_args.kwargs["look_for_keys"])

    def test_without_credentials_the_agent_and_default_keys_are_tried(self):
        bare = ServerTargetConfig(alias="web", host="h", user="u")
        with mock.patch("paramiko.SSHClient.connect", side_effect=ConnectionRefusedError("x")) as connect:
            with self.assertRaises(ConnectionFailed):
                Connection(bare).open_channel()
        self.assertTrue(connect.call_args.kwargs["allow_agent"])

    def test_verify_host_false_accepts_unknown_keys(self):
        seen = {}

        def capture(self, policy):
            seen["policy"] = policy

        with mock.patch("paramiko.SSHClient.set_missing_host_key_policy", capture), \
                mock.patch("paramiko.SSHClient.connect", side_effect=ConnectionRefusedError("x")):
            with self.assertRaises(ConnectionFailed):
                Connection(target(verify_host=False)).open_channel()
        self.assertIsInstance(seen["policy"], paramiko.AutoAddPolicy)

    def test_a_channel_that_cannot_be_opened_drops_the_connection(self):
        connection = Connection(target())
        transport = mock.Mock()
        transport.is_active.return_value = True
        transport.open_session.side_effect = paramiko.SSHException("channel refused")
        client = mock.Mock()
        client.get_transport.return_value = transport
        connection._client = client
        with self.assertRaisesRegex(ConnectionFailed, "Could not open a shell"):
            connection.open_channel()
        client.close.assert_called_once()
        self.assertFalse(connection.is_active())

    def test_a_channel_the_server_refuses_keeps_the_connection_and_its_other_shells(self):
        connection = Connection(target())
        transport = mock.Mock()
        transport.is_active.return_value = True
        transport.open_session.side_effect = paramiko.ChannelException(2, "Connect failed")
        client = mock.Mock()
        client.get_transport.return_value = transport
        connection._client = client
        with self.assertRaisesRegex(ConnectionFailed, "refused another shell.*MaxSessions"):
            connection.open_channel()
        client.close.assert_not_called()
        self.assertTrue(connection.is_active())

    def test_a_dead_connection_is_reconnected_on_next_use(self):
        connection = Connection(target())
        with mock.patch.object(Connection, "_connect", side_effect=ConnectionFailed("down")) as connect:
            with self.assertRaises(ConnectionFailed):
                connection.open_channel()
            with self.assertRaises(ConnectionFailed):
                connection.sftp()
        self.assertEqual(connect.call_count, 2)


if __name__ == "__main__":
    unittest.main()
