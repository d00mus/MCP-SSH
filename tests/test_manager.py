"""Server and session bookkeeping: which session a request lands on, limits, hot reload."""

import json
import os
import tempfile
import unittest
from unittest import mock

from mcp_ssh_gateway.config import ServerTargetConfig, ServersRegistry, Settings
from mcp_ssh_gateway.manager import PRUNE_CHECK_SECONDS, MultiServerManager, UsageError
from tests.fakes import FakeConnection, FakeNdmShell, FakePosixShell
from tests.test_session import echo_script, ndm_script


def servers_json(**servers):
    return {"servers": {alias: {"host": f"{alias}.example", "user": "u", **extra}
                        for alias, extra in servers.items()}}


class ManagerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "servers.json")
        self.connections = {}

    def write(self, document):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)

    def manager(self, document, **settings):
        self.write(document)
        registry = ServersRegistry()
        registry.load_file(self.path)
        options = dict(project_root=self.tmp.name, cache_root=os.path.join(self.tmp.name, "cache"),
                       servers_path=self.path)
        options.update(settings)

        def factory(target, known_hosts):
            kind = FakeNdmShell if target.alias.startswith("router") else FakePosixShell
            make = (lambda: FakeNdmShell(ndm_script, linux_script=echo_script)) if kind is FakeNdmShell \
                else (lambda: FakePosixShell(echo_script))
            connection = FakeConnection(make)
            connection.target = target
            self.connections[target.alias] = connection
            return connection

        manager = MultiServerManager(Settings(**options), registry, connection_factory=factory)
        self.addCleanup(manager.close_all)
        return manager


class TestResolving(ManagerTestCase):
    def test_a_request_without_session_id_always_opens_a_new_shell(self):
        manager = self.manager(servers_json(web={}))
        first = manager.session_for()
        second = manager.session_for()
        self.assertEqual((first.sid, second.sid), ("web/1", "web/2"))
        self.assertIsNot(first, second)
        self.assertEqual(len(self.connections["web"].channels), 2)

    def test_a_session_id_continues_that_shell_and_opens_nothing(self):
        manager = self.manager(servers_json(web={}))
        first = manager.session_for()
        manager.session_for()
        self.assertIs(manager.session_for(session_id=first.sid), first)
        self.assertEqual(len(self.connections["web"].channels), 2)

    def test_a_session_id_finds_its_session_with_or_without_the_server(self):
        manager = self.manager(servers_json(web={}, db={}))
        session = manager.session_for(server="web")
        self.assertIs(manager.session_for(session_id="web/1"), session)
        self.assertIs(manager.session_for(server="web", session_id="1"), session)
        self.assertIs(manager.existing_session("web/1"), session)

    def test_with_several_servers_the_server_must_be_named(self):
        manager = self.manager(servers_json(web={}, db={}))
        with self.assertRaisesRegex(UsageError, "'server' is required.*web, db"):
            manager.session_for()

    def test_an_unknown_server_lists_the_configured_ones(self):
        manager = self.manager(servers_json(web={}, db={}))
        with self.assertRaisesRegex(UsageError, "Unknown server 'nope'.*web, db"):
            manager.session_for(server="nope")

    def test_a_session_that_does_not_exist_lists_the_open_ones(self):
        manager = self.manager(servers_json(web={}))
        manager.session_for()
        with self.assertRaisesRegex(UsageError, r"web/7 does not exist.*web/1"):
            manager.existing_session("web/7")

    def test_conflicting_server_and_session_id_are_refused(self):
        manager = self.manager(servers_json(web={}, db={}))
        manager.session_for(server="web")
        with self.assertRaisesRegex(UsageError, "belongs to"):
            manager.session_for(server="db", session_id="web/1")

    def test_a_malformed_session_id_explains_the_format(self):
        manager = self.manager(servers_json(web={}))
        with self.assertRaisesRegex(UsageError, "looks like 'web/1'"):
            manager.session_for(session_id="abc")

    def test_a_session_number_without_its_server_explains_the_format(self):
        manager = self.manager(servers_json(web={}, db={}))
        manager.session_for(server="web")
        with self.assertRaisesRegex(UsageError, "Bad session_id '1'.*looks like 'web/1'"):
            manager.existing_session("1")

    def test_a_server_allows_eight_shells_by_default_so_that_sftp_fits_under_the_sshd_limit_of_ten(self):
        manager = self.manager(servers_json(web={}))
        for _ in range(8):
            manager.session_for()
        with self.assertRaisesRegex(UsageError, "limit is 8"):
            manager.session_for()

    def test_the_session_limit_names_the_open_shells_to_continue_in_or_to_close(self):
        manager = self.manager(servers_json(web={"max_sessions": 2}))
        manager.session_for()
        manager.session_for().run("sleep 100", wait=0.1)
        with self.assertRaisesRegex(
                UsageError, r"limit is 2.*web/1 idle.*web/2 busy: sleep 100.*session_id.*session_close"):
            manager.session_for()

    def test_closing_frees_the_slot_and_the_id_is_not_reused(self):
        manager = self.manager(servers_json(web={"max_sessions": 1}))
        first = manager.session_for()
        self.assertEqual(manager.close_session("web/1"), "web/1")
        self.assertTrue(first.closed)
        self.assertEqual(manager.session_for().sid, "web/2")


class TestModes(ManagerTestCase):
    def test_a_router_opens_its_cli_unless_the_linux_shell_is_asked_for(self):
        manager = self.manager(servers_json(router={}))
        cli = manager.session_for()
        linux = manager.session_for(shell=True)
        self.assertEqual((cli.mode, linux.mode), ("cli", "shell"))
        self.assertEqual(manager.session_for(shell=False).mode, "cli")

    def test_a_session_id_keeps_its_kind_of_shell(self):
        manager = self.manager(servers_json(router={}))
        cli = manager.session_for()
        linux = manager.session_for(shell=True)
        self.assertIs(manager.session_for(session_id=linux.sid, shell=True), linux)
        self.assertIs(manager.session_for(session_id=cli.sid, shell=False), cli)

    def test_naming_a_session_of_the_wrong_mode_explains_what_to_do(self):
        manager = self.manager(servers_json(router={}))
        manager.session_for()
        with self.assertRaisesRegex(UsageError, "router CLI session.*Leave out session_id"):
            manager.session_for(session_id="router/1", shell=True)


class TestPolicy(ManagerTestCase):
    def test_gateway_wide_guardrails_are_added_to_every_server(self):
        manager = self.manager(servers_json(web={"command_blacklist": ["reboot"]}),
                               read_only=True, command_blacklist=["shutdown"])
        session = manager.session_for()
        self.assertTrue(session.target.read_only)
        self.assertEqual(session.target.command_blacklist, ["reboot", "shutdown"])


class TestListing(ManagerTestCase):
    def test_servers_are_listed_with_their_open_sessions(self):
        manager = self.manager(servers_json(web={"description": "front"}, db={}))
        manager.session_for(server="web")
        rows = {row["server"]: row for row in manager.list_servers()}
        self.assertEqual(rows["web"]["description"], "front")
        self.assertEqual(rows["web"]["sessions"][0]["session_id"], "web/1")
        self.assertNotIn("sessions", rows["db"])


class TestHotReload(ManagerTestCase):
    def test_an_added_server_appears_and_a_removed_one_disappears_with_its_sessions(self):
        manager = self.manager(servers_json(web={}, db={}))
        db = manager.session_for(server="db")
        self.write(servers_json(web={}, cache={}))
        self.assertTrue(manager.reload_if_changed(force=True))
        self.assertEqual(sorted(manager.registry.aliases()), ["cache", "web"])
        self.assertTrue(db.closed)

    def test_a_changed_address_closes_the_sessions_of_that_server_only(self):
        manager = self.manager(servers_json(web={}, db={}))
        web = manager.session_for(server="web")
        db = manager.session_for(server="db")
        document = servers_json(web={}, db={})
        document["servers"]["web"]["host"] = "elsewhere.example"
        self.write(document)
        manager.reload_if_changed(force=True)
        self.assertTrue(web.closed)
        self.assertFalse(db.closed)

    def test_a_policy_change_reaches_open_sessions_without_reconnecting(self):
        manager = self.manager(servers_json(web={}))
        session = manager.session_for()
        self.write(servers_json(web={"read_only": True}))
        manager.reload_if_changed(force=True)
        self.assertFalse(session.closed)
        self.assertTrue(session.target.read_only)

    def test_an_unchanged_file_is_not_reapplied(self):
        manager = self.manager(servers_json(web={}))
        self.assertFalse(manager.reload_if_changed(force=True))

    def test_a_broken_file_keeps_the_current_servers(self):
        manager = self.manager(servers_json(web={}))
        with open(self.path, "w") as handle:
            handle.write("{ not json")
        self.assertFalse(manager.reload_if_changed(force=True))
        self.assertEqual(manager.registry.aliases(), ["web"])

    def test_hosts_imported_from_ssh_config_survive_a_reload(self):
        manager = self.manager(servers_json(web={}))
        manager.registry.register(ServerTargetConfig(alias="laptop", host="l", imported=True))
        self.write(servers_json(web={}, db={}))
        manager.reload_if_changed(force=True)
        self.assertIn("laptop", manager.registry.aliases())


class TestHousekeeping(ManagerTestCase):
    def test_old_logs_are_pruned_again_while_the_gateway_keeps_running(self):
        manager = self.manager(servers_json(web={}))
        with mock.patch.object(manager._logs, "prune") as prune:
            manager.session_for()
            prune.assert_not_called()  # it just ran at the start
            manager._last_prune -= PRUNE_CHECK_SECONDS + 1  # an hour has passed
            manager.session_for()
            manager.session_for()
        self.assertEqual(prune.call_count, 1)

    def test_it_does_not_depend_on_a_servers_file_that_can_be_reloaded(self):
        manager = self.manager(servers_json(web={}), servers_path=None)
        with mock.patch.object(manager._logs, "prune") as prune:
            manager._last_prune -= PRUNE_CHECK_SECONDS + 1
            manager.session_for()
        prune.assert_called_once_with()


class TestAddServer(ManagerTestCase):
    def test_a_new_server_is_registered_and_saved(self):
        manager = self.manager(servers_json(web={}))
        manager.add_server("db", {"host": "db.example", "user": "root"})
        self.assertIsNotNone(manager.registry.get("db"))
        with open(self.path, encoding="utf-8") as handle:
            self.assertIn("db", json.load(handle)["servers"])
        self.assertFalse(manager.reload_if_changed(force=True))  # our own write is not a "change"

    def test_duplicates_and_missing_hosts_are_refused(self):
        manager = self.manager(servers_json(web={}))
        with self.assertRaisesRegex(UsageError, "already exists"):
            manager.add_server("web", {"host": "x"})
        with self.assertRaisesRegex(UsageError, "'host' is required"):
            manager.add_server("db", {"user": "u"})


class TestCancel(ManagerTestCase):
    def test_a_cancelled_request_interrupts_the_command_it_started(self):
        manager = self.manager(servers_json(web={}))
        session = manager.session_for()
        session.run("sleep 100", wait=0.1)
        manager.track("req-1", session)
        self.assertTrue(manager.cancel("req-1"))
        self.assertEqual(session.read(wait=3)["status"], "interrupted")

    def test_cancelling_an_unknown_or_finished_request_does_nothing(self):
        manager = self.manager(servers_json(web={}))
        self.assertFalse(manager.cancel("nope"))
        session = manager.session_for()
        manager.track("done", session)
        self.assertFalse(manager.cancel("done"))


if __name__ == "__main__":
    unittest.main()
