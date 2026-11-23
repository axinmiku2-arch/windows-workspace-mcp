"""Offline tests of durable file approvals using synthetic temporary workspaces."""
from contextlib import nullcontext
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


class SimulatedWorkerStop(BaseException):
    pass


class DurableApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime)
        cls.addClassCleanup(sys.path.remove, runtime)
        with tempfile.TemporaryDirectory(prefix="dot-upgrade-module-") as temp:
            with patch.dict(os.environ, {"WINDOWS_WORKSPACE_MCP_STATE": temp}):
                import core
                # These tests never use the Windows-only relay/file lock implementation.
                stubbed = os.name != "nt" and "msvcrt" not in sys.modules
                if stubbed:
                    sys.modules["msvcrt"] = types.ModuleType("msvcrt")
                try:
                    import workspace
                    import unified_workspace
                finally:
                    if stubbed:
                        del sys.modules["msvcrt"]
        cls.core, cls.ws, cls.profiles = core, workspace, unified_workspace

    def setUp(self):
        temp = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="dot-upgrade-approvals-")))
        self.state, self.root, self.other = temp / "state", temp / "root", temp / "other"
        for folder in (self.state, self.root, self.other):
            folder.mkdir()
        relay = self.state / "relay"
        self.enterContext(patch.multiple(self.core, STATE=self.state, CONFIG=self.state / "config.json",
                                          FUNNEL=relay, FUNNEL_SETTINGS=relay/"endpoint.json"))
        self.enterContext(patch.multiple(self.ws, PENDING=self.state / "pending.json", AUDIT=self.state / "audit.json",
                                        APPROVAL_JOURNAL=self.state / "journal.json", DECISIONS=self.state / "decisions",
                                        BACKUPS=self.state / "backups"))
        self.enterContext(patch.object(self.ws, "clear_expired"))
        local_root = lambda path: Path(path).resolve(strict=True)
        self.enterContext(patch.object(self.ws, "workspace_root", side_effect=local_root))
        self.enterContext(patch.object(self.profiles, "workspace_root", side_effect=local_root))
        self.enterContext(patch.object(self.profiles, "guarded_inbox", side_effect=lambda _: nullcontext()))
        self.origin = "https://synthetic.invalid"
        self.core.configure_local_relay(self.origin, ["https://client.example.invalid/oauth/redirect"])
        self.core.update_config(origin=self.origin)
        self.profiles.grant(str(self.root), "ask")

    def submit(self, gate, path="fixture.txt"):
        return gate.handle({"operation": "workspace_create", "payload": {"relative_path": path, "content": "synthetic"}})

    def lookup(self, gate, request):
        return gate.handle({"operation": "workspace_approval", "payload": {"request_id": request["request_id"]}})

    def decide(self, request, decision):
        self.core.save_json(self.ws.DECISIONS / (request["request_id"] + ".json"), {"decision": decision})

    def test_waiting_deadline_decision_and_receipt_survive_restarts(self):
        first = self.ws.WorkspaceGate()
        with patch.object(self.ws.time, "time", return_value=10_000):
            request = self.submit(first)
            self.assertEqual(request["expires_at"], 11_800)
            shown = self.core.read_json(self.ws.PENDING)["items"][0]
            self.assertNotIn("payload", shown)
            self.assertNotIn("policy", shown)
        self.profiles.grant(str(self.root), "ask", approval_minutes=50)
        with patch.object(self.ws.time, "time", return_value=11_700):
            restarted = self.ws.WorkspaceGate()
            self.assertEqual(self.lookup(restarted, request)["state"], "approval_pending")
            self.assertEqual(restarted.queue[request["request_id"]]["expires"], 11_800)
            self.decide(request, "allow")
            after_decision = self.ws.WorkspaceGate()
            self.assertEqual(self.lookup(after_decision, request)["state"], "executed")
            self.assertEqual((self.root / "fixture.txt").read_text(), "synthetic")
        with patch.object(self.ws.time, "time", return_value=20_000):
            reopened = self.ws.WorkspaceGate()
            self.assertEqual(self.lookup(reopened, request)["state"], "executed")
            self.assertEqual(self.core.read_json(self.ws.PENDING)["items"], [])

    def test_expiry_and_denial_survive_restart_without_file_effect(self):
        self.profiles.grant(str(self.root), "ask", approval_minutes=5)
        first = self.ws.WorkspaceGate()
        with patch.object(self.ws.time, "time", return_value=1000):
            expiring = self.submit(first, "expire.txt")
            denied = self.submit(first, "deny.txt")
            self.decide(denied, "deny")
            self.decide(expiring, "allow")
        with patch.object(self.ws.time, "time", return_value=1100):
            # Consume only the explicit denial while the other request remains waiting.
            (self.ws.DECISIONS / (expiring["request_id"] + ".json")).unlink()
            restarted = self.ws.WorkspaceGate()
            self.assertEqual(self.lookup(restarted, denied)["state"], "denied")
            self.decide(expiring, "allow")
        with patch.object(self.ws.time, "time", return_value=1300):
            restarted = self.ws.WorkspaceGate()
            self.assertEqual(self.lookup(restarted, expiring)["state"], "expired_or_revoked")
            self.assertEqual(self.lookup(restarted, denied)["state"], "denied")
        self.assertFalse((self.root / "expire.txt").exists())
        self.assertFalse((self.root / "deny.txt").exists())

    def test_crash_after_side_effect_is_reported_and_never_reexecuted(self):
        gate = self.ws.WorkspaceGate()
        request = self.submit(gate)
        self.decide(request, "allow")
        original = gate.execute

        def before_receipt(*args):
            original(*args)
            raise SimulatedWorkerStop

        with patch.object(gate, "execute", side_effect=before_receipt):
            with self.assertRaises(SimulatedWorkerStop):
                gate.pump()
        saved = self.core.read_json(self.ws.APPROVAL_JOURNAL)
        self.assertEqual(saved["queue"][request["request_id"]]["phase"], "executing")
        with patch.object(self.ws.WorkspaceGate, "execute", side_effect=AssertionError("must not rerun")):
            restarted = self.ws.WorkspaceGate()
            self.assertEqual(self.lookup(restarted, request)["state"], "interrupted_unknown")
        self.assertEqual((self.root / "fixture.txt").read_text(), "synthetic")

    def test_invalid_journal_fails_closed(self):
        self.ws.APPROVAL_JOURNAL.write_text("{invalid", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "journal"):
            self.ws.WorkspaceGate()
        self.assertEqual(self.ws.APPROVAL_JOURNAL.read_text(), "{invalid")

    def test_write_is_not_started_without_durable_start_fence(self):
        gate = self.ws.WorkspaceGate()
        request = self.submit(gate)
        self.decide(request, "allow")
        actual = self.ws.save_json

        def fail_to_store_start(path, value, **kwargs):
            if path == self.ws.APPROVAL_JOURNAL and any(row["phase"] == "executing" for row in value["queue"].values()):
                raise OSError("simulated write failure")
            return actual(path, value, **kwargs)

        with patch.object(self.ws, "save_json", side_effect=fail_to_store_start):
            with self.assertRaisesRegex(OSError, "simulated"):
                gate.pump()
        self.assertFalse((self.root / "fixture.txt").exists())
        restarted = self.ws.WorkspaceGate()
        self.assertEqual(self.lookup(restarted, request)["state"], "executed")

    def test_legacy_link_not_saved_in_persisted_receipt(self):
        (self.root / "fixture.txt").write_text("synthetic", encoding="utf-8")
        gate = self.ws.WorkspaceGate()
        request = gate.handle({"operation": "workspace_export_file",
                               "payload": {"relative_path": "fixture.txt"}})
        self.decide(request, "allow")
        synthetic_url = "https://unusable.invalid/synthetic-download"
        with patch.object(gate, "execute", return_value={"bytes": 9, "download_url": synthetic_url}):
            result = self.lookup(gate, request)
        self.assertEqual(result["result"]["download_url"], synthetic_url)
        self.assertNotIn(synthetic_url, self.ws.APPROVAL_JOURNAL.read_text())
        reopened = self.lookup(self.ws.WorkspaceGate(), request)
        self.assertEqual(reopened["state"], "executed")
        self.assertNotIn("download_url", reopened["result"])
        self.assertEqual(reopened["result"]["bytes"], 9)

    def test_profiles_are_inactive_until_selected_and_switch_retires_old_requests(self):
        first_profile = self.profiles.list_profiles()[0]
        original_revision = self.core.load_config()["workspace_revision"]
        secondary = self.profiles.save_profile(str(self.other), "rules", approval_minutes=45)
        self.assertFalse(secondary["active"])
        self.assertFalse((self.other / self.core.INBOX_FOLDER).exists())
        self.assertEqual(self.core.load_config()["workspace_root"], str(self.root))
        self.assertEqual(self.profiles.grant(str(self.root), "ask")["workspace_revision"], original_revision)

        gate = self.ws.WorkspaceGate()
        old_request = self.submit(gate)
        self.decide(old_request, "allow")
        active = self.profiles.activate_profile(secondary["profile_id"])
        self.assertEqual(active["workspace_root"], str(self.other))
        self.assertEqual(active["approval_minutes"], 45)
        self.assertNotEqual(active["workspace_revision"], original_revision)
        self.assertEqual(sum(row["active"] for row in self.profiles.list_profiles()), 1)
        restarted = self.ws.WorkspaceGate()
        self.assertEqual(self.lookup(restarted, old_request)["state"], "unknown_or_expired")
        self.assertFalse((self.root / "fixture.txt").exists())
        self.assertFalse((self.other / "fixture.txt").exists())
        self.profiles.activate_profile(first_profile["profile_id"])
        self.assertEqual(self.lookup(restarted, old_request)["state"], "unknown_or_expired")
        self.profiles.revoke()
        self.assertFalse(any(row["active"] for row in self.profiles.list_profiles()))
        self.assertEqual(len(self.profiles.list_profiles()), 2)
        self.profiles.remove_profile(secondary["profile_id"])
        self.assertEqual(len(self.profiles.list_profiles()), 1)

    def test_full_only_explicit_recoverable_actions_opt_in(self):
        gate = self.ws.WorkspaceGate()
        first = self.profiles.grant(str(self.root), "full")
        for op in self.ws.OPTIONAL_FULL_AUTOMATIC:
            self.assertFalse(gate.automatic(first, op, self.root, {}))
        second = self.profiles.grant(str(self.root), "full", automatic_operations=["workspace_move"])
        self.assertNotEqual(first["workspace_revision"], second["workspace_revision"])
        self.assertTrue(gate.automatic(second, "workspace_move", self.root, {}))
        self.assertFalse(gate.automatic(second, "workspace_trash", self.root, {}))
        self.assertFalse(gate.automatic({**second, "approval_mode": "rules"}, "workspace_move", self.root, {}))
        self.assertFalse(gate.automatic({**second, "workspace_unified": False}, "workspace_move", self.root, {}))
        with self.assertRaises(ValueError):
            self.profiles.grant(str(self.root), "full", automatic_operations=["project_start"])
        with self.assertRaises(ValueError):
            self.profiles.grant(str(self.root), "full", approval_minutes=121)


if __name__ == "__main__":
    unittest.main()
