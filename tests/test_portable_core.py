"""Portable configuration tests: temporary app state only, no network or subprocesses."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch


RUNTIME = Path(__file__).resolve().parents[1] / "runtime"


class PortableCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="win-workspace-portable-test-")))
        self.state = self.temp / "portable"
        self.legacy = self.temp / "legacy"
        self.legacy.mkdir()
        self.legacy_config = self.legacy / "config.json"
        self.legacy_config.write_text('{"workspace_enabled": true, "origin": "https://old.example.invalid"}', encoding="utf-8")
        self.original = self.legacy_config.read_bytes()
        saved = {"WINDOWS_WORKSPACE_MCP_STATE": str(self.state), "DOT_MCP_TOOLKIT_STATE": str(self.legacy)}
        self.enterContext(patch.dict(os.environ, saved))
        spec = importlib.util.spec_from_file_location("portable_core_under_test", RUNTIME / "core.py")
        self.core = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(RUNTIME))
        try:
            spec.loader.exec_module(self.core)
        finally:
            sys.path.remove(str(RUNTIME))
        self.origin = "https://workspace.example.invalid"
        self.callback = "https://client.example.invalid/oauth/callback"

    def test_import_does_not_create_state_or_inherit_legacy_settings(self):
        self.assertEqual(self.core.STATE, self.state)
        self.assertFalse(self.state.exists())
        cfg = self.core.load_config()
        for key in ("origin", "plugin_url", "workspace_root", "workspace_revision"):
            self.assertEqual(cfg[key], "")
        for key in ("workspace_enabled", "documents_enabled", "receive_enabled", "task_enabled"):
            self.assertFalse(cfg[key])
        self.assertFalse(self.core.uses_funnel(cfg))
        self.assertFalse(self.core.relay_ready(cfg))
        self.assertEqual(self.core.local_oauth_callbacks(cfg), [])
        self.assertFalse(self.state.exists())
        self.core.initialize_state()
        self.assertFalse(self.core.CONFIG.exists())
        self.assertFalse(self.core.FUNNEL.exists())
        self.assertEqual(self.legacy_config.read_bytes(), self.original)

    def test_existing_unclaimed_state_is_never_read_or_adopted(self):
        self.state.mkdir()
        config = self.state / "config.json"
        config.write_bytes(self.original)
        self.assertEqual(self.core.load_config()["origin"], "")
        with self.assertRaisesRegex(ValueError, "other installation|another installation"):
            self.core.initialize_state()
        with self.assertRaises(ValueError):
            self.core.update_config(origin=self.origin)
        self.assertEqual(config.read_bytes(), self.original)

    def test_local_endpoint_setup_is_explicit_and_idempotent(self):
        self.core.update_config(origin=self.origin)
        self.assertFalse(self.core.uses_funnel())
        self.assertFalse(self.core.relay_ready())
        with self.assertRaises(ValueError):
            self.core.worker_channel(self.core.load_config())
        with self.assertRaises(ValueError):
            self.core.configure_local_relay(self.origin)
        self.assertFalse(self.core.FUNNEL.exists())
        self.assertEqual(self.core.configure_local_relay(self.origin + "/mcp", [self.callback]), self.origin)
        cfg = self.core.load_config()
        self.assertFalse(cfg["workspace_enabled"])
        self.assertTrue(self.core.uses_funnel(cfg))
        self.assertTrue(self.core.relay_ready(cfg))
        self.assertEqual(self.core.local_oauth_callbacks(cfg), [self.callback])
        self.assertEqual(self.core.worker_channel(cfg), f"http://127.0.0.1:{self.core.FUNNEL_PRIVATE_PORT}")
        first = (self.core.worker_key(cfg), self.core.local_consent_code())
        self.assertTrue(first[0] != first[1])
        self.core.configure_local_relay(self.origin, [self.callback])
        self.assertTrue((self.core.worker_key(cfg), self.core.local_consent_code()) == first)
        with self.assertRaises(ValueError):
            self.core.configure_local_relay("https://changed.example.invalid", [self.callback])
        with self.assertRaises(ValueError):
            self.core.configure_local_relay(self.origin, ["https://second.example.invalid/other/callback"])
        self.assertEqual(self.core.load_config()["origin"], self.origin)
        self.assertFalse(self.core.uses_funnel({"origin": "https://changed.example.invalid"}))

    def test_clearing_and_restoring_origin_does_not_reactivate_grant(self):
        self.core.update_config(origin=self.origin)
        self.core.configure_local_relay(self.origin, [self.callback])
        self.core.update_config(workspace_enabled=True, workspace_unified=True, workspace_root=str(self.temp / "workspace"),
                                workspace_revision="synthetic", active_workspace_profile="synthetic")
        self.assertTrue(self.core.load_config()["task_enabled"])
        self.core.update_config(origin="")
        self.assertFalse(self.core.load_config()["workspace_enabled"])
        self.core.update_config(origin=self.origin)
        cfg = self.core.load_config()
        self.assertFalse(cfg["workspace_enabled"])
        self.assertFalse(cfg["task_enabled"])
        self.assertFalse(cfg["active_workspace_profile"])
        self.assertNotEqual(cfg["workspace_revision"], "synthetic")

    def test_callback_changes_are_rejected_and_binding_mismatch_disables_all_scopes(self):
        self.core.update_config(origin=self.origin)
        self.core.configure_local_relay(self.origin, [self.callback])
        self.core.update_config(workspace_enabled=True, workspace_unified=True, workspace_root=str(self.temp / "workspace"),
                                workspace_revision="synthetic")
        before = self.core.load_config()
        self.assertTrue(before["workspace_enabled"])
        changed = ["https://different.example.invalid/oauth/callback"]
        with self.assertRaises(ValueError):
            self.core.configure_local_relay(self.origin, changed)
        self.assertEqual(self.core.local_oauth_callbacks(), [self.callback])
        # A raw local edit is not an authorized settings transition. The saved binding no longer matches.
        self.core.save_json(self.core.FUNNEL_SETTINGS, {"origin": self.origin, "oauth_callbacks": changed})
        cfg = self.core.load_config()
        for name in ("workspace_enabled", "documents_enabled", "receive_enabled", "task_enabled"):
            self.assertFalse(cfg[name])
        self.assertFalse(self.core.uses_funnel(before))
        self.assertFalse(self.core.relay_ready(cfg))

    def test_worker_key_does_not_leave_private_loopback_path(self):
        off_host = Mock()
        local = MagicMock()
        local.open.return_value.__enter__.return_value.read.return_value = b'{"job": null}'
        with patch.object(self.core, "OPENER", off_host), patch.object(self.core, "LOCAL_OPENER", local):
            token = "1" * 64
            for url in (self.origin + "/worker", "http://127.0.0.1:1/worker",
                        f"http://127.0.0.1:{self.core.FUNNEL_PRIVATE_PORT}/mcp"):
                with self.assertRaisesRegex(ValueError, "private loopback"):
                    self.core.request_json(url, {}, key=token)
            endpoint = f"http://127.0.0.1:{self.core.FUNNEL_PRIVATE_PORT}/worker"
            self.assertEqual(self.core.request_json(endpoint, {}, key=token), {"job": None})
            req = local.open.call_args.args[0]
            self.assertEqual(req.get_header("Authorization"), "Bearer " + token)
            off_host.open.assert_not_called()

    def test_settings_support_blank_or_canonical_user_supplied_addresses(self):
        first = self.core.validated_config("", "", "2", "8")
        self.assertEqual((first["origin"], first["plugin_url"]), ("", ""))
        second = self.core.validated_config("https://WORKSPACE.example.invalid:443/mcp/",
                                           "https://mcp.example.invalid/help", 2, 8)
        self.assertEqual(second["origin"], self.origin)
        for origin in ("https://127.0.0.1", "https://foo..invalid", "https://example.invalid/?secret=1",
                       "https://user@workspace.example.invalid", "https://internal.local"):
            with self.assertRaises(ValueError):
                self.core.canonical_origin(origin)


if __name__ == "__main__":
    unittest.main()
