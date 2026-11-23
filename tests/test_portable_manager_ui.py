"""Synthetic local manager onboarding checks, without Tk display or connections."""
from pathlib import Path
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


class Input:
    def __init__(self, value=""):
        self.value = value
        self.state = "normal"

    def get(self, *_args):
        return self.value

    def set(self, value):
        self.value = value

    def delete(self, *_args):
        self.set("")

    def insert(self, _index, value):
        self.set(value)

    def configure(self, *, state):
        self.state = state


class PortableManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime)
        cls.addClassCleanup(sys.path.remove, runtime)
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"WINDOWS_WORKSPACE_MCP_STATE": str(Path(tmp) / "uninitialized")}):
                stubbed = os.name != "nt" and "msvcrt" not in sys.modules
                if stubbed:
                    sys.modules["msvcrt"] = types.ModuleType("msvcrt")
                try:
                    import manager
                finally:
                    if stubbed:
                        del sys.modules["msvcrt"]
        cls.app = manager

    def setUp(self):
        d = self.ui = self.app.Dashboard.__new__(self.app.Dashboard)
        for field in ("origin", "plugin", "mode", "msg", "connection_summary", "remote_mcp_url", "consent_button",
                      "autostart_toggle", "callback_editor", "auto"):
            setattr(d, field, Input())
        d.poll, d.timeout = Input("2"), Input("8")
        d.task_cache, d.bound_callbacks = None, None
        d.root, d.books, d.settings_tab, d.job = Mock(), Mock(), object(), Mock()
        self.cfg = {"origin": "", "workspace_enabled": False}
        self.ready = False
        self.callbacks = []
        self.allowlist = ["https://client.example.invalid/oauth/callback"]
        self.origin = "https://helper.example.invalid"
        self.confirm = self.enterContext(patch.object(self.app.messagebox, "askyesno", return_value=False))
        self.error = self.enterContext(patch.object(self.app.messagebox, "showerror"))
        self.enterContext(patch.multiple(self.app.core, load_config=lambda: dict(self.cfg),
                                         relay_ready=lambda *_: self.ready, current_status=lambda: {"running": False},
                                         local_oauth_callbacks=lambda *_: self.callbacks, create=True))
        self.prepare = self.enterContext(patch.object(self.app.core, "configure_local_relay"))

    def test_blank_first_run_never_starts_or_queries_network(self):
        self.ui.refresh_connection(self.cfg)
        self.ui.connect()
        self.ui.check()
        self.ui.restart_connection()
        self.ui.job.assert_not_called()
        self.prepare.assert_not_called()
        self.assertEqual(self.ui.remote_mcp_url.get(), "")
        self.assertEqual(self.ui.consent_button.state, "disabled")

    def test_prepare_rejects_empty_or_invalid_callbacks_before_confirm(self):
        self.cfg["origin"] = self.origin
        self.ui.origin.set(self.origin)
        self.ui.prepare_relay()
        self.ui.callback_editor.set("*")
        self.ui.prepare_relay()
        self.assertEqual(self.error.call_count, 2)
        self.confirm.assert_not_called()
        self.prepare.assert_not_called()

    def test_prepare_requires_local_confirmation_and_no_start(self):
        self.cfg["origin"] = self.origin
        self.ui.origin.set(self.origin)
        self.ui.callback_editor.set("\n" + self.allowlist[0] + "\n")
        self.ui.prepare_relay()
        self.assertEqual(self.confirm.call_args.kwargs["default"], "no")
        self.prepare.assert_not_called()

        def become_ready(_origin, callbacks):
            self.callbacks = callbacks
            self.ready = True

        self.prepare.side_effect = become_ready
        self.confirm.return_value = True
        self.ui.prepare_relay()
        self.error.assert_not_called()
        self.prepare.assert_called_once_with(self.origin, self.allowlist)
        self.ui.job.assert_not_called()
        self.assertEqual(self.ui.callback_editor.state, "disabled")
        self.assertEqual(self.ui.callback_editor.value, self.allowlist[0])

    def test_url_copy_excludes_any_secret(self):
        self.cfg["origin"] = self.origin
        with patch.object(self.app.core, "local_consent_code") as reveal:
            self.ui.refresh_connection(self.cfg)
            self.ui.copy_mcp_url()
        self.ui.root.clipboard_append.assert_called_once_with(self.origin + "/mcp")
        reveal.assert_not_called()

    def test_changing_endpoint_never_preserves_active_grant(self):
        self.cfg.update(origin=self.origin, workspace_enabled=True)
        self.ui.origin.set("https://replacement.example.invalid")
        with patch.object(self.app.core, "update_config") as update:
            self.ui.save()
        update.assert_not_called()
        self.error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
