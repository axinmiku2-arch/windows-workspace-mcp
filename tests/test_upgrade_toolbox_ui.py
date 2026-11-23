"""Exercise the fixed toolbox with synthetic widgets and an inert shutdown backend."""
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
import shutdown_timer
import upgrade_ui as ui
import diagnostic_ui as routine_ui


class Widget:
    buttons = {}

    def __init__(self, parent=None, **options):
        self.options, self.value = options, ""
        if "command" in options and "text" in options:
            self.buttons[options["text"]] = self

    def __getattr__(self, _key):
        return lambda *_args, **_kw: None

    def configure(self, **options):
        self.options.update(options)

    def set(self, value):
        self.value = value
        variable = self.options.get("textvariable")
        if variable is not None:
            variable.set(value)

    def get(self, *_args):
        return self.value

    def insert(self, _index, value):
        self.value = value

    def invoke(self):
        if self.options.get("state") != "disabled":
            return self.options["command"]()

    def winfo_exists(self):
        return True


class String:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class ToolboxTests(unittest.TestCase):
    def setUp(self):
        Widget.buttons = {}
        self.enterContext(patch.multiple(ui.tk, Toplevel=Widget, Text=Widget, StringVar=String))
        self.enterContext(patch.multiple(ui.ttk, Frame=Widget, Label=Widget, Scrollbar=Widget, Button=Widget,
                                         Combobox=Widget, Spinbox=Widget))
        self.confirm = self.enterContext(patch.object(ui.messagebox, "askyesno", return_value=False))
        self.error = self.enterContext(patch.object(ui.messagebox, "showerror"))
        self.cfg = {"workspace_enabled": True, "task_enabled": True, "workspace_unified": True, "approval_mode": "full"}
        self.submit = Mock()
        self.backend = SimpleNamespace(ping_hosts=Mock(return_value=["example.invalid"]),
                                       save_ping_hosts=Mock(return_value=["second.invalid"]))
        self.presets = {"windows_ipconfig", "windows_listening_ports", "windows_ping"}

    def dialog(self, presets=None, backend=None):
        return ui.ToolboxDialog(Widget(), self.presets if presets is None else presets,
                                {"workspace_move"}, self.cfg, self.backend if backend is None else backend, self.submit)

    def test_fixed_actions_submit_but_never_execute(self):
        dialog = self.dialog()
        Widget.buttons["申请网络配置"].invoke()
        self.submit.assert_called_once_with("windows_ipconfig", None)
        self.submit.reset_mock()
        dialog.ping_choice.set("unknown.invalid")
        Widget.buttons["申请 Ping"].invoke()
        self.submit.assert_not_called()
        dialog.ping_choice.set("example.invalid")
        Widget.buttons["申请 Ping"].invoke()
        self.submit.assert_called_once_with("windows_ping", {"host": "example.invalid"})

    def test_saving_allowlist_is_local_and_updates_fixed_picker(self):
        dialog = self.dialog()
        dialog.editor.value = "  second.invalid  \n\n"
        Widget.buttons["保存 Ping 白名单"].invoke()
        self.backend.save_ping_hosts.assert_called_once_with(["second.invalid"])
        self.assertEqual(dialog.ping_choice.options["values"], ("second.invalid",))
        self.submit.assert_not_called()

    def test_stale_allowlist_does_not_overwrite(self):
        dialog = self.dialog()
        self.backend.ping_hosts.return_value = ["changed.invalid"]
        dialog.save()
        self.backend.save_ping_hosts.assert_not_called()
        self.error.assert_called_once()

    def test_missing_preset_uses_no_backend_and_shows_no_control(self):
        dialog = self.dialog(presets={"windows_listening_ports"})
        self.assertIsNone(dialog.ping_choice)
        self.assertEqual(dialog.editor.options["state"], "disabled")
        self.backend.ping_hosts.assert_not_called()
        self.assertNotIn("申请网络配置", Widget.buttons)
        self.assertIn("申请本机监听端口", Widget.buttons)

    def test_full_mode_does_not_change_diagnostic_approval(self):
        cfg = dict(self.cfg, automatic_operations=["workspace_move"])
        approvals = [row[-1] for row in ui.toolbox_rows(self.presets, {"workspace_move"}, cfg)]
        self.assertEqual(approvals, ["逐次本机批准"] * 3 + ["按本机配置自动批准"])

    def test_shutdown_defaults_to_no_and_root_close_cancels(self):
        self.now = 10
        os_shutdown = Mock()
        local = SimpleNamespace(**{name: getattr(shutdown_timer, name) for name in ("MIN_MINUTES", "MAX_MINUTES")},
                                LocalShutdownTimer=lambda: shutdown_timer.LocalShutdownTimer(clock=lambda: self.now),
                                request_local_shutdown=os_shutdown)
        root, dialog = Widget(), Widget()
        power = ui.LocalPower(root, local)
        power.schedule("2", dialog)
        self.confirm.assert_called_once()
        self.assertEqual(self.confirm.call_args.kwargs["default"], "no")
        self.assertIsNone(power.timer.seconds_remaining())
        self.confirm.return_value = True
        power.schedule("2", dialog)
        self.assertEqual(power.timer.seconds_remaining(), 120)
        power.on_close(SimpleNamespace(widget=dialog))
        self.assertEqual(power.timer.seconds_remaining(), 120)
        power.on_close(SimpleNamespace(widget=root))
        self.now = 131
        power.tick()
        self.assertIsNone(power.timer.seconds_remaining())
        os_shutdown.assert_not_called()


class RoutineDialogTests(unittest.TestCase):
    def setUp(self):
        Widget.buttons = {}
        self.enterContext(patch.multiple(ui.tk, Toplevel=Widget, StringVar=String))
        self.enterContext(patch.multiple(ui.ttk, Frame=Widget, Label=Widget, Entry=Widget, Button=Widget,
                                         Combobox=Widget, Spinbox=Widget))
        self.confirm = self.enterContext(patch.object(ui.messagebox, "askyesno", return_value=False))
        self.error = self.enterContext(patch.object(ui.messagebox, "showerror"))
        self.cfg = {"workspace_enabled": True, "task_enabled": True, "workspace_unified": True,
                    "workspace_revision": "fake-scope", "approval_mode": "rules", "workspace_root": "D:/sample"}
        self.rows = []
        self.connection_id = "a" * 24
        self.routine_id = "b" * 24
        self.routine_preset = "routine:" + self.routine_id
        self.routines = SimpleNamespace(listing=Mock(side_effect=lambda _cfg: self.rows), register=Mock(), revoke=Mock())
        toolbox = SimpleNamespace(ping_hosts=lambda _cfg: ["203.0.113.50", "example.invalid"])
        self.dialog = routine_ui.RoutineDialog(Widget(), lambda: dict(self.cfg), self.routines, toolbox)
        self.dialog.connection.set(self.connection_id)

    def row(self, *, active, current=True):
        return {"active": active, "current_scope": current, "request_preset": self.routine_preset,
                "preset": "windows_ping", "routine_id": self.routine_id, "remaining": 3,
                "expires_at": time.time() + 100, "connection_id": self.connection_id,
                "host": "203.0.113.50", "workspace_root": "D:/sample", "revoked": False}

    def test_default_no_then_fixed_scoped_registration(self):
        self.dialog.register()
        self.assertEqual(self.confirm.call_args.kwargs["default"], "no")
        self.routines.register.assert_not_called()
        self.confirm.return_value = True
        self.dialog.register()
        self.routines.register.assert_called_once_with("windows_ipconfig", self.connection_id, self.cfg,
                                                       host=None, minutes=15, runs=3)

    def test_ping_cannot_register_dns_or_unlisted_target(self):
        self.dialog.kind.set(routine_ui.LABELS["windows_ping"])
        self.dialog.refresh()
        self.assertEqual(self.dialog.targets.options["values"], ("203.0.113.50",))
        self.dialog.host.set("example.invalid")
        self.dialog.register()
        self.confirm.assert_not_called()
        self.routines.register.assert_not_called()
        self.dialog.host.set("203.0.113.50")
        self.confirm.return_value = True
        self.dialog.register()
        self.routines.register.assert_called_once_with("windows_ping", self.connection_id, self.cfg,
                                                       host="203.0.113.50", minutes=15, runs=3)

    def test_pending_dormant_offer_revoke_and_replaced_scope_ignore(self):
        self.rows.append(self.row(active=False, current=False))
        self.dialog.refresh()
        self.assertIsNone(self.dialog.offer)
        self.rows.append(self.row(active=False))
        self.dialog.refresh()
        self.assertEqual(self.dialog.revoke_btn.options["state"], "normal")
        self.assertEqual(self.dialog.copy_btn.options["state"], "disabled")
        self.dialog.register()
        self.routines.register.assert_not_called()
        self.confirm.return_value = True
        self.dialog.revoke()
        self.routines.revoke.assert_called_once_with(self.routine_id)

    def test_scope_change_during_confirm_denies_registration(self):
        def change_scope(*_args, **_kwargs):
            self.cfg["workspace_revision"] = "replaced-scope"
            return True
        self.confirm.side_effect = change_scope
        self.dialog.register()
        self.routines.register.assert_not_called()
        self.error.assert_called_once()

    def test_copy_only_local_request_instructions_no_connection_id(self):
        self.rows.append(self.row(active=True))
        self.dialog.root.clipboard_clear = Mock()
        self.dialog.root.clipboard_append = Mock()
        self.dialog.copy()
        clipboard = self.dialog.root.clipboard_append.call_args.args[0]
        self.assertIn(self.routine_preset, clipboard)
        self.assertIn("request_key", clipboard)
        self.assertNotIn(self.connection_id, clipboard)
        self.routines.register.assert_not_called()


if __name__ == "__main__":
    unittest.main()
