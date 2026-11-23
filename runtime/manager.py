"""Windows Workspace MCP: Tk desktop console and command-line entry point."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import ntpath
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

sys.dont_write_bytecode = True
import core
import diagnostic_ui
import project_tasks
import transfer_mailbox as mailbox
import unified_workspace
import upgrade_ui as visual
import workspace as workspace_api
from extras_ui import Extras
from file_bridge import transfer_max_bytes
from workspace import AUDIT, BACKUPS, DECISIONS, MODE_LABELS, PENDING, workspace_root

try:
    import windows_toolbox
except ModuleNotFoundError as exc:
    if exc.name != "windows_toolbox":
        raise
    windows_toolbox = None

try:
    import shutdown_timer
except ModuleNotFoundError as exc:
    if exc.name != "shutdown_timer":
        raise
    shutdown_timer = None

try:
    import diagnostic_routines
except ModuleNotFoundError as exc:
    if exc.name != "diagnostic_routines":
        raise
    diagnostic_routines = None


class Dashboard:
    def __init__(self, root, workspace_draft=None, mode_draft=None):
        self.root = root
        self.events = queue.Queue()
        self.status_events = queue.Queue()
        self.autostart_epoch = 0
        self.autostart_polling = False
        self.busy = False
        self.task_cache = None
        self.mode = tk.StringVar()
        self.state = tk.StringVar(value="读取本机状态…")
        self.details = tk.StringVar()
        self.msg = tk.StringVar(value="就绪。")
        self.auto = tk.BooleanVar()
        self.autostart_status = tk.StringVar(value="正在读取登录自启状态…")
        self.cfg = core.load_config()
        draft_root = workspace_draft or self.cfg["workspace_root"]
        self.action_root_key = self.root_key(draft_root)
        same_scope = self.action_root_key == self.root_key(self.cfg["workspace_root"])
        self.workspace_path = tk.StringVar(value=draft_root)
        initial_mode = mode_draft or (self.cfg["approval_mode"] if same_scope else "ask")
        self.approval_mode = tk.StringVar(value=MODE_LABELS.get(initial_mode, MODE_LABELS["ask"]))
        self.authorization = tk.StringVar()
        self.documents_state = tk.StringVar()
        self.transfer_mb = tk.StringVar(value=self.cfg["transfer_max_mb"])
        self.approval_tip = tk.StringVar(value="点选待审批项目查看请求摘要。")
        self.approval_cache = []
        self.audit_cache = []
        self.origin = tk.StringVar(value=self.cfg["origin"])
        self.plugin = tk.StringVar(value=self.cfg["plugin_url"])
        self.poll = tk.StringVar(value=self.cfg["poll_seconds"])
        self.timeout = tk.StringVar(value=self.cfg["timeout_seconds"])
        self.connection_summary = tk.StringVar(value="尚未配置 HTTPS 入口。")
        self.remote_mcp_url = tk.StringVar()
        self.bound_callbacks = None
        self.short_state = tk.StringVar(value="正在读取状态…")
        self.current_root = tk.StringVar(value="未授权")
        self.current_mode = tk.StringVar(value="未授权")
        self.current_contact = tk.StringVar(value="无")
        self.automation_summary = tk.StringVar()
        self.profile_rows = {}
        self.expiry_minutes = tk.StringVar(value=self.cfg.get("approval_minutes", 30) if same_scope else 30)
        self.automatic_actions = set(self.cfg.get("automatic_operations", ())) if same_scope else set()
        self.profiles_supported = all(callable(getattr(unified_workspace, key, None))
                                      for key in ("list_profiles", "save_profile", "activate_profile", "remove_profile"))
        self.optional_automatic = dict(getattr(workspace_api, "OPTIONAL_FULL_AUTOMATIC", {}))
        self.family = visual.install_theme(root)
        root.title("Windows Workspace MCP · 本机控制台")
        root.geometry("1100x780")
        root.minsize(950, 660)
        application_menu = tk.Menu(root, tearoff=False)
        tools_menu = tk.Menu(application_menu, tearoff=False)
        tools_menu.add_command(label="Windows 固定工具箱…", command=self.open_toolbox)
        if diagnostic_routines is not None and windows_toolbox is not None:
            tools_menu.add_command(label="固定诊断限时授权…", command=self.open_diagnostic_routines)
        application_menu.add_cascade(label="工具", menu=tools_menu)
        root.configure(menu=application_menu)
        base = ttk.Frame(root, padding=(18, 14, 18, 10), style="Shell.TFrame")
        base.pack(fill="both", expand=True)
        self.status_pill = visual.make_header(base, self.short_state)
        self.local_power = visual.LocalPower(root, shutdown_timer) if os.name == "nt" and shutdown_timer is not None else None
        if self.local_power is not None:
            self.local_power.add_banner(base)
        books = ttk.Notebook(base)
        books.pack(fill="both", expand=True)
        dash, settings = ttk.Frame(books, padding=22), ttk.Frame(books, padding=22)
        books.add(dash, text="总览")
        ws, approvals, audit = (ttk.Frame(books, padding=18) for _ in range(3))
        books.add(ws, text="工作区与权限")
        books.add(approvals, text="待审批")
        self.approvals_tab = approvals
        books.add(audit, text="操作记录")
        documents = ttk.Frame(books, padding=18)
        books.add(documents, text="传输设置")
        self.extras = Extras(self, books)
        self.books = books
        self.mail_tab = self.extras.mail_tab
        books.add(settings, text="连接与开机自启")
        self.settings_tab = settings
        self.workspace_tab = ws
        self.draw_overview(dash)
        self.draw_workspaces(ws)

        self.pending_table = self.table(approvals, ("operation", "path", "expires"), ("请求操作", "相对路径", "过期时间"), (155, 390, 140))
        self.pending_table.bind("<<TreeviewSelect>>", lambda _: self.show_request())
        ttk.Label(approvals, textvariable=self.approval_tip, justify="left", wraplength=740).pack(anchor="w", pady=10)
        decisions = ttk.Frame(approvals)
        decisions.pack(anchor="w")
        ttk.Button(decisions, text="批准选中请求", command=lambda: self.decide("allow")).pack(side="left", padx=(0, 8))
        ttk.Button(decisions, text="拒绝选中请求", command=lambda: self.decide("deny")).pack(side="left")
        self.audit_table = self.table(audit, ("time", "action", "path", "result"), ("时间", "操作", "相对路径", "结果"), (130, 90, 265, 180))

        documents.columnconfigure(0, weight=1)
        ttk.Label(documents, text="原件传输设置", font=("Microsoft YaHei UI", 13, "bold")).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(documents, text="范围在「工作区与权限」统一管理，这里只改传输上限。\n文档预览上限 20 MB；下载链接 7 分钟，可续签。",
                  wraplength=750, foreground="#526173").grid(row=2, column=0, columnspan=2, sticky="w", pady=9)
        ttk.Label(documents, textvariable=self.documents_state, foreground="#315276", wraplength=740).grid(row=4, column=0, columnspan=2, sticky="w", pady=9)
        size_row = ttk.Frame(documents)
        size_row.grid(row=5, column=0, columnspan=2, sticky="w", pady=8)
        ttk.Label(size_row, text="单文件传输上限（20–1000 MB）：").pack(side="left")
        ttk.Entry(size_row, textvariable=self.transfer_mb, width=7).pack(side="left", padx=6)
        ttk.Button(size_row, text="保存传输上限", command=self.save_transfer_limit).pack(side="left", padx=6)

        settings.columnconfigure(1, weight=1)
        ttk.Label(settings, text="连接与认证", style="Section.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 3))
        ttk.Label(settings, textvariable=self.connection_summary, style="Muted.TLabel", justify="left", wraplength=840).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(0, 11))
        for row, (label, value) in enumerate((("自有公网 HTTPS 地址", self.origin), ("客户端页面（可选）", self.plugin),
                                              ("轮询间隔（秒）", self.poll), ("连接超时（秒）", self.timeout)), 2):
            ttk.Label(settings, text=label).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=5)
            ttk.Entry(settings, textvariable=value).grid(row=row, column=1, sticky="ew", pady=5)
        ttk.Label(settings, text="OAuth 回调白名单（每行一个）").grid(row=6, column=0, sticky="nw", padx=(0, 12), pady=5)
        self.callback_editor = tk.Text(settings, height=3, wrap="none", background=visual.PANEL, foreground=visual.INK,
                                       relief="solid", borderwidth=1, highlightthickness=0, padx=6, pady=4)
        self.callback_editor.grid(row=6, column=1, sticky="ew", pady=5)
        ttk.Label(settings, text="请填客户端提供的完整 HTTPS 回调地址，不填通配符、令牌或本机 MCP 地址。",
                  style="Muted.TLabel", wraplength=650).grid(row=7, column=1, sticky="w")
        ttk.Label(settings, text="供客户端填写的 MCP 地址").grid(row=8, column=0, sticky="w", padx=(0, 12), pady=5)
        endpoint_row = ttk.Frame(settings)
        endpoint_row.grid(row=8, column=1, sticky="ew", pady=5)
        ttk.Entry(endpoint_row, textvariable=self.remote_mcp_url, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(endpoint_row, text="复制地址", command=self.copy_mcp_url).pack(side="left", padx=(8, 0))
        settings_actions = ttk.Frame(settings)
        settings_actions.grid(row=9, column=1, sticky="w", pady=(8, 6))
        ttk.Button(settings_actions, text="保存连接配置", command=self.save).pack(side="left", padx=(0, 7))
        ttk.Button(settings_actions, text="准备本机认证…", command=self.prepare_relay, style="Primary.TButton").pack(side="left", padx=(0, 7))
        self.consent_button = ttk.Button(settings_actions, text="查看本机连接口令…", command=self.show_consent_code, state="disabled")
        self.consent_button.pack(side="left")
        self.autostart_toggle = ttk.Checkbutton(settings, text="当前 Windows 用户登录后自动启动", variable=self.auto,
                                               command=self.change_autostart, state="disabled")
        self.autostart_toggle.grid(row=10, column=0, columnspan=2, sticky="w", pady=(10, 5))
        ttk.Label(settings, textvariable=self.autostart_status, style="Muted.TLabel").grid(row=12, column=0, columnspan=2,
                                                                                         sticky="w", pady=(8, 0))
        ttk.Label(settings, text="保存地址不会联网或公开端口。HTTPS 代理或隧道由你另行配置。\n改连接配置后重启工作器。休眠、关机或断网时服务不可用。",
                  foreground="#526173", wraplength=765, justify="left").grid(row=11, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Label(base, textvariable=self.msg, style="Footer.TLabel", wraplength=860).pack(anchor="w", pady=(10, 0))
        root.after(100, self.drain)
        self.refresh()
        if workspace_draft:
            books.select(ws)

    def draw_overview(self, parent):
        title = ttk.Frame(parent)
        title.pack(fill="x")
        title.columnconfigure(0, weight=1)
        ttk.Label(title, text="连接总览", style="Headline.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(title, text="查看工作器、授权范围与最近通信。", style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(3, 0))
        ttk.Button(title, text="固定工具箱…", command=self.open_toolbox).grid(row=0, column=1, rowspan=2, sticky="e", padx=(0, 7))
        ttk.Button(title, text="一键连接", style="Primary.TButton", command=self.connect).grid(row=0, column=2, rowspan=2, sticky="e")
        visual.summary_cards(parent, (("当前工作区", self.current_root, 2), ("授权等级", self.current_mode, 1),
                                      ("最近通信", self.current_contact, 1))).pack(fill="x", pady=(16, 14))

        panel = ttk.Frame(parent, style="Card.TFrame", padding=(15, 12))
        panel.pack(fill="x", pady=(0, 13))
        self.state_label = ttk.Label(panel, textvariable=self.state, style="Section.TLabel")
        self.state_label.pack(anchor="w")
        ttk.Label(panel, textvariable=self.mode, style="Muted.TLabel", wraplength=790).pack(anchor="w", pady=(4, 7))
        ttk.Label(panel, textvariable=self.details, justify="left", wraplength=790).pack(anchor="w")
        controls = ttk.Frame(panel)
        controls.pack(fill="x", pady=(10, 0))
        for text, command in (
            ("检测公网入口", self.check),
            ("重启工作器", self.restart_connection),
            ("停止工作器", lambda: self.job(core.stop_worker, "已请求停止。", critical=True)),
            ("打开客户端页面", self.open_client_page),
        ):
            ttk.Button(controls, text=text, command=command).pack(side="left", padx=(0, 7))

        shortcuts = ttk.Frame(parent)
        shortcuts.pack(fill="x")
        ttk.Label(shortcuts, text="快捷入口", style="MetricLabel.TLabel").pack(anchor="w", pady=(0, 5))
        bar = ttk.Frame(shortcuts)
        bar.pack(fill="x")
        for text, command in (
            ("工作区授权", lambda: self.books.select(self.workspace_tab)),
            ("查看待审批", lambda: self.books.select(self.approvals_tab)),
            ("打开收发件箱", lambda: self.books.select(self.mail_tab)),
            ("连接与认证", lambda: self.books.select(self.settings_tab)),
        ):
            ttk.Button(bar, text=text, command=command).pack(side="left", padx=(0, 7))

    def connect(self):
        cfg = core.load_config()
        if not core.relay_ready(cfg):
            self.books.select(self.settings_tab)
            self.msg.set("先保存你自己的 HTTPS 地址并明确准备本机认证。")
            return
        origin = cfg["origin"]
        self.job(lambda: visual.connect_note(core.start_worker, core.endpoint_status, origin), critical=True)

    def restart_connection(self):
        if not core.relay_ready(core.load_config()):
            self.books.select(self.settings_tab)
            self.msg.set("先准备本机认证，再重启工作器。")
            return
        self.job(core.restart_worker, "已请求重启。", critical=True)

    def open_toolbox(self):
        current = getattr(self, "toolbox_dialog", None)
        if current is not None and current.root.winfo_exists():
            current.root.deiconify()
            current.root.lift()
            return
        self.toolbox_dialog = visual.ToolboxDialog(self.root, project_tasks.PRESETS, workspace_api.OPERATIONS,
                                                   core.load_config(), windows_toolbox, submit=self.request_toolbox,
                                                   power=self.local_power,
                                                   routines=self.open_diagnostic_routines if diagnostic_routines is not None and windows_toolbox is not None else None)

    def open_diagnostic_routines(self):
        current = getattr(self, "routine_dialog", None)
        if current is not None and current.root.winfo_exists():
            current.root.lift()
            return
        if diagnostic_routines is not None and windows_toolbox is not None:
            self.routine_dialog = diagnostic_ui.RoutineDialog(self.root, core.load_config, diagnostic_routines, windows_toolbox)

    def request_toolbox(self, preset, parameters):
        if preset not in {key for key, _, _ in visual.TOOLBOX_CATALOG} or preset not in project_tasks.PRESETS:
            self.msg.set("此版本未接入该固定工具。")
            return

        def enqueue():
            result = project_tasks.start(preset, core.load_config(), parameters=parameters)
            if result.get("state") == "awaiting_approval":
                return "已提交固定工具请求；请到「待审批」确认。"
            return "已提交固定工具请求，当前状态：" + str(result.get("state", "未知"))

        self.job(enqueue, critical=True)
        self.books.select(self.approvals_tab)
        # Keep unsaved entries in the hidden tool window while revealing the inbox.
        if self.toolbox_dialog.root.winfo_exists():
            self.toolbox_dialog.root.withdraw()

    def draw_workspaces(self, parent):
        parent.columnconfigure(0, weight=1)
        ttk.Label(parent, text="工作区与权限", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(parent, textvariable=self.authorization, style="Muted.TLabel", wraplength=860).grid(row=1, column=0, sticky="w", pady=(3, 9))
        form = ttk.Frame(parent, padding=(13, 10), style="Card.TFrame")
        form.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="目录").grid(row=0, column=0, sticky="w", padx=(0, 12))
        ttk.Entry(form, textvariable=self.workspace_path).grid(row=0, column=1, sticky="ew", padx=(0, 7))
        ttk.Button(form, text="选择文件夹…", command=self.pick_workspace).grid(row=0, column=2, sticky="e")
        ttk.Label(form, text="授权等级").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=(7, 0))
        policy = ttk.Frame(form)
        policy.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(7, 0))
        picker = ttk.Combobox(policy, values=list(MODE_LABELS.values()), textvariable=self.approval_mode, state="readonly", width=21)
        picker.pack(side="left", padx=(0, 8))
        if self.profiles_supported:
            low = core.APPROVAL_MINUTES_MIN
            high = core.APPROVAL_MINUTES_MAX
            ttk.Label(policy, text="文件审批窗口（分钟）").pack(side="left", padx=(0, 5))
            ttk.Spinbox(policy, from_=low, to=high, textvariable=self.expiry_minutes, width=4).pack(side="left", padx=(0, 8))
        self.policy_button = ttk.Button(policy, text="自动审批动作…", command=self.configure_automation)
        if self.optional_automatic:
            self.policy_button.pack(side="left")
        self.approval_mode.trace_add("write", lambda *_args: self.update_policy_summary())
        self.workspace_path.trace_add("write", lambda *_args: self.on_draft_root())
        ttk.Label(form, textvariable=self.automation_summary, style="Muted.TLabel", wraplength=825).grid(
            row=2, column=1, columnspan=3, sticky="w", pady=(6, 0))
        actions = ttk.Frame(form)
        actions.grid(row=3, column=1, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Button(actions, text="保存并统一授权", style="Primary.TButton", command=self.grant_workspace).pack(side="left", padx=(0, 7))
        if self.profiles_supported:
            ttk.Button(actions, text="保存待用配置", command=self.save_inactive_profile).pack(side="left", padx=(0, 7))
        ttk.Button(actions, text="打开已授权文件夹", command=self.open_workspace).pack(side="left", padx=(0, 7))
        ttk.Button(actions, text="打开写入备份", command=self.open_backups).pack(side="left")
        self.update_policy_summary()
        if self.profiles_supported:
            parent.rowconfigure(3, weight=1)
            area = ttk.Frame(parent)
            area.grid(row=3, column=0, sticky="nsew")
            ttk.Label(area, text="已保存的工作区配置", style="MetricLabel.TLabel").pack(anchor="w")
            ttk.Label(area, text="可保存多套规则，当前版本最多一套处于远程授权状态；切换可能使旧请求失效。",
                      style="Muted.TLabel", wraplength=860).pack(anchor="w", pady=(2, 4))
            self.profile_table = self.table(area, ("root", "mode", "ttl", "state"),
                                            ("目录", "授权等级", "文件审批窗口", "状态"), (370, 150, 100, 105))
            self.profile_table.configure(height=4)
            self.profile_table.bind("<Double-1>", lambda _event: self.load_profile_draft())
            profile_actions = ttk.Frame(parent)
            profile_actions.grid(row=4, column=0, sticky="ew", pady=(7, 0))
            for text, command in (("载入选中配置", self.load_profile_draft), ("启用配置", self.activate_profile),
                                  ("移除待用配置", self.remove_profile)):
                ttk.Button(profile_actions, text=text, command=command).pack(side="left", padx=(0, 7))
        else:
            profile_actions = ttk.Frame(parent)
            profile_actions.grid(row=4, column=0, sticky="ew")
        ttk.Button(profile_actions, text="撤销全部授权", style="Danger.TButton", command=self.revoke_workspace).pack(side="right")

    @staticmethod
    def root_key(path):
        return ntpath.normcase(ntpath.normpath(path.strip())) if path.strip() else ""

    def on_draft_root(self):
        new_key = self.root_key(self.workspace_path.get())
        if new_key != self.action_root_key:
            self.action_root_key = new_key
            self.automatic_actions.clear()
            self.expiry_minutes.set(getattr(core, "APPROVAL_MINUTES_DEFAULT", 30))
            self.update_policy_summary()

    def selected_mode(self):
        return next((key for key, label in MODE_LABELS.items() if label == self.approval_mode.get()), "ask")

    def update_policy_summary(self):
        mode = self.selected_mode()
        if self.optional_automatic:
            self.policy_button.configure(state="normal" if mode == "full" else "disabled")
        if mode == "ask":
            text = "普通文件操作逐次审批。"
        elif mode == "rules":
            text = "自动放行只读操作与符合条件的小型 TXT、MD、CSV 写入。"
        else:
            text = "常规文件操作按已启用的能力自动处理；Git、项目代码及构建继续人工确认。"
            selected = [name for key, name in self.optional_automatic.items() if key in self.automatic_actions]
            if self.optional_automatic:
                text += (" 额外自动通过：" + "、".join(selected) + "。") if selected else " 移动、回收、恢复默认仍需人工批准。"
        self.automation_summary.set(text)

    def configure_automation(self):
        if self.selected_mode() != "full" or not self.optional_automatic:
            return
        dialog = tk.Toplevel(self.root)
        body = visual.place_dialog(dialog, self.root, "完全访问 · 自动审批清单")
        ttk.Label(body, text="自动审批清单", style="Section.TLabel").pack(anchor="w")
        ttk.Label(body, style="Muted.TLabel", wraplength=480,
                  text="额外动作默认未勾选。所选项只对本配置生效；未选动作仍逐次批准。\n"
                       "这里不会授予 Windows 管理员权限，也不会自动运行任意命令。").pack(anchor="w", pady=(5, 10))
        choices = {key: tk.BooleanVar(value=key in self.automatic_actions) for key in self.optional_automatic}
        for key, label in self.optional_automatic.items():
            ttk.Checkbutton(body, text=label, variable=choices[key]).pack(anchor="w", pady=3)

        def apply():
            self.automatic_actions = {key for key, enabled in choices.items() if enabled.get()}
            self.update_policy_summary()
            self.msg.set("已更新草稿。保存配置后才生效。")
            dialog.destroy()
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="应用到草稿", style="Primary.TButton", command=apply).pack(side="left", padx=(0, 7))
        ttk.Button(buttons, text="取消", command=dialog.destroy).pack(side="left")
        dialog.grab_set()

    def policy_options(self):
        if not self.profiles_supported:
            return {}
        raw = str(self.expiry_minutes.get()).strip()
        if not raw.isdecimal() or not core.APPROVAL_MINUTES_MIN <= int(raw) <= core.APPROVAL_MINUTES_MAX:
            raise ValueError(f"文件审批窗口需为 {core.APPROVAL_MINUTES_MIN}–{core.APPROVAL_MINUTES_MAX} 的整数（分钟）。")
        return {"approval_minutes": int(raw), "automatic_operations": sorted(self.automatic_actions & self.optional_automatic.keys())
                if self.selected_mode() == "full" else []}

    def refresh_profiles(self):
        if not self.profiles_supported:
            return
        try:
            rows = {row["profile_id"]: row for row in unified_workspace.list_profiles()}
        except (OSError, ValueError, TypeError, KeyError):
            return
        if rows == self.profile_rows:
            return
        self.profile_rows = rows
        table = self.profile_table
        selected = table.selection()
        table.delete(*table.get_children())
        for ident, item in sorted(rows.items(), key=lambda entry: (not entry[1]["active"], entry[1]["root"].casefold())):
            table.insert("", "end", iid=ident, values=(item["root"], MODE_LABELS.get(item["mode"], item["mode"]),
                         f"{item['approval_minutes']} 分钟", "当前已启用" if item["active"] else "待用 · 未授权"))
        if selected and table.exists(selected[0]):
            table.selection_set(selected[0])

    def chosen_profile(self):
        selected = self.profile_table.selection() if self.profiles_supported else ()
        row = self.profile_rows.get(selected[0]) if selected else None
        if not row:
            self.msg.set("请先选择一项工作区配置。")
        return row

    def fill_profile(self, row):
        self.workspace_path.set(row["root"])
        self.expiry_minutes.set(row["approval_minutes"])
        self.automatic_actions = set(row.get("automatic_operations", ()))
        self.approval_mode.set(MODE_LABELS[row["mode"]])
        self.update_policy_summary()

    def load_profile_draft(self):
        row = self.chosen_profile()
        if row:
            self.fill_profile(row)
            self.msg.set("已载入编辑草稿，尚未更改生效权限。")

    def save_inactive_profile(self):
        try:
            row = unified_workspace.save_profile(self.workspace_path.get().strip(), self.selected_mode(), **self.policy_options())
            self.refresh_profiles()
            if row and self.profile_table.exists(row["profile_id"]):
                self.profile_table.selection_set(row["profile_id"])
            self.msg.set("已保存为待用配置。当前生效的工作区未改变。")
        except (OSError, ValueError) as exc:
            messagebox.showerror("配置未保存", str(exc), parent=self.root)

    def activate_profile(self):
        row = self.chosen_profile()
        if not row:
            return
        if not core.relay_ready(core.load_config()):
            self.msg.set("先准备本机认证。待用配置尚未授予任何访问。")
            return
        if not row["active"] and not messagebox.askyesno("启用工作区配置",
                f"启用 {row['root']}？\n切换后，旧工作区的待审批或传输请求可能失效。", default="no", parent=self.root):
            return
        try:
            unified_workspace.activate_profile(row["profile_id"])
            self.fill_profile(row)
            self.refresh_profiles()
            self.msg.set("已启用选中的工作区配置。")
        except (OSError, ValueError) as exc:
            messagebox.showerror("配置未启用", str(exc), parent=self.root)

    def remove_profile(self):
        row = self.chosen_profile()
        if not row:
            return
        if row["active"]:
            self.msg.set("当前生效的配置不能移除；先切换或撤销授权。")
            return
        if not messagebox.askyesno("移除待用配置", "只移除这条配置，不删除本机文件。继续？", parent=self.root):
            return
        try:
            unified_workspace.remove_profile(row["profile_id"])
            self.refresh_profiles()
            self.msg.set("已移除待用配置。")
        except (OSError, ValueError) as exc:
            messagebox.showerror("配置未移除", str(exc), parent=self.root)

    def job(self, action, success=None, critical=False):
        if self.busy:
            self.msg.set("已有操作正在完成，请稍候。")
            return
        self.busy = True
        self.msg.set("正在处理…")

        def run():
            try:
                result = action()
                self.events.put((True, success if success is not None else result, critical))
            except Exception as exc:
                self.events.put((False, str(exc), critical))
        threading.Thread(target=run, daemon=True).start()

    def drain(self):
        try:
            while True:
                ok, data, critical = self.events.get_nowait()
                self.busy = False
                if data:
                    self.msg.set(data)
                if not ok and critical:
                    messagebox.showerror("操作未完成", data, parent=self.root)
                self.task_cache = None
                self.autostart_epoch += 1
        except queue.Empty:
            pass
        try:
            while True:
                epoch, enabled = self.status_events.get_nowait()
                self.autostart_polling = False
                if epoch != self.autostart_epoch:
                    continue
                # A failed query is unknown, not proof that the login task is off.
                self.task_cache = enabled if enabled is not None else "unknown"
                prepared = core.relay_ready(core.load_config())
                self.autostart_toggle.configure(state="normal" if self.supports_autostart() and enabled is not None
                                               and (enabled or prepared) else "disabled")
                if enabled is not None:
                    self.auto.set(enabled)
                self.autostart_status.set("独立状态或当前平台不支持登录自启。" if not self.supports_autostart() else
                                          "登录自启已开启。" if enabled is True else "登录自启已关闭。"
                                          if enabled is False else "无法读取登录自启状态；可重新打开管理器再试。")
        except queue.Empty:
            pass
        self.root.after(150, self.drain)

    def refresh_autostart(self):
        if self.task_cache is not None or self.autostart_polling:
            return
        self.autostart_polling = True
        epoch = self.autostart_epoch

        def read():
            try:
                value = bool(core.autostart_enabled())
            except Exception:
                value = None
            self.status_events.put((epoch, value))
        threading.Thread(target=read, daemon=True).start()

    @staticmethod
    def supports_autostart():
        return os.name == "nt" and not os.environ.get(core.STATE_ENV)

    def refresh(self):
        state = core.current_status()
        online = state.get("running") and state.get("phase") == "online" and time.time() - state.get("last_contact", 0) <= 25
        if online:
            label, color, short, badge = "工作器在线", visual.GREEN, "在线", "HeaderLive.TLabel"
        elif state.get("running"):
            label, color, short, badge = "工作器运行中 · 连接未就绪", visual.AMBER, "连接中", "HeaderWait.TLabel"
        else:
            label, color, short, badge = "工作器已停止或尚未启动", visual.MUTED, "未连接", "HeaderMode.TLabel"
        self.state.set(label)
        self.short_state.set(short)
        self.status_pill.configure(style=badge)
        self.state_label.configure(foreground=color)
        cfg = core.load_config()
        origin = cfg.get("origin", "")
        self.refresh_connection(cfg)
        last = (dt.datetime.fromtimestamp(state["last_contact"]).strftime("%Y-%m-%d %H:%M:%S") if state.get("last_contact") else "无")
        status_note = state.get("message", "尚无工作器记录。") if state.get("running") or state.get("phase") == "failed" else "未检测到近期心跳。"
        if state.get("running") and state.get("origin") != origin:
            status_note += " 配置已变化，重启工作器后生效。"
        authorized = f"{cfg['workspace_root']} · {MODE_LABELS.get(cfg['approval_mode'], MODE_LABELS['ask'])}" if cfg["workspace_enabled"] else "未授权"
        scope_note = (" · 已统一授权" if cfg.get("workspace_unified") and cfg["workspace_enabled"] else
                      " · 旧版分项范围；点「保存并统一授权」升级" if cfg["workspace_enabled"] else "")
        self.authorization.set("当前工作区：" + authorized + scope_note)
        self.current_root.set(cfg["workspace_root"] if cfg["workspace_enabled"] else "未授权")
        self.current_mode.set(MODE_LABELS.get(cfg["approval_mode"], MODE_LABELS["ask"]) if cfg["workspace_enabled"] else "未授权")
        self.current_contact.set(last)
        self.documents_state.set("已授权文档范围：" + (cfg.get("document_scope") or cfg["workspace_root"])
                                 if cfg.get("documents_enabled") and cfg.get("workspace_enabled") else "文档预览和原件传输未启用。")
        self.details.set(f"HTTPS：{origin or '未设置'}\n"
                         f"本次读取 {state.get('read_count', 0)} 次，修改 {state.get('write_count', 0)} 次\n"
                         f"状态：{status_note}")
        self.refresh_autostart()
        self.refresh_profiles()
        self.extras.refresh(cfg)
        self.refresh_tables(cfg)
        self.root.after(1800, self.refresh)

    def notify_inbox_count(self, count):
        title = "收发件箱" + (f" ({count})" if count else "")
        if self.books.tab(self.mail_tab, "text") != title:
            self.books.tab(self.mail_tab, text=title)

    def notify_messages(self, count):
        title = "消息" + (f" ({count})" if count else "")
        if self.books.tab(self.extras.messages_tab, "text") != title:
            self.books.tab(self.extras.messages_tab, text=title)

    def save_transfer_limit(self):
        try:
            cfg = core.load_config()
            trial = {**cfg, "transfer_max_mb": int(self.transfer_mb.get())}
            limit = transfer_max_bytes(trial)
            if trial != cfg:
                core.update_config(transfer_max_mb=trial["transfer_max_mb"])
            self.msg.set(f"单文件传输上限已设为 {limit:,} 字节。预览上限未变。")
        except (ValueError, OSError) as exc:
            self.msg.set(f"未保存：{exc}")

    def check(self):
        cfg = core.load_config()
        if not core.relay_ready(cfg):
            self.books.select(self.settings_tab)
            self.msg.set("先准备本机认证；公网检测不会自动创建或修改入口。")
            return
        origin = cfg["origin"]
        self.job(lambda: core.endpoint_status(origin)[1])

    @staticmethod
    def mcp_url(origin):
        if not origin:
            return ""
        try:
            return core.canonical_origin(origin) + "/mcp"
        except (ValueError, TypeError):
            return ""

    def refresh_connection(self, cfg):
        origin = cfg.get("origin", "")
        available = core.relay_ready(cfg)
        self.remote_mcp_url.set(self.mcp_url(origin))
        self.mode.set("自管 HTTPS 入口 · 中继与文件服务在本机回环运行。" if available else
                      "HTTPS 地址已保存，本机认证还未准备。" if origin else "尚未配置 HTTPS 地址。")
        self.connection_summary.set("认证及回调白名单已绑定当前地址。更换地址或回调需新状态；公网可达性需另验。" if available else
                                    "先保存自有 HTTPS 地址，填客户端回调，再点「准备本机认证」。服务不会因此启动。" if origin else
                                    "首次运行：没有 HTTPS 地址或已授权目录，未启用远程访问。")
        callbacks = tuple(core.local_oauth_callbacks(cfg)) if available else None
        if callbacks != self.bound_callbacks:
            self.bound_callbacks = callbacks
            self.callback_editor.configure(state="normal")
            self.callback_editor.delete("1.0", "end")
            if callbacks is not None:
                self.callback_editor.insert("1.0", "\n".join(callbacks))
                self.callback_editor.configure(state="disabled")
        self.consent_button.configure(state="normal" if available else "disabled")
        if not self.supports_autostart() or type(self.task_cache) is bool:
            self.autostart_toggle.configure(state="normal" if self.supports_autostart() and (self.task_cache or available) else "disabled")

    def copy_mcp_url(self):
        url = self.remote_mcp_url.get()
        if not url:
            self.msg.set("保存自有 HTTPS 地址后才能复制 MCP 地址。")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(url)
        self.msg.set("已复制 MCP 地址；未复制任何口令。")

    def save(self):
        try:
            connection = core.validated_config(self.origin.get(), self.plugin.get(), self.poll.get(), self.timeout.get())
            current = core.load_config()
            if connection["origin"] != current.get("origin"):
                if core.current_status().get("running"):
                    raise ValueError("更改 HTTPS 地址前，请先停止工作器。")
                if current.get("workspace_enabled"):
                    raise ValueError("更改 HTTPS 地址前，请先撤销当前工作区授权。")
                if connection["origin"] and core.uses_funnel(current):
                    raise ValueError("本机认证已绑定一个地址；如需换域名，请依照配置手册从独立的新状态开始。")
            core.update_config(**connection)
            self.origin.set(connection["origin"])
            self.plugin.set(connection["plugin_url"])
            self.refresh_connection(core.load_config())
            self.msg.set("已保存设置。没有自动启动服务或公开端口。")
        except (OSError, ValueError) as exc:
            messagebox.showerror("配置未保存", str(exc), parent=self.root)

    def prepare_relay(self):
        try:
            cfg = core.load_config()
            origin = core.canonical_origin(self.origin.get())
            if origin != cfg.get("origin"):
                raise ValueError("请先保存这个 HTTPS 地址，再准备本机认证。")
            if core.relay_ready(cfg):
                self.msg.set("当前地址的本机认证已准备；没有重新生成口令。")
                return
            if core.current_status().get("running") or cfg.get("workspace_enabled"):
                raise ValueError("准备新地址前，请停止工作器并撤销当前工作区授权。")
            callbacks = self.callback_draft()
            if not messagebox.askyesno("确认准备本机认证",
                                       f"为此地址创建本机专用认证：\n{origin}\n\n"
                                       f"将授权返回给你填写的 {len(callbacks)} 个确切客户端回调。请检查表单中的完整地址。\n"
                                       "不会启动服务、创建自启任务、配置公网代理或授权任何文件夹。继续？",
                                       default="no", parent=self.root):
                return
            latest = core.load_config()
            if (latest.get("origin") != origin or latest.get("workspace_enabled") or core.current_status().get("running")
                    or self.callback_draft() != callbacks):
                raise ValueError("确认期间设置已变化，请核对后再试。")
            core.configure_local_relay(origin, callbacks)
            latest = core.load_config()
            if not core.relay_ready(latest):
                raise ValueError("本机认证未通过就绪检查。")
            self.refresh_connection(latest)
            self.msg.set("本机认证已准备。另行配置你的 HTTPS 代理，然后手动连接。")
        except (OSError, ValueError, RuntimeError) as exc:
            messagebox.showerror("认证未准备", str(exc), parent=self.root)

    def callback_draft(self):
        callbacks = [line.strip() for line in self.callback_editor.get("1.0", "end-1c").splitlines() if line.strip()]
        if not 1 <= len(callbacks) <= 16:
            raise ValueError("请输入 1–16 条由客户端提供的完整 OAuth 回调地址，每行一条。")
        return core.validated_oauth_callbacks(callbacks)

    def show_consent_code(self):
        try:
            if not core.relay_ready(core.load_config()):
                raise ValueError("尚未准备本机认证。")
            code = core.local_consent_code()
        except (OSError, ValueError, RuntimeError) as exc:
            messagebox.showerror("无法查看本机口令", str(exc), parent=self.root)
            return
        dialog = tk.Toplevel(self.root)
        body = visual.place_dialog(dialog, self.root, "本机连接口令")
        ttk.Label(body, text="本机连接口令", style="Section.TLabel").pack(anchor="w")
        ttk.Label(body, text="只在你自己的连接授权页使用。不要把口令粘贴到聊天、日志或公开仓库。",
                  style="Muted.TLabel", wraplength=520).pack(anchor="w", pady=(4, 9))
        secret = tk.StringVar(master=dialog, value=code)
        view = ttk.Entry(body, textvariable=secret, state="readonly", show="●", width=56)
        view.pack(fill="x")
        revealed = tk.BooleanVar(master=dialog, value=False)
        ttk.Checkbutton(body, text="在此窗口显示口令", variable=revealed,
                        command=lambda: view.configure(show="" if revealed.get() else "●")).pack(anchor="w", pady=(6, 0))
        ttk.Button(body, text="关闭", command=dialog.destroy).pack(anchor="w", pady=(8, 0))

    def change_autostart(self):
        on = self.auto.get()
        if not self.supports_autostart():
            self.auto.set(False)
            self.msg.set("独立状态或当前平台不支持登录自启。")
            return
        if on and not core.relay_ready(core.load_config()):
            self.auto.set(False)
            self.msg.set("先准备本机认证；登录自启目前未开启。")
            return
        self.job(lambda: core.set_autostart(on), "已启用登录自启。" if on else "已关闭登录自启。", critical=True)

    def open_client_page(self):
        url = core.load_config()["plugin_url"]
        if url:
            webbrowser.open(url)
        else:
            self.msg.set("先在设置里填写可选的客户端页面。")

    @staticmethod
    def table(parent, columns, headings, widths):
        outer = ttk.Frame(parent)
        outer.pack(fill="both", expand=True)
        view = ttk.Treeview(outer, columns=columns, show="headings", height=9, selectmode="browse")
        for key, heading, width in zip(columns, headings, widths):
            view.heading(key, text=heading)
            view.column(key, width=width, minwidth=80)
        y = ttk.Scrollbar(outer, orient="vertical", command=view.yview)
        view.configure(yscrollcommand=y.set)
        view.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")
        return view

    def refresh_tables(self, cfg):
        now = time.time()
        pending = ([{**row, "kind": "workspace"} for row in core.read_json(PENDING).get("items", []) if row["expires"] > now]
                   if cfg["workspace_enabled"] else [])
        for row in self.extras.mail_rows.values():
            if row["direction"] == "incoming" and row["state"] == "awaiting_approval" and row["expires_at"] > now:
                pending.append({"id": row["transfer_id"], "kind": "inbox", "label": "接收原件",
                                "path": row["name"], "expires": row["expires_at"],
                                "preview": f"{row['size_bytes']:,} 字节 · SHA-256: {row['sha256']}"})
        for row in self.extras.project_rows.values():
            expires = row["created"] + project_tasks.APPROVAL_TTL
            if row["state"] == "awaiting_approval" and expires > now:
                source = row.get("relative_path") or row.get("relative_dir", ".")
                destination = row.get("destination_path")
                plan = " → ".join(step["label"] for step in row.get("planned_steps", []))
                details = []
                if row.get("toolbox_scope") == "host":
                    source = row.get("toolbox_host") or "Windows 本机"
                    details.append("作用范围是整台 Windows 主机，不受文件工作区边界限制。")
                    if row.get("toolbox_host"):
                        details.append("Ping 目标：" + row["toolbox_host"])
                if plan:
                    details.append("步骤：" + plan)
                if row.get("runs_project_code"):
                    details.append("会运行项目代码或脚本；已有脚本副作用不会自动回滚。")
                elif not plan and row.get("toolbox_scope") != "host":
                    details.append("在工作区内以 Windows 工作器账户运行。")
                if destination:
                    details.append(f"写入新目标：{destination}（不会覆盖）")
                pending.append({"id": row["job_id"], "kind": "project", "label": row["label"],
                                "path": source, "expires": expires, "preview": "\n".join(details)})
        pending.sort(key=lambda item: item["expires"])
        self.books.tab(self.approvals_tab, text=f"待审批 ({len(pending)})" if pending else "待审批")
        notes = core.read_json(AUDIT).get("items", [])
        if pending != self.approval_cache:
            selected = self.pending_table.selection()
            self.approval_cache = pending
            self.pending_table.delete(*self.pending_table.get_children())
            for item in pending:
                when = dt.datetime.fromtimestamp(item["expires"]).strftime("%H:%M:%S")
                self.pending_table.insert("", "end", iid=item["id"], values=(item["label"], item["path"], when))
            if selected and self.pending_table.exists(selected[0]):
                self.pending_table.selection_set(selected[0])
            self.show_request()
        if notes != self.audit_cache:
            self.audit_cache = notes
            self.audit_table.delete(*self.audit_table.get_children())
            for item in reversed(notes):
                when = dt.datetime.fromtimestamp(item["time"]).strftime("%m-%d %H:%M:%S")
                self.audit_table.insert("", "end", values=(when, item["action"], item["path"], item["outcome"]))

    def show_request(self):
        selected = self.pending_table.selection()
        item = next((row for row in self.approval_cache if selected and selected[0] == row["id"]), None)
        if item:
            preview = item.get("preview", "")
            self.approval_tip.set(f"{item['label']}：{item['path']}\n" + (preview or "这项请求没有写入内容。"))
        else:
            self.approval_tip.set("选中请求查看摘要。若没有请求，说明当前没有需要人工批准的操作。")

    def decide(self, decision):
        selected = self.pending_table.selection()
        item = next((row for row in self.approval_cache if selected and row["id"] == selected[0]), None)
        if not item:
            self.msg.set("请先选中一条请求。")
            return
        if item["kind"] == "inbox":
            action = mailbox.approve_upload if decision == "allow" else mailbox.reject_upload
            self.job(lambda: action(item["id"], core.load_config()), "已处理收件请求。", critical=True)
            return
        if item["kind"] == "project":
            self.job(lambda: project_tasks.decide(item["id"], core.load_config(), decision == "allow"),
                     "已提交项目任务审批。", critical=True)
            return
        try:
            DECISIONS.mkdir(exist_ok=True)
            core.save_json(DECISIONS / (selected[0] + ".json"), {"decision": decision})
            self.msg.set("批准已提交。可以让 MCP 客户端查询该审批结果。" if decision == "allow" else "拒绝已提交。")
        except OSError as exc:
            self.msg.set(f"无法提交审批：{type(exc).__name__}")

    def pick_workspace(self):
        path = filedialog.askdirectory(parent=self.root, initialdir=self.workspace_path.get(), mustexist=True, title="选择供 MCP 使用的专用本地文件夹")
        if path:
            self.workspace_path.set(path.replace("/", "\\"))

    def grant_workspace(self):
        try:
            mode = self.selected_mode()
            path = self.workspace_path.get().strip()
            if not path:
                raise ValueError("先选择你明确授权的专用文件夹。")
            if not core.relay_ready(core.load_config()):
                raise ValueError("先准备本机认证；也可先保存工作区为待用配置。")
            unified_workspace.grant(path, mode, **self.policy_options())
            self.refresh_profiles()
            self.msg.set("工作区已统一授权，无需在其他页面再次授权。")
        except (OSError, ValueError) as exc:
            messagebox.showerror("未授权", str(exc), parent=self.root)

    def revoke_workspace(self):
        try:
            unified_workspace.revoke()
            self.refresh_profiles()
            self.msg.set("已撤销工作区及其文件、传输、任务访问。")
        except OSError as exc:
            self.msg.set(f"撤销未保存：{exc}")

    def open_workspace(self):
        cfg = core.load_config()
        if cfg["workspace_enabled"]:
            os.startfile(str(workspace_root(cfg["workspace_root"])))
        else:
            self.msg.set("当前没有已授权工作区。")

    def open_backups(self):
        if not BACKUPS.is_dir():
            self.msg.set("当前没有写入备份目录。")
            return
        os.startfile(str(BACKUPS))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--autostart", choices=["on", "off"])
    parser.add_argument("--ui-test", action="store_true")
    parser.add_argument("--workspace-draft", help="Prefill the workspace form without changing saved authorization")
    parser.add_argument("--mode-draft", choices=list(MODE_LABELS), help="Prefill the mode without applying it")
    args = parser.parse_args()
    if args.autostart:
        core.set_autostart(args.autostart == "on")
    if args.stop:
        core.stop_worker()
    error = None
    if args.start:
        try:
            core.start_worker()
        except (OSError, ValueError) as exc:
            error = str(exc)
    if args.status:
        print(json.dumps({**core.current_status(), "autostart": core.autostart_enabled(),
                          "relay_prepared": core.relay_ready()}, ensure_ascii=True))
    if args.gui or args.ui_test or not any((args.start, args.stop, args.status, args.autostart)):
        if not args.ui_test:
            core.initialize_state()
        root = tk.Tk()
        if args.ui_test:
            root.withdraw()
        view = Dashboard(root, args.workspace_draft, args.mode_draft)
        if error:
            view.msg.set(error)
        if args.ui_test:
            root.update_idletasks()
            print("Tk dashboard constructed")
            root.destroy()
        else:
            root.mainloop()
    elif error:
        raise SystemExit(error)


if __name__ == "__main__":
    main()
