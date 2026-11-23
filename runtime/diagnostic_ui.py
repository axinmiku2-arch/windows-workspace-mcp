"""Local operator UI for short and bounded fixed diagnostic authorizations."""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
import sqlite3
import time
import tkinter as tk
from tkinter import messagebox, ttk

from upgrade_ui import TOOLBOX_CATALOG, place_dialog

PING = "windows_ping"
LABELS = {key: label for key, label, _ in TOOLBOX_CATALOG}
CONNECTION_ID = re.compile(r"[a-f0-9]{24}\Z")
SCOPE_FIELDS = ("workspace_root", "workspace_revision", "active_workspace_profile", "workspace_unified", "approval_mode",
                "origin", "task_scope", "task_revision")


def exact_ip_targets(allowlist):
    result = []
    for host in allowlist:
        try:
            address = str(ipaddress.ip_address(host))
        except ValueError:
            continue
        if address == host:
            result.append(host)
    return tuple(result)


def bound_number(text, low, high):
    text = text.strip()
    if not text.isascii() or not text.isdecimal() or len(text) > len(str(high)) or not low <= int(text) <= high:
        raise ValueError(f"请输入 {low}–{high} 之间的整数。")
    return int(text)


def scope_identity(cfg):
    return tuple(cfg.get(key) for key in SCOPE_FIELDS)


def current_offer(listing):
    """Include an unspent, dormant authorization so the owner can revoke it too."""
    now = time.time()
    return (next((row for row in listing if row.get("active")), None)
            or next((row for row in listing if row.get("current_scope") and not row.get("revoked")
                     and row["remaining"] > 0 and row["expires_at"] > now), None))


class RoutineDialog:
    def __init__(self, owner, load_config, routines, toolbox):
        self.load_config, self.routines, self.toolbox = load_config, routines, toolbox
        self.root = tk.Toplevel(owner)
        body = place_dialog(self.root, owner, "固定诊断 · 限时授权")
        self.root.resizable(True, False)
        self.root.minsize(690, 455)
        self._poll_id = None
        self.root.bind("<Destroy>", self.cancel_poll, add="+")
        self.title = tk.StringVar(value="正在读取本机配置…")
        self.scope = tk.StringVar()
        self.note = tk.StringVar()
        self.code = tk.StringVar()
        self.kind = tk.StringVar(value=next(iter(LABELS.values())))
        self.host = tk.StringVar()
        self.connection = tk.StringVar()
        self.minutes = tk.StringVar(value="15")
        self.runs = tk.StringVar(value="3")
        self.offer = None
        self.mins = (getattr(routines, "MINUTES_MIN", 5), getattr(routines, "MINUTES_MAX", 60))
        self.counts = (getattr(routines, "RUNS_MIN", 1), getattr(routines, "RUNS_MAX", 5))

        ttk.Label(body, text="固定诊断 · 限时授权", style="Section.TLabel").pack(anchor="w")
        ttk.Label(body, text="仅对选中的固定诊断暂免逐次审批。不会定时运行，不会授予其他文件、项目命令或管理员权限。",
                  style="Muted.TLabel", wraplength=680, justify="left").pack(anchor="w", pady=(3, 8))
        card = ttk.Frame(body, style="Card.TFrame", padding=(12, 9))
        card.pack(fill="x")
        card.columnconfigure(1, weight=1)
        ttk.Label(card, textvariable=self.title, style="MetricLabel.TLabel", wraplength=675).grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(card, textvariable=self.scope, style="Muted.TLabel", wraplength=675).grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 2))
        ttk.Label(card, text="调用预设").grid(row=2, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(card, textvariable=self.code, state="readonly").grid(row=2, column=1, sticky="ew", padx=(0, 7))
        self.copy_btn = ttk.Button(card, text="复制给客户端的指令", command=self.copy)
        self.copy_btn.grid(row=2, column=2, sticky="e")

        form = ttk.Frame(body, padding=(0, 10, 0, 5))
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="固定诊断").grid(row=0, column=0, sticky="w", padx=(0, 12))
        self.presets = ttk.Combobox(form, values=list(LABELS.values()), textvariable=self.kind, state="readonly")
        self.presets.grid(row=0, column=1, sticky="ew")
        self.presets.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        ttk.Label(form, text="Ping 目标 IP").grid(row=1, column=0, sticky="w", pady=(7, 0))
        self.targets = ttk.Combobox(form, textvariable=self.host, state="disabled")
        self.targets.grid(row=1, column=1, sticky="ew", pady=(7, 0))
        ttk.Label(form, text="点选 Ping 后，从已保存白名单选择一个 IP。限时授权不接受域名。",
                  style="Muted.TLabel", wraplength=520).grid(row=2, column=1, sticky="w", pady=(3, 0))
        ttk.Label(form, text="MCP 连接编号").grid(row=3, column=0, sticky="w", pady=(7, 0))
        self.connection_entry = ttk.Entry(form, textvariable=self.connection)
        self.connection_entry.grid(row=3, column=1, sticky="ew", pady=(7, 0))
        ttk.Label(form, text="让当前 MCP 客户端调用 server_info，填返回的 connection_id（24 位小写十六进制）。不要填密码或令牌。",
                  style="Muted.TLabel", wraplength=535, justify="left").grid(row=4, column=1, sticky="w", pady=(3, 0))
        ttk.Label(form, text="有效期与次数").grid(row=5, column=0, sticky="w", pady=(7, 0))
        limits = ttk.Frame(form)
        limits.grid(row=5, column=1, sticky="w", pady=(7, 0))
        self.minutes_field = ttk.Spinbox(limits, textvariable=self.minutes, from_=self.mins[0], to=self.mins[1], width=5)
        self.minutes_field.pack(side="left")
        ttk.Label(limits, text="分钟    ").pack(side="left")
        self.runs_field = ttk.Spinbox(limits, textvariable=self.runs, from_=self.counts[0], to=self.counts[1], width=5)
        self.runs_field.pack(side="left")
        ttk.Label(limits, text="次").pack(side="left", padx=(4, 0))
        ttk.Label(form, text=f"允许 {self.mins[0]}–{self.mins[1]} 分钟、{self.counts[0]}–{self.counts[1]} 次；两次启动至少间隔 "
                             f"{getattr(routines, 'MIN_GAP_SECONDS', 10)} 秒。", style="Muted.TLabel").grid(
            row=6, column=1, sticky="w", pady=(3, 0))
        ttk.Label(body, textvariable=self.note, style="Muted.TLabel", wraplength=675, justify="left").pack(anchor="w", pady=(5, 0))
        bar = ttk.Frame(body)
        bar.pack(fill="x", pady=(8, 0))
        self.add_btn = ttk.Button(bar, text="确认限时授权…", command=self.register, style="Primary.TButton")
        self.add_btn.pack(side="left", padx=(0, 8))
        self.revoke_btn = ttk.Button(bar, text="撤销授权…", command=self.revoke, style="Danger.TButton")
        self.revoke_btn.pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="关闭", command=self.root.destroy).pack(side="left")
        self.poll()

    def preset(self):
        return next((key for key, label in LABELS.items() if self.kind.get() == label), None)

    def can_register(self, cfg):
        can_register = getattr(self.routines, "registration_available", None)
        if callable(can_register):
            return can_register(cfg)
        return bool(cfg.get("workspace_enabled") and cfg.get("task_enabled") and cfg.get("workspace_unified") is True
                    and cfg.get("workspace_revision") and cfg.get("approval_mode") in {"rules", "full"})

    def poll(self):
        self.refresh()
        self._poll_id = self.root.after(1500, self.poll)

    def cancel_poll(self, event):
        if event.widget is self.root and self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None

    def refresh(self):
        try:
            cfg = self.load_config()
            listing = self.routines.listing(cfg)
            self.offer = current_offer(listing)
            targets = exact_ip_targets(self.toolbox.ping_hosts(cfg))
        except (OSError, ValueError, sqlite3.Error) as exc:
            self.offer = None
            cfg, listing, targets = {}, [], ()
            self.note.set(f"无法读取本机授权：{exc}")
        self.scope.set("当前工作区：" + (cfg.get("workspace_root", "未授权") if cfg.get("workspace_enabled") else "未授权"))
        ready = self.can_register(cfg)
        if self.offer:
            row = self.offer
            expiry = dt.datetime.fromtimestamp(row["expires_at"]).strftime("%m-%d %H:%M:%S")
            state = "生效" if row.get("active") else "暂停，仍可撤销"
            self.title.set(f"{state}  ·  {LABELS.get(row['preset'], row['preset'])}  ·  剩余 {row['remaining']} 次  ·  {expiry} 到期"
                           + (f"  ·  {row['host']}" if row.get("host") else ""))
            self.scope.set(f"工作区：{row['workspace_root']}  ·  MCP 连接尾号：{row['connection_id'][-8:]}")
            self.code.set(row["request_preset"] if row.get("active") else "")
        else:
            self.title.set("当前没有生效的限时授权" if ready else "请先统一授权工作区并启用本机任务，选择「帮我批准」或「完全访问」")
            self.code.set("")
        create = ready and not self.offer
        for field in (self.connection_entry, self.minutes_field, self.runs_field):
            field.configure(state="normal" if create else "disabled")
        self.presets.configure(state="readonly" if create else "disabled")
        self.targets.configure(values=targets, state="readonly" if create and self.preset() == PING else "disabled")
        if self.host.get() and self.host.get() not in targets:
            self.host.set("")
        for button, enabled in ((self.add_btn, create), (self.revoke_btn, self.offer), (self.copy_btn, self.offer and self.offer.get("active"))):
            button.configure(state="normal" if enabled else "disabled")

    def register(self):
        try:
            cfg = self.load_config()
            if not self.can_register(cfg) or current_offer(self.routines.listing(cfg)):
                raise ValueError("请先启用统一授权和本机任务；已有未到期授权时，先撤销再创建。")
            preset = self.preset()
            if preset not in LABELS:
                raise ValueError("请选择一个固定诊断。")
            connection = self.connection.get().strip()
            if not CONNECTION_ID.fullmatch(connection):
                raise ValueError("请填写 server_info 返回的 24 位小写十六进制连接编号。")
            target = self.host.get() if preset == PING else None
            if preset == PING and target not in exact_ip_targets(self.toolbox.ping_hosts(cfg)):
                raise ValueError("请从本机已有白名单选一个确切的 IP；不接受域名。")
            minutes = bound_number(self.minutes.get(), *self.mins)
            runs = bound_number(self.runs.get(), *self.counts)
            target_note = f"\n确切目标：{target}" if target else ""
            if not messagebox.askyesno("确认给此 MCP 客户端限时诊断权限",
                                       f"工作区：{cfg['workspace_root']}\n连接编号：{connection}\n"
                                       f"诊断：{LABELS[preset]}{target_note}\n期限：{minutes} 分钟，最多 {runs} 次。\n"
                                       "此连接可在上述范围内无需逐次确认；不会自动执行。继续？",
                                       default="no", parent=self.root):
                return
            latest = self.load_config()
            if scope_identity(latest) != scope_identity(cfg) or not self.can_register(latest):
                raise ValueError("确认时工作区或权限已变更；请核对后重试。")
            self.routines.register(preset, connection, latest, host=target, minutes=minutes, runs=runs)
        except (OSError, ValueError, sqlite3.Error) as exc:
            messagebox.showerror("授权未创建", str(exc), parent=self.root)
            self.refresh()
            return
        self.connection.set("")
        self.note.set("已开通一项限时授权。是否使用由你决定；复制指令不会发送。")
        self.refresh()

    def revoke(self):
        offer = self.offer
        if not offer:
            return
        if not messagebox.askyesno("撤销限时授权", "撤销阻止此授权下的新请求，不保证中止已开始的任务。继续？", default="no", parent=self.root):
            return
        try:
            self.routines.revoke(offer["routine_id"])
        except (OSError, ValueError, sqlite3.Error) as exc:
            messagebox.showerror("未能撤销", str(exc), parent=self.root)
        else:
            self.note.set("已撤销当前限时授权。")
        self.refresh()

    def copy(self):
        self.refresh()
        if not self.offer or not self.offer.get("active"):
            return
        message = (f"请只用已配置的 Windows Workspace MCP 连接的 request_windows_project_job 提交一次固定诊断，preset 为 {self.offer['request_preset']}。"
                   "填写一个新的非空 request_key，若因传输错误重试请沿用同一个 key；不要提交路径或 parameters。"
                   "用返回的 job_id 查询结果。仅报告实际结果或错误，不要自动重跑。")
        self.root.clipboard_clear()
        self.root.clipboard_append(message)
        self.note.set("指令已复制；没有发送到客户端。")
