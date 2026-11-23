"""Local visual styles for the Tk console; no service or state dependencies."""
from __future__ import annotations

import queue
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox, ttk

BG = "#eef3f9"
PANEL = "#ffffff"
INK = "#182640"
MUTED = "#566783"
LINE = "#d8e1ef"
NAVY = "#112349"
BLUE = "#2456d4"
BLUE_HOVER = "#1947be"
BLUE_SOFT = "#eaf1ff"
GREEN = "#10734e"
AMBER = "#8d5400"
RED = "#a12a41"


def install_theme(root):
    """Use portable ttk styles instead of modifying the Windows theme."""
    style = ttk.Style(root)
    style.theme_use("clam")
    root.configure(background=BG)
    family = "Microsoft YaHei UI" if root.tk.call("tk", "windowingsystem") == "win32" else "Noto Sans CJK SC"
    root.option_add("*Font", (family, 10))
    normal = (family, 10)
    strong = (family, 10, "bold")
    style.configure(".", background=PANEL, foreground=INK, font=normal)
    style.configure("Shell.TFrame", background=BG)
    style.configure("Header.TFrame", background=NAVY)
    style.configure("Brand.TLabel", background=NAVY, foreground=PANEL, font=(family, 19, "bold"))
    style.configure("HeaderSub.TLabel", background=NAVY, foreground="#cad7f4", font=normal)
    style.configure("HeaderMode.TLabel", background="#243b6c", foreground=PANEL, font=strong, padding=(10, 5))
    style.configure("HeaderLive.TLabel", background="#164a3d", foreground="#dcf8e9", font=strong, padding=(10, 5))
    style.configure("HeaderWait.TLabel", background="#624820", foreground="#fff0cb", font=strong, padding=(10, 5))
    style.configure("Section.TLabel", font=(family, 15, "bold"))
    style.configure("Headline.TLabel", font=(family, 20, "bold"))
    style.configure("Muted.TLabel", foreground=MUTED)
    style.configure("Card.TFrame", background=PANEL, bordercolor=LINE, borderwidth=1, relief="solid")
    style.configure("MetricLabel.TLabel", foreground=MUTED, font=strong)
    style.configure("Metric.TLabel", foreground=INK, font=(family, 12, "bold"))
    style.configure("Footer.TLabel", background=BG, foreground=MUTED, padding=(1, 0, 0, 0))
    style.configure("TNotebook", background=BG, bordercolor=LINE, borderwidth=1, tabmargins=(0, 0, 0, 0))
    style.configure("TNotebook.Tab", foreground=MUTED, background="#e2eaf6", padding=(13, 9), font=strong)
    style.map("TNotebook.Tab", background=[("selected", PANEL), ("active", BLUE_SOFT)],
              foreground=[("selected", BLUE), ("active", INK)])
    style.configure("TButton", background=PANEL, foreground=INK, bordercolor=LINE, padding=(10, 6))
    style.map("TButton", background=[("pressed", "#dce8ff"), ("active", BLUE_SOFT)], foreground=[("disabled", "#8996ab")])
    style.configure("Primary.TButton", background=BLUE, foreground=PANEL, bordercolor=BLUE, font=strong, padding=(15, 7))
    style.map("Primary.TButton", background=[("disabled", "#9eadd1"), ("pressed", "#163991"), ("active", BLUE_HOVER)],
              foreground=[("disabled", PANEL)])
    style.configure("Danger.TButton", foreground=RED)
    style.configure("TEntry", fieldbackground=PANEL, bordercolor=LINE, padding=5)
    style.configure("TCombobox", fieldbackground=PANEL, bordercolor=LINE, padding=5)
    style.map("TCombobox", fieldbackground=[("readonly", PANEL)], selectbackground=[("readonly", PANEL)],
              selectforeground=[("readonly", INK)])
    style.configure("Treeview", rowheight=28, foreground=INK, fieldbackground=PANEL, background=PANEL, bordercolor=LINE)
    style.configure("Treeview.Heading", background=BLUE_SOFT, foreground=INK, font=strong, padding=(7, 5))
    style.map("Treeview", background=[("selected", BLUE_SOFT)], foreground=[("selected", "#153989")])
    return family


def make_header(parent, status, name="Windows Workspace MCP"):
    band = ttk.Frame(parent, padding=(18, 12), style="Header.TFrame")
    band.pack(fill="x", pady=(0, 12))
    band.columnconfigure(0, weight=1)
    ttk.Label(band, text=name, style="Brand.TLabel").grid(row=0, column=0, sticky="w")
    ttk.Label(band, text="Windows 本机控制台  /  连接、文件与工作区", style="HeaderSub.TLabel").grid(row=1, column=0, sticky="w", pady=(3, 0))
    pill = ttk.Label(band, textvariable=status, style="HeaderMode.TLabel", anchor="center")
    pill.grid(row=0, column=1, rowspan=2, sticky="e", padx=(10, 0))
    return pill


def summary_cards(parent, items):
    holder = ttk.Frame(parent)
    for column, (title, value, width) in enumerate(items):
        holder.columnconfigure(column, weight=width, uniform="summary")
        card = ttk.Frame(holder, style="Card.TFrame", padding=(13, 10))
        card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 7, 0))
        ttk.Label(card, text=title, style="MetricLabel.TLabel").pack(anchor="w")
        label = ttk.Label(card, textvariable=value, style="Metric.TLabel", justify="left")
        label.pack(anchor="w", fill="x", pady=(3, 0))
        card.bind("<Configure>", lambda event, widget=label: widget.configure(wraplength=max(60, event.width - 28)))
    return holder


def place_dialog(dialog, parent, title):
    dialog.title(title)
    dialog.transient(parent)
    dialog.configure(background=BG)
    dialog.resizable(False, False)
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.bind("<Escape>", lambda _event: dialog.destroy())
    body = ttk.Frame(dialog, padding=20)
    body.pack(fill="both", expand=True)
    return body


def connect_note(start, check, origin):
    """Start with existing privileges, and describe the independent endpoint probe."""
    start()
    reachable, summary = check(origin)
    if reachable:
        return "公网入口已响应。工作器连通状态见顶部。"
    return "已请求启动工作器。公网检测未通过：" + summary


TOOLBOX_CATALOG = (
    ("windows_ipconfig", "网络配置", "查看活跃网卡数量和 IPv4/IPv6 状态；不返回 IP。"),
    ("windows_listening_ports", "本机监听端口", "仅报告本机 TCP / UDP 端口号；不扫描远端。"),
    ("windows_ping", "Ping 指定主机", "每次查询仅限一个已列入下方清单的确切目标。"),
)


def toolbox_rows(presets, workspace_operations, cfg):
    task_status = ("工作区未授权" if not cfg.get("workspace_enabled") else
                   "逐次本机批准" if cfg.get("task_enabled") else "本机任务未启用")
    rows = [(label, description, task_status) for key, label, description in TOOLBOX_CATALOG if key in presets]
    if "workspace_move" in workspace_operations:
        automatic = (cfg.get("workspace_unified") and cfg.get("approval_mode") == "full"
                     and "workspace_move" in cfg.get("automatic_operations", ()))
        status = ("工作区未授权" if not cfg.get("workspace_enabled") else
                  "按本机配置自动批准" if automatic else "逐次本机批准")
        rows.append(("移动 / 改名", "仅在当前授权工作区内，不覆盖目标。", status))
    return rows


class ToolboxDialog:
    """Present registered actions and edit a local-only Ping policy; never runs commands."""

    def __init__(self, owner, presets, workspace_operations, cfg, backend, submit=None, power=None, routines=None):
        self.owner = owner
        self.backend = backend
        self.root = tk.Toplevel(owner)
        body = place_dialog(self.root, owner, "Windows 固定工具箱")
        self.root.resizable(True, True)
        self.root.minsize(690, 540)
        ttk.Label(body, text="Windows 固定工具箱", style="Section.TLabel").pack(anchor="w")
        ttk.Label(body, text="普通诊断在「待审批」核对；下方配置 Ping 白名单，不会执行命令。",
                  style="Muted.TLabel", wraplength=680, justify="left").pack(anchor="w", pady=(4, 10))
        card = ttk.Frame(body, style="Card.TFrame", padding=(12, 9))
        card.pack(fill="x")
        card.columnconfigure(1, weight=1)
        for column, heading in enumerate(("固定操作", "用途", "打开时审批状态")):
            ttk.Label(card, text=heading, style="MetricLabel.TLabel").grid(row=0, column=column, sticky="w", padx=(0, 12))
        rows = toolbox_rows(presets, workspace_operations, cfg)
        for row, (label, description, status) in enumerate(rows, 1):
            for column, value in enumerate((label, description, status)):
                ttk.Label(card, text=value, wraplength=340 if column == 1 else 145).grid(
                    row=row, column=column, sticky="w", padx=(0, 12), pady=(5, 0))
        if not rows:
            ttk.Label(card, text="当前版本未注册固定操作。", style="Muted.TLabel").grid(row=1, column=0, columnspan=3, sticky="w")
        can_submit = submit is not None and cfg.get("workspace_enabled") and cfg.get("task_enabled")
        if can_submit:
            requests = ttk.Frame(body)
            requests.pack(fill="x", pady=(8, 0))
            for key, label, _ in TOOLBOX_CATALOG[:2]:
                if key in presets:
                    ttk.Button(requests, text="申请" + label, command=lambda op=key: submit(op, None)).pack(side="left", padx=(0, 7))
        ttk.Label(body, text="Ping 本机白名单", style="MetricLabel.TLabel").pack(anchor="w", pady=(11, 2))
        max_hosts = getattr(backend, "MAX_HOSTS", 20)
        ttk.Label(body, text=f"每行一个确切的完整主机名或 IP，最多 {max_hosts} 条。留空不放行；域名每次重新解析。\n"
                             "只影响此 Ping 工具，不是 Windows 防火墙。",
                  style="Muted.TLabel", wraplength=680, justify="left").pack(anchor="w")
        editor = ttk.Frame(body)
        editor.pack(fill="both", expand=True, pady=(6, 7))
        self.editor = tk.Text(editor, height=4, undo=True, wrap="none", background=PANEL, foreground=INK, relief="solid",
                              borderwidth=1, highlightthickness=0, padx=7, pady=5)
        bar = ttk.Scrollbar(editor, orient="vertical", command=self.editor.yview)
        self.editor.configure(yscrollcommand=bar.set)
        self.editor.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        self.note = tk.StringVar(value="")
        self.saved = None
        if "windows_ping" in presets and callable(getattr(backend, "ping_hosts", None)) and callable(getattr(backend, "save_ping_hosts", None)):
            try:
                self.saved = tuple(backend.ping_hosts())
                self.editor.insert("1.0", "\n".join(self.saved))
                self.note.set(f"已配置 {len(self.saved)} 个 Ping 目标。")
            except (OSError, ValueError) as exc:
                self.note.set(f"无法读取 Ping 白名单：{exc}")
        else:
            self.note.set("此版本没有可配置的 Ping 白名单。")
        if self.saved is None:
            self.editor.configure(state="disabled")
        ttk.Label(body, textvariable=self.note, style="Muted.TLabel", wraplength=680).pack(anchor="w")
        self.ping_choice = None
        if can_submit and self.saved is not None:
            pingbar = ttk.Frame(body)
            pingbar.pack(fill="x", pady=(7, 0))
            selected = tk.StringVar()
            self.ping_choice = ttk.Combobox(pingbar, textvariable=selected, values=self.saved, state="readonly", width=34)
            self.ping_choice.pack(side="left", padx=(0, 7))

            def request_ping():
                host = selected.get()
                if host not in self.saved:
                    self.note.set("请从已保存的白名单选择要 Ping 的目标。")
                    return
                submit("windows_ping", {"host": host})

            ttk.Button(pingbar, text="申请 Ping", command=request_ping).pack(side="left")
        ttk.Label(body, text="不开放任意 CMD / PowerShell 或管理员提权。关机功能不对 MCP 客户端开放。",
                  style="Muted.TLabel", wraplength=680, justify="left").pack(anchor="w", pady=(6, 0))
        if power is not None:
            power.add_controls(body)
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="保存 Ping 白名单", command=self.save, style="Primary.TButton",
                   state="normal" if self.saved is not None else "disabled").pack(side="left", padx=(0, 8))
        if routines is not None:
            ttk.Button(buttons, text="固定诊断限时授权…", command=routines).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="关闭", command=self.root.destroy).pack(side="left")

    def save(self):
        if self.saved is None:
            return
        hosts = [line.strip() for line in self.editor.get("1.0", "end-1c").splitlines() if line.strip()]
        try:
            if tuple(self.backend.ping_hosts()) != self.saved:
                raise ValueError("清单已在本机其他窗口更新，请关闭重开后再编辑。")
            saved = self.backend.save_ping_hosts(hosts)
        except (ValueError, OSError) as exc:
            messagebox.showerror("白名单未保存", str(exc), parent=self.root)
            return
        self.saved = tuple(saved)
        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", "\n".join(self.saved))
        if self.ping_choice is not None:
            self.ping_choice.configure(values=self.saved)
            self.ping_choice.set("")
        self.note.set(f"Ping 白名单已保存：{len(self.saved)} 个目标。普通请求仍须本机批准。")


class LocalPower:
    """Visible, manager-bound timer controlled by the local UI only."""

    def __init__(self, owner, backend):
        self.root = owner
        self.backend = backend
        self.timer = backend.LocalShutdownTimer()
        self.message = tk.StringVar()
        self.completed = queue.Queue()
        self.dispatching = False
        self.notice = None
        self.cancel_buttons = []
        owner.bind("<Destroy>", self.on_close, add="+")
        owner.after(500, self.tick)

    def add_banner(self, parent):
        self.notice = ttk.Frame(parent, padding=(9, 5), style="Card.TFrame")
        ttk.Label(self.notice, textvariable=self.message, style="Muted.TLabel", wraplength=690).pack(side="left", fill="x", expand=True)
        self.add_cancel(self.notice, side="right")

    def add_cancel(self, parent, side="left"):
        button = ttk.Button(parent, text="取消关机倒计时", command=self.cancel, style="Danger.TButton")
        button.pack(side=side, padx=(6, 0))
        self.cancel_buttons.append(button)
        self.render()

    def add_controls(self, parent):
        card = ttk.Frame(parent, style="Card.TFrame", padding=(10, 7))
        card.pack(fill="x", pady=(9, 0))
        ttk.Label(card, text="仅本机 · 计划关机", style="MetricLabel.TLabel").pack(anchor="w")
        ttk.Label(card, text="只在此管理器保持打开时倒计时；关闭主窗口会取消。不强制关闭程序，请先保存。",
                  style="Muted.TLabel", wraplength=680).pack(anchor="w", pady=(3, 0))
        row = ttk.Frame(card)
        row.pack(anchor="w", pady=(6, 0))
        minutes = tk.StringVar(value="5")
        ttk.Spinbox(row, from_=self.backend.MIN_MINUTES, to=self.backend.MAX_MINUTES, width=5, textvariable=minutes).pack(side="left")
        ttk.Label(row, text="分钟").pack(side="left", padx=(4, 6))
        ttk.Button(row, text="设置关机倒计时…", command=lambda: self.schedule(minutes.get(), parent.winfo_toplevel())).pack(side="left")
        self.add_cancel(row)
        ttk.Label(card, textvariable=self.message, style="Muted.TLabel", wraplength=680).pack(anchor="w", pady=(4, 0))

    def schedule(self, text, parent):
        text = text.strip()
        if not text.isascii() or not text.isdecimal() or len(text) > len(str(self.backend.MAX_MINUTES)):
            value = 0
        else:
            value = int(text)
        if not self.backend.MIN_MINUTES <= value <= self.backend.MAX_MINUTES:
            messagebox.showerror("关机倒计时未设置", f"请输入 {self.backend.MIN_MINUTES}–{self.backend.MAX_MINUTES} 分钟之间的整数。", parent=parent)
            return
        if self.dispatching or self.timer.seconds_remaining() is not None:
            messagebox.showerror("关机倒计时未设置", "已有倒计时或正在处理关机请求。", parent=parent)
            return
        if not messagebox.askyesno("确认在本机设置关机倒计时", f"在 {value} 分钟后请求关闭这台 Windows 电脑？\n"
                                   "请先保存文件。主窗口关闭可取消；请求发给 Windows 后不能在小助手内取消。",
                                   default="no", parent=parent):
            return
        try:
            self.timer.schedule(value)
        except ValueError as exc:
            messagebox.showerror("关机倒计时未设置", str(exc), parent=parent)
            return
        self.render()

    def cancel(self):
        if self.timer.cancel():
            self.message.set("已取消关机倒计时；未发送 Windows 关机请求。")
        self.render()

    def on_close(self, event):
        if event.widget is self.root:
            self.timer.cancel()

    def render(self):
        seconds = self.timer.seconds_remaining()
        if seconds is not None:
            minutes, remainder = divmod(seconds, 60)
            self.message.set(f"本机关机倒计时：{minutes:02d}:{remainder:02d} · 关闭管理器会取消")
        active = seconds is not None
        self.cancel_buttons = [button for button in self.cancel_buttons if button.winfo_exists()]
        for button in self.cancel_buttons:
            button.configure(state="normal" if active else "disabled")
        if self.notice is not None and self.message.get():
            self.notice.pack(fill="x", pady=(7, 0))

    def _dispatch(self):
        self.dispatching = True
        self.message.set("正在向 Windows 发送正常关机请求；此时无法在小助手内取消。")

        def run():
            try:
                self.backend.request_local_shutdown()
            except subprocess.TimeoutExpired:
                self.completed.put("等待 Windows 响应超时，无法确认是否接受关机请求；未重试。")
            except OSError as exc:
                self.completed.put(f"无法确认 Windows 已接受关机：{exc}")
            else:
                self.completed.put("已向 Windows 请求关机；不会强制关闭程序。")

        threading.Thread(target=run, daemon=True).start()

    def tick(self):
        try:
            note = self.completed.get_nowait()
        except queue.Empty:
            pass
        else:
            self.dispatching = False
            self.message.set(note)
        if self.timer.tick(self._dispatch) == "cancelled_late":
            self.message.set("倒计时因休眠或界面暂停而过期；未关机。")
        self.render()
        self.root.after(500, self.tick)
