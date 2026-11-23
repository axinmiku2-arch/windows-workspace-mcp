"""Additional tabs on the local Windows console."""
from __future__ import annotations

import json
import os
import sqlite3
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

import core
from recipe_ui import RecipeDialog
import operator_messages
import project_tasks
import transfer_mailbox as mailbox

LABELS = {
    "awaiting_upload": "等 MCP 客户端 发送", "uploading": "传输中", "awaiting_approval": "等待本机批准",
    "delivering": "正在保存", "delivered": "已交付", "received": "MCP 客户端 已验收", "ready": "等 MCP 客户端 取件",
    "queued": "已排队", "copying": "准备中", "running": "执行中", "succeeded": "成功",
    "failed": "失败", "cancelled": "已取消", "cancelling": "取消中", "rejected": "已拒绝",
    "revoked": "授权已撤销", "expired": "已过期", "interrupted": "已中断", "timed_out": "超时",
}


class Extras:
    def __init__(self, owner, books):
        self.view, self.root = owner, owner.root
        self.mail_status = tk.StringVar()
        self.project_state = tk.StringVar()
        self.mail_rows = {}
        self.project_rows = {}
        self.message_rows = {}

        mail = ttk.Frame(books, padding=14)
        books.add(mail, text="收发件箱")
        self.mail_tab = mail
        ttk.Label(mail, text="Windows ⇄ MCP 客户端 文件交付", font=("Microsoft YaHei UI", 13, "bold")).pack(anchor="w")
        ttk.Label(mail, text="按工作区权限发送和接收。完全访问下，校验通过的收件自动保存；其他模式到「待审批」。", wraplength=740).pack(anchor="w", pady=(6, 3))
        ttk.Label(mail, textvariable=self.mail_status, foreground="#315276", wraplength=750).pack(anchor="w", pady=(3, 6))
        mailactions = ttk.Frame(mail)
        mailactions.pack(anchor="w", pady=(2, 8))
        self._buttons(mailactions, [
            ("发送给 MCP 客户端…", self.send_file), ("撤销发件", self.cancel_outgoing),
            ("打开收件目录", self.open_inbox),
        ])
        self.mail_table = owner.table(mail, ("direction", "name", "bytes", "state"),
                                      ("方向", "文件", "进度（字节）", "状态"), (80, 330, 145, 150))
        self.mail_table.bind("<Double-1>", lambda _: self.details_mail())

        project = ttk.Frame(books, padding=14)
        books.add(project, text="本机任务")
        ttk.Label(project, text="本机项目任务", font=("Microsoft YaHei UI", 13, "bold")).pack(anchor="w")
        ttk.Label(project, text="MCP 客户端 可提交文件检查、复制和解包任务。Git、测试和构建到「待审批」确认。", wraplength=740).pack(anchor="w", pady=(6, 3))
        ttk.Label(project, textvariable=self.project_state, foreground="#315276", wraplength=750).pack(anchor="w", pady=(3, 6))
        controls = ttk.Frame(project)
        controls.pack(anchor="w", pady=(2, 8))
        self._buttons(controls, [
            ("取消", lambda: self.project_action("cancel")), ("查看日志", lambda: self.project_action("logs")),
            ("任务配方…", self.open_recipes),
        ])
        self.project_table = owner.table(project, ("tool", "state", "result"),
                                         ("任务", "状态", "退出码"), (390, 155, 125))
        self.project_table.bind("<Double-1>", lambda _: self.project_action("logs"))

        messages = ttk.Frame(books, padding=14)
        books.add(messages, text="消息")
        self.messages_tab = messages
        ttk.Label(messages, text="Windows ⇄ MCP 客户端 留言", font=("Microsoft YaHei UI", 13, "bold")).pack(anchor="w")
        ttk.Label(messages, text="留言保存在本机；MCP 客户端 查询时取走。不会自动发进现有聊天。", wraplength=740).pack(anchor="w", pady=(6, 4))
        self.message_draft = tk.Text(messages, height=3, wrap="word")
        self.message_draft.pack(fill="x", pady=(4, 6))
        actions = ttk.Frame(messages)
        actions.pack(anchor="w", pady=(2, 8))
        self._buttons(actions, [("留言给 MCP 客户端", self.send_message), ("查看留言", lambda: self.message_action(False)),
                                ("标为已读", lambda: self.message_action(True))])
        self.message_table = owner.table(messages, ("direction", "summary", "read"), ("方向", "留言", "状态"), (95, 470, 112))
        self.message_table.bind("<Double-1>", lambda _: self.message_action(False))

    def open_recipes(self):
        current = getattr(self, "recipes_dialog", None)
        if current is not None and current.root.winfo_exists():
            current.root.lift()
            return
        self.recipes_dialog = RecipeDialog(self.root)

    @staticmethod
    def _buttons(parent, actions):
        for name, fn in actions:
            ttk.Button(parent, text=name, command=fn).pack(side="left", padx=(0, 6))

    def send_file(self):
        cfg = core.load_config()
        if not cfg.get("documents_enabled"):
            self.view.msg.set("请先在「工作区与权限」保存统一授权。")
            return
        selected = filedialog.askopenfilename(parent=self.root, initialdir=cfg.get("document_scope") or cfg["workspace_root"],
                                             title="选择发送给 MCP 客户端 的文件")
        if selected:
            self.view.job(lambda: mailbox.queue_outgoing(Path(selected), core.load_config()),
                          "已加入发件箱。请在 MCP 客户端 中查询 Windows 发件箱。", critical=True)

    def open_inbox(self):
        try:
            cfg = core.load_config()
            os.startfile(str(mailbox.validate_receive_scope(cfg.get("receive_scope"), cfg)))
        except (OSError, ValueError, TypeError):
            self.view.msg.set("请先选择并启用一个有效收件目录。")

    def _chosen(self, table):
        selected = table.selection()
        if not selected:
            self.view.msg.set("请先选择列表中的一项。")
            return None
        return selected[0]

    def cancel_outgoing(self):
        ident = self._chosen(self.mail_table)
        if not ident:
            return
        item = self.mail_rows.get(ident, {})
        if item.get("direction") != "outgoing":
            self.view.msg.set("请选中一条发件记录。")
            return
        self.view.job(lambda: mailbox.cancel_outgoing(ident, core.load_config()), "已撤销此发件。", critical=True)

    def project_action(self, action):
        ident = self._chosen(self.project_table)
        if not ident:
            return
        if action == "logs":
            try:
                item = project_tasks.status(ident, core.load_config())
                label = LABELS.get(item["state"], item["state"])
                content = f"{label} · 退出码：{item.get('exit_code', '—')}\n{item.get('message', '')}\n"
                if item.get("output_truncated"):
                    content += "输出较长，以下是末尾片段。\n"
                if item.get("relative_path"):
                    content += f"文件：{item['relative_path']}\n"
                if item.get("destination_path"):
                    content += f"目标：{item['destination_path']}\n"
                source = item.get("submission", {})
                if source.get("transport") == "https_mcp":
                    content += f"提交来源：已认证的 HTTPS MCP · {source['connection_id']}\n"
                elif source.get("transport") == "local":
                    content += "提交来源：本机\n"
                if "result" in item:
                    content += "\n检查结果：\n" + json.dumps(item["result"], ensure_ascii=False, indent=2) + "\n"
                content += f"\n标准输出：\n{item.get('stdout', '')}\n\n错误输出：\n{item.get('stderr', '')}"
                self.show_text(item.get("label", "本机任务"), content)
            except (ValueError, OSError) as exc:
                self.view.msg.set(str(exc))
        elif action == "cancel":
            self.view.job(lambda: project_tasks.cancel(ident, core.load_config()), "已提交任务取消请求。", critical=True)

    def details_mail(self):
        ident = self._chosen(self.mail_table)
        item = self.mail_rows.get(ident, {})
        if not item:
            return
        fields = [
            ("文件", item.get("name")), ("状态", LABELS.get(item.get("state"), item.get("state"))),
            ("大小（字节）", item.get("size_bytes")), ("SHA-256", item.get("sha256")),
            ("保存名称", item.get("saved_name")), ("详情", item.get("error")), ("编号", ident),
        ]
        self.show_text("文件交付详情", "\n".join(f"{name}：{value}" for name, value in fields if value is not None))

    def show_text(self, title, content):
        popup = tk.Toplevel(self.root)
        popup.title(title)
        popup.geometry("740x420")
        holder = ttk.Frame(popup, padding=12)
        holder.pack(fill="both", expand=True)
        text = tk.Text(holder, wrap="word")
        bar = ttk.Scrollbar(holder, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        text.insert("1.0", content)
        text.configure(state="disabled")

    def send_message(self):
        raw = self.message_draft.get("1.0", "end-1c")
        try:
            operator_messages.send("outgoing", raw, core.load_config())
            self.message_draft.delete("1.0", tk.END)
            self.view.msg.set("已保存留言，MCP 客户端 查询时可读取。")
        except (ValueError, OSError, sqlite3.Error) as exc:
            self.view.msg.set(f"留言未发送：{exc}")

    def message_action(self, mark_read):
        key = self._chosen(self.message_table)
        item = self.message_rows.get(key, {})
        if not item:
            return
        if not mark_read:
            self.show_text("留言", item["text"])
        elif item["direction"] != "incoming":
            self.view.msg.set("只可把收到的留言标为已读。")
        else:
            try:
                operator_messages.acknowledge("windows", key, core.load_config())
                self.view.msg.set("已标为已读。")
            except (ValueError, OSError, sqlite3.Error) as exc:
                self.view.msg.set(str(exc))

    @staticmethod
    def _update(table, rows, old, values):
        if rows != old:
            selected = table.selection()
            table.delete(*table.get_children())
            for key, row in rows.items():
                table.insert("", "end", iid=key, values=values(row))
            if selected and table.exists(selected[0]):
                table.selection_set(selected[0])
        return rows

    @staticmethod
    def _mail_columns(row):
        size = row.get("size_bytes") or 0
        complete = row.get("received_bytes", row.get("prepared_bytes", 0)) or 0
        state = row.get("state", "")
        if state in ("ready", "delivered", "received", "awaiting_approval"):
            complete = size
        return ("收件" if row["direction"] == "incoming" else "发件", row["name"], f"{complete:,} / {size:,}",
                LABELS.get(state, state))

    def refresh(self, cfg):
        scope = cfg.get("receive_scope") if cfg.get("receive_enabled") and cfg.get("workspace_enabled") else ""
        self.mail_status.set(f"收件目录：{scope}" if scope else "收件未开启。请先准备本机认证，再选择并启用工作区。")
        scope = cfg.get("task_scope") if cfg.get("task_enabled") and cfg.get("workspace_enabled") else ""
        self.project_state.set(f"项目范围：{scope}" if scope else "请在「工作区与权限」保存统一授权。")
        try:
            info = mailbox.list_mailbox(cfg, limit=12)
            combined = info.get("incoming", []) + info.get("outgoing", [])
            combined.sort(key=lambda row: -row.get("created_at", 0))
            rows = {row["transfer_id"]: row for row in combined}
            self.mail_rows = self._update(self.mail_table, rows, self.mail_rows, self._mail_columns)
            self.view.notify_inbox_count(sum(row["state"] == "awaiting_approval" for row in combined))
        except (OSError, ValueError) as exc:
            self.mail_status.set(str(exc))
        try:
            jobs = project_tasks.listing(cfg).get("jobs", [])
            rows = {row["job_id"]: row for row in jobs}
            self.project_rows = self._update(self.project_table, rows, self.project_rows,
                                             lambda row: (row.get("label"), LABELS.get(row["state"], row["state"]),
                                                          row.get("exit_code", "—")))
        except (OSError, ValueError) as exc:
            self.project_state.set(str(exc))
        try:
            inbox = {}
            if cfg.get("workspace_enabled") and core.uses_funnel(cfg):
                inbox = operator_messages.list_messages("windows", cfg, 12)
                notes = inbox.get("messages", []) + operator_messages.list_messages("dot", cfg, 12).get("messages", [])
            else:
                notes = []
            notes.sort(key=lambda row: -row["created_at"])
            rows = {row["message_id"]: row for row in notes}
            self.message_rows = self._update(self.message_table, rows, self.message_rows,
                                             lambda row: ("来自 MCP 客户端" if row["direction"] == "incoming" else "发给 MCP 客户端",
                                                          row["text"].replace("\n", " ")[:100],
                                                          "已读" if row.get("status") == "read" else "未读"))
            self.view.notify_messages(inbox.get("unread_count", 0))
        except (OSError, ValueError, sqlite3.Error):
            pass
