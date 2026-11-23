"""Editor for the local registry of callable Windows task recipes."""
from __future__ import annotations

import json
import tkinter as tk
from tkinter import messagebox, ttk

import task_recipes as recipes


class RecipeDialog:
    def __init__(self, root):
        self.root = tk.Toplevel(root)
        self.root.title("Windows Workspace MCP · 任务配方")
        self.root.geometry("790x550")
        self.root.minsize(640, 465)
        self.root.transient(root)
        container = ttk.Frame(self.root, padding=14)
        container.pack(fill="both", expand=True)
        ttk.Label(container, text="本机任务配方", font=("Microsoft YaHei UI", 15, "bold")).pack(anchor="w")
        ttk.Label(container, text="保存后 客户端可用 recipe:ID 调用。复制或解包只能放最后；项目命令按原规则审批。").pack(anchor="w", pady=(4, 10))
        body = ttk.Frame(container)
        body.pack(fill="both", expand=True)
        self.items = tk.Listbox(body, width=25, exportselection=False)
        self.items.pack(side="left", fill="y", padx=(0, 12))
        self.items.bind("<<ListboxSelect>>", self.select)
        details = ttk.Frame(body)
        details.pack(side="left", fill="both", expand=True)
        self.id = tk.StringVar()
        self.label = tk.StringVar()
        self.target = tk.StringVar(value="file")
        self.template = tk.StringVar(value="检查 ZIP")
        self.action = tk.StringVar(value="file_sha256")
        self.status = tk.StringVar()
        self.records = []

        controls = ttk.Frame(details)
        controls.pack(fill="x", pady=(0, 6))
        ttk.Combobox(controls, textvariable=self.template, values=tuple(recipes.TEMPLATES),
                     state="readonly", width=21).pack(side="left")
        ttk.Button(controls, text="载入示例", command=self.load_template).pack(side="left", padx=(5, 0))
        for name, var in (("ID", self.id), ("显示名称", self.label)):
            row = ttk.Frame(details)
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=name, width=10).pack(side="left")
            ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True)
        row = ttk.Frame(details)
        row.pack(fill="x", pady=(3, 6))
        ttk.Label(row, text="输入类型", width=10).pack(side="left")
        ttk.Combobox(row, textvariable=self.target, values=("file", "directory"), state="readonly",
                     width=12).pack(side="left")
        ttk.Combobox(row, textvariable=self.action, values=tuple(recipes.OPERATIONS),
                     state="readonly", width=24).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="添加步骤", command=self.append).pack(side="left", padx=(5, 0))
        self.steps = tk.Text(details, height=12, wrap="none")
        self.steps.pack(fill="both", expand=True)
        footer = ttk.Frame(container)
        footer.pack(fill="x", pady=(10, 0))
        for label, handler in (("保存配方", self.save), ("撤下配方", self.remove), ("复制调用名", self.copy_name)):
            ttk.Button(footer, text=label, command=handler).pack(side="left", padx=(0, 7))
        ttk.Label(container, textvariable=self.status, wraplength=700).pack(anchor="w", pady=(7, 0))
        self.refresh()
        if self.records:
            self.items.selection_set(0)
            self.select()
        else:
            self.load_template()

    def show(self, definition):
        self.id.set(definition["id"])
        self.label.set(definition["label"])
        self.target.set(definition["target"])
        self.render_steps(definition["steps"])

    def render_steps(self, steps):
        self.steps.delete("1.0", tk.END)
        self.steps.insert("1.0", json.dumps(steps, ensure_ascii=False, indent=2))

    def read_steps(self):
        try:
            value = json.loads(self.steps.get("1.0", "end-1c"))
        except ValueError as exc:
            raise ValueError("步骤需要是有效的 JSON 列表。") from exc
        if not isinstance(value, list):
            raise ValueError("步骤需要是 JSON 列表。")
        return value

    def load_template(self):
        self.items.selection_clear(0, tk.END)
        self.show(recipes.TEMPLATES[self.template.get()])

    def append(self):
        try:
            step = self.action.get()
            if recipes.OPERATIONS[step]["target"] != self.target.get():
                raise ValueError("步骤的输入类型须与配方一致。")
            current = self.read_steps()
            if len(current) >= recipes.MAX_STEPS:
                raise ValueError("最多 5 步。")
            self.render_steps([*current, {"preset": step}])
        except (KeyError, ValueError) as exc:
            self.status.set(str(exc))

    def refresh(self, selected=None):
        try:
            self.records = recipes.listing()
        except (OSError, ValueError) as exc:
            self.records = []
            self.status.set(str(exc))
        self.items.delete(0, tk.END)
        for index, item in enumerate(self.records):
            self.items.insert(tk.END, item["label"])
            if item["id"] == selected:
                self.items.selection_set(index)
                self.items.see(index)

    def select(self, _event=None):
        selected = self.items.curselection()
        if selected:
            self.show(self.records[selected[0]])
            self.status.set("MCP 调用名：recipe:" + self.id.get())

    def save(self):
        try:
            saved = recipes.register({"id": self.id.get().strip(), "label": self.label.get(),
                                      "target": self.target.get(), "steps": self.read_steps()})
            self.refresh(saved["id"])
            self.show(saved)
            self.status.set("已保存。MCP 调用名：recipe:" + saved["id"])
        except (OSError, ValueError) as exc:
            self.status.set(str(exc))

    def remove(self):
        try:
            ident = self.id.get().strip()
            if not messagebox.askyesno("撤下配方", f"撤下 recipe:{ident}？已生成的文件保留。",
                                       parent=self.root):
                return
            recipes.remove(ident)
            self.refresh()
            self.status.set("配方已撤下。")
        except (OSError, ValueError) as exc:
            self.status.set(str(exc))

    def copy_name(self):
        try:
            ident = self.id.get().strip()
            if not recipes.get(ident):
                raise ValueError("请先保存此配方。")
            name = "recipe:" + ident
            self.root.clipboard_clear()
            self.root.clipboard_append(name)
            self.status.set("已复制：" + name)
        except (OSError, ValueError) as exc:
            self.status.set(str(exc))
