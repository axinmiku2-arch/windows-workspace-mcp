"""Local-only registry for named sequences of typed workspace tasks."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
import time

import core
import task_files
import task_verification
from workspace import relative_parts

REGISTRY = core.STATE / "task-recipes.json"
SLUG = re.compile(r"[a-z][a-z0-9_-]{1,31}\Z")
PREFIX = "recipe:"
MAX_RECIPES = 12
MAX_STEPS = 5
MAX_REGISTRY_BYTES = 64_000
PROJECT_OPERATIONS = {
    "git_status": {"label": "Git 状态", "target": "directory", "approval": True},
    "git_diff": {"label": "Git 未暂存差异", "target": "directory", "approval": True},
    "git_diff_staged": {"label": "Git 已暂存差异", "target": "directory", "approval": True},
    "python_build_check": {"label": "Python 源码语法检查", "target": "directory", "approval": False},
    "python_unittest": {"label": "运行 Python unittest", "target": "directory", "approval": True, "writes": True},
    "npm_test": {"label": "运行 npm test", "target": "directory", "approval": True, "writes": True},
    "npm_build": {"label": "运行 npm run build", "target": "directory", "approval": True, "writes": True},
}
OPERATIONS = {**task_verification.PRESETS, **task_files.PRESETS, **PROJECT_OPERATIONS}
EXAMPLE = {
    "id": "inspect-zip", "label": "核对 ZIP 哈希和完整性", "target": "file",
    "steps": [{"preset": "file_sha256"}, {"preset": "zip_inspect"}],
}
TEMPLATES = {
    "检查 ZIP": EXAMPLE,
    "校验 ZIP 后解包": {"id": "verify-unpack", "label": "校验 ZIP 后解包", "target": "file",
                         "steps": [{"preset": "zip_inspect"}, {"preset": "zip_extract"}]},
    "记录哈希后复制": {"id": "hash-copy", "label": "记录哈希后复制文件", "target": "file",
                       "steps": [{"preset": "file_sha256"}, {"preset": "copy_file"}]},
    "校验文本后生成 DOCX": {"id": "hash-docx", "label": "记录哈希后生成纯文本 DOCX", "target": "file",
                         "steps": [{"preset": "file_sha256"}, {"preset": "text_to_docx"}]},
    "静态检查 Windows 程序": {"id": "inspect-pe", "label": "记录哈希并查看 PE 文件头", "target": "file",
                         "steps": [{"preset": "file_sha256"}, {"preset": "pe_inspect"}]},
    "盘点后复制目录": {"id": "inventory-copy", "label": "盘点后复制目录", "target": "directory",
                       "steps": [{"preset": "directory_inventory", "parameters": {"max_depth": 2}},
                                 {"preset": "copy_directory"}]},
    "Python 语法检查后测试": {"id": "python-check-test", "label": "Python 语法检查后测试", "target": "directory",
                             "steps": [{"preset": "python_build_check"}, {"preset": "python_unittest"}]},
    "npm 测试后构建": {"id": "npm-test-build", "label": "npm 测试后构建", "target": "directory",
                       "steps": [{"preset": "npm_test"}, {"preset": "npm_build"}]},
}
DEFAULTS = (EXAMPLE, TEMPLATES["Python 语法检查后测试"], TEMPLATES["npm 测试后构建"])


def normalize(definition):
    if not isinstance(definition, dict) or set(definition) != {"id", "label", "target", "steps"}:
        raise ValueError("配方需要 id、label、target 和 steps 四项。")
    ident, label, target, steps = (definition[k] for k in ("id", "label", "target", "steps"))
    if not isinstance(ident, str) or not SLUG.fullmatch(ident):
        raise ValueError("配方 ID 用 2–32 个小写字母、数字、连字符或下划线，首位须为字母。")
    if not isinstance(label, str) or not 1 <= len(label.strip()) <= 56 or not label.strip().isprintable():
        raise ValueError("配方名称须为 1–56 个可显示字符。")
    if target not in ("file", "directory"):
        raise ValueError("target 只能是 file 或 directory。")
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise ValueError("每个配方需要 1–5 步。")
    normalized = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or "preset" not in step or set(step) - {"preset", "parameters"}:
            raise ValueError("每步只接受 preset 与可选的 parameters。")
        preset = step["preset"]
        if not isinstance(preset, str) or preset not in OPERATIONS or OPERATIONS[preset]["target"] != target:
            raise ValueError("所有步骤须来自内置任务目录，并使用同一种输入。")
        params = step.get("parameters", {})
        if not isinstance(params, dict):
            raise ValueError("步骤参数须为 JSON 对象。")
        if preset in task_files.PRESETS:
            if index != len(steps) - 1:
                raise ValueError("复制或解包以及其他写入目标的步骤只能放在最后。")
            if set(params) - {"destination_path"}:
                raise ValueError("写入目标的步骤只支持 destination_path 参数。")
            if "destination_path" in params:
                if not isinstance(params["destination_path"], str):
                    raise ValueError("destination_path 必须是工作区相对路径。")
                params = {"destination_path": "/".join(relative_parts(params["destination_path"]))}
        elif preset in PROJECT_OPERATIONS:
            if params:
                raise ValueError("项目命令不能自定义命令行、参数或环境变量。")
        else:
            params = task_verification.arguments(preset, params)
        normalized.append({"preset": preset, "parameters": params})
    return {"id": ident, "label": label.strip(), "target": target, "steps": normalized}


def _load():
    try:
        with REGISTRY.open("rb") as handle:
            raw = handle.read(MAX_REGISTRY_BYTES + 1)
    except FileNotFoundError:
        return {recipe["id"]: normalize(deepcopy(recipe)) for recipe in DEFAULTS}
    if len(raw) > MAX_REGISTRY_BYTES:
        raise ValueError("Task recipes exceed the local registry size limit.")
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("配方登记文件格式无效。") from exc
    if not isinstance(document, dict) or set(document) != {"recipes"} or not isinstance(document["recipes"], list):
        raise ValueError("配方登记文件格式无效。")
    records = document["recipes"]
    if len(records) > MAX_RECIPES:
        raise ValueError("Too many registered local recipes.")
    result = {}
    for entry in records:
        recipe = normalize(entry)
        if recipe["id"] in result:
            raise ValueError("配方 ID 重复。")
        result[recipe["id"]] = recipe
    return result


def listing():
    return list(_load().values())


def get(ident):
    return _load().get(ident) if isinstance(ident, str) and SLUG.fullmatch(ident) else None


def revision(recipe):
    canonical = json.dumps(recipe, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def writes(recipe):
    return any(OPERATIONS[step["preset"]].get("writes") for step in recipe["steps"])


def can_choose_destination(recipe):
    last = recipe["steps"][-1]
    return last["preset"] in task_files.PRESETS and "destination_path" not in last["parameters"]


def arguments(recipe, params):
    if params in (None, {}):
        return {}
    if not can_choose_destination(recipe) or not isinstance(params, dict) or set(params) != {"destination_path"}:
        raise ValueError("This recipe does not accept the supplied runtime parameters.")
    return params


def _save(records):
    body = {"recipes": list(records.values())}
    for delay in (0, 0.04, 0.10, 0.25):
        if delay:
            time.sleep(delay)
        try:
            core.save_json(REGISTRY, body)
            return
        except PermissionError as exc:
            if delay == 0.25 or getattr(exc, "winerror", None) not in (None, 5, 32, 33):
                raise


def register(definition):
    """Used only by the local Windows manager; not an RPC operation."""
    recipe = normalize(definition)
    records = _load()
    if recipe["id"] not in records and len(records) >= MAX_RECIPES:
        raise ValueError("最多可保存 12 个配方。")
    records[recipe["id"]] = recipe
    _save(records)
    return recipe


def remove(ident):
    records = _load()
    if ident not in records:
        raise ValueError("配方不存在。")
    del records[ident]
    _save(records)
