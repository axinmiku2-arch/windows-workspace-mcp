"""Windows-side workspace policy. The relay cannot grant itself local approval."""
from __future__ import annotations

import hashlib
import ctypes
import json
import math
import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time

from core import (APPROVAL_MINUTES_DEFAULT, HIDDEN, OPTIONAL_FULL_OPERATION_IDS, RUNTIME, STATE,
                  read_json, save_json, load_config, relay_pythonw, uses_funnel)
from file_bridge import (DOCUMENT_TYPES, LEGACY_SYNC_MAX_BYTES, begin_archive, begin_export,
                         clear_expired, raw_exportable, snapshot, transfer_max_bytes)

PENDING = STATE / "approvals.json"
APPROVAL_JOURNAL = STATE / "workspace-approval-journal.json"
APPROVAL_ID = re.compile(r"[a-f0-9]{24}\Z")
APPROVAL_QUEUE_LIMIT = 12
APPROVAL_RESULT_LIMIT = 40
APPROVAL_RESULT_TTL = 24 * 3600
APPROVAL_POLICY_FIELDS = frozenset({"workspace_root", "workspace_revision", "approval_mode", "origin",
                                    "automatic_operations", "workspace_unified"})
APPROVAL_DOCUMENT_FIELDS = frozenset({"documents_enabled", "document_scope", "document_revision"})
AUDIT = STATE / "workspace-audit.json"
DECISIONS = STATE / "decisions"
BACKUPS = STATE / "workspace-backups"
MODE_LABELS = {"ask": "请求批准（每次操作）", "rules": "帮我批准（按本机规则）", "full": "完全访问（工作区范围）"}
OPERATIONS = {"workspace_list": "列目录", "workspace_search": "找文件", "workspace_read": "读文件",
              "workspace_create": "新建文件", "workspace_replace": "修改文件",
              "workspace_preview_document": "预览文档", "workspace_export_file": "发送文件原件",
              "workspace_export_start": "准备下载文件原件", "workspace_archive_start": "打包文件夹并准备下载"}
EXTRA_OPERATIONS = {
    "workspace_read_lines": "按行读取文本", "workspace_search_content": "搜索文件正文",
    "workspace_patch": "局部修改文本", "workspace_create_folder": "新建文件夹",
    "workspace_move": "移动或改名", "workspace_trash": "移动到小助手回收站",
    "workspace_restore": "还原回收站项目", "workspace_list_trash": "查看小助手回收站",
}
EXTRA_READS = {"workspace_read_lines", "workspace_search_content", "workspace_list_trash"}
EXTRA_ALWAYS_APPROVE = OPTIONAL_FULL_OPERATION_IDS  # also used for approval identity capture
OPTIONAL_FULL_AUTOMATIC = {op: EXTRA_OPERATIONS[op] for op in sorted(OPTIONAL_FULL_OPERATION_IDS)}
OPERATIONS.update(EXTRA_OPERATIONS)
READS = {"workspace_list", "workspace_search", "workspace_read", "workspace_preview_document"}
READS.update(EXTRA_READS)
EXPORT_OPERATIONS = {"workspace_export_file", "workspace_export_start", "workspace_archive_start"}
DOCUMENT_OPERATIONS = {"workspace_preview_document", *EXPORT_OPERATIONS}
PREVIEW_MAX_BYTES = 20_000_000
LIMIT = 8192
MAX_DEPTH = 8
PAGE_SIZE = 24
PAGE_BUDGET_BYTES = 26000
SEARCH_BUDGET = 5000
EXTENSION_FILTER = re.compile(r"\.[a-z0-9][a-z0-9._+-]{0,24}\Z")
EXTENSIONS = {".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".toml", ".yaml", ".yml", ".xml",
              ".py", ".js", ".ts", ".css", ".html", ".sql", ".ini", ".cfg", ".rst", ".log", ".srt",
              ".vue", ".jsx", ".tsx", ".c", ".cpp", ".h", ".go", ".rs", ".java", ".rb"}
BLOCKED_PART = {"windows", "program files", "program files (x86)", "programdata", "system volume information",
                "$recycle.bin", "appdata", "node_modules", "__pycache__", "recovery", "boot", "efi",
                "windowsapps", "wpsystem", "windowsworkspacemcp", "dot-mcp-本机状态", "dot-mcp-工具包"}
BLOCKED_NAME = re.compile(r"(?:^|[._-])(?:credentials?|secrets?|passwords?|private[._-]?key|id_rsa|id_ed25519)(?:$|[._-])", re.I)


def clean_part(part):
    return (bool(part) and not part.startswith(".") and not part.endswith((".", " ")) and
            not re.search(r'[:<>"|?*\x00-\x1f]|~[0-9]+(?:\.|$)', part) and part.lower() not in BLOCKED_PART and
            not BLOCKED_NAME.search(part) and not PureWindowsPath(part).is_reserved())


def no_link(item, directory):
    attrs = item.lstat()
    if getattr(attrs, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("Symbolic links, junctions and reparse points are not accessible")
    if directory and not stat.S_ISDIR(attrs.st_mode):
        raise ValueError("Expected a normal directory")
    if not directory and (not stat.S_ISREG(attrs.st_mode) or attrs.st_nlink != 1):
        raise ValueError("Expected a normal file without hard links")
    return attrs


def local_drives():
    """Drive root choices; mapped network shares and optical media are excluded."""
    kernel = ctypes.windll.kernel32
    mask = kernel.GetLogicalDrives()
    return [f"{letter}:\\" for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            if mask & (1 << i) and kernel.GetDriveTypeW(f"{letter}:\\") in (2, 3, 6)]


def protected_path(path):
    return any(path == ref or ref in path.parents for ref in (STATE, RUNTIME.parent))


def workspace_root(value):
    root = Path(value)
    if (not re.fullmatch(r"[A-Za-z]:", root.drive) or not root.is_absolute() or
            any(not clean_part(p) for p in root.parts[1:]) or root == Path.home()):
        raise ValueError("请选择本地盘符根目录（例如 D:\\）或其下的非系统文件夹。")
    if protected_path(root):
        raise ValueError("不能授权 Dot MCP 的程序、配置或凭据目录。")
    if root.anchor.upper() not in local_drives():
        raise ValueError("请选择在线的本地盘符；不支持映射的网络盘。")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        no_link(current, True)
    actual = root.resolve(strict=True)
    if actual != root or protected_path(actual) or not all(clean_part(p) for p in actual.parts[1:]):
        raise ValueError("选择实际的工作区文件夹路径，不要使用路径别名。")
    return actual


def relative_parts(value, allow_dot=False):
    if allow_dot and value in ("", "."):
        return []
    if not isinstance(value, str) or len(value) > 224:
        raise ValueError("Provide a short relative path")
    parts = re.split(r"[\\/]", value)
    if len(parts) > MAX_DEPTH or not all(clean_part(p) for p in parts):
        raise ValueError("Not an allowed relative path")
    return parts


def resolve(root, value, *, folder=False, new=False, extensions=EXTENSIONS):
    parts = relative_parts(value, folder)
    current = root
    for part in parts[:-1]:
        current /= part
        if protected_path(current):
            raise ValueError("Protected application or credential directory")
        no_link(current, True)
    if not parts:
        return root
    path = current / parts[-1]
    if protected_path(path):
        raise ValueError("Protected application or credential directory")
    if not folder and extensions is not None and path.suffix.lower() not in extensions:
        raise ValueError("This file format is not allowed for the requested operation")
    if new:
        try:
            path.lstat()
        except FileNotFoundError:
            return path
        raise ValueError("File exists; create cannot overwrite")
    no_link(path, folder)
    return path


def visible_entries(folder):
    for p in folder.iterdir():
        if not clean_part(p.name) or protected_path(p):
            continue
        try:
            attrs = p.lstat()
            if getattr(attrs, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                continue
            if stat.S_ISDIR(attrs.st_mode):
                yield p, True, 0
            elif stat.S_ISREG(attrs.st_mode) and attrs.st_nlink == 1:
                yield p, False, attrs.st_size
        except OSError:
            continue


def display_path(root, path):
    return path.relative_to(root).as_posix()


def identity(root, path):
    return {"name": path.name, "relative_path": display_path(root, path), "extension": path.suffix}


def catalog_entry(root, path, folder, size, docs, exports_enabled, transfer_limit=LEGACY_SYNC_MAX_BYTES):
    item = {**identity(root, path), "type": "folder" if folder else "file"}
    if folder:
        item["extension"] = ""
        usable = len(item["relative_path"]) <= 224 and len(path.relative_to(root).parts) <= MAX_DEPTH
        item["content_tools"] = (["start_workspace_archive", "start_workspace_export"] if usable and exports_enabled and docs is not None
                                 and (docs == path or docs in path.parents) else [])
        return item
    ext = path.suffix.lower()
    methods, reasons = [], []
    usable_path = len(item["relative_path"]) <= 224 and len(path.relative_to(root).parts) <= MAX_DEPTH
    if not usable_path:
        item.update(size_bytes=size, content_tools=methods, content_status="path_limit")
        return item
    document_grant = docs is not None and docs in path.parents
    if ext in EXTENSIONS:
        from workspace_extra import MAX_READ_BYTES
        if size <= LIMIT:
            methods.append("read_workspace_file")
        else:
            reasons.append("text_size_limit")
        if size <= MAX_READ_BYTES:
            methods.append("read_workspace_lines")
    if raw_exportable(path):
        if not document_grant:
            reasons.append("document_scope_required")
        else:
            if ext in DOCUMENT_TYPES:
                if size <= PREVIEW_MAX_BYTES:
                    methods.append("preview_workspace_document")
                else:
                    reasons.append("document_size_limit")
            if exports_enabled:
                if size <= transfer_limit:
                    if size <= LEGACY_SYNC_MAX_BYTES:
                        methods.append("prepare_workspace_file")
                    methods.append("start_workspace_export")
                else:
                    reasons.append("transfer_size_limit")
    else:
        reasons.append("protected_file_format")
    item.update(size_bytes=size, content_tools=methods,
                content_status="available" if methods else (reasons[0] if reasons else "metadata_only"))
    if "document_scope_required" in reasons:
        item["document_scope_required"] = True
    return item


def extension_filter(value):
    if not isinstance(value, str):
        raise ValueError("Extension must be a string such as .pdf")
    value = value.strip().lower()
    if not value:
        return ""
    if not value.startswith("."):
        value = "." + value
    if not EXTENSION_FILTER.fullmatch(value):
        raise ValueError("Pass one extension such as .pdf, not a wildcard or path")
    return value


def page_options(data):
    offset, page_size = data.get("offset", 0), data.get("page_size", PAGE_SIZE)
    if type(offset) is not int or type(page_size) is not int or not 0 <= offset <= 1_000_000 or not 1 <= page_size <= 40:
        raise ValueError("Use offset >= 0 and page_size between 1 and 40")
    return offset, page_size


def paginate(rows, data, render):
    offset, page_size = page_options(data)
    page = rows[offset:offset + page_size]
    while True:
        result = render(page)
        end = offset + len(page)
        result.update(offset=offset, limit=page_size, returned=len(page),
                      next_offset=end if end < len(rows) else None)
        if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) <= PAGE_BUDGET_BYTES:
            return result
        if len(page) <= 1:
            raise ValueError("Directory result is too large; narrow the requested folder")
        page = page[:-1]


def decode_file(path):
    before = no_link(path, False)
    if before.st_size > LIMIT:
        raise ValueError("File is larger than the 8 KiB test limit")
    with path.open("rb") as f:
        data = f.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("File is larger than the 8 KiB test limit")
    return data, data.decode("utf-8")


def text_bytes(text):
    if not isinstance(text, str) or any(ord(c) < 32 and c not in "\t\n\r" for c in text):
        raise ValueError("Expected UTF-8 text")
    value = text.encode("utf-8")
    if len(value) > LIMIT:
        raise ValueError("The test file size limit is 8 KiB")
    return value


def audit(action, relative, outcome, mode):
    entries = read_json(AUDIT).get("items", [])
    entries = (entries if isinstance(entries, list) else [])[-149:]
    entries.append(dict(time=time.time(), action=OPERATIONS.get(action, action), path=relative, outcome=outcome,
                        mode=MODE_LABELS.get(mode, mode)))
    save_json(AUDIT, {"items": entries})


def document_scope(root, cfg):
    if not cfg.get("documents_enabled"):
        return None
    try:
        path = workspace_root(cfg.get("document_scope") or str(root))
    except (OSError, ValueError, TypeError):
        return None
    if root != path and root not in path.parents:
        return None
    return path


def inspect_document(path, data):
    before = no_link(path, False)
    if before.st_size > PREVIEW_MAX_BYTES:
        raise ValueError("Document exceeds the 20,000,000-byte limit")
    with path.open("rb") as handle:
        if not os.path.samestat(before, os.fstat(handle.fileno())):
            raise ValueError("File changed; request it again")
        source = handle.read(PREVIEW_MAX_BYTES + 1)
    if len(source) > PREVIEW_MAX_BYTES:
        raise ValueError("Document exceeds the 20,000,000-byte limit")
    interpreter = relay_pythonw().with_name("python.exe")
    if not interpreter.is_file():
        interpreter = Path(sys.executable)
    try:
        outcome = subprocess.run([str(interpreter), "-X", "utf8", "-B", str(RUNTIME / "document_preview.py"),
                                 path.suffix.lower(), str(data.get("start_page", 1)), str(data.get("page_count", 1)),
                                 data.get("zip_member", "")], input=source, capture_output=True, timeout=8, creationflags=HIDDEN)
    except subprocess.TimeoutExpired:
        raise ValueError("Local preview timed out; use the original-file handoff") from None
    if outcome.returncode:
        raise ValueError("Local preview failed; use the original-file handoff")
    result = json.loads(outcome.stdout.decode("utf-8"))
    if "error" in result:
        raise ValueError(result["error"])
    return result


class WorkspaceGate:
    def __init__(self):
        self.queue = {}
        self.results = {}
        self._projection_dirty = True
        DECISIONS.mkdir(exist_ok=True)
        if APPROVAL_JOURNAL.exists():
            value = read_json(APPROVAL_JOURNAL)
            if (value.get("version") != 1 or not isinstance(value.get("queue"), dict)
                    or not isinstance(value.get("results"), dict)):
                raise ValueError("The local approval journal is unreadable; approval processing was stopped.")
            self.queue, self.results = value["queue"], value["results"]
            self._validate_journal()
        self.pump()

    def _validate_journal(self):
        if (len(self.queue) > APPROVAL_QUEUE_LIMIT or len(self.results) > APPROVAL_RESULT_LIMIT
                or self.queue.keys() & self.results.keys()):
            raise ValueError("The local approval journal is invalid; approval processing was stopped.")
        for key, row in {**self.results, **self.queue}.items():
            if (not APPROVAL_ID.fullmatch(key) or not isinstance(row, dict)
                    or not isinstance(row.get("policy"), dict) or not row["policy"].get("workspace_revision")
                    or set(row["policy"]) not in (APPROVAL_POLICY_FIELDS, APPROVAL_POLICY_FIELDS | APPROVAL_DOCUMENT_FIELDS)):
                raise ValueError("The local approval journal is invalid; approval processing was stopped.")
            if key in self.queue:
                valid = (row.get("id") == key and isinstance(row.get("operation"), str)
                         and row["operation"] in OPERATIONS and row.get("phase") in ("waiting", "executing")
                         and isinstance(row.get("payload"), dict) and self._timestamp(row.get("expires"))
                         and all(isinstance(row.get(k), str) for k in ("label", "path", "preview", "mode"))
                         and (row["operation"] in DOCUMENT_OPERATIONS) == ("document_revision" in row["policy"]))
            else:
                valid = self._timestamp(row.get("until")) and isinstance(row.get("result"), dict)
            if not valid:
                raise ValueError("The local approval journal is invalid; approval processing was stopped.")

    @staticmethod
    def _timestamp(value):
        return type(value) in (int, float) and 0 < value < 253402300800 and math.isfinite(value)

    @staticmethod
    def _policy(cfg, operation=None):
        fields = APPROVAL_POLICY_FIELDS | APPROVAL_DOCUMENT_FIELDS if operation in DOCUMENT_OPERATIONS else APPROVAL_POLICY_FIELDS
        return {name: cfg.get(name) for name in sorted(fields)}

    @staticmethod
    def _policy_current(policy, cfg):
        return bool(cfg.get("workspace_enabled")) and all(cfg.get(key) == value for key, value in policy.items())

    def _commit(self, queue, results):
        # A single worker owns this journal. The manager only writes separate local decisions.
        persisted = {}
        for key, receipt in results.items():
            result = receipt["result"]
            output = result.get("result")
            if isinstance(output, dict) and "download_url" in output:
                # Do not durably duplicate the short-lived legacy download capability in approval history.
                metadata = {k: v for k, v in output.items() if k not in ("download_url", "instructions")}
                metadata["handoff_note"] = "The previous download link is not retained after a Windows worker restart."
                receipt = {**receipt, "result": {**result, "result": metadata}}
            persisted[key] = receipt
        save_json(APPROVAL_JOURNAL, {"version": 1, "queue": queue, "results": persisted}, durable=True)
        self._projection_dirty = self._projection_dirty or queue != self.queue
        self.queue, self.results = queue, results

    def _finish(self, key, item, result, cfg):
        queue, results = dict(self.queue), dict(self.results)
        queue.pop(key)
        if self._policy_current(item["policy"], cfg):
            results[key] = {"until": time.time() + APPROVAL_RESULT_TTL, "policy": item["policy"], "result": result}
            if len(results) > APPROVAL_RESULT_LIMIT:
                results.pop(min(results, key=lambda ident: results[ident]["until"]))
        self._commit(queue, results)

    def configuration(self):
        cfg = load_config()
        if not cfg.get("workspace_enabled"):
            raise ValueError("Workspace is not authorized; choose a folder in the Windows manager")
        return cfg, workspace_root(cfg["workspace_root"])

    def describe(self, op, data):
        if op in ("workspace_list", "workspace_search", "workspace_archive_start"):
            return data.get("relative_dir", ".")
        return data["relative_path"]

    def validate(self, root, op, data, cfg=None):
        cfg = load_config() if cfg is None else cfg
        if op in EXTRA_OPERATIONS:
            from workspace_extra import validate
            return validate(root, op, data)
        path = self.describe(op, data)
        if op in ("workspace_read", "workspace_preview_document"):
            leaf = relative_parts(path)[-1]
            suffix = Path(leaf).suffix.lower()
            if not suffix:
                raise ValueError("Use the exact relative_path returned by list_workspace or search_workspace, including the file extension. Do not guess the suffix.")
            if op == "workspace_read" and suffix in DOCUMENT_TYPES:
                raise ValueError("Use preview_workspace_document or prepare_workspace_file for this document; keep its complete relative_path and extension.")
        types = DOCUMENT_TYPES if op == "workspace_preview_document" else None if op in EXPORT_OPERATIONS else EXTENSIONS
        archive = op == "workspace_archive_start"
        resolved = resolve(root, path, folder=archive or op in ("workspace_list", "workspace_search"),
                           new=op == "workspace_create", extensions=types)
        if op in DOCUMENT_OPERATIONS:
            permitted = document_scope(root, cfg)
            if permitted is None or (permitted not in resolved.parents and not (archive and permitted == resolved)):
                raise ValueError("Document tools are not authorized for this path; check the local Windows manager")
            if archive:
                if resolved == Path(resolved.anchor):
                    raise ValueError("Choose one folder to package, not a whole drive")
                return path or ".", resolved
            if op in EXPORT_OPERATIONS and not raw_exportable(resolved):
                raise ValueError("Key and credential-container formats cannot be exported")
            size = resolved.stat().st_size
            if op == "workspace_preview_document" and size > PREVIEW_MAX_BYTES:
                raise ValueError("This document exceeds the preview limit; use start_workspace_export for the original")
            if op in EXPORT_OPERATIONS and size > transfer_max_bytes(cfg):
                raise ValueError("This file exceeds the configured original transfer limit; nothing was sent")
            if op == "workspace_export_file" and size > LEGACY_SYNC_MAX_BYTES:
                raise ValueError("Use start_workspace_export for originals larger than 20,000,000 bytes")
        if op == "workspace_preview_document":
            start, count, member = data.get("start_page", 1), data.get("page_count", 1), data.get("zip_member", "")
            if (type(start) is not int or not 1 <= start <= 10000 or type(count) is not int or not 1 <= count <= 3 or
                    not isinstance(member, str) or "\x00" in member or len(member) > 255):
                raise ValueError("Preview accepts one to three PDF pages or one short ZIP member name")
        if op in ("workspace_list", "workspace_search"):
            suffix_filter = extension_filter(data.get("extension", ""))
            page_options(data)
            if op == "workspace_search":
                fragment, depth = data.get("name_fragment", ""), data.get("max_depth", 4)
                if (not isinstance(fragment, str) or len(fragment) > 80 or
                        (not fragment.strip() and not suffix_filter)):
                    raise ValueError("Search needs a file-name fragment or an extension, for example .pdf")
                if type(depth) is not int or not 0 <= depth <= MAX_DEPTH:
                    raise ValueError("Use max_depth from 0 to 8")
        if op in ("workspace_create", "workspace_replace"):
            text_bytes(data["content"])
        if op == "workspace_replace" and not re.fullmatch(r"[a-f0-9]{64}", data.get("expected_sha256", "")):
            raise ValueError("Read the file first and supply its exact SHA-256")
        return path or ".", resolved

    def execute(self, root, op, data, cfg=None):
        cfg = load_config() if cfg is None else cfg
        path, target = self.validate(root, op, data, cfg)
        if op in EXTRA_OPERATIONS:
            from workspace_extra import execute
            return execute(root, op, path, target, data)
        if op == "workspace_preview_document":
            return {"file": path, **identity(root, target), **inspect_document(target, data)}
        if op == "workspace_export_file":
            return {**snapshot(target, cfg), **identity(root, target)}
        if op == "workspace_export_start":
            return {**begin_export(target, cfg), **identity(root, target)}
        if op == "workspace_archive_start":
            return begin_archive(target, cfg)
        docs = document_scope(root, cfg) if op in ("workspace_list", "workspace_search") else None
        if op == "workspace_list":
            from itertools import islice
            suffix = extension_filter(data.get("extension", ""))
            exports = uses_funnel(cfg)
            discovered = list(islice(visible_entries(target), SEARCH_BUDGET + 1))
            limit = transfer_max_bytes(cfg) if exports else 0
            rows = [catalog_entry(root, entry, folder, size, docs, exports, limit)
                    for entry, folder, size in discovered[:SEARCH_BUDGET]
                    if folder or not suffix or entry.name.lower().endswith(suffix)]
            rows.sort(key=lambda row: (row["type"] != "folder", row["name"].casefold(), row["name"]))
            return paginate(rows, data, lambda page: {
                "directory": display_path(root, target),
                "folders": [item for item in page if item["type"] == "folder"],
                "files": [item for item in page if item["type"] == "file"],
                "entries": [{"name": item["name"], "type": item["type"]} for item in page],
                "observed_count": len(rows), "scan_limit_reached": len(discovered) > SEARCH_BUDGET,
                "file_extension_filter": suffix,
                "path_hint": "Use the exact relative_path. For a folder ZIP, use start_workspace_archive or start_workspace_export."})
        if op == "workspace_search":
            needle = data.get("name_fragment", "").strip().casefold()
            suffix = extension_filter(data.get("extension", ""))
            if not suffix and EXTENSION_FILTER.fullmatch(needle):
                suffix, needle = needle, ""
            depth_limit = data.get("max_depth", 4)
            exports = uses_funnel(cfg)
            limit = transfer_max_bytes(cfg) if exports else 0
            found, tasks, visited, skipped = [], [(target, 0)], 0, 0
            truncated = False
            while tasks and not truncated:
                folder, depth = tasks.pop()
                try:
                    subfolders = []
                    for entry, is_folder, size in visible_entries(folder):
                        if visited >= SEARCH_BUDGET:
                            truncated = True
                            break
                        visited += 1
                        if is_folder and depth < depth_limit:
                            subfolders.append(entry)
                        elif not is_folder and needle in entry.name.casefold() and (not suffix or entry.name.casefold().endswith(suffix)):
                            found.append(catalog_entry(root, entry, False, size, docs, exports, limit))
                    tasks.extend((entry, depth + 1) for entry in sorted(subfolders, key=lambda p: p.name.casefold(), reverse=True))
                except OSError:
                    if folder == target:
                        raise
                    skipped += 1
            found.sort(key=lambda row: (row["relative_path"].casefold(), row["relative_path"]))
            return paginate(found, data, lambda page: {
                "directory": display_path(root, target), "matches": [item["relative_path"] for item in page],
                "files": page, "file_extension_filter": suffix, "observed_count": len(found), "max_depth": depth_limit,
                "scan_limit_reached": truncated, "skipped_directories": skipped,
                "path_hint": "Pass files[].relative_path unchanged to content tools."})
        if op == "workspace_read":
            raw, content = decode_file(target)
            return {"file": path, **identity(root, target), "content": content, "sha256": hashlib.sha256(raw).hexdigest()}
        replacement = text_bytes(data["content"])
        if op == "workspace_create":
            with target.open("xb") as file:
                file.write(replacement)
            return {"file": path, "created": True, "sha256": hashlib.sha256(replacement).hexdigest()}
        raw, _ = decode_file(target)
        if hashlib.sha256(raw).hexdigest() != data["expected_sha256"]:
            raise ValueError("The file changed; read it again before writing")
        BACKUPS.mkdir(exist_ok=True)
        stored = BACKUPS / (time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4) + "-" + target.name)
        with stored.open("xb") as file:
            file.write(raw)
        temp = None
        try:
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".dot-write-", delete=False) as handle:
                temp = Path(handle.name)
                handle.write(replacement)
            check, _ = decode_file(resolve(root, path))
            if hashlib.sha256(check).hexdigest() != data["expected_sha256"]:
                raise ValueError("The file changed; read it again before writing")
            os.replace(temp, target)
        finally:
            if temp and temp.exists():
                temp.unlink()
        return {"file": path, "updated": True, "sha256": hashlib.sha256(replacement).hexdigest(), "backup_created": True}

    def automatic(self, cfg, op, target, data):
        if op in EXTRA_ALWAYS_APPROVE:
            return (cfg.get("workspace_unified") is True and cfg.get("approval_mode") == "full"
                    and op in cfg.get("automatic_operations", ()))
        if cfg["approval_mode"] == "full":
            return True
        if cfg["approval_mode"] != "rules":
            return False
        if op in READS:
            return True
        if op in EXPORT_OPERATIONS or op in EXTRA_OPERATIONS:
            return False
        return (target.suffix.lower() in (".txt", ".md", ".csv") and
                len(text_bytes(data["content"])) <= 2048 and
                (op == "workspace_create" or no_link(target, False).st_size <= 2048))

    def handle(self, job):
        self.pump()
        try:
            cfg, root = self.configuration()
            op, data = job["operation"], job["payload"]
            if op == "workspace_export_start":
                # Existing clients already know this method. Recognize a real directory
                # and enter the same scoped, audited archive flow as the dedicated tool.
                try:
                    resolve(root, data.get("relative_path"), folder=True)
                except (OSError, ValueError, TypeError):
                    pass
                else:
                    op, data = "workspace_archive_start", {"relative_dir": data["relative_path"]}
            if op == "workspace_approval":
                key = data.get("request_id", "")
                if not isinstance(key, str) or not APPROVAL_ID.fullmatch(key):
                    return {"state": "unknown_or_expired"}
                if key in self.queue and self._policy_current(self.queue[key]["policy"], cfg):
                    return {"state": "approval_pending", "request_id": key}
                entry = self.results.get(key)
                if entry and self._policy_current(entry["policy"], cfg):
                    return entry["result"]
                return {"state": "unknown_or_expired", "request_id": key}
            if op not in OPERATIONS:
                return {"error": "Use the new authorized workspace plugin"}
            rel, target = self.validate(root, op, data, cfg)
            mode = cfg["approval_mode"]
            if self.automatic(cfg, op, target, data):
                if not self._policy_current(self._policy(cfg, op), load_config()):
                    return {"error": "Workspace authorization changed before execution; request the operation again."}
                result = self.execute(root, op, data, cfg)
                audit(op, rel, "规则通过" if mode == "rules" else "直接执行", mode)
                return result
            if len(self.queue) >= APPROVAL_QUEUE_LIMIT:
                return {"error": "The local approval queue is full"}
            if not cfg["workspace_revision"]:
                return {"error": "Save the workspace authorization in the local Windows manager before requesting approval."}
            key = secrets.token_hex(12)
            excerpt = str(data.get("content", ""))[:600]
            if op in EXTRA_OPERATIONS:
                from workspace_extra import approval_details
                data = dict(data)
                excerpt = approval_details(op, target, data)
            if op == "workspace_archive_start":
                excerpt = "将在本机打包这个目录并发送 ZIP。系统项、凭据及链接会排除。"
            elif op in EXPORT_OPERATIONS:
                excerpt = f"将发送这份文件的原始字节。临时链接 7 分钟有效；此文件 {target.stat().st_size:,} 字节。"
            expires = time.time() + cfg.get("approval_minutes", APPROVAL_MINUTES_DEFAULT) * 60
            item = {"id": key, "operation": op, "label": OPERATIONS[op], "path": rel, "preview": excerpt,
                    "expires": expires, "revision": cfg["workspace_revision"], "mode": mode, "payload": data,
                    "phase": "waiting", "policy": self._policy(cfg, op)}
            self._commit({**self.queue, key: item}, dict(self.results))
            audit(op, rel, "等待批准", mode)
            self.publish()
            return {"state": "approval_required", "request_id": key, "operation": OPERATIONS[op], "path": rel,
                    "expires_at": expires,
                    "message": "Approve in the local Windows Dot MCP manager, then call get_approval_result with request_id."}
        except (ValueError, OSError, TypeError, KeyError) as exc:
            return {"error": str(exc) if isinstance(exc, ValueError) else "The requested test workspace operation is not available"}

    def publish(self):
        save_json(PENDING, {"items": [{k: item[k] for k in ("id", "operation", "label", "path", "preview", "expires", "mode")}
                                     for item in self.queue.values() if item["phase"] == "waiting"]})
        self._projection_dirty = False

    def _execute_approved(self, key, item):
        # Write the start fence before attempting any side effect. If the worker stops now, the next
        # worker reports uncertainty and never repeats the operation without an independent request.
        self._commit({**self.queue, key: {**item, "phase": "executing"}}, dict(self.results))
        cfg = load_config()
        if item["expires"] <= time.time() or not self._policy_current(item["policy"], cfg):
            return "过期或授权已撤销", {"state": "expired_or_revoked"}
        try:
            root = workspace_root(cfg["workspace_root"])
            data = self.execute(root, item["operation"], item["payload"], cfg)
            return "用户批准并执行", {"state": "executed", "result": data}
        except (OSError, TypeError, ValueError, KeyError) as exc:
            return "批准后执行失败", {"state": "failed", "error": str(exc) if isinstance(exc, ValueError)
                                    else "Workspace operation failed"}

    def pump(self):
        clear_expired()
        now = time.time()
        cfg = load_config()
        kept = {key: row for key, row in self.results.items()
                if row["until"] > now and self._policy_current(row["policy"], cfg)}
        if len(kept) != len(self.results):
            self._commit(dict(self.queue), kept)
        for key, item in list(self.queue.items()):
            decision_path = DECISIONS / (key + ".json")
            decision = read_json(decision_path).get("decision")
            cfg = load_config()
            if not self._policy_current(item["policy"], cfg):
                outcome, result = "授权已撤销", {"state": "revoked"}
            elif item["phase"] == "executing":
                outcome, result = "上次执行结果不确定", {"state": "interrupted_unknown", "request_id": key,
                    "message": "Execution may already have happened. Check the target and any export before requesting it again."}
            elif item["expires"] <= time.time():
                outcome, result = "审批已过期", {"state": "expired_or_revoked"}
            elif decision == "deny":
                outcome, result = "用户拒绝", {"state": "denied"}
            elif decision == "allow":
                outcome, result = self._execute_approved(key, item)
            else:
                continue
            self._finish(key, item, result, load_config())
            decision_path.unlink(missing_ok=True)
            audit(item["operation"], item["path"], outcome, item["mode"])
        if self._projection_dirty:
            self.publish()
