"""Bounded workspace editing, search, movement, and a recoverable private trash."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import time

from core import STATE, read_json, save_json
from workspace import (BACKUPS, DOCUMENT_TYPES, EXTENSIONS, EXTRA_ALWAYS_APPROVE, MAX_DEPTH, clean_part,
                       display_path, extension_filter, identity, no_link,
                       protected_path, relative_parts, resolve)

MAX_READ_BYTES = 8 * 1024 * 1024
MAX_PATCH_BYTES = 4 * 1024 * 1024
SEARCH_FILE_BYTES = 1024 * 1024
SEARCH_TOTAL_BYTES = 8 * 1024 * 1024
RESULT_BYTES = 18_000
MAX_ENTRIES = 5_000
TRASH = STATE / "workspace-trash"
TRASH_ID = re.compile(r"[0-9a-f]{32}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
NEWLINES = re.compile(r"\r\n|\n|\r")
CRLF = re.compile(r"\r\n")


def _plain(value, description, maximum, *, nonempty=False, multiline=True):
    if isinstance(value, str) and (value or not nonempty):
        try:
            if len(value.encode("utf-8")) <= maximum and all(
                ord(c) >= 32 or c in ("\t\r\n" if multiline else "\t") for c in value
            ):
                return value
        except UnicodeError:
            pass
    raise ValueError(f"Use {description} (UTF-8, at most {maximum} bytes)")


def _int(value, lo, hi, name):
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"Use {name} between {lo} and {hi}")
    return value


def _kind(path):
    info = path.lstat()
    directory = stat.S_ISDIR(info.st_mode)
    return directory, no_link(path, directory)


def _path(root, value, *, new=False):
    # folder=True bypasses the content suffix list without relaxing any name or
    # ancestor checks. We handle the kind ourselves for existing entries.
    relative_parts(value)
    if new:
        return resolve(root, value, folder=True, new=True)
    parts = relative_parts(value)
    parent = resolve(root, "/".join(parts[:-1]), folder=True)
    target = parent / parts[-1]
    if protected_path(target):
        raise ValueError("Protected application or credential directory")
    _kind(target)
    return target


def _text_path(root, value):
    suffix = Path(relative_parts(value)[-1]).suffix.lower()
    if not suffix:
        raise ValueError("Use the exact relative_path with its file extension")
    if suffix in DOCUMENT_TYPES:
        raise ValueError("Use document preview or original transfer for this file")
    return resolve(root, value)


def _metadata(path):
    directory, info = _kind(path)
    return [info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size, directory]


def _slot(key):
    if not isinstance(key, str) or not TRASH_ID.fullmatch(key):
        raise ValueError("Pass the trash_id returned by the workspace trash")
    no_link(TRASH, True)
    slot = TRASH / key
    no_link(slot, True)
    no_link(slot / "entry.json", False)
    return slot


def _manifest(root, key):
    try:
        slot = _slot(key)
        meta = read_json(slot / "entry.json")
        if meta.get("root") != os.path.normcase(str(root)):
            raise ValueError("This trash entry is not in the current authorized workspace")
        stored = slot / "item"
        is_folder, info = _kind(stored)
    except FileNotFoundError:
        raise ValueError("That trash item has already been restored or does not exist") from None
    if (meta.get("type") != ("folder" if is_folder else "file")
            or meta.get("file_id") != [info.st_dev, info.st_ino]):
        raise ValueError("The stored trash item changed")
    return slot, meta


def validate(root, op, data):
    if op == "workspace_list_trash":
        _int(data.get("limit", 20), 1, 50, "limit")
        return ".", root
    if op == "workspace_restore":
        slot, meta = _manifest(root, data.get("trash_id"))
        path = meta["relative_path"]
        _path(root, path, new=True)
        _check_approved(slot / "item", data)
        return path, slot / "item"
    if op == "workspace_search_content":
        _plain(data.get("query"), "a nonempty literal search string", 320,
               nonempty=True, multiline=False)
        suffix = extension_filter(data.get("extension", ""))
        if suffix and suffix not in EXTENSIONS:
            raise ValueError("Content search supports the text file extensions")
        _int(data.get("max_depth", 4), 0, MAX_DEPTH, "max_depth")
        _int(data.get("limit", 40), 1, 80, "limit")
        if type(data.get("case_sensitive", False)) is not bool:
            raise ValueError("case_sensitive must be a boolean")
        directory = data.get("relative_dir", ".")
        return directory or ".", resolve(root, directory, folder=True)
    path = data["relative_path"]
    if op == "workspace_read_lines":
        _int(data.get("start_line", 1), 1, MAX_READ_BYTES, "start_line")
        _int(data.get("line_count", 100), 1, 200, "line_count")
        _int(data.get("start_column", 1), 1, MAX_READ_BYTES + 1, "start_column")
        return path, _text_path(root, path)
    if op == "workspace_patch":
        expected = data.get("expected_sha256")
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise ValueError("Read the file first and pass its exact SHA-256")
        replacements = data.get("replacements")
        if not isinstance(replacements, list) or not 1 <= len(replacements) <= 12:
            raise ValueError("Pass 1 to 12 replacements as {find, replace} objects")
        total = 0
        for change in replacements:
            if not isinstance(change, dict) or set(change) != {"find", "replace"}:
                raise ValueError("Each replacement must contain find and replace")
            a = _plain(change["find"], "a nonempty exact find string", 8192, nonempty=True)
            b = _plain(change["replace"], "an exact replacement string", 8192)
            total += len(a.encode("utf-8")) + len(b.encode("utf-8"))
        if total > 24_576:
            raise ValueError("Replacement text exceeds 24 KiB in total")
        return path, _text_path(root, path)
    if op == "workspace_create_folder":
        return path, _path(root, path, new=True)
    target = _path(root, path)
    _check_approved(target, data)
    if op == "workspace_move":
        destination = _path(root, data.get("destination_path"), new=True)
        if target in destination.parents:
            raise ValueError("A folder cannot be moved inside itself")
    return path, target


def _check_approved(path, data):
    if "_approval_identity" in data and data["_approval_identity"] != _metadata(path):
        raise ValueError("The approved item changed; request the operation again")


def approval_details(op, target, data):
    extra = ""
    if op == "workspace_move":
        extra = "目标：" + data["destination_path"]
    elif op == "workspace_trash":
        extra = "移入小助手私有回收站，可使用回收编号恢复。"
    elif op == "workspace_restore":
        extra = "恢复到原路径，不覆盖同名文件。回收编号：" + data["trash_id"]
    elif op == "workspace_patch":
        change = data["replacements"][0]
        extra = (f'{len(data["replacements"])} 处修改。第一处查找：{change["find"][:240]}\n'
                 f'替换为：{change["replace"][:240]}')
    if op in EXTRA_ALWAYS_APPROVE:
        data["_approval_identity"] = _metadata(target)
    return extra


def _read(path, maximum):
    before = no_link(path, False)
    if before.st_size > maximum:
        raise ValueError(f"Text file exceeds the {maximum:,}-byte operation limit")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if not os.path.samestat(before, opened) or opened.st_nlink != 1:
            raise ValueError("File changed while opening it; read it again")
        raw = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    if len(raw) > maximum or len(raw) != after.st_size or (
        opened.st_size, opened.st_mtime_ns
    ) != (after.st_size, after.st_mtime_ns):
        raise ValueError("File changed while reading; retry")
    return raw


def _decode(raw):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("Expected a valid UTF-8 text file") from None
    if "\x00" in text:
        raise ValueError("This file contains binary data")
    return text


def _lines(text):
    return enumerate(io.StringIO(text, newline=""), 1)


def _read_lines(root, path, data):
    start, count = data.get("start_line", 1), data.get("line_count", 100)
    column = data.get("start_column", 1)
    raw = _read(path, MAX_READ_BYTES)
    items, used, next_line, next_column = [], 0, None, None
    for number, line in _lines(_decode(raw)):
        if number < start:
            continue
        text = line.rstrip("\r\n")
        offset = column - 1 if number == start else 0
        if offset > len(text):
            raise ValueError("start_column is past the end of the selected line")
        clipped = len(text) - offset > 2400
        item = {"line": number, "column": offset + 1, "text": text[offset:offset + 2400],
                "text_truncated": clipped, "line_ending": "" if clipped else line[len(text):]}
        cost = len(json.dumps(item, ensure_ascii=False).encode("utf-8")) + 2
        if len(items) >= count or (items and used + cost > RESULT_BYTES):
            next_line, next_column = number, offset + 1
            break
        items.append(item)
        used += cost
        if clipped:
            next_line, next_column = number, offset + 2401
            break
    return {**identity(root, path), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "start_line": start, "start_column": column,
            "lines": items, "next_start_line": next_line, "next_start_column": next_column}


def _search(root, folder, data):
    deadline = time.monotonic() + 3.0
    pattern = re.compile(re.escape(data["query"]), 0 if data.get("case_sensitive") else re.I)
    suffix = extension_filter(data.get("extension", ""))
    limit, depth = data.get("limit", 40), data.get("max_depth", 4)
    pending, hits = [(folder, 0)], []
    inspected = files_read = bytes_read = skipped = used = 0
    cut_short = None
    while pending and cut_short is None:
        directory, level = pending.pop()
        try:
            no_link(directory, True)
            with os.scandir(directory) as listing:
                for entry in listing:
                    if inspected >= MAX_ENTRIES or time.monotonic() >= deadline:
                        cut_short = "scan_budget"
                        break
                    inspected += 1
                    file = directory / entry.name
                    if not clean_part(entry.name) or protected_path(file):
                        continue
                    rel = display_path(root, file)
                    if len(rel) > 224 or len(file.relative_to(root).parts) > MAX_DEPTH:
                        continue
                    try:
                        # Windows DirEntry.stat omits inode/link-count fields.
                        info = file.lstat()
                        if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            if level < depth:
                                pending.append((file, level + 1))
                            continue
                        ext = file.suffix.lower()
                        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                                or ext not in EXTENSIONS or (suffix and ext != suffix)):
                            continue
                        if info.st_size > SEARCH_FILE_BYTES:
                            skipped += 1
                            continue
                        if info.st_size + bytes_read > SEARCH_TOTAL_BYTES:
                            cut_short = "byte_budget"
                            break
                        raw = _read(_text_path(root, rel),
                                    min(SEARCH_FILE_BYTES, SEARCH_TOTAL_BYTES - bytes_read))
                        files_read += 1
                        bytes_read += len(raw)
                        content = _decode(raw)
                    except (ValueError, OSError):
                        skipped += 1
                        continue
                    for number, line in _lines(content):
                        if number % 128 == 0 and time.monotonic() >= deadline:
                            cut_short = "scan_budget"
                            break
                        match = pattern.search(line)
                        if not match:
                            continue
                        start = max(0, match.start() - 64)
                        end = min(len(line), match.end() + 96)
                        hit = {**identity(root, file), "line": number, "column": match.start() + 1,
                               "text": line[start:end].rstrip("\r\n"), "snippet_column": start + 1}
                        cost = len(json.dumps(hit, ensure_ascii=False).encode("utf-8")) + 2
                        if len(hits) >= limit or used + cost > RESULT_BYTES:
                            cut_short = "result_limit"
                            break
                        hits.append(hit)
                        used += cost
                    if cut_short is not None:
                        break
        except (ValueError, OSError):
            if directory == folder:
                raise
            skipped += 1
    return {"relative_dir": "." if folder == root else display_path(root, folder),
            "matches": hits, "files_read": files_read, "entries_checked": inspected,
            "bytes_read": bytes_read, "skipped": skipped,
            "truncated": cut_short is not None, "stop_reason": cut_short}


@contextmanager
def _locked_parents(*parents):
    """Pin Windows ancestor directories without sharing DELETE; never follow reparse points."""
    paths = {}
    for parent in parents:
        for path in (parent, *parent.parents):
            paths[os.path.normcase(str(path))] = path
    kernel, handles = None, []
    if os.name == "nt":
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
    try:
        for path in sorted(paths.values(), key=lambda p: (len(p.parts), os.path.normcase(str(p)))):
            before = no_link(path, True)
            if kernel is not None:
                # Read attributes, share reads/writes, OPEN_EXISTING,
                # BACKUP_SEMANTICS | OPEN_REPARSE_POINT.
                handle = kernel.CreateFileW(str(path), 0x80, 3, None, 3, 0x02200000, None)
                if handle == ctypes.c_void_p(-1).value:
                    raise ctypes.WinError(ctypes.get_last_error())
                handles.append(handle)
            after = no_link(path, True)
            if not os.path.samestat(before, after):
                raise ValueError("A parent folder changed; request the operation again")
        yield
    finally:
        if kernel is not None:
            for handle in reversed(handles):
                kernel.CloseHandle(handle)


def _ensure_empty_destination(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise ValueError("Destination exists; files and folders are never overwritten")


def _move_no_replace(source, destination):
    if os.name == "nt":
        os.rename(source, destination)  # Windows fails if destination already exists.
    else:
        # Portable test fallback; production desktop is Windows.
        _ensure_empty_destination(destination)
        os.rename(source, destination)


def _original_offsets(text, start, end):
    """Translate normalized LF offsets back to an original UTF-8 text string."""
    skipped, original_start = 0, None
    for match in CRLF.finditer(text):
        normalized = match.start() - skipped
        if normalized >= start and original_start is None:
            original_start = start + skipped
        if normalized >= end:
            break
        skipped += 1
    return start + skipped if original_start is None else original_start, end + skipped


def _patch(root, path, data):
    with _locked_parents(path.parent):
        raw = _read(path, MAX_PATCH_BYTES)
        expected = data["expected_sha256"]
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("The file changed; read it again before patching")
        text = _decode(raw)
        bom = b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b""
        for index, change in enumerate(data["replacements"], 1):
            needle = change["find"].replace("\r\n", "\n").replace("\r", "\n")
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            match = normalized.find(needle)
            if match < 0 or normalized.find(needle, match + 1) >= 0:
                raise ValueError(f"Patch {index}: find text must match exactly once; no edits were written")
            start, end = _original_offsets(text, match, match + len(needle))
            original_endings = NEWLINES.findall(text, start, end)
            following = NEWLINES.search(text, end)
            if following is not None:
                fallback_ending = following.group()
            else:
                previous = max(text.rfind("\r", 0, start), text.rfind("\n", 0, start))
                if previous >= 1 and text[previous-1:previous+1] == "\r\n":
                    fallback_ending = "\r\n"
                else:
                    fallback_ending = text[previous] if previous >= 0 else "\n"
            endings = iter(original_endings)
            replacement = NEWLINES.sub(lambda _: next(endings, fallback_ending), change["replace"])
            text = text[:start] + replacement + text[end:]
            result = bom + text.encode("utf-8")
            if len(result) > MAX_PATCH_BYTES:
                raise ValueError("Patched file would exceed the 4 MiB limit")
        if result == raw:
            return {**identity(root, path), "updated": False, "sha256": expected}
        BACKUPS.mkdir(exist_ok=True)
        temp = None
        stored = BACKUPS / (time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(6) + "-" + path.name)
        with _locked_parents(BACKUPS):
            try:
                with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".dot-patch-", delete=False) as handle:
                    temp = Path(handle.name)
                    handle.write(result)
                    handle.flush()
                    os.fsync(handle.fileno())
                if hashlib.sha256(_read(path, MAX_PATCH_BYTES)).hexdigest() != expected:
                    raise ValueError("The file changed while prepping the patch; read it again")
                with stored.open("xb") as backup:
                    backup.write(raw)
                os.replace(temp, path)
            finally:
                if temp is not None:
                    temp.unlink(missing_ok=True)
    return {**identity(root, path), "updated": True, "backup_created": True,
            "sha256": hashlib.sha256(result).hexdigest(), "replacements_applied": len(data["replacements"])}


def _guard_tree(source, destination, root, *, restoring=False):
    """Keep folder moves bounded, and reject reparse or protected descendants."""
    directory, info = _kind(source)
    if not directory:
        return "file", info.st_size
    pending, checked = [(source, destination, 0)], 0
    deadline = time.monotonic() + 3.0
    while pending:
        current, final, depth = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                checked += 1
                if depth >= MAX_DEPTH or checked > MAX_ENTRIES or time.monotonic() >= deadline:
                    raise ValueError("Folder move is too deep or large; move smaller groups")
                target = final / entry.name
                if not clean_part(entry.name) or protected_path(target):
                    raise ValueError("Folder contains protected names; move individual allowed children")
                if target.is_relative_to(root):
                    relative_parts(display_path(root, target))
                original = current / entry.name
                if not restoring and protected_path(original):
                    raise ValueError("Folder contains protected application data")
                if _kind(original)[0]:
                    pending.append((original, target, depth + 1))
    return "folder", 0


def _public_entry(key, meta):
    return {"trash_id": key, **{k: meta[k] for k in (
        "relative_path", "name", "type", "bytes", "trashed_at"
    )}}


def _trash_list(root, limit):
    if not TRASH.exists():
        return {"entries": [], "total": 0}
    no_link(TRASH, True)
    records = []
    for slot in TRASH.iterdir():
        try:
            _, meta = _manifest(root, slot.name)
            records.append(_public_entry(slot.name, meta))
        except (ValueError, OSError, KeyError):
            continue
    records.sort(key=lambda row: row["trashed_at"], reverse=True)
    page, used = [], 0
    for row in records[:limit]:
        cost = len(json.dumps(row, ensure_ascii=False).encode("utf-8")) + 2
        if used + cost > RESULT_BYTES:
            break
        page.append(row)
        used += cost
    return {"entries": page, "total": len(records), "truncated": len(page) < len(records)}


def _trash_remove(root, path, data):
    TRASH.mkdir(exist_ok=True)
    with _locked_parents(path.parent, TRASH):
        _check_approved(path, data)
        current = _kind(path)[1]
        if TRASH.stat().st_dev != current.st_dev:
            raise ValueError("Recoverable trash needs the same Windows volume as its private state")
        if sum(1 for p in TRASH.iterdir() if TRASH_ID.fullmatch(p.name)) >= 500:
            raise ValueError("Workspace trash is full; restore entries before removing more")
        key = secrets.token_hex(16)
        slot = TRASH / key
        kind, size = _guard_tree(path, path, root)
        meta = {"root": os.path.normcase(str(root)), "relative_path": display_path(root, path),
                "name": path.name, "type": kind, "bytes": size, "trashed_at": time.time(),
                "file_id": [current.st_dev, current.st_ino]}
        slot.mkdir()
        try:
            save_json(slot / "entry.json", meta)
            _check_approved(path, data)
            _move_no_replace(path, slot / "item")
        except BaseException:
            if not (slot / "item").exists():
                (slot / "entry.json").unlink(missing_ok=True)
                slot.rmdir()
            raise
    return {"trashed": True, **_public_entry(key, meta)}


def _trash_restore(root, stored, data):
    key = data["trash_id"]
    slot, meta = _manifest(root, key)
    target = _path(root, meta["relative_path"], new=True)
    with _locked_parents(slot, target.parent):
        _manifest(root, key)
        _check_approved(stored, data)
        if target.parent.stat().st_dev != stored.stat().st_dev:
            raise ValueError("Restore needs the original Windows volume")
        _guard_tree(stored, target, root, restoring=True)
        _ensure_empty_destination(target)
        _move_no_replace(stored, target)
        (slot / "entry.json").unlink(missing_ok=True)
    slot.rmdir()
    return {"restored": True, "trash_id": key, **identity(root, target)}


def execute(root, op, path, target, data):
    if op == "workspace_read_lines":
        return _read_lines(root, target, data)
    if op == "workspace_search_content":
        return _search(root, target, data)
    if op == "workspace_patch":
        return _patch(root, target, data)
    if op == "workspace_create_folder":
        with _locked_parents(target.parent):
            target.mkdir()
        return {"created": True, "type": "folder", **identity(root, target)}
    if op == "workspace_list_trash":
        return _trash_list(root, data.get("limit", 20))
    if op == "workspace_trash":
        return _trash_remove(root, target, data)
    if op == "workspace_restore":
        return _trash_restore(root, target, data)
    if op == "workspace_move":
        destination = _path(root, data["destination_path"], new=True)
        with _locked_parents(target.parent, destination.parent):
            _check_approved(target, data)
            is_folder, source_info = _kind(target)
            if source_info.st_dev != destination.parent.stat().st_dev:
                raise ValueError("Move cannot cross Windows volumes; copy and verify first")
            _guard_tree(target, destination, root)
            _check_approved(target, data)
            _ensure_empty_destination(destination)
            _move_no_replace(target, destination)
        return {"moved": True, "source": path, "type": "folder" if is_folder else "file",
                **identity(root, destination)}
    raise ValueError("Unknown workspace operation")
