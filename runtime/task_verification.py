"""Typed Windows inspection tasks. No input is interpreted as a command."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
import struct
from collections import Counter
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath
import zipfile
import zlib

from file_bridge import raw_exportable
from transfer_mailbox import guarded_inbox
from workspace import clean_part, no_link, protected_path, resolve

CHUNK = 1024 * 1024
MAX_HASH_BYTES = 2_000_000_000
MAX_ZIP_BYTES = 1_000_000_000
MAX_ZIP_EXPANDED = 500_000_000
MAX_MANIFEST = 256 * 1024
MAX_REPORT = 24
MAX_PE_BYTES = 1_000_000_000
MAX_PE_OFFSET = 8 * 1024 * 1024
HASH = re.compile(r"[0-9a-fA-F]{64}\Z")
MANIFEST_LINE = re.compile(r"([0-9a-fA-F]{64})[ \t]+\*?(.+)")
PRESETS = {
    "file_sha256": {"label": "计算或核对文件 SHA-256", "target": "file",
                    "parameters": {"expected_sha256": {"type": "string", "optional": True}}},
    "verify_sha256_manifest": {"label": "核对 SHA-256 清单", "target": "file", "parameters": {}},
    "zip_inspect": {"label": "检查 ZIP 结构和 CRC", "target": "file",
                    "parameters": {"verify_crc": {"type": "boolean", "default": True}}},
    "pe_inspect": {"label": "静态查看 EXE/DLL 的 PE 文件头（不运行）", "target": "file",
                   "parameters": {}},
    "directory_inventory": {"label": "统计目录文件与占用", "target": "directory",
                            "parameters": {"max_depth": {"type": "integer", "min": 0, "max": 8, "default": 2}}},
}


def arguments(preset, params):
    if params is None:
        params = {}
    if not isinstance(params, dict) or set(params) - set(PRESETS[preset]["parameters"]):
        raise ValueError("Unknown task parameter; see list_windows_project_jobs for accepted fields.")
    if preset == "file_sha256" and "expected_sha256" in params:
        digest = params["expected_sha256"]
        if not isinstance(digest, str) or not HASH.fullmatch(digest):
            raise ValueError("expected_sha256 must contain exactly 64 hexadecimal digits.")
        return {"expected_sha256": digest.lower()}
    if preset == "zip_inspect":
        crc = params.get("verify_crc", True)
        if type(crc) is not bool:
            raise ValueError("verify_crc must be true or false.")
        return {"verify_crc": crc}
    if preset == "directory_inventory":
        depth = params.get("max_depth", 2)
        if type(depth) is not int or not 0 <= depth <= 8:
            raise ValueError("max_depth must be an integer from 0 to 8.")
        return {"max_depth": depth}
    return {}


def target_file(base, relative_path, preset=None):
    target = resolve(base, relative_path, extensions=None)
    if not raw_exportable(target):
        raise ValueError("Key and credential container formats are excluded from inspection.")
    if preset == "zip_inspect" and target.suffix.casefold() != ".zip":
        raise ValueError("zip_inspect requires a .zip file.")
    if preset == "pe_inspect" and target.suffix.casefold() not in {".exe", ".dll"}:
        raise ValueError("pe_inspect requires an .exe or .dll file.")
    if preset == "text_to_docx":
        from task_documents import TEXT_SUFFIXES
        if target.suffix.casefold() not in TEXT_SUFFIXES:
            raise ValueError("text_to_docx requires UTF-8 .txt, .md or .csv input.")
    return target


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]


@contextmanager
def read_locked(path, limit, expected_stamp=None):
    with guarded_inbox(path.parent):
        info = no_link(path, False)
        original = stamp(info)
        if expected_stamp is not None and original != expected_stamp:
            raise ValueError("The requested file changed since submission; submit again.")
        if info.st_size > limit:
            raise ValueError("The requested file exceeds the task byte limit.")
        with path.open("rb") as handle:
            if stamp(os.fstat(handle.fileno())) != original:
                raise ValueError("The requested file changed before being opened.")
            yield handle, info.st_size
            if (stamp(os.fstat(handle.fileno())) != original
                    or stamp(no_link(path, False)) != original):
                raise ValueError("The requested file changed during inspection; submit again.")


def digest_file(path, limit, checkpoint, expected_stamp=None):
    total = 0
    digest = hashlib.sha256()
    with read_locked(path, limit, expected_stamp) as (handle, size):
        while data := handle.read(CHUNK):
            total += len(data)
            if total > size:
                raise ValueError("The requested file grew during inspection.")
            digest.update(data)
            checkpoint(total, size)
        if total != size:
            raise ValueError("The requested file changed during inspection.")
    return digest.hexdigest(), total


def file_sha256(path, params, checkpoint, expected_stamp):
    digest, size = digest_file(path, MAX_HASH_BYTES, checkpoint, expected_stamp)
    out = {"sha256": digest, "size_bytes": size}
    if "expected_sha256" in params:
        out["matches"] = hmac.compare_digest(digest, params["expected_sha256"])
    return out


def inspect_pe(path, checkpoint, expected_stamp):
    """Read fixed-size PE header fields; never launch or load executable content."""
    with read_locked(path, MAX_PE_BYTES, expected_stamp) as (handle, size):
        dos = handle.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("The file has no supported PE header.")
        offset = struct.unpack_from("<I", dos, 0x3c)[0]
        if not 64 <= offset <= min(MAX_PE_OFFSET, size - 24):
            raise ValueError("The PE header offset is invalid or exceeds the inspection limit.")
        checkpoint(64, None, force=True)
        handle.seek(offset)
        header = handle.read(24)
        if len(header) != 24 or header[:4] != b"PE\x00\x00":
            raise ValueError("The PE signature is missing or invalid.")
        machine, sections, _, _, _, optional_size, flags = struct.unpack("<HHIIIHH", header[4:])
        if not 1 <= sections <= 96 or not 70 <= optional_size <= 4096:
            raise ValueError("The PE section count or optional header size is unsupported.")
        section_table_end = offset + 24 + optional_size + sections * 40
        if section_table_end > size:
            raise ValueError("The PE optional header or section table is truncated.")
        optional = handle.read(70)
        if len(optional) != 70:
            raise ValueError("The PE optional header is truncated.")
        magic = struct.unpack_from("<H", optional)[0]
        if magic not in {0x10b, 0x20b}:
            raise ValueError("The PE optional header format is unsupported.")
        subsystem = struct.unpack_from("<H", optional, 68)[0]
    return {"format": "PE32+" if magic == 0x20b else "PE32", "size_bytes": size,
            "architecture": {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64",
                             0x1c4: "arm"}.get(machine, "other"),
            "machine_code": f"0x{machine:04x}", "sections": sections,
            "subsystem_code": subsystem, "declares_dll": bool(flags & 0x2000),
            "static_header_only": True}


def verify_manifest(path, checkpoint, expected_stamp):
    with read_locked(path, MAX_MANIFEST, expected_stamp) as (handle, _):
        raw = handle.read(MAX_MANIFEST + 1)
        if len(raw) > MAX_MANIFEST:
            raise ValueError("The manifest exceeds 256 KiB.")
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        raise ValueError("The manifest must use UTF-8.") from None
    seen = set()
    good = total = 0
    failures = []
    for lineno, line in enumerate(lines, 1):
        if not line.strip() or line.startswith("#"):
            continue
        hit = MANIFEST_LINE.fullmatch(line)
        if not hit:
            raise ValueError(f"Manifest line {lineno} must contain a SHA-256 followed by a relative filename.")
        digest, name = hit.groups()
        checkpoint(total, None)
        key = name.replace("\\", "/").casefold()
        if key in seen or len(seen) >= 256:
            raise ValueError("The manifest contains a duplicate path or exceeds 256 entries.")
        seen.add(key)
        try:
            # Scope is the manifest's own folder, which is inside the workspace.
            target = target_file(path.parent, name)
        except (OSError, ValueError):
            failures.append({"line": lineno, "status": "missing_or_disallowed"})
            continue
        remaining = MAX_HASH_BYTES - total
        if target.stat().st_size > remaining:
            raise ValueError("The manifest exceeds the 2 GB total verification limit.")
        offset = total
        observed, count = digest_file(target, remaining, lambda n, _: checkpoint(offset + n, None))
        total += count
        if hmac.compare_digest(digest.lower(), observed):
            good += 1
        else:
            failures.append({"line": lineno, "relative_path": name, "status": "digest_mismatch"})
    if not seen:
        raise ValueError("The manifest contains no checksums.")
    return {"valid": not failures, "files": len(seen), "matched": good, "failed": len(failures),
            "verified_bytes": total, "issues": failures[:MAX_REPORT], "issues_truncated": len(failures) > MAX_REPORT}


def _unsafe_member(info):
    name = info.orig_filename.replace("\\", "/").rstrip("/")
    if not name or "\\" in info.orig_filename or "\x00" in name:
        return True
    parts = name.split("/")
    invalid = any(part in {"", ".", ".."} or part.endswith((".", " ")) or
                  PureWindowsPath(part).is_reserved() or re.search(r'[:<>"|?*\x00-\x1f]', part)
                  for part in parts)
    return bool(invalid or stat.S_ISLNK(info.external_attr >> 16) or info.external_attr & 0x400)


def inspect_zip(path, params, checkpoint, expected_stamp):
    members, issues, seen = [], [], set()
    total = completed = 0
    checked_bytes = 0
    try:
        with read_locked(path, MAX_ZIP_BYTES, expected_stamp) as (handle, size):
            # Guard memory before ZipFile builds objects for the central directory.
            end = zipfile._EndRecData(handle)
            if end is None:
                raise zipfile.BadZipFile("No central directory")
            if end[zipfile._ECD_SIZE] > 4 * 1024 * 1024 or end[zipfile._ECD_ENTRIES_TOTAL] > 5_000:
                raise ValueError("The ZIP central directory exceeds the inspection limit.")
            with zipfile.ZipFile(handle) as archive:
                entries = archive.infolist()
                if len(entries) > 5_000:
                    raise ValueError("The ZIP contains more than 5,000 entries.")
                for info in entries:
                    checkpoint(0, None)
                    key = info.orig_filename.rstrip("/").casefold()
                    display = info.orig_filename[:160]
                    flags = []
                    if _unsafe_member(info):
                        flags.append("unsafe_path_or_link")
                    if key in seen:
                        flags.append("duplicate_path")
                    seen.add(key)
                    if info.flag_bits & 1:
                        flags.append("encrypted")
                    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED} and not info.is_dir():
                        flags.append("unsupported_crc_method")
                    if not info.is_dir():
                        total += info.file_size
                    if flags:
                        issues.append({"name": display, "flags": flags})
                    if len(members) < MAX_REPORT:
                        members.append({"name": display, "directory": info.is_dir(), "size_bytes": info.file_size})
                if params["verify_crc"] and not issues:
                    if total > MAX_ZIP_EXPANDED:
                        raise ValueError("Expanded files exceed the 500 MB CRC inspection limit; use verify_crc=false for metadata.")
                    for info in entries:
                        checkpoint(checked_bytes, total)
                        if info.is_dir():
                            continue
                        member_read = 0
                        with archive.open(info) as contents:
                            while block := contents.read(CHUNK):
                                member_read += len(block)
                                checked_bytes += len(block)
                                if member_read > info.file_size or checked_bytes > total:
                                    raise zipfile.BadZipFile("Expanded data exceeds its declared size")
                                checkpoint(checked_bytes, total)
                        if member_read != info.file_size:
                            raise zipfile.BadZipFile("ZIP member length mismatch")
                        completed += 1
    except (zipfile.BadZipFile, EOFError, RuntimeError, UnicodeError, struct.error, zlib.error, OverflowError) as exc:
        return {"valid_structure": False, "crc_verified": False, "issue": type(exc).__name__}
    return {"valid_structure": True, "safe_member_paths": not any(
                set(issue["flags"]) & {"unsafe_path_or_link", "duplicate_path"} for issue in issues),
            "crc_verified": bool(params["verify_crc"] and not issues), "size_bytes": size,
            "member_count": len(entries), "expanded_bytes": total, "verified_files": completed,
            "members": members, "members_truncated": len(entries) > len(members),
            "issues": issues[:MAX_REPORT], "issues_truncated": len(issues) > MAX_REPORT}


def inventory(folder, params, checkpoint):
    visited = files = folders = skipped = total = truncated = 0
    counts = Counter()

    def visit(directory, depth):
        nonlocal visited, files, folders, skipped, total, truncated
        with guarded_inbox(directory), os.scandir(directory) as entries:
            for entry in entries:
                if visited == 5_000:
                    truncated = 1
                    return
                visited += 1
                checkpoint(visited, 5_000)
                path = Path(entry.path)
                if not clean_part(entry.name) or protected_path(path):
                    skipped += 1
                    continue
                try:
                    # Windows DirEntry.stat can leave st_nlink at zero; lstat
                    # supplies the real count used by the workspace guard.
                    attrs = path.lstat()
                except OSError:
                    skipped += 1
                    continue
                if getattr(attrs, "st_file_attributes", 0) & 0x400:
                    skipped += 1
                elif stat.S_ISDIR(attrs.st_mode):
                    folders += 1
                    if depth < params["max_depth"]:
                        visit(path, depth + 1)
                        if truncated:
                            return
                elif stat.S_ISREG(attrs.st_mode) and attrs.st_nlink == 1 and raw_exportable(path):
                    files += 1
                    total += attrs.st_size
                    counts[path.suffix.casefold()[:35] or "(none)"] += 1
                else:
                    skipped += 1

    visit(folder, 0)
    return {"files": files, "directories": folders, "total_bytes": total, "excluded_entries": skipped,
            "max_depth": params["max_depth"], "scan_truncated": bool(truncated),
            "extensions": dict(counts.most_common(24))}
