"""Bounded, no-overwrite Windows file actions for the typed job runner."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import zipfile
import zlib

import task_verification as verify
from file_bridge import raw_exportable
from transfer_mailbox import guarded_inbox
from workspace import clean_part, no_link, protected_path, relative_parts, resolve

MAX_BYTES = 2_000_000_000
MAX_ENTRIES = 5_000
ID = re.compile(r"[0-9a-f]{32}\Z")
PRESETS = {
    "copy_file": {"label": "复制文件到新位置", "target": "file", "writes": True},
    "copy_directory": {"label": "复制目录到新位置", "target": "directory", "writes": True},
    "zip_extract": {"label": "解压 ZIP 到新目录", "target": "file", "writes": True},
    "text_to_docx": {"label": "UTF-8 文本生成纯文本 DOCX", "target": "file", "writes": True},
}
DESTINATION_PARAMETER = {"destination_path": {"type": "string", "optional": True,
                                               "description": "New workspace-relative path; never overwrites."}}
for _spec in PRESETS.values():
    _spec["parameters"] = DESTINATION_PARAMETER


def _identifier(path, directory):
    attrs = no_link(path, directory)
    return [attrs.st_dev, attrs.st_ino]


def _relative_child(base, candidate):
    rel = candidate.relative_to(base).as_posix()
    relative_parts(rel)
    if protected_path(candidate):
        raise ValueError("The operation reaches a protected workspace path.")
    return rel


def destination(base, source, preset, params=None):
    if params is not None and (not isinstance(params, dict) or set(params) - {"destination_path"}):
        raise ValueError("This preset accepts only parameters.destination_path.")
    default = params is None or "destination_path" not in params
    if default:
        if source == base:
            raise ValueError("Choose a subfolder to copy; its destination must stay inside the workspace.")
        if preset == "copy_file":
            name = source.stem[:160] + "-copy" + source.suffix[:48]
        elif preset == "copy_directory":
            name = source.name[:180] + "-copy"
        elif preset == "text_to_docx":
            name = source.stem[:180] + ".docx"
        else:
            name = source.stem[:180] + "-extracted"
        requested = (source.parent / name).relative_to(base).as_posix()
    else:
        requested = params["destination_path"]
    # Validate as a new opaque path, including all existing ancestors. The new
    # file/dir is created only by a successful, same-directory publication.
    target = _destination_path(base, requested)
    if not raw_exportable(target):
        raise ValueError("Key and credential-container formats cannot be created by this task.")
    if preset == "text_to_docx" and target.suffix.casefold() != ".docx":
        raise ValueError("The DOCX output path must end in .docx.")
    if target == source or source in target.parents:
        raise ValueError("The destination cannot be inside its source directory.")
    return target.relative_to(base).as_posix()


def require_unused(base, relative):
    if os.path.lexists(_destination_path(base, relative)):
        raise ValueError("The destination already exists; nothing was overwritten.")


def _destination_path(base, relative):
    parts = relative_parts(relative)
    parent = resolve(base, "/".join(parts[:-1]) or ".", folder=True)
    target = parent / parts[-1]
    _relative_child(base, target)
    return target


def _stage_path(target, job_id):
    if not isinstance(job_id, str) or not ID.fullmatch(job_id):
        raise ValueError("Invalid file action job.")
    return target.parent / (".dot-action-" + job_id)


def _owned_stage(target, job_id, record):
    stage = _stage_path(target, job_id)
    if stage.parent != target.parent or stage.name != ".dot-action-" + job_id:
        raise ValueError("Unexpected file action stage path.")
    if _identifier(stage, True) != record.get("stage_id"):
        raise ValueError("The staging directory no longer belongs to this file action.")
    return stage


def _cleanup(target, job_id, record):
    """Only remove the exact directory created by this job; never link targets."""
    def remove_owned(folder, expected):
        with guarded_inbox(folder):
            if _identifier(folder, True) != expected:
                raise ValueError("A staging directory was replaced.")
            for child in folder.iterdir():
                info = child.lstat()
                linked = bool(getattr(info, "st_file_attributes", 0) & 0x400)
                if stat.S_ISDIR(info.st_mode) and not linked:
                    remove_owned(child, [info.st_dev, info.st_ino])
                elif linked and getattr(info, "st_file_attributes", 0) & 0x10:
                    child.rmdir()  # remove a junction itself; never scan its target
                else:
                    child.unlink()
        if _identifier(folder, True) != expected:
            raise ValueError("A staging directory changed before cleanup.")
        folder.rmdir()

    with guarded_inbox(target.parent):
        try:
            stage = _owned_stage(target, job_id, record)
        except FileNotFoundError:
            return
        remove_owned(stage, record["stage_id"])


def _copy_stream(source, output, limit, checkpoint, stamp=None):
    digest = hashlib.sha256()
    written = 0
    with verify.read_locked(source, limit, stamp) as (reader, size), output.open("xb") as sink:
        while chunk := reader.read(verify.CHUNK):
            written += len(chunk)
            if written > size:
                raise ValueError("Source grew during copy.")
            digest.update(chunk)
            sink.write(chunk)
            checkpoint(written, size)
        if written != size:
            raise ValueError("Source changed during copy.")
        attrs = os.fstat(reader.fileno())
    os.utime(output, ns=(attrs.st_atime_ns, attrs.st_mtime_ns))
    return written, digest.hexdigest()


def _copy_directory(base, source, logical_dest, temporary, checkpoint):
    total = files = directories = excluded = visited = 0

    def walk(src, actual, logical):
        nonlocal total, files, directories, excluded, visited
        _relative_child(base, logical)
        actual.mkdir()
        with guarded_inbox(src), guarded_inbox(actual):
            for path in src.iterdir():
                visited += 1
                checkpoint(total, None)
                if visited > MAX_ENTRIES:
                    raise ValueError("Directory copy exceeds 5,000 entries.")
                if not clean_part(path.name) or protected_path(path) or not raw_exportable(path):
                    excluded += 1
                    continue
                info = path.lstat()
                if getattr(info, "st_file_attributes", 0) & 0x400:
                    excluded += 1
                    continue
                here, final = actual / path.name, logical / path.name
                _relative_child(base, final)
                _relative_child(base, path)
                if stat.S_ISDIR(info.st_mode):
                    walk(path, here, final)
                    directories += 1
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    prior = total
                    n, _ = _copy_stream(path, here, MAX_BYTES - prior,
                                        lambda done, _: checkpoint(prior + done, None), verify.stamp(info))
                    total += n
                    files += 1
                else:
                    excluded += 1

    walk(source, temporary, logical_dest)
    return {"files": files, "directories": directories, "size_bytes": total, "excluded_entries": excluded}


def _members(archive, base, target, checkpoint):
    seen, members = {}, []
    plan_nodes = {}
    total = 0
    for info in archive.infolist():
        checkpoint(0, None)
        name = info.orig_filename.rstrip("/")
        parts = name.split("/")
        if (verify._unsafe_member(info) or not all(clean_part(part) for part in parts)
                or not raw_exportable(Path(parts[-1]))):
            raise ValueError("ZIP contains a protected, linked, or unsafe member path.")
        if info.flag_bits & 1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise ValueError("ZIP contains an encrypted member or an unsupported compression method.")
        for index in range(1, len(parts) + 1):
            path_parts = tuple(parts[:index])
            key = tuple(part.casefold() for part in path_parts)
            directory = index < len(parts) or info.is_dir()
            old = plan_nodes.setdefault(key, (path_parts, directory))
            if old != (path_parts, directory):
                raise ValueError("ZIP contains conflicting file and directory paths.")
            _relative_child(base, (target / Path(*path_parts)))
            if len(plan_nodes) > MAX_ENTRIES:
                raise ValueError("ZIP exceeds 5,000 output paths.")
        key = tuple(part.casefold() for part in parts)
        if key in seen:
            raise ValueError("ZIP contains duplicate member paths.")
        seen[key] = True
        if not info.is_dir():
            total += info.file_size
            if total > verify.MAX_ZIP_EXPANDED:
                raise ValueError("ZIP would expand beyond 500 MB.")
        members.append((info, parts))
    return members, total


def _extract(base, source, target, temporary, checkpoint, stamp):
    files = done = 0
    directories = set()
    try:
        with verify.read_locked(source, verify.MAX_ZIP_BYTES, stamp) as (reader, _):
            end = zipfile._EndRecData(reader)
            if (end is None or end[zipfile._ECD_ENTRIES_TOTAL] > MAX_ENTRIES or
                    end[zipfile._ECD_SIZE] > 4 * 1024 * 1024):
                raise ValueError("ZIP central directory is missing or exceeds the inspection limit.")
            with zipfile.ZipFile(reader) as archive:
                members, total = _members(archive, base, target, checkpoint)
                if shutil.disk_usage(temporary.parent).free < total:
                    raise ValueError("Not enough free space for the expanded ZIP.")
                temporary.mkdir()
                for info, parts in members:
                    checkpoint(done, total)
                    item = temporary.joinpath(*parts)
                    for count in range(1, len(parts) + (1 if info.is_dir() else 0)):
                        directories.add(tuple(parts[:count]))
                    path = temporary
                    for component in (parts if info.is_dir() else parts[:-1]):
                        with guarded_inbox(path):
                            path /= component
                            path.mkdir(exist_ok=True)
                            no_link(path, True)
                    if info.is_dir():
                        continue
                    written = 0
                    with guarded_inbox(item.parent), archive.open(info) as original, item.open("xb") as output:
                        while chunk := original.read(verify.CHUNK):
                            written += len(chunk)
                            done += len(chunk)
                            if written > info.file_size or done > total:
                                raise ValueError("ZIP member exceeds its declared size.")
                            output.write(chunk)
                            checkpoint(done, total)
                    if written != info.file_size:
                        raise ValueError("ZIP member ended before its declared size.")
                    files += 1
    except (zipfile.BadZipFile, RuntimeError, EOFError, zlib.error, struct.error, UnicodeError, OverflowError) as exc:
        raise ValueError("ZIP is corrupt or its contents could not be verified.") from exc
    return {"files": files, "directories": len(directories), "size_bytes": done, "crc_verified": True}


def execute(base, source, job, checkpoint, journal):
    """Stage bytes next to the destination, then atomically publish a new name."""
    if os.name != "nt":
        raise ValueError("File actions require Windows.")
    preset = job["preset"]
    target = _destination_path(base, job["destination_path"])
    directory = preset in {"copy_directory", "zip_extract"}
    job_id = job["job_id"]
    stage = _stage_path(target, job_id)
    with guarded_inbox(target.parent):
        if os.path.lexists(target):
            raise ValueError("The destination already exists; nothing was overwritten.")
        stage.mkdir(mode=0o700)
        record = {"stage_id": _identifier(stage, True), "phase": "staging"}
        try:
            journal(record)
            with guarded_inbox(stage):
                content = stage / "content"
                if preset == "copy_file":
                    size, digest = _copy_stream(source, content, MAX_BYTES, checkpoint, job["file_stamp"])
                    result = {"files": 1, "size_bytes": size, "sha256": digest}
                elif preset == "copy_directory":
                    result = _copy_directory(base, source, target, content, checkpoint)
                elif preset == "text_to_docx":
                    from task_documents import convert
                    result = convert(source, content, checkpoint, job["file_stamp"])
                else:
                    result = _extract(base, source, target, content, checkpoint, job["file_stamp"])
                result["destination_path"] = job["destination_path"]
                record = {**record, "phase": "publishing", "output_id": _identifier(content, directory),
                          "directory": directory, "result": result}
                journal(record)
                # Recheck authorization and cancellation immediately before the
                # commit. After this rename the operation is already complete.
                checkpoint(result["size_bytes"], result["size_bytes"], force=True)
                try:
                    os.rename(content, target)  # Win32 refuses to replace an existing file or directory.
                except FileExistsError as exc:
                    raise ValueError("The destination already exists; nothing was overwritten.") from exc
                return result
        finally:
            try:
                _cleanup(target, job_id, record)
            except (OSError, ValueError):
                # Runner retains the journal so an interrupted/failed cleanup can
                # retry without treating an unrelated path as temporary output.
                record["cleanup_pending"] = True
            else:
                record.pop("cleanup_pending", None)


def recover(base, job):
    """Keep the committed result if a worker stopped just after an atomic rename."""
    record = job.get("publication")
    if not record:
        return None
    target = _destination_path(base, job["destination_path"])
    recovered = None
    with guarded_inbox(target.parent):
        if record.get("phase") == "publishing":
            try:
                if _identifier(target, record["directory"]) == record.get("output_id"):
                    recovered = record["result"]
            except (OSError, ValueError):
                pass
        try:
            _cleanup(target, job["job_id"], record)
        except (OSError, ValueError):
            record["cleanup_pending"] = True
        else:
            record.pop("cleanup_pending", None)
    return recovered


def retry_cleanup(base, job):
    target = _destination_path(base, job["destination_path"])
    _cleanup(target, job["job_id"], job["publication"])
