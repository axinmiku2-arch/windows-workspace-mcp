"""Short lived HTTPS opens over bounded, immutable outgoing file snapshots."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import mimetypes
import msvcrt
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import threading
import time
import zipfile

from core import FUNNEL, canonical_origin, load_config, read_json, save_json, uses_funnel

DOCUMENT_TYPES = frozenset({".pdf", ".docx", ".zip", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"})
# Original bytes do not use a preview-format allowlist. Keep key stores and
# credential container formats outside the raw transfer/packaging surface.
PRIVATE_FILE_TYPES = frozenset({".pem", ".key", ".pfx", ".p12", ".ppk", ".kdb", ".kdbx", ".jks", ".keystore"})
LEGACY_SYNC_MAX_BYTES = 20_000_000
MAX_BYTES = LEGACY_SYNC_MAX_BYTES  # Compatibility for unchanged imports.
TRANSFER_MAX_MB_DEFAULT = 100
TRANSFER_MAX_MB_MIN = 20
TRANSFER_MAX_MB_MAX = 1000
LINK_SECONDS = 420
TTL = LINK_SECONDS
SNAPSHOT_SECONDS = 24 * 3600
HISTORY_SECONDS = 24 * 3600
MAX_PENDING = 8
MAX_DISK_BYTES = 2_000_000_000
DISK_RESERVE_BYTES = 64_000_000
CHUNK = 1024 * 1024
OUTBOX = FUNNEL / "document-outbox"
QUEUE = OUTBOX / "exports"
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
IN_PROGRESS = {"queued", "copying"}
LIVE_STATES = IN_PROGRESS | {"ready"}
INSTRUCTIONS = (
    "Fetch the exact original from the authorized HTTPS client. Compare SHA-256 when complete. "
    "Use HTTP Range and the SHA-256 ETag to resume; request a fresh link by job_id when needed. "
    "Keep this short-lived URL private."
)
_last_cleanup = 0.0
_runner = None
_runner_start = threading.Lock()


def transfer_max_bytes(cfg):
    value = cfg.get("transfer_max_mb", TRANSFER_MAX_MB_DEFAULT)
    if type(value) is not int or not TRANSFER_MAX_MB_MIN <= value <= TRANSFER_MAX_MB_MAX:
        raise ValueError(f"Original file limit must be an integer between {TRANSFER_MAX_MB_MIN} and {TRANSFER_MAX_MB_MAX} MB")
    return value * 1_000_000


def policy_fingerprint(cfg):
    parts = [cfg.get(name) for name in ("origin", "workspace_enabled", "workspace_root", "workspace_revision",
                                       "approval_mode", "documents_enabled", "document_scope", "document_revision")]
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode()).hexdigest()


def _policy_allows(cfg, record):
    size = record.get("bytes")
    try:
        return (cfg.get("workspace_enabled") and cfg.get("documents_enabled") and uses_funnel(cfg)
                and type(size) is int and 0 <= size <= transfer_max_bytes(cfg)
                and isinstance(record.get("policy"), str)
                and hmac.compare_digest(record["policy"], policy_fingerprint(cfg)))
    except (ValueError, TypeError):
        return False


def files(token):
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise ValueError("Invalid delivery token")
    return OUTBOX / (token + ".json"), OUTBOX / (token + ".bin")


def _job_paths(job_id):
    if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
        raise ValueError("Invalid original export job ID")
    return (QUEUE / (job_id + ".json"), QUEUE / (job_id + ".part"), QUEUE / (job_id + ".bin"))


@contextmanager
def _state_lock(timeout=1.5):
    QUEUE.mkdir(parents=True, exist_ok=True)
    with (QUEUE / "queue.lock").open("a+b") as lock:
        if lock.tell() == 0:
            lock.write(b"0")
            lock.flush()
        end = time.monotonic() + timeout
        while True:
            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() >= end:
                    raise
                time.sleep(0.025)
        try:
            yield
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def _unlink(path):
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass  # A Windows response or copy may still hold the file open.


def _identity(path):
    entry = path.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or
            getattr(entry, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        raise ValueError("Original file must be regular, without links")
    return entry


def _stat_stamp(entry):
    return [entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns, entry.st_ctime_ns]


def raw_exportable(path):
    return Path(path).suffix.casefold() not in PRIVATE_FILE_TYPES


def _source_and_path(source, cfg, folder=False):
    # Deliberately lazy: the workspace imports this module for classification.
    from workspace import document_scope, resolve, workspace_root
    if not cfg.get("workspace_enabled") or not cfg.get("documents_enabled") or not uses_funnel(cfg):
        raise ValueError("Original downloads require document authorization and the local HTTPS relay")
    root = workspace_root(cfg["workspace_root"])
    try:
        p = Path(source).relative_to(root).as_posix()
    except ValueError:
        raise ValueError("Original is outside the authorized workspace") from None
    target = resolve(root, p, folder=folder, extensions=None)
    allowed = document_scope(root, cfg)
    if allowed is None or (allowed not in target.parents and not (folder and allowed == target)):
        raise ValueError("Original is outside the authorized document folder")
    if folder and target == Path(target.anchor):
        raise ValueError("Choose one folder to package, not a whole drive")
    if not folder and not raw_exportable(target):
        raise ValueError("Key and credential-container formats cannot be exported")
    return target, p


def _snapshot_copy(source, target, stamp, limit, observe):
    from transfer_mailbox import guarded_inbox
    with guarded_inbox(source.parent):
        return _snapshot_copy_guarded(source, target, stamp, limit, observe)


def _snapshot_copy_guarded(source, target, stamp, limit, observe):
    digest = hashlib.sha256()
    total = 0
    started = _identity(source)
    if _stat_stamp(started) != stamp:
        raise ValueError("Original file changed since submission; start a new export")
    with source.open("rb") as raw, target.open("xb") as copy:
        opened = os.fstat(raw.fileno())
        if _stat_stamp(opened) != stamp or opened.st_nlink != 1:
            raise ValueError("Original file changed before opening; start a new export")
        last = time.monotonic()
        while chunk := raw.read(CHUNK):
            total += len(chunk)
            if total > min(limit, stamp[2]):
                raise ValueError("Original file grew during copy; start a new export")
            digest.update(chunk)
            copy.write(chunk)
            now = time.monotonic()
            if now - last >= 0.25:
                observe(total)
                last = now
        after = os.fstat(raw.fileno())
        if total != stamp[2] or after.st_nlink != 1 or _stat_stamp(after) != stamp:
            raise ValueError("Original file changed during copy; start a new export")
    if _stat_stamp(_identity(source)) != stamp:
        raise ValueError("Original file was replaced during copy; start a new export")
    observe(total)
    return digest.hexdigest()


def _drop_token(record):
    token = record.get("token")
    if isinstance(token, str) and TOKEN.fullmatch(token):
        _unlink(files(token)[0])
    record.pop("token", None)
    record.pop("link_expires_at", None)


def _set_terminal(record, first, partial, body, state, message=None):
    record.update(state=state, updated_at=time.time())
    if message:
        record["message"] = message
    _drop_token(record)
    save_json(first, record)
    _unlink(partial)
    _unlink(body)


def _reserved(now):
    count, reserved = 0, 0
    for meta in OUTBOX.glob("*.json"):
        if not TOKEN.fullmatch(meta.stem):
            continue
        current = read_json(meta)
        if not current.get("job_id") and current.get("expires", 0) > now:
            count += 1
            reserved += int(current.get("bytes", 0))
    for meta in QUEUE.glob("*.json"):
        if not JOB_ID.fullmatch(meta.stem):
            continue
        current = read_json(meta)
        if current.get("state") in LIVE_STATES and current.get("snapshot_expires_at", 0) > now:
            count += 1
            reserved += int(current.get("bytes", 0))
    return count, reserved


def _reserve(size, now):
    count, reserved = _reserved(now)
    if count >= MAX_PENDING or reserved + size > MAX_DISK_BYTES:
        raise ValueError("The original export outbox is full; cancel an unused export or wait for expiry")
    if shutil.disk_usage(OUTBOX).free < size + DISK_RESERVE_BYTES:
        raise ValueError("Insufficient free disk space for the file snapshot")


def clear_expired(force=False):
    global _last_cleanup
    now = time.time()
    if not OUTBOX.is_dir() or (not force and now - _last_cleanup < 30):
        return
    _last_cleanup = now
    try:
        with _state_lock(timeout=0.05):
            cfg = load_config()
            for meta in OUTBOX.glob("*.json"):
                if not TOKEN.fullmatch(meta.stem):
                    continue
                record = read_json(meta)
                if record.get("expires", 0) <= now or not _policy_allows(cfg, record):
                    manifest, body = files(meta.stem)
                    if not record.get("job_id"):
                        _unlink(body)
                    _unlink(manifest)
            for body in OUTBOX.glob("*.bin"):
                if TOKEN.fullmatch(body.stem) and not body.with_suffix(".json").is_file():
                    try:
                        if body.stat().st_mtime + TTL < now:
                            _unlink(body)
                    except OSError:
                        pass
            for meta in QUEUE.glob("*.json"):
                if not JOB_ID.fullmatch(meta.stem):
                    continue
                record = read_json(meta)
                first, partial, body = _job_paths(meta.stem)
                if record.get("state") in LIVE_STATES:
                    if not _policy_allows(cfg, record):
                        _set_terminal(record, first, partial, body, "revoked", "Document or workspace authorization changed")
                    elif record.get("snapshot_expires_at", 0) <= now:
                        _set_terminal(record, first, partial, body, "expired", "The stable snapshot has expired")
                else:
                    _unlink(partial)
                    _unlink(body)
                    if record and record.get("updated_at", 0) + HISTORY_SECONDS < now:
                        _unlink(first)
            for ext in ("*.part", "*.bin"):
                for body in QUEUE.glob(ext):
                    if JOB_ID.fullmatch(body.stem) and not body.with_suffix(".json").exists():
                        try:
                            if body.stat().st_mtime + HISTORY_SECONDS < now:
                                _unlink(body)
                        except OSError:
                            pass
    except OSError:
        pass  # Cleanup never prevents an authorized download or enqueued task.


def _download_data(cfg, token, record):
    return {"file": record["name"], "bytes": record["bytes"], "sha256": record["sha256"],
            "expires_in_seconds": max(0, int(record["expires"] - time.time())),
            "expires_at": record["expires"],
            "download_url": canonical_origin(cfg["origin"]) + "/dot-files/" + token,
            "instructions": INSTRUCTIONS}


def snapshot(source, cfg):
    """Compatibility path for <=20 MB prepare_workspace_file calls."""
    source, _ = _source_and_path(source, cfg)
    initial = _identity(source)
    limit = min(LEGACY_SYNC_MAX_BYTES, transfer_max_bytes(cfg))
    if initial.st_size > limit:
        raise ValueError("Use the background original export for files larger than 20,000,000 bytes")
    clear_expired(force=True)
    key = secrets.token_urlsafe(32)
    manifest, target = files(key)
    record = {"name": source.name, "bytes": initial.st_size, "expires": time.time() + TTL,
              "mime": mimetypes.guess_type(source.name)[0] or "application/octet-stream",
              "policy": policy_fingerprint(cfg), "pending": True}
    with _state_lock():
        _reserve(initial.st_size, time.time())
        save_json(manifest, record)

    def permitted(_):
        if not _policy_allows(load_config(), record):
            raise ValueError("Document or workspace authorization changed")

    try:
        digest = _snapshot_copy(source, target, _stat_stamp(initial), limit, permitted)
        with _state_lock():
            permitted(initial.st_size)
            record.update(sha256=digest, expires=time.time() + TTL, pending=False)
            save_json(manifest, record)
    except Exception:
        _unlink(target)
        _unlink(manifest)
        raise
    return _download_data(cfg, key, record)


def _get_job(job_id):
    first, partial, body = _job_paths(job_id)
    record = read_json(first)
    if not record or record.get("job_id") != job_id:
        raise ValueError("Original export job was not found or its history expired")
    return record, first, partial, body


def _status(record):
    size = record["bytes"]
    copied = record.get("prepared_bytes", 0)
    max_progress = 100 if record["state"] in {"ready", "delivered"} else 99
    progress = (100 if max_progress == 100 else 0) if size == 0 else (
        min(max_progress, max(0, copied * 100 // size)))
    pending_archive = record.get("kind") == "zip_archive" and record["state"] in IN_PROGRESS
    return {**{name: record[name] for name in ("job_id", "state", "file", "relative_path", "bytes", "snapshot_expires_at")},
            **({"bytes": None, "zip_limit_bytes": size} if pending_archive else {}),
            "prepared_bytes": copied, "progress_percent": progress,
            **({key: record[key] for key in ("kind", "archive_files", "archive_excluded") if key in record}),
            **({"sha256": record["sha256"]} if record["state"] == "delivered" else {}),
            **({"message": record["message"]} if record.get("message") else {})}


def begin_export(source, cfg):
    """Enqueue an original export and return its public status without reading bytes."""
    source, label = _source_and_path(source, cfg)
    initial = _identity(source)
    size = initial.st_size
    limit = transfer_max_bytes(cfg)
    if size > limit:
        raise ValueError(f"Original exceeds the configured {limit:,}-byte transfer limit")
    clear_expired(force=True)
    now = time.time()
    job_id = secrets.token_hex(16)
    first, _, _ = _job_paths(job_id)
    record = {"job_id": job_id, "state": "queued", "file": source.name, "relative_path": label,
              "stamp": _stat_stamp(initial), "bytes": size, "prepared_bytes": 0,
              "policy": policy_fingerprint(cfg), "created_at": now, "updated_at": now,
              "snapshot_expires_at": now + SNAPSHOT_SECONDS}
    with _state_lock():
        if not _policy_allows(load_config(), record):
            raise ValueError("Document or workspace authorization changed")
        _reserve(size, now)
        save_json(first, record)
    return _status(record)


def begin_archive(source, cfg):
    """Queue a directory ZIP without traversing or reading it on the MCP request."""
    source, label = _source_and_path(source, cfg, folder=True)
    info = source.lstat()
    clear_expired(force=True)
    now = time.time()
    job_id = secrets.token_hex(16)
    first, _, _ = _job_paths(job_id)
    filename = source.name[:185] + ".zip"
    limit = transfer_max_bytes(cfg)
    record = {"job_id": job_id, "kind": "zip_archive", "state": "queued", "file": filename,
              "relative_path": label, "directory_id": [info.st_dev, info.st_ino],
              "bytes": limit, "prepared_bytes": 0, "policy": policy_fingerprint(cfg),
              "created_at": now, "updated_at": now, "snapshot_expires_at": now + SNAPSHOT_SECONDS}
    with _state_lock():
        if not _policy_allows(load_config(), record):
            raise ValueError("Document or workspace authorization changed")
        _reserve(limit, now)
        save_json(first, record)
    return _status(record)


class _BoundedArchive:
    def __init__(self, stream, limit):
        self.stream, self.limit = stream, limit

    def write(self, data):
        if self.stream.tell() + len(data) > self.limit:
            raise ValueError("ZIP exceeds the configured transfer size; choose a smaller folder")
        return self.stream.write(data)

    def tell(self):
        return self.stream.tell()

    def seek(self, *args):
        return self.stream.seek(*args)

    def flush(self):
        return self.stream.flush()


def _archive_copy(source, output, record, observe):
    from transfer_mailbox import guarded_inbox
    from workspace import clean_part, no_link, protected_path

    limit = record["bytes"]
    scanned = total = excluded = included = 0
    started = last = time.monotonic()
    deadline = started + 180

    def tick(stream):
        nonlocal last
        now = time.monotonic()
        if now > deadline:
            raise ValueError("ZIP preparation exceeded three minutes; choose a smaller folder")
        if now - last >= 0.25:
            observe(stream.tell())
            last = now

    def walk(folder, member_path, archive, stream, level):
        nonlocal scanned, total, excluded, included
        with guarded_inbox(folder):
            info = no_link(folder, True)
            if folder == source and [info.st_dev, info.st_ino] != record["directory_id"]:
                raise ValueError("The selected folder changed since submission")
            archive.mkdir(member_path)
            for entry in folder.iterdir():
                scanned += 1
                if scanned > 5000:
                    raise ValueError("ZIP folder has too many entries; choose a smaller folder")
                tick(stream)
                if not clean_part(entry.name) or protected_path(entry):
                    excluded += 1
                    continue
                info = entry.lstat()
                if getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                    excluded += 1
                    continue
                arcname = member_path + "/" + entry.name
                if stat.S_ISDIR(info.st_mode):
                    if level >= 16:
                        raise ValueError("ZIP folder exceeds 16 nested levels; choose a smaller folder")
                    walk(entry, arcname, archive, stream, level + 1)
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not raw_exportable(entry):
                    excluded += 1
                    continue
                stamp = _stat_stamp(info)
                if total + info.st_size > min(4 * limit, 2_000_000_000):
                    raise ValueError("ZIP source byte budget exceeded; choose a smaller folder")
                copied = 0
                with entry.open("rb") as original, archive.open(arcname, "w") as member:
                    opened = os.fstat(original.fileno())
                    if opened.st_nlink != 1 or _stat_stamp(opened) != stamp:
                        raise ValueError("An archive source changed before opening; retry the job")
                    while chunk := original.read(CHUNK):
                        copied += len(chunk)
                        if copied > info.st_size:
                            raise ValueError("An archive source grew during packaging; retry the job")
                        member.write(chunk)
                        tick(stream)
                    current = os.fstat(original.fileno())
                    if copied != info.st_size or current.st_nlink != 1 or _stat_stamp(current) != stamp:
                        raise ValueError("An archive source changed during packaging; retry the job")
                if _stat_stamp(_identity(entry)) != stamp:
                    raise ValueError("An archive source was replaced during packaging; retry the job")
                total += copied
                included += 1

    with output.open("xb") as stream:
        guarded = _BoundedArchive(stream, limit)
        with zipfile.ZipFile(guarded, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=3) as archive:
            walk(source, source.name, archive, stream, 0)
        size = stream.tell()
    with output.open("rb") as stream:
        digest = hashlib.sha256()
        while chunk := stream.read(CHUNK):
            digest.update(chunk)
            if time.monotonic() - last >= 0.25:
                observe(size)
                last = time.monotonic()
    observe(size)
    return size, digest.hexdigest(), included, excluded


def _issue_link(record, first, cfg):
    now = time.time()
    key = secrets.token_urlsafe(32)
    expires = min(now + LINK_SECONDS, record["snapshot_expires_at"])
    meta = {"job_id": record["job_id"], "name": record["file"], "bytes": record["bytes"],
            "policy": record["policy"], "sha256": record["sha256"], "expires": expires,
            "mime": mimetypes.guess_type(record["file"])[0] or "application/octet-stream"}
    older = record.get("token")
    save_json(files(key)[0], meta)
    try:
        record.update(token=key, link_expires_at=expires, updated_at=now)
        save_json(first, record)
    except Exception:
        _unlink(files(key)[0])
        raise
    if isinstance(older, str) and TOKEN.fullmatch(older):
        _unlink(files(older)[0])
    return _download_data(cfg, key, meta)


def export_status(job_id, cfg, renew=False):
    """Read an export; an expired link can be renewed over the same snapshot."""
    if type(renew) is not bool:
        raise ValueError("renew must be true or false")
    with _state_lock():
        record, first, partial, body = _get_job(job_id)
        if record["state"] in LIVE_STATES:
            if not _policy_allows(cfg, record) or not _policy_allows(load_config(), record):
                _set_terminal(record, first, partial, body, "revoked", "Document or workspace authorization changed")
            elif record["snapshot_expires_at"] <= time.time():
                _set_terminal(record, first, partial, body, "expired", "The stable snapshot has expired")
        if record["state"] != "ready":
            return _status(record)
        try:
            valid_body = _identity(body).st_size == record["bytes"]
        except (OSError, ValueError):
            valid_body = False
        if not valid_body:
            _set_terminal(record, first, partial, body, "failed", "Original snapshot is no longer available")
            return _status(record)
        token = record.get("token")
        if renew:
            # An active link with plenty of time remaining is kept, so repeated
            # polling with renew=true does not interrupt another reader.
            if token and record.get("link_expires_at", 0) > time.time() + 45:
                meta = read_json(files(token)[0])
                if meta.get("job_id") == job_id:
                    return {**_status(record), **_download_data(cfg, token, meta)}
            return {**_status(record), **_issue_link(record, first, cfg)}
        if token and record.get("link_expires_at", 0) > time.time():
            meta = read_json(files(token)[0])
            if meta.get("job_id") == job_id and meta.get("expires", 0) > time.time():
                return {**_status(record), **_download_data(cfg, token, meta)}
        return {**_status(record), "sha256": record["sha256"], "renew_available": True}


def cancel_export(job_id, cfg):
    with _state_lock():
        record, first, partial, body = _get_job(job_id)
        if record["state"] in LIVE_STATES:
            if not _policy_allows(cfg, record) or not _policy_allows(load_config(), record):
                _set_terminal(record, first, partial, body, "revoked", "Document or workspace authorization changed")
            else:
                _set_terminal(record, first, partial, body, "cancelled", "Original export cancelled")
        return _status(record)


def complete_export(job_id, cfg, sha256):
    """Record the receiver's verified digest and release the outgoing snapshot."""
    if not isinstance(sha256, str) or not SHA256.fullmatch(sha256):
        raise ValueError("Provide the SHA-256 of the bytes actually downloaded")
    with _state_lock():
        record, first, partial, body = _get_job(job_id)
        if record["state"] in LIVE_STATES:
            if not _policy_allows(cfg, record) or not _policy_allows(load_config(), record):
                _set_terminal(record, first, partial, body, "revoked", "Document or workspace authorization changed")
                return _status(record)
            if record["snapshot_expires_at"] <= time.time():
                _set_terminal(record, first, partial, body, "expired", "The stable snapshot has expired")
                return _status(record)
        if record["state"] not in {"ready", "delivered"}:
            raise ValueError("The original export is not ready for a delivery receipt")
        if not hmac.compare_digest(record["sha256"], sha256.lower()):
            raise ValueError("Downloaded SHA-256 does not match; retry before acknowledging delivery")
        if record["state"] == "ready":
            _set_terminal(record, first, partial, body, "delivered", "Receiver confirmed the matching SHA-256")
        return _status(record)


def _copy_job(job_id):
    with _state_lock():
        record, first, partial, body = _get_job(job_id)
        if record["state"] not in IN_PROGRESS:
            return
        _unlink(partial)
        _unlink(body)
        record.update(state="copying", prepared_bytes=0, updated_at=time.time())
        save_json(first, record)

    def observe(total):
        with _state_lock():
            present, _, _, _ = _get_job(job_id)
            if present["state"] != "copying":
                raise InterruptedError("Export is no longer active")
            current = load_config()
            if not _policy_allows(current, present):
                raise PermissionError("Document or workspace authorization changed")
            if present["snapshot_expires_at"] <= time.time():
                raise TimeoutError("The stable snapshot has expired")
            present.update(prepared_bytes=total, updated_at=time.time())
            save_json(first, present)

    try:
        cfg = load_config()
        if not _policy_allows(cfg, record):
            raise PermissionError("Document or workspace authorization changed")
        root = Path(cfg["workspace_root"])
        archive = record.get("kind") == "zip_archive"
        source, _ = _source_and_path(root / record["relative_path"], cfg, folder=archive)
        if shutil.disk_usage(OUTBOX).free < record["bytes"] + DISK_RESERVE_BYTES:
            raise OSError("Insufficient free disk space for the file snapshot")
        if archive:
            size, digest, included, excluded = _archive_copy(source, partial, record, observe)
            ready_fields = {"bytes": size, "archive_files": included, "archive_excluded": excluded}
        else:
            digest = _snapshot_copy(source, partial, record["stamp"], transfer_max_bytes(cfg), observe)
            ready_fields = {}
        with _state_lock():
            record, _, _, _ = _get_job(job_id)
            if record["state"] != "copying":
                raise InterruptedError("Export is no longer active")
            cfg = load_config()
            if not _policy_allows(cfg, record):
                raise PermissionError("Document or workspace authorization changed")
            _source_and_path(source, cfg, folder=archive)
            if record["snapshot_expires_at"] <= time.time():
                raise TimeoutError("The stable snapshot has expired")
            os.replace(partial, body)
            record.update(ready_fields)
            record.update(state="ready", sha256=digest, prepared_bytes=record["bytes"], updated_at=time.time())
            _issue_link(record, first, cfg)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        _unlink(partial)
        with _state_lock():
            present, _, _, _ = _get_job(job_id)
            if present["state"] == "copying":
                if isinstance(exc, PermissionError):
                    state, message = "revoked", "Document or workspace authorization changed"
                elif isinstance(exc, TimeoutError):
                    state, message = "expired", "The stable snapshot has expired"
                elif isinstance(exc, ValueError):
                    state, message = "failed", str(exc)
                else:
                    state, message = "failed", "Unable to prepare the snapshot; check file availability and free disk space"
                _set_terminal(present, first, partial, body, state, message)
            else:
                _unlink(body)


def _run_exports():
    try:
        waiting = []
        for meta in QUEUE.glob("*.json"):
            if not JOB_ID.fullmatch(meta.stem):
                continue
            record = read_json(meta)
            if record.get("state") in IN_PROGRESS:
                waiting.append((record["created_at"], meta.stem))
        for _, job_id in sorted(waiting):
            _copy_job(job_id)
    except (OSError, ValueError, KeyError, TypeError):
        # Worker heartbeat must continue. A later pump can pick up remaining work.
        return


def pump_exports(cfg):
    """Worker-only call. Resume queued or interrupted copies on a background thread."""
    global _runner
    if not QUEUE.is_dir() or not cfg.get("workspace_enabled") or not cfg.get("documents_enabled"):
        return
    with _runner_start:
        if _runner is None or not _runner.is_alive():
            _runner = threading.Thread(target=_run_exports, name="dot-original-exports", daemon=True)
            _runner.start()


def ready_download(token):
    """Relay-only lookup used by GET/HEAD; validate the policy on every request."""
    clear_expired()
    try:
        manifest, body = files(token)
        record = read_json(manifest)
        cfg = load_config()
        sha, name = record.get("sha256"), record.get("name")
        if (record.get("pending") or not _policy_allows(cfg, record)
                or record.get("expires", 0) <= time.time() or not isinstance(sha, str) or not SHA256.fullmatch(sha)
                or not isinstance(name, str) or not name or any(ord(char) < 32 or ord(char) == 127 for char in name)):
            return None
        if job_id := record.get("job_id"):
            job, _, _, body = _get_job(job_id)
            if (job.get("state") != "ready" or job.get("token") != token
                    or job.get("snapshot_expires_at", 0) <= time.time()
                    or job.get("bytes") != record["bytes"] or job.get("sha256") != record["sha256"]
                    or not _policy_allows(cfg, job)):
                return None
        if _identity(body).st_size != record["bytes"]:
            return None
        return body, record
    except (OSError, ValueError, KeyError, TypeError):
        return None
