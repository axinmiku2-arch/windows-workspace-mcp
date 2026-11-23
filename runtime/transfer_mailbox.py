"""Private scoped file mailbox for the Windows HTTPS relay."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import threading
import time

from core import FUNNEL, canonical_origin, load_config, uses_funnel

HOME = FUNNEL / "mailbox"
STAGED = HOME / "staged"
DB = HOME / "mailbox.sqlite3"
TOKEN_TTL = 1200
PENDING_TTL = 86400
HISTORY_TTL = 7 * 86400
LEASE_SECONDS = 90
STREAM_SECONDS = 3600
MAX_PENDING = 6
MAX_OUTGOING = 30
MAX_HISTORY = 250
MAX_STAGED_BYTES = 1_500_000_000
CHUNK = 256 * 1024
ID_RE = re.compile(r"[0-9a-f]{32}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
ACTIVE = ("awaiting_upload", "uploading", "awaiting_approval", "delivering")
TERMINAL = ("delivered", "cancelled", "rejected", "expired", "failed")
_last_cleanup = 0.0


@contextmanager
def store():
    STAGED.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=3, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS incoming (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
          state TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL, expires REAL NOT NULL,
          policy TEXT NOT NULL, scope TEXT NOT NULL, scope_id TEXT NOT NULL,
          request_key TEXT, token_hash TEXT, token_expires REAL,
          received INTEGER NOT NULL DEFAULT 0, lease_id TEXT, lease_until REAL,
          delivery_stamp TEXT, error TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS incoming_request ON incoming(policy, request_key);
        CREATE UNIQUE INDEX IF NOT EXISTS incoming_token ON incoming(token_hash);
        CREATE TABLE IF NOT EXISTS outgoing (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, relative_path TEXT NOT NULL,
          size INTEGER NOT NULL, created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS outgoing_receipts (
          id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, received_at REAL NOT NULL
        );
        """)
        yield db
    finally:
        db.close()


@contextmanager
def transaction(db):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


def validate_receive_scope(value, cfg):
    from workspace import workspace_root

    if not cfg.get("workspace_enabled") or not uses_funnel(cfg):
        raise ValueError("Enable the authorized workspace and fixed Windows relay before setting an inbox")
    if not isinstance(value, (str, os.PathLike)) or not str(value).strip():
        raise ValueError("Choose a dedicated existing Windows inbox folder")
    root = workspace_root(cfg["workspace_root"])
    scope = workspace_root(str(value))
    if root not in scope.parents:
        raise ValueError("Choose a dedicated subfolder inside the authorized workspace for the inbox")
    return scope


def check_receive(cfg):
    if not cfg.get("receive_enabled") or not cfg.get("receive_revision"):
        raise ValueError("Enable the dedicated inbox in the local Windows manager")
    scope = validate_receive_scope(cfg.get("receive_scope", ""), cfg)
    return scope, file_identity(scope.stat())


def policy_fingerprint(cfg):
    values = [cfg.get(field) for field in (
        "origin", "workspace_enabled", "workspace_root", "workspace_revision",
        "workspace_unified", "approval_mode", "receive_enabled", "receive_scope", "receive_revision",
    )]
    return hashlib.sha256(json.dumps(values, ensure_ascii=False).encode("utf-8")).hexdigest()


def file_identity(info):
    return f"{info.st_dev}:{info.st_ino}"


def offered_name(value):
    from workspace import clean_part

    if (not isinstance(value, str) or len(value) > 150 or not value or value != value.strip()
            or "/" in value or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(c in value for c in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
            or not clean_part(value)):
        raise ValueError("Provide a single normal filename with no path, reserved name, or alternate stream")
    return value


def valid_id(transfer_id):
    if not isinstance(transfer_id, str) or not ID_RE.fullmatch(transfer_id):
        raise ValueError("Invalid mailbox transfer ID")
    return transfer_id


def payload_path(transfer_id):
    return STAGED / (valid_id(transfer_id) + ".upload")


def partial_path(transfer_id, lease):
    return STAGED / (valid_id(transfer_id) + "-" + valid_id(lease) + ".part")


def inbox_temp(scope, transfer_id):
    return scope / (".dot-incoming-" + valid_id(transfer_id) + ".part")


def remove(path):
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def select_incoming(db, transfer_id):
    return db.execute("SELECT * FROM incoming WHERE id=?", (valid_id(transfer_id),)).fetchone()


def new_token(db, transfer_id, now):
    token = secrets.token_urlsafe(32)
    expires = now + TOKEN_TTL
    db.execute("UPDATE incoming SET token_hash=?,token_expires=?,updated=? WHERE id=?",
               (hashlib.sha256(token.encode("ascii")).hexdigest(), expires, now, transfer_id))
    return token


def incoming_view(row):
    return dict(transfer_id=row["id"], direction="incoming", name=row["name"], size_bytes=row["size"],
                sha256=row["sha256"], state=row["state"], received_bytes=row["received"],
                created_at=row["created"], updated_at=row["updated"], expires_at=row["expires"],
                can_renew=row["state"] == "awaiting_upload",
                saved_name=row["name"] if row["state"] == "delivered" else None,
                error=row["error"])


def with_upload_link(view, cfg, token):
    if token is not None:
        decision = ("The enabled local full grant permits automatic placement after verification."
                    if auto_receive(cfg) else "The local Windows manager must approve placement after verification.")
        view.update(upload_url=canonical_origin(cfg["origin"]) + "/dot-uploads/" + token,
                    upload_method="PUT", upload_expires_in_seconds=TOKEN_TTL,
                    instructions=("PUT the exact original bytes from the authorized HTTPS client. "
                                  "Do not use form encoding or share this private URL. "
                                  + decision))
    return view


def require_policy(row, cfg):
    if row is None:
        raise ValueError("Unknown mailbox transfer")
    if row["policy"] != policy_fingerprint(cfg):
        raise ValueError("The inbox permission changed; create a new transfer")


def receive_limit(cfg):
    from file_bridge import transfer_max_bytes
    return transfer_max_bytes(cfg)


def create_upload(filename, size_bytes, sha256, cfg, request_key=""):
    name = offered_name(filename)
    if type(size_bytes) is not int or not 0 <= size_bytes <= receive_limit(cfg):
        raise ValueError("Declared file size exceeds the current transfer limit")
    if not isinstance(sha256, str) or not HEX_RE.fullmatch(sha256.lower()):
        raise ValueError("Provide the SHA-256 hex digest of the original file")
    sha256 = sha256.lower()
    if not isinstance(request_key, str) or (request_key and not KEY_RE.fullmatch(request_key)):
        raise ValueError("Invalid request key; use up to 80 ASCII letters, digits, hyphens or underscores")
    scope, scope_id = check_receive(cfg)
    cleanup(cfg)
    now = time.time()
    policy = policy_fingerprint(cfg)
    with store() as db, transaction(db):
        row = None
        if request_key:
            row = db.execute("SELECT * FROM incoming WHERE policy=? AND request_key=?",
                             (policy, request_key)).fetchone()
        if row is not None:
            if (row["name"], row["size"], row["sha256"]) != (name, size_bytes, sha256):
                raise ValueError("This request key is already assigned to a different file")
            transfer_id = row["id"]
            token = new_token(db, transfer_id, now) if row["state"] == "awaiting_upload" else None
        else:
            if os.path.lexists(scope / name):
                raise ValueError("The destination already exists; choose a different filename")
            active, reserved = db.execute(
                "SELECT COUNT(*), COALESCE(SUM(size),0) FROM incoming WHERE state IN (?,?,?,?)", ACTIVE
            ).fetchone()
            if active >= MAX_PENDING or reserved + size_bytes > MAX_STAGED_BYTES:
                raise ValueError("Windows inbox staging is full; finish or cancel an existing transfer")
            # Make space for all reservations on disk, even if they have not started streaming.
            if shutil.disk_usage(STAGED).free < reserved + size_bytes + 16 * 1024 * 1024:
                raise ValueError("Not enough staging space on Windows")
            transfer_id = secrets.token_hex(16)
            db.execute("""INSERT INTO incoming(id,name,size,sha256,state,created,updated,expires,policy,scope,scope_id,request_key)
                          VALUES(?,?,?,?,'awaiting_upload',?,?,?,?,?,?,?)""",
                       (transfer_id, name, size_bytes, sha256, now, now, now + PENDING_TTL,
                        policy, str(scope), scope_id, request_key or None))
            token = new_token(db, transfer_id, now)
        return with_upload_link(incoming_view(select_incoming(db, transfer_id)), cfg, token)


def upload_status(transfer_id, cfg, renew=False):
    cleanup(cfg)
    with store() as db, transaction(db):
        row = select_incoming(db, transfer_id)
        require_policy(row, cfg)
        token = None
        if renew:
            if row["state"] != "awaiting_upload":
                raise ValueError("Only a transfer awaiting upload can receive a new link")
            check_receive(cfg)
            token = new_token(db, row["id"], time.time())
            row = select_incoming(db, transfer_id)
        return with_upload_link(incoming_view(row), cfg, token)


def abort_upload(transfer_id, cfg, rejected=False):
    with store() as db, transaction(db):
        row = select_incoming(db, transfer_id)
        require_policy(row, cfg)
        if row["state"] == "delivering":
            raise ValueError("The local delivery has already started")
        if row["state"] in ACTIVE:
            state = "rejected" if rejected else "cancelled"
            db.execute("""UPDATE incoming SET state=?,updated=?,token_hash=NULL,token_expires=NULL,
                          lease_id=NULL,lease_until=NULL WHERE id=?""", (state, time.time(), transfer_id))
            remove(payload_path(transfer_id))
            if row["state"] == "uploading" and row["lease_id"]:
                remove(partial_path(transfer_id, row["lease_id"]))
        return incoming_view(select_incoming(db, transfer_id))


def cancel_upload(transfer_id, cfg):
    return abort_upload(transfer_id, cfg)


def reject_upload(transfer_id, cfg):
    return abort_upload(transfer_id, cfg, rejected=True)


class TransferError(Exception):
    def __init__(self, status, text):
        super().__init__(text)
        self.status = status


def begin_upload(token, content_length, cfg):
    if not uses_funnel(cfg) or not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise TransferError(404, "Upload link unavailable")
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with store() as db, transaction(db):
        row = db.execute("SELECT * FROM incoming WHERE token_hash=?", (token_hash,)).fetchone()
        now = time.time()
        if (row is None or row["policy"] != policy_fingerprint(cfg) or row["token_expires"] <= now
                or row["expires"] <= now or not cfg.get("receive_enabled")):
            raise TransferError(404, "Upload link unavailable")
        if row["state"] in ("awaiting_approval", "delivering", "delivered"):
            return row, None
        if row["state"] != "awaiting_upload":
            raise TransferError(409, "A transfer is already in progress or no longer available")
        if content_length is not None and (not content_length.isascii() or not content_length.isdecimal()
                                           or len(content_length) > 12 or int(content_length) != row["size"]):
            raise TransferError(400, "Content-Length must match the declared file size")
        if row["size"] > receive_limit(cfg):
            raise TransferError(413, "Declared file size exceeds the current transfer limit")
        try:
            _, scope_id = check_receive(cfg)
        except (ValueError, OSError):
            raise TransferError(404, "Upload link unavailable") from None
        if row["scope_id"] != scope_id:
            raise TransferError(404, "Upload link unavailable")
        lease = secrets.token_hex(16)
        db.execute("""UPDATE incoming SET state='uploading', received=0, error=NULL, lease_id=?,lease_until=?,updated=?
                      WHERE id=?""", (lease, now + LEASE_SECONDS, now, row["id"]))
        return select_incoming(db, row["id"]), lease


def pulse(transfer_id, lease, current_state, received):
    cfg = load_config()
    now = time.time()
    with store() as db, transaction(db):
        changed = db.execute("""UPDATE incoming SET received=?,lease_until=?,updated=?
            WHERE id=? AND lease_id=? AND state=? AND policy=? AND expires>?""",
            (received, now + LEASE_SECONDS, now, transfer_id, lease, current_state,
             policy_fingerprint(cfg), now)).rowcount
        if changed != 1:
            raise TransferError(409, "Transfer was cancelled, expired, or revoked")
    if current_state == "uploading" and received > receive_limit(cfg):
        raise TransferError(413, "Transfer exceeds the current limit")


def seal_upload(transfer_id, lease, path, size):
    cfg = load_config()
    now = time.time()
    with store() as db, transaction(db):
        row = select_incoming(db, transfer_id)
        if (row is None or row["state"] != "uploading" or row["lease_id"] != lease
                or row["policy"] != policy_fingerprint(cfg) or row["expires"] <= now):
            raise TransferError(409, "Transfer was cancelled, expired, or revoked")
        if size > receive_limit(cfg):
            raise TransferError(413, "Transfer exceeds the current limit")
        # A previous interrupted seal may have left an unreferenced file here.
        os.replace(path, payload_path(transfer_id))
        db.execute("""UPDATE incoming SET state='awaiting_approval',received=?,lease_id=NULL,
                      lease_until=NULL,updated=?,error=NULL WHERE id=?""", (size, now, transfer_id))
        return incoming_view(select_incoming(db, transfer_id))


def retry_upload(transfer_id, lease, error):
    with store() as db, transaction(db):
        changed = db.execute("""UPDATE incoming SET state='awaiting_upload',received=0,lease_id=NULL,
                      lease_until=NULL,updated=?,error=? WHERE id=? AND lease_id=? AND state='uploading'""",
                   (time.time(), error, transfer_id, lease)).rowcount
        if changed:
            remove(payload_path(transfer_id))


def flush_file(handle):
    handle.flush()
    os.fsync(handle.fileno())


async def flush_upload(handle):
    task = asyncio.create_task(asyncio.to_thread(flush_file, handle))
    try:
        await asyncio.shield(task)
    except asyncio.CancelledError:
        await task
        raise


async def upload_http(request):
    from starlette.requests import ClientDisconnect
    from starlette.responses import JSONResponse

    cfg = load_config()
    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}
    token = request.path_params.get("token")
    active = None
    submitted = False
    error = "Upload interrupted; send the whole file again"
    try:
        lengths = request.headers.getlist("content-length")
        if len(lengths) > 1:
            raise TransferError(400, "Use at most one Content-Length header")
        row, lease = await asyncio.to_thread(begin_upload, token, lengths[0] if lengths else None, cfg)
        if lease is None:
            return JSONResponse(incoming_view(row), status_code=200, headers=headers)
        transfer_id = row["id"]
        part = partial_path(transfer_id, lease)
        active = (transfer_id, lease, part)
        if request.headers.get("content-encoding", "identity").lower() != "identity" or request.headers.get("content-range"):
            raise TransferError(400, "Upload exact raw bytes in one PUT; do not send compressed HTTP or partial ranges")
        total = 0
        digest = hashlib.sha256()
        last_update = time.monotonic()
        deadline = last_update + STREAM_SECONDS
        stream = request.stream().__aiter__()
        with part.open("xb") as handle:
            while True:
                try:
                    data = await asyncio.wait_for(anext(stream), timeout=min(60, max(0, deadline - time.monotonic())))
                except StopAsyncIteration:
                    break
                if not data:
                    continue
                total += len(data)
                if total > row["size"]:
                    raise TransferError(413, "Received more bytes than declared")
                # ASGI server chunks are bounded; this is a file stream, never an in-memory package.
                digest.update(data)
                handle.write(data)
                if time.monotonic() - last_update >= 1:
                    await asyncio.to_thread(pulse, transfer_id, lease, "uploading", total)
                    last_update = time.monotonic()
            if total != row["size"] or not secrets.compare_digest(digest.hexdigest(), row["sha256"]):
                raise TransferError(422, "File length or SHA-256 did not match the declared original")
            await flush_upload(handle)
        view = await asyncio.to_thread(seal_upload, transfer_id, lease, part, total)
        submitted = True
        return JSONResponse(view, status_code=201, headers=headers)
    except TransferError as exc:
        error = str(exc)
        return JSONResponse({"error": error}, status_code=exc.status, headers=headers)
    except (TimeoutError, ClientDisconnect):
        return JSONResponse({"error": error}, status_code=408, headers=headers)
    except (OSError, sqlite3.Error):
        error = "Windows could not stage the upload; check local disk space and retry"
        return JSONResponse({"error": error}, status_code=503, headers=headers)
    finally:
        if active is not None and not submitted:
            transfer_id, lease, part = active
            remove(part)
            try:
                await asyncio.to_thread(retry_upload, transfer_id, lease, error)
            except (OSError, sqlite3.Error):
                pass


@contextmanager
def guarded_inbox(scope):
    """Keep the validated directory hierarchy from being renamed during placement."""
    if os.name != "nt":
        yield
        return
    import ctypes
    from ctypes import wintypes

    api = ctypes.WinDLL("kernel32", use_last_error=True)
    create, close = api.CreateFileW, api.CloseHandle
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    invalid = ctypes.c_void_p(-1).value
    drive = Path(scope.anchor)
    parent = drive
    handles = []
    try:
        for part in scope.relative_to(drive).parts:
            parent /= part
            handle = create(str(parent), 0x80, 1 | 2, None, 3, 0x02000000 | 0x00200000, None)
            if handle == invalid or handle is None:
                raise ctypes.WinError(ctypes.get_last_error())
            handles.append(handle)
            attrs = parent.lstat()
            if not stat.S_ISDIR(attrs.st_mode) or getattr(attrs, "st_file_attributes", 0) & 0x400:
                raise ValueError("Inbox paths cannot use links or junctions")
        yield
    finally:
        for handle in reversed(handles):
            close(handle)


def place_exclusive(src, dst):
    if os.name == "nt":
        os.rename(src, dst)  # Win32 rename never replaces an existing destination.
    else:
        os.link(src, dst)
        src.unlink()


def record_delivery_stamp(transfer_id, lease, stamp):
    with store() as db, transaction(db):
        updated = db.execute("""UPDATE incoming SET delivery_stamp=? WHERE id=? AND lease_id=?
                                AND state='delivering'""", (stamp, transfer_id, lease)).rowcount
        if updated != 1:
            raise ValueError("Transfer is no longer active")


def approve_upload(transfer_id, cfg):
    from workspace import no_link

    scope, scope_id = check_receive(cfg)
    now = time.time()
    lease = secrets.token_hex(16)
    with store() as db, transaction(db):
        row = select_incoming(db, transfer_id)
        require_policy(row, cfg)
        if row["state"] == "delivered":
            return incoming_view(row)
        if row["state"] != "awaiting_approval" or row["expires"] <= now or row["scope_id"] != scope_id:
            raise ValueError("Only a verified pending upload can be approved for the current inbox")
        db.execute("""UPDATE incoming SET state='delivering',lease_id=?,lease_until=?,updated=?,error=NULL
                      WHERE id=?""", (lease, now + LEASE_SECONDS, now, transfer_id))
    source = payload_path(transfer_id)
    target = scope / row["name"]
    temp = inbox_temp(scope, transfer_id)
    assigned = False
    published = False
    error = None
    try:
        with guarded_inbox(scope):
            current, current_id = check_receive(load_config())
            if current != scope or current_id != scope_id:
                raise ValueError("Inbox folder changed")
            if os.path.lexists(target):
                raise ValueError("The destination already exists; this upload did not overwrite it")
            before = no_link(source, False)
            total = 0
            digest = hashlib.sha256()
            last_update = time.monotonic()
            with source.open("rb") as original, temp.open("xb") as output:
                assigned = True
                # Persist the exact file identity; a restart can recover a completed atomic move.
                stamp = file_identity(os.fstat(output.fileno()))
                record_delivery_stamp(transfer_id, lease, "writing/" + stamp)
                if not os.path.samestat(before, os.fstat(original.fileno())):
                    raise ValueError("The staged upload changed")
                while data := original.read(CHUNK):
                    total += len(data)
                    if total > row["size"]:
                        raise ValueError("Staged file no longer matches the verified upload")
                    digest.update(data)
                    output.write(data)
                    if time.monotonic() - last_update >= 1:
                        pulse(transfer_id, lease, "delivering", row["size"])
                        last_update = time.monotonic()
                if total != row["size"] or not secrets.compare_digest(digest.hexdigest(), row["sha256"]):
                    raise ValueError("Staged file no longer matches the verified upload")
                flush_file(output)
            pulse(transfer_id, lease, "delivering", row["size"])
            if file_identity(temp.lstat()) != stamp:
                raise ValueError("The staged output changed before placement")
            latest = load_config()
            current, current_id = check_receive(latest)
            if current != scope or current_id != scope_id or row["policy"] != policy_fingerprint(latest):
                raise ValueError("Inbox permission changed")
            record_delivery_stamp(transfer_id, lease, "verified/" + stamp)
            place_exclusive(temp, target)
            published = True
            with store() as db, transaction(db):
                db.execute("""UPDATE incoming SET state='delivered',received=size,updated=?,lease_id=NULL,
                              lease_until=NULL,error=NULL WHERE id=? AND lease_id=?""",
                           (time.time(), transfer_id, lease))
                view = incoming_view(select_incoming(db, transfer_id))
            remove(source)
            return view
    except (OSError, ValueError, TransferError) as exc:
        error = str(exc) if isinstance(exc, (ValueError, TransferError)) else (
            "The destination already exists; this upload did not overwrite it" if isinstance(exc, FileExistsError)
            else "Windows could not place the package in the inbox; check folder access or disk space")
    finally:
        if assigned and not published:
            remove(temp)
    if error is not None:
        with store() as db, transaction(db):
            db.execute("""UPDATE incoming SET state='awaiting_approval',updated=?,lease_id=NULL,lease_until=NULL,
                          delivery_stamp=NULL,error=? WHERE id=? AND lease_id=? AND state='delivering'""",
                       (time.time(), error, transfer_id, lease))
        raise ValueError(error)


def auto_receive(cfg):
    return (cfg.get("workspace_unified") is True and cfg.get("approval_mode") == "full" and
            cfg.get("workspace_enabled") and cfg.get("receive_enabled") and uses_funnel(cfg))


class InboundRunner:
    """Only the local worker auto-commits verified files under a unified full grant."""
    def __init__(self):
        self.thread = None
        self.last = 0.0

    def pump(self, cfg):
        now = time.monotonic()
        if (now - self.last < 1 or (self.thread and self.thread.is_alive())
                or not auto_receive(cfg) or not DB.is_file()):
            return
        self.last = now
        try:
            with store() as db:
                row = db.execute("""SELECT id FROM incoming WHERE policy=? AND state='awaiting_approval'
                                    AND error IS NULL AND expires>? ORDER BY created LIMIT 1""",
                                 (policy_fingerprint(cfg), time.time())).fetchone()
        except (OSError, sqlite3.Error):
            return
        if row:
            self.thread = threading.Thread(target=self._deliver, args=(row["id"],), daemon=True)
            self.thread.start()

    @staticmethod
    def _deliver(transfer_id):
        try:
            cfg = load_config()
            if auto_receive(cfg):
                approve_upload(transfer_id, cfg)
        except (OSError, ValueError, sqlite3.Error, TransferError):
            pass  # a placement failure is recorded for manual review


def _recover_incoming(db, row, now, current_policy):
    transfer_id = row["id"]
    state = row["state"]
    if state == "delivering" and row["lease_until"] is not None and row["lease_until"] <= now:
        scope = Path(row["scope"])
        marker, _, stamp = (row["delivery_stamp"] or "").partition("/")
        # Do not act on paths whose folder identity no longer matches.
        try:
            if file_identity(scope.lstat()) != row["scope_id"]:
                raise OSError
            with guarded_inbox(scope):
                target = scope / offered_name(row["name"])
                committed = (marker == "verified" and stamp and not stamp.endswith(":0") and target.is_file()
                             and file_identity(target.lstat()) == stamp)
                temp = inbox_temp(scope, transfer_id)
                if stamp and not stamp.endswith(":0") and temp.is_file() and file_identity(temp.lstat()) == stamp:
                    remove(temp)
        except (OSError, ValueError):
            committed = False
        if committed:
            db.execute("""UPDATE incoming SET state='delivered',received=size,updated=?,lease_id=NULL,
                          lease_until=NULL,error=NULL WHERE id=?""", (now, transfer_id))
            remove(payload_path(transfer_id))
            return
        state = "awaiting_approval"
        db.execute("""UPDATE incoming SET state=?,updated=?,lease_id=NULL,lease_until=NULL,delivery_stamp=NULL,
                      error='Local delivery interrupted; approve again to retry' WHERE id=?""", (state, now, transfer_id))

    if state in ACTIVE and state != "delivering" and (row["expires"] <= now or row["policy"] != current_policy):
        db.execute("""UPDATE incoming SET state='expired',updated=?,token_hash=NULL,token_expires=NULL,
                      lease_id=NULL,lease_until=NULL WHERE id=?""", (now, transfer_id))
        remove(payload_path(transfer_id))
        if state == "uploading" and row["lease_id"]:
            remove(partial_path(transfer_id, row["lease_id"]))
    elif state == "uploading" and row["lease_until"] is not None and row["lease_until"] <= now:
        remove(partial_path(transfer_id, row["lease_id"]))
        remove(payload_path(transfer_id))
        db.execute("""UPDATE incoming SET state='awaiting_upload',received=0,updated=?,lease_id=NULL,lease_until=NULL,
                      error='Upload interrupted; renew the link and retry if necessary' WHERE id=?""", (now, transfer_id))
    elif state in TERMINAL:
        remove(payload_path(transfer_id))


def cleanup(cfg, force=False):
    global _last_cleanup
    now = time.time()
    if not DB.is_file() or (not force and now - _last_cleanup < 3):
        return
    _last_cleanup = now
    with store() as db, transaction(db):
        rows = db.execute("SELECT * FROM incoming WHERE state IN (?,?,?,?)", ACTIVE).fetchall()
        for row in rows:
            _recover_incoming(db, row, now, policy_fingerprint(cfg))
        for path in STAGED.glob("*.part"):
            try:
                if re.fullmatch(r"[0-9a-f]{32}-[0-9a-f]{32}\.part", path.name):
                    transfer_id, lease = path.stem.split("-")
                    row = select_incoming(db, transfer_id)
                    if row is None or row["state"] != "uploading" or row["lease_id"] != lease:
                        remove(path)
            except OSError:
                pass
        for path in STAGED.glob("*.upload"):
            try:
                row = select_incoming(db, path.stem) if ID_RE.fullmatch(path.stem) else None
                if ID_RE.fullmatch(path.stem) and (row is None or row["state"] in TERMINAL):
                    remove(path)
            except (OSError, ValueError):
                pass
        db.execute("DELETE FROM incoming WHERE updated<? AND state IN (?,?,?,?,?)",
                   (now - HISTORY_TTL, *TERMINAL))
        db.execute("""DELETE FROM incoming WHERE id IN (
                       SELECT id FROM incoming WHERE state IN (?,?,?,?,?)
                       ORDER BY updated DESC LIMIT -1 OFFSET ?)""", (*TERMINAL, MAX_HISTORY))
        db.execute("DELETE FROM outgoing WHERE created<?", (now - HISTORY_TTL,))
        db.execute("DELETE FROM outgoing_receipts WHERE id NOT IN (SELECT id FROM outgoing)")


def queue_outgoing(source, cfg):
    from file_bridge import begin_export
    from workspace import document_scope, resolve, workspace_root

    root = workspace_root(cfg["workspace_root"])
    docs = document_scope(root, cfg)
    path = Path(source)
    if not cfg.get("workspace_enabled") or docs is None or docs not in path.parents or not path.is_absolute():
        raise ValueError("Choose a file inside the currently authorized document folder")
    relative = path.relative_to(root).as_posix()
    source = resolve(root, relative, extensions=None)
    size = source.stat().st_size
    result = begin_export(source, cfg)
    job_id = valid_id(result["job_id"])
    with store() as db, transaction(db):
        db.execute("INSERT INTO outgoing VALUES(?,?,?,?,?)", (job_id, source.name, relative, size, time.time()))
        db.execute("""DELETE FROM outgoing WHERE id IN (
                       SELECT id FROM outgoing ORDER BY created DESC LIMIT -1 OFFSET ?)""", (MAX_OUTGOING,))
        row = find_outgoing(db, job_id)
    return outgoing_view(row, cfg)


def outgoing_view(row, cfg, link=False, renew=False):
    from file_bridge import export_status

    view = dict(transfer_id=row["id"], direction="outgoing", name=row["name"], size_bytes=row["size"],
                created_at=row["created"])
    if row["received_at"] is not None:
        return {**view, "state": "received", "sha256": row["receipt_sha256"], "received_at": row["received_at"]}
    try:
        export = export_status(row["id"], cfg, renew=renew)
    except (ValueError, OSError):
        return {**view, "state": "expired"}
    if link:
        view.update(export)
        view["relative_path"] = row["relative_path"]
    else:
        for key in ("state", "sha256", "copied_bytes", "prepared_bytes", "renew_available", "error"):
            if key in export:
                view[key] = export[key]
    return view


def get_outgoing(transfer_id, cfg, renew=False):
    with store() as db:
        row = find_outgoing(db, transfer_id)
    if row is None:
        raise ValueError("Unknown outgoing mailbox transfer")
    return outgoing_view(row, cfg, link=True, renew=renew)


def cancel_outgoing(transfer_id, cfg):
    from file_bridge import cancel_export

    with store() as db:
        row = find_outgoing(db, transfer_id)
    if row is None:
        raise ValueError("Unknown outgoing mailbox transfer")
    if row["received_at"] is None:
        cancel_export(transfer_id, cfg)
    return outgoing_view(row, cfg)


OUTGOING_SELECT = """SELECT outgoing.*,outgoing_receipts.sha256 AS receipt_sha256,outgoing_receipts.received_at
                     FROM outgoing LEFT JOIN outgoing_receipts USING(id)"""


def find_outgoing(db, transfer_id):
    return db.execute(OUTGOING_SELECT + " WHERE id=?", (valid_id(transfer_id),)).fetchone()


def acknowledge_outgoing(transfer_id, sha256, cfg):
    from file_bridge import complete_export

    if not isinstance(sha256, str) or not HEX_RE.fullmatch(sha256.lower()):
        raise ValueError("Provide the SHA-256 hex digest of the received file")
    sha256 = sha256.lower()
    with store() as db:
        row = find_outgoing(db, transfer_id)
        if row is None:
            raise ValueError("Unknown outgoing mailbox transfer")
        if row["received_at"] is not None:
            if not secrets.compare_digest(row["receipt_sha256"], sha256):
                raise ValueError("SHA-256 does not match; the outgoing package was not acknowledged")
        else:
            if complete_export(transfer_id, cfg, sha256).get("state") != "delivered":
                raise ValueError("The outgoing snapshot expired or its approval was revoked")
        with transaction(db):
            db.execute("INSERT OR IGNORE INTO outgoing_receipts VALUES(?,?,?)", (transfer_id, sha256, time.time()))
            row = find_outgoing(db, transfer_id)
    if row is None:
        raise ValueError("The outgoing transfer expired")
    return outgoing_view(row, cfg)


def list_mailbox(cfg, limit=20):
    if type(limit) is not int or not 1 <= limit <= 30:
        raise ValueError("Mailbox limit must be between 1 and 30")
    cleanup(cfg)
    result = {"inbox_enabled": bool(cfg.get("receive_enabled")), "incoming": [], "outgoing": []}
    if not DB.is_file():
        return result
    with store() as db:
        inbox = db.execute("SELECT * FROM incoming WHERE policy=? ORDER BY updated DESC LIMIT ?",
                           (policy_fingerprint(cfg), limit)).fetchall()
        outbox = db.execute(OUTGOING_SELECT + " ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    result["incoming"] = [incoming_view(row) for row in inbox]
    result["outgoing"] = [outgoing_view(row, cfg) for row in outbox]
    return result
