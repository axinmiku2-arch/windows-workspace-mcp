"""Owner-only grants to repeat one fixed, read-only Windows diagnostic."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import ipaddress
import json
import re
import secrets
import sqlite3
import time

import core
import windows_toolbox
from workspace import workspace_root

DB = core.STATE / "diagnostic-routines.sqlite3"
PREFIX = "routine:"
ID = re.compile(r"[0-9a-f]{24}\Z")
JOB = re.compile(r"[0-9a-f]{32}\Z")
MINUTES_MIN, MINUTES_MAX = 5, 60
RUNS_MIN, RUNS_MAX = 1, 5
MIN_GAP_SECONDS = 10
PRESETS = frozenset({"windows_ipconfig", "windows_listening_ports", "windows_ping"})


def _identifier(value):
    return isinstance(value, str) and ID.fullmatch(value) is not None


def _context(cfg):
    if (cfg.get("workspace_unified") is not True or not cfg.get("workspace_enabled")
            or not cfg.get("task_enabled") or cfg.get("approval_mode") not in {"rules", "full"}
            or not cfg.get("workspace_revision") or not core.uses_funnel(cfg)):
        raise ValueError("Reusable diagnostics require a currently authorized unified workspace in rules or full mode.")
    root = workspace_root(cfg["workspace_root"])
    info = root.stat()
    fields = [str(root), info.st_dev, info.st_ino, cfg.get("active_workspace_profile"),
              cfg["workspace_revision"], cfg["approval_mode"], cfg.get("origin")]
    return str(root), hashlib.sha256(json.dumps(fields, ensure_ascii=False).encode("utf-8")).hexdigest()


def registration_available(cfg):
    try:
        _context(cfg)
        return True
    except (ValueError, OSError):
        return False


def _pinned_host(preset, host, cfg):
    if preset not in PRESETS:
        raise ValueError("Use one of the fixed read-only diagnostic presets.")
    if preset != "windows_ping":
        if host is not None:
            raise ValueError("Only Ping accepts a registered target.")
        return None
    checked = windows_toolbox.canonical_host(host)
    try:
        ipaddress.ip_address(checked)
    except ValueError:
        raise ValueError("Reusable Ping requires an exact IP address, not a DNS name.") from None
    return windows_toolbox.parameters(preset, {"host": checked}, cfg)["host"]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS grants (
    routine_id TEXT PRIMARY KEY, preset TEXT NOT NULL, host TEXT,
    connection_id TEXT NOT NULL, scope TEXT NOT NULL, workspace_root TEXT NOT NULL,
    created REAL NOT NULL, expires_at REAL NOT NULL, remaining INTEGER NOT NULL,
    last_spent REAL, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS launches (
    job_id TEXT PRIMARY KEY, routine_id TEXT NOT NULL
);
"""


@contextmanager
def _db(*, write=False):
    if not write and not DB.exists():
        yield None
        return
    conn = sqlite3.connect(DB, timeout=1.0)
    conn.row_factory = sqlite3.Row
    try:
        if write:
            conn.execute("PRAGMA synchronous=FULL")
            conn.executescript(_SCHEMA)
            conn.execute("BEGIN IMMEDIATE")
        yield conn
        if write:
            conn.commit()
    except BaseException:
        if write:
            conn.rollback()
        raise
    finally:
        conn.close()


def _public(row, active, current_scope):
    return {**{key: row[key] for key in (
        "routine_id", "preset", "host", "connection_id", "workspace_root", "remaining", "expires_at")},
        "request_preset": PREFIX + row["routine_id"], "active": bool(active), "revoked": bool(row["revoked"]),
        "current_scope": current_scope}


def _live(row, now, scope):
    return bool(row and row["scope"] == scope and not row["revoked"] and row["created"] <= now < row["expires_at"])


def _still_pinned(row, cfg):
    try:
        return row["host"] == _pinned_host(row["preset"], row["host"], cfg)
    except (ValueError, TypeError):
        return False


def register(preset, connection_id, cfg, *, host=None, minutes=15, runs=3):
    """Local Windows manager only. Not a relay/RPC operation."""
    if not _identifier(connection_id):
        raise ValueError("Copy the 24 lowercase hexadecimal connection ID shown by server_info.")
    if type(minutes) is not int or not MINUTES_MIN <= minutes <= MINUTES_MAX:
        raise ValueError("Routine duration must be from 5 to 60 minutes.")
    if type(runs) is not int or not RUNS_MIN <= runs <= RUNS_MAX:
        raise ValueError("Choose from 1 to 5 launches.")
    if not isinstance(preset, str):
        raise ValueError("Use one of the fixed read-only diagnostic presets.")
    root, scope = _context(cfg)
    host = _pinned_host(preset, host, cfg)
    with _db(write=True) as conn:
        now = time.time()
        conn.execute("DELETE FROM grants WHERE expires_at < ? OR revoked = 1", (now - 86400,))
        conn.execute("DELETE FROM launches WHERE routine_id NOT IN (SELECT routine_id FROM grants)")
        if conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0] >= 64:
            raise ValueError("The local routine registry is temporarily full.")
        if conn.execute("""SELECT 1 FROM grants WHERE scope=? AND revoked=0 AND remaining>0
                           AND expires_at>?""", (scope, now)).fetchone():
            raise ValueError("Revoke or exhaust the current workspace routine before adding another.")
        ident = secrets.token_hex(12)
        conn.execute("""INSERT INTO grants (routine_id,preset,host,connection_id,scope,workspace_root,
                         created,expires_at,remaining) VALUES (?,?,?,?,?,?,?,?,?)""",
                     (ident, preset, host, connection_id, scope, root, now, now + 60 * minutes, runs))
        row = conn.execute("SELECT * FROM grants WHERE routine_id=?", (ident,)).fetchone()
    return _public(row, True, True)


def listing(cfg):
    """Local readout, including inactive grants, never sent to the relay."""
    try:
        _, scope = _context(cfg)
    except (ValueError, OSError):
        scope = None
    with _db() as conn:
        if conn is None:
            return []
        rows = conn.execute("SELECT * FROM grants ORDER BY created DESC").fetchall()
    now = time.time()
    return [_public(row, _live(row, now, scope) and row["remaining"] > 0 and _still_pinned(row, cfg),
                    scope is not None and row["scope"] == scope) for row in rows]


def revoke(routine_id):
    """Local Windows manager only. A claimed launch is never refunded."""
    if not _identifier(routine_id):
        raise ValueError("Unknown reusable diagnostic.")
    with _db(write=True) as conn:
        if conn.execute("UPDATE grants SET revoked=1 WHERE routine_id=?", (routine_id,)).rowcount != 1:
            raise ValueError("Unknown reusable diagnostic.")


def _checked(conn, ident, submission, cfg, now):
    if (conn is None or not _identifier(ident) or not isinstance(submission, dict)
            or submission.get("transport") != "https_mcp"):
        raise ValueError("The reusable diagnostic is not available to this connection.")
    _, scope = _context(cfg)
    row = conn.execute("SELECT * FROM grants WHERE routine_id=?", (ident,)).fetchone()
    if (not _live(row, now, scope) or row["connection_id"] != submission.get("connection_id")
            or not _still_pinned(row, cfg)):
        raise ValueError("The reusable diagnostic is not available to this connection.")
    return row


def plan(ident, submission, cfg):
    with _db() as conn:
        now = time.time()
        row = _checked(conn, ident, submission, cfg, now)
        if row["remaining"] <= 0:
            raise ValueError("The reusable diagnostic has no remaining launches.")
        if row["last_spent"] is not None and now - row["last_spent"] < MIN_GAP_SECONDS:
            raise ValueError("Wait 10 seconds between launches of this reusable diagnostic.")
        return row["preset"], ({"host": row["host"]} if row["host"] else {})


def _match_item(row, item):
    params = {"host": row["host"]} if row["host"] else {}
    if row["preset"] != item["preset"] or params != item.get("parameters"):
        raise ValueError("The fixed diagnostic no longer matches its local grant.")


def check(item, cfg, *, consumed=False):
    ident = item["routine_id"]
    with _db() as conn:
        row = _checked(conn, ident, item.get("submission"), cfg, time.time())
        _match_item(row, item)
        receipt = conn.execute("SELECT routine_id FROM launches WHERE job_id=?", (item["job_id"],)).fetchone()
        if consumed:
            if receipt is None or receipt["routine_id"] != ident:
                raise ValueError("A reusable diagnostic has no matching one-use launch receipt.")
        elif receipt is not None:
            raise ValueError("This reusable diagnostic job has already spent its launch.")


def consume(item, cfg):
    """Durably burn one one-use launch receipt before releasing the worker handshake."""
    ident, job_id = item["routine_id"], item["job_id"]
    if not isinstance(job_id, str) or not JOB.fullmatch(job_id):
        raise ValueError("Invalid reusable diagnostic job ID.")
    with _db(write=True) as conn:
        now = time.time()
        row = _checked(conn, ident, item.get("submission"), cfg, now)
        _match_item(row, item)
        if row["remaining"] <= 0:
            raise ValueError("The reusable diagnostic has no remaining launches.")
        if row["last_spent"] is not None and now - row["last_spent"] < MIN_GAP_SECONDS:
            raise ValueError("Wait 10 seconds between launches of this reusable diagnostic.")
        try:
            conn.execute("INSERT INTO launches (job_id,routine_id) VALUES (?,?)", (job_id, ident))
        except sqlite3.IntegrityError:
            raise ValueError("This reusable diagnostic job has already spent its launch.") from None
        conn.execute("UPDATE grants SET remaining=remaining-1, last_spent=? WHERE routine_id=?", (now, ident))
