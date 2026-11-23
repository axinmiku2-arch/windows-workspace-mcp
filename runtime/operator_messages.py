"""Durable, scoped operator notes. No automatic delivery into a Dot conversation."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import re
import secrets
import sqlite3
import time

import core

DB = core.STATE / "funnel" / "operator-messages.sqlite3"
MAX_CHARS = 1200
MAX_LIMIT = 30
MAX_RESPONSE_BYTES = 24_000
HISTORY = 7 * 86400
MAX_ROWS = 400
DIRECTIONS = {"incoming": "windows", "outgoing": "dot"}
RECIPIENTS = frozenset(DIRECTIONS.values())
REQUEST_KEY = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
IDENTIFIER = re.compile(r"[0-9a-f]{32}\Z")


@contextmanager
def _db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB, timeout=2)
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS notes (
                id TEXT PRIMARY KEY, policy TEXT NOT NULL, direction TEXT NOT NULL,
                recipient TEXT NOT NULL, text TEXT NOT NULL, created REAL NOT NULL,
                ack_at REAL, request_key TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS notes_request
                ON notes(policy,direction,request_key);
            CREATE INDEX IF NOT EXISTS notes_recipient
                ON notes(policy,recipient,created);
        """)
        yield connection
    finally:
        connection.close()


def _scope(cfg):
    if not cfg.get("workspace_enabled") or not cfg.get("workspace_revision") or not core.uses_funnel(cfg):
        raise ValueError("Enable the authorized Windows workspace and fixed relay to use operator messages")
    fields = [cfg.get(key) for key in ("origin", "workspace_root", "workspace_revision")]
    return hashlib.sha256(json.dumps(fields, ensure_ascii=False).encode("utf-8")).hexdigest()


def _policy(cfg):
    policy = _scope(cfg)
    if not secrets.compare_digest(policy, _scope(core.load_config())):
        raise ValueError("Windows workspace authorization changed")
    return policy


def _view(row):
    return dict(
        message_id=row["id"], direction=row["direction"], recipient=row["recipient"], text=row["text"],
        status="read" if row["ack_at"] is not None else "unread", created_at=row["created"],
        acknowledged_at=row["ack_at"],
    )


def _prune(conn, now):
    conn.execute("DELETE FROM notes WHERE created<?", (now - HISTORY,))
    conn.execute("""DELETE FROM notes WHERE id IN (
                    SELECT id FROM notes ORDER BY created DESC,id DESC LIMIT -1 OFFSET ?
                )""", (MAX_ROWS,))


def send(direction, text, cfg, request_key=""):
    if not isinstance(direction, str) or direction not in DIRECTIONS:
        raise ValueError("Message direction must be incoming or outgoing")
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_CHARS:
        raise ValueError("Supply 1–1200 characters of plain text")
    if any(ord(char) < 32 and char not in "\n\r\t" for char in text):
        raise ValueError("The message includes unsupported control characters")
    try:
        text.encode("utf-8")
    except UnicodeError:
        raise ValueError("The message must be valid Unicode") from None
    if not isinstance(request_key, str) or (request_key and not REQUEST_KEY.fullmatch(request_key)):
        raise ValueError("Use up to 80 ASCII letters, digits, hyphens or underscores for the request key")
    policy = _policy(cfg)
    now = time.time()
    with _db() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        _prune(conn, now)
        if request_key:
            earlier = conn.execute("SELECT * FROM notes WHERE policy=? AND direction=? AND request_key=?",
                                   (policy, direction, request_key)).fetchone()
            if earlier is not None:
                if earlier["text"] != text:
                    raise ValueError("This request key is already assigned to a different message")
                return _view(earlier)
        message_id = secrets.token_hex(16)
        conn.execute("""INSERT INTO notes(id,policy,direction,recipient,text,created,request_key)
                        VALUES(?,?,?,?,?,?,?)""",
                     (message_id, policy, direction, DIRECTIONS[direction], text, now, request_key or None))
        _prune(conn, now)
        return _view(conn.execute("SELECT * FROM notes WHERE id=?", (message_id,)).fetchone())


def _validate_recipient(recipient):
    if not isinstance(recipient, str) or recipient not in RECIPIENTS:
        raise ValueError("Message recipient must be windows or dot")


def list_messages(recipient, cfg, limit=20, unread_only=False):
    _validate_recipient(recipient)
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise ValueError("Message list limit must be between 1 and 30")
    if type(unread_only) is not bool:
        raise ValueError("unread_only must be true or false")
    policy = _policy(cfg)
    result = {"recipient": recipient, "unread_count": 0, "messages": [], "has_more": False}
    if not DB.is_file():
        return result
    cutoff = time.time() - HISTORY
    with _db() as conn:
        result["unread_count"] = conn.execute(
            "SELECT COUNT(*) FROM notes WHERE policy=? AND recipient=? AND created>=? AND ack_at IS NULL",
            (policy, recipient, cutoff),
        ).fetchone()[0]
        extra = " AND ack_at IS NULL" if unread_only else ""
        rows = conn.execute(f"""SELECT * FROM notes WHERE policy=? AND recipient=? AND created>=?{extra}
                                ORDER BY created DESC,id DESC LIMIT ?""",
                            (policy, recipient, cutoff, limit + 1)).fetchall()
    result["has_more"] = len(rows) > limit
    for row in rows[:limit]:
        result["messages"].append(_view(row))
        # Count the larger ASCII-escaped representation, including emoji becoming surrogate escapes.
        if len(json.dumps(result, ensure_ascii=True).encode("utf-8")) > MAX_RESPONSE_BYTES - 8:
            result["messages"].pop()
            result["has_more"] = True
            break
    return result


def acknowledge(recipient, message_id, cfg):
    _validate_recipient(recipient)
    if not isinstance(message_id, str) or not IDENTIFIER.fullmatch(message_id):
        raise ValueError("Invalid message ID")
    policy = _policy(cfg)
    now = time.time()
    with _db() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        selection = "SELECT * FROM notes WHERE id=? AND policy=? AND recipient=? AND created>=?"
        parameters = (message_id, policy, recipient, now - HISTORY)
        row = conn.execute(selection, parameters).fetchone()
        if row is None:
            raise ValueError("Message was not found for this recipient or expired")
        if row["ack_at"] is None:
            conn.execute("UPDATE notes SET ack_at=? WHERE id=?", (now, message_id))
            row = conn.execute(selection, parameters).fetchone()
        return _view(row)
