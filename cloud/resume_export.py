"""Receive an already authorized Dot Windows export in a cloud workspace.

This client does not create, approve, revoke, or acknowledge export jobs.
A matching job/size/SHA-256 is required to reuse a local partial. Only a
completely verified copy is published to the requested destination.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from hashlib import file_digest
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
import time
from typing import Callable, Mapping
import urllib.error
import urllib.parse
import urllib.request

MAX_EXPORT_BYTES = 1_000_000_000  # Mirrors the Windows manager's maximum.
DEFAULT_RANGE_BYTES = 4 * 1024 * 1024
READ_BYTES = 128 * 1024
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
TRANSIENT = {408, 429, 500, 502, 503, 504}
RENEWABLE = {404, 410}


class ExportError(Exception):
    """An error safe to display without the private URL."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Snapshot:
    job_id: str
    size: int
    sha256: str
    origin: tuple[str, int]
    url: str = field(repr=False, compare=False)

    @classmethod
    def from_status(cls, data: Mapping) -> Snapshot:
        if not isinstance(data, Mapping):
            raise ExportError("metadata", "An export-status object is required.")
        state = data.get("state")
        if state in ("revoked", "cancelled", "expired", "failed", "delivered"):
            raise ExportError("snapshot_not_available", "The Windows export is no longer available.")
        if state != "ready":
            raise ExportError("snapshot_not_ready", "The Windows export is not ready.")
        job_id, size, sha, url = (
            data.get("job_id"), data.get("bytes"), data.get("sha256"), data.get("download_url")
        )
        if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
            raise ExportError("metadata", "Invalid Windows export job ID.")
        if type(size) is not int or not 0 <= size <= MAX_EXPORT_BYTES:
            raise ExportError("metadata", "Invalid or out-of-limit Windows export size.")
        if not isinstance(sha, str) or not SHA256.fullmatch(sha):
            raise ExportError("metadata", "The Windows export is missing a valid SHA-256.")
        if not isinstance(url, str) or not url:
            raise ExportError("link_unavailable", "Request a fresh link for the same Windows export.")
        if len(url) > 2048 or re.search(r"[\x00-\x20\x7f\\]", url):
            raise ExportError("metadata", "Invalid export URL.")
        try:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port if parsed.port is not None else 443
            hostname = parsed.hostname
        except ValueError:
            raise ExportError("metadata", "Invalid export URL.") from None
        if (
            parsed.scheme != "https" or not hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or parsed.query or not 1 <= port <= 65535
            or not re.fullmatch(r"/dot-files/[A-Za-z0-9_-]{43}", parsed.path)
        ):
            raise ExportError("metadata", "An HTTPS Windows file capability is required.")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            if "." not in hostname or hostname.endswith((".localhost", ".local")) or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname
            ):
                raise ExportError("metadata", "The Windows capability requires a public HTTPS host.") from None
        else:
            if not address.is_global:
                raise ExportError("metadata", "The Windows capability requires a public HTTPS host.")
        return cls(job_id, size, sha.lower(), (hostname, port), url)

    def identity(self):
        return {"job_id": self.job_id, "bytes": self.size, "sha256": self.sha256, "origin": list(self.origin)}


@dataclass
class Metrics:
    resumed_bytes: int = 0
    downloaded_bytes: int = 0
    received_bytes: int = 0
    attempts: int = 0
    retries: int = 0
    renewals: int = 0
    headers_seconds: float = 0.0
    body_seconds: float = 0.0
    retry_wait_seconds: float = 0.0
    renewal_seconds: float = 0.0
    hash_seconds: float = 0.0
    total_seconds: float = 0.0

    def report(self):
        data = asdict(self)
        for k, v in tuple(data.items()):
            if isinstance(v, float):
                data[k] = round(v, 4)
        data["body_mbps"] = round(self.downloaded_bytes * 8 / (self.body_seconds * 1_000_000), 3) if self.body_seconds else None
        data["end_to_end_mbps"] = round(self.downloaded_bytes * 8 / (self.total_seconds * 1_000_000), 3) if self.total_seconds else None
        return data


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener():
    # urllib issues HTTP/1.1 requests. Use the system trust store and no redirects.
    return urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    ).open


def _private_open(path: Path, flags: int):
    # The destination directory must be private and writable by this caller.
    return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)


@contextmanager
def _lock(path: Path):
    if path.is_symlink():
        raise ExportError("local_state", "The local resume lock is not a regular file.")
    fd = _private_open(path, os.O_RDWR | os.O_CREAT)
    try:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ExportError("busy", "This destination already has an active transfer.") from None
        yield
    finally:
        os.close(fd)


def _check_local_file(path: Path):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ExportError("local_state", "A resume path is not a regular file.")


def _recorded_snapshot(manifest: Path):
    _check_local_file(manifest)
    if not manifest.exists():
        return None
    try:
        with manifest.open("rb") as f:
            recorded = json.loads(f.read(4097))
    except (OSError, ValueError):
        raise ExportError("local_state", "The resume record is invalid.") from None
    if not isinstance(recorded, dict):
        raise ExportError("local_state", "The resume record is invalid.")
    return recorded


def _local_state(snapshot: Snapshot, partial: Path, manifest: Path):
    _check_local_file(partial)
    recorded = _recorded_snapshot(manifest)
    if recorded is not None:
        if recorded != snapshot.identity():
            raise ExportError("snapshot_changed", "The snapshot differs. The retained partial was not reused.")
    elif partial.exists():
        raise ExportError("local_state", "The partial is untracked. It was not reused.")
    else:
        fd, name = tempfile.mkstemp(prefix=".dot-resume-", dir=manifest.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(snapshot.identity(), f)
                f.flush()
                os.fsync(f.fileno())
            os.link(temporary, manifest)
        finally:
            temporary.unlink(missing_ok=True)
    if not partial.exists():
        os.close(_private_open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL))
    offset = partial.stat().st_size
    if offset > snapshot.size:
        raise ExportError("local_state", "The retained partial exceeds the expected export size.")
    return offset


def _request(snapshot: Snapshot, start: int, end: int, output, opener, timeout, deadline, metrics):
    headers = {"Range": f"bytes={start}-{end}", "If-Range": f'"{snapshot.sha256}"',
               "Accept-Encoding": "identity", "User-Agent": "DotExportReceiver/1"}
    req = urllib.request.Request(snapshot.url, headers=headers, method="GET")
    ts = time.monotonic()
    metrics.attempts += 1
    try:
        response = opener(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        if code in RENEWABLE:
            raise ExportError("link_unavailable", f"HTTP {code}: the export link is unavailable.") from None
        if code in TRANSIENT:
            raise ExportError("transient", f"HTTP {code}: temporary transfer failure.") from None
        raise ExportError("http", f"HTTP {code}: the range request was refused.") from None
    except ssl.SSLCertVerificationError:
        raise ExportError("tls", "TLS certificate verification failed.") from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            raise ExportError("tls", "TLS certificate verification failed.") from None
        raise ExportError("transient", "Connection failed before response headers.") from None
    except (TimeoutError, OSError, http.client.HTTPException):
        raise ExportError("transient", "Connection failed before response headers.") from None
    finally:
        metrics.headers_seconds += time.monotonic() - ts

    with response:
        expected_range = f"bytes {start}-{end}/{snapshot.size}"
        length = end - start + 1
        status = response.getcode()
        if status != 206 or response.headers.get("Content-Range") != expected_range:
            raise ExportError("range_mismatch", "The server returned an incorrect range. Existing bytes were preserved.")
        etag = response.headers.get("ETag", "")
        if not etag.isascii() or not hmac.compare_digest(etag, f'"{snapshot.sha256}"'):
            raise ExportError("snapshot_changed", "The response ETag does not match the authorized snapshot.")
        digest_header = response.headers.get("X-File-SHA256", "")
        if not digest_header.isascii() or not hmac.compare_digest(digest_header, snapshot.sha256):
            raise ExportError("snapshot_changed", "The response SHA-256 does not match the authorized snapshot.")
        if response.headers.get("Content-Length") != str(length):
            raise ExportError("range_mismatch", "The range Content-Length is incorrect.")
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise ExportError("range_mismatch", "The range response used unexpected content encoding.")
        ts = time.monotonic()
        left = length
        try:
            while left:
                if time.monotonic() - ts > deadline:
                    raise ExportError("transient", "The range exceeded its receive deadline.")
                try:
                    data = response.read(min(READ_BYTES, left))
                except (TimeoutError, OSError, http.client.HTTPException):
                    raise ExportError("transient", "Connection interrupted while receiving the range.") from None
                if not data:
                    raise ExportError("transient", "Connection ended before the complete range arrived.")
                if len(data) > left:
                    raise ExportError("range_mismatch", "The response was larger than the requested range.")
                left -= len(data)
                metrics.received_bytes += len(data)
                output.write(data)
        finally:
            metrics.body_seconds += time.monotonic() - ts


def _verified_hash(path: Path, snapshot: Snapshot, metrics: Metrics):
    ts = time.monotonic()
    if path.stat().st_size != snapshot.size:
        raise ExportError("integrity", "The final size does not match the authorized export.")
    with path.open("rb") as f:
        sha = file_digest(f, "sha256").hexdigest()
    metrics.hash_seconds += time.monotonic() - ts
    if not hmac.compare_digest(sha, snapshot.sha256):
        raise ExportError("integrity", "SHA-256 mismatch. The incomplete or incorrect copy was not published.")


def _receipt(snapshot, metrics):
    return {"state": "verified", "job_id": snapshot.job_id, "bytes": snapshot.size,
            "sha256": snapshot.sha256, "metrics": metrics.report()}


def receive(
    status: Mapping, destination: Path, *,
    renew: Callable[[str], Mapping] | None = None, opener=None,
    segment_bytes: int = DEFAULT_RANGE_BYTES, retries_per_segment: int = 2,
    timeout: float = 25, segment_deadline: float = 90,
    progress: Callable[[dict], None] | None = None, metrics: Metrics | None = None,
) -> dict:
    """Return an independently SHA-256-verified local receipt.

    `status` and the optional `renew(job_id)` come from get_workspace_export.
    The receiver never learns OAuth credentials. Renewals must use the same
    origin, job ID, size and SHA. Never call confirm_workspace_export unless
    this function returned a receipt; then pass its job_id and sha256.
    """
    if not 1 <= segment_bytes <= 16 * 1024 * 1024 or not 0 <= retries_per_segment <= 5:
        raise ExportError("configuration", "Invalid range size or retry count.")
    if timeout <= 0 or segment_deadline <= 0:
        raise ExportError("configuration", "Timeouts must be positive.")
    snapshot = Snapshot.from_status(status)
    destination = Path(destination)
    partial = destination.with_name(destination.name + ".part")
    manifest = destination.with_name(destination.name + ".resume.json")
    lock = destination.with_name(destination.name + ".resume.lock")
    opener = opener or _opener()
    metrics = metrics if metrics is not None else Metrics()
    started = time.monotonic()
    with _lock(lock):
        _check_local_file(destination)
        if destination.exists():
            # Recover a process interruption after atomic publication but
            # before cleanup. Do not treat an arbitrary existing file as ours.
            if _recorded_snapshot(manifest) != snapshot.identity():
                raise ExportError("destination_exists", "The verified export never overwrites an existing destination.")
            _check_local_file(partial)
            if partial.exists() and not partial.samefile(destination):
                raise ExportError("destination_exists", "The verified export never overwrites an existing destination.")
            _verified_hash(destination, snapshot, metrics)
            metrics.resumed_bytes = snapshot.size
            partial.unlink(missing_ok=True)
            manifest.unlink()
            metrics.total_seconds = time.monotonic() - started
            return _receipt(snapshot, metrics)
        offset = _local_state(snapshot, partial, manifest)
        metrics.resumed_bytes = offset
        try:
            while offset < snapshot.size:
                end = min(offset + segment_bytes, snapshot.size) - 1
                renewed = False
                retry_count = 0
                while True:
                    # Stage each bounded range separately; interrupted ranges do
                    # not append data to the main partial.
                    with tempfile.TemporaryFile(dir=partial.parent) as stage:
                        try:
                            _request(snapshot, offset, end, stage, opener, timeout, segment_deadline, metrics)
                        except ExportError as exc:
                            if exc.code == "link_unavailable" and renew and not renewed:
                                ts = time.monotonic()
                                try:
                                    candidate = Snapshot.from_status(renew(snapshot.job_id))
                                except ExportError:
                                    raise
                                except Exception:
                                    raise ExportError("renewal_failed", "The export link could not be renewed.") from None
                                finally:
                                    metrics.renewal_seconds += time.monotonic() - ts
                                if candidate != snapshot:
                                    raise ExportError("snapshot_changed", "Renewal did not identify the same authorized snapshot.")
                                snapshot = candidate
                                metrics.renewals += 1
                                renewed = True
                                continue
                            if exc.code == "transient" and retry_count < retries_per_segment:
                                pause = min(8, 2 ** retry_count)
                                time.sleep(pause)
                                metrics.retry_wait_seconds += pause
                                retry_count += 1
                                metrics.retries += 1
                                continue
                            raise
                        stage.seek(0)
                        with os.fdopen(_private_open(partial, os.O_WRONLY | os.O_APPEND), "ab") as out:
                            if os.fstat(out.fileno()).st_size != offset:
                                raise ExportError("local_state", "The partial changed while downloading.")
                            while data := stage.read(READ_BYTES):
                                out.write(data)
                            out.flush()
                            os.fsync(out.fileno())
                    break
                metrics.downloaded_bytes += end - offset + 1
                offset = end + 1
                if progress:
                    progress({"verified_range_end": offset, "expected_bytes": snapshot.size})
            _verified_hash(partial, snapshot, metrics)
            # link() atomically publishes only if there is no existing
            # destination. The two paths are in the same directory.
            try:
                os.link(partial, destination)
            except FileExistsError:
                raise ExportError("destination_exists", "The verified export never overwrites an existing destination.") from None
            partial.unlink()
            manifest.unlink()
        finally:
            metrics.total_seconds = time.monotonic() - started
    return _receipt(snapshot, metrics)


def main(argv=None):
    p = argparse.ArgumentParser(description="Receive a verified Windows export, passing status JSON via stdin.")
    p.add_argument("destination", type=Path)
    p.add_argument("--segment-mib", type=int, default=4, choices=range(1, 17), metavar="1–16")
    args = p.parse_args(argv)
    metrics = Metrics()
    try:
        # Small fixed limit; no capability may appear in command arguments, a
        # traceback or a persisted resume record.
        status = json.loads(sys.stdin.buffer.read(16_385))
        receipt = receive(status, args.destination, segment_bytes=args.segment_mib * 1024 * 1024, metrics=metrics)
    except (json.JSONDecodeError, UnicodeError):
        print(json.dumps({"state": "error", "code": "metadata", "message": "Invalid export-status JSON."}))
        return 2
    except ExportError as exc:
        print(json.dumps({"state": "error", "code": exc.code, "message": str(exc), "metrics": metrics.report()}))
        return 75 if exc.code in {"link_unavailable", "transient", "busy"} else 2
    except OSError:
        print(json.dumps({"state": "error", "code": "local_io", "message": "The local workspace could not read or write the export."}))
        return 2
    print(json.dumps(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
