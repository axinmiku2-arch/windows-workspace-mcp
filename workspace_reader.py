"""One configured read-only folder; volume/reparse/hard-link defenses."""

from contextlib import contextmanager, ExitStack
from pathlib import Path
import os
import re
import stat
import unicodedata

if os.name == "nt":
    import _windows_fs as win

MAX_BYTES = 16_384
MAX_DEPTH = 8
MAX_PATH = 224
MAX_SCANNED = 300
MAX_ITEMS = 60
TEXT_SUFFIXES = frozenset({".txt", ".md", ".csv", ".tsv", ".json", ".yaml", ".yml", ".toml", ".xml"})
_BLOCKED_PARTS = frozenset({"windows", "winnt", "programdata", "program files", "program files (x86)",
                            "system volume information", "$recycle.bin", "appdata", "windowsapps",
                            "boot", "efi", "recovery", "node_modules", "proc", "sys", "dev", "etc"})
_SENSITIVE_NAME = re.compile(
    r"(?:^|[._\s-])(?:credentials?|secrets?|passwd|passwords?|tokens?|private[-_.\s]?key|"
    r"api[-_.\s]?key|id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys)(?:$|[._\s-])", re.I
)
_DOS_NAME = re.compile(r"(?:con|prn|aux|nul|conin\$|conout\$|com[0-9¹²³]|lpt[0-9¹²³])", re.I)
_BAD_PATH_CHARS = re.compile(r'[:<>"/\\|?*]|~[0-9]+(?:\.|$)')


class WorkspaceError(ValueError):
    """A path-free error safe to display over MCP."""


def _safe_name(name):
    return (1 <= len(name) <= 128 and not name.startswith((".", " ")) and not name.endswith((".", " "))
            and not _BAD_PATH_CHARS.search(name)
            and name.casefold() not in _BLOCKED_PARTS and not _SENSITIVE_NAME.search(name)
            and not _DOS_NAME.fullmatch(name.split(".", 1)[0].rstrip(" "))
            and not any(unicodedata.category(c).startswith("C") for c in name))


def _parts(value, *, directory=False):
    if directory and value == ".":
        return ()
    if not isinstance(value, str) or len(value) > MAX_PATH:
        raise WorkspaceError("Provide a short workspace-relative path.")
    parts = re.split(r"[/\\]", value)
    if len(parts) > MAX_DEPTH or not all(_safe_name(part) for part in parts):
        raise WorkspaceError("Absolute paths, parent traversal and protected names are not allowed.")
    return tuple(parts)


def _identity(st):
    return st.st_dev, st.st_ino


class Reader:
    def __init__(self, root):
        if not isinstance(root, str) or not root or len(root) > MAX_PATH:
            raise WorkspaceError("Set WINDOWS_HELPER_WORKSPACE to one dedicated absolute folder.")
        # Inspect raw components before Path can simplify a dot segment.
        rest = root[3:] if os.name == "nt" else root[1:]
        components = re.split(r"[/\\]" if os.name == "nt" else r"/", rest.rstrip("/\\"))
        base = Path(root)
        if (not base.is_absolute() or base == Path.home() or not all(_safe_name(p) for p in components)
                or base == Path(base.anchor)):
            raise WorkspaceError("Choose a dedicated folder, not a drive root, home, or system folder.")
        if os.name == "nt":
            if not re.fullmatch(r"[A-Za-z]:\\", base.anchor) or not win.fixed_drive(base.anchor):
                raise WorkspaceError("Windows requires a folder on a fixed local drive.")
            if components[0].casefold() == "users" and len(components) < 3:
                raise WorkspaceError("Choose a dedicated subfolder rather than a user profile.")
        self.root = base
        try:
            with self._folder(()) as (_location, marker):
                self.marker = marker
        except OSError:
            raise WorkspaceError("Cannot open the configured workspace without following links.") from None

    @contextmanager
    def _folder(self, parts):
        """Pin all opened directories while the operation is active."""
        with ExitStack() as guard:
            if os.name == "nt":
                path = Path(self.root.anchor)
                handle, meta = win.open_checked(path, directory=True, anchor=True)
                guard.callback(win.close, handle)
                for component in self.root.parts[1:]:
                    path /= component
                    handle, meta = win.open_checked(path, directory=True)
                    guard.callback(win.close, handle)
                marker = win.identity(meta)
                if getattr(self, "marker", marker) != marker:
                    raise WorkspaceError("The configured workspace changed; restart after checking the folder.")
                for component in parts:
                    path /= component
                    handle, meta = win.open_checked(path, directory=True)
                    guard.callback(win.close, handle)
                yield path, marker
                return

            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            handle = os.open(self.root.anchor, flags)
            guard.callback(os.close, handle)
            for component in self.root.parts[1:]:
                handle = os.open(component, flags, dir_fd=handle)
                guard.callback(os.close, handle)
            root_stat = os.fstat(handle)
            marker = _identity(root_stat)
            if getattr(self, "marker", marker) != marker:
                raise WorkspaceError("The configured workspace changed; restart after checking the folder.")
            for component in parts:
                handle = os.open(component, flags, dir_fd=handle)
                guard.callback(os.close, handle)
                if os.fstat(handle).st_dev != root_stat.st_dev:
                    raise WorkspaceError("Mounted paths inside a workspace are not supported.")
            yield handle, marker

    def describe(self):
        try:
            with self._folder(()) as _:
                return {"access": "read-only", "active": True, "text_limit_bytes": MAX_BYTES,
                        "text_extensions": sorted(TEXT_SUFFIXES), "entries_limit": MAX_ITEMS}
        except OSError:
            raise WorkspaceError("The configured workspace is unavailable.") from None

    def list(self, relative_dir="."):
        parts = _parts(relative_dir, directory=True)
        result, truncated = [], False
        try:
            with self._folder(parts) as (location, marker), os.scandir(location) as records:
                for index, entry in enumerate(records):
                    if index >= MAX_SCANNED or len(result) >= MAX_ITEMS:
                        truncated = True
                        break
                    if not _safe_name(entry.name):
                        continue
                    full = "/".join((*parts, entry.name))
                    if len(full) > MAX_PATH or len(parts) >= MAX_DEPTH:
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    attrs = getattr(info, "st_file_attributes", 0)
                    if attrs & 0x406:
                        continue
                    if os.name != "nt" and info.st_dev != marker[0]:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        result.append({"type": "directory", "relative_path": full})
                    elif (stat.S_ISREG(info.st_mode) and Path(entry.name).suffix.lower() in TEXT_SUFFIXES
                          and not entry.is_symlink()):
                        # Windows DirEntry.stat may omit link count; lstat by path
                        # with the parent pinned, and never follow it at read time.
                        try:
                            actual = Path(location, entry.name).lstat() if os.name == "nt" else info
                        except OSError:
                            continue
                        if actual.st_nlink == 1 and stat.S_ISREG(actual.st_mode) and not (
                                getattr(actual, "st_file_attributes", 0) & 0x406):
                            result.append({"type": "file", "relative_path": full,
                                           "readable_by_size": actual.st_size <= MAX_BYTES})
        except OSError:
            raise WorkspaceError("The directory is unavailable or unsupported.") from None
        return {"entries": sorted(result, key=lambda x: x["relative_path"].casefold()), "truncated": truncated}

    def read(self, relative_path):
        parts = _parts(relative_path)
        if Path(parts[-1]).suffix.lower() not in TEXT_SUFFIXES:
            raise WorkspaceError("This file type is not on the UTF-8 text allowlist.")
        try:
            with self._folder(parts[:-1]) as (location, marker):
                if os.name == "nt":
                    raw = win.read_file(Path(location, parts[-1]), MAX_BYTES)
                else:
                    fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=location)
                    try:
                        info = os.fstat(fd)
                        if not stat.S_ISREG(info.st_mode) or info.st_dev != marker[0] or info.st_nlink != 1:
                            raise OSError("Unsupported file type.")
                        if info.st_size > MAX_BYTES:
                            raise WorkspaceError("The UTF-8 preview exceeds the byte limit.")
                        with os.fdopen(fd, "rb", closefd=False) as source:
                            raw = source.read(MAX_BYTES + 1)
                        current = os.fstat(fd)
                        if (current.st_nlink != 1 or current.st_mtime_ns != info.st_mtime_ns
                                or current.st_size != info.st_size):
                            raise WorkspaceError("The file changed during the read; try again.")
                    finally:
                        os.close(fd)
        except OSError:
            raise WorkspaceError("The file is unavailable or unsupported.") from None
        if len(raw) > MAX_BYTES:
            raise WorkspaceError("The UTF-8 preview exceeds the byte limit.")
        try:
            content = raw.decode("utf-8-sig")
        except UnicodeError:
            raise WorkspaceError("This file is not valid UTF-8 text.") from None
        if any((ord(c) < 32 and c not in "\t\r\n") or 127 <= ord(c) <= 159 for c in content):
            raise WorkspaceError("The file contains unsupported binary or control bytes.")
        return {"relative_path": "/".join(parts), "byte_count": len(raw), "text": content}
