"""Win32 handle helpers. No write access and no reparse-point traversal."""

import ctypes
from ctypes import wintypes
import msvcrt
import os


class _FileInfo(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("created", wintypes.FILETIME),
        ("accessed", wintypes.FILETIME),
        ("written", wintypes.FILETIME),
        ("volume", wintypes.DWORD),
        ("size_high", wintypes.DWORD),
        ("size_low", wintypes.DWORD),
        ("links", wintypes.DWORD),
        ("index_high", wintypes.DWORD),
        ("index_low", wintypes.DWORD),
    ]


_kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
_create = _kernel.CreateFileW
_create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
_create.restype = wintypes.HANDLE
_info = _kernel.GetFileInformationByHandle
_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(_FileInfo)]
_info.restype = wintypes.BOOL
_type = _kernel.GetFileType
_type.argtypes = [wintypes.HANDLE]
_type.restype = wintypes.DWORD
_close = _kernel.CloseHandle
_close.argtypes = [wintypes.HANDLE]
_close.restype = wintypes.BOOL
_drive = _kernel.GetDriveTypeW
_drive.argtypes = [wintypes.LPCWSTR]
_drive.restype = wintypes.UINT
_INVALID = ctypes.c_void_p(-1).value

_READ_ATTRIBUTES = 0x80
_GENERIC_READ = 0x80000000
_SHARE_READ = 0x1  # no share-write or share-delete; deny rename and replacing a component
_OPEN_EXISTING = 3
_OPEN_REPARSE = 0x00200000
_BACKUP_SEMANTICS = 0x02000000
_DIRECTORY = 0x10
_PERMANENTLY_EXCLUDED = 0x400 | 0x2 | 0x4  # reparse point, hidden, system


def fixed_drive(anchor):
    return _drive(anchor) == 3


def open_checked(path, *, directory, anchor=False):
    access = _READ_ATTRIBUTES if directory else _GENERIC_READ
    handle = _create(str(path), access, _SHARE_READ, None, _OPEN_EXISTING,
                     _OPEN_REPARSE | _BACKUP_SEMANTICS, None)
    if handle is None or handle == _INVALID:
        raise OSError("Windows rejected opening that item without following links.")
    try:
        meta = _FileInfo()
        if _type(handle) != 1 or not _info(handle, ctypes.byref(meta)):  # disk / filesystem
            raise OSError("Windows did not return a regular filesystem handle.")
        ignored = 0x2 | 0x4 if anchor else 0
        if ((meta.attributes & (_PERMANENTLY_EXCLUDED & ~ignored))
                or bool(meta.attributes & _DIRECTORY) != directory
                or not directory and meta.links != 1):
            raise OSError("Unsupported or protected workspace item.")
        return handle, meta
    except BaseException:
        _close(handle)
        raise


def close(handle):
    _close(handle)


def identity(meta):
    return (int(meta.volume), int(meta.index_high) << 32 | int(meta.index_low))


def read_file(path, limit):
    handle, meta = open_checked(path, directory=False)
    try:
        if (int(meta.size_high) << 32 | int(meta.size_low)) > limit:
            raise ValueError("The UTF-8 preview exceeds the byte limit.")
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        _close(handle)
        raise

    # open_osfhandle transfers ownership; normal close must now be through fd.
    try:
        with os.fdopen(fd, "rb", closefd=False) as source:
            return source.read(limit + 1)
    finally:
        os.close(fd)
