"""Local, non-persistent shutdown countdown. Do not expose it through MCP."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import subprocess
import time


MIN_MINUTES = 1
MAX_MINUTES = 12 * 60
MAX_LATENESS_SECONDS = 30


class LocalShutdownTimer:
    """This object is held only by the local Windows manager UI."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._deadline: float | None = None

    def schedule(self, minutes: int) -> None:
        if type(minutes) is not int or not MIN_MINUTES <= minutes <= MAX_MINUTES:
            raise ValueError(f"请填写 {MIN_MINUTES}–{MAX_MINUTES} 分钟之间的整数。")
        if self._deadline is not None:
            raise ValueError("已有倒计时。请先取消，再设置新的关机时间。")
        self._deadline = self._clock() + minutes * 60

    def cancel(self) -> bool:
        active = self._deadline is not None
        self._deadline = None
        return active

    def seconds_remaining(self) -> int | None:
        if self._deadline is None:
            return None
        return max(0, int(self._deadline - self._clock() + 0.999999))

    def tick(self, dispatch) -> str:
        if self._deadline is None:
            return "inactive"
        late = self._clock() - self._deadline
        if late < 0:
            return "waiting"
        self._deadline = None  # One shot, including subprocess or policy failure.
        if late > MAX_LATENESS_SECONDS:
            return "cancelled_late"  # Don't turn the machine off unexpectedly after a long pause.
        dispatch()
        return "dispatched"


def request_local_shutdown() -> None:
    """Ask Windows to shut down normally; never force applications or elevate."""
    if os.name != "nt":
        raise OSError("此功能只能在 Windows 上运行。")
    system = ctypes.create_unicode_buffer(32768)
    size = ctypes.windll.kernel32.GetSystemDirectoryW(system, len(system))
    if not 0 < size < len(system):
        raise OSError("无法确认 Windows 系统目录。")
    exe = Path(system.value) / "shutdown.exe"
    # A Windows timeout greater than zero implies /f; use the local UI timer instead.
    result = subprocess.run(
        [str(exe), "/s", "/t", "0"], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False, timeout=8,
        creationflags=subprocess.CREATE_NO_WINDOW, check=False,
    )
    if result.returncode:
        raise OSError(f"Windows 未接受关机请求（退出码 {result.returncode}）。")
