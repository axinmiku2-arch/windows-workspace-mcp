"""Outbound Windows worker for the locally approved workspace."""
from __future__ import annotations

import msvcrt
import os
import secrets
import sqlite3
import sys
import time
from urllib.error import HTTPError

sys.dont_write_bytecode = True
from core import CONFIG, STATE, STATUS, STOP, canonical_origin, load_config, read_json, request_json, save_json, worker_channel, worker_key
from bridge_ops import dispatch
from file_bridge import pump_exports
from transfer_mailbox import InboundRunner, cleanup as mailbox_cleanup
from project_tasks import Runner
from workspace import WorkspaceGate


def main():
    with (STATE / "worker.lock").open("a+b") as lock:
        if lock.tell() == 0:
            lock.write(b"0")
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return 0
        instance = secrets.token_hex(8)
        details = dict(instance=instance, pid=os.getpid(), started=time.time(), last_contact=0,
                       last_operation="", read_count=0, write_count=0, origin="")

        def record(phase, message):
            try:
                save_json(STATUS, {**details, "phase": phase, "message": message, "heartbeat": time.time()})
            except OSError:
                pass

        def stopped():
            return read_json(STOP).get("instance") == instance

        def pause(seconds):
            end = time.monotonic() + seconds
            while not stopped() and time.monotonic() < end:
                time.sleep(min(0.25, max(0, end - time.monotonic())))

        try:
            cfg = load_config()
            details["config_present"] = CONFIG.is_file()
            details["configured_origin"] = bool(cfg.get("origin"))
            origin = canonical_origin(cfg["origin"])
            details["origin"] = origin
            channel = worker_channel(cfg)
            details["channel"] = "local" if channel != origin else "remote"
            key = worker_key(cfg)
            gate = WorkspaceGate()
            task_runner = Runner()
            inbound_runner = InboundRunner()
            poll = max(1, min(8, int(cfg["poll_seconds"])))
            timeout = max(3, min(20, int(cfg["timeout_seconds"])))
        except (OSError, ValueError, TypeError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            record("failed", f"启动失败：{reason}；请检查配置和测试文件。")
            return 2
        result = None
        delay = poll
        last_cleanup = 0
        record("starting", "正在连接 MCP 中继…")
        while not stopped():
            try:
                gate.pump()
                current = load_config()
                pump_exports(current)
                task_runner.pump(current)
                inbound_runner.pump(current)
                if time.monotonic() - last_cleanup > 30:
                    try:
                        mailbox_cleanup(current)
                    except (OSError, sqlite3.Error):
                        pass  # retry housekeeping on the next cycle
                    last_cleanup = time.monotonic()
                wire = {k: v for k, v in result.items() if k != "local_op"} if result else None
                response = request_json(channel + "/worker", {"completed": wire}, key, timeout=timeout)
                if not isinstance(response, dict) or "job" not in response:
                    raise ValueError("Bad worker reply")
                details["last_contact"] = time.time()
                if result:
                    op = result.pop("local_op", None)
                    if not (result["output"].get("error") or result["output"].get("state")):
                        if op == "workspace_read":
                            details["read_count"] += 1
                        elif op in ("workspace_replace", "workspace_create"):
                            details["write_count"] += 1
                        details["last_operation"] = op
                result = None
                delay = poll
                record("online", "已连接；权限与审批在这台 Windows 上执行。")
                if job := response.get("job"):
                    job_id, op = job["id"], job.get("operation")
                    output = dispatch(gate, job)
                    result = {"id": job_id, "output": output, "local_op": op}
                    continue
            except HTTPError as exc:
                message = ("服务拒绝工作器密钥；请检查中继配置。" if exc.code == 401 else
                           f"中继返回 HTTP {exc.code}，正在重试。")
                record("reconnecting", message)
                delay = min(max(2, delay * 2), 10)
            except (OSError, ValueError, TypeError, KeyError) as exc:
                record("reconnecting", f"连接中断，正在重试（{type(exc).__name__}）。")
                delay = min(max(2, delay * 2), 10)
            pause(delay)
        record("stopped", "工作器已停止。")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
