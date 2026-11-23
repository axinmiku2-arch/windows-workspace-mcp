"""Start the explicitly provisioned Windows HTTPS origin on loopback."""
from __future__ import annotations

import json
import msvcrt
import os
import runpy
import sys
from contextlib import redirect_stderr, redirect_stdout

sys.dont_write_bytecode = True
from core import (FUNNEL, FUNNEL_PRIVATE_PORT, FUNNEL_PUBLIC_PORT, RUNTIME,
                  initialize_state, load_config, local_oauth_callbacks, relay_ready)


def main():
    initialize_state()
    cfg = load_config()
    callbacks = local_oauth_callbacks(cfg)
    if not callbacks or not relay_ready(cfg):
        raise ValueError("First provision an explicitly approved HTTPS origin in the local manager.")
    origin = cfg["origin"]
    with (FUNNEL / "relay.lock").open("a+b") as lock:
        if lock.tell() == 0:
            lock.write(b"0")
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return
        os.environ.update(CREDENTIALS_DIRECTORY=str(FUNNEL), STATE_DIRECTORY=str(FUNNEL),
                          PROBE_ORIGIN=origin, PROBE_WORKSPACE="1", PROBE_REQUIRE_LOCAL_BINDING="1",
                          PROBE_OAUTH_CALLBACKS_JSON=json.dumps(callbacks),
                          PROBE_REFRESH_SECONDS="2592000", PROBE_PORT=str(FUNNEL_PUBLIC_PORT),
                          PROBE_PRIVATE_WORKER_PORT=str(FUNNEL_PRIVATE_PORT))
        log_path = FUNNEL / "relay.log"
        if log_path.is_file() and log_path.stat().st_size > 1048576:
            log_path.replace(FUNNEL / "relay.previous.log")
        with log_path.open("a", encoding="utf-8", buffering=1) as handle, redirect_stdout(handle), redirect_stderr(handle):
            try:
                runpy.run_path(str(RUNTIME.parent / "vps" / "probe.py"), run_name="__main__")
            except Exception:
                import traceback
                traceback.print_exc()
                raise


if __name__ == "__main__":
    main()
