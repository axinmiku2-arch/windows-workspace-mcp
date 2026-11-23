"""Durable Windows job queue for fixed, locally approved project actions."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
from ctypes import wintypes
from pathlib import Path

if __name__ != "__main__":
    import core
    import diagnostic_routines
    import task_files
    import task_recipes
    import task_verification
    import windows_toolbox
    from workspace import no_link, resolve, workspace_root

    QUEUE = core.STATE / "project-tasks"
    PROJECT_PRESETS = task_recipes.PROJECT_OPERATIONS
    TYPED_PRESETS = {**task_verification.PRESETS, **task_files.PRESETS}
    TOOLBOX_PRESETS = windows_toolbox.PRESETS
    PRESETS = {key: spec["label"] for key, spec in {**PROJECT_PRESETS, **TYPED_PRESETS, **TOOLBOX_PRESETS}.items()}
ACTIVE = frozenset({"awaiting_approval", "queued", "running", "cancelling"})
IDENTIFIER = re.compile(r"[0-9a-f]{32}\Z")
CONNECTION_ID = re.compile(r"[0-9a-f]{24}\Z")
REQUEST = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
OUT_LIMIT = 3500
APPROVAL_TTL = 1800
KEEP = 7 * 86400
UNATTENDED_PRESETS = frozenset({"python_build_check"})
_JOB_IO = threading.RLock()


def validate_scope(value, cfg):
    if not cfg.get("workspace_enabled") or not core.uses_funnel(cfg):
        raise ValueError("Enable the local Windows workspace and fixed HTTPS relay first.")
    root, folder = workspace_root(cfg["workspace_root"]), workspace_root(value)
    if folder == Path(folder.anchor) or (folder != root and root not in folder.parents):
        raise ValueError("Select one project folder within the workspace, not an entire drive.")
    path = resolve(root, folder.relative_to(root).as_posix(), folder=True)
    if path != folder:
        raise ValueError("The selected project path is invalid.")
    return folder


def _policy(cfg):
    return hashlib.sha256(json.dumps([cfg.get(k) for k in ("workspace_root", "workspace_revision", "task_scope",
                "task_revision", "origin")], ensure_ascii=False).encode()).hexdigest()


def _base(cfg):
    if not cfg.get("task_enabled"):
        raise ValueError("Windows project tasks are disabled in the local manager.")
    if cfg.get("workspace_unified") is True:
        if not cfg.get("workspace_enabled") or not core.uses_funnel(cfg):
            raise ValueError("The Windows workspace is not available.")
        return workspace_root(cfg["workspace_root"])
    return validate_scope(cfg.get("task_scope"), cfg)


def _scope(cfg, relative_dir="."):
    base = _base(cfg)
    if cfg.get("workspace_unified") is not True and relative_dir != ".":
        raise ValueError("Use the existing project folder or migrate to unified workspace authorization.")
    target = resolve(base, relative_dir, folder=True)
    if target == Path(target.anchor):
        raise ValueError("Select a project subfolder via relative_dir; a drive root cannot run a project task.")
    return target


def _folder_id(folder):
    info = folder.lstat()
    return [info.st_dev, info.st_ino]


def _job_files():
    return QUEUE.glob("*.json") if QUEUE.is_dir() else ()


def _path(job_id):
    if not isinstance(job_id, str) or not IDENTIFIER.fullmatch(job_id):
        raise ValueError("Invalid project job ID.")
    return QUEUE / (job_id + ".json")


def _signal(job_id, operation):
    return _path(job_id).with_suffix("." + operation)


def _read(job_id, cfg):
    item = _load_job(_path(job_id))
    if not item or item.get("policy") != _policy(cfg):
        raise ValueError("Project job is unavailable under the current authorization.")
    return item


def _write(job):
    path = _path(job["job_id"])
    for delay in (0.0, 0.025, 0.075, 0.15, 0.30):
        if delay:
            time.sleep(delay)
        with _JOB_IO:
            try:
                core.save_json(path, job)
                return
            except PermissionError as exc:
                if delay == 0.30 or getattr(exc, "winerror", None) not in (None, 5, 32, 33):
                    raise


def _load_job(path):
    # Status polls, journal updates, and the worker use the same files on Windows.
    # Hold the same process lock so a short-lived reader cannot block os.replace.
    with _JOB_IO:
        return core.read_json(path)


def _present(item, include_output=False, *, reveal_toolbox_host=True):
    out = {k: item[k] for k in ("job_id", "preset", "label", "state", "created", "updated",
                                "relative_dir", "relative_path", "destination_path", "step_count", "progress",
                                "planned_steps", "runs_project_code", "submission", "toolbox_scope", "routine_id") if k in item}
    if reveal_toolbox_host and "toolbox_host" in item:
        out["toolbox_host"] = item["toolbox_host"]
    if "exit_code" in item:
        out["exit_code"] = item["exit_code"]
    if "message" in item:
        out["message"] = item["message"]
    if include_output:
        for key in ("stdout", "stderr", "output_truncated", "result"):
            if key in item:
                out[key] = item[key]
    return out


def _finish(job, state, **extra):
    result = {**job, "state": state, "updated": time.time(), **extra}
    _write(result)
    return result


def _signal_exists(job_id, action):
    return _signal(job_id, action).is_file()


def _automatic(preset, cfg, recipe=None):
    if cfg.get("workspace_unified") is not True:
        return False
    mode = cfg.get("approval_mode")
    if recipe is not None:
        return all(_automatic(step["preset"], cfg) for step in recipe["steps"])
    if preset in TOOLBOX_PRESETS:
        return False  # OS diagnostics are never approved automatically.
    if preset in task_verification.PRESETS:
        return mode in {"full", "rules"}
    if preset in task_files.PRESETS:
        return mode == "full"
    return mode == "full" and preset in UNATTENDED_PRESETS


def _arguments(preset, cfg, relative_dir, relative_path, parameters):
    base = _base(cfg)
    if preset in TOOLBOX_PRESETS:
        if relative_dir != "." or relative_path is not None:
            raise ValueError("Fixed Windows diagnostics do not accept a workspace path.")
        params = windows_toolbox.parameters(preset, parameters, cfg)
        return {"relative_dir": ".", "parameters": params, "toolbox_scope": "host",
                **({"toolbox_host": params["host"]} if "host" in params else {})}
    spec = TYPED_PRESETS.get(preset)
    file_action = preset in task_files.PRESETS
    if spec:
        if not file_action:
            parameters = task_verification.arguments(preset, parameters)
        if spec["target"] == "file":
            # Already-installed clients know relative_dir, so a file path passed
            # in that old argument remains usable for a file-only preset.
            if relative_path is not None and relative_dir not in {".", ""}:
                raise ValueError("For a file task, supply relative_path or its older relative_dir alias, not both.")
            target = task_verification.target_file(base, relative_path if relative_path is not None else relative_dir,
                                                   "zip_inspect" if preset == "zip_extract" else preset)
            label = target.relative_to(base).as_posix()
            fields = {"relative_dir": target.parent.relative_to(base).as_posix(), "relative_path": label,
                      "file_stamp": task_verification.stamp(no_link(target, False))}
            if file_action:
                return {**fields, "parameters": {}, "destination_path": task_files.destination(base, target, preset, parameters)}
            return {**fields, "parameters": parameters}
    elif parameters not in (None, {}):
        raise ValueError("This preset does not accept task parameters.")
    if relative_path is not None:
        raise ValueError("This preset uses relative_dir, not relative_path.")
    folder = _scope(cfg, relative_dir)
    fields = {"relative_dir": folder.relative_to(base).as_posix(), "folder_id": _folder_id(folder)}
    if file_action:
        return {**fields, "parameters": {}, "destination_path": task_files.destination(base, folder, preset, parameters)}
    if PROJECT_PRESETS.get(preset, {}).get("writes"):
        fields["runs_project_code"] = True
    if preset in {"npm_test", "npm_build"}:
        fields["npm_manifest_sha256"] = _npm_manifest_digest(folder / "package.json")
    return {**fields, "parameters": parameters or {}}


def _recipe_arguments(recipe, cfg, relative_dir, relative_path, parameters):
    parameters = task_recipes.arguments(recipe, parameters)
    steps = []
    for index, step in enumerate(recipe["steps"]):
        steps_override = step["parameters"]
        if index == len(recipe["steps"]) - 1 and parameters:
            steps_override = {**steps_override, **parameters}
        fields = _arguments(step["preset"], cfg, relative_dir, relative_path, steps_override)
        steps.append({"preset": step["preset"], **fields})
    common = {k: v for k, v in steps[0].items()
              if k in {"relative_path", "relative_dir", "file_stamp", "folder_id"}}
    if any(any(other.get(k) != v for k, v in common.items()) for other in steps[1:]):
        raise ValueError("The recipe target changed while planning; submit again.")
    npm_stamps = {step["npm_manifest_sha256"] for step in steps if "npm_manifest_sha256" in step}
    if len(npm_stamps) > 1:
        raise ValueError("package.json changed while planning; submit again.")
    npm_plan = {"npm_manifest_sha256": next(iter(npm_stamps))} if npm_stamps else {}
    return {**common, "parameters": {}, "recipe_id": recipe["id"], "recipe_revision": task_recipes.revision(recipe),
            "recipe_steps": steps, "step_count": len(steps), **npm_plan,
            "planned_steps": [{"preset": s["preset"], "label": PRESETS[s["preset"]]} for s in steps],
            "runs_project_code": any(PROJECT_PRESETS.get(s["preset"], {}).get("writes") for s in steps),
            **({"destination_path": steps[-1]["destination_path"]} if "destination_path" in steps[-1] else {})}


def _submission(source):
    if source is None:
        return {"transport": "local"}
    if (not isinstance(source, dict) or set(source) != {"transport", "connection_id"}
            or source["transport"] != "https_mcp" or not isinstance(source["connection_id"], str)
            or CONNECTION_ID.fullmatch(source["connection_id"]) is None):
        raise ValueError("The worker received an invalid authenticated submission record.")
    return {"transport": "https_mcp", "connection_id": source["connection_id"]}


def start(preset, cfg, request_key="", relative_dir=".", relative_path=None, parameters=None, *, submission=None):
    recipe, routine_id = None, None
    if not isinstance(request_key, str) or request_key and not REQUEST.fullmatch(request_key):
        raise ValueError("Request key must use 1–64 letters, digits or ._:-")
    source = _submission(submission)
    now = time.time()
    entries = [_load_job(p) for p in _job_files()]
    policy = _policy(cfg)
    if isinstance(preset, str) and preset.startswith(diagnostic_routines.PREFIX):
        _base(cfg)
        routine_id = preset[len(diagnostic_routines.PREFIX):]
        if not request_key:
            raise ValueError("Provide a stable request_key for this reusable diagnostic.")
        if (relative_dir != "." or relative_path is not None
                or parameters is not None and (not isinstance(parameters, dict) or parameters)):
            raise ValueError("Reusable diagnostics use only their locally registered settings.")
        prior = next((old for old in entries if old.get("policy") == policy
                      and old.get("request_key") == request_key and old.get("submission") == source
                      and old.get("routine_id") == routine_id and now - old.get("created", 0) < KEEP), None)
        if prior is not None:
            return _present(prior, reveal_toolbox_host=False)
        preset, parameters = diagnostic_routines.plan(routine_id, source, cfg)
        if any(old.get("policy") == policy and old.get("routine_id") == routine_id
               and old.get("state") in ACTIVE for old in entries):
            raise ValueError("A request for this reusable diagnostic is already queued or running.")
    if isinstance(preset, str) and preset.startswith(task_recipes.PREFIX):
        recipe = task_recipes.get(preset[len(task_recipes.PREFIX):])
    if not isinstance(preset, str) or (preset not in PRESETS and recipe is None):
        raise ValueError("Use one of the locally offered project task presets.")
    fields = (_recipe_arguments(recipe, cfg, relative_dir, relative_path, parameters) if recipe is not None
              else _arguments(preset, cfg, relative_dir, relative_path, parameters))
    if routine_id is not None:
        fields["routine_id"] = routine_id
    if request_key:
        for old in entries:
            if old.get("policy") == policy and old.get("request_key") == request_key and now - old.get("created", 0) < KEEP:
                if "submission" in old and old["submission"] != source:
                    raise ValueError("This request key is associated with another submission connection.")
                if old["preset"] != preset or any(old.get(k, default) != fields.get(k, default)
                    for k, default in (("relative_dir", "."), ("relative_path", None), ("parameters", {}),
                                       ("destination_path", None), ("recipe_revision", None),
                                       ("npm_manifest_sha256", None), ("routine_id", None))):
                    raise ValueError("This request key was used for another preset, target or parameters.")
                return _present(old, reveal_toolbox_host=source["transport"] == "local")
    if sum(item.get("state") in ACTIVE and item.get("policy") == policy for item in entries) >= 8:
        raise ValueError("Project task queue is full.")
    if "destination_path" in fields:
        task_files.require_unused(_base(cfg), fields["destination_path"])
    QUEUE.mkdir(parents=True, exist_ok=True)
    automatic = routine_id is not None or _automatic(preset, cfg, recipe)
    item = {"job_id": uuid.uuid4().hex, "preset": preset, "label": recipe["label"] if recipe else PRESETS[preset],
            "state": "queued" if automatic else "awaiting_approval",
            "created": now, "updated": now, "policy": policy, "submission": source, **fields,
            "request_key": request_key, "message": "Queued under the current workspace policy."
            if automatic else "Approve this project job in the Windows manager."}
    _write(item)
    return _present(item, reveal_toolbox_host=source["transport"] == "local")


def _visible_to_remote(item, submission=None):
    # A diagnosis submitted using the manager's local button is private to the
    # operator, even when the same workspace is connected over HTTPS.
    if "routine_id" in item:
        return submission is not None and item.get("submission") == _submission(submission)
    return (item.get("preset") not in TOOLBOX_PRESETS
            or item.get("submission", {}).get("transport") == "https_mcp")


def status(job_id, cfg, *, remote=False, submission=None):
    _base(cfg)
    item = _read(job_id, cfg)
    if remote and not _visible_to_remote(item, submission):
        raise ValueError("Project job is unavailable under the current authorization.")
    return _present(item, include_output=True, reveal_toolbox_host=not remote)


def listing(cfg, limit=20, *, remote=False):
    if not cfg.get("task_enabled") or not cfg.get("workspace_enabled"):
        return {"enabled": False, "presets": [], "jobs": []}
    base = _base(cfg)
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("Use a list limit between 1 and 50.")
    entries = [_load_job(p) for p in _job_files()]
    jobs = [j for j in entries if j.get("policy") == _policy(cfg) and (not remote or _visible_to_remote(j))]
    jobs.sort(key=lambda j: (j["state"] not in ACTIVE, -j["created"]))
    view = {"enabled": True, "execution_host": "windows",
            "relative_dir_required": base == Path(base.anchor),
            "presets": [{"id": k, "label": v, "automatic": _automatic(k, cfg),
                         "target": TYPED_PRESETS.get(k, {}).get("target", "directory"),
                         "path_argument": "relative_path" if TYPED_PRESETS.get(k, {}).get("target") == "file" else "relative_dir",
                         "writes_workspace": bool(TYPED_PRESETS.get(k, {}).get("writes") or PROJECT_PRESETS.get(k, {}).get("writes")),
                         "parameters": TYPED_PRESETS.get(k, {}).get("parameters", {})}
                        for k, v in PRESETS.items() if k not in TOOLBOX_PRESETS],
            "compatibility_note": "For a file preset, an older client may pass the exact file path in relative_dir.",
            "jobs": [_present(j, reveal_toolbox_host=not remote) for j in jobs[:limit]], "jobs_truncated": len(jobs) > limit}
    for key, spec in TOOLBOX_PRESETS.items():
        view["presets"].append({"id": key, "label": spec["label"], "kind": "fixed_windows_toolbox",
                                "automatic": False, "target": "host", "path_argument": None,
                                "writes_workspace": False,
                                "available": key != "windows_ping" or bool(windows_toolbox.ping_hosts(cfg)),
                                "parameters": spec["parameters"]})
    try:
        for recipe in task_recipes.listing():
            view["presets"].append({
                "id": task_recipes.PREFIX + recipe["id"], "label": recipe["label"], "kind": "local_recipe",
                "automatic": _automatic(None, cfg, recipe),
                "target": recipe["target"],
                "path_argument": "relative_path" if recipe["target"] == "file" else "relative_dir",
                "writes_workspace": task_recipes.writes(recipe),
                "runs_project_code": any(PROJECT_PRESETS.get(step["preset"], {}).get("writes") for step in recipe["steps"]),
                "parameters": task_files.DESTINATION_PARAMETER if task_recipes.can_choose_destination(recipe) else {},
                "steps": [step["preset"] for step in recipe["steps"]],
            })
    except (OSError, ValueError):
        view["recipe_catalog_error"] = "Saved recipes are unavailable. Open the local Windows manager."
    while view["jobs"] and len(json.dumps(view, ensure_ascii=False).encode("utf-8")) > 23_000:
        view["jobs"].pop()
        view["jobs_truncated"] = True
    return view


def _set_signal(job_id, action):
    core.save_json(_signal(job_id, action), {"time": time.time()})


def decide(job_id, cfg, allow):
    """Manager-only approval; workers process approval records."""
    _base(cfg)
    item = _read(job_id, cfg)
    if item["state"] != "awaiting_approval" or item["created"] + APPROVAL_TTL <= time.time():
        raise ValueError("This project job is no longer awaiting approval.")
    _set_signal(job_id, "approve" if allow else "deny")
    return _present(item)


def cancel(job_id, cfg, *, remote=False, submission=None):
    _base(cfg)
    item = _read(job_id, cfg)
    if remote and not _visible_to_remote(item, submission):
        raise ValueError("Project job is unavailable under the current authorization.")
    if item["state"] in ACTIVE:
        _set_signal(job_id, "cancel")
        return {**_present(item, reveal_toolbox_host=not remote), "state": "cancelling"}
    return _present(item, reveal_toolbox_host=not remote)


def _windows_job(process):
    class Basic(ctypes.Structure):
        _fields_ = [("ProcessTime", ctypes.c_longlong), ("JobTime", ctypes.c_longlong), ("Flags", wintypes.DWORD),
                    ("MinSet", ctypes.c_size_t), ("MaxSet", ctypes.c_size_t), ("ActiveLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("Priority", wintypes.DWORD), ("Scheduling", wintypes.DWORD)]
    class Counters(ctypes.Structure):
        _fields_ = [(f"v{i}", ctypes.c_ulonglong) for i in range(6)]
    class Extended(ctypes.Structure):
        _fields_ = [("Basic", Basic), ("Io", Counters)] + [(f"n{i}", ctypes.c_size_t) for i in range(4)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise OSError("Could not create the Windows process group.")
    info = Extended()
    info.Basic.Flags = 0x2000  # KILL_ON_JOB_CLOSE
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(info), ctypes.sizeof(info)) or not kernel.AssignProcessToJobObject(handle, int(process._handle)):
        kernel.CloseHandle(handle)
        raise OSError("Could not safely attach the task to a Windows process group.")
    return lambda: kernel.CloseHandle(handle)


def _env(executable):
    names = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMDATA", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE")
    out = {n: os.environ[n] for n in names if n in os.environ}
    windows = Path(out.get("SYSTEMROOT", r"C:\Windows"))
    gitpath = _git_binary()
    out["PATH"] = os.pathsep.join(dict.fromkeys([str(executable.parent), str(Path(sys.executable).parent),
                   *( [str(gitpath.parent)] if gitpath else []), str(windows / "System32"), str(windows)]))
    out.update(COMSPEC=str(windows / "System32" / "cmd.exe"), PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="NUL", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0",
               # Git status/diff must not lazy-fetch partial clone objects or open a remote transport.
               GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="", GIT_PAGER="", NO_COLOR="1", npm_config_update_notifier="false", npm_config_logs_max="0",
               npm_config_cache=str(core.STATE / "task-npm-cache"),
               npm_config_userconfig=str(core.STATE / "task-npm-user.npmrc"),
               npm_config_globalconfig=str(core.STATE / "task-npm-global.npmrc"))
    return out


def _git_binary():
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    installed = [program_files / "Git" / "cmd" / "git.exe"]
    if os.environ.get("LOCALAPPDATA"):
        installed.append(Path(os.environ["LOCALAPPDATA"]) / "Programs" / "Git" / "cmd" / "git.exe")
    regular = next((item for item in installed if item.is_file()), None)
    if regular:
        return regular.resolve()
    found = shutil.which("git.exe")
    if found:
        return Path(found).resolve()
    setting = core.load_config().get("task_git_path", "")
    if isinstance(setting, str) and setting:
        pinned = Path(setting)
        if pinned.is_absolute() and pinned.name.lower() == "git.exe" and not pinned.is_symlink() and pinned.is_file():
            return pinned.resolve()
    return None


def _command(folder, preset):
    if preset not in PROJECT_PRESETS:
        raise ValueError("Unknown fixed Windows project command.")
    python = Path(sys.executable).resolve()
    if python.name.casefold() == "pythonw.exe" and python.with_name("python.exe").is_file():
        python = python.with_name("python.exe")
    if preset == "python_unittest":
        return [str(python), "-B", "-X", "utf8", "-m", "unittest", "discover"]
    if preset == "python_build_check":
        return [str(python), "-I", "-B", "-X", "utf8", str(Path(__file__).resolve()), "--compile"]
    if preset in {"git_status", "git_diff", "git_diff_staged"}:
        no_link(folder / ".git", True)  # require a local checkout, not an external Git worktree
        git = _git_binary()
        if not git:
            raise ValueError("Git is not available to the Windows worker.")
        args = [str(git), "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=NUL",
                "-c", "core.untrackedCache=false", "-c", "core.worktree=.", "-c", "core.quotePath=false"]
        if preset == "git_status":
            return args + ["status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=all"]
        return args + ["diff", "--no-ext-diff", "--no-textconv", "--ignore-submodules=all",
                       *(["--cached"] if preset == "git_diff_staged" else []), "--"]
    if preset not in {"npm_test", "npm_build"}:
        raise ValueError("Unknown fixed Windows project command.")
    node = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodejs" / "node.exe"
    if not node.is_file():
        node = Path(shutil.which("node.exe") or "").resolve()
    cli = node.parent / "node_modules" / "npm" / "bin" / "npm-cli.js"
    if not node.is_file() or not cli.is_file():
        raise ValueError("Node.js with npm is not available to the Windows worker.")
    no_link(folder / "package.json", False)
    return [str(node), str(cli), "--prefix", str(folder), "run", "build" if preset == "npm_build" else "test"]


def _tail(stream, capture):
    try:
        while chunk := stream.read(8192):
            capture["bytes"] += len(chunk)
            capture["tail"] = (capture["tail"] + chunk)[-OUT_LIMIT:]
    finally:
        stream.close()


def _safe_output(data):
    return "".join(c if c in "\n\r\t" or c.isprintable() else "?" for c in data.decode("utf-8", "replace"))


def _command_stop(job, deadline, *, routine_consumed=False):
    cfg = core.load_config()
    if not cfg.get("task_enabled") or not cfg.get("workspace_enabled") or _policy(cfg) != job["policy"]:
        return "revoked"
    if job["preset"] in TOOLBOX_PRESETS:
        try:
            if "routine_id" in job:
                diagnostic_routines.check(job, cfg, consumed=routine_consumed)
            elif not _signal_exists(job["job_id"], "approve"):
                return "rejected"
            windows_toolbox.parameters(job["preset"], job.get("parameters"), cfg)
        except (ValueError, OSError, sqlite3.Error):
            return "revoked"
    if (PROJECT_PRESETS.get(job["preset"], {}).get("approval")
            and not _signal_exists(job["job_id"], "approve")):
        return "rejected"
    if "recipe_id" in job and not _current_recipe(job):
        return "revoked"
    if _signal_exists(job["job_id"], "cancel"):
        return "cancelled"
    if time.monotonic() >= deadline:
        return "timed_out"
    return ""


def _npm_manifest_digest(path):
    digest, _ = task_verification.digest_file(path, 2_000_000, lambda done, total: None)
    return digest


def _run(job, folder, recipe_deadline=None):
    preset = job["preset"]
    toolbox = preset in TOOLBOX_PRESETS
    routine = toolbox and "routine_id" in job
    seconds = windows_toolbox.TIMEOUT_SECONDS if toolbox else (120 if preset.startswith(("npm_", "python_")) else 25)
    deadline = time.monotonic() + seconds
    if recipe_deadline is not None:
        deadline = min(deadline, recipe_deadline)
    earlier = _command_stop(job, deadline)
    if earlier:
        return earlier, {"message": "The Windows command was stopped before launch."}
    if toolbox:
        args, working_dir, env = windows_toolbox.launch_spec(preset, job.get("parameters"), core.load_config())
    else:
        args = _command(folder, preset)
        working_dir, env = folder, _env(Path(args[0]))
    parent = Path(sys.executable).with_name("python.exe")
    if not parent.is_file():
        parent = Path(sys.executable)
    wrapper = [str(parent), "-I", "-B", "-X", "utf8", str(Path(__file__).resolve()), "--launch", *args]
    process = subprocess.Popen(wrapper, cwd=working_dir, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               shell=False, creationflags=core.HIDDEN, env=env)
    close_job = None
    readers, sinks = [], []
    reason = ""
    try:
        close_job = _windows_job(process)
        for stream in (process.stdout, process.stderr):
            sink = {"bytes": 0, "tail": b""}
            thread = threading.Thread(target=_tail, args=(stream, sink), daemon=True)
            sinks.append(sink)
            readers.append(thread)
            thread.start()
        before = _command_stop(job, deadline)
        if before:
            return before, {"message": "The Windows command was stopped before launch."}
        if job["preset"] in {"npm_test", "npm_build"}:
            expected_manifest = job.get("npm_manifest_sha256")
            if not expected_manifest or _npm_manifest_digest(folder / "package.json") != expected_manifest:
                raise ValueError("package.json changed or was not recorded at submission; request again for approval.")
        if routine:
            try:
                diagnostic_routines.consume(job, core.load_config())
            except ValueError as exc:
                return "rejected", {"message": str(exc)}
            after_claim = _command_stop(job, deadline, routine_consumed=True)
            if after_claim:
                return after_claim, {"message": "The reusable diagnostic was stopped before launch."}
        process.stdin.write(b"1")
        process.stdin.close()
        while process.poll() is None:
            reason = _command_stop(job, deadline, routine_consumed=routine)
            if reason:
                break
            time.sleep(0.25)
    finally:
        if close_job:
            close_job()  # also stops any leftover grandchildren on success
        if process.poll() is None:
            if not close_job:
                process.kill()
            process.wait(timeout=5)
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        for thread in readers:
            thread.join(2)
        if not readers:
            process.stdout.close()
            process.stderr.close()
    stdout, stderr = sinks
    if toolbox:
        # Do not expose raw output or errors from Windows to the caller. It may
        # contain OS strings, adapter information or a resolved network address.
        if reason:
            return reason, {"message": "The fixed Windows diagnostic stopped."}
        if process.returncode != 0:
            return "failed", {"message": "The fixed Windows diagnostic exited unsuccessfully."}
        if stdout["bytes"] > OUT_LIMIT:
            return "failed", {"message": "The fixed Windows diagnostic exceeded its output limit."}
        result = windows_toolbox.structured_result(preset, stdout["tail"])
        return "succeeded", {"exit_code": 0, "result": result,
                             "message": "The fixed Windows diagnostic completed."}
    return reason or ("succeeded" if process.returncode == 0 else "failed"), {
        "exit_code": process.returncode, "stdout": _safe_output(stdout["tail"]), "stderr": _safe_output(stderr["tail"]),
        "output_truncated": any(s["bytes"] > OUT_LIMIT for s in sinks), "message": ""}


class _Stopped(Exception):
    def __init__(self, state, message):
        self.state, self.message = state, message


def _current_recipe(job):
    try:
        recipe = task_recipes.get(job["recipe_id"])
        return recipe is not None and task_recipes.revision(recipe) == job["recipe_revision"]
    except (OSError, ValueError):
        return False


def _read_action(step, target, checkpoint):
    preset, params = step["preset"], step["parameters"]
    if preset == "file_sha256":
        result = task_verification.file_sha256(target, params, checkpoint, step["file_stamp"])
        ok, final = result.get("matches", True), result["size_bytes"]
    elif preset == "verify_sha256_manifest":
        result = task_verification.verify_manifest(target, checkpoint, step["file_stamp"])
        ok, final = result["valid"], result["verified_bytes"]
    elif preset == "zip_inspect":
        result = task_verification.inspect_zip(target, params, checkpoint, step["file_stamp"])
        ok = (result["valid_structure"] and result["safe_member_paths"]
              and (not params["verify_crc"] or result["crc_verified"]))
        final = result.get("expanded_bytes", 0) if result["crc_verified"] else 0
    elif preset == "pe_inspect":
        result = task_verification.inspect_pe(target, checkpoint, step["file_stamp"])
        ok, final = True, 158  # DOS, signature/COFF, and bounded optional-header bytes.
    else:
        result = task_verification.inventory(target, params, checkpoint)
        ok = True
        final = result["files"] + result["directories"] + result["excluded_entries"]
    checkpoint(final, final, force=True)
    return ok, result


def _bound_result(result, limit):
    for key in ("stdout", "stderr"):
        if isinstance(result.get(key), str):
            raw = result[key].encode("utf-8")
            if len(raw) > 950:
                result[key] = _safe_output(raw[-950:])
                result["output_truncated"] = True
    for key in ("members", "issues"):
        if isinstance(result.get(key), list):
            while result[key] and len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > limit:
                result[key].pop()
                result[key + "_truncated"] = True
    if isinstance(result.get("extensions"), dict):
        while result["extensions"] and len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > limit:
            result["extensions"].popitem()
            result["extensions_truncated"] = True
    while len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > limit:
        key = max(("stdout", "stderr"), key=lambda field: len(result.get(field, "")))
        if not result.get(key):
            break
        result[key] = result[key][(len(result[key]) + 1) // 2:]
        result["output_truncated"] = True
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > limit:
        raise ValueError("Inspection result exceeds the response limit.")
    return result


def _typed_result(job, target):
    recipe = "recipe_id" in job
    steps = job["recipe_steps"] if recipe else [job]
    summaries = []
    has_project_commands = recipe and any(s["preset"] in PROJECT_PRESETS for s in steps)
    deadline = time.monotonic() + (300 if has_project_commands else 120)
    last = 0.0
    last_progress = {}
    index = 0
    preset = steps[0]["preset"]

    def checkpoint(completed, total, force=False):
        nonlocal last, last_progress
        now = time.monotonic()
        if now >= deadline:
            raise _Stopped("timed_out", "The Windows task exceeded its execution time limit.")
        if not force and now - last < 0.30:
            return
        cfg = core.load_config()
        if not cfg.get("task_enabled") or not cfg.get("workspace_enabled") or _policy(cfg) != job["policy"]:
            raise _Stopped("revoked", "Workspace authorization changed.")
        if recipe and not _current_recipe(job):
            raise _Stopped("revoked", "The local task recipe was changed or removed.")
        if _signal_exists(job["job_id"], "cancel"):
            raise _Stopped("cancelled", "Windows inspection cancelled.")
        last = now
        last_progress = {"done": completed, "total": total,
                         "unit": "command" if preset in PROJECT_PRESETS else
                         "entries" if preset == "directory_inventory" else "bytes"}
        if recipe:
            last_progress.update(step=index + 1, steps=len(steps), step_preset=preset)
        _write({**job, "updated": time.time(), "progress": last_progress})
        return cfg

    def journal(record):
        if recipe and record.get("phase") == "publishing":
            output = record["result"]
            record["result"] = {"recipe_id": job["recipe_id"],
                                "steps": summaries + [{"preset": preset, "state": "succeeded", "result": output}],
                                "destination_path": output["destination_path"]}
        job["publication"] = record
        _write({**job, "updated": time.time(), "progress": last_progress})

    try:
        ok = True
        terminal, exit_code = "succeeded", 0
        for index, step in enumerate(steps):
            preset = step["preset"]
            active_cfg = checkpoint(0, None, force=True)
            step_state = None
            try:
                if preset in task_files.PRESETS:
                    base = _base(active_cfg)
                    job["publication_base"] = str(base)
                    entry = {**step, "job_id": job["job_id"]}
                    result = task_files.execute(base, target, entry, checkpoint, journal)
                    ok = True
                elif preset in PROJECT_PRESETS:
                    if PROJECT_PRESETS[preset].get("approval") and not _signal_exists(job["job_id"], "approve"):
                        raise _Stopped("rejected", "A local approval is required before running the project command.")
                    step_state, result = _run({**job, "preset": preset}, target, recipe_deadline=deadline)
                    ok = step_state == "succeeded"
                    if ok:
                        last_progress.update(done=1, total=1)
                else:
                    ok, result = _read_action(step, target, checkpoint)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                if not recipe:
                    raise
                result = {"message": _safe_output(str(exc).encode("utf-8")[:1200])}
                ok = False
            result = _bound_result(result, 3_200 if recipe else 18_000)
            if step_state is None:
                step_state = "succeeded" if ok else "failed"
            if recipe:
                summaries.append({"preset": preset, "state": step_state, "result": result})
            if not ok:
                terminal = step_state
                exit_code = result.get("exit_code", 2)
                break
    except _Stopped as exc:
        out = {"message": exc.message, "progress": last_progress}
        if recipe:
            out["result"] = {"recipe_id": job["recipe_id"], "steps": summaries}
        return exc.state, out
    if recipe:
        result = {"recipe_id": job["recipe_id"], "steps": summaries,
                  **({"destination_path": job["destination_path"]} if ok and "destination_path" in job else {})}
    return terminal, {
        "exit_code": exit_code, "result": result, "progress": last_progress,
        "message": "Windows task completed." if ok else "The Windows step did not finish successfully; no later step ran."
    }


class Runner:
    """Only the singleton local worker may start jobs."""
    def __init__(self):
        self.recovered = False
        self.thread = None
        self.active = None
        self.last = 0.0

    def pump(self, cfg):
        now = time.time()
        if now - self.last < 0.5 or not QUEUE.is_dir():
            return
        self.last = now
        busy = self.thread is not None and self.thread.is_alive()
        policy = _policy(cfg) if cfg.get("workspace_enabled") and cfg.get("task_enabled") else ""
        queued = []
        cleanup_tried = False
        for item in [_load_job(p) for p in _job_files()]:
            job_id, state = item.get("job_id", ""), item.get("state", "")
            if not IDENTIFIER.fullmatch(job_id or ""):
                continue
            if state not in ACTIVE:
                if (not cleanup_tried and item.get("publication", {}).get("cleanup_pending")
                        and now >= item.get("cleanup_retry_at", 0)):
                    cleanup_tried = True
                    self._retry_cleanup(item, now)
                if now - item.get("updated", 0) > KEEP:
                    for action in ("approve", "deny", "cancel"):
                        _signal(job_id, action).unlink(missing_ok=True)
                    _path(job_id).unlink(missing_ok=True)
                continue
            if state == "running":
                if not self.recovered or not busy or job_id != self.active:
                    self._recover(item, policy)
                continue
            if item.get("policy") != policy:
                _finish(item, "revoked", message="The local project authorization changed.")
            elif "recipe_id" in item and not _current_recipe(item):
                _finish(item, "revoked", message="The local task recipe was changed or removed.")
            elif _signal_exists(job_id, "cancel"):
                _finish(item, "cancelled", message="Cancelled before execution.")
            elif state == "awaiting_approval":
                if _signal_exists(job_id, "deny"):
                    _finish(item, "rejected", message="Rejected in the Windows manager.")
                elif now >= item["created"] + APPROVAL_TTL:
                    _finish(item, "expired", message="Local approval expired.")
                elif _signal_exists(job_id, "approve"):
                    queued.append(_finish(item, "queued", message="Approved in the Windows manager."))
            elif state == "queued":
                queued.append(item)
        self.recovered = True
        if busy or not queued:
            return
        item = min(queued, key=lambda i: i["created"])
        try:
            if item["preset"] in TOOLBOX_PRESETS:
                target = None  # run only from the protected Windows system directory
                _base(cfg)
            elif "relative_path" in item:
                target = task_verification.target_file(_base(cfg), item["relative_path"], item["preset"])
            else:
                target = _scope(cfg, item.get("relative_dir", "."))
                current_id = _folder_id(target)
                if item.get("folder_id", current_id) != current_id:
                    raise ValueError("Project directory changed after submission.")
        except (ValueError, OSError, TypeError):
            _finish(item, "failed", message="The configured project or file is no longer available.")
            return
        item = _finish(item, "running", message="Running on Windows.")
        self.active = item["job_id"]
        self.thread = threading.Thread(target=self._complete, args=(item, target), daemon=True)
        self.thread.start()

    def _complete(self, item, target):
        try:
            from transfer_mailbox import guarded_inbox
            if item["preset"] in TOOLBOX_PRESETS:
                state, result = _run(item, None)
            elif item["preset"] in TYPED_PRESETS or "recipe_id" in item:
                with guarded_inbox(target.parent if "relative_path" in item else target):
                    if "relative_path" not in item and _folder_id(target) != item["folder_id"]:
                        raise ValueError("The directory changed since submission.")
                    state, result = _typed_result(item, target)
            else:
                with guarded_inbox(target):
                    current_id = _folder_id(target)
                    if item.get("folder_id", current_id) != current_id:
                        raise ValueError("Project directory changed after submission.")
                    state, result = _run(item, target)
        except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as exc:
            message = ("The fixed Windows diagnostic could not run." if item["preset"] in TOOLBOX_PRESETS
                       else _safe_output(str(exc).encode("utf-8")[:1200]))
            state, result = "failed", {"message": message}
        _finish(item, state, **result)

    @staticmethod
    def _recover(job, policy):
        try:
            result = (task_files.recover(workspace_root(job["publication_base"]), job)
                      if job.get("publication") else None)
        except (OSError, ValueError, KeyError, TypeError):
            _finish(job, "interrupted", message="The worker restarted; owned staging could not be recovered automatically.")
            return
        if result is not None:
            _finish(job, "succeeded", exit_code=0, result=result, message="Windows recovered the completed file action.")
        else:
            _finish(job, "interrupted" if job.get("policy") == policy else "revoked",
                    message="The Windows worker stopped before the task completed.")

    @staticmethod
    def _retry_cleanup(item, now):
        try:
            task_files.retry_cleanup(workspace_root(item["publication_base"]), item)
        except (OSError, ValueError, KeyError, TypeError):
            item["cleanup_retry_at"] = now + 60
        else:
            item["publication"].pop("cleanup_pending", None)
            item.pop("cleanup_retry_at", None)
        _write(item)


def _compile():
    excluded = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist", "appdata",
                "windowsworkspacemcp", "mcp-inbox", "dot-mcp-本机状态", "dot-mcp-工具包", "dot-mcp-收件箱"}
    reserved = re.compile(r"(?:^|[._-])(?:credentials?|secrets?|passwords?|private[._-]?key|id_rsa|id_ed25519)(?:$|[._-])", re.I)
    count, seen = 0, 0
    for folder, dirs, files in os.walk(Path.cwd(), followlinks=False):
        dirs[:] = [name for name in dirs if name.lower() not in excluded and not reserved.search(name)
                   and _regular(Path(folder) / name, True)]
        for name in files:
            seen += 1
            if seen > 10000:
                sys.exit("Source scan stopped after 10,000 entries.")
            candidate = Path(folder) / name
            if name.endswith(".py") and not reserved.search(name) and _regular(candidate):
                with candidate.open("rb") as source:
                    data = source.read(2_000_001)
                if len(data) > 2_000_000:
                    sys.exit("Python source exceeds the 2 MB per-file syntax check limit.")
                label = str(candidate.relative_to(Path.cwd()))
                try:
                    compile(data, label, "exec")
                except SyntaxError as exc:
                    sys.exit(f"SyntaxError: {label}:{exc.lineno or 1} · {exc.msg}")
                count += 1
    print(f"Python syntax OK: {count} files")


def _regular(path, directory=False):
    try:
        info = path.lstat()
        return (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1) and not (
            getattr(info, "st_file_attributes", 0) & 0x400) and not path.is_symlink()
    except OSError:
        return False


if __name__ == "__main__":
    if sys.argv[1:2] == ["--launch"] and sys.stdin.buffer.read(1) == b"1":
        sys.exit(subprocess.call(sys.argv[2:], shell=False, stdin=subprocess.DEVNULL))
    if sys.argv[1:2] == ["--compile"]:
        _compile()
