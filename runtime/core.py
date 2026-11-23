"""Per-user configuration and fixed local Windows Workspace MCP lifecycle."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from xml.sax.saxutils import escape

from relay_config import validated_https_url, validated_oauth_callbacks

RUNTIME = Path(__file__).resolve().parent
STATE_ENV = "WINDOWS_WORKSPACE_MCP_STATE"
APP_STATE_NAME = "WindowsWorkspaceMCP"
STATE_OWNER = {"product": "windows-workspace-mcp", "format": 1}


def state_home():
    override = os.environ.get(STATE_ENV)
    if override:
        path = Path(override)
        if not path.is_absolute():
            raise ValueError(f"{STATE_ENV} must be an absolute dedicated state directory.")
        return path
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    if not base.is_absolute():
        raise ValueError("The per-user state base must be absolute.")
    return base / APP_STATE_NAME


STATE = state_home()
ROOT = STATE / "local-sample"
TARGET = ROOT / "workspace-sample.txt"
CONFIG = STATE / "config.json"
STATUS = STATE / "status.json"
STOP = STATE / "stop.json"
# Include the per-user state identity so previews cannot replace the prior product's tasks.
_TASK_SUFFIX = hashlib.sha256(os.path.normcase(str(STATE)).encode("utf-8")).hexdigest()[:12]
TASK = f"WindowsWorkspaceMCP-Worker-{_TASK_SUFFIX}"
RELAY_TASK = f"WindowsWorkspaceMCP-Relay-{_TASK_SUFFIX}"
# These compatibility names describe the local relay, not a required tunnel vendor.
FUNNEL = STATE / "relay"
FUNNEL_SETTINGS = FUNNEL / "endpoint.json"
KEY = FUNNEL / "worker_key"
FUNNEL_PUBLIC_PORT = 18773
FUNNEL_PRIVATE_PORT = 18774
APPROVAL_MINUTES_DEFAULT = 30
APPROVAL_MINUTES_MIN = 5
APPROVAL_MINUTES_MAX = 120
OPTIONAL_FULL_OPERATION_IDS = frozenset({"workspace_move", "workspace_trash", "workspace_restore"})
DEFAULT = {"origin": "", "plugin_url": "", "relay_binding": "", "poll_seconds": 2, "timeout_seconds": 8,
           "workspace_enabled": False, "workspace_root": "", "workspace_revision": "", "approval_mode": "ask",
           "approval_minutes": APPROVAL_MINUTES_DEFAULT, "automatic_operations": [],
           "workspace_profiles": [], "active_workspace_profile": "",
           "documents_enabled": False, "document_scope": "", "document_revision": "", "transfer_max_mb": 100,
           "receive_enabled": False, "receive_scope": "", "receive_revision": "",
           "task_enabled": False, "task_scope": "", "task_revision": "", "task_git_path": "",
           "workspace_unified": False}
INBOX_FOLDER = "MCP-Inbox"
HIDDEN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = build_opener(NoRedirect)
LOCAL_OPENER = build_opener(ProxyHandler({}), NoRedirect)


def read_json(path):
    try:
        with path.open(encoding="utf-8-sig") as file:
            result = json.load(file)
        return result if isinstance(result, dict) else {}
    except (OSError, ValueError):
        return {}


def _ordinary_path(path, directory):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    return (kind(info.st_mode) and not path.is_symlink() and
            not (getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT) and
            (directory or info.st_nlink == 1))


def _state_owned():
    marker = STATE / ".workspace-mcp-state.json"
    try:
        return (_ordinary_path(STATE, True) and _ordinary_path(marker, False) and
                marker.stat().st_size < 1024 and read_json(marker) == STATE_OWNER)
    except OSError:
        return False


def initialize_state():
    """Claim a new/empty app-owned state folder only on explicit startup or setup."""
    if _state_owned():
        return STATE
    if STATE == Path(STATE.anchor) or STATE == Path.home():
        raise ValueError("Choose a dedicated application state folder, not a drive or user root.")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not _ordinary_path(STATE, True) or any(STATE.iterdir()):
        raise ValueError("The state folder belongs to another installation or is not empty. Choose a new dedicated folder.")
    marker = STATE / ".workspace-mcp-state.json"
    try:
        with marker.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(STATE_OWNER) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        if not _state_owned():
            raise ValueError("Cannot verify the application state directory.") from None
    return STATE


def _saved_config():
    if not _state_owned():
        return {}
    try:
        return read_json(CONFIG) if _ordinary_path(CONFIG, False) else {}
    except OSError:
        return {}


def write_atomic(path, data, *, durable=False):
    temp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as f:
            temp = Path(f.name)
            f.write(data)
            if durable:
                f.flush()
                os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp is not None and temp.exists():
            temp.unlink()


def save_json(path, value, *, durable=False):
    write_atomic(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n", durable=durable)


def validate_approval_settings(minutes, operations):
    if type(minutes) is not int or not APPROVAL_MINUTES_MIN <= minutes <= APPROVAL_MINUTES_MAX:
        raise ValueError(f"普通审批有效期必须为 {APPROVAL_MINUTES_MIN}–{APPROVAL_MINUTES_MAX} 分钟。")
    if (not isinstance(operations, (list, tuple)) or any(not isinstance(op, str) or
            op not in OPTIONAL_FULL_OPERATION_IDS for op in operations)):
        raise ValueError("免确认项目仅可选工作区内可恢复的文件操作。")
    return minutes, sorted(set(operations))


def load_config():
    cfg = {**DEFAULT, **_saved_config()}
    try:
        cfg["approval_minutes"], cfg["automatic_operations"] = validate_approval_settings(
            cfg["approval_minutes"], cfg["automatic_operations"])
    except ValueError:
        cfg.update(approval_minutes=APPROVAL_MINUTES_DEFAULT, automatic_operations=[])
    cfg["workspace_enabled"] = bool(cfg.get("workspace_enabled") is True and cfg.get("workspace_root")
                                    and cfg.get("workspace_revision") and uses_funnel(cfg))
    if cfg.get("workspace_unified") is True:
        root = cfg["workspace_root"]
        revision = cfg["workspace_revision"]
        enabled = cfg["workspace_enabled"]
        inbox = str(Path(root) / INBOX_FOLDER) if isinstance(root, str) and root else ""
        cfg.update(documents_enabled=enabled, document_scope=root, document_revision=revision,
                   receive_enabled=enabled, receive_scope=inbox, receive_revision=revision,
                   task_enabled=enabled, task_scope=root, task_revision=revision)
    else:
        for name in ("documents_enabled", "receive_enabled", "task_enabled"):
            cfg[name] = cfg[name] is True and cfg["workspace_enabled"]
    return cfg


def update_config(**changes):
    """Save only the editable settings, not the effective derived scopes."""
    initialize_state()
    old = _saved_config()
    if "origin" in changes:
        changes["origin"] = canonical_origin(changes["origin"]) if changes["origin"] else ""
        if old.get("origin", "") != changes["origin"]:
            # A newly selected address must not inherit the previous address's workspace grant.
            changes.update(workspace_enabled=False, active_workspace_profile="", workspace_revision=secrets.token_hex(12))
    save_json(CONFIG, {**old, **changes}, durable=True)


def canonical_origin(value):
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("请输入有效的 HTTPS 地址。")
    url = urlsplit(value.strip())
    if (url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment
            or url.path not in ("", "/", "/mcp", "/mcp/") or not 1 <= (url.port or 443) <= 65535):
        raise ValueError("请输入 HTTPS 地址，例如 https://mcp.example.com/mcp。")
    host = url.hostname.lower()
    netloc = f"[{host}]" if ":" in host else host
    if url.port and url.port != 443:
        netloc += f":{url.port}"
    return validated_https_url("https://" + netloc)


def validated_config(origin, plugin, poll, timeout):
    origin = canonical_origin(origin) if origin.strip() else ""
    plugin = plugin.strip()
    if plugin:
        url = urlsplit(plugin)
        if (any(ord(c) < 32 or ord(c) == 127 for c in plugin) or url.scheme != "https" or not url.hostname
                or url.username or url.password or url.query or url.fragment):
            raise ValueError("连接帮助链接必须是无账号、密钥或参数的普通 HTTPS 地址。")
        canonical_origin(f"https://{url.netloc}")
    if not 1 <= int(poll) <= 8 or not 3 <= int(timeout) <= 20:
        raise ValueError("轮询间隔允许 1–8 秒，请求超时允许 3–20 秒。")
    return dict(origin=origin, plugin_url=plugin, poll_seconds=int(poll), timeout_seconds=int(timeout))


def uses_funnel(cfg=None):
    return bool(local_oauth_callbacks(cfg))


def local_oauth_callbacks(cfg=None):
    cfg = _saved_config() if cfg is None else cfg
    try:
        origin = cfg.get("origin")
        if (not origin or not _state_owned() or not _ordinary_path(FUNNEL, True) or
                not _ordinary_path(FUNNEL_SETTINGS, False) or canonical_origin(origin) != origin):
            return []
        marker = read_json(FUNNEL_SETTINGS)
        if marker.get("origin") != origin:
            return []
        callbacks = validated_oauth_callbacks(marker.get("oauth_callbacks", []))
        return callbacks if cfg.get("relay_binding") == _relay_binding(origin, callbacks) else []
    except (OSError, ValueError, TypeError):
        return []


def _relay_binding(origin, callbacks):
    return hashlib.sha256(json.dumps([origin, callbacks], ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()


def _relay_secret(path, pattern):
    if not _ordinary_path(FUNNEL, True) or not _ordinary_path(path, False) or path.stat().st_size >= 256:
        raise ValueError("Cannot read a valid local relay credential.")
    value = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(pattern, value):
        raise ValueError("The local relay credential has an invalid format.")
    return value


def configure_local_relay(origin, oauth_callbacks=()):
    """Explicit operator-only initialization; never contacts any host or activates files."""
    origin = canonical_origin(origin)
    callbacks = validated_oauth_callbacks(list(oauth_callbacks) if isinstance(oauth_callbacks, tuple) else oauth_callbacks)
    if not callbacks:
        raise ValueError("Enter at least one exact OAuth callback from your client before enabling the local relay.")
    initialize_state()
    FUNNEL.mkdir(mode=0o700, exist_ok=True)
    if not _ordinary_path(FUNNEL, True):
        raise ValueError("The local relay folder is not an ordinary app-owned directory.")
    if FUNNEL_SETTINGS.exists():
        bound = {**_saved_config(), "origin": origin}
        if local_oauth_callbacks(bound) != callbacks:
            raise ValueError("This instance already has a different or invalid address or OAuth callback list. Use a new dedicated state directory.")
        worker_key(bound)
        local_consent_code()
        return origin
    if any(FUNNEL.iterdir()):
        raise ValueError("The relay directory is not empty. Use a fresh dedicated state directory.")
    update_config(relay_binding=_relay_binding(origin, callbacks), workspace_enabled=False,
                  active_workspace_profile="", workspace_revision=secrets.token_hex(12))
    for filename, value in (("worker_key", secrets.token_hex(32)), ("probe_key", secrets.token_urlsafe(32))):
        path = FUNNEL / filename
        with path.open("x", encoding="ascii") as handle:
            handle.write(value + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            path.chmod(0o600)
    save_json(FUNNEL_SETTINGS, {"origin": origin, "oauth_callbacks": callbacks}, durable=True)
    return origin


def local_consent_code():
    if not _state_owned() or not FUNNEL_SETTINGS.is_file():
        raise ValueError("Prepare the local relay before showing its connection passcode.")
    return _relay_secret(FUNNEL / "probe_key", r"[A-Za-z0-9_-]{32,128}")


def relay_ready(cfg=None):
    try:
        worker_key(cfg)
        local_consent_code()
    except (OSError, ValueError):
        return False
    return True


def worker_channel(cfg):
    if not uses_funnel(cfg):
        raise ValueError("Prepare and select this instance’s local relay before starting the worker.")
    return f"http://127.0.0.1:{FUNNEL_PRIVATE_PORT}"


def worker_key_path(cfg=None):
    if not uses_funnel(cfg):
        raise ValueError("This connection is not bound to the local relay.")
    return FUNNEL / "worker_key"


def worker_key(cfg=None):
    return _relay_secret(worker_key_path(cfg), r"[0-9a-f]{64}")


def save_worker_key(key, cfg=None):
    if not re.fullmatch(r"[0-9a-f]{64}", key.strip()):
        raise ValueError("工作器密钥需要 64 位十六进制字符。")
    write_atomic(worker_key_path(cfg), key.strip(), durable=True)


def request_json(url, data, key=None, timeout=8):
    heads = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    local_worker = url == f"http://127.0.0.1:{FUNNEL_PRIVATE_PORT}/worker"
    if key is not None and (not local_worker or not re.fullmatch(r"[0-9a-f]{64}", key)):
        raise ValueError("The worker credential may only be sent to its private loopback endpoint.")
    if key:
        heads["Authorization"] = "Bearer " + key
    request = Request(url, data=json.dumps(data, ensure_ascii=False).encode(), headers=heads, method="POST")
    opener = LOCAL_OPENER if local_worker else OPENER
    with opener.open(request, timeout=timeout) as response:
        return json.loads(response.read(49152))


def endpoint_status(origin, timeout=5):
    try:
        request_json(canonical_origin(origin) + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, timeout=timeout)
        return False, "MCP 接受了匿名请求，请检查 OAuth。"
    except HTTPError as exc:
        if exc.code == 401 and "Bearer" in exc.headers.get("WWW-Authenticate", ""):
            return True, "HTTPS 入口已响应并拒绝匿名请求；OAuth 登录仍需实际验证。"
        return False, f"公网入口返回 HTTP {exc.code}。"
    except (OSError, ValueError) as exc:
        return False, f"无法验证公网入口：{type(exc).__name__}"


def current_status():
    data = read_json(STATUS) if _state_owned() else {}
    stamp = data.get("heartbeat", 0)
    fresh = type(stamp) in (int, float) and 0 <= time.time() - stamp < 30
    return {**data, "running": bool(fresh and data.get("phase") not in ("stopped", "failed"))}


def pythonw():
    path = Path(sys.executable)
    candidate = path.with_name("pythonw.exe")
    return candidate if candidate.is_file() else path


def start_worker():
    _require_windows()
    initialize_state()
    cfg = load_config()
    if not relay_ready(cfg):
        raise ValueError("请先设置、保存本机中继公网 HTTPS 地址，再启动工作器。")
    ensure_relay()
    if current_status().get("running"):
        return
    subprocess.Popen([str(pythonw()), str(RUNTIME / "worker.py")], cwd=str(RUNTIME),
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=HIDDEN)


def stop_worker():
    data = current_status()
    if data.get("running") and data.get("instance"):
        save_json(STOP, {"instance": data["instance"]}, durable=True)


def restart_worker():
    stop_worker()
    deadline = time.monotonic() + 22
    while current_status().get("running") and time.monotonic() < deadline:
        time.sleep(0.4)
    if current_status().get("running"):
        raise ValueError("工作器尚未停止，请稍后重试。")
    start_worker()


def _require_windows():
    if os.name != "nt":
        raise ValueError("此生命周期操作仅支持 Windows。")


def _system_program(name):
    _require_windows()
    if name not in {"schtasks.exe", "whoami.exe"}:
        raise ValueError("Unsupported Windows lifecycle executable.")
    import ctypes
    directory = ctypes.create_unicode_buffer(32768)
    count = ctypes.windll.kernel32.GetSystemDirectoryW(directory, len(directory))
    if not 0 < count < len(directory):
        raise OSError("Cannot locate the Windows system directory.")
    return str(Path(directory.value) / name)


def _lifecycle_command(args):
    return subprocess.run([_system_program(args[0]), *args[1:]], shell=False,
                          creationflags=HIDDEN, capture_output=True, timeout=20)


def task_exists(name):
    if name not in {TASK, RELAY_TASK}:
        raise ValueError("Unknown application scheduled task.")
    return os.name == "nt" and _lifecycle_command(["schtasks.exe", "/Query", "/TN", name]).returncode == 0


def autostart_enabled():
    return not os.environ.get(STATE_ENV) and _state_owned() and task_exists(TASK) and task_exists(RELAY_TASK)


def relay_pythonw():
    return pythonw()


def ensure_relay():
    _require_windows()
    if not relay_ready():
        raise ValueError("请先配置本机中继并保存 HTTPS 地址。")
    if not relay_pythonw().is_file():
        raise ValueError("本机 HTTPS 中继的运行环境未安装。")
    if task_exists(RELAY_TASK):
        # An already running single-instance task remains running.
        _lifecycle_command(["schtasks.exe", "/Run", "/TN", RELAY_TASK])
    else:
        subprocess.Popen([str(relay_pythonw()), str(RUNTIME / "relay.py")], cwd=str(RUNTIME),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=HIDDEN)


def set_autostart(enabled):
    _require_windows()
    if os.environ.get(STATE_ENV):
        raise ValueError("独立开发状态只能手动运行；不创建登录启动任务。")
    initialize_state()
    if enabled:
        if not relay_ready():
            raise ValueError("请先配置本机中继再启用登录时启动。")
        set_task(RELAY_TASK, relay_pythonw(), RUNTIME / "relay.py", True, "Windows Workspace MCP local relay")
    set_task(TASK, pythonw(), RUNTIME / "worker.py", enabled, "Windows Workspace MCP worker")
    if not enabled:
        set_task(RELAY_TASK, relay_pythonw(), RUNTIME / "relay.py", False, "Windows Workspace MCP local relay")


def set_task(name, executable, entry, enabled, description):
    expected = {TASK: (pythonw(), RUNTIME / "worker.py"), RELAY_TASK: (relay_pythonw(), RUNTIME / "relay.py")}
    if name not in expected or (Path(executable), Path(entry)) != expected[name]:
        raise ValueError("Only fixed application process entrypoints can be scheduled.")
    if not enabled and not task_exists(name):
        return
    if not enabled:
        result = _lifecycle_command(["schtasks.exe", "/Delete", "/TN", name, "/F"])
    else:
        who = _lifecycle_command(["whoami.exe", "/user", "/fo", "csv", "/nh"])
        match = re.search(rb"S-1-(?:[0-9]+-)+[0-9]+", who.stdout)
        if who.returncode or not match:
            raise RuntimeError("未能读取当前 Windows 用户的 SID。")
        sid = match.group().decode("ascii")
        cmd, workdir = escape(str(executable)), escape(str(RUNTIME))
        args = escape('"' + str(entry) + '"')
        xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>{escape(description)}</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="DotUser"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>4</Count></RestartOnFailure></Settings>
  <Actions Context="DotUser"><Exec><Command>{cmd}</Command><Arguments>{args}</Arguments><WorkingDirectory>{workdir}</WorkingDirectory></Exec></Actions>
</Task>'''
        with tempfile.TemporaryDirectory(prefix="workspace-mcp-task-") as folder:
            path = Path(folder) / "task.xml"
            path.write_text(xml, encoding="utf-16")
            result = _lifecycle_command(["schtasks.exe", "/Create", "/TN", name, "/XML", str(path), "/F"])
    if result.returncode:
        reason = (result.stderr or result.stdout).decode("mbcs", errors="replace").strip()
        raise RuntimeError(f"任务计划程序：{reason or result.returncode}")


def file_digest():
    if not _state_owned() or not TARGET.is_file():
        return "测试文件不存在"
    return hashlib.sha256(TARGET.read_bytes()).hexdigest()
