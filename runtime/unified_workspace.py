"""Local workspace profile store. Saved profiles do not grant concurrent access."""
from __future__ import annotations

import re
import secrets
from pathlib import Path

import core
from transfer_mailbox import guarded_inbox
from workspace import MODE_LABELS, resolve, workspace_root

MAX_PROFILES = 24
PROFILE_ID = re.compile(r"[a-f0-9]{24}\Z")


def _profiles(cfg):
    saved = cfg.get("workspace_profiles")
    if not isinstance(saved, list):
        return []
    seen_ids, seen_roots, profiles = set(), set(), []
    for item in saved[:MAX_PROFILES]:
        if not isinstance(item, dict):
            continue
        ident, root, mode = item.get("profile_id"), item.get("root"), item.get("mode")
        if (not isinstance(ident, str) or not PROFILE_ID.fullmatch(ident) or ident in seen_ids
                or not isinstance(root, str) or not root or Path(root) in seen_roots
                or not isinstance(mode, str) or mode not in MODE_LABELS):
            continue
        try:
            minutes, actions = core.validate_approval_settings(item.get("approval_minutes"),
                                                               item.get("automatic_operations"))
        except ValueError:
            continue
        seen_ids.add(ident)
        seen_roots.add(Path(root))
        profiles.append(dict(profile_id=ident, root=root, mode=mode,
                             approval_minutes=minutes, automatic_operations=actions if mode == "full" else []))
    return profiles


def _active(cfg, item):
    return (cfg.get("workspace_enabled") is True and cfg.get("workspace_unified") is True and
            cfg.get("active_workspace_profile") == item["profile_id"])


def list_profiles():
    cfg = core.load_config()
    return [{**row, "active": _active(cfg, row)} for row in _profiles(cfg)]


def _preferred(cfg, root, mode, minutes, actions):
    if not isinstance(mode, str) or mode not in MODE_LABELS:
        raise ValueError("请选择一种工作区审批模式。")
    profiles = _profiles(cfg)
    previous = next((item for item in profiles if Path(item["root"]) == root), None)
    same_active_root = cfg.get("workspace_unified") is True and Path(cfg.get("workspace_root") or ".") == root
    saved_minutes = previous["approval_minutes"] if previous else (
        cfg["approval_minutes"] if same_active_root else core.APPROVAL_MINUTES_DEFAULT)
    saved_actions = previous["automatic_operations"] if previous else (
        cfg["automatic_operations"] if same_active_root else [])
    minutes, actions = core.validate_approval_settings(saved_minutes if minutes is None else minutes,
                                                       saved_actions if actions is None else actions)
    if mode != "full":
        actions = []
    if previous is None and len(profiles) >= MAX_PROFILES:
        raise ValueError("已达到工作区配置数量上限；请先删除一个停用的配置。")
    profile = dict(profile_id=previous["profile_id"] if previous else secrets.token_hex(12), root=str(root),
                   mode=mode, approval_minutes=minutes, automatic_operations=actions)
    if previous is None:
        profiles.append(profile)
    else:
        profiles[profiles.index(previous)] = profile
    return profile, profiles


def save_profile(path, mode, *, approval_minutes=None, automatic_operations=None):
    """Remember local preferences without activating the scope or creating an inbox."""
    root = workspace_root(path)
    cfg = core.load_config()
    profile, profiles = _preferred(cfg, root, mode, approval_minutes, automatic_operations)
    if (_active(cfg, profile) or (cfg.get("workspace_enabled") is True and cfg.get("workspace_unified") is True
                                  and Path(cfg.get("workspace_root") or ".") == root)):
        raise ValueError("要修改当前授权，请使用保存并统一授权。")
    core.update_config(workspace_profiles=profiles)
    return {**profile, "active": False}


def grant(path, mode, *, approval_minutes=None, automatic_operations=None):
    root = workspace_root(path)
    if not core.uses_funnel(core.load_config()):
        raise ValueError("统一授权需要当前固定 HTTPS 本机中继。请先检查连接设置。")
    with guarded_inbox(root):
        current = workspace_root(str(root))
        cfg = core.load_config()
        if not core.uses_funnel(cfg):
            raise ValueError("统一授权需要当前固定 HTTPS 本机中继。请先检查连接设置。")
        profile, profiles = _preferred(cfg, current, mode, approval_minutes, automatic_operations)
        folder = current / core.INBOX_FOLDER
        folder.mkdir(exist_ok=True)
        resolve(current, core.INBOX_FOLDER, folder=True)
        revision = cfg["workspace_revision"]
        if (cfg.get("workspace_unified") is not True or not cfg.get("workspace_enabled") or not revision
                or current != Path(cfg["workspace_root"]) or cfg["approval_mode"] != mode
                or cfg["automatic_operations"] != profile["automatic_operations"]):
            revision = secrets.token_hex(12)
        # An expiry setting applies to new requests only; existing deadlines never move.
        core.update_config(workspace_root=str(current), workspace_enabled=True, workspace_unified=True,
                           approval_mode=mode, workspace_revision=revision,
                           approval_minutes=profile["approval_minutes"],
                           automatic_operations=profile["automatic_operations"],
                           active_workspace_profile=profile["profile_id"], workspace_profiles=profiles)
    return core.load_config()


def activate_profile(profile_id):
    profile = next((row for row in list_profiles() if row["profile_id"] == profile_id), None)
    if profile is None:
        raise ValueError("未找到已保存的工作区配置。")
    return grant(profile["root"], profile["mode"], approval_minutes=profile["approval_minutes"],
                 automatic_operations=profile["automatic_operations"])


def remove_profile(profile_id):
    cfg = core.load_config()
    profiles = _profiles(cfg)
    profile = next((row for row in profiles if row["profile_id"] == profile_id), None)
    if profile is None:
        raise ValueError("未找到已保存的工作区配置。")
    if _active(cfg, profile):
        raise ValueError("请先撤销当前授权，再删除这个配置。")
    profiles.remove(profile)
    core.update_config(workspace_profiles=profiles)


def revoke():
    core.update_config(workspace_enabled=False, active_workspace_profile="", workspace_revision=secrets.token_hex(12))
