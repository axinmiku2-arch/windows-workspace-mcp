"""Worker-side dispatch for transfer and fixed project actions."""
from __future__ import annotations

import sqlite3

import core
import file_bridge
import operator_messages
import transfer_mailbox as mailbox
import project_tasks
from workspace import PREVIEW_MAX_BYTES


def dispatch(gate, job):
    operation, data = job.get("operation"), job.get("payload", {})
    if not isinstance(operation, str) or not isinstance(data, dict):
        return {"error": "Invalid Windows worker job."}
    if operation not in {"workspace_export_status", "workspace_export_cancel", "workspace_export_ack"} and not operation.startswith(("connection_", "mailbox_", "project_", "message_")):
        return gate.handle(job)
    cfg = core.load_config()
    try:
        if operation == "connection_status":
            return {
                "online": True, "workspace_enabled": bool(cfg.get("workspace_enabled")),
                "unified_workspace": cfg.get("workspace_unified") is True,
                "approval_mode": cfg.get("approval_mode"),
                "documents_enabled": bool(cfg.get("documents_enabled") and cfg.get("workspace_enabled")),
                "receive_enabled": bool(cfg.get("receive_enabled") and cfg.get("workspace_enabled")),
                "automatic_inbox": bool(mailbox.auto_receive(cfg)),
                "project_tasks_enabled": bool(cfg.get("task_enabled") and cfg.get("workspace_enabled")),
                "transfer_max_bytes": file_bridge.transfer_max_bytes(cfg),
                "preview_max_bytes": PREVIEW_MAX_BYTES,
                "original_transfer": "Authorized regular file bytes; executable and shortcut files are not run or followed.",
                "folder_zip_tool": "start_workspace_archive" if core.uses_funnel(cfg) and cfg.get("documents_enabled") else None,
                "pending_workspace_approvals": sum(item["revision"] == cfg.get("workspace_revision")
                                                   for item in gate.queue.values()),
            }
        if operation == "workspace_export_status":
            return file_bridge.export_status(data.get("job_id"), cfg, renew=data.get("renew", False))
        if operation == "workspace_export_cancel":
            return file_bridge.cancel_export(data.get("job_id"), cfg)
        if operation == "workspace_export_ack":
            return file_bridge.complete_export(data.get("job_id"), cfg, data.get("sha256"))
        if operation == "mailbox_list":
            return mailbox.list_mailbox(cfg, data.get("limit", 12))
        if operation == "mailbox_outgoing":
            return mailbox.get_outgoing(data.get("transfer_id"), cfg, renew=data.get("renew", False))
        if operation == "mailbox_outgoing_cancel":
            return mailbox.cancel_outgoing(data.get("transfer_id"), cfg)
        if operation == "mailbox_ack":
            return mailbox.acknowledge_outgoing(data.get("transfer_id"), data.get("sha256"), cfg)
        if operation == "mailbox_upload_create":
            return mailbox.create_upload(data.get("filename"), data.get("size_bytes"), data.get("sha256"), cfg,
                                         request_key=data.get("request_key", ""))
        if operation == "mailbox_upload_status":
            return mailbox.upload_status(data.get("transfer_id"), cfg, renew=data.get("renew", False))
        if operation == "mailbox_upload_cancel":
            return mailbox.cancel_upload(data.get("transfer_id"), cfg)
        if operation == "project_list":
            return project_tasks.listing(cfg, data.get("limit", 16), remote=True)
        if operation == "project_start":
            return project_tasks.start(data.get("preset"), cfg, data.get("request_key", ""),
                                       data.get("relative_dir", "."), data.get("relative_path"), data.get("parameters"),
                                       submission=job.get("submission"))
        if operation == "project_status":
            return project_tasks.status(data.get("job_id"), cfg, remote=True, submission=job.get("submission"))
        if operation == "project_cancel":
            return project_tasks.cancel(data.get("job_id"), cfg, remote=True, submission=job.get("submission"))
        if operation == "message_list":
            return operator_messages.list_messages("dot", cfg, data.get("limit", 20), data.get("unread_only", False))
        if operation == "message_send":
            return operator_messages.send("incoming", data.get("text"), cfg, data.get("request_key", ""))
        if operation == "message_ack":
            return operator_messages.acknowledge("dot", data.get("message_id"), cfg)
    except (ValueError, OSError, TypeError, sqlite3.Error) as exc:
        return {"error": str(exc) if isinstance(exc, ValueError) else "The Windows action could not be completed."}
    return {"error": "This Windows action is not available."}
