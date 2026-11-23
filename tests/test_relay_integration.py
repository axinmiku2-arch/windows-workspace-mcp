"""Isolated loopback OAuth/MCP/worker acceptance; launch with the relay Python."""
from __future__ import annotations

import base64
from contextlib import ExitStack
import hashlib
from http.client import HTTPConnection
from io import BytesIO
import json
import os
from pathlib import Path
import runpy
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit
import zipfile

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE / "runtime"))
CALLBACK = "https://chatgpt.com/connector_platform_oauth_redirect"
SCOPE = "mcp:workspace"
CASE_SIZE = 100_000_000


def endpoint_and_ports():
    with socket.create_server(("127.0.0.1", 0)) as first, socket.create_server(("127.0.0.1", 0)) as second:
        public, private = first.getsockname()[1], second.getsockname()[1]
    return f"https://dot-relay-integration.test:{public}", public, private


def local_path(url):
    value = urlsplit(url)
    return value.path + ("?" + value.query if value.query else "")


def zip_bytes():
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", "Synthetic Dot relay integration receipt fixture")
    return stream.getvalue()


def write_large(path):
    name = "acceptance.txt"
    block = b"dot-relay-fixture\r\n" * 58_254
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        with archive.open(name, "w") as member:
            remaining = CASE_SIZE - 98 - 2 * len(name)
            while remaining:
                chunk = block[:remaining]
                member.write(chunk)
                remaining -= len(chunk)
    if path.stat().st_size != CASE_SIZE:
        raise RuntimeError("Unexpected ZIP fixture size")
    with path.open("rb") as payload:
        return hashlib.file_digest(payload, "sha256").hexdigest()


class Wire:
    def __init__(self, port, host):
        self.port = port
        self.host = host
        self.token = None
        self.protocol = None
        self.rpc_id = 0

    def request(self, method, path, body=None, headers=None):
        parsed = urlsplit(path)
        if parsed.hostname is not None or not path.startswith("/"):
            raise ValueError("The isolated client only accepts loopback-relative routes")
        connection = HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            connection.request(method, path, body=body, headers={"Host": self.host, **(headers or {})})
            response = connection.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
        finally:
            connection.close()

    def rpc(self, method, params=None, *, notify=False):
        self.rpc_id += 1
        message = {"jsonrpc": "2.0", "method": method}
        if not notify:
            message["id"] = self.rpc_id
        if params is not None:
            message["params"] = params
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.protocol:
            headers["MCP-Protocol-Version"] = self.protocol
        status, _, raw = self.request("POST", "/mcp", json.dumps(message).encode(), headers)
        if status != (202 if notify else 200):
            raise AssertionError(f"MCP {method} returned HTTP {status}: {raw[:500]!r}")
        if notify:
            return None
        reply = json.loads(raw)
        if "error" in reply:
            raise AssertionError(f"MCP {method} failed: {reply['error']!r}")
        return reply["result"]

    def tool(self, name, **arguments):
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise AssertionError(f"MCP tool {name} failed: {result.get('content')!r}")
        if isinstance(result.get("structuredContent"), dict):
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])


class RelayAcceptance(unittest.TestCase):
    def _launch(self, stack, role, fixture, env):
        stream = stack.enter_context((fixture / (role + ".log")).open("wb"))
        process = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), "--" + role],
                                   cwd=PACKAGE, env=env, stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.STDOUT, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

        def finish():
            if process.poll() is None:
                if role == "worker":
                    import core
                    identity = core.read_json(core.STATUS).get("instance")
                    if identity:
                        core.save_json(core.STOP, {"instance": identity})
                else:
                    (fixture / "relay.stop").touch()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        stack.callback(finish)
        return process

    def _wait_for(self, fn, wanted, *, seconds=12):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                val = fn()
                if wanted(val):
                    return val
            except (ConnectionError, OSError):
                pass
            time.sleep(.15)
        self.fail("Timed out waiting for the isolated worker to reach the expected state")

    def _authorize(self, wire, origin, consent):
        discovery = "/.well-known/oauth-protected-resource/mcp"
        status, _, raw = wire.request("GET", discovery)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["resource"], origin + "/mcp")
        unauth, _, _ = wire.request("POST", "/mcp", b"{}", {"Content-Type": "application/json",
                                                             "Accept": "application/json, text/event-stream"})
        self.assertEqual(unauth, 401)
        status, _, raw = wire.request("POST", "/register", json.dumps({
            "client_name": "Isolated Windows relay acceptance",
            "redirect_uris": [CALLBACK],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "token_endpoint_auth_method": "none",
            "scope": SCOPE,
        }).encode(), {"Content-Type": "application/json"})
        self.assertEqual(status, 201)
        client = json.loads(raw)["client_id"]
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        state = secrets.token_urlsafe(20)
        params = {"client_id": client, "redirect_uri": CALLBACK, "response_type": "code", "state": state,
                  "code_challenge_method": "S256", "code_challenge": challenge,
                  "scope": SCOPE, "resource": origin + "/mcp"}
        status, headers, _ = wire.request("GET", "/authorize?" + urlencode(params))
        self.assertIn(status, {302, 307})
        self.assertEqual(urlsplit(headers["location"]).hostname, urlsplit(origin).hostname)
        ticket = parse_qs(urlsplit(headers["location"]).query)["t"][0]
        form = {"Content-Type": "application/x-www-form-urlencoded"}
        status, headers, _ = wire.request("POST", "/probe-consent", urlencode({"ticket": ticket, "key": consent}), form)
        self.assertEqual(status, 303)
        location = urlsplit(headers["location"])
        self.assertEqual((location.scheme, location.hostname, location.path),
                         ("https", "chatgpt.com", urlsplit(CALLBACK).path))
        query = parse_qs(location.query)
        self.assertEqual(query["state"], [state])
        status, _, raw = wire.request("POST", "/token", urlencode({
            "grant_type": "authorization_code", "client_id": client, "redirect_uri": CALLBACK,
            "code": query["code"][0], "code_verifier": verifier, "resource": origin + "/mcp",
        }), form)
        self.assertEqual(status, 200)
        wire.token = json.loads(raw)["access_token"]
        result = wire.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                          "clientInfo": {"name": "local-acceptance", "version": "1"}})
        wire.protocol = result["protocolVersion"]
        wire.rpc("notifications/initialized", notify=True)
        print("OAuth PKCE and authenticated MCP initialization passed")

    def _file_tools(self, wire):
        names = {item["name"] for item in wire.rpc("tools/list")["tools"]}
        needed = {"list_workspace", "read_workspace_file", "read_workspace_lines", "patch_workspace_file",
                  "start_workspace_export", "get_workspace_export", "confirm_workspace_export",
                  "create_windows_upload", "get_windows_upload", "list_windows_mailbox"}
        self.assertLessEqual(needed, names)
        self.assertNotIn("run_command", names)
        self.assertTrue(wire.tool("get_windows_connection")["online"])
        top = wire.tool("list_workspace")
        self.assertEqual({item["name"] for item in top["folders"]}, {"docs", "inbox"})
        doc = wire.tool("list_workspace", relative_dir="docs")
        by_name = {item["name"]: item for item in doc["files"]}
        self.assertEqual(by_name["large.zip"]["extension"], ".zip")
        self.assertEqual(by_name["large.zip"]["relative_path"], "docs/large.zip")
        self.assertIn("start_workspace_export", by_name["large.zip"]["content_tools"])
        before = wire.tool("read_workspace_file", relative_path="docs/legacy.txt")
        self.assertEqual(before["content"], "one\ntwo\nthree\n")
        paged = wire.tool("read_workspace_lines", relative_path="docs/legacy.txt", start_line=2, line_count=1)
        self.assertEqual(paged["lines"][0]["text"], "two")
        self.assertEqual(paged["next_start_line"], 3)
        patched = wire.tool("patch_workspace_file", relative_path="docs/legacy.txt", expected_sha256=before["sha256"],
                            replacements=[{"find": "two", "replace": "replacement"}])
        self.assertTrue(patched["updated"])
        current = wire.tool("read_workspace_file", relative_path="docs/legacy.txt")
        self.assertEqual(current["content"], "one\nreplacement\nthree\n")
        self.assertEqual(current["sha256"], patched["sha256"])
        small = wire.tool("prepare_workspace_file", relative_path="docs/legacy.txt")
        status, _, data = wire.request("GET", local_path(small["download_url"]))
        self.assertEqual(status, 200)
        self.assertEqual(hashlib.sha256(data).hexdigest(), current["sha256"])
        print(f"Discovered {len(names)} MCP tools; legacy list/read/export and new line read/patch passed")

    def _file_range(self, wire, href, first, last, digest):
        etag = '"' + digest + '"'
        status, headers, body = wire.request("GET", local_path(href),
            headers={"Range": f"bytes={first}-{last}", "If-Range": etag})
        self.assertEqual(status, 206)
        self.assertEqual(headers["content-range"], f"bytes {first}-{last}/{CASE_SIZE}")
        self.assertEqual(headers["etag"], etag)
        self.assertEqual(len(body), last - first + 1)
        return body

    def _large(self, wire, expected):
        import core
        import file_bridge

        queued = wire.tool("start_workspace_export", relative_path="docs/large.zip")
        self.assertEqual(queued["state"], "queued")
        job_id = queued["job_id"]
        ready = self._wait_for(lambda: wire.tool("get_workspace_export", job_id=job_id),
                               lambda response: response.get("state") == "ready")
        self.assertEqual(ready["bytes"], CASE_SIZE)
        self.assertEqual(ready["sha256"], expected)
        first_href = ready["download_url"]
        got = hashlib.sha256(self._file_range(wire, first_href, 0, 9_999_999, expected))
        # Expire only the isolated lease, leaving the immutable snapshot intact.
        meta, _, _ = file_bridge._job_paths(job_id)
        token = urlsplit(first_href).path.rsplit("/", 1)[1]
        manifest, _ = file_bridge.files(token)
        with file_bridge._state_lock():
            core.save_json(meta, dict(core.read_json(meta), link_expires_at=time.time() - 1))
            core.save_json(manifest, dict(core.read_json(manifest), expires=time.time() - 1))
        self.assertEqual(wire.request("HEAD", local_path(first_href))[0], 404)
        renewed = wire.tool("get_workspace_export", job_id=job_id, renew=True)
        self.assertNotEqual(renewed["download_url"], first_href)
        self.assertEqual(renewed["sha256"], expected)
        for start in range(10_000_000, CASE_SIZE, 10_000_000):
            got.update(self._file_range(wire, renewed["download_url"], start, start + 9_999_999, expected))
        self.assertEqual(got.hexdigest(), expected)
        acknowledged = wire.tool("confirm_workspace_export", job_id=job_id, sha256=got.hexdigest())
        self.assertEqual(acknowledged["state"], "delivered")
        self.assertEqual(wire.request("HEAD", local_path(renewed["download_url"]))[0], 404)
        print("100,000,000-byte ZIP: HTTP ranges, lease renewal, final SHA-256 and delivery acknowledgement passed")

    def _inbox(self, wire, inbox, cfg):
        from transfer_mailbox import approve_upload
        raw = zip_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()

        def upload(name, request_key):
            offered = wire.tool("create_windows_upload", filename=name, size_bytes=len(raw), sha256=sha256,
                                request_key=request_key)
            self.assertEqual(offered["state"], "awaiting_upload")
            status, _, body = wire.request("PUT", local_path(offered["upload_url"]), raw,
                                            {"Content-Type": "application/octet-stream"})
            self.assertEqual(status, 201, body[:300])
            transfer_id = offered["transfer_id"]
            self.assertEqual(json.loads(body)["state"], "awaiting_approval")
            self.assertEqual(wire.tool("get_windows_upload", transfer_id=transfer_id)["state"], "awaiting_approval")
            self.assertFalse((inbox / name).exists())
            return transfer_id

        transfer_id = upload("delivery.zip", "acceptance-main")
        # Local manager approval endpoint is the production function, not a remote MCP tool.
        self.assertEqual(approve_upload(transfer_id, cfg)["state"], "delivered")
        receipt = wire.tool("get_windows_upload", transfer_id=transfer_id)
        self.assertEqual(receipt["state"], "delivered")
        self.assertEqual(receipt["sha256"], sha256)
        self.assertEqual((inbox / "delivery.zip").read_bytes(), raw)

        collision = upload("collision.zip", "acceptance-collision")
        (inbox / "collision.zip").write_bytes(b"existing local content")
        with self.assertRaisesRegex(ValueError, "did not overwrite"):
            approve_upload(collision, cfg)
        self.assertEqual((inbox / "collision.zip").read_bytes(), b"existing local content")
        self.assertEqual(wire.tool("cancel_windows_upload", transfer_id=collision)["state"], "cancelled")
        print("Raw HTTP PUT, staged approval, MCP receipt, and no-overwrite collision passed")

    def _outgoing(self, wire, source, cfg):
        from transfer_mailbox import queue_outgoing

        outgoing = queue_outgoing(source, cfg)
        transfer_id = outgoing["transfer_id"]
        listing = wire.tool("list_windows_mailbox")
        listed = next(item for item in listing["outgoing"] if item["transfer_id"] == transfer_id)
        self.assertNotIn("download_url", listed)
        ready = self._wait_for(lambda: wire.tool("get_windows_outgoing", transfer_id=transfer_id),
                               lambda result: result.get("state") == "ready")
        status, _, received = wire.request("GET", local_path(ready["download_url"]))
        self.assertEqual(status, 200)
        sha256 = hashlib.sha256(received).hexdigest()
        self.assertEqual(sha256, ready["sha256"])
        self.assertEqual(received, source.read_bytes())
        receipt = wire.tool("acknowledge_windows_outgoing", transfer_id=transfer_id, sha256=sha256)
        self.assertEqual(receipt["state"], "received")
        self.assertEqual(wire.request("HEAD", local_path(ready["download_url"]))[0], 404)
        print("Windows manager selection, mailbox discovery, HTTPS pull, and outgoing receipt passed")

    def _messages_and_project(self, wire, cfg):
        import operator_messages
        import project_tasks

        note = operator_messages.send("outgoing", "Windows to Dot", cfg)
        self.assertEqual(wire.tool("list_windows_messages")["messages"][0]["text"], "Windows to Dot")
        self.assertEqual(wire.tool("acknowledge_windows_message", message_id=note["message_id"])["status"], "read")
        back = wire.tool("send_windows_message", text="Dot to Windows", request_key="test_note")
        self.assertEqual(operator_messages.list_messages("windows", cfg)["unread_count"], 1)
        self.assertEqual(operator_messages.acknowledge("windows", back["message_id"], cfg)["status"], "read")
        self.assertTrue(wire.tool("list_windows_project_jobs")["enabled"])
        job = wire.tool("request_windows_project_job", preset="python_build_check", request_key="test_build")
        self.assertEqual(job["state"], "awaiting_approval")
        project_tasks.decide(job["job_id"], cfg, True)
        done = self._wait_for(lambda: wire.tool("get_windows_project_job", job_id=job["job_id"]),
                              lambda result: result["state"] in {"succeeded", "failed"})
        self.assertEqual(done["state"], "succeeded")
        self.assertEqual(done["exit_code"], 0)
        self.assertIn("Python syntax OK: 1 files", done["stdout"])
        print("Bidirectional text and read receipts; MCP project request with local approval and Windows output passed")

    def _unified(self, wire, root):
        import core
        import unified_workspace
        import transfer_mailbox
        cfg = unified_workspace.grant(str(root), "full")
        self.assertEqual(cfg["document_scope"], str(root))
        self.assertEqual(cfg["workspace_revision"], cfg["document_revision"])
        self.assertTrue(wire.tool("get_windows_connection")["automatic_inbox"])
        (root / "root-visible.txt").write_bytes(b"unified scope")
        self.assertIn("prepare_workspace_file", next(f for f in wire.tool("list_workspace")["files"]
                                                      if f["name"] == "root-visible.txt")["content_tools"])
        self._verification_jobs(wire, root)
        self._file_actions(wire, root)
        self._recipe_jobs(wire, root)
        self._project_recipe_jobs(wire, root)
        self._archive_and_binary(wire, root)
        raw = zip_bytes()
        offer = wire.tool("create_windows_upload", filename="unattended.zip", size_bytes=len(raw),
                          sha256=hashlib.sha256(raw).hexdigest())
        status, _, _ = wire.request("PUT", local_path(offer["upload_url"]), raw,
                                    {"Content-Length": str(len(raw))})
        self.assertEqual(status, 201)
        self._wait_for(lambda: wire.tool("get_windows_upload", transfer_id=offer["transfer_id"]),
                       lambda record: record["state"] == "delivered")
        self.assertEqual((Path(cfg["receive_scope"]) / "unattended.zip").read_bytes(), raw)
        task = wire.tool("request_windows_project_job", preset="python_build_check", relative_dir="docs")
        self.assertEqual(task["state"], "queued")
        result = self._wait_for(lambda: wire.tool("get_windows_project_job", job_id=task["job_id"]),
                                lambda job: job["state"] in {"succeeded", "failed"})
        self.assertEqual(result["state"], "succeeded")
        script = wire.tool("request_windows_project_job", preset="python_unittest", relative_dir="docs")
        self.assertEqual(script["state"], "awaiting_approval")
        with self.assertRaises(AssertionError):
            wire.tool("request_windows_project_job", preset="python_build_check", relative_dir="../")
        unified_workspace.revoke()
        self.assertFalse(wire.tool("get_windows_connection")["workspace_enabled"])
        self.assertFalse(transfer_mailbox.auto_receive(core.load_config()))
        print("Unified grant: root-area document tools, automatic ZIP receipt, scoped Python check and combined revoke passed")

    def _verification_jobs(self, wire, root):
        folder = root / "verification"
        folder.mkdir()
        data = b"unexecuted package bytes"
        (folder / "app.exe").write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        (folder / "SHA256.txt").write_text(digest + "  app.exe\n", encoding="utf-8")
        (folder / "payload.zip").write_bytes(zip_bytes())
        (folder / "broken.zip").write_bytes(b"not a zip archive")
        catalog = {item["id"]: item for item in wire.tool("list_windows_project_jobs")["presets"]}
        self.assertEqual(catalog["file_sha256"]["path_argument"], "relative_path")
        self.assertTrue(catalog["verify_sha256_manifest"]["automatic"])
        self.assertFalse(catalog["npm_build"]["automatic"])
        info = wire.rpc("tools/call", {"name": "server_info", "arguments": {}})
        marker = info["content"][0]["text"]
        self.assertIn(" connection_id=", marker)
        connection_id = marker.split(" connection_id=", 1)[1].strip()
        self.assertRegex(connection_id, r"^[0-9a-f]{24}$")

        def run(preset, **args):
            started = wire.tool("request_windows_project_job", preset=preset, **args)
            self.assertEqual(started["state"], "queued")
            self.assertEqual(started["submission"], {"transport": "https_mcp", "connection_id": connection_id})
            return self._wait_for(lambda: wire.tool("get_windows_project_job", job_id=started["job_id"]),
                                  lambda item: item["state"] not in {"queued", "running"})

        original = run("file_sha256", relative_path="verification/app.exe", parameters={"expected_sha256": digest})
        self.assertEqual(original["result"], {"sha256": digest, "size_bytes": len(data), "matches": True})
        self.assertEqual(original["submission"]["connection_id"], connection_id)
        self.assertEqual(original["progress"]["done"], len(data))
        manifest = run("verify_sha256_manifest", relative_dir="verification/SHA256.txt")
        self.assertTrue(manifest["result"]["valid"])
        self.assertEqual(manifest["result"]["matched"], 1)
        (folder / "app.exe").write_bytes(b"changed fixture")
        changed = run("verify_sha256_manifest", relative_path="verification/SHA256.txt")
        self.assertEqual((changed["state"], changed["result"]["issues"][0]["status"]), ("failed", "digest_mismatch"))
        tested = run("zip_inspect", relative_path="verification/payload.zip")
        self.assertTrue(tested["result"]["crc_verified"])
        self.assertEqual(tested["result"]["verified_files"], 1)
        broken = run("zip_inspect", relative_dir="verification/broken.zip")
        self.assertEqual((broken["state"], broken["result"]["valid_structure"]), ("failed", False))
        counted = run("directory_inventory", relative_dir="verification", parameters={"max_depth": 0})
        self.assertEqual(counted["result"]["extensions"][".zip"], 2)
        with self.assertRaises(AssertionError):
            wire.tool("request_windows_project_job", preset="file_sha256", relative_path="../outside.txt")
        with self.assertRaises(AssertionError):
            wire.tool("request_windows_project_job", preset="zip_inspect", relative_path="verification/payload.zip",
                      parameters={"verify_crc": "true"})
        print("Typed task catalog, Windows SHA-256 and manifests, ZIP CRC, directory inventory and scope validation passed")

    def _file_actions(self, wire, root):
        source = root / "actions"
        (source / "folder" / "empty").mkdir(parents=True)
        (source / "input.bin").write_bytes(b"abc\0test")
        (source / "folder" / "note.txt").write_bytes(b"directory copy fixture")
        (source / "payload.zip").write_bytes(zip_bytes())
        catalog = {r["id"]: r for r in wire.tool("list_windows_project_jobs")["presets"]}
        self.assertTrue(catalog["zip_extract"]["writes_workspace"])
        self.assertTrue(catalog["zip_extract"]["automatic"])

        def run(preset, **args):
            offer = wire.tool("request_windows_project_job", preset=preset, **args)
            self.assertEqual(offer["state"], "queued")
            return self._wait_for(lambda: wire.tool("get_windows_project_job", job_id=offer["job_id"]),
                                  lambda item: item["state"] not in {"queued", "running"})

        original = {"preset": "copy_file", "relative_dir": "actions/input.bin", "request_key": "copy_once"}
        copied = run(**original)
        self.assertEqual(copied["state"], "succeeded", copied)
        self.assertEqual(copied["result"]["destination_path"], "actions/input-copy.bin")
        self.assertEqual((source / "input-copy.bin").read_bytes(), (source / "input.bin").read_bytes())
        repeated = wire.tool("request_windows_project_job", **original)
        self.assertEqual(repeated["job_id"], copied["job_id"])
        with self.assertRaises(AssertionError):
            wire.tool("request_windows_project_job", preset="copy_file", relative_path="actions/input.bin")
        folder = run("copy_directory", relative_dir="actions/folder",
                     parameters={"destination_path": "actions/verified-copy"})
        self.assertEqual(folder["state"], "succeeded", folder)
        self.assertTrue((source / "verified-copy" / "empty").is_dir())
        expanded = run("zip_extract", relative_dir="actions/payload.zip")
        self.assertEqual(expanded["state"], "succeeded", expanded)
        self.assertTrue(expanded["result"]["crc_verified"])
        self.assertTrue((source / "payload-extracted" / "README.txt").is_file())
        self.assertFalse(list(source.glob(".dot-action-*")))
        print("Typed copy/file/directory/extract via MCP, no overwrite, request-key retry and temp cleanup passed")

    def _recipe_jobs(self, wire, root):
        import task_recipes
        task_recipes.register(task_recipes.TEMPLATES["校验 ZIP 后解包"])
        catalog = {r["id"]: r for r in wire.tool("list_windows_project_jobs")["presets"]}
        self.assertEqual(catalog["recipe:inspect-zip"]["kind"], "local_recipe")
        self.assertEqual(catalog["recipe:verify-unpack"]["steps"], ["zip_inspect", "zip_extract"])
        self.assertTrue(catalog["recipe:verify-unpack"]["automatic"])

        def run(preset, source, **params):
            created = wire.tool("request_windows_project_job", preset=preset, relative_dir=source, **params)
            self.assertEqual(created["state"], "queued")
            self.assertEqual(created["step_count"], 2)
            return self._wait_for(lambda: wire.tool("get_windows_project_job", job_id=created["job_id"]),
                                  lambda item: item["state"] not in {"queued", "running"})

        checked = run("recipe:inspect-zip", "actions/payload.zip")
        self.assertEqual(checked["state"], "succeeded")
        steps = checked["result"]["steps"]
        self.assertIn("sha256", steps[0]["result"])
        self.assertEqual(steps[1]["result"]["crc_verified"], True)
        success = run("recipe:verify-unpack", "actions/payload.zip",
                      parameters={"destination_path": "actions/recipe-out"})
        self.assertEqual(success["state"], "succeeded", success)
        self.assertEqual(success["result"]["destination_path"], "actions/recipe-out")
        self.assertTrue((root / "actions" / "recipe-out" / "README.txt").exists())
        failed = run("recipe:verify-unpack", "verification/broken.zip")
        self.assertEqual(failed["state"], "failed")
        self.assertEqual([step["preset"] for step in failed["result"]["steps"]], ["zip_inspect"])
        self.assertFalse((root / "verification" / "broken-extracted").exists())
        task_recipes.remove("verify-unpack")
        self.assertNotIn("recipe:verify-unpack", {r["id"] for r in wire.tool("list_windows_project_jobs")["presets"]})
        print("Local recipe discovery and runtime, step-level results and write suppression after failed validation passed")

    def _project_recipe_jobs(self, wire, root):
        import core
        import project_tasks
        import task_recipes
        task_recipes.register(task_recipes.TEMPLATES["Python 语法检查后测试"])
        task_recipes.register(task_recipes.TEMPLATES["npm 测试后构建"])
        visible = {entry["id"]: entry for entry in wire.tool("list_windows_project_jobs")["presets"]}
        self.assertFalse(visible["recipe:npm-test-build"]["automatic"])
        self.assertTrue(visible["recipe:npm-test-build"]["runs_project_code"])

        def request(preset, project):
            request = wire.tool("request_windows_project_job", preset=preset,
                                relative_dir=project.relative_to(root).as_posix())
            self.assertEqual(request["state"], "awaiting_approval")
            self.assertTrue(request["runs_project_code"])
            self.assertEqual(len(request["planned_steps"]), 2)
            return request

        def approve(request):
            project_tasks.decide(request["job_id"], core.load_config(), True)
            return self._wait_for(lambda: wire.tool("get_windows_project_job", job_id=request["job_id"]),
                                  lambda item: item["state"] in {"succeeded", "failed", "revoked", "rejected"},
                                  seconds=18)

        python = root / "python-project"
        python.mkdir()
        (python / "test_example.py").write_text("import unittest\nclass Demo(unittest.TestCase):\n"
                                                 "    def test_value(self):\n        self.assertEqual(2 + 2, 4)\n",
                                                 encoding="utf-8")
        pytest_job = approve(request("recipe:python-check-test", python))
        self.assertEqual(pytest_job["state"], "succeeded", pytest_job)
        self.assertEqual([s["preset"] for s in pytest_job["result"]["steps"]],
                         ["python_build_check", "python_unittest"])

        def node_project(name, failing=False):
            folder = root / name
            folder.mkdir()
            manifest = {"name": name, "version": "1.0.0", "scripts": {"test": "node test.js", "build": "node build.js"}}
            (folder / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
            (folder / "test.js").write_text("require('node:fs').writeFileSync('tested.tag','yes');\n" +
                                             ("process.exit(9);\n" if failing else "console.log('test ok');\n"), encoding="utf-8")
            (folder / "build.js").write_text("require('node:fs').writeFileSync('built.tag','yes');\n", encoding="utf-8")
            return folder

        good = node_project("node-good")
        waiting = request("recipe:npm-test-build", good)
        self.assertFalse((good / "tested.tag").exists())
        finished = approve(waiting)
        self.assertEqual(finished["state"], "succeeded", finished)
        self.assertTrue((good / "built.tag").exists())
        bad = node_project("node-fail", failing=True)
        failed = approve(request("recipe:npm-test-build", bad))
        self.assertEqual(failed["state"], "failed", failed)
        self.assertEqual(failed["exit_code"], 9)
        self.assertTrue((bad / "tested.tag").exists())
        self.assertFalse((bad / "built.tag").exists())
        self.assertEqual([s["preset"] for s in failed["result"]["steps"]], ["npm_test"])
        changed = node_project("node-changed")
        waiting = request("recipe:npm-test-build", changed)
        manifest = changed / "package.json"
        manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        denied = approve(waiting)
        self.assertEqual(denied["state"], "failed")
        self.assertIn("package.json changed", denied["result"]["steps"][0]["result"]["message"])
        self.assertFalse((changed / "tested.tag").exists())
        print("Python and npm recipe flows, local approval gating, exit-code propagation and manifest changes passed")

    def _archive_and_binary(self, wire, root):
        folder = root / "Release"
        folder.mkdir()
        (folder / "empty").mkdir()
        original = b"test binary bytes only\x00" * 1_000_001
        specimens = {"SampleApp.exe": original, "Display.bat": b"echo not executed",
                     "Example.lnk": b"opaque shortcut bytes", "LICENSE": b"local test data"}
        for name, data in {**specimens, "keystore.pfx": b"excluded", ".env": b"excluded"}.items():
            (folder / name).write_bytes(data)
        listing = wire.tool("list_workspace", relative_dir="Release")
        tools = {item["name"]: item["content_tools"] for item in listing["files"]}
        self.assertIn("start_workspace_export", tools["SampleApp.exe"])
        self.assertNotIn("prepare_workspace_file", tools["SampleApp.exe"])
        self.assertIn("prepare_workspace_file", tools["Example.lnk"])
        self.assertIn("prepare_workspace_file", tools["LICENSE"])
        self.assertEqual(tools["keystore.pfx"], [])
        self.assertIn("start_workspace_archive", next(item for item in wire.tool("list_workspace")["folders"]
                                                       if item["name"] == "Release")["content_tools"])

        def ready(job):
            return self._wait_for(lambda: wire.tool("get_workspace_export", job_id=job["job_id"]),
                                  lambda result: result["state"] in {"ready", "failed"})

        binary = ready(wire.tool("start_workspace_export", relative_path="Release/SampleApp.exe"))
        self.assertEqual(binary["state"], "ready")
        status, _, data = wire.request("GET", local_path(binary["download_url"]))
        self.assertEqual((status, data), (200, original))
        self.assertEqual(wire.tool("confirm_workspace_export", job_id=binary["job_id"],
                                   sha256=hashlib.sha256(data).hexdigest())["state"], "delivered")
        packed = ready(wire.tool("start_workspace_archive", relative_dir="Release"))
        self.assertEqual(packed["state"], "ready", packed)
        self.assertEqual((packed["archive_files"], packed["archive_excluded"]), (4, 2))
        status, _, data = wire.request("GET", local_path(packed["download_url"]))
        self.assertEqual(status, 200)
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(packed["sha256"], digest)
        with zipfile.ZipFile(BytesIO(data)) as archive:
            self.assertIn("Release/empty/", archive.namelist())
            self.assertEqual({name for name in archive.namelist() if not name.endswith("/")},
                             {"Release/" + name for name in specimens})
            self.assertEqual(archive.read("Release/SampleApp.exe"), original)
            self.assertIsNone(archive.testzip())
        self.assertEqual(wire.tool("confirm_workspace_export", job_id=packed["job_id"], sha256=digest)["state"],
                         "delivered")
        fallback = ready(wire.tool("start_workspace_export", relative_path="Release/empty"))
        self.assertEqual((fallback["state"], fallback["kind"]), ("ready", "zip_archive"))
        wire.tool("cancel_workspace_export", job_id=fallback["job_id"])
        self.assertTrue((folder / "SampleApp.exe").is_file())
        print("Binary and extensionless export discovery, raw EXE round trip, Windows directory ZIP and receipt passed")

    @unittest.skipUnless(os.name == "nt", "Windows worker and secure Win32 placement are required")
    def test_real_loopback_http(self):
        with tempfile.TemporaryDirectory(prefix="DotRelayAcceptance-", dir=PACKAGE.parent) as temp:
            fixture = Path(temp)
            state, workspace = fixture / "state", fixture / "workspace"
            os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = str(state)
            import core
            self.assertEqual(core.STATE, state, "Run in a new standalone Python process")
            docs, inbox = workspace / "docs", workspace / "inbox"
            docs.mkdir(parents=True)
            inbox.mkdir()
            (docs / "legacy.txt").write_bytes(b"one\ntwo\nthree\n")
            (docs / "validate.py").write_bytes(b"number = 42\n")
            expected = write_large(docs / "large.zip")
            origin, public, private = endpoint_and_ports()
            core.configure_local_relay(origin, [CALLBACK])
            consent = core.local_consent_code()
            cfg = dict(core.load_config(), origin=origin, poll_seconds=1, workspace_enabled=True, workspace_root=str(workspace),
                       workspace_revision="isolated-workspace", approval_mode="full", documents_enabled=True,
                       document_scope=str(docs), document_revision="isolated-documents", transfer_max_mb=100,
                       receive_enabled=True, receive_scope=str(inbox), receive_revision="isolated-inbox",
                       task_enabled=True, task_scope=str(docs), task_revision="isolated-tasks")
            core.save_json(core.CONFIG, cfg)
            env = dict(os.environ, PROBE_ORIGIN=origin, CREDENTIALS_DIRECTORY=str(core.FUNNEL),
                       STATE_DIRECTORY=str(core.FUNNEL), PROBE_WORKSPACE="1",
                       PROBE_OAUTH_CALLBACKS_JSON=json.dumps([CALLBACK]),
                       PROBE_PORT=str(public), PROBE_PRIVATE_WORKER_PORT=str(private), PYTHONUTF8="1")
            wire = Wire(public, urlsplit(origin).netloc)
            try:
                with ExitStack() as stack:
                    self._launch(stack, "relay", fixture, env)
                    self._wait_for(lambda: wire.request("GET", "/.well-known/oauth-protected-resource/mcp")[0],
                                   lambda status: status == 200)
                    self._launch(stack, "worker", fixture, env)
                    self._wait_for(lambda: core.read_json(core.STATUS), lambda status: status.get("phase") == "online")
                    self.assertEqual(wire.request("POST", "/worker", b"{}")[0], 404)
                    self._authorize(wire, origin, consent)
                    self._file_tools(wire)
                    self._large(wire, expected)
                    self._inbox(wire, inbox, cfg)
                    self._outgoing(wire, docs / "legacy.txt", cfg)
                    self._messages_and_project(wire, cfg)
                    self._unified(wire, workspace)
            except BaseException:
                for role in ("relay", "worker"):
                    log = fixture / (role + ".log")
                    if log.is_file():
                        print(f"--- {role} diagnostic tail ---")
                        print(log.read_text(encoding="utf-8", errors="replace")[-2500:])
                raise


if __name__ == "__main__":
    if sys.argv[1:] == ["--relay"]:
        relay = runpy.run_path(str(PACKAGE / "vps" / "probe.py"))
        import uvicorn
        config = uvicorn.Config(relay["app_with_trace"], access_log=False, proxy_headers=False, log_config=None)
        server = uvicorn.Server(config)
        stop_file = Path(os.environ["WINDOWS_WORKSPACE_MCP_STATE"]).parent / "relay.stop"

        def stop_watch():
            while not stop_file.exists():
                time.sleep(.1)
            server.should_exit = True

        threading.Thread(target=stop_watch, name="acceptance-relay-shutdown", daemon=True).start()
        with ExitStack() as listeners:
            sockets = [listeners.enter_context(socket.create_server(("127.0.0.1", int(os.environ[port]))))
                       for port in ("PROBE_PORT", "PROBE_PRIVATE_WORKER_PORT")]
            server.run(sockets=sockets)
    elif sys.argv[1:] == ["--worker"]:
        import core
        import worker
        core.FUNNEL_PRIVATE_PORT = int(os.environ["PROBE_PRIVATE_WORKER_PORT"])
        raise SystemExit(worker.main())
    else:
        unittest.main(verbosity=2)
