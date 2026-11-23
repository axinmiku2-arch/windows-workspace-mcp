"""Offline test suite. Uses synthetic files, one stdio subprocess, and in-memory ASGI calls."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from starlette.testclient import TestClient

from helper import DEFAULT_PORT, LoopbackBearer, make_http_app
from workspace_reader import MAX_BYTES, Reader, WorkspaceError

PROJECT = Path(__file__).resolve().parents[1]
HOST = f"127.0.0.1:{DEFAULT_PORT}"
TOKEN_FIXTURE = "x" * 43


class Sample:
    def setUp(self):
        fixture = tempfile.TemporaryDirectory(prefix="workspace-helper-test-")
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name) / "workspace"
        self.root.mkdir()
        (self.root / "sample.txt").write_text("示例内容 • пример", encoding="utf-8")
        self.reader = Reader(str(self.root))


class WorkspaceTests(Sample, unittest.TestCase):
    def test_read_limit_utf8_and_text_only(self):
        self.assertEqual(self.reader.read("sample.txt")["text"], "示例内容 • пример")
        (self.root / "good.txt").write_bytes(b"a" * MAX_BYTES)
        (self.root / "large.txt").write_bytes(b"a" * (MAX_BYTES + 1))
        (self.root / "binary.txt").write_bytes(b"some\0bytes")
        (self.root / "garbled.txt").write_bytes(b"\xff\xfe\xf2")
        (self.root / "program.exe").touch()
        self.assertEqual(self.reader.read("good.txt")["byte_count"], MAX_BYTES)
        for path in ("large.txt", "binary.txt", "garbled.txt", "program.exe"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.reader.read(path)

    def test_protected_names_and_traversal(self):
        for name in (".env", ".hidden.txt", "secret.txt", "api-key.json", "CON.txt", "LPT¹.txt", "program.exe"):
            if os.name == "nt" and name in {"CON.txt", "LPT¹.txt"}:
                continue
            (self.root / name).touch()
        self.assertEqual([x["relative_path"] for x in self.reader.list()["entries"]], ["sample.txt"])
        for value in ("../sample.txt", "..\\sample.txt", "/sample.txt", "C:\\Windows\\a.txt",
                      "C:sample.txt", "sample.txt:stream", "a//sample.txt", "./sample.txt", "A~1.txt",
                      "quiet/../sample.txt", "NUL.txt", "NUL .txt", "folder/", "x\x00y.txt",
                      "x\u202ey.txt", "q/" * 9 + "sample.txt", ".hidden.txt", "secret.txt", "api-key.json"):
            with self.subTest(value=value), self.assertRaises(WorkspaceError):
                self.reader.read(value)

    def test_hard_links_cannot_be_listed_or_read(self):
        other = self.root.parent / "outside.txt"
        other.write_text("outside", encoding="utf-8")
        try:
            os.link(other, self.root / "hard.txt")
        except OSError:
            self.skipTest("The fixture volume does not support hard links.")
        names = {x["relative_path"] for x in self.reader.list()["entries"]}
        self.assertNotIn("hard.txt", names)
        with self.assertRaises(WorkspaceError):
            self.reader.read("hard.txt")

    def test_symbolic_links_and_linked_root_fail_closed(self):
        other = self.root.parent / "outside"
        other.mkdir()
        (other / "outside.txt").write_text("outside", encoding="utf-8")
        try:
            (self.root / "linked-dir").symlink_to(other, target_is_directory=True)
            (self.root / "linked.txt").symlink_to(other / "outside.txt")
        except OSError:
            self.skipTest("Symlink creation needs privileges on this Windows host.")
        self.assertEqual([x["relative_path"] for x in self.reader.list()["entries"]], ["sample.txt"])
        for read in ("linked.txt", "linked-dir/outside.txt"):
            with self.assertRaises(WorkspaceError):
                self.reader.read(read)
        with self.assertRaises(WorkspaceError):
            Reader(str(self.root / "linked-dir"))

    def test_scope_must_be_explicit_and_remain_the_original_directory(self):
        for value in (None, "", str(self.root.anchor), "relative/path", str(self.root) + os.sep + "..",
                      str(Path.home())):
            with self.assertRaises(WorkspaceError):
                Reader(value)
        self.root.rename(self.root.with_name("old-workspace"))
        self.root.mkdir()
        with self.assertRaisesRegex(WorkspaceError, "changed"):
            self.reader.list()

    def test_listing_is_bounded_and_returns_only_relative_paths(self):
        for i in range(100):
            (self.root / f"note-{i}.md").touch()
        data = self.reader.list()
        self.assertTrue(data["truncated"])
        self.assertEqual(len(data["entries"]), 60)
        self.assertNotIn(str(self.root), json.dumps(data))
        self.assertNotIn(str(self.root), json.dumps(self.reader.describe()))


class HttpTests(Sample, unittest.TestCase):
    HEADERS = {"authorization": "Bearer " + TOKEN_FIXTURE, "accept": "application/json, text/event-stream"}

    def client(self, target=("127.0.0.1", 45678)):
        return TestClient(make_http_app(self.reader, TOKEN_FIXTURE),
                          base_url="http://" + HOST, client=target, follow_redirects=False)

    def test_reject_missing_bad_duplicate_tokens_and_browser_origin(self):
        with self.client() as client:
            for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic " + TOKEN_FIXTURE},
                            {"Authorization": "Bearer " + TOKEN_FIXTURE + " extra"},
                            (("Authorization", "Bearer " + TOKEN_FIXTURE), ("Authorization", "Bearer " + TOKEN_FIXTURE))):
                with self.subTest(headers=headers):
                    self.assertEqual(client.post("/mcp", headers=headers).status_code, 401)
            self.assertEqual(client.post("/mcp", headers={**self.HEADERS, "origin": "https://browser.invalid"}).status_code, 403)
            self.assertEqual(client.post("/mcp", headers={**self.HEADERS, "host": "other.invalid"}).status_code, 403)
            duplicate_host = [*self.HEADERS.items(), ("Host", HOST), ("Host", HOST)]
            self.assertEqual(client.post("/mcp", headers=duplicate_host).status_code, 403)
            self.assertEqual(client.post("/mcp?unexpected=1", headers=self.HEADERS).status_code, 400)
            self.assertEqual(client.post("/mcp/", headers=self.HEADERS).status_code, 404)
        with self.client(("192.0.2.123", 45678)) as client:
            self.assertEqual(client.post("/mcp", headers={**self.HEADERS, "x-forwarded-for": "127.0.0.1"}).status_code, 403)

    def test_mcp_initialize_and_read_over_authenticated_asgi(self):
        with self.client() as client:
            response = client.post("/mcp", headers=self.HEADERS, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "offline-test", "version": "1"}}})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.headers["cache-control"], "no-store")
            protocol = response.json()["result"]["protocolVersion"]
            headers = {**self.HEADERS, "MCP-Protocol-Version": protocol}
            response = client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "read_workspace_file", "arguments": {"relative_path": "sample.txt"}}})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["result"]["structuredContent"]["text"], "示例内容 • пример")
            self.assertNotIn(str(self.root), response.text)
            response = client.post("/mcp", headers=headers, content=b"x" * 33_000)
            self.assertIn(response.status_code, (400, 413, 415))
            response = client.get("/mcp", headers=headers)
            self.assertEqual(response.status_code, 405)  # no session/SSE stream provided

    def test_fails_closed_when_http_secret_is_blank_or_invalid(self):
        for secret in (None, "", "short", ("x" * 42) + " ", ("x" * 42) + "\n"):
            with self.assertRaises(ValueError):
                LoopbackBearer(None, secret, DEFAULT_PORT)


class StdioTests(Sample, unittest.IsolatedAsyncioTestCase):
    async def test_real_stdio_sdk_round_trip(self):
        settings = StdioServerParameters(
            command=sys.executable, args=["-B", str(PROJECT / "helper.py")],
            env={"WINDOWS_HELPER_WORKSPACE": str(self.root)})
        async with stdio_client(settings) as (receive, send), ClientSession(receive, send) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            self.assertEqual({t.name for t in tools}, {"workspace_info", "list_workspace", "read_workspace_file"})
            self.assertTrue(all(t.annotations.readOnlyHint for t in tools))
            read = await session.call_tool("read_workspace_file", {"relative_path": "sample.txt"})
            self.assertFalse(read.isError)
            self.assertEqual(read.structuredContent["text"], "示例内容 • пример")
            invalid = await session.call_tool("read_workspace_file", {"relative_path": "../sample.txt"})
            self.assertTrue(invalid.isError)
            self.assertNotIn(str(self.root), str(invalid.content))

    def test_cli_bad_config_exits_before_server_starts(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WINDOWS_HELPER_WORKSPACE", None)
            os.environ.pop("WINDOWS_HELPER_BEARER_TOKEN", None)
            args = [sys.executable, "-B", str(PROJECT / "helper.py")]
            run = subprocess.run(args, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 2)
            self.assertIn(b"WINDOWS_HELPER_WORKSPACE", run.stderr)
            os.environ["WINDOWS_HELPER_WORKSPACE"] = str(self.root)
            run = subprocess.run([*args, "--transport", "streamable-http"], capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 2)
            self.assertIn(b"WINDOWS_HELPER_BEARER_TOKEN", run.stderr)
            self.assertNotIn(str(self.root).encode(), run.stderr)


if __name__ == "__main__":
    unittest.main()
