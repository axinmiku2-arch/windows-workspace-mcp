"""Offline ASGI checks for the portable operator-approved ingress."""

import base64
import hashlib
import json
from pathlib import Path
import runpy
import secrets
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from relay_config import validated_oauth_callbacks

ORIGIN = "https://mcp.safety-fixture.test:18773"
ALLOWED = "https://client.safety-fixture.test/oauth/exact-callback"
APP = ROOT / "vps" / "probe.py"


class RelayTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.passcode, self.worker = secrets.token_urlsafe(32), secrets.token_hex(32)
        (self.folder / "probe_key").write_text(self.passcode, encoding="ascii")
        (self.folder / "worker_key").write_text(self.worker, encoding="ascii")
        self.env = {
            "PROBE_ORIGIN": ORIGIN, "PROBE_OAUTH_CALLBACKS_JSON": json.dumps([ALLOWED]),
            "PROBE_WORKSPACE": "1", "PROBE_PORT": "18773", "PROBE_PRIVATE_WORKER_PORT": "18774",
            "CREDENTIALS_DIRECTORY": str(self.folder), "STATE_DIRECTORY": "", "PROBE_REQUIRE_LOCAL_BINDING": "0",
        }

    def load(self, **changes):
        with patch.dict("os.environ", {**self.env, **changes}):
            return runpy.run_path(str(APP))

    @staticmethod
    def client(module, base_url=ORIGIN, peer="127.0.0.1"):
        return TestClient(module["app_with_trace"], base_url=base_url, client=(peer, 45000),
                          follow_redirects=False)

    @staticmethod
    def registration(callback):
        return {"client_name": "Generic offline test", "redirect_uris": [callback],
                "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                "token_endpoint_auth_method": "none", "scope": "mcp:workspace"}

    def test_blank_and_invalid_callback_lists_fail_before_listening(self):
        with self.assertRaisesRegex(ValueError, "exact HTTPS OAuth callback"):
            self.load(PROBE_OAUTH_CALLBACKS_JSON="[]")
        for candidate in ("http://client.safety-fixture.test/oauth", "https://*.safety-fixture.test/oauth",
                          "https://client.safety-fixture.test/", "https://client.safety-fixture.test/oauth#frag",
                          "https://127.0.0.1/callback", "https://client.safety-fixture.test/oauth?state=some",
                          "https://user@client.safety-fixture.test/callback", "https://client.safety-fixture.test/a/../b"):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validated_oauth_callbacks([candidate])

    def test_ports_workers_and_peer_do_not_cross(self):
        module = self.load()
        with self.client(module) as public:
            self.assertEqual(public.post("/worker", json={}, headers={"Authorization": "Bearer " + self.worker}).status_code, 404)
            self.assertEqual(public.get("/.well-known/oauth-protected-resource/mcp", headers={"Host": "bad.safety-fixture.test"}).status_code, 403)
            self.assertEqual(public.post("/register", content=b"x" * 16385).status_code, 413)
        with self.client(self.load(), "http://127.0.0.1:18774") as private:
            self.assertEqual(private.post("/mcp", json={}).status_code, 404)
            self.assertEqual(private.post("/worker", json={}).status_code, 401)
            auth = {"Authorization": "Bearer " + self.worker}
            self.assertEqual(private.post("/worker", json={}, headers=auth).json(), {"job": None})
            self.assertEqual(private.post("/worker?unexpected=true", json={}, headers=auth).status_code, 404)
            self.assertEqual(private.post("/worker", json={}, headers={**auth, "Origin": ORIGIN}).status_code, 404)
        with self.client(self.load(), peer="192.0.2.7") as direct:
            self.assertEqual(direct.post("/mcp", json={}).status_code, 403)

    def test_exact_configured_generic_client_can_complete_oauth(self):
        module = self.load()
        with self.client(module) as client:
            auth_headers = {"Accept": "application/json, text/event-stream"}
            self.assertEqual(client.post("/mcp", json={}, headers=auth_headers).status_code, 401)
            self.assertEqual(client.get("/.well-known/oauth-protected-resource/mcp").json()["resource"], ORIGIN + "/mcp")
            for wrong in ("https://chatgpt.com/connector_platform_oauth_redirect", ALLOWED + "-different", ALLOWED + "/"):
                with self.subTest(wrong=wrong):
                    rejected = client.post("/register", json=self.registration(wrong))
                    self.assertEqual(rejected.status_code, 400)
                    self.assertEqual(rejected.json()["error"], "invalid_redirect_uri")
            r = client.post("/register", json=self.registration(ALLOWED))
            self.assertEqual(r.status_code, 201)
            client_id = r.json()["client_id"]
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            url = client.get("/authorize", params={"redirect_uri": ALLOWED, "client_id": client_id,
                       "response_type": "code", "state": "offline-state", "code_challenge_method": "S256",
                       "code_challenge": challenge, "scope": "mcp:workspace", "resource": ORIGIN + "/mcp"})
            self.assertIn(url.status_code, {302, 307})
            ticket = parse_qs(urlsplit(url.headers["location"]).query)["t"][0]
            self.assertEqual(client.post("/probe-consent", data={"ticket": ticket, "key": "wrong-passcode"}).status_code, 401)
            consent = client.post("/probe-consent", data={"ticket": ticket, "key": self.passcode})
            self.assertEqual(consent.status_code, 303)
            callback = urlsplit(consent.headers["location"])
            self.assertEqual(f"{callback.scheme}://{callback.netloc}{callback.path}", ALLOWED)
            fields = parse_qs(callback.query)
            self.assertEqual(fields["state"], ["offline-state"])
            self.assertEqual(client.post("/probe-consent", data={"ticket": ticket, "key": self.passcode}).status_code, 401)
            tokens = client.post("/token", data={"grant_type": "authorization_code", "client_id": client_id,
                          "redirect_uri": ALLOWED, "code": fields["code"][0], "code_verifier": verifier,
                          "resource": ORIGIN + "/mcp"})
            self.assertEqual(tokens.status_code, 200, tokens.text)
            token = tokens.json()["access_token"]
            request = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                  "clientInfo": {"name": "offline", "version": "1"}}}
            response = client.post("/mcp", json=request, headers={**auth_headers,
                                   "Authorization": "Bearer " + token})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn("result", response.json())
            protocol = response.json()["result"]["protocolVersion"]
            tool = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                          "params": {"name": "get_windows_connection", "arguments": {}}},
                          headers={**auth_headers, "Authorization": "Bearer " + token,
                                   "MCP-Protocol-Version": protocol})
            self.assertEqual(tool.status_code, 200, tool.text)
            self.assertIn("worker is offline", tool.text)
            # This is an SDK + server routing test; follow no callback or other network.

    def test_persistent_oauth_state_cannot_be_reused_under_modified_allowlist(self):
        first = self.load(STATE_DIRECTORY=str(self.folder))
        first["provider"].disk.db.close()
        with self.assertRaisesRegex(ValueError, "bound to a different"):
            self.load(STATE_DIRECTORY=str(self.folder),
                      PROBE_OAUTH_CALLBACKS_JSON=json.dumps(["https://another.safety-fixture.test/auth/cb"]))

    def test_live_relay_rejects_stale_operator_binding(self):
        module = self.load(PROBE_REQUIRE_LOCAL_BINDING="1")
        with patch("core.load_config", return_value={"origin": ORIGIN}), \
                patch("core.local_oauth_callbacks", side_effect=[[ALLOWED], []]):
            with self.client(module) as public:
                self.assertEqual(public.get("/.well-known/oauth-protected-resource/mcp").status_code, 200)
                self.assertEqual(public.get("/.well-known/oauth-protected-resource/mcp").status_code, 503)


if __name__ == "__main__":
    unittest.main(verbosity=2)
