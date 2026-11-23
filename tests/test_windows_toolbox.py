"""Offline Windows toolbox acceptance tests: no external DNS, Ping, process, or power actions."""
from __future__ import annotations

import io
import os
from pathlib import Path
import subprocess  # import before the minimal msvcrt compatibility shim
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

_FIXTURE = tempfile.TemporaryDirectory(prefix="dot-toolbox-tests-")
os.environ["WINDOWS_WORKSPACE_MCP_STATE"] = _FIXTURE.name
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
if os.name != "nt" and "msvcrt" not in sys.modules:
    sys.modules["msvcrt"] = types.SimpleNamespace()

import core
import project_tasks as tasks
import windows_toolbox as box


class ToolboxTest(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.TemporaryDirectory(dir=_FIXTURE.name)
        self.addCleanup(self.state.cleanup)
        self.root = Path(self.state.name)
        self.cfg = {**core.DEFAULT, "task_enabled": True, "workspace_enabled": True,
                    "workspace_unified": True, "workspace_root": str(self.root),
                    "workspace_revision": "test", "task_revision": "test", "approval_mode": "full",
                    box.HOSTS_FIELD: ["probe.example.test", "192.0.2.12", "2001:db8::12"]}
        self.stack = [
            patch.object(tasks, "QUEUE", self.root / "jobs"),
            patch.object(tasks, "_base", return_value=self.root),
            patch.object(core, "load_config", side_effect=lambda: self.cfg),
        ]
        for unit in self.stack:
            unit.start()
            self.addCleanup(unit.stop)

    def test_exact_hosts_and_fail_closed_configuration(self):
        self.assertEqual(box.parameters("windows_ping", {"host": "Probe.Example.Test"}, self.cfg),
                         {"host": "probe.example.test"})
        self.assertEqual(box.parameters("windows_ping", {"host": "2001:0db8:0:0::12"}, self.cfg),
                         {"host": "2001:db8::12"})
        rejected = ["https://probe.example.test", "probe.example.test:443", "probe.example.test.",
                    "probe.example.test/anything", "probe.example.test\n", "*.example.test",
                    "evil.probe.example.test", "other.example.test", "one-host", ".example.test",
                    "[2001:db8::12]", "fe80::1%4", "192.0.2.12:81", "192.000.2.12",
                    "0x7f.0x1", "0.0.0.0", "::", "255.255.255.255", "224.1.2.3",
                    "::ffff:224.1.2.3", "ff02::1", "probe..example.test", "中国.test",
                    "probe.example.test;exit", "-probe.test", "probe.example.test ",
                    "a" * 64 + ".test", False, {}, None]
        for host in rejected:
            with self.subTest(host=host), self.assertRaises(ValueError):
                box.parameters("windows_ping", {"host": host}, self.cfg)
        self.assertEqual(box.ping_hosts({}), [])
        self.assertEqual(box.ping_hosts({box.HOSTS_FIELD: ["probe.example.test", "*"]}), [])
        with self.assertRaises(ValueError):
            box.parameters("windows_ping", {"host": "probe.example.test"}, {})
        with patch.object(core, "update_config") as update:
            self.assertEqual(box.save_ping_hosts(["Probe.Example.Test", "probe.example.test", "192.0.2.12"]),
                             ["probe.example.test", "192.0.2.12"])
            update.assert_called_once_with(windows_toolbox_ping_hosts=["probe.example.test", "192.0.2.12"])
            with self.assertRaises(ValueError):
                box.save_ping_hosts(["a.test"] * (box.MAX_HOSTS + 1))
            self.assertEqual(update.call_count, 1)

    def test_shapes_paths_and_always_manual_approval(self):
        for mode in ("ask", "rules", "full"):
            self.cfg["approval_mode"] = mode
            for preset in box.PRESETS:
                args = {"host": "probe.example.test"} if preset == "windows_ping" else None
                job = tasks.start(preset, self.cfg, parameters=args)
                self.assertEqual(job["state"], "awaiting_approval")
                self.assertEqual(job["toolbox_scope"], "host")
                self.assertEqual(job.get("toolbox_host"), "probe.example.test" if args else None)
                if mode != "full":
                    tasks._finish(tasks._read(job["job_id"], self.cfg), "cancelled")
        for fields in ({"relative_path": "code.ps1"}, {"relative_dir": ".."},
                       {"parameters": {"namespace": "all"}}, {"parameters": []}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                tasks.start("windows_ipconfig", self.cfg, **fields)
        for data in (None, {}, {"host": 12}, {"host": "probe.example.test", "count": 4},
                     {"host": "probe.example.test", "payload": "hi"}, {"argument": "probe.example.test"}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                tasks.start("windows_ping", self.cfg, parameters=data)
        with self.assertRaisesRegex(ValueError, "presets"):
            tasks.start("shutdown", self.cfg)
        with self.assertRaisesRegex(ValueError, "presets"):
            tasks.start("cmd", self.cfg)
        with self.assertRaisesRegex(ValueError, "presets"):
            tasks.start("powershell", self.cfg)

    def test_fixed_launch_spec_binary_directory_and_data_channel(self):
        system = self.root / "System32"
        executable = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        executable.parent.mkdir(parents=True)
        executable.touch()
        with patch.object(box, "_system_directory", return_value=system):
            dns = box.launch_spec("windows_ping", {"host": "probe.example.test"}, self.cfg)
            ip = box.launch_spec("windows_ping", {"host": "192.0.2.12"}, self.cfg)
            summary = box.launch_spec("windows_ipconfig", {}, self.cfg)
        self.assertEqual(dns[0], ip[0])
        self.assertEqual(dns[0][:5], [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
        self.assertNotIn("probe.example.test", str(dns[0]))
        self.assertIn("[byte[]]::new(16)", dns[0][-1])
        self.assertIn("$i -lt 2", dns[0][-1])
        self.assertIn("$ping.Send($address, 800, $bytes)", dns[0][-1])
        self.assertEqual(dns[1], system)
        self.assertEqual(dns[2]["DOT_TOOLBOX_PING_HOST"], "probe.example.test")
        self.assertEqual(dns[2]["DOT_TOOLBOX_PING_HOST_KIND"], "dns")
        self.assertEqual(ip[2]["DOT_TOOLBOX_PING_HOST_KIND"], "address")
        self.assertNotIn("DOT_TOOLBOX_PING_HOST", summary[2])
        self.assertEqual(box.TIMEOUT_SECONDS, 10)

    def test_runner_approval_then_allowlist_revocation_prevents_launch(self):
        job = tasks.start("windows_ping", self.cfg, "same-id", parameters={"host": "probe.example.test"})
        same = tasks.start("windows_ping", self.cfg, "same-id", parameters={"host": "Probe.Example.Test"})
        self.assertEqual(same["job_id"], job["job_id"])
        mgr_runner = tasks.Runner()
        with patch.object(tasks.subprocess, "Popen", side_effect=AssertionError("no launch permitted")) as process:
            mgr_runner.pump(self.cfg)
            self.assertIsNone(mgr_runner.thread)
            tasks.decide(job["job_id"], self.cfg, True)
            self.cfg[box.HOSTS_FIELD] = []
            mgr_runner.last = 0
            mgr_runner.pump(self.cfg)
            mgr_runner.thread.join(2)
            self.assertFalse(mgr_runner.thread.is_alive())
            self.assertEqual(tasks.status(job["job_id"], self.cfg)["state"], "revoked")
            process.assert_not_called()

    def test_mocked_process_uses_fixed_job_runner_and_return_is_redacted(self):
        job = tasks.start("windows_ping", self.cfg, parameters={"host": "probe.example.test"})
        tasks.decide(job["job_id"], self.cfg, True)
        item = tasks._read(job["job_id"], self.cfg)
        fake = Mock(returncode=0, stdout=io.BytesIO(b"DOT_PING_V1|reply:23|timeout\r\n"),
                    stderr=io.BytesIO(b"resolved_address=192.0.2.77"), stdin=io.BytesIO())
        fake.poll.return_value = 0
        launch = (["system/powershell.exe", "-Command", "Fixed"], self.root / "protected", {"PATH": "system"})
        with patch.object(box, "launch_spec", return_value=launch), patch.object(tasks, "_windows_job") as group, \
                 patch.object(tasks.subprocess, "Popen", return_value=fake) as process:
            state, result = tasks._run(item, None)
        group.assert_called_once_with(fake)
        self.assertFalse(process.call_args.kwargs["shell"])
        self.assertEqual(process.call_args.kwargs["cwd"], launch[1])
        self.assertEqual(process.call_args.kwargs["env"], launch[2])
        self.assertEqual(state, "succeeded")
        self.assertEqual(result["result"]["attempts"], [{"status": "reply", "round_trip_ms": 23}, {"status": "timeout"}])
        self.assertNotIn("192.0.2.77", str(result))
        self.assertNotIn("stderr", result)

    def test_structured_results_are_bounded_and_do_not_return_machine_addresses(self):
        self.assertEqual(box.structured_result("windows_ipconfig", b"DOT_IP_V1|5|4|3|2\r\n"),
                         {"interfaces": 5, "up_interfaces": 4, "up_with_ipv4": 3, "up_with_ipv6": 2})
        self.assertEqual(box.structured_result("windows_listening_ports", b"DOT_PORTS_V1|2|80,443|1|53"),
                         {"tcp_listening_ports": [80, 443], "udp_bound_ports": [53],
                          "tcp_unique_count": 2, "udp_unique_count": 1, "truncated": False})
        truncated = "DOT_PORTS_V1|66|" + ",".join(map(str, range(1, 65))) + "|0|"
        self.assertTrue(box.structured_result("windows_listening_ports", truncated.encode())["truncated"])
        self.assertEqual(box.structured_result("windows_ping", b"DOT_PING_V1|unresolved")["sent_attempts"], 0)
        for preset, unsafe in (("windows_ipconfig", b"DOT_IP_V1|0|1|0|0"),
                               ("windows_ipconfig", b"DOT_IP_V1|0|0|0|192.0.2.1"),
                               ("windows_listening_ports", b"DOT_PORTS_V1|1|0|0|"),
                               ("windows_listening_ports", b"DOT_PORTS_V1|2|80,80|0|"),
                               ("windows_ping", b"DOT_PING_V1|reply:99999999|timeout"),
                               ("windows_ping", b"DOT_PING_V1|reply:3|timeout|192.0.2.2"),
                               ("windows_ping", b"\x00\xff")):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                box.structured_result(preset, unsafe)

    def test_local_toolbox_jobs_are_private_and_remote_status_hides_host(self):
        params = {"host": "probe.example.test"}
        local = tasks.start("windows_ping", self.cfg, parameters=params)
        remote = tasks.start("windows_ping", self.cfg, parameters=params,
                             submission={"transport": "https_mcp", "connection_id": "a" * 24})
        self.assertNotIn("toolbox_host", remote)
        local_rows = {x["job_id"]: x for x in tasks.listing(self.cfg)["jobs"]}
        self.assertEqual(local_rows[remote["job_id"]]["toolbox_host"], "probe.example.test")
        self.assertEqual(local_rows[local["job_id"]]["toolbox_host"], "probe.example.test")
        self.assertEqual([x["job_id"] for x in tasks.listing(self.cfg, remote=True)["jobs"]],
                         [remote["job_id"]])
        self.assertNotIn("toolbox_host", tasks.status(remote["job_id"], self.cfg, remote=True))
        for hidden in (tasks.status, tasks.cancel):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                hidden(local["job_id"], self.cfg, remote=True)

    def test_launch_gate_blocks_without_approval_cancelled_and_out_of_time(self):
        job = tasks.start("windows_ipconfig", self.cfg)
        ident = job["job_id"]
        item = tasks._read(ident, self.cfg)
        with patch.object(tasks.subprocess, "Popen", side_effect=AssertionError("no launch permitted")) as process:
            self.assertEqual(tasks._run(item, None)[0], "rejected")
            tasks.decide(ident, self.cfg, True)
            self.assertEqual(tasks._command_stop(item, time.monotonic() - 1), "timed_out")
            tasks.cancel(ident, self.cfg)
            self.assertEqual(tasks._run(item, None)[0], "cancelled")
            process.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
