"""Discoverable unit checks for the Dot Windows development workspace."""
from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
EXCLUDED = {"test_relay_integration.py"}


def run_scripts(scripts, timeout):
    failed = []
    with tempfile.TemporaryDirectory(prefix="DotDevCheck-") as scratch:
        profile = Path(scratch) / "profile"
        profile.mkdir()
        env = {
            **os.environ,
            "WINDOWS_WORKSPACE_MCP_STATE": str(Path(scratch) / "state"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "USERPROFILE": str(profile),
        }
        for script in scripts:
            print(f"--- {script.name} ---", flush=True)
            try:
                result = subprocess.run(
                    [sys.executable, "-I", "-B", "-X", "utf8", str(script)],
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    env=env,
                    timeout=timeout,
                    check=False,
                )
                if result.returncode:
                    failed.append(f"{script.name}: exit {result.returncode}")
            except subprocess.TimeoutExpired:
                failed.append(f"{script.name}: timed out")
    return failed


class DevelopmentChecks(unittest.TestCase):
    def test_unit_suites(self):
        scripts = [
            path for path in sorted((ROOT / "tests").glob("test_*.py"))
            if path.name not in EXCLUDED
        ]
        self.assertTrue(scripts, "No unit suites were found")
        self.assertEqual(run_scripts(scripts, timeout=90), [])


if __name__ == "__main__":
    if sys.argv[1:] == ["--relay"]:
        failures = run_scripts([ROOT / "tests" / "test_relay_integration.py"], timeout=240)
        for problem in failures:
            print(problem, file=sys.stderr)
        raise SystemExit(bool(failures))
    unittest.main(verbosity=2)
