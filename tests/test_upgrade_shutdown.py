"""Countdown model tests. Do not call the real Windows shutdown dispatcher."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from shutdown_timer import LocalShutdownTimer


class ShutdownTimerTest(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.calls = 0
        self.timer = LocalShutdownTimer(clock=lambda: self.now)

    def dispatch(self):
        self.calls += 1

    def test_dispatches_once_only_at_deadline(self):
        self.timer.schedule(2)
        self.assertEqual(self.timer.seconds_remaining(), 120)
        self.now = 219.25
        self.assertEqual(self.timer.seconds_remaining(), 1)
        self.assertEqual(self.timer.tick(self.dispatch), "waiting")
        self.now = 220
        self.assertEqual(self.timer.tick(self.dispatch), "dispatched")
        self.assertEqual(self.timer.tick(self.dispatch), "inactive")
        self.assertEqual(self.calls, 1)

    def test_cancellation_and_no_late_dispatch(self):
        self.timer.schedule(1)
        self.assertTrue(self.timer.cancel())
        self.now = 160
        self.assertEqual(self.timer.tick(self.dispatch), "inactive")
        self.timer.schedule(1)
        self.now = 251
        self.assertEqual(self.timer.tick(self.dispatch), "cancelled_late")
        self.assertEqual(self.calls, 0)

    def test_invalid_input_and_no_implicit_replacement(self):
        for invalid in (0, 721, "5", True, 2.5):
            with self.assertRaises(ValueError):
                self.timer.schedule(invalid)
        self.timer.schedule(1)
        with self.assertRaises(ValueError):
            self.timer.schedule(2)
        self.assertEqual(self.timer.seconds_remaining(), 60)

    def test_dispatch_failure_does_not_retry(self):
        self.timer.schedule(1)
        self.now = 160
        def fail():
            self.dispatch()
            raise OSError("mock refusal")
        with self.assertRaises(OSError):
            self.timer.tick(fail)
        self.assertEqual(self.timer.tick(fail), "inactive")
        self.assertEqual(self.calls, 1)


if __name__ == "__main__":
    unittest.main()
