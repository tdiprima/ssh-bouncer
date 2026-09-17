import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import actions  # noqa: E402
import sshbouncer  # noqa: E402
from config import load_config  # noqa: E402
from state import StateStore, dry_run_state_path  # noqa: E402

ATTACKER = "203.0.113.9"
THRESHOLD = 3


def failed_login(ip=ATTACKER):
    return {"type": "failed_password", "ip": ip, "user": "root"}


class DaemonTestCase(unittest.TestCase):
    """Builds a real Daemon from a validated config that points every path into a temp dir."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.state_path = self.root / "state.json"

    def make_config(self, **overrides):
        settings = {
            "auth_log": str(self.root / "auth.log"),
            "log_file": str(self.root / "sshbouncer.log"),
            "state_file": str(self.state_path),
            "threshold": THRESHOLD,
            "block_enabled": True,
            "block_method": "iptables",
            "cooldown_minutes": 0,
            "whitelist": [],
        }
        settings.update(overrides)
        config_path = self.root / "config.json"
        config_path.write_text(json.dumps(settings))
        return load_config(str(config_path))


class DryRunIsolationTests(DaemonTestCase):
    def setUp(self):
        super().setUp()
        # Production state that a dry run must never read into its own table or overwrite.
        now = datetime(2026, 1, 1, 12, 0, 0)
        StateStore(str(self.state_path)).save(
            {"198.51.100.1": {"blocked_at": now, "expires_at": now + timedelta(hours=1), "method": "iptables"}},
            {"198.51.100.2": [now]},
        )
        self.production_bytes = self.state_path.read_bytes()
        self.subprocess_run = mock.patch.object(actions.subprocess, "run").start()
        self.addCleanup(mock.patch.stopall)

    def test_daemon_dry_run_isolates_firewall_and_state(self):
        daemon = sshbouncer.Daemon(self.make_config(), dry_run=True)
        daemon.engine.restore_state()

        self.assertEqual(daemon.engine.blocked, {}, "dry run must not load production blocks")
        for _ in range(THRESHOLD):
            daemon.engine.process_event(failed_login())
        self.assertIn(ATTACKER, daemon.engine.blocked)

        daemon.engine.blocked[ATTACKER]["expires_at"] = datetime.now() - timedelta(seconds=1)
        self.assertEqual(daemon.engine.expire_blocks(), [ATTACKER])
        daemon.engine.save_state()

        self.subprocess_run.assert_not_called()
        self.assertEqual(self.state_path.read_bytes(), self.production_bytes)
        simulated_path = Path(dry_run_state_path(str(self.state_path)))
        self.assertTrue(simulated_path.is_file())
        self.assertNotEqual(simulated_path, self.state_path)
        simulated = StateStore(str(simulated_path)).load()
        self.assertNotIn("198.51.100.1", simulated["blocks"])

    def test_dry_run_block_is_recorded_in_simulated_state_only(self):
        daemon = sshbouncer.Daemon(self.make_config(), dry_run=True)
        for _ in range(THRESHOLD):
            daemon.engine.process_event(failed_login())
        self.subprocess_run.assert_not_called()
        simulated = StateStore(dry_run_state_path(str(self.state_path))).load()
        self.assertIn(ATTACKER, simulated["blocks"])
        self.assertNotIn(ATTACKER, StateStore(str(self.state_path)).load()["blocks"])
        self.assertEqual(self.state_path.read_bytes(), self.production_bytes)

    def test_dry_run_alert_body_says_simulated(self):
        daemon = sshbouncer.Daemon(self.make_config(), dry_run=True)
        self.assertIn("simulated", daemon.engine.build_alert_body(ATTACKER, THRESHOLD, True))

    def test_live_daemon_uses_production_state_and_real_firewall(self):
        """Control case: without --dry-run the same wiring does touch both. Proves the test can fail."""
        self.subprocess_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        daemon = sshbouncer.Daemon(self.make_config(), dry_run=False)
        for _ in range(THRESHOLD):
            daemon.engine.process_event(failed_login())
        self.subprocess_run.assert_called_once()
        self.assertEqual(self.subprocess_run.call_args[0][0][0], "iptables")
        self.assertNotEqual(self.state_path.read_bytes(), self.production_bytes)


class IdleSchedulingTests(DaemonTestCase):
    def setUp(self):
        super().setUp()
        self.clock = {"now": 1000.0}
        mock.patch.object(sshbouncer.time, "monotonic", side_effect=lambda: self.clock["now"]).start()
        self.sleep = mock.patch.object(sshbouncer.time, "sleep").start()
        self.addCleanup(mock.patch.stopall)
        self.daemon = sshbouncer.Daemon(self.make_config(), dry_run=False)
        self.firewall = mock.Mock(method="iptables")
        self.daemon.engine.firewall = self.firewall

    def advance(self, seconds):
        self.clock["now"] += seconds

    def seed_expired_block(self):
        past = datetime.now() - timedelta(minutes=5)
        self.daemon.engine.blocked[ATTACKER] = {
            "blocked_at": past - timedelta(hours=1), "expires_at": past, "method": "iptables"}

    def test_idle_services_expiry_and_save_retry(self):
        self.seed_expired_block()
        self.daemon.engine.unsaved_changes = True

        self.advance(sshbouncer.EXPIRY_CHECK_INTERVAL_SECONDS - 1)
        self.daemon.idle(0.5)
        self.firewall.unblock.assert_not_called()
        self.assertTrue(self.daemon.engine.unsaved_changes)
        self.assertFalse(self.state_path.exists())
        self.sleep.assert_called_once_with(0.5)

        self.advance(1)
        self.daemon.idle(0.5)
        self.firewall.unblock.assert_called_once_with(ATTACKER)
        self.assertNotIn(ATTACKER, self.daemon.engine.blocked)
        self.assertFalse(self.daemon.engine.unsaved_changes)
        self.assertEqual(StateStore(str(self.state_path)).load()["blocks"], {})

    def test_save_retry_runs_even_when_nothing_expired(self):
        self.daemon.engine.unsaved_changes = True
        self.advance(sshbouncer.EXPIRY_CHECK_INTERVAL_SECONDS)
        self.daemon.idle(0.5)
        self.assertFalse(self.daemon.engine.unsaved_changes)
        self.assertTrue(self.state_path.is_file())

    def test_expiry_interval_resets_after_each_check(self):
        self.advance(sshbouncer.EXPIRY_CHECK_INTERVAL_SECONDS)
        self.daemon.idle(0.5)
        self.seed_expired_block()
        self.advance(sshbouncer.EXPIRY_CHECK_INTERVAL_SECONDS - 1)
        self.daemon.idle(0.5)
        self.firewall.unblock.assert_not_called()
        self.advance(1)
        self.daemon.idle(0.5)
        self.firewall.unblock.assert_called_once_with(ATTACKER)

    def test_failed_unblock_keeps_record_for_next_cycle(self):
        self.seed_expired_block()
        self.firewall.unblock.side_effect = actions.FirewallError("busy")
        self.advance(sshbouncer.EXPIRY_CHECK_INTERVAL_SECONDS)
        self.daemon.idle(0.5)
        self.assertIn(ATTACKER, self.daemon.engine.blocked)
        self.firewall.unblock.side_effect = None
        self.advance(sshbouncer.EXPIRY_CHECK_INTERVAL_SECONDS)
        self.daemon.idle(0.5)
        self.assertNotIn(ATTACKER, self.daemon.engine.blocked)

    def test_housekeeping_prunes_stale_tracker_entries(self):
        stale = datetime.now() - timedelta(hours=1)
        self.daemon.engine.tracker[ATTACKER] = [stale]
        self.advance(sshbouncer.HOUSEKEEPING_INTERVAL_SECONDS)
        self.daemon.idle(0.5)
        self.assertNotIn(ATTACKER, self.daemon.engine.tracker)

    def test_idle_does_not_sleep_once_stop_requested(self):
        self.daemon.stop_requested = True
        self.daemon.idle(0.5)
        self.sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
