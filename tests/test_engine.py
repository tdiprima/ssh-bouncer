import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from actions import FirewallError  # noqa: E402
from config import parse_whitelist  # noqa: E402
from engine import DetectionEngine  # noqa: E402


class FakeClock:
    def __init__(self):
        self.current = datetime(2026, 1, 1, 12, 0, 0)

    def now(self):
        return self.current

    def advance(self, **kwargs):
        self.current += timedelta(**kwargs)


def make_engine(clock, **overrides):
    config = {
        "threshold": 2,
        "window_seconds": 60,
        "block_enabled": False,
        "block_method": "ufw",
        "block_duration_minutes": 60,
        "email_enabled": False,
        "cooldown_minutes": 10,
        "whitelist": parse_whitelist(["127.0.0.1", "10.0.0.0/8"]),
    }
    config.update(overrides)
    return DetectionEngine(config, state_store=None, now_fn=clock.now)


def failure(ip):
    return {"type": "failed_password", "ip": ip, "user": "root"}


class WhitelistTests(unittest.TestCase):
    def test_whitelisted_single_ip_never_tracked_or_alerted(self):
        clock = FakeClock()
        engine = make_engine(clock)
        with mock.patch.object(engine, "trigger") as trigger:
            for _ in range(5):
                engine.process_event(failure("127.0.0.1"))
        trigger.assert_not_called()
        self.assertNotIn("127.0.0.1", engine.tracker)

    def test_whitelisted_cidr_matches_member_address(self):
        engine = make_engine(FakeClock())
        self.assertTrue(engine.is_whitelisted("10.20.30.40"))
        self.assertFalse(engine.is_whitelisted("11.0.0.1"))

    def test_unparseable_ip_is_treated_as_whitelisted(self):
        engine = make_engine(FakeClock())
        self.assertTrue(engine.is_whitelisted("999.999.999.999"))
        self.assertTrue(engine.is_whitelisted(""))

    def test_empty_whitelist_blocks_nothing_from_alerting(self):
        clock = FakeClock()
        engine = make_engine(clock, whitelist=[])
        with mock.patch.object(engine, "trigger") as trigger:
            engine.process_event(failure("127.0.0.1"))
            engine.process_event(failure("127.0.0.1"))
        trigger.assert_called_once_with("127.0.0.1")


class ThresholdTests(unittest.TestCase):
    def test_below_threshold_does_not_trigger(self):
        engine = make_engine(FakeClock())
        with mock.patch.object(engine, "trigger") as trigger:
            engine.process_event(failure("1.2.3.4"))
        trigger.assert_not_called()

    def test_failures_outside_window_are_forgotten(self):
        clock = FakeClock()
        engine = make_engine(clock)
        with mock.patch.object(engine, "trigger") as trigger:
            engine.process_event(failure("1.2.3.4"))
            clock.advance(seconds=61)
            engine.process_event(failure("1.2.3.4"))
        trigger.assert_not_called()

    def test_accepted_login_is_ignored(self):
        engine = make_engine(FakeClock())
        engine.process_event({"type": "accepted_login", "ip": "1.2.3.4", "user": "x"})
        self.assertNotIn("1.2.3.4", engine.tracker)


class CooldownTests(unittest.TestCase):
    def test_alert_only_mode_respects_cooldown(self):
        clock = FakeClock()
        engine = make_engine(clock)
        with mock.patch("engine.send_email") as send_email:
            engine.config["email_enabled"] = True
            for _ in range(4):
                engine.process_event(failure("1.2.3.4"))
        self.assertEqual(send_email.call_count, 1)

    def test_alert_fires_again_after_cooldown(self):
        clock = FakeClock()
        engine = make_engine(clock, cooldown_minutes=1)
        with mock.patch("engine.send_email") as send_email:
            engine.config["email_enabled"] = True
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
            clock.advance(seconds=61)  # past cooldown (1 min) and past the 60s window
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
        self.assertEqual(send_email.call_count, 2)

    def test_zero_cooldown_alerts_every_time(self):
        clock = FakeClock()
        engine = make_engine(clock, cooldown_minutes=0)
        with mock.patch("engine.send_email") as send_email:
            engine.config["email_enabled"] = True
            for _ in range(4):
                engine.process_event(failure("1.2.3.4"))
        self.assertEqual(send_email.call_count, 3)


class BlockingTests(unittest.TestCase):
    def test_firewall_failure_does_not_record_block(self):
        clock = FakeClock()
        engine = make_engine(clock, block_enabled=True)
        with mock.patch("engine.block_ip", side_effect=FirewallError("ufw: denied")):
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
        self.assertNotIn("1.2.3.4", engine.blocked)

    def test_firewall_failure_is_retried_after_cooldown(self):
        clock = FakeClock()
        engine = make_engine(clock, block_enabled=True, cooldown_minutes=1)
        with mock.patch("engine.block_ip", side_effect=[FirewallError("boom"), None]) as block_ip:
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
            clock.advance(minutes=2)
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
        self.assertEqual(block_ip.call_count, 2)
        self.assertIn("1.2.3.4", engine.blocked)

    def test_successful_block_records_expiry(self):
        clock = FakeClock()
        engine = make_engine(clock, block_enabled=True, block_duration_minutes=15)
        with mock.patch("engine.block_ip") as block_ip:
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
        block_ip.assert_called_once_with("1.2.3.4", "ufw")
        self.assertEqual(engine.blocked["1.2.3.4"]["expires_at"], clock.now() + timedelta(minutes=15))

    def test_dry_run_never_calls_firewall(self):
        clock = FakeClock()
        engine = make_engine(clock, block_enabled=True)
        engine.dry_run = True
        with mock.patch("engine.block_ip") as block_ip:
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
        block_ip.assert_not_called()
        self.assertEqual(engine.blocked, {})

    def test_blocked_ip_is_not_alerted_again(self):
        clock = FakeClock()
        engine = make_engine(clock, block_enabled=True, cooldown_minutes=0)
        with mock.patch("engine.block_ip") as block_ip:
            for _ in range(5):
                engine.process_event(failure("1.2.3.4"))
        block_ip.assert_called_once()


class ExpiryTests(unittest.TestCase):
    def test_expired_block_is_removed(self):
        clock = FakeClock()
        engine = make_engine(clock, block_enabled=True, block_duration_minutes=1)
        with mock.patch("engine.block_ip"):
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
        clock.advance(minutes=1)
        with mock.patch("engine.unblock_ip") as unblock_ip:
            released = engine.expire_blocks()
        unblock_ip.assert_called_once_with("1.2.3.4", "ufw")
        self.assertEqual(released, ["1.2.3.4"])
        self.assertEqual(engine.blocked, {})

    def test_unexpired_block_is_kept(self):
        clock = FakeClock()
        engine = make_engine(clock, block_enabled=True, block_duration_minutes=10)
        with mock.patch("engine.block_ip"):
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
        clock.advance(minutes=9)
        with mock.patch("engine.unblock_ip") as unblock_ip:
            engine.expire_blocks()
        unblock_ip.assert_not_called()
        self.assertIn("1.2.3.4", engine.blocked)

    def test_failed_unblock_keeps_record_for_retry(self):
        clock = FakeClock()
        engine = make_engine(clock, block_enabled=True, block_duration_minutes=1)
        with mock.patch("engine.block_ip"):
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
        clock.advance(minutes=2)
        with mock.patch("engine.unblock_ip", side_effect=FirewallError("nope")):
            self.assertEqual(engine.expire_blocks(), [])
        self.assertIn("1.2.3.4", engine.blocked)


class StatusTests(unittest.TestCase):
    def test_status_rows_show_recent_failures_and_block(self):
        clock = FakeClock()
        engine = make_engine(clock, block_enabled=True)
        with mock.patch("engine.block_ip"):
            engine.process_event(failure("1.2.3.4"))
            engine.process_event(failure("1.2.3.4"))
        engine.process_event(failure("5.6.7.8"))
        rows = engine.status_rows()
        self.assertEqual(rows[0][0], "1.2.3.4")
        self.assertEqual(rows[0][1], 2)
        self.assertIsNotNone(rows[0][2])
        self.assertEqual(rows[1], ("5.6.7.8", 1, None))


if __name__ == "__main__":
    unittest.main()
