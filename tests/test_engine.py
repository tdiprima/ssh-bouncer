import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from actions import FirewallError  # noqa: E402
from config import parse_whitelist  # noqa: E402
from engine import DetectionEngine  # noqa: E402
from firewall import FirewallLifecycle  # noqa: E402


class FakeFirewall(FirewallLifecycle):
    """Records calls instead of running commands. Failures are scripted per call."""

    def __init__(self, method="ufw", dry_run=False, block_errors=(), unblock_errors=(), rules=None):
        super().__init__(method, dry_run=dry_run, runner=self.forbidden)
        self.block_calls = []
        self.unblock_calls = []
        self.block_errors = list(block_errors)
        self.unblock_errors = list(unblock_errors)
        self.rules = {} if rules is None else rules

    @staticmethod
    def forbidden(cmd):
        raise AssertionError(f"real firewall command attempted: {cmd}")

    def block(self, ip):
        self.block_calls.append(ip)
        if self.block_errors:
            error = self.block_errors.pop(0)
            if error:
                raise error

    def unblock(self, ip):
        self.unblock_calls.append(ip)
        if self.unblock_errors:
            error = self.unblock_errors.pop(0)
            if error:
                raise error

    def list_rules(self):
        return dict(self.rules)


class FakeNotifier:
    def __init__(self):
        self.sent = []

    def enqueue(self, subject, body):
        self.sent.append((subject, body))
        return True


class FakeClock:
    def __init__(self):
        self.current = datetime(2026, 1, 1, 12, 0, 0)

    def now(self):
        return self.current

    def advance(self, **kwargs):
        self.current += timedelta(**kwargs)


def make_engine(clock, firewall=None, notifier=None, state_store=None, dry_run=False, **overrides):
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
    return DetectionEngine(
        config, state_store=state_store, now_fn=clock.now, firewall=firewall or FakeFirewall(),
        notifier=notifier, dry_run=dry_run,
    )


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
        notifier = FakeNotifier()
        engine = make_engine(FakeClock(), notifier=notifier)
        for _ in range(4):
            engine.process_event(failure("1.2.3.4"))
        self.assertEqual(len(notifier.sent), 1)

    def test_alert_fires_again_after_cooldown(self):
        clock = FakeClock()
        notifier = FakeNotifier()
        engine = make_engine(clock, notifier=notifier, cooldown_minutes=1)
        engine.process_event(failure("1.2.3.4"))
        engine.process_event(failure("1.2.3.4"))
        clock.advance(seconds=61)  # past cooldown (1 min) and past the 60s window
        engine.process_event(failure("1.2.3.4"))
        engine.process_event(failure("1.2.3.4"))
        self.assertEqual(len(notifier.sent), 2)

    def test_zero_cooldown_alerts_every_time(self):
        notifier = FakeNotifier()
        engine = make_engine(FakeClock(), notifier=notifier, cooldown_minutes=0)
        for _ in range(4):
            engine.process_event(failure("1.2.3.4"))
        self.assertEqual(len(notifier.sent), 3)

    def test_no_notifier_means_no_alert_delivery_and_no_crash(self):
        engine = make_engine(FakeClock(), notifier=None)
        engine.process_event(failure("1.2.3.4"))
        engine.process_event(failure("1.2.3.4"))
        self.assertIn("1.2.3.4", engine.last_alert)


def trip_threshold(engine, ip="1.2.3.4"):
    engine.process_event(failure(ip))
    engine.process_event(failure(ip))


class BlockingTests(unittest.TestCase):
    def test_firewall_failure_does_not_record_block(self):
        firewall = FakeFirewall(block_errors=[FirewallError("ufw: denied")])
        engine = make_engine(FakeClock(), firewall=firewall, block_enabled=True)
        trip_threshold(engine)
        self.assertNotIn("1.2.3.4", engine.blocked)

    def test_firewall_failure_is_retried_after_cooldown(self):
        clock = FakeClock()
        firewall = FakeFirewall(block_errors=[FirewallError("boom"), None])
        engine = make_engine(clock, firewall=firewall, block_enabled=True, cooldown_minutes=1)
        trip_threshold(engine)
        clock.advance(minutes=2)
        trip_threshold(engine)
        self.assertEqual(firewall.block_calls, ["1.2.3.4", "1.2.3.4"])
        self.assertIn("1.2.3.4", engine.blocked)

    def test_successful_block_records_expiry(self):
        clock = FakeClock()
        firewall = FakeFirewall()
        engine = make_engine(clock, firewall=firewall, block_enabled=True, block_duration_minutes=15)
        trip_threshold(engine)
        self.assertEqual(firewall.block_calls, ["1.2.3.4"])
        self.assertEqual(engine.blocked["1.2.3.4"]["expires_at"], clock.now() + timedelta(minutes=15))
        self.assertEqual(engine.blocked["1.2.3.4"]["method"], "ufw")

    def test_dry_run_never_runs_firewall_commands_but_simulates_block(self):
        runner = mock.Mock()
        firewall = FirewallLifecycle("ufw", dry_run=True, runner=runner)
        engine = make_engine(FakeClock(), firewall=firewall, dry_run=True, block_enabled=True)
        trip_threshold(engine)
        runner.assert_not_called()
        self.assertIn("1.2.3.4", engine.blocked)

    def test_dry_run_alert_body_says_simulated(self):
        engine = make_engine(FakeClock(), dry_run=True, block_enabled=True)
        self.assertIn("simulated", engine.build_alert_body("1.2.3.4", 2, True))

    def test_blocked_ip_is_not_alerted_again(self):
        firewall = FakeFirewall()
        engine = make_engine(FakeClock(), firewall=firewall, block_enabled=True, cooldown_minutes=0)
        for _ in range(5):
            engine.process_event(failure("1.2.3.4"))
        self.assertEqual(len(firewall.block_calls), 1)

    def test_state_is_saved_before_notification(self):
        order = []
        store = mock.Mock()
        store.save.side_effect = lambda *_: order.append("save") or True
        notifier = mock.Mock()
        notifier.enqueue.side_effect = lambda **_: order.append("notify") or True
        engine = make_engine(FakeClock(), state_store=store, notifier=notifier, block_enabled=True)
        trip_threshold(engine)
        self.assertEqual(order, ["save", "notify"])

    def test_failed_save_after_block_is_remembered_and_retried(self):
        store = mock.Mock()
        store.save.side_effect = [False, True]
        engine = make_engine(FakeClock(), state_store=store, block_enabled=True)
        trip_threshold(engine)
        self.assertTrue(engine.unsaved_changes)
        self.assertIn("1.2.3.4", engine.blocked)
        engine.retry_save_if_needed()
        self.assertFalse(engine.unsaved_changes)
        self.assertEqual(store.save.call_count, 2)

    def test_retry_is_a_noop_when_nothing_is_pending(self):
        store = mock.Mock()
        engine = make_engine(FakeClock(), state_store=store)
        engine.retry_save_if_needed()
        store.save.assert_not_called()


class ExpiryTests(unittest.TestCase):
    def test_expired_block_is_removed(self):
        clock = FakeClock()
        firewall = FakeFirewall()
        engine = make_engine(clock, firewall=firewall, block_enabled=True, block_duration_minutes=1)
        trip_threshold(engine)
        clock.advance(minutes=1)
        released = engine.expire_blocks()
        self.assertEqual(firewall.unblock_calls, ["1.2.3.4"])
        self.assertEqual(released, ["1.2.3.4"])
        self.assertEqual(engine.blocked, {})

    def test_unexpired_block_is_kept(self):
        clock = FakeClock()
        firewall = FakeFirewall()
        engine = make_engine(clock, firewall=firewall, block_enabled=True, block_duration_minutes=10)
        trip_threshold(engine)
        clock.advance(minutes=9)
        engine.expire_blocks()
        self.assertEqual(firewall.unblock_calls, [])
        self.assertIn("1.2.3.4", engine.blocked)

    def test_failed_unblock_keeps_record_for_retry(self):
        clock = FakeClock()
        firewall = FakeFirewall(unblock_errors=[FirewallError("nope")])
        engine = make_engine(clock, firewall=firewall, block_enabled=True, block_duration_minutes=1)
        trip_threshold(engine)
        clock.advance(minutes=2)
        self.assertEqual(engine.expire_blocks(), [])
        self.assertIn("1.2.3.4", engine.blocked)

    def test_dry_run_expiry_never_runs_firewall_commands(self):
        clock = FakeClock()
        runner = mock.Mock()
        firewall = FirewallLifecycle("ufw", dry_run=True, runner=runner)
        engine = make_engine(clock, firewall=firewall, dry_run=True, block_enabled=True, block_duration_minutes=1)
        trip_threshold(engine)
        clock.advance(minutes=2)
        self.assertEqual(engine.expire_blocks(), ["1.2.3.4"])
        runner.assert_not_called()


class RestoreTests(unittest.TestCase):
    def saved(self, clock, blocks=None, tracker=None):
        store = mock.Mock()
        store.load.return_value = {"blocks": blocks or {}, "tracker": tracker or {}}
        store.save.return_value = True
        return store

    def block_record(self, clock, minutes_left=30):
        return {
            "blocked_at": clock.now(),
            "expires_at": clock.now() + timedelta(minutes=minutes_left),
            "method": "ufw",
        }

    def test_restore_drops_record_whose_rule_is_gone(self):
        clock = FakeClock()
        store = self.saved(clock, blocks={"1.2.3.4": self.block_record(clock)})
        engine = make_engine(clock, firewall=FakeFirewall(rules={}), state_store=store, block_enabled=True)
        engine.restore_state()
        self.assertEqual(engine.blocked, {})
        store.save.assert_called()

    def test_restore_adopts_owned_rule_without_record(self):
        clock = FakeClock()
        store = self.saved(clock)
        firewall = FakeFirewall(rules={"9.9.9.9": True, "8.8.8.8": False})
        engine = make_engine(clock, firewall=firewall, state_store=store, block_enabled=True, block_duration_minutes=5)
        engine.restore_state()
        self.assertEqual(list(engine.blocked), ["9.9.9.9"])
        self.assertEqual(engine.blocked["9.9.9.9"]["expires_at"], clock.now() + timedelta(minutes=5))

    def test_restore_keeps_record_for_legacy_untagged_rule(self):
        clock = FakeClock()
        store = self.saved(clock, blocks={"1.2.3.4": self.block_record(clock)})
        engine = make_engine(clock, firewall=FakeFirewall(rules={"1.2.3.4": False}), state_store=store, block_enabled=True)
        engine.restore_state()
        self.assertIn("1.2.3.4", engine.blocked)

    def test_restore_skips_reconcile_when_listing_fails(self):
        clock = FakeClock()
        store = self.saved(clock, blocks={"1.2.3.4": self.block_record(clock)})
        firewall = FakeFirewall()
        firewall.list_rules = mock.Mock(side_effect=FirewallError("ufw missing"))
        engine = make_engine(clock, firewall=firewall, state_store=store, block_enabled=True)
        engine.restore_state()
        self.assertIn("1.2.3.4", engine.blocked)

    def test_restore_does_not_touch_firewall_when_blocking_disabled(self):
        clock = FakeClock()
        store = self.saved(clock)
        firewall = FakeFirewall()
        firewall.list_rules = mock.Mock(side_effect=AssertionError("must not list"))
        engine = make_engine(clock, firewall=firewall, state_store=store, block_enabled=False)
        engine.restore_state()

    def test_restore_prunes_stale_failure_history(self):
        clock = FakeClock()
        old = clock.now() - timedelta(hours=1)
        store = self.saved(clock, tracker={"1.2.3.4": [old], "5.6.7.8": [clock.now()]})
        engine = make_engine(clock, state_store=store)
        engine.restore_state()
        self.assertEqual(list(engine.tracker), ["5.6.7.8"])


class PruneTests(unittest.TestCase):
    def test_prune_forgets_quiet_addresses(self):
        clock = FakeClock()
        engine = make_engine(clock)
        engine.process_event(failure("1.2.3.4"))
        clock.advance(seconds=61)
        engine.prune()
        self.assertNotIn("1.2.3.4", engine.tracker)

    def test_prune_keeps_recent_failures(self):
        clock = FakeClock()
        engine = make_engine(clock)
        engine.process_event(failure("1.2.3.4"))
        clock.advance(seconds=30)
        engine.process_event(failure("5.6.7.8"))
        clock.advance(seconds=31)
        engine.prune()
        self.assertEqual(list(engine.tracker), ["5.6.7.8"])

    def test_prune_clears_elapsed_cooldowns_only(self):
        clock = FakeClock()
        engine = make_engine(clock, cooldown_minutes=10)
        engine.last_alert = {"old": clock.now() - timedelta(minutes=10), "new": clock.now()}
        engine.prune()
        self.assertEqual(list(engine.last_alert), ["new"])

    def test_prune_on_empty_engine_is_safe(self):
        engine = make_engine(FakeClock())
        engine.prune()
        self.assertEqual(dict(engine.tracker), {})

    def test_save_prunes_before_persisting(self):
        clock = FakeClock()
        store = mock.Mock()
        store.save.return_value = True
        engine = make_engine(clock, state_store=store)
        engine.process_event(failure("1.2.3.4"))
        clock.advance(seconds=61)
        engine.save_state()
        self.assertEqual(store.save.call_args[0][1], {})


class IPv6Tests(unittest.TestCase):
    ATTACKER = "2001:db8::1"

    def test_ipv6_threshold_triggers_block(self):
        clock = FakeClock()
        firewall = FakeFirewall(method="iptables")
        engine = make_engine(clock, firewall=firewall, block_enabled=True, block_method="iptables")
        engine.process_event(failure(self.ATTACKER))
        self.assertEqual(firewall.block_calls, [])
        engine.process_event(failure(self.ATTACKER))
        self.assertEqual(firewall.block_calls, [self.ATTACKER])
        self.assertIn(self.ATTACKER, engine.blocked)

    def test_ipv6_whitelist_cidr_is_honoured(self):
        engine = make_engine(FakeClock(), whitelist=parse_whitelist(["2001:db8::/32", "::1"]))
        self.assertTrue(engine.is_whitelisted("2001:db8:ffff::9"))
        self.assertTrue(engine.is_whitelisted("::1"))
        self.assertFalse(engine.is_whitelisted("2001:db9::1"))
        self.assertFalse(engine.is_whitelisted("1.2.3.4"))

    def test_ipv6_block_expires_and_unblocks(self):
        clock = FakeClock()
        firewall = FakeFirewall(method="iptables")
        engine = make_engine(clock, firewall=firewall, block_enabled=True, block_method="iptables")
        for _ in range(2):
            engine.process_event(failure(self.ATTACKER))
        clock.advance(minutes=61)
        self.assertEqual(engine.expire_blocks(), [self.ATTACKER])
        self.assertEqual(firewall.unblock_calls, [self.ATTACKER])
        self.assertNotIn(self.ATTACKER, engine.blocked)

    def test_real_lifecycle_routes_ipv6_to_ip6tables(self):
        runner = mock.Mock(return_value="")
        engine = make_engine(FakeClock(), firewall=FirewallLifecycle("iptables", runner=runner),
                             block_enabled=True, block_method="iptables")
        for _ in range(2):
            engine.process_event(failure(self.ATTACKER))
        self.assertEqual(runner.call_args[0][0][0], "ip6tables")
        self.assertIn(self.ATTACKER, runner.call_args[0][0])

    def test_ipv6_rule_is_reconciled_on_restore(self):
        clock = FakeClock()
        firewall = FakeFirewall(method="iptables", rules={self.ATTACKER: True})
        store = mock.Mock()
        store.load.return_value = {"blocks": {}, "tracker": {}}
        store.save.return_value = True
        engine = make_engine(clock, firewall=firewall, state_store=store,
                             block_enabled=True, block_method="iptables")
        engine.restore_state()
        self.assertIn(self.ATTACKER, engine.blocked)


class StatusTests(unittest.TestCase):
    def test_status_rows_show_recent_failures_and_block(self):
        clock = FakeClock()
        engine = make_engine(clock, block_enabled=True)
        trip_threshold(engine)
        engine.process_event(failure("5.6.7.8"))
        rows = engine.status_rows()
        self.assertEqual(rows[0][0], "1.2.3.4")
        self.assertEqual(rows[0][1], 2)
        self.assertIsNotNone(rows[0][2])
        self.assertEqual(rows[1], ("5.6.7.8", 1, None))


if __name__ == "__main__":
    unittest.main()
