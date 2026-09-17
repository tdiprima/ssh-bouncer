import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from actions import RULE_TAG, FirewallError  # noqa: E402
from firewall import FirewallLifecycle, reconcile_blocks  # noqa: E402

NOW = datetime(2026, 1, 1, 12, 0, 0)
HOUR = timedelta(hours=1)


def record(method="ufw"):
    return {"blocked_at": NOW, "expires_at": NOW + HOUR, "method": method}


class ReconcileTests(unittest.TestCase):
    def test_empty_inputs_give_empty_result(self):
        result = reconcile_blocks({}, {}, "ufw", NOW, HOUR)
        self.assertEqual(result, {"blocks": {}, "adopted": [], "dropped": []})

    def test_recorded_and_present_is_kept_unchanged(self):
        result = reconcile_blocks({"1.2.3.4": record()}, {"1.2.3.4": True}, "ufw", NOW, HOUR)
        self.assertEqual(result["blocks"], {"1.2.3.4": record()})
        self.assertEqual(result["adopted"], [])
        self.assertEqual(result["dropped"], [])

    def test_recorded_but_missing_is_dropped(self):
        result = reconcile_blocks({"1.2.3.4": record()}, {}, "ufw", NOW, HOUR)
        self.assertEqual(result["blocks"], {})
        self.assertEqual(result["dropped"], ["1.2.3.4"])

    def test_owned_rule_without_record_is_adopted_with_fresh_expiry(self):
        result = reconcile_blocks({}, {"9.9.9.9": True}, "iptables", NOW, HOUR)
        self.assertEqual(result["adopted"], ["9.9.9.9"])
        self.assertEqual(
            result["blocks"]["9.9.9.9"],
            {"blocked_at": NOW, "expires_at": NOW + HOUR, "method": "iptables"},
        )

    def test_foreign_rule_without_record_is_ignored(self):
        result = reconcile_blocks({}, {"8.8.8.8": False}, "ufw", NOW, HOUR)
        self.assertEqual(result["blocks"], {})

    def test_legacy_untagged_rule_with_record_is_kept(self):
        result = reconcile_blocks({"1.2.3.4": record()}, {"1.2.3.4": False}, "ufw", NOW, HOUR)
        self.assertIn("1.2.3.4", result["blocks"])

    def test_inputs_are_not_mutated(self):
        recorded = {"1.2.3.4": record()}
        live = {"9.9.9.9": True}
        reconcile_blocks(recorded, live, "ufw", NOW, HOUR)
        self.assertEqual(recorded, {"1.2.3.4": record()})
        self.assertEqual(live, {"9.9.9.9": True})

    def test_many_rules(self):
        live = {f"10.0.{i // 256}.{i % 256}": True for i in range(5000)}
        result = reconcile_blocks({}, live, "ufw", NOW, HOUR)
        self.assertEqual(len(result["adopted"]), 5000)


class LifecycleTests(unittest.TestCase):
    def test_block_runs_tagged_command(self):
        runner = mock.Mock(return_value="")
        FirewallLifecycle("ufw", runner=runner).block("1.2.3.4")
        self.assertIn(RULE_TAG, runner.call_args[0][0])

    def test_block_error_propagates(self):
        runner = mock.Mock(side_effect=FirewallError("no"))
        with self.assertRaises(FirewallError):
            FirewallLifecycle("ufw", runner=runner).block("1.2.3.4")

    def test_unblock_falls_back_to_legacy_spec(self):
        runner = mock.Mock(side_effect=[FirewallError("no such rule"), ""])
        FirewallLifecycle("iptables", runner=runner).unblock("1.2.3.4")
        self.assertEqual(runner.call_count, 2)
        self.assertNotIn("comment", runner.call_args_list[1][0][0])

    def test_unblock_raises_when_both_specs_fail(self):
        runner = mock.Mock(side_effect=FirewallError("no"))
        with self.assertRaises(FirewallError):
            FirewallLifecycle("iptables", runner=runner).unblock("1.2.3.4")

    def test_dry_run_runs_nothing_for_any_operation(self):
        runner = mock.Mock()
        firewall = FirewallLifecycle("ufw", dry_run=True, runner=runner)
        firewall.block("1.2.3.4")
        firewall.unblock("1.2.3.4")
        self.assertEqual(firewall.list_rules(), {})
        self.assertEqual(firewall.remove_owned_rules(), ([], []))
        runner.assert_not_called()

    def test_list_rules_parses_runner_output(self):
        runner = mock.Mock(return_value="-A INPUT -s 1.2.3.4/32 -m comment --comment sshbouncer -j DROP\n")
        self.assertEqual(FirewallLifecycle("iptables", runner=runner).list_rules(), {"1.2.3.4": True})

    def test_remove_owned_rules_skips_foreign_and_reports_failures(self):
        listing = (
            "-A INPUT -s 1.2.3.4/32 -m comment --comment sshbouncer -j DROP\n"
            "-A INPUT -s 5.5.5.5/32 -m comment --comment sshbouncer -j DROP\n"
            "-A INPUT -s 8.8.8.8/32 -j DROP\n"
        )
        # list, delete 1.2.3.4 ok, delete 5.5.5.5 tagged fails, legacy fails
        runner = mock.Mock(side_effect=[listing, "", FirewallError("x"), FirewallError("y")])
        removed, failed = FirewallLifecycle("iptables", runner=runner).remove_owned_rules()
        self.assertEqual(removed, ["1.2.3.4"])
        self.assertEqual(failed, ["5.5.5.5"])
        deleted_ips = [call[0][0][4] for call in runner.call_args_list[1:]]
        self.assertNotIn("8.8.8.8", deleted_ips)

    def test_remove_owned_rules_when_listing_fails(self):
        runner = mock.Mock(side_effect=FirewallError("ufw: command not found"))
        self.assertEqual(FirewallLifecycle("ufw", runner=runner).remove_owned_rules(), ([], []))


if __name__ == "__main__":
    unittest.main()
