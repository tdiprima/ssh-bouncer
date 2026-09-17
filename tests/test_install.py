import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

import install  # noqa: E402
from actions import FirewallError  # noqa: E402
from firewall import FirewallLifecycle  # noqa: E402

TAGGED_RULE = "-A INPUT -s 1.2.3.4/32 -m comment --comment sshbouncer -j DROP\n"
STATE_BYTES = json.dumps({"version": 1, "blocks": {"1.2.3.4": {
    "blocked_at": "2026-01-01T00:00:00", "expires_at": "2026-01-01T01:00:00", "method": "iptables"}},
    "tracker": {}}).encode()


def lifecycle_with_runner(runner):
    """Stand-in for install.load_firewall_lifecycle: real FirewallLifecycle, scripted commands."""
    return lambda method: FirewallLifecycle(method, runner=runner)


def only_iptables(name):
    return "/usr/sbin/iptables" if name == "iptables" else None


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        root = Path(self.tempdir.name)
        self.state_dir = root / "state"
        self.install_dir = root / "opt"
        self.systemd_file = root / "sshbouncer.service"
        self.state_dir.mkdir()
        self.install_dir.mkdir()
        (self.state_dir / "state.json").write_bytes(STATE_BYTES)
        (self.install_dir / "sshbouncer.py").write_text("# app")
        self.systemd_file.write_text("[Unit]")

        self.systemctl = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        patches = [
            mock.patch.object(install, "STATE_DIR", self.state_dir),
            mock.patch.object(install, "INSTALL_DIR", self.install_dir),
            mock.patch.object(install, "SYSTEMD_FILE", self.systemd_file),
            mock.patch.object(install.os, "geteuid", return_value=0),
            mock.patch.object(install.subprocess, "run", self.systemctl),
            mock.patch.object(install.shutil, "which", only_iptables),
            mock.patch("sys.stderr", new_callable=io.StringIO),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def run_uninstall_with(self, runner):
        with mock.patch.object(install, "load_firewall_lifecycle", return_value=lifecycle_with_runner(runner)):
            install.run_uninstall()
        return runner

    def assert_state_preserved(self):
        self.assertTrue(self.state_dir.is_dir())
        self.assertEqual((self.state_dir / "state.json").read_bytes(), STATE_BYTES)

    def assert_program_files_removed(self):
        self.assertFalse(self.install_dir.exists())
        self.assertFalse(self.systemd_file.exists())

    def test_uninstall_preserves_state_on_listing_failure(self):
        runner = self.run_uninstall_with(mock.Mock(side_effect=FirewallError("iptables: permission denied")))
        runner.assert_called_once()  # listing only; nothing was deleted
        self.assert_state_preserved()
        self.assert_program_files_removed()
        self.assertIn("could not list iptables rules", sys.stderr.getvalue())
        self.assertIn(str(self.state_dir), sys.stderr.getvalue())

    def test_uninstall_preserves_state_on_deletion_failure(self):
        # list ok, tagged delete fails, legacy delete fails
        runner = mock.Mock(side_effect=[TAGGED_RULE, FirewallError("tagged"), FirewallError("legacy")])
        self.run_uninstall_with(runner)
        self.assertEqual(runner.call_count, 3)
        self.assert_state_preserved()
        self.assert_program_files_removed()
        self.assertIn("could not remove iptables rule for 1.2.3.4", sys.stderr.getvalue())

    def test_uninstall_removes_state_after_clean_rule_removal(self):
        runner = mock.Mock(side_effect=[TAGGED_RULE, ""])
        self.run_uninstall_with(runner)
        self.assertFalse(self.state_dir.exists())
        self.assert_program_files_removed()
        self.assertEqual(sys.stderr.getvalue(), "")

    def test_uninstall_removes_state_when_no_owned_rules_exist(self):
        foreign_only = "-A INPUT -s 8.8.8.8/32 -j DROP\n"
        runner = mock.Mock(return_value=foreign_only)
        self.run_uninstall_with(runner)
        runner.assert_called_once()
        self.assertFalse(self.state_dir.exists())

    def test_uninstall_refuses_without_root(self):
        with mock.patch.object(install.os, "geteuid", return_value=1000):
            with self.assertRaises(SystemExit):
                install.run_uninstall()
        self.assert_state_preserved()
        self.assertTrue(self.install_dir.exists())


class RemoveFirewallRulesTests(unittest.TestCase):
    def setUp(self):
        for patch in (
            mock.patch.object(install.shutil, "which", only_iptables),
            mock.patch("sys.stderr", new_callable=io.StringIO),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def remove_with(self, runner):
        with mock.patch.object(install, "load_firewall_lifecycle", return_value=lifecycle_with_runner(runner)):
            return install.remove_firewall_rules()

    def test_listing_failure_reports_incomplete(self):
        self.assertFalse(self.remove_with(mock.Mock(side_effect=FirewallError("boom"))))

    def test_deletion_failure_reports_incomplete(self):
        self.assertFalse(self.remove_with(mock.Mock(side_effect=[TAGGED_RULE, FirewallError("a"), FirewallError("b")])))

    def test_clean_removal_reports_complete(self):
        self.assertTrue(self.remove_with(mock.Mock(side_effect=[TAGGED_RULE, ""])))

    def test_no_firewall_tools_installed_reports_complete(self):
        runner = mock.Mock()
        with mock.patch.object(install.shutil, "which", return_value=None):
            self.assertTrue(self.remove_with(runner))
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
