import smtplib
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import actions  # noqa: E402
from actions import (  # noqa: E402
    RULE_TAG,
    FirewallError,
    build_block_command,
    build_legacy_unblock_command,
    build_list_command,
    build_unblock_command,
    parse_rule_listing,
    run_firewall_command,
    send_email,
)


def completed(returncode, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr=stderr)


UFW_STATUS = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] Anywhere                   DENY IN     1.2.3.4                    # sshbouncer
[ 2] 22/tcp                     ALLOW IN    Anywhere
[ 3] Anywhere                   DENY IN     5.6.7.8
[ 4] Anywhere                   DENY IN     9.9.9.9                    # somebody else
[ 5] Anywhere (v6)              DENY IN     2001:db8::1                # sshbouncer
[ 6] Anywhere                   DENY IN     Anywhere
"""

IPTABLES_STATUS = """-P INPUT ACCEPT
-A INPUT -s 1.2.3.4/32 -m comment --comment sshbouncer -j DROP
-A INPUT -s 5.6.7.8/32 -j DROP
-A INPUT -s 9.9.9.9/32 -m comment --comment "other tool" -j DROP
-A INPUT -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
"""


class FirewallCommandTests(unittest.TestCase):
    def test_success_when_exit_zero_returns_stdout(self):
        with mock.patch("actions.subprocess.run", return_value=completed(0)) as run:
            output = run_firewall_command(build_block_command("1.2.3.4", "ufw"))
        self.assertEqual(
            run.call_args[0][0],
            ["ufw", "insert", "1", "deny", "from", "1.2.3.4", "to", "any", "comment", RULE_TAG],
        )
        self.assertEqual(output, "")

    def test_nonzero_exit_raises(self):
        with mock.patch("actions.subprocess.run", return_value=completed(1, "ERROR: bad")):
            with self.assertRaises(FirewallError) as ctx:
                run_firewall_command(build_block_command("1.2.3.4", "iptables"))
        self.assertIn("bad", str(ctx.exception))

    def test_missing_binary_raises(self):
        with mock.patch("actions.subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(FirewallError):
                run_firewall_command(["ufw"])

    def test_timeout_raises(self):
        with mock.patch("actions.subprocess.run", side_effect=subprocess.TimeoutExpired("ufw", 30)):
            with self.assertRaises(FirewallError):
                run_firewall_command(["ufw"])

    def test_unknown_method_raises(self):
        for builder in (build_block_command, build_unblock_command, build_legacy_unblock_command):
            with self.assertRaises(ValueError):
                builder("1.2.3.4", "pf")
        with self.assertRaises(ValueError):
            build_list_command("pf")
        with self.assertRaises(ValueError):
            parse_rule_listing("", "pf")

    def test_ip_is_passed_as_argument_not_shell(self):
        hostile = "1.2.3.4; rm -rf /"
        with mock.patch("actions.subprocess.run", return_value=completed(0)) as run:
            run_firewall_command(build_block_command(hostile, "iptables"))
        self.assertIn(hostile, run.call_args[0][0])
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_iptables_rules_are_tagged(self):
        cmd = build_block_command("1.2.3.4", "iptables")
        self.assertEqual(cmd[cmd.index("--comment") + 1], RULE_TAG)
        self.assertEqual(
            build_unblock_command("1.2.3.4", "iptables"),
            ["iptables", "-D", "INPUT", "-s", "1.2.3.4", "-m", "comment", "--comment", RULE_TAG, "-j", "DROP"],
        )

    def test_legacy_unblock_has_no_tag(self):
        self.assertEqual(
            build_legacy_unblock_command("1.2.3.4", "iptables"),
            ["iptables", "-D", "INPUT", "-s", "1.2.3.4", "-j", "DROP"],
        )
        self.assertNotIn("comment", build_legacy_unblock_command("1.2.3.4", "ufw"))


class RuleListingParserTests(unittest.TestCase):
    def test_ufw_listing_marks_owned_and_foreign_rules(self):
        rules = parse_rule_listing(UFW_STATUS, "ufw")
        self.assertEqual(
            rules,
            {"1.2.3.4": True, "5.6.7.8": False, "9.9.9.9": False, "2001:db8::1": True},
        )

    def test_iptables_listing_marks_owned_and_foreign_rules(self):
        rules = parse_rule_listing(IPTABLES_STATUS, "iptables")
        self.assertEqual(rules, {"1.2.3.4": True, "5.6.7.8": False, "9.9.9.9": False})

    def test_empty_and_inactive_listings_give_no_rules(self):
        self.assertEqual(parse_rule_listing("", "ufw"), {})
        self.assertEqual(parse_rule_listing("Status: inactive\n", "ufw"), {})
        self.assertEqual(parse_rule_listing("", "iptables"), {})

    def test_garbage_lines_are_ignored(self):
        self.assertEqual(parse_rule_listing("[ 1] DENY\n\x00junk\n", "ufw"), {})
        self.assertEqual(parse_rule_listing("-A INPUT -s 'unterminated -j DROP\n", "iptables"), {})

    def test_large_listing_is_handled(self):
        lines = [f"-A INPUT -s 10.{i // 256}.{i % 256}.1/32 -m comment --comment sshbouncer -j DROP"
                 for i in range(10000)]
        rules = parse_rule_listing("\n".join(lines), "iptables")
        self.assertEqual(len(rules), 10000)
        self.assertTrue(all(rules.values()))


class SendEmailTests(unittest.TestCase):
    def config(self, **overrides):
        base = {
            "email_enabled": True,
            "email_to": "admin@example.com",
            "email_from": "",
            "smtp_server": "localhost",
            "smtp_port": 25,
            "smtp_tls": False,
            "smtp_user": "",
            "smtp_pass": "",
        }
        base.update(overrides)
        return base

    def test_disabled_returns_false_without_connecting(self):
        with mock.patch("actions.smtplib.SMTP") as smtp:
            self.assertFalse(send_email("s", "b", self.config(email_enabled=False)))
        smtp.assert_not_called()

    def test_missing_email_from_uses_hostname_fallback(self):
        with mock.patch("actions.smtplib.SMTP") as smtp, \
                mock.patch("actions.socket.gethostname", return_value="box"):
            server = smtp.return_value.__enter__.return_value
            self.assertTrue(send_email("s", "b", self.config()))
        sender = server.sendmail.call_args[0][0]
        self.assertEqual(sender, "sshbouncer@box")

    def test_config_without_email_from_key_does_not_raise(self):
        config = self.config()
        del config["email_from"]
        with mock.patch("actions.smtplib.SMTP"):
            self.assertTrue(send_email("s", "b", config))

    def test_smtp_timeout_is_set(self):
        with mock.patch("actions.smtplib.SMTP") as smtp:
            send_email("s", "b", self.config())
        self.assertEqual(smtp.call_args.kwargs["timeout"], actions.SMTP_TIMEOUT_SECONDS)

    def test_smtp_error_is_contained(self):
        with mock.patch("actions.smtplib.SMTP", side_effect=smtplib.SMTPConnectError(421, "busy")):
            self.assertFalse(send_email("s", "b", self.config()))

    def test_network_error_is_contained(self):
        with mock.patch("actions.smtplib.SMTP", side_effect=ConnectionRefusedError()):
            self.assertFalse(send_email("s", "b", self.config()))

    def test_tls_and_login_used_when_configured(self):
        with mock.patch("actions.smtplib.SMTP") as smtp:
            server = smtp.return_value.__enter__.return_value
            send_email("s", "b", self.config(smtp_tls=True, smtp_user="u", smtp_pass="p"))
        server.starttls.assert_called_once()
        server.login.assert_called_once_with("u", "p")


if __name__ == "__main__":
    unittest.main()
