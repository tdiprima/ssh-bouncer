import smtplib
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import actions  # noqa: E402
from actions import FirewallError, block_ip, send_email, unblock_ip  # noqa: E402


def completed(returncode, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr=stderr)


class BlockIpTests(unittest.TestCase):
    def test_success_when_exit_zero(self):
        with mock.patch("actions.subprocess.run", return_value=completed(0)) as run:
            block_ip("1.2.3.4", "ufw")
        self.assertEqual(run.call_args[0][0], ["ufw", "insert", "1", "deny", "from", "1.2.3.4", "to", "any"])

    def test_nonzero_exit_raises(self):
        with mock.patch("actions.subprocess.run", return_value=completed(1, "ERROR: bad")):
            with self.assertRaises(FirewallError) as ctx:
                block_ip("1.2.3.4", "iptables")
        self.assertIn("bad", str(ctx.exception))

    def test_missing_binary_raises(self):
        with mock.patch("actions.subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(FirewallError):
                block_ip("1.2.3.4", "ufw")

    def test_timeout_raises(self):
        with mock.patch("actions.subprocess.run", side_effect=subprocess.TimeoutExpired("ufw", 30)):
            with self.assertRaises(FirewallError):
                block_ip("1.2.3.4", "ufw")

    def test_unknown_method_raises_before_running_anything(self):
        with mock.patch("actions.subprocess.run") as run:
            with self.assertRaises(ValueError):
                block_ip("1.2.3.4", "pf")
        run.assert_not_called()

    def test_ip_is_passed_as_argument_not_shell(self):
        hostile = "1.2.3.4; rm -rf /"
        with mock.patch("actions.subprocess.run", return_value=completed(0)) as run:
            block_ip(hostile, "iptables")
        self.assertIn(hostile, run.call_args[0][0])
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_unblock_uses_delete_command(self):
        with mock.patch("actions.subprocess.run", return_value=completed(0)) as run:
            unblock_ip("1.2.3.4", "iptables")
        self.assertEqual(run.call_args[0][0], ["iptables", "-D", "INPUT", "-s", "1.2.3.4", "-j", "DROP"])


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
