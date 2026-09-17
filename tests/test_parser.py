import sys
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from engine import DetectionEngine  # noqa: E402
from parser import parse_line  # noqa: E402

SUPPORTED_LINES = {
    "failed password": (
        "Jan  1 12:00:00 host sshd[100]: Failed password for root from 1.2.3.4 port 22 ssh2",
        {"type": "failed_password", "ip": "1.2.3.4", "user": "root"},
    ),
    "failed password, invalid user": (
        "Jan  1 12:00:00 host sshd[100]: Failed password for invalid user admin from 10.0.0.9 port 4242 ssh2",
        {"type": "failed_password", "ip": "10.0.0.9", "user": "admin"},
    ),
    "standalone invalid user": (
        "Jan  1 12:00:00 host sshd[100]: Invalid user oracle from 203.0.113.7 port 51000",
        {"type": "invalid_user", "ip": "203.0.113.7", "user": "oracle"},
    ),
    "accepted password": (
        "Jan  1 12:00:00 host sshd[100]: Accepted password for alice from 192.168.1.20 port 22 ssh2",
        {"type": "accepted_login", "ip": "192.168.1.20", "user": "alice"},
    ),
    "accepted publickey": (
        "Jan  1 12:00:00 host sshd[100]: Accepted publickey for bob from 192.168.1.21 port 22 ssh2: RSA SHA256:abc",
        {"type": "accepted_login", "ip": "192.168.1.21", "user": "bob"},
    ),
    "no port suffix": (
        "Failed password for root from 255.255.255.255",
        {"type": "failed_password", "ip": "255.255.255.255", "user": "root"},
    ),
}

UNRELATED_LINES = [
    "",
    "Jan  1 12:00:00 host sshd[100]: Connection closed by 1.2.3.4 port 22 [preauth]",
    "Jan  1 12:00:00 host sshd[100]: pam_unix(sshd:auth): authentication failure; rhost=1.2.3.4",
    "Jan  1 12:00:00 host sshd[100]: Disconnected from invalid user admin 1.2.3.4 port 22",
    "Jan  1 12:00:00 host CRON[5]: session opened for user root",
]

MALFORMED_ADDRESS_LINES = [
    "Failed password for root from 1.2.3.4.5 port 22 ssh2",
    "Failed password for root from 1.2.3 port 22 ssh2",
    "Failed password for root from 1.2.3. port 22 ssh2",
    "Failed password for root from .1.2.3.4 port 22 ssh2",
    "Failed password for root from 999.1.1.1 port 22 ssh2",
    "Failed password for root from 1.2.3.4x port 22 ssh2",
    "Invalid user admin from 1.2.3.4.5 port 22",
    "Accepted publickey for bob from 1.2.3.4.5 port 22 ssh2",
    "Failed password for root from 2001:db8::1 port 22 ssh2",
]


class ParseSupportedEventsTests(unittest.TestCase):
    def test_parse_supported_events(self):
        for name, (line, expected) in SUPPORTED_LINES.items():
            with self.subTest(name):
                self.assertEqual(parse_line(line), expected)

    def test_unrelated_lines_yield_no_event(self):
        for line in UNRELATED_LINES:
            with self.subTest(line=line):
                self.assertIsNone(parse_line(line))

    def test_user_with_hostile_characters_is_kept_verbatim(self):
        line = "Failed password for invalid user ';drop from 1.2.3.4 port 22 ssh2"
        self.assertEqual(parse_line(line), {"type": "failed_password", "ip": "1.2.3.4", "user": "';drop"})

    def test_oversized_line_is_handled(self):
        line = "Failed password for " + ("a" * 100_000) + " from 1.2.3.4 port 22 ssh2"
        self.assertEqual(parse_line(line)["ip"], "1.2.3.4")


class RejectMalformedAddressTests(unittest.TestCase):
    def test_reject_malformed_address_tokens(self):
        for line in MALFORMED_ADDRESS_LINES:
            with self.subTest(line=line):
                self.assertIsNone(parse_line(line))

    def test_malformed_address_never_reaches_tracker_or_block(self):
        config = {"threshold": 1, "window_seconds": 300, "block_enabled": True,
                  "block_duration_minutes": 60, "cooldown_minutes": 0, "whitelist": []}
        blocked = []
        firewall = mock.Mock(method="ufw", block=lambda ip: blocked.append(ip))
        engine = DetectionEngine(config, firewall=firewall)
        for line in MALFORMED_ADDRESS_LINES:
            event = parse_line(line)
            if event:
                engine.process_event(event)
        self.assertEqual(dict(engine.tracker), {})
        self.assertEqual(engine.blocked, {})
        self.assertEqual(blocked, [])


if __name__ == "__main__":
    unittest.main()
