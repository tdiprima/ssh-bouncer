import ipaddress
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
    "trailing whitespace": (
        "Failed password for root from 255.255.255.255 port 22 ssh2  ",
        {"type": "failed_password", "ip": "255.255.255.255", "user": "root"},
    ),
    "ipv6 failed password": (
        "Jan  1 12:00:00 host sshd[100]: Failed password for root from 2001:db8::1 port 22 ssh2",
        {"type": "failed_password", "ip": "2001:db8::1", "user": "root"},
    ),
    "ipv6 invalid user": (
        "Jan  1 12:00:00 host sshd[100]: Invalid user admin from fe80::1%eth0 port 22",
        {"type": "invalid_user", "ip": "fe80::1", "user": "admin"},  # zone index dropped
    ),
    "ipv6 accepted publickey": (
        "Jan  1 12:00:00 host sshd[100]: Accepted publickey for bob from 2001:db8::2 port 22 ssh2: ED25519 SHA256:x",
        {"type": "accepted_login", "ip": "2001:db8::2", "user": "bob"},
    ),
    "ipv6 uppercase and expanded is normalised": (
        "Failed password for root from 2001:0DB8:0000:0000:0000:0000:0000:0001 port 22 ssh2",
        {"type": "failed_password", "ip": "2001:db8::1", "user": "root"},
    ),
    "ipv4-mapped ipv6 collapses to ipv4": (
        "Failed password for root from ::ffff:203.0.113.5 port 22 ssh2",
        {"type": "failed_password", "ip": "203.0.113.5", "user": "root"},
    ),
    "empty invalid username": (
        "Jan  1 12:00:00 host sshd[100]: Invalid user  from 203.0.113.7 port 51000",
        {"type": "invalid_user", "ip": "203.0.113.7", "user": ""},
    ),
    "username containing spaces": (
        "Jan  1 12:00:00 host sshd[100]: Invalid user John Smith from 203.0.113.7 port 51000",
        {"type": "invalid_user", "ip": "203.0.113.7", "user": "John Smith"},
    ),
}

ATTACKER = "198.51.100.23"
VICTIM = "203.0.113.99"

# sshd copies the client-supplied username verbatim into these messages. Each username here
# carries a forged connection suffix naming VICTIM; the real client is always ATTACKER.
FORGED_USERNAMES = [
    f"alice from {VICTIM}",
    f"alice from {VICTIM} port 22 ssh2",
    f"alice from {VICTIM} port 22",
    f"invalid user alice from {VICTIM} port 22 ssh2",
    f"alice from {VICTIM} port 22 ssh2\tFailed password for bob from {VICTIM}",
    f"from {VICTIM} port 22 ssh2: RSA SHA256:abc",
    f"from 2001:db8::bad port 22 ssh2",
]


def forged_lines(username):
    prefix = "Jan  1 12:00:00 host sshd[100]: "
    return {
        "failed_password": f"{prefix}Failed password for invalid user {username} from {ATTACKER} port 4444 ssh2",
        "invalid_user": f"{prefix}Invalid user {username} from {ATTACKER} port 4444",
        "accepted_login": f"{prefix}Accepted publickey for {username} from {ATTACKER} port 4444 ssh2: RSA SHA256:k",
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
    "Failed password for root from 2001:db8::zzzz port 22 ssh2",
    "Failed password for root from 1.2.3.4 port 22 ssh2 extra trailing text",
    "Failed password for root from 1.2.3.4 port ssh2",
    "Failed password for root from 1.2.3.4",
    "Failed password for root from  port 22 ssh2",
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

    def test_forged_username_never_supplies_the_address(self):
        for username in FORGED_USERNAMES:
            for event_type, line in forged_lines(username).items():
                with self.subTest(event_type=event_type, username=username):
                    event = parse_line(line)
                    self.assertIsNotNone(event, "real client must still be attributed")
                    self.assertEqual(event["type"], event_type)
                    self.assertEqual(event["ip"], ATTACKER)
                    self.assertEqual(event["user"], username)

    def test_forged_username_reaches_threshold_against_attacker_only(self):
        config = {"threshold": 3, "window_seconds": 300, "block_enabled": True,
                  "block_duration_minutes": 60, "cooldown_minutes": 0,
                  "whitelist": [ipaddress.ip_network(ATTACKER)]}
        blocked = []
        firewall = mock.Mock(method="ufw", block=lambda ip: blocked.append(ip))
        engine = DetectionEngine(config, firewall=firewall)
        # Attacker is whitelisted here to prove a forged suffix cannot escape the whitelist either.
        for _ in range(3):
            engine.process_event(parse_line(forged_lines(FORGED_USERNAMES[1])["failed_password"]))
        self.assertEqual(blocked, [])
        self.assertNotIn(VICTIM, engine.tracker)

        engine = DetectionEngine(dict(config, whitelist=[]), firewall=firewall)
        for _ in range(3):
            engine.process_event(parse_line(forged_lines(FORGED_USERNAMES[1])["invalid_user"]))
        self.assertEqual(blocked, [ATTACKER])
        self.assertNotIn(VICTIM, engine.tracker)
        self.assertNotIn(VICTIM, engine.blocked)

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
