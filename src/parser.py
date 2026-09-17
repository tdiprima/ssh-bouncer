# Only responsible for turning log lines into structured events.
import ipaddress
import re

# Four dotted octets, not followed by another digit or dot, so "1.2.3.4.5" never yields "1.2.3.4".
IPV4_TOKEN = r"(?P<ip>(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.]))"

PATTERNS = {
    "failed_password": re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from " + IPV4_TOKEN
    ),
    "invalid_user": re.compile(
        r"Invalid user (?P<user>\S+) from " + IPV4_TOKEN
    ),
    "accepted_login": re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from " + IPV4_TOKEN
    ),
}


def is_valid_ipv4(token: str) -> bool:
    try:
        return ipaddress.ip_address(token).version == 4
    except ValueError:
        return False


def parse_line(line: str) -> dict | None:
    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if not match:
            continue
        if not is_valid_ipv4(match.group("ip")):
            return None
        return {
            "type": event_type,
            "ip": match.group("ip"),
            "user": match.groupdict().get("user", "unknown"),
        }
    return None
