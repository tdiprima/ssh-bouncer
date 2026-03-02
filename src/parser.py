# Only responsible for turning log lines into structured events.
import re

PATTERNS = {
    "failed_password": re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "invalid_user": re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "accepted_login": re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
}

def parse_line(line: str) -> dict | None:
    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if match:
            return {
                "type": event_type,
                "ip": match.group("ip"),
                "user": match.groupdict().get("user", "unknown"),
            }
    return None
