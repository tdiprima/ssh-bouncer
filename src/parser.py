# Only responsible for turning log lines into structured events.
#
# sshd interpolates the client-supplied username into these messages, so a username can itself
# contain " from 203.0.113.99 port 22 ssh2". The genuine connection suffix is always the LAST
# "from <addr> port <n>" on the line and sshd appends nothing after it that an attacker controls.
# Every pattern therefore takes the username greedily and anchors the address to the end of line.
import ipaddress
import re

# Address between the final " from " and " port <n>". Validated with ipaddress afterwards.
CONNECTION_SUFFIX = r" from (?P<ip>\S+) port (?P<port>\d+)"

PATTERNS = {
    "failed_password": re.compile(
        r"Failed password for (?:invalid user )?(?P<user>.*)" + CONNECTION_SUFFIX + r" ssh2\s*$"
    ),
    "invalid_user": re.compile(
        r"Invalid user (?P<user>.*)" + CONNECTION_SUFFIX + r"\s*$"
    ),
    "accepted_login": re.compile(
        r"Accepted (?:password|publickey) for (?P<user>.*)" + CONNECTION_SUFFIX + r" ssh2(?::.*)?$"
    ),
}


def normalize_address(token: str) -> str | None:
    """Canonical text form of an IPv4 or IPv6 address, or None when the token is not one.

    IPv4-mapped IPv6 (::ffff:1.2.3.4) collapses to the IPv4 form and a zone index (fe80::1%eth0)
    is dropped, so tracker, whitelist, and firewall rules all key on one spelling per client.
    """
    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        return None
    if address.version == 6:
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        if address.scope_id is not None:
            address = ipaddress.IPv6Address(int(address))
    return str(address)


def parse_line(line: str) -> dict | None:
    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if not match:
            continue
        ip = normalize_address(match.group("ip"))
        if ip is None:
            return None
        return {"type": event_type, "ip": ip, "user": match.group("user")}
    return None
