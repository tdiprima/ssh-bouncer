# 🛡️ SSHGuardian — Real-Time SSH Intrusion Detection for Linux

SSHGuardian is a lightweight, real-time intrusion detection tool for monitoring SSH authentication activity on Ubuntu/Linux servers.

It focuses on **early visibility** — detecting failed login bursts and suspicious SSH activity *as it starts*, then sending immediate (optional) email alerts. Optional IP blocking via UFW or iptables can be enabled, but **visibility always comes first**.

Designed for VPS, cloud servers, and home labs where SSH is exposed to the internet and operators want a clear signal before a full security stack is deployed.

---

## Features

| Feature | Description |
|---|---|
| **Real-time monitoring** | Tails `/var/log/auth.log` live — detects events within seconds |
| **Brute-force detection** | Configurable threshold (e.g. 5 failures in 300s) per source IP |
| **Email alerts** | Immediate SMTP notifications with full threat details |
| **Auto IP blocking** | Optional — block via UFW or iptables with auto-expiry |
| **Whitelist** | Protect known IPs from ever being blocked or alerted |
| **Log rotation aware** | Handles `logrotate` seamlessly (inode + size detection) |
| **State persistence** | Survives restarts — tracked IPs and blocks persist to disk |
| **Systemd service** | Runs as a daemon, starts on boot, restarts on failure |
| **Live status** | Send `SIGUSR1` or run `--status` for a threat summary table |
| **Dry-run mode** | Full monitoring with no blocking — safe to test |
| **Zero dependencies** | Python 3 standard library only — nothing to install |

---

## Quick Start

```bash
# 1. Clone or copy the project
git clone https://github.com/tdiprima/SSH-Guardian
cd SSH-Guardian

# 2. Run the interactive installer
sudo python3 install.py

# 3. Start the service
sudo systemctl start sshguardian
sudo systemctl enable sshguardian

# 4. Watch it work
sudo journalctl -u sshguardian -f
```

---

## Project Structure

```
sshguardian/
├── sshguardian.py        # Main monitoring daemon
├── install.py            # Interactive installer / uninstaller
├── test_sim.py           # Attack simulation + self-test
├── config.example.json   # Example configuration
└── README.md             # This file
```

---

## Installation (Detailed)

### Prerequisites

- **Ubuntu 20.04+** (also works on Debian, but designed for Ubuntu)
- **Python 3.8+** (pre-installed on Ubuntu)
- **Root access** (reads auth logs, manages firewall)
- **SSH server running** (`sshd`)

### Interactive Install

```bash
sudo python3 install.py
```

The installer will prompt you for:

1. **Threshold** — how many failed attempts trigger an alert (default: 5)
2. **Detection window** — time window in seconds (default: 300)
3. **Whitelist** — IPs to never alert/block on (default: 127.0.0.1)
4. **Blocking** — enable/disable automatic IP blocking (default: off)
5. **Email alerts** — SMTP configuration for notifications (default: off)

Files are installed to:

| Path | Purpose |
|---|---|
| `/opt/sshguardian/sshguardian.py` | Main script |
| `/etc/sshguardian/config.json` | Configuration (mode 600) |
| `/var/log/sshguardian.log` | Application log |
| `/var/lib/sshguardian/state.json` | Persistent state |
| `/etc/systemd/system/sshguardian.service` | Systemd unit |

### Uninstall

```bash
sudo python3 install.py --uninstall
```

This stops the service, removes program files, and keeps your config/logs (tells you how to remove those too).

---

## Configuration

Edit `/etc/sshguardian/config.json` (created by the installer) or copy and edit `config.example.json`.

### All Settings

| Setting | Type | Default | Description |
|---|---|---|---|
| `auth_log` | string | `"auto"` | Path to auth log. `"auto"` tries `/var/log/auth.log` then `/var/log/secure` |
| `threshold` | int | `5` | Failed attempts before alert fires |
| `window_seconds` | int | `300` | Sliding time window (seconds) for counting failures |
| `block_enabled` | bool | `false` | Auto-block offending IPs |
| `block_method` | string | `"ufw"` | `"ufw"` or `"iptables"` |
| `block_duration_minutes` | int | `60` | How long blocks last before auto-expiry |
| `email_enabled` | bool | `false` | Send email alerts |
| `email_to` | string | `""` | Recipient address |
| `email_from` | string | `""` | Sender address (auto-generated if blank) |
| `smtp_server` | string | `"localhost"` | SMTP server hostname |
| `smtp_port` | int | `25` | SMTP port |
| `smtp_tls` | bool | `false` | Use STARTTLS |
| `smtp_user` | string | `""` | SMTP auth username (blank = no auth) |
| `smtp_pass` | string | `""` | SMTP auth password |
| `whitelist` | list | `["127.0.0.1"]` | IPs that are never alerted or blocked |
| `log_file` | string | `"/var/log/sshguardian.log"` | SSHGuardian's own log |
| `log_level` | string | `"INFO"` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `cooldown_minutes` | int | `10` | Minimum time between repeat alerts for same IP |

### Example: Alert-Only Mode (Recommended Start)

```json
{
    "threshold": 5,
    "window_seconds": 300,
    "block_enabled": false,
    "email_enabled": true,
    "email_to": "admin@example.com",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_tls": true,
    "smtp_user": "alerts@example.com",
    "smtp_pass": "app-password-here",
    "whitelist": ["127.0.0.1", "YOUR.STATIC.IP.HERE"]
}
```

### Example: Full Blocking Mode

```json
{
    "threshold": 5,
    "window_seconds": 300,
    "block_enabled": true,
    "block_method": "ufw",
    "block_duration_minutes": 120,
    "whitelist": ["127.0.0.1", "YOUR.STATIC.IP.HERE"],
    "email_enabled": true,
    "email_to": "admin@example.com"
}
```

> ⚠️ **Always whitelist your own IP before enabling blocking.** If you lock yourself out, you'll need console/out-of-band access to recover.

After editing config, restart the service:

```bash
sudo systemctl restart sshguardian
```

---

## Usage

### Service Management

```bash
# Start / stop / restart
sudo systemctl start sshguardian
sudo systemctl stop sshguardian
sudo systemctl restart sshguardian

# Enable on boot
sudo systemctl enable sshguardian

# Check service status
sudo systemctl status sshguardian
```

### Viewing Logs

```bash
# Live follow (systemd journal)
sudo journalctl -u sshguardian -f

# SSHGuardian's own log file
sudo tail -f /var/log/sshguardian.log
```

### Threat Status Table

View a summary of all tracked IPs, fail counts, and block status:

```bash
# Static snapshot (can run anytime)
sudo python3 /opt/sshguardian/sshguardian.py --status
```

```bash
# Live status while running (send SIGUSR1)
sudo kill -USR1 $(pgrep -f sshguardian.py)
```

### Dry-Run Mode

Full monitoring with no blocking actions taken — safe for testing:

```bash
sudo python3 /opt/sshguardian/sshguardian.py --dry-run
```

### Running Directly (Without Systemd)

```bash
# With default config location
sudo python3 sshguardian.py

# With custom config
sudo python3 sshguardian.py -c /path/to/config.json

# Dry-run + custom config
sudo python3 sshguardian.py -c /path/to/config.json --dry-run
```

---

## Testing

SSHGuardian includes a simulation script that generates realistic SSH log entries so you can verify detection works before deploying.

### Self-Test (Recommended)

Runs SSHGuardian and the simulator together, then reports pass/fail:

```bash
sudo python3 test_sim.py --self-test
```

Expected output:

```
═══ SSHGuardian Self-Test ═══

  Starting SSHGuardian (dry-run)...

═══ SSHGuardian Test Simulation ═══

  ▸ Scenario 1: Slow probe (below threshold)
      FAIL  admin@10.0.0.50
      FAIL  root@10.0.0.50

  ▸ Scenario 2: Brute-force burst (exceeds threshold)
      FAIL  root@192.168.1.100
      FAIL  admin@192.168.1.100
      FAIL  ubuntu@192.168.1.100
      FAIL  test@192.168.1.100
      FAIL  deploy@192.168.1.100
  ...

  Results:
  ✓ PASS — 3 alerts detected (expected ≥ 2)
  ✓ PASS — Whitelisted IP (127.0.0.1) was not alerted
  ✓ PASS — Legitimate login was logged
```

### Two-Terminal Test

If you prefer to watch the detection happen live:

```bash
# Terminal 1 — start SSHGuardian on the fake log
sudo python3 sshguardian.py -c /tmp/sshguardian_test_config.json --dry-run

# Terminal 2 — generate fake attacks
python3 test_sim.py
```

(Run `test_sim.py` without `--self-test` first to generate the test config file, or create it manually.)

---

## How It Works

```
  /var/log/auth.log
         │
         ▼
  ┌──────────────┐     ┌──────────────────┐
  │  tail_follow  │────▶│  parse_line()    │
  │  (real-time)  │     │  regex matching  │
  └──────────────┘     └────────┬─────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │  DetectionEngine      │
                    │  • per-IP tracking    │
                    │  • sliding window     │
                    │  • threshold check    │
                    └───────────┬───────────┘
                                │
                     threshold exceeded?
                       ┌───────┴───────┐
                       ▼               ▼
                 ┌──────────┐   ┌──────────┐
                 │ 📧 Email │   │ 🔒 Block │
                 │  Alert   │   │  IP      │
                 └──────────┘   └──────────┘
                                      │
                                 auto-expire
                                 after N min
```

1. **Tail** — Follows the auth log in real-time (handles log rotation)
2. **Parse** — Regex matches against known SSH failure patterns
3. **Track** — Per-IP sliding window counts failures
4. **Alert** — When threshold is exceeded: log, email, and optionally block
5. **Expire** — Blocks auto-remove after configured duration
6. **Persist** — State survives service restarts

### Detected Events

| Pattern | Example Log Line |
|---|---|
| Failed password | `Failed password for invalid user admin from 1.2.3.4` |
| Invalid user | `Invalid user test from 1.2.3.4` |
| Pre-auth disconnect | `Connection closed by authenticating user root 1.2.3.4` |
| Too many auth failures | `Disconnecting authenticating user root 1.2.3.4 ... Too many authentication failures` |
| Accepted login (info) | `Accepted password for deploy from 10.0.0.1` |

---

## Real-World Workflow

When SSHGuardian fires an alert, the recommended workflow is:

1. **Receive the alert** (email or journal log)
2. **Capture system state** immediately (use a tool like your Incident Snapshot tool to preserve evidence before logs rotate)
3. **Investigate** — check the threat table (`--status`), review auth.log, identify patterns
4. **Decide** — escalate, permanently block, or dismiss
5. **Harden** — update firewall rules, disable password auth, add to permanent blocklist

SSHGuardian gives you the **early warning** so you can act before evidence disappears.

---

## Signals

| Signal | Action |
|---|---|
| `SIGTERM` / `SIGINT` | Graceful shutdown (saves state) |
| `SIGUSR1` | Print live threat status table to stdout/journal |

---

## FAQ

**Q: Will this lock me out of my own server?**  
A: Not if you whitelist your IP. Blocking is disabled by default. When you enable it, always add your IP to the `whitelist` array first.

**Q: Does this replace fail2ban?**  
A: It can, for SSH-specific monitoring. SSHGuardian is simpler, lighter, and focused on visibility first. fail2ban is more mature and covers more services. Use whichever fits your needs.

**Q: What Python version do I need?**  
A: Python 3.8+ (ships with Ubuntu 20.04+). No external packages required.

**Q: Does it work with key-only SSH?**  
A: Yes. It will still detect and alert on failed attempts — bots don't know you've disabled passwords. You'll just see `Failed password` entries from attackers.

**Q: How do I test email alerts?**  
A: Run the self-test with email enabled in your config. The brute-force simulation will trigger a real alert email.

**Q: What about IPv6?**  
A: The current regex patterns match IPv4 addresses. IPv6 support can be added by extending the patterns in `sshguardian.py`.

---

## License

MIT — Use it, modify it, deploy it. No warranty.

<br>
