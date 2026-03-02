# 🛡️ SSH Bouncer

**Real-Time SSH Brute-Force Detection (Python + Linux + systemd)**

GitHub: [https://github.com/tdiprima/ssh-bouncer](https://github.com/tdiprima/ssh-bouncer)

## What It Is

A lightweight Python daemon that watches SSH logs in real time and detects brute-force attacks.

No third-party packages.  
Runs as a systemd service.  
Optional automatic IP blocking.

## What It Does

* Monitors `/var/log/auth.log` live
* Tracks failed login attempts per IP
* Triggers alerts when a threshold is exceeded
* Optionally blocks attacking IPs (UFW / iptables)
* Persists state across restarts
* Handles log rotation

Built for Linux servers (Ubuntu-focused).

## Why It's Interesting

* Zero dependencies (Python standard library only)
* Sliding window detection algorithm
* Firewall automation with auto-expiring bans
* Dry-run mode for safe testing
* Designed with operational visibility first

## Tech Stack

* Python 3.11+
* Linux (Ubuntu 20.04+)
* systemd
* UFW / iptables

## What It Covers

Detects repeated failed SSH login attempts from the same IP (pre-auth brute force).

Not a full SIEM. Not behavioral analytics. Focused and intentional.

## Quick Start

```bash
git clone https://github.com/tdiprima/ssh-bouncer
cd ssh-bouncer
sudo python3 install.py
sudo systemctl enable sshbouncer
sudo systemctl start sshbouncer
```

## ⚠️ Disclaimer

This software is provided as-is, without warranty.  
Always test in a staging or controlled environment before deploying to production infrastructure.

<br>
