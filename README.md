# 🛡️ SSH Bouncer

**Real-Time SSH Brute-Force Detection (Python, Linux, Systemd)**

A lightweight, dependency-free daemon that monitors SSH authentication logs in real-time and alerts on brute-force activity.

Covers the pre-authentication attack surface: threshold-based detection per source IP, optional firewall enforcement, state persistence across restarts, and log rotation handling — with zero external dependencies.

GitHub: [https://github.com/tdiprima/ssh-bouncer](https://github.com/tdiprima/ssh-bouncer)

---

## 📌 Overview

SSH Bouncer provides early detection of SSH brute-force activity by continuously monitoring authentication logs and applying threshold-based detection per source IP.

It prioritizes **operational visibility first**, with optional automated response (IP blocking).

Designed for:

* VPS / cloud servers
* Self-hosted infrastructure
* Hardened Ubuntu deployments
* DevOps / SRE security baselines

---

## 🧠 Architecture Highlights

* Real-time log tailing with rotation awareness
* Sliding window detection algorithm (per-IP tracking)
* Persistent state across restarts
* Optional automated firewall enforcement (UFW / iptables)
* Systemd service integration
* Dry-run mode for safe validation
* Zero third-party packages (Python standard library only)

---

## 🔍 Detection Model

* Configurable failure threshold (e.g. 5 attempts)
* Configurable time window (e.g. 300 seconds)
* Cooldown to prevent alert storms
* Whitelist protection to prevent self-lockout

When the threshold is exceeded:

1. Structured log event generated
2. Optional SMTP alert sent
3. Optional temporary firewall block applied
4. Block auto-expires after defined duration

---

## 🚀 Installation

```bash
git clone https://github.com/tdiprima/ssh-bouncer
cd ssh-bouncer
sudo python3 install.py
sudo systemctl enable sshbouncer
sudo systemctl start sshbouncer
```

---

## 🧪 Testing & Validation

Built-in attack simulation and self-test framework:

```bash
sudo python3 test_sim.py --self-test
```

Enables deterministic validation before production deployment.

---

## 🛠 Tech Stack

* Python 3.11+
* Linux (Ubuntu 20.04+ recommended)
* systemd
* UFW / iptables (optional)

---

## 🔐 Security Philosophy

* Detection-first design
* Least dependency footprint
* Explicit configuration
* Operational transparency
* Safe defaults (blocking disabled by default)

---

## 🚧 Scope & Limitations

SSH Bouncer targets **pre-authentication brute-force attacks** — repeated failed logins from a single IP. It is not a full SSH behavioral analysis tool.

It does **not** currently detect:

* Anomalies in successful logins (new source IP for a known user, unusual hours, impossible travel)
* Post-authentication session activity
* IPv6 source addresses
* Attacks distributed across many source IPs (low-and-slow or botnet patterns)

For deeper behavioral coverage, pair with `auditd`, a SIEM, or a UEBA tool. For a more established alternative in the same pre-auth space, see [fail2ban](https://github.com/fail2ban/fail2ban).

---

## ⚠️ Disclaimer

This software is provided as-is, without warranty.  
Always test in a staging or controlled environment before deploying to production infrastructure.

---

## 📄 License

MIT License

<br>
