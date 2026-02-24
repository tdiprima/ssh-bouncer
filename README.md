# 🛡️ SSH Guardian

**Production-Ready Real-Time SSH Intrusion Detection (Python, Linux, Systemd)**

A lightweight, dependency-free intrusion detection daemon for monitoring SSH authentication activity on Linux servers.

Built with production deployment in mind: systemd integration, state persistence, log rotation handling, optional firewall enforcement, and zero external dependencies.

GitHub: [https://github.com/tdiprima/SSH-Guardian](https://github.com/tdiprima/SSH-Guardian)

---

## 📌 Overview

SSHGuardian provides early detection of SSH brute-force activity by continuously monitoring authentication logs and applying threshold-based detection per source IP.

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
git clone https://github.com/tdiprima/SSH-Guardian
cd SSH-Guardian
sudo python3 install.py
sudo systemctl enable sshguardian
sudo systemctl start sshguardian
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

## ⚠️ Disclaimer

This software is provided as-is, without warranty.  
Always test in a staging or controlled environment before deploying to production infrastructure.

---

## 📄 License

MIT License

<br>
