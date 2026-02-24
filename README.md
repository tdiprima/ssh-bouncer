# 🛡️ SSH Guardian

**Real-Time SSH Intrusion Detection for Linux**

SSHGuardian is a lightweight Python daemon that monitors SSH authentication logs in real time and alerts you when suspicious activity starts.

It detects brute-force login attempts and can optionally block offending IP addresses.

Built for Ubuntu servers, VPS instances, and home labs where SSH is exposed to the internet.

---

## ✨ What It Does

* Monitors `/var/log/auth.log` live
* Detects repeated failed SSH login attempts
* Sends optional email alerts
* Can auto-block IPs via UFW or iptables
* Survives restarts (state persistence)
* Runs as a systemd service
* No external dependencies (Python 3 only)

---

## 🚀 Quick Start

```bash
git clone https://github.com/tdiprima/SSH-Guardian
cd SSH-Guardian
sudo python3 install.py
sudo systemctl start sshguardian
```

Watch logs:

```bash
sudo journalctl -u sshguardian -f
```

---

## ⚙️ How It Works

1. Follows SSH auth logs in real time
2. Tracks failed login attempts per IP
3. Triggers when a threshold is exceeded
4. Alerts you (and optionally blocks the IP)

---

## 🔧 Requirements

* Ubuntu 20.04+ (Debian-compatible)
* Python 3.8+
* Root access
* SSH server running

---

## 🧪 Testing

Run the built-in simulation:

```bash
sudo python3 test_sim.py --self-test
```

---

## ⚠️ Important

* Blocking is **disabled by default**.
* Always whitelist your own IP before enabling auto-blocking.
* This tool focuses on visibility first — blocking is optional.
* This is not a replacement for a full security stack.

---

## 📄 License

MIT License. Use at your own risk.

---

## ⚖️ Disclaimer

This software is provided "as is", without warranty of any kind.
The author is not responsible for service interruption, lockouts, data loss, or security incidents resulting from its use.  
Always test in a controlled environment before deploying to production.

<br>
