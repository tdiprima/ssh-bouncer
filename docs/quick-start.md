## SSH Guardian

Fully built, tested, and passing all checks. The project has 4 files:

**`sshguardian.py`** — The main daemon. Tails `/var/log/auth.log` in real-time, tracks failed SSH attempts per IP in a sliding window, fires alerts when thresholds are crossed, and optionally blocks via UFW/iptables. Handles log rotation, persists state across restarts, and responds to `SIGUSR1` for a live status dump.

**`install.py`** — Interactive installer that walks you through config choices (threshold, blocking, email), installs to `/opt/sshguardian`, writes a locked-down config to `/etc/sshguardian/config.json`, and sets up a systemd service. Also supports `--uninstall`.

**`test_sim.py`** — Attack simulator with 5 scenarios (slow probes, brute-force bursts, multiple attackers, legitimate logins, whitelisted IPs). Run `sudo python3 test_sim.py --self-test` for an automated smoke test — it passed all 3 checks here.

**`config.example.json`** — Reference config with all available settings.

The quickest path to running it on your server: copy the folder over, run `sudo python3 install.py`, then `sudo systemctl start sshguardian`. Zero external dependencies — pure Python 3 stdlib.

---

## Config

No, that won't touch your existing UFW rules at all. The whitelist in SSHGuardian's config is purely internal to the application — it just tells SSHGuardian "don't alert or block these IPs." It never writes any UFW allow rules.

The only time SSHGuardian interacts with UFW is when it *blocks* an offending IP (and only if `block_enabled` is `true`). In that case it runs `ufw insert 1 deny from <ip>`, which *adds* a deny rule — it doesn't modify or remove anything already there. When the block expires, it removes only the rule it created.

So your existing UFW ruleset stays untouched. The whitelist is just SSHGuardian's own "ignore list."

---

## No email

You have a few options without email enabled:

**Live log stream** — this is the most direct way. SSHGuardian logs every failed attempt, every alert, and every accepted login as it happens:

```bash
sudo journalctl -u sshguardian -f
```

or

```bash
sudo tail -f /var/log/sshguardian.log
```

**Threat status table** — a snapshot of all tracked IPs, their fail counts, targeted usernames, and block status:

```bash
sudo python3 /opt/sshguardian/sshguardian.py --status
```

**Live status signal** — if the daemon is running and you want a quick status dump without stopping it:

```bash
sudo kill -USR1 $(pgrep -f sshguardian.py)
```

That prints the threat table to the journal, so check `journalctl -u sshguardian` right after.

Of these, the `--status` command is probably the most useful for a quick daily check. The log stream is what you'd want if you're actively investigating something. And if you decide later that you want push notifications, you can always flip `email_enabled` to `true` in the config and restart the service.

---

## Status

```sh
# Send SIGUSR1 for live status:
sudo kill -USR1 $(pidof -x sshguardian.py)
```

It's a way to ask a running program to do something without stopping it.

**`kill`** is a bit of a misleading name — it doesn't necessarily kill anything. It sends a *signal* to a process. `SIGUSR1` is a user-defined signal that programs can listen for and respond to however they want.

In SSHGuardian's case, when it receives `SIGUSR1`, it prints the current threat status table (all tracked IPs, fail counts, block status) to its log output.

Breaking down the command:

- **`sudo`** — run as root (needed since SSHGuardian runs as root)
- **`kill -USR1`** — send the SIGUSR1 signal
- **`$(pidof -x sshguardian.py)`** — this part finds the process ID of the running SSHGuardian daemon automatically

So instead of looking up the process ID yourself, the command does it in one shot. It's the equivalent of saying "hey SSHGuardian, print me a status report right now" while it keeps running in the background.

After running it, you'd see the output in:

```bash
sudo journalctl -u sshguardian -n 20
```

That said, running `sudo python3 /opt/sshguardian/sshguardian.py --status` gives you the same information and is simpler. The `SIGUSR1` approach is more of a sysadmin shortcut for when you're already in a terminal and want a quick peek.

<br>
