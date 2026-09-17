# 🛡 SSH Bouncer

Bots are out here spamming your SSH login 24/7. SSH Bouncer watches the log, catches the sus IPs, and (if you want) yeets them off your firewall. No pip installs. No drama. Just Python.

Works on Ubuntu, Debian, RHEL, and Rocky. You need root and Python 3.11+. That's it.

## Install it (fr, it's like 30 seconds)

```bash
git clone https://github.com/tdiprima/ssh-bouncer
cd ssh-bouncer
sudo python3 install.py
```

The installer asks you a few questions. Vibes for each one:

| It asks... | What to say |
|---|---|
| Failed login threshold | How many fails before it flags an IP. `5` is fine. |
| Detection window (seconds) | How long those fails have to happen in. `300` is fine. |
| Whitelisted IPs/CIDRs | **PUT YOUR OWN IP HERE.** Comma-separated. Single IPs or CIDR ranges like `10.0.0.0/8`. Not doing this = you might lock yourself out. Not a vibe. |
| Enable IP blocking? | Say `n` the first time. Watch it work before you let it swing. |
| Block method (ufw/iptables) | Only asked if blocking is on. `ufw` on Ubuntu/Debian, `iptables` on RHEL/Rocky. IPv6 attackers get blocked too: `ufw` handles both families, `iptables` mode also drives `ip6tables` (ships in the same package). |
| Block duration (minutes) | Only asked if blocking is on. How long an IP stays blocked. `60` is fine. |
| Enable email alerts? | `y` if you want emails. It'll ask for your SMTP stuff. |
| Start service now? | `y` |

If you turned on email with a password, put it in the config file. `/etc/sshbouncer/config.json` is root-only (mode `0600`), so that's already the safe spot:

```bash
sudo nano /etc/sshbouncer/config.json    # set "smtp_pass"
sudo systemctl restart sshbouncer
```

Prefer to keep it out of the config? Use a systemd credential. The service can read it, other local users cannot:

```bash
echo -n 'your-app-password' | sudo tee /etc/sshbouncer/smtp_pass >/dev/null
sudo chmod 0600 /etc/sshbouncer/smtp_pass
sudo systemctl edit sshbouncer
```

Then add:

```ini
[Service]
LoadCredential=smtp_pass:/etc/sshbouncer/smtp_pass
```

Do **not** use `Environment=SSHBOUNCER_SMTP_PASS=...` in the unit. systemd exposes unit environment to every local user via `systemctl show`. The env var still works for manual runs from your own shell, that's all it's for.

A username is only accepted together with `"smtp_tls": true`, and the server certificate is verified. No verified TLS, no password leaves the box.

## Run it

Installer already started it. Confirm it's alive:

```bash
sudo systemctl status sshbouncer
```

Watch it cook in real time:

```bash
sudo journalctl -u sshbouncer -f
```

See who's been trying to get in:

```bash
sudo python3 /opt/sshbouncer/sshbouncer.py --status
```

Or poke the running service and it'll print the same table into the journal:

```bash
sudo systemctl kill --signal=SIGUSR1 sshbouncer
sudo journalctl -u sshbouncer -n 20
```

## Change your mind later

Edit the config:

```bash
sudo nano /etc/sshbouncer/config.json
sudo systemctl restart sshbouncer
```

Ready to actually block people? Flip `"block_enabled": false` to `true`. Double check your IP is in `"whitelist"` first. Seriously.

Blocks aren't forever. Each one expires after `"block_duration_minutes"` (default `60`) and the firewall rule gets pulled automatically. On every startup SSH Bouncer compares its records against the live firewall: records for rules that vanished get dropped, and leftover `sshbouncer`-tagged rules with no record get adopted so they still expire on schedule.

## Test it without touching anything real

Fake attack, fake log, zero firewall changes. No sudo needed:

```bash
python3 src/test_sim.py --self-test
```

All green checkmarks = you're good.

Hacking on the code? Run the unit tests too. Stdlib `unittest`, nothing to install:

```bash
python3 -m unittest discover tests
```

`--dry-run` mode never runs a firewall command, not for blocking and not for unblocking. It keeps its own state file (`state.dry-run.json` next to the real one) so a dry run can't mess with live records.

## Uninstall

```bash
sudo python3 install.py --uninstall
```

Stops the service, removes every firewall rule SSH Bouncer added (they're tagged `sshbouncer` so nothing else gets touched), then deletes the app. Keeps your config and logs in case you come back. We know you will.

If a rule can't be removed, the state file in `/var/lib/sshbouncer` is kept so you can see what's still blocked.

## ⚠️ Real talk

No warranty. Test on a box you don't care about first. If you enable blocking without whitelisting yourself and get locked out, that's on you bestie.

<br>
