# 🛡 SSH Bouncer

Bots are out here spamming your SSH login 24/7. SSH Bouncer watches the log, catches the sus IPs, and (if you want) yeets them off your firewall. No pip installs. No drama. Just Python.

Works on Ubuntu, Debian, RHEL, and Rocky. You need root. That's it.

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
| Whitelisted IPs | **PUT YOUR OWN IP HERE.** Comma-separated. Not doing this = you might lock yourself out. Not a vibe. |
| Enable IP blocking? | Say `n` the first time. Watch it work before you let it swing. |
| Enable email alerts? | `y` if you want emails. It'll ask for your SMTP stuff. |
| Start service now? | `y` |

If you turned on email with a password, set it as an env var so it isn't chilling in a file:

```bash
sudo systemctl edit sshbouncer
```

Then add:

```ini
[Service]
Environment=SSHBOUNCER_SMTP_PASS=your-app-password
```

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

## Change your mind later

Edit the config:

```bash
sudo nano /etc/sshbouncer/config.json
sudo systemctl restart sshbouncer
```

Ready to actually block people? Flip `"block_enabled": false` to `true`. Double check your IP is in `"whitelist"` first. Seriously.

## Test it without touching anything real

Fake attack, fake log, zero firewall changes. No sudo needed:

```bash
python3 src/test_sim.py --self-test
```

All green checkmarks = you're good.

## Uninstall

```bash
sudo python3 install.py --uninstall
```

Keeps your config and logs in case you come back. We know you will.

## ⚠️ Real talk

No warranty. Test on a box you don't care about first. If you enable blocking without whitelisting yourself and get locked out, that's on you bestie.

<br>
