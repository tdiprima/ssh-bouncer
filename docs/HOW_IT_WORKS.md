# How This System Works

## 1. What It Does

SSH Bouncer is a small daemon that watches a Linux server's SSH authentication log, notices when one client address fails to log in too many times too quickly, and reacts. Its reaction is configurable: it always writes a warning to its own log, it can send an email, and it can install a temporary firewall rule that drops all traffic from that address.

**Input:** the live `sshd` log file (`/var/log/auth.log` on Debian/Ubuntu, `/var/log/secure` on RHEL/Rocky), plus a JSON config file.

**What it does:** tails the log, extracts login failures per source IP, counts them inside a sliding time window, and decides when an address has crossed the line.

**Final output:** log lines describing each detection, optional email alerts, optional time-limited `ufw` or `iptables`/`ip6tables` deny rules that are automatically removed when they expire, and a JSON state file that lets the daemon resume after a restart. A `--status` mode prints a table of currently tracked and blocked addresses.

Everything is Python standard library. There are no third-party dependencies.

## 2. The Whole Process in 60 Seconds

1. **Load and validate configuration.** Built-in defaults are merged with the JSON config file. The SMTP password, if any, is pulled from a systemd credential or an environment variable in preference to the file. Every field is type-checked and range-checked; a bad value aborts startup.
2. **Restore saved state.** The daemon reloads the list of active blocks and recent failure timestamps from its state file, then compares that list against the rules actually present in the firewall and fixes any mismatch.
3. **Tail the auth log.** A follower reads new lines as they appear, starting at the end of the file, and survives log rotation.
4. **Parse each line.** Three regular expressions pick out failed passwords, invalid usernames, and accepted logins, along with the client IP. Anything else is ignored.
5. **Count failures per IP.** Each failure appends a timestamp to that IP's list; timestamps older than the detection window are discarded. Whitelisted addresses are skipped entirely.
6. **Trigger when the threshold is hit.** If the list length reaches the configured threshold, and the IP is not already blocked or inside its alert cooldown, the daemon fires.
7. **Act.** Firing means: log a warning, install a tagged firewall deny rule (if blocking is on), save state to disk, and queue an email (if email is on).
8. **Expire and clean up.** Every 30 seconds the daemon removes firewall rules whose block duration has passed. Every 5 minutes it forgets stale failure timestamps and old cooldowns.
9. **Shut down cleanly.** On SIGTERM or SIGINT it saves state, drains the email queue, and exits. Blocks persist across restarts because they are on disk and in the firewall.

## 3. The Major Jobs

### Job 1: Building a Trustworthy Configuration

**What happens.** The daemon assembles one configuration dictionary from three layers and refuses to run if anything in it is wrong.

**Why.** The daemon runs as root and can edit the firewall. A typo in the threshold, a whitelist entry that is not really an IP, or an SMTP password sent over cleartext could lock the operator out or leak a secret. Catching this at startup is cheaper than catching it at 3 a.m.

**How it works.** The layers are applied in order:

1. Built-in defaults (threshold 5, window 300 seconds, blocking off, email off, whitelist `127.0.0.1`, and so on).
2. The JSON file. Explicit `-c path` wins. Without it, `/etc/sshbouncer/config.json` is used only if it exists; otherwise the defaults stand alone. A `_comment` key is stripped so it never reaches validation.
3. The SMTP password from a systemd credential named `smtp_pass` (read from the directory systemd exposes in `CREDENTIALS_DIRECTORY`), falling back to the `SSHBOUNCER_SMTP_PASS` environment variable, and only then to the file value.

Validation then checks each field: positive integers for threshold, window, and block duration; a non-negative integer for cooldown; real booleans (Python's `True` is an `int`, so the checks explicitly reject `bool` where an integer is expected); block method must be `ufw` or `iptables`; log level must be a known name. The whitelist is converted from strings to `ipaddress` network objects, so a bare IP becomes a `/32` or `/128` network and every later membership test is a proper subnet check rather than string comparison.

Email fields are only validated when email is enabled. One rule is worth noting: **a username may only be set when STARTTLS is also on.** Without that, the daemon will not start, because it would otherwise send a password in plain text.

Finally, `auth_log: "auto"` is resolved to the first of `/var/log/auth.log` or `/var/log/secure` that exists. If neither exists, startup fails with a message telling the operator to set the path explicitly.

**What comes out.** A validated config dictionary that every later stage reads from. Any failure produces a `ConfigError`, printed to stderr with exit code 2.

### Job 2: Restoring Memory and Squaring It With the Firewall

**What happens.** Before reading any new log lines, the daemon reloads what it knew before it last stopped and checks whether the firewall still agrees.

**Why.** Blocks are supposed to expire. If the daemon crashed and forgot that it had blocked an address, that firewall rule would live forever. Conversely, if someone removed a rule by hand, the daemon should not keep believing the address is blocked. The state file and the firewall are two sources of truth that drift; startup is when they get reconciled.

**How it works.** The state file is JSON with two sections: `blocks` (IP to blocked-at, expires-at, method) and `tracker` (IP to list of failure timestamps). Loading is lenient: a missing file means empty state, a corrupt file is logged and treated as empty, and individual malformed records are skipped with a warning rather than aborting.

Reconciliation only runs when blocking is enabled. The daemon lists the current firewall rules (`ufw status numbered`, or `iptables -S INPUT` plus `ip6tables -S INPUT`) and parses out every single-host deny rule, noting whether it carries the `sshbouncer` comment tag. Then a pure function merges the two views:

- A recorded block whose rule is still present is kept.
- A recorded block whose rule is gone is dropped, since there is nothing left to expire.
- A tagged rule with no record is **adopted**: the daemon creates a fresh record with a full block duration starting now, so the orphaned rule will eventually be released.
- Untagged rules for IPs the daemon does not know about are left alone; they belong to someone else.

If listing the firewall fails, reconciliation is skipped and logged rather than treated as "no rules exist." An empty answer from a failed command would look identical to a clean firewall and could cause records to be wrongly dropped.

After reconciliation, stale tracker entries are pruned and any block already past its expiry is released immediately.

**What comes out.** In-memory `blocked` and `tracker` tables that match reality. If reconciliation changed anything, the corrected state is saved back to disk.

### Job 3: Following the Log Without Losing Lines

**What happens.** A follower object yields new complete lines from the auth log, forever, until asked to stop.

**Why.** Auth logs are rotated by `logrotate`, sometimes by renaming the file and creating a new one, sometimes by truncating it in place. A naive `tail -f` implementation either stops receiving lines or re-reads the whole file. The follower has to handle both cases and never split a line in half.

**How it works.** On open it records the file's inode and seeks to the end, so old history is not replayed. Each poll:

1. Reads every complete line currently available. A trailing partial line (no newline yet) is rewound and left for the next poll.
2. Stats the path on disk. If the inode differs, the file was renamed: the follower drains anything still readable through the old handle, reopens the new file from offset zero, and drains that too. If the file is smaller than the last read position, it was truncated: the follower seeks to zero and reads from there.
3. If the path is temporarily missing (the gap between rename and recreate), it waits one second and retries.

When there is nothing to read it sleeps for half a second. That sleep is not a plain `time.sleep`; the daemon passes in its own idle function, which runs the periodic tasks described in Job 6 before sleeping. This is how block expiry keeps happening even on a totally quiet server.

**What comes out.** A stream of raw log line strings, handed one at a time to the parser.

### Job 4: Turning Log Lines Into Events

**What happens.** Each line is matched against three patterns and, on a hit, becomes a small event dictionary: `{"type", "ip", "user"}`.

**Why.** The auth log is full of noise (cron, sudo, PAM sessions). Only three message shapes matter here: `Failed password for ...`, `Invalid user ...`, and `Accepted password|publickey for ...`. Everything else is discarded as early as possible.

**How it works.** The interesting detail is defensive. `sshd` interpolates the attacker-supplied username into the message. That means a username can literally contain the text `from 203.0.113.99 port 22 ssh2`, which would fool a naive regex into blaming the wrong address. The patterns therefore consume the username greedily and anchor the address to the **last** `from <addr> port <n>` before end of line, which is the part `sshd` itself appends and the attacker cannot control.

The extracted address is then normalized through `ipaddress`: anything that is not a real IP is rejected (the line is dropped), IPv4-mapped IPv6 addresses like `::ffff:1.2.3.4` collapse to plain IPv4, and IPv6 zone identifiers are stripped. This guarantees that the tracker, the whitelist, and the firewall all key on exactly one spelling per client.

**What comes out.** An event dictionary, or `None` for lines that do not matter. Events go to the detection engine.

### Job 5: Deciding Whether an Address Has Crossed the Line

**What happens.** The detection engine keeps a per-IP list of failure timestamps and fires when the list gets long enough inside the window.

**Why.** This is the core judgment. It has to be strict enough to catch bots but fenced enough to never act on the operator's own address or hammer the same IP with repeated alerts.

**How it works.** For each event:

1. **Accepted logins** are logged at info level and otherwise ignored. They do not reset the failure count.
2. **Whitelist check.** The IP is tested against every configured network. If it matches, the event is dropped. If the IP somehow cannot be parsed, the engine treats it as whitelisted; the code's own comment calls this "fail closed: never act on something we cannot parse."
3. **Sliding window.** The current time is appended to the IP's list, then the list is filtered to keep only timestamps newer than `now - window_seconds`. The count is therefore always "failures in the last N seconds," not "failures ever."
4. **Threshold.** If the filtered list has at least `threshold` entries, the engine calls `trigger`.

`trigger` has two guard gates before acting:

- If the IP is already in the blocked table, do nothing. Log lines can keep arriving for a moment after a rule is installed, and there is no point re-blocking.
- If the IP alerted within the last `cooldown_minutes`, suppress. This stops a persistent attacker in non-blocking mode from generating an email every few seconds. Note that cooldown is in memory only; a restart clears it.

When both gates pass, the engine logs a `brute_force_detected` warning, records the alert time, and moves on to Job 6.

**What comes out.** A decision to act on one specific IP, with the failure count that justified it.

### Job 6: Acting on a Detection, and Undoing It Later

**What happens.** Block, persist, notify. Later: unblock on schedule.

**Why.** Each of these has failure modes that must not take the others down with them. Ordering matters.

**How it works.**

*Block.* If `block_enabled` is false, nothing happens and the alert simply says "not blocked." Otherwise the engine asks the firewall lifecycle object to install a deny rule. The command is built as an argument list (never a shell string) and always carries the `sshbouncer` comment tag so the rule can be found again later. For `ufw` the rule is inserted at position 1 so it takes precedence over any allow rules. For `iptables` mode the engine picks `iptables` or `ip6tables` based on the address family. The command runs with a 30-second timeout; a non-zero exit, a timeout, or a missing binary raises a `FirewallError`, which the engine catches and logs. In that case the block is recorded as not applied and the alert still goes out. On success the engine records `blocked_at`, `expires_at = now + block_duration_minutes`, and the method used.

In `--dry-run` mode the lifecycle object logs a simulated block and returns without running anything. The same object handles unblocking, so dry-run is enforced in one place for both directions.

*Persist.* The engine saves state to disk **before** sending email. The comment in the code explains why: "a slow or failed SMTP call must never delay or lose the record." Saving is atomic (write to a temp file in the same directory with mode 0600, then rename over the target), so a crash mid-write cannot corrupt the file. If the save fails, the engine remembers that it has unsaved changes and retries on the next 30-second cycle.

*Notify.* If email is enabled, the alert (subject, body with IP, count, window, and action taken) is placed on a bounded queue of 100 items. A single background thread drains the queue and sends via SMTP. If the queue is full, the newest alert is dropped and logged. SMTP delivery uses a 30-second timeout, verifies the server certificate when STARTTLS is on, and refuses to log in without TLS even if a hand-edited config asks for it. Email failures are logged and never propagate back into the monitoring loop.

*Expire.* Every 30 seconds the engine scans the blocked table for entries whose `expires_at` has passed and asks the firewall to delete each rule. Deletion first tries the tagged rule spec; if that fails it falls back to the untagged spec that older versions of the program installed. On success the record is removed and the IP's tracker history is cleared, giving it a clean slate. On failure the record is **kept** so the daemon retries next cycle instead of forgetting a live rule.

*Prune.* Every 5 minutes, and also before every save, the engine drops tracker timestamps outside the window and cooldown entries older than the cooldown period, so memory does not grow with the number of distinct addresses that ever touched the server.

**What comes out.** A firewall that matches the blocked table, a state file that matches memory, and a log and inbox that describe what happened.

### Job 7: Reporting and Stopping

**What happens.** Two side paths exist alongside the main loop.

*Status.* `--status` builds an engine with no firewall access, loads the state file, and prints a table of IP, recent failure count, and blocked-until time. It never runs a firewall command. Sending SIGUSR1 to the running daemon prints the same table to its stdout (which under systemd lands in the journal), using live in-memory data.

*Shutdown.* SIGTERM and SIGINT set a flag; the follower's stop check sees it on the next poll. The `finally` block closes the log handle, saves state one last time, and asks the notifier to drain. The notifier pushes a sentinel onto its queue and waits up to 35 seconds (one SMTP timeout plus slack) for the worker to finish. Anything still pending is logged as undelivered.

### Job 8: Installation and Uninstallation

The installer is a separate script and not part of the runtime pipeline, but it shapes how the daemon is deployed. It asks interactive questions, writes `/etc/sshbouncer/config.json` with mode 0600, copies the source files to `/opt/sshbouncer`, and writes a systemd unit that runs the daemon with `Restart=on-failure`. If the operator enters an SMTP username without TLS, the installer silently turns TLS on and says so. It deliberately does not ask for the password; it tells the operator to put it in the root-only config file or use a systemd `LoadCredential`.

Uninstall stops the service, then reuses the same firewall lifecycle object to list and delete every rule tagged `sshbouncer`, across both `ufw` and `iptables` if both binaries exist. Rules are removed before the state directory is deleted. If any rule cannot be removed, the state directory is kept so the operator can see what is still blocked. Config and logs are always preserved.

## 4. How the Pieces Work Together

The stages form a straight line with two feedback loops.

- **Config feeds everything.** The validated dictionary is handed to the engine, the notifier, the log follower (via the resolved auth log path), and the state store (via the state file path, with a `.dry-run` suffix inserted in dry-run mode so simulated runs never touch real records).
- **State restore feeds the engine's tables**, and the engine's tables feed the firewall reconciliation, whose corrections flow back into the tables and then to disk.
- **The follower feeds the parser feeds the engine.** This is the main line. Each stage discards what the next does not need: the follower discards partial lines, the parser discards irrelevant lines and unparseable addresses, the engine discards whitelisted and below-threshold events.
- **The engine feeds three sinks:** the firewall lifecycle (block/unblock), the state store (save), and the notifier (enqueue). None of the three can stall the engine: firewall commands have timeouts and their errors are caught, saves return `False` instead of raising, and email is queued to another thread.
- **The follower's idle hook feeds back into the engine.** Because the daemon's sleep function runs periodic tasks, expiry and pruning happen whether or not any new log lines arrive.

The dependency that is easiest to miss: **blocking depends on the tag.** Reconciliation at startup, expiry, and uninstall all rely on every rule carrying the `sshbouncer` comment. That tag is what lets the program tell its own rules apart from anyone else's.

## 5. Important External Pieces

- **`sshd` and its log.** The sole input. The daemon reads the file; it does not talk to `sshd` directly and does not use journald.
- **`ufw`, `iptables`, `ip6tables`.** The enforcement mechanism. Invoked as subprocesses with argument lists, never through a shell. `ufw` handles both address families itself; in `iptables` mode the daemon chooses the binary per address.
- **systemd.** Runs the daemon, restarts it on failure, delivers SIGTERM on stop and SIGUSR1 for status. Also the preferred carrier for the SMTP password via `LoadCredential`, because that is hidden from `systemctl show` while `Environment=` is not.
- **An SMTP server.** Optional. Reached through Python's `smtplib` with STARTTLS and certificate verification when configured.
- **Python 3.11+ standard library only.** `re`, `ipaddress`, `json`, `subprocess`, `smtplib`, `ssl`, `queue`, `threading`, `signal`, `logging`. No pip installs.
- **The state file** at `/var/lib/sshbouncer/state.json`. Not external to the program, but it is the only durable memory the daemon has between runs.

## 6. End-to-End Example

Assume the installed defaults: threshold 5, window 300 seconds, blocking enabled with `ufw`, block duration 60 minutes, email enabled, cooldown 10 minutes, whitelist `127.0.0.1`.

1. The daemon starts. Config validates. The state file is empty. `ufw status numbered` shows no tagged rules, so there is nothing to reconcile. The follower opens `/var/log/auth.log` and seeks to the end.

2. At 14:00:01 a bot at `203.0.113.7` begins. `sshd` writes:

   ```c
   Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2
   ```
   The follower yields the line. The parser matches `failed_password`, extracts `admin` and `203.0.113.7`, and normalizes the address. The engine checks the whitelist (no match), appends `14:00:01` to the tracker for that IP. Count is 1. Nothing else happens.

3. Three more failures arrive by 14:00:09. Count is 4. Still below threshold.

4. At 14:00:12 the fifth failure arrives. The window filter keeps all five timestamps (all within 300 seconds). Count is 5, which meets the threshold. The IP is not blocked and has no recent alert, so `trigger` proceeds.

5. The engine logs:

   ```c
   level=WARNING component=sshbouncer.engine event=brute_force_detected ip=203.0.113.7 failures=5 window_seconds=300
   ```
   It records the alert time, then runs:

   ```sh
   ufw insert 1 deny from 203.0.113.7 to any comment sshbouncer
   ```

   The command succeeds. The blocked table gains an entry expiring at 15:00:12.

6. State is written atomically to `/var/lib/sshbouncer/state.json`. Then an email is queued with subject `Brute-force detected from 203.0.113.7` and a body stating five failures in 300 seconds, action taken: blocked. The worker thread sends it over STARTTLS.

7. Two more failure lines arrive a second later (packets already in flight before the rule took effect). The engine counts them, sees the threshold met again, but `trigger` returns early because the IP is already blocked. No duplicate rule, no duplicate email.

8. Meanwhile the operator logs in from `127.0.0.1`. The parser produces an `accepted_login` event; the engine logs it and takes no action. A mistyped password from `127.0.0.1` produces a failure event, but the whitelist check drops it before counting.

9. At 15:00:30, during a periodic check, the engine finds `203.0.113.7` past its expiry and runs:

   ```sh
   ufw delete deny from 203.0.113.7 to any comment sshbouncer
   ```
   The record and the IP's tracker history are removed and state is saved. The address can connect again; if it resumes attacking it will need five fresh failures to be blocked again.

10. That evening the server is rebooted. On startup the daemon reloads whatever blocks were active, lists `ufw` rules, keeps records whose rules survived, and resumes.

Had the daemon been started with `--dry-run`, steps 5 and 9 would have logged `firewall_block_simulated` and `firewall_unblock_simulated` instead of running `ufw`, the email body would have said "blocked (dry-run, simulated)", and the state would have gone to `state.dry-run.json`.

## 7. The Simplest Mental Model

It tails the SSH log, boils every line down to "which IP just failed to log in," keeps a short rolling list of failure times per IP, and the moment one list gets long enough it writes a tagged deny rule into the firewall, saves a note to disk saying when to remove it, and drops an email in a queue. A timer keeps checking the notes and pulls each rule when its time is up. On every restart it compares its notes against the firewall and fixes whichever one is wrong.

<br>
