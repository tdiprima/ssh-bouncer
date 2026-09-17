# Persistent state: active blocks and per-IP failure history, stored as JSON on disk.
import json
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("sshbouncer.state")

STATE_VERSION = 1
DRY_RUN_SUFFIX = ".dry-run"


def dry_run_state_path(path: str) -> str:
    """Sibling file for simulated state so a dry run never reads or overwrites production records."""
    original = Path(path)
    return str(original.with_name(original.stem + DRY_RUN_SUFFIX + original.suffix))


class StateStore:
    """Loads and saves engine state. Writes are atomic (temp file + rename)."""

    def __init__(self, path: str):
        self.path = Path(path)

    def load(self) -> dict:
        """Return {"blocks": {...}, "tracker": {...}}. Missing file means empty state."""
        empty = {"blocks": {}, "tracker": {}}
        if not self.path.is_file():
            return empty

        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            logger.error("event=state_load_failed path=%s error=%s", self.path, error)
            return empty

        if not isinstance(data, dict):
            logger.error("event=state_load_failed path=%s error=not_an_object", self.path)
            return empty

        return {
            "blocks": parse_blocks(data.get("blocks", {})),
            "tracker": parse_tracker(data.get("tracker", {})),
        }

    def save(self, blocks: dict, tracker: dict) -> bool:
        """Serialize state. Returns False and logs on failure instead of raising."""
        payload = {
            "version": STATE_VERSION,
            "saved_at": datetime.now().isoformat(),
            "blocks": {
                ip: {
                    "blocked_at": block["blocked_at"].isoformat(),
                    "expires_at": block["expires_at"].isoformat(),
                    "method": block["method"],
                }
                for ip, block in blocks.items()
            },
            "tracker": {
                ip: [timestamp.isoformat() for timestamp in timestamps]
                for ip, timestamps in tracker.items()
                if timestamps
            },
        }

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            write_atomically(self.path, json.dumps(payload, indent=2))
        except OSError as error:
            logger.error("event=state_save_failed path=%s error=%s", self.path, error)
            return False
        return True


def write_atomically(path: Path, content: str) -> None:
    """Write to a temp file in the same directory, then rename over the target."""
    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    except OSError:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
        raise


def parse_blocks(raw_blocks) -> dict:
    """Convert stored block records back to datetimes. Bad records are dropped with a log line."""
    blocks = {}
    if not isinstance(raw_blocks, dict):
        return blocks

    for ip, record in raw_blocks.items():
        try:
            blocks[ip] = {
                "blocked_at": datetime.fromisoformat(record["blocked_at"]),
                "expires_at": datetime.fromisoformat(record["expires_at"]),
                "method": str(record["method"]),
            }
        except (KeyError, TypeError, ValueError) as error:
            logger.warning("event=state_block_record_invalid ip=%s error=%s", ip, error)
    return blocks


def parse_tracker(raw_tracker) -> dict:
    """Convert stored failure timestamps back to datetimes. Bad entries are skipped."""
    tracker = {}
    if not isinstance(raw_tracker, dict):
        return tracker

    for ip, timestamps in raw_tracker.items():
        if not isinstance(timestamps, list):
            continue
        parsed = []
        for value in timestamps:
            try:
                parsed.append(datetime.fromisoformat(value))
            except (TypeError, ValueError):
                logger.warning("event=state_tracker_entry_invalid ip=%s value=%r", ip, value)
        if parsed:
            tracker[ip] = parsed
    return tracker
