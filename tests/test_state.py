import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from state import StateStore, dry_run_state_path  # noqa: E402


class StateStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = os.path.join(self.tempdir.name, "nested", "state.json")
        self.store = StateStore(self.path)

    def test_missing_file_gives_empty_state(self):
        self.assertEqual(self.store.load(), {"blocks": {}, "tracker": {}})

    def test_round_trip(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        blocks = {"1.2.3.4": {"blocked_at": now, "expires_at": now + timedelta(hours=1), "method": "ufw"}}
        tracker = {"5.6.7.8": [now, now + timedelta(seconds=5)], "9.9.9.9": []}
        self.assertTrue(self.store.save(blocks, tracker))
        loaded = self.store.load()
        self.assertEqual(loaded["blocks"], blocks)
        self.assertEqual(loaded["tracker"], {"5.6.7.8": tracker["5.6.7.8"]})

    def test_file_is_private(self):
        self.store.save({}, {})
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_corrupt_file_gives_empty_state(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("{{{")
        self.assertEqual(self.store.load(), {"blocks": {}, "tracker": {}})

    def test_bad_records_are_skipped_not_fatal(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump({
                "blocks": {"1.2.3.4": {"blocked_at": "garbage"}, "5.6.7.8": {
                    "blocked_at": "2026-01-01T00:00:00", "expires_at": "2026-01-01T01:00:00", "method": "ufw"}},
                "tracker": {"a": "not a list", "b": ["2026-01-01T00:00:00", 42]},
            }, handle)
        loaded = self.store.load()
        self.assertEqual(list(loaded["blocks"]), ["5.6.7.8"])
        self.assertEqual(loaded["tracker"], {"b": [datetime(2026, 1, 1)]})

    def test_unwritable_location_returns_false(self):
        store = StateStore("/proc/definitely/not/writable/state.json")
        self.assertFalse(store.save({}, {}))


class DryRunPathTests(unittest.TestCase):
    def test_dry_run_path_is_a_sibling_file(self):
        self.assertEqual(dry_run_state_path("/var/lib/sshbouncer/state.json"),
                         "/var/lib/sshbouncer/state.dry-run.json")

    def test_dry_run_path_never_equals_production_path(self):
        for path in ("state.json", "/tmp/x", "/a/b/state", "/a/b/.hidden"):
            self.assertNotEqual(dry_run_state_path(path), path)


if __name__ == "__main__":
    unittest.main()
