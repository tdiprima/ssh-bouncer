import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from logfollow import LogFollower  # noqa: E402


def append(path, text):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)


class LogFollowerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = os.path.join(self.tempdir.name, "auth.log")
        append(self.path, "old line\n")
        self.follower = LogFollower(self.path, sleep_fn=lambda _s: None)
        self.addCleanup(self.follower.close)

    def test_starts_at_end_and_skips_existing_content(self):
        self.follower.open()
        self.assertEqual(self.follower.read_available_lines(), [])

    def test_reads_new_lines(self):
        self.follower.open()
        append(self.path, "a\nb\n")
        self.assertEqual(self.follower.read_available_lines(), ["a", "b"])
        self.assertEqual(self.follower.read_available_lines(), [])

    def test_partial_line_waits_for_newline(self):
        self.follower.open()
        append(self.path, "half")
        self.assertEqual(self.follower.read_available_lines(), [])
        append(self.path, " done\n")
        self.assertEqual(self.follower.read_available_lines(), ["half done"])

    def test_rename_rotation_reads_tail_of_old_file_and_new_file(self):
        self.follower.open()
        append(self.path, "before rotate\n")
        os.rename(self.path, self.path + ".1")
        append(self.path + ".1", "written after rename\n")
        append(self.path, "first in new file\n")
        self.assertEqual(
            self.follower.read_available_lines(),
            ["before rotate", "written after rename", "first in new file"],
        )
        append(self.path, "second in new file\n")
        self.assertEqual(self.follower.read_available_lines(), ["second in new file"])

    def test_copytruncate_rotation_resets_position(self):
        self.follower.open()
        append(self.path, "line one\nline two\n")
        self.assertEqual(len(self.follower.read_available_lines()), 2)
        with open(self.path, "w", encoding="utf-8"):
            pass  # truncate
        append(self.path, "after truncate\n")
        self.assertEqual(self.follower.read_available_lines(), ["after truncate"])

    def test_rotation_with_gap_waits_for_new_file(self):
        self.follower.open()
        os.rename(self.path, self.path + ".1")
        # No new file yet: follower must not crash and must report nothing.
        self.assertEqual(self.follower.read_available_lines(), [])
        append(self.path, "new\n")
        self.assertEqual(self.follower.read_available_lines(), ["new"])

    def test_follow_stops_when_asked(self):
        calls = {"n": 0}

        def should_stop():
            calls["n"] += 1
            return calls["n"] > 2

        append(self.path, "x\n")
        self.follower.start_at_end = False
        lines = list(self.follower.follow(should_stop=should_stop))
        self.assertEqual(lines, ["old line", "x"])

    def test_large_burst_is_read_completely(self):
        self.follower.open()
        append(self.path, "".join(f"line {i}\n" for i in range(20000)))
        self.assertEqual(len(self.follower.read_available_lines()), 20000)


if __name__ == "__main__":
    unittest.main()
