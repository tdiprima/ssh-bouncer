# Tails a log file and survives logrotate (rename, copytruncate, or temporary absence).
import logging
import os
import time

logger = logging.getLogger("sshbouncer.logfollow")

POLL_INTERVAL_SECONDS = 0.5
MISSING_FILE_RETRY_SECONDS = 1.0


class LogFollower:
    """Yields new lines from a file, reopening it when the inode changes or it shrinks."""

    def __init__(self, path: str, start_at_end: bool = True, sleep_fn=time.sleep):
        self.path = path
        self.start_at_end = start_at_end
        self.sleep = sleep_fn
        self.handle = None
        self.inode = None
        self.position = 0

    def open(self) -> None:
        """Open the file and record its inode. Raises OSError if it cannot be opened."""
        self.close()
        self.handle = open(self.path, "r", encoding="utf-8", errors="replace")
        self.inode = os.fstat(self.handle.fileno()).st_ino
        if self.start_at_end:
            self.handle.seek(0, os.SEEK_END)
        self.position = self.handle.tell()
        logger.info("event=log_opened path=%s inode=%s position=%s", self.path, self.inode, self.position)

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def read_available_lines(self) -> list:
        """Return complete new lines since the last call, handling rotation first."""
        if self.handle is None:
            self.open()

        lines = self.drain_lines()
        rotation = self.detect_rotation()
        if rotation == "inode_changed":
            # Lines written to the old file between our last read and the rotation are
            # still readable through the open handle. Drain them before switching.
            lines.extend(self.drain_lines())
            self.reopen_from_start()
            lines.extend(self.drain_lines())
        elif rotation == "truncated":
            self.handle.seek(0)
            self.position = 0
            lines.extend(self.drain_lines())
        return lines

    def drain_lines(self) -> list:
        """Read every complete line currently available from the open handle."""
        lines = []
        while True:
            line = self.handle.readline()
            if not line.endswith("\n"):
                # Partial line: rewind so the next call re-reads it once it is complete.
                self.handle.seek(self.position)
                break
            self.position = self.handle.tell()
            lines.append(line.rstrip("\n"))
        return lines

    def detect_rotation(self) -> str | None:
        """Return "inode_changed", "truncated", or None."""
        try:
            current = os.stat(self.path)
        except FileNotFoundError:
            # Rename-based rotation may leave a gap before the new file exists.
            return None
        if current.st_ino != self.inode:
            logger.info("event=log_rotated reason=inode_changed path=%s", self.path)
            return "inode_changed"
        if current.st_size < self.position:
            logger.info("event=log_rotated reason=truncated path=%s", self.path)
            return "truncated"
        return None

    def reopen_from_start(self) -> None:
        """Open the new file at offset 0, waiting if rotation left a gap with no file."""
        self.start_at_end = False
        try:
            self.open()
        except FileNotFoundError:
            self.close()
            self.wait_for_file()
            self.open()

    def wait_for_file(self) -> None:
        while not os.path.exists(self.path):
            logger.warning("event=log_missing path=%s", self.path)
            self.sleep(MISSING_FILE_RETRY_SECONDS)

    def follow(self, should_stop=lambda: False):
        """Generator: yield lines forever until should_stop() returns True."""
        while not should_stop():
            try:
                lines = self.read_available_lines()
            except FileNotFoundError:
                self.close()
                self.wait_for_file()
                continue
            if not lines:
                self.sleep(POLL_INTERVAL_SECONDS)
                continue
            for line in lines:
                yield line
