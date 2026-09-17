import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from notify import EmailNotifier  # noqa: E402


def config(enabled=True):
    return {"email_enabled": enabled, "email_to": "a@example.com"}


class EmailNotifierTests(unittest.TestCase):
    def test_disabled_notifier_never_starts_or_queues(self):
        sender = mock.Mock()
        notifier = EmailNotifier(config(enabled=False), sender=sender)
        notifier.start()
        self.assertFalse(notifier.enqueue("s", "b"))
        self.assertFalse(notifier.worker.is_alive())
        notifier.shutdown()
        sender.assert_not_called()

    def test_alerts_are_delivered_in_background(self):
        delivered = threading.Event()
        sender = mock.Mock(side_effect=lambda **_: delivered.set() or True)
        notifier = EmailNotifier(config(), sender=sender)
        notifier.start()
        self.assertTrue(notifier.enqueue("subject", "body"))
        self.assertTrue(delivered.wait(2))
        notifier.shutdown(timeout=2)
        sender.assert_called_once_with(subject="subject", body="body", config=config())

    def test_enqueue_returns_immediately_while_delivery_is_slow(self):
        release = threading.Event()
        sender = mock.Mock(side_effect=lambda **_: release.wait(5))
        notifier = EmailNotifier(config(), sender=sender)
        notifier.start()
        for _ in range(3):
            self.assertTrue(notifier.enqueue("s", "b"))
        release.set()
        notifier.shutdown(timeout=2)
        self.assertEqual(sender.call_count, 3)

    def test_full_queue_drops_newest_and_counts(self):
        notifier = EmailNotifier(config(), max_queue_size=2, sender=mock.Mock())
        # worker not started, so nothing drains
        self.assertTrue(notifier.enqueue("1", "b"))
        self.assertTrue(notifier.enqueue("2", "b"))
        self.assertFalse(notifier.enqueue("3", "b"))
        self.assertEqual(notifier.dropped, 1)
        self.assertEqual(notifier.queue.qsize(), 2)

    def test_sender_failure_does_not_kill_worker(self):
        calls = []
        done = threading.Event()

        def sender(**kwargs):
            calls.append(kwargs["subject"])
            if len(calls) == 2:
                done.set()
            return False

        notifier = EmailNotifier(config(), sender=sender)
        notifier.start()
        notifier.enqueue("first", "b")
        notifier.enqueue("second", "b")
        self.assertTrue(done.wait(2))
        notifier.shutdown(timeout=2)
        self.assertEqual(calls, ["first", "second"])

    def test_shutdown_before_start_is_safe(self):
        EmailNotifier(config(), sender=mock.Mock()).shutdown()


if __name__ == "__main__":
    unittest.main()
