# Email delivery off the monitoring loop: bounded queue + one worker thread.
import logging
import queue
import threading

from actions import send_email

logger = logging.getLogger("sshbouncer.notify")

DEFAULT_QUEUE_SIZE = 100
SHUTDOWN_TIMEOUT_SECONDS = 35  # one SMTP timeout plus slack


class EmailNotifier:
    """Queues alerts and delivers them in the background.

    Overflow policy: when the queue is full the newest alert is dropped and logged.
    Delivery is best effort; failures are logged by send_email and never raised here.
    """

    def __init__(self, config: dict, max_queue_size: int = DEFAULT_QUEUE_SIZE, sender=send_email):
        self.config = config
        self.send = sender
        self.queue = queue.Queue(maxsize=max_queue_size)
        self.worker = threading.Thread(target=self.deliver_forever, name="email-notifier", daemon=True)
        self.dropped = 0
        self.stop_sentinel = object()

    @property
    def enabled(self) -> bool:
        return bool(self.config.get("email_enabled"))

    def start(self) -> None:
        if self.enabled:
            self.worker.start()

    def enqueue(self, subject: str, body: str) -> bool:
        """Queue one alert. Returns False when email is off or the queue is full."""
        if not self.enabled:
            return False
        try:
            self.queue.put_nowait((subject, body))
        except queue.Full:
            self.dropped += 1
            logger.warning(
                "event=email_dropped reason=queue_full subject=%r dropped_total=%d",
                subject, self.dropped,
            )
            return False
        return True

    def deliver_forever(self) -> None:
        while True:
            item = self.queue.get()
            if item is self.stop_sentinel:
                return
            subject, body = item
            self.send(subject=subject, body=body, config=self.config)

    def shutdown(self, timeout: float = SHUTDOWN_TIMEOUT_SECONDS) -> None:
        """Let queued alerts drain, then stop the worker. Logs what could not be delivered in time."""
        if not self.worker.is_alive():
            return
        self.queue.put(self.stop_sentinel)
        self.worker.join(timeout)
        if self.worker.is_alive():
            logger.warning("event=email_shutdown_timeout pending=%d", self.queue.qsize())
