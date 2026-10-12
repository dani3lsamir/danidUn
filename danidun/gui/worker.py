"""Run blocking work off the Tk thread and marshal results back safely."""
from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk

log = logging.getLogger(__name__)


class Dispatcher:
    """Thread-safe bridge: background threads post callables, the Tk loop runs them."""

    def __init__(self, root: tk.Misc, interval: int = 60) -> None:
        self.root = root
        self.queue: queue.Queue = queue.Queue()
        self.interval = interval
        self._alive = True
        root.after(interval, self._pump)

    def post(self, fn, *args) -> None:
        self.queue.put((fn, args))

    def _pump(self) -> None:
        if not self._alive:
            return
        try:
            while True:
                fn, args = self.queue.get_nowait()
                try:
                    fn(*args)
                except Exception:  # noqa: BLE001 - never kill the UI loop
                    log.exception("UI callback failed")
        except queue.Empty:
            pass
        try:
            self.root.after(self.interval, self._pump)
        except tk.TclError:
            self._alive = False

    def stop(self) -> None:
        self._alive = False

    def run(self, work, on_done=None, on_error=None) -> threading.Thread:
        def target():
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                log.exception("background task failed")
                if on_error:
                    self.post(on_error, exc)
                return
            if on_done:
                self.post(on_done, result)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        return thread

    def ask(self, fn) -> object:
        """From a worker thread: run ``fn`` on the UI thread and wait for its return value."""
        done = threading.Event()
        box: list = []

        def call():
            try:
                box.append(fn())
            finally:
                done.set()

        self.post(call)
        done.wait()
        return box[0] if box else None
