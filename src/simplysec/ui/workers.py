"""Run slow work (scans, fixes, undo) on a QThreadPool so the window never freezes.

Every task ends with exactly one signal (``result`` or ``error``) delivered on the GUI thread.
The "finished" callback runs from that same delivery, before the result handler, so the busy
state always clears (and clears before any result dialog opens). Workers are kept referenced
until then, so a queued signal can't be lost when Python frees the worker.
"""

from __future__ import annotations

import inspect
import logging
import traceback
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

log = logging.getLogger(__name__)

_running: set[Worker] = set()


class WorkerSignals(QObject):
    progress = Signal(str)
    result = Signal(object)
    error = Signal(str)


class Worker(QRunnable):
    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs
        self.signals = WorkerSignals()
        self.setAutoDelete(False)

    def run(self) -> None:
        try:
            if (
                "progress" in inspect.signature(self.fn).parameters
                and "progress" not in self.kwargs
            ):
                self.kwargs["progress"] = self.signals.progress.emit
        except (TypeError, ValueError):
            pass
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as exc:
            log.error("background task failed: %s", traceback.format_exc())
            self.signals.error.emit(str(exc) or exc.__class__.__name__)
        else:
            self.signals.result.emit(result)


def run_in_background(
    fn: Callable[..., Any],
    *args: Any,
    on_result: Callable[[Any], None] | None = None,
    on_error: Callable[[str], None] | None = None,
    on_progress: Callable[[str], None] | None = None,
    on_finished: Callable[[], None] | None = None,
    **kwargs: Any,
) -> Worker:
    worker = Worker(fn, *args, **kwargs)

    def end(handler: Callable[[Any], None] | None, value: Any) -> None:
        _running.discard(worker)
        try:
            if on_finished:
                on_finished()
        finally:
            if handler:
                handler(value)

    worker.signals.result.connect(lambda value: end(on_result, value))
    worker.signals.error.connect(lambda message: end(on_error, message))
    if on_progress:
        worker.signals.progress.connect(on_progress)
    _running.add(worker)
    QThreadPool.globalInstance().start(worker)
    return worker
