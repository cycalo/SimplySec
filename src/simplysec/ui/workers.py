"""Run slow work (scans, fixes, undo) on a QThreadPool so the window never freezes."""

from __future__ import annotations

import inspect
import logging
import traceback
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

log = logging.getLogger(__name__)


class WorkerSignals(QObject):
    progress = Signal(str)
    result = Signal(object)
    error = Signal(str)
    finished = Signal()


class Worker(QRunnable):
    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs
        self.signals = WorkerSignals()
        self.setAutoDelete(True)

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
        finally:
            self.signals.finished.emit()


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
    if on_result:
        worker.signals.result.connect(on_result)
    if on_error:
        worker.signals.error.connect(on_error)
    if on_progress:
        worker.signals.progress.connect(on_progress)
    if on_finished:
        worker.signals.finished.connect(on_finished)
    QThreadPool.globalInstance().start(worker)
    return worker
