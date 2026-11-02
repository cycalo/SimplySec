"""Glue between the pages and the engine: scans, the fix flow, Keep and undo.

When SimplySec runs as administrator, fixes and undo run in-process on a worker thread.
Otherwise the confirmed selection is handed to one elevated ``simplysec fix``/``undo`` call
(Windows shows a UAC prompt); the elevated process re-derives the plan from a fresh scan and
re-checks every action against the allow-lists. Results are then read from the journal.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QMessageBox, QWidget

from ..app import elevation, paths
from ..core.engine import Engine, NeedsAdmin, Plan, ScanResult, Selection
from ..core.history import compare
from ..core.journal import Journal
from ..core.models import Finding, FixOption
from ..core.progress import NETWORK_STEPS_PER_TARGET, SCAN_STEPS
from .widgets.fix_dialogs import PreviewDialog, ResultDialog, ResultLine
from .workers import run_in_background

log = logging.getLogger(__name__)


class Controller(QObject):
    busy_changed = Signal(bool, str)
    progress = Signal(str)
    scan_finished = Signal(object)  # ScanResult
    changes_updated = Signal()
    error = Signal(str)
    show_finding = Signal(object)  # Finding: navigate to its full card

    def __init__(self, parent_widget: QWidget) -> None:
        super().__init__(parent_widget)
        self.window = parent_widget
        self.engine = Engine()
        self.result: ScanResult | None = None
        self.previous: dict[str, Any] | None = None
        self.busy = False
        self.task_steps = 0
        self.task_typical: float | None = None
        self._history_warned = False

    # ----------------------------------------------------------------- state
    @property
    def is_admin(self) -> bool:
        return elevation.is_admin()

    def journal(self) -> Journal:
        return Journal(paths.journal_path(), readonly=not self.is_admin)

    def _set_busy(
        self, busy: bool, text: str = "", steps: int = 0, typical: float | None = None
    ) -> None:
        """``steps``/``typical`` describe the task for the progress panel (0: unknown)."""
        self.busy = busy
        self.task_steps, self.task_typical = steps, typical
        self.busy_changed.emit(busy, text)

    def _typical(self, key: str, default: float) -> float:
        """How long this task took last time on this PC (or a typical default)."""
        try:
            value = self.engine.history.get_setting(key)
        except Exception:
            value = None
        return float(value) if value else default

    def _remember_duration(self, key: str, started: float) -> None:
        try:
            self.engine.history.set_setting(key, round(time.monotonic() - started, 1))
        except Exception as exc:
            log.debug("could not store duration: %s", exc)

    def comparison(self) -> Any:
        if self.result is None:
            return None
        return compare(self.previous, self.result.to_dict(include_facts=False))

    # ----------------------------------------------------------------- scan
    def start_scan(self, then: Any = None) -> None:
        if self.busy:
            return
        self._set_busy(
            True, "Scanning this PC…", SCAN_STEPS, self._typical("last_scan_seconds", 15)
        )
        started = time.monotonic()

        def work(progress: Any) -> tuple[ScanResult, dict[str, Any] | None]:
            prev = None
            try:
                latest = self.engine.history.latest(1)
                prev = latest[0] if latest else None
            except Exception as exc:
                log.warning("history unavailable: %s", exc)
            res = self.engine.scan(progress=progress)
            self._remember_duration("last_scan_seconds", started)
            return res, prev

        def done(value: tuple[ScanResult, dict[str, Any] | None]) -> None:
            self.result, self.previous = value
            self.scan_finished.emit(self.result)
            if then:
                then()

        run_in_background(
            work,
            on_result=done,
            on_error=lambda e: self.error.emit(f"The scan failed: {e}"),
            on_progress=self.progress.emit,
            on_finished=lambda: self._set_busy(False),
        )

    def scan_network(self, targets: list[Any], deep: bool = False) -> None:
        """Scan confirmed home networks and merge the devices into the current result."""
        if self.busy or self.result is None:
            return
        self._set_busy(
            True,
            "Scanning your network…",
            NETWORK_STEPS_PER_TARGET * len(targets),
            self._typical("last_network_scan_seconds", 40),
        )
        current = self.result
        started = time.monotonic()

        def work(progress: Any) -> ScanResult:
            from ..core import lan

            lan.scan_network(self.engine, current, targets, progress=progress, deep=deep)
            if not deep:
                self._remember_duration("last_network_scan_seconds", started)
            try:
                self.engine.history.save_scan(current, kind="network")
            except Exception as exc:
                log.warning("could not save network scan: %s", exc)
            return current

        def done(res: ScanResult) -> None:
            self.result = res
            self.scan_finished.emit(res)

        run_in_background(
            work,
            on_result=done,
            on_error=lambda e: self.error.emit(f"The network scan failed: {e}"),
            on_progress=self.progress.emit,
            on_finished=lambda: self._set_busy(False),
        )

    def set_daily_check(self, enable: bool, time: str) -> None:
        if self.busy:
            return
        self._set_busy(True, "Updating the daily check…")

        def work(progress: Any) -> str:
            from ..core import monitor

            if self.is_admin:
                if enable:
                    res = monitor.enable(self.engine, time)
                    return (
                        f"Daily check scheduled at {time}."
                        if res.ok
                        else "Could not schedule the daily check."
                    )
                return (
                    "Daily check removed."
                    if monitor.disable(self.engine)
                    else "Could not remove the daily check."
                )
            argv = ["monitor", "--enable", time] if enable else ["monitor", "--disable"]
            code = elevation.run_elevated_and_wait(argv)
            if code is None:
                return "Administrator permission was not given, so nothing changed."
            if code == 0:
                settings = self.engine.history.get_setting(monitor.SETTING, {}) or {}
                self.engine.history.set_setting(
                    monitor.SETTING, {**settings, "enabled": enable, "time": time}
                )
            return "Done." if code == 0 else f"Finished with problems (code {code})."

        def done(message: str) -> None:
            self.changes_updated.emit()
            if self.result is not None:
                self.scan_finished.emit(self.result)
            QMessageBox.information(self.window, "Daily check", message)

        run_in_background(
            work,
            on_result=done,
            on_error=lambda e: self.error.emit(f"Could not change the daily check: {e}"),
            on_progress=self.progress.emit,
            on_finished=lambda: self._set_busy(False),
        )

    # ----------------------------------------------------------------- keep
    def keep(self, finding: Finding) -> None:
        if not finding.keep_key:
            return
        self.engine.history.accept(finding.keep_key, finding.width, finding.title)
        self.start_scan()

    def unkeep(self, key: str) -> None:
        self.engine.history.unaccept(key)
        self.start_scan()

    # ----------------------------------------------------------------- fixes
    def request_fix(self, finding: Finding | None, option: FixOption) -> None:
        if option.guidance_only:
            self._open_guidance(option)
            return
        self.request_fixes(
            [Selection(option.fix_id, option.params, finding.id if finding else None)]
        )

    def request_recommended(self) -> None:
        sels = self.engine.recommended(self.result)
        if not sels:
            QMessageBox.information(
                self.window,
                "Nothing to fix",
                "There are no recommended, non-disruptive fixes for the open findings.",
            )
            return
        self.request_fixes(sels)

    def _open_guidance(self, option: FixOption) -> None:
        from ..core.checks import FIXES
        from ..windows import system

        fix = FIXES.get(option.fix_id)
        if fix and fix.guidance:
            try:
                system.open_settings(fix.guidance)
            except Exception as exc:
                self.error.emit(f"Could not open Settings: {exc}")

    def request_fixes(self, selections: list[Selection]) -> None:
        if self.busy:
            return
        plan = self.engine.plan(selections)
        if not plan.items:
            QMessageBox.warning(
                self.window, "Can't apply", "\n".join(plan.refused) or "Nothing to apply."
            )
            return
        findings = {f.id: f for f in (self.result.findings if self.result else [])}
        dlg = PreviewDialog(plan, self.is_admin, self.window, findings)
        dlg.exec()
        choice = dlg.choice()
        if not choice.accepted:
            return
        if choice.extra:
            extra = [
                Selection(w.offer_fix, w.offer_params, None) for w in choice.extra if w.offer_fix
            ]
            selections = extra + selections
            plan = self.engine.plan(selections)
        before = self.result
        if self.is_admin:
            self._apply_in_process(plan, choice.restore_point, before)
        else:
            self._apply_elevated(selections, plan, choice.restore_point, bool(choice.extra), before)

    def _apply_in_process(self, plan: Plan, restore_point: bool, before: ScanResult | None) -> None:
        self._set_busy(True, "Applying changes…")

        def work(progress: Any) -> tuple[Any, ScanResult]:
            res = self.engine.apply(plan, restore_point=restore_point, progress=progress)
            after = self.engine.scan(progress=progress)
            return res, after

        def done(value: tuple[Any, ScanResult]) -> None:
            res, after = value
            lines = [
                ResultLine(o.spec.summary, o.status, o.verified, o.error) for o in res.outcomes
            ]
            self._show_results(lines, plan, before, after, res.warnings)

        run_in_background(
            work,
            on_result=done,
            on_error=lambda e: self.error.emit(f"Applying failed: {e}"),
            on_progress=self.progress.emit,
            on_finished=lambda: self._set_busy(False),
        )

    def _apply_elevated(
        self,
        selections: list[Selection],
        plan: Plan,
        restore_point: bool,
        mark_private: bool,
        before: ScanResult | None,
    ) -> None:
        self._set_busy(True, "Waiting for administrator permission…")
        last_batch = max(
            (b.id for b in Journal(paths.journal_path(), readonly=True).batches()), default=0
        )
        argv = ["fix"]
        for sel in selections:
            if sel.finding_id and not sel.fix_id.startswith("network."):
                argv += ["--select", f"{sel.finding_id}={sel.fix_id}"]
        if mark_private:
            argv.append("--mark-private")
        if restore_point:
            argv.append("--restore-point")
        argv.append("--yes")

        def work(progress: Any) -> tuple[int | None, list[Any], ScanResult]:
            code = elevation.run_elevated_and_wait(argv)
            progress("Checking the result…")
            journal = Journal(paths.journal_path(), readonly=True)
            changes = [c for c in journal.changes() if c.batch_id > last_batch]
            after = self.engine.scan(progress=progress)
            return code, changes, after

        def done(value: tuple[int | None, list[Any], ScanResult]) -> None:
            code, changes, after = value
            if code is None:
                QMessageBox.information(
                    self.window,
                    "Nothing changed",
                    "Administrator permission was not given, so nothing was changed.",
                )
                self.result = after
                self.scan_finished.emit(after)
                return
            lines = [ResultLine(c.summary, c.status, c.verified, c.error or "") for c in changes]
            warnings = (
                []
                if code == 0
                else [
                    f"The elevated helper finished with code {code}. Details are in {paths.log_dir()}."
                ]
            )
            if not lines:
                warnings.append("No changes were recorded.")
            self._show_results(lines, plan, before, after, warnings)

        run_in_background(
            work,
            on_result=done,
            on_error=lambda e: self.error.emit(f"Applying failed: {e}"),
            on_progress=self.progress.emit,
            on_finished=lambda: self._set_busy(False),
        )

    def _show_results(
        self,
        lines: list[ResultLine],
        plan: Plan,
        before: ScanResult | None,
        after: ScanResult,
        warnings: list[str],
    ) -> None:
        ids = [i.finding_id for i in plan.items if i.finding_id]
        resolved = Engine.resolved(before, after, ids) if before else {}
        titles = {f.id: f.title for f in (before.findings if before else [])}
        self.previous = before.to_dict(include_facts=False) if before else self.previous
        self.result = after
        self.scan_finished.emit(after)
        self.changes_updated.emit()
        ResultDialog(
            lines,
            resolved,
            titles,
            before.score if before else None,
            after.score,
            warnings,
            self.window,
        ).exec()

    # ----------------------------------------------------------------- undo
    def undo(
        self,
        change_ids: list[int] | None = None,
        batch_id: int | None = None,
        everything: bool = False,
        rules: bool = False,
    ) -> None:
        if self.busy:
            return
        what = (
            "every change SimplySec made"
            if everything
            else "all SimplySec firewall rules"
            if rules
            else f"batch {batch_id}"
            if batch_id
            else f"{len(change_ids or [])} change(s)"
        )
        if (
            QMessageBox.question(
                self.window, "Undo", f"Undo {what}? The previous settings will be restored."
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        self._set_busy(True, "Undoing…")

        def work(progress: Any) -> tuple[list[str], ScanResult]:
            messages: list[str] = []
            if self.is_admin:
                if rules:
                    outcomes, leftovers = self.engine.remove_all_rules()
                    messages += [f"Removed unrecorded SimplySec rule {n}" for n in leftovers]
                else:
                    outcomes = self.engine.undo(
                        change_ids=change_ids, batch_id=batch_id, everything=everything
                    )
                for o in outcomes:
                    messages.append(
                        f"{'Restored' if o.ok else 'FAILED'}: {o.change.summary}"
                        + (f" ({o.error})" if o.error else "")
                    )
            else:
                argv = ["undo", "--yes"]
                if everything:
                    argv.append("--all")
                elif rules:
                    argv.append("--rules")
                elif batch_id:
                    argv += ["--batch", str(batch_id)]
                else:
                    argv += ["--change", *map(str, change_ids or [])]
                code = elevation.run_elevated_and_wait(argv)
                if code is None:
                    messages.append(
                        "Administrator permission was not given, so nothing was undone."
                    )
                else:
                    messages.append(
                        "Undo finished."
                        if code == 0
                        else f"Undo finished with problems (code {code}); see the Changes page."
                    )
            progress("Checking the result…")
            return messages, self.engine.scan(progress=progress)

        def done(value: tuple[list[str], ScanResult]) -> None:
            messages, after = value
            self.result = after
            self.scan_finished.emit(after)
            self.changes_updated.emit()
            QMessageBox.information(self.window, "Undo", "\n".join(messages) or "Nothing to undo.")

        def failed(e: str) -> None:
            if isinstance(e, str) and "administrator" in e.lower():
                self.error.emit(str(NeedsAdmin(e)))
            else:
                self.error.emit(f"Undo failed: {e}")

        run_in_background(
            work,
            on_result=done,
            on_error=failed,
            on_progress=self.progress.emit,
            on_finished=lambda: self._set_busy(False),
        )
