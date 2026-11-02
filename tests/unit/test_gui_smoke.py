"""GUI smoke test: every page renders a real scan; the preview dialog builds; nothing blocks."""

from __future__ import annotations

import pytest

pytest.importorskip("pytestqt")

from simplysec.core.engine import Selection, analyze_with_context


@pytest.fixture
def window(qtbot, qapp, this_pc_raw):
    from simplysec.ui import theme
    from simplysec.ui.main_window import MainWindow

    theme.apply(qapp)
    w = MainWindow()
    qtbot.addWidget(w)
    result, ctx = analyze_with_context(this_pc_raw)
    eng = w.ctl.engine
    eng.last_raw, eng.last_result, eng.last_ctx = this_pc_raw, result, ctx
    w.ctl.result = result
    w.ctl.scan_finished.emit(result)
    return w


def test_pages_render(window, qtbot):
    for i in range(window.nav.count()):
        window.nav.setCurrentRow(i)
        qtbot.wait(10)
    ports = window.pages["Open ports"]
    assert ports.model.rowCount() > 20
    assert ports.proxy.rowCount() < ports.model.rowCount()  # "reachable only" filter is on
    overview = window.pages["Overview"]
    assert overview.ring.score == window.ctl.result.score


def test_preview_dialog_lists_changes_and_offer(window):
    from simplysec.ui.widgets.fix_dialogs import PreviewDialog

    plan = window.ctl.engine.plan(
        [Selection("exposure.block_program_public", {"exe": r"C:\x\a.exe", "label": "A"}, None)]
    )
    dlg = PreviewDialog(plan, is_admin=False)
    assert dlg._offers, "the Public-network warning should offer to mark the network Private"
    assert dlg.choice().accepted is False
