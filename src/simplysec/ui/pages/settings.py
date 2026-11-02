"""Settings: administrator status, accepted risks, data folders (daily check and owned
networks are added by later milestones through ``extra_sections``)."""

from __future__ import annotations

import html
import os

from PySide6.QtWidgets import QApplication, QHBoxLayout, QMessageBox, QPushButton, QVBoxLayout

from ...app import elevation, paths
from ..controller import Controller
from ..widgets import card, label
from . import Page


class SettingsPage(Page):
    def __init__(self, ctl: Controller) -> None:
        super().__init__("Settings")
        self.ctl = ctl

        admin_card, al = card()
        al.addWidget(label("Administrator", object_name="SectionTitle"))
        self.admin_text = label("")
        al.addWidget(self.admin_text)
        self.restart = QPushButton("Restart as administrator")
        self.restart.clicked.connect(self._restart)
        row = QHBoxLayout()
        row.addWidget(self.restart)
        row.addStretch(1)
        al.addLayout(row)
        self.body.addWidget(admin_card)

        self.extra = QVBoxLayout()
        self.body.addLayout(self.extra)
        self._build_daily_check()

        nets_card, self.nets_layout = card()
        self.body.addWidget(nets_card)

        acc_card, self.acc_layout = card()
        self.body.addWidget(acc_card)

        data_card, dl = card()
        dl.addWidget(label("Data folders", object_name="SectionTitle"))
        for title, path in (
            (
                "Change journal and firewall backups (only administrators can change these)",
                paths.data_dir(),
            ),
            ("Your scan history, settings and log", paths.user_dir()),
        ):
            r = QHBoxLayout()
            r.addWidget(label(f"{title}:<br><code>{html.escape(str(path))}</code>", rich=True), 1)
            btn = QPushButton("Open")
            btn.clicked.connect(lambda _=False, p=path: os.startfile(p) if p.exists() else None)
            r.addWidget(btn)
            dl.addLayout(r)
        self.body.addWidget(data_card)

        ctl.scan_finished.connect(lambda _r: self.refresh())
        self.refresh()

    def refresh(self) -> None:
        admin = elevation.is_admin()
        self.admin_text.setText(
            "SimplySec is running as administrator: fixes and undo apply directly."
            if admin
            else "SimplySec is running in read-only mode. Scans work fully; fixes and undo ask Windows for "
            "administrator permission each time, or you can restart as administrator."
        )
        self.restart.setVisible(not admin)

        self._fill_networks()
        settings = self.ctl.engine.history.get_setting("daily_check", {}) or {}
        self.daily_status.setText(
            f"On, daily at {settings.get('time')}." if settings.get("enabled") else "Off."
        )
        self.clear(self.acc_layout)
        self.acc_layout.addWidget(label("Accepted risks (Keep)", object_name="SectionTitle"))
        try:
            accepted = self.ctl.engine.history.accepted()
        except Exception as exc:
            self.acc_layout.addWidget(label(f"Could not read: {exc}", object_name="Dim"))
            return
        if not accepted:
            self.acc_layout.addWidget(
                label(
                    "None. Use 'Keep: I need this' on a finding to stop scoring it.",
                    object_name="Dim",
                )
            )
        for a in accepted:
            r = QHBoxLayout()
            r.addWidget(
                label(
                    f"{html.escape(a.get('title') or a['keep_key'])}<br><span style='font-size:9pt'>since {a['created'][:10]}</span>",
                    rich=True,
                ),
                1,
            )
            b = QPushButton("Score again")
            b.clicked.connect(lambda _=False, k=a["keep_key"]: self.ctl.unkeep(k))
            r.addWidget(b)
            self.acc_layout.addLayout(r)

    def _build_daily_check(self) -> None:
        from PySide6.QtCore import QTime
        from PySide6.QtWidgets import QCheckBox, QTimeEdit

        dc, dl = card()
        dl.addWidget(label("Daily check", object_name="SectionTitle"))
        dl.addWidget(
            label(
                "Once a day SimplySec runs a read-only scan in the background and shows a notification "
                "only if something got worse: the risk score rises by 5 or more, a new high-risk finding, "
                "a new device on your network, or antivirus or the firewall turned off. It never "
                "changes anything. The scheduled task is recorded on the Changes page.",
                object_name="Dim",
            )
        )
        row = QHBoxLayout()
        self.daily = QCheckBox("Run the daily check at")
        self.daily_time = QTimeEdit()
        self.daily_time.setDisplayFormat("HH:mm")
        settings = self.ctl.engine.history.get_setting("daily_check", {}) or {}
        hh, mm = (settings.get("time") or "12:00").split(":")
        self.daily_time.setTime(QTime(int(hh), int(mm)))
        self.daily.setChecked(bool(settings.get("enabled")))
        row.addWidget(self.daily)
        row.addWidget(self.daily_time)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._apply_daily)
        row.addWidget(apply_btn)
        row.addStretch(1)
        dl.addLayout(row)
        self.daily_status = label("", object_name="Dim")
        dl.addWidget(self.daily_status)
        self.extra.addWidget(dc)

    def _apply_daily(self) -> None:
        enable = self.daily.isChecked()
        time = self.daily_time.time().toString("HH:mm")
        self.ctl.set_daily_check(enable, time)

    def _fill_networks(self) -> None:
        from ...core import lan

        self.clear(self.nets_layout)
        self.nets_layout.addWidget(label("Networks I own", object_name="SectionTitle"))
        nets = lan.owned_networks(self.ctl.engine.history)
        if not nets:
            self.nets_layout.addWidget(
                label(
                    "None yet. SimplySec asks before it scans a network for devices.",
                    object_name="Dim",
                )
            )
        for key, info in nets.items():
            r = QHBoxLayout()
            confirmed = str(info.get("confirmed", ""))[:10]
            text = f"{html.escape(info.get('label', key))}<br><span style='font-size:9pt'>confirmed {confirmed}</span>"
            r.addWidget(label(text, rich=True), 1)
            b = QPushButton("Forget")
            b.clicked.connect(
                lambda _=False, k=key: (
                    lan.forget_network(self.ctl.engine.history, k),
                    self.refresh(),
                )
            )
            r.addWidget(b)
            self.nets_layout.addLayout(r)

    def _restart(self) -> None:
        if elevation.relaunch_elevated([], gui=True):
            QApplication.quit()
        else:
            QMessageBox.information(
                self, "Not restarted", "Administrator permission was not given."
            )
