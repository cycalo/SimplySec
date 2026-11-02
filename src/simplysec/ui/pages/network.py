"""My network: devices, the router (UPnP port forwards) and this PC's saved Wi-Fi networks."""

from __future__ import annotations

import html
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from ...core import knowledge, lan
from ...core.lan.inventory import Device, risky_services
from ...core.models import Finding, FindingStatus, Severity
from ...core.util import as_list
from ..controller import Controller
from ..widgets import card, label
from ..widgets.finding_card import FindingCard
from . import Page

COLUMNS = ["Trusted", "Name", "Vendor", "IP", "First seen", "Last seen", "Services"]


class NetworkPage(Page):
    def __init__(self, ctl: Controller) -> None:
        super().__init__(
            "My network",
            "Devices on your home network, your router's port forwards and this PC's saved Wi-Fi "
            "networks. SimplySec only scans networks you confirm are yours, and never changes other devices.",
        )
        self.ctl = ctl
        row = QHBoxLayout()
        self.scan_btn = QPushButton("Scan my network")
        self.scan_btn.setObjectName("Primary")
        self.scan_btn.clicked.connect(self._scan)
        row.addWidget(self.scan_btn)
        self.deep = QCheckBox("Deep scan with nmap (if installed)")
        row.addWidget(self.deep)
        row.addStretch(1)
        self.body.addLayout(row)
        self.targets = label("", object_name="Dim", rich=True)
        self.body.addWidget(self.targets)

        self.body.addWidget(label("Devices", object_name="SectionTitle"))
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setMinimumHeight(260)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        for col, w in enumerate([70, 220, 180, 110, 110, 110]):
            self.table.setColumnWidth(col, w)
        self.table.itemChanged.connect(self._trusted_changed)
        self.table.cellClicked.connect(self._row_clicked)
        self.body.addWidget(self.table)

        self.advice_title = label("What to do about your devices", object_name="SectionTitle")
        self.body.addWidget(self.advice_title)
        self.advice_note = label(
            "SimplySec never changes other devices. Each card says what the risk is and what to "
            "change in that device's settings or app. Click a device in the table to jump to it.",
            object_name="Dim",
        )
        self.body.addWidget(self.advice_note)
        self.advice = QVBoxLayout()
        self.advice.setSpacing(10)
        self.body.addLayout(self.advice)
        self.device_cards: dict[str, FindingCard] = {}

        self.router_card, self.router_layout = card()
        self.body.addWidget(self.router_card)
        self.wifi_card, self.wifi_layout = card()
        self.body.addWidget(self.wifi_card)
        ctl.scan_finished.connect(lambda _r: self.refresh())
        ctl.busy_changed.connect(lambda busy, _t: self.scan_btn.setEnabled(not busy))
        self.refresh()

    # ----------------------------------------------------------------- actions
    def _scan(self) -> None:
        result = self.ctl.result
        if result is None:
            QMessageBox.information(
                self, "Scan first", "Run a scan of this PC first (Overview > Scan & Protect)."
            )
            return
        targets = lan.scan_targets(result.interfaces)
        if not targets:
            QMessageBox.information(
                self,
                "No home network",
                "This PC isn't connected to a home network SimplySec can scan (only VPN, virtual or public-address adapters).",
            )
            return
        history = self.ctl.engine.history
        for t in targets:
            if lan.is_owned(history, t):
                continue
            answer = QMessageBox.question(
                self,
                "Is this your network?",
                f"Is <b>{html.escape(t.label)}</b> your network?<br><br>SimplySec will look for devices on it "
                "and check which services they offer. Only scan networks you own or manage, never "
                "public Wi-Fi.",
            )
            if answer == QMessageBox.StandardButton.Yes:
                lan.set_owned(history, t, True)
        owned = [t for t in targets if lan.is_owned(history, t)]
        if owned:
            self.ctl.scan_network(owned, deep=self.deep.isChecked())
        self.refresh()

    def _trusted_changed(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        mac = item.data(Qt.ItemDataRole.UserRole)
        if mac:
            self.ctl.engine.history.set_device_trusted(
                mac, item.checkState() == Qt.CheckState.Checked
            )

    # ----------------------------------------------------------------- display
    def refresh(self) -> None:
        result = self.ctl.result
        history = self.ctl.engine.history
        if result is not None:
            targets = lan.scan_targets(result.interfaces)
            parts = []
            for t in targets:
                state = (
                    "confirmed as yours"
                    if lan.is_owned(history, t)
                    else "not confirmed yet (you'll be asked)"
                )
                parts.append(f"{html.escape(t.label)}: {state}")
            self.targets.setText(
                "<br>".join(parts) or "No home network found on this PC's adapters."
            )
        extras = result.extras if result else {}
        devices = extras.get("devices")
        self._fill_devices(devices if devices is not None else self._stored_devices())
        findings = [
            f for f in (result.findings if result else []) if f.status == FindingStatus.OPEN
        ]
        self._fill_advice([f for f in findings if f.check == "lan"])
        self._fill_router(extras.get("router") or {})
        for f in findings:
            if f.check == "router" and f.severity > Severity.INFO:
                self.router_layout.addWidget(self._card(f))
        self._fill_wifi(result.facts.get("wifi", {}).get("value") if result else None)

    def _card(self, f: Finding) -> FindingCard:
        c = FindingCard(f, show_advice=True)
        c.fix_requested.connect(self.ctl.request_fix)
        c.keep_requested.connect(self.ctl.keep)
        c.unkeep_requested.connect(lambda fi: self.ctl.unkeep(fi.keep_key))
        return c

    def _fill_advice(self, findings: list[Finding]) -> None:
        self.clear(self.advice)
        self.device_cards = {}
        if not findings:
            text = (
                "No risky services or unknown new devices found."
                if self.ctl.result and self.ctl.result.extras.get("devices")
                else "Scan your network to get advice about its devices."
            )
            self.advice.addWidget(label(text, object_name="Dim"))
            return
        for f in findings:
            c = self._card(f)
            mac = f.id.rsplit(".", 1)[-1]
            self.device_cards.setdefault(mac, c)
            self.advice.addWidget(c)

    def _row_clicked(self, row: int, _col: int) -> None:
        item = self.table.item(row, 0)
        mac = item.data(Qt.ItemDataRole.UserRole) if item else None
        card = self.device_cards.get(mac or "")
        if card is None:
            return
        self.ensureWidgetVisible(card, 0, 40)
        card.setStyleSheet("#Card { border: 2px solid palette(highlight); }")
        QTimer.singleShot(2000, lambda: card.setStyleSheet(""))

    def _stored_devices(self) -> list[dict[str, Any]]:
        out = []
        for d in self.ctl.engine.history.devices():
            out.append(
                {
                    "ip": d["ip"],
                    "mac": d["mac"],
                    "vendor": d["vendor"],
                    "name": d.get("label") or d.get("name") or "",
                    "first_seen": d["first_seen"],
                    "last_seen": d["last_seen"],
                    "trusted": d["trusted"],
                    "open_ports": d["data"].get("open_ports", []),
                    "randomized": False,
                }
            )
        return out

    def _fill_devices(self, devices: list[dict[str, Any]]) -> None:
        kb = knowledge.get()
        self.table.blockSignals(True)
        self.table.setRowCount(len(devices))
        for row, d in enumerate(devices):
            trusted = QTableWidgetItem()
            trusted.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            trusted.setCheckState(
                Qt.CheckState.Checked if d.get("trusted") else Qt.CheckState.Unchecked
            )
            trusted.setData(Qt.ItemDataRole.UserRole, d.get("mac"))
            self.table.setItem(row, 0, trusted)
            name = d.get("name") or ""
            if not name and d.get("randomized"):
                name = "Private address (likely a phone)"
            elif not name:
                name = f"{d['vendor']} device" if d.get("vendor") else "Unknown device"
            if d.get("is_gateway"):
                name = f"{name or 'Router'} (router)"
            if d.get("new"):
                name = f"{name} – new"
            dev = Device(
                ip=d.get("ip", ""),
                mac=d.get("mac", ""),
                open_ports=d.get("open_ports", []),
                is_gateway=bool(d.get("is_gateway")),
            )
            risky = {p for p, _, _ in risky_services(dev, kb)}
            services = []
            for p in d.get("open_ports", []):
                info = kb.port("tcp", p)
                text = f"{p} {info.name}" if info else str(p)
                services.append(f"⚠ {text}" if p in risky else text)
            values = [
                name,
                d.get("vendor") or "",
                d.get("ip", ""),
                (d.get("first_seen") or "")[:10],
                (d.get("last_seen") or "")[:10],
                ", ".join(services),
            ]
            for col, v in enumerate(values, start=1):
                item = QTableWidgetItem(v)
                if col == 6 and risky:
                    item.setToolTip("⚠ marks services that are often attacked")
                self.table.setItem(row, col, item)
        self.table.blockSignals(False)

    def _fill_router(self, router: dict[str, Any]) -> None:
        self.clear(self.router_layout)
        self.router_layout.addWidget(label("Router", object_name="SectionTitle"))
        if not router:
            self.router_layout.addWidget(
                label(
                    "Scan your network to read your router's UPnP status and port forwards.",
                    object_name="Dim",
                )
            )
            return
        if not router.get("found"):
            self.router_layout.addWidget(
                label("Your router does not offer UPnP port forwarding. That's the safer setting.")
            )
            return
        name = router.get("friendly_name") or router.get("model") or "Your router"
        ext = router.get("external_ip") or "unknown"
        cgnat = (
            " (a private address: your provider blocks connections from the internet)"
            if router.get("external_is_private")
            else ""
        )
        self.router_layout.addWidget(
            label(
                f"<b>{html.escape(name)}</b> has UPnP turned on. Internet address: {html.escape(ext)}{cgnat}.",
                rich=True,
            )
        )
        maps = router.get("mappings", [])
        if not maps:
            self.router_layout.addWidget(
                label("No port forwards are open right now.", object_name="Dim")
            )
        for m in maps:
            line = f"{m.get('protocol')} {m.get('external_port')} → {m.get('internal_client')}:{m.get('internal_port')} – {m.get('description') or 'no description'}"
            self.router_layout.addWidget(label(html.escape(line), rich=True))
        if router.get("error"):
            self.router_layout.addWidget(
                label(f"Note: {html.escape(router['error'])}", object_name="Dim")
            )

    def _fill_wifi(self, profiles: Any) -> None:
        self.clear(self.wifi_layout)
        self.wifi_layout.addWidget(
            label("Saved Wi-Fi networks on this PC", object_name="SectionTitle")
        )
        items = as_list(profiles)
        if not items:
            self.wifi_layout.addWidget(
                label("No saved Wi-Fi networks (or no Wi-Fi adapter).", object_name="Dim")
            )
            return
        for p in items:
            sec = p.get("weak") or f"{p.get('authentication')} / {p.get('encryption')}"
            mode = (
                "connects automatically"
                if p.get("connection_mode") == "auto"
                else "only when you choose it"
            )
            mark = "⚠ " if p.get("weak") else ""
            self.wifi_layout.addWidget(
                label(
                    f"{mark}<b>{html.escape(p.get('name', ''))}</b> – {html.escape(sec)}, {mode}",
                    rich=True,
                )
            )
