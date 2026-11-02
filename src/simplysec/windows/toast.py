"""Windows toast notifications through PowerShell's WinRT bridge (no extra package)."""

from __future__ import annotations

import logging
from xml.sax.saxutils import escape

from . import runner

log = logging.getLogger(__name__)

# PowerShell's registered AppUserModelID: lets an unpackaged app show toasts.
APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

_SCRIPT = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($P.xml)
$toast = New-Object Windows.UI.Notifications.ToastNotification $doc
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($P.app).Show($toast)
'null'
"""


def toast_xml(title: str, lines: list[str]) -> str:
    texts = "".join(f"<text>{escape(line[:200])}</text>" for line in lines[:2])
    return (
        '<toast><visual><binding template="ToastGeneric">'
        f"<text>{escape(title[:120])}</text>{texts}"
        "</binding></visual></toast>"
    )


def show(title: str, lines: list[str]) -> bool:
    try:
        runner.powershell_json(_SCRIPT, {"xml": toast_xml(title, lines), "app": APP_ID}, timeout=30)
        return True
    except Exception as exc:
        log.warning("toast failed: %s", exc)
        return False
