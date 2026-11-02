"""The SimplySec daily check as a Task Scheduler task (created from XML, so locale-neutral).

The task runs ``simplysec monitor --run`` as the signed-in user with highest privileges, only
while that user is signed in. It is created and removed through the journaled
``task.schedule`` primitive, so it can be undone like any other change.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
import tempfile
from pathlib import Path
from xml.sax.saxutils import escape

from . import runner

log = logging.getLogger(__name__)

TASK_NAME = r"\SimplySec\Daily check"
SCHTASKS = str(runner.SYSTEM32 / "schtasks.exe")


def current_user_sid() -> str:
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    return str(win32security.ConvertSidToStringSid(sid))


def build_xml(
    time: str, command: str, arguments: str, user_sid: str, today: dt.date | None = None
) -> str:
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", time):
        raise ValueError("time must be HH:MM")
    start = (today or dt.date.today()).isoformat() + f"T{time}:00"
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>SimplySec</Author>
    <Description>SimplySec daily read-only security check. It never changes settings. Remove it in SimplySec (Settings or Changes).</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user_sid)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(command)}</Command>
      <Arguments>{escape(arguments)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def exists(name: str = TASK_NAME) -> bool:
    return runner.run([SCHTASKS, "/Query", "/TN", name], timeout=30).ok


def export_xml(name: str = TASK_NAME) -> str | None:
    res = runner.run([SCHTASKS, "/Query", "/TN", name, "/XML"], timeout=30)
    return res.stdout if res.ok and "<Task" in res.stdout else None


def _create_from_xml(name: str, xml: str) -> None:
    with tempfile.TemporaryDirectory(prefix="simplysec-task-") as tmp:
        path = Path(tmp) / "task.xml"
        path.write_text(xml, encoding="utf-16")
        runner.run(
            [SCHTASKS, "/Create", "/TN", name, "/XML", str(path), "/F"], timeout=60, check=True
        )


def create(name: str, time: str) -> None:
    from ..app.elevation import command_for

    exe, args = command_for(["monitor", "--run"], gui=True)
    _create_from_xml(name, build_xml(time, exe, args, current_user_sid()))
    log.info("scheduled task created: %s at %s", name, time)


def delete(name: str = TASK_NAME) -> None:
    if exists(name):
        runner.run([SCHTASKS, "/Delete", "/TN", name, "/F"], timeout=30, check=True)
        log.info("scheduled task deleted: %s", name)


def restore(name: str, xml: str | None) -> None:
    """Put the task back as it was: recreate it from its old XML, or remove it."""
    if xml:
        _create_from_xml(name, xml)
    else:
        delete(name)


def next_run(name: str = TASK_NAME) -> str:
    data = runner.powershell_json(
        "$t = Get-ScheduledTask -TaskPath '\\SimplySec\\' -TaskName 'Daily check' -ErrorAction SilentlyContinue;"
        " if ($t) { $i = $t | Get-ScheduledTaskInfo; [ordered]@{ next = $i.NextRunTime; last = $i.LastRunTime;"
        " result = $i.LastTaskResult } | ConvertTo-Json -Compress } else { 'null' }"
    )
    return str((data or {}).get("next") or "")
