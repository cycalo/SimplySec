"""Run external programs safely: no shell, no console window, timeouts, real exit codes.

PowerShell is only ever used to return objects converted to JSON, never to parse localized
text. Parameters are passed as base64-encoded JSON, so nothing is spliced into script text.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

CREATE_NO_WINDOW = 0x08000000
SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
POWERSHELL = str(SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe")


class CommandError(RuntimeError):
    def __init__(self, message: str, result: RunResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass
class RunResult:
    args: list[str]
    code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.code == 0


def run(
    args: list[str], timeout: float = 60, check: bool = False, input_text: str | None = None
) -> RunResult:
    """Run a program (never through a shell). Decodes output as UTF-8 with replacement."""
    log.debug("run %s", args)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
            input=input_text.encode("utf-8") if input_text is not None else None,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"{Path(args[0]).name} timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise CommandError(f"could not start {args[0]}: {exc}") from exc
    result = RunResult(
        args=args,
        code=proc.returncode,
        stdout=proc.stdout.decode("utf-8", errors="replace"),
        stderr=proc.stderr.decode("utf-8", errors="replace"),
    )
    if result.code != 0:
        log.info(
            "%s exited with %s: %s", Path(args[0]).name, result.code, result.stderr.strip()[:500]
        )
    if check and not result.ok:
        detail = (result.stderr or result.stdout).strip()[:400]
        raise CommandError(f"{Path(args[0]).name} failed (exit {result.code}): {detail}", result)
    return result


_PRELUDE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$P = $null
if ($env:SIMPLYSEC_PARAMS) {
  $P = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SIMPLYSEC_PARAMS)) | ConvertFrom-Json
}
"""


def _encode_command(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def powershell(script: str, params: dict[str, Any] | None = None, timeout: float = 90) -> RunResult:
    """Run an inline PowerShell script. ``$P`` holds ``params`` (decoded from JSON)."""
    env = os.environ.copy()
    if params is not None:
        env["SIMPLYSEC_PARAMS"] = base64.b64encode(json.dumps(params).encode("utf-8")).decode(
            "ascii"
        )
    args = [
        POWERSHELL,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        _encode_command(_PRELUDE + script),
    ]
    log.debug("powershell (%d chars) params=%s", len(script), list((params or {}).keys()))
    try:
        proc = subprocess.run(
            args, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW, env=env
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"PowerShell timed out after {timeout:.0f}s") from exc
    return RunResult(
        args=["powershell", "<script>"],
        code=proc.returncode,
        stdout=proc.stdout.decode("utf-8", errors="replace"),
        stderr=proc.stderr.decode("utf-8", errors="replace"),
    )


def powershell_json(script: str, params: dict[str, Any] | None = None, timeout: float = 90) -> Any:
    """Run PowerShell that writes one JSON document to stdout and return it parsed.

    Raises CommandError on a non-zero exit code or unparsable output, so failures are never
    silently treated as success.
    """
    res = powershell(script, params, timeout)
    if not res.ok:
        raise CommandError(f"PowerShell failed (exit {res.code}): {res.stderr.strip()[:600]}", res)
    text = res.stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CommandError(f"PowerShell returned invalid JSON: {text[:200]}", res) from exc


def powershell_file(path: Path, timeout: float = 120) -> Any:
    """Run a bundled .ps1 that prints JSON."""
    args = [
        POWERSHELL,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(path),
    ]
    res = run(args, timeout=timeout)
    if not res.ok:
        raise CommandError(f"{path.name} failed (exit {res.code}): {res.stderr.strip()[:600]}", res)
    try:
        return json.loads(res.stdout.strip() or "null")
    except json.JSONDecodeError as exc:
        raise CommandError(f"{path.name} returned invalid JSON: {res.stdout[:200]}", res) from exc
