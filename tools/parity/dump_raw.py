"""Python v2 side of the live parity check (see compare_live.py).

    .venv\\Scripts\\python tools\\parity\\dump_raw.py collect OUT.json
        Collect a RawScan on this PC (windows.collect.collect()) and write it as JSON.
    .venv\\Scripts\\python tools\\parity\\dump_raw.py analyze RAW.json OUT.json
        Analyse a saved RawScan (Python's or C#'s) and write ScanResult.to_dict(include_facts=False).

Read-only: nothing is saved to history and no setting is changed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))


def _write(path: str, data: object) -> None:
    Path(path).write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "collect":
        from simplysec.windows.collect import collect

        _write(argv[1], collect().to_dict())
        return 0
    if len(argv) == 3 and argv[0] == "analyze":
        from simplysec.core.engine import RawScan, analyze

        raw = RawScan.from_dict(json.loads(Path(argv[1]).read_text(encoding="utf-8")))
        _write(argv[2], analyze(raw).to_dict(include_facts=False))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
