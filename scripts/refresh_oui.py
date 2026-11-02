"""Rebuild src/simplysec/resources/oui.csv.gz from the IEEE MA-L registry.

    python scripts/refresh_oui.py                 # download from IEEE
    python scripts/refresh_oui.py path/to/oui.csv # convert a file you downloaded

The output keeps only the 6-hex-digit prefix and the organisation name (data only, nothing
executable), sorted, gzip-compressed.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = Path(__file__).resolve().parents[1] / "src" / "simplysec" / "resources" / "oui.csv.gz"


def convert(raw: bytes) -> list[tuple[str, str]]:
    rows = {}
    reader = csv.reader(io.StringIO(raw.decode("utf-8", errors="replace")))
    header = next(reader, None)
    if not header or "Assignment" not in header:
        raise SystemExit("unexpected file format (no 'Assignment' column)")
    a, o = header.index("Assignment"), header.index("Organization Name")
    for row in reader:
        if len(row) <= max(a, o):
            continue
        prefix = row[a].strip().upper()
        if re.fullmatch(r"[0-9A-F]{6}", prefix):
            rows[prefix] = " ".join(row[o].split())[:80]
    return sorted(rows.items())


def main() -> int:
    if len(sys.argv) > 1:
        raw = Path(sys.argv[1]).read_bytes()
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "SimplySec OUI refresh"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read()
    rows = convert(raw)
    if len(rows) < 10000:
        raise SystemExit(f"only {len(rows)} entries; refusing to overwrite")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerows(rows)
    OUT.write_bytes(gzip.compress(buf.getvalue().encode("utf-8"), mtime=0))
    print(f"wrote {len(rows)} prefixes to {OUT} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
