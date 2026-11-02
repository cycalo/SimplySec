"""Entry point: ``python -m simplysec`` (GUI by default, CLI with a sub-command)."""

from __future__ import annotations

import sys


def main() -> int:
    from .cli import main as cli_main

    return cli_main(sys.argv[1:])


def gui_main() -> int:
    from .app import logs
    from .ui.app import run_gui

    logs.setup()
    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
