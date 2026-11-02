"""Entry point for the windowed SimplySec.exe (GUI, or CLI sub-commands without a console)."""

import sys

from simplysec.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
