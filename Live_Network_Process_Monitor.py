"""Backward-compatible entry point. Same as: python -m lnpm"""

import sys

from lnpm.cli import main

if __name__ == "__main__":
    sys.exit(main())
