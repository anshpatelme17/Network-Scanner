"""Run the collector with ``python -m windows_collector``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
