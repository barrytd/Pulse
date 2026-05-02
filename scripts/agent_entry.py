"""PyInstaller entry point for pulse-agent.exe.

Calling ``python -m pulse.agent`` works fine in dev, but PyInstaller's
spec file needs a regular script as its starting analysis target —
giving it a top-level package's ``__main__.py`` doesn't reliably pull
in every transitive import. This file is a one-line shim that delegates
to the real CLI in ``pulse.agent.__main__``.

Tests don't import this file. The Pulse server doesn't reference it.
Its sole job is to give PyInstaller a stable starting point.
"""

import sys

from pulse.agent.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
