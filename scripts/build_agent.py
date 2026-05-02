"""Build pulse-agent.exe via PyInstaller.

Usage::

    python scripts/build_agent.py            # one-folder build
    python scripts/build_agent.py --onefile  # single .exe (slower start)
    python scripts/build_agent.py --clean    # nuke build/ + dist/ first

The output lives under ``dist/pulse-agent/`` (one-folder mode) or
``dist/pulse-agent.exe`` (one-file mode).

Targets Windows x64 by design. PyInstaller can also produce a non-
Windows binary on macOS / Linux for testing; those won't be useful for
the agent's stated job (scanning a Windows event log via wevtutil) but
will run --help / status fine for CI smoke tests.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_FILE = REPO_ROOT / "pulse-agent.spec"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--clean", action="store_true",
                   help="Wipe build/ and dist/ before building")
    p.add_argument("--onefile", action="store_true",
                   help="Produce a single .exe instead of a folder bundle")
    args = p.parse_args()

    if not SPEC_FILE.exists():
        print(f"spec file not found: {SPEC_FILE}", file=sys.stderr)
        return 1

    if args.clean:
        for d in ("build", "dist"):
            target = REPO_ROOT / d
            if target.exists():
                print(f"[clean] removing {target}")
                shutil.rmtree(target)

    # If --onefile is requested, flip the toggle inside the spec just
    # for this run. We do this by patching a single line in-place and
    # restoring it after the build finishes — keeps the spec the
    # source of truth without duplicating the file.
    spec_text = SPEC_FILE.read_text(encoding="utf-8")
    original = spec_text
    if args.onefile and "ONEFILE = False" in spec_text:
        SPEC_FILE.write_text(spec_text.replace("ONEFILE = False", "ONEFILE = True"),
                             encoding="utf-8")

    try:
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--noconfirm",
            "--clean",
            str(SPEC_FILE),
        ]
        print("[build] " + " ".join(cmd))
        rc = subprocess.call(cmd, cwd=str(REPO_ROOT))
    finally:
        if args.onefile:
            SPEC_FILE.write_text(original, encoding="utf-8")

    if rc != 0:
        print(f"\n[build] PyInstaller exited with {rc}", file=sys.stderr)
        return rc

    # Locate the resulting binary so the operator gets a clear pointer.
    if args.onefile:
        out = REPO_ROOT / "dist" / ("pulse-agent.exe" if os.name == "nt" else "pulse-agent")
    else:
        ext = ".exe" if os.name == "nt" else ""
        out = REPO_ROOT / "dist" / "pulse-agent" / ("pulse-agent" + ext)

    if out.exists():
        size_mb = out.stat().st_size / (1024 * 1024)
        print(f"\n[build] success — {out}  ({size_mb:.1f} MB)")
    else:
        print(f"\n[build] PyInstaller succeeded but output not found at {out}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
