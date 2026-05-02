# PyInstaller spec for pulse-agent.exe.
#
# Build with:    python scripts/build_agent.py
# Or directly:   pyinstaller --clean --noconfirm pulse-agent.spec
#
# Outputs `dist/pulse-agent/pulse-agent.exe` (one-folder build) or
# `dist/pulse-agent.exe` (one-file, when --onefile is enabled below).
#
# We default to one-FOLDER because:
#   1. faster cold-start (no per-launch unpack into TEMP)
#   2. easier to ACL the token-config + binary together
#   3. the difference in install size is small once httpx + python-evtx
#      are pulled in either way
# Operators who want a single .exe just flip ONEFILE = True below.
#
# This spec is Windows-targeted — pulse-agent runs on the customer's
# Windows host, scanning the local event log via wevtutil. Building on
# macOS / Linux still produces a binary but it won't be useful for the
# agent's stated purpose.

import os

ONEFILE = False

block_cipher = None


a = Analysis(
    ['scripts/agent_entry.py'],
    pathex=[os.path.abspath('.')],
    binaries=[],
    # No data files needed — the agent's config (agent.yaml) lives on
    # disk under %PROGRAMDATA% and is created by `enroll`. Detection
    # rules + remediation strings are all pure-Python modules that
    # PyInstaller picks up by following imports.
    datas=[],
    # PyInstaller's import-tracing misses dynamic imports inside our
    # detection pipeline (`run_all_detections` uses introspection over
    # the `pulse.core.detections` module). List every detection module
    # explicitly so the bundled binary doesn't crash at first scan.
    hiddenimports=[
        'pulse.core.detections',
        'pulse.core.parser',
        'pulse.core.rules_config',
        'pulse.core.known_good',
        'pulse.whitelist',
        'pulse.monitor.system_scan',
        'pulse.monitor.monitor',
        'pulse.reports.reporter',
        'pulse.agent',
        'pulse.agent.config',
        'pulse.agent.transport',
        'pulse.agent.scanner',
        'pulse.agent.runtime',
        # httpx and yaml have C-accelerated parsers in some builds; keep
        # the explicit reference so the optional speedups land in the
        # bundle when they're available.
        'httpx',
        'h11',
        'yaml',
        'Evtx',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Excluding the FastAPI server tree keeps the agent binary small —
    # the agent never imports those modules but PyInstaller would
    # otherwise pull them in transitively because they sit inside the
    # same `pulse` package on disk.
    excludes=[
        'pulse.api',
        'pulse.agents',          # server-side enrollment helper, not the agent runtime
        'pulse.auth',
        'pulse.database',
        'pulse.intel',
        'pulse.interactive',
        'pulse.rate_limit',
        'pulse.firewall',
        'pulse.alerts',
        'pulse.monitor.monitor_service',
        'pulse.monitor.scheduled_scan',
        'fastapi',
        'uvicorn',
        'starlette',
        'pydantic',
        'reportlab',
        'matplotlib',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)


if ONEFILE:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name='pulse-agent',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name='pulse-agent',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name='pulse-agent',
    )
