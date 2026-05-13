# test_agent_permissions.py
# -------------------------
# Sprint 7 — bearer-token ACL audit + harden helpers.
#
# Covers:
#   - audit returns `not_windows` on non-Windows hosts (no-op)
#   - audit returns `not_found` when the file doesn't exist
#   - audit returns `loose` when icacls output mentions Everyone /
#     BUILTIN\Users / Authenticated Users (mocked subprocess)
#   - audit returns `ok` when icacls output is clean (mocked subprocess)
#   - audit returns `error` when icacls itself fails (mocked)
#   - harden is `not_windows` off-Windows
#   - harden invokes icacls with the right args and surfaces the result
#   - the runtime's startup audit fires _audit_token_permissions and
#     logs at WARNING when the verdict is `loose`
#
# We mock subprocess so the tests are deterministic on every host —
# no actual ACL surgery is performed.

import logging
import platform
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from pulse.agent.permissions import (
    PermissionsVerdict,
    audit_token_file_permissions,
    harden_token_file,
    log_audit_result,
)


# ---------------------------------------------------------------------------
# audit_token_file_permissions
# ---------------------------------------------------------------------------

def test_audit_on_non_windows_is_no_op(monkeypatch, tmp_path):
    """POSIX semantics differ; the audit just reports `not_windows` so
    the runtime knows to skip without flagging anything."""
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    fake_file = tmp_path / "agent.yaml"
    fake_file.write_text("server_url: x\n")
    v = audit_token_file_permissions(str(fake_file))
    assert v.status == "not_windows"
    assert v.is_loose is False


def test_audit_when_file_missing(monkeypatch, tmp_path):
    """Fresh install pre-enrollment: agent.yaml doesn't exist yet.
    Audit reports `not_found` (silent at INFO) so the operator doesn't
    see a false alarm before they've enrolled."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    missing = str(tmp_path / "nope.yaml")
    v = audit_token_file_permissions(missing)
    assert v.status == "not_found"


def _fake_run(output: str, returncode: int = 0):
    """Build a subprocess.run mock that returns the given stdout."""
    result = MagicMock()
    result.stdout = output
    result.stderr = ""
    result.returncode = returncode
    return MagicMock(return_value=result)


def test_audit_detects_everyone(monkeypatch, tmp_path):
    """The clearest "this is bad" signal — icacls reports the file is
    readable by Everyone. We must report `loose` so the runtime warns."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    fake_file = tmp_path / "agent.yaml"
    fake_file.write_text("agent_token: pa_x\n")
    icacls_output = (
        f"{fake_file}\n"
        f"  NT AUTHORITY\\SYSTEM:(F)\n"
        f"  BUILTIN\\Administrators:(F)\n"
        f"  Everyone:(R)\n"
    )
    monkeypatch.setattr(
        "pulse.agent.permissions.subprocess.run",
        _fake_run(icacls_output),
    )
    v = audit_token_file_permissions(str(fake_file))
    assert v.status == "loose"
    assert v.is_loose is True
    assert "Everyone" in v.message


def test_audit_detects_builtin_users(monkeypatch, tmp_path):
    """The default ACL on C:\\ProgramData includes BUILTIN\\Users via
    inheritance — that's exactly the case the install instructions
    warn against. Make sure we catch it."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    fake_file = tmp_path / "agent.yaml"
    fake_file.write_text("agent_token: pa_x\n")
    icacls_output = (
        f"{fake_file}\n"
        f"  NT AUTHORITY\\SYSTEM:(F)\n"
        f"  BUILTIN\\Administrators:(F)\n"
        f"  BUILTIN\\Users:(R)\n"
    )
    monkeypatch.setattr(
        "pulse.agent.permissions.subprocess.run",
        _fake_run(icacls_output),
    )
    v = audit_token_file_permissions(str(fake_file))
    assert v.status == "loose"


def test_audit_detects_authenticated_users(monkeypatch, tmp_path):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    fake_file = tmp_path / "agent.yaml"
    fake_file.write_text("agent_token: pa_x\n")
    icacls_output = (
        f"{fake_file}\n"
        f"  NT AUTHORITY\\SYSTEM:(F)\n"
        f"  NT AUTHORITY\\Authenticated Users:(R)\n"
    )
    monkeypatch.setattr(
        "pulse.agent.permissions.subprocess.run",
        _fake_run(icacls_output),
    )
    v = audit_token_file_permissions(str(fake_file))
    assert v.status == "loose"


def test_audit_accepts_locked_down_acl(monkeypatch, tmp_path):
    """Post-harden ACL: only SYSTEM + Administrators. Audit must
    report `ok` so the runtime stays quiet at INFO."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    fake_file = tmp_path / "agent.yaml"
    fake_file.write_text("agent_token: pa_x\n")
    icacls_output = (
        f"{fake_file}\n"
        f"  NT AUTHORITY\\SYSTEM:(R,W)\n"
        f"  BUILTIN\\Administrators:(F)\n"
    )
    monkeypatch.setattr(
        "pulse.agent.permissions.subprocess.run",
        _fake_run(icacls_output),
    )
    v = audit_token_file_permissions(str(fake_file))
    assert v.status == "ok"


def test_audit_handles_icacls_failure(monkeypatch, tmp_path):
    """If icacls itself errors out (binary missing, sandboxed environment)
    we report `error` rather than crash. Runtime treats this as INFO,
    not WARNING — we don't want a false alarm on a missing binary."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    fake_file = tmp_path / "agent.yaml"
    fake_file.write_text("agent_token: pa_x\n")

    def raise_oserror(*a, **kw):
        raise FileNotFoundError("icacls not found")
    monkeypatch.setattr(
        "pulse.agent.permissions.subprocess.run", raise_oserror,
    )
    v = audit_token_file_permissions(str(fake_file))
    assert v.status == "error"


# ---------------------------------------------------------------------------
# harden_token_file
# ---------------------------------------------------------------------------

def test_harden_off_windows_is_no_op(monkeypatch, tmp_path):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    fake_file = tmp_path / "agent.yaml"
    fake_file.write_text("agent_token: pa_x\n")
    v = harden_token_file(str(fake_file))
    assert v.status == "not_windows"


def test_harden_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    v = harden_token_file(str(tmp_path / "missing.yaml"))
    assert v.status == "not_found"


def test_harden_invokes_icacls_with_right_args(monkeypatch, tmp_path):
    """Verify the icacls invocation: /inheritance:r + /grant:r for
    SYSTEM + Administrators. Order matters (inheritance strip first,
    then grants) so the parent dir's ACEs can't re-clobber the grants."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    fake_file = tmp_path / "agent.yaml"
    fake_file.write_text("agent_token: pa_x\n")

    runner = _fake_run("processed file: ...\n", returncode=0)
    monkeypatch.setattr(
        "pulse.agent.permissions.subprocess.run", runner,
    )
    v = harden_token_file(str(fake_file))
    assert v.status == "ok"
    args = runner.call_args[0][0]
    assert args[0] == "icacls"
    assert args[1] == str(fake_file)
    # Inheritance strip must come before the grants so it doesn't wipe
    # them away (icacls processes flags left-to-right).
    inh_idx = args.index("/inheritance:r")
    grant_indices = [i for i, a in enumerate(args) if a == "/grant:r"]
    assert grant_indices, "harden must issue at least one /grant:r"
    assert all(i > inh_idx for i in grant_indices)
    # Required principals.
    assert "SYSTEM:(R,W)" in args
    assert "Administrators:(F)" in args


def test_harden_reports_icacls_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    fake_file = tmp_path / "agent.yaml"
    fake_file.write_text("agent_token: pa_x\n")
    runner = _fake_run("access denied\n", returncode=5)
    monkeypatch.setattr(
        "pulse.agent.permissions.subprocess.run", runner,
    )
    v = harden_token_file(str(fake_file))
    assert v.status == "error"
    assert "5" in v.message  # rc surfaced for debugging


# ---------------------------------------------------------------------------
# log_audit_result — the right log level for each verdict
# ---------------------------------------------------------------------------

def test_log_audit_loose_emits_warning():
    captured = []

    class _Capture(logging.Handler):
        def emit(self, rec): captured.append((rec.levelno, rec.getMessage()))

    log = logging.getLogger("pulse.agent.permissions")
    h = _Capture(level=logging.INFO)
    log.addHandler(h)
    try:
        log_audit_result(PermissionsVerdict(
            status="loose", message="ACL is loose", path="/x",
        ))
    finally:
        log.removeHandler(h)
    levels = [lvl for lvl, _ in captured]
    assert logging.WARNING in levels


def test_log_audit_ok_does_not_warn():
    captured = []

    class _Capture(logging.Handler):
        def emit(self, rec): captured.append((rec.levelno, rec.getMessage()))

    log = logging.getLogger("pulse.agent.permissions")
    h = _Capture(level=logging.INFO)
    log.addHandler(h)
    try:
        log_audit_result(PermissionsVerdict(
            status="ok", message="locked down", path="/x",
        ))
    finally:
        log.removeHandler(h)
    levels = [lvl for lvl, _ in captured]
    # ok / info-level — never warning.
    assert logging.WARNING not in levels


# ---------------------------------------------------------------------------
# Runtime startup — the audit fires once at run_forever() time
# ---------------------------------------------------------------------------

def test_runtime_run_forever_invokes_audit():
    """AgentRuntime.run_forever() calls _audit_token_permissions exactly
    once. Stop the loop on the first tick so we don't sleep — the audit
    runs before that anyway."""
    from pulse.agent.config import AgentConfig
    from pulse.agent.runtime import AgentRuntime

    cfg = AgentConfig(server_url="http://test", agent_token="pa_x")
    fake_transport = MagicMock()
    fake_transport.heartbeat.return_value = {"status": "ok", "paused": False}
    fake_transport.get_latest_version.return_value = {
        "version": "1.7.0", "download_url": "https://x",
    }
    runtime = AgentRuntime(cfg, transport=fake_transport)
    runtime.stop()  # Don't actually loop.

    with patch.object(runtime, "_audit_token_permissions") as audit:
        runtime.run_forever()
    assert audit.called
