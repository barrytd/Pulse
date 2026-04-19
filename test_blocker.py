# test_blocker.py
# ---------------
# Tests for pulse/blocker.py — IP block list + netsh wrappers.
#
# Every subprocess / platform call is patched so these run on any OS. The
# real netsh is never invoked, which means the tests don't need admin and
# don't touch the host firewall.

import os
import tempfile

import pytest

from pulse import blocker, database


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(path)
    return path


def _drop(path):
    try:
        os.remove(path)
    except Exception:
        pass


class _FakeRun:
    """Callable that mimics subprocess.run. Controls returncode/stderr/stdout
    and records every invocation for assertions."""
    def __init__(self, returncode=0, stderr="", stdout=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        class _R:
            pass
        r = _R()
        r.returncode = self.returncode
        r.stderr = self.stderr
        r.stdout = self.stdout
        return r


# ---------------------------------------------------------------------------
# _validate_ip
# ---------------------------------------------------------------------------

def test_validate_ip_accepts_public_ipv4():
    parsed = blocker._validate_ip("8.8.8.8")
    assert str(parsed) == "8.8.8.8"


@pytest.mark.parametrize("bad", [
    "127.0.0.1",       # loopback
    "10.0.0.5",        # RFC1918
    "192.168.1.10",    # RFC1918
    "172.16.0.1",      # RFC1918
    "169.254.1.1",     # link-local
    "0.0.0.0",         # unspecified
    "224.0.0.1",       # multicast
])
def test_validate_ip_rejects_reserved_ranges(bad):
    with pytest.raises(ValueError):
        blocker._validate_ip(bad)


def test_validate_ip_rejects_garbage():
    with pytest.raises(ValueError):
        blocker._validate_ip("not-an-ip")
    with pytest.raises(ValueError):
        blocker._validate_ip("")


# ---------------------------------------------------------------------------
# stage_ip
# ---------------------------------------------------------------------------

def test_stage_ip_success_creates_pending_row(monkeypatch):
    path = _fresh_db()
    try:
        # Pretend the local host has no IPs — otherwise _get_local_ips() might
        # return something that coincidentally matches and flip the test.
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        result = blocker.stage_ip(path, "8.8.8.8", comment="dns")
        assert result["ok"] is True
        assert result["row"]["ip_address"] == "8.8.8.8"
        assert result["row"]["status"] == "pending"
        assert result["row"]["comment"] == "dns"

        rows = blocker.list_blocks(path)
        assert len(rows) == 1
        assert rows[0]["ip_address"] == "8.8.8.8"
    finally:
        _drop(path)


def test_stage_ip_rejects_private_ip(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        result = blocker.stage_ip(path, "10.0.0.5")
        assert result["ok"] is False
        assert "private" in result["message"].lower() or "rfc1918" in result["message"].lower()
        assert blocker.list_blocks(path) == []
    finally:
        _drop(path)


def test_stage_ip_rejects_loopback(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        result = blocker.stage_ip(path, "127.0.0.1")
        assert result["ok"] is False
        assert "loopback" in result["message"].lower()
    finally:
        _drop(path)


def test_stage_ip_rejects_self_block(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: {"8.8.8.8"})
        result = blocker.stage_ip(path, "8.8.8.8")
        assert result["ok"] is False
        assert "self-block" in result["message"].lower() or "own ip" in result["message"].lower()
    finally:
        _drop(path)


def test_stage_ip_rejects_duplicate(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        first = blocker.stage_ip(path, "8.8.8.8")
        assert first["ok"] is True
        second = blocker.stage_ip(path, "8.8.8.8")
        assert second["ok"] is False
        assert "already" in second["message"].lower()
        assert len(blocker.list_blocks(path)) == 1
    finally:
        _drop(path)


# ---------------------------------------------------------------------------
# stage_ip — force override (two-tier safety)
# ---------------------------------------------------------------------------

def test_stage_ip_force_accepts_private_ip(monkeypatch):
    """force=True flips the RFC1918 refusal into an accepted stage with a
    distinct audit action so the override is visible after the fact."""
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        result = blocker.stage_ip(path, "10.0.0.160", comment="insider", force=True)
        assert result["ok"] is True
        assert result["forced"] is True
        assert "forced" in result["message"].lower() or "override" in result["message"].lower()

        rows = blocker.list_blocks(path)
        assert len(rows) == 1
        assert rows[0]["ip_address"] == "10.0.0.160"

        audit = blocker.get_audit_log(path, limit=10)
        actions = [a["action"] for a in audit]
        assert "stage_forced" in actions
    finally:
        _drop(path)


def test_stage_ip_force_does_not_affect_public_ip(monkeypatch):
    """Passing force=True for a public IP must NOT mark it as forced — the
    override flag only applies when the soft-refusal would have triggered."""
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        result = blocker.stage_ip(path, "8.8.8.8", force=True)
        assert result["ok"] is True
        assert result["forced"] is False

        audit = blocker.get_audit_log(path, limit=10)
        actions = [a["action"] for a in audit]
        assert "stage" in actions
        assert "stage_forced" not in actions
    finally:
        _drop(path)


def test_stage_ip_force_still_rejects_loopback(monkeypatch):
    """Hard refusals (loopback) ignore force=True — this is critical so a
    buggy frontend can't self-lockout the machine."""
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        result = blocker.stage_ip(path, "127.0.0.1", force=True)
        assert result["ok"] is False
        assert result["forced"] is False
        assert "loopback" in result["message"].lower()
    finally:
        _drop(path)


def test_stage_ip_force_still_rejects_self_block(monkeypatch):
    """Self-block is another hard refusal that force can't bypass."""
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: {"10.0.0.160"})
        result = blocker.stage_ip(path, "10.0.0.160", force=True)
        assert result["ok"] is False
        assert result["forced"] is False
        assert "self" in result["message"].lower() or "own" in result["message"].lower()
    finally:
        _drop(path)


def test_stage_ip_force_still_rejects_link_local(monkeypatch):
    """Link-local is a hard refusal even with force=True."""
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        result = blocker.stage_ip(path, "169.254.1.1", force=True)
        assert result["ok"] is False
        assert result["forced"] is False
    finally:
        _drop(path)


# ---------------------------------------------------------------------------
# list_blocks
# ---------------------------------------------------------------------------

def test_list_blocks_returns_newest_first(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        blocker.stage_ip(path, "8.8.8.8")
        blocker.stage_ip(path, "1.1.1.1")
        rows = blocker.list_blocks(path)
        assert [r["ip_address"] for r in rows] == ["1.1.1.1", "8.8.8.8"]
    finally:
        _drop(path)


# ---------------------------------------------------------------------------
# push_pending — platform / admin gating
# ---------------------------------------------------------------------------

def test_push_pending_skips_when_not_windows(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        blocker.stage_ip(path, "8.8.8.8")
        monkeypatch.setattr(blocker, "is_windows", lambda: False)
        result = blocker.push_pending(path)
        assert result["ok"] is False
        assert result["pushed"] == 0
        assert "windows" in result["message"].lower()
        # Row stays pending.
        rows = blocker.list_blocks(path)
        assert rows[0]["status"] == "pending"
    finally:
        _drop(path)


def test_push_pending_skips_when_not_admin(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        blocker.stage_ip(path, "8.8.8.8")
        monkeypatch.setattr(blocker, "is_windows", lambda: True)
        monkeypatch.setattr(blocker, "_is_admin", lambda: False)
        result = blocker.push_pending(path)
        assert result["ok"] is False
        assert "admin" in result["message"].lower()
        rows = blocker.list_blocks(path)
        assert rows[0]["status"] == "pending"
    finally:
        _drop(path)


def test_push_pending_with_no_pending_returns_ok(monkeypatch):
    path = _fresh_db()
    try:
        result = blocker.push_pending(path)
        assert result["ok"] is True
        assert result["pushed"] == 0
    finally:
        _drop(path)


def test_push_pending_success_flips_status_to_active(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        blocker.stage_ip(path, "8.8.8.8")
        blocker.stage_ip(path, "1.1.1.1")
        monkeypatch.setattr(blocker, "is_windows", lambda: True)
        monkeypatch.setattr(blocker, "_is_admin", lambda: True)
        fake = _FakeRun(returncode=0)
        monkeypatch.setattr(blocker.subprocess, "run", fake)

        result = blocker.push_pending(path)
        assert result["ok"] is True
        assert result["pushed"] == 2
        assert result["failures"] == []
        assert len(fake.calls) == 2
        # Every netsh invocation names the rule with the Pulse-managed prefix.
        for cmd in fake.calls:
            joined = " ".join(cmd)
            assert "Pulse-managed:" in joined
            assert "action=block" in joined
            assert "dir=in" in joined

        rows = blocker.list_blocks(path)
        assert all(r["status"] == "active" for r in rows)
        assert all(r["pushed_at"] for r in rows)
        assert all(r["rule_name"] and r["rule_name"].startswith("Pulse-managed:") for r in rows)
    finally:
        _drop(path)


def test_push_pending_captures_netsh_failure(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        blocker.stage_ip(path, "8.8.8.8")
        monkeypatch.setattr(blocker, "is_windows", lambda: True)
        monkeypatch.setattr(blocker, "_is_admin", lambda: True)
        fake = _FakeRun(returncode=1, stderr="Access is denied.")
        monkeypatch.setattr(blocker.subprocess, "run", fake)

        result = blocker.push_pending(path)
        assert result["ok"] is False
        assert result["pushed"] == 0
        assert len(result["failures"]) == 1
        assert "access is denied" in result["failures"][0]["error"].lower()

        rows = blocker.list_blocks(path)
        assert rows[0]["status"] == "pending"
    finally:
        _drop(path)


# ---------------------------------------------------------------------------
# unblock_ip
# ---------------------------------------------------------------------------

def test_unblock_ip_removes_pending_row_without_touching_firewall(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        blocker.stage_ip(path, "8.8.8.8")
        # netsh should NEVER be called for pending rows.
        fake = _FakeRun(returncode=0)
        monkeypatch.setattr(blocker.subprocess, "run", fake)

        result = blocker.unblock_ip(path, "8.8.8.8")
        assert result["ok"] is True
        assert blocker.list_blocks(path) == []
        assert fake.calls == []
    finally:
        _drop(path)


def test_unblock_ip_active_row_calls_netsh_delete(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        blocker.stage_ip(path, "8.8.8.8")
        monkeypatch.setattr(blocker, "is_windows", lambda: True)
        monkeypatch.setattr(blocker, "_is_admin", lambda: True)
        fake = _FakeRun(returncode=0)
        monkeypatch.setattr(blocker.subprocess, "run", fake)
        blocker.push_pending(path)
        fake.calls.clear()

        result = blocker.unblock_ip(path, "8.8.8.8")
        assert result["ok"] is True
        assert len(fake.calls) == 1
        assert fake.calls[0][3] == "delete"   # netsh advfirewall firewall delete rule
        assert blocker.list_blocks(path) == []
    finally:
        _drop(path)


def test_unblock_ip_unknown_returns_error(monkeypatch):
    path = _fresh_db()
    try:
        result = blocker.unblock_ip(path, "8.8.8.8")
        assert result["ok"] is False
        assert "not in the block list" in result["message"].lower()
    finally:
        _drop(path)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def test_audit_log_records_stage_and_push(monkeypatch):
    path = _fresh_db()
    try:
        monkeypatch.setattr(blocker, "_get_local_ips", lambda: set())
        blocker.stage_ip(path, "8.8.8.8", comment="test", user="alice")
        monkeypatch.setattr(blocker, "is_windows", lambda: True)
        monkeypatch.setattr(blocker, "_is_admin", lambda: True)
        monkeypatch.setattr(blocker.subprocess, "run", _FakeRun(returncode=0))
        blocker.push_pending(path, user="alice")

        audit = blocker.get_audit_log(path)
        actions = [r["action"] for r in audit]
        assert "stage" in actions
        assert "push" in actions
        # Newest-first — push happened after stage.
        assert actions.index("push") < actions.index("stage")
    finally:
        _drop(path)
