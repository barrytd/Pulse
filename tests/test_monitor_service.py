# test_monitor_service.py
# -----------------------
# Unit tests for the live-monitor email throttle in MonitorManager.
# The full async polling loop has side effects (threads, SSE clients)
# so we target only the pure helper: _monitor_email_due.

from datetime import datetime, timedelta

from pulse.monitor.monitor_service import MonitorManager


def _mk_manager():
    """A MonitorManager with dummy paths/config getter. We never start it,
    so the db/config paths don't need to be real."""
    return MonitorManager(db_path=None, config_path=None, config_getter=lambda: {})


def test_monitor_email_due_true_on_first_call():
    m = _mk_manager()
    assert m._monitor_email_due(30) is True


def test_monitor_email_due_false_within_interval():
    m = _mk_manager()
    m._last_monitor_email_at = datetime.now() - timedelta(minutes=5)
    assert m._monitor_email_due(30) is False


def test_monitor_email_due_true_after_interval():
    m = _mk_manager()
    m._last_monitor_email_at = datetime.now() - timedelta(minutes=45)
    assert m._monitor_email_due(30) is True


def test_monitor_email_due_interval_zero_disables_throttle():
    m = _mk_manager()
    m._last_monitor_email_at = datetime.now()
    assert m._monitor_email_due(0) is True


def test_monitor_email_due_accepts_explicit_now():
    m = _mk_manager()
    past  = datetime(2026, 1, 1, 12, 0, 0)
    later = datetime(2026, 1, 1, 12, 31, 0)
    m._last_monitor_email_at = past
    assert m._monitor_email_due(30, now=later) is True
    assert m._monitor_email_due(60, now=later) is False
