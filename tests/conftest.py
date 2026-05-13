# tests/conftest.py
# -----------------
# Shared pytest fixtures + global marker registration. Two things:
#
#   1. _reset_rate_limits — clears the in-process rate-limit buckets
#      between tests so bursts from one test don't bleed 429s into
#      unrelated cases.
#
#   2. The `network` pytest marker is registered here so pytest doesn't
#      emit a PytestUnknownMarkWarning when tests use
#      `@pytest.mark.network`. Run `pytest -m "not network"` to skip
#      network-dependent tests in air-gapped / offline environments.

import pytest

from pulse import rate_limit


def pytest_configure(config):
    """Register custom markers so they're not flagged as unknown."""
    config.addinivalue_line(
        "markers",
        "network: marks tests that require network access "
        "(e.g. pip-audit CVE checks). Skip with `-m 'not network'`.",
    )


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    rate_limit.reset_all_for_tests()
    yield
    rate_limit.reset_all_for_tests()
