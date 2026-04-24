# tests/conftest.py
# -----------------
# Shared pytest fixtures. The only one right now resets the in-process
# rate limiter before every test so bursts from previous tests don't
# bleed 429s into unrelated cases.

import pytest

from pulse import rate_limit


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    rate_limit.reset_all_for_tests()
    yield
    rate_limit.reset_all_for_tests()
