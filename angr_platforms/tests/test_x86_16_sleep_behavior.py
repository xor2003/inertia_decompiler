"""Prove the Sleep oracle accepts equivalent code and rejects semantic defects."""

from pathlib import Path

import pytest
from x86_16_sleep_behavior import assert_sleep_behavior

_PREFIX = "typedef long clock_t; clock_t clock(void);\nvoid Sleep(long wait) {"
_BODY = "long goal = clock() + wait; while (clock() <= goal) {}"


@pytest.mark.parametrize("body", [
    _BODY,
    "unsigned long goal = clock() + wait; while (1) { if ((long)clock() > (long)goal) break; }",
])
def test_sleep_oracle_accepts_equivalent_deadlines(tmp_path: Path, body: str) -> None:
    assert_sleep_behavior(_PREFIX + body + "}", tmp_path)


@pytest.mark.parametrize("body", [
    _BODY.replace("<=", "<"),
    _BODY.replace("<=", ">="),
    _BODY.replace("+ wait", "- wait"),
    _BODY.replace("long goal", "short goal"),
    _BODY.replace("while", "if"),
    _BODY + "clock();",
    _BODY.replace("clock() <= goal", "(unsigned long)clock() <= (unsigned long)goal"),
])
def test_sleep_oracle_rejects_compilable_corruption(tmp_path: Path, body: str) -> None:
    with pytest.raises(AssertionError, match="violated the clock deadline oracle"):
        assert_sleep_behavior(_PREFIX + body + "}", tmp_path)
