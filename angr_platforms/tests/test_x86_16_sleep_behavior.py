"""Prove the Sleep oracle accepts equivalent code and rejects semantic defects."""

from pathlib import Path

import pytest
from x86_16_sleep_behavior import SLEEP_REGISTER_STATE_PRELUDE, assert_sleep_behavior

_PREFIX = "typedef long clock_t; clock_t clock(void);\nvoid Sleep(long wait) {"
_BODY = "long goal = clock() + wait; while (clock() <= goal) {}"


@pytest.mark.parametrize("body", [
    _BODY,
    "unsigned long goal = clock() + wait; while (1) { if ((long)clock() > (long)goal) break; }",
    "long goal = clock() + wait; while (1) { long now = clock(); if (now > goal) break; }",
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
    "long goal = clock() + wait; while (1) { unsigned short now = clock(); if (now > goal) break; }",
])
def test_sleep_oracle_rejects_compilable_corruption(tmp_path: Path, body: str) -> None:
    with pytest.raises(AssertionError, match="violated the clock deadline oracle"):
        assert_sleep_behavior(_PREFIX + body + "}", tmp_path)


@pytest.mark.parametrize("register", ["inertia_esi", "inertia_edi"])
def test_sleep_oracle_rejects_saved_register_corruption(tmp_path: Path, register: str) -> None:
    text = _PREFIX + _BODY + f"{register} ^= 1;}}"
    with pytest.raises(AssertionError, match="violated the clock deadline oracle"):
        assert_sleep_behavior(text, tmp_path, harness_prelude=SLEEP_REGISTER_STATE_PRELUDE)


def test_sleep_oracle_accepts_preserved_register_state(tmp_path: Path) -> None:
    assert_sleep_behavior(_PREFIX + _BODY + "}", tmp_path, harness_prelude=SLEEP_REGISTER_STATE_PRELUDE)
