from __future__ import annotations

import pytest
from tests.fixtures.x86_16_timeout_support import scaled_decompile_timeout


@pytest.mark.parametrize(("raw_scale", "expected"), (("", 20), ("bad", 20), ("1", 20), ("4", 80)))
def test_explicit_decompiler_timeout_scale(monkeypatch, raw_scale: str, expected: int) -> None:
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    if raw_scale:
        monkeypatch.setenv("INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE", raw_scale)
    else:
        monkeypatch.delenv("INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE", raising=False)

    assert scaled_decompile_timeout(20) == expected


def test_xdist_decompiler_timeout_scale_defaults_to_bounded_headroom(monkeypatch) -> None:
    monkeypatch.delenv("INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE", raising=False)
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw0")

    assert scaled_decompile_timeout(20) == 30
