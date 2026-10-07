from __future__ import annotations

from inertia.cli.readability_set import (
    GOLDEN_READABILITY_SET,
    describe_x86_16_golden_readability_set,
    summarize_x86_16_golden_readability_set,
)


def test_x86_16_golden_readability_set_names_expected_cases() -> None:
    cases = describe_x86_16_golden_readability_set()

    assert [case.proc_name for case in cases] == ["_mset_pos", "_ChangeWeather", "_start", "_max", "_ConfigCrts"]
    assert cases == GOLDEN_READABILITY_SET


def test_x86_16_golden_readability_set_carries_anchor_counts() -> None:
    summary = summarize_x86_16_golden_readability_set()

    assert summary[0] == ("cod/f14/MONOPRIN.COD", "_mset_pos", 5)
    assert summary[1] == ("cod/f14/NHORZ.COD", "_ChangeWeather", 5)
    assert summary[-1] == ("angr_platforms/x16_samples/COCKPIT.COD", "_ConfigCrts", 3)
