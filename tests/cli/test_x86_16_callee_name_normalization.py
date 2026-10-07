from __future__ import annotations

from inertia.semantics.callee_name_normalization import normalize_callee_name_8616


def test_normalize_callee_name_strips_reporting_call_suffix() -> None:
    assert normalize_callee_name_8616("  DosBeep()  ") == "DosBeep"


def test_normalize_callee_name_unwraps_angr_namespace_label() -> None:
    assert normalize_callee_name_8616("::0x1234::aNchkstk") == "aNchkstk"


def test_normalize_callee_name_rejects_non_string_or_blank_labels() -> None:
    assert normalize_callee_name_8616(None) is None
    assert normalize_callee_name_8616("   ") is None
