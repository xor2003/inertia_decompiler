from __future__ import annotations

from tools.compiler_toolchain.build_msc6_examples import _dos_safe_names


def test_rebuilt_names_cannot_overwrite_number_suffixed_original() -> None:
    rebuilt_names = _dos_safe_names("COMP32", counter=2)

    assert rebuilt_names == ("DCOMP02.C", "DCOMP02.OBJ", "DCOMP02.EXE", "DCOMP02.MAP")
    assert all(name.split(".", 1)[0] != "COMP32" for name in rebuilt_names)


def test_rebuilt_names_remain_distinct_when_default_marker_matches_source() -> None:
    rebuilt_names = _dos_safe_names("DDDDD00", counter=0)

    assert rebuilt_names == ("RDDDD00.C", "RDDDD00.OBJ", "RDDDD00.EXE", "RDDDD00.MAP")
    assert all(len(name.split(".", 1)[0]) <= 8 for name in rebuilt_names)
