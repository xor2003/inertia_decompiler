"""Repeated matching bodies cannot supply unique library identity evidence."""

import pytest

from omf_pat import PatModule, PatPublicName, match_pat_modules


@pytest.mark.parametrize("copies", [1, 2])
def test_only_unique_body_supplies_library_labels(copies):
    body = bytes.fromhex("55 8b ec b8 00 00 57 56 8b 46 04 5e 5f 8b e5 5d c3")
    module = PatModule(
        source_path="<test>", compiler_name="test compiler", module_name="runtime",
        pattern_bytes=tuple(body), module_length=len(body),
        public_names=(PatPublicName(offset=0, name="runtime"),),
        referenced_names=(), tail_bytes=(),
    )
    labels, ranges, compilers = match_pat_modules(
        (body + b"\x90") * copies, 0x10000, [module], backend="python_regex",
    )
    if copies == 1:
        assert labels == {0x10000: "runtime"}
        assert ranges == {0x10000: (0x10000, 0x10000 + len(body))}
        assert compilers == ("test compiler",)
    else:
        assert labels == {}
        assert ranges == {}
        assert compilers == ()
