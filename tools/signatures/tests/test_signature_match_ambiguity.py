"""Repeated matching bodies cannot supply unique library identity evidence."""

import pytest

from tools.signatures.omf_pat import PatModule, PatPublicName, match_pat_modules


@pytest.mark.parametrize("copies", [1, 2])
def test_only_unique_body_supplies_library_labels(copies):
    body = bytes.fromhex("55 8b ec b8 00 00 57 56 8b 46 04 5e 5f 8b e5 5d c3")
    module = PatModule(
        source_path="<test>", compiler_name="test compiler", module_name="runtime",
        pattern_bytes=tuple(body), module_length=len(body),
        public_names=(PatPublicName(offset=0, name="runtime"),),
        referenced_names=(), tail_bytes=(),
    )
    pat_match = match_pat_modules(
        (body + b"\x90") * copies, 0x10000, [module], backend="python_regex",
    )
    labels, ranges, compilers = (
        pat_match.code_labels, pat_match.code_ranges, pat_match.matched_compiler_names)
    if copies == 1:
        assert labels == {0x10000: "runtime"}
        assert ranges == {0x10000: (0x10000, 0x10000 + len(body))}
        assert compilers == ("test compiler",)
    else:
        assert labels == {}
        assert ranges == {}
        assert compilers == ()


@pytest.mark.parametrize("tail_length", [0, 7, 8])
@pytest.mark.parametrize("cached", [False, True])
def test_only_full_checked_extent_supplies_library_range(tail_length, cached):
    """A partial pattern may label its entry but cannot hide unmatched bytes."""
    from tools.signatures.omf_pat import _compile_pat_module_to_cached_regex

    body = bytes(range(1, 41))
    module = PatModule(
        source_path="<test>", compiler_name="test", module_name="runtime",
        pattern_bytes=tuple(body[:32]), module_length=len(body),
        public_names=(PatPublicName(offset=0, name="runtime"),),
        referenced_names=(), tail_bytes=tuple(body[32:32 + tail_length]),
    )
    pattern = _compile_pat_module_to_cached_regex(module) if cached else module
    pat_match = match_pat_modules(body, 0x1000, [pattern], backend="python_regex")
    labels, ranges = pat_match.code_labels, pat_match.code_ranges
    assert labels == {0x1000: "runtime"}
    assert ranges == ({0x1000: (0x1000, 0x1028)} if tail_length == 8 else {})


def test_short_prefix_cannot_claim_full_declared_extent():
    """Structured callers cannot turn an undersized prefix into full coverage."""
    module = PatModule(
        source_path="<test>", compiler_name="test", module_name="runtime",
        pattern_bytes=(1, 2, 3, 4), module_length=16,
        public_names=(PatPublicName(offset=0, name="runtime"),),
        referenced_names=(), tail_bytes=(),
    )
    pat_match = match_pat_modules(bytes(range(1, 17)), 0x1000, [module])
    labels, ranges = pat_match.code_labels, pat_match.code_ranges
    assert labels == {0x1000: "runtime"}
    assert ranges == {}


def test_unverified_crc_pat_record_is_refused():
    """CRC bytes are not literal/wildcard coverage until CRC checking exists."""
    from tools.signatures.omf_pat import parse_pat_line

    line = bytes(range(32)).hex() + " 08 1234 0028 :0000 runtime"
    assert parse_pat_line(line, source_path="<test>") is None
