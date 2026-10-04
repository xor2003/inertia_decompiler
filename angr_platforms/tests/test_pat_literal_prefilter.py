"""Exact PAT candidate filtering must preserve the existing matching oracle."""
from itertools import product

import pytest

import omf_pat
from pat_literal_filter import required_pat_literal


def _module(pattern: tuple[int | None, ...]) -> omf_pat.PatModule:
    return omf_pat.PatModule("<test>", "", "candidate", pattern, len(pattern), (), (), ())


@pytest.mark.parametrize("cached", [False, True])
def test_absent_required_literal_avoids_regex_compilation(monkeypatch, cached):
    module = _module((None, 0xAA, 0xBB, None))
    candidate = omf_pat._compile_pat_module_to_cached_regex(module) if cached else module

    def forbidden(_candidate):
        pytest.fail("An absent required byte sequence must reject before regex compilation")

    monkeypatch.setattr(omf_pat, "_get_pat_module_regex", forbidden)
    assert omf_pat._find_pat_matches(b"\x00" * 16, candidate, backend="python_regex") == []


@pytest.mark.parametrize("cached", [False, True])
def test_literal_filter_preserves_wildcards_overlaps_and_ambiguity(cached):
    images = tuple(bytes(values) for width in range(5) for values in product((0, 10, 65), repeat=width))
    for width in range(1, 4):
        for pattern in product((None, 0, 10, 65), repeat=width):
            module = _module(pattern)
            candidate = omf_pat._compile_pat_module_to_cached_regex(module) if cached else module
            regex = omf_pat._get_pat_module_regex(module)
            for image in images:
                expected = [match.start() for match in regex.finditer(image)
                            if match.start() < len(image) - module.module_length + 1][:5]
                assert omf_pat._find_pat_matches(image, candidate, backend="python_regex") == expected


def test_literal_uses_only_checked_prefix_and_tail():
    assert required_pat_literal((65, 66, 67), 1, (68, 69)) == b"A"
    assert required_pat_literal((None,) * 32 + (65,) * 8, 40, (66, 67)) == b"BC"
    assert required_pat_literal((None,) * 32, 40, (None, None)) == b""


@pytest.mark.parametrize("cached", [False, True])
def test_literal_filter_preserves_exact_tail_match(cached):
    module = omf_pat.PatModule("<test>", "", "tail", (None,) * 32, 34, (), (), (10, 65))
    candidate = omf_pat._compile_pat_module_to_cached_regex(module) if cached else module
    image = bytes(32) + b"\nA"
    assert omf_pat._find_pat_matches(image, candidate, backend="python_regex") == [0]
    assert omf_pat._find_pat_matches(bytes(34), candidate, backend="python_regex") == []
