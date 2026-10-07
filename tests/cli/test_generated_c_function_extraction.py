"""Tests for exact generated C definition extraction and relabeling."""

from __future__ import annotations

import pytest

from inertia.cli.generated_c_function_extraction import (
    relabel_generated_function_definition,
)


def test_relabels_only_the_exact_generated_definition() -> None:
    source = "void sub_108d0(void) { sub_108d0(); }\n"

    result = relabel_generated_function_definition(source, "sub_108d0", "BubbleSort")

    assert result == "void BubbleSort(void) { sub_108d0(); }\n"


def test_relabel_keeps_an_already_labeled_definition() -> None:
    source = "void BubbleSort(void) {}\n"

    assert relabel_generated_function_definition(source, "sub_108d0", "BubbleSort") == source


@pytest.mark.parametrize(
    "source,new_name",
    [
        ("void other(void) {}\n", "BubbleSort"),
        ("void sub_108d0(void) {}\nvoid sub_108d0(int x) {}\n", "BubbleSort"),
        ("void sub_108d0(void) {}\n", "not-a-c-identifier"),
    ],
)
def test_relabel_refuses_missing_ambiguous_or_invalid_definitions(
    source: str,
    new_name: str,
) -> None:
    with pytest.raises(ValueError):
        relabel_generated_function_definition(source, "sub_108d0", new_name)
