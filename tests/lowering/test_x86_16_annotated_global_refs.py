"""Tests for exact direct-global annotation binding."""

from __future__ import annotations

from types import SimpleNamespace

from inertia.lowering.annotated_global_refs import collect_annotated_direct_global_refs_8616


def test_collects_only_annotations_with_binary_direct_operand_evidence() -> None:
    function = SimpleNamespace(
        info={
            "x86_16_annotations": {
                "global_vars": {
                    0x1238: {"name": "sum_word"},
                    0x9999: {"name": "not_referenced"},
                }
            }
        }
    )
    summaries = [
        SimpleNamespace(
            op0_kind="direct_mem",
            op0_value=0x1238,
            op0_size=2,
            op1_kind="reg",
            op1_value="ax",
            op1_size=2,
        )
    ]

    refs = collect_annotated_direct_global_refs_8616(function, summaries)

    assert [(ref.offset, ref.width, ref.name) for ref in refs] == [(0x1238, 2, "sum_word")]
