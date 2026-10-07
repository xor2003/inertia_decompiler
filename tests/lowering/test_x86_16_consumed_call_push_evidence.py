"""Regressions for consumed PUSH provenance across call predecessors."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
)
from angr.sim_type import SimTypeShort
from inertia.semantics.callsite_summary import CallsiteSummary8616
import inertia.lowering.real_mode_linear as real_mode_linear
from inertia.lowering.consumed_call_push_evidence import (
    ConsumedCallPushEvidenceStatus8616,
    normalize_consumed_call_push_evidence_8616,
)
from archinfo import ArchX86

from inertia.alias.callsite_stack_merge import (
    CallsitePredecessorStackMerge8616,
    CallsitePushTrace8616,
)


def _summary(*, mismatched_trace: bool = False) -> CallsiteSummary8616:
    """Build two predecessor traces plus one shared call-block PUSH."""
    second_trace_addrs = (0x113F, 0x1146, 0x114B) if mismatched_trace else (0x113F, 0x1146)
    traces = (
        CallsitePushTrace8616(
            (2, 2),
            (("global", 0x7000), ("imm", 18)),
            (0x1119, 0x1120),
            predecessor_addr=0x1108,
        ),
        CallsitePushTrace8616(
            (2, 2),
            (("global", 0x7000), ("imm", 17)),
            second_trace_addrs,
            predecessor_addr=0x112E,
        ),
    )
    merge = CallsitePredecessorStackMerge8616(
        widths=(2, 2),
        sources=(("global", 0x7000), None),
        representative_instruction_addrs=(0x1119, 0x1120),
        alternative_instruction_addrs=((0x1119, 0x113F), (0x1120, 0x1146)),
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        traces=traces,
    )
    return CallsiteSummary8616(
        callsite_addr=0x10FE,
        target_addr=0x2000,
        return_addr=0x1101,
        kind="near",
        arg_count=3,
        arg_widths=(2, 2, 2),
        stack_cleanup=6,
        return_register="ax",
        return_used=True,
        push_arg_sources=(("global", 0x7000), None, ("imm", 7)),
        push_arg_instruction_addrs=(0x1119, 0x1120, 0x10FA),
        predecessor_stack_merge=merge,
    )


def _codegen() -> tuple[SimpleNamespace, CFunctionCall]:
    """Build one structured call with a current machine identity."""
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=ArchX86()),
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
    )
    call = CFunctionCall(
        "ScaleRotate",
        None,
        [CConstant(7, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
        tags={"ins_addr": 0x10FE},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=CStatements(
            [CExpressionStatement(call, codegen=codegen)],
            codegen=codegen,
        ),
    )
    return codegen, call


def test_normalizes_every_predecessor_alternative_push_address() -> None:
    """Representative addresses must expand to the complete Alias path set."""
    result = normalize_consumed_call_push_evidence_8616(_summary())

    assert result.status is ConsumedCallPushEvidenceStatus8616.NORMALIZED
    assert result.instruction_addrs == (0x1119, 0x113F, 0x1120, 0x1146, 0x10FA)
    assert result.raw_fact_count == 7
    assert result.normalized_fact_count == 5
    assert result.failure_count == 0


def test_refuses_alternative_addresses_that_disagree_with_preserved_traces() -> None:
    """Do not consume an address projection inconsistent with Alias traces."""
    result = normalize_consumed_call_push_evidence_8616(
        _summary(mismatched_trace=True)
    )

    assert result.status is ConsumedCallPushEvidenceStatus8616.REFUSED
    assert result.instruction_addrs == ()
    assert result.failure_count == 1


def test_materialized_call_replay_passes_all_path_addresses_to_pruning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Lowering replay consumes branch alternatives, not representatives only."""
    codegen, _call = _codegen()
    summary = _summary()
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}
    captured: list[frozenset[int]] = []

    def capture(
        _project: object,
        _codegen: object,
        instruction_addrs: frozenset[int],
        **_kwargs: object,
    ) -> bool:
        captured.append(instruction_addrs)
        return False

    monkeypatch.setattr(
        real_mode_linear,
        "prune_consumed_call_push_stack_assignments_8616",
        capture,
    )

    assert not real_mode_linear.prune_materialized_call_push_stack_assignments_8616(
        codegen.project,
        codegen,
    )

    assert captured == [frozenset({0x1119, 0x113F, 0x1120, 0x1146, 0x10FA})]
    replay = codegen._inertia_materialized_call_push_replay_8616
    assert replay.consumed_push_instruction_count == 5
    assert replay.failure_count == 0
