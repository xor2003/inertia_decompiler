"""Regress exact callsite ownership during direct stack-return lowering."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable, SimTemporaryVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import IRCallOutputProvenance8616, IRCallOutputShape8616
from angr_platforms.X86_16.lowering.call_return_stack_bindings import call_result_escapes_group_8616
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
    _replace_tagged_call_statement_with_stack_assignment_8616,
    _tree_has_zero_arg_call_return_assignment_8616,
)
from angr_platforms.X86_16.lowering.wide_call_output_assignment_contracts import (
    WideCallOutputAssignmentArtifact8616,
    WideCallOutputAssignmentFact8616,
    WideCallOutputAssignmentResolution8616,
    WideCallOutputAssignmentStats8616,
    WideCallOutputAssignmentVerdict8616,
)
from angr_platforms.X86_16.lowering.wide_call_output_assignment_replay import (
    WideCallOutputAuthoritativeOwnershipStatus8616,
    classify_authoritative_wide_call_output_projection_8616,
)
from angr_platforms.X86_16.semantics.carry_borrow_contracts import CarryBorrowKind8616

_INITIAL_CALLSITE = 0x100B
_LATER_CALLSITE = 0x101A


class _Codegen:
    """Minimal structured-C boundary for callsite ownership tests."""

    def __init__(self, project: object) -> None:
        """Initialize deterministic node identifiers."""
        self._index = 0
        self.cstyle_null_cmp = False
        self.project = project

    def next_idx(self, _name: str) -> int:
        """Return the next node identifier."""
        self._index += 1
        return self._index

    def next_node_idx(self) -> int:
        """Return the next node identifier through angr's alternate API."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Return a stable generated identifier."""
        return name


def _fixture() -> tuple[object, _Codegen, CVariable]:
    """Build the dynamic project and destination variable boundaries."""
    project = SimpleNamespace(
        arch=Arch86_16(),
        _inertia_original_linear_delta=0,
    )
    codegen = _Codegen(project)
    destination = CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_4"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    return project, codegen, destination


def test_same_target_fallback_preserves_distinct_later_callsite() -> None:
    """Do not replace another same-target call after the exact call was consumed."""
    project, codegen, destination = _fixture()
    consumed_call = CFunctionCall(
        "clock", None, [], codegen=codegen, tags={"ins_addr": 0x100B}
    )
    existing = CAssignment(destination, consumed_call, codegen=codegen)
    later_call = CFunctionCall(
        "clock", None, [], codegen=codegen, tags={"ins_addr": 0x101A}
    )
    later_statement = CExpressionStatement(later_call, codegen=codegen)
    root = CStatements([existing, later_statement], codegen=codegen)

    result = _replace_tagged_call_statement_with_stack_assignment_8616(
        root,
        project,
        0x100B,
        "clock",
        lambda tags: CAssignment(destination, consumed_call, codegen=codegen, tags=tags),
    )

    assert result is None
    assert root.statements == [existing, later_statement]
    assert later_call.tags["ins_addr"] == _LATER_CALLSITE


def test_direct_stack_call_replacement_preserves_live_temporary() -> None:
    """Retain the original call result when later statements still consume it."""
    project, codegen, destination = _fixture()
    temporary = CVariable(SimTemporaryVariable(0, 2), variable_type=SimTypeShort(False), codegen=codegen)
    call = CFunctionCall("callee", None, [], codegen=codegen, tags={"ins_addr": _INITIAL_CALLSITE})
    producer = CAssignment(temporary, call, codegen=codegen)
    use = CAssignment(destination, temporary, codegen=codegen)
    root = CStatements([producer, use], codegen=codegen)
    rebuilt_call = CFunctionCall("callee", None, [], codegen=codegen, tags=call.tags)

    result = _replace_tagged_call_statement_with_stack_assignment_8616(
        root, project, _INITIAL_CALLSITE, "callee",
        lambda tags: CAssignment(destination, rebuilt_call, codegen=codegen, tags=tags),
    )

    assert isinstance(root.statements[0], CStatements)
    assert root.statements[0].statements == [producer, result]
    assert producer.rhs is call
    assert result.rhs is temporary
    assert root.statements[1] is use
    fact = DirectStackMoveFact8616(
        dst_offset=-4, width=2, source_kind=DirectStackMoveSourceKind8616.ZERO_ARG_CALL_RETURN,
        ins_addr=_INITIAL_CALLSITE + 3, source_call_ins_addr=_INITIAL_CALLSITE, source_call_name="callee",
    )
    assert _tree_has_zero_arg_call_return_assignment_8616(root, project, fact, destination)
    assert not _tree_has_zero_arg_call_return_assignment_8616(
        root, project, replace(fact, source_call_ins_addr=_LATER_CALLSITE), destination,
    )
    result.rhs = CVariable(SimTemporaryVariable(1, 2), variable_type=SimTypeShort(False), codegen=codegen)
    assert not _tree_has_zero_arg_call_return_assignment_8616(root, project, fact, destination)


@pytest.mark.parametrize("external", [False, True])
def test_call_carrier_group_proof_counts_shared_outer_uses(external):
    """An outer read of the same AST object remains a distinct occurrence."""
    _project, codegen, destination = _fixture()
    temporary = CVariable(SimTemporaryVariable(0, 2), variable_type=SimTypeShort(False), codegen=codegen)
    call = CFunctionCall("callee", None, [], codegen=codegen)
    producer = CAssignment(temporary, call, codegen=codegen)
    copy = CAssignment(destination, temporary, codegen=codegen)
    bridge = CStatements([producer, copy], codegen=codegen)
    root = CStatements([bridge, copy] if external else [bridge], codegen=codegen)

    assert call_result_escapes_group_8616(root, producer, (copy,)) is external


def test_unique_same_target_fallback_remains_available_without_exact_callsite() -> None:
    """Retain the conservative unique fallback when the exact call tag is absent."""
    project, codegen, destination = _fixture()
    degraded_call = CFunctionCall(
        "clock", None, [], codegen=codegen, tags={"ins_addr": 0x101A}
    )
    root = CStatements(
        [CExpressionStatement(degraded_call, codegen=codegen)],
        codegen=codegen,
    )

    result = _replace_tagged_call_statement_with_stack_assignment_8616(
        root,
        project,
        0x100B,
        "clock",
        lambda tags: CAssignment(destination, degraded_call, codegen=codegen, tags=tags),
    )

    assert result is root.statements[0]
    assert result.tags["ins_addr"] == _INITIAL_CALLSITE


def _wide_fact(callsite_addr: int = 0x100B) -> WideCallOutputAssignmentFact8616:
    """Build the exact wide call-output fact used by ownership tests."""
    return WideCallOutputAssignmentFact8616(
        call_output=IRCallOutputProvenance8616(
            callsite_addr=callsite_addr,
            target_addr=0x1446,
            shape=IRCallOutputShape8616.DX_AX,
        ),
        kind=CarryBorrowKind8616.ADD_WITH_CARRY,
        source_offset=4,
        destination_offset=-4,
        carrier_ins_addrs=(0x100B, 0x100E, 0x1011, 0x1014, 0x1017),
        store_ins_addrs=(0x1014, 0x1017),
    )


@pytest.mark.parametrize("delta", [0, 0x10000])
@pytest.mark.parametrize("target_adjustment", [0, 1])
@pytest.mark.parametrize("shape", [IRCallOutputShape8616.DX_AX, IRCallOutputShape8616.AX])
def test_authoritative_wide_assignment_blocks_legacy_projection(delta, target_adjustment, shape) -> None:
    """Treat the exact dedicated wide-call result as the sole semantic owner."""
    project, codegen, _destination = _fixture()
    project._inertia_original_linear_delta = delta
    fact = _wide_fact()
    fact = replace(fact, call_output=replace(
        fact.call_output, target_addr=fact.call_output.target_addr + delta + target_adjustment, shape=shape,
    ))
    resolution = WideCallOutputAssignmentResolution8616(
        source=object(),
        verdict=WideCallOutputAssignmentVerdict8616.MATERIALIZED,
        fact=fact,
        placement_classified=True,
    )
    codegen._inertia_wide_call_output_assignment_artifact_8616 = (
        WideCallOutputAssignmentArtifact8616(
            function_addr=0x1000,
            resolutions=(resolution,),
            stats=WideCallOutputAssignmentStats8616(
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
            ),
        )
    )

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen,
        callsite_addr=0x100B,
        target_addr=0x1446,
        kind=CarryBorrowKind8616.ADD_WITH_CARRY,
        source_offset=4,
        destination_offset=-4,
        low_arithmetic_addr=0x100E,
        high_arithmetic_addr=0x1011,
        low_store_addr=0x1014,
        high_store_addr=0x1017,
    )

    accepted = target_adjustment == 0 and shape is IRCallOutputShape8616.DX_AX
    expected_status = (
        WideCallOutputAuthoritativeOwnershipStatus8616.MATERIALIZED if accepted
        else WideCallOutputAuthoritativeOwnershipStatus8616.FACT_ABSENT
    )
    assert ownership.status is expected_status
    assert ownership.blocks_legacy_materialization is accepted
    assert ownership.materialized is accepted
    if accepted:
        assert ownership.fact == fact


def test_different_wide_callsite_does_not_claim_legacy_projection() -> None:
    """Do not suppress a direct projection when the dedicated fact is different."""
    _project, codegen, _destination = _fixture()
    resolution = WideCallOutputAssignmentResolution8616(
        source=object(),
        verdict=WideCallOutputAssignmentVerdict8616.MATERIALIZED,
        fact=_wide_fact(callsite_addr=0x1020),
        placement_classified=True,
    )
    codegen._inertia_wide_call_output_assignment_artifact_8616 = (
        WideCallOutputAssignmentArtifact8616(
            function_addr=0x1000,
            resolutions=(resolution,),
            stats=WideCallOutputAssignmentStats8616(
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
            ),
        )
    )

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen,
        callsite_addr=0x100B,
        target_addr=0x1446,
        kind=CarryBorrowKind8616.ADD_WITH_CARRY,
        source_offset=4,
        destination_offset=-4,
        low_arithmetic_addr=0x100E,
        high_arithmetic_addr=0x1011,
        low_store_addr=0x1014,
        high_store_addr=0x1017,
    )

    assert ownership.status is WideCallOutputAuthoritativeOwnershipStatus8616.FACT_ABSENT
    assert ownership.blocks_legacy_materialization is False
    assert ownership.materialized is False
