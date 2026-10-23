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

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import IRCallOutputShape8616
from inertia.lowering.call_return_stack_bindings import call_result_escapes_group_8616
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
    _replace_tagged_call_statement_with_stack_assignment_8616,
    _tree_has_zero_arg_call_return_assignment_8616,
)
from inertia.lowering.wide_call_output_assignment_contracts import (
    WideCallOutputAssignmentArtifact8616,
    WideCallOutputAssignmentFact8616,
    WideCallOutputAssignmentResolution8616,
    WideCallOutputAssignmentStats8616,
    WideCallOutputAssignmentVerdict8616,
)
from inertia.lowering.wide_call_output_assignment_evidence import (
    normalize_wide_call_output_assignment_fact_8616,
)
from inertia.lowering.wide_call_output_assignment_replay import (
    WideCallOutputAuthoritativeOwnershipStatus8616,
    classify_authoritative_wide_call_output_projection_8616,
)
from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.widening.pair_type_contracts import WidePairState8616
from tests.fixtures.x86_16_carry_borrow_call_output_support import (
    WIDE_STACK_ADD,
    WIDE_STACK_SUB,
    wide_assignment_fixture,
    wide_assignment_storage,
)

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


def _wide_authority_fixture(code: bytes = WIDE_STACK_ADD):
    """Build a real lifted wide fact, storage, and codegen boundary."""
    codegen, _root, _call, _source = wide_assignment_fixture(code=code)
    pipeline, storage = wide_assignment_storage(codegen)
    fact = normalize_wide_call_output_assignment_fact_8616(pipeline, storage)
    assert isinstance(fact, WideCallOutputAssignmentFact8616)
    return codegen, storage, fact


def _legacy_classify_kwargs(fact: WideCallOutputAssignmentFact8616) -> dict:
    """Project one real fact into the legacy classifier's scalar surface."""
    arithmetic = sorted(
        set(fact.carrier_ins_addrs)
        - {fact.call_output.callsite_addr}
        - set(fact.store_ins_addrs)
    )
    return {
        "callsite_addr": fact.call_output.callsite_addr,
        "target_addr": fact.call_output.target_addr,
        "kind": fact.kind,
        "source_offset": fact.source_offset,
        "destination_offset": fact.destination_offset,
        "low_arithmetic_addr": arithmetic[0],
        "high_arithmetic_addr": arithmetic[-1],
        "low_store_addr": fact.store_ins_addrs[0],
        "high_store_addr": fact.store_ins_addrs[1],
    }


def _publish_artifact(codegen, storage, fact: WideCallOutputAssignmentFact8616) -> None:
    """Attach one materialized-resolution artifact to the codegen boundary."""
    resolution = WideCallOutputAssignmentResolution8616(
        source=storage,
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


@pytest.mark.parametrize("delta", [0, 0x10000])
@pytest.mark.parametrize("target_adjustment", [0, 1])
@pytest.mark.parametrize("shape", [IRCallOutputShape8616.DX_AX, IRCallOutputShape8616.AX])
def test_authoritative_wide_assignment_blocks_legacy_projection(delta, target_adjustment, shape) -> None:
    """Treat the exact dedicated wide-call result as the sole semantic owner."""
    codegen, storage, fact = _wide_authority_fixture()
    codegen.project._inertia_original_linear_delta = delta
    base_target = fact.call_output.target_addr
    fact = replace(fact, call_output=replace(
        fact.call_output, target_addr=base_target + delta + target_adjustment, shape=shape,
    ))
    _publish_artifact(codegen, storage, fact)

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen, **_legacy_classify_kwargs(fact) | {"target_addr": base_target}
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
    codegen, storage, fact = _wide_authority_fixture()
    foreign = replace(
        fact,
        call_output=replace(fact.call_output, callsite_addr=0x1020),
        carrier_ins_addrs=tuple(
            sorted(
                set(fact.carrier_ins_addrs)
                - {fact.call_output.callsite_addr}
                | {0x1020}
            )
        ),
    )
    _publish_artifact(codegen, storage, foreign)

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen, **_legacy_classify_kwargs(fact)
    )

    assert ownership.status is WideCallOutputAuthoritativeOwnershipStatus8616.FACT_ABSENT
    assert ownership.blocks_legacy_materialization is False
    assert ownership.materialized is False


@pytest.mark.parametrize(
    "corrupt",
    (
        pytest.param(lambda fact: replace(fact, pair=None), id="missing-pair"),
        pytest.param(
            lambda fact: replace(
                fact, pair=replace(fact.pair, state=WidePairState8616.UNPAIRED)
            ),
            id="unpaired",
        ),
        pytest.param(
            lambda fact: replace(
                fact, pair=replace(fact.pair, state=WidePairState8616.SPLIT)
            ),
            id="split-only",
        ),
        pytest.param(
            lambda fact: replace(
                fact,
                pair=replace(fact.pair, low=fact.pair.high, high=fact.pair.low),
            ),
            id="foreign-halves",
        ),
    ),
)
def test_wide_authority_refuses_unauthenticated_pair(corrupt) -> None:
    """Missing or inconsistent pair evidence never certifies authority."""
    codegen, storage, fact = _wide_authority_fixture()
    _publish_artifact(codegen, storage, corrupt(fact))

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen, **_legacy_classify_kwargs(fact)
    )

    assert ownership.status is WideCallOutputAuthoritativeOwnershipStatus8616.REFUSED
    assert ownership.blocks_legacy_materialization
    assert not ownership.materialized


def test_wide_authority_refuses_unauthenticated_source() -> None:
    """A foreign resolution source never certifies authority."""
    codegen, _storage, fact = _wide_authority_fixture()
    _publish_artifact(codegen, object(), fact)

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen, **_legacy_classify_kwargs(fact)
    )

    assert ownership.status is WideCallOutputAuthoritativeOwnershipStatus8616.REFUSED
    assert ownership.blocks_legacy_materialization
    assert not ownership.materialized


@pytest.mark.parametrize(
    ("code", "kind"),
    (
        pytest.param(WIDE_STACK_ADD, CarryBorrowKind8616.ADD_WITH_CARRY, id="add"),
        pytest.param(WIDE_STACK_SUB, CarryBorrowKind8616.SUB_WITH_BORROW, id="sub"),
    ),
)
def test_authoritative_wide_kind_blocks_legacy_projection(code, kind) -> None:
    """The dedicated owner claims its exact ADD or SUB projection."""
    codegen, storage, fact = _wide_authority_fixture(code)
    assert fact.kind is kind
    _publish_artifact(codegen, storage, fact)

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen, **_legacy_classify_kwargs(fact)
    )

    assert ownership.status is WideCallOutputAuthoritativeOwnershipStatus8616.MATERIALIZED
    assert ownership.blocks_legacy_materialization
    assert ownership.materialized
    assert ownership.fact == fact


def test_wide_authority_refuses_forged_operation_kind() -> None:
    """A resolution claiming a different arithmetic kind never certifies."""
    codegen, storage, fact = _wide_authority_fixture()
    forged = replace(fact, kind=CarryBorrowKind8616.SUB_WITH_BORROW)
    _publish_artifact(codegen, storage, forged)

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen, **_legacy_classify_kwargs(forged)
    )

    assert ownership.status is WideCallOutputAuthoritativeOwnershipStatus8616.REFUSED
    assert ownership.blocks_legacy_materialization
    assert not ownership.materialized


def test_wide_authority_refuses_coherent_shifted_destination() -> None:
    """A destination offset agreeing with the fact but not the stores refuses."""
    codegen, storage, fact = _wide_authority_fixture()
    forged_source = replace(
        storage, address=replace(storage.address, offset=2)
    )
    forged = replace(fact, destination_offset=2)
    _publish_artifact(codegen, forged_source, forged)

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen, **_legacy_classify_kwargs(forged)
    )

    assert ownership.status is WideCallOutputAuthoritativeOwnershipStatus8616.REFUSED
    assert ownership.blocks_legacy_materialization
    assert not ownership.materialized
