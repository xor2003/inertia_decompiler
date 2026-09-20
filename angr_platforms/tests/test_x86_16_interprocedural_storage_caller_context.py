"""Exact caller SSA context joins for interprocedural return trials."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering import callee_callsite_census
from angr_platforms.X86_16.lowering.callee_callsite_census import (
    CalleeCallsiteCensus8616,
    CalleeCallsiteFact8616,
    collect_callee_callsite_census_8616,
)
from angr_platforms.X86_16.lowering.callee_callsite_contracts import (
    callee_callsite_censuses_by_addr_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_caller_context import (
    CallerSSAContextVerdict8616,
    caller_ssa_context_for_return_use_8616,
)

CALLEE_ADDR = 0x1100
CALLER_ADDR = 0x1000
CALLSITE_ADDR = 0x1010


def _return_use() -> CallerReturnUseFact8616:
    return CallerReturnUseFact8616(
        caller_addr=CALLER_ADDR,
        callsite_addr=CALLSITE_ADDR,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=CallsiteReturnUseKind8616.VALUE,
        witness_instruction_addr=0x1013,
    )


def _summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=CALLSITE_ADDR,
        target_addr=CALLEE_ADDR,
        return_addr=0x1013,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
    )


def _caller_fact(project: object, boundary: object) -> CalleeCallsiteFact8616:
    return CalleeCallsiteFact8616(
        evidence_project=project,
        caller_function=boundary,
        evidence_target_addr=CALLEE_ADDR,
        caller_addr=CALLER_ADDR,
        callsite_addr=CALLSITE_ADDR,
        summary=_summary(),
    )


def _project_with_facts(
    facts: tuple[CalleeCallsiteFact8616, ...],
) -> SimpleNamespace:
    census = CalleeCallsiteCensus8616(
        target_addr=CALLEE_ADDR,
        facts=facts,
        raw_fact_count=len(facts),
        normalized_fact_count=len(facts),
        failure_count=0,
    )
    return SimpleNamespace(_inertia_callee_callsite_census_8616={CALLEE_ADDR: census})


def test_return_use_selects_census_owned_project_and_boundary() -> None:
    evidence_project = SimpleNamespace(name="original")
    boundary = SimpleNamespace(addr=CALLER_ADDR, block_addrs_set={CALLER_ADDR})
    project = _project_with_facts((_caller_fact(evidence_project, boundary),))

    result = caller_ssa_context_for_return_use_8616(
        project,
        CALLEE_ADDR,
        _return_use(),
    )

    assert result.verdict is CallerSSAContextVerdict8616.PROVEN
    assert result.complete
    assert result.evidence_project is evidence_project
    assert result.caller_function is boundary


def test_missing_return_use_context_is_typed_unavailable() -> None:
    result = caller_ssa_context_for_return_use_8616(
        _project_with_facts(()),
        CALLEE_ADDR,
        _return_use(),
    )

    assert result.verdict is CallerSSAContextVerdict8616.UNAVAILABLE
    assert not result.complete


def test_duplicate_return_use_context_is_typed_conflict() -> None:
    project_a = SimpleNamespace(name="a")
    project_b = SimpleNamespace(name="b")
    boundary = SimpleNamespace(addr=CALLER_ADDR, block_addrs_set={CALLER_ADDR})
    project = _project_with_facts(
        (
            _caller_fact(project_a, boundary),
            _caller_fact(project_b, boundary),
        )
    )

    result = caller_ssa_context_for_return_use_8616(
        project,
        CALLEE_ADDR,
        _return_use(),
    )

    assert result.verdict is CallerSSAContextVerdict8616.CONFLICT
    assert not result.complete


def test_empty_census_before_fact_materialization_is_not_cached(monkeypatch) -> None:
    """Late exact caller facts must replace provisional early absence."""
    functions = SimpleNamespace(values=lambda: ())
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=functions),
        _inertia_caller_function_ranges_8616=((CALLER_ADDR, CALLER_ADDR + 0x20),),
    )
    boundary = SimpleNamespace(addr=CALLER_ADDR, block_addrs_set={CALLER_ADDR})

    early = collect_callee_callsite_census_8616(project, CALLEE_ADDR)

    assert early.raw_fact_count == 0
    assert CALLEE_ADDR not in callee_callsite_censuses_by_addr_8616(project)

    monkeypatch.setattr(
        callee_callsite_census,
        "collect_range_callsite_facts_for_target_8616",
        lambda _project, _target, _ranges: (_caller_fact(project, boundary),),
    )

    rebuilt = collect_callee_callsite_census_8616(project, CALLEE_ADDR)

    assert rebuilt.complete
    assert rebuilt.facts[0].callsite_addr == CALLSITE_ADDR


@pytest.mark.parametrize("duplicate", (False, True))
def test_memory_live_out_uses_exact_census_owner(monkeypatch, duplicate) -> None:
    """A callee-only slice must use caller-owned SSA and condition evidence."""
    from angr_platforms.X86_16.ir import (
        AddressStatus,
        IRAddress,
        IRInstr,
        IRValue,
        MemSpace,
        SegmentOrigin,
    )
    from angr_platforms.X86_16.ir.condition_ir import ConditionIR
    from angr_platforms.X86_16.ir.function_ssa_registry import FunctionSSAArtifactStage8616
    from angr_platforms.X86_16.ir.ssa import SSABlock
    from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
    from angr_platforms.X86_16.lowering import interprocedural_storage_live_out as live_out
    from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import CallsiteStorageTrials8616
    from angr_platforms.X86_16.lowering.interprocedural_storage_live_out_contracts import (
        MemoryLiveOutCollectionVerdict8616,
    )

    address = IRAddress(
        MemSpace.DS, offset=0x200, size=1, status=AddressStatus.STABLE, segment_origin=SegmentOrigin.PROVEN
    )
    byte = IRValue(MemSpace.REG, name="al", size=1)
    store = IRInstr("STORE", None, (address, byte), size=1, addr=CALLEE_ADDR)
    callee = SSAFunctionArtifact(CALLEE_ADDR, (SSABlock(CALLEE_ADDR, (store,), ()),), predecessor_map={CALLEE_ADDR: ()})
    load_addr = CALLSITE_ADDR + 3
    call = IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=CALLEE_ADDR, size=2),), size=2, addr=CALLSITE_ADDR)
    load = IRInstr("LOAD", byte, (address,), size=1, addr=load_addr)
    caller = SSAFunctionArtifact(
        CALLER_ADDR, (SSABlock(CALLER_ADDR, (call, load), ()),), predecessor_map={CALLER_ADDR: ()}
    )
    source = SimpleNamespace(
        _inertia_function_ssa_artifacts_8616={CALLER_ADDR: caller},
        _inertia_function_ssa_stages_8616={CALLER_ADDR: FunctionSSAArtifactStage8616.SEMANTIC},
    )
    boundary = SimpleNamespace(addr=CALLER_ADDR, block_addrs_set={CALLER_ADDR})
    fact = _caller_fact(source, boundary)
    facts = (fact, _caller_fact(object(), boundary)) if duplicate else (fact,)
    project = _project_with_facts(facts)
    project._inertia_function_ssa_artifacts_8616 = {CALLEE_ADDR: callee}
    project._inertia_function_ssa_stages_8616 = {CALLEE_ADDR: FunctionSSAArtifactStage8616.SEMANTIC}
    project.factory = SimpleNamespace(
        block=lambda *args, **kwargs: SimpleNamespace(
            capstone=SimpleNamespace(insns=(SimpleNamespace(mnemonic="ret"),))
        )
    )
    condition = ConditionIR(
        op="slt",
        lhs=IRValue(MemSpace.DS, offset=0x200, size=1, memory_access_size=1, memory_access_insn=load_addr),
        rhs=IRValue(MemSpace.CONST, const=0, size=1),
        width_bits=8,
        producer_insn=load_addr,
    )

    def conditions(owner, function_addr):
        assert not duplicate, "conflicting caller census must refuse before consuming SSA"
        assert owner is source
        assert function_addr == CALLER_ADDR
        return (condition,), ()

    monkeypatch.setattr(live_out, "collect_typed_condition_artifacts_8616", conditions)
    result = live_out.collect_function_memory_live_out_trials_8616(
        project,
        CALLEE_ADDR,
        (CallsiteStorageTrials8616(CALLER_ADDR, CALLEE_ADDR, CALLSITE_ADDR, stack_delta=0),),
        (CALLEE_ADDR,),
    )
    if duplicate:
        assert result.verdict is MemoryLiveOutCollectionVerdict8616.CONFLICT
        assert not result.callsites
        assert result.failures[0].caller_addr == CALLER_ADDR
        assert result.failures[0].callsite_addr == CALLSITE_ADDR
    else:
        assert result.complete, result.failures
        assert result.stats.materialized_count == 1
        assert len(result.callsites[0].trials) == 1


def test_memory_conditions_cache_is_scoped_to_the_caller_project(monkeypatch) -> None:
    """Equal caller addresses in distinct evidence projects must not share facts."""
    from angr_platforms.X86_16.lowering import interprocedural_storage_live_out as live_out

    first, second = object(), object()
    seen = []

    def collect(project, caller_addr):
        seen.append((project, caller_addr))
        return (), ()

    monkeypatch.setattr(live_out, "collect_typed_condition_artifacts_8616", collect)
    cache = {}
    for project in (first, second, first):
        assert live_out._caller_conditions_8616(project, CALLER_ADDR, cache) == ()
    assert seen == [(first, CALLER_ADDR), (second, CALLER_ADDR)]
