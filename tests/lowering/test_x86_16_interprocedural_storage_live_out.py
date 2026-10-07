from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.condition_ir import ConditionIR, ConditionOp
from inertia.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact
import inertia.lowering.interprocedural_storage_live_out as interprocedural_storage_live_out
import inertia.lowering.interprocedural_storage_live_out_flow as interprocedural_storage_live_out_flow
from inertia.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
)
from inertia.lowering.interprocedural_storage_live_out import (
    collect_function_memory_live_out_trials_8616,
)
from inertia.lowering.interprocedural_storage_live_out_contracts import (
    MemoryLiveOutCandidateResult8616,
    MemoryLiveOutFailureKind8616,
    MemoryLiveOutUseDisposition8616,
)
from inertia.lowering.interprocedural_storage_live_out_flow import (
    materialize_memory_live_out_candidate_8616,
)
from inertia.lowering.interprocedural_storage_return_defs import CallOutputDefinitionResult8616

from inertia.alias.terminal_memory_outputs import (
    classify_terminal_memory_output_aliases_8616,
)
from inertia.semantics.terminal_memory_output_contracts import (
    TerminalMemoryOutputDisposition8616,
    TerminalMemoryOutputEvidence8616,
    TerminalMemoryOutputFact8616,
    TerminalMemoryOutputStats8616,
    TerminalMemoryStoreSite8616,
)
from inertia.widening.terminal_memory_output_views import (
    collect_terminal_memory_output_views_8616,
)

CALLER = 0x1000
CALLEE = 0x1020
CALLSITE = 0x1000
LOAD_ADDR = 0x1003


def _address(*, size: int = 1, base: tuple[str, ...] = ()) -> IRAddress:
    return IRAddress(
        MemSpace.DS,
        base=base,
        offset=0x1234,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _call(address: int = CALLSITE, target: int = CALLEE) -> IRInstr:
    return IRInstr(
        "CALL",
        None,
        (IRValue(MemSpace.CONST, const=target, size=2),),
        size=2,
        addr=address,
    )


def _load(address: int = LOAD_ADDR, *, size: int = 1) -> IRInstr:
    return IRInstr(
        "LOAD",
        IRValue(MemSpace.TMP, name="t0", size=size),
        (_address(size=size),),
        size=size,
        addr=address,
    )


def _store(address: int = 0x1002, *, base: tuple[str, ...] = ()) -> IRInstr:
    return IRInstr(
        "STORE",
        None,
        (_address(base=base), IRValue(MemSpace.REG, name="al", size=1)),
        size=1,
        addr=address,
    )


def _artifact(*instructions: IRInstr) -> SSAFunctionArtifact:
    return SSAFunctionArtifact(
        function_addr=CALLER,
        blocks=(SSABlock(CALLER, instructions, ()),),
        predecessor_map={CALLER: ()},
    )


def _mixed_path_artifact(
    *blocked_instructions: IRInstr,
    blocked_reaches_load: bool = True,
) -> SSAFunctionArtifact:
    clean_block = 0x1004
    blocked_block = 0x1006
    merge_block = 0x1008
    return SSAFunctionArtifact(
        function_addr=CALLER,
        blocks=(
            SSABlock(CALLER, (_call(),), ()),
            SSABlock(clean_block, (), ()),
            SSABlock(blocked_block, blocked_instructions, ()),
            SSABlock(merge_block, (_load(merge_block),), ()),
        ),
        predecessor_map={
            CALLER: (),
            clean_block: (CALLER,),
            blocked_block: (CALLER,),
            merge_block: (
                (clean_block, blocked_block) if blocked_reaches_load else (clean_block,)
            ),
        },
    )


def _disconnected_load_artifact() -> SSAFunctionArtifact:
    load_block = 0x1008
    return SSAFunctionArtifact(
        function_addr=CALLER,
        blocks=(
            SSABlock(CALLER, (_call(), _call(0x1002, 0x1100)), ()),
            SSABlock(load_block, (_load(load_block),), ()),
        ),
        predecessor_map={CALLER: (), load_block: ()},
    )


def _output(
    disposition: TerminalMemoryOutputDisposition8616 = TerminalMemoryOutputDisposition8616.MUST_WRITE,
    *,
    size: int = 1,
) -> TerminalMemoryOutputFact8616:
    definite = (
        (CALLEE,)
        if disposition is TerminalMemoryOutputDisposition8616.MUST_WRITE
        else ()
    )
    return TerminalMemoryOutputFact8616(
        _address(size=size),
        disposition,
        (TerminalMemoryStoreSite8616(CALLEE, 0, CALLEE),),
        (CALLEE,),
        definite,
    )


def _condition(
    op: ConditionOp = "ne",
    *,
    load_addr: int = LOAD_ADDR,
    size: int = 1,
) -> ConditionIR:
    return ConditionIR(
        op=op,
        lhs=IRValue(
            MemSpace.DS,
            offset=0x1234,
            size=size,
            memory_access_size=size,
            memory_access_insn=load_addr,
        ),
        rhs=IRValue(MemSpace.CONST, const=0, size=size),
        width_bits=size * 8,
        producer_insn=load_addr,
    )


def _materialize(
    artifact: SSAFunctionArtifact,
    output: TerminalMemoryOutputFact8616 | None = None,
    conditions: tuple[ConditionIR, ...] | None = None,
) -> MemoryLiveOutCandidateResult8616:
    terminal_output = output or _output()
    terminal = TerminalMemoryOutputEvidence8616(
        CALLEE,
        (terminal_output,),
        None,
        TerminalMemoryOutputStats8616(1, 1, 1, 1),
    )
    alias_evidence = classify_terminal_memory_output_aliases_8616(terminal)
    assert alias_evidence.complete is True
    views = collect_terminal_memory_output_views_8616(
        alias_evidence.canonical_facts[0], artifact
    )
    assert views.complete is True
    if not views.facts:
        return MemoryLiveOutCandidateResult8616(False)
    assert len(views.facts) == 1
    return materialize_memory_live_out_candidate_8616(
        artifact,
        views.facts[0],
        CALLER,
        CALLEE,
        CALLSITE,
        (CALLEE,),
        conditions if conditions is not None else (_condition(),),
    )


def test_exact_direct_condition_use_materializes_live_out_trial() -> None:
    result = _materialize(_artifact(_call(), _load()))

    assert result.complete is True
    assert result.failure is None
    assert result.fact is not None
    assert result.fact.disposition is MemoryLiveOutUseDisposition8616.USED
    assert result.fact.signedness is StorageTrialSignedness8616.SIGN_INSENSITIVE
    assert result.trial is not None
    assert result.trial.is_complete is True
    assert result.trial.role is StorageTrialRole8616.LIVE_OUT
    assert result.trial.reaching_definition.value.space is MemSpace.DS


def test_absent_direct_load_does_not_create_unused_fact() -> None:
    result = _materialize(_artifact(_call()))

    assert result.complete is True
    assert result.activated is False
    assert result.fact is result.trial is result.failure is None


def test_direct_load_without_condition_provenance_does_not_activate() -> None:
    result = _materialize(_artifact(_call(), _load()), conditions=())

    assert result.complete is True
    assert result.activated is False
    assert result.fact is result.trial is result.failure is None


def test_exact_store_before_load_closes_as_not_reached() -> None:
    result = _materialize(_artifact(_call(), _store(), _load()))

    assert result.complete is True
    assert result.fact is not None
    assert result.fact.disposition is MemoryLiveOutUseDisposition8616.NOT_REACHED
    assert result.trial is None


def test_partial_overwrite_refuses_live_out_attribution() -> None:
    result = _materialize(
        _artifact(_call(), _store(), _load(size=2)),
        output=_output(size=2),
        conditions=(_condition(size=2),),
    )

    assert result.fact is None
    assert result.trial is None
    assert result.failure is MemoryLiveOutFailureKind8616.INTERVENING_WRITE


@pytest.mark.parametrize(
    ("blocker", "failure"),
    (
        ((_store(0x1006),), MemoryLiveOutFailureKind8616.INTERVENING_WRITE),
        (
            (_store(0x1006, base=("bx",)),),
            MemoryLiveOutFailureKind8616.INTERVENING_ALIAS,
        ),
        ((_call(0x1006, 0x1100),), MemoryLiveOutFailureKind8616.INTERVENING_CALL),
    ),
)
def test_mixed_clean_and_blocked_paths_refuse_live_out_attribution(
    blocker: tuple[IRInstr, ...], failure: MemoryLiveOutFailureKind8616
) -> None:
    result = _materialize(
        _mixed_path_artifact(*blocker),
        conditions=(_condition(load_addr=0x1008),),
    )

    assert result.fact is None
    assert result.trial is None
    assert result.failure is failure


def test_blocked_branch_that_cannot_reach_load_does_not_refuse_attribution() -> None:
    result = _materialize(
        _mixed_path_artifact(
            _call(0x1006, 0x1100),
            blocked_reaches_load=False,
        ),
        conditions=(_condition(load_addr=0x1008),),
    )

    assert result.complete is True
    assert result.failure is None
    assert result.fact is not None
    assert result.fact.disposition is MemoryLiveOutUseDisposition8616.USED
    assert result.trial is not None


def test_disconnected_load_closes_as_not_reached_despite_unrelated_blocker() -> None:
    result = _materialize(
        _disconnected_load_artifact(),
        conditions=(_condition(load_addr=0x1008),),
    )

    assert result.complete is True
    assert result.failure is None
    assert result.fact is not None
    assert result.fact.disposition is MemoryLiveOutUseDisposition8616.NOT_REACHED
    assert result.trial is None


def test_indirect_alias_and_intervening_call_refuse_attribution() -> None:
    alias = _materialize(_artifact(_call(), _store(base=("bx",)), _load()))
    second_call = _materialize(_artifact(_call(), _call(0x1002, 0x1100), _load()))

    assert alias.failure is MemoryLiveOutFailureKind8616.INTERVENING_ALIAS
    assert second_call.failure is MemoryLiveOutFailureKind8616.INTERVENING_CALL


def test_conditional_write_retains_typed_effect_without_value_trial() -> None:
    conditional = _materialize(
        _artifact(_call(), _load()),
        _output(TerminalMemoryOutputDisposition8616.CONDITIONAL),
    )

    assert conditional.complete is True
    assert conditional.failure is None
    assert conditional.trial is None
    assert conditional.fact is not None
    assert conditional.fact.disposition is MemoryLiveOutUseDisposition8616.USED
    assert (
        conditional.fact.terminal_output.disposition
        is TerminalMemoryOutputDisposition8616.CONDITIONAL
    )


def test_conflicting_condition_signedness_refuses() -> None:
    second_load = 0x1005
    result = _materialize(
        _artifact(_call(), _load(), _load(second_load)),
        conditions=(_condition("slt"), _condition("ult", load_addr=second_load)),
    )

    assert result.failure is MemoryLiveOutFailureKind8616.SIGNEDNESS_CONFLICT


def test_call_target_mismatch_is_typed_conflict() -> None:
    result = _materialize(_artifact(_call(target=0x1200), _load()))

    assert result.failure is MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_CONFLICT
    assert result.definition_failure is not None


def test_function_collection_connects_terminal_store_to_caller_live_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """The definition proof receives the same project as caller SSA collection."""
    caller = _artifact(_call(), _load())
    callee = SSAFunctionArtifact(
        function_addr=CALLEE,
        blocks=(SSABlock(CALLEE, (_store(CALLEE),), ()),),
        predecessor_map={CALLEE: ()},
    )

    class _Factory:
        def block(self, address: int, *, opt_level: int) -> object:
            assert address == CALLEE
            assert opt_level == 0
            instruction = SimpleNamespace(mnemonic="ret")
            return SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)))

    project = SimpleNamespace(
        factory=_Factory(),
        _inertia_function_ssa_artifacts_8616={CALLER: caller, CALLEE: callee},
        _inertia_function_ssa_stages_8616={
            CALLER: FunctionSSAArtifactStage8616.SEMANTIC,
            CALLEE: FunctionSSAArtifactStage8616.SEMANTIC,
        },
    )
    resolve = interprocedural_storage_live_out_flow.resolve_storage_call_output_definitions_8616
    observed_projects: list[object] = []

    def resolve_with_project(*args: Any, **kwargs: Any) -> CallOutputDefinitionResult8616:
        """Observe real definition resolution without substituting its verdict."""
        assert kwargs.get("project") is project
        observed_projects.append(project)
        return resolve(*args, **kwargs)

    monkeypatch.setattr(
        interprocedural_storage_live_out_flow,
        "resolve_storage_call_output_definitions_8616", resolve_with_project,
    )
    monkeypatch.setattr(
        interprocedural_storage_live_out,
        "collect_typed_condition_artifacts_8616",
        lambda _project, _address: ([_condition()], ()),
    )
    callsites = (CallsiteStorageTrials8616(CALLER, CALLEE, CALLSITE, stack_delta=0),)

    collection = collect_function_memory_live_out_trials_8616(
        project, CALLEE, callsites, (CALLEE,)
    )

    assert collection.complete is True
    assert observed_projects == [project]
    assert collection.stats.raw_fact_count == collection.stats.materialized_count == 1
    assert len(collection.callsites) == 1
    assert collection.callsites[0].trials[0].role is StorageTrialRole8616.LIVE_OUT


def test_function_collection_retains_conditional_effect_without_value_trial(monkeypatch) -> None:
    caller = _artifact(_call(), _load())
    stored_return = CALLEE + 2
    clean_return = CALLEE + 4
    callee = SSAFunctionArtifact(
        function_addr=CALLEE,
        blocks=(
            SSABlock(CALLEE, (), ()),
            SSABlock(stored_return, (_store(stored_return),), ()),
            SSABlock(clean_return, (), ()),
        ),
        predecessor_map={
            CALLEE: (),
            stored_return: (CALLEE,),
            clean_return: (CALLEE,),
        },
    )

    class _Factory:
        def block(self, address: int, *, opt_level: int) -> object:
            assert address in {stored_return, clean_return}
            assert opt_level == 0
            instruction = SimpleNamespace(mnemonic="ret")
            return SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)))

    project = SimpleNamespace(
        factory=_Factory(),
        _inertia_function_ssa_artifacts_8616={CALLER: caller, CALLEE: callee},
        _inertia_function_ssa_stages_8616={
            CALLER: FunctionSSAArtifactStage8616.SEMANTIC,
            CALLEE: FunctionSSAArtifactStage8616.SEMANTIC,
        },
    )
    monkeypatch.setattr(
        interprocedural_storage_live_out,
        "collect_typed_condition_artifacts_8616",
        lambda _project, _address: ([_condition()], ()),
    )
    callsites = (CallsiteStorageTrials8616(CALLER, CALLEE, CALLSITE, stack_delta=0),)

    collection = collect_function_memory_live_out_trials_8616(
        project, CALLEE, callsites, (CALLEE,)
    )

    assert collection.complete is True
    assert collection.stats.raw_fact_count == collection.stats.materialized_count == 1
    effect = collection.callsites[0].facts[0]
    assert effect.complete is True
    assert effect.terminal_output.disposition is TerminalMemoryOutputDisposition8616.CONDITIONAL
    assert effect.terminal_output.definitely_written_terminal_block_addrs == (stored_return,)
    assert collection.callsites[0].trials == ()
