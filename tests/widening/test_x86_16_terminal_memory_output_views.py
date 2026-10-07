from __future__ import annotations

from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.lowering.interprocedural_storage_live_out_contracts import (
    MemoryLiveOutFailureKind8616,
)
from inertia.lowering.interprocedural_storage_live_out_flow import (
    materialize_memory_live_out_candidate_8616,
)

from inertia.alias.terminal_memory_outputs import (
    TerminalMemoryAliasFact8616,
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
    TerminalMemoryOutputViewFailure8616,
    TerminalMemoryOutputViewKind8616,
    collect_terminal_memory_output_views_8616,
)

FUNCTION = 0x1000
CALLER = 0x2000


def _address(
    offset: int,
    size: int,
    *,
    space: MemSpace = MemSpace.DS,
    base: tuple[str, ...] = (),
    segment_origin: SegmentOrigin = SegmentOrigin.PROVEN,
) -> IRAddress:
    return IRAddress(
        space,
        base=base,
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=segment_origin,
    )


def _owner(offset: int = 0x1200, size: int = 2) -> TerminalMemoryAliasFact8616:
    address = _address(offset, size)
    output = TerminalMemoryOutputFact8616(
        address,
        TerminalMemoryOutputDisposition8616.MUST_WRITE,
        (TerminalMemoryStoreSite8616(FUNCTION, 0, FUNCTION),),
        (FUNCTION,),
        (FUNCTION,),
    )
    terminal = TerminalMemoryOutputEvidence8616(
        FUNCTION,
        (output,),
        None,
        TerminalMemoryOutputStats8616(1, 1, 1, 1),
    )
    aliases = classify_terminal_memory_output_aliases_8616(terminal)
    assert aliases.complete is True
    return aliases.canonical_facts[0]


def _load(
    offset: int,
    size: int,
    *,
    address_size: int | None = None,
    space: MemSpace = MemSpace.DS,
    base: tuple[str, ...] = (),
    segment_origin: SegmentOrigin = SegmentOrigin.PROVEN,
    ins_addr: int = CALLER,
) -> IRInstr:
    return IRInstr(
        "LOAD",
        IRValue(MemSpace.TMP, name=f"t{ins_addr:x}", size=size),
        (
            _address(
                offset,
                size if address_size is None else address_size,
                space=space,
                base=base,
                segment_origin=segment_origin,
            ),
        ),
        size=size,
        addr=ins_addr,
    )


def _artifact(*instructions: IRInstr) -> SSAFunctionArtifact:
    return SSAFunctionArtifact(
        function_addr=CALLER,
        blocks=(SSABlock(CALLER, instructions, ()),),
        predecessor_map={CALLER: ()},
    )


def _call() -> IRInstr:
    return IRInstr(
        "CALL",
        None,
        (IRValue(MemSpace.CONST, const=FUNCTION, size=2),),
        size=2,
        addr=CALLER,
    )


def _store(offset: int, size: int, *, ins_addr: int) -> IRInstr:
    return IRInstr(
        "STORE",
        None,
        (
            _address(offset, size),
            IRValue(MemSpace.REG, name="ax" if size == 2 else "al", size=size),
        ),
        size=size,
        addr=ins_addr,
    )


def _high_byte_condition(load_addr: int) -> ConditionIR:
    return ConditionIR(
        "ne",
        IRValue(
            MemSpace.DS,
            offset=0x1201,
            size=1,
            memory_access_size=1,
            memory_access_insn=load_addr,
        ),
        IRValue(MemSpace.CONST, const=0, size=1),
        width_bits=8,
        producer_insn=load_addr,
    )


def test_exact_owner_load_retains_whole_view() -> None:
    evidence = collect_terminal_memory_output_views_8616(
        _owner(),
        _artifact(_load(0x1200, 2)),
    )

    assert evidence.complete is True
    assert len(evidence.facts) == 1
    assert evidence.facts[0].kind is TerminalMemoryOutputViewKind8616.WHOLE
    assert evidence.facts[0].byte_offset == 0
    assert evidence.facts[0].width == 2


def test_contained_high_byte_load_retains_projection_offset() -> None:
    evidence = collect_terminal_memory_output_views_8616(
        _owner(),
        _artifact(_load(0x1201, 1)),
    )

    assert evidence.complete is True
    assert len(evidence.facts) == 1
    assert evidence.facts[0].kind is TerminalMemoryOutputViewKind8616.CONTAINED
    assert evidence.facts[0].byte_offset == 1
    assert evidence.facts[0].address == _address(0x1201, 1)


def test_duplicate_exact_loads_form_one_view_with_two_accesses() -> None:
    evidence = collect_terminal_memory_output_views_8616(
        _owner(),
        _artifact(_load(0x1200, 2), _load(0x1200, 2, ins_addr=CALLER + 2)),
    )

    assert evidence.complete is True
    assert evidence.stats.raw_fact_count == 2
    assert evidence.stats.normalized_fact_count == 1
    assert evidence.stats.materialized_count == 1
    assert tuple(access.instr_addr for access in evidence.facts[0].accesses) == (
        CALLER,
        CALLER + 2,
    )


def test_crossing_load_refuses_without_partial_views() -> None:
    evidence = collect_terminal_memory_output_views_8616(
        _owner(),
        _artifact(_load(0x1201, 2)),
    )

    assert evidence.complete is False
    assert evidence.facts == ()
    assert evidence.failure is TerminalMemoryOutputViewFailure8616.CROSSING_OVERLAP
    assert evidence.stats.failure_count == 1


def test_unproven_overlapping_load_refuses_view_identity() -> None:
    evidence = collect_terminal_memory_output_views_8616(
        _owner(),
        _artifact(
            _load(
                0x1201,
                1,
                segment_origin=SegmentOrigin.DEFAULTED,
            )
        ),
    )

    assert evidence.complete is False
    assert evidence.facts == ()
    assert evidence.failure is TerminalMemoryOutputViewFailure8616.RANGE_BUILD_REFUSED


def test_access_width_conflict_refuses_view_identity() -> None:
    evidence = collect_terminal_memory_output_views_8616(
        _owner(),
        _artifact(_load(0x1201, 2, address_size=1)),
    )

    assert evidence.complete is False
    assert evidence.facts == ()
    assert evidence.failure is TerminalMemoryOutputViewFailure8616.ACCESS_WIDTH_CONFLICT


def test_other_segment_and_indirect_accesses_are_not_claimed_as_views() -> None:
    evidence = collect_terminal_memory_output_views_8616(
        _owner(),
        _artifact(
            _load(0x1200, 2, space=MemSpace.ES),
            _load(0x1200, 2, base=("bx",), ins_addr=CALLER + 2),
        ),
    )

    assert evidence.complete is True
    assert evidence.facts == ()
    assert evidence.stats.raw_fact_count == 0


def test_disjoint_low_byte_write_preserves_high_byte_call_output_view() -> None:
    load_addr = CALLER + 4
    artifact = _artifact(
        _call(),
        _store(0x1200, 1, ins_addr=CALLER + 2),
        _load(0x1201, 1, ins_addr=load_addr),
    )
    views = collect_terminal_memory_output_views_8616(_owner(), artifact)
    assert views.complete is True
    assert len(views.facts) == 1

    result = materialize_memory_live_out_candidate_8616(
        artifact,
        views.facts[0],
        CALLER,
        FUNCTION,
        CALLER,
        (FUNCTION,),
        (_high_byte_condition(load_addr),),
    )

    assert result.complete is True
    assert result.failure is None
    assert result.trial is not None
    assert result.trial.storage.address == _address(0x1201, 1)


def test_whole_owner_write_refuses_high_byte_call_output_attribution() -> None:
    load_addr = CALLER + 4
    artifact = _artifact(
        _call(),
        _store(0x1200, 2, ins_addr=CALLER + 2),
        _load(0x1201, 1, ins_addr=load_addr),
    )
    views = collect_terminal_memory_output_views_8616(_owner(), artifact)
    assert views.complete is True
    assert len(views.facts) == 1

    result = materialize_memory_live_out_candidate_8616(
        artifact,
        views.facts[0],
        CALLER,
        FUNCTION,
        CALLER,
        (FUNCTION,),
        (_high_byte_condition(load_addr),),
    )

    assert result.fact is None
    assert result.trial is None
    assert result.failure is MemoryLiveOutFailureKind8616.INTERVENING_WRITE
