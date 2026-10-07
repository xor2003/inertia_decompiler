"""Tests for exact Semantics-owned caller-frame effects."""

from __future__ import annotations

from dataclasses import replace

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import (
    CallsiteArgumentClass8616,
    CallsiteSummary8616,
)
from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRCallStackEffect8616,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.logical_memory_contracts import (
    empty_ir_logical_memory_artifact_8616,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa

from inertia.alias.partial_register_address_break import (
    PartialRegisterAddressBreakEvidence8616,
)
from inertia.semantics.call_stack_effect_contracts import (
    CallStackEffectFailure8616,
    CallStackEffectVerdict8616,
)
from inertia.semantics.call_stack_effects import (
    materialize_call_stack_effects_8616,
)


def test_arch_call_stack_fix_matches_near_return_address_push() -> None:
    """Keep angr's post-CALL stack coordinate aligned with the 16-bit frame."""
    arch = Arch86_16()

    assert arch.call_pushes_ret is True
    assert arch.call_sp_fix == arch.stack_change == -2


def _slot() -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=-2,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _slot_at(offset: int, *, size: int = 2) -> IRAddress:
    """Return one exact stable BP-relative test range."""
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _artifact(
    *,
    duplicate_call: bool = False,
    slots: tuple[IRAddress, ...] | None = None,
) -> IRFunctionArtifact:
    tracked_slots = (_slot(),) if slots is None else slots
    calls = (
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1003),
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1003),
    ) if duplicate_call else (
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1003),
    )
    return IRFunctionArtifact(
        0x1000,
        (
            IRBlock(
                0x1000,
                (
                    *(
                        IRInstr(
                            "STORE",
                            None,
                            (slot, IRValue(MemSpace.CONST, const=1, size=slot.size)),
                            size=slot.size,
                        )
                        for slot in tracked_slots
                    ),
                    *calls,
                    *(
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.REG, name=f"read_{index}", size=slot.size),
                            (slot,),
                            size=slot.size,
                        )
                        for index, slot in enumerate(tracked_slots)
                    ),
                ),
            ),
        ),
    )


def _summary(
    *,
    arg_widths: tuple[int, ...] = (),
    logical_arg_classes: tuple[CallsiteArgumentClass8616, ...] = (),
    push_arg_sources: tuple[tuple[object, ...] | None, ...] | None = None,
    cleanup: int | None = 0,
    callee_cleanup: bool = False,
) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1003,
        target_addr=0x2000,
        return_addr=0x1006,
        kind="direct_near",
        arg_count=len(arg_widths),
        arg_widths=arg_widths,
        stack_cleanup=cleanup,
        return_register="ax",
        return_used=True,
        logical_arg_widths=arg_widths,
        logical_arg_classes=logical_arg_classes,
        push_arg_sources=(
            tuple(("imm", index) for index, _width in enumerate(arg_widths))
            if push_arg_sources is None
            else push_arg_sources
        ),
        stack_cleanup_instruction_addr=0x1006 if cleanup and not callee_cleanup else None,
    )


def test_zero_argument_call_preserves_exact_bp_range_for_memory_ssa() -> None:
    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: _summary()})

    assert result.complete is True
    assert result.stats.to_dict() == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    assert result.facts[0].verdict is CallStackEffectVerdict8616.PROVEN
    assert result.facts[0].effect.preserved_ranges == (_slot(),)
    function_ssa = build_x86_16_function_ssa(result.function)
    assert function_ssa.memory_stats.failure_count == 0
    assert len(function_ssa.memory_bindings) == 1


def test_call_stack_effect_projection_preserves_logical_memory_artifact() -> None:
    marker = empty_ir_logical_memory_artifact_8616(0x1000)
    source = replace(_artifact(), logical_memory=marker)

    result = materialize_call_stack_effects_8616(source, {0x1003: _summary()})

    assert result.function.logical_memory is marker


def test_zero_argument_call_proves_zero_cleanup_when_summary_omits_it() -> None:
    """No argument bytes means there is no caller/callee cleanup ambiguity."""
    result = materialize_call_stack_effects_8616(
        _artifact(),
        {0x1003: _summary(cleanup=None)},
    )

    assert result.complete is True
    assert result.facts[0].verdict is CallStackEffectVerdict8616.PROVEN
    assert result.facts[0].effect.net_stack_delta == 0
    assert result.facts[0].effect.preserved_ranges == (_slot(),)


def test_callee_cleanup_preserves_exact_bp_range_with_known_sp_delta() -> None:
    """A proven callee cleanup moves SP without rebasing the caller's BP slot."""
    result = materialize_call_stack_effects_8616(
        _artifact(),
        {
            0x1003: _summary(
                arg_widths=(2,),
                logical_arg_classes=(CallsiteArgumentClass8616.VALUE,),
                cleanup=2,
                callee_cleanup=True,
            )
        },
    )

    assert result.complete is True
    assert result.facts[0].effect.net_stack_delta == 2
    assert result.facts[0].effect.preserves(_slot()) is True
    function_ssa = build_x86_16_function_ssa(result.function)
    assert function_ssa.memory_stats.failure_count == 0
    assert len(function_ssa.memory_bindings) == 1


def test_nonzero_delta_does_not_preserve_current_sp_coordinate() -> None:
    """A current-SP range moves when a complete call changes SP."""
    sp_slot = IRAddress(
        MemSpace.SS,
        base=("sp",),
        offset=2,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
    effect = IRCallStackEffect8616(
        net_stack_delta=2,
        preserved_ranges=(sp_slot,),
        complete=True,
    )

    assert effect.preserves(sp_slot) is False


def test_unknown_delta_does_not_preserve_bp_coordinate() -> None:
    """Explicit range identity cannot compensate for an unknown stack delta."""
    effect = IRCallStackEffect8616(
        preserved_ranges=(_slot(),),
        complete=True,
    )

    assert effect.preserves(_slot()) is False


def test_missing_call_summary_materializes_typed_refusal() -> None:
    result = materialize_call_stack_effects_8616(_artifact(), {})

    assert result.stats.closed is True
    assert result.complete is False
    assert result.facts[0].failure is CallStackEffectFailure8616.SUMMARY_MISSING
    assert result.facts[0].effect.complete is False
    function_ssa = build_x86_16_function_ssa(result.function)
    assert {item.kind for item in function_ssa.memory_refusals} == {"unknown_call_stack_effect"}


def test_unknown_pointer_source_refuses_caller_frame_preservation() -> None:
    summary = _summary(
        arg_widths=(2,),
        logical_arg_classes=(CallsiteArgumentClass8616.POINTER,),
        push_arg_sources=(None,),
        cleanup=2,
    )
    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: summary})

    assert result.facts[0].failure is CallStackEffectFailure8616.ARGUMENT_SOURCES_INCOMPLETE
    assert result.facts[0].effect.complete is False


def test_partial_register_write_proves_unknown_value_does_not_escape_stack() -> None:
    """Separate whole-word value uncertainty from stack-address provenance."""
    evidence = PartialRegisterAddressBreakEvidence8616(
        push_instruction_addr=0x1002,
        definition_instruction_addr=0x1000,
        carrier_register="ax",
        written_register="al",
        immediate=2,
    )
    summary = replace(
        _summary(
            arg_widths=(2,),
            push_arg_sources=(None,),
            cleanup=2,
        ),
        push_arg_instruction_addrs=(0x1002,),
        push_arg_address_break_evidence=(evidence,),
    )

    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: summary})

    assert result.complete
    assert result.facts[0].failure is None
    assert result.facts[0].effect.preserved_ranges == (_slot(),)


def test_partial_register_address_break_requires_matching_push_identity() -> None:
    """Refuse evidence attached to a different physical PUSH."""
    evidence = PartialRegisterAddressBreakEvidence8616(
        push_instruction_addr=0x1001,
        definition_instruction_addr=0x1000,
        carrier_register="ax",
        written_register="al",
        immediate=2,
    )
    summary = replace(
        _summary(arg_widths=(2,), push_arg_sources=(None,), cleanup=2),
        push_arg_instruction_addrs=(0x1002,),
        push_arg_address_break_evidence=(evidence,),
    )

    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: summary})

    assert (
        result.facts[0].failure
        is CallStackEffectFailure8616.ARGUMENT_ADDRESS_PROVENANCE_CONFLICT
    )


def test_exact_bp_address_escapes_only_its_tracked_range() -> None:
    escaped_slot = _slot_at(-82, size=1)
    scalar_slot = _slot()
    summary = _summary(
        arg_widths=(2,),
        logical_arg_classes=(),
        push_arg_sources=(("bp_addr", -82),),
        cleanup=2,
    )

    result = materialize_call_stack_effects_8616(
        _artifact(slots=(escaped_slot, scalar_slot)),
        {0x1003: summary},
    )

    assert result.complete is True
    assert result.facts[0].failure is None
    assert result.facts[0].effect.escaped_ranges == (escaped_slot,)
    assert result.facts[0].effect.preserved_ranges == (scalar_slot,)
    function_ssa = build_x86_16_function_ssa(result.function)
    assert {binding.address.offset for binding in function_ssa.memory_bindings} == {-2}
    assert {item.kind for item in function_ssa.memory_refusals} == {
        "unknown_call_stack_effect"
    }


def test_dynamic_bp_address_source_retains_full_pointer_refusal() -> None:
    summary = _summary(
        arg_widths=(2,),
        logical_arg_classes=(),
        push_arg_sources=(("bp_index_addr", -82, "si", 1),),
        cleanup=2,
    )

    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: summary})

    assert result.complete is False
    assert result.facts[0].failure is CallStackEffectFailure8616.POINTER_ARGUMENT_MAY_ESCAPE
    assert result.facts[0].effect.escaped_ranges == (_slot(),)


def test_duplicate_machine_call_address_refuses_both_producers() -> None:
    result = materialize_call_stack_effects_8616(
        _artifact(duplicate_call=True),
        {0x1003: _summary()},
    )

    assert result.stats.raw_fact_count == 2
    assert result.stats.materialized_count == 2
    assert result.stats.failure_count == 2
    assert {fact.failure for fact in result.facts} == {
        CallStackEffectFailure8616.DUPLICATE_CALL_ADDRESS
    }
