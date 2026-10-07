"""Tests for the typed whole-program global-object context decision."""

from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.global_object_program_requirement import (
    GlobalObjectProgramRequirementReason8616,
    GlobalObjectProgramRequirementVerdict8616,
    recover_global_object_program_requirement_8616,
)

from inertia.alias.indexed_address_program import (
    IndexedAliasProgramEvidence8616,
    IndexedAliasProgramStats8616,
)


def _empty_alias_program() -> IndexedAliasProgramEvidence8616:
    return IndexedAliasProgramEvidence8616(
        functions=(),
        refusals=(),
        stats=IndexedAliasProgramStats8616(),
    )


def _summary(*sources: tuple[object, ...] | None) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x109C1,
        target_addr=0x107B8,
        return_addr=0x109C4,
        kind="near",
        arg_count=len(sources),
        arg_widths=(2,) * len(sources),
        stack_cleanup=2 * len(sources),
        return_register=None,
        return_used=False,
        push_arg_sources=sources,
    )


def test_global_pointer_call_source_requires_program_context() -> None:
    evidence = recover_global_object_program_requirement_8616(
        _empty_alias_program(),
        (_summary(("expr", ("stack", "bp", -2), (("shl", 1), ("add", 0x0B4C))), ("imm", 0x0B4C)),),
        {0x107B8: (0, 1)},
    )

    assert evidence.closed
    assert evidence.verdict is GlobalObjectProgramRequirementVerdict8616.REQUIRED
    assert evidence.reasons == (
        GlobalObjectProgramRequirementReason8616.CALLEE_GLOBAL_POINTER_SOURCE,
    )
    assert evidence.global_pointer_source_count == 2
    assert evidence.raw_fact_count == evidence.materialized_count == 2
    assert evidence.failure_count == 0


def test_mixed_call_uses_c_argument_order_for_pointer_index() -> None:
    evidence = recover_global_object_program_requirement_8616(
        _empty_alias_program(),
        (_summary(("imm", 7), ("imm", 0x0B4C)),),
        {0x107B8: (0,)},
    )

    assert evidence.closed
    assert evidence.requires_program
    assert evidence.global_pointer_source_count == 1
    assert evidence.stack_pointer_source_count == 0


def test_proven_stack_pointer_does_not_require_global_catalog() -> None:
    evidence = recover_global_object_program_requirement_8616(
        _empty_alias_program(),
        (_summary(("imm", 7), ("bp_addr", -4)),),
        {0x107B8: (0,)},
    )

    assert evidence.closed
    assert evidence.verdict is GlobalObjectProgramRequirementVerdict8616.NOT_REQUIRED
    assert evidence.stack_pointer_source_count == 1
    assert evidence.failure_count == 0


def test_unknown_pointer_source_refuses_without_guessing_global_storage() -> None:
    evidence = recover_global_object_program_requirement_8616(
        _empty_alias_program(),
        (_summary(("imm", 7), ("bp", 4)),),
        {0x107B8: (0,)},
    )

    assert evidence.closed
    assert evidence.verdict is GlobalObjectProgramRequirementVerdict8616.UNKNOWN_REFUSE
    assert evidence.classified_fact_count == 0
    assert evidence.materialized_count == 0
    assert evidence.failure_count == 1
