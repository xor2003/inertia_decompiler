"""Tests for the typed whole-program global-object context decision."""

import io
from types import SimpleNamespace

import angr

from inertia.alias.indexed_address_program import (
    IndexedAliasFunctionRefusal8616,
    IndexedAliasFunctionSelection8616,
    IndexedAliasProgramEvidence8616,
    IndexedAliasProgramFailureKind8616,
    IndexedAliasProgramStats8616,
    build_indexed_alias_program_evidence_8616,
)
from inertia.frontend.x86_16 import lift_86_16  # noqa: F401
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.global_object_program_requirement import (
    GlobalObjectProgramRequirementReason8616,
    GlobalObjectProgramRequirementVerdict8616,
    recover_global_object_program_requirement_8616,
)
from inertia.semantics.callsite_summary import CallsiteSummary8616


def _empty_alias_program() -> IndexedAliasProgramEvidence8616:
    return IndexedAliasProgramEvidence8616(
        functions=(),
        refusals=(),
        stats=IndexedAliasProgramStats8616(),
    )


def _ir_build_refusal_program() -> IndexedAliasProgramEvidence8616:
    refusal = IndexedAliasFunctionRefusal8616(
        0x12000,
        IndexedAliasProgramFailureKind8616.IR_BUILD_FAILED,
        "exact IR/SSA construction refused: test",
    )
    return IndexedAliasProgramEvidence8616(
        functions=(),
        refusals=(refusal,),
        stats=IndexedAliasProgramStats8616(
            raw_fact_count=1,
            failure_count=1,
        ),
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


def test_unavailable_local_function_refuses_instead_of_not_required() -> None:
    program = _ir_build_refusal_program()
    assert program.closed

    evidence = recover_global_object_program_requirement_8616(program, (), {})

    assert evidence.closed
    assert evidence.verdict is GlobalObjectProgramRequirementVerdict8616.UNKNOWN_REFUSE
    assert evidence.raw_fact_count == 1
    assert evidence.classified_fact_count == 0
    assert evidence.materialized_count == 0
    assert evidence.failure_count == 1


def test_proven_required_reason_keeps_local_refusal_accounted() -> None:
    evidence = recover_global_object_program_requirement_8616(
        _ir_build_refusal_program(),
        (_summary(("imm", 7), ("imm", 0x0B4C)),),
        {0x107B8: (0,)},
    )

    assert evidence.closed
    assert evidence.verdict is GlobalObjectProgramRequirementVerdict8616.REQUIRED
    assert evidence.reasons == (
        GlobalObjectProgramRequirementReason8616.CALLEE_GLOBAL_POINTER_SOURCE,
    )
    assert evidence.raw_fact_count == 2
    assert evidence.classified_fact_count == 1
    assert evidence.materialized_count == 1
    assert evidence.global_pointer_source_count == 1
    assert evidence.failure_count == 1


def test_closed_local_access_refusal_cannot_prove_catalog_unnecessary() -> None:
    # BX+SI combines two dynamic address terms: its storage role is unproven.
    code = bytes.fromhex(
        "55 89 e5 83 ec 02 c7 46 fe 01 00 8b 76 fe d1 e6 8b 80 00 02 c9 c3"
    )
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    program = build_indexed_alias_program_evidence_8616(
        project, (IndexedAliasFunctionSelection8616(0x1000, function),),
    )
    assert program.closed
    assert not program.refusals
    accesses = program.functions[0].accesses
    assert accesses.closed
    assert accesses.refusals

    evidence = recover_global_object_program_requirement_8616(program, (), {})

    assert evidence.closed
    assert evidence.verdict is GlobalObjectProgramRequirementVerdict8616.UNKNOWN_REFUSE
    assert evidence.raw_fact_count == evidence.failure_count == len(accesses.refusals)
    assert evidence.materialized_count == 0
