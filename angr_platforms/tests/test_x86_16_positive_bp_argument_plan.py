from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CStatements, CVariable
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering.authoritative_function_prototypes import (
    authoritative_function_prototype_8616,
)
from angr_platforms.X86_16.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    CalleeArgumentCountVerdict8616,
)
from angr_platforms.X86_16.lowering.callee_argument_width_evidence import (
    CalleeArgumentWidthEvidence8616,
    CalleeArgumentWidthVerdict8616,
)
from angr_platforms.X86_16.lowering.near_pointer_type import near_pointer_type_8616
from angr_platforms.X86_16.lowering.positive_bp_argument_plan import (
    PositiveBpArgumentPlanDecision8616,
    PositiveBpArgumentPlanEntry8616,
    complete_positive_bp_argument_plan_8616,
    complete_positive_bp_body_word_access_plan_8616,
)
from angr_platforms.X86_16.lowering.positive_bp_arguments import (
    _canonical_argument_name_8616,
    _merge_existing_and_body_argument_type_8616,
    materialize_positive_bp_arguments_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
)


def _closed_three_word_evidence(*, complete_sources: bool) -> CalleeArgumentCountEvidence8616:
    sources = (
        (("global", 0xDA, 2), ("global", 0xD8, 2), ("global", 0xD6, 2))
        if complete_sources
        else (("global", 0xDA, 2), None, ("global", 0xD6, 2))
    )
    summary = CallsiteSummary8616(
        callsite_addr=0x101D2,
        target_addr=0x10058,
        return_addr=0x101D5,
        kind="near",
        arg_count=3,
        arg_widths=(2, 2, 2),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
        push_arg_sources=sources,
    )
    return CalleeArgumentCountEvidence8616(
        target_addr=0x10058,
        verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
        argument_count=3,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        callsite_addrs=(summary.callsite_addr,),
        callsite_summaries=(summary,),
    )


def _production_shape(
    *,
    complete_sources: bool,
    projected: bool = False,
) -> tuple[SimpleNamespace, SimpleNamespace, CVariable, CVariable, CVariable]:
    arch = Arch86_16()
    byte_type = SimTypeChar().with_arch(arch)
    word_type = SimTypeShort(False).with_arch(arch)
    pointer_type = near_pointer_type_8616(word_type, arch)
    stale_prototype = SimTypeFunction(
        [byte_type, byte_type, pointer_type],
        word_type,
        arg_names=("arg", "arg_5", "arg_5_2"),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x10058,
        prototype=stale_prototype,
        prototype_source=PrototypeSource.CCA_DECOMPILER,
        is_prototype_guessed=False,
        info={},
    )
    project = SimpleNamespace(
        arch=arch,
        # This fixture supplies caller evidence, but no decoded callee body.
        factory=SimpleNamespace(
            block=lambda *_args, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=())),
        ),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function),
        ),
        _inertia_callee_argument_count_evidence_8616={
            0x10058: _closed_three_word_evidence(complete_sources=complete_sources),
        },
    )
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
    )
    coordinate_bias = -2 if projected else 0
    argc = CVariable(
        SimStackVariable(4 + coordinate_bias, 1, base="bp", name="arg", region=0x10058),
        variable_type=byte_type,
        codegen=codegen,
    )
    stale_byte = CVariable(
        SimStackVariable(5 + coordinate_bias, 1, base="bp", name="arg_5", region=0x10058),
        variable_type=byte_type,
        codegen=codegen,
    )
    argv = CVariable(
        SimStackVariable(6 + coordinate_bias, 2, base="bp", name="arg_6", region=0x10058),
        variable_type=pointer_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x10058,
        arg_list=[argc, stale_byte, argv],
        functy=stale_prototype,
        prototype=stale_prototype,
        statements=CStatements([argc, argv], codegen=codegen),
        variables_in_use={
            argc.variable: argc,
            stale_byte.variable: stale_byte,
            argv.variable: argv,
        },
        unified_local_vars={},
    )
    if projected:
        for cvar, bp_offset in ((argc, 4), (stale_byte, 5), (argv, 6)):
            record_stack_variable_coordinate_projection_8616(
                codegen,
                variable=cvar.variable,
                cvar=cvar,
                bp_offset=bp_offset,
                entry_sp_offset=cvar.variable.offset,
                size=cvar.variable.size,
            )
    return project, codegen, argc, stale_byte, argv


def test_positive_bp_plan_completes_unused_caller_proven_tail() -> None:
    project, codegen, argc, stale_byte, argv = _production_shape(complete_sources=True)

    assert materialize_positive_bp_arguments_8616(project, codegen) is True

    arguments = tuple(codegen.cfunc.arg_list)
    assert tuple(argument.variable.offset for argument in arguments) == (4, 6, 8)
    assert tuple(argument.variable.size for argument in arguments) == (2, 2, 2)
    assert tuple(argument.variable.name for argument in arguments) == ("arg", "arg_6", "arg_8")
    assert arguments[:2] == (argc, argv)
    assert arguments[1].variable_type == argv.variable_type
    assert stale_byte.variable not in codegen.cfunc.variables_in_use
    assert tuple(codegen.cfunc.functy.arg_names or ()) == ("arg", "arg_6", "arg_8")

    restored = authoritative_function_prototype_8616(
        project,
        project.kb.functions.function(addr=0x10058, create=False),
        argument_count=3,
    )
    assert restored == codegen.cfunc.functy
    assert materialize_positive_bp_arguments_8616(project, codegen) is False
    assert tuple(argument.variable.name for argument in codegen.cfunc.arg_list) == (
        "arg",
        "arg_6",
        "arg_8",
    )


def test_positive_bp_plan_projects_synthetic_tail_to_entry_sp_coordinates() -> None:
    project, codegen, argc, _stale_byte, argv = _production_shape(
        complete_sources=True,
        projected=True,
    )

    assert materialize_positive_bp_arguments_8616(project, codegen) is True

    arguments = tuple(codegen.cfunc.arg_list)
    assert arguments[:2] == (argc, argv)
    assert tuple(argument.variable.offset for argument in arguments) == (2, 4, 6)
    assert tuple(
        machine_bp_offset_for_stack_variable_8616(codegen, argument.variable)
        for argument in arguments
    ) == (4, 6, 8)
    cloned_tail = SimStackVariable(6, 2, base="bp", name="arg_8", region=0x10058)
    assert machine_bp_offset_for_stack_variable_8616(codegen, cloned_tail) == 8


def test_projected_entry_sp_argument_drops_stale_coordinate_name() -> None:
    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
    )
    candidate = CVariable(
        SimStackVariable(2, 2, base="bp", name="ret_addr"),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )

    assert (
        _canonical_argument_name_8616(
            candidate,
            4,
            entry_sp_offset=2,
        )
        == "arg_4"
    )


def test_positive_bp_plan_refuses_incomplete_width_census_atomically() -> None:
    _project, codegen, argc, stale_byte, argv = _production_shape(complete_sources=False)
    before_args = tuple(codegen.cfunc.arg_list)
    before = tuple(
        (candidate.variable.size, candidate.variable.name, candidate.variable_type)
        for candidate in before_args
    )

    assert materialize_positive_bp_arguments_8616(codegen.project, codegen) is False

    assert tuple(codegen.cfunc.arg_list) == before_args
    assert tuple(
        (candidate.variable.size, candidate.variable.name, candidate.variable_type)
        for candidate in codegen.cfunc.arg_list
    ) == before
    assert tuple(codegen.cfunc.arg_list) == (argc, stale_byte, argv)
    stats = codegen._inertia_positive_bp_argument_stats_8616
    assert stats.materialized_count == 0
    assert stats.failure_count > 0


def test_body_partition_accepts_matching_incomplete_physical_caller_shape() -> None:
    summary = CallsiteSummary8616(
        callsite_addr=0x1010,
        target_addr=0x1000,
        return_addr=0x1013,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        push_arg_sources=(None, ("bp", -2, 2)),
    )
    count_evidence = CalleeArgumentCountEvidence8616(
        target_addr=0x1000,
        verdict=CalleeArgumentCountVerdict8616.UNKNOWN,
        raw_fact_count=1,
        normalized_fact_count=1,
        failure_count=1,
        callsite_addrs=(summary.callsite_addr,),
        callsite_summaries=(summary,),
    )
    evidence = CalleeArgumentWidthEvidence8616(
        target_addr=0x1000,
        verdict=CalleeArgumentWidthVerdict8616.UNKNOWN,
        raw_fact_count=1,
        failure_count=1,
        count_evidence=count_evidence,
    )
    word = SimTypeShort(False)
    entries = (
        PositiveBpArgumentPlanEntry8616(4, 2, "left", word),
        PositiveBpArgumentPlanEntry8616(6, 2, "right", word),
    )

    plan = complete_positive_bp_argument_plan_8616(
        entries,
        evidence,
        default_argument_type=word,
    )

    assert plan.decision is PositiveBpArgumentPlanDecision8616.BODY_CALLER_PHYSICAL
    assert plan.entries == entries


def test_body_word_access_plan_restores_contiguous_erased_tail() -> None:
    word = SimTypeShort(False)
    first = PositiveBpArgumentPlanEntry8616(4, 2, "left", word)

    completed = complete_positive_bp_body_word_access_plan_8616(
        (first,),
        (4, 6, 8),
        default_argument_type=word,
    )

    assert completed[0] is first
    assert tuple((entry.bp_offset, entry.width) for entry in completed) == (
        (4, 2),
        (6, 2),
        (8, 2),
    )
    assert tuple(entry.cvar for entry in completed) == (None, None, None)


def test_body_word_access_plan_refuses_to_bridge_binary_gap() -> None:
    word = SimTypeShort(False)

    completed = complete_positive_bp_body_word_access_plan_8616(
        (),
        (4, 8),
        default_argument_type=word,
    )

    assert tuple((entry.bp_offset, entry.width) for entry in completed) == ((4, 2),)


def test_body_word_access_plan_coalesces_widening_proven_adjacent_words() -> None:
    word = SimTypeShort(False)
    entries = tuple(
        PositiveBpArgumentPlanEntry8616(offset, 2, name, word)
        for offset, name in ((4, "left_low"), (6, "left_high"), (8, "right"))
    )

    completed = complete_positive_bp_body_word_access_plan_8616(
        entries,
        (4, 6, 8),
        default_argument_type=word,
        wide_access_offsets=(4,),
    )

    assert tuple((entry.bp_offset, entry.width) for entry in completed) == (
        (4, 4),
        (8, 2),
    )
    assert tuple(entry.name for entry in completed) == ("left_low", "right")


def test_positive_bp_pointer_class_join_preserves_existing_pointee() -> None:
    arch = Arch86_16()
    byte_pointer = near_pointer_type_8616(SimTypeChar(False).with_arch(arch), arch)
    word_pointer = near_pointer_type_8616(SimTypeShort(False).with_arch(arch), arch)
    entry = PositiveBpArgumentPlanEntry8616(
        bp_offset=4,
        width=2,
        name="dst",
        argument_type=word_pointer,
        cvar=object(),
    )

    assert isinstance(byte_pointer, SimTypePointer)
    assert _merge_existing_and_body_argument_type_8616(byte_pointer, entry) is byte_pointer
    assert _merge_existing_and_body_argument_type_8616(
        SimTypeShort(False).with_arch(arch),
        entry,
    ) is word_pointer
