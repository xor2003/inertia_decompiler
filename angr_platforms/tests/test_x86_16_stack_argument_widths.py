from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.annotations import ANNOTATION_KEY
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from angr_platforms.X86_16.lowering import stack_prototype_materialization as prototype_lowering
from angr_platforms.X86_16.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    CalleeArgumentCountVerdict8616,
)
from angr_platforms.X86_16.lowering.callee_argument_width_evidence import (
    CalleeArgumentWidthEvidence8616,
    CalleeArgumentWidthVerdict8616,
)
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    FunctionParameterWidthFact8616,
    materialize_annotated_stack_prototype_8616,
    reconcile_exact_stack_argument_prototype_8616,
)
from angr_platforms.X86_16.widening.stack_argument_widths import (
    StackWordArithmeticFact8616,
    StackWordRegisterRole8616,
    WideStackArgumentWidthEvidence8616,
    analyze_wide_stack_argument_widths_8616,
    project_logical_stack_argument_widths_8616,
)


def _fact(
    mnemonic: str,
    register: int | None,
    offset: int | None,
    *,
    compared_register: int | None = None,
    destination_role: StackWordRegisterRole8616 = StackWordRegisterRole8616.OTHER,
) -> StackWordArithmeticFact8616:
    return StackWordArithmeticFact8616(
        mnemonic=mnemonic,
        destination_register=register,
        source_bp_offset=offset,
        compared_register=compared_register,
        destination_role=destination_role,
    )


def _short_parameter_fixture() -> tuple[object, object, object]:
    arch = Arch86_16()
    short_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([short_type], short_type, arg_names=("wait",)).with_arch(arch)
    function = SimpleNamespace(prototype=prototype, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    wait_variable = SimStackVariable(4, 2, base="bp", name="wait", region=0x1000)
    wait = structured_c.CVariable(wait_variable, variable_type=short_type, codegen=c_codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[wait],
        functy=prototype,
        statements=None,
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, _inertia_callsite_summaries={})
    return project, codegen, function


def _closed_one_long_argument_evidence() -> CalleeArgumentWidthEvidence8616:
    count_evidence = CalleeArgumentCountEvidence8616(
        target_addr=0x1000,
        verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
        argument_count=1,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
    )
    storage = IRAddress(
        space=MemSpace.SS,
        base=("bp",),
        offset=4,
        size=4,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )
    return CalleeArgumentWidthEvidence8616(
        target_addr=0x1000,
        verdict=CalleeArgumentWidthVerdict8616.CONSISTENT,
        widths_by_offset=((4, 4),),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        argument_count=1,
        argument_storage=(storage,),
        count_evidence=count_evidence,
    )


def _surplus_long_parameter_fixture() -> tuple[object, object, object]:
    arch = Arch86_16()
    long_type = SimTypeLong(True).with_arch(arch)
    prototype = SimTypeFunction(
        [long_type, long_type],
        SimTypeShort(False).with_arch(arch),
        arg_names=("wait", "surplus"),
    ).with_arch(arch)
    function = SimpleNamespace(prototype=prototype, is_prototype_guessed=False)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    variables = (
        SimStackVariable(4, 4, base="bp", name="wait", region=0x1000),
        SimStackVariable(8, 4, base="bp", name="surplus", region=0x1000),
    )
    cvars = tuple(
        structured_c.CVariable(variable, variable_type=long_type, codegen=c_codegen)
        for variable in variables
    )
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=list(cvars),
        functy=prototype,
        statements=None,
        unified_local_vars={},
        variables_in_use=dict(zip(variables, cvars, strict=False)),
    )
    codegen = SimpleNamespace(cfunc=cfunc, _inertia_callsite_summaries={})
    return project, codegen, function


def test_carry_linked_adjacent_bp_words_prove_one_wide_parameter() -> None:
    evidence = analyze_wide_stack_argument_widths_8616(
        (
            (
                _fact("add", 1, 4),
                _fact("adc", 2, 6),
            ),
        )
    )

    assert evidence.raw_fact_count == 1
    assert evidence.normalized_fact_count == 1
    assert evidence.classified_offsets == (4,)
    assert evidence.terminal_return_offsets == ()
    assert evidence.failure_count == 0


def test_terminal_dx_ax_stack_passthrough_proves_one_wide_parameter() -> None:
    evidence = analyze_wide_stack_argument_widths_8616(
        (
            (
                _fact("mov", 1, 4, destination_role=StackWordRegisterRole8616.AX_LOW_RETURN),
                _fact("mov", 2, 6, destination_role=StackWordRegisterRole8616.DX_HIGH_RETURN),
                _fact("ret", None, None),
            ),
        )
    )

    assert evidence.classified_offsets == (4,)
    assert evidence.terminal_return_offsets == (4,)
    assert evidence.failure_count == 0


def test_terminal_dx_ax_stack_passthrough_refuses_later_low_word_write() -> None:
    evidence = analyze_wide_stack_argument_widths_8616(
        (
            (
                _fact("mov", 1, 4, destination_role=StackWordRegisterRole8616.AX_LOW_RETURN),
                _fact("mov", 2, 6, destination_role=StackWordRegisterRole8616.DX_HIGH_RETURN),
                _fact("add", 1, None, destination_role=StackWordRegisterRole8616.AX_LOW_RETURN),
                _fact("ret", None, None),
            ),
        )
    )

    assert evidence.classified_offsets == ()
    assert evidence.terminal_return_offsets == ()
    assert evidence.failure_count == 1


def test_carry_chain_proves_matching_loaded_wide_accumulator_and_source() -> None:
    evidence = analyze_wide_stack_argument_widths_8616(
        (
            (
                _fact("mov", 1, 4),
                _fact("mov", 2, 6),
                _fact("sub", 1, 8),
                _fact("sbb", 2, 10),
            ),
        )
    )

    assert evidence.raw_fact_count == 2
    assert evidence.normalized_fact_count == 2
    assert evidence.classified_offsets == (4, 8)
    assert evidence.failure_count == 0


def test_carry_chain_refuses_loaded_pair_with_mismatched_destination() -> None:
    evidence = analyze_wide_stack_argument_widths_8616(
        (
            (
                _fact("mov", 3, 4),
                _fact("mov", 2, 6),
                _fact("sub", 1, 8),
                _fact("sbb", 2, 10),
            ),
        )
    )

    assert evidence.classified_offsets == (8,)
    assert evidence.failure_count == 1


def test_high_word_compare_proves_both_adjacent_stack_pairs() -> None:
    evidence = analyze_wide_stack_argument_widths_8616(
        (
            (
                _fact("mov", 1, 4),
                _fact("mov", 2, 6),
                _fact("cmp", None, 10, compared_register=2),
                _fact("jle", None, None),
            ),
        )
    )

    assert evidence.raw_fact_count == 1
    assert evidence.normalized_fact_count == 1
    assert evidence.classified_offsets == (4, 8)
    assert evidence.failure_count == 0


def test_high_word_compare_refuses_mismatched_register_identity() -> None:
    evidence = analyze_wide_stack_argument_widths_8616(
        (
            (
                _fact("mov", 1, 4),
                _fact("mov", 2, 6),
                _fact("cmp", None, 10, compared_register=3),
            ),
        )
    )

    assert evidence.classified_offsets == ()
    assert evidence.failure_count == 1


def test_wide_stack_projection_joins_two_word_pushes_into_one_logical_argument() -> None:
    assert project_logical_stack_argument_widths_8616((2, 2), (4,)) == (4,)


def test_wide_stack_projection_preserves_source_order_around_wide_argument() -> None:
    assert project_logical_stack_argument_widths_8616((2, 2, 2), (6,)) == (2, 4)


@pytest.mark.parametrize(
    ("physical_widths", "wide_offsets"),
    (
        ((2,), (4,)),
        ((4,), (6,)),
        ((2, 2, 2), (4, 6)),
        ((1, 1, 2), (4,)),
    ),
)
def test_wide_stack_projection_refuses_incomplete_or_overlapping_proofs(
    physical_widths: tuple[int, ...],
    wide_offsets: tuple[int, ...],
) -> None:
    assert project_logical_stack_argument_widths_8616(physical_widths, wide_offsets) is None


def test_parameter_lowering_materializes_proven_wide_body_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen, function = _short_parameter_fixture()
    evidence = WideStackArgumentWidthEvidence8616(1, 1, (4,))
    monkeypatch.setattr(
        prototype_lowering,
        "collect_wide_stack_argument_width_evidence_8616",
        lambda _project, _function: evidence,
    )

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is True
    assert isinstance(codegen.cfunc.functy.args[0], SimTypeLong)
    assert isinstance(function.prototype.args[0], SimTypeLong)
    assert codegen.cfunc.arg_list[0].variable.size == 4
    assert codegen._inertia_function_parameter_width_facts_8616 == (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=4),
    )
    assert codegen._inertia_wide_stack_argument_width_evidence_8616.materialized_count == 1


def test_parameter_lowering_grows_storage_when_wide_type_is_already_correct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Make the physical owner cover every byte proven by body widening."""
    project, codegen, function = _short_parameter_fixture()
    wide_type = SimTypeLong(False).with_arch(project.arch)
    prototype = SimTypeFunction(
        [wide_type],
        SimTypeShort(False).with_arch(project.arch),
        arg_names=("wait",),
    ).with_arch(project.arch)
    function.prototype = prototype
    codegen.cfunc.functy = prototype
    codegen.cfunc.arg_list[0].variable_type = wide_type
    monkeypatch.setattr(
        prototype_lowering,
        "collect_wide_stack_argument_width_evidence_8616",
        lambda _project, _function: WideStackArgumentWidthEvidence8616(1, 1, (4,)),
    )

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.arg_list[0].variable.size == 4
    assert codegen._inertia_wide_stack_argument_width_evidence_8616.materialized_count == 1


def test_parameter_lowering_refuses_conflicting_body_and_callsite_widths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen, function = _short_parameter_fixture()
    codegen._inertia_callsite_summaries = {
        0x1020: SimpleNamespace(push_arg_sources=(("bp", 4),), arg_widths=(2,))
    }
    evidence = WideStackArgumentWidthEvidence8616(1, 1, (4,))
    monkeypatch.setattr(
        prototype_lowering,
        "collect_wide_stack_argument_width_evidence_8616",
        lambda _project, _function: evidence,
    )

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is False
    assert isinstance(codegen.cfunc.functy.args[0], SimTypeShort)
    assert isinstance(function.prototype.args[0], SimTypeShort)
    assert codegen.cfunc.arg_list[0].variable.size == 2
    assert codegen._inertia_stack_prototype_width_stats_8616.failure_count == 1


def test_parameter_lowering_prunes_surplus_argument_from_closed_incoming_layout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen, function = _surplus_long_parameter_fixture()
    monkeypatch.setattr(
        prototype_lowering,
        "collect_callee_argument_width_evidence_8616",
        lambda _project, _target: _closed_one_long_argument_evidence(),
    )
    monkeypatch.setattr(
        prototype_lowering,
        "collect_wide_stack_argument_width_evidence_8616",
        lambda _project, _function: WideStackArgumentWidthEvidence8616(1, 1, (4,)),
    )
    monkeypatch.setattr(
        prototype_lowering,
        "collect_bp_stack_access_widths_from_instructions_8616",
        lambda _project, _codegen: {4: 2, 6: 2},
    )

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.arg_list) == 1
    assert len(codegen.cfunc.functy.args) == 1
    assert len(function.prototype.args) == 1
    assert codegen.cfunc.arg_list[0].variable.offset == 4
    assert codegen._inertia_stack_prototype_width_stats_8616.failure_count == 0


def test_parameter_lowering_refuses_to_prune_accessed_surplus_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen, function = _surplus_long_parameter_fixture()
    monkeypatch.setattr(
        prototype_lowering,
        "collect_callee_argument_width_evidence_8616",
        lambda _project, _target: _closed_one_long_argument_evidence(),
    )
    monkeypatch.setattr(
        prototype_lowering,
        "collect_wide_stack_argument_width_evidence_8616",
        lambda _project, _function: WideStackArgumentWidthEvidence8616(1, 1, (4,)),
    )
    monkeypatch.setattr(
        prototype_lowering,
        "collect_bp_stack_access_widths_from_instructions_8616",
        lambda _project, _codegen: {4: 2, 6: 2, 8: 2},
    )

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is False
    assert len(codegen.cfunc.arg_list) == 2
    assert len(codegen.cfunc.functy.args) == 2
    assert len(function.prototype.args) == 2
    assert codegen._inertia_stack_prototype_width_stats_8616.failure_count == 1


def test_annotated_slots_ignore_overlapping_high_byte_argument_type() -> None:
    arch = Arch86_16()
    unsigned_word = SimTypeShort(False).with_arch(arch)
    signed_word = SimTypeShort(True).with_arch(arch)
    byte_type = SimTypeChar().with_arch(arch)
    stale_prototype = SimTypeFunction(
        [unsigned_word, byte_type, signed_word],
        unsigned_word,
        arg_names=("frequency", "arg_5", "duration"),
    ).with_arch(arch)
    function = SimpleNamespace(
        info={ANNOTATION_KEY: {"stack_vars": {4: "frequency", 6: "duration"}}},
        prototype=stale_prototype,
        is_prototype_guessed=True,
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    variables = (
        SimStackVariable(4, 2, base="bp", name="frequency", region=0x1000),
        SimStackVariable(5, 1, base="bp", name="arg_5", region=0x1000),
        SimStackVariable(6, 2, base="bp", name="duration", region=0x1000),
    )
    cvars = (
        structured_c.CVariable(variables[0], variable_type=unsigned_word, codegen=codegen),
        structured_c.CVariable(variables[1], variable_type=byte_type, codegen=codegen),
        structured_c.CVariable(variables[2], variable_type=signed_word, codegen=codegen),
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=list(cvars),
        functy=stale_prototype,
        statements=None,
        unified_local_vars={},
        variables_in_use=dict(zip(variables, cvars, strict=False)),
    )
    codegen._inertia_callsite_summaries = {}

    changed = materialize_annotated_stack_prototype_8616(project, codegen)

    assert changed is True
    assert [cvar.variable.offset for cvar in codegen.cfunc.arg_list] == [4, 6]
    assert isinstance(codegen.cfunc.functy.args[0], SimTypeShort)
    assert codegen.cfunc.functy.args[0].signed is False
    assert isinstance(codegen.cfunc.functy.args[1], SimTypeShort)
    assert codegen.cfunc.functy.args[1].signed is True


def test_annotated_slots_preserve_width_correct_prototype_signedness() -> None:
    arch = Arch86_16()
    signed_word = SimTypeShort(True).with_arch(arch)
    unsigned_word = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction(
        [signed_word, signed_word],
        signed_word,
        arg_names=("left", "right"),
    ).with_arch(arch)
    function = SimpleNamespace(
        info={ANNOTATION_KEY: {"stack_vars": {4: "left", 6: "right"}}},
        prototype=prototype,
        is_prototype_guessed=False,
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    variables = (
        SimStackVariable(4, 2, base="bp", name="left", region=0x1000),
        SimStackVariable(6, 2, base="bp", name="right", region=0x1000),
    )
    cvars = tuple(
        structured_c.CVariable(variable, variable_type=unsigned_word, codegen=codegen)
        for variable in variables
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=list(cvars),
        functy=prototype,
        unified_local_vars={},
        variables_in_use=dict(zip(variables, cvars, strict=False)),
    )

    codegen.cfunc.statements = None
    materialize_annotated_stack_prototype_8616(project, codegen)

    assert all(isinstance(arg_type, SimTypeShort) for arg_type in codegen.cfunc.functy.args)
    assert all(arg_type.signed is True for arg_type in codegen.cfunc.functy.args)


def test_shifted_header_keeps_char_value_width_separate_from_word_slot_spacing() -> None:
    arch = Arch86_16()
    char_type = SimTypeChar().with_arch(arch)
    prototype = SimTypeFunction(
        [char_type, char_type],
        char_type,
        arg_names=("left", "right"),
    ).with_arch(arch)
    function = SimpleNamespace(
        info={ANNOTATION_KEY: {"stack_vars": {4: "left", 6: "right"}}},
        prototype=prototype,
        is_prototype_guessed=False,
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    variables = (
        SimStackVariable(2, 1, base="bp", name="left", region=0x1000),
        SimStackVariable(4, 2, base="bp", name="right", region=0x1000),
    )
    cvars = tuple(
        structured_c.CVariable(variable, variable_type=char_type, codegen=codegen)
        for variable in variables
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=list(cvars),
        functy=prototype,
        unified_local_vars={},
        variables_in_use=dict(zip(variables, cvars, strict=False)),
    )
    codegen._inertia_callsite_summaries = {}

    codegen.cfunc.statements = None
    assert materialize_annotated_stack_prototype_8616(project, codegen) is True
    assert all(isinstance(arg_type, SimTypeChar) for arg_type in codegen.cfunc.functy.args)
    assert codegen._inertia_function_parameter_width_facts_8616 == (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=1),
        FunctionParameterWidthFact8616(stack_offset=6, width_bytes=1),
    )
