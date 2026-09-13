import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeInt, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.annotations import ANNOTATION_KEY, _source_function_pointer_local_types_8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    record_caller_return_use_evidence_8616,
)
from angr_platforms.X86_16.lowering.near_pointer_type import SimTypeNearPointer16_8616
from angr_platforms.X86_16.lowering.stack_argument_identity import (
    unify_positive_bp_argument_identity_8616,
)
from angr_platforms.X86_16.lowering.stack_lowering_from_facts import attach_cod_stack_alias_annotations_8616
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    FunctionParameterWidthFact8616,
    align_pointer_flags_to_stack_argument_widths_8616,
    materialize_annotated_stack_prototype_8616,
    reconcile_exact_stack_argument_prototype_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_alias_8616,
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.pipeline.contracts import assert_pipeline_contracts_8616

REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)

import contextlib

from angr_platforms.X86_16 import decompiler_postprocess as postprocess


class _FakePrototype:
    def __init__(self, args=None, returnty=None, *, arg_names=None, variadic=False):
        self.args = [SimTypeShort(False)] if args is None else list(args)
        self.returnty = SimTypeLong() if returnty is None else returnty
        self.arg_names = ("a0",) if arg_names is None else arg_names
        self.variadic = variadic

    def with_arch(self, _arch):
        with contextlib.suppress(Exception):
            self.returnty = self.returnty.with_arch(_arch)
        self.args = [arg.with_arch(_arch) if hasattr(arg, "with_arch") else arg for arg in self.args]
        return self


def test_source_function_pointer_local_type_is_not_collected_from_source_lines():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)

    local_types = _source_function_pointer_local_types_8616(
        project,
        (
            "int select_and_apply(int which, int value)",
            "{",
            "    int (*fn)(int);",
            "}",
        ),
    )

    assert local_types == {}


def test_positive_bp_arg_promotion_materializes_contained_high_byte_arg():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    word_var = SimStackVariable(4, 2, base="bp", name="frequency", region=0x1000)
    high_var = SimStackVariable(5, 1, base="bp", name="arg_5", region=0x1000)
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    word_cvar = structured_c.CVariable(word_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_cvar = structured_c.CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    call = structured_c.CFunctionCall(
        "outp",
        None,
        [
            structured_c.CConstant(66, SimTypeShort(False), codegen=codegen),
            high_cvar,
        ],
        codegen=codegen,
    )
    root = structured_c.CStatements([structured_c.CExpressionStatement(call, codegen=codegen)], codegen=codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={word_var: word_cvar, high_var: high_cvar},
        unified_local_vars={word_var: {(word_cvar, SimTypeShort(False))}, high_var: {(high_cvar, SimTypeShort(False))}},
        arg_list=[word_cvar, high_cvar],
        functy=None,
        prototype=None,
        statements=root,
    )
    codegen.cfunc = cfunc

    changed = postprocess._promote_positive_bp_stack_slots_to_args_8616(project, codegen)

    assert changed is True
    assert cfunc.arg_list == [word_cvar]
    assert tuple(cfunc.functy.arg_names) == ("frequency",)
    assert high_var not in cfunc.variables_in_use
    assert high_var not in cfunc.unified_local_vars
    projected = call.args[1]
    assert isinstance(projected, structured_c.CBinaryOp)
    assert projected.op == "Shr"
    assert projected.lhs is word_cvar
    assert getattr(projected.rhs, "value", None) == 8
    assert codegen._inertia_stack_arg_high_byte_projection_candidates_8616 == 1
    assert codegen._inertia_stack_arg_high_byte_projection_materialized_8616 == 1


def test_positive_bp_arg_promotion_keeps_high_byte_assignment_destination_without_projection_lane():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    word_var = SimStackVariable(4, 2, base="bp", name="frequency", region=0x1000)
    high_var = SimStackVariable(5, 1, base="bp", name="arg_5", region=0x1000)
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    word_cvar = structured_c.CVariable(word_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_cvar = structured_c.CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    assignment = structured_c.CAssignment(
        high_cvar,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = structured_c.CStatements([assignment], codegen=codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={word_var: word_cvar, high_var: high_cvar},
        unified_local_vars={word_var: {(word_cvar, SimTypeShort(False))}, high_var: {(high_cvar, SimTypeShort(False))}},
        arg_list=[word_cvar, high_cvar],
        functy=None,
        prototype=None,
        statements=root,
    )
    codegen.cfunc = cfunc

    changed = postprocess._promote_positive_bp_stack_slots_to_args_8616(project, codegen)

    assert changed is True
    assert cfunc.arg_list == [word_cvar, high_cvar]
    assert high_var in cfunc.variables_in_use
    assert high_var in cfunc.unified_local_vars
    assert not hasattr(codegen, "_inertia_stack_arg_high_byte_projection_lane_8616")
    assert_pipeline_contracts_8616(codegen)


def test_positive_bp_arg_promotion_prunes_stale_high_byte_formal_without_lane_failure():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    word_var = SimStackVariable(4, 2, base="bp", name="frequency", region=0x1000)
    high_var = SimStackVariable(5, 1, base="bp", name="arg_5", region=0x1000)
    duration_var = SimStackVariable(6, 2, base="bp", name="duration", region=0x1000)
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    word_cvar = structured_c.CVariable(word_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_cvar = structured_c.CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    duration_cvar = structured_c.CVariable(duration_var, variable_type=SimTypeShort(False), codegen=codegen)
    call = structured_c.CFunctionCall(
        "BeepDelay",
        None,
        [word_cvar, duration_cvar],
        codegen=codegen,
    )
    root = structured_c.CStatements([structured_c.CExpressionStatement(call, codegen=codegen)], codegen=codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={word_var: word_cvar, high_var: high_cvar, duration_var: duration_cvar},
        unified_local_vars={
            word_var: {(word_cvar, SimTypeShort(False))},
            high_var: {(high_cvar, SimTypeShort(False))},
            duration_var: {(duration_cvar, SimTypeShort(False))},
        },
        arg_list=[word_cvar, high_cvar, duration_cvar],
        functy=None,
        prototype=None,
        statements=root,
    )
    codegen.cfunc = cfunc

    changed = postprocess._promote_positive_bp_stack_slots_to_args_8616(project, codegen)

    assert changed is True
    assert cfunc.arg_list == [word_cvar, duration_cvar]
    assert high_var not in cfunc.variables_in_use
    assert high_var not in cfunc.unified_local_vars
    assert not hasattr(codegen, "_inertia_stack_arg_high_byte_projection_lane_8616")
    assert_pipeline_contracts_8616(codegen)


def test_pointer_arg_offset_map_uses_prototype_names_for_duplicate_arg_names():
    arch = Arch86_16()
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(arch)
    first_var = SimStackVariable(4, 2, base="bp", name="right", region=0x1000)
    second_var = SimStackVariable(6, 2, base="bp", name="right", region=0x1000)
    c_codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=arch),
        cstyle_null_cmp=False,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    first_cvar = structured_c.CVariable(first_var, variable_type=pointer_type, codegen=c_codegen)
    second_cvar = structured_c.CVariable(second_var, variable_type=pointer_type, codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            arg_list=[first_cvar, second_cvar],
            functy=SimTypeFunction(
                [pointer_type, pointer_type],
                SimTypeBottom(),
                arg_names=("left", "right"),
            ).with_arch(arch),
        )
    )

    offsets = postprocess._pointer_arg_offsets_for_codegen_8616(codegen)

    assert offsets == {4: first_cvar, 6: second_cvar}
    assert first_var.name == "left"
    assert second_var.name == "right"


def test_positive_bp_arg_promotion_uses_source_name_for_generic_arg_slot():
    arch = Arch86_16()
    arg_var = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000)
    func = SimpleNamespace(
        addr=0x1000,
        prototype=None,
        info={ANNOTATION_KEY: {"stack_vars": {4: {"name": "iTop"}}}},
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: func)),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    root = structured_c.CStatements([structured_c.CExpressionStatement(arg_cvar, codegen=codegen)], codegen=codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={arg_var: arg_cvar},
        unified_local_vars={arg_var: {(arg_cvar, SimTypeShort(False))}},
        arg_list=[],
        functy=None,
        prototype=None,
        statements=root,
    )
    codegen.cfunc = cfunc

    changed = postprocess._promote_positive_bp_stack_slots_to_args_8616(project, codegen)

    assert changed is True
    assert arg_var.name == "iTop"
    assert cfunc.arg_list == [arg_cvar]
    assert tuple(cfunc.functy.arg_names) == ("iTop",)


def test_stack_prototype_promotion_collapses_existing_contained_high_byte_arg():
    arch = Arch86_16()
    prototype = SimTypeFunction(
        [SimTypeShort(False).with_arch(arch), SimTypeShort(False).with_arch(arch)],
        SimTypeBottom().with_arch(arch),
        arg_names=("frequency", "duration"),
    ).with_arch(arch)
    func = SimpleNamespace(addr=0x1000, prototype=prototype, is_prototype_guessed=False)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    word_var = SimStackVariable(4, 2, base="bp", name="frequency", region=0x1000)
    high_var = SimStackVariable(5, 1, base="bp", name="arg_5", region=0x1000)
    duration_var = SimStackVariable(6, 2, base="bp", name="duration", region=0x1000)
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    word_cvar = structured_c.CVariable(word_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_cvar = structured_c.CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    duration_cvar = structured_c.CVariable(duration_var, variable_type=SimTypeShort(False), codegen=codegen)
    call = structured_c.CFunctionCall(
        "outp",
        None,
        [
            structured_c.CConstant(66, SimTypeShort(False), codegen=codegen),
            high_cvar,
        ],
        codegen=codegen,
    )
    root = structured_c.CStatements([structured_c.CExpressionStatement(call, codegen=codegen)], codegen=codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={word_var: word_cvar, high_var: high_cvar, duration_var: duration_cvar},
        unified_local_vars={
            word_var: {(word_cvar, SimTypeShort(False))},
            high_var: {(high_cvar, SimTypeShort(False))},
            duration_var: {(duration_cvar, SimTypeShort(False))},
        },
        arg_list=[word_cvar, high_cvar, duration_cvar],
        functy=prototype,
        prototype=prototype,
        statements=root,
    )
    codegen.cfunc = cfunc

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert cfunc.arg_list == [word_cvar, duration_cvar]
    assert high_var not in cfunc.variables_in_use
    assert high_var not in cfunc.unified_local_vars
    projected = call.args[1]
    assert isinstance(projected, structured_c.CBinaryOp)
    assert projected.op == "Shr"
    assert projected.lhs is word_cvar
    assert getattr(projected.rhs, "value", None) == 8


def test_positive_bp_arg_promotion_uses_body_reference_for_contained_high_byte_arg():
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    word_var = SimStackVariable(4, 2, base="bp", name="frequency", region=0x1000)
    high_var = SimStackVariable(5, 1, base="bp", name="arg_5", region=0x1000)
    duration_var = SimStackVariable(6, 2, base="bp", name="duration", region=0x1000)
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    word_cvar = structured_c.CVariable(word_var, variable_type=SimTypeShort(False), codegen=codegen)
    high_cvar = structured_c.CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    duration_cvar = structured_c.CVariable(duration_var, variable_type=SimTypeShort(False), codegen=codegen)
    call = structured_c.CFunctionCall(
        "outp",
        None,
        [
            structured_c.CConstant(66, SimTypeShort(False), codegen=codegen),
            high_cvar,
        ],
        codegen=codegen,
    )
    root = structured_c.CStatements([structured_c.CExpressionStatement(call, codegen=codegen)], codegen=codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={word_var: word_cvar, duration_var: duration_cvar},
        unified_local_vars={
            word_var: {(word_cvar, SimTypeShort(False))},
            duration_var: {(duration_cvar, SimTypeShort(False))},
        },
        arg_list=[word_cvar, duration_cvar],
        functy=None,
        prototype=None,
        statements=root,
    )
    codegen.cfunc = cfunc

    changed = postprocess._promote_positive_bp_stack_slots_to_args_8616(project, codegen)

    assert changed is True
    assert cfunc.arg_list == [word_cvar, duration_cvar]
    projected = call.args[1]
    assert isinstance(projected, structured_c.CBinaryOp)
    assert projected.op == "Shr"
    assert projected.lhs is word_cvar
    assert getattr(projected.rhs, "value", None) == 8


def test_prototype_stack_layout_uses_cod_offsets_for_near_function_pointer_args():
    arch = Arch86_16()
    fnptr_type = SimTypePointer(
        SimTypeFunction([SimTypeShort(False).with_arch(arch)], SimTypeShort(False).with_arch(arch))
    ).with_arch(arch)
    value_type = SimTypeShort(False).with_arch(arch)
    func = SimpleNamespace(addr=0x1000)
    project = SimpleNamespace(arch=arch)
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            variables_in_use={},
            unified_local_vars={},
            arg_list=[],
            functy=None,
        ),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    prototype = SimTypeFunction(
        [fnptr_type, value_type],
        SimTypeShort(False).with_arch(arch),
        arg_names=("fn", "value"),
    ).with_arch(arch)

    changed = postprocess._sync_arg_list_from_prototype_stack_layout_8616(
        project=project,
        codegen=codegen,
        func=func,
        prototype=prototype,
        arg_names=["fn", "value"],
        source_pointer_flags=(True, False),
        annotated_args=[(4, "fn"), (6, "value")],
    )

    assert changed is True
    assert [getattr(arg.variable, "offset", None) for arg in codegen.cfunc.arg_list] == [4, 6]
    assert [getattr(arg.variable, "size", None) for arg in codegen.cfunc.arg_list] == [2, 2]
    assert codegen.cfunc.functy is prototype


def test_prototype_stack_layout_reuses_body_stack_slot_missing_from_variable_map():
    arch = Arch86_16()
    arg_type = SimTypeShort(True).with_arch(arch)
    prototype = SimTypeFunction([arg_type], SimTypeShort(False).with_arch(arch), arg_names=("local",)).with_arch(arch)
    func = SimpleNamespace(addr=0x1000, prototype=prototype, is_prototype_guessed=False)
    project = SimpleNamespace(arch=arch)
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    body_var = SimStackVariable(4, 2, base="bp", name="local_4", region=0x1000)
    body_cvar = structured_c.CVariable(body_var, variable_type=arg_type, codegen=codegen)
    ret = structured_c.CReturn(body_cvar, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={},
        unified_local_vars={},
        arg_list=[],
        functy=prototype,
        prototype=prototype,
        statements=structured_c.CStatements([ret], codegen=codegen),
    )

    changed = postprocess._sync_arg_list_from_prototype_stack_layout_8616(
        project=project,
        codegen=codegen,
        func=func,
        prototype=prototype,
        arg_names=["local"],
        source_pointer_flags=(False,),
        annotated_args=[(4, "local")],
    )

    assert changed is True
    assert codegen.cfunc.arg_list == [body_cvar]
    assert ret.retval is body_cvar
    assert body_var.name == "local"
    assert codegen.cfunc.variables_in_use == {body_var: body_cvar}


def test_collect_stack_promotion_inputs_uses_structured_prototype_pointer_flags():
    func = SimpleNamespace(
        addr=0x1000,
        prototype=_FakePrototype(args=[SimTypeShort(False)], arg_names=("x",)),
        is_prototype_guessed=False,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {2: {"name": "x"}},
            }
        },
    )

    _annotations, source_pointer_flags, _stack_specs, annotated_args = postprocess._collect_stack_promotion_inputs_8616(
        func
    )

    assert source_pointer_flags == (False,)
    assert annotated_args == [(4, "x")]


def test_lowering_materializes_normalized_stack_annotation_prototype_before_postprocess():
    arch = Arch86_16()
    func = SimpleNamespace(
        addr=0x1000,
        name="inc_one",
        prototype=SimTypeFunction((), SimTypeShort(False).with_arch(arch)).with_arch(arch),
        is_prototype_guessed=True,
        info={ANNOTATION_KEY: {"stack_vars": {2: {"name": "value"}}}},
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    cfunc = SimpleNamespace(
        addr=0x1000,
        name="inc_one",
        variables_in_use={},
        unified_local_vars={},
        arg_list=[],
        functy=func.prototype,
        prototype=func.prototype,
        statements=structured_c.CStatements([], codegen=c_codegen),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cfunc=cfunc, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)

    changed = materialize_annotated_stack_prototype_8616(project, codegen)

    assert changed is True
    assert [getattr(arg.variable, "offset", None) for arg in cfunc.arg_list] == [4]
    assert [arg.name for arg in cfunc.arg_list] == ["value"]
    assert tuple(func.prototype.arg_names) == ("value",)
    assert len(func.prototype.args) == 1
    assert postprocess._apply_annotations_8616(project, codegen) is False


def test_lowering_joins_current_argument_surface_by_machine_bp_coordinate() -> None:
    """Preserve types when entry-SP variables project to shifted BP slots."""
    arch = Arch86_16()
    short_type = SimTypeShort(False).with_arch(arch)
    pointer_type = SimTypeNearPointer16_8616(short_type).with_arch(arch)
    generated_prototype = SimTypeFunction(
        (pointer_type, short_type), short_type, arg_names=("arg_4", "arg_6")
    ).with_arch(arch)
    func = SimpleNamespace(
        addr=0x1000,
        name="set_value",
        prototype=generated_prototype,
        is_prototype_guessed=True,
        info={ANNOTATION_KEY: {"stack_vars": {2: {"name": "dst"}, 4: {"name": "value"}}}},
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: func if addr == 0x1000 else None
            )
        ),
    )
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=project,
        cstyle_null_cmp=False,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
    )
    dst_var = SimStackVariable(2, 2, base="bp", name="arg_4", region=0x1000)
    dst_cvar = structured_c.CVariable(dst_var, variable_type=pointer_type, codegen=codegen)
    value_var = SimStackVariable(4, 2, base="bp", name="arg_6", region=0x1000)
    value_cvar = structured_c.CVariable(value_var, variable_type=short_type, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={dst_var: dst_cvar, value_var: value_cvar},
        unified_local_vars={},
        arg_list=[dst_cvar, value_cvar],
        functy=generated_prototype,
        prototype=generated_prototype,
        statements=structured_c.CStatements([], codegen=codegen),
    )
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=dst_var, cvar=dst_cvar, bp_offset=4, entry_sp_offset=2, size=2
    )
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=value_var, cvar=value_cvar, bp_offset=6, entry_sp_offset=4, size=2
    )

    changed = materialize_annotated_stack_prototype_8616(project, codegen)

    assert changed is True
    assert [argument.variable.name for argument in codegen.cfunc.arg_list] == ["dst", "value"]
    assert isinstance(codegen.cfunc.functy.args[0], SimTypeNearPointer16_8616)
    assert tuple(func.prototype.arg_names) == ("dst", "value")


def test_lowering_materializes_wide_argument_from_adjacent_annotation_starts() -> None:
    """Collapse physical word slots when structured BP starts prove one wide object."""
    arch = Arch86_16()
    short_type = SimTypeShort(False).with_arch(arch)
    pointer_type = SimTypeNearPointer16_8616(SimTypeShort(False)).with_arch(arch)
    physical_prototype = SimTypeFunction(
        [short_type, short_type, short_type, pointer_type, pointer_type],
        short_type,
        arg_names=("file", "cmdline", "cmdline_hi", "cs", "ss"),
    ).with_arch(arch)
    func = SimpleNamespace(
        addr=0x1000,
        name="load_program",
        prototype=physical_prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    2: {"name": "file"},
                    4: {"name": "cmdline"},
                    8: {"name": "cs"},
                    10: {"name": "ss"},
                }
            }
        },
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    physical_args = []
    variables_in_use = {}
    for offset, name, variable_type in zip(
        (4, 6, 8, 10, 12), physical_prototype.arg_names, physical_prototype.args, strict=False
    ):
        variable = SimStackVariable(offset, 2, base="bp", name=name, region=0x1000)
        cvar = structured_c.CVariable(variable, variable_type=variable_type, codegen=c_codegen)
        variables_in_use[variable] = cvar
        physical_args.append(cvar)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use=variables_in_use,
        unified_local_vars={},
        arg_list=physical_args,
        functy=physical_prototype,
        prototype=physical_prototype,
        statements=structured_c.CStatements([], codegen=c_codegen),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cfunc=cfunc, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)

    assert materialize_annotated_stack_prototype_8616(project, codegen)

    assert [arg.variable.offset for arg in cfunc.arg_list] == [4, 6, 10, 12]
    assert [arg.variable.size for arg in cfunc.arg_list] == [2, 4, 2, 2]
    assert isinstance(cfunc.functy.args[1], SimTypeLong)
    assert all(isinstance(cfunc.functy.args[index], SimTypeNearPointer16_8616) for index in (2, 3))
    assert codegen._inertia_function_parameter_width_facts_8616 == (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
        FunctionParameterWidthFact8616(stack_offset=6, width_bytes=4),
        FunctionParameterWidthFact8616(stack_offset=10, width_bytes=2),
        FunctionParameterWidthFact8616(stack_offset=12, width_bytes=2),
    )


def test_lowering_stack_prototype_preserves_explicit_void_return_type():
    arch = Arch86_16()
    void_type = SimTypeBottom(label="void").with_arch(arch)
    func = SimpleNamespace(
        addr=0x1000,
        name="draw",
        prototype=SimTypeFunction((), void_type).with_arch(arch),
        is_prototype_guessed=False,
        info={ANNOTATION_KEY: {"stack_vars": {2: {"name": "row"}}}},
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={},
        unified_local_vars={},
        arg_list=[],
        functy=func.prototype,
        prototype=func.prototype,
        statements=structured_c.CStatements([], codegen=c_codegen),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cfunc=cfunc, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)

    changed = materialize_annotated_stack_prototype_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeBottom)
    assert func.prototype.returnty.label == "void"
    assert isinstance(cfunc.functy.returnty, SimTypeBottom)
    assert cfunc.functy.returnty.label == "void"

    postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert isinstance(func.prototype.returnty, SimTypeBottom)
    assert func.prototype.returnty.label == "void"
    assert isinstance(cfunc.functy.returnty, SimTypeBottom)
    assert cfunc.functy.returnty.label == "void"


def test_lowering_explicit_annotated_zero_args_blocks_legacy_positive_bp_promotion():
    arch = Arch86_16()
    void_type = SimTypeBottom(label="void").with_arch(arch)
    annotated_prototype = SimTypeFunction((), void_type).with_arch(arch)
    guessed_prototype = SimTypeFunction((SimTypeShort(False),), void_type, arg_names=("arg_4",)).with_arch(arch)
    func = SimpleNamespace(
        addr=0x1000,
        name="no_args",
        prototype=guessed_prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "prototype": annotated_prototype,
                "stack_vars": {2: {"name": "stale_positive_bp_slot"}},
            }
        },
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    stale_var = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000)
    stale_cvar = structured_c.CVariable(stale_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={stale_var: stale_cvar},
        unified_local_vars={},
        arg_list=[stale_cvar],
        functy=guessed_prototype,
        prototype=guessed_prototype,
        statements=structured_c.CStatements([], codegen=c_codegen),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cfunc=cfunc, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)

    changed = materialize_annotated_stack_prototype_8616(project, codegen)

    assert changed is True
    assert cfunc.arg_list == []
    assert tuple(cfunc.functy.args or ()) == ()
    assert codegen._inertia_authoritative_zero_arg_prototype_8616 is True
    assert postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen) is False
    assert cfunc.arg_list == []


def test_lowering_explicit_zero_args_without_positive_stack_facts_blocks_legacy_promotion():
    arch = Arch86_16()
    void_type = SimTypeBottom(label="void").with_arch(arch)
    explicit_prototype = SimTypeFunction((), void_type).with_arch(arch)
    guessed_prototype = SimTypeFunction((SimTypeShort(False),), void_type, arg_names=("arg_4",)).with_arch(arch)
    func = SimpleNamespace(
        addr=0x1000,
        name="no_args",
        prototype=explicit_prototype,
        is_prototype_guessed=False,
        info={
            ANNOTATION_KEY: {
                "prototype": explicit_prototype,
                "stack_vars": {-2: {"name": "local_word"}},
            }
        },
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    stale_var = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000)
    stale_cvar = structured_c.CVariable(stale_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={stale_var: stale_cvar},
        unified_local_vars={},
        arg_list=[stale_cvar],
        functy=guessed_prototype,
        prototype=guessed_prototype,
        statements=structured_c.CStatements([], codegen=c_codegen),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cfunc=cfunc, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)

    changed = materialize_annotated_stack_prototype_8616(project, codegen)

    assert changed is True
    assert cfunc.arg_list == []
    assert tuple(cfunc.functy.args or ()) == ()
    assert codegen._inertia_authoritative_zero_arg_prototype_8616 is True
    assert postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen) is False


def test_lowering_materializes_wide_stack_argument_reads_and_retains_high_word_writes():
    arch = Arch86_16()
    wide_type = SimTypeLong(False).with_arch(arch)
    func = SimpleNamespace(
        addr=0x1000,
        name="sub_ulong",
        prototype=SimTypeFunction(
            [wide_type, wide_type],
            wide_type,
            arg_names=("a", "b"),
        ).with_arch(arch),
        is_prototype_guessed=True,
        info={ANNOTATION_KEY: {"stack_vars": {2: {"name": "a"}, 6: {"name": "b"}}}},
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    high_a = SimStackVariable(6, 2, base="bp", name="local_6", region=0x1000)
    high_b = SimStackVariable(10, 2, base="bp", name="local_a", region=0x1000)
    high_a_cvar = structured_c.CVariable(high_a, variable_type=SimTypeShort(False), codegen=c_codegen)
    high_b_cvar = structured_c.CVariable(high_b, variable_type=SimTypeShort(False), codegen=c_codegen)
    high_a_return = structured_c.CReturn(high_a_cvar, codegen=c_codegen)
    high_b_store = structured_c.CAssignment(
        high_b_cvar,
        structured_c.CConstant(7, SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    cfunc = SimpleNamespace(
        addr=0x1000,
        name="sub_ulong",
        variables_in_use={high_a: high_a_cvar, high_b: high_b_cvar},
        unified_local_vars={high_a: {(high_a_cvar, SimTypeShort(False))}, high_b: {(high_b_cvar, SimTypeShort(False))}},
        arg_list=[],
        functy=func.prototype,
        prototype=func.prototype,
        statements=structured_c.CStatements([high_a_return, high_b_store], codegen=c_codegen),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cfunc=cfunc, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)

    changed = materialize_annotated_stack_prototype_8616(project, codegen)

    assert changed is True
    assert [getattr(arg.variable, "offset", None) for arg in cfunc.arg_list] == [4, 8]
    assert [getattr(arg.variable, "size", None) for arg in cfunc.arg_list] == [4, 4]
    assert [arg.name for arg in cfunc.arg_list] == ["a", "b"]
    assert tuple(func.prototype.arg_names) == ("a", "b")
    assert tuple(func.prototype.args) == (wide_type, wide_type)
    assert high_a not in cfunc.variables_in_use
    assert high_b in cfunc.variables_in_use
    assert high_a not in cfunc.unified_local_vars
    assert high_b in cfunc.unified_local_vars
    assert isinstance(high_a_return.retval, structured_c.CBinaryOp)
    assert high_a_return.retval.op == "And"
    high_shift = high_a_return.retval.lhs
    assert isinstance(high_shift, structured_c.CBinaryOp)
    assert high_shift.op == "Shr"
    assert isinstance(high_shift.lhs, structured_c.CVariable)
    assert high_shift.lhs.variable is cfunc.arg_list[0].variable
    subview_result = codegen._inertia_wide_stack_argument_subview_result_8616
    assert (
        subview_result.raw_fact_count,
        subview_result.normalized_fact_count,
        subview_result.classified_fact_count,
        subview_result.materialized_count,
        subview_result.failure_count,
    ) == (2, 1, 1, 1, 1)


def test_lowering_constrains_guessed_wide_args_to_exact_independent_word_slots():
    arch = Arch86_16()
    guessed_wide = SimTypeLong(False).with_arch(arch)
    func = SimpleNamespace(
        addr=0x1000,
        name="select_and_apply",
        prototype=SimTypeFunction(
            [guessed_wide, guessed_wide],
            SimTypeShort(False),
            arg_names=("which", "value"),
        ).with_arch(arch),
        is_prototype_guessed=True,
        info={ANNOTATION_KEY: {"stack_vars": {2: {"name": "which"}, 4: {"name": "value"}}}},
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    which_var = SimStackVariable(2, 2, base="bp", name="arg_2", region=0x1000)
    value_var = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000)
    which_cvar = structured_c.CVariable(which_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    value_cvar = structured_c.CVariable(value_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        name="select_and_apply",
        variables_in_use={which_var: which_cvar, value_var: value_cvar},
        unified_local_vars={},
        arg_list=[which_cvar, value_cvar],
        functy=func.prototype,
        prototype=func.prototype,
        statements=structured_c.CStatements([], codegen=c_codegen),
    )
    codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, cfunc=cfunc, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)

    changed = materialize_annotated_stack_prototype_8616(project, codegen)

    assert changed is True
    assert [arg.variable.offset for arg in cfunc.arg_list] == [4, 6]
    assert [arg.variable.size for arg in cfunc.arg_list] == [2, 2]
    assert all(isinstance(arg_type, SimTypeShort) for arg_type in cfunc.functy.args)
    assert codegen._inertia_stack_prototype_width_stats_8616.raw_fact_count == 2
    assert codegen._inertia_stack_prototype_width_stats_8616.classified_fact_count == 2
    assert codegen._inertia_stack_prototype_width_stats_8616.materialized_count == 2
    assert codegen._inertia_stack_prototype_width_stats_8616.failure_count == 0
    assert codegen._inertia_function_parameter_width_facts_8616 == (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
        FunctionParameterWidthFact8616(stack_offset=6, width_bytes=2),
    )


def test_reconcile_exact_stack_argument_prototype_narrows_all_word_slots():
    arch = Arch86_16()
    guessed_wide = SimTypeLong(False).with_arch(arch)
    prototype = SimTypeFunction(
        [guessed_wide, guessed_wide],
        SimTypeShort(False),
        arg_names=("which", "value"),
    ).with_arch(arch)
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    which_var = SimStackVariable(4, 2, base="bp", name="which", region=0x1000)
    value_var = SimStackVariable(6, 4, base="bp", name="value", region=0x1000)
    which = structured_c.CVariable(which_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    value = structured_c.CVariable(value_var, variable_type=guessed_wide, codegen=c_codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[which, value],
        functy=prototype,
        prototype=prototype,
        unified_local_vars={}, statements=None,
    )
    codegen = SimpleNamespace(
        cfunc=cfunc,
        _inertia_callsite_summaries={
            0x1020: SimpleNamespace(
                push_arg_sources=(("bp", 4), ("bp", 6)),
                arg_widths=(2, 2),
            )
        },
    )

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is True
    assert all(isinstance(arg_type, SimTypeShort) for arg_type in cfunc.functy.args)
    assert all(isinstance(arg_type, SimTypeShort) for arg_type in func.prototype.args)
    assert isinstance(value.variable_type, SimTypeShort)
    assert [arg.variable.size for arg in cfunc.arg_list] == [2, 2]
    assert codegen._inertia_stack_prototype_width_stats_8616.materialized_count == 2
    assert codegen._inertia_function_parameter_width_facts_8616 == (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
        FunctionParameterWidthFact8616(stack_offset=6, width_bytes=2),
    )


def test_reconcile_aggregates_split_call_sources_covering_one_wide_stack_object() -> None:
    """Keep a wide argument when one call consumes both exact word slices."""
    arch = Arch86_16()
    short_type = SimTypeShort(False).with_arch(arch)
    wide_type = SimTypeLong(False).with_arch(arch)
    prototype = SimTypeFunction(
        [short_type, wide_type],
        short_type,
        arg_names=("file", "cmdline"),
    ).with_arch(arch)
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=False)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    file_var = SimStackVariable(4, 2, base="bp", name="file", region=0x1000)
    cmdline_var = SimStackVariable(6, 4, base="bp", name="cmdline", region=0x1000)
    file_arg = structured_c.CVariable(file_var, variable_type=short_type, codegen=c_codegen)
    cmdline_arg = structured_c.CVariable(cmdline_var, variable_type=short_type, codegen=c_codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[file_arg, cmdline_arg],
        functy=prototype,
        prototype=prototype,
        unified_local_vars={}, statements=None,
    )
    codegen = SimpleNamespace(
        cfunc=cfunc,
        _inertia_callsite_summaries={
            0x1020: SimpleNamespace(
                push_arg_sources=(("bp", 8), ("bp", 6), ("bp", 4)),
                arg_widths=(2, 2, 2),
            )
        },
    )

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is True
    assert isinstance(cfunc.functy.args[1], SimTypeLong)
    assert isinstance(cmdline_arg.variable_type, SimTypeLong)
    assert cmdline_arg.variable.size == 4
    assert codegen._inertia_function_parameter_width_facts_8616 == (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
        FunctionParameterWidthFact8616(stack_offset=6, width_bytes=4),
    )


def test_reconcile_uses_exact_near_pointer_parameter_slot_width() -> None:
    assert align_pointer_flags_to_stack_argument_widths_8616((False, False, False, True, True), (4, 6, 10, 12), {4: 2, 6: 4, 10: 2, 12: 2}) == (False, False, True, True)
    arch = Arch86_16()
    guessed_wide = SimTypeLong(False).with_arch(arch)
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(arch)
    prototype = SimTypeFunction(
        [guessed_wide, pointer_type],
        SimTypeShort(False),
        arg_names=("count", "values"),
    ).with_arch(arch)
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    count_var = SimStackVariable(4, 2, base="bp", name="count", region=0x1000)
    values_var = SimStackVariable(6, 2, base="bp", name="values", region=0x1000)
    count = structured_c.CVariable(count_var, variable_type=guessed_wide, codegen=c_codegen)
    values = structured_c.CVariable(values_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[count, values],
        functy=prototype,
        prototype=prototype,
        unified_local_vars={}, statements=None,
    )
    codegen = SimpleNamespace(
        cfunc=cfunc,
        _inertia_callsite_summaries={
            0x1020: SimpleNamespace(
                push_arg_sources=(("bp", 4), ("bp", 6)),
                arg_widths=(2, 4),
            )
        },
    )

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is True
    assert isinstance(cfunc.functy.args[0], SimTypeShort)
    assert isinstance(cfunc.functy.args[1], SimTypePointer)
    assert isinstance(values.variable_type, SimTypePointer) and values.variable.size == 2
    assert codegen._inertia_stack_prototype_width_stats_8616.failure_count == 0
    assert codegen._inertia_function_parameter_width_facts_8616 == (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
        FunctionParameterWidthFact8616(stack_offset=6, width_bytes=2),
    )


def test_reconcile_retains_exact_width_fact_when_prototype_is_already_correct() -> None:
    arch = Arch86_16()
    short_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([short_type], short_type, arg_names=("value",)).with_arch(arch)
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=False)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    value_var = SimStackVariable(4, 2, base="bp", name="value", region=0x1000)
    value = structured_c.CVariable(value_var, variable_type=short_type, codegen=c_codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[value],
        functy=prototype,
        unified_local_vars={}, statements=None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, _inertia_callsite_summaries={})

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is False
    assert codegen._inertia_function_parameter_width_facts_8616 == (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
    )
    assert codegen._inertia_stack_prototype_width_stats_8616.classified_fact_count == 1
    assert codegen._inertia_stack_prototype_width_stats_8616.materialized_count == 1


def test_reconcile_replaces_stale_zero_arg_function_metadata_from_exact_stack_args() -> None:
    arch = Arch86_16()
    short_type = SimTypeShort(False).with_arch(arch)
    codegen_prototype = SimTypeFunction(
        [short_type, short_type],
        SimTypeBottom(label="void"),
        arg_names=("left", "right"),
    ).with_arch(arch)
    stale_prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(arch)
    func = SimpleNamespace(prototype=stale_prototype, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    left_var = SimStackVariable(4, 2, base="bp", name="left", region=0x1000)
    right_var = SimStackVariable(6, 2, base="bp", name="right", region=0x1000)
    left = structured_c.CVariable(left_var, variable_type=short_type, codegen=c_codegen)
    right = structured_c.CVariable(right_var, variable_type=short_type, codegen=c_codegen)
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[left, right],
        functy=codegen_prototype,
        unified_local_vars={}, statements=None,
    )
    codegen = SimpleNamespace(cfunc=cfunc, _inertia_callsite_summaries={})

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is True
    assert len(func.prototype.args) == 2
    assert func.is_prototype_guessed is False
    assert codegen._inertia_stack_prototype_width_stats_8616.classified_fact_count == 2
    assert codegen._inertia_stack_prototype_width_stats_8616.materialized_count == 2
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True


def test_materialize_uses_abi_word_for_vex_wide_simtype_int() -> None:
    arch = Arch86_16()
    int_type = SimTypeInt(True).with_arch(arch)
    return_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction(
        [int_type],
        return_type,
        arg_names=("value",),
    ).with_arch(arch)
    func = SimpleNamespace(
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    2: {"name": "value"},
                },
            },
        },
        prototype=prototype,
        is_prototype_guessed=True,
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: func if addr == 0x1000 else None
            )
        ),
    )
    stack_var = SimStackVariable(
        4,
        4,
        base="bp",
        name="value",
        region=0x1000,
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    value = structured_c.CVariable(
        stack_var,
        variable_type=int_type,
        codegen=c_codegen,
    )
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[value],
        functy=prototype,
        variables_in_use={stack_var: value},
        unified_local_vars={}, statements=None,
    )
    codegen = SimpleNamespace(
        cfunc=cfunc,
        next_idx=lambda _name: 1,
        project=project,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)

    changed = materialize_annotated_stack_prototype_8616(project, codegen)

    assert changed is True
    assert isinstance(cfunc.functy.args[0], SimTypeInt)
    assert not isinstance(cfunc.functy.args[0], SimTypeLong)
    assert value.variable.size == 2
    assert codegen._inertia_function_parameter_width_facts_8616 == (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
    )


def test_materialize_preserves_exact_near_pointer_stack_slot_width() -> None:
    arch = Arch86_16()
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(arch)
    prototype = SimTypeFunction(
        [pointer_type],
        SimTypeShort(False),
        arg_names=("values",),
    ).with_arch(arch)
    func = SimpleNamespace(
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    2: {"name": "values"},
                },
            },
        },
        prototype=prototype,
        is_prototype_guessed=True,
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: func if addr == 0x1000 else None
            )
        ),
    )
    stack_var = SimStackVariable(4, 2, base="bp", name="values", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    values = structured_c.CVariable(
        stack_var,
        variable_type=pointer_type,
        codegen=c_codegen,
    )
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[values],
        functy=prototype,
        variables_in_use={stack_var: values},
        unified_local_vars={}, statements=None,
    )
    codegen = SimpleNamespace(
        cfunc=cfunc,
        next_idx=lambda _name: 1,
        project=project,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)

    changed = materialize_annotated_stack_prototype_8616(project, codegen)

    assert changed is False
    assert isinstance(cfunc.functy.args[0], SimTypePointer)
    assert values.variable.size == 2
    assert codegen._inertia_annotated_stack_prototype_materialized_8616 == 1
    assert postprocess._apply_annotations_8616(project, codegen) is False
    assert codegen._inertia_stack_prototype_width_stats_8616.failure_count == 0
    assert codegen._inertia_function_parameter_width_facts_8616 == (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
    )


def test_positive_stack_specs_normalization_prefers_arg_list_over_stale_bp2_slot():
    arch = Arch86_16()
    first_var = SimStackVariable(4, 2, base="bp", name="value", region=0x1000)
    second_var = SimStackVariable(6, 2, base="bp", name="limit", region=0x1000)
    stale_var = SimStackVariable(2, 2, base="bp", name="local_2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    first_cvar = structured_c.CVariable(first_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    second_cvar = structured_c.CVariable(second_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    stale_cvar = structured_c.CVariable(stale_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            arg_list=[first_cvar, second_cvar],
            variables_in_use={first_var: first_cvar, second_var: second_cvar, stale_var: stale_cvar},
        )
    )

    assert postprocess._positive_stack_specs_are_normalized_for_codegen_8616(
        {2: {"name": "value"}, 4: {"name": "limit"}},
        codegen,
    )


def test_bp_stack_prototype_promotion_rejects_mixed_stack_regions(monkeypatch):
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    project = SimpleNamespace(
        arch=SimpleNamespace(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(
                    prototype=_FakePrototype(),
                    is_prototype_guessed=True,
                )
            )
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(statements=[]),
            variables_in_use={
                SimStackVariable(4, 1, base="bp", name="a0", region=0x1000): SimpleNamespace(),
                SimStackVariable(6, 1, base="bp", name="a1", region=0x2000): SimpleNamespace(),
            },
        )
    )
    ret0 = structured_c.CReturn(SimpleNamespace(), codegen=c_codegen)
    ret1 = structured_c.CReturn(SimpleNamespace(), codegen=c_codegen)
    codegen.cfunc.statements.statements = [ret0, ret1]

    fake_nodes = [object(), object()]
    monkeypatch.setattr(postprocess, "_iter_c_nodes_deep_8616", lambda _retval: iter(fake_nodes))
    monkeypatch.setattr(
        postprocess, "_match_bp_stack_load_8616", lambda node, _project: 4 if node is fake_nodes[0] else 6
    )

    assert not postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)


def test_bp_stack_prototype_promotion_uses_annotated_stack_vars():
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False)],
            arg_names=("funcNumber",),
            returnty=SimTypeShort(False),
        ),
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "ovlLoadSegment"},
                    6: {"name": "funcNumber"},
                },
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=SimpleNamespace(statements=[]), variables_in_use={})
    )

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert len(func.prototype.args) == 2
    assert func.prototype.arg_names == ["ovlLoadSegment", "funcNumber"]


def test_bp_stack_prototype_promotion_preserves_pointer_evidence():
    stack_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False)],
            arg_names=("s",),
            returnty=SimTypeShort(False),
        ),
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "s"},
                },
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(
                statements=[
                    structured_c.CUnaryOp("Dereference", stack_cvar, codegen=c_codegen),
                ]
            ),
            variables_in_use={stack_var: stack_cvar},
        )
    )
    stack_cvar.codegen = codegen

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.args[0], SimTypePointer)
    assert "s *" in str(func.prototype.args[0]) or func.prototype.args[0].__class__.__name__ == "SimTypePointer"


def test_bp_stack_prototype_promotion_preserves_pointer_evidence_without_annotations():
    stack_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False)],
            arg_names=("s",),
            returnty=SimTypeShort(False),
        ),
        is_prototype_guessed=True,
        info={ANNOTATION_KEY: {}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(
                statements=[
                    structured_c.CUnaryOp("Dereference", stack_cvar, codegen=c_codegen),
                ]
            ),
            variables_in_use={stack_var: stack_cvar},
            arg_list=[stack_cvar],
            functy=func.prototype,
        )
    )
    stack_cvar.codegen = codegen

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.args[0], SimTypePointer)
    assert codegen.cfunc.functy is func.prototype
    assert codegen.cfunc.arg_list == [stack_cvar]


def test_bp_stack_prototype_promotion_respects_scalar_source_decl_over_weak_pointer_promotion():
    stack_var = SimStackVariable(6, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False), SimTypeShort(False)],
            arg_names=("iRow1", "iRow2"),
            returnty=SimTypeBottom(),
        ),
        is_prototype_guessed=False,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "iRow1"},
                    6: {"name": "iRow2"},
                },
                "source_lines": (
                    "void SwapBars(int iRow1, int iRow2)",
                    "{",
                    "}",
                ),
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(
                statements=[
                    structured_c.CUnaryOp("Dereference", stack_cvar, codegen=c_codegen),
                ]
            ),
            variables_in_use={stack_var: stack_cvar},
            arg_list=[None, stack_cvar],
            functy=func.prototype,
        ),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    stack_cvar.codegen = codegen

    postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert not isinstance(func.prototype.args[1], SimTypePointer)


def test_bp_stack_prototype_promotion_demotes_pointer_cvar_from_structured_scalar_arg():
    arch = Arch86_16()
    first_stack_var = SimStackVariable(4, 2, base="bp", name="iRow1", region=0x1000)
    stack_var = SimStackVariable(6, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    first_stack_cvar = structured_c.CVariable(
        first_stack_var,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    stack_cvar = structured_c.CVariable(
        stack_var,
        variable_type=SimTypePointer(SimTypeShort(False)).with_arch(arch),
        codegen=c_codegen,
    )
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False).with_arch(arch), SimTypeShort(False).with_arch(arch)],
            arg_names=("iRow1", "iRow2"),
            returnty=SimTypeBottom(),
        ),
        is_prototype_guessed=False,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "iRow1"},
                    6: {"name": "iRow2"},
                }
            }
        },
    )
    project = SimpleNamespace(
        arch=arch,
        _inertia_c_target="portable-flat",
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(statements=[]),
            variables_in_use={first_stack_var: first_stack_cvar, stack_var: stack_cvar},
            arg_list=[first_stack_cvar, stack_cvar],
            functy=func.prototype,
        ),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    first_stack_cvar.codegen = codegen
    stack_cvar.codegen = codegen

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert not isinstance(func.prototype.args[1], SimTypePointer)
    assert not isinstance(stack_cvar.variable_type, SimTypePointer)


def test_annotation_arg_sync_demotes_pointer_from_structured_scalar_arg():
    arch = Arch86_16()
    first_stack_var = SimStackVariable(4, 2, base="bp", name="iRow1", region=0x1000)
    second_stack_var = SimStackVariable(6, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    first_stack_cvar = structured_c.CVariable(
        first_stack_var,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    second_stack_cvar = structured_c.CVariable(
        second_stack_var,
        variable_type=SimTypePointer(SimTypeShort(False)).with_arch(arch),
        codegen=c_codegen,
    )
    func = SimpleNamespace(
        addr=0x1000,
        prototype=_FakePrototype(
            args=[SimTypeShort(False).with_arch(arch), SimTypeShort(False).with_arch(arch)],
            arg_names=("iRow1", "iRow2"),
            returnty=SimTypeBottom(),
        ),
        is_prototype_guessed=False,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    2: {"name": "iRow1"},
                    4: {"name": "iRow2"},
                }
            }
        },
    )
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch, _inertia_c_target="portable-flat"),
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=func.prototype,
            arg_list=[first_stack_cvar, second_stack_cvar],
        ),
    )
    first_stack_cvar.codegen = codegen
    second_stack_cvar.codegen = codegen

    changed = postprocess._sync_arg_list_from_annotations_8616(
        codegen=codegen,
        func=func,
        stack_specs=func.info[ANNOTATION_KEY]["stack_vars"],
        resolve_stack_cvar=lambda offset: {4: first_stack_cvar, 6: second_stack_cvar}.get(offset),
        promote_near_pointers=False,
    )

    assert changed is True
    assert not isinstance(codegen.cfunc.functy.args[1], SimTypePointer)
    assert not isinstance(second_stack_cvar.variable_type, SimTypePointer)


def test_annotation_arg_sync_ignores_project_cod_source_flags_without_structured_scalar_prototype():
    arch = Arch86_16()
    first_stack_var = SimStackVariable(2, 2, base="bp", name="iRow1", region=0x1000)
    second_stack_var = SimStackVariable(4, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    first_stack_cvar = structured_c.CVariable(
        first_stack_var,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    second_stack_cvar = structured_c.CVariable(
        second_stack_var,
        variable_type=SimTypePointer(SimTypeShort(False)).with_arch(arch),
        codegen=c_codegen,
    )
    func = SimpleNamespace(
        addr=0x1000,
        prototype=_FakePrototype(
            args=[SimTypeShort(False).with_arch(arch), SimTypePointer(SimTypeShort(False)).with_arch(arch)],
            arg_names=("iRow1", "iRow2"),
            returnty=SimTypeBottom(),
        ),
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {2: {"name": "iRow1"}, 4: {"name": "iRow2"}},
                "source_lines": (),
            }
        },
    )
    codegen = SimpleNamespace(
        project=SimpleNamespace(
            arch=arch,
            _inertia_c_target="portable-flat",
            _inertia_cod_metadata_by_func_addr_8616={
                0x1000: SimpleNamespace(source_lines=("void SwapBars( int iRow1, int iRow2 )", "{", "}"))
            },
        ),
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=func.prototype,
            arg_list=[first_stack_cvar, second_stack_cvar],
        ),
    )
    first_stack_cvar.codegen = codegen
    second_stack_cvar.codegen = codegen

    changed = postprocess._sync_arg_list_from_annotations_8616(
        codegen=codegen,
        func=func,
        stack_specs=func.info[ANNOTATION_KEY]["stack_vars"],
        resolve_stack_cvar=lambda offset: {2: first_stack_cvar, 4: second_stack_cvar}.get(offset),
        promote_near_pointers=False,
    )

    assert changed is False
    assert isinstance(codegen.cfunc.functy.args[1], SimTypePointer)
    assert isinstance(second_stack_cvar.variable_type, SimTypePointer)


def test_fallback_arg_promotion_demotes_pointer_from_project_cod_scalar_flags():
    arch = Arch86_16()
    first_stack_var = SimStackVariable(2, 2, base="bp", name="iRow1", region=0x1000)
    second_stack_var = SimStackVariable(4, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    first_stack_cvar = structured_c.CVariable(
        first_stack_var,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    second_stack_cvar = structured_c.CVariable(
        second_stack_var,
        variable_type=SimTypePointer(SimTypeShort(False)).with_arch(arch),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(
        args=[SimTypeShort(False).with_arch(arch), SimTypePointer(SimTypeShort(False)).with_arch(arch)],
        arg_names=("iRow1", "iRow2"),
        returnty=SimTypeBottom(),
    )
    func = SimpleNamespace(addr=0x1000, prototype=prototype)
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch, _inertia_c_target="portable-flat"),
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=prototype,
            arg_list=[first_stack_cvar, second_stack_cvar],
            statements=SimpleNamespace(statements=[]),
        ),
    )
    first_stack_cvar.codegen = codegen
    second_stack_cvar.codegen = codegen

    changed = postprocess._promote_from_fallback_args_8616(
        project=codegen.project,
        codegen=codegen,
        func=func,
        current_proto=prototype,
        existing_args=[first_stack_cvar, second_stack_cvar],
        source_pointer_flags=(False, False),
        promote_near_pointers=False,
    )

    assert changed is True
    assert not isinstance(codegen.cfunc.functy.args[1], SimTypePointer)
    assert not isinstance(second_stack_cvar.variable_type, SimTypePointer)


def test_apply_annotations_uses_structured_prototype_for_active_function():
    arch = Arch86_16()
    func = SimpleNamespace(
        addr=0x1000,
        name="SwapBars",
        prototype=SimTypeFunction(
            [SimTypeShort(True).with_arch(arch), SimTypeShort(True).with_arch(arch)],
            SimTypeBottom(label="void"),
            arg_names=("iRow1", "iRow2"),
        ).with_arch(arch),
        is_prototype_guessed=False,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    2: {"name": "iRow1"},
                    4: {"name": "iRow2"},
                },
            }
        },
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    first_stack_cvar = structured_c.CVariable(
        SimStackVariable(2, 2, base="bp", name="iRow1", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    second_stack_cvar = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow2", region=0x1000),
        variable_type=SimTypePointer(SimTypeShort(False)).with_arch(arch),
        codegen=c_codegen,
    )
    duplicate_second_cvar = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_6", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    body_call = structured_c.CFunctionCall("DrawBar", None, [duplicate_second_cvar], codegen=c_codegen)

    class _Functions:
        def function(self, *, addr, create=False):
            assert addr == 0x1000
            return func

    project = SimpleNamespace(
        arch=arch,
        _inertia_c_target="portable-flat",
        _inertia_cod_metadata_by_func_addr_8616={},
        kb=SimpleNamespace(functions=_Functions()),
    )
    codegen = SimpleNamespace(
        project=project,
        _function=SimpleNamespace(prototype=None, is_prototype_guessed=True),
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=None,
            arg_list=[first_stack_cvar, second_stack_cvar],
            statements=structured_c.CStatements(
                [structured_c.CExpressionStatement(body_call, codegen=c_codegen)],
                codegen=c_codegen,
            ),
            variables_in_use={
                first_stack_cvar.variable: first_stack_cvar,
                second_stack_cvar.variable: second_stack_cvar,
                duplicate_second_cvar.variable: duplicate_second_cvar,
            },
        ),
    )
    first_stack_cvar.codegen = codegen
    second_stack_cvar.codegen = codegen
    duplicate_second_cvar.codegen = codegen
    body_call.codegen = codegen

    changed = postprocess._apply_annotations_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeBottom)
    assert not any(isinstance(arg, SimTypePointer) for arg in func.prototype.args)
    assert not isinstance(second_stack_cvar.variable_type, SimTypePointer)
    assert codegen.cfunc.functy is func.prototype
    assert codegen._function.prototype is func.prototype
    assert codegen._function.is_prototype_guessed is False
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True
    assert codegen._inertia_codegen_prototype_sync_count_8616 >= 1
    arg_var = getattr(body_call.args[0], "variable", None)
    assert isinstance(arg_var, SimStackVariable)
    assert getattr(arg_var, "offset", None) == getattr(second_stack_cvar.variable, "offset", None)
    assert getattr(arg_var, "name", None) == "iRow2"


def test_annotation_rewrites_do_not_alias_next_argument_to_shifted_placeholder_name():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=arch),
        cstyle_null_cmp=False,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    word = SimTypeShort(False).with_arch(arch)
    which = structured_c.CVariable(
        SimStackVariable(2, 2, base="bp", name="which", region=0x1000),
        variable_type=word,
        codegen=c_codegen,
    )
    value = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="value", region=0x1000),
        variable_type=word,
        codegen=c_codegen,
    )
    placeholder = structured_c.CVariable(
        SimStackVariable(2, 2, base="bp", name="arg_6", region=0x1000),
        variable_type=word,
        codegen=c_codegen,
    )
    condition = structured_c.CBinaryOp(
        "CmpNE",
        placeholder,
        structured_c.CConstant(0, word, codegen=c_codegen),
        codegen=c_codegen,
    )
    if_stmt = structured_c.CIfElse(
        [(condition, structured_c.CStatements([], codegen=c_codegen))],
        None,
        codegen=c_codegen,
    )
    statements = structured_c.CStatements([if_stmt], codegen=c_codegen)
    cfunc = SimpleNamespace(
        arg_list=[which, value],
        statements=statements,
        variables_in_use={
            which.variable: which,
            value.variable: value,
            placeholder.variable: placeholder,
        },
    )
    codegen = SimpleNamespace(cfunc=cfunc)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=which.variable,
        cvar=which,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=value.variable,
        cvar=value,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )
    record_stack_variable_coordinate_alias_8616(
        codegen,
        bp_offset=4,
        size=2,
        variable=placeholder.variable,
    )

    changed = postprocess._apply_annotation_rewrites_8616(
        project=SimpleNamespace(arch=arch),
        codegen=codegen,
        stack_vars_by_offset={4: which, 6: value},
        global_spec_for=lambda _addr: (None, None),
        resolve_stack_cvar=lambda offset: {4: which, 6: value}.get(offset),
        materialize_stack_cvar=lambda _offset, _type: None,
        stack_candidate_score=lambda _variable, _cvar, *, exact: (int(exact), 0, 0, 0, 0),
    )

    assert changed is True
    rewritten_condition = if_stmt.condition_and_nodes[0][0]
    assert rewritten_condition.lhs.variable.offset == 2
    assert rewritten_condition.lhs.variable.name == "which"


def test_argument_identity_refuses_unproven_shifted_header_arg():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    stale_arg_cvar = structured_c.CVariable(
        SimStackVariable(2, 2, base="bp", name="local", region=0x1000),
        variable_type=SimTypeShort(True).with_arch(arch),
        codegen=c_codegen,
    )
    body_arg_cvar = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000),
        variable_type=SimTypeShort(True).with_arch(arch),
        codegen=c_codegen,
    )
    ret = structured_c.CReturn(body_arg_cvar, codegen=c_codegen)
    cfunc = SimpleNamespace(
        arg_list=[stale_arg_cvar],
        statements=structured_c.CStatements([ret], codegen=c_codegen),
        variables_in_use={
            stale_arg_cvar.variable: stale_arg_cvar,
            body_arg_cvar.variable: body_arg_cvar,
        },
        unified_local_vars={
            body_arg_cvar.variable: {(body_arg_cvar, body_arg_cvar.variable_type)},
        },
    )
    codegen = SimpleNamespace(cfunc=cfunc)

    changed = unify_positive_bp_argument_identity_8616(codegen)

    assert changed is False
    assert cfunc.arg_list == [stale_arg_cvar]
    assert ret.retval is body_arg_cvar
    assert body_arg_cvar.variable in cfunc.variables_in_use
    assert body_arg_cvar.variable in cfunc.unified_local_vars
    assert not hasattr(codegen, "_inertia_codegen_decl_refresh_required_8616")


def test_argument_identity_refuses_selector_return_contract():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    arg_cvar = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="iRow2", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    duplicate_cvar = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_6", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    call = structured_c.CFunctionCall("DrawBar", None, [duplicate_cvar], codegen=c_codegen)
    cfunc = SimpleNamespace(
        arg_list=[arg_cvar],
        statements=structured_c.CStatements(
            [structured_c.CExpressionStatement(call, codegen=c_codegen)],
            codegen=c_codegen,
        ),
        variables_in_use={
            arg_cvar.variable: arg_cvar,
            duplicate_cvar.variable: duplicate_cvar,
        },
        unified_local_vars={
            duplicate_cvar.variable: {(duplicate_cvar, duplicate_cvar.variable_type)},
        },
    )
    codegen = SimpleNamespace(cfunc=cfunc, _inertia_return_selector_materialized_8616=True)

    changed = unify_positive_bp_argument_identity_8616(codegen)

    assert changed is False
    assert call.args[0] is duplicate_cvar
    assert duplicate_cvar.variable in cfunc.variables_in_use
    assert duplicate_cvar.variable in cfunc.unified_local_vars
    assert not hasattr(codegen, "_inertia_codegen_decl_refresh_required_8616")


def test_metadata_lookup_does_not_merge_rebased_source_body_annotations():
    active = SimpleNamespace(
        addr=0x1000,
        prototype=None,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {2: {"name": "iRow1"}},
                "global_vars": {},
                "source_lines": (),
                "source_return_lines": (),
            }
        },
    )
    rebased = SimpleNamespace(
        addr=0x10768,
        prototype=None,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {},
                "global_vars": {},
                "source_lines": ("void SwapBars( int iRow1, int iRow2 )", "{", "}"),
                "source_return_lines": (),
            }
        },
    )

    class _Functions:
        def function(self, *, addr, create=False):
            assert create is False
            return {0x1000: active, 0x10768: rebased}.get(addr)

    project = SimpleNamespace(
        _inertia_original_linear_delta=0xF768,
        kb=SimpleNamespace(functions=_Functions()),
    )

    selected = postprocess._metadata_function_for_codegen_addr_8616(project, 0x1000)

    assert selected is active
    assert active.info[ANNOTATION_KEY]["source_lines"] == ()


def test_lowering_attaches_cod_stack_aliases_as_normalized_stack_specs():
    active = SimpleNamespace(
        addr=0x1000,
        prototype=None,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {2: {"name": "iRow1"}},
                "global_vars": {},
                "source_lines": (),
                "source_return_lines": (),
            }
        },
    )

    class _Functions:
        def function(self, *, addr, create=False):
            return active if addr == 0x1000 else None

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=_Functions()),
    )

    changed = attach_cod_stack_alias_annotations_8616(
        project,
        0x1000,
        SimpleNamespace(stack_aliases={-4: "i", 4: "iRow1", 6: "iRow2"}),
    )

    assert changed is True
    assert active.info[ANNOTATION_KEY]["stack_vars"] == {
        -4: {"name": "i"},
        2: {"name": "iRow1"},
        4: {"name": "iRow2"},
    }


def test_bp_stack_prototype_promotion_shrinks_overguessed_stack_arguments():
    prototype = _FakePrototype(
        args=[SimTypeShort(False), SimTypeShort(False)],
        arg_names=("s", "a1"),
        returnty=SimTypeShort(False),
    )
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "s"},
                },
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(statements=[]),
            variables_in_use={},
            arg_list=["first", "second"],
            functy=prototype,
        )
    )

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert len(func.prototype.args) == 1
    assert func.prototype.arg_names == ["s"]
    assert codegen.cfunc.arg_list == ["first"]
    assert codegen.cfunc.functy is func.prototype


def test_bp_stack_prototype_promotion_counts_only_real_stack_arguments():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeShort(False))
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=SimpleNamespace(statements=[]), variables_in_use={})
    )
    ret = structured_c.CReturn(SimpleNamespace(), codegen=c_codegen)
    codegen.cfunc.statements.statements = [ret]
    fake_node = object()

    def fake_iter(_retval):
        return iter([fake_node])

    original_iter = postprocess._iter_c_nodes_deep_8616
    original_match = postprocess._match_bp_stack_load_8616
    try:
        postprocess._iter_c_nodes_deep_8616 = fake_iter
        postprocess._match_bp_stack_load_8616 = lambda node, _project: 4 if node is fake_node else None

        changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)
    finally:
        postprocess._iter_c_nodes_deep_8616 = original_iter
        postprocess._match_bp_stack_load_8616 = original_match

    assert changed is False
    assert len(func.prototype.args) == 0
    assert func.prototype.arg_names == ()


def test_bp_stack_return_address_pruning_keeps_annotated_arguments():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    arg_var = SimStackVariable(2, 2, base="bp", name="segment", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    prototype = _FakePrototype(args=[SimTypeShort(False)], arg_names=("segment",), returnty=SimTypeShort(False))
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={ANNOTATION_KEY: {"stack_vars": {2: {"name": "segment"}}}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000, arg_list=[arg_cvar], statements=structured_c.CStatements([], codegen=c_codegen)
        )
    )

    changed = postprocess._prune_return_address_stack_arguments_8616(project, codegen)

    assert changed is False
    assert codegen.cfunc.arg_list == [arg_cvar]
    assert func.prototype.arg_names == ("segment",)


def test_bp_stack_return_address_pruning_drops_body_assignment_artifact():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    retaddr_var = SimStackVariable(0, 2, base="bp", name="local_0", region=0x1000)
    retaddr_cvar = structured_c.CVariable(retaddr_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    rhs = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="fn", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=c_codegen,
    )
    artifact = structured_c.CAssignment(retaddr_cvar, rhs, codegen=c_codegen)
    ret = structured_c.CReturn(
        structured_c.CConstant(0, SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    func = SimpleNamespace(prototype=None, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    statements = structured_c.CStatements([artifact, ret], codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            arg_list=[],
            statements=statements,
            body=statements,
            variables_in_use={retaddr_var: retaddr_cvar},
        )
    )

    changed = postprocess._prune_return_address_stack_arguments_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements == [ret]
    assert retaddr_var not in codegen.cfunc.variables_in_use


def test_bp_stack_return_address_pruning_walks_cstatements_root_without_body_alias():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    retaddr_var = SimStackVariable(0, 2, base="bp", name="local_0", region=0x1000)
    retaddr_cvar = structured_c.CVariable(retaddr_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    rhs = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="fn", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=c_codegen,
    )
    artifact = structured_c.CAssignment(retaddr_cvar, rhs, codegen=c_codegen)
    ret = structured_c.CReturn(
        structured_c.CConstant(0, SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    func = SimpleNamespace(prototype=None, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    statements = structured_c.CStatements([artifact, ret], codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            arg_list=[],
            statements=statements,
            variables_in_use={retaddr_var: retaddr_cvar},
        )
    )

    changed = postprocess._prune_return_address_stack_arguments_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.statements is statements
    assert codegen.cfunc.statements.statements == [ret]
    assert retaddr_var not in codegen.cfunc.variables_in_use


def test_bp_stack_return_address_pruning_refuses_selector_return_contract():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    arg_var = SimStackVariable(6, 2, base="bp", name="limit", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    codegen = SimpleNamespace(
        _inertia_return_selector_materialized_8616=True,
        cfunc=SimpleNamespace(
            addr=0x1000,
            arg_list=[arg_cvar],
            statements=structured_c.CStatements([], codegen=c_codegen),
        ),
    )

    changed = postprocess._prune_return_address_stack_arguments_8616(SimpleNamespace(arch=Arch86_16()), codegen)

    assert changed is False
    assert codegen.cfunc.arg_list == [arg_cvar]
    assert codegen._inertia_retaddr_prune_refused_selector_return_8616 == 1


def test_classify_return_shape_promotes_scalar_returns_from_void_prototypes(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_RETURN_SHAPE_CLASSIFY", "1")
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    ret = structured_c.CReturn(
        structured_c.CConstant(0, SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(returnty=SimTypeBottom())
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([ret], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeShort)
    assert func.prototype.returnty.size == 16


def test_return_shape_classification_preserves_provisional_codegen_arguments(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_RETURN_SHAPE_CLASSIFY", "1")
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    authoritative = SimTypeFunction(
        [word_type, word_type],
        SimTypeBottom(),
        arg_names=("first", "second"),
    ).with_arch(arch)
    provisional = SimTypeFunction(
        [word_type, word_type, word_type],
        SimTypeBottom(),
        arg_names=("first", "contained", "second"),
    ).with_arch(arch)
    func = SimpleNamespace(
        addr=0x1000,
        prototype=authoritative,
        is_prototype_guessed=True,
        info={},
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: func if addr == 0x1000 else None
            )
        ),
    )
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
    )
    arguments = [
        structured_c.CVariable(
            SimStackVariable(offset, 2, base="bp", region=0x1000),
            variable_type=word_type,
            codegen=codegen,
        )
        for offset in (4, 5, 6)
    ]
    ret = structured_c.CReturn(
        structured_c.CConstant(0, word_type, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=arguments,
        functy=provisional,
        prototype=provisional,
        statements=structured_c.CStatements([ret], codegen=codegen),
    )

    assert postprocess._classify_return_shape_8616(project, codegen) is True
    assert tuple(codegen.cfunc.arg_list) == tuple(arguments)
    assert len(codegen.cfunc.functy.args) == 3
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeShort)
    assert len(func.prototype.args) == 2
    assert isinstance(func.prototype.returnty, SimTypeShort)


def test_classify_return_shape_does_not_treat_unused_callers_as_void():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    ret = structured_c.CReturn(
        structured_c.CConstant(0, SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(Arch86_16())
    evidence = CallerReturnUseEvidence8616(
        target_addr=0x1000,
        verdict=CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=2,
        callsite_addrs=(0x2000, 0x2100),
    )
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={},
        addr=0x1000,
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=prototype,
            statements=structured_c.CStatements([ret], codegen=c_codegen),
        ),
        _inertia_current_function_8616=func,
    )
    record_caller_return_use_evidence_8616(project, 0x1000, evidence)

    classified = postprocess._classify_return_shape_8616(project, codegen)
    pruned = postprocess._prune_void_function_return_values_8616(project, codegen)

    assert classified is False
    assert pruned is False
    assert isinstance(func.prototype.returnty, SimTypeShort)
    assert ret.retval is not None


def test_classify_return_shape_ignores_source_return_lines_when_returns_are_missing(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_RETURN_SHAPE_CLASSIFY", "1")
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    prototype = _FakePrototype(returnty=SimTypeBottom())
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "source_return_lines": ("return MK_FP(sreg.es, rout.x.bx);",),
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is False
    assert func.prototype.returnty is prototype.returnty


def test_classify_return_shape_is_idempotent_for_structured_void_prototype_when_returns_are_missing(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_RETURN_SHAPE_CLASSIFY", "1")
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeBottom(label="void"))
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=False,
        info={ANNOTATION_KEY: {"source_return_lines": ()}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is False
    assert func.prototype is prototype


def test_classify_return_shape_treats_explicit_void_returns_as_void(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_RETURN_SHAPE_CLASSIFY", "1")
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    ret = structured_c.CReturn(None, codegen=c_codegen)
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeShort(False))
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([ret], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeBottom)


def test_classify_return_shape_refuses_unused_guessed_no_return_as_void():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    prototype = _FakePrototype(args=[SimTypeLong(False)], arg_names=("wait",), returnty=SimTypeShort(False))
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        _inertia_return_compat_caller_uses_return_8616=False,
        info={},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is False
    assert isinstance(func.prototype.returnty, SimTypeShort)


def test_classify_return_shape_keeps_unresolved_unused_return_carrier():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    unresolved_var = SimStackVariable(-2, 2, base="bp", name="vvar_21", region=0x1000)
    unresolved_return = structured_c.CReturn(
        structured_c.CVariable(unresolved_var, variable_type=SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeShort(False))
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        _inertia_return_compat_caller_uses_return_8616=False,
        info={},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([unresolved_return], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is False
    assert isinstance(func.prototype.returnty, SimTypeShort)
    assert unresolved_return.retval is not None


def test_classify_return_shape_keeps_unobserved_terminal_call_result():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    call = structured_c.CFunctionCall("outtext", None, [], codegen=c_codegen)
    call_return = structured_c.CReturn(call, codegen=c_codegen)
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeShort(False))
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=False,
        _inertia_return_compat_caller_uses_return_8616=False,
        info={},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=prototype,
            statements=structured_c.CStatements([call_return], codegen=c_codegen),
        ),
        _inertia_current_function_8616=func,
    )

    classified = postprocess._classify_return_shape_8616(project, codegen)
    pruned = postprocess._prune_void_function_return_values_8616(project, codegen)

    assert classified is False
    assert pruned is False
    assert isinstance(func.prototype.returnty, SimTypeShort)
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert isinstance(statements[0], structured_c.CReturn)
    assert statements[0].retval is call


def test_collapse_adjacent_unresolved_return_carrier_uses_concrete_ax_return():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    unresolved_var = SimStackVariable(-2, 2, base="bp", name="vvar_21", region=0x1000)
    ax_var = SimRegisterVariable(0, 2, name="ax")
    unresolved_return = structured_c.CReturn(
        structured_c.CVariable(unresolved_var, variable_type=SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    ax_return = structured_c.CReturn(
        structured_c.CVariable(ax_var, variable_type=SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(statements=structured_c.CStatements([unresolved_return, ax_return], codegen=c_codegen))
    )

    changed = postprocess._collapse_adjacent_unresolved_return_carrier_8616(SimpleNamespace(), codegen)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert isinstance(statements[0], structured_c.CReturn)
    assert statements[0].retval.variable is ax_var
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True


def test_collapse_terminal_unresolved_return_carrier_uses_concrete_ax_variable():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    unresolved_var = SimStackVariable(-2, 2, base="bp", name="vvar_21", region=0x1000)
    ax_var = SimRegisterVariable(0, 2, name="ax")
    ax_cvar = structured_c.CVariable(ax_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    unresolved_return = structured_c.CReturn(
        structured_c.CVariable(unresolved_var, variable_type=SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            statements=structured_c.CStatements(
                [
                    structured_c.CAssignment(
                        ax_cvar,
                        structured_c.CConstant(0, SimTypeShort(False), codegen=c_codegen),
                        codegen=c_codegen,
                    ),
                    unresolved_return,
                ],
                codegen=c_codegen,
            )
        )
    )

    changed = postprocess._collapse_adjacent_unresolved_return_carrier_8616(SimpleNamespace(), codegen)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert isinstance(statements[-1], structured_c.CReturn)
    assert statements[-1].retval is ax_cvar


def test_collapse_terminal_dirty_unresolved_return_carrier_uses_concrete_ax_variable():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    dirty_return = structured_c.CReturn(
        structured_c.CDirtyExpression(SimpleNamespace(varid=21, name="vvar_21"), codegen=c_codegen),
        codegen=c_codegen,
    )
    ax_var = SimRegisterVariable(0, 2, name="ax")
    ax_cvar = structured_c.CVariable(ax_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            statements=structured_c.CStatements(
                [
                    structured_c.CAssignment(
                        ax_cvar,
                        structured_c.CConstant(0, SimTypeShort(False), codegen=c_codegen),
                        codegen=c_codegen,
                    ),
                    dirty_return,
                ],
                codegen=c_codegen,
            )
        )
    )

    changed = postprocess._collapse_adjacent_unresolved_return_carrier_8616(SimpleNamespace(), codegen)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert isinstance(statements[-1], structured_c.CReturn)
    assert statements[-1].retval is ax_cvar


def test_collapse_terminal_dirty_register_tagged_return_carrier_uses_concrete_ax_variable():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    dirty_return = structured_c.CReturn(
        structured_c.CDirtyExpression(SimpleNamespace(varid=21, name="r0|4b"), codegen=c_codegen),
        codegen=c_codegen,
    )
    ax_var = SimRegisterVariable(0, 2, name="ax")
    ax_cvar = structured_c.CVariable(ax_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            statements=structured_c.CStatements(
                [
                    structured_c.CAssignment(
                        ax_cvar,
                        structured_c.CConstant(0, SimTypeShort(False), codegen=c_codegen),
                        codegen=c_codegen,
                    ),
                    dirty_return,
                ],
                codegen=c_codegen,
            )
        )
    )

    changed = postprocess._collapse_adjacent_unresolved_return_carrier_8616(SimpleNamespace(), codegen)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert isinstance(statements[-1], structured_c.CReturn)
    assert statements[-1].retval is ax_cvar


def test_collapse_terminal_dirty_unresolved_return_carrier_uses_dirty_ax_carrier():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    dirty_return = structured_c.CReturn(
        structured_c.CDirtyExpression(SimpleNamespace(varid=21, name="vvar_21"), codegen=c_codegen),
        codegen=c_codegen,
    )
    dirty_ax = structured_c.CDirtyExpression(SimpleNamespace(name="ax"), codegen=c_codegen)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            statements=structured_c.CStatements(
                [
                    structured_c.CAssignment(
                        dirty_ax,
                        structured_c.CConstant(0, SimTypeShort(False), codegen=c_codegen),
                        codegen=c_codegen,
                    ),
                    dirty_return,
                ],
                codegen=c_codegen,
            )
        )
    )

    changed = postprocess._collapse_adjacent_unresolved_return_carrier_8616(SimpleNamespace(), codegen)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert isinstance(statements[-1], structured_c.CReturn)
    assert statements[-1].retval is dirty_ax


def test_void_return_value_prune_preserves_call_side_effect_and_control_flow():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    call = structured_c.CFunctionCall(
        "DrawTime",
        None,
        [structured_c.CConstant(1, SimTypeShort(False), codegen=c_codegen)],
        codegen=c_codegen,
    )
    ret = structured_c.CReturn(call, codegen=c_codegen)
    scalar_ret = structured_c.CReturn(
        structured_c.CConstant(75, SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    scalar_retval = scalar_ret.retval
    after = structured_c.CExpressionStatement(
        structured_c.CFunctionCall("After", None, [], codegen=c_codegen),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeBottom(label="void"))
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=False, info={})
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=SimpleNamespace(returnty=SimTypeShort(False)),
            statements=structured_c.CStatements([ret, scalar_ret, after], codegen=c_codegen),
        ),
        _inertia_current_function_8616=SimpleNamespace(prototype=prototype),
    )

    changed = postprocess._prune_void_function_return_values_8616(project, codegen)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert isinstance(statements[0], structured_c.CExpressionStatement)
    assert statements[0].expr is call
    assert isinstance(statements[1], structured_c.CReturn)
    assert statements[1].retval is None
    assert statements[1] is not scalar_ret
    assert scalar_ret.retval is scalar_retval
    assert isinstance(statements[2], structured_c.CReturn)
    assert statements[2].retval is None
    assert statements[3] is after
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True


def test_void_return_value_prune_keeps_call_result_without_owned_liveness_proof():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    carrier_var = SimStackVariable(-2, 2, base="bp", name="vvar_21", region=0x1000)
    carrier = structured_c.CVariable(carrier_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    call = structured_c.CFunctionCall("outtext", None, [], codegen=c_codegen)
    assignment = structured_c.CAssignment(carrier, call, codegen=c_codegen)
    ret = structured_c.CReturn(None, codegen=c_codegen)
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeBottom(label="void"))
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=False, info={})
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=SimpleNamespace(returnty=SimTypeShort(False)),
            statements=structured_c.CStatements([assignment, ret], codegen=c_codegen),
            variables_in_use={carrier_var: carrier},
            unified_local_vars={carrier_var: {(carrier, SimTypeShort(False))}},
        ),
        _inertia_current_function_8616=SimpleNamespace(prototype=prototype),
    )

    changed = postprocess._prune_void_function_return_values_8616(project, codegen)

    assert changed is False
    statements = codegen.cfunc.statements.statements
    assert statements == [assignment, ret]
    assert assignment.rhs is call
    assert codegen.cfunc.variables_in_use[carrier_var] is carrier
    assert carrier_var in codegen.cfunc.unified_local_vars


def test_classify_return_shape_promotes_far_pointer_returns_from_void_prototypes(monkeypatch):
    monkeypatch.setenv("INERTIA_ENABLE_RETURN_SHAPE_CLASSIFY", "1")
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()), next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    ret = structured_c.CReturn(
        structured_c.CFunctionCall(
            "MK_FP",
            None,
            [
                structured_c.CConstant(0x1234, SimTypeShort(False), codegen=c_codegen),
                structured_c.CConstant(0x20, SimTypeShort(False), codegen=c_codegen),
            ],
            codegen=c_codegen,
        ),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(returnty=SimTypeBottom())
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([ret], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeLong)
    assert func.prototype.returnty.size == 32
