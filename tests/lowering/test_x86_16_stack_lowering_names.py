from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.real_mode_linear import (
    RealModeLinearStackAccess8616,
    _apply_annotation_names_to_existing_stack_cvars_8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)
from inertia.lowering.stack_lowering_from_facts import (
    materialize_stack_cvar_at_offset_from_facts_8616,
)
from inertia.lowering.stack_variable_binding import (
    StackVariableBinding,
    select_normalized_stack_argument_annotation_spec_8616,
    select_stack_annotation_spec_8616,
)

from inertia.lowering.annotations import ANNOTATION_KEY


class _DummyCodegen(SimpleNamespace):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _codegen_with_stack_specs(stack_specs):
    codegen = _DummyCodegen(
        _func=SimpleNamespace(info={ANNOTATION_KEY: {"stack_vars": stack_specs}}),
        project=SimpleNamespace(arch=Arch86_16()),
        cfunc=SimpleNamespace(
            addr=0x1000,
            arg_list=[],
            variables_in_use={},
            unified_local_vars={},
        ),
    )
    positive_specs = {key: value for key, value in stack_specs.items() if isinstance(key, int) and key > 0}
    if 2 in positive_specs and 6 not in positive_specs:
        arg_offsets = ((4, positive_specs.get(2)), (6, positive_specs.get(4)))
    else:
        arg_offsets = tuple((key, value) for key, value in sorted(positive_specs.items()) if key >= 4)
    for offset, spec in arg_offsets:
        if not isinstance(offset, int):
            continue
        name = spec.get("name") if isinstance(spec, dict) else None
        if not isinstance(name, str) or not name:
            name = f"arg_{offset:x}"
        variable = SimStackVariable(offset, 2, base="bp", name=name, region=0x1000)
        cvar = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
        codegen.cfunc.arg_list.append(cvar)
        codegen.cfunc.variables_in_use[variable] = cvar
    return codegen


def test_stable_stack_names_use_single_object_bias_for_positive_args():
    codegen = _codegen_with_stack_specs(
        {
            2: {"name": "value"},
            4: {"name": "limit"},
        }
    )

    value = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(4, 2))
    limit = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(6, 2))

    assert value.name == "value"
    assert value.variable.offset == 4
    assert limit.name == "limit"
    assert limit.variable.offset == 6
    assert [arg.name for arg in codegen.cfunc.arg_list] == ["value", "limit"]
    assert not codegen.cfunc.unified_local_vars


def test_stable_stack_names_use_exact_positive_arg_specs_without_bias():
    codegen = _codegen_with_stack_specs(
        {
            4: {"name": "value"},
            6: {"name": "limit"},
        }
    )

    value = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(4, 2))
    limit = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(6, 2))

    assert value.name == "value"
    assert value.variable.offset == 4
    assert limit.name == "limit"
    assert limit.variable.offset == 6
    assert [arg.name for arg in codegen.cfunc.arg_list] == ["value", "limit"]
    assert not codegen.cfunc.unified_local_vars


def test_stable_stack_arg_types_use_source_prototype_by_bp_offset():
    arch = Arch86_16()
    signed_word = SimTypeShort(True).with_arch(arch)
    codegen = _codegen_with_stack_specs(
        {
            2: {"name": "value"},
            4: {"name": "limit"},
        }
    )
    source_proto = SimTypeFunction(
        [signed_word, signed_word],
        signed_word,
        arg_names=("value", "limit"),
    ).with_arch(arch)
    codegen._func = SimpleNamespace(prototype=source_proto, is_prototype_guessed=False)
    codegen.cfunc.functy = source_proto

    value = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(4, 2))
    limit = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(6, 2))

    assert getattr(value.variable_type, "signed", None) is True
    assert getattr(limit.variable_type, "signed", None) is True
    assert [getattr(arg_type, "signed", None) for arg_type in codegen.cfunc.functy.args] == [True, True]
    assert codegen._inertia_stack_arg_source_prototype_type_materialized_8616 >= 1


def test_fact_stack_lowering_preserves_annotated_function_pointer_local_type():
    arch = Arch86_16()
    fn_type = SimTypeFunction([SimTypeShort(False).with_arch(arch)], SimTypeShort(False).with_arch(arch)).with_arch(
        arch
    )
    fn_ptr_type = SimTypePointer(fn_type).with_arch(arch)
    variable = SimStackVariable(-2, 2, base="bp", name="fn", region=0x1000)
    codegen = _codegen_with_stack_specs({})
    cvar = structured_c.CVariable(variable, variable_type=fn_ptr_type, codegen=codegen)
    codegen.cfunc.variables_in_use[variable] = cvar
    codegen.cfunc.unified_local_vars[variable] = {(cvar, fn_ptr_type)}

    resolved = materialize_stack_cvar_at_offset_from_facts_8616(codegen, -2, size=2, preferred_name="fn")

    assert resolved is cvar
    assert resolved.variable_type is fn_ptr_type
    assert isinstance(resolved.variable_type, SimTypePointer)


def test_fact_stack_lowering_preserves_existing_signed_arg_surface():
    arch = Arch86_16()
    signed_word = SimTypeShort(True).with_arch(arch)
    unsigned_word = SimTypeShort(False).with_arch(arch)
    codegen = _codegen_with_stack_specs({})
    arg_var = SimStackVariable(4, 2, base="bp", name="a", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=signed_word, codegen=codegen)
    stale_var = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000)
    stale_cvar = structured_c.CVariable(stale_var, variable_type=unsigned_word, codegen=codegen)
    codegen.cfunc.arg_list = [arg_cvar]
    codegen.cfunc.variables_in_use[stale_var] = stale_cvar

    resolved = materialize_stack_cvar_at_offset_from_facts_8616(codegen, 4, size=2, preferred_name="arg_4")

    assert resolved is arg_cvar
    assert resolved.variable.name == "a"
    assert getattr(resolved.variable_type, "signed", None) is True
    assert codegen.cfunc.variables_in_use[arg_var] is arg_cvar


def test_stack_annotation_selector_refuses_containing_object_name_for_interior_view():
    wide = StackVariableBinding(-4, 4, var_name="goal")
    high_word = StackVariableBinding(-2, 2, var_name="goal")

    selected = select_stack_annotation_spec_8616(
        high_word,
        stack_specs={-4: {"name": "goal", "type": "long"}},
        candidate_offsets=(-2, -4),
        known_bindings=(wide, high_word),
    )

    assert selected is None


def test_normalized_stack_argument_selector_uses_one_unambiguous_coordinate():
    which = StackVariableBinding(4, 2, var_name="value")

    selected = select_normalized_stack_argument_annotation_spec_8616(
        which,
        stack_specs={2: {"name": "which"}, 4: {"name": "value"}},
    )

    assert selected is not None
    assert selected.name == "which"


def test_lowering_reconciles_duplicate_annotation_name_to_wide_stack_owner():
    codegen = _codegen_with_stack_specs({-4: {"name": "goal", "type": "long"}})
    codegen._inertia_active_stack_base_bp_bias_8616 = 2
    codegen.cfunc.statements = structured_c.CStatements([], codegen=codegen)
    wide_var = SimStackVariable(-4, 4, base="bp", name="goal", region=0x1000)
    high_var = SimStackVariable(-2, 2, base="bp", name="goal", region=0x1000)
    wide_cvar = structured_c.CVariable(wide_var, variable_type=SimTypeLong(False), codegen=codegen)
    high_cvar = structured_c.CVariable(high_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use = {
        wide_var: wide_cvar,
        high_var: high_cvar,
    }

    changed = _apply_annotation_names_to_existing_stack_cvars_8616(codegen)

    assert changed is True
    assert wide_var.name == "goal"
    assert high_var.name == "local_2"
    assert wide_cvar.name == "goal"
    assert high_cvar.name == "local_2"
