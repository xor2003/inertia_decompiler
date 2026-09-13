from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _normalize_stack_variable_identifiers_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_display_names import (
    reapply_stack_variable_projection_names_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self._next_idx = 0

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def test_normalizer_uses_machine_bp_coordinate_for_projected_argument() -> None:
    codegen = _Codegen()
    variable = SimStackVariable(2, 2, base="bp", name="stack_sp_p2")
    cvar = structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    prototype = SimTypeFunction(
        [SimTypeShort(False)],
        SimTypeShort(False),
        arg_names=["arg_4"],
    ).with_arch(codegen.project.arch)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[cvar],
        functy=prototype,
        statements=cvar,
        unified_local_vars={variable: {(cvar, cvar.variable_type)}},
        variables_in_use={variable: cvar},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
        display_name="arg_4",
    )

    _normalize_stack_variable_identifiers_8616(codegen)
    reapply_stack_variable_projection_names_8616(codegen)

    assert variable.name == "arg_4"


@pytest.mark.parametrize("projection_surface", ["stale", "body", "map", "argument", "declaration"])
def test_projection_name_reservation_requires_a_live_owner(projection_surface: str) -> None:
    codegen = _Codegen()
    projected_offset = 6
    projected = SimStackVariable(projected_offset, 1, base="bp", name="local_6", ident="projected")
    projected_cvar = structured_c.CVariable(projected, codegen=codegen)
    local = SimStackVariable(-6, 1, base="bp", name="local_6", ident="native")
    local_cvar = structured_c.CVariable(local, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={local: local_cvar}, unified_local_vars={}, arg_list=[],
        statements=structured_c.CStatements([local_cvar], codegen=codegen),
    )
    if projection_surface == "body":
        codegen.cfunc.statements.statements.append(projected_cvar)
    elif projection_surface == "map":
        codegen.cfunc.variables_in_use[projected] = projected_cvar
    elif projection_surface == "argument":
        codegen.cfunc.arg_list.append(projected_cvar)
    elif projection_surface == "declaration":
        codegen.cfunc.unified_local_vars[projected] = {(projected_cvar, None)}
    projection = record_stack_variable_coordinate_projection_8616(
        codegen, variable=projected, cvar=projected_cvar, bp_offset=6,
        entry_sp_offset=6, size=1, display_name="local_6",
    )

    reapply_stack_variable_projection_names_8616(codegen)

    assert local.name == ("local_6" if projection_surface == "stale" else "stack_sp_m6_1")
    assert projection.entry_sp_offset == projected_offset
    assert projected.name == "local_6"
