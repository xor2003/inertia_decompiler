from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)

from inertia.validation.tail_validation_fingerprint import (
    _source_arg_location_fingerprint_8616,
)


def test_tail_validation_uses_machine_bp_coordinate_after_arg_regeneration() -> None:
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction(
            (SimTypeShort(False),),
            SimTypeShort(False),
            arg_names=("arg",),
        ),
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, **_kwargs: function if addr == 0x1000 else None
            )
        ),
    )
    codegen = SimpleNamespace(
        next_ident=lambda name: name,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
    )
    formal = SimStackVariable(2, 2, base="bp", name="arg", ident="arg_0")
    cvar = CVariable(formal, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, arg_list=(cvar,))
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=formal,
        cvar=cvar,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
        display_name="arg",
    )
    regenerated = CVariable(
        SimStackVariable(2, 2, base="bp", name="arg", ident="regenerated"),
        codegen=codegen,
    )

    assert _source_arg_location_fingerprint_8616(regenerated, project) == (
        "stack_arg:arg:size2:bp+0x4"
    )
