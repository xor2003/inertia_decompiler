from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
import inertia.postprocess.decompiler_postprocess as postprocess
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.near_pointer_type import SimTypeNearPointer16_8616
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)

from inertia.lowering.annotations import ANNOTATION_KEY


def test_annotations_preserve_lowering_owned_argument_cvars_over_byte_views() -> None:
    arch = Arch86_16()
    word = SimTypeShort(False).with_arch(arch)
    dword = SimTypeLong(False).with_arch(arch)
    pointer = SimTypeNearPointer16_8616(word).with_arch(arch)
    prototype = SimTypeFunction(
        [word, dword, pointer, pointer],
        word,
        arg_names=("file", "cmdline", "cs", "ss"),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        name="annotated_wrapper",
        prototype=prototype,
        is_prototype_guessed=False,
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

    class _Functions:
        def function(self, addr: int, create: bool = False) -> object | None:
            _ = create
            return function if addr == function.addr else None

    project = SimpleNamespace(
        arch=arch,
        _inertia_c_target="portable-flat",
        _inertia_cod_metadata_by_func_addr_8616={},
        kb=SimpleNamespace(functions=_Functions()),
    )
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
        cstyle_null_cmp=False,
        _function=SimpleNamespace(prototype=prototype, is_prototype_guessed=False),
    )

    argument_specs = (
        (2, 2, "file", word, 4),
        (4, 4, "cmdline", dword, 6),
        (8, 2, "cs", pointer, 10),
        (10, 2, "ss", pointer, 12),
    )
    arguments: list[structured_c.CVariable] = []
    for entry_sp_offset, size, name, type_, _bp_offset in argument_specs:
        variable = SimStackVariable(
            entry_sp_offset,
            size,
            base="bp",
            name=name,
            region=function.addr,
        )
        arguments.append(
            structured_c.CVariable(variable, variable_type=type_, codegen=codegen)
        )

    byte_views: list[structured_c.CVariable] = []
    for bp_offset, name in ((10, "arg_a"), (12, "arg_c")):
        variable = SimStackVariable(
            bp_offset,
            1,
            base="bp",
            name=name,
            region=function.addr,
        )
        byte_views.append(
            structured_c.CVariable(variable, variable_type=None, codegen=codegen)
        )

    codegen.cfunc = SimpleNamespace(
        addr=function.addr,
        functy=prototype,
        arg_list=list(arguments),
        statements=structured_c.CStatements([], codegen=codegen),
        variables_in_use={
            arguments[0].variable: arguments[0],
            arguments[1].variable: arguments[1],
            byte_views[0].variable: byte_views[0],
            byte_views[1].variable: byte_views[1],
        },
        unified_local_vars={},
    )
    for argument, (entry_sp_offset, size, _name, _type, bp_offset) in zip(
        arguments,
        argument_specs,
        strict=True,
    ):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=argument.variable,
            cvar=argument,
            bp_offset=bp_offset,
            entry_sp_offset=entry_sp_offset,
            size=size,
        )
    for byte_view, bp_offset in zip(byte_views, (10, 12), strict=True):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=byte_view.variable,
            cvar=byte_view,
            bp_offset=bp_offset,
            entry_sp_offset=bp_offset,
            size=1,
        )

    postprocess._apply_annotations_8616(project, codegen)

    assert all(
        actual is expected
        for actual, expected in zip(codegen.cfunc.arg_list, arguments, strict=True)
    )
    assert [argument.variable.size for argument in codegen.cfunc.arg_list] == [2, 4, 2, 2]
    assert isinstance(codegen.cfunc.arg_list[0].variable_type, SimTypeShort)
    assert isinstance(codegen.cfunc.arg_list[1].variable_type, SimTypeLong)
    assert all(
        isinstance(argument.variable_type, SimTypePointer)
        for argument in codegen.cfunc.arg_list[2:]
    )
    assert [argument.variable_type.size for argument in codegen.cfunc.arg_list] == [16, 32, 16, 16]
