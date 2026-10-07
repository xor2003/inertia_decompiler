"""Tests for typed 16-bit stack-prototype layout projection."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.stack_prototype_layout import (
    stack_prototype_argument_layout_8616,
    stack_prototype_cvar_for_machine_bp_range_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    stack_cvar_for_machine_bp_range_8616,
)


def test_stack_prototype_layout_keeps_two_word_scalar_as_one_argument() -> None:
    """A 32-bit argument owns both adjacent 16-bit stack views."""
    arch = Arch86_16()
    prototype = SimTypeFunction([SimTypeLong()], SimTypeLong()).with_arch(arch)

    layout = stack_prototype_argument_layout_8616(prototype, arch)

    assert [(argument.offset, argument.storage_width) for argument in layout] == [(4, 4)]


def test_stack_prototype_layout_places_pointer_and_word_contiguously() -> None:
    """A near pointer and word occupy distinct two-byte ABI slots."""
    arch = Arch86_16()
    prototype = SimTypeFunction(
        [SimTypePointer(SimTypeChar()), SimTypeShort()],
        SimTypeShort(),
    ).with_arch(arch)

    layout = stack_prototype_argument_layout_8616(prototype, arch)

    assert [(argument.offset, argument.storage_width) for argument in layout] == [(4, 2), (6, 2)]


def test_prototype_resolves_proven_entry_sp_arguments_without_publication() -> None:
    """Owned types and frame delta resolve formals without global mutation."""
    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_ident=lambda name: name,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        _inertia_vex_ir_frame=FrameAccessArtifact(
            bp_coordinate=BPFrameCoordinateEvidence8616(
                FrameCoordinateStatus8616.PROVEN,
                -2,
                "test",
                FrameCoordinateStats8616(1, 1, 1, 1, 0),
            )
        )
    )
    arguments = tuple(
        structured_c.CVariable(
            SimStackVariable(offset, 2, base="bp", name=name),
            codegen=codegen,
        )
        for offset, name in ((2, "lhs"), (4, "rhs"))
    )
    prototype = SimTypeFunction(
        [SimTypeShort(False), SimTypeShort(False)],
        SimTypeShort(False),
    ).with_arch(arch)
    codegen.cfunc = SimpleNamespace(
        arg_list=arguments,
        functy=prototype,
        prototype=prototype,
    )

    assert stack_prototype_cvar_for_machine_bp_range_8616(codegen, 4, 2) is arguments[0]
    assert stack_prototype_cvar_for_machine_bp_range_8616(codegen, 6, 2) is arguments[1]
    assert stack_prototype_cvar_for_machine_bp_range_8616(codegen, 5, 2) is None
    assert stack_cvar_for_machine_bp_range_8616(codegen, 4, 2) is None
