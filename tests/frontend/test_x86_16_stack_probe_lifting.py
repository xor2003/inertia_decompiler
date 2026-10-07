"""Regress binary-proven stack-probe effects at the frontend boundary."""

from __future__ import annotations

import io

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16


def _probe_block(allocation_size: int) -> tuple[object, Arch86_16]:
    """Lift ``mov ax, size; call probe`` with a registered probe target."""
    arch = Arch86_16()
    arch._inertia_stack_probe_helper_targets_8616 = frozenset({0x1010})
    code = bytes((0xB8, allocation_size & 0xFF, allocation_size >> 8, 0xE8, 0x0A, 0x00))
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": arch,
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    project.arch._inertia_stack_probe_helper_targets_8616 = frozenset({0x1010})
    return project.factory.block(0x1000, opt_level=0), project.arch


def _put_offsets_at_call(block: object) -> tuple[int, ...]:
    """Return register offsets written by the call instruction in one VEX block."""
    current_addr: int | None = None
    offsets: list[int] = []
    for statement in block.vex.statements:
        if statement.tag == "Ist_IMark":
            current_addr = statement.addr
        elif statement.tag == "Ist_Put" and current_addr == 0x1003:
            offsets.append(statement.offset)
    return tuple(offsets)


def test_zero_size_probe_retains_native_call_frame() -> None:
    """Zero helper allocation does not eliminate the CALL's return-address push."""
    block, arch = _probe_block(0)

    offsets = _put_offsets_at_call(block)

    assert offsets == (arch.registers["sp"][0],)
    assert block.vex.jumpkind == "Ijk_Call"


def test_nonzero_probe_retains_stack_pointer_effect() -> None:
    """The helper's input size cannot replace native CALL frame effects."""
    block, arch = _probe_block(2)

    assert arch.registers["sp"][0] in _put_offsets_at_call(block)
    assert block.vex.jumpkind == "Ijk_Call"
