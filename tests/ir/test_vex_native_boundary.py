"""Layer: Tests.

Responsibility: preserve native branch entries hidden inside recovered blocks.
"""

import io
from types import SimpleNamespace

import angr

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.vex_import import raw_x86_16_function_bundle_8616


def _world(*, include_return: bool = True) -> tuple[angr.Project, SimpleNamespace]:
    """Retain real native bytes with a deliberately merged recovered block."""
    # test ax,ax; je right; mov ax,1; tail: jmp done;
    # right: mov ax,2; jmp tail; done: ret
    code = bytes.fromhex("85c0 7405 b80100 eb05 b80200 ebf9 c3")
    base = 0x1000
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob", "arch": arch,
            "base_addr": base, "entry_point": base,
        },
        auto_load_libs=False,
    )
    # The recovered graph merged tail into its predecessor. Its byte witnesses
    # still cover tail; reconstructing it requires no new decoding authority.
    extents = ((0, 4), (4, 5), (9, 5), (14, 1))
    if not include_return:
        extents = extents[:-1]
    recovered = SimpleNamespace(
        addr=base,
        block_addrs_set={base + offset for offset, _ in extents},
        blocks=tuple(
            project.factory.block(base + offset, size=size, opt_level=0)
            for offset, size in extents
        ),
    )
    return project, recovered


def test_native_import_restores_interior_branch_entry() -> None:
    """An optimized graph's merged block must not erase a native jump target."""
    project, recovered = _world()
    base = recovered.addr
    bundle = raw_x86_16_function_bundle_8616(project, recovered)
    blocks = {block.addr: block for block in bundle.artifact.blocks}
    assert base + 7 in blocks
    assert blocks[base + 4].successor_addrs == (base + 7,)
    # The raw backward jump may still need its selector proof; its target's
    # native block must nevertheless exist before that proof can run.
    assert {instruction.addr for instruction in blocks[base + 7].instrs} == {base + 7}


def test_native_import_does_not_expand_past_witnessed_bytes() -> None:
    """A mapped RET outside every supplied extent cannot complete the census."""
    project, recovered = _world(include_return=False)
    bundle = raw_x86_16_function_bundle_8616(project, recovered)
    heads = {block.addr for block in bundle.artifact.blocks}
    assert recovered.addr + 14 not in heads
    assert any(
        successor not in heads
        for block in bundle.artifact.blocks
        for successor in block.successor_addrs
    )
