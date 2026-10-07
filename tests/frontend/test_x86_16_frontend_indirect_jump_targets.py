from __future__ import annotations

from types import SimpleNamespace

from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from inertia.frontend.x86_16.frontend_indirect_jump_targets import (
    ConstantIndirectJumpStatus8616,
    collect_constant_indirect_jump_edges_8616,
)


class _Memory:
    def __init__(self, values: dict[int, bytes]) -> None:
        self.values = values

    def load(self, address: int, size: int) -> bytes:
        value = self.values[address]
        if len(value) != size:
            raise KeyError(address)
        return value


def _instruction(address: int, mnemonic: str, operands: tuple[object, ...]) -> object:
    names = {1: "si"}
    inner = SimpleNamespace(
        address=address,
        mnemonic=mnemonic,
        operands=operands,
        reg_name=lambda register_id: names[register_id],
    )
    return SimpleNamespace(insn=inner)


def _block(address: int, *instructions: object) -> object:
    return SimpleNamespace(addr=address, capstone=SimpleNamespace(insns=instructions))


def test_resolves_unique_relocation_backed_push_pop_jump_target() -> None:
    push = _instruction(0x1000, "push", (SimpleNamespace(type=X86_OP_IMM, imm=2),))
    call = _instruction(0x1002, "call", (SimpleNamespace(type=X86_OP_IMM, imm=0x1200),))
    pop = _instruction(0x1005, "pop", (SimpleNamespace(type=X86_OP_REG, reg=1),))
    jump_memory = SimpleNamespace(base=1, index=0, scale=1, disp=-0x7852)
    jump = _instruction(
        0x1006,
        "jmp",
        (SimpleNamespace(type=X86_OP_MEM, size=2, mem=jump_memory),),
    )
    memory = _Memory(
        {
            0x1000: (0x0200).to_bytes(2, "little"),
            0x0FFF: b"\xb8\x00\x02\x8e\xd8",
            0x1010: (0x0300).to_bytes(2, "little"),
            0xA7AE: (0x0070).to_bytes(2, "little"),
            0xA7B0: (0x0080).to_bytes(2, "little"),
            0xB7AE: (0x0500).to_bytes(2, "little"),
            0xB7B0: (0x0090).to_bytes(2, "little"),
        }
    )
    original_project = SimpleNamespace(
        loader=SimpleNamespace(
            memory=memory,
            main_object=SimpleNamespace(
                mz_load_segment=0x100,
                mz_relocation_entries=((0, 0), (0, 1)),
                initial_register_values={"cs": 0x600},
            ),
        )
    )
    slice_project = SimpleNamespace(
        _inertia_original_project=original_project,
        _inertia_original_linear_delta=0x5000,
        loader=SimpleNamespace(
            memory=_Memory(
                {
                    0x1070: b"\x90",
                    0x1080: b"\xc3",
                }
            )
        ),
    )

    artifact = collect_constant_indirect_jump_edges_8616(
        slice_project,
        blocks=(_block(0x1000, push, call), _block(0x1005, pop, jump)),
        successor_edges=((0x1000, 0x1005),),
        region_start=0x1000,
        region_end=0x1100,
    )

    assert artifact.complete is True
    assert artifact.resolved_edges == ((0x1005, 0x1080),)
    assert artifact.records[0].status is ConstantIndirectJumpStatus8616.RESOLVED
    assert artifact.records[0].selector_byte_offset == 2
    assert artifact.records[0].table_linear_addr == 0xA7AE
    assert artifact.records[0].target_linear_addr == 0x6080
    assert artifact.raw_fact_count == artifact.materialized_count == 1
    assert artifact.failure_count == 0


def test_refuses_indirect_jump_without_exact_pop_selector() -> None:
    jump_memory = SimpleNamespace(base=1, index=0, scale=1, disp=0x200)
    jump = _instruction(
        0x1000,
        "jmp",
        (SimpleNamespace(type=X86_OP_MEM, size=2, mem=jump_memory),),
    )

    artifact = collect_constant_indirect_jump_edges_8616(
        SimpleNamespace(),
        blocks=(_block(0x1000, jump),),
        successor_edges=(),
        region_start=0x1000,
        region_end=0x1100,
    )

    assert artifact.complete is False
    assert artifact.records[0].status is ConstantIndirectJumpStatus8616.POP_SELECTOR_MISSING
    assert artifact.materialized_count == 0
    assert artifact.failure_count == 1
