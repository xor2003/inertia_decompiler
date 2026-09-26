from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from angr import Project
from angr_platforms.X86_16.frontend_block_inventory import collect_decoded_block_evidence_8616
from angr_platforms.X86_16.frontend_capstone_decode import (
    DirectCapstoneInstruction8616,
    decode_exact_capstone_block_8616,
)
from cle.backends.externs import ExternObject


class _Instruction:
    address = 0x1000
    size = 2
    mnemonic = "cmp"
    op_str = "ax, bx"
    groups: tuple[int, ...] = ()
    operands: tuple[str, ...] = ("ax", "bx")

    def reg_name(self, register_id: int) -> str:
        return f"reg_{register_id}"


class _Decoder:
    def disasm(self, _code: bytes, _address: int) -> tuple[_Instruction, ...]:
        return (_Instruction(),)


def test_direct_instruction_preserves_capstone_detail_contract() -> None:
    project = SimpleNamespace(arch=SimpleNamespace(capstone=_Decoder()))

    artifact = decode_exact_capstone_block_8616(project, 0x1000, b"\x39\xd8")

    assert artifact.complete is True
    assert artifact.block is not None
    instruction = artifact.block.instructions[0]
    assert isinstance(instruction, DirectCapstoneInstruction8616)
    assert instruction.operands == ("ax", "bx")
    assert instruction.reg_name(7) == "reg_7"
@pytest.mark.parametrize("num_inst,opt_level", [(None, 0), (1, 0), (None, 1)])
def test_synthetic_extern_memory_is_not_binary_instruction_evidence(num_inst, opt_level):
    """Even return-looking bytes in angr's fake object cannot prove a DOS ABI."""
    calls = []
    synthetic = object.__new__(ExternObject)

    def block(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(capstone=SimpleNamespace(insns=()))

    project = Mock(spec=Project,
        loader=SimpleNamespace(find_object_containing=lambda address: synthetic),
        factory=SimpleNamespace(block=block),
    )
    with pytest.raises(ValueError, match="synthetic"):
        collect_decoded_block_evidence_8616(project, 0x100012, num_inst=num_inst, opt_level=opt_level)
    assert calls == []


def test_loaded_code_outside_main_image_still_uses_factory_fallback():
    """Refusal is based on synthetic ownership, not an address cutoff."""
    instructions = (_Instruction(),)
    factory = Mock()
    factory.block.return_value = SimpleNamespace(capstone=SimpleNamespace(insns=instructions))
    project = Mock(spec=Project,
        loader=SimpleNamespace(find_object_containing=lambda address: SimpleNamespace()),
        factory=factory,
    )
    result = collect_decoded_block_evidence_8616(project, 0x100012, num_inst=1)
    assert result.instructions == instructions
    factory.block.assert_called_once_with(0x100012, num_inst=1, opt_level=0)


def test_synthetic_callee_does_not_acquire_terminal_cleanup_proof():
    """The consumer retains incomplete evidence instead of decoding stub bytes."""
    from angr_platforms.X86_16.semantics.terminal_stack_cleanup import terminal_stack_cleanup_at_address_8616

    synthetic = Mock(spec=ExternObject, min_addr=0x100000, max_addr=0x107fff)
    factory = Mock()
    project = Mock(spec=Project,
        loader=SimpleNamespace(find_object_containing=lambda address: synthetic),
        factory=factory,
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **kwargs: None)),
    )
    evidence = terminal_stack_cleanup_at_address_8616(project, 0x100012)
    assert not evidence.complete
    assert evidence.consistent_cleanup is None
    factory.block.assert_not_called()
