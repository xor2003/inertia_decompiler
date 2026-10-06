"""Parent regression: decoded near calls must prove the return-frame width."""

import capstone
import pytest
import test_x86_16_near_return_continuation as worker
from angr.block import CapstoneInsn


@pytest.mark.parametrize("wide", [False, True])
def test_near_call_frame_requires_word_return_address(wide: bool) -> None:
    """A 66-prefixed near CALL pushes a dword, not the admitted return word."""
    head, target = 0x1000, 0x1100
    size = 6 if wide else 3
    width = 4 if wide else 2
    code = (b"\x66" if wide else b"") + b"\xe8"
    code += ((target - head - size) & ((1 << (width * 8)) - 1)).to_bytes(width, "little")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instruction, = tuple(decoder.disasm(code, head))
    assert instruction.size == size
    assert instruction.operands[0].imm == target
    row = worker.DecodedDirectCallsite8616(
        caller_start=head, instructions=(instruction,), instruction_index=0,
        callsite_addr=head, target_addr=target,
    )
    index = worker._callsite_index(row, target)
    premise = worker.nrc.prove_near_call_frame_premise_8616(row, index, target)
    if wide:
        assert premise is None
    else:
        assert premise is not None


@pytest.mark.parametrize("wrapped", [False, True])
def test_detail_disabled_call_refuses_without_exception(wrapped: bool) -> None:
    """Both real decoder representations refuse missing detail evidence."""
    owner = worker.nrc
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    instruction, = tuple(decoder.disasm(bytes.fromhex("e8fd00"), 0x1000))
    row = worker.DecodedDirectCallsite8616(
        caller_start=0x1000,
        instructions=(CapstoneInsn(instruction) if wrapped else instruction,),
        instruction_index=0, callsite_addr=0x1000, target_addr=0x1100,
    )
    assert owner.prove_near_call_frame_premise_8616(
        row, worker._callsite_index(row, 0x1100), 0x1100,
    ) is None


def test_lost_decoder_detail_revokes_call_premise() -> None:
    """An admitted premise becomes stale when decoder evidence disappears."""
    owner = worker.nrc
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instruction, = tuple(decoder.disasm(bytes.fromhex("e8fd00"), 0x1000))
    row = worker.DecodedDirectCallsite8616(
        caller_start=0x1000, instructions=(instruction,),
        instruction_index=0, callsite_addr=0x1000, target_addr=0x1100,
    )
    premise = owner.prove_near_call_frame_premise_8616(
        row, worker._callsite_index(row, 0x1100), 0x1100,
    )
    assert premise is not None
    decoder.detail = False
    assert owner.near_call_frame_premise_stale_8616(premise)


def test_unexpected_decoder_error_propagates() -> None:
    """Unrelated Capstone failures preserve their exact exception identity."""
    owner = worker.nrc
    error = capstone.CsError(capstone.CS_ERR_MEM)

    class BrokenWrapper:
        @property
        def insn(self) -> object:
            raise error

    with pytest.raises(capstone.CsError) as raised:
        owner._near_call_word_evidence_8616(BrokenWrapper())
    assert raised.value is error
