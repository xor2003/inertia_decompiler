from types import SimpleNamespace

import pytest
from inertia.semantics.callsite_summary import (
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
    _linear_return_use_after_call_8616,
    _return_use_after_call,
)
from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_REG

from inertia.semantics.register_value_preservation import (
    AxValueView8616,
    ByteReturnExtensionKind8616,
    decoded_byte_return_extension_8616,
    decoded_instruction_self_clears_register_8616,
)


class _Operand:
    def __init__(self, operand_type: int, *, reg: int = 0, imm: int = 0) -> None:
        self.type = operand_type
        self.reg = reg
        self.imm = imm


class _Instruction:
    def __init__(
        self,
        address: int,
        mnemonic: str,
        operands: tuple[_Operand, ...] = (),
        *,
        reg_names: dict[int, str] | None = None,
        size: int = 1,
    ) -> None:
        self.address = address
        self.mnemonic = mnemonic
        self.size = size
        self.insn = SimpleNamespace(
            operands=operands,
            reg_name=lambda reg: (reg_names or {}).get(reg, ""),
        )


@pytest.mark.parametrize("mnemonic", ("sub", "xor"))
def test_exact_same_register_zero_idiom_self_clears_ax(mnemonic: str) -> None:
    instruction = _Instruction(
        0x1000,
        mnemonic,
        (_Operand(X86_OP_REG, reg=2), _Operand(X86_OP_REG, reg=2)),
        reg_names={2: "ax"},
    )

    assert decoded_instruction_self_clears_register_8616(instruction, "ax") is True


def test_different_register_subtraction_does_not_self_clear_ax() -> None:
    instruction = _Instruction(
        0x1000,
        "sub",
        (_Operand(X86_OP_REG, reg=2), _Operand(X86_OP_REG, reg=3)),
        reg_names={2: "ax", 3: "dx"},
    )

    assert decoded_instruction_self_clears_register_8616(instruction, "ax") is False


@pytest.mark.parametrize("written,queried,expected", [
    ("al", "ax", False), ("ah", "ax", False),
    ("al", "ah", False), ("ah", "al", False),
    ("ax", "al", True), ("ax", "ah", True),
])
@pytest.mark.parametrize("mnemonic", ("sub", "xor"))
def test_self_clear_requires_coverage_of_queried_register(written, queried, expected, mnemonic):
    instruction = _Instruction(
        0x1000, mnemonic,
        (_Operand(X86_OP_REG, reg=2), _Operand(X86_OP_REG, reg=2)),
        reg_names={2: written},
    )
    assert decoded_instruction_self_clears_register_8616(instruction, queried) is expected


def test_direct_capstone_high_byte_clear_is_zero_extension() -> None:
    disassembler = Cs(CS_ARCH_X86, CS_MODE_16)
    disassembler.detail = True
    instruction = next(iter(disassembler.disasm(bytes.fromhex("2ae4"), 0x1000)))

    assert decoded_instruction_self_clears_register_8616(instruction, "ah") is True
    assert (
        decoded_byte_return_extension_8616(instruction)
        is ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX
    )


def test_partial_low_byte_clear_does_not_discard_full_return_value():
    instructions = (
        _Instruction(0x1000, "call", size=3),
        _Instruction(0x1003, "xor", (_Operand(X86_OP_REG, reg=2), _Operand(X86_OP_REG, reg=2)),
                     reg_names={2: "al"}, size=2),
        _Instruction(0x1005, "push", (_Operand(X86_OP_REG, reg=3),), reg_names={3: "ax"}),
    )
    register, used, kind = _return_use_after_call(SimpleNamespace(), instructions, 0, 0x1000)
    assert register == "ax"
    assert used is True
    assert kind is CallsiteReturnUseKind8616.VALUE


def test_post_call_sub_ax_ax_is_clobber_not_return_value_use() -> None:
    reg_names = {1: "sp", 2: "ax"}
    instructions = (
        _Instruction(0x1000, "call", size=5),
        _Instruction(
            0x1005,
            "add",
            (_Operand(X86_OP_REG, reg=1), _Operand(X86_OP_IMM, imm=0x10)),
            reg_names=reg_names,
            size=3,
        ),
        _Instruction(
            0x1008,
            "sub",
            (_Operand(X86_OP_REG, reg=2), _Operand(X86_OP_REG, reg=2)),
            reg_names=reg_names,
            size=2,
        ),
        _Instruction(
            0x100A,
            "push",
            (_Operand(X86_OP_REG, reg=2),),
            reg_names=reg_names,
        ),
    )

    return_register, return_used, return_use_kind = _return_use_after_call(
        SimpleNamespace(),
        instructions,
        0,
        0x1000,
    )

    assert return_register == "ax"
    assert return_used is False
    assert return_use_kind is CallsiteReturnUseKind8616.CLOBBERED


@pytest.mark.parametrize(
    ("extension_instruction", "expected"),
    (
        (
            _Instruction(
                0x1008,
                "sub",
                (_Operand(X86_OP_REG, reg=3), _Operand(X86_OP_REG, reg=3)),
                reg_names={3: "ah"},
                size=2,
            ),
            ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX,
        ),
        (
            _Instruction(0x1008, "cbw"),
            ByteReturnExtensionKind8616.SIGN_EXTEND_AL_TO_AX,
        ),
    ),
)
def test_linear_return_use_retains_byte_extension_until_ax_use(
    extension_instruction: _Instruction,
    expected: ByteReturnExtensionKind8616,
) -> None:
    reg_names = {1: "sp", 2: "ax"}
    instructions = (
        _Instruction(0x1000, "call", size=5),
        _Instruction(
            0x1005,
            "add",
            (_Operand(X86_OP_REG, reg=1), _Operand(X86_OP_IMM, imm=4)),
            reg_names=reg_names,
            size=3,
        ),
        extension_instruction,
        _Instruction(
            0x100A,
            "push",
            (_Operand(X86_OP_REG, reg=2),),
            reg_names=reg_names,
        ),
    )

    fact = _linear_return_use_after_call_8616(instructions, 0, 0x1000, 0x1000)
    return_register, return_used, return_use_kind = _return_use_after_call(
        SimpleNamespace(),
        instructions,
        0,
        0x1000,
    )

    assert fact.verdict is CallerReturnUseVerdict8616.USED
    assert fact.kind is CallsiteReturnUseKind8616.VALUE
    assert fact.witness_instruction_addr == 0x100A
    assert fact.byte_extension is expected
    assert fact.byte_extension_instruction_addr == 0x1008
    assert fact.observed_value_view is AxValueView8616.AX
    assert fact.classified is True
    assert return_register == "ax"
    assert return_used is True
    assert return_use_kind is CallsiteReturnUseKind8616.VALUE
