"""Regression tests for proof-gated 32-bit rotate frontend semantics."""

from __future__ import annotations

import bitstring
import pyvex
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY
from pyvex.expr import Binop
from pyvex.stmt import Dirty, WrTmp

from inertia.semantics.status_flag_liveness import StatusFlag8616

_ROR_EAX_16 = bytes.fromhex("66c1c810")


def test_ror_eax_imm32_keeps_full_lift_without_dead_flag_proof() -> None:
    """A live or unknown CF/OF effect must retain the architectural lifter."""
    instruction = Instruction_ANY(
        bitstring.ConstBitStream(bytes=_ROR_EAX_16),
        Arch86_16(),
        0x4000,
    )

    assert instruction.simple_semantics is None


def test_ror_eax_imm32_uses_direct_value_semantics_when_flags_are_dead(monkeypatch) -> None:
    """Dead CF/OF proof must avoid unsupported rotate helper expressions."""
    requested_masks: list[StatusFlag8616] = []

    def _flags_are_dead(self: Instruction_ANY, written: StatusFlag8616) -> bool:
        requested_masks.append(written)
        return True

    monkeypatch.setattr(Instruction_ANY, "status_flag_write_is_dead_8616", _flags_are_dead)

    instruction = Instruction_ANY(
        bitstring.ConstBitStream(bytes=_ROR_EAX_16),
        Arch86_16(),
        0x4000,
    )
    irsb = pyvex.lift(
        _ROR_EAX_16,
        0x4000,
        Arch86_16(),
        opt_level=0,
        max_inst=1,
    )

    assert instruction.simple_semantics == ("ror_reg_imm32_dead_flags", "eax", 16)
    assert requested_masks
    assert all(mask == StatusFlag8616.CARRY | StatusFlag8616.OVERFLOW for mask in requested_masks)
    assert not any(isinstance(statement, Dirty) for statement in irsb.statements)
    operations = [
        statement.data.op
        for statement in irsb.statements
        if isinstance(statement, WrTmp) and isinstance(statement.data, Binop)
    ]
    assert operations == ["Iop_Shr32", "Iop_Shl32", "Iop_Or32"]
