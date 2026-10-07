"""Regressions for indexed carrier observations in callee pointer evidence."""

from types import SimpleNamespace

from inertia.ir.core import IRAddress, MemSpace
from inertia.lowering.callee_pointer_codec import (
    callee_pointer_argument_evidence_from_record_8616,
    callee_pointer_argument_evidence_record_8616,
)
from inertia.lowering.callee_pointer_evidence import (
    recover_callee_pointer_argument_evidence_at_address_8616,
)
from inertia.lowering.interprocedural_storage_trial_types import (
    _pointer_evidence_for_storage_8616,
)
from capstone.x86_const import (
    X86_INS_MOV,
    X86_INS_RET,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_INVALID,
    X86_REG_SI,
)


def test_index_carrier_is_recorded_but_not_guessed_as_pointer() -> None:
    """A BP argument used as SI in BX+SI is observable, not pointer proof."""
    load_argument = SimpleNamespace(
        id=X86_INS_MOV,
        mnemonic="mov",
        operands=(
            SimpleNamespace(type=X86_OP_REG, reg=X86_REG_SI),
            SimpleNamespace(
                type=X86_OP_MEM,
                size=2,
                mem=SimpleNamespace(
                    base=X86_REG_BP,
                    index=X86_REG_INVALID,
                    disp=4,
                ),
            ),
        ),
    )
    indexed_read = SimpleNamespace(
        id=X86_INS_MOV,
        mnemonic="mov",
        operands=(
            SimpleNamespace(type=X86_OP_REG, reg=X86_REG_AX),
            SimpleNamespace(
                type=X86_OP_MEM,
                size=2,
                mem=SimpleNamespace(base=X86_REG_BX, index=X86_REG_SI, disp=0),
            ),
        ),
    )
    ret = SimpleNamespace(id=X86_INS_RET, mnemonic="ret", operands=())
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(load_argument, indexed_read, ret)))
    project = SimpleNamespace(
        factory=SimpleNamespace(block=lambda _address, **_kwargs: block),
    )

    evidence = recover_callee_pointer_argument_evidence_at_address_8616(
        project,
        0x100F1,
    )

    assert evidence.raw_fact_count == 1
    assert evidence.pointer_stack_offsets == ()
    assert evidence.pointer_argument_indices == ()
    assert evidence.ambiguous_displaced_stack_offsets == ()
    assert evidence.ambiguous_indexed_stack_offsets == (4,)
    assert evidence.failure_count == 1
    assert not evidence.closes_classification
    assert _pointer_evidence_for_storage_8616(
        evidence,
        IRAddress(MemSpace.SS, offset=4, size=2),
        0,
    ) == (False, True)
    record = callee_pointer_argument_evidence_record_8616(evidence)
    assert callee_pointer_argument_evidence_from_record_8616(record) == evidence
