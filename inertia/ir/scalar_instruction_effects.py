"""Typed per-instruction register-effect classification over scalar IR.

Layer: IR.
Responsibility: own the single typed decision over whether one typed IR
instruction's architectural-register effects are *closed* (fully described by
its explicit destination), *memory-only* (a proven STORE), *IP-only* (a proven
control transfer), or *unknown*. This finite backend decoding table lives only
here; consumers must never copy opcode lists or use substring/prefix matching.
The decision is effect-only: it never proves flag, segment, or callee
preservation, and value-equality/provenance proofs stay with their own owners —
a decorated or displaced source still reads without writing another register.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeGuard

from .core import (
    IRAddress,
    IRAtom,
    IRCondition,
    IRInstr,
    IRValue,
    MemSpace,
)
from .no_effect_instructions import (
    NO_EFFECT_INSTRUCTION_OP_8616,
    no_effect_claim_shape_8616,
)
from .scalar_value_projection import (
    ScalarBinaryKind8616,
    ScalarBinaryOp8616,
    scalar_binary_operation_8616,
)

__all__ = [
    "ScalarInstructionClobber8616",
    "ScalarInstructionEffect8616",
    "ScalarInstructionEffectKind8616",
    "scalar_instruction_effect_8616",
]


class ScalarInstructionEffectKind8616(StrEnum):
    """How completely one instruction's register effects are described."""

    CLOSED_DESTINATION = "closed_destination"
    NO_REGISTER_WRITE = "no_register_write"
    INSTRUCTION_POINTER_WRITE = "instruction_pointer_write"
    UNKNOWN = "unknown"


class ScalarInstructionClobber8616(StrEnum):
    """Which architectural storage one classified instruction writes.

    Data-register tracking consumes this field directly: ``NONE`` and
    ``MEMORY`` preserve every architectural register, ``DATA_REGISTER`` writes
    only the declared destination register, and ``INSTRUCTION_POINTER``
    preserves data registers while rewriting IP — a control transfer is never
    "no effect". ``UNKNOWN`` proves nothing.
    """

    NONE = "none"
    DATA_REGISTER = "data_register"
    MEMORY = "memory"
    INSTRUCTION_POINTER = "instruction_pointer"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ScalarInstructionEffect8616:
    """One typed register-effect classification and its exact branch target.

    ``control_target`` retains the validated raw IR literal. Consumers must
    not independently decode targets or infer guest-address normalization.
    Other effects carry no control target.
    """

    kind: ScalarInstructionEffectKind8616
    clobber: ScalarInstructionClobber8616
    detail: str = ""
    control_target: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this classification deterministically."""
        return {
            "kind": self.kind.value,
            "clobber": self.clobber.value,
            "detail": self.detail,
            "control_target": self.control_target,
        }


# Comparison spellings exactly as the custom frontend emits them:
# ``IRSBCustomizer``'s ``mkcmpop`` formats ``Iop_Cmp{relation}{width}{sign}``
# — equality carries no signedness at every width, and ordered comparisons
# carry a trailing S/U at every width, including spellings absent from the
# stock VEX enum (``Iop_CmpLT16U`` is observed in real lifted IR).
# ``Iop_CmpLTU16``-style misspellings are not emitted. Values map each
# exact spelling to its operand width in bits. Equality at width 1 is
# emitted by one-bit comparisons (``Iop_CmpEQ1``/``Iop_CmpNE1`` — observed
# in REPNE/REPE string-operation tails and single-flag tests); like the
# predicate destination, one-bit operands occupy one byte of IR storage.
_COMPARISON_OPS_8616: dict[str, int] = {
    f"Iop_Cmp{relation}{bits}": bits
    for relation in ("EQ", "NE")
    for bits in (1, 8, 16, 32, 64)
} | {
    f"Iop_Cmp{relation}{bits}{signedness}": bits
    for relation in ("LT", "LE", "GT", "GE")
    for bits in (8, 16, 32, 64)
    for signedness in ("S", "U")
}

# Widening products have different operand/result widths and therefore must
# not enter the same-width scalar_binary_operation descriptor table.
_WIDENING_PRODUCT_BYTES_8616: dict[str, int] = {
    f"Iop_Mull{signedness}{bits}": bits // 8
    for signedness in ("S", "U")
    for bits in (8, 16, 32)
}


def _unknown_8616(detail: str) -> ScalarInstructionEffect8616:
    """One honest non-result: no effect evidence was established."""
    return ScalarInstructionEffect8616(
        ScalarInstructionEffectKind8616.UNKNOWN,
        ScalarInstructionClobber8616.UNKNOWN,
        detail,
    )


def _readable_scalar_source_8616(value: object) -> TypeGuard[IRValue]:
    """A typed scalar operand is a read, never an implicit second write.

    Decorations, displacements, and provenance belong to value-equality
    proofs, not to the register-effect decision: an unknown-provenance or
    displaced view still reads without writing another register. Only the
    storage class is checked — a CONST read must carry its literal.
    """
    return isinstance(value, IRValue) and (
        value.space in {MemSpace.TMP, MemSpace.REG, MemSpace.UNKNOWN}
        or (value.space is MemSpace.CONST and value.const is not None)
    )


def _closed_destination_8616(instruction: IRInstr) -> IRValue | None:
    """Return an explicit scalar TMP/REG destination, or refuse contradictions.

    A closed destination is exact storage: no displacement, index, decoration,
    or fabricated literal, and a positive width. TMPs retain producer identity;
    REGs retain their name and never carry a tmp's capture identity. An active
    computation cannot identify destination storage. The
    instruction width agrees with the declared destination width.
    """
    destination = instruction.dst
    if not isinstance(destination, IRValue):
        return None
    if destination.space not in {MemSpace.TMP, MemSpace.REG}:
        return None
    if destination.size <= 0:
        return None
    if destination.offset or destination.index is not None or destination.index_shift:
        return None
    if (destination.expr or destination.const is not None
            or destination.call_output is not None or destination.active_unary is not None):
        return None
    if destination.source_tmp is not None and destination.space is not MemSpace.TMP:
        return None
    if destination.space is MemSpace.TMP and destination.source_tmp is None:
        return None
    if destination.space is MemSpace.REG and destination.name is None:
        return None
    if instruction.size != destination.size:
        return None
    return destination


def _closed_write_8616(
    instruction: IRInstr, detail: str,
) -> ScalarInstructionEffect8616 | None:
    """Close an instruction whose only write is its validated destination."""
    destination = _closed_destination_8616(instruction)
    if destination is None:
        return None
    clobber = (
        ScalarInstructionClobber8616.DATA_REGISTER
        if destination.space is MemSpace.REG
        else ScalarInstructionClobber8616.NONE
    )
    return ScalarInstructionEffect8616(
        ScalarInstructionEffectKind8616.CLOSED_DESTINATION, clobber, detail,
    )


def _const_target_8616(value: object) -> TypeGuard[IRValue]:
    """Require an exact target literal, never a conflicting projected view."""
    if not isinstance(value, IRValue) or value.space is not MemSpace.CONST:
        return False
    if value.const is None or value.size <= 0:
        return False
    if value.offset or value.index is not None or value.index_shift:
        return False
    return (
        not value.expr and value.source_tmp is None
        and value.call_output is None and value.active_unary is None
    )


def _classify_mov_8616(instruction: IRInstr) -> ScalarInstructionEffect8616:
    """A MOV writes exactly its destination when the source is a scalar read."""
    if len(instruction.args) == 1 and _readable_scalar_source_8616(instruction.args[0]):
        effect = _closed_write_8616(instruction, "mov")
        if effect is not None:
            return effect
    return _unknown_8616("mov_shape")


def _classify_load_8616(instruction: IRInstr) -> ScalarInstructionEffect8616:
    """A LOAD writes exactly its destination when the operand is a typed address."""
    if len(instruction.args) == 1 and isinstance(instruction.args[0], IRAddress):
        effect = _closed_write_8616(instruction, "load")
        if effect is not None:
            return effect
    return _unknown_8616("load_shape")


def _classify_call_8616(instruction: IRInstr) -> ScalarInstructionEffect8616:
    """A CALL's register results and clobbers are never modeled here."""
    return _unknown_8616("call")


def _classify_cjmp_8616(instruction: IRInstr) -> ScalarInstructionEffect8616:
    """A proven conditional transfer rewrites IP and preserves data registers."""
    target = instruction.args[1] if len(instruction.args) == 2 else None
    if (
        instruction.dst is None
        and len(instruction.args) == 2
        and isinstance(instruction.args[0], IRCondition)
        and _const_target_8616(target)
    ):
        return ScalarInstructionEffect8616(
            ScalarInstructionEffectKind8616.INSTRUCTION_POINTER_WRITE,
            ScalarInstructionClobber8616.INSTRUCTION_POINTER,
            "cjmp",
            control_target=target.const,
        )
    return _unknown_8616("cjmp_shape")


def _classify_jmp_8616(instruction: IRInstr) -> ScalarInstructionEffect8616:
    """Close only a literal unconditional IP transfer with no data destination."""
    target = instruction.args[0] if len(instruction.args) == 1 else None
    if (instruction.dst is None and instruction.size == 0
            and _const_target_8616(target) and type(target.const) is int):
        return ScalarInstructionEffect8616(
            ScalarInstructionEffectKind8616.INSTRUCTION_POINTER_WRITE,
            ScalarInstructionClobber8616.INSTRUCTION_POINTER,
            "jmp", control_target=target.const,
        )
    return _unknown_8616("jmp_shape")


def _classify_nop_8616(instruction: IRInstr) -> ScalarInstructionEffect8616:
    """A proven no-effect instruction writes no register; unproven claims refuse.

    The honest closure writes nothing architectural, so it requires the same
    mark-bound provenance the census authenticates against the bound project —
    the shared ``no_effect_claim_shape_8616`` predicate: an ``Ist_IMark``
    origin with integer block/statement coordinates and no contradictory
    terminal or data-flow fields. A bare or decorated ``NOP`` shape without
    that provenance is a claim, not evidence — it stays UNKNOWN so a
    fabricated entry cannot erase a real instruction's effects.
    """
    if no_effect_claim_shape_8616(instruction):
        return ScalarInstructionEffect8616(
            ScalarInstructionEffectKind8616.NO_REGISTER_WRITE,
            ScalarInstructionClobber8616.NONE,
            "nop",
        )
    return _unknown_8616("nop_shape")


def _classify_store_8616(instruction: IRInstr) -> ScalarInstructionEffect8616:
    """A STORE writes memory only: it never writes an architectural register."""
    if (
        instruction.dst is None
        and len(instruction.args) == 2
        and isinstance(instruction.args[0], IRAddress)
        and _readable_scalar_source_8616(instruction.args[1])
    ):
        return ScalarInstructionEffect8616(
            ScalarInstructionEffectKind8616.NO_REGISTER_WRITE,
            ScalarInstructionClobber8616.MEMORY,
            "store",
        )
    return _unknown_8616("store_shape")


def _classify_comparison_8616(
    instruction: IRInstr,
) -> ScalarInstructionEffect8616 | None:
    """Close a pure integer comparison producing a one-byte predicate.

    The IR represents the 1-bit predicate in one byte: ``dst.size`` and the
    instruction size are 1 while both operands are typed reads of exactly the
    width encoded in the exact custom-emitter operation spelling. One-bit
    operand spellings share that same one-byte storage convention.
    """
    operand_bits = _COMPARISON_OPS_8616.get(instruction.op)
    if operand_bits is None or len(instruction.args) != 2:
        return None
    operand_bytes = max(1, operand_bits // 8)
    left, right = instruction.args
    if not (
        _readable_scalar_source_8616(left)
        and _readable_scalar_source_8616(right)
        and left.size == right.size == operand_bytes
    ):
        return _unknown_8616("compare_shape")
    destination = _closed_destination_8616(instruction)
    if destination is None or destination.size != 1:
        return _unknown_8616("compare_shape")
    return ScalarInstructionEffect8616(
        ScalarInstructionEffectKind8616.CLOSED_DESTINATION,
        (
            ScalarInstructionClobber8616.DATA_REGISTER
            if destination.space is MemSpace.REG
            else ScalarInstructionClobber8616.NONE
        ),
        "compare",
    )


def _binary_operands_valid_8616(
    operation: ScalarBinaryOp8616, args: tuple[IRAtom, ...],
) -> bool:
    """Both operands are typed reads whose widths match the descriptor.

    Data operands carry the operation width; shifts keep their right operand
    at an independent count width.
    """
    left, right = args
    if not (_readable_scalar_source_8616(left) and _readable_scalar_source_8616(right)):
        return False
    if left.size != operation.bits // 8:
        return False
    if operation.kind in {ScalarBinaryKind8616.SHL, ScalarBinaryKind8616.SHR}:
        return bool(right.size > 0)
    return bool(right.size == operation.bits // 8)


def _classify_binary_8616(
    instruction: IRInstr,
) -> ScalarInstructionEffect8616 | None:
    """Close a registered scalar binary op whose widths match its descriptor."""
    operation = scalar_binary_operation_8616(instruction.op)
    if operation is None or len(instruction.args) != 2:
        return None
    if operation.bits // 8 != instruction.size:
        return _unknown_8616("binary_width")
    if not _binary_operands_valid_8616(operation, instruction.args):
        return _unknown_8616("binary_shape")
    effect = _closed_write_8616(instruction, operation.kind.value)
    return effect if effect is not None else _unknown_8616("binary_shape")


def _classify_boolean_binary_8616(instruction: IRInstr) -> ScalarInstructionEffect8616 | None:
    """Close backend Boolean effects using the IR's one-byte predicate storage.

    These VEX one-bit operations are not eight-bit integer arithmetic. This
    closes writes only; it does not invent a Boolean value or constant theorem.
    """
    if instruction.op not in {"Iop_Xor1", "Iop_And1", "Iop_Or1"}:
        return None
    operands_closed = (len(instruction.args) == 2 and all(
        _readable_scalar_source_8616(value) and value.size == 1 for value in instruction.args
    ))
    if instruction.size != 1 or not operands_closed:
        return _unknown_8616("boolean_shape")
    effect = _closed_write_8616(instruction, "boolean")
    return effect if effect is not None else _unknown_8616("boolean_shape")


def _classify_widening_product_8616(
    instruction: IRInstr,
) -> ScalarInstructionEffect8616 | None:
    """Close a pure product's explicit double-width write, without proving its value."""
    operand_bytes = _WIDENING_PRODUCT_BYTES_8616.get(instruction.op)
    if operand_bytes is None:
        return None
    if instruction.size != 2 * operand_bytes or len(instruction.args) != 2:
        return _unknown_8616("widening_product_shape")
    if not all(
        _readable_scalar_source_8616(value) and value.size == operand_bytes
        for value in instruction.args
    ):
        return _unknown_8616("widening_product_shape")
    effect = _closed_write_8616(instruction, "widening_product")
    return effect if effect is not None else _unknown_8616("widening_product_shape")


_CLASSIFIERS_8616: dict[str, Callable[[IRInstr], ScalarInstructionEffect8616]] = {
    "MOV": _classify_mov_8616,
    "LOAD": _classify_load_8616,
    "CALL": _classify_call_8616,
    "CJMP": _classify_cjmp_8616,
    "JMP": _classify_jmp_8616,
    "STORE": _classify_store_8616,
    NO_EFFECT_INSTRUCTION_OP_8616: _classify_nop_8616,
}


def scalar_instruction_effect_8616(
    instruction: IRInstr,
) -> ScalarInstructionEffect8616:
    """Classify one typed instruction's register-effect closure.

    MOV/LOAD and registered ``scalar_binary_operation_8616`` descriptors are
    closed only under validated typed shapes whose widths agree with the
    operator. Exact integer comparisons are pure one-byte-destination
    operations. Widening products require a destination twice the operand
    width; effect closure does not establish a numeric product value.
    A valid STORE writes memory and no register; a valid CJMP
    writes IP explicitly rather than claiming "no register write". Literal
    JMP shapes likewise close their explicit IP transfer; indirect jumps stay
    unknown. CALL and
    every malformed or unsupported form remain UNKNOWN.
    """
    classifier = _CLASSIFIERS_8616.get(instruction.op)
    if classifier is not None:
        return classifier(instruction)
    for classify in (
        _classify_comparison_8616, _classify_binary_8616,
        _classify_boolean_binary_8616, _classify_widening_product_8616,
    ):
        effect = classify(instruction)
        if effect is not None:
            return effect
    return _unknown_8616("unsupported_op")
