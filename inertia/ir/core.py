# cython: language_level=3, infer_types=True
"""Core typed IR objects for values, addresses, conditions, and instructions.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import dataclasses
import typing
import cython

from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import TYPE_CHECKING

from .instruction_origin import IRInstructionOrigin8616
import operator
IRCallStackCoordinates8616 = typing.TypeVar("IRCallStackCoordinates8616")
IRScopedCallStackCoordinates8616 = typing.TypeVar("IRScopedCallStackCoordinates8616")

if TYPE_CHECKING:
    from .call_stack_coordinates import IRCallStackCoordinates8616
    from .scoped_call_stack_coordinates import (
        IRScopedCallStackCoordinates8616,
    )

__all__ = [
    "SEGMENTED_LOAD_ADDRESS_TAG_8616",
    "AddressStatus",
    "IRActiveUnary8616",
    "IRAddress",
    "IRAtom",
    "IRBinaryValue",
    "IRBlock",
    "IRCallOutputProvenance8616",
    "IRCallOutputShape8616",
    "IRCallStackEffect8616",
    "IRCondition",
    "IRFunctionArtifact",
    "IRInstr",
    "IRRefusal",
    "IRValue",
    "MemSpace",
    "SegmentOrigin",
    "is_stack_address_8616",
]

SEGMENTED_LOAD_ADDRESS_TAG_8616: str = "inertia_x86_16_segmented_load_address"


class MemSpace(Enum):
    """Segmented storage space for typed IR values and addresses."""

    REG = "reg"
    CS = "cs"
    DS = "ds"
    ES = "es"
    SS = "ss"
    CONST = "const"
    TMP = "tmp"
    UNKNOWN = "unknown"


class AddressStatus(Enum):
    """Confidence status for a recovered typed IR address."""

    STABLE = "stable"
    PROVISIONAL = "provisional"
    UNKNOWN = "unknown"


class SegmentOrigin(Enum):
    """Evidence source for an address segment choice."""

    PROVEN = "proven"
    DEFAULTED = "defaulted"
    UNKNOWN = "unknown"


class IRCallOutputShape8616(StrEnum):
    """Binary-proven register layout produced by one machine call."""

    AX = "ax"
    DX_AX = "dx_ax"


@dataclasses.dataclass(frozen=True, )
class IRCallOutputProvenance8616:
    """Exact call boundary that produced one retained register output."""

    callsite_addr: cython.longlong
    target_addr: cython.longlong
    shape: IRCallOutputShape8616

    def to_dict(self) -> dict[str, object]:
        """Serialize exact call-output identity for diagnostics and workers."""
        return {
            "callsite_addr": self.callsite_addr,
            "target_addr": self.target_addr,
            "shape": self.shape.value,
        }


@dataclasses.dataclass(frozen=True, )
class IRActiveUnary8616:
    """One active unary computation that still produces this value.

    ``op`` is the exact VEX operation name (``Iop_*``) and ``operand`` the
    already-converted typed input value — nested operations therefore keep
    their inner operation instead of collapsing into one provenance tag.
    ``result_bits`` is the authoritative VEX result width in *bits* so a
    one-bit result (``Iop_Not1``) is not widened to its byte storage.

    This evidence lives only on the view that must still apply the
    operation. A ``source_tmp``-pinned reference names the already
    computed producer result, so captured views never carry it; the
    producer instruction's operand retains the active computation.
    ``IRValue.expr`` remains the compatibility/provenance projection.
    """

    op: object
    operand: IRValue
    result_bits: cython.longlong

    def to_dict(self) -> dict[str, object]:
        """Serialize this active unary evidence for diagnostics."""
        return {
            "op": self.op,
            "operand": self.operand.to_dict(),
            "result_bits": self.result_bits,
        }


@dataclasses.dataclass(frozen=True, )
class IRValue:
    """Typed scalar or storage value with optional exact access provenance."""

    space: MemSpace
    name: object = None
    offset: cython.longlong = 0
    const: int | None = None
    size: cython.longlong = 0
    version: int | None = None
    expr: object = None
    index: IRValue | IRBinaryValue | None = None
    index_shift: cython.longlong = 0
    memory_access_size: int | None = None
    memory_access_insn: int | None = field(default=None, compare=False)
    source_tmp: int | None = field(default=None, compare=False)
    call_output: IRCallOutputProvenance8616 | None = None
    active_unary: IRActiveUnary8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR value for diagnostics and artifacts."""
        return {
            "kind": "value",
            "space": self.space.value,
            "name": self.name,
            "offset": self.offset,
            "const": self.const,
            "size": self.size,
            "version": self.version,
            "expr": self.expr,
            "index": None if self.index is None else self.index.to_dict(),
            "index_shift": self.index_shift,
            "memory_access_size": self.memory_access_size,
            "memory_access_insn": self.memory_access_insn,
            "source_tmp": self.source_tmp,
            "call_output": None if self.call_output is None else self.call_output.to_dict(),
            "active_unary": (
                None if self.active_unary is None else self.active_unary.to_dict()
            ),
        }


@dataclasses.dataclass(frozen=True, )
class IRBinaryValue:
    """Typed binary value expression whose operands retain storage identity."""

    op: object
    lhs: IRValue | IRBinaryValue
    rhs: IRValue | IRBinaryValue
    size: cython.longlong = 0

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed value expression for diagnostics and artifacts."""
        return {
            "kind": "binary_value",
            "op": self.op,
            "lhs": self.lhs.to_dict(),
            "rhs": self.rhs.to_dict(),
            "size": self.size,
        }


@dataclasses.dataclass(frozen=True, )
class IRAddress:
    """Typed segmented memory address recovered from instruction evidence."""

    space: MemSpace
    base: tuple[str, ...] = ()
    offset: cython.longlong = 0
    size: cython.longlong = 0
    status: AddressStatus = AddressStatus.UNKNOWN
    segment_origin: SegmentOrigin = SegmentOrigin.UNKNOWN
    expr: object = None
    version: int | None = None
    base_values: tuple[IRValue, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR address for diagnostics and artifacts."""
        return {
            "kind": "address",
            "space": self.space.value,
            "base": list(self.base),
            "offset": self.offset,
            "size": self.size,
            "status": self.status.value,
            "segment_origin": self.segment_origin.value,
            "expr": self.expr,
            "version": self.version,
            "base_values": [value.to_dict() for value in iter(self.base_values)],
        }


@dataclasses.dataclass(frozen=True, )
class IRCallStackEffect8616:
    """Typed stack storage and frame-register effects for one call boundary.

    ``bp_preserved`` proves the incoming BP word survives the callee. False is
    absence of that proof, not a claim that BP must change. Memory preservation
    alone never establishes the value of a register used to address that memory.
    ``stack_coordinates`` retains the independently evidenced per-call
    decomposition (callee purge, caller cleanup, return-frame width, argument
    top); ``net_stack_delta`` remains the owned caller-visible SP projection
    and a proven coordinate derives and validates it.
    """

    net_stack_delta: int | None = None
    preserved_ranges: tuple[IRAddress, ...] = ()
    escaped_ranges: tuple[IRAddress, ...] = ()
    complete: cython.bint = False
    bp_preserved: cython.bint = False
    stack_coordinates: IRCallStackCoordinates8616 | None = None
    scoped_coordinates: IRScopedCallStackCoordinates8616 | None = None

    def scoped_net_stack_delta_for(
        self, caller_scope: object, callee_scope: object,
    ) -> int | None:
        """Project the caller-visible delta under both authenticated scopes.

        The scoped carrier owns every check; this accessor adds nothing to
        ``current_net_stack_delta`` and never fabricates a universal value.
        """
        carrier: object
        carrier = self.scoped_coordinates
        if carrier is None:
            return None
        return carrier.net_sp_delta_for(caller_scope, callee_scope)

    @property
    def current_net_stack_delta(self) -> int | None:
        """Consume present coordinate authority without falling back to a guess."""
        coordinates: object
        coordinates = self.stack_coordinates
        if coordinates is None:
            return self.net_stack_delta
        if not coordinates.has_proven_sp_delta or operator.ne(coordinates.net_sp_delta, self.net_stack_delta):
            return None
        return self.net_stack_delta

    def preserves(self, address: IRAddress) -> cython.bint:
        """Require explicit preservation and no overlapping or unresolved escape."""
        current_delta: object
        # Imported here because the range predicate consumes this module's types.
        from .stack_range_overlap import stack_ranges_may_overlap_8616

        identity = (address.space, address.base, address.offset, address.size)
        preserved = {
            (item.space, item.base, item.offset, item.size) for item in iter(self.preserved_ranges)
        }
        escaped = any(stack_ranges_may_overlap_8616(address, item) for item in iter(self.escaped_ranges))
        current_delta = self.current_net_stack_delta
        coordinate_is_stable = address.base != ("sp",) or current_delta == 0
        return bool(
            self.complete and current_delta is not None and coordinate_is_stable
            and identity in preserved and not escaped
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize this call effect for diagnostics and clean workers."""
        return {
            "net_stack_delta": self.net_stack_delta,
            "current_net_stack_delta": self.current_net_stack_delta,
            "bp_preserved": self.bp_preserved,
            "preserved_ranges": [item.to_dict() for item in iter(self.preserved_ranges)],
            "escaped_ranges": [item.to_dict() for item in iter(self.escaped_ranges)],
            "complete": self.complete,
            "stack_coordinates": (
                None
                if self.stack_coordinates is None
                else self.stack_coordinates.to_dict()
            ),
            "scoped_coordinates": (
                None
                if self.scoped_coordinates is None
                else self.scoped_coordinates.to_dict()
            ),
        }


def is_stack_address_8616(addr: IRAddress) -> cython.bint:
    """Return whether an address is a proven or likely SS:BP/SP stack slot."""

    def _impl() -> cython.bint:
        """Classify stack addresses without lowering them.

        AGENTS rule: SS:BP+offset MUST become a stack slot, never fallback to memory.
        """
        if operator.ne(addr.space, MemSpace.SS):
            return False
        # Proven segment origin: explicit SS segment instruction
        if operator.eq(addr.segment_origin, SegmentOrigin.PROVEN):
            base_set = set(addr.base)
            if {"ss"} & base_set or {"bp"} & base_set or {"sp"} & base_set:
                return True
        # Expression-based: BP or SP appears in the expression tuple
        if addr.expr:
            expr_set = set(addr.expr)
            if {"bp", "sp", "ss"} & expr_set:
                return True
        # Defaulted segment with BP base hint
        if operator.eq(addr.segment_origin, SegmentOrigin.DEFAULTED) and operator.eq(addr.space, MemSpace.SS):
            base_set = set(addr.base)
            if {"bp"} & base_set:
                return True
        return False

    return _impl()


@dataclasses.dataclass(frozen=True, )
class IRCondition:
    """Typed branch or predicate condition in the IR layer."""

    op: object
    args: object
    expr: object = None
    width_bits: int | None = field(default=None, compare=False)

    @property
    def is_signed(self) -> cython.bint:
        """Return whether this condition uses signed ordering semantics."""
        return self.op in {"slt", "sle", "sgt", "sge"}

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR condition for diagnostics and artifacts."""
        return {
            "kind": "condition",
            "op": self.op,
            "args": [_atom_to_dict(arg) for arg in iter(self.args)],
            "expr": self.expr,
            "width_bits": self.width_bits,
        }


IRAtom = typing.TypeAliasType("IRAtom", IRValue | IRBinaryValue | IRAddress | IRCondition)


@cython.ccall
def _atom_to_dict(atom: IRAtom) -> object:
    """Serialize one owned typed atom without losing its metadata."""
    return atom.to_dict()


@dataclasses.dataclass(frozen=True, )
class IRInstr:
    """Typed instruction fact with destination, arguments, size, and address.

    ``CALL.dst`` is an input call target, not an output definition. Register
    results and clobbers require separate explicit semantic evidence; a CALL
    target use never proves a producer, return value or preservation effect.
    """

    op: object
    dst: IRValue | None
    args: object
    size: cython.longlong = 0
    addr: int | None = None
    call_stack_effect: IRCallStackEffect8616 | None = None
    origin: IRInstructionOrigin8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR instruction for diagnostics and artifacts."""
        return {
            "op": self.op,
            "dst": None if self.dst is None else self.dst.to_dict(),
            "args": [_atom_to_dict(arg) for arg in iter(self.args)],
            "size": self.size,
            "addr": self.addr,
            "call_stack_effect": (
                None if self.call_stack_effect is None else self.call_stack_effect.to_dict()
            ),
            "origin": None if self.origin is None else self.origin.to_dict(),
        }


@dataclasses.dataclass(frozen=True, )
class IRRefusal:
    """Structured reason why an IR fact could not be recovered."""

    kind: object
    detail: object
    block_addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this IR refusal for diagnostics and artifacts."""
        return {
            "kind": self.kind,
            "detail": self.detail,
            "block_addr": self.block_addr,
        }


@dataclasses.dataclass(frozen=True, )
class IRBlock:
    """Typed IR block with instructions, refusals, and successor addresses."""

    addr: cython.longlong
    instrs: tuple[IRInstr, ...] = ()
    refusals: tuple[IRRefusal, ...] = ()
    successor_addrs: tuple[cython.longlong, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR block for diagnostics and artifacts."""
        return {
            "addr": self.addr,
            "instrs": [instr.to_dict() for instr in iter(self.instrs)],
            "refusals": [item.to_dict() for item in iter(self.refusals)],
            "successor_addrs": list(self.successor_addrs),
        }


# The split artifact imports IRBlock/IRRefusal, so its compatibility re-export is late.
from .function_artifact import IRFunctionArtifact  # noqa: E402
