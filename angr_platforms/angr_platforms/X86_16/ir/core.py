"""Core typed IR objects for values, addresses, conditions, and instructions.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, StrEnum

from .instruction_origin import IRInstructionOrigin8616

__all__ = [
    "SEGMENTED_LOAD_ADDRESS_TAG_8616",
    "AddressStatus",
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


@dataclass(frozen=True, slots=True)
class IRCallOutputProvenance8616:
    """Exact call boundary that produced one retained register output."""

    callsite_addr: int
    target_addr: int
    shape: IRCallOutputShape8616

    def to_dict(self) -> dict[str, object]:
        """Serialize exact call-output identity for diagnostics and workers."""
        return {
            "callsite_addr": self.callsite_addr,
            "target_addr": self.target_addr,
            "shape": self.shape.value,
        }


@dataclass(frozen=True, slots=True)
class IRValue:
    """Typed scalar or storage value with optional exact access provenance."""

    space: MemSpace
    name: str | None = None
    offset: int = 0
    const: int | None = None
    size: int = 0
    version: int | None = None
    expr: tuple[str, ...] | None = None
    index: IRValue | IRBinaryValue | None = None
    index_shift: int = 0
    memory_access_size: int | None = None
    memory_access_insn: int | None = field(default=None, compare=False)
    source_tmp: int | None = field(default=None, compare=False)
    call_output: IRCallOutputProvenance8616 | None = None

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
        }


@dataclass(frozen=True, slots=True)
class IRBinaryValue:
    """Typed binary value expression whose operands retain storage identity."""

    op: str
    lhs: IRValue | IRBinaryValue
    rhs: IRValue | IRBinaryValue
    size: int = 0

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed value expression for diagnostics and artifacts."""
        return {
            "kind": "binary_value",
            "op": self.op,
            "lhs": self.lhs.to_dict(),
            "rhs": self.rhs.to_dict(),
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class IRAddress:
    """Typed segmented memory address recovered from instruction evidence."""

    space: MemSpace
    base: tuple[str, ...] = ()
    offset: int = 0
    size: int = 0
    status: AddressStatus = AddressStatus.UNKNOWN
    segment_origin: SegmentOrigin = SegmentOrigin.UNKNOWN
    expr: tuple[str, ...] | None = None
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
            "base_values": [value.to_dict() for value in self.base_values],
        }


@dataclass(frozen=True, slots=True)
class IRCallStackEffect8616:
    """Typed stack storage and frame-register effects for one call boundary.

    ``bp_preserved`` proves the incoming BP word survives the callee. False is
    absence of that proof, not a claim that BP must change. Memory preservation
    alone never establishes the value of a register used to address that memory.
    """

    net_stack_delta: int | None = None
    preserved_ranges: tuple[IRAddress, ...] = ()
    escaped_ranges: tuple[IRAddress, ...] = ()
    complete: bool = False
    bp_preserved: bool = False

    def preserves(self, address: IRAddress) -> bool:
        """Require explicit preservation and no overlapping or unresolved escape."""
        # Imported here because the range predicate consumes this module's types.
        from .stack_range_overlap import stack_ranges_may_overlap_8616

        identity = (address.space, address.base, address.offset, address.size)
        preserved = {
            (item.space, item.base, item.offset, item.size) for item in self.preserved_ranges
        }
        escaped = any(stack_ranges_may_overlap_8616(address, item) for item in self.escaped_ranges)
        coordinate_is_stable = address.base != ("sp",) or self.net_stack_delta == 0
        return bool(
            self.complete and self.net_stack_delta is not None and coordinate_is_stable
            and identity in preserved and not escaped
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize this call effect for diagnostics and clean workers."""
        return {
            "net_stack_delta": self.net_stack_delta,
            "bp_preserved": self.bp_preserved,
            "preserved_ranges": [item.to_dict() for item in self.preserved_ranges],
            "escaped_ranges": [item.to_dict() for item in self.escaped_ranges],
            "complete": self.complete,
        }


def is_stack_address_8616(addr: IRAddress) -> bool:
    """Return whether an address is a proven or likely SS:BP/SP stack slot."""

    def _impl() -> bool:
        """Classify stack addresses without lowering them.

        AGENTS rule: SS:BP+offset MUST become a stack slot, never fallback to memory.
        """
        if addr.space != MemSpace.SS:
            return False
        # Proven segment origin: explicit SS segment instruction
        if addr.segment_origin == SegmentOrigin.PROVEN:
            base_set = set(addr.base)
            if {"ss"} & base_set or {"bp"} & base_set or {"sp"} & base_set:
                return True
        # Expression-based: BP or SP appears in the expression tuple
        if addr.expr:
            expr_set = set(addr.expr)
            if {"bp", "sp", "ss"} & expr_set:
                return True
        # Defaulted segment with BP base hint
        if addr.segment_origin == SegmentOrigin.DEFAULTED and addr.space == MemSpace.SS:
            base_set = set(addr.base)
            if {"bp"} & base_set:
                return True
        return False

    return _impl()


@dataclass(frozen=True, slots=True)
class IRCondition:
    """Typed branch or predicate condition in the IR layer."""

    op: str
    args: tuple[IRAtom, ...]
    expr: tuple[str, ...] | None = None
    width_bits: int | None = field(default=None, compare=False)

    @property
    def is_signed(self) -> bool:
        """Return whether this condition uses signed ordering semantics."""
        return self.op in {"slt", "sle", "sgt", "sge"}

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR condition for diagnostics and artifacts."""
        return {
            "kind": "condition",
            "op": self.op,
            "args": [_atom_to_dict(arg) for arg in self.args],
            "expr": self.expr,
            "width_bits": self.width_bits,
        }


type IRAtom = IRValue | IRBinaryValue | IRAddress | IRCondition


def _atom_to_dict(atom: IRAtom) -> dict[str, object]:
    return atom.to_dict()


@dataclass(frozen=True, slots=True)
class IRInstr:
    """Typed instruction fact with destination, arguments, size, and address."""

    op: str
    dst: IRValue | None
    args: tuple[IRAtom, ...]
    size: int = 0
    addr: int | None = None
    call_stack_effect: IRCallStackEffect8616 | None = None
    origin: IRInstructionOrigin8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR instruction for diagnostics and artifacts."""
        return {
            "op": self.op,
            "dst": None if self.dst is None else self.dst.to_dict(),
            "args": [_atom_to_dict(arg) for arg in self.args],
            "size": self.size,
            "addr": self.addr,
            "call_stack_effect": (
                None if self.call_stack_effect is None else self.call_stack_effect.to_dict()
            ),
            "origin": None if self.origin is None else self.origin.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class IRRefusal:
    """Structured reason why an IR fact could not be recovered."""

    kind: str
    detail: str
    block_addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this IR refusal for diagnostics and artifacts."""
        return {
            "kind": self.kind,
            "detail": self.detail,
            "block_addr": self.block_addr,
        }


@dataclass(frozen=True, slots=True)
class IRBlock:
    """Typed IR block with instructions, refusals, and successor addresses."""

    addr: int
    instrs: tuple[IRInstr, ...] = ()
    refusals: tuple[IRRefusal, ...] = ()
    successor_addrs: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR block for diagnostics and artifacts."""
        return {
            "addr": self.addr,
            "instrs": [instr.to_dict() for instr in self.instrs],
            "refusals": [item.to_dict() for item in self.refusals],
            "successor_addrs": list(self.successor_addrs),
        }


# The split artifact imports IRBlock/IRRefusal, so its compatibility re-export is late.
from .function_artifact import IRFunctionArtifact  # noqa: E402
