# cython: language_level=3, infer_types=True
"""Layer: Analysis.

Responsibility: summarize SS frame accesses from typed IR artifacts.
Entry-frame proof must follow the last BP write before use; overwritten setup
candidates are neither live evidence nor conflicting alternatives.
Later contradictory BP access coordinates invalidate the published relation.
Captured register views retain their source temporary: trace that SSA value
instead of adding an old SP displacement to the current stack delta again.
Forbidden: inventing locals/args without segmented SS:BP/SP evidence.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import IRAddress, IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.frame_memory_accesses import frame_memory_accesses_8616
from inertia.ir.scalar_affine_contracts import ScalarAffineEntryRegister8616
from inertia.ir.scalar_affine_trace import trace_scalar_affine_expression_8616
from inertia.ir.ssa import build_x86_16_block_local_ssa
from inertia.ir.ssa_function import SSAFunctionArtifact, build_x86_16_ir_predecessor_map
from inertia.ir.ssa_memory_ranges import StackCoordinateAgreement8616, stack_coordinate_agreement_8616
import dataclasses
import operator

_FIRST_NEAR_ARGUMENT_OFFSET = 4

__all__ = [
    "BPFrameCoordinateEvidence8616",
    "FrameAccessArtifact",
    "FrameCoordinateStats8616",
    "FrameCoordinateStatus8616",
    "StackFrameSlot",
    "build_x86_16_ir_frame_access_artifact",
]


class FrameCoordinateStatus8616(StrEnum):
    """Typed state of the BP-to-entry-SP coordinate proof."""

    UNKNOWN = "unknown"
    PROVEN = "proven"
    CONFLICT = "conflict"


@dataclasses.dataclass(frozen=True, )
class FrameCoordinateStats8616:
    """Closed evidence accounting for one frame-coordinate proof."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every normalized relation has one outcome."""
        return (
            self.raw_fact_count >= self.normalized_fact_count
            and operator.eq(self.normalized_fact_count, self.classified_fact_count)
            and operator.eq(self.classified_fact_count, self.materialized_count + self.failure_count)
        )

    def to_dict(self) -> dict[str, cython.longlong]:
        """Return the mandatory five evidence counters."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclasses.dataclass(frozen=True, )
class BPFrameCoordinateEvidence8616:
    """Proven relation from machine BP to angr's entry-SP coordinate."""

    status: FrameCoordinateStatus8616 = FrameCoordinateStatus8616.UNKNOWN
    bp_entry_sp_delta: int | None = None
    detail: str = "no BP-relative stack access"
    stats: FrameCoordinateStats8616 = FrameCoordinateStats8616()

    @property
    def complete(self) -> cython.bint:
        """Return whether counters close and the typed state is coherent."""
        if not self.stats.complete:
            return False
        return operator.eq((self.status is FrameCoordinateStatus8616.PROVEN), isinstance(self.bp_entry_sp_delta, int))

    def to_dict(self) -> dict[str, object]:
        """Serialize the coordinate proof for diagnostics and gates."""
        return {
            "status": self.status.value,
            "bp_entry_sp_delta": self.bp_entry_sp_delta,
            "detail": self.detail,
            "stats": self.stats.to_dict(),
            "complete": self.complete,
        }


@dataclasses.dataclass(frozen=True, )
class StackFrameSlot:
    """Evidence-backed SS:BP/SP stack-frame access."""

    base: object
    offset: cython.longlong
    role: object
    size: cython.longlong

    def to_dict(self) -> dict[str, object]:
        """Serialize this stack-frame slot for diagnostics and artifacts."""
        return {
            "base": self.base,
            "offset": self.offset,
            "role": self.role,
            "size": self.size,
        }


@dataclasses.dataclass(frozen=True, )
class FrameAccessArtifact:
    """Summary of stack-frame accesses recovered from typed IR."""

    slots: tuple[StackFrameSlot, ...] = ()
    refusals: tuple[str, ...] = ()
    bp_coordinate: BPFrameCoordinateEvidence8616 = BPFrameCoordinateEvidence8616()

    def to_dict(self) -> dict[str, object]:
        """Serialize the frame-access artifact for diagnostics and artifacts."""
        return {
            "slots": [item.to_dict() for item in iter(self.slots)],
            "refusals": list(self.refusals),
            "bp_coordinate": self.bp_coordinate.to_dict(),
        }


@cython.ccall
def _slot_role(base: object, offset: cython.longlong) -> str:
    """Classify one exact frame slot without naming it."""
    if base == "bp":
        if offset >= _FIRST_NEAR_ARGUMENT_OFFSET:
            return "arg"
        if offset < 0:
            return "local"
        return "frame_meta"
    return "sp_relative"


@cython.ccall
def _writes_register_8616(instruction: IRInstr, register: object) -> cython.bint:
    """Return whether one typed instruction writes the exact register."""
    destination = instruction.dst
    return isinstance(destination, IRValue) and destination.space is MemSpace.REG and operator.eq(destination.name, register)


def _bp_access_8616(instruction: IRInstr) -> cython.bint:
    """Return whether one instruction accesses exact SS:BP storage."""
    return any(
        isinstance(argument, IRAddress) and argument.space is MemSpace.SS and argument.base == ("bp",)
        for argument in iter(instruction.args)
    )


@cython.ccall
def _sp_relative_value_8616(instruction: IRInstr) -> IRValue | None:
    """Return a direct SP read; captured temporaries require SSA provenance."""
    if instruction.op != "MOV" or len(instruction.args) != 1:
        return None
    source = instruction.args[0]
    if (
        isinstance(source, IRValue)
        and source.space is MemSpace.REG
        and source.name == "sp"
        and source.source_tmp is None
    ):
        return source
    return None


@cython.ccall
def _traced_entry_sp_delta_8616(ssa_artifact: SSAFunctionArtifact, index: cython.longlong) -> int | None:
    """Resolve indirect setup through exact entry-block SSA provenance."""
    expression: object
    root: object
    block = ssa_artifact.blocks[0]
    root = block.instrs[index].dst
    if root is None:
        return None
    trace = trace_scalar_affine_expression_8616(
        ssa_artifact, root, block_addr=block.addr,
        before_index=index + 1, allow_entry_registers=True,
    )
    expression = trace.expression
    if not trace.complete or expression is None or len(expression.terms) != 1:
        return None
    term = expression.terms[0]
    if not (
        isinstance(term.source, ScalarAffineEntryRegister8616)
        and term.source.register_name == "sp" and term.coefficient == 1
    ):
        return None
    return (expression.constant + 0x8000) % 0x10000 - 0x8000


@cython.ccall
def _reaching_bp_delta_8616(entry_block: IRBlock, ssa_artifact: SSAFunctionArtifact) -> tuple[int | None, cython.longlong]:
    """Follow setup until first BP use, retaining the last reaching definition."""
    recovered: object
    source: object
    index: object
    instruction: object
    sp_delta = 0
    sp_delta_known = True
    bp_delta: int | None = None
    bp_write_count = 0
    for index, instruction in enumerate(entry_block.instrs):
        if _bp_access_8616(instruction):
            break
        if _writes_register_8616(instruction, "sp"):
            source = _sp_relative_value_8616(instruction)
            if source is None or not sp_delta_known:
                recovered = _traced_entry_sp_delta_8616(ssa_artifact, index)
                sp_delta_known = recovered is not None
                if recovered is not None:
                    sp_delta = recovered
            else:
                sp_delta += source.offset
            continue
        if _writes_register_8616(instruction, "bp"):
            bp_write_count += 1
            source = _sp_relative_value_8616(instruction)
            bp_delta = (sp_delta + source.offset if source is not None and sp_delta_known
                        else _traced_entry_sp_delta_8616(ssa_artifact, index))
    return bp_delta, bp_write_count


def _build_bp_coordinate_evidence_8616(artifact: IRFunctionArtifact) -> BPFrameCoordinateEvidence8616:
    """Prove BP's entry-SP delta from typed register effects before first use."""
    bp_delta: object
    entry_block: object
    has_bp_access = any(_bp_access_8616(instruction) for block in iter(artifact.blocks) for instruction in iter(block.instrs))
    if not has_bp_access:
        return BPFrameCoordinateEvidence8616()

    entry_block = next((block for block in iter(artifact.blocks) if operator.eq(block.addr, artifact.function_addr)), None)
    if entry_block is None:
        stats = FrameCoordinateStats8616(1, 1, 1, 0, 1)
        return BPFrameCoordinateEvidence8616(
            detail="function entry block is unavailable",
            stats=stats,
        )

    predecessors = build_x86_16_ir_predecessor_map(artifact)
    if predecessors.get(entry_block.addr):
        return BPFrameCoordinateEvidence8616(
            detail="entry block has incoming CFG edges; entry-register origin is unproven",
            stats=FrameCoordinateStats8616(1, 1, 1, 0, 1),
        )

    coordinate_blocks = (
        build_x86_16_block_local_ssa(entry_block),
        *(build_x86_16_block_local_ssa(block) for block in iter(artifact.blocks)
          if operator.ne(block.addr, entry_block.addr)),
    )
    if stack_coordinate_agreement_8616(coordinate_blocks) is StackCoordinateAgreement8616.CONFLICT:
        return BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.CONFLICT,
            detail="captured BP accesses have contradictory frame coordinates",
            stats=FrameCoordinateStats8616(1, 1, 1, 0, 1),
        )
    # The scalar consumer requires a real entry-edge census. Keep all supplied
    # blocks and their exact predecessors; an omitted map is not an empty CFG.
    ssa_artifact = SSAFunctionArtifact(
        artifact.function_addr, coordinate_blocks, predecessor_map=predecessors,
    )

    bp_delta, bp_write_count = _reaching_bp_delta_8616(entry_block, ssa_artifact)
    raw_count = max(1, bp_write_count)
    if bp_delta is not None:
        stats = FrameCoordinateStats8616(raw_count, 1, 1, 1, 0)
        return BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=bp_delta,
            detail="the reaching typed BP write establishes a known entry-SP delta",
            stats=stats,
        )
    stats = FrameCoordinateStats8616(raw_count, 1, 1, 0, 1)
    return BPFrameCoordinateEvidence8616(
        status=FrameCoordinateStatus8616.UNKNOWN,
        detail="the reaching BP value has no proven entry-SP relation",
        stats=stats,
    )


def build_x86_16_ir_frame_access_artifact(artifact: IRFunctionArtifact) -> FrameAccessArtifact:
    """Build stack-frame access evidence from SS addresses in typed IR."""

    def _impl() -> FrameAccessArtifact:
        size: object
        value: object
        slots: dict[tuple[str, cython.longlong, cython.longlong], StackFrameSlot] = {}
        refusals: list[str] = []
        for value, size in frame_memory_accesses_8616(artifact):
            base = value.base[0] if len(value.base) == 1 else None
            if base not in {"bp", "sp"}:
                refusals.append("non_frame_ss_access")
                continue
            key = (base, value.offset, size)
            slots.setdefault(key, StackFrameSlot(base=base, offset=value.offset,
                                                role=_slot_role(base, value.offset), size=size))
        return FrameAccessArtifact(
            slots=tuple(sorted(tuple(slots.values()), key=lambda item: (item.base, item.offset, item.size))),
            refusals=tuple(sorted(tuple(set(refusals)))),
            bp_coordinate=_build_bp_coordinate_evidence_8616(artifact),
        )

    return _impl()
