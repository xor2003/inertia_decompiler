"""Typed no-effect instruction evidence bound to exact decoded native bytes.

Layer: IR.
Responsibility: bridge one VEX instruction mark whose lifted statement span
contained zero statements to an explicit typed no-effect IR instruction that
preserves its frontend instruction head. Evidence is emitted only when the
lifter's mark has complete integer provenance and the exact native bytes at
the marked extent are the canonical x86 NOP encoding; every other
empty span stays uncovered so the instruction census, block refusals, and
effect gates keep refusing unsupported, lost, faulting, control, or unknown
instructions. Missing IR is never itself evidence of no effect.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.

Census-side authentication re-derives every claim from the bound project's
decoded block: the decoded instruction extent, the exact native bytes, an
exact-byte relift for ``Ist_IMark`` statement identity and span emptiness,
and the boundary's own fallthrough edges for a block-final mark. An emitted
or forged ``NOP`` instruction whose artifact-carried provenance disagrees
with any bound fact is refused; artifact claims alone are never evidence.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol, cast

import pyvex
from pyvex.errors import LiftingException, PyVEXError

from ..frontend_function_boundary import ExactFunctionRangeBoundary8616
from .condition_cache_relift_cache import ConditionReliftArtifactCache8616, ConditionReliftCacheRequest8616
from .condition_lift_capture import isolated_condition_lift_session_8616
from .core import IRInstr
from .instruction_origin import vex_imark_origin_8616

__all__ = [
    "NO_EFFECT_INSTRUCTION_OP_8616",
    "BoundNoEffectBlock8616",
    "LiftedNoEffectMark8616",
    "bound_no_effect_block_8616",
    "bound_no_effect_instr_8616",
    "lifted_no_effect_instr_8616",
    "no_effect_claim_shape_8616",
    "terminal_no_effect_instr_8616",
]

# A decoded x86 ``xchg ax,ax`` / NOP has no architectural effect only for the
# documented operand-size (0x66) and address-size (0x67) prefix family. LOCK
# (0xF0) raises #UD on a non-memory instruction — a faulting effect, never a
# no-effect instruction. REP/REPE prefixes change the instruction identity
# (``F3 90`` is the architected PAUSE hint, not NOP), and segment-override
# prefixes are unsupported here: those encodings stay honest refusals rather
# than claimed equivalences.
_NOP_PREFIX_BYTES_8616: frozenset[int] = frozenset({0x66, 0x67})
_NOP_OPCODE_8616 = 0x90


class _NativeBlockBoundary8616(Protocol):
    """Minimal angr block surface exposing lifted byte and extent facts."""

    addr: object
    size: object
    bytes: object


class _CapstoneInsnBoundary8616(Protocol):
    """Minimal decoded-instruction surface for bound extent facts."""

    address: object
    size: object


class _CapstoneOwnerBoundary8616(Protocol):
    """Minimal block surface exposing the decoded instruction inventory."""

    capstone: object


class _CapstoneViewBoundary8616(Protocol):
    """Minimal capstone view surface listing decoded instructions."""

    insns: object


class _VexMarkBoundary8616(Protocol):
    """Minimal pyvex statement surface for instruction-mark authentication."""

    tag: object
    addr: object
    delta: object
    len: object


class _LiftedBlockBoundary8616(Protocol):
    """Minimal pyvex IRSB surface consumed by census authentication."""

    statements: object
    jumpkind: object
    next: object


class _ProjectArchBoundary8616(Protocol):
    """Minimal project surface exposing the bound architecture."""

    arch: object


class _LoaderMemoryBoundary8616(Protocol):
    """Minimal loader-memory surface for exact current-byte reads."""

    def load(self, address: int, size: int) -> object:
        """Read up to ``size`` current native bytes at ``address``."""
        ...


class _ProjectLoaderBoundary8616(Protocol):
    """Minimal project surface exposing the bound loader image."""

    loader: _LoaderMemoryBoundary8616


class _LoaderBoundarySurface8616(Protocol):
    """Minimal loader surface exposing the memory view."""

    memory: _LoaderMemoryBoundary8616


def _external_int_8616(value: object) -> int:
    """Coerce external angr integer-like values without owning their type."""
    return int(cast(Any, value))


def _block_addr_8616(block: object) -> int | None:
    """Return the loader-linear base from the angr block boundary."""
    try:
        addr = _external_int_8616(cast(_NativeBlockBoundary8616, block).addr)
    except (AttributeError, TypeError, ValueError):
        return None
    return addr if type(addr) is int and addr >= 0 else None


def _block_size_8616(block: object) -> int | None:
    """Return the decoded byte size from the angr block boundary."""
    try:
        size = _external_int_8616(cast(_NativeBlockBoundary8616, block).size)
    except (AttributeError, TypeError, ValueError):
        return None
    return size if type(size) is int and size >= 0 else None


def _block_bytes_8616(block: object) -> bytes | None:
    """Return the exact lifted byte string from the angr block boundary."""
    try:
        data = cast(_NativeBlockBoundary8616, block).bytes
    except AttributeError:
        return None
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    return None


def _block_instruction_encoding_8616(
    block: object,
    instruction_addr: int,
    instruction_size: int,
) -> bytes | None:
    """Slice the exact native bytes the lifter decoded at one marked extent.

    The marked instruction must sit inside the lifted byte string at its own
    loader-linear offset. A missing or inconsistent block extent means the
    bytes cannot bind the mark, so the caller keeps refusing.
    """
    block_addr = _block_addr_8616(block)
    block_size = _block_size_8616(block)
    data = _block_bytes_8616(block)
    if block_addr is None or block_size is None or data is None:
        return None
    if len(data) != block_size:
        return None
    offset = instruction_addr - block_addr
    if offset < 0 or instruction_size <= 0 or offset + instruction_size > block_size:
        return None
    return data[offset : offset + instruction_size]


def _block_instruction_extents_8616(
    block: object,
    block_addr: int,
    block_size: int,
) -> dict[int, int] | None:
    """Return decoded head→extent pairs, or no evidence when incomplete."""
    try:
        insns = cast(_CapstoneViewBoundary8616, cast(
            _CapstoneOwnerBoundary8616, block).capstone).insns
        instructions = tuple(cast(Iterable[object], insns))
    except (AttributeError, TypeError):
        return None
    if not instructions:
        return None
    extents: dict[int, int] = {}
    for instruction in instructions:
        boundary = cast(_CapstoneInsnBoundary8616, instruction)
        try:
            head = _external_int_8616(boundary.address)
            extent = _external_int_8616(boundary.size)
        except (TypeError, ValueError):
            return None
        in_bounds = (
            type(head) is int
            and type(extent) is int
            and extent > 0
            and block_addr <= head
            and head + extent <= block_addr + block_size
        )
        if not in_bounds or head in extents:
            return None
        extents[head] = extent
    return extents


def _is_nop_encoding_8616(encoding: bytes) -> bool:
    """Return whether the exact encoding is the canonical x86 NOP family.

    Only a final ``0x90`` (``xchg ax,ax``/NOP) preceded exclusively by
    operand-size/address-size prefix bytes qualifies. Any other opcode —
    including HLT, WAIT, PAUSE, undefined encodings, or prefix forms that can
    fault — is not no-effect.
    """
    if not encoding or encoding[-1] != _NOP_OPCODE_8616:
        return False
    return all(byte in _NOP_PREFIX_BYTES_8616 for byte in encoding[:-1])


@dataclass(frozen=True, slots=True)
class LiftedNoEffectMark8616:
    """One observed empty VEX statement span at a decoded instruction mark.

    ``statement_index`` is the IMark's exact position in the block's statement
    list — the source coordinate the emitted instruction's origin retains.
    ``next_addr`` is the following decoded instruction head inside the same
    block, or ``None`` when the mark ends the block's statement list and the
    caller must prove the boring-fallthrough tail instead.
    """

    statement_index: int
    addr: int
    size: int
    next_addr: int | None = None


NO_EFFECT_INSTRUCTION_OP_8616: str = "NOP"


def _valid_mark_facts_8616(mark: LiftedNoEffectMark8616) -> bool:
    """Require exact integer head, width, and source coordinate for a mark."""
    for value, minimum in (
        (mark.statement_index, 0),
        (mark.addr, 0),
        (mark.size, 1),
    ):
        if type(value) is not int or value < minimum:
            return False
    return True


def lifted_no_effect_instr_8616(
    block: object,
    mark: LiftedNoEffectMark8616,
) -> IRInstr | None:
    """Emit a source-bound no-effect instruction for one proven empty span.

    Every binding is required: integer head and positive decoded width from
    the lifter's mark, a contiguous following head when one exists, and the
    marked extent's exact bytes matching the canonical NOP encoding. The
    emitted instruction carries IMark-statement provenance so the census can
    distinguish this evidence from a fabricated bare ``NOP`` shape.
    """
    if not _valid_mark_facts_8616(mark):
        return None
    if mark.next_addr is not None and (
        type(mark.next_addr) is not int or mark.next_addr != mark.addr + mark.size
    ):
        return None
    encoding = _block_instruction_encoding_8616(block, mark.addr, mark.size)
    if encoding is None or not _is_nop_encoding_8616(encoding):
        return None
    block_addr = _block_addr_8616(block)
    if block_addr is None:
        return None
    return IRInstr(
        op=NO_EFFECT_INSTRUCTION_OP_8616,
        dst=None,
        args=(),
        size=0,
        addr=mark.addr,
        origin=vex_imark_origin_8616(
            block_addr=block_addr,
            statement_index=mark.statement_index,
        ),
    )


def terminal_no_effect_instr_8616(
    block: object,
    mark: LiftedNoEffectMark8616,
    *,
    jumpkind: str,
    next_const: int | None,
) -> IRInstr | None:
    """Emit tail no-effect evidence only for a proven boring fallthrough.

    A block-final mark has no following IMark to bound its span, so the
    block's own transfer must prove the instruction simply falls through: the
    lift stayed ``Ijk_Boring`` and the constant ``next`` equals the mark's
    sequential next head. A symbolic or differently-jumped tail, a call, a
    return, or a decode fault is a control effect owned by other evidence —
    it never earns a no-effect instruction here.
    """
    if mark.next_addr is not None or jumpkind != "Ijk_Boring":
        return None
    if next_const is None or next_const != mark.addr + mark.size:
        return None
    return lifted_no_effect_instr_8616(block, mark)


def _mark_head_8616(statement: object) -> int | None:
    """Return the exact decoded head carried by a relifted IMark statement."""
    boundary = cast(_VexMarkBoundary8616, statement)
    try:
        head = _external_int_8616(boundary.addr) + _external_int_8616(boundary.delta)
    except (AttributeError, TypeError, ValueError):
        return None
    return head if type(head) is int and head >= 0 else None


def _mark_extent_8616(statement: object) -> int | None:
    """Return the decoded byte width carried by a relifted IMark statement."""
    try:
        extent = _external_int_8616(cast(_VexMarkBoundary8616, statement).len)
    except (AttributeError, TypeError, ValueError):
        return None
    return extent if type(extent) is int and extent > 0 else None


def _statement_tag_8616(statement: object) -> str:
    """Return a pyvex statement tag, or ``""`` for an unreadable boundary."""
    try:
        return str(cast(_VexMarkBoundary8616, statement).tag)
    except AttributeError:
        return ""


class _VexExprConst8616(Protocol):
    """Minimal ``Iex_Const`` wrapper surface exposing the child constant."""

    con: object


class _VexConstValue8616(Protocol):
    """Minimal pyvex constant surface exposing the literal value."""

    value: object


def _lifted_next_const_8616(expr: object | None) -> int | None:
    """Return the literal carried by a block ``next`` expression, or none."""
    if expr is None:
        return None
    try:
        con = cast(_VexExprConst8616, expr).con
    except AttributeError:
        con = None
    if con is not None:
        try:
            return _external_int_8616(cast(_VexConstValue8616, con).value)
        except (AttributeError, TypeError, ValueError):
            return None
    try:
        return _external_int_8616(cast(_VexConstValue8616, expr).value)
    except (AttributeError, TypeError, ValueError):
        return None


def _current_block_bytes_8616(
    project: object,
    block_addr: int,
    block_size: int,
) -> bytes | None:
    """Return the bound project's current native bytes for one exact extent.

    ``None`` is the honest non-result: no loader memory surface, an
    unreadable range, or a short read. A retained claim evaluated against
    bytes the project no longer holds is stale evidence and must refuse.
    """
    try:
        loader = cast(_ProjectLoaderBoundary8616, project).loader
        memory = cast(_LoaderBoundarySurface8616, loader).memory
        data = memory.load(block_addr, block_size)
    except (AttributeError, TypeError, ValueError, KeyError):
        return None
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    current = bytes(data)
    return current if len(current) == block_size else None


@dataclass(frozen=True, slots=True)
class _NativeMark8616:
    """Immutable source coordinates of one native instruction mark."""

    head: int | None
    extent: int | None


@dataclass(frozen=True, slots=True)
class _NativeLiftFacts8616:
    """Only immutable mark and transfer facts; never retain mutable VEX IR."""

    statements: tuple[_NativeMark8616 | None, ...]
    jumpkind: str
    next_const: int | None


_NO_EFFECT_RELIFT_CACHE_8616 = ConditionReliftArtifactCache8616[_NativeLiftFacts8616](max_entries=16)
_MAX_CACHED_CODE_BYTES_8616 = 4096
_MAX_CACHED_STATEMENTS_8616 = 2048


def _relift_bound_block_8616(
    arch: object,
    block_addr: int,
    code: bytes,
) -> _NativeLiftFacts8616 | None:
    """Relift one bound block's exact bytes for statement-level mark facts.

    This is the same exact-byte direct lift used by the condition-relift
    owner: ``pyvex.lift`` over the retained decoded bytes under the bound
    architecture at ``opt_level=0`` reproduces the statement list the import
    observed. ``None`` is the honest non-result for a lift failure or an
    unreadable IRSB surface.
    """
    request = ConditionReliftCacheRequest8616(
        ((block_addr, len(code), code),), frozenset(),
    )
    cacheable = len(code) <= _MAX_CACHED_CODE_BYTES_8616
    if cacheable:
        cached = _NO_EFFECT_RELIFT_CACHE_8616.lookup(arch, request)
        if cached is not None:
            return cached
    try:
        with isolated_condition_lift_session_8616():
            lifted = pyvex.lift(code, block_addr, arch, max_bytes=len(code), opt_level=0)
    except (LiftingException, PyVEXError):
        return None
    boundary_lift = cast(_LiftedBlockBoundary8616, lifted)
    try:
        statements = tuple(cast(Iterable[object], boundary_lift.statements))
        jumpkind = str(boundary_lift.jumpkind)
    except (AttributeError, TypeError):
        return None
    try:
        next_expr = boundary_lift.next
    except AttributeError:
        next_expr = None
    facts = _NativeLiftFacts8616(
        tuple(
            _NativeMark8616(_mark_head_8616(stmt), _mark_extent_8616(stmt))
            if _statement_tag_8616(stmt) == "Ist_IMark" else None
            for stmt in statements
        ),
        jumpkind,
        _lifted_next_const_8616(next_expr),
    )
    if cacheable and len(statements) <= _MAX_CACHED_STATEMENTS_8616:
        _NO_EFFECT_RELIFT_CACHE_8616.publish(arch, request, facts)
    return facts


@dataclass(frozen=True, slots=True)
class BoundNoEffectBlock8616:
    """Bound-project evidence authenticating census NOP claims on one block.

    Every fact derives from the boundary's retained decoded block *and* the
    project's current loader bytes — never from artifact-carried claims: the
    decoded instruction extents, the exact native bytes (proven identical to
    the currently mapped bytes), one exact-byte relift whose statements carry
    ``Ist_IMark`` identity, the block's terminal kind and constant ``next``
    when boring, and the boundary's own outgoing edges. Exact immutable lift
    facts may be reused from a fixed-capacity architecture-aware cache; current
    bytes, decoded extents and outgoing edges are checked on every evaluation.
    """

    block_addr: int
    instruction_extents: dict[int, int]
    code: bytes
    statements: tuple[_NativeMark8616 | None, ...]
    jumpkind: str
    next_const: int | None
    fallthrough_targets: frozenset[int]


def bound_no_effect_block_8616(
    boundary: ExactFunctionRangeBoundary8616,
    block_addr: int,
) -> BoundNoEffectBlock8616 | None:
    """Collect bound-project authentication facts for one census block.

    ``None`` is the honest non-result: the boundary has no unique decoded
    block at this address, its byte/extent evidence is incomplete, the
    project's current loader bytes no longer equal the retained decoded
    bytes (native mutation makes every derived fact stale), the project
    exposes no architecture, or the exact-byte relift failed. Every census
    NOP claim against a missing context refuses.
    """
    if type(block_addr) is not int or block_addr < 0:
        return None
    matches = [
        block
        for block in boundary.blocks
        if _block_addr_8616(block) == block_addr
    ]
    if len(matches) != 1:
        return None
    block = matches[0]
    block_size = _block_size_8616(block)
    code = _block_bytes_8616(block)
    if block_size is None or block_size <= 0 or code is None or len(code) != block_size:
        return None
    extents = _block_instruction_extents_8616(block, block_addr, block_size)
    if not extents:
        return None
    try:
        arch = cast(_ProjectArchBoundary8616, boundary.project).arch
    except AttributeError:
        return None
    current = _current_block_bytes_8616(boundary.project, block_addr, block_size)
    if current is None or current != code:
        return None
    relifted = _relift_bound_block_8616(arch, block_addr, code)
    if relifted is None:
        return None
    return BoundNoEffectBlock8616(
        block_addr=block_addr,
        instruction_extents=extents,
        code=code,
        statements=relifted.statements,
        jumpkind=relifted.jumpkind,
        next_const=relifted.next_const,
        fallthrough_targets=frozenset(
            target
            for source, target in boundary.successor_edges
            if source == block_addr
        ),
    )


def no_effect_claim_shape_8616(instruction: IRInstr) -> bool:
    """Return whether an instruction carries the exact no-effect claim shape.

    This is the single per-instruction predicate every consumer shares: the
    ``NOP`` op with no destination, operands, or data width, an integer head,
    and a mark-bound origin — ``is_instruction_mark`` set with integer block
    and statement coordinates and no contradictory terminal or data-flow
    fields. It asserts provenance shape only; block-level binding to decoded
    extents, native bytes, and statement identity is owned by
    ``bound_no_effect_instr_8616``.
    """
    origin = instruction.origin
    if (
        instruction.op != NO_EFFECT_INSTRUCTION_OP_8616
        or instruction.dst is not None
        or instruction.args
        or instruction.size != 0
        or type(instruction.addr) is not int
    ):
        return False
    if (
        origin is None
        or not origin.is_instruction_mark
        or origin.is_block_next
        or origin.address_tmp is not None
        or origin.block_next_tmp is not None
    ):
        return False
    return bool(
        type(origin.block_addr) is int
        and origin.block_addr >= 0
        and type(origin.statement_index) is int
        and origin.statement_index >= 0
    )


def bound_no_effect_instr_8616(
    context: BoundNoEffectBlock8616,
    instruction: IRInstr,
) -> bool:
    """Authenticate one census NOP claim against bound-project block facts.

    The claim is accepted only when every bound fact agrees: the exact
    no-effect claim shape, the origin's block coordinate equal to this bound
    block, the claimed address at a real decoded instruction extent, the
    marked native bytes matching the canonical NOP encoding, the relifted
    statement at ``statement_index`` being an ``Ist_IMark`` at the claimed
    head and width, and a proven-empty span — either an immediately following
    IMark at the contiguous next decoded head, or a block tail whose lift
    stayed ``Ijk_Boring`` with a constant ``next`` fallthrough the bound
    boundary records as a real edge.
    """
    address = instruction.addr
    if not no_effect_claim_shape_8616(instruction) or address is None:
        return False
    origin = instruction.origin
    if origin is None or origin.block_addr != context.block_addr:
        return False
    extent = context.instruction_extents.get(address)
    if extent is None:
        return False
    offset = address - context.block_addr
    if not _is_nop_encoding_8616(context.code[offset : offset + extent]):
        return False
    index = origin.statement_index
    if index >= len(context.statements):
        return False
    mark = context.statements[index]
    if mark is None:
        return False
    if mark.head != address or mark.extent != extent:
        return False
    next_head = address + extent
    if index + 1 < len(context.statements):
        follower = context.statements[index + 1]
        return bool(
            follower is not None
            and follower.head == next_head
            and next_head in context.instruction_extents
        )
    return bool(
        context.jumpkind == "Ijk_Boring"
        and context.next_const == next_head
        and next_head in context.fallthrough_targets
    )
