"""Per-path proven-write byte overlay for the real-mode invocation census.

Layer: IR (invocation/control proof).
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.

Responsibility: provide the single path-associated memory lattice shared by
the raw-effect census (``real16_invocation_domain``) and the known-bits
edge-feasibility interpreter (``real16_edge_feasibility8616``). Memory
writes are path facts exactly like register facts: they travel inside the
per-block abstract state, join must-style at CFG merges, invalidate under
loop fixpoint re-meets, and transport across an admitted leaf-callee call
coherently with the register state. Census visitation order is never used
as memory execution order — a byte is proven only when every contributing
path agrees on it.

The union-of-spans ledger this replaces still exists nowhere in this
lattice: a span union answered "some path may have written here" for
guards, but could never answer "every path wrote the same byte". The
overlay below keeps both questions distinct — ``known`` is the must-write
answer, ``unknown`` the may-write evidence, ``tainted`` the unbounded
boundary.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .core import IRAddress, IRBinaryValue, IRInstr, IRValue, MemSpace
from .real16_initial_memory8616 import InvocationInitialMemory8616

#: Linear-address formation from a proven 16-bit segment base.
SEGMENT_SHIFT_8616: int = 4

# The effective-address segment bases this domain can resolve: SS, DS and
# ES are proven from their named register lanes. Every other address space
# is either a bare absolute offset (``MemSpace.UNKNOWN`` with the
# ``absolute_const`` provenance, handled by the store evaluator) or an
# unproven span.
SEGMENT_BASE_NAME_8616: dict[MemSpace, str] = {
    MemSpace.SS: "ss",
    MemSpace.DS: "ds",
    MemSpace.ES: "es",
}


@dataclass(slots=True)
class PathMemory8616:
    """One path position's proven memory-write overlay.

    ``known`` maps a linear byte address to the byte value every path
    reaching this position provably wrote. A byte absent from both maps is
    *unmodified* initial-image memory — it keeps whatever the declared
    boot surface says it held.

    ``unknown`` holds linear bytes at least one contributing path may have
    written without a proven value: a proven-span store whose data bytes
    did not evaluate, the architectural INT frame whose contents are
    never modeled, or a byte whose predecessors disagree (written on one
    path only, or written to different values). A byte in ``unknown`` can
    never be read back as initial memory.

    ``tainted`` means a boundary this lattice cannot bound — an unproven
    callee return, a store whose span did not evaluate, an unbounded
    control row — may have modified memory anywhere. Readers must treat
    every byte as unproven once it is set; the maps stay cleared so the
    state is canonical.
    """

    known: dict[int, int] = field(default_factory=dict)
    unknown: set[int] = field(default_factory=set)
    tainted: bool = False

    def copy(self) -> PathMemory8616:
        """Return an independent overlay with the same contents."""
        return PathMemory8616(
            known=dict(self.known),
            unknown=set(self.unknown),
            tainted=self.tainted,
        )

    def assign(self, other: PathMemory8616) -> None:
        """Overwrite this overlay's contents with ``other``'s."""
        self.known.clear()
        self.known.update(other.known)
        self.unknown.clear()
        self.unknown.update(other.unknown)
        self.tainted = other.tainted

    def taint(self) -> None:
        """Collapse to the fully unproven canonical state.

        Used when a boundary may have written memory outside every modeled
        span — nothing about byte contents is provable afterward, so the
        maps clear to keep the state canonical for fixpoint equality.
        """
        self.known.clear()
        self.unknown.clear()
        self.tainted = True

    def apply_write(self, base: int, size: int, data: bytes | None) -> None:
        """Commit one proven-span write of ``size`` bytes at ``base``.

        ``data`` carries the exact written bytes when the store's value
        is proven — each byte enters ``known`` and leaves ``unknown``.
        ``None`` records the span's bytes as modified with unproven
        contents — each byte leaves ``known`` and enters ``unknown``.
        """
        if data is not None and len(data) != size:
            raise ValueError(
                "apply_write data must cover exactly the proven span"
            )
        for index in range(size):
            byte_addr = base + index
            if data is None:
                self.known.pop(byte_addr, None)
                self.unknown.add(byte_addr)
            else:
                self.known[byte_addr] = data[index]
                self.unknown.discard(byte_addr)


def path_memory_initial_8616() -> PathMemory8616:
    """Return the empty overlay — every byte is unmodified initial memory."""
    return PathMemory8616()


def path_memory_tainted_8616() -> PathMemory8616:
    """Return the canonical fully-unproven overlay."""
    return PathMemory8616(tainted=True)


@dataclass(frozen=True, slots=True)
class PathMemorySnapshot8616:
    """Frozen, equality-comparable image of one ``PathMemory8616`` overlay.

    The retained transport surface for path memory across a proven call
    edge: the parent's callsite memory must be replayable verbatim, so
    the mutable overlay is projected to sorted tuples — the same
    capture-equality discipline ``callsite_call_state`` uses for the
    register lanes.
    """

    known: tuple[tuple[int, int], ...]
    unknown: tuple[int, ...]
    tainted: bool


def snapshot_path_memory_8616(
    memory: PathMemory8616,
) -> PathMemorySnapshot8616:
    """Freeze one overlay into its retained, replayable image."""
    return PathMemorySnapshot8616(
        known=tuple(sorted(memory.known.items())),
        unknown=tuple(sorted(memory.unknown)),
        tainted=memory.tainted,
    )


def restore_path_memory_8616(
    snapshot: PathMemorySnapshot8616,
) -> PathMemory8616:
    """Rebuild the mutable overlay a retained snapshot freezes."""
    return PathMemory8616(
        known=dict(snapshot.known),
        unknown=set(snapshot.unknown),
        tainted=snapshot.tainted,
    )


def meet_path_memory_8616(
    states: Iterable[PathMemory8616],
) -> PathMemory8616:
    """Must-meet path memories: a byte is proven only on unanimous paths.

    A byte stays ``known`` iff every contributing state carries it with
    the identical value. Any disagreement — different proven values, a
    byte proven on one path but unmodified or unproven on another — lands
    in ``unknown``: the byte may differ from initial memory but no value
    is provable. ``tainted`` meets disjunctively: one unbounded path
    contaminates the join.

    An empty iterable yields the initial overlay, mirroring the register
    must-meet's empty-state rule; callers always pass the seed or at least
    one predecessor exit.
    """
    iterator = iter(states)
    try:
        result = next(iterator).copy()
    except StopIteration:
        return PathMemory8616()
    for state in iterator:
        for byte_addr in tuple(result.known):
            if state.known.get(byte_addr) != result.known[byte_addr]:
                del result.known[byte_addr]
                result.unknown.add(byte_addr)
        result.unknown.update(state.unknown)
        for byte_addr in state.known:
            if byte_addr not in result.known:
                result.unknown.add(byte_addr)
        result.tainted = result.tainted or state.tainted
    if result.tainted:
        # Canonical form: once a path may have written anywhere, no byte
        # fact is provable and the maps must not pretend otherwise.
        result.known.clear()
        result.unknown.clear()
    return result


def store_atom_clean_8616(
    atom: object, dirty: set[str] | frozenset[str]
) -> bool:
    """Return whether one store-data atom reads no dirty register.

    A register written earlier inside the same machine instruction cannot
    be read through the instruction-entry snapshot — such a value is
    unknown, never a stale constant. Tmp-captured values are pinned to
    their own capture point and stay clean. Shared by the concrete
    effect census and the known-bits feasibility evaluator so both apply
    the identical cleanliness rule.
    """
    if isinstance(atom, IRValue):
        if (
            atom.space is MemSpace.REG
            and atom.name is not None
            and atom.name in dirty
        ):
            return False
        if atom.active_unary is not None:
            return store_atom_clean_8616(atom.active_unary.operand, dirty)
        return True
    if isinstance(atom, IRBinaryValue):
        return store_atom_clean_8616(atom.lhs, dirty) and store_atom_clean_8616(
            atom.rhs, dirty
        )
    return True


def path_load_value_8616(
    instruction: IRInstr,
    span: tuple[int, int] | None,
    memory: PathMemory8616,
    initial: InvocationInitialMemory8616 | None,
) -> int | None:
    """Read an authenticated LOAD span through the path's must-meet overlay.

    Caller binds the row to native bytes and proves its segmented effective
    address. Unknown writes, taint, unsupported widths and undeclared bytes
    refuse. Even a known overlay cannot authorize an undeclared memory region.
    """
    dst = instruction.dst
    if (
        initial is None or span is None or memory.tainted
        or instruction.op != "LOAD" or len(instruction.args) != 1
    ):
        return None
    if (
        type(dst) is not IRValue or dst.space is not MemSpace.TMP
        or type(dst.source_tmp) is not int or dst.source_tmp < 0
        or dst.active_unary is not None
    ):
        return None
    if (
        type(instruction.args[0]) is not IRAddress
    ):
        return None
    address = instruction.args[0]
    base, size = span
    if (
        type(base) is not int or type(size) is not int or size not in (1, 2, 4, 8)
    ):
        return None
    if (
        type(dst.size) is not int or dst.size != size
        or type(address.size) is not int or address.size != size
    ):
        return None
    value = 0
    for offset in range(size):
        byte_addr = base + offset
        original = initial.byte_at(byte_addr)
        if original is None or byte_addr in memory.unknown:
            return None
        byte = memory.known.get(byte_addr, original)
        if type(byte) is not int or not 0 <= byte <= 255:
            return None
        value |= byte << (offset * 8)
    return value
