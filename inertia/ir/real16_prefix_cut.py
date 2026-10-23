"""Bounded structural admission for an earlier CALL cut.

Layer: IR.
Responsibility: bind exact CALL rows to a closed acyclic CFG and establish
dominance without granting semantic proof, state reuse or callback reuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from time import monotonic

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRBlock, IRFunctionArtifact, IRInstr
from .ir_boundary_cfg import _closed_boundary_census_8616


class PrefixCutExtent8616(StrEnum):
    """Extent of structural closure; neither extent authorizes state reuse."""

    FULL_FUNCTION = "full_function"
    BEFORE_LATER_CALL = "before_later_call"


class PrefixCutFailure8616(StrEnum):
    """Reasons a structural cut supplies no admission."""

    IDENTITY = "identity"
    ORDER = "order"
    INCOMPLETE_CFG = "incomplete_cfg"
    DUPLICATE_BLOCK = "duplicate_block"
    DUPLICATE_CALL = "duplicate_call"
    DUPLICATE_EDGE = "duplicate_edge"
    MALFORMED_ROW = "malformed_row"
    MISSING_EDGE = "missing_edge"
    UNREACHABLE = "unreachable"
    BYPASS = "bypass"
    CYCLE = "cycle"
    WORK = "work"
    DEADLINE = "deadline"


class _Refused(Exception):
    """Carry a named structural or resource refusal to the result boundary."""

    def __init__(self, failure: PrefixCutFailure8616) -> None:
        self.failure = failure
        super().__init__(failure.value)


@dataclass(slots=True)
class PrefixCutBudget8616:
    """Shared nonrenewable work allowance and absolute monotonic deadline."""

    max_work_units: int
    deadline: float
    work_units: int = 0

    def charge(self, units: int = 1) -> None:
        """Consume admitted work, refusing before a resource limit is crossed."""
        if not monotonic() < self.deadline:
            raise _Refused(PrefixCutFailure8616.DEADLINE)
        if units < 0 or self.work_units + units > self.max_work_units:
            raise _Refused(PrefixCutFailure8616.WORK)
        self.work_units += units


@dataclass(frozen=True, slots=True)
class PrefixCallRow8616:
    """Identity-bound instruction position within one exact raw artifact."""

    artifact: IRFunctionArtifact
    block: IRBlock
    index: int
    row: IRInstr


@dataclass(frozen=True, slots=True)
class PrefixCutStats8616:
    """Closed admission-candidate ledger; these are not semantic census facts."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class PrefixCutWitness8616:
    """Structural-only cut retaining the exact boundary and both row owners."""

    artifact: IRFunctionArtifact
    boundary: ExactFunctionRangeBoundary8616
    prior: PrefixCallRow8616
    later: PrefixCallRow8616
    extent: PrefixCutExtent8616
    region: frozenset[int]


@dataclass(frozen=True, slots=True)
class PrefixCutResult8616:
    """A complete structural witness or a typed refusal without partial data."""

    witness: PrefixCutWitness8616 | None
    failure: PrefixCutFailure8616 | None
    work_units: int
    stats: PrefixCutStats8616

    @property
    def complete(self) -> bool:
        """Expose structural admission only, never semantic equivalence."""
        return self.failure is None and self.witness is not None


def _bind_row(artifact: IRFunctionArtifact, ref: PrefixCallRow8616,
              blocks: dict[int, IRBlock]) -> None:
    """Reject equal copies, foreign owners and invalid selected positions."""
    owned = blocks.get(ref.block.addr)
    if owned is None or ref.artifact is not artifact or owned is not ref.block:
        raise _Refused(PrefixCutFailure8616.IDENTITY)
    if type(ref.index) is not int or not 0 <= ref.index < len(owned.instrs):
        raise _Refused(PrefixCutFailure8616.IDENTITY)
    if owned.instrs[ref.index] is not ref.row or ref.row.op != "CALL":
        raise _Refused(PrefixCutFailure8616.IDENTITY)


def _scan_rows(block: IRBlock, calls: set[int], budget: PrefixCutBudget8616,
               *, control_geometry: bool = True) -> None:
    """Require unambiguous CALL addresses and terminal-only control geometry."""
    for index, instruction in enumerate(block.instrs):
        budget.charge()
        if type(instruction) is not IRInstr:
            raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
        if control_geometry and instruction.op in ("RET", "JMP", "CJMP") and index != len(block.instrs) - 1:
            raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
        if instruction.op == "CALL":
            if type(instruction.addr) is not int:
                raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
            if instruction.addr in calls:
                raise _Refused(PrefixCutFailure8616.DUPLICATE_CALL)
            calls.add(instruction.addr)


def _scan(artifact: IRFunctionArtifact, budget: PrefixCutBudget8616,
          extent: PrefixCutExtent8616) -> dict[int, IRBlock]:
    """Inspect every owned block and row once under the supplied budget."""
    blocks: dict[int, IRBlock] = {}
    calls: set[int] = set()
    for block in artifact.blocks:
        budget.charge()
        if type(block) is not IRBlock or type(block.addr) is not int:
            raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
        if block.addr in blocks:
            raise _Refused(PrefixCutFailure8616.DUPLICATE_BLOCK)
        if extent is PrefixCutExtent8616.FULL_FUNCTION and block.refusals:
            raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)
        blocks[block.addr] = block
        _scan_rows(block, calls, budget, control_geometry=extent is PrefixCutExtent8616.FULL_FUNCTION)
    return blocks


def _edges(blocks: dict[int, IRBlock], budget: PrefixCutBudget8616) -> frozenset[tuple[int, int]]:
    """Collect validated edges once for the shared CFG agreement owner."""
    edges: set[tuple[int, int]] = set()
    for block in blocks.values():
        budget.charge()
        seen: set[int] = set()
        for target in block.successor_addrs:
            budget.charge()
            if type(target) is not int or target not in blocks:
                raise _Refused(PrefixCutFailure8616.MISSING_EDGE)
            if target in seen:
                raise _Refused(PrefixCutFailure8616.DUPLICATE_EDGE)
            seen.add(target)
            edges.add((block.addr, target))
    budget.charge(len(edges))
    return frozenset(edges)


def _cut_successors(block: IRBlock, stop: int | None) -> tuple[int, ...]:
    """Return graph successors within an explicitly absorbing extent."""
    return () if block.addr == stop else block.successor_addrs


def _acyclic(blocks: dict[int, IRBlock], budget: PrefixCutBudget8616,
             stop: int | None = None) -> None:
    """Use charged indegree elimination to reject all cycles and reentry."""
    indegree: dict[int, int] = {}
    for addr in blocks:
        budget.charge()
        indegree[addr] = 0
    for block in blocks.values():
        budget.charge()
        for target in _cut_successors(block, stop):
            budget.charge()
            indegree[target] += 1
    pending: list[int] = []
    for addr, degree in indegree.items():
        budget.charge()
        if degree == 0:
            pending.append(addr)
    visited = 0
    while pending:
        budget.charge()
        block = blocks[pending.pop()]
        visited += 1
        for target in _cut_successors(block, stop):
            budget.charge()
            indegree[target] -= 1
            if indegree[target] == 0:
                pending.append(target)
    if visited != len(blocks):
        raise _Refused(PrefixCutFailure8616.CYCLE)


def _reachable(blocks: dict[int, IRBlock], start: int, budget: PrefixCutBudget8616,
               excluded: int | None = None, stop: int | None = None) -> set[int]:
    """Collect charged reachability, optionally cutting one entire block."""
    reached: set[int] = set()
    pending = [start]
    while pending:
        budget.charge()
        addr = pending.pop()
        if addr == excluded or addr in reached:
            continue
        reached.add(addr)
        if addr == stop:
            continue
        for target in blocks[addr].successor_addrs:
            budget.charge()
            if target not in reached:
                pending.append(target)
    return reached


def _boundary_edges(boundary: ExactFunctionRangeBoundary8616,
                    budget: PrefixCutBudget8616) -> None:
    """Reject malformed or duplicate native edges before set normalization."""
    boundary_edges: set[tuple[int, int]] = set()
    for edge in boundary.successor_edges:
        budget.charge()
        if type(edge) is not tuple or len(edge) != 2:
            raise _Refused(PrefixCutFailure8616.MISSING_EDGE)
        if type(edge[0]) is not int or type(edge[1]) is not int:
            raise _Refused(PrefixCutFailure8616.MISSING_EDGE)
        if edge in boundary_edges:
            raise _Refused(PrefixCutFailure8616.DUPLICATE_EDGE)
        boundary_edges.add(edge)


def _region_blocks(blocks: dict[int, IRBlock], reachable: set[int],
                   budget: PrefixCutBudget8616) -> dict[int, IRBlock]:
    """Validate every pre-stop row/refusal without altering the raw artifact."""
    relevant: dict[int, IRBlock] = {}
    calls: set[int] = set()
    for addr in reachable:
        budget.charge()
        block = blocks[addr]
        if block.refusals:
            raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)
        _scan_rows(block, calls, budget)
        relevant[addr] = block
    return relevant


def _admit(artifact: IRFunctionArtifact, boundary: ExactFunctionRangeBoundary8616,
           prior: PrefixCallRow8616, later: PrefixCallRow8616,
           budget: PrefixCutBudget8616, extent: PrefixCutExtent8616) -> frozenset[int]:
    """Close graph authority before testing dominance and row ordering."""
    budget.charge()
    if type(extent) is not PrefixCutExtent8616:
        raise _Refused(PrefixCutFailure8616.IDENTITY)
    if artifact.refusals or type(boundary) is not ExactFunctionRangeBoundary8616:
        raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)
    blocks = _scan(artifact, budget, extent)
    edges = _edges(blocks, budget)
    _boundary_edges(boundary, budget)
    _bind_row(artifact, prior, blocks)
    _bind_row(artifact, later, blocks)
    # Reuse the exact census collected above. The semantic owner meters each
    # operation before doing it, including allocations and reachability.
    budget.charge(len(blocks))
    if not _closed_boundary_census_8616(
        artifact.function_addr, boundary, frozenset(blocks), edges, charge=budget.charge,
    ):
        raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)
    budget.charge(0)
    stop = later.block.addr if extent is PrefixCutExtent8616.BEFORE_LATER_CALL else None
    if stop is not None and later.index != len(later.block.instrs) - 1:
        raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
    reachable = _reachable(blocks, artifact.function_addr, budget, stop=stop)
    relevant = blocks if stop is None else _region_blocks(blocks, reachable, budget)
    _acyclic(relevant, budget, stop=stop)
    if prior.block.addr not in reachable or later.block.addr not in reachable:
        raise _Refused(PrefixCutFailure8616.UNREACHABLE)
    if prior.block is later.block:
        if prior.index >= later.index:
            raise _Refused(PrefixCutFailure8616.ORDER)
    elif later.block.addr in _reachable(blocks, artifact.function_addr, budget, prior.block.addr, stop=stop):
        raise _Refused(PrefixCutFailure8616.BYPASS)
    budget.charge(len(reachable))
    region = frozenset(reachable)
    budget.charge(0)
    return region


def admit_prefix_cut_8616(
    artifact: IRFunctionArtifact, boundary: ExactFunctionRangeBoundary8616,
    prior: PrefixCallRow8616, later: PrefixCallRow8616, *, budget: PrefixCutBudget8616,
    extent: PrefixCutExtent8616 = PrefixCutExtent8616.FULL_FUNCTION,
) -> PrefixCutResult8616:
    """Admit a bounded exact structural cut without granting semantic reuse.

    The caller authenticates the supplied native boundary and artifact. This
    owner consumes their existing CFG agreement contract, not a Boolean claim
    of completeness. BEFORE_LATER_CALL absorbs the physical-terminal later
    CALL and proves closure only before that stop. Its consumer must separately
    require actual execution scope within witness.region. Original outside
    refusals remain untouched. Neither extent authorizes state/proof transport.
    """
    initial_work = budget.work_units
    try:
        region = _admit(artifact, boundary, prior, later, budget, extent)
    except _Refused as refused:
        return PrefixCutResult8616(None, refused.failure, budget.work_units - initial_work,
                                   PrefixCutStats8616(1, 1, 1, 0, 1))
    return PrefixCutResult8616(PrefixCutWitness8616(artifact, boundary, prior, later, extent, region), None,
                               budget.work_units - initial_work, PrefixCutStats8616(1, 1, 1, 1, 0))
