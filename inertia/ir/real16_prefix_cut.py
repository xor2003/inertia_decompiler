# cython: language_level=3, infer_types=True
"""Bounded structural admission for an earlier CALL cut.

Layer: IR.
Responsibility: bind exact CALL rows to a closed acyclic CFG and establish
dominance without granting semantic proof, state reuse or callback reuse.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
from time import monotonic

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRBlock, IRFunctionArtifact, IRInstr, IRRefusal
from .ir_boundary_cfg import _closed_boundary_census_8616
import dataclasses
import operator


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


@cython.dataclasses.dataclass()
class PrefixCutBudget8616:
    """Shared nonrenewable work allowance and absolute monotonic deadline."""

    max_work_units: cython.longlong
    deadline: cython.double
    work_units: cython.longlong = 0

    @cython.ccall
    def charge(self, units: cython.longlong = 1) -> None:
        """Consume admitted work, refusing before a resource limit is crossed."""
        if not monotonic() < self.deadline:
            raise _Refused(PrefixCutFailure8616.DEADLINE)
        if units < 0 or self.work_units + units > self.max_work_units:
            raise _Refused(PrefixCutFailure8616.WORK)
        self.work_units += units


@dataclasses.dataclass(frozen=True, )
class PrefixCallRow8616:
    """Identity-bound instruction position within one exact raw artifact."""

    artifact: IRFunctionArtifact
    block: IRBlock
    index: cython.longlong
    row: IRInstr


@dataclasses.dataclass(frozen=True, )
class PrefixCutStats8616:
    """Closed admission-candidate ledger; these are not semantic census facts."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong


@dataclasses.dataclass(frozen=True, )
class PrefixCutWitness8616:
    """Structural-only cut retaining the exact boundary and both row owners."""

    artifact: IRFunctionArtifact
    boundary: ExactFunctionRangeBoundary8616
    prior: PrefixCallRow8616
    later: PrefixCallRow8616
    extent: PrefixCutExtent8616
    region: object


@dataclasses.dataclass(frozen=True, )
class PrefixCutResult8616:
    """A complete structural witness or a typed refusal without partial data."""

    witness: PrefixCutWitness8616 | None
    failure: PrefixCutFailure8616 | None
    work_units: cython.longlong
    stats: PrefixCutStats8616

    @property
    def complete(self) -> cython.bint:
        """Expose structural admission only, never semantic equivalence."""
        return self.failure is None and self.witness is not None


@cython.ccall
def _bind_row(artifact: IRFunctionArtifact, ref: PrefixCallRow8616,
              blocks: object) -> None:
    """Reject equal copies, foreign owners and invalid selected positions."""
    owned: object
    owned = blocks.get(ref.block.addr)
    if owned is None or ref.artifact is not artifact or owned is not ref.block:
        raise _Refused(PrefixCutFailure8616.IDENTITY)
    if type(ref.index) is not int or not 0 <= ref.index < len(owned.instrs):
        raise _Refused(PrefixCutFailure8616.IDENTITY)
    if owned.instrs[ref.index] is not ref.row or ref.row.op != "CALL":
        raise _Refused(PrefixCutFailure8616.IDENTITY)


@cython.ccall
def _scan_rows(block: IRBlock, calls: object, budget: PrefixCutBudget8616,
               *, control_geometry: cython.bint = True) -> cython.bint:
    """Census CALL identity once and retain terminal-control geometry for this block."""
    index: object
    instruction: object
    geometry_valid = True
    for index, instruction in enumerate(block.instrs):
        budget.charge()
        if type(instruction) is not IRInstr:
            raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
        if instruction.op in ("RET", "JMP", "CJMP") and operator.ne(index, len(block.instrs) - 1):
            if control_geometry:
                raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
            geometry_valid = False
        if instruction.op == "CALL":
            if type(instruction.addr) is not int:
                raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
            if instruction.addr in calls:
                raise _Refused(PrefixCutFailure8616.DUPLICATE_CALL)
            calls.add(instruction.addr)
    return geometry_valid


@cython.ccall
def _scan(artifact: IRFunctionArtifact, budget: PrefixCutBudget8616,
          extent: PrefixCutExtent8616) -> tuple[dict[cython.longlong, IRBlock], set[cython.longlong]]:
    """Inspect all rows once, retaining misplaced controls for absorbing-region checks."""
    block: object
    blocks: dict[cython.longlong, IRBlock] = {}
    calls: set[cython.longlong] = set()
    misplaced_controls: set[cython.longlong] = set()
    for block in artifact.blocks:
        budget.charge()
        if type(block) is not IRBlock or type(block.addr) is not int:
            raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
        if block.addr in blocks:
            raise _Refused(PrefixCutFailure8616.DUPLICATE_BLOCK)
        if extent is PrefixCutExtent8616.FULL_FUNCTION and block.refusals:
            raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)
        blocks[block.addr] = block
        if not _scan_rows(block, calls, budget, control_geometry=extent is PrefixCutExtent8616.FULL_FUNCTION):
            misplaced_controls.add(block.addr)
    return blocks, misplaced_controls


@cython.ccall
def _edges(blocks: object, budget: PrefixCutBudget8616) -> frozenset[tuple[cython.longlong, cython.longlong]]:
    """Collect validated edges once for the shared CFG agreement owner."""
    block: object
    target: object
    edges: set[tuple[cython.longlong, cython.longlong]] = set()
    for block in blocks.values():
        budget.charge()
        seen: set[cython.longlong] = set()
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


@cython.ccall
def _cut_successors(block: IRBlock, stop: int | None) -> object:
    """Return graph successors within an explicitly absorbing extent."""
    return () if operator.eq(block.addr, stop) else block.successor_addrs


@cython.ccall
def _acyclic(blocks: object, budget: PrefixCutBudget8616,
             stop: int | None = None) -> None:
    """Use charged indegree elimination to reject all cycles and reentry."""
    addr: object
    block: object
    degree: object
    target: object
    indegree: dict[cython.longlong, cython.longlong] = {}
    for addr in blocks:
        budget.charge()
        indegree[addr] = 0
    for block in blocks.values():
        budget.charge()
        for target in _cut_successors(block, stop):
            budget.charge()
            indegree[target] += 1
    pending: list[cython.longlong] = []
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
    if operator.ne(visited, len(blocks)):
        raise _Refused(PrefixCutFailure8616.CYCLE)


@cython.ccall
def _reachable(blocks: object, start: cython.longlong, budget: PrefixCutBudget8616,
               excluded: int | None = None, stop: int | None = None) -> object:
    """Collect charged reachability, optionally cutting one entire block."""
    addr: object
    target: object
    reached: set[cython.longlong] = set()
    pending = [start]
    while pending:
        budget.charge()
        addr = pending.pop()
        if operator.eq(addr, excluded) or addr in reached:
            continue
        reached.add(addr)
        if operator.eq(addr, stop):
            continue
        for target in blocks[addr].successor_addrs:
            budget.charge()
            if target not in reached:
                pending.append(target)
    return reached


@cython.ccall
def _boundary_edges(boundary: ExactFunctionRangeBoundary8616,
                    budget: PrefixCutBudget8616) -> None:
    """Reject malformed or duplicate native edges before set normalization."""
    edge: object
    boundary_edges: set[tuple[cython.longlong, cython.longlong]] = set()
    for edge in boundary.successor_edges:
        budget.charge()
        if type(edge) is not tuple or len(edge) != 2:
            raise _Refused(PrefixCutFailure8616.MISSING_EDGE)
        if type(edge[0]) is not int or type(edge[1]) is not int:
            raise _Refused(PrefixCutFailure8616.MISSING_EDGE)
        if edge in boundary_edges:
            raise _Refused(PrefixCutFailure8616.DUPLICATE_EDGE)
        boundary_edges.add(edge)


@cython.ccall
def _region_blocks(blocks: object, reachable: object,
                   budget: PrefixCutBudget8616, misplaced_controls: object) -> object:
    """Consume the completed row census and reject pre-stop control/refusal defects."""
    addr: object
    relevant: dict[cython.longlong, IRBlock] = {}
    for addr in reachable:
        budget.charge()
        block = blocks[addr]
        if block.refusals:
            raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)
        if addr in misplaced_controls:
            raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
        relevant[addr] = block
    return relevant


@cython.ccall
def _exclude_artifact_refusals(
    artifact: IRFunctionArtifact, blocks: object, region: object,
    budget: PrefixCutBudget8616,
) -> None:
    """Exclude only exact block-local refusals beyond the absorbing CALL cut.

    The artifact may mirror a suffix block's refusal in its function inventory.
    Unlocated, unmatched or reachable refusals still deny prefix admission.
    Neither the inventory nor the raw blocks acquire universal completeness.
    """
    block: object
    refusal: object
    for refusal in artifact.refusals:
        budget.charge()
        if type(refusal) is not IRRefusal or type(refusal.block_addr) is not int:
            raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)
        block = blocks.get(refusal.block_addr)
        if block is None or block.addr in region:
            raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)
        budget.charge(len(block.refusals))
        if refusal not in block.refusals:
            raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)


@cython.ccall
def _bind_cut_order(
    prior: PrefixCallRow8616, later: PrefixCallRow8616,
    blocks: object, reachable: object, head: cython.longlong,
    stop: int | None, budget: PrefixCutBudget8616,
) -> None:
    """Require reachable ordered CALL rows and dominance in the absorbing graph."""
    if prior.block.addr not in reachable or later.block.addr not in reachable:
        raise _Refused(PrefixCutFailure8616.UNREACHABLE)
    if prior.block is later.block:
        if prior.index >= later.index:
            raise _Refused(PrefixCutFailure8616.ORDER)
    elif later.block.addr in _reachable(blocks, head, budget, prior.block.addr, stop=stop):
        raise _Refused(PrefixCutFailure8616.BYPASS)


@cython.ccall
def _admit(artifact: IRFunctionArtifact, boundary: ExactFunctionRangeBoundary8616,
           prior: PrefixCallRow8616, later: PrefixCallRow8616,
           budget: PrefixCutBudget8616, extent: PrefixCutExtent8616) -> object:
    """Close graph authority before testing dominance and row ordering."""
    stop: object
    budget.charge()
    if type(extent) is not PrefixCutExtent8616:
        raise _Refused(PrefixCutFailure8616.IDENTITY)
    if type(boundary) is not ExactFunctionRangeBoundary8616:
        raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)
    if extent is PrefixCutExtent8616.FULL_FUNCTION and artifact.refusals:
        raise _Refused(PrefixCutFailure8616.INCOMPLETE_CFG)
    blocks, misplaced_controls = _scan(artifact, budget, extent)
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
    if stop is not None and operator.ne(later.index, len(later.block.instrs) - 1):
        raise _Refused(PrefixCutFailure8616.MALFORMED_ROW)
    reachable = _reachable(blocks, artifact.function_addr, budget, stop=stop)
    _exclude_artifact_refusals(artifact, blocks, reachable, budget)
    relevant = blocks if stop is None else _region_blocks(blocks, reachable, budget, misplaced_controls)
    _acyclic(relevant, budget, stop=stop)
    _bind_cut_order(prior, later, blocks, reachable, artifact.function_addr, stop, budget)
    budget.charge(len(reachable))
    region = frozenset(reachable)
    budget.charge(0)
    return region


@cython.ccall
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
