"""Layer: dosunit ordered native access evidence (staging).

Responsibility: retain every raw VEX read and each intermediate store before
liveness filtering. These diagnostics do not prove binding, permissions,
address/fault safety or fetched-code preservation.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from enum import StrEnum

import pyvex
from pyvex.expr import IRExpr, Load
from pyvex.stmt import CAS, LLSC, Dirty, IMark, IRStmt, LoadG, Store, StoreG

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.contracts.proof_contracts import FactCounters


class NativeAccessKind(StrEnum):
    """The actual memory operation or an unmodeled raw access form."""

    READ = "read"
    WRITE = "write"
    OPAQUE = "opaque"


class NativeAccessReason(StrEnum):
    """Typed admission or the exact boundary withholding access evidence."""

    COLLECTED = "ordered_native_accesses_collected"
    LOWERING = "native_access_lowering_refused"
    FORM = "native_access_form_unsupported"
    RESOURCE = "native_access_work_budget_exhausted"
    DEADLINE = "native_access_deadline_exhausted"
    MANIFEST = "native_access_manifest_incomplete"


@dataclass(frozen=True, slots=True)
class NativeAccessId:
    """One raw occurrence, independent of expression equality or liveness."""

    statement: int
    occurrence: int


@dataclass(frozen=True, slots=True)
class NativeAccessFact:
    """Physical execution address and exact pre/post memory of one access."""

    id: NativeAccessId
    instruction: int
    kind: NativeAccessKind
    width: int
    address: S.SsaExpr | None
    memory_before: S.SsaExpr
    memory_after: S.SsaExpr
    reason: NativeAccessReason
    detail: str = ""


@dataclass(frozen=True, slots=True)
class NativeAccessReport:
    """A closed occurrence ledger; collection cannot establish binary behavior."""

    reason: NativeAccessReason
    required: tuple[NativeAccessId, ...]
    facts: tuple[NativeAccessFact, ...]
    counters: FactCounters
    raw_complete: bool
    detail: str = ""

    @property
    def complete(self) -> bool:
        """Require all raw occurrences and fully lowered access operands."""
        ids = tuple(fact.id for fact in self.facts)
        count = len(self.required)
        manifest_closed = (len(set(self.required)) == count
                           and len(ids) == count and len(set(ids)) == count
                           and set(ids) == set(self.required))
        operands_closed = all(
            fact.reason is NativeAccessReason.COLLECTED
            and fact.kind in {NativeAccessKind.READ, NativeAccessKind.WRITE}
            and fact.address is not None and fact.address.width == 32
            and type(fact.width) is int and fact.width > 0 and fact.width % 8 == 0
            for fact in self.facts)
        return (self.raw_complete and self.reason is NativeAccessReason.COLLECTED
                and manifest_closed and operands_closed
                and self.counters == FactCounters(count, count, count, count, 0))

    @property
    def binary_equivalence_proved(self) -> bool:
        """Source, physical, fault and relational proofs remain independent."""
        return False


@dataclass(frozen=True, slots=True)
class NativeAccessLimits:
    """Finite raw scanning and lowering under one absolute deadline."""

    deadline: float
    max_statements: int = 4096
    max_expression_nodes: int = 65536
    max_accesses: int = 4096

    def __post_init__(self) -> None:
        """Validate finite original time and positive work budgets once."""
        if any(type(value) is not int or value <= 0 for value in
               (self.max_statements, self.max_expression_nodes, self.max_accesses)):
            raise ValueError("native access work limits must be positive integers")
        if type(self.deadline) not in {float, int} or not math.isfinite(self.deadline):
            raise ValueError("native access deadline must be finite")

    def check(self) -> None:
        """Charge every scan/lowering stage to the original absolute deadline."""
        if time.monotonic() >= self.deadline:
            raise _AccessStop(NativeAccessReason.DEADLINE, "original access deadline exhausted")


class _AccessStop(Exception):
    """Named raw intake refusal, preserving the work-boundary cause."""

    def __init__(self, reason: NativeAccessReason, detail: str) -> None:
        """Carry typed reason and diagnostic without substituting a success."""
        self.reason = reason
        super().__init__(detail)


def _children(value: IRExpr | IRStmt, remaining: int) -> tuple[IRExpr, ...]:
    """Inspect the dynamic pyvex slot boundary without recursive child helpers.

    Pyvex child_expressions recursively expands its tree before returning it;
    slot access instead lets our own finite walker charge every occurrence.
    """
    children: list[IRExpr] = []
    for name in value.__slots__:
        field = getattr(value, name)  # Dynamic third-party boundary: VEX exposes runtime slot names.
        candidates = (field,) if isinstance(field, IRExpr) else field if isinstance(field, (tuple, list)) else ()
        for child in candidates:
            if isinstance(child, IRExpr):
                if len(children) >= remaining:
                    raise _AccessStop(NativeAccessReason.RESOURCE, "raw child allocation budget exhausted")
                children.append(child)
    return tuple(children)


def _raw_plan(irsb: pyvex.IRSB, limits: NativeAccessLimits,
              plan: dict[int, tuple[IRExpr | IRStmt, ...]]) -> None:
    """Freeze reads in expression evaluation order and writes after their inputs."""
    nodes = accesses = 0
    if len(irsb.statements) > limits.max_statements:
        raise _AccessStop(NativeAccessReason.RESOURCE, "raw statement budget exhausted")
    for index, statement in enumerate(irsb.statements):
        limits.check()
        found: list[IRExpr | IRStmt] = []
        active: set[int] = set()
        roots = _children(statement, limits.max_expression_nodes - nodes)
        nodes += len(roots)
        pending = [(child, False) for child in reversed(roots)]
        while pending:
            limits.check()
            expr, exiting = pending.pop()
            if exiting:
                active.remove(id(expr))
                if isinstance(expr, Load):
                    found.append(expr)
                continue
            if id(expr) in active:
                raise _AccessStop(NativeAccessReason.RESOURCE, "raw expression work/cycle boundary")
            active.add(id(expr))
            pending.append((expr, True))
            children = _children(expr, limits.max_expression_nodes - nodes)
            nodes += len(children)
            pending.extend((child, False) for child in reversed(children))
        if isinstance(statement, (Store, LoadG, StoreG, CAS, LLSC, Dirty)):
            found.append(statement)
        accesses += len(found)
        if accesses > limits.max_accesses:
            raise _AccessStop(NativeAccessReason.RESOURCE, "raw access budget exhausted")
        if found:
            plan[index] = tuple(found)


def _read_address(expr: Load, state: S._IrsbLowerState, irsb: pyvex.IRSB) -> S.SsaExpr:
    """Use authoritative SSA storage versions for the physical load operand."""
    address = S._lower_expr(expr.addr, temp_defs=state.temp_defs, temp_failures=state.temp_failures,
                            reg_versions=state.reg_versions, tyenv=irsb.tyenv, memory=state.mem_version)
    if isinstance(address, S.LowerFailure):
        raise address
    failure = S._expr_failure(address)
    if failure is not None:
        raise failure
    return S._coerce_width(address, 32)


def _fact(index: int, occurrence: int, instruction: int, expr: IRExpr | IRStmt,
          state: S._IrsbLowerState, irsb: pyvex.IRSB, before: S.SsaExpr) -> NativeAccessFact:
    """Retain exact access effects; guarded/atomic/opaque forms fail closed."""
    identifier = NativeAccessId(index, occurrence)
    if isinstance(expr, Load):
        if expr.endness != "Iend_LE":
            return NativeAccessFact(identifier, instruction, NativeAccessKind.READ, 0, None, before, before,
                                    NativeAccessReason.FORM, "non-native load byte order")
        address = _read_address(expr, state, irsb)
        return NativeAccessFact(identifier, instruction, NativeAccessKind.READ, int(expr.result_size(irsb.tyenv)),
                                address, before, before, NativeAccessReason.COLLECTED)
    if isinstance(expr, Store):
        after = state.mem_version
        return NativeAccessFact(identifier, instruction, NativeAccessKind.WRITE, after.args[2].width,
                                after.args[1], before, after, NativeAccessReason.COLLECTED)
    return NativeAccessFact(identifier, instruction, NativeAccessKind.OPAQUE, 0, None, before, before,
                            NativeAccessReason.FORM, f"unclosed raw access form: {type(expr).__name__}")


def _lower_plan(irsb: pyvex.IRSB, limits: NativeAccessLimits,
                plan: dict[int, tuple[IRExpr | IRStmt, ...]], state: S._IrsbLowerState,
                facts: list[NativeAccessFact]) -> None:
    """Lower every raw prefix through the last required memory occurrence.

    The complete raw plan includes dead reads, overwritten stores and opaque
    helpers. A later register/control write cannot change any already executed
    memory access. Its full-state proof belongs to the independent effect owner;
    this report proves only the ordered access ledger and never binary equality.
    """
    instruction = int(irsb.addr)
    last_access = max(plan, default=-1)
    for index, statement in enumerate(irsb.statements):
        if index > last_access:
            break
        limits.check()
        if isinstance(statement, IMark):
            instruction = int(statement.addr)
            continue
        before = state.mem_version
        rows = plan.get(index, ())
        for occurrence, expr in enumerate(rows):
            if isinstance(expr, Load):
                facts.append(_fact(index, occurrence, instruction, expr, state, irsb, before))
        failure = S._lower_irsb_statement(statement, state, tyenv=irsb.tyenv,
                                         output_regs=tuple(S.INTERNAL_STATE_REGS))
        if failure is not None:
            raise failure
        for occurrence, expr in enumerate(rows):
            if not isinstance(expr, Load):
                facts.append(_fact(index, occurrence, instruction, expr, state, irsb, before))


def collect_native_memory_accesses(irsb: pyvex.IRSB, limits: NativeAccessLimits) -> NativeAccessReport:
    """Collect all raw accesses, including dead reads and overwritten stores.

    Use fresh binary-derived, unoptimized VEX as input. This owner establishes
    neither its byte provenance nor outcome safety; those require independent
    receipts. Never use the production liveness-filtered statement selection.
    """
    plan: dict[int, tuple[IRExpr | IRStmt, ...]] = {}
    facts: list[NativeAccessFact] = []
    complete = False
    reason, detail = NativeAccessReason.COLLECTED, ""
    state = S._IrsbLowerState(S._initial_reg_versions(), S.SsaExpr("mem_input", 0, name="mem"),
                             S.SsaExpr("mem_input", 0, name="io"))
    try:
        limits.check()
        _raw_plan(irsb, limits, plan)
        complete = True
        _lower_plan(irsb, limits, plan, state, facts)
    except _AccessStop as refusal:
        reason, detail = refusal.reason, str(refusal)
    except S.LowerFailure as refusal:
        reason, detail = NativeAccessReason.LOWERING, f"{refusal.reason}: {refusal.message}"
    except RecursionError as refusal:
        reason, detail = NativeAccessReason.RESOURCE, f"SSA operand recursion boundary: {refusal}"
    required = tuple(NativeAccessId(index, occurrence) for index, rows in plan.items()
                     for occurrence in range(len(rows)))
    failed = len(required) - len(facts) + sum(fact.reason is not NativeAccessReason.COLLECTED for fact in facts)
    if not complete or reason is not NativeAccessReason.COLLECTED:
        failed += 1
    if any(fact.reason is not NativeAccessReason.COLLECTED for fact in facts) and reason is NativeAccessReason.COLLECTED:
        reason = NativeAccessReason.FORM
    counts = FactCounters(len(required), len(required), len(required),
                          sum(fact.address is not None for fact in facts), failed)
    return NativeAccessReport(reason, required, tuple(facts), counts, complete, detail)
