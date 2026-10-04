"""Binary-derived real16 call-graph admission for joint recursive proposals.

Layer: dosunit real16 call-graph admission.

Responsibility: consume one lowered full-state document and a requested root
function, walk each reached function's blocks against the actual composed raw
SSA effect (``S._compose_block_outputs`` over ``initial_state``), resolve every
reached CALL site through ``checked_call_site`` and ``decoded_call_frame``, and
emit a typed admission report retaining every call site plus a deduplicated
``CallGraph``/SCC partition proposal. Admission is structural only: a complete
graph grants no equality and no PROVED status, callees are never inlined, and
every missing/ambiguous/indirect/unmapped piece of evidence is retained as a
typed refusal record instead of being silently skipped. One shared step and
wall-clock budget covers both the walk and the delegated SCC analysis; the SCC
owner only ever receives the remaining budget, never a replenished one.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import tools.dosunit.straightline_ssa as S
from tools.dosunit.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallLimits,
    Real16CallRefusal,
    initial_state,
)
from tools.dosunit.real16_call_control import checked_call_site
from tools.dosunit.real16_call_evidence import (
    block_source,
    block_transfer,
    check_lowering_refusals,
    group_functions,
)
from tools.dosunit.real16_call_frames import CallFrameKind, decoded_call_frame
from tools.dosunit.recursive_proofs.recursive_call_components import (
    CallEdge,
    CallGraph,
    ComponentAnalysis,
    ComponentLimits,
    FunctionId,
    RecursiveCallRefusal,
    analyze_call_graph,
)
from tools.dosunit.recursive_proofs.recursive_static_control import (
    StaticControlLimits,
    StaticControlReason,
    resolve_static_control,
)

REPORT_SCHEMA: str = "dosunit.real16_call_admission.v1"


class CoverageScope(StrEnum):
    """What the admitted graph claims to cover."""

    REACHABLE_FROM_ROOT = "reachable_from_root"


class AdmissionVerdict(StrEnum):
    """Whether every reached call site admitted cleanly."""

    ADMITTED = "admitted"
    INCOMPLETE = "incomplete"


class SiteStatus(StrEnum):
    """Per-site resolution outcome."""

    RESOLVED = "resolved"
    CALLEE_UNDECLARED = "callee_undeclared"
    REFUSED = "refused"


class AdmissionRefusalReason(StrEnum):
    """Typed stable reasons admission evidence is incomplete."""

    DOCUMENT_MALFORMED = "document_malformed"
    DOCUMENT_LIMIT_EXCEEDED = "document_limit_exceeded"
    FUNCTION_LIMIT_EXCEEDED = "function_limit_exceeded"
    BLOCK_LIMIT_EXCEEDED = "block_limit_exceeded"
    SITE_LIMIT_EXCEEDED = "site_limit_exceeded"
    STEP_BUDGET_EXCEEDED = "step_budget_exceeded"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    ROOT_AMBIGUOUS = "root_ambiguous"
    ROOT_NOT_FOUND = "root_not_found"
    FUNCTION_RANGE_INCOMPLETE = "function_range_incomplete"
    FULL_STATE_MISSING = "full_state_missing"
    UNSUPPORTED_EFFECT = "unsupported_effect"
    LOWERING_REFUSAL = "lowering_refusal"
    CALL_KIND_UNSUPPORTED = "call_kind_unsupported"
    CALL_TARGET_UNRESOLVED = "call_target_unresolved"
    CALL_TARGET_MISMATCH = "call_target_mismatch"
    CALL_CONTINUATION_MISSING = "call_continuation_missing"
    CALL_FRAME_UNPROVED = "call_frame_unproved"
    CALLEE_UNDECLARED = "callee_undeclared"
    BLOCK_UNDECLARED = "block_undeclared"
    SUCCESSOR_MISMATCH = "successor_mismatch"
    CONTROL_TRANSFER_UNSUPPORTED = "control_transfer_unsupported"
    RETURN_CONTROL_UNSUPPORTED = "return_control_unsupported"
    EXIT_UNSUPPORTED = "exit_unsupported"
    ANALYSIS_REFUSED = "analysis_refused"
    EVIDENCE_REFUSED = "evidence_refused"


_LEGACY_REASON_MAP: dict[str, AdmissionRefusalReason] = {
    "function_not_found": AdmissionRefusalReason.ROOT_NOT_FOUND,
    "function_range_incomplete": AdmissionRefusalReason.FUNCTION_RANGE_INCOMPLETE,
    "full_state_outputs_missing": AdmissionRefusalReason.FULL_STATE_MISSING,
    "unsupported_io_effect": AdmissionRefusalReason.UNSUPPORTED_EFFECT,
    "unsupported_return_control": AdmissionRefusalReason.RETURN_CONTROL_UNSUPPORTED,
    "lowering_refusals_present": AdmissionRefusalReason.LOWERING_REFUSAL,
    "unsupported_call": AdmissionRefusalReason.CALL_KIND_UNSUPPORTED,
    "call_target_unresolved": AdmissionRefusalReason.CALL_TARGET_UNRESOLVED,
    "call_target_mismatch": AdmissionRefusalReason.CALL_TARGET_MISMATCH,
    "call_fallthrough_missing": AdmissionRefusalReason.CALL_CONTINUATION_MISSING,
    "successor_outside_region": AdmissionRefusalReason.CALL_CONTINUATION_MISSING,
    "call_frame_unproved": AdmissionRefusalReason.CALL_FRAME_UNPROVED,
    "call_target_unmapped": AdmissionRefusalReason.CALLEE_UNDECLARED,
    "successor_delta_mismatch": AdmissionRefusalReason.SUCCESSOR_MISMATCH,
    "unsupported_control_transfer": AdmissionRefusalReason.CONTROL_TRANSFER_UNSUPPORTED,
    "unsupported_ir": AdmissionRefusalReason.CONTROL_TRANSFER_UNSUPPORTED,
    "loop_requires_inductive_proof": AdmissionRefusalReason.CONTROL_TRANSFER_UNSUPPORTED,
    "unsupported_exit": AdmissionRefusalReason.EXIT_UNSUPPORTED,
    "return_ip_unobserved": AdmissionRefusalReason.RETURN_CONTROL_UNSUPPORTED,
    "compose_budget_exceeded": AdmissionRefusalReason.DEADLINE_EXCEEDED,
}


def _map_reason(legacy: str) -> AdmissionRefusalReason:
    """Exact-match one legacy refusal string to its owned typed reason."""
    return _LEGACY_REASON_MAP.get(legacy, AdmissionRefusalReason.EVIDENCE_REFUSED)


@dataclass(frozen=True)
class AdmissionLimits:
    """Bounded admission resources shared with the delegated SCC analysis.

    ``deadline_ms < 0`` disables the wall-clock deadline; ``deadline_ms == 0``
    refuses at the first accounted step. ``max_function_records`` bounds the
    raw document parts checked before any expensive grouping begins;
    ``max_steps`` bounds total accounted work across walk and analysis.
    """

    max_function_records: int = 4_096
    max_functions: int = 1_024
    max_blocks: int = 65_536
    max_sites: int = 65_536
    max_steps: int = 4_194_304
    deadline_ms: int = -1

    def __post_init__(self) -> None:
        """Reject limits that cannot describe a finite bounded admission."""
        if type(self.max_function_records) is not int or self.max_function_records < 0:
            raise ValueError("max_function_records must be a non-negative integer")
        for value in (self.max_functions, self.max_blocks, self.max_sites, self.max_steps):
            if type(value) is not int or value <= 0:
                raise ValueError("admission limits must be positive integers")
        if type(self.deadline_ms) is not int:
            raise ValueError("deadline must be an integer millisecond budget")


@dataclass(frozen=True)
class CallSiteRecord:
    """One retained reached CALL site with its binary-derived resolution."""

    caller: FunctionId
    delta: int
    block_linear: int
    call_linear: int | None
    status: SiteStatus
    callee: FunctionId | None
    target_linear: int | None
    fallthrough_linear: int | None
    fall_delta: int | None
    frame: CallFrameKind | None


@dataclass(frozen=True)
class AdmissionRefusal:
    """Typed boundary where admission evidence was incomplete or refused."""

    reason: AdmissionRefusalReason
    function: str | None
    delta: int | None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdmissionCounters:
    """Closed diagnostic counters for one admission run."""

    document_records: int = 0
    reached_functions: int = 0
    blocks_composed: int = 0
    call_sites: int = 0
    resolved_sites: int = 0
    refused_sites: int = 0
    refusals: int = 0
    edges: int = 0
    steps: int = 0
    analysis_steps: int = 0


@dataclass(frozen=True)
class AdmissionReport:
    """Typed admission result; ``verdict=ADMITTED`` is structure, not proof."""

    root: FunctionId | None
    scope: CoverageScope
    verdict: AdmissionVerdict
    sites: tuple[CallSiteRecord, ...]
    refusals: tuple[AdmissionRefusal, ...]
    counters: AdmissionCounters
    graph: CallGraph | None = None
    analysis: ComponentAnalysis | None = None


class _BudgetExhausted(Exception):
    """Internal typed budget stop; translated to a refusal record."""

    def __init__(self, reason: AdmissionRefusalReason, detail: dict[str, Any] | None = None) -> None:
        """Retain the exact limit that tripped."""
        super().__init__(reason.value)
        self.reason = reason
        self.detail = dict(detail or {})


@dataclass
class _Budget:
    """Single shared step/deadline account for walk plus SCC analysis."""

    limits: AdmissionLimits
    deadline: float
    stats: dict[str, Any]
    steps: int = 0

    @classmethod
    def start(cls, limits: AdmissionLimits) -> _Budget:
        """Open the shared budget; ``deadline_ms < 0`` disables wall time."""
        deadline = -1.0
        stats: dict[str, Any] = {}
        if limits.deadline_ms >= 0:
            deadline = time.monotonic() + limits.deadline_ms / 1000.0
            stats["deadline"] = deadline
        return cls(limits=limits, deadline=deadline, stats=stats)

    def bump(self, count: int = 1) -> None:
        """Charge accounted work; stop on step budget or deadline."""
        self.steps += count
        if self.steps > self.limits.max_steps:
            raise _BudgetExhausted(
                AdmissionRefusalReason.STEP_BUDGET_EXCEEDED,
                {"counter": "steps", "limit": self.limits.max_steps},
            )
        if self.deadline >= 0.0 and time.monotonic() > self.deadline:
            raise _BudgetExhausted(AdmissionRefusalReason.DEADLINE_EXCEEDED, {"counter": "deadline"})

    def remaining_ms(self) -> int:
        """Remaining wall-clock budget; ``-1`` when the deadline is disabled."""
        if self.deadline < 0.0:
            return -1
        return max(int((self.deadline - time.monotonic()) * 1000), 0)


@dataclass
class _Acc:
    """Mutable accumulators for one bounded admission walk."""

    sites: list[CallSiteRecord] = field(default_factory=list)
    refusals: list[AdmissionRefusal] = field(default_factory=list)
    edges: set[CallEdge] = field(default_factory=set)
    reached: dict[str, FunctionCtx] = field(default_factory=dict)
    enqueued: set[str] = field(default_factory=set)
    queue: list[FunctionCtx] = field(default_factory=list)
    blocks: int = 0


def _refuse(
    acc: _Acc, reason: AdmissionRefusalReason, function: str | None, delta: int | None, detail: dict[str, Any]
) -> None:
    """Record one typed refusal at its exact boundary."""
    acc.refusals.append(AdmissionRefusal(reason=reason, function=function, delta=delta, detail=detail))


def _check_document(
    acc: _Acc, budget: _Budget, raw: object, record_count: int, limits: AdmissionLimits
) -> AdmissionReport | None:
    """Bounded pre-grouping input boundary.

    Refuses a non-list ``functions`` field, a record count beyond the
    configured document limit, every record grouping would silently drop or
    mis-key, and an already-expired shared deadline or step budget — all
    before ``group_functions`` ever runs. Returns the early typed report when
    any refusal stands, ``None`` when grouping may proceed.
    """
    if raw is not None and not isinstance(raw, list):
        _refuse(acc, AdmissionRefusalReason.DOCUMENT_MALFORMED, None, None, {"field": "functions"})
    elif record_count > limits.max_function_records:
        _refuse(
            acc, AdmissionRefusalReason.DOCUMENT_LIMIT_EXCEEDED, None, None,
            {"count": record_count, "limit": limits.max_function_records},
        )
    if not acc.refusals:
        try:
            if isinstance(raw, list):
                _check_function_records(acc, budget, raw)
            budget.bump()
        except _BudgetExhausted as exc:
            _refuse(acc, exc.reason, None, None, exc.detail)
    if acc.refusals:
        return _report(acc, budget, None, record_count)
    return None


def _check_function_records(acc: _Acc, budget: _Budget, records: list[Any]) -> None:
    """Refuse every record that grouping would silently drop or mis-key.

    Grouping skips non-mapping records and derives each key as
    ``str(function.id or function.name or "")``, discarding records whose
    identity is empty. Admission must instead refuse those records loudly and
    refuse identities grouping would coerce through ``str()`` (a non-string id
    mis-keys the group under its coerced form). Every record scan and the
    grouping step itself are charged to the one shared budget so an expired
    deadline or exhausted step budget stops before grouping ever runs.
    """
    for index, part in enumerate(records):
        budget.bump()
        if not isinstance(part, dict):
            _refuse(
                acc, AdmissionRefusalReason.DOCUMENT_MALFORMED, None, None,
                {"field": "functions", "index": index, "expected": "mapping record"},
            )
            continue
        function = part.get("function")
        if not isinstance(function, dict):
            _refuse(
                acc, AdmissionRefusalReason.DOCUMENT_MALFORMED, None, None,
                {"field": "functions", "index": index, "expected": "mapping function"},
            )
            continue
        identity = function.get("id") or function.get("name")
        if not isinstance(identity, str) or not identity:
            _refuse(
                acc, AdmissionRefusalReason.DOCUMENT_MALFORMED, None, None,
                {"field": "functions", "index": index, "expected": "non-empty string function id"},
            )


def _call_linear(block: dict[str, Any]) -> int | None:
    """Linear address of the final (CALL) instruction, when recorded."""
    instructions = block_source(block).get("instructions")
    if not isinstance(instructions, list) or not instructions:
        return None
    last = instructions[-1]
    address = last.get("address") if isinstance(last, dict) else None
    if not isinstance(address, dict):
        return None
    value: int | None = S._optional_int(address.get("linear"))
    return value


def _follow_control(
    acc: _Acc, ctx: FunctionCtx, delta: int, block: dict[str, Any],
    state: dict[str, dict[str, Any]], pending: list[tuple[int, dict[str, dict[str, Any]]]],
    *, budget: _Budget,
) -> None:
    """Queue the composed control destination(s); refuse unknown transfers.

    The lifted ``control_ip`` term must describe exactly the block's declared
    static successors. Expansion collects every constant arm (``ite`` arms
    recurse; any other leaf keeps its explicit unsupported-control refusal
    and marks the term unresolved). A fully resolved term must satisfy exact
    closure — ``discovered == declared`` — or one ``SUCCESSOR_MISMATCH``
    refusal retains the declared/discovered/missing/extra evidence and no
    partial walk queues. An unresolved term cannot prove closure, so its
    discovered arms still gate individually against the declaration and the
    block table: proven arms queue so real reachability evidence is not
    hidden behind the refusal, while each undeclared arm refuses
    ``SUCCESSOR_MISMATCH`` and each missing block ``BLOCK_UNDECLARED``.
    """
    declared = S._direct_successor_delta_set(block)
    budget.bump()
    remaining = budget.limits.max_steps - budget.steps
    if remaining <= 0:
        budget.bump()
    control = resolve_static_control(state.get("control_ip"), deadline=budget.deadline,
                                     limits=StaticControlLimits(max_nodes=min(65_536, remaining)))
    budget.bump(control.node_count)
    if control.reason is StaticControlReason.DEADLINE:
        raise _BudgetExhausted(AdmissionRefusalReason.DEADLINE_EXCEEDED, {"counter": "static_control"})
    if control.reason is StaticControlReason.NODE_LIMIT and remaining <= 65_536:
        raise _BudgetExhausted(AdmissionRefusalReason.STEP_BUDGET_EXCEEDED, {"counter": "static_control"})
    discovered = {value - ctx.entry_linear for value in control.targets}
    if not control.complete:
        _refuse(acc, AdmissionRefusalReason.CONTROL_TRANSFER_UNSUPPORTED, ctx.function_id, delta,
                {"static_reason": control.reason, "node_count": control.node_count})
    if control.complete and discovered != declared:
        _refuse(
            acc, AdmissionRefusalReason.SUCCESSOR_MISMATCH, ctx.function_id, delta,
            {
                "declared": sorted(declared),
                "discovered": sorted(discovered),
                "missing": sorted(declared - discovered),
                "extra": sorted(discovered - declared),
            },
        )
        return
    for target_delta in sorted(discovered):
        if target_delta not in declared:
            _refuse(
                acc, AdmissionRefusalReason.SUCCESSOR_MISMATCH, ctx.function_id, delta,
                {"target_delta": target_delta, "declared": sorted(declared),
                 "discovered": sorted(discovered)},
            )
            continue
        if target_delta not in ctx.blocks:
            _refuse(
                acc, AdmissionRefusalReason.BLOCK_UNDECLARED, ctx.function_id, delta,
                {"target_delta": target_delta},
            )
            continue
        pending.append((target_delta, state))


def _admit_site(
    acc: _Acc, budget: _Budget, ctx: FunctionCtx, delta: int, block: dict[str, Any],
    state: dict[str, dict[str, Any]], by_entry: dict[int, FunctionCtx],
    pending: list[tuple[int, dict[str, dict[str, Any]]]],
) -> None:
    """Resolve one reached CALL; retain the site and enqueue its continuation."""
    if len(acc.sites) >= budget.limits.max_sites:
        raise _BudgetExhausted(
            AdmissionRefusalReason.SITE_LIMIT_EXCEEDED,
            {"function": ctx.function_id, "delta": delta, "limit": budget.limits.max_sites},
        )
    caller = FunctionId(ctx.function_id)
    linear = _call_linear(block)
    try:
        # Share the admission deadline with the authoritative full-control
        # solver. Correct CS-relative CALL effects need universal selector
        # evidence rather than the former truncated literal shortcut.
        query_limits = Real16CallLimits(ret_check_timeout_ms=1000)
        query_deadline = budget.deadline
        if query_deadline < 0:
            query_deadline = time.monotonic() + query_limits.ret_check_timeout_ms / 1000
        session = ComposeSession(query_limits, {"deadline": query_deadline})
        site = checked_call_site(ctx, delta, block, state, session=session)
        frame = decoded_call_frame(block)
    except Real16CallRefusal as exc:
        acc.sites.append(
            CallSiteRecord(caller, delta, ctx.entry_linear + delta, linear, SiteStatus.REFUSED,
                           None, None, None, None, None)
        )
        _refuse(
            acc, _map_reason(exc.reason), ctx.function_id, delta,
            dict(exc.detail, legacy_reason=exc.reason),
        )
        return
    callee_ctx = by_entry.get(site.target)
    callee = FunctionId(callee_ctx.function_id) if callee_ctx is not None else None
    status = SiteStatus.RESOLVED if callee_ctx is not None else SiteStatus.CALLEE_UNDECLARED
    acc.sites.append(
        CallSiteRecord(caller, delta, ctx.entry_linear + delta, linear, status, callee,
                       site.target, site.fallthrough, site.fall_delta, frame)
    )
    if callee_ctx is None:
        _refuse(acc, AdmissionRefusalReason.CALLEE_UNDECLARED, ctx.function_id, delta, {"target": site.target})
    else:
        assert callee is not None
        acc.edges.add(CallEdge(caller, callee))
        if callee_ctx.function_id not in acc.reached and callee_ctx.function_id not in acc.enqueued:
            acc.enqueued.add(callee_ctx.function_id)
            acc.queue.append(callee_ctx)
    # The callee is never inlined and no post-call state is fabricated: the
    # continuation is walked from a fully symbolic state so call-site reach
    # stays an over-approximation and nothing is silently pruned.
    pending.append((site.fall_delta, initial_state()))


def _compose_refusal_or_stop(acc: _Acc, ctx: FunctionCtx, delta: int, exc: S.LowerFailure) -> None:
    """Translate one compose ``LowerFailure`` on its exact typed ``reason``.

    ``compose_budget_exceeded`` is the shared-budget stop: it raises
    ``_BudgetExhausted(DEADLINE_EXCEEDED)`` with ``exc`` chained as the
    cause. Every other reason is ordinary unsupported SSA — a per-block
    ``LOWERING_REFUSAL`` retaining the exact ``reason``/``message`` while
    the remaining queued cutpoints keep walking.
    """
    detail: dict[str, Any] = {
        "function": ctx.function_id,
        "delta": delta,
        "lowering_reason": exc.reason,
        "lowering_message": exc.message,
    }
    if exc.reason == "compose_budget_exceeded":
        raise _BudgetExhausted(AdmissionRefusalReason.DEADLINE_EXCEEDED, detail) from exc
    _refuse(acc, AdmissionRefusalReason.LOWERING_REFUSAL, ctx.function_id, delta, detail)


def _compose_cutpoint(acc: _Acc, budget: _Budget, ctx: FunctionCtx, delta: int,
                       block: dict[str, Any]) -> dict[str, dict[str, Any]] | None:
    """Compose fresh full state; retain unsupported effects and chained stops."""
    outputs = block.get("outputs")
    try:
        state: dict[str, dict[str, Any]] = S._compose_block_outputs(
            block, outputs if isinstance(outputs, dict) else {},
            initial_state(), compose_stats=budget.stats)
        return state
    except S.LowerFailure as exc:
        _compose_refusal_or_stop(acc, ctx, delta, exc)
        return None


def _follow_cutpoint(acc: _Acc, budget: _Budget, ctx: FunctionCtx, delta: int,
                      block: dict[str, Any], state: dict[str, dict[str, Any]],
                      by_entry: dict[int, FunctionCtx],
                      pending: list[tuple[int, dict[str, dict[str, Any]]]]) -> None:
    """Dispatch a retained native effect without inventing post-call state."""
    jumpkind = str(block_source(block).get("jumpkind") or "")
    kind = str(block_transfer(block).get("kind") or "")
    if jumpkind == "Ijk_Ret":
        ip = state.get("control_ip")
        if isinstance(ip, dict) and ip.get("op") == "ite":
            _refuse(acc, AdmissionRefusalReason.RETURN_CONTROL_UNSUPPORTED, ctx.function_id, delta, {"ip": "conditional"})
        return
    if kind == "nonreturning_interrupt":
        _refuse(acc, AdmissionRefusalReason.UNSUPPORTED_EFFECT, ctx.function_id, delta, {"kind": kind})
        return
    if jumpkind == "Ijk_Call" or kind == "direct_call":
        _admit_site(acc, budget, ctx, delta, block, state, by_entry, pending)
        return
    if jumpkind and jumpkind != "Ijk_Boring":
        _refuse(acc, AdmissionRefusalReason.EXIT_UNSUPPORTED, ctx.function_id, delta, {"jumpkind": jumpkind})
        return
    _follow_control(acc, ctx, delta, block, state, pending, budget=budget)


def _walk_function(
    acc: _Acc, budget: _Budget, ctx: FunctionCtx, by_entry: dict[int, FunctionCtx]
) -> None:
    """Walk block-local symbolic effects, retaining every reached CALL site.

    Each structural cutpoint is visited once. Its effect must therefore start
    from a fresh symbolic state, rather than whichever predecessor happens to
    arrive first. Path-specific constants cannot resolve a block's unknown
    transfer or make admission depend on worklist order. The queued state is
    retained by the control helper as partial evidence, not as an input domain.

    A ``LowerFailure`` out of composition is translated on its exact typed
    ``reason``: ``compose_budget_exceeded`` is the shared-budget stop and
    stays ``DEADLINE_EXCEEDED`` with the original failure chained; every
    other reason is ordinary unsupported SSA — a per-block
    ``LOWERING_REFUSAL`` retaining the exact ``reason``/``message`` while
    the remaining queued cutpoints keep walking.
    """
    pending: list[tuple[int, dict[str, dict[str, Any]]]] = [(0, initial_state())]
    visited: set[int] = set()
    while pending:
        delta, _predecessor_state = pending.pop()
        if delta in visited:
            continue
        visited.add(delta)
        budget.bump()
        acc.blocks += 1
        if acc.blocks > budget.limits.max_blocks:
            raise _BudgetExhausted(
                AdmissionRefusalReason.BLOCK_LIMIT_EXCEEDED,
                {"function": ctx.function_id, "delta": delta, "limit": budget.limits.max_blocks},
            )
        block = ctx.blocks.get(delta)
        if block is None:
            _refuse(acc, AdmissionRefusalReason.BLOCK_UNDECLARED, ctx.function_id, delta, {})
            continue
        state = _compose_cutpoint(acc, budget, ctx, delta, block)
        if state is None:
            continue
        _follow_cutpoint(acc, budget, ctx, delta, block, state, by_entry, pending)


def _resolve_root(
    acc: _Acc, ctxs: dict[str, FunctionCtx], root_key: str
) -> FunctionCtx | None:
    """Resolve the requested root by stable id, then by unique display alias.

    An exact stable function id always wins. A display-name alias selects a
    function only when exactly one grouped function carries it: zero matches
    refuse as ``ROOT_NOT_FOUND`` and multiple matches refuse as
    ``ROOT_AMBIGUOUS`` with every matching id retained, rather than letting
    ``next()`` silently pick one grouped function. The alias is a selection
    boundary only — it grants no equality proof.
    """
    root = ctxs.get(root_key)
    if root is not None:
        return root
    matches = [ctx for ctx in ctxs.values() if ctx.name == root_key]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        _refuse(acc, AdmissionRefusalReason.ROOT_NOT_FOUND, root_key, None, {})
        return None
    _refuse(
        acc, AdmissionRefusalReason.ROOT_AMBIGUOUS, root_key, None,
        {"matches": sorted(ctx.function_id for ctx in matches)},
    )
    return None


def _walk_reached(acc: _Acc, budget: _Budget, by_entry: dict[int, FunctionCtx]) -> None:
    """Drain the reached-function frontier under the original shared budget."""
    while acc.queue:
        current = acc.queue.pop(0)
        if current.function_id in acc.reached:
            continue
        acc.reached[current.function_id] = current
        budget.bump()
        if len(acc.reached) > budget.limits.max_functions:
            raise _BudgetExhausted(
                AdmissionRefusalReason.FUNCTION_LIMIT_EXCEEDED,
                {"function": current.function_id, "limit": budget.limits.max_functions},
            )
        _walk_function(acc, budget, current, by_entry)


def admit_call_graph(
    doc: dict[str, Any], root_key: str, *, limits: AdmissionLimits | None = None
) -> AdmissionReport:
    """Admit the bounded binary-derived call graph reachable from ``root_key``.

    Returns a typed report in every case: ``ADMITTED`` retains the deduplicated
    complete ``CallGraph`` plus its SCC partition proposal; ``INCOMPLETE``
    retains typed refusal records and the partial site evidence. A complete
    graph is a structural proposal only — it grants no equality or PROVED
    status. Malformed caller contracts raise ``ValueError`` instead.
    """
    if not isinstance(doc, dict):
        raise ValueError("admission document must be a mapping")
    if type(root_key) is not str or not root_key:
        raise ValueError("root function key must be a non-empty string")
    active = limits if limits is not None else AdmissionLimits()
    budget = _Budget.start(active)
    acc = _Acc()
    raw = doc.get("functions")
    record_count = len(raw) if isinstance(raw, list) else 0
    early = _check_document(acc, budget, raw, record_count, active)
    if early is not None:
        return early
    ctxs: dict[str, FunctionCtx] = {}
    try:
        ctxs = group_functions(doc)
    except Real16CallRefusal as exc:
        _refuse(acc, _map_reason(exc.reason), None, None, dict(exc.detail, legacy_reason=exc.reason))
        return _report(acc, budget, None, record_count)
    root = _resolve_root(acc, ctxs, root_key)
    if root is None:
        return _report(acc, budget, None, record_count)
    by_entry = {c.entry_linear: c for c in ctxs.values()}
    acc.enqueued.add(root.function_id)
    acc.queue.append(root)
    try:
        _walk_reached(acc, budget, by_entry)
    except _BudgetExhausted as exc:
        _refuse(acc, exc.reason, None, None, exc.detail)
    try:
        check_lowering_refusals(doc, set(acc.reached))
    except Real16CallRefusal as exc:
        _refuse(acc, _map_reason(exc.reason), None, None, dict(exc.detail, legacy_reason=exc.reason))
    return _report(acc, budget, FunctionId(root.function_id), record_count)


def _report(
    acc: _Acc, budget: _Budget, root: FunctionId | None, record_count: int
) -> AdmissionReport:
    """Assemble the typed report, delegating SCC only on a clean admission."""
    graph: CallGraph | None = None
    analysis: ComponentAnalysis | None = None
    if root is not None and not acc.refusals:
        remaining_ms = budget.remaining_ms()
        remaining_steps = budget.limits.max_steps - budget.steps
        if remaining_ms == 0:
            _refuse(acc, AdmissionRefusalReason.DEADLINE_EXCEEDED, None, None, {"counter": "deadline"})
        elif remaining_steps <= 0:
            _refuse(acc, AdmissionRefusalReason.STEP_BUDGET_EXCEEDED, None, None, {"counter": "steps"})
        else:
            vertices = {FunctionId(fid) for fid in acc.reached}
            for edge in acc.edges:
                vertices.add(edge.caller)
                vertices.add(edge.callee)
            try:
                analysis = analyze_call_graph(
                    vertices=sorted(vertices),
                    edges=sorted(acc.edges),
                    limits=ComponentLimits(
                        max_vertices=budget.limits.max_functions,
                        max_edges=budget.limits.max_sites,
                        max_steps=remaining_steps,
                        deadline_ms=remaining_ms,
                    ),
                )
                graph = analysis.graph
            except RecursiveCallRefusal as exc:
                _refuse(
                    acc, AdmissionRefusalReason.ANALYSIS_REFUSED, None, None,
                    dict(exc.detail, component_reason=str(exc.reason)),
                )
    resolved = sum(1 for site in acc.sites if site.status is SiteStatus.RESOLVED)
    return AdmissionReport(
        root=root,
        scope=CoverageScope.REACHABLE_FROM_ROOT,
        verdict=AdmissionVerdict.ADMITTED if not acc.refusals else AdmissionVerdict.INCOMPLETE,
        sites=tuple(acc.sites),
        refusals=tuple(acc.refusals),
        counters=AdmissionCounters(
            document_records=record_count,
            reached_functions=len(acc.reached),
            blocks_composed=acc.blocks,
            call_sites=len(acc.sites),
            resolved_sites=resolved,
            refused_sites=len(acc.sites) - resolved,
            refusals=len(acc.refusals),
            edges=len(acc.edges),
            steps=budget.steps,
            analysis_steps=analysis.counters.steps if analysis is not None else 0,
        ),
        graph=graph,
        analysis=analysis,
    )
