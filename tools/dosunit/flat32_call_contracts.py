"""Layer: validation call composition contracts.

Responsibility: typed limits, refusal type and shared state for bounded
flat-i386 direct-call composition.

The dataclasses here are the owned contract between
``flat32_call_lowering`` (VEX lift + part lowering), ``flat32_call_execution``
(acyclic path composition and call inlining) and the public
``flat32_call_composition`` surface.  Nothing in this module lifts,
executes or compares; it only names the shapes and bounds those stages share.
"""

from __future__ import annotations

import itertools
import math
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from tools.dosunit import straightline_ssa as S
from tools.dosunit.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.proof_contracts import ProofStatus

if TYPE_CHECKING:
    import angr
    import pyvex

PRESERVED_OUTPUTS: tuple[str, ...] = ("ebx", "ebp", "esi", "edi", "esp")
"""ABI-preserved registers that are always observable in a composed proof.

Caller-selected ``outputs`` pick which return values matter; a callee that
clobbers a preserved register must still fail the proof even when the caller
only asked for ``eax``, so these names are always unioned into the observed
output set.  ``eip``, ``memory`` and ``io`` are mandatory as well and are
added by ``summarize_with_calls``.
"""


@dataclass(frozen=True)
class CallCompositionLimits:
    """Bound lifting, inlining and solver work for one composed function.

    ``max_term_nodes`` budgets *distinct* shared-DAG dict nodes as measured
    by :func:`_term_nodes`, which derives its outbound-slot and depth caps
    from the same value; a subexpression referenced from N parents is
    charged once, not N times.

    ``max_tail_transfers`` bounds admitted unconditional tail transfers
    (terminal ``jmp`` to a foreign declared entry).  Each tail transfer also
    consumes one ``max_inline_depth`` level like a real call, so thunk
    chains stay bounded by both limits.

    ``max_total_seconds`` is an optional wall-clock bound for one
    ``summarize_with_calls`` composition, measured on ``time.monotonic``
    from session start.  ``None`` (the default) preserves the historical
    behaviour: the composition is bounded only by an explicit
    ``total_deadline`` argument.  ``compare_functions_with_calls`` always
    imposes its own absolute deadline derived from ``timeout_ms`` /
    ``total_deadline`` and each side's session takes the tightest
    applicable bound, so the compare path is bounded regardless of this
    field.

    ``max_indirect_call_targets`` bounds the selector leaves enumerated at
    one deferred-indirect call site.  Every leaf is a separate
    return-target proof obligation, so the bound counts proof paths, not
    just distinct callees — which ``max_inlined_calls`` already charges.
    Appended last so existing positional construction keeps its meaning.
    """

    max_blocks_per_function: int = 64
    max_inline_depth: int = 4
    max_inlined_calls: int = 32
    max_compositions: int = 128
    max_term_nodes: int = 12000
    max_lift_bytes: int = 4096
    max_assignments_per_block: int = 2048
    ret_check_timeout_ms: int = 1000
    max_solver_inputs: int = 64
    max_memory_stores: int = 128
    max_tail_transfers: int = 32
    max_total_seconds: float | None = None
    max_indirect_call_targets: int = 8


class CallProofSide(StrEnum):
    """Comparison origin of a retained direct-call proof failure."""

    ORACLE = "oracle"
    CANDIDATE = "candidate"


@dataclass(frozen=True)
class ReturnTargetProofFailure:
    """Typed evidence retained when a callee return-target proof fails.

    Populated only by ``flat32_call_execution._prove_return_target`` and
    carried on :class:`CallCompositionRefusal`; every other refusal leaves the
    slot empty.  ``solver_result`` is the bounded SSA comparison document for
    the substituted return target versus the recorded fallthrough — its
    ``mismatches`` hold the Z3 countermodel inputs when ``status`` is
    ``ProofStatus.COUNTEREXAMPLE``.  ``status`` is ``None`` only when the
    backend returned a status string outside the legacy map.  ``side`` is
    stamped by the public two-project comparator, the only stage that can
    distinguish oracle from candidate evidence.

    ``callsite`` is the exact terminal CALL IMark address; ``call_block`` is
    the owning block's start, which can include argument setup instructions.

    ``selector`` is the composed path predicate under which the failed
    return-target obligation ran — present only for a deferred-indirect
    call leaf, where it names exactly which selector arm could not prove
    its return frame.  A direct call carries ``None``.
    """

    status: ProofStatus | None
    callsite: int
    call_block: int
    target: int
    fallthrough: int
    solver_result: dict[str, Any]
    callee: str = ""
    side: CallProofSide | None = None
    selector: dict[str, Any] | None = None

    def to_document(self) -> dict[str, Any]:
        """Serialize the failure as a JSON-safe compare-report payload."""
        return {
            "status": self.status.value if self.status is not None else None,
            "callsite": hex(self.callsite),
            "call_block": hex(self.call_block),
            "target": hex(self.target),
            "fallthrough": hex(self.fallthrough),
            "callee": self.callee,
            "side": self.side.value if self.side is not None else None,
            "selector": self.selector,
            "solver_result": self.solver_result,
        }


class CallCompositionRefusal(ValueError):
    """An incomplete or unsupported call region, never an equivalence verdict.

    ``str(error)`` remains the stable machine-readable reason.  ``evidence``
    optionally carries the typed return-target proof failure; it is populated
    only for ``call_return_target_*`` refusals.
    """

    def __init__(
        self, reason: str, *, evidence: ReturnTargetProofFailure | None = None
    ) -> None:
        """Bind the stable reason string and optional typed proof evidence."""
        super().__init__(reason)
        self.evidence: ReturnTargetProofFailure | None = evidence


@dataclass(frozen=True)
class _LiftedBlock:
    """One lifted and lowered VEX block with validated transfer metadata.

    ``tail_targets`` records admitted acyclic tail transfers: the block's
    unconditional terminal ``Ijk_Boring`` target is a separately declared
    function entry outside the owning function's byte range, with no
    conditional ``Ist.Exit`` edges and a real jump (not contiguous
    fallthrough into the next declared range).  Tail targets are never part
    of ``successors`` — they leave the owning closure — and execution
    composes the destination summary over the live state with no
    return-address push and no stack adjustment.  Conditional exits to
    foreign entries, foreign interior targets and undeclared targets are
    never admitted here; they keep refusing as
    ``edge_outside_declared_function``.

    ``call_target`` is ``None`` for an ``Ijk_Call`` block whose
    ``irsb.next`` is not a lifted constant — a deferred-indirect call
    admitted only while ``_ComposeSession.admit_indirect_calls`` is set.
    Execution then proves the finite target set from the block's composed
    ``ip`` term; it is never a wildcard.
    """

    address: int
    irsb: pyvex.IRSB
    part: dict[str, Any]
    jumpkind: str
    successors: tuple[int, ...]
    call_target: int | None
    fallthrough: int | None
    tail_targets: frozenset[int] = frozenset()


@dataclass
class _ComposeSession:
    """Per-binary lifting, lowering and inlining state for one comparison side.

    ``entry_domain`` is the optional caller-declared premise on the root
    entry ``esp`` input. Generic nested summaries cannot reuse this interval
    for their own entry frame. A bounded retry may instead bind every callee
    input to the root's live symbolic state before walking it. Only in that
    mode do all free inputs refer to the root, including at nested callsites.
    ``root_bound_inputs`` never transports an interval to a different frame.
    Work counters remain charged across a retry; its failed attempt's summary
    cache and proof records are discarded. Root-call failures already contain
    caller context and are not retried.

    ``tail_transfers`` and ``tail_sites`` record the dependency evidence for
    admitted tail transfers (unconditional terminal ``jmp`` to a foreign
    declared entry, composed over the live state with no return-address
    push).  They are parallel to ``inlined_calls``/``call_sites`` but remain
    distinct: a tail transfer is not a call, carries no return-target proof
    of its own, and its composed ``eip`` is discharged by the enclosing
    call's proof or observed as the root summary's terminal state.

    ``compose_stats`` is the shared budget-owner dict consumed by
    ``S._compose_deadline_check`` and propagated into
    ``S._compose_block_outputs`` / ``S._merge_abi_states`` so their inner
    loops enforce the same bound.  Its ``"deadline"`` key holds an absolute
    ``time.monotonic()`` float when the caller supplied or derived a total
    deadline; an absent or non-float value means unbounded, matching the
    shared owner's convention.  The same dict also carries the merge
    ``eq_cache``/``eq_keepalive`` the shared merge helper maintains.

    ``admit_indirect_calls`` is the composed-call engine mode set by
    ``flat32_call_execution._compose_root``: while it is set, an
    ``Ijk_Call`` block whose ``irsb.next`` is not a lifted constant is
    lifted with ``call_target=None`` and the finite target set is proved
    from the composed ``ip`` term during execution.  Direct
    ``_lift_function`` consumers that never pass through ``_compose_root``
    keep the historical lift-time ``call_indirect_target`` refusal.
    """

    project: angr.Project
    functions: dict[int, int]
    labels: dict[int, str]
    limits: CallCompositionLimits
    reg_widths: dict[str, int]
    entry_domain: Flat32ProofDomain | None = None
    blocks: dict[int, dict[int, _LiftedBlock]] = field(default_factory=dict)
    summaries: dict[int, dict[str, dict[str, Any]]] = field(default_factory=dict)
    call_sites: list[dict[str, Any]] = field(default_factory=list)
    tail_sites: list[dict[str, Any]] = field(default_factory=list)
    compositions: int = 0
    blocks_lifted: int = 0
    inlined_calls: int = 0
    tail_transfers: int = 0
    return_targets_proved: int = 0
    compose_stats: dict[str, Any] = field(default_factory=dict)
    root_bound_inputs: bool = False
    admit_indirect_calls: bool = False


def _check_compose_deadline(compose_stats: dict[str, Any] | None) -> None:
    """Enforce the shared absolute deadline as a typed call-composition refusal.

    Reuses ``S._compose_deadline_check`` — the owned budget check — and
    converts its ``LowerFailure`` into :class:`CallCompositionRefusal` with
    the same stable ``compose_budget_exceeded`` reason, so an expired
    deadline can never escape this layer as an untyped exception or be
    mistaken for a verdict.  With no deadline key the shared check is a
    no-op, preserving the unbounded opt-out.
    """
    try:
        S._compose_deadline_check(compose_stats)
    except S.LowerFailure as error:
        raise CallCompositionRefusal(error.reason) from error


def _compose_remaining_ms(compose_stats: dict[str, Any] | None) -> int | None:
    """Return whole milliseconds left before the shared deadline, if set.

    ``None`` means no deadline is bound.  A non-positive value means the
    deadline has already passed; callers refuse before granting that budget
    to a nested solver run.
    """
    if not isinstance(compose_stats, dict):
        return None
    deadline = compose_stats.get("deadline")
    if not isinstance(deadline, float) or not math.isfinite(deadline):
        return None
    return int((deadline - time.monotonic()) * 1000)


def _ret_proof_timeout_ms(session: _ComposeSession) -> int:
    """Clamp a return-target proof's solver budget to the shared deadline.

    Each callee return-target proof gets at most
    ``limits.ret_check_timeout_ms`` *and* never more than the milliseconds
    remaining before the session deadline — the whole comparison draws from
    one budget rather than granting each proof a fresh allotment.  An
    already-expired deadline refuses with ``compose_budget_exceeded``
    instead of running the solver at all.
    """
    remaining_ms = _compose_remaining_ms(session.compose_stats)
    if remaining_ms is not None and remaining_ms <= 0:
        raise CallCompositionRefusal("compose_budget_exceeded")
    if remaining_ms is None:
        return session.limits.ret_check_timeout_ms
    if session.limits.ret_check_timeout_ms <= 0:
        # Zero means unlimited to Z3; the shared finite budget still applies.
        return remaining_ms
    return min(session.limits.ret_check_timeout_ms, remaining_ms)


def _resolve_total_deadline(
    limits: CallCompositionLimits, total_deadline: float | None
) -> float | None:
    """Compute the tightest applicable absolute ``time.monotonic`` deadline.

    An explicit ``total_deadline`` argument (the shared compare deadline when
    called through ``compare_functions_with_calls``) and the optional
    ``limits.max_total_seconds`` bound both apply; the session takes their
    minimum.  ``None`` keeps the composition deadline-free, which remains
    available only to direct ``summarize_with_calls`` callers that opt out.
    A non-finite bound (``NaN``/``±inf``) is refused with
    ``invalid_total_deadline``: ``NaN`` comparisons never hold, so it would
    silently disable the shared deadline instead of bounding it.
    """
    deadline = float(total_deadline) if total_deadline is not None else None
    if deadline is not None and not math.isfinite(deadline):
        raise CallCompositionRefusal("invalid_total_deadline")
    if limits.max_total_seconds is not None:
        own = time.monotonic() + limits.max_total_seconds
        if not math.isfinite(own):
            raise CallCompositionRefusal("invalid_total_deadline")
        deadline = own if deadline is None else min(deadline, own)
    return deadline


def _register_widths() -> dict[str, int]:
    """Read the installed 32-bit register map; refuse a 16-bit or absent seam."""
    widths = dict(S.REG_BY_OFFSET.values())
    if widths.get("esp") != 32 or widths.get("eip") != 32:
        raise CallCompositionRefusal("unsupported_register_map")
    return widths


def _const_term_int(term: Any) -> int | None:  # noqa: ANN401 — dynamic SSA JSON leaf
    """Accept only a full-width constant term; everything else is not a target."""
    if not isinstance(term, dict) or term.get("op") != "const" or term.get("width") != 32:
        return None
    value = term.get("value")
    if not isinstance(value, (int, str)):
        return None
    parsed = int(value, 0) if isinstance(value, str) else value
    return parsed if 0 <= parsed <= 0xFFFFFFFF else None


_TERM_EDGE_FACTOR: int = 8
"""Outbound-slot budget for ``_term_nodes`` as a multiple of ``max_term_nodes``.

Realistic composed term dicts carry at most about seven outbound slots (a
handful of scalar fields plus a short ``args`` list), so this derived cap
refuses pathological fan-out — including scalar-only giant payloads —
while keeping the full distinct-node budget reachable for real terms.
"""

_TERM_DEPTH_LIMIT: int = 256
"""Depth cap for ``_term_nodes``, sized under interpreter recursion headroom.

Recursive consumers such as ``straightline_ssa._materialize_json_term``
walk term structure one frame per level, so an over-deep chain must refuse
here instead of overflowing the interpreter stack downstream.
"""


def _term_height(
    current: dict[Any, Any] | list[Any] | tuple[Any, ...], heights: Mapping[int, int]
) -> int:
    """Return the longest container suffix after every child has been visited.

    Shared children retain their full suffix height. This prevents visiting a
    subtree first through a shallow root from hiding a later over-deep path.
    The caller has already bounded the number of outbound slots.
    """
    children = current.values() if isinstance(current, dict) else current
    height = 0
    for child in children:
        if isinstance(child, (dict, list, tuple)):
            height = max(height, 1 + heights[id(child)])
    return height


def _term_nodes(terms: object, limit: int) -> int:
    """Count distinct inlined JSON term nodes under a bounded DAG traversal.

    Composed states reuse subexpression objects across registers, ``ite``
    arms and inlined calls, so ``terms`` is a shared DAG, not a tree: an
    occurrence count misreports retained work by orders of magnitude.  Each
    distinct dict is charged once by ``id`` for the duration of this single
    walk; the caller's ``terms`` reference keeps every reachable object
    alive, so no id can be recycled mid-walk, and nothing is persisted.

    Any violated bound returns ``limit + 1`` so every caller refuses:

    - ``nodes``: distinct dicts — the retained term count — over ``limit``;
    - ``edges``: outbound dict/list/tuple slots over
      ``limit * _TERM_EDGE_FACTOR``, charged via ``len`` before children are
      queued, which also bounds container metadata and scalar-only payloads
      without an unbounded copy or walk ahead of the guard;
    - ``depth``: longest container path over ``_TERM_DEPTH_LIMIT``; cached
      suffix heights make this independent of root/operand traversal order;
    - cycles: a container reached while still on the DFS stack is a real
      cycle — a DAG cross-edge already has a cached height — and refuses
      rather than looping.
    """
    edge_budget = limit * _TERM_EDGE_FACTOR
    pending: list[tuple[object, bool, int]] = [(terms, False, 0)]
    active: set[int] = set()
    heights: dict[int, int] = {}
    nodes = 0
    edges = 0
    while pending:
        current, leaving, depth = pending.pop()
        if not isinstance(current, (dict, list, tuple)):
            continue
        key = id(current)
        if leaving:
            active.remove(key)
            heights[key] = _term_height(current, heights)
        if depth + heights.get(key, 0) > _TERM_DEPTH_LIMIT or key in active:
            return limit + 1
        if key in heights:
            continue
        active.add(key)
        pending.append((current, True, depth))
        edges += len(current)
        if edges > edge_budget:
            return limit + 1
        children: Iterator[object]
        if isinstance(current, dict):
            nodes += 1
            if nodes > limit:
                return limit + 1
            children = map(current.__getitem__, reversed(current))
        else:
            children = reversed(current)
        pending.extend(
            (child, False, depth + 1) for child in children if isinstance(child, (dict, list, tuple))
        )
    return nodes


def _initial_state(reg_widths: Mapping[str, int]) -> dict[str, dict[str, Any]]:
    """Give the composed function unconstrained flat machine inputs."""
    state = {name: {"op": "input", "name": name, "width": width} for name, width in reg_widths.items()}
    state["memory"] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    state["io"] = {"op": "mem_input", "name": "io", "addr_width": 32, "value_width": 8}
    return state


def _normalize_function_map(functions: Mapping[int, int]) -> dict[int, int]:
    """Validate declared complete function byte ranges; names are not semantics."""
    normalized: dict[int, int] = {}
    spans: list[tuple[int, int]] = []
    for entry, size in functions.items():
        if (
            not isinstance(entry, int)
            or not isinstance(size, int)
            or entry < 0
            or entry > 0xFFFFFFFF
            or size <= 0
        ):
            raise CallCompositionRefusal("invalid_function_ranges")
        normalized[entry] = size
        spans.append((entry, entry + size))
    spans.sort()
    for (_lower_start, lower_end), (upper_start, _upper_end) in itertools.pairwise(spans):
        if upper_start < lower_end:
            raise CallCompositionRefusal("overlapping_function_ranges")
    return normalized
