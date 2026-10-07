"""Layer: tools/dosunit real-mode comparator contracts.

Responsibility: typed boundaries and term machinery for bounded real16
direct-call composition (limits, refusals, session counters, grouped-function
context, substitution, DAG-aware term counting, term materialization, and the
Z3 equality-proof primitive).  No control-flow walking lives here; see
``real16_call_execution`` for composition and ``real16_call_evidence`` for
document admission.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector

if TYPE_CHECKING:
    from tools.dosunit.contracts.ordered_io_environment import OrderedIoContract


@dataclass(frozen=True)
class Real16CallLimits:
    """Composition resource bounds; exceeding any of them refuses."""

    max_inline_depth: int = 8
    max_inlined_calls: int = 64
    max_compositions: int = 512
    max_term_nodes: int = 4_000_000
    max_indirect_call_targets: int = 4
    max_indirect_call_candidates: int = 16
    ret_check_timeout_ms: int = 15_000
    max_solver_assignments: int = 0
    max_solver_inputs: int = 0
    max_solver_memory_stores: int = 32


class Real16CallRefusal(Exception):
    """Fail-closed composition refusal carrying a stable reason string."""

    def __init__(self, reason: str, detail: dict[str, Any] | None = None) -> None:
        """Retain the explicit admission or proof obligation that failed."""
        super().__init__(reason)
        self.reason = reason
        self.detail = dict(detail or {})


@dataclass
class ComposeSession:
    """Mutable per-composition counters and the shared deadline."""

    limits: Real16CallLimits
    stats: dict[str, Any]
    inlined_calls: int = 0
    return_targets_proved: int = 0
    cs_preserved_proved: int = 0
    admit_indirect_calls: bool = False
    indirect_call_sites: int = 0
    indirect_targets_proved: int = 0
    resolved_contexts: dict[str, FunctionCtx] = field(default_factory=dict)
    indirect_resolver: IndirectTargetResolver | None = None
    io_model: OrderedIoContract | None = None

    @classmethod
    def with_deadline(cls, limits: Real16CallLimits, timeout_ms: int) -> ComposeSession:
        """Create a session whose deadline trips ``_compose_deadline_check``."""
        return cls(
            limits=limits,
            stats={"deadline": time.monotonic() + max(timeout_ms, 1) / 1000.0},
        )

    def bump(self) -> None:
        """Charge one block composition; refuse on budget/deadline."""
        self.stats["compositions"] = self.stats.get("compositions", 0) + 1
        if self.stats["compositions"] > self.limits.max_compositions:
            raise Real16CallRefusal(
                "compose_budget_exceeded",
                {"counter": "compositions", "limit": self.limits.max_compositions},
            )
        S._compose_deadline_check(self.stats)

    def remaining_ms(self, maximum: int) -> int:
        """Cap one solver operation by the remaining shared composition budget."""
        deadline = self.stats["deadline"]
        if not isinstance(deadline, float):
            raise Real16CallRefusal("compose_deadline_missing")
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise Real16CallRefusal("compose_budget_exceeded", {"counter": "deadline"})
        return min(max(maximum, 1), remaining)


@dataclass(frozen=True)
class FunctionCtx:
    """One grouped function: entry linear address and blocks keyed by delta."""

    function_id: str
    name: str
    entry_linear: int
    blocks: dict[int, dict[str, Any]]
    body_size: int
    body_sha256: str


@dataclass(frozen=True)
class DirectCallSite:
    """Binary-derived direct target and caller continuation of a decoded CALL."""

    target: int
    fallthrough: int
    fall_delta: int


@dataclass(frozen=True)
class IndirectCallPostState:
    """Closed multi-target callee post-state plus the caller continuation."""

    state: dict[str, dict[str, Any]]
    fall_delta: int
    targets: tuple[int, ...]


class IndirectTargetResolver(Protocol):
    """Catalog-backed proposal surface for bounded indirect call targets.

    The resolver only proposes which catalog entries exist and owns each one;
    admission is proved by the SSA solver against the composed control term.
    """

    def candidate_entries(self, session: ComposeSession) -> list[int]:
        """Bounded candidate enumeration; refuses before materializing too many.

        The session's ``max_indirect_call_candidates`` limit bounds discovery
        and sorting; exceeding it refuses with ``compose_budget_exceeded``
        rather than truncating the set and pretending coverage was proved.
        """
        ...

    def resolve(self, entry: int, session: ComposeSession) -> FunctionCtx:
        """Return the unique validated owner under the shared composition deadline."""
        ...


def substitute(term: Any, state: dict[str, dict[str, Any]], cache: dict[int, dict[str, Any]]) -> Any:  # noqa: ANN401
    """Substitute ``input``/``mem_input`` leaves with live caller-state terms."""
    if not isinstance(term, dict):
        return term
    cached = cache.get(id(term))
    if cached is not None:
        return cached
    op = term.get("op")
    if op == "input":
        result = state.get(str(term.get("name")), term)
    elif op == "mem_input":
        result = state.get("memory" if str(term.get("name")) == "mem" else str(term.get("name")), term)
    else:
        args = term.get("args")
        if isinstance(args, list):
            result = dict(term)
            result["args"] = [substitute(item, state, cache) for item in args]
        else:
            result = term
    cache[id(term)] = result
    return result


def substitute_state_term(term: Any, state: dict[str, dict[str, Any]]) -> Any:  # noqa: ANN401
    """Substitute a callee term against caller state with a fresh cache."""
    return substitute(term, state, {})


def term_nodes(terms: object, limit: int) -> int:
    """DAG-aware node count over dict/list structure, early exit at ``limit``."""
    seen: set[int] = set()
    stack = [terms]
    count = 0
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if id(node) in seen:
                continue
            seen.add(id(node))
            count += 1
            if count > limit:
                return count
            stack.extend(node.values())
        elif isinstance(node, (list, tuple)):
            stack.extend(node)
    return count


def const_term(term: Any) -> int | None:  # noqa: ANN401
    """Resolve exact literal bitvector conversions; symbolic terms remain unknown."""
    if isinstance(term, dict):
        literal = constant_bitvector(term)
        return literal[0] if literal is not None else None
    return None


def initial_state() -> dict[str, dict[str, Any]]:
    """Fully symbolic real16 entry state over the active register model."""
    state: dict[str, dict[str, Any]] = {
        str(name): {"op": "input", "name": str(name), "width": int(width)}
        for name, width in S._ssa_register_widths().items()
    }
    state["memory"] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    state["io"] = {"op": "mem_input", "name": "io", "addr_width": 32, "value_width": 8}
    return state


def materialize_function(function_id: str, state: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Materialize a composed state into a ``_compare_functions`` document."""
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    outputs = {
        str(name): S._materialize_json_term(
            term, assignments=assignments, memo=memo, term_cache=cache
        )
        for name, term in state.items()
        if isinstance(term, dict)
    }
    return {
        "function": {"id": function_id, "name": function_id},
        "inputs": S._term_input_items(outputs.values(), assignments),
        "assignments": assignments,
        "outputs": outputs,
    }


def prove_terms_equal(
    term_a: dict[str, Any],
    term_b: dict[str, Any],
    timeout_ms: int,
    *, input_constraints: list[dict[str, Any]] | None = None,
) -> ProofStatus:
    """Z3-prove two substituted SSA terms equal; refusal/unknown never proves."""
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    left = S._materialize_json_term(term_a, assignments=assignments, memo=memo, term_cache=cache)
    right = S._materialize_json_term(term_b, assignments=assignments, memo=memo, term_cache=cache)
    inputs = S._term_input_items([left, right], assignments)
    result = S._compare_functions(
        {
            "function": {"id": "proof:a"},
            "inputs": inputs,
            "assignments": assignments,
            "outputs": {"v": left},
        },
        {
            "function": {"id": "proof:b"},
            "inputs": inputs,
            "assignments": assignments,
            "outputs": {"v": right},
        },
        timeout_ms=timeout_ms, input_constraints=input_constraints,
    )
    status = proof_status_from_legacy(result.get("status"))
    return status if status is not None else ProofStatus.UNKNOWN
