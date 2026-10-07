"""Bounded real16 symbolic-control proof adapters for the SSA comparator.

Layer: dosunit semantic comparison.

Responsibility: connect recorded real16 SSA control terms to the
``real16_control_targets`` proof owner through the comparator's existing Z3
seam.  Each proof attempt shares one memoized, deadline-checked encode
context: every unique DAG node and every assignment ref encodes at most once
across the control term, the live ``cs`` binding, and branch arms — composed
DAGs cost linear encode work instead of repeated recursive encoding.  Cycles,
missing refs, malformed nodes and conflicting input specs are typed refusals.
Work is capped by a per-attempt wall-clock guard plus the caller's compose
deadline; the per-query solver timeout alone is never the budget.  Evidence
accounting follows the authoritative ``FactCounters`` contract: classified
work must materialize or count as failure, so the pipeline fails closed.
"""

from __future__ import annotations

import contextlib
import sys
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from tools.dosunit.compare.real16_control_targets import (
    DEFAULT_PROOF_BUDGET,
    ControlDestinationProof,
    ControlDomainFailure,
    ControlProofBudget,
    ControlProofVerdict,
    _leaf_spec,
    producer_domain_fact,
    prove_call_control_output,
    prove_control_term,
)
from tools.dosunit.contracts.model import DosUnitError
from tools.dosunit.contracts.proof_contracts import FactCounters
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector

__all__ = [
    "CONTROL_PROOF_ATTEMPT_SECONDS",
    "BoundaryProof",
    "ControlEvidenceFailure",
    "ControlProofLedger",
    "Z3TermCallbacks",
    "fetch_domain_marker",
    "prove_call_bound_output",
    "prove_composed_control_term",
]

CONTROL_PROOF_ATTEMPT_SECONDS: Final[float] = 0.25
"""Hard per-attempt wall-clock cap; a tighter caller deadline always wins."""

_LEAF_OPS: Final[frozenset[str]] = frozenset({"input", "mem_input", "const"})
_BUDGET_STRIDE: Final[int] = 64
_MAX_ATTEMPT_RECORDS: Final[int] = 128


@dataclass(frozen=True, slots=True)
class Z3TermCallbacks:
    """Comparator-owned Z3 seam passed explicitly at this boundary.

    The boundary never interprets operators: leaves go through ``term``,
    composites through ``apply``, input specs through ``inputs`` — op
    semantics stay owned by the comparator; no import cycles.
    """

    inputs: Callable[[dict[str, Any], dict[str, Any], Any], dict[str, tuple[Any, int]]]
    term: Callable[..., Any]
    apply: Callable[[str, int, list[Any], Any], Any]


class ControlEvidenceFailure(StrEnum):
    """Typed refusal when attempted control evidence has no consumed product."""

    UNMATERIALIZED = "control_evidence_unmaterialized"
    PROOF_REFUSED = "control_proof_refused"


class _LedgerFailure(StrEnum):
    """Ledger-level failure notes that are not solver-verdict failures."""

    PRODUCT_NOT_CONSUMED = "product_not_consumed"


@dataclass(slots=True)
class ControlProofLedger:
    """Closed ``FactCounters`` accounting for one caller's proof attempts.

    ``raw`` counts obligations offered, ``normalized`` counts attempts that
    reached an encodable input set, ``classified`` counts solver verdicts,
    and ``materialized`` counts consumed products.  Every classified-but-
    unproven or proven-but-unconsumed attempt counts as failure, so
    ``counters().closed()`` reports the authoritative pipeline invariant.
    Per-attempt diagnostics (role/verdict/query/time/domain) are retained in
    ``attempts`` bounded by ``_MAX_ATTEMPT_RECORDS``.
    """

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    solver_queries: int = 0
    solver_time_ms: int = 0
    term_nodes: int = 0
    encoded_nodes: int = 0
    failure_reasons: list[str] = field(default_factory=list)
    attempts: list[dict[str, Any]] = field(default_factory=list)
    attempts_truncated: bool = False
    pending_products: int = 0

    def counters(self) -> FactCounters:
        """Snapshot the five counters as the authoritative contract type."""
        return FactCounters(self.raw_fact_count, self.normalized_fact_count,
                            self.classified_fact_count, self.materialized_count,
                            self.failure_count)

    def accounting_failure(self) -> ControlEvidenceFailure | None:
        """Require the shared invariant and settlement of every produced product.

        FactCounters closes the aggregate census; pending_products additionally
        prevents one consumed proof from concealing a different dropped product.
        """
        if not self.counters().closed() or self.pending_products:
            return ControlEvidenceFailure.UNMATERIALIZED
        if self.failure_count:
            return ControlEvidenceFailure.PROOF_REFUSED
        return None

    def document(self) -> dict[str, Any]:
        """Serialize counters, solver evidence and per-attempt detail."""
        counters = self.counters()
        return {
            "raw_fact_count": counters.raw_fact_count,
            "normalized_fact_count": counters.normalized_fact_count,
            "classified_fact_count": counters.classified_fact_count,
            "materialized_count": counters.materialized_count,
            "failure_count": counters.failure_count,
            "closed": self.accounting_failure() is None,
            "pending_products": self.pending_products,
            "solver_queries": self.solver_queries,
            "solver_time_ms": self.solver_time_ms,
            "term_nodes": self.term_nodes,
            "encoded_nodes": self.encoded_nodes,
            "failure_reasons": list(self.failure_reasons),
            "attempts": list(self.attempts),
            "attempts_truncated": self.attempts_truncated,
        }

    def _note(self, record: dict[str, Any]) -> None:
        if len(self.attempts) >= _MAX_ATTEMPT_RECORDS:
            self.attempts_truncated = True
        else:
            self.attempts.append(record)

    def refuse(self, failure: ControlDomainFailure, *, role: str, domain: dict[str, Any]) -> None:
        """Record a typed refusal reached before any solver verdict."""
        self.failure_count += 1
        self.failure_reasons.append(str(failure))
        self._note({"role": role, "verdict": None, "failure": str(failure), "domain": domain})

    def record_verdict(self, proof: ControlDestinationProof, *, role: str, domain: dict[str, Any],
                       encoded_nodes: int, produced: bool) -> None:
        """Record one solver verdict with its query/time/node evidence."""
        self.classified_fact_count += 1
        self.solver_queries += proof.stats.queries
        self.solver_time_ms += proof.stats.solver_time_ms
        self.term_nodes += proof.stats.term_nodes
        self.encoded_nodes += encoded_nodes
        if proof.verdict is ControlProofVerdict.PROVEN and produced:
            self.pending_products += 1
        if proof.verdict is not ControlProofVerdict.PROVEN or not produced:
            self.failure_count += 1
            self.failure_reasons.append(
                str(proof.failure) if proof.failure is not None else "verdict_without_product")
        self._note({
            "role": role, "verdict": str(proof.verdict),
            "failure": str(proof.failure) if proof.failure is not None else None,
            "value": proof.value, "queries": proof.stats.queries,
            "solver_time_ms": proof.stats.solver_time_ms, "term_nodes": proof.stats.term_nodes,
            "encoded_nodes": encoded_nodes, "domain": domain,
        })


@dataclass(slots=True)
class BoundaryProof:
    """One adapter outcome; ``normalized``/``value`` are ``None`` on refusal.

    Proof detail is retained, never discarded; the caller records consumption
    explicitly via :meth:`consume`/:meth:`unconsumed`.  Each outcome may be
    settled exactly once — a second call raises rather than corrupting the
    ledger's materialized/failure counts.
    """

    verdict: ControlProofVerdict | None
    failure: ControlDomainFailure | None
    normalized: dict[str, Any] | None
    value: int | None
    proof: ControlDestinationProof | None
    encoded_nodes: int
    ledger: ControlProofLedger
    _settled: bool = field(default=False, init=False, repr=False, compare=False)

    def consume(self) -> None:
        """Record that the caller consumed this attempt's product."""
        self._settle()
        self.ledger.pending_products -= 1
        self.ledger.materialized_count += 1

    def unconsumed(self) -> None:
        """Record a produced normalization the caller could not consume."""
        self._settle()
        self.ledger.pending_products -= 1
        self.ledger.failure_count += 1
        self.ledger.failure_reasons.append(_LedgerFailure.PRODUCT_NOT_CONSUMED.value)

    def _settle(self) -> None:
        if self._settled:
            raise DosUnitError("boundary proof outcome settled twice")
        if self.verdict is not ControlProofVerdict.PROVEN or (self.normalized is None and self.value is None):
            raise DosUnitError("cannot settle a control proof without a proved product")
        if self.ledger.pending_products <= 0:
            raise DosUnitError("control proof has no pending product in its ledger")
        self._settled = True


class _EncodePhase(StrEnum):
    """Typed phases of the iterative DAG encoder work stack."""

    VISIT = "visit"
    REF = "ref"
    FINALIZE = "finalize"


class _EncodeContext:
    """Shared-memo Z3 encoder bounded by unique-node and time budgets.

    The control term, the ``cs`` binding and every branch arm share
    ``memo``/``ref_cache`` — each unique node and each assignment encodes at
    most once.  ``keepalive`` retains encoded values so ``id()`` keys cannot
    be recycled while the memo lives.  Inline-DAG and ref cycles raise
    ``DosUnitError`` → the proof owner's typed ``term_unencodable`` refusal.
    """

    def __init__(self, *, document: dict[str, Any], inputs: dict[str, tuple[Any, int]],
                 z3: Any, callbacks: Z3TermCallbacks,  # noqa: ANN401
                 assignments: dict[str, dict[str, Any]], deadline: float, max_nodes: int) -> None:
        # This theorem relates raw control effects to native addresses. Relocation
        # substitutions belong only to pair equality, never to native replay.
        self.document = {key: value for key, value in document.items()
                         if key not in {"_constant_normalization", "_constant_normalization_reasons",
                                        "_call_return_address_keys"}}
        self.inputs, self.z3, self.callbacks = inputs, z3, callbacks
        self.assignments, self.deadline, self.max_nodes = assignments, deadline, max_nodes
        self.memo: dict[int, Any] = {}
        self.ref_cache: dict[str, Any] = {}
        self.ref_inflight: set[str] = set()
        self.node_inflight: set[int] = set()
        self.keepalive: list[Any] = []
        self.encoded_nodes = 0

    def encode(self, root: dict[str, Any]) -> Any:  # noqa: ANN401
        """Encode ``root`` through the core seam; each unique node once."""
        if not isinstance(root, dict):
            raise DosUnitError("real16 control term root is not a node")
        stack: list[tuple[_EncodePhase, Any]] = [(_EncodePhase.VISIT, root)]
        while stack:
            self._check_budget()
            tag, payload = stack.pop()
            if tag is _EncodePhase.REF:
                ref_name, node_id, target = payload
                self.ref_inflight.discard(ref_name)
                value = self.memo[id(target)]
                self.ref_cache[ref_name] = value
                self._store(node_id, value)
            elif tag is _EncodePhase.FINALIZE:
                self.node_inflight.discard(id(payload))
                self._store(id(payload), self.callbacks.apply(
                    str(payload["op"]), self._width(payload),
                    [self.memo[id(arg)] for arg in payload["args"]], self.z3))
            elif id(payload) not in self.memo:
                self._visit(payload, id(payload), stack)
        return self.memo[id(root)]

    def _visit(self, node: dict[str, Any], node_id: int, stack: list[tuple[_EncodePhase, Any]]) -> None:
        """First pass over one node: dispatch ref/leaf or expand composite."""
        if "ref" in node:
            self._visit_ref(node, node_id, stack)
            return
        op = node.get("op")
        if op in _LEAF_OPS:
            self._store(node_id, self.callbacks.term(
                node, document=self.document, inputs=self.inputs, z3=self.z3))
            return
        if not isinstance(op, str) or not op:
            raise DosUnitError("real16 control term node has no operator")
        args = node.get("args", [])
        if not isinstance(args, list):
            raise DosUnitError("real16 control term args are not a list")
        self.node_inflight.add(node_id)
        stack.append((_EncodePhase.FINALIZE, node))
        for arg in args:
            self._push_arg(arg, stack)

    def _visit_ref(self, node: dict[str, Any], node_id: int, stack: list[tuple[_EncodePhase, Any]]) -> None:
        """Dispatch one ``ref`` node through the deduplicating ref cache."""
        ref = node.get("ref")
        if not isinstance(ref, str) or not ref:
            raise DosUnitError("real16 control term ref is not an assignment id")
        if ref in self.ref_cache:
            self._store(node_id, self.ref_cache[ref])
            return
        if ref in self.ref_inflight:
            raise DosUnitError(f"cyclic SSA assignment ref: {ref}")
        target = self.assignments.get(ref)
        if not isinstance(target, dict):
            raise DosUnitError(f"unresolved SSA assignment ref: {ref}")
        self.ref_inflight.add(ref)
        stack.append((_EncodePhase.REF, (ref, node_id, target)))
        stack.append((_EncodePhase.VISIT, target))

    def _push_arg(self, arg: Any, stack: list[tuple[_EncodePhase, Any]]) -> None:  # noqa: ANN401
        """Validate and schedule one composite argument for encoding."""
        if not isinstance(arg, dict):
            raise DosUnitError("real16 control term arg is not a node")
        if id(arg) in self.node_inflight:
            raise DosUnitError("cyclic real16 control term DAG")
        if id(arg) not in self.memo:
            stack.append((_EncodePhase.VISIT, arg))

    @staticmethod
    def _width(node: dict[str, Any]) -> int:
        """Declared node width; malformed widths refuse instead of guessing."""
        width = node.get("width", 16)
        if type(width) is not int or width <= 0:
            raise DosUnitError(f"real16 control term node has invalid width: {width!r}")
        return width

    def _check_budget(self) -> None:
        """Enforce the shared unique-node cap and the attempt deadline."""
        if self.encoded_nodes > self.max_nodes:
            raise DosUnitError("real16 control encode exceeded its unique-node budget")
        if time.monotonic() > self.deadline:
            raise DosUnitError("real16 control encode exceeded its attempt deadline")

    def _store(self, node_id: int, value: Any) -> None:  # noqa: ANN401
        """Memoize one encoded node; keep it alive for id-key safety."""
        self.memo[node_id] = value
        self.keepalive.append(value)
        self.encoded_nodes += 1


def _spec_signature(spec: dict[str, Any]) -> tuple[str, int, int] | None:
    """Comparable (kind, width, second width) identity of one input spec."""
    widths = []
    for key in ("addr_width", "value_width") if spec.get("kind") == "memory" else ("width",):
        value = spec.get(key)
        if type(value) is not int and isinstance(value, str):
            try:
                value = int(value, 0)
            except ValueError:
                value = None
        if type(value) is not int or value <= 0:
            return None
        widths.append(value)
    if spec.get("kind") == "memory":
        return ("memory", widths[0], widths[1])
    return ("scalar", widths[0], 0)


def _walk_input_leaves(
    roots: Iterable[Any], *, assignments: dict[str, dict[str, Any]], max_nodes: int, deadline: float
) -> list[dict[str, Any]] | ControlDomainFailure:
    """Bounded shared walk collecting ``input``/``mem_input`` leaf specs.

    ``seen`` is shared across every root so each unique node is visited at
    most once — a true unique-node bound, not a per-root one.  Missing or
    malformed refs and unparseable leaves refuse ``TERM_UNENCODABLE``; the
    node cap and the deadline refuse ``BUDGET_EXHAUSTED``.
    """
    leaves: dict[str, dict[str, Any]] = {}
    seen: set[int] = set()
    stack = [root for root in roots if isinstance(root, dict)]
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if len(seen) > max_nodes or (len(seen) % _BUDGET_STRIDE == 0 and time.monotonic() > deadline):
            return ControlDomainFailure.BUDGET_EXHAUSTED
        if "ref" in node:
            ref = node.get("ref")
            if not isinstance(ref, str) or not ref or not isinstance(assignments.get(ref), dict):
                return ControlDomainFailure.TERM_UNENCODABLE
            stack.append(assignments[ref])
        elif node.get("op") in ("input", "mem_input"):
            spec = _leaf_spec(node)
            if spec is None or not spec.get("name"):
                return ControlDomainFailure.TERM_UNENCODABLE
            name = str(spec["name"])
            if name in leaves and _spec_signature(leaves[name]) != _spec_signature(spec):
                return ControlDomainFailure.TERM_UNENCODABLE
            leaves[name] = spec
        else:
            args = node.get("args", [])
            if isinstance(args, list):
                stack.extend(arg for arg in args if isinstance(arg, dict))
    return list(leaves.values())


def _proof_inputs(
    part: dict[str, Any], terms: Iterable[Any], *, z3: Any, callbacks: Z3TermCallbacks,  # noqa: ANN401
    assignments: dict[str, dict[str, Any]], deadline: float, max_nodes: int,
) -> dict[str, tuple[Any, int]] | ControlDomainFailure:
    """Merge declared inputs with walked leaves; refuse conflicting specs."""
    specs: dict[str, dict[str, Any]] = {}
    for item in part.get("inputs", []) or []:
        if isinstance(item, dict) and item.get("name"):
            name = str(item["name"])
            if _spec_signature(item) is None or (
                    name in specs and _spec_signature(specs[name]) != _spec_signature(item)):
                return ControlDomainFailure.TERM_UNENCODABLE
            specs[name] = item
    walked = _walk_input_leaves(terms, assignments=assignments, max_nodes=max_nodes, deadline=deadline)
    if isinstance(walked, ControlDomainFailure):
        return walked
    for leaf in walked:
        name = str(leaf["name"])
        if name in specs and _spec_signature(specs[name]) != _spec_signature(leaf):
            return ControlDomainFailure.TERM_UNENCODABLE
        specs.setdefault(name, leaf)
    return callbacks.inputs({"inputs": list(specs.values())}, {"inputs": []}, z3)


@contextlib.contextmanager
def _attempt_guard(
    alarm_ms: Callable[[int], contextlib.AbstractContextManager[Any]] | None, seconds: float
) -> Iterator[None]:
    """Hard attempt cap via the caller's alarm factory.

    Signal alarms refuse ``ValueError`` outside the main thread; the encode
    loop's deadline checks plus the per-query solver timeout still bound the
    attempt in that case — never open-ended.
    """
    guard: contextlib.AbstractContextManager[Any] | None = None
    if alarm_ms is not None:
        try:
            guard = alarm_ms(max(1, int(seconds * 1000)))
            guard.__enter__()
        except ValueError:
            guard = None
    try:
        yield
    finally:
        if guard is not None:
            guard.__exit__(*sys.exc_info())


def _domain_of(part: dict[str, Any]) -> dict[str, Any]:
    """The recorded fetch-window quad attached to attempt diagnostics."""
    source_raw: Any = part.get("source")
    source: dict[str, Any] = source_raw if isinstance(source_raw, dict) else {}
    fact_raw: Any = source.get("control_domain")
    fact: dict[str, Any] = fact_raw if isinstance(fact_raw, dict) else {}
    return {key: fact.get(key) for key in ("head_linear", "terminal_linear", "selector_min", "selector_max")}


def _refusal(ledger: ControlProofLedger, role: str, domain: dict[str, Any],
             failure: ControlDomainFailure, encoded: int = 0) -> BoundaryProof:
    """Record a pre-verdict refusal and return the empty proof result."""
    ledger.refuse(failure, role=role, domain=domain)
    return BoundaryProof(None, failure, None, None, None, encoded, ledger)


def _run_attempt(
    part: dict[str, Any], roots: list[Any], *, callbacks: Z3TermCallbacks,
    ledger: ControlProofLedger, deadline: float | None,
    alarm_ms: Callable[[int], contextlib.AbstractContextManager[Any]] | None, role: str,
    prove: Callable[[Callable[[dict[str, Any]], Any], ControlProofBudget, Any],
                    tuple[dict[str, Any] | None, int | None, ControlDestinationProof]],
) -> BoundaryProof:
    """Preflight, bound and record one control-proof attempt.

    ``prove`` receives the shared memoized encoder, the attempt budget and
    the ``z3`` module, runs the proof owner, and returns
    ``(normalized, value, proof)`` — the retained verdict plus the product
    the caller may consume.
    """
    ledger.raw_fact_count += 1
    domain = _domain_of(part)
    attempt_deadline = time.monotonic() + CONTROL_PROOF_ATTEMPT_SECONDS
    if deadline is not None:
        attempt_deadline = min(attempt_deadline, float(deadline))
    remaining = attempt_deadline - time.monotonic()
    if remaining <= 0:
        return _refusal(ledger, role, domain, ControlDomainFailure.BUDGET_EXHAUSTED)
    try:
        import z3
    except ImportError:
        return _refusal(ledger, role, domain, ControlDomainFailure.PROOF_BACKEND_UNAVAILABLE)
    budget = ControlProofBudget(
        max_queries=DEFAULT_PROOF_BUDGET.max_queries,
        solver_timeout_ms=max(1, int(remaining * 1000)),
        solver_rlimit=DEFAULT_PROOF_BUDGET.solver_rlimit,
        max_term_nodes=DEFAULT_PROOF_BUDGET.max_term_nodes,
        deadline=attempt_deadline,
    )
    assignments = {str(item["id"]): item
                   for item in part.get("assignments", []) or [] if isinstance(item, dict) and "id" in item}
    context: _EncodeContext | None = None
    try:
        with _attempt_guard(alarm_ms, remaining):
            inputs = _proof_inputs(part, roots, z3=z3, callbacks=callbacks, assignments=assignments,
                                   deadline=attempt_deadline, max_nodes=budget.max_term_nodes)
            if isinstance(inputs, ControlDomainFailure):
                return _refusal(ledger, role, domain, inputs)
            context = _EncodeContext(document=part, inputs=inputs, z3=z3, callbacks=callbacks,
                                     assignments=assignments, deadline=attempt_deadline,
                                     max_nodes=budget.max_term_nodes)
            ledger.normalized_fact_count += 1
            normalized, value, proof = prove(context.encode, budget, z3)
            if time.monotonic() >= attempt_deadline:
                raise TimeoutError("real16 control proof exceeded its attempt deadline")
    except TimeoutError:
        return _refusal(ledger, role, domain, ControlDomainFailure.BUDGET_EXHAUSTED,
                        context.encoded_nodes if context else 0)
    except (DosUnitError, KeyError, TypeError, ValueError, RecursionError, z3.Z3Exception):
        return _refusal(ledger, role, domain, ControlDomainFailure.TERM_UNENCODABLE,
                        context.encoded_nodes if context else 0)
    produced = normalized is not None or value is not None
    ledger.record_verdict(proof, role=role, domain=domain,
                          encoded_nodes=context.encoded_nodes, produced=produced)
    return BoundaryProof(proof.verdict, proof.failure, normalized, value, proof,
                         context.encoded_nodes, ledger)


def fetch_domain_marker(
    arch: object, *, head_linear: int, terminal_linear: int | None
) -> dict[str, Any] | None:
    """Emit the producer fetch-domain marker; ``None`` unless real16."""
    return producer_domain_fact(arch, head_linear=head_linear, terminal_linear=terminal_linear)


def prove_call_bound_output(
    part: dict[str, Any], term: dict[str, Any], *, output_name: str,
    bound_values: Iterable[int], logical_ip: int | None, current_cs: Any,  # noqa: ANN401
    callbacks: Z3TermCallbacks, ledger: ControlProofLedger | None = None,
    deadline: float | None = None,
    alarm_ms: Callable[[int], contextlib.AbstractContextManager[Any]] | None = None,
) -> BoundaryProof:
    """Prove a call block's control output denotes the decoded callee.

    A refusal carries the retained ``ControlDestinationProof`` and leaves
    the caller's existing skip behavior untouched.
    """
    book = ledger if ledger is not None else ControlProofLedger()
    if not isinstance(term, dict) or constant_bitvector(term) is not None:
        return BoundaryProof(None, None, None, None, None, 0, book)
    cs_term = current_cs if isinstance(current_cs, dict) else None

    def prove(
        encode: Callable[[dict[str, Any]], Any], budget: ControlProofBudget, z3: Any  # noqa: ANN401
    ) -> tuple[dict[str, Any] | None, int | None, ControlDestinationProof]:
        proof = prove_call_control_output(
            part, term, output_name=output_name, bound_values=bound_values,
            logical_ip=logical_ip, current_cs=cs_term, encode_term=encode, z3=z3, budget=budget)
        return None, proof.value if proof.proven else None, proof

    return _run_attempt(part, [term, cs_term], callbacks=callbacks, ledger=book, deadline=deadline,
                        alarm_ms=alarm_ms, role=f"call_output.{output_name}", prove=prove)


def prove_composed_control_term(
    part: dict[str, Any], term: dict[str, Any], *, current_cs: Any,  # noqa: ANN401
    callbacks: Z3TermCallbacks, ledger: ControlProofLedger | None = None,
    deadline: float | None = None,
    alarm_ms: Callable[[int], contextlib.AbstractContextManager[Any]] | None = None,
) -> BoundaryProof:
    """Normalize a composed control term proved under the fetch domain.

    The returned normalized term keeps the ITE's original predicate and only
    swaps individually proved arms for their declared destinations; every
    refusal leaves the caller's ``control_flow_unproved`` path intact.
    """
    book = ledger if ledger is not None else ControlProofLedger()
    if not isinstance(term, dict) or constant_bitvector(term) is not None:
        return BoundaryProof(None, None, None, None, None, 0, book)
    cs_term = current_cs if isinstance(current_cs, dict) else None

    def prove(
        encode: Callable[[dict[str, Any]], Any], budget: ControlProofBudget, z3: Any  # noqa: ANN401
    ) -> tuple[dict[str, Any] | None, int | None, ControlDestinationProof]:
        normalized, proof = prove_control_term(
            part, term, current_cs=cs_term, encode_term=encode, z3=z3, budget=budget)
        return normalized, None, proof

    return _run_attempt(part, [term, cs_term], callbacks=callbacks, ledger=book, deadline=deadline,
                        alarm_ms=alarm_ms, role="control_route", prove=prove)
