"""Prove real16 SSA control terms denote exact native destinations.

Layer: dosunit semantic comparison.

Responsibility: close the real16 symbolic-control boundary. A lowered
``control_ip``/``ip`` term may stay symbolic in the ``cs`` input because the
frontend emits the ``control_coordinates.relative_continuation``
composition ``CS<<4 + word16(next_linear - CS<<4 + displacement)``.  This
module proves — by replaying the actual recorded term DAG through the
existing Z3 boundary — that under *every* selector able to fetch the block
head, the term denotes exactly the destination decoded from the block's own
native terminal bytes.  Only that verdict may normalize a control term or
route a composed successor; every other outcome is a typed refusal and the
original SSA is retained.

The fetch window is execution definedness, never a caller-supplied
selector: it is the set of ``cs`` values for which some 16-bit ``ip``
satisfies ``cs<<4 + ip == head`` for both the block entry and its terminal
instruction, sharing the all-fetch-window geometry owned by
``X86_16/semantics/direct_near_call_target_binding``.  Evidence binds to
the producer's own ``control_domain`` fact (emitted by the lifter contract,
not guessed from a cs field), the recomputed native machine-code hash, the
terminal instruction bytes, and the live cs binding.  Missing, foreign,
stale, tampered, or budget-exhausted evidence refuses.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from tools.dosunit.model import DosUnitError, normalize_hex

__all__ = [
    "DEFAULT_PROOF_BUDGET",
    "ControlDestinationProof",
    "ControlDomainFailure",
    "ControlDomainKind",
    "ControlProofBudget",
    "ControlProofStats",
    "ControlProofVerdict",
    "FetchDomain",
    "NativeTransferKind",
    "TerminalDestinations",
    "decoded_terminal_destinations",
    "fetch_window",
    "producer_domain_fact",
    "prove_branch_destinations",
    "prove_call_control_output",
    "prove_control_term",
    "prove_term_destination",
    "term_input_leaves",
]

REAL16_ARCH_NAME: Final[str] = "86_16"
REAL16_CONTROL_DOMAIN: Final[str] = "loader_linear"
_CS_INPUT_NAME: Final[str] = "cs"


class ControlDomainKind(StrEnum):
    """The only admitted fetch-domain contract for real16 control proofs."""

    REAL16_FETCH_WINDOW = "real16_fetch_window"


FETCH_DOMAIN_KIND: Final[str] = ControlDomainKind.REAL16_FETCH_WINDOW.value


class NativeTransferKind(StrEnum):
    """Owned decode classification of a block's native terminal transfer.

    ``source.transfer.kind`` JSON strings are a serialization boundary; the
    values here are what this module itself decoded from the native terminal
    bytes and verified against that boundary.
    """

    DIRECT_CALL = "direct_call"
    DIRECT_SUCCESSORS = "direct_successors"


class ControlProofVerdict(StrEnum):
    """Closed verdict for one control-destination proof attempt."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class ControlDomainFailure(StrEnum):
    """Typed reasons a control term cannot be bound to a native destination."""

    DOMAIN_FACT_MISSING = "domain_fact_missing"
    DOMAIN_FACT_MALFORMED = "domain_fact_malformed"
    DOMAIN_ARCH_MISMATCH = "domain_arch_mismatch"
    DOMAIN_HEAD_MISMATCH = "domain_head_mismatch"
    DOMAIN_TERMINAL_MISMATCH = "domain_terminal_mismatch"
    DOMAIN_WINDOW_MISMATCH = "domain_window_mismatch"
    MACHINE_CODE_MISSING = "machine_code_missing"
    MACHINE_CODE_MISMATCH = "machine_code_mismatch"
    TERMINAL_DECODE_UNSUPPORTED = "terminal_decode_unsupported"
    TERMINAL_DECODE_MISMATCH = "terminal_decode_mismatch"
    CS_BINDING_MISSING = "cs_binding_missing"
    CS_BINDING_FOREIGN = "cs_binding_foreign"
    FETCH_PREMISE_UNSAT = "fetch_premise_unsat"
    SHARED_GUARD_REFUSED = "shared_guard_refused"
    TERM_UNENCODABLE = "term_unencodable"
    DESTINATION_UNPROVED = "destination_unproved"
    COVERAGE_INCOMPLETE = "coverage_incomplete"
    SOLVER_UNKNOWN = "solver_unknown"
    BUDGET_EXHAUSTED = "budget_exhausted"
    PROOF_BACKEND_UNAVAILABLE = "proof_backend_unavailable"


@dataclass(frozen=True, slots=True)
class FetchDomain:
    """Selector window for which this block's native bytes are fetch-defined."""

    head_linear: int
    terminal_linear: int
    selector_min: int
    selector_max: int


@dataclass(frozen=True, slots=True)
class ControlProofBudget:
    """Hard bounds on one proof: solver work, queries, and term traversal."""

    max_queries: int = 8
    solver_timeout_ms: int = 2_000
    solver_rlimit: int = 2_000_000
    max_term_nodes: int = 8_192
    deadline: float | None = None


DEFAULT_PROOF_BUDGET: Final[ControlProofBudget] = ControlProofBudget()


@dataclass(frozen=True, slots=True)
class ControlProofStats:
    """Closed accounting for one proof attempt."""

    queries: int
    term_nodes: int
    solver_time_ms: int
    failures: int


@dataclass(frozen=True, slots=True)
class ControlDestinationProof:
    """Verdict for one term-to-destination proof under the fetch domain."""

    verdict: ControlProofVerdict
    value: int | None
    failure: ControlDomainFailure | None
    stats: ControlProofStats

    @property
    def proven(self) -> bool:
        """True only when the term denotes ``value`` for the whole window."""
        return self.verdict is ControlProofVerdict.PROVEN and self.value is not None


@dataclass(frozen=True, slots=True)
class TerminalDestinations:
    """Destinations decoded from the block's own native terminal bytes."""

    kind: NativeTransferKind
    destinations: frozenset[int]
    fallthrough: int | None


@dataclass(frozen=True, slots=True)
class _EvidenceGate:
    """Verified evidence bundle consumed by the solver replay."""

    domain: FetchDomain
    decoded: TerminalDestinations
    encoded_cs: Any
    encoded_term: Any
    term_nodes: int


def _optional_int(value: Any) -> int | None:  # noqa: ANN401
    """Parse an integer-or-hex-string field without raising."""
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _dict_field(node: dict[str, Any], key: str) -> dict[str, Any]:
    """Return ``node[key]`` as a dict, or ``{}`` when absent/foreign."""
    value = node.get(key)
    return value if isinstance(value, dict) else {}


def _refuse(
    failure: ControlDomainFailure,
    *,
    queries: int = 0,
    term_nodes: int = 0,
    solver_time_ms: int = 0,
) -> ControlDestinationProof:
    """Build a typed refusal retaining the evidence accounting."""
    return ControlDestinationProof(
        verdict=ControlProofVerdict.UNKNOWN_REFUSE,
        value=None,
        failure=failure,
        stats=ControlProofStats(queries, term_nodes, solver_time_ms, 1),
    )


def _term_width(term: dict[str, Any]) -> int:
    """Width of a JSON term, defaulting to the architectural word."""
    width = term.get("width")
    return int(width) if type(width) is int and width > 0 else 16


def _resolve_ref(part: dict[str, Any], term: dict[str, Any]) -> dict[str, Any]:
    """Resolve a top-level ``ref`` node to its recorded assignment body."""
    ref = term.get("ref")
    if isinstance(ref, str):
        for item in part.get("assignments", []) or []:
            if isinstance(item, dict) and str(item.get("id")) == ref:
                return item
    return term


def _const_value(term: dict[str, Any]) -> int | None:
    """Concrete value of a literal term, else None."""
    if term.get("op") != "const":
        return None
    value = _optional_int(term.get("value"))
    return None if value is None else value & ((1 << _term_width(term)) - 1)


def fetch_window(head_linear: int, terminal_linear: int | None = None) -> tuple[int, int] | None:
    """Selectors ``cs`` whose instruction fetch observes this block's bytes.

    ``cs`` can fetch linear address ``head`` exactly when a 16-bit ``ip``
    exists with ``cs<<4 + ip == head`` (no wrap).  This is the same window
    the shared all-fetch-window guard
    ``direct_near_call_target_binding._target_in_all_fetch_windows_8616``
    computes; here both the block entry *and* terminal head must be
    fetchable under one selector, so the lower bound takes the tighter
    terminal endpoint.
    """
    if type(head_linear) is not int or head_linear < 0:
        return None
    terminal = head_linear if terminal_linear is None else terminal_linear
    if type(terminal) is not int or terminal < 0:
        return None
    minimum = max(0, (terminal - 0xFFFF + 15) // 16, (head_linear - 0xFFFF + 15) // 16)
    maximum = min(0xFFFF, head_linear // 16, terminal // 16)
    if minimum > maximum:
        return None
    return minimum, maximum


def _is_real16_loader_linear_arch(arch: object) -> bool:
    """Whether ``arch`` is the genuine real16 loader-linear contract object.

    ``angr``'s VEX lifter reports the arch's modeling width (32) rather than
    the 16-bit ISA width, so the contract binds to the ``Arch86_16`` class
    itself plus its ``loader_linear`` control-address domain — never to a
    name or a cs-shaped field alone.  When the contract module cannot be
    imported the arch is unverifiable and no marker is produced.
    """
    try:
        from angr_platforms.X86_16.arch_86_16 import Arch86_16
    except ImportError:
        return False
    return isinstance(arch, Arch86_16) and arch.control_address_domain.value == REAL16_CONTROL_DOMAIN


def producer_domain_fact(arch: object, *, head_linear: int, terminal_linear: int | None = None) -> dict[str, Any] | None:
    """Emit the producer fetch-domain marker for one lowered part.

    The marker exists only when the *actual* lifter architecture contract is
    the real16 loader-linear one — a verified ``Arch86_16`` instance whose
    ``control_address_domain`` is ``loader_linear`` — never from a cs field
    or a guessed architecture.  Returns ``None`` for any other contract so
    the producer simply omits the fact and downstream proofs refuse.
    """
    if not _is_real16_loader_linear_arch(arch):
        return None
    terminal = head_linear if terminal_linear is None else terminal_linear
    window = fetch_window(head_linear, terminal)
    if window is None:
        return None
    return {
        "kind": FETCH_DOMAIN_KIND,
        "arch": REAL16_ARCH_NAME,
        "control_address_domain": REAL16_CONTROL_DOMAIN,
        "head_linear": normalize_hex(head_linear),
        "terminal_linear": normalize_hex(terminal),
        "selector_min": normalize_hex(window[0], width=4),
        "selector_max": normalize_hex(window[1], width=4),
    }


def _domain_evidence(part: dict[str, Any]) -> FetchDomain | ControlDomainFailure:
    """Re-derive and verify the producer-recorded fetch window.

    Every recorded field must agree with the part's own entry coordinates and
    a fresh geometric recomputation; any disagreement means the fact is
    foreign, stale, or tampered and the proof refuses.
    """
    source = _dict_field(part, "source")
    entry = _dict_field(part, "entry")
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    fact = source.get("control_domain")
    if fact is None:
        return ControlDomainFailure.DOMAIN_FACT_MISSING
    if not isinstance(fact, dict) or fact.get("kind") != FETCH_DOMAIN_KIND:
        return ControlDomainFailure.DOMAIN_FACT_MALFORMED
    if fact.get("arch") != REAL16_ARCH_NAME or fact.get("control_address_domain") != REAL16_CONTROL_DOMAIN:
        return ControlDomainFailure.DOMAIN_ARCH_MISMATCH
    head = _optional_int(fact.get("head_linear"))
    terminal = _optional_int(fact.get("terminal_linear"))
    selector_min = _optional_int(fact.get("selector_min"))
    selector_max = _optional_int(fact.get("selector_max"))
    entry_linear = _optional_int(entry.get("linear"))
    if not instructions or head is None or terminal is None:
        return ControlDomainFailure.DOMAIN_FACT_MALFORMED
    if selector_min is None or selector_max is None or not 0 <= selector_min <= selector_max <= 0xFFFF:
        return ControlDomainFailure.DOMAIN_FACT_MALFORMED
    if entry_linear is None or head != entry_linear:
        return ControlDomainFailure.DOMAIN_HEAD_MISMATCH
    last_linear = _optional_int(_dict_field(instructions[-1], "address").get("linear"))
    if last_linear is None or terminal != last_linear:
        return ControlDomainFailure.DOMAIN_TERMINAL_MISMATCH
    recomputed = fetch_window(head, terminal)
    if recomputed is None or recomputed != (selector_min, selector_max):
        return ControlDomainFailure.DOMAIN_WINDOW_MISMATCH
    return FetchDomain(head, terminal, selector_min, selector_max)


def _instruction_bytes(instruction: dict[str, Any]) -> bytes | None:
    """Parse one recorded instruction byte string exactly."""
    raw = instruction.get("bytes")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return None


def _machine_code_binding(part: dict[str, Any]) -> ControlDomainFailure | None:
    """Recompute the recorded machine-code digest over instruction bytes.

    The recomputed digest must equal ``source.machine_code_sha256`` and the
    byte stream must be contiguous from the block entry to the terminal
    instruction, so the decoded destinations are bound to the same bytes the
    lifter consumed.
    """
    source = _dict_field(part, "source")
    entry = _dict_field(part, "entry")
    entry_linear = _optional_int(entry.get("linear"))
    recorded_hash = source.get("machine_code_sha256")
    recorded_size = _optional_int(source.get("machine_code_size"))
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    if entry_linear is None or not isinstance(recorded_hash, str) or recorded_size is None:
        return ControlDomainFailure.MACHINE_CODE_MISSING
    if not instructions:
        return ControlDomainFailure.MACHINE_CODE_MISSING
    chunks: list[bytes] = []
    cursor = entry_linear
    for instruction in instructions:
        data = _instruction_bytes(instruction)
        address = _dict_field(instruction, "address")
        linear = _optional_int(address.get("linear"))
        size = _optional_int(instruction.get("size"))
        if data is None or linear is None or size is None or size != len(data) or linear != cursor:
            return ControlDomainFailure.MACHINE_CODE_MISMATCH
        chunks.append(data)
        cursor += size
    if hashlib.sha256(b"".join(chunks)).hexdigest() != recorded_hash:
        return ControlDomainFailure.MACHINE_CODE_MISMATCH
    if recorded_size != cursor - entry_linear:
        return ControlDomainFailure.MACHINE_CODE_MISMATCH
    return None


def _signed(value: int, bits: int) -> int:
    """Interpret a bit pattern with an explicit sign."""
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _decode_terminal(source: dict[str, Any]) -> tuple[NativeTransferKind, frozenset[int], int | None] | None:
    """Decode declared destinations from the native terminal bytes alone."""
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    if not instructions:
        return None
    last = instructions[-1]
    data = _instruction_bytes(last)
    linear = _optional_int(_dict_field(last, "address").get("linear"))
    size = _optional_int(last.get("size"))
    if data is None or linear is None or size is None or size != len(data):
        return None
    next_linear = linear + size
    if data[0] == 0xE8 and size == 3:
        return NativeTransferKind.DIRECT_CALL, frozenset({next_linear + _signed(int.from_bytes(data[1:3], "little"), 16)}), next_linear
    if data[0] == 0xEB and size == 2:
        return NativeTransferKind.DIRECT_SUCCESSORS, frozenset({next_linear + _signed(data[1], 8)}), next_linear
    if data[0] == 0xE9 and size == 3:
        return NativeTransferKind.DIRECT_SUCCESSORS, frozenset({next_linear + _signed(int.from_bytes(data[1:3], "little"), 16)}), next_linear
    if 0x70 <= data[0] <= 0x7F and size == 2:
        return NativeTransferKind.DIRECT_SUCCESSORS, frozenset({next_linear + _signed(data[1], 8), next_linear}), next_linear
    if data[0] == 0x0F and size == 4 and 0x80 <= data[1] <= 0x8F:
        return NativeTransferKind.DIRECT_SUCCESSORS, frozenset({next_linear + _signed(int.from_bytes(data[2:4], "little"), 16), next_linear}), next_linear
    if 0xE0 <= data[0] <= 0xE3 and size == 2:
        return NativeTransferKind.DIRECT_SUCCESSORS, frozenset({next_linear + _signed(data[1], 8), next_linear}), next_linear
    return None


def decoded_terminal_destinations(part: dict[str, Any]) -> TerminalDestinations | ControlDomainFailure:
    """Decode and cross-check the block's declared native destinations.

    The decoded byte-level destinations must equal the recorded
    ``source.transfer`` destinations; a disagreement means the recorded
    transfer is foreign to the bytes and the proof refuses.
    """
    source = _dict_field(part, "source")
    decoded = _decode_terminal(source)
    if decoded is None:
        return ControlDomainFailure.TERMINAL_DECODE_UNSUPPORTED
    kind, destinations, fallthrough = decoded
    transfer = _dict_field(source, "transfer")
    if kind is NativeTransferKind.DIRECT_CALL:
        if str(source.get("jumpkind") or "") != "Ijk_Call" or transfer.get("kind") != NativeTransferKind.DIRECT_CALL:
            return ControlDomainFailure.TERMINAL_DECODE_MISMATCH
        target = _optional_int(_dict_field(transfer, "target").get("raw"))
        recorded_fallthrough = _optional_int(_dict_field(transfer, "fallthrough").get("linear"))
        if target is None or recorded_fallthrough is None:
            return ControlDomainFailure.TERMINAL_DECODE_MISMATCH
        if destinations != frozenset({target}) or recorded_fallthrough != fallthrough:
            return ControlDomainFailure.TERMINAL_DECODE_MISMATCH
        return TerminalDestinations(NativeTransferKind.DIRECT_CALL, destinations, fallthrough)
    if transfer.get("kind") != NativeTransferKind.DIRECT_SUCCESSORS:
        return ControlDomainFailure.TERMINAL_DECODE_MISMATCH
    recorded = {
        value
        for value in (
            _optional_int(item.get("linear"))
            for item in transfer.get("successors", []) or []
            if isinstance(item, dict)
        )
        if value is not None
    }
    if not recorded or recorded != destinations:
        return ControlDomainFailure.TERMINAL_DECODE_MISMATCH
    return TerminalDestinations(NativeTransferKind.DIRECT_SUCCESSORS, destinations, fallthrough)


def _shared_fetch_guard(head_linear: int, target: int) -> bool | None:
    """Apply the semantics-layer all-fetch-window guard when importable."""
    try:
        from angr_platforms.X86_16.semantics.direct_near_call_target_binding import (
            _target_in_all_fetch_windows_8616,
        )
    except ImportError:
        return None
    verdict = _target_in_all_fetch_windows_8616(head_linear, target)
    return verdict if isinstance(verdict, bool) else None


def _leaf_spec(node: dict[str, Any]) -> dict[str, Any] | None:
    """The input-leaf descriptor for one ``input``/``mem_input`` node."""
    op = node.get("op")
    name = str(node.get("name") or "")
    if op == "input" and name:
        return {"name": name, "width": int(node.get("width", 16))}
    if op == "mem_input" and name:
        return {
            "kind": "memory",
            "name": name,
            "addr_width": int(node.get("addr_width", 32)),
            "value_width": int(node.get("value_width", 8)),
        }
    return None


def term_input_leaves(
    term: dict[str, Any],
    *,
    assignments: dict[str, dict[str, Any]] | None = None,
    max_nodes: int = 8192,
) -> tuple[list[dict[str, Any]], int] | None:
    """Collect ``input``/``mem_input`` leaves, bounded by ``max_nodes``.

    ``ref`` nodes resolve through ``assignments``.  Returns ``None`` when the
    walk exceeds the node budget or a ref cannot be resolved — the caller
    must refuse rather than encode a partial term.  The second element is the
    bounded node count actually walked, for proof accounting.
    """
    leaves: dict[str, dict[str, Any]] = {}
    seen: set[int] = set()
    nodes = 0
    stack: list[dict[str, Any]] = [term]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        nodes += 1
        if nodes > max_nodes:
            return None
        ref = node.get("ref")
        if isinstance(ref, str):
            target = (assignments or {}).get(ref)
            if not isinstance(target, dict):
                return None
            stack.append(target)
            continue
        spec = _leaf_spec(node)
        if node.get("op") in {"input", "mem_input"}:
            if spec is None:
                return None
            leaves[str(spec["name"])] = spec
            continue
        stack.extend(arg for arg in node.get("args", []) or [] if isinstance(arg, dict))
    return list(leaves.values()), nodes


def _encode_current_cs(
    current_cs: dict[str, Any],
    encode_term: Callable[[dict[str, Any]], Any],
    z3: Any,  # noqa: ANN401
) -> Any | ControlDomainFailure:  # noqa: ANN401
    """Encode the term currently bound to ``cs`` for the window premise.

    A literal ``input`` cs leaf must be the real ``cs`` input — a bare
    foreign input here means the block wrote cs (far transfer) or the caller
    supplied an unrelated selector, both of which refuse.  Composite terms
    may embed other inputs legitimately (e.g. a proved cs relation); they are
    replayed through the encoder and constrained by the window premise.
    """
    op = current_cs.get("op")
    if op == "input" and str(current_cs.get("name") or "").lower() != _CS_INPUT_NAME:
        return ControlDomainFailure.CS_BINDING_FOREIGN
    if op == "const" and _optional_int(current_cs.get("value")) is None:
        return ControlDomainFailure.CS_BINDING_FOREIGN
    try:
        return encode_term(current_cs)
    except (DosUnitError, KeyError, TypeError, ValueError, z3.Z3Exception):
        return ControlDomainFailure.CS_BINDING_FOREIGN


def _evidence_gate(
    part: dict[str, Any],
    term: dict[str, Any],
    *,
    current_cs: dict[str, Any] | None,
    encode_term: Callable[[dict[str, Any]], Any],
    z3: Any,  # noqa: ANN401
    budget: ControlProofBudget,
) -> _EvidenceGate | ControlDestinationProof:
    """Verify every evidence link and encode the term under the domain.

    Order matters: the producer-recorded fetch domain must agree with the
    part's own entry coordinates; the native machine-code hash must recompute
    over contiguous bytes; the decoded terminal destinations must equal the
    recorded transfer; the cs binding must be the live selector or a
    provably-related term.  Only then is the actual term DAG encoded for
    replay.
    """
    domain = _domain_evidence(part)
    if isinstance(domain, ControlDomainFailure):
        return _refuse(domain)
    binding = _machine_code_binding(part)
    if binding is not None:
        return _refuse(binding)
    decoded = decoded_terminal_destinations(part)
    if isinstance(decoded, ControlDomainFailure):
        return _refuse(decoded)
    if current_cs is None:
        return _refuse(ControlDomainFailure.CS_BINDING_MISSING)
    encoded_cs = _encode_current_cs(current_cs, encode_term, z3)
    if isinstance(encoded_cs, ControlDomainFailure):
        return _refuse(encoded_cs)
    const_cs = _const_value(current_cs)
    if const_cs is not None and not domain.selector_min <= const_cs <= domain.selector_max:
        return _refuse(ControlDomainFailure.FETCH_PREMISE_UNSAT)
    assignments = {
        str(item["id"]): item
        for item in part.get("assignments", []) or []
        if isinstance(item, dict) and "id" in item
    }
    walked = term_input_leaves(term, assignments=assignments, max_nodes=budget.max_term_nodes)
    if walked is None:
        return _refuse(ControlDomainFailure.TERM_UNENCODABLE, term_nodes=budget.max_term_nodes)
    try:
        encoded_term = encode_term(term)
    except (DosUnitError, KeyError, TypeError, ValueError, z3.Z3Exception):
        return _refuse(ControlDomainFailure.TERM_UNENCODABLE, term_nodes=walked[1])
    return _EvidenceGate(domain, decoded, encoded_cs, encoded_term, walked[1])


def _bounded_solver_check(solver: Any, budget: ControlProofBudget) -> Any:  # noqa: ANN401
    """Bound every query by the shared attempt deadline, including worker threads.

    Recompute remaining time before each query and reject late results after
    it returns. Solver timeouts alone are per-query, not per-attempt limits.
    """
    import time

    if budget.deadline is None:
        return solver.check()
    remaining = budget.deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("real16 control proof attempt deadline expired")
    solver.set("timeout", min(budget.solver_timeout_ms, max(1, int(remaining * 1000))))
    result = solver.check()
    if time.monotonic() >= budget.deadline:
        raise TimeoutError("real16 control proof query exceeded attempt deadline")
    return result


def _premise_checked_solver(
    gate: _EvidenceGate,
    budget: ControlProofBudget,
    started: float,
    z3: Any,  # noqa: ANN401
) -> Any | ControlDestinationProof:  # noqa: ANN401
    """Build one solver, assert the fetch-window premise and confirm it is sat.

    The premise is execution definedness: the selector term bound to ``cs``
    lies inside the verified fetch window.  Exactly one satisfiability query
    is issued here; callers sharing the returned solver across several terms
    add that single query to their running total exactly once.
    """
    import time

    # The incremental solver core decides these quantifier-free BV/array
    # queries directly; the default tactic-wrapped ``Solver`` pays a large
    # first-check pipeline cost that dominates this module's small queries.
    # ``timeout``/``rlimit`` are still honored, and deadline checks in
    # ``_bounded_solver_check`` keep bounding every query end-to-end.
    solver = z3.SimpleSolver()
    solver.set("timeout", budget.solver_timeout_ms)
    solver.set("rlimit", budget.solver_rlimit)
    solver.add(
        z3.And(
            z3.UGE(gate.encoded_cs, gate.domain.selector_min),
            z3.ULE(gate.encoded_cs, gate.domain.selector_max),
        )
    )
    if _bounded_solver_check(solver, budget) != z3.sat:
        return _refuse(
            ControlDomainFailure.FETCH_PREMISE_UNSAT,
            queries=1,
            term_nodes=gate.term_nodes,
            solver_time_ms=int((time.monotonic() - started) * 1000),
        )
    return solver


def _prove_candidates_on(
    solver: Any,  # noqa: ANN401
    gate: _EvidenceGate,
    term_width: int,
    candidates: Iterable[int],
    *,
    require_shared_guard: bool,
    budget: ControlProofBudget,
    started: float,
    z3: Any,  # noqa: ANN401
    queries: int,
) -> ControlDestinationProof:
    """Replay ``term != candidate`` on a premise-checked solver; unsat proves.

    ``queries`` is the number of solver queries already issued on ``solver``
    (the premise check plus any earlier terms sharing it); the returned stats
    keep counting from there so shared-solver callers never double count.
    """
    import time

    mask = (1 << term_width) - 1
    seen: set[int] = set()
    for candidate in sorted(set(candidates)):
        if candidate != (candidate & mask) or candidate in seen:
            continue  # a wider candidate would silently alias through the low word
        seen.add(candidate)
        if require_shared_guard and term_width == 32:
            guard = _shared_fetch_guard(gate.domain.head_linear, candidate)
            if guard is False:
                continue
            if guard is None:
                return _refuse(
                    ControlDomainFailure.SHARED_GUARD_REFUSED,
                    queries=queries,
                    term_nodes=gate.term_nodes,
                )
        if queries >= budget.max_queries:
            return _refuse(
                ControlDomainFailure.BUDGET_EXHAUSTED,
                queries=queries,
                term_nodes=gate.term_nodes,
                solver_time_ms=int((time.monotonic() - started) * 1000),
            )
        solver.push()
        solver.add(gate.encoded_term != z3.BitVecVal(candidate, term_width))
        result = _bounded_solver_check(solver, budget)
        solver.pop()
        queries += 1
        if result == z3.unsat:
            return ControlDestinationProof(
                verdict=ControlProofVerdict.PROVEN,
                value=candidate,
                failure=None,
                stats=ControlProofStats(
                    queries, gate.term_nodes, int((time.monotonic() - started) * 1000), 0
                ),
            )
        if result == z3.unknown:
            return _refuse(
                ControlDomainFailure.SOLVER_UNKNOWN,
                queries=queries,
                term_nodes=gate.term_nodes,
                solver_time_ms=int((time.monotonic() - started) * 1000),
            )
    return _refuse(
        ControlDomainFailure.DESTINATION_UNPROVED,
        queries=queries,
        term_nodes=gate.term_nodes,
        solver_time_ms=int((time.monotonic() - started) * 1000),
    )


def _prove_candidates(
    gate: _EvidenceGate,
    term_width: int,
    candidates: Iterable[int],
    *,
    require_shared_guard: bool,
    budget: ControlProofBudget,
    started: float,
    z3: Any,  # noqa: ANN401
) -> ControlDestinationProof:
    """Replay ``term != candidate`` under the window premise; unsat proves it."""
    solver = _premise_checked_solver(gate, budget, started, z3)
    if isinstance(solver, ControlDestinationProof):
        return solver
    return _prove_candidates_on(
        solver,
        gate,
        term_width,
        candidates,
        require_shared_guard=require_shared_guard,
        budget=budget,
        started=started,
        z3=z3,
        queries=1,
    )


def prove_term_destination(
    part: dict[str, Any],
    term: dict[str, Any],
    *,
    current_cs: dict[str, Any] | None,
    candidates: Iterable[int],
    encode_term: Callable[[dict[str, Any]], Any],
    z3: Any,  # noqa: ANN401
    budget: ControlProofBudget = DEFAULT_PROOF_BUDGET,
    require_shared_guard: bool = True,
) -> ControlDestinationProof:
    """Prove ``term`` denotes one candidate for every valid fetch selector.

    Premise: the selector term currently bound to ``cs`` lies inside the
    verified fetch window of this block (execution definedness).  Theorem:
    for every input assignment satisfying that premise, the replayed term
    equals the candidate destination.  ``unsat(term != candidate)`` under
    the premise is the proof; a counterexample or unknown verdict refuses.
    """
    import time

    if budget.max_queries <= 0:
        return _refuse(ControlDomainFailure.BUDGET_EXHAUSTED)
    started = time.monotonic()
    gate = _evidence_gate(
        part,
        term,
        current_cs=current_cs,
        encode_term=encode_term,
        z3=z3,
        budget=budget,
    )
    if isinstance(gate, ControlDestinationProof):
        return gate
    return _prove_candidates(
        gate,
        _term_width(_resolve_ref(part, term)),
        candidates,
        require_shared_guard=require_shared_guard,
        budget=budget,
        started=started,
        z3=z3,
    )


def _prove_branch_arms(
    part: dict[str, Any],
    arms: list[dict[str, Any]],
    *,
    current_cs: dict[str, Any] | None,
    destinations: frozenset[int],
    encode_term: Callable[[dict[str, Any]], Any],
    z3: Any,  # noqa: ANN401
    budget: ControlProofBudget,
) -> tuple[list[int] | None, ControlDestinationProof]:
    """Prove each arm denotes a destination on one shared premise solver.

    The fetch window and the cs binding are identical for every arm of the
    ITE, so the window premise is asserted and satisfiability-checked once;
    re-asserting and re-checking it per arm is duplicate proof work, not new
    evidence.  Every arm's evidence gate still runs and every candidate
    query counts against the shared ``max_queries`` budget.  A ``None``
    proved list pairs with the typed refusal inside the returned proof.
    """
    import time

    proved: list[int] = []
    total_queries = 0
    started = time.monotonic()
    solver: Any = None
    for arm in arms:
        if total_queries >= budget.max_queries:
            return None, _refuse(
                ControlDomainFailure.BUDGET_EXHAUSTED,
                queries=total_queries,
                solver_time_ms=int((time.monotonic() - started) * 1000),
            )
        gate = _evidence_gate(
            part, arm, current_cs=current_cs, encode_term=encode_term, z3=z3, budget=budget
        )
        if isinstance(gate, ControlDestinationProof):
            total_queries += gate.stats.queries
            return None, ControlDestinationProof(
                verdict=gate.verdict,
                value=None,
                failure=gate.failure,
                stats=ControlProofStats(
                    total_queries, gate.stats.term_nodes,
                    int((time.monotonic() - started) * 1000), 1,
                ),
            )
        if solver is None:
            premise = _premise_checked_solver(gate, budget, started, z3)
            if isinstance(premise, ControlDestinationProof):
                total_queries += premise.stats.queries
                return None, ControlDestinationProof(
                    verdict=premise.verdict,
                    value=None,
                    failure=premise.failure,
                    stats=ControlProofStats(
                        total_queries, premise.stats.term_nodes,
                        int((time.monotonic() - started) * 1000), 1,
                    ),
                )
            solver = premise
            total_queries += 1
        outcome = _prove_candidates_on(
            solver,
            gate,
            _term_width(_resolve_ref(part, arm)),
            destinations,
            require_shared_guard=True,
            budget=budget,
            started=started,
            z3=z3,
            queries=total_queries,
        )
        total_queries = outcome.stats.queries
        if not outcome.proven or outcome.value is None:
            return None, ControlDestinationProof(
                verdict=outcome.verdict,
                value=None,
                failure=outcome.failure,
                stats=ControlProofStats(
                    total_queries, outcome.stats.term_nodes,
                    int((time.monotonic() - started) * 1000), 1,
                ),
            )
        proved.append(outcome.value)
    return proved, ControlDestinationProof(
        verdict=ControlProofVerdict.PROVEN,
        value=None,
        failure=None,
        stats=ControlProofStats(
            total_queries, 0, int((time.monotonic() - started) * 1000), 0,
        ),
    )


def prove_branch_destinations(
    part: dict[str, Any],
    ite_term: dict[str, Any],
    *,
    current_cs: dict[str, Any] | None,
    encode_term: Callable[[dict[str, Any]], Any],
    z3: Any,  # noqa: ANN401
    budget: ControlProofBudget = DEFAULT_PROOF_BUDGET,
) -> tuple[dict[str, Any] | None, ControlDestinationProof]:
    """Prove each arm of a control ITE denotes a distinct declared successor.

    The root ITE keeps its exact original predicate; only arms individually
    proved under the fetch domain normalize to their declared destination.
    Arm values must cover the decoded successor set bijectively — a swapped,
    duplicated, or out-of-set arm refuses and no normalization is emitted.
    """
    if ite_term.get("op") != "ite":
        return None, _refuse(ControlDomainFailure.TERM_UNENCODABLE)
    args = [arg for arg in ite_term.get("args", []) or [] if isinstance(arg, dict)]
    if len(args) != 3:
        return None, _refuse(ControlDomainFailure.TERM_UNENCODABLE)
    arms = [_resolve_ref(part, arg) for arg in args[1:3]]
    if any(arm.get("op") is None for arm in arms):
        return None, _refuse(ControlDomainFailure.TERM_UNENCODABLE)
    decoded = decoded_terminal_destinations(part)
    if isinstance(decoded, ControlDomainFailure):
        return None, _refuse(decoded)
    if decoded.kind is not NativeTransferKind.DIRECT_SUCCESSORS or len(decoded.destinations) != 2:
        return None, _refuse(ControlDomainFailure.TERMINAL_DECODE_UNSUPPORTED)
    proved, outcome = _prove_branch_arms(
        part,
        arms,
        current_cs=current_cs,
        destinations=decoded.destinations,
        encode_term=encode_term,
        z3=z3,
        budget=budget,
    )
    if proved is None:
        return None, outcome
    if len(set(proved)) != 2 or set(proved) != decoded.destinations:
        return None, ControlDestinationProof(
            verdict=ControlProofVerdict.UNKNOWN_REFUSE,
            value=None,
            failure=ControlDomainFailure.COVERAGE_INCOMPLETE,
            stats=ControlProofStats(
                outcome.stats.queries, 0, outcome.stats.solver_time_ms, 1,
            ),
        )
    arm_widths = [_term_width(arm) for arm in arms]
    normalized = {
        "op": "ite",
        "width": _term_width(ite_term),
        "args": [
            args[0],
            {
                "op": "const",
                "value": normalize_hex(proved[0], width=max(1, (arm_widths[0] + 3) // 4)),
                "width": arm_widths[0],
            },
            {
                "op": "const",
                "value": normalize_hex(proved[1], width=max(1, (arm_widths[1] + 3) // 4)),
                "width": arm_widths[1],
            },
        ],
    }
    return normalized, outcome


def prove_control_term(
    part: dict[str, Any],
    term: dict[str, Any],
    *,
    current_cs: dict[str, Any] | None,
    encode_term: Callable[[dict[str, Any]], Any],
    z3: Any,  # noqa: ANN401
    budget: ControlProofBudget = DEFAULT_PROOF_BUDGET,
) -> tuple[dict[str, Any] | None, ControlDestinationProof]:
    """Normalize a proved control term for routing; ``None`` on refusal.

    A scalar term must denote the single decoded successor.  An ITE keeps
    its original predicate and gains proved constant arms.  Every other
    outcome leaves routing to the caller's existing refusal path; the
    original SSA is retained either way.
    """
    resolved_term = _resolve_ref(part, term)
    if resolved_term.get("op") == "ite":
        return prove_branch_destinations(
            part, resolved_term, current_cs=current_cs, encode_term=encode_term, z3=z3, budget=budget
        )
    decoded = decoded_terminal_destinations(part)
    if isinstance(decoded, ControlDomainFailure):
        return None, _refuse(decoded)
    if len(decoded.destinations) != 1:
        return None, _refuse(ControlDomainFailure.TERMINAL_DECODE_UNSUPPORTED)
    target = next(iter(decoded.destinations))
    candidates = {target, target & 0xFFFF} if _term_width(resolved_term) == 16 else {target}
    outcome = prove_term_destination(
        part,
        term,
        current_cs=current_cs,
        candidates=candidates,
        encode_term=encode_term,
        z3=z3,
        budget=budget,
    )
    if not outcome.proven or outcome.value is None:
        return None, outcome
    width = _term_width(resolved_term)
    normalized = {
        "op": "const",
        "value": normalize_hex(outcome.value & ((1 << width) - 1), width=max(1, (width + 3) // 4)),
        "width": width,
    }
    return normalized, outcome


def prove_call_control_output(
    part: dict[str, Any],
    term: dict[str, Any],
    *,
    output_name: str,
    bound_values: Iterable[int],
    logical_ip: int | None,
    current_cs: dict[str, Any] | None,
    encode_term: Callable[[dict[str, Any]], Any],
    z3: Any,  # noqa: ANN401
    budget: ControlProofBudget = DEFAULT_PROOF_BUDGET,
) -> ControlDestinationProof:
    """Prove a call block's control output denotes the resolved callee.

    The decoded E8 destination must itself be inside ``bound_values`` — the
    resolved callee has to be the natively decoded target, not merely a
    numerically matching constant.  Accepted output values mirror
    ``_call_control_matches_destination``: full-width ``control_ip`` binds
    only the exact physical destination; the word ``ip`` projection accepts
    the callee's logical entry offset or the low word of a bound value.
    """
    decoded = decoded_terminal_destinations(part)
    if isinstance(decoded, ControlDomainFailure):
        return _refuse(decoded)
    if decoded.kind is not NativeTransferKind.DIRECT_CALL:
        return _refuse(ControlDomainFailure.TERMINAL_DECODE_MISMATCH)
    bound = {int(value) for value in bound_values}
    if not decoded.destinations <= bound:
        return _refuse(ControlDomainFailure.TERMINAL_DECODE_MISMATCH)
    term = _resolve_ref(part, term)
    width = _term_width(term)
    if width == 32:
        candidates = set(decoded.destinations)
    elif output_name == "ip" and width == 16:
        candidates = {target & 0xFFFF for target in decoded.destinations}
        if logical_ip is not None:
            candidates.add(logical_ip & 0xFFFF)
    else:
        return _refuse(ControlDomainFailure.TERM_UNENCODABLE)
    return prove_term_destination(
        part,
        term,
        current_cs=current_cs,
        candidates=candidates,
        encode_term=encode_term,
        z3=z3,
        budget=budget,
    )
