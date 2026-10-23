"""Layer: validation call composition execution.

Responsibility: compose acyclic lifted function bodies into final-state SSA
summaries, inlining proved direct calls.

Composition walks each acyclic path through ``compose_block_outputs`` and
merges conditional direct-branch exits with ``merge_states``.  At an
admitted ``Ijk_Call`` block the callee's own composed final state is
substituted with the caller's live state, its ``eip`` must be Z3-proved equal
to the recorded fallthrough, and only then does the caller continue.  A
deferred-indirect call (``call_target=None``) decomposes its composed ``ip``
term into a finite ``ite`` selector: every leaf must be a constant naming a
declared entry, each leaf runs the same callee composition and return-target
proof under its exact path predicate, and the per-arm post-states merge like
guarded branches.  At an admitted tail transfer (``_LiftedBlock.tail_targets``)
the destination's complete summary is substituted over the live state with no
return-address push and no stack adjustment — the destination's own ``ret``
resolves the return slot already present in the caller frame, and any
enclosing call's return-target proof discharges that composed ``eip``.
Loops, recursion (including tail cycles), unconstrained or undeclared call
targets, unprovable return targets and exhausted budgets refuse; nothing
falls back to assumed post-call equality.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from tools.dosunit.architectures.flat32_control_word import bind_x87_obligations
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionRefusal,
    CallRefusalLocation,
    IndirectReadProposal,
    InductiveLoopRequired,
    ReturnTargetProofFailure,
    _check_compose_deadline,
    _ComposeSession,
    _const_term_int,
    _initial_state,
    _LiftedBlock,
    _ret_proof_timeout_ms,
    _term_nodes,
)
from tools.dosunit.compare.flat32_call_lowering import _lift_function
from tools.dosunit.compare.flat32_constant_branches import (
    BranchValue,
    branch_under_path,
    constant_branch,
    constant_call_target,
    finite_call_selector,
)
from tools.dosunit.compare.flat32_external_binding import prove_import_target, terminal_import_thunk_slot
from tools.dosunit.compare.flat32_external_call import external_call_state
from tools.dosunit.compare.flat32_memory_preservation import prove_region_preserved
from tools.dosunit.compare.flat32_return_footprint import reduce_return_read
from tools.dosunit.contracts.flat32_buffer_domain import Flat32EntryMemoryRange, Flat32StackDisjointBuffer
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.ssa.composition import compose_block_outputs, merge_states
from tools.dosunit.ssa.literal_read_reduction import reduce_literal_reads
from tools.dosunit.ssa.materialization import input_items, materialize_term
from tools.dosunit.ssa.ssa_output_lemmas import ScalarPreprocessing


def _substitute_state_term(
    term: dict[str, Any],
    state: Mapping[str, dict[str, Any]],
    compose_stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replace callee input leaves with the caller's current state terms.

    ``compose_stats`` carries the shared absolute deadline so deep callee
    terms cannot substitute past the total budget unchecked.
    """
    return _substitute(term, state, {}, compose_stats)


def _callee_term(
    term: dict[str, Any], state: Mapping[str, dict[str, Any]], session: _ComposeSession,
) -> dict[str, Any]:
    """Instantiate a generic summary once; root-bound terms need no substitution."""
    if session.root_bound_inputs:
        return term
    return _substitute_state_term(term, state, session.compose_stats)


def _and_guard(guard: dict[str, Any] | None, condition: dict[str, Any]) -> dict[str, Any]:
    """Conjoin a path guard with a width-1 branch condition term."""
    if guard is None:
        return condition
    return {"op": "and", "width": 1, "args": [guard, condition]}


def _obligation_sink(session: _ComposeSession) -> list[dict[str, Any]]:
    """Route bound obligations to the innermost function frame (or root)."""
    if session.obligation_frames:
        return session.obligation_frames[-1]
    return session.x87_obligations


def _transfer_callee_obligations(
    session: _ComposeSession,
    target: int,
    state: Mapping[str, dict[str, Any]],
    guard: dict[str, Any] | None,
    *,
    callsite: int | None = None,
    obligations: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None,
) -> None:
    """Substitute a callee's obligation terms into the caller's live state.

    Generic callee frames bind to the callee's own input leaves; every call
    site re-instantiates them against its actual composed state and wraps
    them under the path guard reaching this site — a checking instruction
    inside the callee only executes when the call itself is reached.
    """
    source = obligations if obligations is not None else session.summary_obligations.get(target, ())
    for obligation in source:
        predicate = obligation.get("predicate")
        if not isinstance(predicate, dict):
            continue
        term = _callee_term(predicate, state, session)
        if guard is not None:
            term = {
                "op": "ite", "width": 1,
                "args": [guard, term, {"op": "const", "width": 1, "value": "0x1"}],
            }
        site = dict(obligation.get("site") or {})
        site["callee"] = hex(target)
        if callsite is not None:
            site["callsite"] = hex(callsite)
        _obligation_sink(session).append({**obligation, "site": site, "predicate": term})


def _substitute(
    term: dict[str, Any],
    state: Mapping[str, dict[str, Any]],
    cache: dict[int, dict[str, Any]],
    compose_stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Name-aware input/mem_input substitution into composed callee terms.

    The deadline is re-checked per uncached node: substitution is real work
    that must share the session's total budget, and a refused check aborts
    the walk before a partial substitution can be published.
    """
    _check_compose_deadline(compose_stats)
    cached = cache.get(id(term))
    if cached is not None:
        return cached
    op = term.get("op")
    if op == "input":
        replacement = state.get(str(term.get("name")))
        result = replacement if isinstance(replacement, dict) else term
    elif op == "mem_input":
        name = str(term.get("name"))
        replacement = state.get("memory" if name == "mem" else name)
        result = replacement if isinstance(replacement, dict) else term
    else:
        result = dict(term)
        args = term.get("args")
        if isinstance(args, list):
            result["args"] = [
                _substitute(arg, state, cache, compose_stats)
                for arg in args
                if isinstance(arg, dict)
            ]
    cache[id(term)] = result
    return result


def _prove_return_target(
    return_target: dict[str, Any],
    fallthrough: int,
    *,
    timeout_ms: int,
    callsite: int,
    call_block: int,
    target: int,
    callee: str,
    input_constraints: list[dict[str, Any]] | None = None,
    selector: dict[str, Any] | None = None,
    buffer_domains: tuple[tuple[Flat32StackDisjointBuffer, int], ...] = (),
    proof_records: list[dict[str, Any]] | None = None,
) -> None:
    """Require Z3 proof that the composed return target is the call fallthrough.

    A countermodel or inconclusive solver result refuses with the same stable
    reason string as before and additionally carries the typed
    :class:`ReturnTargetProofFailure` so callers can inspect which call site
    failed and why.  ``input_constraints`` is the optional caller-declared
    premise on the free inputs of ``return_target``; when present it is echoed
    into the retained solver result so the applied assumptions are auditable.
    ``selector`` is the composed path predicate for a deferred-indirect call
    leaf; it is retained on the failure evidence so the audited report names
    the exact selector arm whose return frame could not be proved.
    """
    proof_started = time.monotonic()
    obligations = [item.obligation(depth) for item, depth in buffer_domains]
    skipped = 0
    for item, depth in buffer_domains:
        reduction = reduce_return_read(return_target, item, depth)
        return_target = reduction.term
        skipped += reduction.skipped_stores
    assignments: list[dict[str, Any]] = []
    materialized = materialize_term(return_target, assignments=assignments, memo={})
    oracle = {
        "outputs": {"eip": materialized},
        "assignments": assignments,
        "inputs": input_items([materialized, *[item["predicate"] for item in obligations]], assignments),
        "obligations": obligations,
    }
    candidate = {
        "outputs": {"eip": {"op": "const", "value": hex(fallthrough), "width": 32}},
        "assignments": [],
        "inputs": [],
    }
    oracle = reduce_literal_reads(oracle, input_constraints or [],
                                  deadline=proof_started + timeout_ms / 1000)
    remaining_ms = max(1, timeout_ms - int((time.monotonic() - proof_started) * 1000))
    result = S._compare_functions(
        oracle, candidate, timeout_ms=remaining_ms,
        input_constraints=input_constraints,
        scalar_preprocessing=ScalarPreprocessing.READ_OVER_WRITE,
    )
    result["literal_read_reduction"] = oracle.get("literal_read_reduction", {})
    result["scalar_preprocessing"] = ScalarPreprocessing.READ_OVER_WRITE.value
    if input_constraints:
        result["input_constraints"] = [dict(item) for item in input_constraints]
    if obligations:
        result["root_buffer_domains"] = obligations
    status = proof_status_from_legacy(result.get("status"))
    if status is ProofStatus.PROVED:
        if obligations and proof_records is not None:
            proof_records.append({"callsite": hex(callsite), "target": hex(target),
                "skipped_stores": skipped, "obligations": obligations, "status": "conditional"})
        return
    failure = ReturnTargetProofFailure(
        status=status,
        callsite=callsite,
        call_block=call_block,
        target=target,
        fallthrough=fallthrough,
        solver_result=result,
        callee=callee,
        selector=selector,
    )
    if status is ProofStatus.COUNTEREXAMPLE:
        raise CallCompositionRefusal("call_return_target_mismatch", evidence=failure)
    raise CallCompositionRefusal(
        f"call_return_target_unproved:{result.get('reason')}", evidence=failure
    )


def _apply_callee_state(
    session: _ComposeSession,
    state: dict[str, dict[str, Any]],
    callee_state: dict[str, dict[str, Any]],
    fallthrough: int,
) -> dict[str, dict[str, Any]]:
    """Substitute a proved callee's outputs over the caller state and pin the
    return address to the proved fallthrough.

    Every non-control output — registers, flags, memory and I/O — is
    substituted under the caller's live terms; ``ip``/``eip`` always become
    the proved fallthrough constant rather than the callee's own terminal.
    """
    post = dict(state)
    for name, term in callee_state.items():
        if name not in {"eip", "ip"}:
            _check_compose_deadline(session.compose_stats)
            post[name] = _callee_term(term, state, session)
    proved_return = {"op": "const", "value": hex(fallthrough), "width": 32}
    post["ip"] = dict(proved_return)
    post["eip"] = proved_return
    return post


def _compose_call(
    session: _ComposeSession, blocks: dict[int, _LiftedBlock], function_entry: int,
    block: _LiftedBlock, state: dict[str, dict[str, Any]], path: frozenset[int],
    active: frozenset[int], depth: int, guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Apply a proved call then continue along the original caller path."""
    if block.fallthrough is None:
        raise CallCompositionRefusal("call_target_unmapped")
    if block.call_target is None:
        return _compose_indirect_call(
            session, blocks, function_entry, block, state, path, active, depth, guard
        )
    post = _compose_direct_call_state(session, function_entry, block, state, active, depth, guard)
    return _walk(session, blocks, function_entry, block.fallthrough, post, path, active, depth, guard)


def _compose_direct_call_state(
    session: _ComposeSession, function_entry: int, block: _LiftedBlock,
    state: dict[str, dict[str, Any]], active: frozenset[int], depth: int,
    guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Apply all direct-callee effects and obligations without composing the suffix."""
    target, fallthrough = block.call_target, block.fallthrough
    if target is None or fallthrough is None:
        raise CallCompositionRefusal("call_target_unmapped")
    if _const_term_int(state.get("ip")) != target:
        raise CallCompositionRefusal("call_target_mismatch")
    if target in active:
        raise CallCompositionRefusal(f"recursive_call:{hex(target)}")
    thunk_slot = (
        terminal_import_thunk_slot(session.project, target, session.functions.get(target, 0))
        if session.external_bindings else None
    )
    terminal_import = thunk_slot is not None and thunk_slot in session.external_bindings
    reusable_summary = target in session.summaries
    if depth + 1 > session.limits.max_inline_depth and not (terminal_import or reusable_summary):
        from tools.dosunit.compare.flat32_summary_schedule import prepare_internal_summary

        reusable_summary = prepare_internal_summary(session, target, active, _compose_function)
    if depth + 1 > session.limits.max_inline_depth and not (terminal_import or reusable_summary):
        raise CallCompositionRefusal(
            "call_inline_depth_limit",
            location=CallRefusalLocation(
                function_entry, block.address,
                block.irsb.instruction_addresses[-1] if block.irsb.instruction_addresses else None,
            ),
        )
    if session.inlined_calls >= session.limits.max_inlined_calls:
        raise CallCompositionRefusal("call_inline_budget")
    # Reserve work before descending: nested composition shares this cap.
    # A refused session is discarded and can never publish partial counters.
    session.inlined_calls += 1
    callee_state = _compose_function(
        session, target, active | {target}, depth + 1,
        incoming=state if session.root_bound_inputs else None,
        incoming_guard=guard if session.root_bound_inputs else None,
    )
    callee_return = callee_state.get("eip")
    if not isinstance(callee_return, dict):
        raise CallCompositionRefusal("callee_terminal_missing")
    instruction_addresses = block.irsb.instruction_addresses
    if not instruction_addresses:
        raise CallCompositionRefusal("call_instruction_address_missing")
    _transfer_callee_obligations(
        session, target, state, guard, callsite=instruction_addresses[-1],
        obligations=session.last_obligation_frame if session.root_bound_inputs else None,
    )
    # The domain always binds ROOT input ESP. In the contextual retry, callee
    # entry registers/memory already contain root expressions, so no shifted
    # nested frame is mistaken for the root input.
    root_constraints = (
        session.entry_domain.constraints()
        if session.entry_domain is not None and (depth == 0 or session.root_bound_inputs)
        else None
    )
    _prove_return_target(
        _callee_term(callee_return, state, session),
        fallthrough,
        timeout_ms=_ret_proof_timeout_ms(session),
        callsite=instruction_addresses[-1],
        call_block=block.address,
        target=target,
        callee=session.labels.get(target, ""),
        input_constraints=root_constraints,
        buffer_domains=session.root_buffer_domains if session.root_bound_inputs else (),
        proof_records=session.return_buffer_proofs,
    )
    post = _apply_callee_state(session, state, callee_state, fallthrough)
    session.return_targets_proved += 1
    session.call_sites.append(
        {
            "callsite": hex(instruction_addresses[-1]),
            "call_block": hex(block.address),
            "target": hex(target),
            "fallthrough": hex(fallthrough),
            "depth": depth + 1,
            "cached_summary_depth_exemption": reusable_summary and depth + 1 > session.limits.max_inline_depth,
            "terminal_import_depth_exemption": terminal_import,
            "callee": session.labels.get(target, ""),
            "proved_under_entry_domain": root_constraints is not None,
        }
    )
    return post


@dataclass
class _IndirectCallSite:
    """Per-call-site state while decomposing one deferred-indirect call.

    ``callees`` caches each distinct target's caller-substituted post-state
    return term and checking obligations so a target reached through several selector paths is
    inlined — and charged against ``max_inlined_calls`` — exactly once,
    while ``leaves`` bounds the enumerated proof obligations against
    ``limits.max_indirect_call_targets``; a leaf found under a different
    path predicate still re-runs its return-target proof.
    """

    callees: dict[int, tuple[dict[str, dict[str, Any]], dict[str, Any], tuple[dict[str, Any], ...]]] = field(
        default_factory=dict
    )
    leaves: int = 0


def _selector_const(width: int, value: int) -> dict[str, Any]:
    """Build a full-width constant term in the shared SSA JSON shape."""
    return {"op": "const", "value": hex(value & ((1 << width) - 1)), "width": width}


def _selector_test(cond: dict[str, Any], taken: bool) -> dict[str, Any]:
    """Build the one-bit term that is nonzero exactly on the selected ``ite`` arm."""
    zero = _selector_const(max(1, S._term_width(cond)), 0)
    return {"op": "ne" if taken else "eq", "width": 1, "args": [cond, zero]}


def _selector_conjunction(predicates: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    """Fold the arm tests accumulated to a leaf into one one-bit path predicate."""
    term = predicates[0]
    for predicate in predicates[1:]:
        term = {"op": "and", "width": 1, "args": [term, predicate]}
    return term


def _seed_premise_allowed(session: _ComposeSession, function_entry: int, depth: int) -> bool:
    """True only where ``mem_input`` denotes canonical top-level entry memory.

    A generic nested callee's ``mem_input`` is its own arbitrary callsite
    state; image bytes may never anchor a premise there.  Root-bound callees
    carry the root's entry leaf inside ``incoming``, and the root's own
    depth-0 frame uses the same canonical leaf.
    """
    return session.root_entry is not None and (
        session.root_bound_inputs or (depth == 0 and function_entry == session.root_entry)
    )


def _seed_constraints(session: _ComposeSession) -> list[dict[str, Any]]:
    """Entry-domain input bounds for interval analysis; empty when undeclared."""
    return session.entry_domain.constraints() if session.entry_domain is not None else []


def _preserved_cell_read(
    node: dict[str, Any], constraints: list[dict[str, Any]]
) -> tuple[dict[str, Any], int, dict[str, Any]] | None:
    """Return ``(memory, address, address_term)`` for a preserved literal read.

    Only a ``loadle`` with a literal-constant 32-bit address whose range is
    proved disjoint from every intervening store qualifies; everything else
    stays symbolic.
    """
    if node.get("op") != "loadle" or node.get("width") != 32:
        return None
    args = node.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    memory, address_term = args
    if not isinstance(memory, dict) or not isinstance(address_term, dict):
        return None
    address = _const_term_int(address_term)
    if address is None or address > 0xFFFFFFFC:
        return None
    if prove_region_preserved(memory, address, 4, constraints) is None:
        return None
    return memory, address, address_term


def _cell_image_dword(session: _ComposeSession, address: int) -> int | None:
    """Read four initial image bytes at one cell, refusing unmapped reads."""
    try:
        raw = session.project.loader.memory.load(address, 4)
    except (KeyError, TypeError, ValueError, IndexError):
        return None
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 4:
        return None
    return int.from_bytes(bytes(raw), "little")


def _indirect_read_proposal(
    session: _ComposeSession, function_entry: int, depth: int, term: dict[str, Any]
) -> IndirectReadProposal | None:
    """Propose image-derived root-entry premises for preserved literal reads.

    The deferred ``ip`` leaf may be any DAG whose target value flows through
    ``loadle`` reads of concrete global cells — ``or eax, eax`` rewriting the
    register is the common shape.  Every ``loadle``/``loadbe`` node in the
    leaf must name a preserved width-32 literal address; a symbolic-addressed
    table read, an unpreserved cell, an unmapped cell or a narrower load can
    never be discharged by entry bytes, so the stable refusal stands.  Each
    admitted cell names initial image bytes as a disclosed top-level premise;
    a nested callee whose ``mem_input`` is not the root entry still refuses.
    """
    if not isinstance(term, dict) or not _seed_premise_allowed(session, function_entry, depth):
        return None
    constraints = _seed_constraints(session)
    cells: dict[int, int] = {}
    seen: set[int] = set()
    stack = [term]
    blocked = False
    while stack and not blocked:
        _check_compose_deadline(session.compose_stats)
        node = stack.pop()
        if id(node) in seen or not isinstance(node, dict):
            continue
        seen.add(id(node))
        args = node.get("args")
        if node.get("op") in {"loadle", "loadbe"}:
            hit = _preserved_cell_read(node, constraints)
            if hit is None:
                blocked = True
                break
            value = _cell_image_dword(session, hit[1])
            if value is None:
                blocked = True
                break
            cells[hit[1]] = value
            continue
        if isinstance(args, list):
            stack.extend(arg for arg in args if isinstance(arg, dict))
    if blocked or not cells:
        return None
    return IndirectReadProposal(cells)


def _reduce_seeded_reads(
    term: dict[str, Any],
    session: _ComposeSession,
    constraints: list[dict[str, Any]],
    function_entry: int,
    memo: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    """Fold one proved-preserved seeded-cell read to its disclosed value.

    A ``loadle`` at a seeded literal address is rewritten only after
    ``prove_region_preserved`` discharges every intervening store against the
    canonical root-entry leaf; the read then names
    ``loadle(storele(mem_input, cell, value), cell)`` so existing constant
    proofs fold it while every other byte stays live.  Unpreserved or
    unseeded reads keep their original terms.
    """
    cached = memo.get(id(term))
    if cached is not None:
        return cached
    _check_compose_deadline(session.compose_stats)
    result = term
    args = term.get("args")
    if isinstance(args, list) and args:
        reduced = [
            _reduce_seeded_reads(arg, session, constraints, function_entry, memo)
            if isinstance(arg, dict) else arg
            for arg in args
        ]
        if any(new is not old for new, old in zip(reduced, args, strict=True)):
            result = {**term, "args": reduced}
    hit = _preserved_cell_read(result, constraints)
    if hit is not None and hit[1] in session.seed_cells:
        _, address, address_term = hit
        session.cells_used.setdefault(function_entry, set()).add(address)
        result = {
            "op": "loadle",
            "width": 32,
            "args": [
                {
                    "op": "storele",
                    "width": 0,
                    "args": [
                        {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                        address_term,
                        {"op": "const", "width": 32, "value": hex(session.seed_cells[address])},
                    ],
                },
                address_term,
            ],
        }
    memo[id(term)] = result
    return result


def _reduce_seeded_state(
    state: dict[str, dict[str, Any]], session: _ComposeSession, function_entry: int, depth: int
) -> dict[str, dict[str, Any]]:
    """Apply seeded-cell read reductions to every composed output term."""
    if not session.seed_cells or not _seed_premise_allowed(session, function_entry, depth):
        return state
    constraints = _seed_constraints(session)
    memo: dict[int, dict[str, Any]] = {}
    return {
        name: _reduce_seeded_reads(term, session, constraints, function_entry, memo)
        for name, term in state.items()
    }


def _indirect_cell_obligation(function_entry: int, address: int, value: int) -> dict[str, Any]:
    """Bind one discovered cell as an explicit root-entry singleton premise.

    The record reuses the accepted ``flat32_entry_memory_unsigned_range``
    contract — the same shape the reviewed ABI catalog pins for this very
    allocator callback — extended with the discovery site and provenance so a
    report can distinguish image-derived seeded retries from caller-declared
    catalog ranges.  It binds canonical root-entry memory only and is never
    substituted into callsite state.
    """
    obligation: dict[str, Any] = Flat32EntryMemoryRange(address, 32, value, value).obligation()
    obligation["provenance"] = "discovered_indirect_target_bytes"
    obligation["site"] = {"function_entry": hex(function_entry)}
    obligation["scope"] = (
        "canonical root entry memory only; image-derived disclosed premise, "
        "not an immutability claim"
    )
    return obligation


@dataclass(frozen=True)
class _EvidenceSnapshot:
    """Remember published evidence lengths, never consumed work or deadlines."""

    call_sites: int
    tail_sites: int
    external_sites: int
    constant_branch_proofs: int
    unreachable_exception_proofs: int
    return_buffer_proofs: int
    block_lift_retries: int
    return_targets_proved: int
    last_obligation_frame: list[dict[str, Any]]


def _evidence_snapshot(session: _ComposeSession) -> _EvidenceSnapshot:
    """Record evidence-list lengths before a composition attempt that may retry.

    Shared deadlines, budgets and consumed work are deliberately not
    snapshotted: a retried attempt still pays for the work it discarded.
    """
    return _EvidenceSnapshot(
        call_sites=len(session.call_sites), tail_sites=len(session.tail_sites),
        external_sites=len(session.external_sites),
        constant_branch_proofs=len(session.constant_branch_proofs),
        unreachable_exception_proofs=len(session.unreachable_exception_proofs),
        return_buffer_proofs=len(session.return_buffer_proofs),
        block_lift_retries=len(session.block_lift_retries),
        return_targets_proved=session.return_targets_proved,
        last_obligation_frame=list(session.last_obligation_frame),
    )


def _restore_evidence(session: _ComposeSession, snapshot: _EvidenceSnapshot) -> None:
    """Drop partial proof records from a discarded attempt; work stays charged."""
    del session.call_sites[snapshot.call_sites:]
    del session.tail_sites[snapshot.tail_sites:]
    del session.external_sites[snapshot.external_sites:]
    del session.constant_branch_proofs[snapshot.constant_branch_proofs:]
    del session.unreachable_exception_proofs[snapshot.unreachable_exception_proofs:]
    del session.return_buffer_proofs[snapshot.return_buffer_proofs:]
    del session.block_lift_retries[snapshot.block_lift_retries:]
    session.return_targets_proved = snapshot.return_targets_proved
    session.last_obligation_frame = snapshot.last_obligation_frame


def _compose_indirect_call(
    session: _ComposeSession,
    blocks: dict[int, _LiftedBlock],
    function_entry: int,
    block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    path: frozenset[int],
    active: frozenset[int],
    depth: int,
    guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Inline every finitely enumerable target of a deferred-indirect call.

    The block's composed ``ip`` term is the complete selector under the
    actual caller state: it decomposes into ``ite`` arms whose leaves must
    each be a full-width constant naming a declared function entry —
    universal destination membership, proved, never sampled or allowlisted.
    A nonconstant leaf gets bounded exact bit-vector/array simplification;
    only a universal constant can proceed. Symbolic leaves still refuse.  The structural walk is total,
    so a returned post-state witnesses nonvacuity: at least one feasible
    target was found, inlined and proved.  Each leaf runs the same callee
    composition and return-target proof as a direct call, under the exact
    path predicate accumulated from the ``ite`` guards
    (``ite(predicate, ret, fallthrough) == fallthrough``), and the per-arm
    post-states merge with ``merge_states`` like guarded branches
    before the caller continues at the fallthrough.  Cycles, missing
    entries, over-wide selectors and budget exhaustion keep the typed call
    refusals.
    """
    fallthrough = block.fallthrough
    if fallthrough is None:
        raise CallCompositionRefusal("call_target_unmapped")
    ip = state.get("ip")
    if not isinstance(ip, dict):
        raise CallCompositionRefusal("call_indirect_target_unconstrained")
    instruction_addresses = block.irsb.instruction_addresses
    if not instruction_addresses:
        raise CallCompositionRefusal("call_instruction_address_missing")
    # The domain always binds ROOT input ESP, exactly as in _compose_call.
    root_constraints = (
        session.entry_domain.constraints()
        if session.entry_domain is not None and (depth == 0 or session.root_bound_inputs)
        else None
    )
    site = _IndirectCallSite()
    post = _compose_indirect_arm(
        session,
        block,
        state,
        ip,
        (),
        site,
        function_entry=function_entry,
        active=active,
        depth=depth,
        fallthrough=fallthrough,
        callsite=instruction_addresses[-1],
        root_constraints=root_constraints,
        guard=guard,
    )
    return _walk(session, blocks, function_entry, fallthrough, post, path, active, depth, guard)


def _compose_indirect_arm(
    session: _ComposeSession,
    block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    term: dict[str, Any],
    predicates: tuple[dict[str, Any], ...],
    site: _IndirectCallSite,
    *,
    function_entry: int,
    active: frozenset[int],
    depth: int,
    fallthrough: int,
    callsite: int,
    root_constraints: list[dict[str, Any]] | None,
    guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Walk one arm of the selector term and merge its guarded post-state."""
    _check_compose_deadline(session.compose_stats)
    target = _const_term_int(term)
    target_proof = None
    if target is None and term.get("op") != "ite":
        recovered = constant_call_target(term)
        _check_compose_deadline(session.compose_stats)
        if recovered is not None:
            target, target_proof = recovered
    if target is not None:
        post = _compose_indirect_leaf(
            session,
            block,
            state,
            target,
            predicates,
            site,
            active=active,
            depth=depth,
            fallthrough=fallthrough,
            callsite=callsite,
            root_constraints=root_constraints,
            guard=guard,
        )
        if target_proof is not None:
            session.call_sites[-1]["target_constant_proof"] = target_proof
        return post
    if term.get("op") != "ite":
        recovered_selector = finite_call_selector(
            term, set(session.functions),
            max_targets=session.limits.max_indirect_call_targets,
            timeout_ms=_ret_proof_timeout_ms(session),
        )
        _check_compose_deadline(session.compose_stats)
        if recovered_selector is not None:
            selector_term, selector_proof = recovered_selector
            start = len(session.call_sites)
            post = _compose_indirect_arm(
                session, block, state, selector_term, predicates, site,
                function_entry=function_entry,
                active=active, depth=depth, fallthrough=fallthrough,
                callsite=callsite, root_constraints=root_constraints,
                guard=guard,
            )
            _record_target_selector_proof(session.call_sites[start:], callsite, depth, selector_proof)
            return post
    args = term.get("args") if isinstance(term, dict) else None
    if (
        not isinstance(term, dict)
        or term.get("op") != "ite"
        or not isinstance(args, list)
        or len(args) != 3
        or not all(isinstance(arg, dict) for arg in args)
    ):
        proposal = _indirect_read_proposal(session, function_entry, depth, term)
        if proposal is not None:
            raise proposal
        raise CallCompositionRefusal("call_indirect_target_unconstrained")
    true_post = _compose_indirect_arm(
        session,
        block,
        state,
        args[1],
        (*predicates, _selector_test(args[0], True)),
        site,
        function_entry=function_entry,
        active=active,
        depth=depth,
        fallthrough=fallthrough,
        callsite=callsite,
        root_constraints=root_constraints,
        guard=guard,
    )
    false_post = _compose_indirect_arm(
        session,
        block,
        state,
        args[2],
        (*predicates, _selector_test(args[0], False)),
        site,
        function_entry=function_entry,
        active=active,
        depth=depth,
        fallthrough=fallthrough,
        callsite=callsite,
        root_constraints=root_constraints,
        guard=guard,
    )
    merged: dict[str, dict[str, Any]] = merge_states(
        args[0], true_post, false_post, compose_stats=session.compose_stats
    )
    if _term_nodes(merged, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    return merged



def _record_target_selector_proof(
    records: list[dict[str, Any]], callsite: int, depth: int, proof: dict[str, Any],
) -> None:
    """Attach membership evidence to this selector's leaves, excluding nested calls."""
    for record in records:
        if record.get("callsite") == hex(callsite) and record.get("depth") == depth + 1:
            record["target_selector_proof"] = proof


def _compose_indirect_leaf(
    session: _ComposeSession,
    block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    target: int,
    predicates: tuple[dict[str, Any], ...],
    site: _IndirectCallSite,
    *,
    active: frozenset[int],
    depth: int,
    fallthrough: int,
    callsite: int,
    root_constraints: list[dict[str, Any]] | None,
    guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Compose and prove one feasible target under its exact path predicate.

    Membership, acyclicity and depth/inline budgets reuse the same typed
    refusals as a direct call.  A distinct target is inlined once per call
    site; the return-target proof is re-run per leaf so every selector arm
    carries its own obligation under ``predicates``.
    """
    site.leaves += 1
    if site.leaves > session.limits.max_indirect_call_targets:
        raise CallCompositionRefusal("call_indirect_target_limit")
    if target not in session.functions:
        raise CallCompositionRefusal(f"call_target_unmapped:{hex(target)}")
    if target in active:
        raise CallCompositionRefusal(f"recursive_call:{hex(target)}")
    reusable_summary = not session.root_bound_inputs and target in session.summaries
    if depth + 1 > session.limits.max_inline_depth and not reusable_summary:
        raise CallCompositionRefusal("call_inline_depth_limit")
    cached = site.callees.get(target)
    if cached is None:
        if session.inlined_calls >= session.limits.max_inlined_calls:
            raise CallCompositionRefusal("call_inline_budget")
        # Reserve work before descending: nested composition shares this cap.
        session.inlined_calls += 1
        callee_state = _compose_function(
            session,
            target,
            active | {target},
            depth + 1,
            incoming=state if session.root_bound_inputs else None,
            incoming_guard=guard if session.root_bound_inputs else None,
        )
        callee_return = callee_state.get("eip")
        if not isinstance(callee_return, dict):
            raise CallCompositionRefusal("callee_terminal_missing")
        cached = (
            _apply_callee_state(session, state, callee_state, fallthrough),
            _callee_term(callee_return, state, session),
            tuple(session.last_obligation_frame),
        )
        site.callees[target] = cached
    post, return_target, callee_obligations = cached
    leaf_guard = _and_guard(guard, _selector_conjunction(predicates)) if predicates else guard
    _transfer_callee_obligations(
        session, target, state, leaf_guard, callsite=callsite,
        obligations=(list(callee_obligations) if session.root_bound_inputs
                     else session.summary_obligations.get(target, ())),
    )
    selector = _selector_conjunction(predicates) if predicates else None
    if selector is None:
        proof_target = return_target
    else:
        proof_target = {
            "op": "ite",
            "width": 32,
            "args": [selector, return_target, _selector_const(32, fallthrough)],
        }
    _prove_return_target(
        proof_target,
        fallthrough,
        timeout_ms=_ret_proof_timeout_ms(session),
        callsite=callsite,
        call_block=block.address,
        target=target,
        callee=session.labels.get(target, ""),
        input_constraints=root_constraints,
        buffer_domains=session.root_buffer_domains if session.root_bound_inputs else (),
        proof_records=session.return_buffer_proofs,
        selector=selector,
    )
    session.return_targets_proved += 1
    session.call_sites.append(
        {
            "callsite": hex(callsite),
            "call_block": hex(block.address),
            "target": hex(target),
            "fallthrough": hex(fallthrough),
            "depth": depth + 1,
            "cached_summary_depth_exemption": reusable_summary and depth + 1 > session.limits.max_inline_depth,
            "callee": session.labels.get(target, ""),
            "proved_under_entry_domain": root_constraints is not None,
            "indirect": True,
            "arm": site.leaves,
        }
    )
    return post


def _compose_tail(
    session: _ComposeSession,
    block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    target: int,
    active: frozenset[int],
    depth: int,
    guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Compose an admitted tail transfer's destination over the live state.

    A tail ``jmp`` pushes no return address and performs no stack
    adjustment, so the destination's complete input-free summary is
    substituted over the caller's live ``state`` verbatim — including the
    destination's ``eip``, which resolves the return slot already present
    in the caller frame.  The tail carries no return-target proof of its
    own: an enclosing ``Ijk_Call`` discharges its fallthrough proof against
    this composed ``eip``, and at root the composed ``eip`` simply remains
    the summary's observed terminal state.  Tail transfers consume the
    shared inline-depth budget and a dedicated ``max_tail_transfers``
    budget, refuse cycles through ``active`` like real calls, and leave the
    optional root ESP domain untouched — no nested proof ever transports
    it by assumption.
    """
    if target in active:
        raise CallCompositionRefusal(f"recursive_tail_transfer:{hex(target)}")
    reusable_summary = target in session.summaries
    if depth + 1 > session.limits.max_inline_depth and not reusable_summary:
        from tools.dosunit.compare.flat32_summary_schedule import prepare_internal_summary

        reusable_summary = prepare_internal_summary(session, target, active, _compose_function)
    if depth + 1 > session.limits.max_inline_depth and not reusable_summary:
        raise CallCompositionRefusal("tail_inline_depth_limit")
    if session.tail_transfers >= session.limits.max_tail_transfers:
        raise CallCompositionRefusal("tail_transfer_budget")
    # Reserve before descent so nested tail chains cannot overshoot the cap.
    session.tail_transfers += 1
    callee_state = _compose_function(
        session, target, active | {target}, depth + 1,
        incoming=state if session.root_bound_inputs else None,
        incoming_guard=guard if session.root_bound_inputs else None,
    )
    callee_return = callee_state.get("eip")
    if not isinstance(callee_return, dict):
        raise CallCompositionRefusal("callee_terminal_missing")
    instruction_addresses = block.irsb.instruction_addresses
    _transfer_callee_obligations(
        session, target, state, guard,
        callsite=instruction_addresses[-1] if instruction_addresses else None,
        obligations=session.last_obligation_frame if session.root_bound_inputs else None,
    )
    composed: dict[str, dict[str, Any]] = {}
    for name, term in callee_state.items():
        _check_compose_deadline(session.compose_stats)
        composed[name] = _callee_term(term, state, session)
    if _term_nodes(composed, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    session.tail_sites.append(
        {
            "site": hex(instruction_addresses[-1]) if instruction_addresses else hex(block.address),
            "block": hex(block.address),
            "target": hex(target),
            "depth": depth + 1,
            "callee": session.labels.get(target, ""),
            "cached_summary_depth_exemption": reusable_summary and depth + 1 > session.limits.max_inline_depth,
        }
    )
    return composed


def _compose_ip_targets(
    session: _ComposeSession,
    blocks: dict[int, _LiftedBlock],
    function_entry: int,
    block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    ip: dict[str, Any],
    path: frozenset[int],
    active: frozenset[int],
    depth: int,
    guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Walk each arm of a possibly nested direct-branch ite exit chain.

    A constant arm naming one of the owning block's admitted
    ``tail_targets`` tail-composes the foreign destination instead of
    walking it as an intra-function successor; every other arm keeps the
    existing walk/refuse behavior.
    """
    target = _const_term_int(ip)
    if target is not None:
        if target in block.tail_targets:
            return _compose_tail(session, block, state, target, active, depth, guard)
        return _walk(session, blocks, function_entry, target, state, path, active, depth, guard)
    args = ip.get("args")
    if ip.get("op") != "ite" or not isinstance(args, list) or len(args) != 3:
        raise CallCompositionRefusal("indirect_or_unmodeled_branch")
    if not all(isinstance(arg, dict) for arg in args):
        raise CallCompositionRefusal("indirect_or_unmodeled_branch")
    _check_compose_deadline(session.compose_stats)
    proof = constant_branch(args[0])
    if proof.value is BranchValue.UNKNOWN:
        proof = branch_under_path(
            args[0], guard,
            timeout_ms=min(1000, _ret_proof_timeout_ms(session)) if session.root_memory_bindings else 0,
            input_constraints=(session.entry_domain.constraints()
                               if session.entry_domain is not None and session.root_bound_inputs else None),
        ) or proof
    _check_compose_deadline(session.compose_stats)
    if proof.value is not BranchValue.UNKNOWN:
        selected = args[1] if proof.value is BranchValue.TRUE else args[2]
        selected_target = _const_term_int(selected)
        revisit = selected_target in path and selected_target in blocks
        session.constant_branch_proofs.append({
            "function_entry": hex(function_entry), "block": hex(block.address),
            "depth": depth, "proof": proof.to_document(),
            "revisited_target": hex(selected_target) if revisit and selected_target is not None else None,
        })
        # A proved concrete backedge can execute another iteration. This is
        # finite execution, not induction: retain the full state, recompute
        # every later guard, and publish only after all paths reach a return.
        # Existing composition, expression and deadline limits remain shared.
        next_path = frozenset() if revisit else path
        return _compose_ip_targets(session, blocks, function_entry, block, state, selected, next_path, active, depth, guard)
    true_state = _compose_ip_targets(
        session, blocks, function_entry, block, state, args[1], path, active, depth,
        _and_guard(guard, args[0]),
    )
    false_state = _compose_ip_targets(
        session, blocks, function_entry, block, state, args[2], path, active, depth,
        _and_guard(guard, {"op": "not", "width": 1, "args": [args[0]]}),
    )
    merged: dict[str, dict[str, Any]] = merge_states(
        args[0], true_state, false_state, compose_stats=session.compose_stats
    )
    if _term_nodes(merged, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    return merged


def _external_post(
    session: _ComposeSession, block: _LiftedBlock, state: dict[str, dict[str, Any]],
    guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Authenticate a live imported target and apply its declared returning effects."""
    if block.external_slot is None:
        raise CallCompositionRefusal("external_slot_missing")
    binding = session.external_bindings[block.external_slot]
    target_proof = prove_import_target(
        state["ip"], binding, timeout_ms=_ret_proof_timeout_ms(session),
        input_constraints=session.entry_domain.constraints() if session.entry_domain is not None else None,
        path_guard=guard,
    )
    preserved_slots = tuple(sorted(session.external_bindings)) if binding.contract.preserve_import_bindings else ()
    post: dict[str, dict[str, Any]] = external_call_state(binding.contract, state, import_slots=preserved_slots)
    session.external_sites.append({
        "site": hex(block.irsb.instruction_addresses[-1]),
        "target_preserved": True, **binding.declared_fields(),
        "target_preservation_proof": target_proof,
        "preserved_import_slots": [hex(slot) for slot in preserved_slots],
    })
    if block.jumpkind != "Ijk_Call":
        return post
    if block.fallthrough is None:
        raise CallCompositionRefusal("external_call_fallthrough_missing")
    _prove_return_target(
        post["eip"], block.fallthrough, timeout_ms=_ret_proof_timeout_ms(session),
        callsite=block.irsb.instruction_addresses[-1], call_block=block.address,
        target=binding.slot, callee=binding.contract.name,
        buffer_domains=session.root_buffer_domains if session.root_bound_inputs else (),
        proof_records=session.return_buffer_proofs,
        input_constraints=session.entry_domain.constraints() if session.entry_domain is not None else None,
    )
    session.return_targets_proved += 1
    # Publish the proved continuation for both path and DAG consumers.
    proved_return = {"op": "const", "width": 32, "value": hex(block.fallthrough)}
    post["ip"], post["eip"] = proved_return, proved_return
    return post


def _continue_external(
    session: _ComposeSession, blocks: dict[int, _LiftedBlock], function_entry: int,
    block: _LiftedBlock, state: dict[str, dict[str, Any]], path: frozenset[int],
    active: frozenset[int], depth: int, guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Finish an imported tail transfer or continue a returning imported CALL."""
    post = _external_post(session, block, state, guard)
    if block.fallthrough is None:
        return post
    return _walk(session, blocks, function_entry, block.fallthrough, post, path, active, depth, guard)


def _compose_located_call(
    session: _ComposeSession, blocks: dict[int, _LiftedBlock],
    function_entry: int, block: _LiftedBlock,
    state: dict[str, dict[str, Any]], path: frozenset[int],
    active: frozenset[int], depth: int, guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Preserve the innermost unresolved callback site for contextual retry."""
    try:
        return _compose_call(session, blocks, function_entry, block, state, path, active, depth, guard)
    except CallCompositionRefusal as error:
        if str(error) == "call_indirect_target_unconstrained" and error.location is None:
            addresses = block.irsb.instruction_addresses
            error.location = CallRefusalLocation(
                function_entry, block.address, addresses[-1] if addresses else None,
            )
        raise


def _bind_checking_obligations(
    session: _ComposeSession,
    block: _LiftedBlock,
    function_entry: int,
    address: int,
    incoming: dict[str, dict[str, Any]],
    guard: dict[str, Any] | None,
) -> None:
    """Bind a lifted block's checking-instruction obligations at this site."""
    if block.part.get("obligations"):
        _obligation_sink(session).extend(
            bind_x87_obligations(block.part, incoming, site={
                "address": address, "function_entry": function_entry,
            }, guard=guard)
        )


def _walk(
    session: _ComposeSession,
    blocks: dict[int, _LiftedBlock],
    function_entry: int,
    address: int,
    incoming: dict[str, dict[str, Any]],
    path: frozenset[int],
    active: frozenset[int],
    depth: int,
    guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Compose a path to a near return, inlining calls and proved loop steps.

    Every block visit re-checks the shared deadline before touching work and
    hands the session ``compose_stats`` to ``compose_block_outputs`` so
    that helper's per-output inner loop enforces the same bound.
    """
    _check_compose_deadline(session.compose_stats)
    if address in path:
        raise InductiveLoopRequired(
            location=CallRefusalLocation(
                function_entry=function_entry, block_address=address,
                instruction_address=None,
            ),
        )
    block = blocks.get(address)
    if block is None:
        raise CallCompositionRefusal(f"successor_outside_complete_region:{hex(address)}")
    session.compositions += 1
    if session.compositions > session.limits.max_compositions:
        raise CallCompositionRefusal("region_composition_limit")
    _bind_checking_obligations(session, block, function_entry, address, incoming, guard)
    state: dict[str, dict[str, Any]] = compose_block_outputs(
        block.part, block.part.get("outputs", {}), incoming, compose_stats=session.compose_stats
    )
    state = _reduce_seeded_state(state, session, function_entry, depth)
    if _term_nodes(state, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    ip = state.get("ip")
    if not isinstance(ip, dict):
        raise CallCompositionRefusal("full_width_ip_unobserved")
    if block.jumpkind == "Ijk_Ret":
        if ip.get("op") == "ite":
            raise CallCompositionRefusal("conditional_exit_in_return_block")
        state["eip"] = ip
        return state
    # A backedge may target an instruction inside the first lifted block.
    # Track executed instruction boundaries so a proved guard can recognize
    # that revisit and start the next bounded iteration with the live state.
    next_path = path | {address, *block.irsb.instruction_addresses}
    if block.external_slot is not None:
        return _continue_external(session, blocks, function_entry, block, state, next_path, active, depth, guard)
    if block.jumpkind == "Ijk_Call":
        return _compose_located_call(session, blocks, function_entry, block, state, next_path, active, depth, guard)
    return _compose_ip_targets(session, blocks, function_entry, block, state, ip, next_path, active, depth, guard)


def _compose_dag_call_state(
    session: _ComposeSession, entry: int, active: frozenset[int], depth: int,
    block: _LiftedBlock, state: dict[str, dict[str, Any]], reach: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Keep call checks with their existing owner at a merged DAG state."""
    if block.external_slot is not None:
        return _external_post(session, block, state, reach)
    return _compose_direct_call_state(session, entry, block, state, active, depth, reach)


def _compose_function_once(
    session: _ComposeSession, entry: int, active: frozenset[int], depth: int,
    *, incoming: dict[str, dict[str, Any]] | None,
    incoming_guard: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Run one lift-and-walk attempt for the composing function."""
    blocks = _lift_function(session, entry)
    from tools.dosunit.compare.flat32_dag_composition import compose_dag_if_needed

    initial = _initial_state(session.reg_widths) if incoming is None else incoming
    call_step = partial(_compose_dag_call_state, session, entry, active, depth)
    final: dict[str, dict[str, Any]] | None = compose_dag_if_needed(
        session, blocks, entry, initial,
        call_step=call_step, incoming_guard=incoming_guard)
    if final is None:
        final = _walk(
            session, blocks, entry, entry, initial,
            frozenset(), active, depth, incoming_guard,
        )
    return final


def _admit_seed_proposal(session: _ComposeSession, proposal: IndirectReadProposal) -> bool:
    """Register newly proposed cells; a repeat keeps the stable refusal."""
    fresh = {
        address: value
        for address, value in proposal.cells.items()
        if address not in session.seed_cells
    }
    if not fresh or len(session.seed_cells) + len(fresh) > session.limits.max_indirect_call_targets:
        return False
    session.seed_cells.update(fresh)
    _check_compose_deadline(session.compose_stats)
    return True


def _publish_consumed_cells(session: _ComposeSession, entry: int) -> None:
    """Bind every cell this entry consumed as a root-entry premise record.

    Published directly on ``x87_obligations`` so the predicate keeps the
    canonical root-entry ``mem_input`` leaf and is never substituted into
    callsite state — the premise is top-level by construction.
    """
    for address in sorted(session.cells_used.pop(entry, ())):
        key = (entry, address)
        if key in session.cells_published:
            continue
        session.cells_published.add(key)
        session.x87_obligations.append(
            _indirect_cell_obligation(entry, address, session.seed_cells[address])
        )


def _compose_function_retried(
    session: _ComposeSession, entry: int, active: frozenset[int], depth: int,
    *, incoming: dict[str, dict[str, Any]] | None,
    incoming_guard: dict[str, Any] | None,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Compose with seeded-cell retries; return the final state and its frame.

    A preserved literal indirect-target read raises ``IndirectReadProposal``;
    each newly proposed cell seeds one retry under its disclosed root-entry
    premise, and every consumed cell publishes its exact obligation before the
    summary completes.  A repeated proposal keeps the stable
    ``call_indirect_target_unconstrained`` refusal.
    """
    while True:
        session.obligation_frames.append([])
        snapshot = _evidence_snapshot(session)
        try:
            final = _compose_function_once(
                session, entry, active, depth,
                incoming=incoming, incoming_guard=incoming_guard,
            )
        except IndirectReadProposal as proposal:
            # Retry once per newly proposed cell so seeded reads fold; a
            # repeat means the premise did not resolve the call.
            session.obligation_frames.pop()
            _restore_evidence(session, snapshot)
            if not _admit_seed_proposal(session, proposal):
                raise CallCompositionRefusal(
                    "call_indirect_target_unconstrained",
                    evidence=proposal.evidence,
                    location=proposal.location,
                ) from proposal
            continue
        except S.LowerFailure as error:
            # Deadline checks inside shared inner loops raise LowerFailure;
            # every refusal leaving composition is the typed contract refusal.
            session.obligation_frames.pop()
            raise CallCompositionRefusal(error.reason) from error
        except CallCompositionRefusal:
            session.obligation_frames.pop()
            raise
        frame = session.obligation_frames.pop()
        _publish_consumed_cells(session, entry)
        return final, frame


def _compose_function(
    session: _ComposeSession, entry: int, active: frozenset[int], depth: int,
    *, incoming: dict[str, dict[str, Any]] | None = None,
    incoming_guard: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Compose one complete acyclic function body into a final-state summary.

    The shared deadline is checked before the summary cache is consulted, so
    even an O(1) cached return cannot publish work after the budget expired.
    A complete generic cached summary needs no recursive descent and may be
    substituted beyond the inline-depth cap; call-count and return proofs still
    apply. Root-bound summaries are never reusable by entry alone. An incoming
    guard belongs to the same root-bound state and is never cached generically.
    """
    _check_compose_deadline(session.compose_stats)
    if (incoming is not None or incoming_guard is not None) and not session.root_bound_inputs:
        raise CallCompositionRefusal("contextual_state_requires_root_binding")
    if session.root_bound_inputs and incoming is not None and entry not in session.summaries:
        from tools.dosunit.compare.flat32_summary_schedule import prepare_leaf_summary

        prepare_leaf_summary(session, entry, _compose_function)
    cached: dict[str, dict[str, Any]] | None = session.summaries.get(entry)
    if cached is not None:
        session.last_obligation_frame = list(session.summary_obligations.get(entry, ()))
        if session.root_bound_inputs:
            state = _initial_state(session.reg_widths) if incoming is None else incoming
            session.last_obligation_frame = [
                {**obligation, "predicate": _substitute_state_term(obligation["predicate"], state, session.compose_stats)}
                for obligation in session.last_obligation_frame
            ]
            return {name: _substitute_state_term(term, state, session.compose_stats) for name, term in cached.items()}
        return cached
    final, frame = _compose_function_retried(
        session, entry, active, depth, incoming=incoming, incoming_guard=incoming_guard
    )
    session.last_obligation_frame = frame
    if not session.root_bound_inputs:
        session.summaries[entry] = final
        # Generic (input-leaf) obligations are cached beside the summary so
        # every call site re-instantiates them against its own live state;
        # the root owner drains this entry into ``x87_obligations``.
        session.summary_obligations[entry] = frame
    elif not session.obligation_frames:
        # Root-bound obligations already bind caller terms; the root itself
        # has no caller, so they publish directly.
        session.x87_obligations.extend(frame)
    return final


def _compose_root(session: _ComposeSession, entry: int) -> dict[str, dict[str, Any]]:
    """Retry a contextual return or callback refusal once over live root inputs.

    A context-free callee can overwrite an unconstrained return slot even when
    its actual caller proves disjointness, or lack a callback target established
    by the caller. Retry by composing the same blocks
    over the live root state; every return still requires Z3 proof. Lifted blocks
    are reused, but context-dependent summaries are never cached by entry alone.
    Work counters and the absolute deadline are shared across both attempts.
    Discard proof records from the failed attempt before publishing evidence.

    ``_compose_root`` is the composed-call engine boundary: it enables
    ``session.admit_indirect_calls`` so ``_lift_function`` defers a
    non-constant call target to the composed ``ip`` selector instead of
    refusing at lift time.  Direct ``_lift_function`` consumers — the
    loop-composition lane and fixture tooling — never pass through here and
    keep the ``call_indirect_target`` lift refusal.
    """
    session.admit_indirect_calls = True
    session.root_entry = entry
    if session.external_bindings or session.root_buffer_domains or session.root_memory_bindings:
        # IAT and buffer obligations refer to root-entry memory. Generic
        # callee summaries would prove preservation relative to the wrong frame.
        session.root_bound_inputs = True
        incoming = None
        if session.root_memory_bindings:
            incoming = _initial_state(session.reg_widths)
            for binding in session.root_memory_bindings:
                incoming["memory"] = binding.seed(incoming["memory"])
        final = _compose_function(session, entry, frozenset({entry}), 0, incoming=incoming)
        session.x87_obligations.extend(session.summary_obligations.pop(entry, ()))
        return final
    try:
        final = _compose_function(session, entry, frozenset({entry}), 0)
        session.x87_obligations.extend(session.summary_obligations.pop(entry, ()))
        return final
    except CallCompositionRefusal as error:
        nested_callback = (
            str(error) == "call_indirect_target_unconstrained"
            and error.location is not None
            and error.location.function_entry != entry
        )
        nested_return = (
            error.evidence is not None
            and error.evidence.call_block not in session.blocks.get(entry, {})
        )
        if not (nested_callback or nested_return):
            # Root-call obligations already substitute the actual caller state;
            # replaying them cannot supply any missing outer context.
            raise
    _check_compose_deadline(session.compose_stats)
    session.root_bound_inputs = True
    session.summaries.clear()
    session.summary_obligations.clear()
    session.x87_obligations.clear()
    session.cells_used.clear()
    session.cells_published.clear()
    session.last_obligation_frame = []
    session.compose_stats.pop("eq_cache", None)
    session.compose_stats.pop("eq_keepalive", None)
    session.call_sites.clear()
    session.constant_branch_proofs.clear()
    session.tail_sites.clear()
    session.return_targets_proved = 0
    final = _compose_function(session, entry, frozenset({entry}), 0)
    session.x87_obligations.extend(session.summary_obligations.pop(entry, ()))
    return final
