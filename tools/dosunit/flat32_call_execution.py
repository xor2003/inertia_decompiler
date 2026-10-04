"""Layer: validation call composition execution.

Responsibility: compose acyclic lifted function bodies into final-state SSA
summaries, inlining proved direct calls.

Composition walks each acyclic path through ``S._compose_block_outputs`` and
merges conditional direct-branch exits with ``S._merge_abi_states``.  At an
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

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from tools.dosunit import straightline_ssa as S
from tools.dosunit.flat32_call_contracts import (
    CallCompositionRefusal,
    ReturnTargetProofFailure,
    _check_compose_deadline,
    _ComposeSession,
    _const_term_int,
    _initial_state,
    _LiftedBlock,
    _ret_proof_timeout_ms,
    _term_nodes,
)
from tools.dosunit.flat32_call_lowering import _lift_function
from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.ssa_output_lemmas import ScalarPreprocessing


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
    assignments: list[dict[str, Any]] = []
    materialized = S._materialize_json_term(return_target, assignments=assignments, memo={})
    oracle = {
        "outputs": {"eip": materialized},
        "assignments": assignments,
        "inputs": S._term_input_items([materialized], assignments),
    }
    candidate = {
        "outputs": {"eip": {"op": "const", "value": hex(fallthrough), "width": 32}},
        "assignments": [],
        "inputs": [],
    }
    result = S._compare_functions(
        oracle, candidate, timeout_ms=timeout_ms,
        input_constraints=input_constraints,
        scalar_preprocessing=ScalarPreprocessing.READ_OVER_WRITE,
    )
    result["scalar_preprocessing"] = ScalarPreprocessing.READ_OVER_WRITE.value
    if input_constraints:
        result["input_constraints"] = [dict(item) for item in input_constraints]
    status = proof_status_from_legacy(result.get("status"))
    if status is ProofStatus.PROVED:
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
    session: _ComposeSession,
    blocks: dict[int, _LiftedBlock],
    function_entry: int,
    block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    path: frozenset[int],
    active: frozenset[int],
    depth: int,
) -> dict[str, dict[str, Any]]:
    """Inline the proved callee(s) and continue the caller at the fallthrough.

    A declared direct target inlines one callee; a deferred-indirect call
    (``call_target=None``) decomposes its composed ``ip`` selector and
    inlines every finitely enumerable target under its own path predicate.
    """
    target = block.call_target
    fallthrough = block.fallthrough
    if fallthrough is None:
        raise CallCompositionRefusal("call_target_unmapped")
    if target is None:
        return _compose_indirect_call(
            session, blocks, function_entry, block, state, path, active, depth
        )
    if _const_term_int(state.get("ip")) != target:
        raise CallCompositionRefusal("call_target_mismatch")
    if target in active:
        raise CallCompositionRefusal(f"recursive_call:{hex(target)}")
    if depth + 1 > session.limits.max_inline_depth:
        raise CallCompositionRefusal("call_inline_depth_limit")
    if session.inlined_calls >= session.limits.max_inlined_calls:
        raise CallCompositionRefusal("call_inline_budget")
    # Reserve work before descending: nested composition shares this cap.
    # A refused session is discarded and can never publish partial counters.
    session.inlined_calls += 1
    callee_state = _compose_function(
        session, target, active | {target}, depth + 1,
        incoming=state if session.root_bound_inputs else None,
    )
    callee_return = callee_state.get("eip")
    if not isinstance(callee_return, dict):
        raise CallCompositionRefusal("callee_terminal_missing")
    instruction_addresses = block.irsb.instruction_addresses
    if not instruction_addresses:
        raise CallCompositionRefusal("call_instruction_address_missing")
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
            "callee": session.labels.get(target, ""),
            "proved_under_entry_domain": root_constraints is not None,
        }
    )
    return _walk(session, blocks, function_entry, fallthrough, post, path, active, depth)


@dataclass
class _IndirectCallSite:
    """Per-call-site state while decomposing one deferred-indirect call.

    ``callees`` caches each distinct target's caller-substituted post-state
    and return term so a target reached through several selector paths is
    inlined — and charged against ``max_inlined_calls`` — exactly once,
    while ``leaves`` bounds the enumerated proof obligations against
    ``limits.max_indirect_call_targets``; a leaf found under a different
    path predicate still re-runs its return-target proof.
    """

    callees: dict[int, tuple[dict[str, dict[str, Any]], dict[str, Any]]] = field(
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


def _compose_indirect_call(
    session: _ComposeSession,
    blocks: dict[int, _LiftedBlock],
    function_entry: int,
    block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    path: frozenset[int],
    active: frozenset[int],
    depth: int,
) -> dict[str, dict[str, Any]]:
    """Inline every finitely enumerable target of a deferred-indirect call.

    The block's composed ``ip`` term is the complete selector under the
    actual caller state: it decomposes into ``ite`` arms whose leaves must
    each be a full-width constant naming a declared function entry —
    universal destination membership, proved, never sampled or allowlisted.
    A leaf that is not a constant (input, memory load or an unmodeled op)
    is an unconstrained target and refuses.  The structural walk is total,
    so a returned post-state witnesses nonvacuity: at least one feasible
    target was found, inlined and proved.  Each leaf runs the same callee
    composition and return-target proof as a direct call, under the exact
    path predicate accumulated from the ``ite`` guards
    (``ite(predicate, ret, fallthrough) == fallthrough``), and the per-arm
    post-states merge with ``S._merge_abi_states`` like guarded branches
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
        active=active,
        depth=depth,
        fallthrough=fallthrough,
        callsite=instruction_addresses[-1],
        root_constraints=root_constraints,
    )
    return _walk(session, blocks, function_entry, fallthrough, post, path, active, depth)


def _compose_indirect_arm(
    session: _ComposeSession,
    block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    term: dict[str, Any],
    predicates: tuple[dict[str, Any], ...],
    site: _IndirectCallSite,
    *,
    active: frozenset[int],
    depth: int,
    fallthrough: int,
    callsite: int,
    root_constraints: list[dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """Walk one arm of the selector term and merge its guarded post-state."""
    _check_compose_deadline(session.compose_stats)
    target = _const_term_int(term)
    if target is not None:
        return _compose_indirect_leaf(
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
        )
    args = term.get("args") if isinstance(term, dict) else None
    if (
        not isinstance(term, dict)
        or term.get("op") != "ite"
        or not isinstance(args, list)
        or len(args) != 3
        or not all(isinstance(arg, dict) for arg in args)
    ):
        raise CallCompositionRefusal("call_indirect_target_unconstrained")
    true_post = _compose_indirect_arm(
        session,
        block,
        state,
        args[1],
        (*predicates, _selector_test(args[0], True)),
        site,
        active=active,
        depth=depth,
        fallthrough=fallthrough,
        callsite=callsite,
        root_constraints=root_constraints,
    )
    false_post = _compose_indirect_arm(
        session,
        block,
        state,
        args[2],
        (*predicates, _selector_test(args[0], False)),
        site,
        active=active,
        depth=depth,
        fallthrough=fallthrough,
        callsite=callsite,
        root_constraints=root_constraints,
    )
    merged: dict[str, dict[str, Any]] = S._merge_abi_states(
        args[0], true_post, false_post, compose_stats=session.compose_stats
    )
    if _term_nodes(merged, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    return merged


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
    if depth + 1 > session.limits.max_inline_depth:
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
        )
        callee_return = callee_state.get("eip")
        if not isinstance(callee_return, dict):
            raise CallCompositionRefusal("callee_terminal_missing")
        cached = (
            _apply_callee_state(session, state, callee_state, fallthrough),
            _callee_term(callee_return, state, session),
        )
        site.callees[target] = cached
    post, return_target = cached
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
    if depth + 1 > session.limits.max_inline_depth:
        raise CallCompositionRefusal("tail_inline_depth_limit")
    if session.tail_transfers >= session.limits.max_tail_transfers:
        raise CallCompositionRefusal("tail_transfer_budget")
    # Reserve before descent so nested tail chains cannot overshoot the cap.
    session.tail_transfers += 1
    callee_state = _compose_function(
        session, target, active | {target}, depth + 1,
        incoming=state if session.root_bound_inputs else None,
    )
    callee_return = callee_state.get("eip")
    if not isinstance(callee_return, dict):
        raise CallCompositionRefusal("callee_terminal_missing")
    composed: dict[str, dict[str, Any]] = {}
    for name, term in callee_state.items():
        _check_compose_deadline(session.compose_stats)
        composed[name] = _callee_term(term, state, session)
    if _term_nodes(composed, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    instruction_addresses = block.irsb.instruction_addresses
    session.tail_sites.append(
        {
            "site": hex(instruction_addresses[-1]) if instruction_addresses else hex(block.address),
            "block": hex(block.address),
            "target": hex(target),
            "depth": depth + 1,
            "callee": session.labels.get(target, ""),
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
            return _compose_tail(session, block, state, target, active, depth)
        return _walk(session, blocks, function_entry, target, state, path, active, depth)
    args = ip.get("args")
    if ip.get("op") != "ite" or not isinstance(args, list) or len(args) != 3:
        raise CallCompositionRefusal("indirect_or_unmodeled_branch")
    if not all(isinstance(arg, dict) for arg in args):
        raise CallCompositionRefusal("indirect_or_unmodeled_branch")
    true_state = _compose_ip_targets(session, blocks, function_entry, block, state, args[1], path, active, depth)
    false_state = _compose_ip_targets(session, blocks, function_entry, block, state, args[2], path, active, depth)
    merged: dict[str, dict[str, Any]] = S._merge_abi_states(
        args[0], true_state, false_state, compose_stats=session.compose_stats
    )
    if _term_nodes(merged, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    return merged


def _walk(
    session: _ComposeSession,
    blocks: dict[int, _LiftedBlock],
    function_entry: int,
    address: int,
    incoming: dict[str, dict[str, Any]],
    path: frozenset[int],
    active: frozenset[int],
    depth: int,
) -> dict[str, dict[str, Any]]:
    """Compose one acyclic path to a near return, inlining admitted calls.

    Every block visit re-checks the shared deadline before touching work and
    hands the session ``compose_stats`` to ``S._compose_block_outputs`` so
    that helper's per-output inner loop enforces the same bound.
    """
    _check_compose_deadline(session.compose_stats)
    if address in path:
        raise CallCompositionRefusal("loop_requires_inductive_proof")
    block = blocks.get(address)
    if block is None:
        raise CallCompositionRefusal(f"successor_outside_complete_region:{hex(address)}")
    session.compositions += 1
    if session.compositions > session.limits.max_compositions:
        raise CallCompositionRefusal("region_composition_limit")
    state: dict[str, dict[str, Any]] = S._compose_block_outputs(
        block.part, block.part.get("outputs", {}), incoming, compose_stats=session.compose_stats
    )
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
    next_path = path | {address}
    if block.jumpkind == "Ijk_Call":
        return _compose_call(session, blocks, function_entry, block, state, next_path, active, depth)
    return _compose_ip_targets(session, blocks, function_entry, block, state, ip, next_path, active, depth)


def _compose_function(
    session: _ComposeSession, entry: int, active: frozenset[int], depth: int,
    *, incoming: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Compose one complete acyclic function body into a final-state summary.

    The shared deadline is checked before the summary cache is consulted, so
    even an O(1) cached return cannot publish work after the budget expired.
    """
    _check_compose_deadline(session.compose_stats)
    if incoming is not None and not session.root_bound_inputs:
        raise CallCompositionRefusal("contextual_state_requires_root_binding")
    cached = None if session.root_bound_inputs else session.summaries.get(entry)
    if cached is not None:
        return cached
    try:
        blocks = _lift_function(session, entry)
        final = _walk(
            session,
            blocks,
            entry,
            entry,
            _initial_state(session.reg_widths) if incoming is None else incoming,
            frozenset(),
            active,
            depth,
        )
    except S.LowerFailure as error:
        # Deadline checks inside shared inner loops raise LowerFailure;
        # every refusal leaving composition is the typed contract refusal.
        raise CallCompositionRefusal(error.reason) from error
    if not session.root_bound_inputs:
        session.summaries[entry] = final
    return final


def _compose_root(session: _ComposeSession, entry: int) -> dict[str, dict[str, Any]]:
    """Retry a failed return proof once with exact root-bound callee inputs.

    A context-free callee can overwrite an unconstrained return slot even when
    its actual caller proves disjointness. Retry by composing the same blocks
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
    try:
        return _compose_function(session, entry, frozenset({entry}), 0)
    except CallCompositionRefusal as error:
        if error.evidence is None or error.evidence.call_block in session.blocks.get(entry, {}):
            # Root-call obligations already substitute the actual caller state;
            # replaying them cannot supply any missing outer context.
            raise
    _check_compose_deadline(session.compose_stats)
    session.root_bound_inputs = True
    session.summaries.clear()
    session.compose_stats.pop("eq_cache", None)
    session.compose_stats.pop("eq_keepalive", None)
    session.call_sites.clear()
    session.tail_sites.clear()
    session.return_targets_proved = 0
    return _compose_function(session, entry, frozenset({entry}), 0)
