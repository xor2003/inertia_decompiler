"""Native complete transitions for flat32 loop induction.

Layer: dosunit relational loop proofs.
Responsibility: compose actual root members and complete callees, prove native
return targets, and encode paired cutpoint control without assuming effects.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from functools import partial
from typing import Any

from tools.dosunit.architectures.flat32 import X87_REGISTER_NAMES
from tools.dosunit.architectures.flat32_control_word import bind_x87_obligations
from tools.dosunit.compare.flat32_call_contracts import (
    PRESERVED_OUTPUTS,
    CallCompositionRefusal,
    _check_compose_deadline,
    _ComposeSession,
    _const_term_int,
    _initial_state,
    _LiftedBlock,
    _ret_proof_timeout_ms,
    _term_nodes,
)
from tools.dosunit.compare.flat32_call_execution import (
    _apply_callee_state,
    _callee_term,
    _compose_function,
    _compose_indirect_arm,
    _IndirectCallSite,
    _prove_return_target,
    _transfer_callee_obligations,
)
from tools.dosunit.compare.flat32_native_constants import NativeConstantProof, constant_term
from tools.dosunit.compare.flat32_transition_context import compose_with_transition_context
from tools.dosunit.compare.paired_region_graph import (
    CollapsedRegion,
    RegionExitKind,
)
from tools.dosunit.contracts.register_affine_relations import RegisterRelation
from tools.dosunit.contracts.register_state_relations import IDENTITY_RELATION
from tools.dosunit.ssa.composition import compose_block_outputs
from tools.dosunit.ssa.materialization import input_items, materialize_term
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector

CONTROL_WIDTH: int = 32


class Flat32LoopCallReason(StrEnum):
    """Named verdict/refusal reasons owned by the flat32 call-loop lane."""

    INDUCTION = "call_loop_induction"
    TRANSITIONS_UNPROVED = "call_loop_transitions_unproved"
    CONTROL_LEAF_UNMAPPED = "call_loop_unmapped_successor"
    CONTROL_SHAPE = "call_loop_control_shape_unexpected"
    IP_UNOBSERVED = "call_loop_ip_unobserved"
    NORMALIZATION_TOKEN_OVERLAP = "call_loop_normalization_control_token_overlap"
    NATIVE_CONSTANT_DOMAIN_MISMATCH = "call_loop_native_constant_domain_mismatch"


def _cutpoint_tokens(
    regions: list[CollapsedRegion],
    ordered_indices: list[int],
    blocks: Mapping[int, _LiftedBlock],
    pair_tokens: list[int] | None = None,
) -> dict[int, int]:
    """Assign transition tokens: pair position for region heads, extra ids for interiors."""
    labels = list(range(len(ordered_indices))) if pair_tokens is None else pair_tokens
    pair_index = dict(zip(ordered_indices, labels, strict=True))
    tokens = {
        regions[region_index].members[0]: pair_index[region_index]
        for region_index in ordered_indices
    }
    for address in sorted(set(blocks) - set(tokens)):
        tokens[address] = max(tokens.values(), default=-1) + 1
    return tokens


def _map_exit_tokens(term: dict[str, Any], tokens: Mapping[int, int]) -> dict[str, Any]:
    """Lower a transition's exit ``ip`` term from binary addresses to cutpoint tokens."""
    const = constant_bitvector(term)
    if const is not None:
        value, width = const
        if width != CONTROL_WIDTH or value not in tokens:
            raise CallCompositionRefusal(Flat32LoopCallReason.CONTROL_LEAF_UNMAPPED.value)
        return {"op": "const", "value": hex(tokens[value]), "width": CONTROL_WIDTH}
    if term.get("op") == "ite":
        args = term.get("args")
        if (
            isinstance(args, list)
            and len(args) == 3
            and all(isinstance(arg, dict) for arg in args)
        ):
            return {
                "op": "ite",
                "width": term.get("width", CONTROL_WIDTH),
                "args": [
                    args[0],
                    _map_exit_tokens(args[1], tokens),
                    _map_exit_tokens(args[2], tokens),
                ],
            }
    raise CallCompositionRefusal(Flat32LoopCallReason.CONTROL_SHAPE.value)


def _compose_indirect_transition(
    session: _ComposeSession,
    call_block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    active: frozenset[int],
    fallthrough: int,
    *, function_entry: int,
) -> dict[str, dict[str, Any]]:
    """Prove finite indirect targets without assuming root-entry constraints."""
    ip = state.get("ip")
    if not isinstance(ip, dict):
        raise CallCompositionRefusal("call_indirect_target_unconstrained")
    addresses = call_block.irsb.instruction_addresses
    if not addresses:
        raise CallCompositionRefusal("call_instruction_address_missing")
    # A transition starts at an arbitrary cutpoint, not the root entry.
    post: dict[str, dict[str, Any]] = _compose_indirect_arm(
        session, call_block, state, ip, (), _IndirectCallSite(),
        function_entry=function_entry,
        active=active, depth=0, fallthrough=fallthrough,
        callsite=addresses[-1], root_constraints=None, guard=None,
    )
    return post


def _compose_call_transition(
    session: _ComposeSession,
    call_block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    active: frozenset[int],
    *, function_entry: int,
) -> dict[str, dict[str, Any]]:
    """Inline one proved callee and continue at the recorded fallthrough.

    Reuses the M2 machinery verbatim: the callee body is composed by
    ``_compose_function`` (which itself refuses recursion, cycles, unmapped or
    unsupported transfers) and its symbolic return target is proved to equal
    the recorded fallthrough by ``_prove_return_target`` under the shared
    deadline.  The post-state carries the proved concrete fallthrough so the
    continuation is an ordinary member/cutpoint edge, never an assumption.
    """
    target = call_block.call_target
    fallthrough = call_block.fallthrough
    if fallthrough is None:
        raise CallCompositionRefusal("call_target_unmapped")
    if target is None:
        return _compose_indirect_transition(
            session, call_block, state, active, fallthrough, function_entry=function_entry,
        )
    if _const_term_int(state.get("ip")) != target:
        raise CallCompositionRefusal("call_target_mismatch")
    if target in active:
        raise CallCompositionRefusal(f"recursive_call:{hex(target)}")
    if session.limits.max_inline_depth < 1:
        raise CallCompositionRefusal("call_inline_depth_limit")
    if session.inlined_calls >= session.limits.max_inlined_calls:
        raise CallCompositionRefusal("call_inline_budget")
    session.inlined_calls += 1
    callee_state = _compose_function(
        session, target, active | {target}, 1,
        incoming=state if session.root_bound_inputs else None,
    )
    callee_return = callee_state.get("eip")
    if not isinstance(callee_return, dict):
        raise CallCompositionRefusal("callee_terminal_missing")
    instruction_addresses = call_block.irsb.instruction_addresses
    if not instruction_addresses:
        raise CallCompositionRefusal("call_instruction_address_missing")
    _transfer_callee_obligations(
        session, target, state, None, callsite=instruction_addresses[-1],
        obligations=session.last_obligation_frame if session.root_bound_inputs else None,
    )
    _prove_return_target(
        _callee_term(callee_return, state, session),
        fallthrough,
        timeout_ms=_ret_proof_timeout_ms(session),
        callsite=instruction_addresses[-1],
        call_block=call_block.address,
        target=target,
        callee=session.labels.get(target, ""),
    )
    post: dict[str, dict[str, Any]] = _apply_callee_state(session, state, callee_state, fallthrough)
    session.return_targets_proved += 1
    session.call_sites.append(
        {
            "callsite": hex(instruction_addresses[-1]),
            "call_block": hex(call_block.address),
            "target": hex(target),
            "fallthrough": hex(fallthrough),
            "depth": 1,
            "callee": session.labels.get(target, ""),
            "proved_under_entry_domain": False,
        }
    )
    return post


def _bind_member_obligations(
    block: _LiftedBlock,
    incoming: dict[str, dict[str, Any]],
    address: int,
    obligations: list[dict[str, Any]] | None,
) -> None:
    """Bind one member's checking-instruction obligations at its own entry."""
    if obligations is not None and block.part.get("obligations"):
        obligations.extend(bind_x87_obligations(
            block.part, incoming, site={"address": address}))


def _compose_call_member(
    session: _ComposeSession,
    block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    function_entry: int,
    obligations: list[dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """Compose one call member and drain its callee obligations per transition.

    Callee sites bind to this cutpoint's actual state via
    ``_transfer_callee_obligations``; the appended delta is routed into this
    transition's own obligation list rather than the session sink.
    """
    start = len(session.x87_obligations)
    state = compose_with_transition_context(
        session, partial(
            _compose_call_transition,
            session, block, state, frozenset({function_entry}), function_entry=function_entry,
        ),
    )
    if obligations is not None:
        obligations.extend(session.x87_obligations[start:])
    del session.x87_obligations[start:]
    return state


def _compose_region_state(
    region: CollapsedRegion,
    lifted: Mapping[int, _LiftedBlock],
    session: _ComposeSession,
    *,
    function_entry: int,
    is_entry: bool,
    relation: RegisterRelation = IDENTITY_RELATION,
    native_constants: NativeConstantProof | None = None,
    obligations: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Compose one region's members into the post-state before exit mapping.

    Members compose sequentially with a const-progress check so an
    unconditional chain can never silently drop a member; an ``Ijk_Call``
    member additionally composes the proved callee and leaves ``ip`` at the
    recorded fallthrough, so the residual boundary is only the region kind.
    Related coordinates apply only to interior inputs. Entry inputs remain
    identical; the transition owner separately handles continuing outputs.
    """
    state: dict[str, dict[str, Any]] = _initial_state(session.reg_widths)
    if not is_entry:
        state = relation.candidate_inputs(state)
    members = region.members
    if native_constants is not None and not is_entry:
        state.update({key: constant_term(value) for key, value
                      in native_constants.constants.get(members[0], {}).items()})
    for index, address in enumerate(members):
        _check_compose_deadline(session.compose_stats)
        block = lifted[address]
        member_outputs = block.part.get("outputs", {})
        if block.part.get("trap_exits") or "io" in member_outputs:
            raise CallCompositionRefusal("unsupported_effect_in_superblock")
        session.compositions += 1
        if session.compositions > session.limits.max_compositions:
            raise CallCompositionRefusal("region_composition_limit")
        incoming = state
        state = compose_block_outputs(
            block.part,
            member_outputs,
            state,
            compose_stats=session.compose_stats,
        )
        _bind_member_obligations(block, incoming, address, obligations)
        if block.jumpkind == "Ijk_Call":
            state = _compose_call_member(
                session, block, state, function_entry, obligations)
        if (
            _term_nodes(state, session.limits.max_term_nodes)
            > session.limits.max_term_nodes
        ):
            raise CallCompositionRefusal("region_expression_limit")
        if index < len(members) - 1:
            control = constant_bitvector(state.get("ip", {}))
            if control != (members[index + 1], CONTROL_WIDTH):
                raise CallCompositionRefusal(
                    Flat32LoopCallReason.CONTROL_SHAPE.value
                )
    return state


def _compose_transition(
    region: CollapsedRegion,
    lifted: Mapping[int, _LiftedBlock],
    session: _ComposeSession,
    tokens: Mapping[int, int],
    *,
    function_entry: int,
    is_entry: bool,
    module: str,
    name: str,
    outputs: tuple[str, ...],
    full_state: tuple[str, ...],
    relation: RegisterRelation = IDENTITY_RELATION,
    native_constants: NativeConstantProof | None = None,
) -> dict[str, Any]:
    """Compose one paired region's members into a full-state transition document.

    ``Ijk_Ret`` exposes the return value; every other tail maps branch leaves
    onto cutpoint tokens, mirroring
    ``flat32_cfg_regions._compose_superblock``.
    Continuing outputs invert the proposed register relation. Returns and
    transitions back to the function entry must restore identity instead.
    """
    bound_obligations: list[dict[str, Any]] = []
    state = _compose_region_state(
        region, lifted, session, function_entry=function_entry, is_entry=is_entry, relation=relation,
        native_constants=native_constants, obligations=bound_obligations,
    )
    ip_term = state.get("ip")
    if not isinstance(ip_term, dict):
        raise CallCompositionRefusal(Flat32LoopCallReason.IP_UNOBSERVED.value)
    reenters_entry = any(tokens[target] == 0 for target in region.exits)
    if region.kind is RegionExitKind.RETURN:
        state["eip"] = ip_term
    else:
        state["eip"] = _map_exit_tokens(ip_term, tokens)
    if region.kind is not RegionExitKind.RETURN:
        state = relation.continuing_outputs(
            state, control_field="eip", reenters_entry=reenters_entry
        )
    observed = tuple(dict.fromkeys(
        (*outputs, *PRESERVED_OUTPUTS, "eip", "memory", "io", *X87_REGISTER_NAMES)
        if region.kind is RegionExitKind.RETURN
        else (*full_state, "memory")
    ))
    terms: dict[str, Any] = {}
    for reg in observed:
        if reg not in state:
            raise CallCompositionRefusal(f"missing_state:{reg}")
        terms[reg] = state[reg]
    if _term_nodes(terms, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    term_cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    materialized = {
        reg: materialize_term(
            term, assignments=assignments, memo=memo, term_cache=term_cache
        )
        for reg, term in terms.items()
    }
    entry = {"linear": hex(region.members[0])}
    # A CALL tail is already composed into the transition terms and discharged
    # by ``_prove_return_target``; the document's residual boundary is a
    # resolved cutpoint edge, not an unresolved call.  Emitting the machine
    # ``Ijk_Call`` would ask the document comparator to re-resolve a callee
    # that legitimately has no standalone doc entry, so the composed marker
    # carries the truth and the machine jumpkind stays as inert provenance.
    source: dict[str, Any] = {
        "cutpoint_token": tokens[region.members[0]],
        "jumpkind": (
            "call_composed" if region.kind is RegionExitKind.CALL else region.kind.value
        ),
        "reblocked_members": len(region.members),
    }
    if native_constants is not None:
        source["proved_native_entry_constants"] = native_constants.constants.get(region.members[0], {})
    if region.kind is RegionExitKind.CALL:
        source["machine_jumpkind"] = region.kind.value
    return {
        "id": f"{module}:{name}",
        "function": {"id": f"{module}:{name}", "name": name},
        "part": {"kind": "superblock", "index": 0, "entry_delta": "0x0"},
        "entry": entry,
        "function_entry": entry,
        "source": source,
        "inputs": input_items(
            list(materialized.values()) + [o.get("predicate") for o in bound_obligations],
            assignments,
        ),
        "outputs": materialized,
        "assignments": assignments,
        "obligations": bound_obligations,
    }


def _lower_transitions(
    regions: list[CollapsedRegion],
    pairs: list[tuple[int, int]],
    lifted: Mapping[int, _LiftedBlock],
    session: _ComposeSession,
    tokens: Mapping[int, int],
    *,
    function_entry: int,
    module: str,
    outputs: tuple[str, ...],
    full_state: tuple[str, ...],
    left: bool,
    relation: RegisterRelation = IDENTITY_RELATION,
    native_constants: NativeConstantProof | None = None,
) -> dict[str, Any]:
    """Compose every paired region for one side into transition documents."""
    functions = []
    for index, (oracle_region, candidate_region) in enumerate(pairs):
        region = regions[oracle_region if left else candidate_region]
        functions.append(
            _compose_transition(
                region,
                lifted,
                session,
                tokens,
                function_entry=function_entry,
                is_entry=index == 0,
                module=module,
                name=f"sb_{index}",
                outputs=outputs,
                full_state=full_state,
                relation=relation,
                native_constants=native_constants,
            )
        )
    return {"functions": functions}
