"""Staged flat32 macro-path term helpers: composition, masking, documents.

Layer: dosunit relational macro-step proof.
Responsibility: compose concatenated frontier paths over flat32 member
blocks through the real ``_compose_block_outputs`` seam, extract join guards
from the composed ``eip`` term, build per-row masked outputs and emit the
production document shape consumed by ``compare_attempt``. Internal
``_Flat32Refusal`` carries typed ``MacroStepReason`` boundaries only.
"""

from __future__ import annotations

import time
from typing import Any

from tools.dosunit import flat32_cfg_regions as F
from tools.dosunit import region_path_terms as T
from tools.dosunit import straightline_ssa as S
from tools.dosunit.macro_step_contracts import (
    MacroCoverageProof,
    MacroEndpointKind,
    MacroStepLimits,
    MacroStepReason,
)
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_call_contracts import prove_terms_equal, term_nodes
from tools.dosunit.ssa_constant_terms import constant_bitvector


class _Flat32Refusal(Exception):
    """Internal typed staging boundary carrying a ``MacroStepReason``."""

    def __init__(self, reason: MacroStepReason, detail: object = "") -> None:
        super().__init__(f"{reason.value}: {detail}")
        self.reason = reason
        self.detail = detail


def remaining_ms32(deadline: float) -> int:
    """Refuse expired work before entering composition or the solver."""
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise _Flat32Refusal(MacroStepReason.MACRO_DEADLINE)
    return remaining


def compose_region32(
    current: dict[str, Any], member_docs: dict[int, dict[str, Any]],
    region: Any, tokens: dict[int, int], adapter: Any, deadline: float,  # noqa: ANN401
) -> dict[str, Any]:
    """Compose one region's member blocks, checking each internal step."""
    for member_index, address in enumerate(region.members):
        remaining_ms32(deadline)
        doc = member_docs[address]
        outputs = doc.get("outputs", {})
        if doc.get("trap_exits") or "io" in outputs:
            raise _Flat32Refusal(
                MacroStepReason.MACRO_UNSUPPORTED_BOUNDARY,
                {"member": address, "outputs": sorted(outputs)},
            )
        current = adapter.S._compose_block_outputs(doc, outputs, current)
        if member_index + 1 < len(region.members):
            internal = constant_bitvector(current["eip"])
            next_member = region.members[member_index + 1]
            if internal != (tokens[next_member], 32):
                raise _Flat32Refusal(
                    MacroStepReason.MACRO_PROGRESS,
                    {"member": address, "next": next_member},
                )
    return current


def compose_concat32(
    member_docs: dict[int, dict[str, Any]], paths: tuple[Any, ...],
    tokens: dict[int, int], adapter: Any, macro_limits: MacroStepLimits,  # noqa: ANN401
    deadline: float,
) -> tuple[dict[str, Any], T.Term]:
    """Compose a concatenated frontier path over flat32 member blocks.

    Mirrors the production superblock check: each region head guard is read
    from the real ``eip`` term, internal members must pin ``eip`` to the
    block token of the next member, and a continuing macro-step arm selects
    the cut-head token at the final exit. Calls, faults and io stay refused.
    """
    current = F._initial_state(adapter)
    guard = T.guard_true()
    for path_index, path in enumerate(paths):
        for region in path.regions:
            if path_index or region is not path.regions[0]:
                join = T.path_guard_term(current["eip"], tokens[region.members[0]])
                if join is None:
                    raise _Flat32Refusal(
                        MacroStepReason.MACRO_GUARD_UNRESOLVED,
                        {"head": region.members[0]},
                    )
                guard = T.guard_and(guard, join)
            current = compose_region32(
                current, member_docs, region, tokens, adapter, deadline,
            )
            if term_nodes(current, macro_limits.max_term_nodes) > macro_limits.max_term_nodes:
                raise _Flat32Refusal(
                    MacroStepReason.MACRO_TERM_LIMIT, {"counter": "term_nodes"},
                )
    last = paths[-1]
    if last.end_kind is MacroEndpointKind.CONTINUING:
        end_guard = T.path_guard_term(current["eip"], tokens[last.end_head])
        if end_guard is None:
            raise _Flat32Refusal(
                MacroStepReason.MACRO_GUARD_UNRESOLVED, {"end": last.end_head},
            )
        guard = T.guard_and(guard, end_guard)
    return current, guard


def masked_state32(
    state: dict[str, Any], guard: T.Term, adapter: Any,  # noqa: ANN401
) -> dict[str, T.Term]:
    """Per-row masked outputs over the complete modeled flat32 state.

    Every row observes every modeled scalar (all ``REG32`` names, including
    ``ecx``, the lazy ``cc_*`` flag state, segments and ``eip``) plus memory.
    No narrower ABI projection is offered: a return row keeps the physical
    end state, and a continuing row keeps the tokenized endpoint under its
    path guard. Missing or malformed observables refuse ``MACRO_ADMISSION``.
    """
    masked = T.masked_state(state, guard)
    if "memory" not in masked:
        raise _Flat32Refusal(MacroStepReason.MACRO_ADMISSION, "missing_state:memory")
    terms = {"memory": masked["memory"]}
    for reg, _width in adapter.REG32.values():
        if reg not in masked:
            raise _Flat32Refusal(MacroStepReason.MACRO_ADMISSION, f"missing_state:{reg}")
        terms[reg] = masked[reg]
    return terms


def macro_doc(
    module: str, name: str, masked: dict[str, T.Term], first_head: int,
    end_kind: MacroEndpointKind, member_count: int,
) -> dict[str, Any]:
    """One masked macro-path function in the production document shape."""
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    term_cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    materialized = {
        name: S._materialize_json_term(
            term, assignments=assignments, memo=memo, term_cache=term_cache,
        )
        for name, term in masked.items()
    }
    return {
        "id": f"{module}:{name}",
        "function": {"id": f"{module}:{name}", "name": name},
        "part": {"kind": "superblock", "index": 0, "entry_delta": "0x0"},
        "entry": {"linear": hex(first_head)},
        "function_entry": {"linear": hex(first_head)},
        "source": {"jumpkind": end_kind.value, "reblocked_members": member_count},
        "inputs": S._term_input_items(materialized.values(), assignments),
        "outputs": materialized,
        "assignments": assignments,
    }


def coverage32(
    side: str, guards: list[T.Term], adapter: Any, deadline: float,  # noqa: ANN401
) -> tuple[MacroCoverageProof, int, int]:
    """Complete disjoint guard coverage over one side's physical cut states."""
    facts = failures = 0
    covered = T.guard_false()
    for guard in guards:
        covered = T.guard_or(covered, guard)
    remaining = remaining_ms32(deadline)
    with adapter.installed():
        completeness = prove_terms_equal(covered, T.guard_true(), remaining)
    facts += 1
    disjoint_pairs = disjoint_failures = 0
    for left_index, left_guard in enumerate(guards):
        for right_guard in guards[left_index + 1:]:
            remaining = remaining_ms32(deadline)
            with adapter.installed():
                status = prove_terms_equal(
                    T.guard_and(left_guard, right_guard), T.guard_false(), remaining,
                )
            disjoint_pairs += 1
            facts += 1
            if status is not ProofStatus.PROVED:
                disjoint_failures += 1
                failures += 1
    if completeness is not ProofStatus.PROVED:
        failures += 1
    proof = MacroCoverageProof(
        side, completeness, disjoint_pairs, disjoint_failures, {"guards": len(guards)},
    )
    return proof, facts, failures


def endpoint_discharge32(
    state: dict[str, Any], end_token: int, guard: T.Term,
    adapter: Any, deadline: float,  # noqa: ANN401
) -> ProofStatus:
    """``guard -> eip == paired cut token`` for one continuing macro-step arm."""
    term = T.endpoint_consistency_term(state["eip"], end_token, guard)
    remaining = remaining_ms32(deadline)
    with adapter.installed():
        return prove_terms_equal(term, T.guard_true(), remaining)
