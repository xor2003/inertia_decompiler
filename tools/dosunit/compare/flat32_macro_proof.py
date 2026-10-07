"""Flat32 bounded macro-step proof over exact real-byte eip32 state.

Layer: dosunit relational macro-step proof.
Responsibility: reuse the production flat32 seam modules (adapter/cfg/catalog/
verdict), real VEX block lowering and ``compare_attempt`` solver path, and
discharge unequal-step pairings proposed at the paired entry macro-cut.
Concatenated frontier paths compose through ``adapter.S._compose_block_outputs``
per member block, with each join guard read from the real ``eip`` term.
Register, flag, memory and eip observables keep the exact production masking
contract: every row observes the complete modeled state — all ``REG32``
scalars (including ``ecx`` and the lazy ``cc_*`` flag state), segments, ``eip``
and memory — masked under the row's exact path guard.
"""

from __future__ import annotations

from dataclasses import asdict
from functools import partial
from typing import Any

from tools.comparator.services import proof_owners
from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.architectures.flat32_control import finish_flat32_control
from tools.dosunit.compare import flat32_macro_terms as ft
from tools.dosunit.compare import macro_step_pairing as pairing
from tools.dosunit.compare.flat32_environment_coverage import environment_parts
from tools.dosunit.compare.flat32_macro_terms import _Flat32Refusal
from tools.dosunit.compare.flat32_region_attempts import compare_attempt, comparison_deadline
from tools.dosunit.compare.macro_step_contracts import (
    MacroCoverageProof,
    MacroDirection,
    MacroEndpointKind,
    MacroObligation,
    MacroStepAttempt,
    MacroStepLimits,
    MacroStepReason,
    MacroStepRefusal,
    MacroTransitionProof,
)
from tools.dosunit.compare.paired_region_graph import (
    RegionExitKind,
    RegionGraphRefusal,
    RegionNode,
)
from tools.dosunit.compare.real16_call_contracts import prove_terms_equal
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus, proof_status_from_legacy
from tools.dosunit.contracts.proof_scope import ProofScope, admit_scope_status
from tools.dosunit.ssa import region_path_terms as T


def _block_tokens(blocks: dict[int, Any], entry: int) -> dict[int, int]:
    """Stable token map: the physical entry block is always token zero."""
    tokens = {entry: 0}
    for address in sorted(set(blocks) - {entry}):
        tokens[address] = len(tokens)
    return tokens


def _lower_members(
    blocks: dict[int, Any], adapter: Any, tokens: dict[int, int],  # noqa: ANN401
    refusal: Any, deadline: float,  # noqa: ANN401
) -> dict[int, dict[str, Any]]:
    """Lower every discovered CFG block under the adapter token map."""
    docs: dict[int, dict[str, Any]] = {}
    full_state = tuple(name for name, _width in adapter.REG32.values())
    for address, block in sorted(blocks.items()):
        ft.remaining_ms32(deadline)
        body = adapter.S._lower_irsb(
            block.irsb, output_regs=full_state, max_assignments_per_function=4096,
            architecture=flat32_register_architecture(),
            block_finisher=partial(finish_flat32_control, control_targets=tokens),
        )
        if isinstance(body, adapter.S.LowerFailure):
            raise refusal(f"{body.reason}: {body.message}")
        docs[address] = body
    return docs


def _resolve_pairs(
    proposal: Any, oracle_docs: dict[int, dict[str, Any]],  # noqa: ANN401
    candidate_docs: dict[int, dict[str, Any]],
    oracle_tokens: dict[int, int], candidate_tokens: dict[int, int],
    adapter: Any, deadline: float, macro_limits: MacroStepLimits,  # noqa: ANN401
) -> tuple[list[tuple[Any, Any, dict[str, Any], T.Term, dict[str, Any], T.Term]], int, int]:
    """Compose the fast side and find its guard-equal slow concat per path."""
    oracle_is_fast = proposal.direction is MacroDirection.CANDIDATE_SLOWER
    fast_docs = oracle_docs if oracle_is_fast else candidate_docs
    slow_docs = candidate_docs if oracle_is_fast else oracle_docs
    fast_tokens = oracle_tokens if oracle_is_fast else candidate_tokens
    slow_tokens = candidate_tokens if oracle_is_fast else oracle_tokens
    facts = failures = 0
    resolved: list[tuple[Any, Any, dict[str, Any], T.Term, dict[str, Any], T.Term]] = []
    for path_index, pairing_candidate in enumerate(proposal.pairings):
        fast_state, fast_guard = ft.compose_concat32(
            fast_docs, (pairing_candidate.fast_path,), fast_tokens, adapter,
            macro_limits, deadline,
        )
        paired = False
        for slow_concat in pairing_candidate.slow_concats:
            slow_state, slow_guard = ft.compose_concat32(
                slow_docs, slow_concat, slow_tokens, adapter, macro_limits, deadline,
            )
            remaining = ft.remaining_ms32(deadline)
            equal = prove_terms_equal(fast_guard, slow_guard, remaining)
            facts += 1
            if equal is not ProofStatus.PROVED:
                continue
            if oracle_is_fast:
                resolved.append((pairing_candidate.fast_path, slow_concat,
                                 fast_state, fast_guard, slow_state, slow_guard))
            else:
                resolved.append((pairing_candidate.fast_path, slow_concat,
                                 slow_state, slow_guard, fast_state, fast_guard))
            paired = True
            break
        if paired:
            continue
        remaining = ft.remaining_ms32(deadline)
        infeasible = prove_terms_equal(fast_guard, T.guard_false(), remaining)
        facts += 1
        if infeasible is ProofStatus.PROVED:
            continue  # Provably infeasible frontier path: recorded, never paired.
        failures += 1
        raise _Flat32Refusal(
            MacroStepReason.MACRO_PATH_UNPAIRED if infeasible is not ProofStatus.UNKNOWN
            else MacroStepReason.MACRO_GUARD_UNRESOLVED,
            {"path": path_index},
        )
    return resolved, facts, failures


def _member_count(paths: tuple[Any, ...]) -> int:
    """Total binary member blocks consumed by a concatenated path."""
    return sum(len(region.members) for path in paths for region in path.regions)


def _attempt_flat32(
    proposal: Any, oracle_docs: dict[int, dict[str, Any]],  # noqa: ANN401
    candidate_docs: dict[int, dict[str, Any]],
    oracle_tokens: dict[int, int], candidate_tokens: dict[int, int],
    adapter: Any, catalog: Any, verdict: Any,  # noqa: ANN401
    deadline: float, macro_limits: MacroStepLimits,
) -> tuple[MacroStepAttempt, list[dict[str, Any]], dict[str, Any]]:
    """Discharge one directional proposal through the real compare path."""
    oracle_is_fast = proposal.direction is MacroDirection.CANDIDATE_SLOWER
    facts = failures = 0
    rows: list[MacroTransitionProof] = []
    coverage: list[MacroCoverageProof] = []
    compared: dict[str, Any] = {}
    verdicts: list[dict[str, Any]] = []
    try:
        resolved, pair_facts, pair_failures = _resolve_pairs(
            proposal, oracle_docs, candidate_docs, oracle_tokens, candidate_tokens,
            adapter, deadline, macro_limits,
        )
        facts += pair_facts
        failures += pair_failures
        ossa = {"name": "oracle", "functions": []}
        cssa = {"name": "candidate", "functions": []}
        for index, (fast_path, slow_concat, o_state, o_guard, c_state, c_guard) in enumerate(resolved):
            oracle_paths = (fast_path,) if oracle_is_fast else slow_concat
            candidate_paths = slow_concat if oracle_is_fast else (fast_path,)
            end_kind = oracle_paths[-1].end_kind
            o_masked = ft.masked_state32(o_state, o_guard, adapter)
            c_masked = ft.masked_state32(c_state, c_guard, adapter)
            ossa["functions"].append(ft.macro_doc(
                "oracle", f"sb_{index}", o_masked,
                oracle_paths[0].regions[0].members[0], end_kind, _member_count(oracle_paths),
            ))
            cssa["functions"].append(ft.macro_doc(
                "candidate", f"sb_{index}", c_masked,
                candidate_paths[0].regions[0].members[0], end_kind, _member_count(candidate_paths),
            ))
        _status, compared, verdicts = compare_attempt(
            ossa, cssa, deadline, adapter, catalog, verdict,
        )
        by_name = {
            row.get("function", {}).get("name"): row for row in verdicts
            if isinstance(row.get("function"), dict)
        }
        for index, (fast_path, slow_concat, o_state, o_guard, c_state, c_guard) in enumerate(resolved):
            oracle_paths = (fast_path,) if oracle_is_fast else slow_concat
            candidate_paths = slow_concat if oracle_is_fast else (fast_path,)
            end_kind = oracle_paths[-1].end_kind
            row_verdict = by_name.get(f"sb_{index}", {})
            row_status = proof_status_from_legacy(row_verdict.get("status")) or ProofStatus.UNKNOWN
            row_status = admit_scope_status(row_status, ProofScope.CUTPOINT_SIMULATION)
            if row_status is not ProofStatus.PROVED:
                row_status = ProofStatus.UNKNOWN
            facts += 1
            if row_status is not ProofStatus.PROVED:
                failures += 1
            obligations = [
                MacroObligation.PATH_GUARD_EQUALITY,
                MacroObligation.MASKED_STATE_EQUALITY,
                MacroObligation.POSITIVE_PROGRESS,
            ]
            if end_kind is MacroEndpointKind.CONTINUING:
                for _side, state, paths, guard, tokens in (
                    ("oracle", o_state, oracle_paths, o_guard, oracle_tokens),
                    ("candidate", c_state, candidate_paths, c_guard, candidate_tokens),
                ):
                    endpoint = ft.endpoint_discharge32(
                        state, tokens[paths[-1].end_head], guard, adapter, deadline,
                    )
                    facts += 1
                    if endpoint is not ProofStatus.PROVED:
                        failures += 1
                        row_status = ProofStatus.UNKNOWN
                obligations.append(MacroObligation.ENDPOINT_CONSISTENCY)
            rows.append(MacroTransitionProof(
                index,
                tuple(m for p in oracle_paths for r in p.regions for m in r.members),
                tuple(m for p in candidate_paths for r in p.regions for m in r.members),
                len(oracle_paths), len(candidate_paths), end_kind, 0, row_status,
                ProofStatus.PROVED, tuple(obligations), {"verdict": row_verdict},
            ))
        oracle_guards = [g for _p, _c, _s, g, _cs, _cg in resolved] if oracle_is_fast else [
            g for _p, _c, _s, _g, _cs, g in resolved
        ]
        candidate_guards = [g for _p, _c, _s, _g, _cs, g in resolved] if oracle_is_fast else [
            g for _p, _c, _s, g, _cs, _cg in resolved
        ]
        for side, guards in (("oracle", oracle_guards), ("candidate", candidate_guards)):
            proof, cover_facts, cover_failures = ft.coverage32(
                side, guards, adapter, deadline,
            )
            coverage.append(proof)
            facts += cover_facts
            failures += cover_failures
    except _Flat32Refusal as error:
        counters = FactCounters(facts, facts, facts, facts, failures + 1)
        attempt = MacroStepAttempt(
            proposal.direction, ProofStatus.UNKNOWN, tuple(rows), tuple(coverage),
            counters, error.reason, str(error.detail),
        )
        return attempt, verdicts, compared
    result_status = ProofStatus.PROVED if rows and not failures else ProofStatus.UNKNOWN
    counters = FactCounters(facts, facts, facts, facts, failures)
    attempt = MacroStepAttempt(
        proposal.direction, result_status, tuple(rows), tuple(coverage), counters,
        None if result_status is ProofStatus.PROVED else MacroStepReason.MACRO_PATH_UNPAIRED,
        "",
    )
    return attempt, verdicts, compared


def compare_macro_cfg(
    projects: tuple[Any, Any], oracle_range: tuple[int, int],
    candidate_range: tuple[int, int], outputs: tuple[str, ...],
    timeout_ms: int, max_blocks: int = 128, *, name: str = "macro_step",
    macro_limits: MacroStepLimits | None = None, total_deadline: float | None = None,
) -> dict[str, Any]:
    """Bounded unequal-step flat32 proof over real discovered CFG blocks.

    The result keeps the production ``compare_reblocked_cfg`` surface shape
    (status, verdicts, counters) plus a typed ``macro`` payload carrying the
    proposals, discharged transitions, coverage and attempts. ``outputs`` is
    retained for the production call shape only: every row always observes
    the complete modeled state, and no narrower ABI projection is offered.
    The scope stays CUTPOINT_SIMULATION: no whole-program or
    initialized-image claim is made.
    """
    macro_bound = macro_limits or MacroStepLimits()
    deadline = comparison_deadline(timeout_ms, total_deadline)
    owners = proof_owners()
    adapter, cfg, catalog, verdict = owners.model, owners.cfg, owners.catalog, owners.verdict
    oracle, candidate = projects
    base = {"function": {"name": name}, "reason": "macro_step_cfg_induction",
            "proof_scope": ProofScope.CUTPOINT_SIMULATION}
    try:
        ft.remaining_ms32(deadline)
        oblocks = cfg.discover(oracle, *oracle_range, max_blocks)
        ft.remaining_ms32(deadline)
        cblocks = cfg.discover(candidate, *candidate_range, max_blocks)
        ft.remaining_ms32(deadline)
        o_nodes = {
            address: RegionNode(
                address, tuple(block.successors), RegionExitKind(block.irsb.jumpkind),
            )
            for address, block in oblocks.items()
        }
        c_nodes = {
            address: RegionNode(
                address, tuple(block.successors), RegionExitKind(block.irsb.jumpkind),
            )
            for address, block in cblocks.items()
        }
        o_tokens = _block_tokens(oblocks, oracle_range[0])
        c_tokens = _block_tokens(cblocks, candidate_range[0])
        search = pairing.propose_macro_steps(
            o_nodes, c_nodes, oracle_range[0], candidate_range[0],
            limits=macro_bound,
            deadline_seconds=ft.remaining_ms32(deadline) / 1000.0,
        )
        o_docs = _lower_members(oblocks, adapter, o_tokens, cfg.CfgRefusal, deadline)
        c_docs = _lower_members(cblocks, adapter, c_tokens, cfg.CfgRefusal, deadline)
        attempts: list[MacroStepAttempt] = []
        verdicts: list[dict[str, Any]] = []
        compared: dict[str, Any] = {}
        for proposal in search.proposals:
            attempt, attempt_verdicts, attempt_compared = _attempt_flat32(
                proposal, o_docs, c_docs, o_tokens, c_tokens,
                adapter, catalog, verdict, deadline, macro_bound,
            )
            if attempt_verdicts or attempt_compared:
                verdicts, compared = attempt_verdicts, attempt_compared
            attempts.append(attempt)
            if attempt.status is ProofStatus.PROVED:
                break
    except cfg.CfgRefusal as error:
        return {**base, "status": verdict.Status.REFUSED, "reason": str(error)}
    except RegionGraphRefusal as error:
        return {**base, "status": verdict.Status.REFUSED, "reason": error.reason.value}
    except MacroStepRefusal as error:
        return {**base, "status": verdict.Status.REFUSED, "reason": error.reason.value,
                "macro_detail": str(error.detail)}
    except _Flat32Refusal as error:
        return {**base, "status": verdict.Status.REFUSED, "reason": error.reason.value,
                "macro_detail": str(error.detail)}
    proved = next((a for a in attempts if a.status is ProofStatus.PROVED), None)
    counters = proved.counters if proved else (attempts[-1].counters if attempts
                                              else FactCounters(0, 0, 0, 0, 0))
    return {
        **base,
        "status": verdict.Status.PASSED if proved else verdict.Status.REFUSED,
        "reason": "macro_step_cfg_induction" if proved else "macro_step_unproved",
        "macro": {
            "search": {"status": search.status.value,
                       "counters": asdict(search.counters)},
            "attempts": [asdict(a) for a in attempts],
        },
        "counters": asdict(counters),
        "block_compare": compared,
        "block_verdicts": verdicts,
        "environment_coverage": {"oracle": environment_parts(oblocks),
                                 "candidate": environment_parts(cblocks)},
    }
