"""Shared binary-derived retries for staged flat32 comparators.

Layer: dosunit validation orchestration.
Responsibility: replace incomplete region evidence only with a complete checked
call-or-tail composition or closed reblocked CFG proof, preserving refusals.
"""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.contracts.proof_contracts import Architecture, ProofStatus, proof_status_from_legacy

if TYPE_CHECKING:
    import angr

    from tools.dosunit.contracts.ordered_io_environment import OrderedIoContract

type ProofContext = tuple['angr.Project', 'angr.Project', dict[str, tuple[int, int]], dict[str, tuple[int, int]]]


def call_block_retry_cap(args: argparse.Namespace) -> int | None:
    """Read and validate the opt-in cap at the public argparse boundary."""
    # Dynamic third-party argparse boundary: older adapter namespaces omit this option.
    cap = getattr(args, 'retry_block_limit', None)
    if cap is None:
        return None
    from tools.dosunit.compare.flat32_call_contracts import CallCompositionLimits

    if args.mode not in {'region', 'auto', 'matched-cfg'}:
        raise ValueError('block-limit continuation requires a whole-region proof mode')
    return CallCompositionLimits(retry_max_blocks_per_function=cap).retry_max_blocks_per_function


def build_proof_context(
    mode: str, oracle: angr.Project, candidate: angr.Project,
    select: Callable[[], tuple[dict[str, tuple[int, int]], dict[str, tuple[int, int]], list[dict[str, Any]]]],
) -> ProofContext | None:
    """Collect declared dependency ranges only for whole-region proof modes."""
    if mode not in {'region', 'auto', 'matched-cfg'}:
        return None
    oracle_ranges, candidate_ranges, _ = select()
    return oracle, candidate, oracle_ranges, candidate_ranges


def _composition_dependencies(document: dict[str, Any]) -> bool:
    """Return True when a verdict consumed proved call or tail member dependencies.

    Inlined direct calls and admitted tail transfers are the same class of
    evidence: either means the verdict was built from separately declared
    member ranges, so it must pass the environment gate before publication.
    The ``tail_sites``/``call_sites`` records are metadata for these counters,
    not independent evidence.
    """
    counters = (
        "oracle_inlined_calls", "candidate_inlined_calls",
        "oracle_tail_transfers", "candidate_tail_transfers",
    )
    for name in counters:
        value = document.get(name)
        # JSON evidence counts are exact nonnegative integers, never truthy
        # strings, booleans, floats or negative sentinels.
        if type(value) is int and value > 0:
            return True
    return False


def _conditional_io_verdict(verdict: dict[str, Any], io_model: OrderedIoContract) -> dict[str, Any]:
    """Rebind a discharged verdict as conditional on the I/O premise.

    The ordered event relation is a declared caller premise — identical
    environment responses for an identical ordered event history — never a
    proved property of the real device.  A verdict that consumed covered
    port events therefore cannot remain PASSED; it is republished
    ``conditional`` with the premise payload and relation identity recorded.
    """
    from tools.dosunit.contracts.ordered_io_environment import ORDERED_IO_PREMISE_NAME

    assumptions = dict(verdict.get("assumptions") or {})
    assumptions[ORDERED_IO_PREMISE_NAME] = io_model.premise_document()
    bound: dict[str, Any] = {
        **verdict,
        "status": "conditional",
        "assumptions": assumptions,
        "environment_premise": {
            "premise": io_model.premise_document(),
            "relation_identity": io_model.identity_digest(),
        },
    }
    if proof_status_from_legacy(verdict.get("status")) is ProofStatus.PROVED:
        bound["backend_status"] = verdict.get("status")
        bound["reason"] = "ordered_io_environment_premise"
    return bound


def checked_environment_verdict(
    verdict: dict[str, Any], context: ProofContext | None,
    oracle_parts: list[dict[str, Any]], candidate_parts: list[dict[str, Any]],
    *,
    io_model: OrderedIoContract | None = None,
) -> dict[str, Any]:
    """Require binary environment coverage before publishing a region proof.

    The gate covers PROVED verdicts and composed dependency-dependent
    CONDITIONAL verdicts alike: a premise-dependent composition is still
    published proof evidence, so the member ranges it was built from must
    validate before publication. A conditional verdict without composed call
    or tail evidence keeps its previous behavior unchanged.

    ``io_model`` binds the declared ordered-I/O environment contract — or
    inherits the ambient caller-installed binding when omitted.  Under a
    binding the scan checks the decoded event stream against the declared
    coverage: uncovered events, malformed lifted sequences and machine-state
    instructions still refuse, and a discharged verdict whose parts carried
    covered events is republished CONDITIONAL with the premise retained.
    """
    from tools.dosunit.contracts.binary_environment import active_ordered_io

    io_model = io_model if io_model is not None else active_ordered_io()
    if io_model is not None:
        io_model.validate_for(Architecture.FLAT32)
    status = proof_status_from_legacy(verdict.get('status'))
    dependent_conditional = status is ProofStatus.CONDITIONAL and _composition_dependencies(verdict)
    gated = (
        status is ProofStatus.PROVED
        or dependent_conditional
        or (io_model is not None and status is ProofStatus.CONDITIONAL)
    )
    if context is None or not gated:
        return verdict
    from tools.dosunit.contracts.binary_environment import scan_lowered_parts

    coverage = verdict.get("environment_coverage")
    if isinstance(coverage, dict):
        original_parts, rebuilt_parts = coverage.get("oracle"), coverage.get("candidate")
        oracle_parts = original_parts if isinstance(original_parts, list) else []
        candidate_parts = rebuilt_parts if isinstance(rebuilt_parts, list) else []
    checks = (
        scan_lowered_parts(context[0], oracle_parts, io_model=io_model),
        scan_lowered_parts(context[1], candidate_parts, io_model=io_model),
    )
    if any(check.requires_contract for check in checks):
        return {'status': 'refused', 'reason': 'external_environment_contract_required'}
    if not all(check.complete for check in checks):
        return {'status': 'refused', 'reason': 'environment_effect_coverage_incomplete'}
    if io_model is not None and any(check.events for check in checks):
        return _conditional_io_verdict(verdict, io_model)
    return verdict



def checked_cfg_environment_verdict(
    verdict: dict[str, Any], original: dict[str, Any], context: ProofContext | None,
    *,
    io_model: OrderedIoContract | None = None,
) -> dict[str, Any]:
    """Admit a CFG result only with retained binary block environment coverage.

    Retry success cannot stand in for source-byte evidence. Prefer retained
    retry member ranges; otherwise use original lowering coverage. Missing
    coverage remains a refusal. ``io_model`` binds the declared ordered-I/O
    environment contract through to the shared gate.
    """
    parts: list[list[dict[str, Any]]] = []
    for side in ("oracle_ssa", "candidate_ssa"):
        document = original.get(side)
        functions = document.get("functions") if isinstance(document, dict) else None
        parts.append(functions if isinstance(functions, list) else [])
    return checked_environment_verdict(verdict, context, parts[0], parts[1], io_model=io_model)


def _retry_call_loop(
    name: str, oracle: angr.Project, candidate: angr.Project,
    oracle_ranges: dict[str, tuple[int, int]], candidate_ranges: dict[str, tuple[int, int]],
    outputs: tuple[str, ...], deadline: float,
) -> dict[str, Any]:
    """Run the shared closed call-loop induction under the same deadline.

    A loop containing an admitted direct call is refused by both earlier
    lanes; this lane composes each proved callee into its paired transition
    and keeps the same typed refusals.
    """
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    if remaining_ms <= 0:
        return {'status': 'refused', 'reason': 'compose_deadline_exceeded'}
    from tools.dosunit.compare.flat32_loop_calls import compare_flat32_loop_calls
    return compare_flat32_loop_calls(
        (oracle, candidate), oracle_ranges[name], candidate_ranges[name],
        outputs, remaining_ms, name=name,
        oracle_functions=dict(oracle_ranges.values()),
        candidate_functions=dict(candidate_ranges.values()),
        oracle_labels={rng[0]: label for label, rng in oracle_ranges.items()},
        candidate_labels={rng[0]: label for label, rng in candidate_ranges.items()},
        total_deadline=deadline,
    )


def _retry_after_reblocked(
    name: str, oracle: angr.Project, candidate: angr.Project,
    oracle_ranges: dict[str, tuple[int, int]], candidate_ranges: dict[str, tuple[int, int]],
    outputs: tuple[str, ...], deadline: float,
    calls: dict[str, Any], cfg: dict[str, Any], attempts: dict[str, Any],
) -> dict[str, Any] | None:
    """Run the call-loop and macro induction lanes after a refused CFG proof.

    The call-loop lane runs only when both earlier lanes report their named
    refusals: a cyclic caller for composition and a call/exception boundary
    for the call-free CFG lane, which is exactly a loop containing a call.
    Macro-step induction keeps the previous order.
    """
    if (calls.get('reason') == 'loop_requires_inductive_proof'
            and cfg.get('reason') == 'call_or_exception_boundary'):
        loop_calls = _retry_call_loop(
            name, oracle, candidate, oracle_ranges, candidate_ranges, outputs, deadline,
        )
        attempts['call_loop'] = loop_calls
        if proof_status_from_legacy(loop_calls.get('status')) is ProofStatus.PROVED:
            return {key: value for key, value in {**loop_calls, 'proof_method': 'closed_call_loop_induction',
                                                'additional_proof_attempts': attempts}.items()
                    if key not in {'function', 'oracle_ssa', 'candidate_ssa', 'block_compare'}}
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    if remaining_ms > 0:
        from tools.dosunit.compare.flat32_macro_proof import compare_macro_cfg
        macro = compare_macro_cfg((oracle, candidate), oracle_ranges[name], candidate_ranges[name],
                                  outputs, remaining_ms, name=name, total_deadline=deadline)
        attempts['macro_step'] = macro
        if proof_status_from_legacy(macro.get('status')) is ProofStatus.PROVED:
            return {key: value for key, value in {**macro, 'proof_method': 'closed_macro_step_induction',
                                                'additional_proof_attempts': attempts}.items()
                    if key not in {'function', 'oracle_ssa', 'candidate_ssa', 'block_compare'}}
    return None


def retry_function_proof(
    name: str, original: dict[str, Any], context: ProofContext | None,
    outputs: tuple[str, ...], timeout_ms: int,
    *, entry_domain: Flat32ProofDomain | None = None,
    io_model: OrderedIoContract | None = None,
    call_block_retry_cap: int | None = None,
) -> dict[str, Any]:
    """Retry unproved evidence using independently checked complete binary models.

    Constant relocation is deliberately absent: these retries compare strict
    memory effects. Existing assumptions disappear only after a strict proof.
    A modeled counterexample from an existing method is retained.

    ``entry_domain`` is an optional caller-declared premise bounding the
    top-level entry ``esp`` input, forwarded to the checked direct-call
    composition. A composed verdict that needed the premise is accepted only
    as CONDITIONAL with actual inlined calls or admitted tail transfers and
    its serialized assumptions retained; it is never promoted to PROVED, and
    a conditional verdict without retained assumptions is not admitted.
    Independent unconditional methods (reblocked CFG and macro-step
    induction) still run without the premise and keep their own verdicts.

    ``io_model`` binds the declared ordered-I/O environment contract to every
    retry lane, including unowned composition internals, through a scoped
    ambient install — or inherits the caller's ambient binding when omitted.
    Publication marking lives in ``checked_environment_verdict``.

    ``call_block_retry_cap`` enables bounded continuation only when call
    lifting actually reaches its original block cap. Both attempts and all
    following proof lanes retain the same absolute deadline; other limits
    remain unchanged. Omission preserves the original 64-block call cap.
    """
    from tools.dosunit.contracts.binary_environment import active_ordered_io, scoped_ordered_io

    io_model = io_model if io_model is not None else active_ordered_io()
    if io_model is not None:
        io_model.validate_for(Architecture.FLAT32)
    status = proof_status_from_legacy(original.get('status'))
    if context is None or status not in {ProofStatus.UNKNOWN, ProofStatus.CONDITIONAL}:
        return original
    oracle, candidate, oracle_ranges, candidate_ranges = context
    if name not in oracle_ranges or name not in candidate_ranges:
        return original
    deadline = time.monotonic() + max(timeout_ms, 0) / 1000.0
    if timeout_ms <= 0:
        return original
    from tools.dosunit.compare.flat32_call_composition import CallCompositionLimits, compare_functions_with_calls
    from tools.dosunit.compare.flat32_cfg_regions import compare_reblocked_cfg

    # Explicit native architecture flows through every retry lane. The
    # scoped ordered-I/O context covers every retry lane — direct-call
    # composition, reblocked CFG, call-loop and macro induction — so unowned
    # lowering gates observe the identical declared model.
    with scoped_ordered_io(io_model):
        calls = compare_functions_with_calls(
            oracle, candidate, oracle_entry=oracle_ranges[name][0], candidate_entry=candidate_ranges[name][0],
            oracle_functions=dict(oracle_ranges.values()),
            candidate_functions=dict(candidate_ranges.values()),
            oracle_labels={value[0]: label for label, value in oracle_ranges.items()},
            candidate_labels={value[0]: label for label, value in candidate_ranges.items()},
            outputs=outputs, timeout_ms=timeout_ms, entry_domain=entry_domain,
            total_deadline=deadline,
            limits=CallCompositionLimits(retry_max_blocks_per_function=call_block_retry_cap),
        )
        call_status = proof_status_from_legacy(calls.get('status'))
        dependent = _composition_dependencies(calls)
        conditional = call_status is ProofStatus.CONDITIONAL and bool(calls.get('assumptions'))
        if dependent and (call_status in {ProofStatus.PROVED, ProofStatus.COUNTEREXAMPLE} or conditional):
            return {**calls, 'proof_method': 'checked_direct_call_composition'}
        attempts = {'calls': calls}
        remaining_ms = int((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            return {**original, 'additional_proof_attempts': attempts}
        cfg = compare_reblocked_cfg((oracle, candidate), oracle_ranges[name], candidate_ranges[name],
                                   outputs, remaining_ms, name=name, total_deadline=deadline)
        cfg_status = proof_status_from_legacy(cfg.get('status'))
        if cfg_status in {ProofStatus.PROVED, ProofStatus.COUNTEREXAMPLE}:
            return {key: value for key, value in {**cfg, 'proof_method': 'closed_reblocked_cfg_induction'}.items()
                    if key not in {'function', 'oracle_ssa', 'candidate_ssa', 'block_compare'}}
        attempts['reblocked_cfg'] = cfg
        retried = _retry_after_reblocked(
            name, oracle, candidate, oracle_ranges, candidate_ranges, outputs, deadline,
            calls, cfg, attempts,
        )
        if retried is not None:
            return retried
        return {**original, 'additional_proof_attempts': attempts}
