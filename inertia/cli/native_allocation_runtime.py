"""Native-hook orchestration for restartable variable allocation.

Layer: CLI/runtime.
Responsibility: drive the real angr Clinic ``_stage_recover_variables`` boundary
through the Lowering-owned convergence session using the Frontend adapter's
native snapshot/reset/restore operations. Recovery always executes on first
entry; revised allocator inputs restart the stage transactionally; unchanged
inputs reuse the validated accepted publication; cycle/exhaustion keep the
prior publication and record a typed refusal for downstream gating. Unexpected
native errors propagate with original cause after full checkpoint restore.
"""

from __future__ import annotations

import dataclasses
import typing
from collections.abc import Callable

import inertia.frontend.x86_16.variable_allocation_convergence as alloc_native
from inertia.lowering.allocation_convergence import (
    AllocationConvergenceRefusal,
    AllocationConvergenceSession,
    AllocationDecisionKind,
    AllocationDiagnostics,
    AllocationFingerprintRefusal,
    AllocationInputFingerprint,
    AllocationRestartResult,
    AllocationRestartVerdict,
)

if typing.TYPE_CHECKING:
    from angr.analyses.decompiler.clinic import Clinic
    from angr.project import Project

    from inertia.frontend.x86_16.variable_allocation_convergence import NativeAllocationCheckpoint

_SESSIONS_ATTR = "_inertia_allocation_convergence_sessions_8616"
_DEFAULT_MAX_ROUNDS = 4


def _session_for(
    project: Project, func_addr: int, max_rounds: int = _DEFAULT_MAX_ROUNDS
) -> AllocationConvergenceSession:
    """Return the per-function convergence session stored on the project."""
    # dynamic third-party boundary: sessions live on the angr project object
    sessions = getattr(project, _SESSIONS_ATTR, None)
    if not isinstance(sessions, dict):
        sessions = {}
        # dynamic third-party boundary: session store on the angr project
        setattr(project, _SESSIONS_ATTR, sessions)
    session = sessions.get(func_addr)
    if session is None:
        session = AllocationConvergenceSession(max_rounds=max_rounds)
        sessions[func_addr] = session
    return session


def session_for(
    project: Project, func_addr: int, max_rounds: int = _DEFAULT_MAX_ROUNDS
) -> AllocationConvergenceSession:
    """Public accessor for the per-function session (diagnostics/tests)."""
    return _session_for(project, func_addr, max_rounds)


def _converged_invoke_8616(
    project: Project,
    clinic: Clinic,
    invoke: Callable[[], object],
    session: AllocationConvergenceSession,
    entry_fp: AllocationInputFingerprint,
    checkpoint: NativeAllocationCheckpoint,
    raw_graph: object,
) -> tuple[object, AllocationInputFingerprint, int]:
    """Run the stage, iterating while input evidence is revised mid-run.

    Returns ``(invoke_result, final_evidence_fingerprint, preserved_types)``.
    Any post-invoke failure (including typed fingerprint refusal and the
    publication checks) restores the full checkpoint before propagating;
    cycle/exhaustion restore and raise a typed refusal.
    """
    func_addr = clinic.function.addr
    evidence = entry_fp.evidence_only()
    preserved = 0
    result: object = None
    while True:
        try:
            alloc_native.install_input_graph(clinic, raw_graph)
            preserved = alloc_native.reset_function_variables(project, func_addr)
            result = invoke()
            post_evidence = alloc_native.fingerprint_allocation_inputs(
                clinic, include_graph=False
            ).evidence_only()
        except AllocationFingerprintRefusal as exc:
            alloc_native.restore_native_checkpoint(project, clinic, checkpoint)
            session.record_refusal(
                AllocationRestartVerdict.REFUSED, f"post-run fingerprint: {exc}"
            )
            raise AllocationConvergenceRefusal(
                AllocationRestartVerdict.REFUSED, func_addr, f"post-run fingerprint: {exc}"
            ) from exc
        except BaseException:
            alloc_native.restore_native_checkpoint(project, clinic, checkpoint)
            session.record_failure(entry_fp)
            raise
        if post_evidence == evidence:
            return result, post_evidence, preserved  # converged: inputs stable
        step = session.record_revision_round(post_evidence)
        if step.kind is not AllocationDecisionKind.RUN:
            verdict = (
                AllocationRestartVerdict.EXHAUSTED
                if step.kind is AllocationDecisionKind.EXHAUSTED
                else AllocationRestartVerdict.CYCLE
            )
            alloc_native.restore_native_checkpoint(project, clinic, checkpoint)
            session.record_refusal(verdict, step.detail)
            raise AllocationConvergenceRefusal(verdict, func_addr, step.detail)
        evidence = post_evidence


def run_recovery_stage_8616(
    project: Project,
    clinic: Clinic,
    invoke: Callable[[], object],
) -> object:
    """Run the native recover-variables stage under convergence control.

    ``invoke`` is the original native stage callable. The transaction retains
    the raw entry AIL graph (the stage rewrites it into output) and iterates
    only while authoritative non-graph input evidence (types, argument maps,
    hints, prototype, calling convention) is revised during the run. Reuse is
    allowed solely when the accepted publication's manager/link-map/graph
    objects are still this clinic's live surfaces. Fingerprint refusal,
    cycle and exhaustion raise :class:`AllocationConvergenceRefusal` so no
    stale or unverified state can reach downstream consumers.
    """
    func_addr = clinic.function.addr
    session = _session_for(project, func_addr)
    try:
        entry_fp = alloc_native.fingerprint_allocation_inputs(clinic)
    except AllocationFingerprintRefusal as exc:
        session.record_refusal(AllocationRestartVerdict.REFUSED, f"fingerprint: {exc}")
        raise AllocationConvergenceRefusal(
            AllocationRestartVerdict.REFUSED, func_addr, f"fingerprint: {exc}"
        ) from exc

    try:
        bound = alloc_native.accepted_publication_bound(
            project, func_addr, clinic, session.accepted_handle,
        )
    except AllocationFingerprintRefusal as exc:
        session.record_refusal(AllocationRestartVerdict.REFUSED, str(exc))
        raise AllocationConvergenceRefusal(
            AllocationRestartVerdict.REFUSED, func_addr, str(exc),
        ) from exc
    if (
        not bound
        and entry_fp == session.accepted_output_fingerprint
        and alloc_native.publication_generation_current_8616(
            project, func_addr, clinic, session.accepted_handle,
        )
    ):
        detail = "accepted native publication contents changed without an input revision"
        session.record_refusal(AllocationRestartVerdict.REFUSED, detail)
        raise AllocationConvergenceRefusal(AllocationRestartVerdict.REFUSED, func_addr, detail)
    decision = session.decide(entry_fp, bound)
    if decision.kind is AllocationDecisionKind.SKIP:
        session.record_skip()
        session.last_result = AllocationRestartResult(
            verdict=AllocationRestartVerdict.UNCHANGED,
            function_addr=func_addr,
            fingerprint=entry_fp,
            census=session.census(),
            diagnostics=AllocationDiagnostics(),
            detail=decision.detail,
        )
        return None

    pre_vars, pre_links = alloc_native.output_surface_counts(project, func_addr, clinic)
    checkpoint = alloc_native.capture_native_checkpoint(project, clinic)
    raw_graph = alloc_native.copy_input_graph(
        clinic, handle=session.accepted_handle, entry=entry_fp,
        accepted_output=session.accepted_output_fingerprint,
    )
    session.begin_transaction(entry_fp)
    result, evidence, preserved = _converged_invoke_8616(
        project, clinic, invoke, session, entry_fp, checkpoint, raw_graph
    )

    try:
        out_vars, out_links = alloc_native.output_surface_counts(project, func_addr, clinic)
        dropped = alloc_native.prune_unpublished_links(clinic)
        handle = alloc_native.published_handle(
            project, func_addr, clinic, input_graph=raw_graph,
        )
        output_fp = alloc_native.fingerprint_allocation_inputs(clinic)
        input_nodes, input_edges = alloc_native.fingerprint_allocation_graph_8616(raw_graph)
        final_input_fp = dataclasses.replace(
            evidence, graph_nodes=input_nodes, graph_edges=input_edges,
        )
    except AllocationFingerprintRefusal as exc:
        alloc_native.restore_native_checkpoint(project, clinic, checkpoint)
        session.record_refusal(
            AllocationRestartVerdict.REFUSED, f"publication fingerprint: {exc}"
        )
        raise AllocationConvergenceRefusal(
            AllocationRestartVerdict.REFUSED, func_addr, f"publication fingerprint: {exc}"
        ) from exc
    except BaseException:
        alloc_native.restore_native_checkpoint(project, clinic, checkpoint)
        session.record_failure(entry_fp)
        raise

    # the accepted input is the retained raw graph plus the FINAL converged
    # evidence - not the initial entry evidence a revision loop moved past
    session.record_published(final_input_fp, output_fp, handle)
    session.last_result = AllocationRestartResult(
        verdict=AllocationRestartVerdict.RESTARTED,
        function_addr=func_addr,
        fingerprint=final_input_fp,
        census=session.census(),
        diagnostics=AllocationDiagnostics(
            input_variables=pre_vars,
            output_variables=out_vars,
            input_links=pre_links,
            output_links=out_links,
            preserved_manual_types=preserved,
            dropped_stale_facts=dropped,
        ),
        detail=decision.detail,
    )
    return result
