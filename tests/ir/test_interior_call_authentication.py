"""Interior calls authenticate separately before manifest, before and after simulation."""

import sys
import time
from collections import Counter
from dataclasses import replace

import pytest

from inertia.ir import entry_domain_call_preservation as intake
from inertia.ir import real16_invocation_domain as domain
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from tests.ir.test_declared_function_entry_domain import _recompute
from tests.ir.test_raw_callee_scoped_call_chain import _collect
from tests.ir.test_raw_callee_scoped_call_chain import calls_with_pending_helper as calls_with_pending_helper

pytestmark = pytest.mark.decompiler


def test_one_authentication_per_immediate_call_consumption(
    calls_with_pending_helper: tuple[object, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Manifest and pre/post simulation each require one current authentication."""
    counts = Counter()
    original = intake.EntryDomainCallPreservation8616.complete_for
    census = domain._census_callee_bytes_8616
    feasibility = domain._feasibility_call_scratch_8616
    speculative_depth = 0

    def tracked_feasibility(*args: object, **kwargs: object) -> bool:
        """Keep speculative authentication and manifest counts separate."""
        nonlocal speculative_depth
        speculative_depth += 1
        try:
            return feasibility(*args, **kwargs)
        finally:
            speculative_depth -= 1

    def tracked(
        proof: intake.EntryDomainCallPreservation8616,
        scope: domain.Real16InvocationDomain8616 | None,
    ) -> bool:
        caller = sys._getframe(1).f_code.co_name
        direct = caller in {
            "_call_boundary_proof_8616",
            "_consume_call_boundary_8616",
            "_consume_entry_call_record_8616",
            "_census_path_callees_8616",
        }
        projected = caller == "preserved_registers_for" and sys._getframe(2).f_code.co_name in {
            "_cross_call_8616",
            "_consume_call_boundary_8616",
            "_consume_entry_call_record_8616",
            "_reconcile_call_exit_8616",
            "_consume_cross_call_boundary_8616",
        }
        if direct or projected:
            key = "authentication_speculative" if speculative_depth else "authentication"
            counts[key] += 1
        return original(proof, scope)

    def tracked_census(*args: object, **kwargs: object) -> domain.Real16InvocationFailure8616 | None:
        key = "manifest_speculative" if speculative_depth else "manifest"
        counts[key] += 1
        return census(*args, **kwargs)

    monkeypatch.setattr(intake.EntryDomainCallPreservation8616, "complete_for", tracked)
    monkeypatch.setattr(domain, "_census_callee_bytes_8616", tracked_census)
    monkeypatch.setattr(domain, "_feasibility_call_scratch_8616", tracked_feasibility)
    records = _collect(calls_with_pending_helper)
    assert len(records) == 2 and all(record.failure is None for record in records)
    assert counts["manifest"] > 0
    assert counts["authentication"] == 3 * counts["manifest"], counts
    # This native caller has no conditional branches to consume refinement.
    assert counts["manifest_speculative"] == 0
    assert counts["authentication_speculative"] == 0


def test_changed_owned_scope_after_projection_refuses(
    calls_with_pending_helper: tuple[object, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A projection cannot transport a callback-replaced entry authority."""
    from dataclasses import replace

    original = intake.EntryDomainCallPreservation8616.preserved_registers_for
    crossing = domain._cross_call_8616
    observed = []
    changed = []

    def revoke(
        proof: intake.EntryDomainCallPreservation8616,
        scope: domain.Real16InvocationDomain8616 | None,
    ) -> tuple[str, ...]:
        names = original(proof, scope)
        caller = sys._getframe(1).f_code.co_name
        if (
            names
            and scope is not None
            and not changed
            and caller
            in {
                "_cross_call_8616",
                "_consume_entry_call_record_8616",
            }
        ):
            object.__setattr__(proof, "invocation_scope", replace(scope, source_sha256="0" * 64))
            changed.append(True)
        return names

    def tracked_cross(*args: object, **kwargs: object) -> domain.Real16InvocationFailure8616 | None:
        result = crossing(*args, **kwargs)
        if changed:
            observed.append(result)
        return result

    monkeypatch.setattr(intake.EntryDomainCallPreservation8616, "preserved_registers_for", revoke)
    monkeypatch.setattr(domain, "_cross_call_8616", tracked_cross)
    _collect(calls_with_pending_helper)
    assert changed
    assert observed[0] is domain.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def test_replaying_scope_reauthenticates_after_scope_callback(
    calls_with_pending_helper: tuple[object, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Callback-capable scope matching keeps its old projection replay ordering."""
    from dataclasses import replace

    current_scope = domain._ctx_consuming_scope_8616
    crossing = domain._cross_call_8616
    observed = []
    changed = []

    def revoke_after_scope(
        ctx: domain._PathCensusContext8616,
        artifact: object,
        proof: domain._BoundaryProof8616,
    ) -> object:
        scope = current_scope(ctx, artifact, proof)
        if (
            isinstance(scope, domain.Real16InvocationDomain8616)
            and not changed
            and sys._getframe(1).f_code.co_name == "_consume_cross_call_boundary_8616"
        ):
            object.__setattr__(proof, "invocation_scope", replace(scope, source_sha256="0" * 64))
            changed.append(True)
        return scope

    def tracked_cross(*args: object, **kwargs: object) -> domain.Real16InvocationFailure8616 | None:
        result = crossing(*args, **kwargs)
        if changed:
            observed.append(result)
        return result

    monkeypatch.setattr(domain, "_call_scope_uses_owned_identity_8616", lambda _ctx: False)
    monkeypatch.setattr(domain, "_ctx_consuming_scope_8616", revoke_after_scope)
    monkeypatch.setattr(domain, "_cross_call_8616", tracked_cross)
    _collect(calls_with_pending_helper)
    assert changed
    assert observed[0] is domain.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def test_revoked_proof_after_real_simulation_refuses_original_cross_call(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revoke a real preservation only after its authentic callee simulation."""
    project, boot, artifact, boundary, _resolver, admission = calls_with_pending_helper
    records = _collect(calls_with_pending_helper)
    assert len(records) == 2 and all(record.failure is None for record in records)
    original_simulate = domain._simulate_callee_8616
    original_cross = domain._cross_call_8616
    simulations = []
    crosses = []

    def simulate_then_revoke(
        ctx: domain._PathCensusContext8616, proof: domain._BoundaryProof8616, seed: domain._PathState8616
    ) -> dict[int, domain._PathState8616] | domain.Real16InvocationFailure8616:
        exits = original_simulate(ctx, proof, seed)
        assert not isinstance(exits, domain.Real16InvocationFailure8616)
        assert isinstance(proof, intake.EntryDomainCallPreservation8616)
        assert proof.failure is None
        object.__setattr__(proof, "failure", intake.EntryDomainCallPreservationFailure8616.CALLEE_UNRESOLVED)
        assert proof.preserved_registers_for(proof.required_scope) == ()
        simulations.append(proof)
        return exits

    def observed_cross(
        ctx: domain._PathCensusContext8616,
        current: IRFunctionArtifact,
        block: IRBlock,
        instruction: IRInstr,
        registers: dict[str, int],
        memory: domain.PathMemory8616,
    ) -> domain.Real16InvocationFailure8616 | None:
        result = original_cross(ctx, current, block, instruction, registers, memory)
        if simulations and instruction.addr == 0x1043:
            crosses.append(result)
        return result

    monkeypatch.setattr(domain, "_simulate_callee_8616", simulate_then_revoke)
    monkeypatch.setattr(domain, "_cross_call_8616", observed_cross)
    with direct_evidence_deadline_scope_8616(project, time.monotonic() + 20), native_import_request_8616():
        domain.prove_real16_declared_function_entry_domain_8616(
            project,
            domain.DeclaredFunctionEntryLink8616(admission, artifact, boundary),
            0x1046,
            boot=boot,
            boot_recompute=_recompute,
            entry_call_preservations=records,
        )
    assert simulations
    assert crosses[0] is domain.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def test_invalid_entry_projection_keeps_service_fallback(
    calls_with_pending_helper: tuple[object, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A revoked authentic record falls through instead of masking declared effects."""
    captured = []
    crossing = domain._cross_call_8616

    def capture(*args: object, **kwargs: object) -> domain.Real16InvocationFailure8616 | None:
        ctx, artifact, _block, instruction, _registers, _memory = args
        if ctx.callsite_addr == 0x1046 and artifact.function_addr == 0x1040 and instruction.addr == 0x1043:
            captured.append(args)
        return crossing(*args, **kwargs)

    monkeypatch.setattr(domain, "_cross_call_8616", capture)
    records = _collect(calls_with_pending_helper)
    assert len(records) == 2 and all(record.failure is None for record in records)
    assert captured
    ctx, artifact, block, instruction, registers, memory = captured[0]
    assert ctx.entry_call_preservations
    revoked = replace(records[0], failure=intake.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE)
    ctx.entry_call_preservations = (revoked,)
    ctx.call_preservations = ()
    fallback = []

    def service(*args: object, **kwargs: object) -> domain.Real16InvocationFailure8616:
        fallback.append(True)
        return domain.Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN

    def no_simulation(*args: object, **kwargs: object) -> object:
        pytest.fail("revoked entry proof reached callee simulation")

    monkeypatch.setattr(domain, "_declared_service_crossing_8616", service)
    monkeypatch.setattr(domain, "_simulate_callee_8616", no_simulation)
    assert (
        crossing(ctx, artifact, block, instruction, registers, memory)
        is domain.Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    )
    assert fallback == [True]
