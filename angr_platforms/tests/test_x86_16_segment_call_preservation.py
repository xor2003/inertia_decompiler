"""Consume exact leaf evidence without retaining GP proxies or guessing effects."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from angr_platforms.X86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from angr_platforms.X86_16.ir import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
    build_x86_16_segment_state_artifact,
)
from angr_platforms.X86_16.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from angr_platforms.X86_16.ir.segment_call_preservation import prove_segment_call_preservation_8616
from angr_platforms.X86_16.ir.segment_effect_closure import prove_segment_effect_closure_8616


def test_callee_resolution_keeps_registry_conflicts_loudly_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Conflicting retained IR is not permission to rebuild another projection."""
    from angr_platforms.X86_16 import segment_call_preservation_stage as stage

    project = SimpleNamespace(_inertia_function_ir_artifacts_8616={
        0x2000: IRFunctionArtifact(0x3000, ()),
    })

    def unexpected_resolution(*_):
        pytest.fail("SSA rebuild requested despite retained raw-IR conflict")

    monkeypatch.setattr(stage, "function_ssa_artifact_at_address_8616", unexpected_resolution)
    assert stage.resolve_callee_segment_contract_8616(project, 0x2000) is None


def test_summary_refreshes_call_preservation_before_join(monkeypatch: pytest.MonkeyPatch) -> None:
    """The production summary stage must consume preservation before publishing."""
    from angr_platforms.X86_16 import segment_call_preservation_stage as stage
    from angr_platforms.X86_16 import segment_function_summary as summary
    from angr_platforms.X86_16.ir.segment_contract import SegmentFunctionContract

    local = SegmentFunctionContract(function_addr=0x1000)
    refreshed = replace(local)
    project = SimpleNamespace()
    codegen = SimpleNamespace(_inertia_segment_function_contract=local)
    monkeypatch.setattr(summary, "_function_for_contract", lambda *_: object())
    monkeypatch.setattr(summary, "build_x86_16_segment_control_transfers", lambda *_: ())
    observed = []

    def refresh(project_arg, codegen_arg, caller, contracts, requests):
        assert project_arg is project and codegen_arg is codegen
        assert caller is local and contracts[0x1000] is local and requests == ()
        observed.append(True)
        return refreshed

    monkeypatch.setattr(stage, "refresh_segment_call_preservation_state_8616", refresh)
    summary.apply_x86_16_segment_function_summary(project, codegen)
    assert observed == [True]
    assert project._inertia_segment_local_contracts_8616[0x1000] is refreshed


@pytest.mark.parametrize("helper_code,accepted,ds_source,ss_source", (
    ("c3", 2, "ss", "ss"),
    ("b8 00 00 8e d8 c3", 2, None, "ss"),
    ("e8 01 00 c3 c3", 0, None, None),
    ("eb fe", 0, None, None),
))
def test_catalog_free_repeated_callee_collection_retains_contextual_equality(
    helper_code: str, accepted: int, ds_source: str | None, ss_source: str | None,
) -> None:
    """Real repeated calls share one callee IR without optional function catalogs."""
    from angr_platforms.X86_16.ir.segment_contract import build_x86_16_segment_function_contract
    from angr_platforms.X86_16.segment_call_preservation_stage import (
        SegmentCallPreservationRequest8616,
        refresh_segment_call_preservation_state_8616,
    )
    from test_x86_16_direct_call_segment_context import _context

    # startup calls main; main calls the same leaf twice, then returns.
    context = _context("e8 04 00 e8 01 00 c3 " + helper_code)
    assert context.complete
    project = context.callee.boundary.project
    artifact = context.callee.artifact
    ordinary = build_x86_16_segment_state_artifact(artifact)
    caller = build_x86_16_segment_function_contract(artifact, ordinary, coverage=context.callee)
    codegen = SimpleNamespace(
        _inertia_vex_ir_artifact=artifact,
        _inertia_segment_state_artifact=ordinary,
        _inertia_segment_function_contract=caller,
    )
    requests = (SegmentCallPreservationRequest8616(0x1007, 0x100e),
                SegmentCallPreservationRequest8616(0x100a, 0x100e))
    refreshed = refresh_segment_call_preservation_state_8616(project, codegen, caller, {}, requests)
    collection = codegen._inertia_segment_call_preservation_collection_8616
    assert collection.complete
    assert collection.materialized_count == accepted and collection.failure_count == 2 - accepted
    assert len(collection.proofs) == accepted
    source = registered_function_ir_artifact_8616(project, 0x100e).artifact
    assert source is not None
    assert all(proof.callee.coverage.artifact is source for proof in collection.proofs)
    contextual = build_x86_16_segment_state_artifact(
        artifact, entry_context=context, call_preservations=collection.proofs,
    )
    assert contextual.state_after_instruction(0x100a, "ds").source == ds_source
    assert contextual.state_after_instruction(0x100a, "ss").source == ss_source
    refresh_segment_call_preservation_state_8616(project, codegen, refreshed, {}, requests)
    repeated = codegen._inertia_segment_call_preservation_collection_8616
    assert repeated.complete and repeated.materialized_count == accepted
    assert all(proof.callee.coverage.artifact is source for proof in repeated.proofs)
    assert collection.complete  # A later request must not invalidate earlier evidence.


@pytest.mark.parametrize("mode", ("valid", "absent", "duplicate", "foreign", "stale", "far", "invalidate_after"))
def test_closed_leaf_call_preserves_ds_but_drops_gp_proxy(mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A proven callee preserves DS while its ES write and unknown AX remain explicit."""
    project = SimpleNamespace()
    caller = IRFunctionArtifact(0x1000, (IRBlock(0x1000, instrs=(
        IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2),
                (IRValue(MemSpace.REG, name="ds", size=2),), addr=0x1000),
        IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1002),
        IRInstr("MOV", IRValue(MemSpace.REG, name="es", size=2),
                (IRValue(MemSpace.REG, name="ax", size=2),), addr=0x1005),
        IRInstr("RET", None, (), addr=0x1007),
    )),))
    callee = IRFunctionArtifact(0x2000, (IRBlock(0x2000, instrs=(
        IRInstr("MOV", IRValue(MemSpace.REG, name="es", size=2),
                (IRValue(MemSpace.CONST, const=0xB800, size=2),), addr=0x2000),
        IRInstr("RET", None, (), addr=0x2003),
    )),))
    publish_function_ir_artifact_8616(project, caller)
    publish_function_ir_artifact_8616(project, callee)
    caller_boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 8, frozenset({0x1000}), frozenset({0x1000, 0x1002, 0x1005, 0x1007}), (),
    )
    callee_boundary = ExactFunctionRangeBoundary8616(
        project, 0x2000, 4, frozenset({0x2000}), frozenset({0x2000, 0x2003}), (),
    )
    caller_coverage = prove_ir_boundary_coverage_8616(project, caller_boundary, caller)
    callee_coverage = prove_ir_boundary_coverage_8616(project, callee_boundary, callee)
    closure = prove_segment_effect_closure_8616(callee_coverage, build_x86_16_segment_state_artifact(callee))
    entry = DecodedDirectCallsite8616(0x1000, (SimpleNamespace(address=0x1002),), 0, 0x1002, 0x2000)
    index = DecodedDirectCallsiteIndex8616({0x2000: (entry,)}, DecodedDirectCallsiteIndexStats8616(1, 1, 1, 1, 0))
    proof = prove_segment_call_preservation_8616(caller_coverage, closure, index, 0x1002)
    assert proof.complete
    assert "ds" in proof.preserved_registers
    assert "es" not in proof.preserved_registers
    if mode == "valid":
        from angr_platforms.X86_16.frontend_caller_return_use_program import (
            CallerReturnUseProgramEvidence8616,
            CallerReturnUseProgramStats8616,
            CallerReturnUseProgramStatus8616,
        )
        from angr_platforms.X86_16.ir.segment_contract import build_x86_16_segment_function_contract
        from angr_platforms.X86_16.segment_call_preservation_stage import (
            SegmentCallPreservationRequest8616,
            collect_segment_call_preservations_8616,
        )

        caller_contract = build_x86_16_segment_function_contract(
            caller, build_x86_16_segment_state_artifact(caller), coverage=caller_coverage,
        )
        callee_contract = build_x86_16_segment_function_contract(
            callee, build_x86_16_segment_state_artifact(callee), coverage=callee_coverage,
        )
        program = CallerReturnUseProgramEvidence8616(
            project, ((0x1000, 0x1008),), index, CallerReturnUseProgramStatus8616.READY,
            CallerReturnUseProgramStats8616(1, 1, 1, 1, 0),
        )
        request = SegmentCallPreservationRequest8616(0x1002, 0x2000)
        import capstone
        from angr_platforms.X86_16.callsite_summary import caller_return_use_program_scope_8616
        from angr_platforms.X86_16.frontend_caller_return_use_program import (
            current_caller_return_use_program_evidence_8616,
        )

        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        decoder.detail = True
        machine_bytes = bytes.fromhex("8cd8e8fb0f8ec0c3")
        project.arch = SimpleNamespace(capstone=decoder)
        project.loader = SimpleNamespace(memory=SimpleNamespace(
            load=lambda address, size: machine_bytes[address - 0x1000:address - 0x1000 + size],
        ))
        with caller_return_use_program_scope_8616(project, ((0x1000, 0x1008),)):
            decoded_program = current_caller_return_use_program_evidence_8616(project, ((0x1000, 0x1008),))
            decoded_collection = collect_segment_call_preservations_8616(
                project, caller_contract, {0x2000: callee_contract}, (request,), decoded_program,
            )
        assert decoded_collection.complete and decoded_collection.materialized_count == 1
        from angr_platforms.X86_16.ir import segment_contract as contract_owner
        from angr_platforms.X86_16.segment_call_preservation_stage import refresh_segment_call_preservation_state_8616

        monkeypatch.setattr(contract_owner, "function_boundary_at_address_8616",
                            lambda _project, address: caller_boundary if address == 0x1000 else callee_boundary)
        codegen = SimpleNamespace(
            _inertia_vex_ir_artifact=caller,
            _inertia_segment_state_artifact=build_x86_16_segment_state_artifact(caller),
            _inertia_segment_function_contract=caller_contract,
        )
        refreshed = refresh_segment_call_preservation_state_8616(
            project, codegen, caller_contract, {0x2000: callee_contract}, (request,),
        )
        assert refreshed.effects_complete
        assert codegen._inertia_segment_state_artifact.exit_states[0x1000]["ds"].origin is SegmentOrigin.PROVEN
        derived = refresh_segment_call_preservation_state_8616(project, codegen, refreshed, {}, (request,))
        assert derived.effects_complete
        assert codegen._inertia_segment_call_preservation_collection_8616.materialized_count == 1
        from angr_platforms.X86_16 import segment_call_preservation_stage as stage_owner
        from angr_platforms.X86_16.ir.function_ssa_registry import (
            FunctionSSAArtifactResolution8616,
            FunctionSSAArtifactStage8616,
            FunctionSSAArtifactVerdict8616,
        )
        from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa

        requested = []

        def resolve_callee(project_arg, address):
            assert project_arg is project and address == 0x2000
            requested.append(address)
            publish_function_ir_artifact_8616(project, callee)
            return FunctionSSAArtifactResolution8616(
                address, FunctionSSAArtifactVerdict8616.PROVEN,
                build_x86_16_function_ssa(callee), None, FunctionSSAArtifactStage8616.IR,
            )

        monkeypatch.setattr(stage_owner, "function_ssa_artifact_at_address_8616", resolve_callee, raising=False)
        project._inertia_function_ir_artifacts_8616.pop(0x2000)
        derived = refresh_segment_call_preservation_state_8616(project, codegen, derived, {}, (request,))
        assert requested == [0x2000]
        assert codegen._inertia_segment_call_preservation_collection_8616.materialized_count == 1
        refresh_segment_call_preservation_state_8616(project, codegen, derived, {}, ())
        assert codegen._inertia_segment_call_preservations_8616 == ()
        assert codegen._inertia_segment_state_artifact.exit_states[0x1000]["ds"].origin is SegmentOrigin.UNKNOWN
        for contracts, requests, evidence, accepted in (
            ({0x2000: callee_contract}, (request,), program, 1),
            ({}, (request,), program, 0),
            ({0x2000: callee_contract}, (request, request), program, 0),
            ({0x2000: callee_contract}, (request,), None, 0),
        ):
            collection = collect_segment_call_preservations_8616(
                project, caller_contract, contracts, requests, evidence,
            )
            assert collection.complete
            assert collection.materialized_count == accepted
            assert collection.failure_count == len(requests) - accepted
    proofs = (proof,)
    source = caller
    if mode == "absent":
        proofs = ()
    elif mode == "duplicate":
        proofs = (proof, proof)
    elif mode == "foreign":
        source = replace(caller)
    elif mode == "stale":
        publish_function_ir_artifact_8616(project, replace(callee))
    elif mode == "far":
        proof = replace(proof, index=DecodedDirectCallsiteIndex8616(
            {0x2000: (replace(entry, is_far=True),)}, index.stats,
        ))
        proofs = (proof,)
    state = build_x86_16_segment_state_artifact(source, call_preservations=proofs)
    preserves = mode in {"valid", "invalidate_after"}
    assert (state.exit_states[0x1000]["ds"].origin is SegmentOrigin.PROVEN) is preserves
    assert state.summary["classified_call_count"] == int(preserves)
    assert state.exit_states[0x1000]["es"].origin is SegmentOrigin.UNKNOWN
    if mode == "invalidate_after":
        caller_closure = prove_segment_effect_closure_8616(caller_coverage, state)
        assert caller_closure.complete
        publish_function_ir_artifact_8616(project, replace(callee))
        assert not caller_closure.complete
