"""Native call effects refine a following branch without publishing scratch facts."""

import hashlib
import io
import sys
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.declared_function_entry import admit_declared_function_entry_8616
from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import entry_domain_call_preservation as intake
from inertia.ir import real16_invocation_domain as owner
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_raw_callee_scoped_call_chain import _collect, _recompute
from tests.ir.test_raw_callee_scoped_call_chain import calls_with_pending_helper as calls_with_pending_helper
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("resource", ["work", "deadline"])
def test_feasibility_resource_stop_precedes_callee_authentication(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, resource: str,
) -> None:
    """An exhausted feasibility phase cannot enter further proof consumers."""
    import time

    from tests.ir.test_invocation_entry_pool_reads import _derive

    census = owner._census_invocation_8616
    feasibility = owner.invocation_feasible_scope_8616
    active = []

    def capture(ctx: owner._PathCensusContext8616, *args: object, **kwargs: object) -> object:
        active.append(ctx)
        try:
            return census(ctx, *args, **kwargs)
        finally:
            active.pop()

    def exhaust(*args: object, **kwargs: object) -> object:
        result = feasibility(*args, **kwargs)
        ctx = active[-1]
        if resource == "deadline":
            ctx.deadline = time.monotonic() - 1
            return result
        return replace(result, work_units=ctx.work_limit - ctx.work_units + 1)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("feasibility exhausted resources before callee authentication")

    monkeypatch.setattr(owner, "_census_invocation_8616", capture)
    monkeypatch.setattr(owner, "invocation_feasible_scope_8616", exhaust)
    monkeypatch.setattr(owner, "_census_path_callees_8616", forbidden)
    _domain, derived = _derive(calls_with_pending_helper, 0x1043, ())
    expected = (
        owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
        if resource == "work" else owner.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    )
    assert derived.failure is expected
    assert derived.domain is None


def _branch_world(world: tuple) -> tuple:
    """Rebind real native CALL/CMP/JNE bytes under the existing declared source."""
    _, original, _, _, _, admission = world
    caller = bytes.fromhex("b83412e8caff3d00007505bb0100eb03bb0200e8baffc3")
    helper = bytes.fromhex("eb13c3") + b"\x90" * 18 + bytes.fromhex("33c0ebe9")
    source = bytearray(original.source)
    source[0x60 : 0x60 + len(caller)] = caller
    source[0x30 : 0x30 + len(helper)] = helper
    boot = program_from_mz_bytes(
        bytes(source),
        original.environment,
        code_ranges=(
            LinearRange(0x1000, 2),
            LinearRange(0x1010, 25),
            LinearRange(0x1040, len(caller)),
            LinearRange(0x1070, 1),
        ),
    )
    module = boot.image.chunks[0][1]
    project = angr.Project(
        io.BytesIO(module),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(project, 0x1040, 0x1040 + len(caller))
    assert boundary is not None
    artifact = owner.real16_native_census_import_8616(project, boundary)
    assert artifact is not None
    spec = replace(
        admission.spec,
        source_sha256=hashlib.sha256(boot.source).hexdigest(),
        relocated_sha256=hashlib.sha256(module).hexdigest(),
        native_sha256=hashlib.sha256(caller).hexdigest(),
        range_end=0x1040 + len(caller),
    )
    admission = admit_declared_function_entry_8616(
        spec, source=boot.source, loaded_module=module, environment_sha256=spec.environment_sha256
    )

    def resolver(instruction: owner.IRInstr) -> int | None:
        return resolve_direct_call_target_from_instruction_8616(project, instruction)

    index = build_boundary_direct_callsite_index_8616(boundary, direct_target_resolver=resolver)
    intake.install_real16_invocation_source_8616(
        project,
        intake.Real16InvocationSource8616(
            boot,
            _recompute,
            index,
            function_entries=(admission,),
        ),
    )
    return project, boot, artifact, boundary, resolver, admission


@pytest.mark.parametrize("resource", ["work", "shared_work", "deadline"])
def test_call_authentication_resource_stop_preserves_typed_cause(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, resource: str,
) -> None:
    """A proof lookup exhausting resources cannot masquerade as a missing call."""
    import time

    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
    from tests.ir.test_invocation_entry_pool_reads import _derive

    census = owner._census_invocation_8616
    contexts = []

    def capture(ctx: owner._PathCensusContext8616, *args: object, **kwargs: object) -> object:
        result = census(ctx, *args, **kwargs)
        contexts.append(ctx)
        return result

    monkeypatch.setattr(owner, "_census_invocation_8616", capture)
    _domain, derived = _derive(calls_with_pending_helper, 0x1043, ())
    assert derived.failure is None and contexts
    ctx = contexts[-1]
    artifact = calls_with_pending_helper[2]
    block, row = next(
        (block, row) for block in artifact.blocks for row in block.instrs
        if row.op == "CALL" and row.addr == 0x1046
    )

    with segment_call_dependency_traversal_scope_8616() as traversal:
        def exhaust(*args: object, **kwargs: object) -> None:
            if resource == "work":
                ctx.work_units = ctx.work_limit + 1
            elif resource == "shared_work":
                traversal.census_work_units = owner._CENSUS_WORK_LIMIT_8616 + 1
            else:
                ctx.deadline = time.monotonic() - 1

        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("resource refusal must precede declared-service fallback")

        monkeypatch.setattr(owner, "_consume_cross_call_boundary_8616", exhaust)
        monkeypatch.setattr(owner, "_declared_service_crossing_8616", forbidden)
        failure = owner._cross_call_8616(
            ctx, artifact, block, row, {}, owner.path_memory_initial_8616(),
        )
    expected = (
        owner.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
        if resource == "deadline" else owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    )
    assert failure is expected


def test_native_return_zero_prunes_following_branch(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A simulated source-bound XOR result makes the native JNE edge infeasible."""
    world = _branch_world(calls_with_pending_helper)
    original = owner._census_invocation_8616
    seen = []
    states = []
    speculative_depth = 0
    authentications = 0
    manifests = 0
    authenticate = intake.EntryDomainCallPreservation8616.complete_for
    apply_call = owner._feasibility_call_scratch_8616
    census = owner._census_callee_bytes_8616

    def tracked_call(*args: object, **kwargs: object) -> bool:
        """Mark authentic speculative consumption without changing its effects."""
        nonlocal speculative_depth
        speculative_depth += 1
        try:
            return apply_call(*args, **kwargs)
        finally:
            speculative_depth -= 1

    def tracked_authentication(
        proof: intake.EntryDomainCallPreservation8616,
        scope: owner.Real16InvocationDomain8616 | None,
    ) -> bool:
        """Count current proof checks before and after speculative simulation."""
        nonlocal authentications
        if (
            speculative_depth
            and sys._getframe(1).f_code.co_name == "preserved_registers_for"
            and sys._getframe(2).f_code.co_name
            in {
                "_consume_entry_call_record_8616",
                "_consume_cross_call_boundary_8616",
                "_reconcile_call_exit_8616",
            }
        ):
            authentications += 1
        return authenticate(proof, scope)

    def tracked_manifest(*args: object, **kwargs: object) -> owner.Real16InvocationFailure8616 | None:
        """Count source-bound callee manifests within speculative consumption."""
        nonlocal manifests
        if speculative_depth:
            manifests += 1
        return census(*args, **kwargs)

    def capture(ctx: owner._PathCensusContext8616, *args: object, **kwargs: object) -> object:
        result = original(ctx, *args, **kwargs)
        if ctx.edge_feasibility is not None and ctx.callsite_addr == 0x1053:
            seen.append(ctx.edge_feasibility)
            states.append(
                dict(ctx.callsite_call_state) if ctx.callsite_call_state is not None else None
            )
        return result

    monkeypatch.setattr(owner, "_census_invocation_8616", capture)
    monkeypatch.setattr(owner, "_feasibility_call_scratch_8616", tracked_call)
    monkeypatch.setattr(owner, "_census_callee_bytes_8616", tracked_manifest)
    monkeypatch.setattr(intake.EntryDomainCallPreservation8616, "complete_for", tracked_authentication)
    records = _collect(world)
    assert len(records) == 2
    assert any(edge.infeasible_edges for edge in seen)
    assert records[1].failure is None
    assert states and all(state is not None for state in states)
    assert all(state.get("ax") == 0 and state.get("bx") == 1 for state in states)
    assert manifests > 0
    assert authentications == 2 * manifests


def _ledger(ctx: owner._PathCensusContext8616) -> tuple:
    """Snapshot published receipts independently of authorized work accounting."""
    return (
        tuple(ctx.manifest),
        ctx.fetched_span_admissions,
        dict(ctx.machine_bytes),
        {address: dict(blocks) for address, blocks in ctx.native_blocks.items()},
        tuple(ctx.service_consumptions),
        set(ctx.censused_callees),
        set(ctx.raw_facts),
        set(ctx.normalized_facts),
        set(ctx.classified_facts),
        set(ctx.materialized_facts),
        ctx.failures,
        ctx.checked_stores,
        ctx.callsite_call_state,
        ctx.callsite_memory,
        ctx.first_failure_site,
    )


@pytest.mark.parametrize(
    "mode", ["missing_proof", "caller_native", "callee_native", "work", "deadline", "caller_store", "callee_store"]
)
def test_unproven_native_effects_keep_edges(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """Refused speculative crossings never publish constants or census facts."""
    import time

    world = _branch_world(calls_with_pending_helper)
    original = owner._feasibility_call_scratch_8616
    seen = []
    outcomes = []
    census = owner._census_invocation_8616

    def capture(ctx: owner._PathCensusContext8616, *args: object, **kwargs: object) -> object:
        result = census(ctx, *args, **kwargs)
        if ctx.callsite_addr == 0x1053 and ctx.edge_feasibility is not None:
            seen.append(ctx.edge_feasibility)
        return result

    monkeypatch.setattr(owner, "_census_invocation_8616", capture)

    def attempt(
        ctx: owner._PathCensusContext8616,
        artifact: owner.IRFunctionArtifact,
        block: owner.IRBlock,
        row: owner.IRInstr,
        registers: dict[str, int],
        memory: owner.PathMemory8616,
        caller_spans: tuple[tuple[int, int], ...] | frozenset[tuple[int, int]],
        *, caller_range: owner.ScratchCallerRange8616 | None = None,
    ) -> bool:
        before = _ledger(ctx)
        before_registers, before_memory = dict(registers), memory.copy()
        target = (
            replace(ctx, work_limit=0)
            if mode == "work"
            else replace(ctx, deadline=time.monotonic() - 1)
            if mode == "deadline"
            else ctx
        )
        actual_memory = memory.copy()
        if mode in ("caller_store", "callee_store"):
            actual_memory.apply_write(artifact.function_addr if mode == "caller_store" else 0x1025, 1, b"\x90")
        with monkeypatch.context() as patch:
            if mode in ("work", "deadline"):

                def forbidden(*args: object) -> None:
                    raise AssertionError("budget must refuse before proof authentication")

                patch.setattr(owner, "_consume_cross_call_boundary_8616", forbidden)
            if mode == "missing_proof":
                patch.setattr(owner, "_consume_cross_call_boundary_8616", lambda *args: None)
            if mode in ("caller_native", "callee_native"):
                current = owner._feasibility_callsite_bytes_current_8616

                def mutate(scratch: owner._PathCensusContext8616, instruction: owner.IRInstr) -> bool:
                    world[0].loader.memory.store(instruction.addr if mode == "caller_native" else 0x1025, b"\x90")
                    return current(scratch, instruction)

                patch.setattr(owner, "_feasibility_callsite_bytes_current_8616", mutate)
            result = original(target, artifact, block, row, registers, actual_memory, caller_spans, caller_range=caller_range)
        outcomes.append(result)
        assert not result
        assert registers == before_registers and memory == before_memory
        assert _ledger(ctx) == before
        return False

    monkeypatch.setattr(owner, "_feasibility_call_scratch_8616", attempt)
    records = _collect(world)
    assert len(records) == 2 and outcomes
    assert seen and all(not evidence.infeasible_edges for evidence in seen)
