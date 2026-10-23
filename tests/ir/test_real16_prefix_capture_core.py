"""Canonical prefix capture keeps ordinary results and original resource limits."""

from dataclasses import replace

import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.native_import_surface_cache import NativeCensusSourceBinding8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from tests.ir.test_fused_caller_prefix import _caller_world
from tests.ir.test_x86_16_invocation_domain import _boot, _recompute, _world

pytestmark = pytest.mark.decompiler


def _install_high_capture_advice(monkeypatch):
    """Test DATA_ONLY ownership with high capture advice, retaining real work advice."""
    retain = owner._retain_prefix_census_8616

    def advised(ctx, *args):
        saved = ctx.prefix_simulation_work
        ctx.prefix_simulation_work = 100000
        try:
            data = retain(ctx, *args)
        finally:
            ctx.prefix_simulation_work = saved
        if data is not None:
            object.__setattr__(data, "simulation_work", saved)
        return data

    monkeypatch.setattr(owner, "_retain_prefix_census_8616", advised)


@pytest.fixture(autouse=True)
def high_capture_advice(monkeypatch):
    """Supply explicit high capture advice for private ownership controls."""
    _install_high_capture_advice(monkeypatch)


def test_requested_cut_enables_fresh_branchless_call_rows_only_when_bound():
    """Optional current-state capture needs hooks; default branch pruning does not."""
    from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace

    row = IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x30, size=2),), addr=0x10)
    current = replace(row, addr=0x20)
    block = IRBlock(0x10, (row,), successor_addrs=(0x20,))
    later = IRBlock(0x20, (current,))
    artifact = IRFunctionArtifact(0x10, (block, later))
    blocks = {item.addr: item for item in artifact.blocks}
    cut = owner.kb_owner_8616.Real16CallCutRequest8616(artifact, block, 0, row)
    assert owner._feasibility_call_rows_8616(blocks, blocks, frozenset(blocks), 0x20) == {}
    assert owner._feasibility_call_rows_8616(
        blocks, blocks, frozenset(blocks), 0x20, call_cut=cut,
    ) == {id(row): (block, row)}
    changed = {**blocks, 0x10: replace(block, instrs=(replace(row, op="RET"),))}
    assert owner._feasibility_call_rows_8616(
        blocks, changed, frozenset(blocks), 0x20, call_cut=cut,
    ) == {}


def derive(*, capture, stack_sp=0x100, stack_ss=0x10):
    boot = _boot(stack_sp=stack_sp, stack_ss=stack_ss)
    project, coverage, _, preservation = _world(boot)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        result = owner._derive_invocation_domain_8616(
            project, coverage, 0x1032, boot, _recompute, (preservation,),
            prefix_capture=capture,
        )
        return result, traversal.census_work_units


def test_canonical_capture_owns_exact_completed_census():
    ordinary, work = derive(capture=False)
    captured, captured_work = derive(capture=True)
    assert ordinary.failure is captured.failure is None
    assert ordinary.prefix_census is None
    data = captured.prefix_census
    assert data is not None
    ctx = data.context
    terminal = ctx.prefix_terminal_call
    assert terminal is not None
    assert terminal.artifact is data.artifact
    assert terminal.block.instrs[terminal.index] is terminal.instruction
    assert terminal.index == len(terminal.block.instrs) - 1
    assert terminal.instruction.addr == ctx.callsite_addr == 0x1032
    assert terminal.current_addr == ctx.callsite_addr
    assert data.boot_recompute is _recompute
    assert owner._census_counts_8616(ctx) == (
        captured.raw_fact_count, captured.normalized_fact_count,
        captured.classified_fact_count, captured.materialized_count,
        captured.failure_count,
    )
    # Independently built worlds have different owning artifact/boundary
    # identities. Every other ordinary derived field must match exactly.
    assert replace(
        ordinary.domain, callsite_artifact=captured.domain.callsite_artifact,
        callsite_boundary=captured.domain.callsite_boundary,
    ) == captured.domain
    assert (
        ordinary.raw_fact_count, ordinary.normalized_fact_count,
        ordinary.classified_fact_count, ordinary.materialized_count,
        ordinary.failure_count, ordinary.entry_call_pool_consultation,
    ) == (
        captured.raw_fact_count, captured.normalized_fact_count,
        captured.classified_fact_count, captured.materialized_count,
        captured.failure_count, captured.entry_call_pool_consultation,
    )
    assert captured_work > work
    assert captured_work - work < owner._CENSUS_WORK_LIMIT_8616
    assert data.fact_ownership is not None


def test_failed_census_does_not_retain_prefix():
    result, _ = derive(capture=True, stack_ss=0, stack_sp=0x34)
    assert result.failure is owner.Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    assert result.prefix_census is None


def test_terminal_continuation_survives_call_register_reset():
    ctx, artifact, block, seed = _caller_world()
    ctx.prefix_capture_requested = True
    result = owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=ctx.callsite_addr)
    assert isinstance(result, owner._PathState8616)
    terminal = ctx.prefix_terminal_call
    assert terminal is not None
    assert result.registers == {}
    assert ctx.callsite_call_state["ax"] == 81
    assert terminal.instruction_entry
    assert terminal.tmps
    assert seed.registers["sp"] == 0x200
    assert terminal.current_addr == block.instrs[-1].addr
    before = ctx.callsite_memory.copy()
    result.memory.apply_write(123, 1, b"x")
    result.registers["ax"] = 99
    assert ctx.callsite_memory == before
    assert ctx.callsite_call_state["ax"] == 81


def test_same_block_suffix_declines_ownership_transfer():
    ctx, artifact, block, seed = _caller_world()
    ctx.prefix_capture_requested = True
    # Stop at the same bound CALL, but its block has a later instruction.
    suffix = replace(block.instrs[-1], op="RET", addr=ctx.callsite_addr + 3)
    changed = replace(block, instrs=(*block.instrs, suffix))
    # An irrelevant suffix may stay outside the ordinary stop range; capture
    # still declines because transferring its scalar containers is unproved.
    result = owner._simulate_path_block_8616(ctx, artifact, changed, seed, stop_after=ctx.callsite_addr)
    assert isinstance(result, owner._PathState8616)
    assert ctx.prefix_terminal_call is None


@pytest.mark.parametrize("resource", ["local", "ambient", "deadline"])
def test_optional_handoff_miss_never_changes_success(resource):
    derived, _ = derive(capture=True)
    data = derived.prefix_census
    ctx = replace(data.context, prefix_capture_requested=True)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if resource == "local":
            ctx.work_limit = ctx.work_units
        elif resource == "ambient":
            traversal.census_work_units = owner._CENSUS_WORK_LIMIT_8616
        else:
            ctx.deadline = 0
        before = ctx.work_units, traversal.census_work_units
        assert owner._retain_prefix_census_8616(
            ctx, data.seed, data.artifact, data.boundary, data.boot_recompute,
        ) is None
        assert (ctx.work_units, traversal.census_work_units) == before
        assert derived.failure is None


def test_completed_context_transfers_ownership_only_once():
    derived, _ = derive(capture=True)
    data = derived.prefix_census
    before = data.context.work_units
    assert owner._retain_prefix_census_8616(
        data.context, data.seed, data.artifact, data.boundary, data.boot_recompute,
    ) is None
    assert data.context.work_units == before


def test_source_binding_capture_disabled_leaves_metadata_untouched():
    ctx, _, _, _ = _caller_world()
    owner._retain_prefix_source_binding_8616(ctx, None, None)
    assert ctx.prefix_sources.complete
    assert ctx.prefix_sources.bindings == {}


def test_missing_scratch_source_authority_propagates_to_root():
    derived, _ = derive(capture=True)
    data = derived.prefix_census
    ctx = replace(data.context, prefix_capture_requested=True,
                  prefix_sources=owner._PrefixSourceBindings8616())
    scratch = replace(ctx)
    before = ctx.work_units
    owner._retain_prefix_source_binding_8616(scratch, data.boundary, None)
    assert scratch.prefix_sources is ctx.prefix_sources
    assert not ctx.prefix_sources.complete
    assert ctx.work_units == before


def test_rebuilt_equal_key_declines_capture_without_replacing_original():
    derived, _ = derive(capture=True)
    data = derived.prefix_census
    ctx = replace(data.context, prefix_capture_requested=True,
                  prefix_sources=owner._PrefixSourceBindings8616())
    binding = NativeCensusSourceBinding8616(ctx.project, data.boundary, (1, 2), ())
    before = ctx.work_units
    owner._retain_prefix_source_binding_8616(ctx, data.boundary, binding)
    owner._retain_prefix_source_binding_8616(ctx, data.boundary, binding)
    assert ctx.prefix_sources.complete
    new_key = (*binding.key,)
    assert new_key == binding.key and new_key is not binding.key
    rebuilt = replace(binding, key=new_key)
    owner._retain_prefix_source_binding_8616(ctx, data.boundary, rebuilt)
    assert not ctx.prefix_sources.complete
    assert ctx.prefix_sources.bindings[data.boundary.addr] is binding
    owner._retain_prefix_source_binding_8616(ctx, data.boundary, binding)
    assert not ctx.prefix_sources.complete
    assert ctx.work_units == before


def _terminal_world():
    ctx, artifact, block, seed = _caller_world()
    ctx.prefix_capture_requested = True
    ordinary = owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=ctx.callsite_addr)
    assert isinstance(ordinary, owner._PathState8616)
    terminal = ctx.prefix_terminal_call
    state = owner._PathState8616(dict(ctx.callsite_call_state), ctx.callsite_memory.copy(), terminal.direction)
    return ctx, artifact, terminal, state, ordinary


def _current_cut_world():
    from inertia.ir.real16_edge_feasibility8616 import Real16CallCutState8616, Real16EdgeFeasibility8616

    ctx, artifact, terminal, state, _ = _terminal_world()
    cut = Real16CallCutState8616(
        artifact, terminal.block, terminal.index, terminal.instruction,
        tuple(sorted(state.registers.items())), tuple(sorted(state.memory.known.items())),
        tuple(sorted(state.memory.unknown)), state.direction,
    )
    ctx.edge_feasibility = Real16EdgeFeasibility8616(
        live_blocks=frozenset((terminal.block.addr,)), infeasible_edges=(),
        evaluated_cjmps=0, proven_edges=0, converged=True, work_units=0, call_cut=cut,
    )
    return ctx, artifact, terminal, state, cut


def test_current_cut_matches_complete_ordinary_pre_call_state():
    ctx, artifact, terminal, state, _ = _current_cut_world()
    before = dict(state.registers), state.memory.copy()
    work = ctx.work_units
    assert owner._prefix_cut_state_matches_8616(ctx, artifact, terminal, state)
    assert ctx.work_units > work
    assert (state.registers, state.memory) == before


def test_native_feasibility_cut_matches_ordinary_call_frame_and_state():
    from inertia.ir.real16_edge_feasibility8616 import Real16CallCutRequest8616, invocation_feasible_scope_8616
    from inertia.ir.ssa_function import build_x86_16_ir_predecessor_map

    ctx, artifact, block, seed = _caller_world()
    ctx.prefix_capture_requested = True
    ordinary = owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=ctx.callsite_addr)
    assert isinstance(ordinary, owner._PathState8616)
    terminal = ctx.prefix_terminal_call
    state = owner._PathState8616(dict(ctx.callsite_call_state), ctx.callsite_memory.copy(), terminal.direction)
    ctx.edge_feasibility = invocation_feasible_scope_8616(
        artifact=artifact, dangerous=frozenset((terminal.block.addr,)),
        predecessor_map=build_x86_16_ir_predecessor_map(artifact),
        head_addr=artifact.function_addr, call_block_addr=terminal.block.addr,
        callsite_addr=terminal.instruction.addr,
        seed=seed.registers, seed_memory=seed.memory,
        apply_service=lambda *args: False, iteration_limit=16,
        deadline=ctx.deadline, work_limit=20000,
        call_cut=Real16CallCutRequest8616(artifact, terminal.block, terminal.index, terminal.instruction),
    )
    assert ctx.edge_feasibility.call_cut is not None
    assert owner._prefix_cut_state_matches_8616(ctx, artifact, terminal, state)


@pytest.mark.parametrize("change", ["register", "known", "unknown", "direction", "row", "artifact", "index", "incomplete", "tainted", "duplicate"])
def test_current_cut_rejects_stale_or_partial_state(change):
    ctx, artifact, terminal, state, cut = _current_cut_world()
    if change == "register":
        cut = replace(cut, registers=((*cut.registers, ("foreign", 17))))
    elif change == "known":
        cut = replace(cut, memory_known=((*cut.memory_known, (12345, 17))))
    elif change == "unknown":
        cut = replace(cut, memory_unknown=((*cut.memory_unknown, 12345)))
    elif change == "direction":
        cut = replace(cut, direction=not state.direction)
    elif change == "row":
        cut = replace(cut, instruction=replace(terminal.instruction))
    elif change == "artifact":
        cut = replace(cut, artifact=replace(artifact))
    elif change == "index":
        cut = replace(cut, index=-1)
    elif change == "incomplete":
        ctx.edge_feasibility = replace(ctx.edge_feasibility, converged=False)
    elif change == "tainted":
        state.memory.tainted = True
    else:
        cut = replace(cut, registers=(*cut.registers, cut.registers[0]))
    ctx.edge_feasibility = replace(ctx.edge_feasibility, call_cut=cut)
    assert not owner._prefix_cut_state_matches_8616(ctx, artifact, terminal, state)


def test_current_cut_rejects_terminal_direction_used_by_resume():
    ctx, artifact, terminal, state, _ = _current_cut_world()
    terminal = replace(terminal, direction=not state.direction)
    assert not owner._prefix_cut_state_matches_8616(ctx, artifact, terminal, state)


@pytest.mark.parametrize("resource", ["work", "deadline"])
def test_current_cut_declines_before_state_comparison_without_resources(resource):
    ctx, artifact, terminal, state, _ = _current_cut_world()
    if resource == "work":
        ctx.work_limit = ctx.work_units
    else:
        ctx.deadline = 0
    assert not owner._prefix_cut_state_matches_8616(ctx, artifact, terminal, state)


def test_current_cut_rechecks_deadline_after_state_comparison(monkeypatch):
    ctx, artifact, terminal, state, _ = _current_cut_world()
    clock = iter((ctx.deadline - 1, ctx.deadline + 1))
    monkeypatch.setattr(owner.time, "monotonic", lambda: next(clock, ctx.deadline + 1))
    assert not owner._prefix_cut_state_matches_8616(ctx, artifact, terminal, state)


def _extension_world(monkeypatch, *, helper=b"\x40\xc3", targets=(0x60, 0x60, 0x60)):
    """Three genuine near CALLs share a native helper and source-bound MZ."""
    import hashlib
    import io

    import angr

    from inertia.frontend.x86_16.arch_86_16 import Arch86_16
    from inertia.frontend.x86_16.declared_function_entry import (
        DeclaredEntryMemory8616,
        DeclaredEntryReturn8616,
        DeclaredEntryReturnKind8616,
        DeclaredFunctionEntryAdmission8616,
        DeclaredFunctionEntrySpec8616,
        admit_declared_function_entry_8616,
    )
    from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
    from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
    from inertia.ir import entry_domain_call_preservation as entry_owner
    from inertia.ir.real16_declared_interrupt8616 import declared_environment_digest_8616
    from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
    from tests.ir.test_x86_16_boot_entry_link import _mz
    from tests.ir.test_x86_16_declared_interrupt_boundary import _environment
    from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
    from tools.dosunit.runtime.real16_replay_model import LinearRange

    code = bytearray(bytes.fromhex("b80100") + bytes.fromhex("83c001") * 8)
    sites = []
    for target in targets:
        sites.append(0x1000 + len(code))
        displacement = target - (len(code) + 3)
        code.extend(b"\xe8" + displacement.to_bytes(2, "little"))
        code.extend(bytes.fromhex("83c001"))
    code.append(0xc3)
    image = bytes(code) + bytes(0x60 - len(code)) + helper + bytes(16 - len(helper)) + b"\xc3"
    executable = bytearray(_mz(image))
    executable[12:14] = (0x40).to_bytes(2, "little")
    boot = program_from_mz_bytes(
        bytes(executable), replace(_environment(), psp_segment=0xf0, allocation=bytes(0x500)),
        code_ranges=(LinearRange(0x1000, len(code)), LinearRange(0x1060, len(helper)), LinearRange(0x1070, 1)),
    )
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(io.BytesIO(boot.image.chunks[0][1]), main_opts={
        "backend": "blob", "arch": arch, "base_addr": 0x1000, "entry_point": 0x1000,
    }, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(code))
    assert boundary is not None
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    digest = declared_environment_digest_8616(boot.environment)
    assert digest is not None
    module = boot.image.chunks[0][1]
    spec = DeclaredFunctionEntrySpec8616(
        version=1, source_sha256=hashlib.sha256(boot.source).hexdigest(),
        relocated_sha256=hashlib.sha256(module).hexdigest(), load_segment=0x100,
        entry_segment=0x100, entry_offset=0, range_start=0x1000,
        range_end=0x1000 + len(code), native_sha256=hashlib.sha256(code).hexdigest(),
        environment_sha256=digest, use_environment_memory=False,
        registers=(("ds", 0x100), ("sp", 0x80), ("ss", 0x120)),
        memory=(DeclaredEntryMemory8616(0x1280, bytes.fromhex("7000")),),
        return_boundary=DeclaredEntryReturn8616(DeclaredEntryReturnKind8616.NEAR, 0x100, 0x70),
    )
    admission = admit_declared_function_entry_8616(
        spec, source=boot.source, loaded_module=module, environment_sha256=digest,
    )
    assert isinstance(admission, DeclaredFunctionEntryAdmission8616)
    source = entry_owner.Real16InvocationSource8616(boot, _recompute, index, function_entries=(admission,))
    entry_owner.install_real16_invocation_source_8616(project, source)
    original = entry_owner._exact_boundary_for_8616
    monkeypatch.setattr(entry_owner, "_exact_boundary_for_8616", lambda current, head:
                        boundary if current is project and head == 0x1000 else original(current, head))
    return project, source, tuple(sites)


def test_three_call_native_extension_matches_ordinary_full_census(monkeypatch, record_property):
    """Actual prefix transfer preserves full native census and transported state."""
    from inertia.ir import entry_domain_call_preservation as entry_owner
    from inertia.ir.native_import_surface_cache import native_import_request_8616

    project, source, sites = _extension_world(monkeypatch)
    captures = []
    derived_results = []
    original = owner._enroll_prefix_census_data_8616

    def observe(subject, derived):
        # Explicit test-only advice exercises authority despite this tiny
        # fixture being unprofitable; every real proof guard remains active.
        if derived.prefix_census is not None and derived.prefix_census.context.callsite_addr == sites[1]:
            object.__setattr__(derived.prefix_census, "simulation_work", 100000)
        original(subject, derived)
        captures.append((subject.kind, derived.prefix_census))
        if derived.prefix_census is not None:
            derived_results.append(derived)

    monkeypatch.setattr(owner, "_enroll_prefix_census_data_8616", observe)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616

        boundary = entry_owner._exact_boundary_for_8616(project, 0x1000)
        artifact = owner.real16_native_census_import_8616(project, boundary)
        assert artifact is not None
        records = entry_owner.collect_entry_domain_call_preservations_8616(
            project, artifact, boundary, direct_target_resolver=lambda instruction:
            resolve_direct_call_target_from_instruction_8616(project, instruction),
        )
        assert len(records) == 3 and all(record.failure is None for record in records), [
            record.failure for record in records
        ]
    def sequence():
        with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as current:
            for site in sites:
                premise = entry_owner._declared_function_premise_8616(
                    project, source, source.function_entries[0], artifact, boundary, site, records,
                )
                assert premise is not None and premise.complete, (
                    None if premise is None else premise.failure,
                    None if premise is None else premise.refusal_site,
                )
            assert current.invocation_prefixes
            return current.census_work_units

    resumed_work = sequence()
    resumed = tuple(derived_results)
    retained = [data for _, data in captures if data is not None]
    assert len(retained) == 3
    assert all(data.fact_ownership is not None for data in retained)
    assert not retained[0].context.prefix_consumed
    assert retained[1].context.prefix_consumed
    assert all(not stage for stage in (
        retained[1].context.raw_facts, retained[1].context.normalized_facts,
        retained[1].context.classified_facts, retained[1].context.materialized_facts,
    ))
    captures.clear()
    derived_results.clear()
    with monkeypatch.context() as ordinary_path:
        ordinary_path.setattr(owner, "_select_prefix_extension_8616", lambda *args: None)
        ordinary_work = sequence()
    ordinary = tuple(derived_results)
    assert len(ordinary) == len(resumed) == 3
    for expected, actual in zip(ordinary, resumed, strict=True):
        assert replace(expected.domain, callsite_artifact=actual.domain.callsite_artifact,
                       callsite_boundary=actual.domain.callsite_boundary) == actual.domain
        assert (
            expected.failure, expected.raw_fact_count, expected.normalized_fact_count,
            expected.classified_fact_count, expected.materialized_count, expected.failure_count,
            expected.entry_call_pool_consultation,
        ) == (
            actual.failure, actual.raw_fact_count, actual.normalized_fact_count,
            actual.classified_fact_count, actual.materialized_count, actual.failure_count,
            actual.entry_call_pool_consultation,
        )
    # Both variants retain the original ambient bound; neither refunds hooks.
    assert resumed_work <= owner._CENSUS_WORK_LIMIT_8616
    assert ordinary_work <= owner._CENSUS_WORK_LIMIT_8616
    record_property("resumed_work", resumed_work)
    record_property("ordinary_work", ordinary_work)
    final_state = dict(resumed[-1].domain.callsite_call_state)
    assert final_state["ax"] == 13
    assert final_state["sp"] == 0x7e


def test_terminal_resume_preserves_frame_and_complete_scalar_state():
    """Resume only CALL, keeping its already executed native stack writes."""
    ctx, artifact, terminal, state, ordinary = _terminal_world()
    before = dict(state.registers), state.memory.copy()
    scalars = dict(terminal.tmps), set(terminal.dirty), dict(terminal.instruction_entry)
    counts = owner._census_counts_8616(ctx)
    stores = ctx.checked_stores
    ordinary_work = ctx.work_units
    result = owner._resume_terminal_call_8616(ctx, artifact, terminal, state)
    assert isinstance(result, owner._PathState8616)
    assert result == ordinary
    assert (state.registers, state.memory) == before
    assert owner._census_counts_8616(ctx) == counts
    assert ctx.checked_stores == stores
    assert ctx.callsite_call_state["sp"] == before[0]["sp"]
    assert ctx.callsite_memory == before[1]
    assert (terminal.tmps, terminal.dirty, terminal.instruction_entry) == scalars
    assert ctx.work_units - ordinary_work < ordinary_work


@pytest.mark.parametrize("producer", ["_simulate_instruction_8616", "_resume_path_block_8616"])
def test_terminal_resume_does_not_lend_scalar_maps_to_foreign_producer(producer, monkeypatch):
    ctx, artifact, terminal, state, _ = _terminal_world()
    scalars = dict(terminal.tmps), set(terminal.dirty), dict(terminal.instruction_entry)

    def forbidden(*args):
        raise AssertionError("foreign producer received retained scalar containers")

    monkeypatch.setattr(owner, producer, forbidden)
    assert owner._resume_terminal_call_8616(ctx, artifact, terminal, state) is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert (terminal.tmps, terminal.dirty, terminal.instruction_entry) == scalars


@pytest.mark.parametrize("target", [0x1032, 0x0FF0])
def test_terminal_resume_executes_authenticated_interior_callee_afresh(monkeypatch, target):
    """Native RET restores the already pushed frame without another push."""
    boot = _boot(entry_ip=0)
    project, _, _, proof = _world(boot)
    with segment_call_dependency_traversal_scope_8616():
        captured = owner._derive_invocation_domain_8616(
            project, proof.caller, 0x1000, boot, _recompute, (proof,), prefix_capture=True,
        )
        assert captured.failure is None
        data = captured.prefix_census
        terminal = data.context.prefix_terminal_call
        state = owner._PathState8616(
            dict(data.context.callsite_call_state), data.context.callsite_memory.copy(), terminal.direction,
        )
        resumed = replace(
            data.context, callsite_addr=target, stop_block_addr=target, prefix_capture_requested=False,
            callsite_call_state=None, callsite_memory=None, work_units=0, accounted_work_units=0,
        )
        ordinary = replace(
            resumed, raw_facts=set(), normalized_facts=set(), classified_facts=set(),
            materialized_facts=set(), checked_stores=0,
        )
        assert owner._census_callee_bytes_8616(resumed, proof) is None
        ordinary.native_blocks = resumed.native_blocks
        ordinary.manifest = resumed.manifest
        ordinary.machine_bytes = resumed.machine_bytes
        expected = owner._simulate_path_block_8616(
            ordinary, data.artifact, terminal.block, data.seed, stop_after=None,
        )
        assert isinstance(expected, owner._PathState8616)
        calls = []
        original = owner._consume_cross_call_boundary_8616

        def authenticate(*args, **kwargs):
            calls.append(args[3])
            return original(*args, **kwargs)

        monkeypatch.setattr(owner, "_consume_cross_call_boundary_8616", authenticate)
        actual = owner._resume_terminal_call_8616(resumed, data.artifact, terminal, state)
        assert isinstance(actual, owner._PathState8616)
        assert actual == expected
        assert actual.registers["sp"] == data.seed.registers["sp"]
        assert calls == [terminal.instruction]
        assert owner._census_counts_8616(resumed) == owner._census_counts_8616(ordinary)
        assert (resumed.raw_facts, resumed.normalized_facts, resumed.classified_facts, resumed.materialized_facts) == (
            ordinary.raw_facts, ordinary.normalized_facts, ordinary.classified_facts, ordinary.materialized_facts,
        )
        assert resumed.checked_stores == ordinary.checked_stores


def test_terminal_ownership_scan_is_admitted_before_touching_blocks(monkeypatch):
    ctx, artifact, terminal, state, _ = _terminal_world()
    ctx.work_limit = ctx.work_units

    def forbidden(*args):
        raise AssertionError("ownership scan executed before resource admission")

    monkeypatch.setattr(owner, "_terminal_call_owned_8616", forbidden)
    assert owner._resume_terminal_call_8616(ctx, artifact, terminal, state) is owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED


@pytest.mark.parametrize("changed", ["index", "instruction", "artifact", "native"])
def test_terminal_resume_rejects_changed_owners_before_call(changed, monkeypatch):
    ctx, artifact, terminal, state, _ = _terminal_world()
    if changed == "index":
        terminal = replace(terminal, index=-1)
    elif changed == "instruction":
        terminal = replace(terminal, instruction=replace(terminal.instruction))
    elif changed == "artifact":
        artifact = replace(artifact)
    else:
        native = ctx.native_blocks[artifact.function_addr][terminal.block.addr]
        rows = list(native.instrs)
        rows[0] = replace(rows[0], op="RET")
        ctx.native_blocks[artifact.function_addr][terminal.block.addr] = replace(native, instrs=tuple(rows))
    calls = []
    monkeypatch.setattr(owner, "_simulate_instruction_8616", lambda *args: calls.append(args))
    result = owner._resume_terminal_call_8616(ctx, artifact, terminal, state)
    assert result is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert not calls


@pytest.mark.parametrize("changed", ["overlap", "unknown_overlap", "tainted", "work", "deadline"])
def test_terminal_resume_rechecks_carried_writes_and_resources(changed, monkeypatch):
    ctx, artifact, terminal, state, _ = _terminal_world()
    expected = owner.Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    if changed in ("overlap", "unknown_overlap"):
        written = next(iter(state.memory.known))
        ctx.manifest.add((written, 1))
        if changed == "unknown_overlap":
            state.memory.apply_write(written, 1, None)
    elif changed == "tainted":
        state.memory.taint()
    elif changed == "work":
        ctx.work_limit = ctx.work_units
        expected = owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    else:
        ctx.deadline = 0
        expected = owner.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    calls = []
    monkeypatch.setattr(owner, "_simulate_instruction_8616", lambda *args: calls.append(args))
    before = dict(state.registers), state.memory.copy()
    assert owner._resume_terminal_call_8616(ctx, artifact, terminal, state) is expected
    assert not calls
    assert (state.registers, state.memory) == before
