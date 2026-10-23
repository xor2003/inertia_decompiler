"""Pure leaf transfer preserves native priority while avoiding a second row walk."""
from __future__ import annotations

import io
import time
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import real16_invocation_domain as owner
from inertia.ir.core import IRBinaryValue, IRValue, MemSpace
from inertia.ir.real16_fused_callee_transfer import source_bound_callee_transfer_8616
from inertia.ir.real16_path_memory8616 import PathMemory8616

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("registry", [
    owner.scalar_owner_8616._CLASSIFIERS_8616,
    owner.kb_owner_8616._KB_BINOP_PLAIN_8616,
    owner._NATIVE_COMPARATORS_8616,
])
def test_static_dispatch_membership_is_immutable(registry):
    """Authority identity must bind entries without a mutable backing container."""
    assert type(registry) is tuple
    assert all(type(entry) is tuple and len(entry) == 2 for entry in registry)
    with pytest.raises(TypeError):
        registry[0][1] = lambda *args: None


def _world(code=None, *, single_block=True):
    if code is None:
        code = bytes.fromhex("b80100") + bytes.fromhex("83c001") * 80 + bytes.fromhex("c3")
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(io.BytesIO(code), main_opts={
        "backend": "blob", "arch": arch, "base_addr": 0x1000, "entry_point": 0x1000,
    }, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(code))
    assert boundary is not None
    artifact = owner.real16_native_census_import_8616(project, boundary)
    assert artifact is not None
    if single_block:
        assert len(artifact.blocks) == 1
    block = artifact.blocks[0]
    ctx = owner._PathCensusContext8616(
        project=project, selector=0x100, image=SimpleNamespace(), boot=object(),
        chain=None, call_preservations=(), entry_call_preservations=(),
        declared_services=(), environment_digest=None, environment=None, arena=None,
        service_consumptions=[], stop_block_addr=None, callsite_addr=None,
        callsite_call_state=None, callsite_memory=None, manifest=set(),
        machine_bytes={}, native_blocks={artifact.function_addr: {block.addr: deepcopy(block)}},
        checked_stores=0, censused_callees=set(), raw_facts=set(), normalized_facts=set(),
        classified_facts=set(), materialized_facts=set(), failures=0,
        work_units=0, work_limit=10000, deadline=time.monotonic() + 30,
    )
    seed = owner._PathState8616({"cs": 0x100, "ds": 0x100, "ss": 0x100, "sp": 0x200}, PathMemory8616())
    return ctx, artifact, block, seed


def _run(ctx, artifact, block, seed):
    with source_bound_callee_transfer_8616(ctx, artifact, owner._BASE_FUSED_CALLEE_OPERATIONS_8616):
        return owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=None)


def test_authentic_scalar_leaf_fits_one_walk_budget():
    ctx, artifact, block, seed = _world()
    baseline = owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=None)
    assert isinstance(baseline, owner._PathState8616)
    counts = tuple(len(values) for values in (ctx.raw_facts, ctx.normalized_facts,
                   ctx.classified_facts, ctx.materialized_facts)), ctx.failures
    fresh = replace(ctx, raw_facts=set(), normalized_facts=set(), classified_facts=set(),
                    materialized_facts=set(), work_units=0, accounted_work_units=0,
                    work_limit=len(block.instrs) + len(owner._BASE_FUSED_CALLEE_OPERATIONS_8616.producers) + 20)
    result = _run(fresh, artifact, block, seed)
    assert isinstance(result, owner._PathState8616)
    assert result.registers == baseline.registers and result.memory == baseline.memory
    assert (tuple(len(values) for values in (fresh.raw_facts, fresh.normalized_facts,
            fresh.classified_facts, fresh.materialized_facts)), fresh.failures) == counts
    assert fresh.checked_stores == ctx.checked_stores


def test_late_native_origin_mismatch_refuses_all_rows():
    ctx, artifact, block, seed = _world()
    rows = list(block.instrs)
    rows[-2] = replace(rows[-2], size=rows[-2].size + 1)
    tampered = replace(block, instrs=tuple(rows))
    before = seed.memory.copy()
    result = _run(ctx, artifact, tampered, seed)
    assert result is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert seed.memory == before
    assert len(ctx.classified_facts) == len(block.instrs)
    assert not ctx.materialized_facts and ctx.failures == len(block.instrs)
    assert ctx.first_failure_site is not None


def test_foreign_charge_cannot_run_during_fused_eligibility(monkeypatch):
    from inertia.ir.real16_fused_callee_transfer import try_fused_callee_transfer_8616

    ctx, artifact, block, seed = _world()
    calls = []
    def foreign_charge(context):
        calls.append(context)
        return False
    operations = replace(owner._BASE_FUSED_CALLEE_OPERATIONS_8616, charge=foreign_charge)
    with source_bound_callee_transfer_8616(ctx, artifact, owner._BASE_FUSED_CALLEE_OPERATIONS_8616):
        result = try_fused_callee_transfer_8616(
            ctx, artifact, block, seed, stop_after=None, operations=operations,
        )
    assert result is None and not calls


def test_deceptive_callable_equality_cannot_authorize_transfer():
    from inertia.ir.real16_fused_callee_transfer import canonical_fused_operations_match_8616

    class Foreign:
        def __eq__(self, other):
            return True
        def __call__(self, *args):
            raise AssertionError("foreign transfer must never execute")
    original = owner._BASE_FUSED_CALLEE_OPERATIONS_8616
    assert not canonical_fused_operations_match_8616(replace(original, transfer=Foreign()), original)


def test_producer_inventory_must_not_invoke_foreign_iterator():
    from inertia.ir.real16_fused_callee_transfer import canonical_fused_operations_match_8616

    class Foreign:
        def __iter__(self):
            raise AssertionError("foreign inventory must never be iterated")
    original = owner._BASE_FUSED_CALLEE_OPERATIONS_8616
    assert not canonical_fused_operations_match_8616(replace(original, producers=Foreign()), original)


@pytest.mark.parametrize("store_refused", [False, True])
def test_late_binding_mismatch_rolls_back_store_and_preserves_native_priority(store_refused):
    code = bytes.fromhex("c70600020100") + bytes.fromhex("b80100") + bytes.fromhex("83c001") * 80 + bytes.fromhex("c3")
    ctx, artifact, block, seed = _world(code)
    ctx.machine_bytes[0x1000] = bytes.fromhex("c70600020100")
    if store_refused:
        ctx.manifest.add((0x1200, 2))
    baseline = owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=None)
    if store_refused:
        assert baseline is owner.Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    else:
        assert isinstance(baseline, owner._PathState8616) and ctx.checked_stores > 0
    rows = list(block.instrs)
    rows[-2] = replace(rows[-2], size=rows[-2].size + 1)
    tampered = replace(block, instrs=tuple(rows))
    fresh = replace(ctx, raw_facts=set(), normalized_facts=set(), classified_facts=set(),
                    materialized_facts={(block.addr, 0)}, work_units=0, accounted_work_units=0,
                    checked_stores=0, failures=0, first_failure_site=None)
    result = _run(fresh, artifact, tampered, seed)
    assert result is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert fresh.checked_stores == 0 and not fresh.materialized_facts
    assert fresh.failures == len(block.instrs) and seed.memory == PathMemory8616()


def test_native_comparison_retains_depth_three_limit():
    ctx, artifact, block, seed = _world()
    # A deeply nested provenance/operand must retain the original depth budget.
    value = IRValue(MemSpace.CONST, const=1)
    for _ in range(65):
        value = IRBinaryValue("add", value, IRValue(MemSpace.CONST, const=1))
    rows = list(block.instrs)
    rows[0] = replace(rows[0], args=(value,))
    nested = replace(block, instrs=tuple(rows))
    ctx.native_blocks[artifact.function_addr][block.addr] = deepcopy(nested)
    assert not owner._native_block_bound_8616(ctx.native_blocks[artifact.function_addr][block.addr], nested, stop_after=None)
    assert _run(ctx, artifact, nested, seed) is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN


def test_midwalk_budget_never_publishes_partial_exit():
    ctx, artifact, block, seed = _world()
    ctx.work_limit = len(owner._BASE_FUSED_CALLEE_OPERATIONS_8616.producers) + 20
    before = dict(seed.registers), seed.memory.copy()
    assert _run(ctx, artifact, block, seed) is owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    assert (seed.registers, seed.memory) == before
    assert ctx.work_units > ctx.work_limit
    assert ctx.materialized_facts <= ctx.classified_facts <= ctx.normalized_facts <= ctx.raw_facts


def test_changed_transitive_effect_owner_keeps_whole_block_binding(monkeypatch):
    ctx, artifact, block, seed = _world()
    rows = list(block.instrs)
    rows[-2] = replace(rows[-2], size=rows[-2].size + 1)
    changed = replace(block, instrs=tuple(rows))
    calls = []
    original = owner._simulate_tmp_write_8616
    def foreign(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(owner, "_simulate_tmp_write_8616", foreign)
    assert _run(ctx, artifact, changed, seed) is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert not calls and not ctx.materialized_facts


@pytest.mark.parametrize("boundary", ["scalar", "direction"])
def test_changed_dispatch_owner_cannot_observe_unbound_rows(monkeypatch, boundary):
    ctx, artifact, block, seed = _world()
    rows = list(block.instrs)
    rows[-2] = replace(rows[-2], size=rows[-2].size + 1)
    calls = []
    def foreign(*args, **kwargs):
        calls.append(True)
        raise AssertionError("unbound callback")
    if boundary == "scalar":
        monkeypatch.setattr(owner.scalar_owner_8616, "_CLASSIFIERS_8616", {
            **dict(owner.scalar_owner_8616._CLASSIFIERS_8616), "MOV": foreign,
        })
    else:
        monkeypatch.setattr(owner.kb_owner_8616, "_kb_data_row_8616", foreign)
    assert _run(ctx, artifact, replace(block, instrs=tuple(rows)), seed) is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert not calls


@pytest.mark.parametrize("name", ["_make_fused_callee_operations_8616", "_fused_callee_producers_8616"])
def test_changed_operation_builder_falls_back_without_calling_it(monkeypatch, name):
    ctx, artifact, block, seed = _world()
    rows = list(block.instrs)
    rows[-2] = replace(rows[-2], size=rows[-2].size + 1)
    calls = []
    def foreign():
        calls.append(True)
        raise AssertionError("operation builder must be guarded before invocation")
    monkeypatch.setattr(owner, name, foreign)
    assert _run(ctx, artifact, replace(block, instrs=tuple(rows)), seed) is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert not calls and not ctx.materialized_facts


def test_unexpected_bound_call_never_invokes_call_authority(monkeypatch):
    ctx, artifact, block, seed = _world()
    rows = list(block.instrs)
    rows[-2] = replace(rows[-2], op="CALL")
    changed = replace(block, instrs=tuple(rows))
    ctx.native_blocks[artifact.function_addr][block.addr] = deepcopy(changed)
    calls = []
    def foreign(*args, **kwargs):
        calls.append(True)
        raise AssertionError("unexpected leaf call must never execute")
    monkeypatch.setattr(owner, "_cross_call_8616", foreign)
    assert _run(ctx, artifact, changed, seed) is owner.Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    assert not calls


def test_repeat_geometry_without_nonrepeat_witness_retains_ordinary_route():
    from inertia.ir.real16_fused_callee_transfer import try_fused_callee_transfer_8616
    ctx, artifact, block, seed = _world()
    changed = replace(block, instrs=tuple(replace(row, addr=block.addr) for row in block.instrs))
    ctx.native_blocks[artifact.function_addr][block.addr] = deepcopy(changed)
    with source_bound_callee_transfer_8616(ctx, artifact, owner._BASE_FUSED_CALLEE_OPERATIONS_8616):
        result = try_fused_callee_transfer_8616(
            ctx, artifact, changed, seed, stop_after=None,
            operations=owner._make_fused_callee_operations_8616(),
        )
    assert result is None and not ctx.materialized_facts


def test_foreign_initial_memory_rejected_before_read():
    from inertia.ir.real16_fused_callee_transfer import try_fused_callee_transfer_8616
    from inertia.ir.real16_initial_memory8616 import InvocationInitialMemory8616
    class Foreign(InvocationInitialMemory8616):
        def byte_at(self, address):
            raise AssertionError("foreign reader must not execute during eligibility")
    ctx, artifact, block, seed = _world()
    ctx.initial_memory = Foreign(())
    with source_bound_callee_transfer_8616(ctx, artifact, owner._BASE_FUSED_CALLEE_OPERATIONS_8616):
        result = try_fused_callee_transfer_8616(
            ctx, artifact, block, seed, stop_after=None,
            operations=owner._make_fused_callee_operations_8616(),
        )
    assert result is None and not ctx.materialized_facts


def test_expired_deadline_never_publishes_exit():
    ctx, artifact, block, seed = _world()
    ctx.deadline = 0
    before = dict(seed.registers), seed.memory.copy()
    assert _run(ctx, artifact, block, seed) is owner.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    assert (seed.registers, seed.memory) == before and not ctx.materialized_facts


@pytest.mark.parametrize(("module_name", "dependency_name"), [
    ("real16_path_memory8616", "canonical_known_root_8616"),
    ("real16_fused_callee_transfer", "canonical_known_root_8616"),
    ("scalar_instruction_effects", "no_effect_claim_shape_8616"),
    ("scalar_instruction_effects", "scalar_binary_operation_8616"),
    ("real16_edge_feasibility8616", "scalar_instruction_effect_8616"),
    ("real16_edge_feasibility8616", "register_value_family_8616"),
    ("real16_edge_feasibility8616", "register_value_projection_8616"),
    ("real16_edge_feasibility8616", "wide_multiply_shape_8616"),
    ("real16_edge_feasibility8616", "wide_multiply_value_8616"),
])
def test_consumer_dependency_cannot_observe_unbound_rows(monkeypatch, module_name, dependency_name):
    """Changing a consumer helper preserves full native binding before effects."""
    import importlib

    ctx, artifact, block, seed = _world()
    rows = list(block.instrs)
    rows[-2] = replace(rows[-2], size=rows[-2].size + 1)
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("changed consumer dependency observed unbound rows")
    consumer = importlib.import_module("inertia.ir." + module_name)
    monkeypatch.setattr(consumer, dependency_name, forbidden)
    assert _run(ctx, artifact, replace(block, instrs=tuple(rows)), seed) is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert not calls and not ctx.materialized_facts
