"""Parent controls: rebound LOAD and copied STORE owners stay observable."""

import time
from pathlib import Path

import pytest

from inertia.ir import real16_edge_feasibility8616 as edge
from inertia.ir import real16_invocation_domain as domain
from inertia.ir import real16_path_memory8616 as path_memory
from inertia.ir.core import IRAddress, IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.ssa_function import build_x86_16_ir_predecessor_map
from tests.ir import test_callee_local_feasibility as fixtures

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("target", ["path_byte", "memory_copy", "memory_write", "memory_taint", "store_row", "checker", "binding_class", "binding_constructor", "ordinary_target", "store_data", "eval_atom", "store_clean", "branch_successor"])
def test_foreign_effect_owner_keeps_snapshot_replay(
    target: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A foreign observer cannot be hidden by a previously armed policy."""
    ctx, _proof = fixtures.world(tmp_path, fixtures.SHARED)
    ctx.deadline = time.monotonic() + 30
    ctx.work_units = 0
    hooks = domain._snapshot_omission_hooks_8616(ctx)
    assert hooks is not None
    repeat_noop, readonly = hooks
    block = IRBlock(10, (
        IRInstr("Iop_Add16", IRValue(MemSpace.REG, name="ax", size=2),
                (IRValue(MemSpace.CONST, const=1, size=2),
                 IRValue(MemSpace.CONST, const=2, size=2)), addr=10),
    ), successor_addrs=(30,))
    assert repeat_noop(block)
    assert readonly()
    targets = {
        "path_byte": (path_memory, "_path_byte_8616"),
        "memory_copy": (path_memory.PathMemory8616, "copy"),
        "memory_write": (path_memory.PathMemory8616, "apply_write"),
        "memory_taint": (path_memory.PathMemory8616, "taint"),
        "store_row": (edge, "_kb_store_row_8616"),
        "checker": (domain, "_snapshot_bindings_check_8616"),
        "binding_class": (domain, "_FeasibilityCallBinding8616"),
        "binding_constructor": (domain._FeasibilityCallBinding8616, "__init__"),
        "ordinary_target": (edge, "_ordinary_call_target_8616"),
        "store_data": (edge, "_kb_store_data_8616"),
        "eval_atom": (edge, "_kb_eval_atom_8616"),
        "store_clean": (edge, "store_atom_clean_8616"),
        "branch_successor": (edge, "_cjmp_live_successor_8616"),
    }
    owner, name = targets[target]
    monkeypatch.setattr(owner, name, lambda *args, **kwargs: target == "checker")
    assert not repeat_noop(block), target
    assert not readonly(), target


def test_store_taint_observer_is_not_suppressed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real STORE transfer invokes a foreign taint observer in both paths."""
    ctx, _proof = fixtures.world(tmp_path, fixtures.SHARED)
    ctx.deadline = time.monotonic() + 30
    ctx.work_units = 0
    hooks = domain._snapshot_omission_hooks_8616(ctx)
    assert hooks is not None
    repeat_noop, readonly = hooks
    artifact = IRFunctionArtifact(10, (
        IRBlock(10, (
            IRInstr("STORE", None, (
                IRAddress(space=MemSpace.DS, offset=0x40, size=2),
                IRValue(MemSpace.CONST, const=1, size=2)), addr=10),
        ), successor_addrs=(30,)),
        IRBlock(30, (IRInstr("CALL", None,
                (IRValue(MemSpace.CONST, const=40, size=2),), addr=30),)),
    ))
    assert not edge._kb_snapshot_observed_8616(artifact.blocks[0], has_load_hook=False)
    seen: list[int] = []
    original = path_memory.PathMemory8616.taint

    def observer(memory: path_memory.PathMemory8616) -> None:
        seen.append(1)
        original(memory)

    monkeypatch.setattr(path_memory.PathMemory8616, "taint", observer)

    def run(owned: bool) -> tuple[object, int]:
        seen.clear()
        result = edge.invocation_feasible_scope_8616(
            artifact=artifact, dangerous=frozenset({10, 30}),
            predecessor_map=build_x86_16_ir_predecessor_map(artifact),
            head_addr=10, call_block_addr=30, callsite_addr=30,
            seed={}, seed_memory=path_memory.PathMemory8616(),
            apply_service=lambda *_: False,
            apply_repeat=lambda block, regs, memory, direction:
                domain._apply_repeated_store_8616(ctx, artifact, block, regs, memory, direction, count_store=False)[0],
            repeat_consult_noop=repeat_noop if owned else None,
            load_reader_readonly=readonly if owned else None,
            iteration_limit=64, deadline=time.monotonic() + 5, work_limit=10000,
        )
        return result, len(seen)

    baseline, ordinary_count = run(False)
    optimized, owned_count = run(True)
    assert baseline.converged and optimized.converged
    assert baseline.infeasible_edges == optimized.infeasible_edges
    assert ordinary_count > 0
    assert owned_count == ordinary_count
