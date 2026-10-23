"""Optional current snapshot CALL state is detached data, never admission."""
import time
from dataclasses import replace

import pytest

pytestmark = pytest.mark.decompiler

import inertia.ir.real16_edge_feasibility8616 as owner
from inertia.ir.core import IRBlock, IRCondition, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.real16_path_memory8616 import PathMemory8616


def world():
    row = IRInstr("CALL", dst=None, args=(IRValue(MemSpace.CONST, const=0x30, size=2),), addr=0x10)
    block = IRBlock(0x10, instrs=(row,))
    return IRFunctionArtifact(0x10, (block,)), block, row


def run(artifact, request=None, **changes):
    calls = []

    def apply(row, regs, memory):
        calls.append(row)
        memory.apply_write(0x200, 1, b"x")
        return True

    kwargs = {
        "artifact": artifact, "dangerous": frozenset(b.addr for b in artifact.blocks),
                  "predecessor_map": {}, "head_addr": artifact.function_addr, "call_block_addr": 0x99,
                  "callsite_addr": 0x99, "seed": {"ax": 7, "flags": 0x400},
                  "seed_memory": PathMemory8616({0x100: 3}, {0x101}),
                  "apply_service": lambda *args: False, "apply_call": apply, "iteration_limit": 8,
                  "deadline": time.monotonic() + 10, "work_limit": 10000}
    kwargs.update(changes)
    if request is not None:
        kwargs["call_cut"] = request
    return owner.invocation_feasible_scope_8616(**kwargs), calls


def test_capture_before_effect_detached_without_extra_callbacks():
    artifact, block, row = world()
    baseline, calls = run(artifact)
    result, observed = run(artifact, owner.Real16CallCutRequest8616(artifact, block, 0, row))
    cut = result.call_cut
    assert cut is not None
    assert cut.artifact is artifact and cut.block is block and cut.instruction is row
    assert dict(cut.registers)["ax"] == 7 and cut.direction is True
    assert cut.memory_known == ((0x100, 3),) and cut.memory_unknown == (0x101,)
    assert observed == calls
    assert result.work_units > baseline.work_units
    assert baseline.call_cut is None


@pytest.mark.parametrize("change", ["foreign", "index", "nonterminal", "unreachable"])
def test_bad_exact_request_has_no_witness(change):
    artifact, block, row = world()
    request = owner.Real16CallCutRequest8616(artifact, block, 0, row)
    if change == "foreign":
        request = replace(request, instruction=replace(row))
    elif change == "index":
        request = replace(request, index=-1)
    elif change == "nonterminal":
        block = replace(block, instrs=(row, IRInstr("RET", None, (), addr=0x11)))
        artifact = replace(artifact, blocks=(block,))
        request = replace(request, artifact=artifact, block=block)
    else:
        artifact = IRFunctionArtifact(1, (IRBlock(1), block))
        request = replace(request, artifact=artifact)
    result, _ = run(artifact, request)
    assert result.call_cut is None


@pytest.mark.parametrize("changes", [{"work_limit": 0}, {"deadline": 0}, {"iteration_limit": 1}])
def test_incomplete_round_never_publishes_cut(changes):
    artifact, block, row = world()
    result, _ = run(artifact, owner.Real16CallCutRequest8616(artifact, block, 0, row), **changes)
    assert result.call_cut is None


def diamond():
    reg = IRValue(MemSpace.REG, name="bx", size=2)
    const = IRValue(MemSpace.CONST, const=0, size=2)
    branch = IRInstr("CJMP", None, (IRCondition("eq", (reg, const)),
                                   IRValue(MemSpace.CONST, const=0x20, size=2)), addr=0x10)
    blocks = [IRBlock(0x10, (branch,), successor_addrs=(0x20, 0x30))]
    for addr, value in ((0x20, 7), (0x30, 9)):
        move = IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2),
                       (IRValue(MemSpace.CONST, const=value, size=2),), size=2, addr=addr)
        blocks.append(IRBlock(addr, (move,), successor_addrs=(0x40,)))
    row = IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x50, size=2),), addr=0x40)
    block = IRBlock(0x40, (row,))
    blocks.append(block)
    artifact = IRFunctionArtifact(0x10, tuple(blocks))
    return artifact, owner.Real16CallCutRequest8616(artifact, block, 0, row)


@pytest.mark.parametrize("known_branch", [False, True])
def test_join_snapshot_is_final_round_and_callbacks_are_not_added(known_branch):
    artifact, request = diamond()
    kwargs = {"predecessor_map": {0x20: (0x10,), 0x30: (0x10,), 0x40: (0x20, 0x30)},
                  "call_block_addr": 0x40, "callsite_addr": 0x40, "seed": {"bx": 0} if known_branch else {}}
    baseline, calls = run(artifact, **kwargs)
    result, observed = run(artifact, request, **kwargs)
    assert result.call_cut is not None
    assert observed == calls
    assert result.infeasible_edges == baseline.infeasible_edges
    if known_branch:
        assert dict(result.call_cut.registers)["ax"] == 7
    else:
        assert "ax" not in dict(result.call_cut.registers)


def test_committed_pruning_without_recomputed_round_has_no_current_cut(monkeypatch):
    artifact, request = diamond()
    monkeypatch.setattr(owner, "_EDGE_REFINEMENT_ROUND_LIMIT_8616", 1)
    result, _ = run(artifact, request, predecessor_map={0x20: (0x10,), 0x30: (0x10,),
                                                     0x40: (0x20, 0x30)},
                    call_block_addr=0x40, callsite_addr=0x40, seed={"bx": 0})
    assert result.converged and result.infeasible_edges
    assert result.call_cut is None


def test_partial_snapshot_discards_captured_data(monkeypatch):
    artifact, block, row = world()
    original = owner._kb_cjmp_snapshots_8616

    def incomplete(*args, **kwargs):
        original(*args, **kwargs)
        return None

    monkeypatch.setattr(owner, "_kb_cjmp_snapshots_8616", incomplete)
    result, _ = run(artifact, owner.Real16CallCutRequest8616(artifact, block, 0, row))
    assert result.call_cut is None


def test_memory_snapshot_is_detached_from_seed_and_callback_mutation():
    artifact, block, row = world()
    memory = PathMemory8616({0x100: 3}, {0x101})
    result, _ = run(artifact, owner.Real16CallCutRequest8616(artifact, block, 0, row),
                    seed_memory=memory)
    memory.known[0x100] = 99
    memory.unknown.clear()
    assert result.call_cut.memory_known == ((0x100, 3),)
    assert result.call_cut.memory_unknown == (0x101,)


def test_tainted_pre_call_memory_has_no_witness():
    artifact, block, row = world()
    result, _ = run(artifact, owner.Real16CallCutRequest8616(artifact, block, 0, row),
                    seed_memory=PathMemory8616(tainted=True))
    assert result.call_cut is None


def test_final_ownership_exhaustion_drops_only_optional_witness():
    artifact, block, row = world()
    request = owner.Real16CallCutRequest8616(artifact, block, 0, row)
    complete, _ = run(artifact, request)
    exhausted, _ = run(artifact, request, work_limit=complete.work_units - 1)
    assert exhausted.converged
    assert exhausted.call_cut is None


def test_preceding_return_cannot_publish_later_call_state():
    artifact, block, row = world()
    block = replace(block, instrs=(IRInstr("RET", None, (), addr=0xF), row))
    artifact = replace(artifact, blocks=(block,))
    result, _ = run(artifact, owner.Real16CallCutRequest8616(artifact, block, 1, row))
    assert result.call_cut is None


def test_default_walk_never_invokes_cut_observer(monkeypatch):
    artifact, _, _ = world()

    def forbidden(*args):
        raise AssertionError("default feasibility invoked optional cut observer")

    monkeypatch.setattr(owner, "_observe_call_cut_8616", forbidden)
    result, calls = run(artifact)
    assert result.converged and result.call_cut is None
    assert calls


@pytest.mark.parametrize("stage", ["validation", "sorting"])
def test_expiry_after_final_validation_or_sorting_drops_only_cut(monkeypatch, stage):
    artifact, block, row = world()
    request = owner.Real16CallCutRequest8616(artifact, block, 0, row)
    clock = [100.0]
    monkeypatch.setattr(owner.time, "monotonic", lambda: clock[0])
    if stage == "validation":
        original = owner._call_cut_owned_8616
        validations = []

        def validate(*args, **kwargs):
            result = original(*args, **kwargs)
            validations.append(result)
            if len(validations) == 2:
                clock[0] = 102.0
            return result

        monkeypatch.setattr(owner, "_call_cut_owned_8616", validate)
    else:
        original = sorted

        def sort(values, *args, **kwargs):
            result = original(values, *args, **kwargs)
            if isinstance(values, frozenset) and not values:
                clock[0] = 102.0
            return result

        monkeypatch.setattr(owner, "sorted", sort, raising=False)
    result, _ = run(artifact, request, deadline=101.0)
    assert result.converged
    assert result.call_cut is None


def test_absent_cut_publication_does_not_read_clock(monkeypatch):
    def forbidden():
        raise AssertionError("absent cut publication added a deadline read")

    monkeypatch.setattr(owner.time, "monotonic", forbidden)
    assert owner._current_call_cut_8616(None, [0], 0) is None
