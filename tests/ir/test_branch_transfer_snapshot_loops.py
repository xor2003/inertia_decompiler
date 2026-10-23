"""Loop backedge must-meet must overwrite provisional branch snapshots."""

import pytest

from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.real16_path_memory8616 import PathMemory8616
from tests.ir.test_branch_transfer_snapshots import _observations, _run
from tests.ir.test_x86_16_invocation_edge_refinement import _branch, _value

pytestmark = pytest.mark.decompiler


def _inner_branch_loop(back_value: int) -> IRFunctionArtifact:
    """Block 20's branch first transfers on the forward predecessor alone."""
    return IRFunctionArtifact(0, (
        IRBlock(0, (IRInstr("JMP", None, (_value(10),), addr=0),),
                successor_addrs=(10,)),
        IRBlock(10, (IRInstr("MOV", IRValue(MemSpace.REG, name="cx", size=2),
                             (_value(0),), size=2, addr=10),),
                successor_addrs=(20,)),
        IRBlock(20, (_branch(20, "cx", 0, 40),), successor_addrs=(30, 40)),
        IRBlock(30, (IRInstr("MOV", IRValue(MemSpace.REG, name="cx", size=2),
                             (_value(back_value),), size=2, addr=30),),
                successor_addrs=(20,)),
        IRBlock(40, (IRInstr("RET", None, (), addr=40),)),
    ))


def test_pure_transfer_loop_never_publishes_provisional_pruning():
    """Backedge must-meet revokes the first-iteration branch observation."""
    artifact = _inner_branch_loop(1)
    baseline = _run(artifact)
    assert baseline.converged
    assert baseline.evaluated_cjmps == 1
    assert not baseline.infeasible_edges
    actual = _run(artifact, pure=True)
    assert _observations(actual) == _observations(baseline)


def test_pure_transfer_loop_agreeing_backedge_keeps_pruning():
    """A backedge that agrees with the forward value proves the pruning real."""
    artifact = _inner_branch_loop(0)
    baseline = _run(artifact)
    actual = _run(artifact, pure=True)
    assert baseline.converged
    assert baseline.infeasible_edges == ((20, 30),)
    assert baseline.live_blocks == frozenset({0, 10, 20, 40})
    assert _observations(actual) == _observations(baseline)


def test_pure_transfer_head_seed_revoked_by_backedge():
    """The head's own seed cannot outlive a disagreeing backedge write."""
    artifact = IRFunctionArtifact(0, (
        IRBlock(0, (_branch(0, "cx", 0, 40),), successor_addrs=(10, 40)),
        IRBlock(10, (IRInstr("MOV", IRValue(MemSpace.REG, name="cx", size=2),
                             (_value(1),), size=2, addr=10),),
                successor_addrs=(0,)),
        IRBlock(40, (IRInstr("RET", None, (), addr=40),)),
    ))
    baseline = _run(artifact)
    actual = _run(artifact, pure=True)
    assert baseline.converged
    assert not baseline.infeasible_edges
    assert _observations(actual) == _observations(baseline)


def test_observable_load_reader_keeps_fresh_snapshot_replay():
    """A hooked LOAD under OBSERVABLE replay falls back to fresh snapshots."""
    load = IRInstr("LOAD", IRValue(MemSpace.TMP, source_tmp=1, size=2),
                   (_value(0x200),), size=2, addr=0)
    artifact = IRFunctionArtifact(0, (
        IRBlock(0, (load, _branch(1, "cx", 0, 40)), successor_addrs=(10, 40)),
        IRBlock(10, (IRInstr("NOP", None, (), addr=10),), successor_addrs=(40,)),
        IRBlock(40, (IRInstr("RET", None, (), addr=40),)),
    ))
    reads: list[int] = []

    def read_load(instruction: IRInstr, _span: tuple[int, int] | None,
                  _memory: PathMemory8616) -> int | None:
        """Count every consultation; the fixpoint alone cannot reach three."""
        reads.append(instruction.addr)
        return None

    baseline = _run(artifact, read_load=read_load)
    expected = len(reads)
    reads.clear()
    actual = _run(artifact, pure=True, read_load=read_load)
    assert len(reads) == expected and expected >= 3
    assert actual == baseline
