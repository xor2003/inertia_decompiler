"""Proven early edges must refine later register and memory branch evidence."""
import time
from collections.abc import Callable
from dataclasses import replace
from typing import cast

import pytest

import inertia.ir.real16_edge_feasibility8616 as edge
import tests.ir.test_x86_16_declared_resize_boundary as native
from inertia.ir.core import IRBlock, IRCondition, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.real16_path_memory8616 import PathMemory8616
from inertia.ir.real16_repeated_store8616 import RepeatedStoreStatus8616
from inertia.ir.ssa_function import build_x86_16_ir_predecessor_map


def test_native_chained_diamond_refines_later_branch() -> None:
    """The first dead branch's CX write cannot poison the later JCXZ join."""
    caller=bytes.fromhex("b80000 83f800 7405 b90100 eb03 b90000 e302 ffd1 e80100 c3")
    boot=native._boot(caller)
    project,raw,coverage=native._world(boot,len(caller))
    premise=native._resize_premise(project,coverage,native.MODULE_BASE+20,boot,())
    assert premise.complete, premise.failure
    assert (native.MODULE_BASE,native.MODULE_BASE+8) in premise.infeasible_edges
    assert (native.MODULE_BASE+16,native.MODULE_BASE+18) in premise.infeasible_edges
    mov=next(row for block in raw.blocks for row in block.instrs if row.addr==native.MODULE_BASE+13 and row.op=="MOV" and row.dst.name=="cx")
    source=mov.args[0]
    object.__setattr__(mov,"args",(replace(source,const=1),))
    assert not premise.complete



@pytest.mark.parametrize("initial", ["b80100", "64a10005"])
def test_native_feasible_or_unknown_initial_branch_keeps_call(initial: str) -> None:
    """A feasible alternate CX write or unknown guard must remain obligated."""
    caller=bytes.fromhex(initial + " 83f800 7405 b90100 eb03 b90000 e302 ffd1 e80100 c3")
    boot=native._boot(caller)
    project,_raw,coverage=native._world(boot,len(caller))
    premise=native._resize_premise(project,coverage,native.MODULE_BASE+len(caller)-4,boot,())
    assert not premise.complete
    assert (native.MODULE_BASE+len(bytes.fromhex(initial))+13,native.MODULE_BASE+len(bytes.fromhex(initial))+15) not in premise.infeasible_edges


@pytest.mark.parametrize("initial, complete", [("b80000",True),("b80100",False),("64a10005",False)])
def test_native_memory_diamond_refines_only_dead_write(initial: str, complete: bool) -> None:
    """A removed store stops poisoning LOAD; feasible/unknown stores do not."""
    caller=bytes.fromhex("b80001 8ed8 " + initial + " 83f800 7406 c70600020100 8b0e0002 e302 ffd1 e80100 c3")
    image=caller+b"\xc3"
    mz=bytearray(native._mz(image))
    mz[6:8]=b"\0\0"
    boot=native.program_from_mz_bytes(bytes(mz),native._environment(),code_ranges=(native.LinearRange(native.MODULE_BASE,len(image)),))
    project,_raw,coverage=native._world(boot,len(caller))
    premise=native._resize_premise(project,coverage,native.MODULE_BASE+len(caller)-4,boot,())
    assert premise.complete is complete, premise.failure


def _value(value: int) -> IRValue:
    """One word constant for focused dataflow controls."""
    return IRValue(MemSpace.CONST,const=value,size=2)


def _branch(addr: int, register: str, value: int, target: int) -> IRInstr:
    """Build a typed equality branch without rendered-text recovery."""
    return IRInstr("CJMP",None,(IRCondition("eq",(IRValue(MemSpace.REG,name=register,size=2),_value(value)),width_bits=16),_value(target)),addr=addr)


def _live_source_diamond() -> IRFunctionArtifact:
    """Dead direct edge leaves its source live; predecessor filtering is required."""
    return IRFunctionArtifact(0,(
        IRBlock(0,(IRInstr("MOV",IRValue(MemSpace.REG,name="cx",size=2),(_value(0),),size=2,addr=0),_branch(1,"ax",0,10)),successor_addrs=(10,20)),
        IRBlock(10,(IRInstr("MOV",IRValue(MemSpace.REG,name="cx",size=2),(_value(1),),size=2,addr=10),),successor_addrs=(20,)),
        IRBlock(20,(_branch(20,"cx",1,40),),successor_addrs=(30,40)),
        IRBlock(30,(IRInstr("CALL",None,(),addr=30),),successor_addrs=(40,)),
        IRBlock(40,(IRInstr("NOP",None,(),addr=40),)),
    ))


def _feasible(artifact: IRFunctionArtifact, *, work: int = 10000, iterations: int = 64, deadline: float | None = None, transfer_order: tuple[int, ...] | None = None) -> edge.Real16EdgeFeasibility8616:
    """Run only the existing bounded known-bits interpreter over typed fixture IR."""
    return edge.invocation_feasible_scope_8616(artifact=artifact,dangerous=frozenset(block.addr for block in artifact.blocks),predecessor_map=build_x86_16_ir_predecessor_map(artifact),head_addr=0,call_block_addr=40,callsite_addr=40,seed={"ax":0,"cx":0},seed_memory=PathMemory8616(),apply_service=lambda *_:False,iteration_limit=iterations,deadline=time.monotonic()+5 if deadline is None else deadline,work_limit=work,transfer_order=transfer_order)


@pytest.mark.parametrize("order", [(0, 10, 20, 30, 40, 999), (0, 10, 20, 40), (0, 10, 20, 30, 30)])
def test_malformed_original_order_cannot_publish_pruning(order: tuple[int, ...]) -> None:
    """Validate the original complete proposal before filtering refined live blocks."""
    result = _feasible(_live_source_diamond(), transfer_order=order)
    assert not result.converged
    assert not result.infeasible_edges
    assert result.work_units == 0
    assert result.live_blocks == frozenset({0, 10, 20, 30, 40})


def test_live_source_dead_edge_is_filtered_from_next_round() -> None:
    """Removing blocks alone cannot repair a dead edge between live blocks."""
    result=_feasible(_live_source_diamond())
    assert result.converged
    assert result.infeasible_edges==((0,20),(20,30))
    assert result.live_blocks==frozenset({0,10,20,40})


def test_snapshot_budget_keeps_branchless_effects_in_fixpoint() -> None:
    """Discarded pure snapshot exits must not exhaust a small valid proof budget."""
    def arm(address: int, value: int) -> IRBlock:
        """Keep enough genuine transfers to distinguish a full second walk."""
        rows = tuple(
            IRInstr("Iop_Add16", IRValue(MemSpace.REG, name="cx", size=2),
                    (_value(value), _value(offset)), size=2, addr=address + offset)
            for offset in range(8)
        )
        return IRBlock(address, (*rows, IRInstr("JMP", None, (_value(40),), addr=address + 8)),
                       successor_addrs=(40,))

    artifact = IRFunctionArtifact(0, (
        IRBlock(0, (_branch(0, "bx", 0, 10),), successor_addrs=(10, 20)),
        arm(10, 1), arm(20, 2),
        IRBlock(40, (IRInstr("RET", None, (), addr=40),)),
    ))
    result = _feasible(artifact, work=30)
    assert result.converged
    assert result.evaluated_cjmps == 1
    assert not result.infeasible_edges
    assert result.live_blocks == frozenset({0, 10, 20, 40})
    assert result.work_units <= 30


def test_branchless_load_snapshot_still_invokes_hook() -> None:
    """A discarded block exit does not make its external LOAD hook disposable."""
    load = IRInstr("LOAD", IRValue(MemSpace.TMP, source_tmp=1, size=2),
                   (_value(0),), size=2, addr=0)
    artifact = IRFunctionArtifact(0, (
        IRBlock(0, (load,), successor_addrs=(40,)),
        IRBlock(40, (IRInstr("RET", None, (), addr=40),)),
    ))
    seen: list[IRInstr] = []

    def read_load(instruction: IRInstr, _span: tuple[int, int] | None,
                  _memory: PathMemory8616) -> int | None:
        """Record both transfer and fresh snapshot consumption."""
        seen.append(instruction)
        return None

    result = edge.invocation_feasible_scope_8616(
        artifact=artifact, dangerous=frozenset({0, 40}),
        predecessor_map=build_x86_16_ir_predecessor_map(artifact),
        head_addr=0, call_block_addr=40, callsite_addr=40,
        seed={}, seed_memory=PathMemory8616(), apply_service=lambda *_: False,
        read_load=read_load, iteration_limit=64,
        deadline=time.monotonic() + 5, work_limit=100,
    )
    assert result.converged
    assert seen == [load, load]


def test_mid_refinement_exhaustion_keeps_only_committed_round(monkeypatch: pytest.MonkeyPatch) -> None:
    """The next round shares the original budget/deadline and leaks no facts."""
    original=cast(Callable[..., object], edge._kb_fixpoint_8616)
    calls: list[tuple[object, list[int], int, object]]=[]
    def bounded(*args: object, **kwargs: object) -> object:
        """Exhaust the same work cell before a second dataflow round can close."""
        budget=cast(list[int], args[10])
        calls.append((args[9],budget,budget[0],kwargs["infeasible_edges"]))
        if len(calls)==2:
            assert budget is calls[0][1]
            assert args[9]==calls[0][0]
            assert budget[0]<calls[0][2]
            budget[0]=0
            return None
        return original(*args,**kwargs)
    monkeypatch.setattr(edge,"_kb_fixpoint_8616",bounded)
    result=_feasible(_live_source_diamond())
    assert len(calls)==2
    assert result.converged
    assert result.infeasible_edges==((0,20),)
    assert 30 in result.live_blocks
    assert result.work_units==10000


@pytest.mark.parametrize("work, iterations, deadline", [(0,64,None),(10000,0,None),(10000,64,0.0)])
def test_initial_budget_or_deadline_exhaustion_publishes_nothing(work: int, iterations: int, deadline: float | None) -> None:
    """No completed first round means no pruning or convergence claim."""
    result=_feasible(_live_source_diamond(),work=work,iterations=iterations,deadline=deadline)
    assert not result.converged
    assert not result.infeasible_edges
    assert result.live_blocks==frozenset({0,10,20,30,40})


def test_round_cap_keeps_only_completed_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    """A finite refinement cap cannot authorize the as-yet unresolved branch."""
    monkeypatch.setattr(edge,"_EDGE_REFINEMENT_ROUND_LIMIT_8616",1)
    result=_feasible(_live_source_diamond())
    assert result.converged
    assert result.infeasible_edges==((0,20),)
    assert 30 in result.live_blocks


def test_loop_seed_is_not_a_converged_branch_fact() -> None:
    """Backedge disagreement invalidates the initially known seed condition."""
    artifact=IRFunctionArtifact(0,(
        IRBlock(0,(_branch(0,"cx",0,40),),successor_addrs=(10,40)),
        IRBlock(10,(IRInstr("MOV",IRValue(MemSpace.REG,name="cx",size=2),(_value(1),),size=2,addr=10),),successor_addrs=(0,)),
        IRBlock(40,(IRInstr("NOP",None,(),addr=40),)),
    ))
    assert not _feasible(artifact,iterations=1).infeasible_edges
    result=_feasible(artifact)
    assert result.converged and not result.infeasible_edges


def test_later_call_revocation_keeps_earlier_branch_obligated() -> None:
    """A later callback can revoke the evidence for an unchanged predecessor."""
    artifact = IRFunctionArtifact(0, (
        IRBlock(0, (IRInstr("CALL", None, (_value(100),), addr=0),
                    _branch(1, "ax", 0, 10)), successor_addrs=(10, 20)),
        IRBlock(10, (IRInstr("CALL", None, (_value(200),), addr=10),),
                successor_addrs=(30,)),
        IRBlock(20, successor_addrs=(30,)),
        IRBlock(30),
    ))
    authority_current = True
    calls: list[tuple[int | None, bool]] = []

    def authenticate_call(row: IRInstr, registers: dict[str, int],
                          _memory: PathMemory8616) -> bool:
        """The second call invalidates the first call's previously known AX."""
        nonlocal authority_current
        target = row.args[0].const
        calls.append((target, authority_current))
        if target == 200:
            authority_current = False
            return True
        if not authority_current:
            return False
        registers["ax"] = 0
        return True

    result = edge.invocation_feasible_scope_8616(
        artifact=artifact, dangerous=frozenset({0, 10, 20, 30}),
        predecessor_map=build_x86_16_ir_predecessor_map(artifact),
        head_addr=0, call_block_addr=30, callsite_addr=30,
        seed={"ax": 1}, seed_memory=PathMemory8616(),
        apply_service=lambda *_: False, apply_call=authenticate_call,
        iteration_limit=64, deadline=time.monotonic() + 5, work_limit=10000,
    )
    assert (100, True) in calls and (200, True) in calls
    assert (100, False) in calls
    assert result.converged
    assert not result.infeasible_edges
    assert result.live_blocks == frozenset({0, 10, 20, 30})


@pytest.mark.parametrize("callback", ["call", "repeat"])
def test_downstream_callback_cannot_leave_opposite_dead_edges(callback: str) -> None:
    """Callbacks may change upstream IR even without a forward data dependency."""
    source = _value(0)
    call_rows = (IRInstr("CALL", None, (_value(200),), addr=10),) if callback == "call" else ()
    artifact = IRFunctionArtifact(0, (
        IRBlock(0, (IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2),
                           (source,), size=2, addr=0), _branch(1, "ax", 0, 10)),
                successor_addrs=(10, 20)),
        IRBlock(10, call_rows, successor_addrs=(30,)),
        IRBlock(20, successor_addrs=(30,)),
        IRBlock(30),
    ))
    consulted: list[int] = []

    def apply_call(row: IRInstr, _registers: dict[str, int],
                   _memory: PathMemory8616) -> bool:
        """Mutate a previously interpreted source through the call boundary."""
        consulted.append(row.addr)
        object.__setattr__(source, "const", 1)
        return True

    def apply_repeat(block: IRBlock, _registers: dict[str, int],
                     _memory: PathMemory8616, _direction: bool | None) -> RepeatedStoreStatus8616:
        """NOT_APPLICABLE is a result, not a promise of callback purity."""
        consulted.append(block.addr)
        if block.addr == 10:
            object.__setattr__(source, "const", 1)
        return RepeatedStoreStatus8616.NOT_APPLICABLE

    result = edge.invocation_feasible_scope_8616(
        artifact=artifact, dangerous=frozenset({0, 10, 20, 30}),
        predecessor_map=build_x86_16_ir_predecessor_map(artifact),
        head_addr=0, call_block_addr=30, callsite_addr=30,
        seed={}, seed_memory=PathMemory8616(), apply_service=lambda *_: False,
        apply_call=apply_call if callback == "call" else None,
        apply_repeat=apply_repeat if callback == "repeat" else None,
        iteration_limit=64, deadline=time.monotonic() + 5, work_limit=10000,
    )
    assert 10 in consulted
    assert result.converged
    assert result.infeasible_edges == ((0, 10),)
    assert 20 in result.live_blocks
