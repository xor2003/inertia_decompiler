"""Operation-local protection has bounded admission and no foreign-row surface."""
import time
from types import SimpleNamespace
from typing import cast

import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

pytestmark = pytest.mark.decompiler


def _context(limit: int=1000) -> owner._PathCensusContext8616:
    """Supply only the resource/protection fields this preparation consumes."""
    return cast(owner._PathCensusContext8616,SimpleNamespace(project=object(),manifest=set(),callsite_addr=111,work_units=0,
        accounted_work_units=0,work_limit=limit,deadline=time.monotonic()+10))


def _artifact() -> tuple[IRFunctionArtifact,IRInstr,dict[int,tuple[IRBlock,IRInstr]]]:
    """Provide nine immutable rows and one selected ordinary call."""
    call=IRInstr('CALL',None,(),addr=100,size=3)
    block=IRBlock(100,instrs=(call,*(IRInstr('MOV',None,(),addr=103+i,size=1) for i in range(8))))
    artifact=IRFunctionArtifact(100,(block,))
    return artifact,call,{id(call):(block,call)}


def _boundary(ctx: owner._PathCensusContext8616, artifact: IRFunctionArtifact) -> owner.ExactFunctionRangeBoundary8616:
    """Retain the complete native extent underlying these expanded IR rows."""
    native = SimpleNamespace(addr=100, size=11)
    return owner.ExactFunctionRangeBoundary8616(ctx.project, artifact.function_addr, 11, frozenset({100}),
        frozenset({100, *range(103,111)}), (), (native,))


@pytest.mark.parametrize(('limit','admitted','units'),[(4,True,4),(3,False,4)])
def test_preparation_exact_budget(limit: int,admitted: bool,units: int) -> None:
    """Native extent and ownership checks retain exact-limit admission."""
    ctx=_context(limit)
    artifact,_call,rows=_artifact()
    with segment_call_dependency_traversal_scope_8616():
        assert (owner._feasibility_call_handler_8616(ctx,artifact,_boundary(ctx,artifact),rows) is not None) is admitted
    assert ctx.work_units==units


def test_empty_expired_and_exhausted_skip_preparation() -> None:
    """Admission refuses before traversing caller geometry."""
    artifact,_call,rows=_artifact()
    for kind in ('empty','expired','work','no-callsite'):
        ctx=_context(-1 if kind=='work' else 1000)
        if kind=='expired':
            ctx.deadline=time.monotonic()-1
        if kind=='no-callsite':
            ctx.callsite_addr=None
        with segment_call_dependency_traversal_scope_8616():
            assert owner._feasibility_call_handler_8616(ctx,artifact,_boundary(ctx,artifact),{} if kind=='empty' else rows) is None
        assert ctx.work_units==0


def test_selected_geometry_is_local_and_fetched_manifest_stays_fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    """Copies cannot inject foreign rows; current code spans remain per crossing."""
    ctx=_context()
    artifact,call,rows=_artifact()
    seen=[]
    def reject(_ctx: owner._PathCensusContext8616,_artifact: IRFunctionArtifact,_block: IRBlock,
        _row: IRInstr,_regs: dict[str,int],_memory: owner.PathMemory8616,
        spans: tuple[tuple[int,int],...] | frozenset[tuple[int,int]], *,
        caller_range: owner.ScratchCallerRange8616 | None = None) -> bool:
        assert caller_range is not None
        seen.append(set(spans))
        return False
    monkeypatch.setattr(owner,'_feasibility_call_scratch_8616',reject)
    with segment_call_dependency_traversal_scope_8616():
        apply=owner._feasibility_call_handler_8616(ctx,artifact,_boundary(ctx,artifact),rows)
        assert apply is not None
        for address in (200,300):
            ctx.manifest.add((address,2))
            assert not apply(call,{},owner.PathMemory8616())
        foreign=IRInstr('CALL',None,(),addr=100,size=3)
        rows[id(foreign)]=(artifact.blocks[0],foreign)
        assert not apply(foreign,{},owner.PathMemory8616())
        object.__setattr__(artifact,'blocks',(*artifact.blocks,))
        assert not apply(call,{},owner.PathMemory8616())
    assert len(seen)==2 and (200,2) in seen[0] and (300,2) not in seen[0]
    assert {(200,2),(300,2)}<=seen[1]
    assert ctx.work_units==4
