"""One invocation owns caller projection while every crossing stays fresh."""
from collections import Counter
from collections.abc import Callable

import pytest

from inertia.ir import real16_invocation_domain as owner
from tests.ir.test_native_call_feasibility import _branch_world
from tests.ir.test_raw_callee_scoped_call_chain import _collect
from tests.ir.test_raw_callee_scoped_call_chain import calls_with_pending_helper as calls_with_pending_helper

pytestmark = pytest.mark.decompiler


def test_one_caller_preparation(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """Count operation-local preparations without changing any native proof."""
    world=_branch_world(calls_with_pending_helper)
    original=owner._dosbox_resize_code_spans_8616
    preparations: Counter[int]=Counter()
    retained: list[owner._PathCensusContext8616]=[]
    def projected(ctx: owner._PathCensusContext8616,artifact: owner.IRFunctionArtifact) -> tuple[tuple[int,int],...]:
        if artifact.function_addr==world[2].function_addr:
            preparations[id(ctx)]+=1
            retained.append(ctx)
        return original(ctx,artifact)
    monkeypatch.setattr(owner,'_dosbox_resize_code_spans_8616',projected)
    handler=owner._feasibility_call_handler_8616
    def counted(ctx: owner._PathCensusContext8616,artifact: owner.IRFunctionArtifact,boundary: owner.ExactFunctionRangeBoundary8616,rows: dict[int,tuple[owner.IRBlock,owner.IRInstr]]) -> Callable[[owner.IRInstr,dict[str,int],owner.PathMemory8616],bool] | None:
        if artifact.function_addr==world[2].function_addr and rows:
            preparations[id(ctx)]+=1
            retained.append(ctx)
        return handler(ctx,artifact,boundary,rows)
    monkeypatch.setattr(owner,'_feasibility_call_handler_8616',counted)
    records=_collect(world)
    assert len(records)==2 and all(record.failure is None for record in records)
    call_states=[dict(ctx.callsite_call_state) for ctx in retained
                 if ctx.callsite_call_state is not None]
    assert call_states and all(state.get('bx')==1 for state in call_states)
    assert preparations and max(preparations.values())==1


@pytest.mark.parametrize('mutation',['row-address','row-size','native-byte'])
def test_after_prepare_caller_mutation_refuses(calls_with_pending_helper: tuple,monkeypatch: pytest.MonkeyPatch,mutation: str) -> None:
    """Fresh native/caller authentication must reject mutation after capture."""
    world=_branch_world(calls_with_pending_helper)
    original=owner._feasibility_call_effect_8616
    seen=[]
    def changed(ctx: owner._PathCensusContext8616,artifact: owner.IRFunctionArtifact,block: owner.IRBlock,instruction: owner.IRInstr,state: owner._PathState8616, *, caller_range: owner.ScratchCallerRange8616 | None = None) -> bool:
        row=next(row for member in artifact.blocks for row in member.instrs if row.addr is not None and row is not instruction and row.addr!=instruction.addr)
        field='addr' if mutation=='row-address' else 'size'
        before=row.addr if field=='addr' else row.size
        encoded=None
        if mutation=='native-byte':
            encoded=ctx.project.loader.memory.load(row.addr,1)
            ctx.project.loader.memory.store(row.addr,bytes([encoded[0]^1]))
        else:
            object.__setattr__(row,field,before+1)
        try:
            result=original(ctx,artifact,block,instruction,state,caller_range=caller_range)
            seen.append(result)
            return result
        finally:
            if mutation=='native-byte':
                ctx.project.loader.memory.store(row.addr,encoded)
            else:
                object.__setattr__(row,field,before)
    monkeypatch.setattr(owner,'_feasibility_call_effect_8616',changed)
    _collect(world)
    assert seen and not any(seen)
