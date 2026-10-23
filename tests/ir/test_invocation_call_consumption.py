"""Real typed call proofs authenticate register projection once per use."""
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import real16_invocation_domain as owner
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.ir.segment_call_preservation import (
    SegmentCallPreservationResult8616,
    prove_segment_call_preservation_8616,
    segment_call_dependency_traversal_scope_8616,
)
from inertia.ir.segment_effect_closure import prove_segment_effect_closure_8616
from inertia.ir.segment_state import build_x86_16_segment_state_artifact

pytestmark = pytest.mark.decompiler


def _call_context(**fields: object) -> SimpleNamespace:
    """Provide call-consumption bookkeeping without enabling prefix capture."""
    return SimpleNamespace(
        work_units=0, accounted_work_units=0, prefix_capture_requested=False,
        work_limit=owner._CENSUS_WORK_LIMIT_8616, deadline=float("inf"),
        **fields,
    )


_CALLER_CODE = bytes.fromhex("e8fd0fc3")  # call 0x2000; ret
_CALLEE_CODE = bytes.fromhex("b800b8c3")  # mov ax,0xb800; ret


def _load_native_bytes_8616(addr: int, size: int) -> bytes:
    """Serve retained native bytes for the two mock block extents."""
    for base, code in ((0x1000, _CALLER_CODE), (0x2000, _CALLEE_CODE)):
        if base <= addr and addr + size <= base + len(code):
            return code[addr - base: addr - base + size]
    return b""


def _decoded_block_8616(addr: int, code: bytes,
                        extents: tuple[tuple[int, int], ...]) -> object:
    """Mint the decoded-block surface bound-block authentication reads."""
    return SimpleNamespace(
        addr=addr, size=len(code), bytes=code,
        capstone=SimpleNamespace(insns=tuple(
            SimpleNamespace(address=head, size=size) for head, size in extents)),
    )


def _world(no_cs: bool = False) -> tuple:
    # Bound-block authentication requires a real arch, live loader bytes and
    # retained decoded blocks; the mock supplies that exact surface.
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=SimpleNamespace(load=_load_native_bytes_8616)),
    )
    call = IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1000)
    caller = IRFunctionArtifact(0x1000, (IRBlock(0x1000, instrs=(call,IRInstr("RET",None,(),addr=0x1003))),))
    instructions = ((IRInstr("MOV",IRValue(MemSpace.REG,name="cs",size=2),(IRValue(MemSpace.CONST,const=0,size=2),),addr=0x2000),) if no_cs else ())
    callee = IRFunctionArtifact(0x2000,(IRBlock(0x2000,instrs=(*instructions,IRInstr("RET",None,(),addr=0x2003))),))
    for artifact in (caller,callee):
        publish_function_ir_artifact_8616(project, artifact)
    def coverage(artifact: IRFunctionArtifact) -> object:
        code = _CALLER_CODE if artifact.function_addr == 0x1000 else _CALLEE_CODE
        boundary=ExactFunctionRangeBoundary8616(project,artifact.function_addr,4,frozenset({artifact.function_addr}),frozenset(row.addr for row in artifact.blocks[0].instrs),(),
            blocks=(_decoded_block_8616(artifact.function_addr, code,
                ((artifact.function_addr, 3), (artifact.function_addr + 3, 1))),))
        return prove_ir_boundary_coverage_8616(project,boundary,artifact)
    closure=prove_segment_effect_closure_8616(coverage(callee),build_x86_16_segment_state_artifact(callee))
    entry=DecodedDirectCallsite8616(0x1000,(SimpleNamespace(address=0x1000),),0,0x1000,0x2000)
    index=DecodedDirectCallsiteIndex8616({0x2000:(entry,)},DecodedDirectCallsiteIndexStats8616(1,1,1,1,0))
    proof=prove_segment_call_preservation_8616(coverage(caller),closure,index,0x1000)
    assert proof.complete
    return project,caller,call,proof


def test_single_projection_keeps_selection_and_post_simulation_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Registry selection and both projections retain their three freshness checks."""
    _project,artifact,call,proof=_world()
    calls=[]
    original=SegmentCallPreservationResult8616.complete_for
    def complete(self: SegmentCallPreservationResult8616, scope: object) -> bool:
        calls.append(1)
        return original(self,scope)
    monkeypatch.setattr(SegmentCallPreservationResult8616,"complete_for",complete)
    selected=[]
    selector=owner.bound_call_preservation_at_instruction_8616
    def select(*args: object) -> object:
        result=selector(*args)
        selected.append(len(calls))
        return result
    monkeypatch.setattr(owner,"bound_call_preservation_at_instruction_8616",select)
    simulated=[]
    def simulate(ctx: object, actual: object, state: owner._PathState8616) -> dict:
        simulated.append(len(calls))
        return {0x2000:state}
    monkeypatch.setattr(owner,"_simulate_callee_8616",simulate)
    ctx=_call_context(callsite_addr=0x1003,call_preservations=(proof,),entry_call_preservations=(),selector=0x100,chain=None)
    assert owner._cross_call_8616(ctx,artifact,artifact.blocks[0],call,{"cs":0x100,"sp":0x80},owner.PathMemory8616()) is None
    assert selected == [0]
    assert simulated == [2]
    assert len(calls) == 3


@pytest.mark.parametrize("mode", ["foreign", "foreign_scope", "no_cs", "mutation_after"])
def test_real_proof_refusal_and_post_simulation_freshness(mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Foreign proof/no CS refuse; callback mutation is rechecked after simulation."""
    project,artifact,call,proof=_world(no_cs=mode=="no_cs")
    if mode=="foreign":
        proof=replace(proof,caller=replace(proof.caller,boundary=replace(proof.caller.boundary,project=object())))
    if mode == "foreign_scope":
        foreign = owner.prove_real16_declared_function_entry_domain_8616(object(), None, 0x1000, boot=None, boot_recompute=None)
        proof = replace(proof, invocation_scope=foreign)
    seen=[]
    def simulate(ctx: object, actual: object, state: owner._PathState8616) -> dict:
        seen.append(1)
        project._inertia_function_ir_artifacts_8616[0x2000]=IRFunctionArtifact(0x2001,())
        state.memory.apply_write(0x3000, 1, b"\x55")
        return {0x2000:state}
    monkeypatch.setattr(owner,"_simulate_callee_8616",simulate)
    ctx=_call_context(callsite_addr=0x1003,call_preservations=(proof,),entry_call_preservations=(),selector=0x100,
                        project=project,chain=None,boot=object(),image=SimpleNamespace(file_sha256=""))
    registers={"cs":0x100,"sp":0x80}
    memory=owner.PathMemory8616(known={0x3010:0x12}, unknown={0x3011})
    before=memory.copy()
    result=owner._cross_call_8616(ctx,artifact,artifact.blocks[0],call,registers,memory)
    assert memory == before
    if mode=="mutation_after":
        assert seen == [1]
        assert result is owner.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
        assert registers == {"cs":0x100,"sp":0x80}
    else:
        assert result is owner.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
        assert not seen


@pytest.mark.parametrize("malformed", [None, object()])
def test_malformed_closure_coverage_refuses_before_field_access(malformed: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """A malformed typed closure cannot bypass projection reauthentication."""
    _project, artifact, call, proof = _world()
    canonical = owner.bound_call_preservation_at_instruction_8616
    def selected_then_malformed(*args: object) -> object:
        selected = canonical(*args)
        assert selected is proof
        return replace(proof, callee=replace(proof.callee, coverage=malformed))
    monkeypatch.setattr(owner, "bound_call_preservation_at_instruction_8616", selected_then_malformed)
    def unexpected_simulation(*args: object) -> object:
        pytest.fail("malformed coverage reached simulation")
    monkeypatch.setattr(owner, "_simulate_callee_8616", unexpected_simulation)
    ctx = _call_context(callsite_addr=0x1003,call_preservations=(proof,),entry_call_preservations=(),selector=0x100,chain=None)
    assert owner._cross_call_8616(ctx,artifact,artifact.blocks[0],call,{},owner.PathMemory8616()) is owner.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


@pytest.mark.parametrize("offset", [0, -1, 1])
def test_shared_budget_boundary_preserves_existing_limit(offset: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exhausted requests avoid body work; equality keeps the canonical path."""
    calls = []
    expected = owner._early_derivation_8616(owner.Real16InvocationFailure8616.CALLSITE_UNREACHABLE)
    def body(*args: object, **kwargs: object) -> owner._Derivation8616:
        calls.append(1)
        return expected
    monkeypatch.setattr(owner, "_derive_invocation_domain_body_8616", body)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = time.monotonic() + 100.0
        traversal.census_work_units = owner._CENSUS_WORK_LIMIT_8616 + offset
        result = owner._derive_invocation_domain_8616(object(), None, 0, object(), None, ())
        assert traversal.census_work_units == owner._CENSUS_WORK_LIMIT_8616 + offset
    if offset > 0:
        assert calls == []
        assert result.failure is owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
        assert (result.raw_fact_count, result.classified_fact_count, result.materialized_count, result.failure_count) == (0,0,0,0)
    else:
        assert calls == [1] and result is expected


def test_expired_deadline_keeps_precedence_over_exhausted_work(monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing deadline refusal wins and no body work begins."""
    def unexpected(*args: object, **kwargs: object) -> object:
        pytest.fail("expired request entered expensive derivation body")
    monkeypatch.setattr(owner, "_derive_invocation_domain_body_8616", unexpected)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = 0.0
        traversal.census_work_units = owner._CENSUS_WORK_LIMIT_8616 + 1
        result = owner._derive_invocation_domain_8616(object(), None, 0, object(), None, ())
    assert result.failure is owner.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
