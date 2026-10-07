"""Source-bound near-CALL CFG discovery and refusal controls.

These exercise the production ``frontend_cfg_direct_call`` module directly:
resolver outcome, typed evidence, refusal preservation, registration
idempotence, and non-x86-16 / non-call isolation.
"""
from __future__ import annotations

import copy
import io

import angr
import cle
import pytest
import pyvex
from angr.analyses.cfg.indirect_jump_resolvers.default_resolvers import DEFAULT_RESOLVERS
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.vex_import import _block_to_ir

from inertia.frontend.x86_16.frontend_cfg_direct_call import (
    NativeDirectCallResolver8616,
    native_direct_call_evidence_8616,
    register_native_direct_call_resolver_8616,
)
from inertia.frontend.x86_16.frontend_cfg_direct_jump import NativeDirectJumpResolver8616
from inertia.frontend.x86_16.frontend_direct_callsite_index import DecodedDirectCallsite8616
from inertia.frontend.x86_16.relative_control_edge import (
    RelativeEdgeRefusal,
    RelativeEdgeRefusalReason,
)
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallTargetBinding8616,
    DirectNearCallTargetBindingFailure8616,
    DirectNearCallTargetBindingStats8616,
    DirectNearCallTargetBindingVerdict8616,
    prove_direct_near_call_target_binding_from_decoded_8616,
)
from inertia.cli.project_loading import _build_project_from_bytes

_CODE = (
    bytes.fromhex("e80d00" + "8cc0" + "c3")
    + b"\x90" * 10
    + bytes.fromhex("31db" + "8ec3" + "c3")
)


def _project(code: bytes, base: int = 0x1000, entry: int = 0x1000) -> angr.Project:
    return _build_project_from_bytes(code, base_addr=base, entry_point=entry)


def test_resolver_proves_decoded_e8_target() -> None:
    """The resolver returns the byte-proven callee as the only target."""
    project = _project(_CODE)
    block = project.factory.block(0x1000, size=3, opt_level=0).vex
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    resolver = NativeDirectCallResolver8616(project)
    assert resolver.resolve(cfg, 0x1000, 0x1000, block, "Ijk_Call") == (True, [0x1010])


def test_evidence_is_closed_and_proven() -> None:
    """The shared binding verdict closes its five-stage counters on the proof."""
    project = _project(_CODE)
    evidence = native_direct_call_evidence_8616(
        project, block_addr=0x1000, block_size=3
    )
    assert isinstance(evidence, DirectNearCallTargetBinding8616)
    assert evidence.verdict is DirectNearCallTargetBindingVerdict8616.PROVEN
    assert evidence.complete
    assert evidence.target_addr == 0x1010
    assert evidence.stats == DirectNearCallTargetBindingStats8616(1, 1, 1, 1, 0)
    assert evidence.stats.closed


def test_proof_never_rewrites_execution_vex() -> None:
    """Resolving discovery leaves the symbolic next operand untouched."""
    project = _project(_CODE)
    block = project.factory.block(0x1000, opt_level=0).vex
    assert isinstance(block.next, pyvex.expr.RdTmp)
    evidence = native_direct_call_evidence_8616(
        project, block_addr=0x1000, block_size=block.size
    )
    assert isinstance(evidence, DirectNearCallTargetBinding8616) and evidence.complete
    again = project.factory.block(0x1000, opt_level=0).vex
    assert isinstance(again.next, pyvex.expr.RdTmp)
    assert again.jumpkind == "Ijk_Call"


def test_indirect_call_keeps_typed_refusal() -> None:
    """``call ax`` decodes to no relative edge: unsupported, never resolved."""
    project = _project(bytes.fromhex("ffd0c3") + b"\x90" * 8)
    block = project.factory.block(0x1000, opt_level=0).vex
    assert block.jumpkind == "Ijk_Call"
    evidence = native_direct_call_evidence_8616(
        project, block_addr=0x1000, block_size=block.size
    )
    assert isinstance(evidence, RelativeEdgeRefusal)
    assert evidence.reason is RelativeEdgeRefusalReason.UNSUPPORTED_FORM
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    resolver = NativeDirectCallResolver8616(project)
    assert resolver.resolve(cfg, 0x1000, 0x1000, block, "Ijk_Call") == (False, [])


def test_far_call_keeps_typed_refusal() -> None:
    """``call far ptr`` is outside the near-E8 contract and stays unresolved."""
    project = _project(bytes.fromhex("9a34127856") + b"\x90" * 8)
    block = project.factory.block(0x1000, opt_level=0).vex
    evidence = native_direct_call_evidence_8616(
        project, block_addr=0x1000, block_size=block.size
    )
    assert isinstance(evidence, RelativeEdgeRefusal)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    resolver = NativeDirectCallResolver8616(project)
    assert resolver.resolve(cfg, 0x1000, 0x1000, block, "Ijk_Call") == (False, [])


def test_operand_prefixed_call_keeps_typed_refusal() -> None:
    """``66 e8`` rel32 is decoded but refused by the word-E8 encoding owner."""
    project = _project(bytes.fromhex("66e800000000") + b"\x90" * 8)
    block = project.factory.block(0x1000, opt_level=0).vex
    assert block.jumpkind == "Ijk_Call"
    evidence = native_direct_call_evidence_8616(
        project, block_addr=0x1000, block_size=block.size
    )
    assert isinstance(evidence, DirectNearCallTargetBinding8616)
    assert evidence.failure is DirectNearCallTargetBindingFailure8616.DECODED_ENCODING_MISMATCH
    assert not evidence.complete
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    resolver = NativeDirectCallResolver8616(project)
    assert resolver.resolve(cfg, 0x1000, 0x1000, block, "Ijk_Call") == (False, [])


def test_selector_dependent_call_is_refused() -> None:
    """A target outside the fetch-window intersection is never published."""
    image = bytearray(b"\x90" * 0x10010)
    image[0xF000:0xF003] = bytes.fromhex("e8fd00")  # e8@0x10000 -> 0x10100
    project = _project(bytes(image))
    evidence = native_direct_call_evidence_8616(
        project, block_addr=0x10000, block_size=3
    )
    assert isinstance(evidence, DirectNearCallTargetBinding8616)
    assert evidence.failure is DirectNearCallTargetBindingFailure8616.SELECTOR_WINDOW_UNPROVED
    assert not evidence.complete
    block = project.factory.block(0x10000, size=3, opt_level=0).vex
    resolver = NativeDirectCallResolver8616(project)
    # A failed source theorem must refuse before consulting CFG target validity.
    # Scanning the 64 KiB padding adds no evidence to that refusal obligation.
    assert resolver.resolve(None, 0x10000, 0x10000, block, "Ijk_Call") == (False, [])


def test_selector_invariant_high_layout_is_proven() -> None:
    """A high-layout call invariant under every fetching selector still proves."""
    image = bytearray(b"\x90" * 0x10010)
    image[0xF000:0xF003] = bytes.fromhex("e80200")  # e8@0x10000 -> 0x10005
    project = _project(bytes(image))
    evidence = native_direct_call_evidence_8616(
        project, block_addr=0x10000, block_size=3
    )
    assert isinstance(evidence, DirectNearCallTargetBinding8616)
    assert evidence.complete
    assert evidence.target_addr == 0x10005


def _decoded_entry(native: object, head: int, target_addr: int) -> DecodedDirectCallsite8616:
    insns = tuple(native.capstone.insns)
    index = next(i for i, insn in enumerate(insns) if insn.address == head)
    return DecodedDirectCallsite8616(
        caller_start=native.addr,
        instructions=insns,
        instruction_index=index,
        callsite_addr=head,
        target_addr=target_addr,
        is_far=False,
    )


def test_binding_refuses_target_diverging_from_bytes() -> None:
    """A decoded entry disagreeing with mapped E8 bytes is a typed refusal."""
    project = _project(_CODE)
    native = project.factory.block(0x1000, size=3, opt_level=0, collect_data_refs=True)
    ir_block, _t, _j = _block_to_ir(native)
    call = next(i for i in reversed(ir_block.instrs) if i.op == "CALL")
    entry = _decoded_entry(native, 0x1000, 0x1011)  # bytes encode 0x1010
    binding = prove_direct_near_call_target_binding_from_decoded_8616(
        project, block=ir_block, instruction=call, decoded=entry
    )
    assert binding.verdict is DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE
    assert binding.failure is DirectNearCallTargetBindingFailure8616.DECODED_TARGET_MISMATCH
    assert not binding.complete


def test_binding_refuses_foreign_callsite() -> None:
    """A callsite that is not the instruction's own address refuses identity."""
    project = _project(_CODE)
    native = project.factory.block(0x1000, size=3, opt_level=0, collect_data_refs=True)
    ir_block, _t, _j = _block_to_ir(native)
    call = next(i for i in reversed(ir_block.instrs) if i.op == "CALL")
    entry = _decoded_entry(native, 0x1000, 0x1010)
    entry = DecodedDirectCallsite8616(
        caller_start=entry.caller_start,
        instructions=entry.instructions,
        instruction_index=entry.instruction_index,
        callsite_addr=0x1001,  # mid-instruction foreign coordinate
        target_addr=0x1010,
        is_far=False,
    )
    binding = prove_direct_near_call_target_binding_from_decoded_8616(
        project, block=ir_block, instruction=call, decoded=entry
    )
    assert binding.failure is DirectNearCallTargetBindingFailure8616.CALLSITE_MISMATCH
    assert not binding.complete


def test_non_call_terminal_is_not_evidence() -> None:
    """A boring or return block tail produces no call evidence at all."""
    project = _project(bytes.fromhex("eb00c3") + b"\x90" * 8)
    block = project.factory.block(0x1000, size=2, opt_level=0).vex
    assert block.jumpkind == "Ijk_Boring"
    assert native_direct_call_evidence_8616(
        project, block_addr=0x1000, block_size=block.size
    ) is None


def test_resolvers_stay_disjoint_and_architecture_scoped() -> None:
    """Call and jump adapters own disjoint jumpkinds; flat32 is untouched."""
    project = _project(_CODE)
    block = project.factory.block(0x1000, size=3, opt_level=0).vex
    call_resolver = NativeDirectCallResolver8616(project)
    jump_resolver = NativeDirectJumpResolver8616(project)
    assert call_resolver.filter(object(), 0x1000, 0x1000, block, "Ijk_Call")
    assert not call_resolver.filter(object(), 0x1000, 0x1000, block, "Ijk_Boring")
    assert not jump_resolver.filter(object(), 0x1000, 0x1000, block, "Ijk_Call")
    flat = angr.Project(
        io.BytesIO(bytes.fromhex("e80100c3")),
        main_opts={"backend": "blob", "arch": "x86", "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    foreign = NativeDirectCallResolver8616(flat)
    flat_block = flat.factory.block(0x1000, opt_level=0).vex
    assert not foreign.filter(object(), 0x1000, 0x1000, flat_block, "Ijk_Call")


def test_call_resolver_registration_is_idempotent() -> None:
    """Repeated bootstrap retains one call resolver without duplicating it."""
    register_native_direct_call_resolver_8616()
    before = tuple(DEFAULT_RESOLVERS[Arch86_16.name][cle.Backend])
    register_native_direct_call_resolver_8616()
    register_native_direct_call_resolver_8616()
    after = tuple(DEFAULT_RESOLVERS[Arch86_16.name][cle.Backend])
    assert after == before
    assert after.count(NativeDirectCallResolver8616) == 1


@pytest.mark.parametrize("constant", [False, True])
def test_supplied_irsb_corrupted_next_refuses(constant: bool) -> None:
    """An altered ``next`` tmp on the supplied IRSB is never authorized.

    The supplied operand preserves addr/size/Ijk_Call but rebinds the control
    operand to an unrelated temporary; the owner must refuse to publish the
    fresh re-lift's proven target for that inconsistent discovery operand.
    """
    project = _project(_CODE)
    supplied = copy.deepcopy(project.factory.block(0x1000, size=3, opt_level=0).vex)
    assert supplied.next.tmp != 7
    supplied.next = (
        pyvex.expr.Const(pyvex.const.U32(0x1011)) if constant else pyvex.expr.RdTmp(7)
    )
    resolver = NativeDirectCallResolver8616(project)
    assert resolver.resolve(None, 0x1000, 0x1000, supplied, "Ijk_Call") == (False, [])


@pytest.mark.parametrize("constant", [False, True])
def test_supplied_irsb_corrupted_producer_refuses(constant: bool) -> None:
    """An altered continuation producer DAG on the supplied IRSB refuses."""
    project = _project(_CODE)
    supplied = copy.deepcopy(project.factory.block(0x1000, size=3, opt_level=0).vex)
    producer = next(
        stmt
        for stmt in supplied.statements
        if isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp == supplied.next.tmp
    )
    producer.data = (
        pyvex.expr.Const(pyvex.const.U32(0x1011)) if constant else pyvex.expr.RdTmp(0)
    )
    resolver = NativeDirectCallResolver8616(project)
    assert resolver.resolve(None, 0x1000, 0x1000, supplied, "Ijk_Call") == (False, [])


def test_supplied_irsb_foreign_instruction_stream_refuses() -> None:
    """An IRSB for a different instruction stream is not bound to the site.

    Same bytes, same ``Ijk_Call`` terminal, foreign block coordinates: the
    IMark/address binding refuses before any target can be published.
    """
    project = _project(_CODE)
    supplied = _project(_CODE, base=0x2000, entry=0x2000).factory.block(
        0x2000, size=3, opt_level=0
    ).vex
    assert supplied.jumpkind == "Ijk_Call"
    resolver = NativeDirectCallResolver8616(project)
    assert resolver.resolve(None, 0x1000, 0x1000, supplied, "Ijk_Call") == (False, [])


def test_native_near_call_discovers_callee_function() -> None:
    """CFGFast must create the decoded E8 callee despite symbolic ``next``."""
    project = _build_project_from_bytes(_CODE, base_addr=0x1000, entry_point=0x1000)
    block = project.factory.block(0x1000, opt_level=0).vex
    # Execution VEX must stay faithful: the call destination is the symbolic
    # CS-relative continuation, never a rewritten constant.
    assert isinstance(block.next, pyvex.expr.RdTmp)
    assert block.jumpkind == "Ijk_Call"
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    assert 0x1010 in cfg.functions
    caller = cfg.functions[0x1000]
    assert caller.block_addrs_set == {0x1000, 0x1003}
    node = cfg.model.get_any_node(0x1000)
    callee_node = cfg.model.get_any_node(0x1010)
    return_node = cfg.model.get_any_node(0x1003)
    assert node is not None and callee_node is not None and return_node is not None
    assert cfg.graph.has_edge(node, callee_node)
    assert cfg.graph.get_edge_data(node, callee_node)["jumpkind"] == "Ijk_Call"
    assert cfg.graph.has_edge(node, return_node)
    assert cfg.graph.get_edge_data(node, return_node)["jumpkind"] == "Ijk_FakeRet"
    assert (0x1000, 0x1010) in cfg.kb.callgraph.edges
    # The proved call edge was consumed at the earliest job seam; it must not
    # enter indirect-jump bookkeeping as an unresolved artifact.
    assert 0x1000 not in cfg.indirect_jumps
