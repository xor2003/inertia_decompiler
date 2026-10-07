from __future__ import annotations

from types import SimpleNamespace

import inertia.semantics.segment_function_summary as segment_summary
from inertia.ir import build_x86_16_segment_state_artifact
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.ir.segment_contract import (
    SegmentFactVerdict,
    SegmentFunctionContract,
    build_x86_16_segment_function_contract,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.semantics.segment_function_summary import (
    SegmentControlTransferDistance8616,
    SegmentControlTransferFact8616,
    SegmentControlTransferKind8616,
    apply_x86_16_segment_function_summary,
    build_x86_16_segment_control_transfers,
    join_x86_16_segment_function_summaries,
)

from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.lowering.analysis_helpers import (
    CallTargetKind8616,
    CallTargetSeed,
    collect_direct_far_call_targets,
    collect_neighbor_call_targets,
    resolve_direct_call_target_from_block,
)
from tests.ir.test_segment_call_binding_regression import _project


def _local_contract(function_addr: int, *clobbers: str) -> SegmentFunctionContract:
    return SegmentFunctionContract(
        function_addr=function_addr,
        clobbered_registers=clobbers,
        summary={
            "raw_fact_count": 0,
            "normalized_fact_count": 0,
            "classified_fact_count": 0,
            "materialized_count": 0,
            "failure_count": 0,
        },
    )


def _transfer(site: int, target: int) -> SegmentControlTransferFact8616:
    return SegmentControlTransferFact8616(
        instruction_addr=site,
        kind=SegmentControlTransferKind8616.CALL,
        distance=SegmentControlTransferDistance8616.NEAR,
        target_addr=target,
        return_addr=site + 3,
        verdict=SegmentFactVerdict.PROVEN,
    )


def test_empty_local_contract_cannot_authorize_callee_preservation() -> None:
    """Existence of a callee contract is not complete body/effect evidence."""
    contracts = {0x1000: _local_contract(0x1000), 0x2000: _local_contract(0x2000)}
    summaries = join_x86_16_segment_function_summaries(
        contracts, {0x1000: (_transfer(0x1003, 0x2000),)},
    )
    assert summaries[0x1000].callee_effects[0].verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    assert not summaries[0x2000].local_effects_complete
    assert summaries[0x2000].summary["failure_count"] == 1


def _closed_function_code_8616(
    function_addr: int,
    calls: tuple[int, ...],
    call_target: int,
) -> tuple[bytes, int]:
    """Encode contiguous native NOP/direct-CALL/RET bytes for one leaf shape.

    Every call site carries a real ``call rel16`` aimed at ``call_target`` and
    the region ends one byte past the final ``ret``, so the decoded census,
    lifted IR, and call sites all come from bytes a project actually owns.
    """
    end = max((function_addr, *calls)) + 3
    code = bytearray(b"\x90" * (end + 1 - function_addr))
    code[-1] = 0xC3
    previous_end = function_addr
    for site in sorted(calls):
        if site < previous_end or site + 3 > end:
            raise ValueError("call site has no room for its three-byte encoding")
        relative = (call_target - (site + 3)) & 0xFFFF
        code[site - function_addr: site + 3 - function_addr] = (
            b"\xe8" + relative.to_bytes(2, "little")
        )
        previous_end = site + 3
    return bytes(code), end + 1


def _closed_contract(
    function_addr: int,
    calls: tuple[int, ...] = (),
    *,
    project: object | None = None,
    call_target: int | None = None,
) -> SegmentFunctionContract:
    """Construct actual registered raw IR and solved state, not a proof flag."""
    end = max((function_addr, *calls)) + 3
    code, region_end = _closed_function_code_8616(
        function_addr, calls, end if call_target is None else call_target,
    )
    if project is None:
        project = _project(code, base=function_addr)
    boundary = exact_function_range_boundary_8616(project, function_addr, region_end)
    assert boundary is not None
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, artifact)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    assert coverage.complete
    return build_x86_16_segment_function_contract(
        artifact, build_x86_16_segment_state_artifact(artifact), coverage=coverage,
    )


def test_closed_leaf_contract_authorizes_known_callee_effect() -> None:
    """Closed caller and leaf evidence from one project supplies exact effects."""
    caller_code, _ = _closed_function_code_8616(0x1000, (0x1003,), 0x2000)
    callee_code, _ = _closed_function_code_8616(0x2000, (), 0x2000)
    image = bytearray(0x2000)
    image[: len(caller_code)] = caller_code
    image[0x1000 : 0x1000 + len(callee_code)] = callee_code
    project = _project(bytes(image), base=0x1000, image_size=0x2000)
    contracts = {
        0x1000: _closed_contract(0x1000, (0x1003,), project=project, call_target=0x2000),
        0x2000: _closed_contract(0x2000, project=project),
    }
    summaries = join_x86_16_segment_function_summaries(
        contracts, {0x1000: (_transfer(0x1003, 0x2000),)},
    )
    assert summaries[0x1000].callee_effects[0].verdict is SegmentFactVerdict.PROVEN
    assert summaries[0x1000].callee_effects[0].clobbered_registers == ()
    assert summaries[0x2000].local_effects_complete


def test_closed_body_with_omitted_call_census_refuses_transitively() -> None:
    """Body completeness cannot hide an unreported local call."""
    contracts = {0x1000: _local_contract(0x1000), 0x2000: _closed_contract(0x2000, (0x2003,))}
    summaries = join_x86_16_segment_function_summaries(
        contracts, {0x1000: (_transfer(0x1003, 0x2000),)},
    )
    assert summaries[0x1000].callee_effects[0].verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    assert not summaries[0x2000].local_effects_complete


def test_cross_project_callee_proof_cannot_authorize_effects() -> None:
    """Equal target addresses cannot transport another project's raw IR proof."""
    contracts = {
        0x1000: _closed_contract(0x1000, (0x1003,), call_target=0x2000),
        0x2000: _closed_contract(0x2000),
    }
    summaries = join_x86_16_segment_function_summaries(
        contracts, {0x1000: (_transfer(0x1003, 0x2000),)},
    )
    assert summaries[0x1000].local_effects_complete
    assert summaries[0x2000].local_effects_complete
    assert summaries[0x1000].callee_effects[0].verdict is SegmentFactVerdict.UNKNOWN_REFUSE


def test_control_transfers_preserve_near_far_and_unresolved_calls(monkeypatch) -> None:
    function = SimpleNamespace(get_call_sites=lambda: (0x10, 0x20, 0x30))
    monkeypatch.setattr(
        segment_summary,
        "collect_neighbor_call_targets",
        lambda _function: (
            CallTargetSeed(0x10, 0x110, 0x13, CallTargetKind8616.DIRECT_NEAR_CALL),
            CallTargetSeed(0x20, 0x220, 0x25, CallTargetKind8616.DIRECT_FAR_CALL),
            CallTargetSeed(0x40, 0x440, None, CallTargetKind8616.DIRECT_FAR_TAIL_JUMP),
        ),
    )

    facts = build_x86_16_segment_control_transfers(function)

    assert tuple(fact.distance for fact in facts) == (
        SegmentControlTransferDistance8616.NEAR,
        SegmentControlTransferDistance8616.FAR,
        SegmentControlTransferDistance8616.UNKNOWN,
        SegmentControlTransferDistance8616.FAR,
    )
    assert facts[2].target_addr is None
    assert facts[2].verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    assert facts[3].kind is SegmentControlTransferKind8616.TAIL_JUMP


def test_function_summary_propagates_transitive_callee_clobbers() -> None:
    contracts = {
        0x100: _local_contract(0x100),
        0x200: _local_contract(0x200),
        0x300: _local_contract(0x300, "es"),
    }
    transfers = {0x100: (_transfer(0x110, 0x200),), 0x200: (_transfer(0x210, 0x300),)}

    summaries = join_x86_16_segment_function_summaries(contracts, transfers)

    assert summaries[0x100].effective_clobbered_registers == ("es",)
    assert summaries[0x100].callee_effects[0].clobbered_registers == ("es",)
    assert summaries[0x100].callee_effects[0].verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    assert summaries[0x100].unresolved_effect_sites == (0x110,)


def test_function_summary_refuses_missing_or_transitively_unknown_callee() -> None:
    contracts = {0x100: _local_contract(0x100, "ds"), 0x200: _local_contract(0x200)}
    transfers = {0x100: (_transfer(0x110, 0x200),), 0x200: (_transfer(0x210, 0x999),)}

    summaries = join_x86_16_segment_function_summaries(contracts, transfers)

    assert summaries[0x100].effective_clobbered_registers == ("ds",)
    assert summaries[0x100].callee_effects[0].verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    assert summaries[0x100].unresolved_effect_sites == (0x110,)
    assert summaries[0x200].unresolved_effect_sites == (0x210,)


def test_function_summary_refuses_unproved_transfer_even_with_known_target() -> None:
    """A target address alone cannot certify an unclassified CALL effect."""
    contracts = {
        0x50: _local_contract(0x50),
        0x100: _local_contract(0x100),
        0x200: _local_contract(0x200),
    }
    transfer = SegmentControlTransferFact8616(
        instruction_addr=0x110,
        kind=SegmentControlTransferKind8616.CALL,
        distance=SegmentControlTransferDistance8616.UNKNOWN,
        target_addr=0x200,
        return_addr=None,
        verdict=SegmentFactVerdict.UNKNOWN_REFUSE,
    )

    summaries = join_x86_16_segment_function_summaries(
        contracts,
        {0x50: (_transfer(0x60, 0x100),), 0x100: (transfer,)},
    )

    assert summaries[0x100].callee_effects[0].verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    assert summaries[0x100].unresolved_effect_sites == (0x110,)
    assert summaries[0x100].summary["failure_count"] == 3
    assert summaries[0x50].callee_effects[0].verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    assert summaries[0x50].unresolved_effect_sites == (0x60,)


def test_apply_function_summary_registers_current_project_contract(monkeypatch) -> None:
    function = SimpleNamespace(addr=0x100, get_call_sites=lambda: ())
    project = SimpleNamespace(_inertia_active_structuring_function_8616=function)
    codegen = SimpleNamespace(_inertia_segment_function_contract=_local_contract(0x100))
    monkeypatch.setattr(segment_summary, "collect_neighbor_call_targets", lambda _function: ())

    changed = apply_x86_16_segment_function_summary(project, codegen)

    assert changed is False
    assert codegen._inertia_segment_function_summary_8616.function_addr == 0x100
    assert project._inertia_segment_function_summaries_8616[0x100].summary["failure_count"] == 1


def test_apply_function_summary_accepts_slotted_angr_function_surface(monkeypatch) -> None:
    class SlottedFunction:
        __slots__ = ("addr",)

        def __init__(self) -> None:
            self.addr = 0x100

        def get_call_sites(self) -> tuple[int, ...]:
            return ()

    function = SlottedFunction()
    project = SimpleNamespace(_inertia_active_structuring_function_8616=function)
    codegen = SimpleNamespace(_inertia_segment_function_contract=_local_contract(0x100))
    monkeypatch.setattr(segment_summary, "collect_neighbor_call_targets", lambda _function: ())

    changed = apply_x86_16_segment_function_summary(project, codegen)

    assert changed is False
    assert codegen._inertia_segment_function_summary_8616.function_addr == 0x100
    assert project._inertia_segment_function_summaries_8616[0x100].function_addr == 0x100


def test_neighbor_collection_distinguishes_direct_far_call() -> None:
    def operand(immediate: int) -> SimpleNamespace:
        return SimpleNamespace(type=2, imm=immediate)

    instruction = SimpleNamespace(
        address=0x10010,
        mnemonic="lcall",
        size=5,
        insn=SimpleNamespace(operands=(operand(0x1000), operand(0x20)), size=5),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)), size=5)
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x1000)),
        factory=SimpleNamespace(block=lambda _addr, opt_level=0: block),
    )
    function = SimpleNamespace(
        project=project,
        get_call_sites=lambda: (0x10010,),
        get_call_target=lambda _addr: None,
        get_call_return=lambda _addr: 0x10015,
        block_addrs_set={0x10010},
    )

    seeds = collect_neighbor_call_targets(function)

    assert len(seeds) == 1
    assert seeds[0].target_addr == 0x10020
    assert seeds[0].kind is CallTargetKind8616.DIRECT_FAR_CALL

    instruction.mnemonic = "call"
    instruction.insn.operands = (operand(0x10020),)
    assert collect_direct_far_call_targets(function) == []
    assert collect_neighbor_call_targets(function)[0].kind is CallTargetKind8616.DIRECT_NEAR_CALL

    instruction.mnemonic = "lcall"
    instruction.insn.operands = (operand(0), operand(0))
    assert resolve_direct_call_target_from_block(project, 0x10010) == 0
    assert collect_neighbor_call_targets(function) == []
