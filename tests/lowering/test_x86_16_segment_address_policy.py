from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CConstant, CFunctionCall
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.segment_contract import (
    SegmentFactVerdict,
    SegmentFunctionContract,
    SegmentInstructionStateFact,
)
from inertia.lowering.callsite_segment_provenance import (
    attach_callsite_segment_address_provenance_8616,
)
from inertia.lowering.segment_access_policy import (
    SegmentAccessLoweringDecision8616,
    classify_codegen_segment_address_8616,
    classify_local_segment_access_8616,
    classify_local_segment_address_8616,
)


def _state(
    instruction_addr: int,
    *,
    source: str | None = "ds",
    verdict: SegmentFactVerdict = SegmentFactVerdict.PROVEN,
) -> SegmentInstructionStateFact:
    return SegmentInstructionStateFact(
        block_addr=0x1000,
        instruction_addr=instruction_addr,
        register="ds",
        physical_source=source,
        verdict=verdict,
    )


def test_address_policy_uses_exact_state_without_fabricating_memory_access() -> None:
    contract = SegmentFunctionContract(function_addr=0x1000, instruction_states=(_state(0x1010),))

    address_result = classify_local_segment_address_8616(
        contract,
        instruction_addrs=frozenset({0x1010}),
        segment_register="ds",
    )
    access_result = classify_local_segment_access_8616(
        contract,
        instruction_addrs=frozenset({0x1010}),
        segment_register="ds",
        offset=None,
        width=None,
    )

    assert address_result.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    assert address_result.instruction_states == contract.instruction_states
    assert access_result.decision is SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE


def test_address_policy_requires_proof_at_every_tagged_instruction() -> None:
    contract = SegmentFunctionContract(
        function_addr=0x1000,
        instruction_states=(
            _state(0x1010),
            _state(0x1012, source=None, verdict=SegmentFactVerdict.UNKNOWN_REFUSE),
        ),
    )

    result = classify_local_segment_address_8616(
        contract,
        instruction_addrs=frozenset({0x1010, 0x1012}),
        segment_register="ds",
    )

    assert result.decision is SegmentAccessLoweringDecision8616.UNKNOWN_REFUSE
    assert result.stats.failure_count == 1


def test_callsite_provenance_service_connects_generated_helper_to_policy() -> None:
    contract = SegmentFunctionContract(function_addr=0x1000, instruction_states=(_state(0x1010),))
    codegen = SimpleNamespace(
        _inertia_segment_function_contract=contract,
        next_idx=lambda _name: 0,
        project=SimpleNamespace(arch=Arch86_16()),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    offset = CConstant(0, SimTypeShort(False), codegen=codegen)
    node = CFunctionCall("SEG_PTR", None, [offset], codegen=codegen)

    attach_callsite_segment_address_provenance_8616((node,), (0x1010,))

    result = classify_codegen_segment_address_8616(
        codegen,
        node,
        segment_register="ds",
    )

    assert result.decision is SegmentAccessLoweringDecision8616.ENTRY_DS_OBJECT
    assert result.stats.classified_fact_count == 1
