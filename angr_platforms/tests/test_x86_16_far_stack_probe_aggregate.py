"""Source-free far stack-probe allocation evidence for aggregate recovery."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
import capstone
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.stack_aggregate_objects import (
    StackAggregateEvidenceKind8616,
    StackAggregateRecovery8616,
    StackAggregateRecoveryStatus8616,
    collect_stack_aggregate_object_facts_8616,
)

_FUNCTION = bytes.fromhex(
    "b8 10 00 9a 00 00 00 07 8d 46 f0 8d 46 f0 cb"
)
_FAR_PROBE = bytes.fromhex(
    "59 5a 8b dc 2b d8 72 0b 3b 1e be 00 72 05 8b e3 52 51 cb"
)


def _recover(*, mutation: str | None = None) -> StackAggregateRecovery8616:
    """Decode mapped guest bytes and collect only binary-backed helper facts."""
    function = bytearray(_FUNCTION)
    helper = bytearray(_FAR_PROBE)
    if mutation == "target_segment":
        function[6] = 1
    elif mutation == "target_offset":
        function[4] = 1
    elif mutation == "indirect_call":
        function[3:8] = bytes.fromhex("ff 1e 00 20 90")
    elif mutation == "helper_branch":
        helper[7] = 0
    image = bytearray(0x6000 + len(helper))
    image[: len(function)] = function
    image[0x6000:] = helper
    project = angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instructions = tuple(decoder.disasm(function, 0x1000))
    return collect_stack_aggregate_object_facts_8616(
        project,
        SimpleNamespace(),
        instructions=instructions,
    )


def test_exact_far_probe_allocation_materializes_full_frame_object() -> None:
    """A direct segment:offset target joins a recognized far helper and frame."""
    result = _recover()

    assert result.status is StackAggregateRecoveryStatus8616.MATERIALIZABLE
    assert len(result.facts) == 1
    fact = result.facts[0]
    assert (fact.base_offset, fact.byte_size, fact.frame_allocation_size) == (-16, 16, 16)
    assert fact.evidence_kind is StackAggregateEvidenceKind8616.FULL_FRAME_ADDRESS
    assert result.raw_fact_count == result.normalized_fact_count == 3
    assert result.classified_fact_count == 1
    assert result.failure_count == 0


@pytest.mark.parametrize(
    "mutation", ["target_segment", "target_offset", "indirect_call", "helper_branch"]
)
def test_far_probe_allocation_refuses_unmatched_binary_evidence(mutation: str) -> None:
    """A changed target or helper branch cannot invent a stack allocation."""
    result = _recover(mutation=mutation)

    assert result.status is StackAggregateRecoveryStatus8616.NO_EVIDENCE
    assert result.classified_fact_count == result.materialized_count == 0
    assert result.refusals == ("missing_stack_allocation_evidence",)
