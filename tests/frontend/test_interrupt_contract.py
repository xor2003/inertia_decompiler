"""Interrupt coordinate and closed registry behavior survives namespace moves."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from inertia.frontend.x86_16.interrupt_contract import (
    SoftwareInterruptServiceTargetFact8616,
    interrupt_core_addr_8616,
    interrupt_vector_from_core_addr_8616,
    record_software_interrupt_service_target_8616,
    software_interrupt_service_fact_8616,
)


@pytest.mark.parametrize("vector", [0, 0x21, 0xFF])
def test_interrupt_vector_roundtrip(vector: int) -> None:
    assert interrupt_vector_from_core_addr_8616(interrupt_core_addr_8616(vector)) == vector


@pytest.mark.parametrize("vector", [-1, 0x100])
def test_out_of_range_vectors_are_rejected(vector: int) -> None:
    with pytest.raises(ValueError):
        interrupt_core_addr_8616(vector)


def test_service_registry_closes_evidence_and_rejects_contradiction() -> None:
    owner = SimpleNamespace()
    fact = SoftwareInterruptServiceTargetFact8616(0x1000, 0x1020, 0x21, 0xFE009, "dos_print")
    registry = record_software_interrupt_service_target_8616(owner, fact)
    assert registry.closes_evidence
    assert record_software_interrupt_service_target_8616(owner, fact).facts == (fact,)
    assert software_interrupt_service_fact_8616(owner, function_addr=0x1000, callsite_addr=0x1020, vector=0x21) == fact
    assert software_interrupt_service_fact_8616(owner, function_addr=0x1000, callsite_addr=0x1020, vector=0x20) is None
    contradictory = SoftwareInterruptServiceTargetFact8616(0x1000, 0x1020, 0x21, 0xFE04C, "dos_exit")
    with pytest.raises(ValueError):
        record_software_interrupt_service_target_8616(owner, contradictory)
    assert owner._inertia_software_interrupt_service_targets_8616 is not None
    assert owner._inertia_software_interrupt_service_targets_8616.facts == (fact,)
