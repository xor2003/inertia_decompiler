from __future__ import annotations

import time
from dataclasses import dataclass

import pytest

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_call_contracts import initial_state
from tools.dosunit.recursive_proofs.real16_entry_domain import Real16ScalarDomain
from tools.dosunit.recursive_proofs.real16_native_control_scope import ControlScopeReason, prove_native_control_scope
from tools.dosunit.register_state_relations import MachineState


def _entry(head: int, *, cs: int | None = 0x1000, stack: bool = False) -> MachineState:
    """Use exact entry literals; leave other native inputs unrestricted."""
    entry = initial_state()
    if cs is not None:
        entry["cs"] = {"op": "const", "width": 16, "value": hex(cs)}
    entry["control_ip"] = {"op": "const", "width": 32, "value": hex(head)}
    if stack:
        entry["ss"] = {"op": "const", "width": 16, "value": "0x3000"}
        entry["sp"] = {"op": "const", "width": 16, "value": "0x1000"}
    return entry


@dataclass(frozen=True, slots=True)
class EdgeCase:
    """Exact byte/control input and expected typed local outcome."""

    name: str
    data: bytes
    head: int
    entry: MachineState
    domain: Real16ScalarDomain | None
    status: ProofStatus
    reason: str
    expired: bool = False


def _cases() -> tuple[EdgeCase, ...]:
    """Keep successful and refused coordinates distinct from whole-system claims."""
    head = 0x10020
    domain = Real16ScalarDomain(0x3000, 0x1000)
    missing_head = _entry(head)
    del missing_head["control_ip"]
    odd_stack = _entry(0x20, cs=0, stack=True)
    odd_stack["sp"] = {"op": "const", "width": 16, "value": "0x1001"}
    return (
        EdgeCase("bootstrap_zero_cs_jmp", b"\xeb\x00", 0x20, _entry(0x20, cs=0), None,
                 ProofStatus.PROVED, "native_control_coordinates_discharged"),
        EdgeCase("bootstrap_odd_sp_jmp", b"\xeb\x00", 0x20, odd_stack, None,
                 ProofStatus.PROVED, "native_control_coordinates_discharged"),
        EdgeCase("bootstrap_nonzero_cs_jmp", b"\xeb\x00", head, _entry(head), None,
                 ProofStatus.PROVED, "native_control_coordinates_discharged"),
        EdgeCase("bootstrap_ret", b"\xc3", head, _entry(head, stack=True), None,
                 ProofStatus.PROVED, "native_control_coordinates_discharged"),
        EdgeCase("bootstrap_prefix_ret", b"\x90\xc3", head, _entry(head, stack=True), None,
                 ProofStatus.PROVED, "native_control_coordinates_discharged"),
        EdgeCase("component_prefix_jmp", b"\x90\xeb\x00", head, _entry(head, stack=True), domain,
                 ProofStatus.PROVED, "native_control_coordinates_discharged"),
        EdgeCase("wrong_head", b"\xeb\x00", head, _entry(head + 1), None,
                 ProofStatus.UNKNOWN, "native_control_domain_or_entry_unproved"),
        EdgeCase("missing_head", b"\xeb\x00", head, missing_head, None,
                 ProofStatus.UNKNOWN, "native_control_domain_or_entry_unproved"),
        EdgeCase("missing_bootstrap_cs", b"\xeb\x00", head, _entry(head, cs=None), None,
                 ProofStatus.UNKNOWN, "native_control_domain_or_entry_unproved"),
        EdgeCase("crossed_cs_window", b"\xeb\x00", 0x1FFFF, _entry(0x1FFFF), None,
                 ProofStatus.UNKNOWN, "native_control_domain_or_entry_unproved"),
        EdgeCase("expired_deadline", b"\xeb\x00", head, _entry(head), None,
                 ProofStatus.UNKNOWN, "native_control_original_deadline_exhausted", True),
    )


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case.name)
def test_bootstrap_and_control_refusal_boundaries(case: EdgeCase) -> None:
    """A missing coordinate premise never becomes a vacuous positive proof."""
    result = prove_native_control_scope(case.data, case.head, case.entry, case.domain,
                                       deadline=time.monotonic() + (-1 if case.expired else 15))
    assert result.status is case.status
    assert result.reason is ControlScopeReason(case.reason)
    assert result.complete == (case.status is ProofStatus.PROVED)
    if result.complete and case.data.endswith(b"\xeb\x00"):
        assert result.native_targets == result.expected_targets == {case.head + len(case.data)}
    assert not result.binary_equivalence_proved
