"""Layer: tests.
Responsibility: keep decoded external effects out of native integer proofs.
"""

from __future__ import annotations

import hashlib

import capstone
import pytest

from tools.dosunit.binary_environment import (
    EnvironmentEffect,
    instruction_port_effect,
    instruction_requires_machine_state,
)
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_call_contracts import initial_state
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import bind_real16_mz
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBindingReason,
    NativeBlockRequest,
    bind_real16_native_effects,
)


@pytest.mark.parametrize("code", [
    "e460",       # IN AL, immediate port: currently folded by the real16 lifter.
    "e560",       # IN AX, immediate port.
    "ec",         # IN AL, DX.
    "e680",       # OUT immediate port, AL.
    "0f01e0",     # SMSW AX: unmodeled machine state, sometimes lifted as no-op.
    "0f0108",     # SIDT [BX+SI].
    "0f0000",     # SLDT [BX+SI].
    "0f0020",     # VERR word [BX+SI].
    "0f20c0",     # MOV EAX, CR0.
    "0f21c0",     # MOV EAX, DR0.
])
def test_native_binding_requires_environment_for_decoded_effect(code: str) -> None:
    """Refuse from exact byte evidence before endorsing any proposed effect."""
    from test_dosunit_tool import _mz_exe

    data = bytes.fromhex(code)
    load = bind_real16_mz(_mz_exe(bytes(0x200) + data), load_segment=0x1000)
    proposal = canonical_json_bytes(initial_state())
    request = NativeBlockRequest(
        0x10200, len(data), hashlib.sha256(proposal).hexdigest(), proposal
    )
    result = bind_real16_native_effects(load, (request,), timeout_ms=15000)
    assert result.status is ProofStatus.UNKNOWN
    assert result.reason is NativeBindingReason.FAULT, result
    assert not result.blocks
    assert result.counters.failure_count > 0


@pytest.mark.parametrize(("code", "port", "machine"), [
    ("b8e460", None, False),  # MOV AX, immediate containing IN opcode bytes.
    ("b8e00f", None, False),
    ("89d8", None, False),
    ("8e d8", None, False),  # ordinary segment-register MOV remains modeled.
    ("e460", EnvironmentEffect.PORT_READ, False),
    ("ee", EnvironmentEffect.PORT_WRITE, False),
    ("0f01e0", None, True),
    ("0f20c0", None, True),
    ("0f21c0", None, True),
])
def test_native_environment_classification_uses_instruction_identity(
    code: str, port: EnvironmentEffect | None, machine: bool,
) -> None:
    """Classify actual instructions, preserving ordinary register/immediate data."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instructions = tuple(decoder.disasm(bytes.fromhex(code), 0x10200))
    assert len(instructions) == 1
    assert instruction_port_effect(instructions[0]) is port
    assert instruction_requires_machine_state(instructions[0]) is machine
