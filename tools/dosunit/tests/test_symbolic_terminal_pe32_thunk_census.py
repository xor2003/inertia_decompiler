"""Source-bound continuation checks for declared PE32 import thunks.

Layer: tests.
Responsibility: reject coherent receipt edits without adding solver calls to census verification.
"""
from __future__ import annotations

import struct
from dataclasses import replace

import pytest
from tools.dosunit.tests.test_pe32_import_service import (
    ENTRY,
    EXIT,
    IAT_SLOT,
    call_service,
    pe32_import_bytes,
    pe_environment,
)

import tools.dosunit.compare.symbolic_terminal as ST


def _thunk(prefix: bytes = b"") -> bytes:
    """Push the real continuation then jump through the actual import table."""
    return prefix + b"\x68" + struct.pack("<I", ENTRY + len(prefix) + 11) + b"\xff\x25" + struct.pack("<I", IAT_SLOT)


def _exit(code: bytes) -> bytes:
    """End at the declared synthetic gateway with a fixed exit argument."""
    code += bytes.fromhex("682a000000")
    return code + b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(code) + 5))


def test_coherent_thunk_continuation_skip_refuses() -> None:
    """Deleting a real second invocation and repairing all census counts still refuses."""
    trace = ST.trace_flat32_terminal(pe32_import_bytes(_exit(_thunk() + call_service())), pe_environment())
    assert len(trace.blocks) == 3 and len(trace.service_events) == 2
    blocks = (replace(trace.blocks[0], next_target=trace.blocks[-1].address), trace.blocks[-1])
    events = trace.service_events[:1]
    evidence = len(blocks) + len(events)
    counters = replace(trace.counters, raw_fact_count=evidence, normalized_fact_count=evidence,
                       classified_fact_count=evidence + 1,
                       materialized_count=len(trace.document["outputs"]) + len(events))
    forged = replace(trace, blocks=blocks, service_events=events, counters=counters)
    refusal = ST.verify_terminal_trace(forged)
    assert refusal is not None, "coherent thunk continuation omission was accepted"
    assert refusal.kind is ST.TerminalRefusalKind.STALE_EVIDENCE


def test_authentic_thunk_custom_budget_and_fault() -> None:
    """Fresh frame replay supports explicit larger limits and early fault outcomes."""
    for code, limits in (
        (_exit(_thunk(bytes.fromhex("eb0190") * 7)), ST.TerminalLimits(max_blocks=9)),
        (_thunk() + bytes.fromhex("31dbf7f3"), ST.TerminalLimits()),
    ):
        trace = ST.trace_flat32_terminal(pe32_import_bytes(code), pe_environment(), limits=limits)
        assert ST.verify_terminal_trace(trace) is None


def test_call_iat_verification_does_not_rewalk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ordinary native fallthrough binds CALL-IAT without an extra lowering pass."""
    trace = ST.trace_flat32_terminal(pe32_import_bytes(_exit(call_service())), pe_environment())

    def forbidden(*args: object, **kwargs: object) -> None:
        """Fail if a simple native fallthrough is needlessly replayed."""
        pytest.fail("CALL-IAT unnecessarily replayed")

    monkeypatch.setattr(ST, "_seeded_flat32_walk", forbidden)
    assert ST.verify_terminal_trace(trace) is None
