"""Controls for the conditional native near-CALL entry context.

Layer: tests.
Responsibility: exercise the bind/consume contract against a real tiny
16-bit blob project — a forward ``E8`` into a ``RET`` callee — and prove
that foreign projects, indexes, boundaries, mutated mapped bytes, forged
coordinates, normalized lookup aliases, changed widths, and expired
deadlines all revoke the conditional entry authority.
"""
from __future__ import annotations

import time
from dataclasses import replace
from types import SimpleNamespace

import capstone
import pytest

from inertia.cli.project_loading import _build_project_from_bytes
from inertia.frontend.x86_16 import near_call_entry_context as nec
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from inertia.frontend.x86_16.frontend_near_return_continuation import (
    NearCallFramePremise8616,
    prove_near_call_frame_premise_8616,
)
from inertia.ir.direct_evidence_deadline import (
    direct_evidence_deadline_scope_8616,
)

pytestmark = pytest.mark.decompiler

_BASE = 0x1000
_CALLSITE = _BASE
_CALLEE = _BASE + 4
_OTHER = _BASE + 5
_CODE = bytes.fromhex("e8 01 00 c3 c3 c3")
_FAILURE = nec.NativeNearCallEntryFailure8616


def _project() -> object:
    """Build one real blob project with current source bytes in memory."""
    return _build_project_from_bytes(_CODE, base_addr=_BASE, entry_point=_BASE)


def _decode(code: bytes, address: int) -> object:
    """Decode one real 16-bit instruction for a callsite row."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    (instruction,) = tuple(decoder.disasm(code, address))
    return instruction


def _row(code: bytes = _CODE[:3], target_addr: int = _CALLEE) -> DecodedDirectCallsite8616:
    """Retain one real decoded instruction as a callsite row."""
    return DecodedDirectCallsite8616(
        caller_start=_BASE,
        instructions=(_decode(code, _CALLSITE),),
        instruction_index=0,
        callsite_addr=_CALLSITE,
        target_addr=target_addr,
    )


def _index(
    row: DecodedDirectCallsite8616, target_addr: int, *, closed: bool = True
) -> DecodedDirectCallsiteIndex8616:
    """Retain one row under its normalized near-target key."""
    stats = DecodedDirectCallsiteIndexStats8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1 if closed else 0,
        materialized_count=1 if closed else 0,
        failure_count=0,
    )
    return DecodedDirectCallsiteIndex8616({target_addr & 0xFFFF: (row,)}, stats)


def _premise(
    target_addr: int = _CALLEE,
) -> NearCallFramePremise8616:
    """Prove the canonical source-bound premise for one near-CALL row."""
    row = _row(target_addr=target_addr)
    premise = prove_near_call_frame_premise_8616(
        row, _index(row, target_addr), target_addr
    )
    assert premise is not None
    return premise


def _boundary(
    project: object, start: int, end: int
) -> ExactFunctionRangeBoundary8616:
    """Resolve one exact decoded boundary or fail the fixture loudly."""
    boundary = exact_function_range_boundary_8616(project, start, end)
    assert boundary is not None
    return boundary


def _bound() -> tuple[
    object,
    ExactFunctionRangeBoundary8616,
    NearCallFramePremise8616,
    DecodedDirectCallsiteIndex8616,
]:
    """Assemble the positive fixture: project, callee boundary, premise."""
    project = _project()
    boundary = _boundary(project, _CALLEE, _CALLEE + 1)
    premise = _premise()
    return project, boundary, premise, premise.callsite_index


def _bind(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    premise: NearCallFramePremise8616,
    index: DecodedDirectCallsiteIndex8616,
) -> nec.NativeNearCallEntry8616:
    """Bind the positive context or fail the fixture loudly."""
    context = nec.bind_native_near_call_entry_8616(
        project, boundary, premise, callsite_index=index
    )
    assert type(context) is nec.NativeNearCallEntry8616
    return context


def test_bind_positive_context() -> None:
    """An authentic forward E8 into a bound callee yields the interval."""
    project, boundary, premise, index = _bound()
    context = _bind(project, boundary, premise, index)
    assert context.project is project
    assert context.boundary is boundary
    assert context.premise is premise
    assert context.callsite_index is index
    assert context.callsite_addr == _CALLSITE
    assert context.next_addr == _CALLSITE + 3
    assert context.target_addr == _CALLEE == boundary.addr
    assert context.callee_addr == _CALLEE
    assert context.call_encoding == _CODE[:3]
    assert (context.selector_low, context.selector_high) == (0, _CALLSITE >> 4)
    assert context.conditional_only
    assert context.cs_preservation_required
    assert context.reachability_unproved
    assert context.callee_preservation_unproved
    assert not hasattr(context, "complete")
    assert context.to_dict()["target_addr"] == _CALLEE
    assert nec.consume_native_near_call_entry_8616(
        project, context, callsite_index=index
    )


def test_mutated_callsite_bytes_revoke_context() -> None:
    """Changing the mapped CALL bytes revokes the retained encoding."""
    project, boundary, premise, index = _bound()
    context = _bind(project, boundary, premise, index)
    project.loader.memory.store(_CALLSITE, b"\x90\x90\x90")
    assert not nec.consume_native_near_call_entry_8616(
        project, context, callsite_index=index
    )
    project.loader.memory.store(_CALLSITE, _CODE[:3])
    assert nec.consume_native_near_call_entry_8616(
        project, context, callsite_index=index
    )


def test_stale_callee_bytes_revoke_context() -> None:
    """Changing the mapped callee bytes revokes the byte witnesses."""
    project, boundary, premise, index = _bound()
    context = _bind(project, boundary, premise, index)
    project.loader.memory.store(_CALLEE, b"\x90")
    assert not nec.consume_native_near_call_entry_8616(
        project, context, callsite_index=index
    )
    project.loader.memory.store(_CALLEE, b"\xc3")
    assert nec.consume_native_near_call_entry_8616(
        project, context, callsite_index=index
    )


def test_foreign_project_rejected() -> None:
    """A context never transfers to a different project object."""
    project, boundary, premise, index = _bound()
    context = _bind(project, boundary, premise, index)
    other = _project()
    assert not nec.consume_native_near_call_entry_8616(
        other, context, callsite_index=index
    )
    foreign_boundary = _boundary(other, _CALLEE, _CALLEE + 1)
    refused = nec.bind_native_near_call_entry_8616(
        project, foreign_boundary, premise, callsite_index=index
    )
    assert type(refused) is nec.NativeNearCallEntryRefusal8616
    assert refused.failure is _FAILURE.FOREIGN_BOUNDARY


def test_foreign_index_rejected() -> None:
    """The explicitly supplied index must be the retained identical one."""
    project, boundary, premise, index = _bound()
    context = _bind(project, boundary, premise, index)
    twin = _index(_row(), _CALLEE)  # equal facts, foreign object
    assert not nec.consume_native_near_call_entry_8616(
        project, context, callsite_index=twin
    )
    refused = nec.bind_native_near_call_entry_8616(
        project, boundary, premise, callsite_index=twin
    )
    assert type(refused) is nec.NativeNearCallEntryRefusal8616
    assert refused.failure is _FAILURE.FOREIGN_CALLSITE_INDEX
    open_index = _index(_row(), _CALLEE, closed=False)
    refused = nec.bind_native_near_call_entry_8616(
        project, boundary, premise, callsite_index=open_index
    )
    assert type(refused) is nec.NativeNearCallEntryRefusal8616
    assert refused.failure is _FAILURE.FOREIGN_CALLSITE_INDEX


def test_normalized_alias_entry_refuses() -> None:
    """The raw E8 destination, not a normalized lookup alias, must bind."""
    project, _callee_boundary, _premise_real, _index_real = _bound()
    alias_premise = _premise(target_addr=_BASE)
    assert alias_premise.callee_addr == _BASE != _CALLEE
    caller_boundary = _boundary(project, _BASE, _CALLEE)
    refused = nec.bind_native_near_call_entry_8616(
        project,
        caller_boundary,
        alias_premise,
        callsite_index=alias_premise.callsite_index,
    )
    assert type(refused) is nec.NativeNearCallEntryRefusal8616
    assert refused.failure is _FAILURE.RAW_TARGET_NOT_ENTRY
    other_boundary = _boundary(project, _OTHER, _OTHER + 1)
    refused = nec.bind_native_near_call_entry_8616(
        project, other_boundary, _premise_real, callsite_index=_index_real
    )
    assert type(refused) is nec.NativeNearCallEntryRefusal8616
    assert refused.failure is _FAILURE.RAW_TARGET_NOT_ENTRY


def test_forged_context_rejected() -> None:
    """Copied contexts with forged bounds, coordinates or widths refuse."""
    project, boundary, premise, index = _bound()
    context = _bind(project, boundary, premise, index)
    for field_name in (
        "callsite_addr",
        "next_addr",
        "target_addr",
        "callee_addr",
        "selector_low",
        "selector_high",
    ):
        forged = replace(
            context, **{field_name: getattr(context, field_name) + 1}
        )
        assert not nec.consume_native_near_call_entry_8616(
            project, forged, callsite_index=index
        )
    forged = replace(context, call_encoding=b"\x66\xe8\x01\x00")
    assert not nec.consume_native_near_call_entry_8616(
        project, forged, callsite_index=index
    )
    forged = replace(context, call_encoding=bytearray(_CODE[:3]))
    assert not nec.consume_native_near_call_entry_8616(
        project, forged, callsite_index=index
    )
    twin_row = _row()
    forged = replace(context, premise=replace(premise, callsite=twin_row))
    assert not nec.consume_native_near_call_entry_8616(
        project, forged, callsite_index=index
    )


def test_rebuilt_and_forged_premises_refuse() -> None:
    """A twin row or forged coordinate revokes the premise at bind."""
    project, boundary, premise, index = _bound()
    twin = replace(premise, callsite=_row())
    refused = nec.bind_native_near_call_entry_8616(
        project, boundary, twin, callsite_index=index
    )
    assert type(refused) is nec.NativeNearCallEntryRefusal8616
    assert refused.failure is _FAILURE.PREMISE_REPROOF_FAILED
    forged = replace(premise, callsite_addr=premise.callsite_addr + 1)
    refused = nec.bind_native_near_call_entry_8616(
        project, boundary, forged, callsite_index=index
    )
    assert type(refused) is nec.NativeNearCallEntryRefusal8616
    assert refused.failure is _FAILURE.PREMISE_COORDINATE_FORGERY
    wide = _row(code=b"\x66\xe8\x01\x00\x00\x00", target_addr=_CALLEE)
    forged = replace(premise, callsite=wide)
    refused = nec.bind_native_near_call_entry_8616(
        project, boundary, forged, callsite_index=index
    )
    assert type(refused) is nec.NativeNearCallEntryRefusal8616
    assert refused.failure is _FAILURE.PREMISE_REPROOF_FAILED


def test_invalid_architecture_and_inputs_refuse() -> None:
    """Non-Arch86_16 projects and untyped inputs never bind."""
    project, boundary, premise, index = _bound()
    for foreign in (SimpleNamespace(), SimpleNamespace(arch=SimpleNamespace())):
        refused = nec.bind_native_near_call_entry_8616(
            foreign, boundary, premise, callsite_index=index
        )
        assert type(refused) is nec.NativeNearCallEntryRefusal8616
        assert refused.failure is _FAILURE.UNSUPPORTED_ARCHITECTURE
    refused = nec.bind_native_near_call_entry_8616(
        project, object(), premise, callsite_index=index
    )
    assert type(refused) is nec.NativeNearCallEntryRefusal8616
    assert refused.failure is _FAILURE.FOREIGN_BOUNDARY
    refused = nec.bind_native_near_call_entry_8616(
        project, boundary, object(), callsite_index=index
    )
    assert type(refused) is nec.NativeNearCallEntryRefusal8616
    assert refused.failure is _FAILURE.PREMISE_ABSENT
    assert not nec.consume_native_near_call_entry_8616(
        project, object(), callsite_index=index
    )


def test_expired_deadline_revokes_consumption() -> None:
    """An elapsed direct-evidence deadline refuses consumption."""
    project, boundary, premise, index = _bound()
    context = _bind(project, boundary, premise, index)
    with direct_evidence_deadline_scope_8616(project, time.monotonic() - 1.0):
        assert not nec.consume_native_near_call_entry_8616(
            project, context, callsite_index=index
        )
    assert nec.consume_native_near_call_entry_8616(
        project, context, callsite_index=index
    )


@pytest.mark.parametrize("expire", [True, False])
def test_evidence_changes_during_replay_refuse(
    monkeypatch: pytest.MonkeyPatch, expire: bool,
) -> None:
    """Native replay cannot return success after expiry or CALL-byte change."""
    project, boundary, premise, index = _bound()
    context = _bind(project, boundary, premise, index)
    original = nec.restore_function_boundary_8616

    def restore_then_change(
        bound_project: object, witness: nec.FunctionBoundaryWitness8616,
    ) -> ExactFunctionRangeBoundary8616 | None:
        restored = original(bound_project, witness)
        if expire:
            monkeypatch.setattr(
                project, "_inertia_direct_evidence_deadline_8616",
                time.monotonic() - 1.0, raising=False,
            )
        else:
            project.loader.memory.store(_CALLSITE, b"\x90\x90\x90")
        return restored

    monkeypatch.setattr(nec, "restore_function_boundary_8616", restore_then_change)
    assert not nec.consume_native_near_call_entry_8616(
        project, context, callsite_index=index,
    )


def test_expired_binding_does_not_start_native_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An already expired request refuses before starting native proof work."""
    project, boundary, premise, index = _bound()

    def unexpected_capture(*args: object) -> None:
        raise AssertionError("expired binding started native capture")

    monkeypatch.setattr(nec, "capture_function_boundary_8616", unexpected_capture)
    with direct_evidence_deadline_scope_8616(project, time.monotonic() - 1.0):
        result = nec.bind_native_near_call_entry_8616(
            project, boundary, premise, callsite_index=index,
        )
    assert isinstance(result, nec.NativeNearCallEntryRefusal8616)
    assert result.failure is _FAILURE.BUDGET_EXHAUSTED
