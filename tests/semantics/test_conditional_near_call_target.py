"""Controls for the conditional direct near-CALL target theorem.

Layer: tests.
Responsibility: exercise ``prove_conditional_near_call_target_8616`` and
``consume_conditional_near_call_target_8616`` against a real tiny 16-bit
blob — an incoming ``E8`` at 0x1000 entering a root at 0x1010 whose own
``E8`` reaches backward to a leaf at 0x1008 external to the root range.
The outgoing call alone permits selectors up to 0x101, so the universal
binding refuses ``SELECTOR_WINDOW_UNPROVED`` while the authenticated
incoming interval [0, 0x100] admits the target; the theorem must stay
CONDITIONAL, retain its unproved CS-preservation obligation, and refuse
on copied, foreign, expired, mutated, or forged evidence.
"""
from __future__ import annotations

import time
from dataclasses import replace
from typing import NamedTuple

import angr
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
from inertia.ir.core import IRBlock, IRInstr
from inertia.ir.direct_evidence_deadline import (
    direct_evidence_deadline_scope_8616,
)
from inertia.ir.function_artifact import IRFunctionArtifact
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.semantics.conditional_near_call_target import (
    ConditionalNearCallTargetFailure8616,
    ConditionalNearCallTargetStats8616,
    ConditionalNearCallTargetTheorem8616,
    ConditionalNearCallTargetVerdict8616,
    consume_conditional_near_call_target_8616,
    prove_conditional_near_call_target_8616,
)
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallCoordinates8616,
    DirectNearCallTargetBindingFailure8616,
    prove_direct_near_call_target_binding_at_coordinates_8616,
)

pytestmark = pytest.mark.decompiler

_BASE = 0x1000
_INCOMING = 0x1000
_LEAF = 0x1008
_ROOT = 0x1010
_OUTGOING = 0x1010
_NEXT = 0x1013
_ROOT_END = 0x1014
_INCOMING_HIGH = 0x100
_CODE = bytes.fromhex(
    "e80d00"  # 0x1000: incoming near CALL -> root 0x1010
    "9090909090"  # 0x1003: filler
    "c3"  # 0x1008: earlier leaf RET, external to the root range
    "90909090909090"  # 0x1009: filler
    "e8f5ff"  # 0x1010: outgoing near CALL -> leaf 0x1008
    "c3"  # 0x1013: root RET
)
_FAILURE = ConditionalNearCallTargetFailure8616


class _Surface(NamedTuple):
    """One bound incoming context and its exact raw outgoing-CALL surface."""

    project: angr.Project
    boundary: ExactFunctionRangeBoundary8616
    context: nec.NativeNearCallEntry8616
    artifact: IRFunctionArtifact
    block: IRBlock
    call: IRInstr
    coordinates: DirectNearCallCoordinates8616


def _decode(code: bytes, address: int) -> capstone.CsInsn:
    """Decode one real 16-bit instruction for a callsite row."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    (instruction,) = tuple(decoder.disasm(code, address))
    return instruction


def _incoming_row(target_addr: int = _ROOT) -> DecodedDirectCallsite8616:
    """Retain the real decoded incoming CALL as a callsite row."""
    return DecodedDirectCallsite8616(
        caller_start=_INCOMING,
        instructions=(_decode(_CODE[:3], _INCOMING),),
        instruction_index=0,
        callsite_addr=_INCOMING,
        target_addr=target_addr,
    )


def _index(
    row: DecodedDirectCallsite8616, target_addr: int
) -> DecodedDirectCallsiteIndex8616:
    """Retain one row under its normalized near-target key."""
    stats = DecodedDirectCallsiteIndexStats8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )
    return DecodedDirectCallsiteIndex8616({target_addr & 0xFFFF: (row,)}, stats)


def _premise(
    row: DecodedDirectCallsite8616, index: DecodedDirectCallsiteIndex8616,
    target_addr: int,
) -> NearCallFramePremise8616:
    """Prove the canonical source-bound premise for the incoming row."""
    premise = prove_near_call_frame_premise_8616(row, index, target_addr)
    assert premise is not None
    return premise


def _surface(code: bytes = _CODE, *, base: int = _BASE,
             incoming: int = _INCOMING, root: int = _ROOT, root_end: int = _ROOT_END,
             outgoing: int = _OUTGOING, next_addr: int = _NEXT,
             target: int = _LEAF) -> _Surface:
    """Assemble the real project, entry context, artifact and CALL surface."""
    project = _build_project_from_bytes(code, base_addr=base, entry_point=incoming)
    boundary = exact_function_range_boundary_8616(project, root, root_end)
    assert boundary is not None
    row = DecodedDirectCallsite8616(
        caller_start=incoming,
        instructions=(_decode(code[incoming - base:incoming - base + 3], incoming),),
        instruction_index=0,
        callsite_addr=incoming,
        target_addr=root,
    )
    index = _index(row, root)
    premise = _premise(row, index, root)
    context = nec.bind_native_near_call_entry_8616(
        project, boundary, premise, callsite_index=index
    )
    assert type(context) is nec.NativeNearCallEntry8616
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    block = next(
        candidate
        for candidate in artifact.blocks
        if any(
            instruction.addr == outgoing and instruction.op == "CALL"
            for instruction in candidate.instrs
        )
    )
    call = next(
        instruction
        for instruction in block.instrs
        if instruction.addr == outgoing and instruction.op == "CALL"
    )
    return _Surface(
        project, boundary, context, artifact, block, call,
        DirectNearCallCoordinates8616(outgoing, next_addr, target),
    )


def _prove(surface: _Surface, **overrides: object) -> ConditionalNearCallTargetTheorem8616:
    """Evaluate the conditional theorem with per-key surface overrides."""
    arguments = {
        "artifact": surface.artifact,
        "context": surface.context,
        "block": surface.block,
        "instruction": surface.call,
        "coordinates": surface.coordinates,
    }
    arguments.update(overrides)
    return prove_conditional_near_call_target_8616(surface.project, **arguments)


def _consume(
    surface: _Surface, theorem: object, **overrides: object
) -> bool:
    """Consume a retained theorem with per-key surface overrides."""
    arguments = {
        "artifact": surface.artifact,
        "context": surface.context,
        "block": surface.block,
        "instruction": surface.call,
    }
    arguments.update(overrides)
    return consume_conditional_near_call_target_8616(
        surface.project, theorem, **arguments
    )


def test_conditional_theorem_positive() -> None:
    """An authenticated interval yields the CONDITIONAL theorem, with the
    unproved CS-preservation obligation retained as typed data."""
    surface = _surface()
    theorem = _prove(surface)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.CONDITIONAL
    assert theorem.failure is None
    assert theorem.preflight_failure is None
    assert theorem.stats == ConditionalNearCallTargetStats8616(1, 1, 1, 1, 0)
    assert theorem.stats.closed
    assert theorem.callsite_addr == _OUTGOING
    assert theorem.next_addr == _NEXT
    assert theorem.target_addr == _LEAF
    assert (theorem.selector_low, theorem.selector_high) == (0, _INCOMING_HIGH)
    assert theorem.context is surface.context
    assert theorem.artifact is surface.artifact
    assert theorem.block is surface.block
    assert theorem.instruction is surface.call
    assert theorem.shape is not None and theorem.shape.segment_register == "cs"
    obligation = theorem.obligation
    assert obligation is not None
    assert obligation.context is surface.context
    assert obligation.callsite_addr == _OUTGOING
    assert (obligation.selector_low, obligation.selector_high) == (0, _INCOMING_HIGH)
    assert obligation.admits_selector(0) and obligation.admits_selector(_INCOMING_HIGH)
    assert not obligation.admits_selector(_INCOMING_HIGH + 1)
    assert theorem.conditional_only
    assert theorem.cs_preservation_required
    assert theorem.reachability_unproved
    assert theorem.callee_preservation_unproved
    assert not hasattr(theorem, "complete")
    assert _consume(surface, theorem)


def test_default_public_binding_still_refuses() -> None:
    """The ordinary binding keeps its universal selector-window refusal."""
    surface = _surface()
    binding = prove_direct_near_call_target_binding_at_coordinates_8616(
        surface.project,
        block=surface.block,
        instruction=surface.call,
        coordinates=surface.coordinates,
    )
    assert not binding.complete
    assert (
        binding.failure
        is DirectNearCallTargetBindingFailure8616.SELECTOR_WINDOW_UNPROVED
    )


def test_interval_membership_bitvector_boundary() -> None:
    """Independent arithmetic: every admitted selector binds the target,
    and the first non-admitted selector (permitted by the outgoing CALL's
    own fetch window) binds a different target."""
    offset = _OUTGOING - _BASE
    assert _CODE[offset] == 0xE8
    displacement = int.from_bytes(_CODE[offset + 1:offset + 3], "little", signed=True)
    assert _NEXT + displacement == _LEAF
    for selector in range(_INCOMING_HIGH + 1):
        base = selector << 4
        bound = base + ((_NEXT - base + displacement) & 0xFFFF)
        assert bound == _LEAF
    admitted_outgoing = _OUTGOING >> 4
    assert admitted_outgoing == _INCOMING_HIGH + 1
    base = admitted_outgoing << 4
    bound = base + ((_NEXT - base + displacement) & 0xFFFF)
    assert bound != _LEAF


def test_foreign_and_copied_context_refuses() -> None:
    """Omitted, foreign, or field-forged contexts never authenticate."""
    surface = _surface()
    theorem = _prove(surface, context=object())
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
    assert theorem.failure is _FAILURE.FOREIGN_CONTEXT
    for field_name in (
        "callsite_addr", "next_addr", "target_addr", "callee_addr",
        "selector_low", "selector_high",
    ):
        forged = replace(
            surface.context,
            **{field_name: getattr(surface.context, field_name) + 1},
        )
        theorem = _prove(surface, context=forged)
        assert theorem.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
        # A forged target_addr desyncs the retained root before consumption.
        expected = (
            _FAILURE.FOREIGN_ROOT
            if field_name == "target_addr"
            else _FAILURE.CONTEXT_NOT_AUTHENTICATED
        )
        assert theorem.failure is expected
    foreign_index = _index(_incoming_row(), _ROOT)
    assert foreign_index is not surface.context.callsite_index
    forged = replace(surface.context, callsite_index=foreign_index)
    theorem = _prove(surface, context=forged)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
    assert theorem.failure is _FAILURE.CONTEXT_NOT_AUTHENTICATED


def test_foreign_root_block_and_instruction_refuse() -> None:
    """A wrong root, a look-alike block, or a copied instruction refuses."""
    surface = _surface()
    leaf_boundary = exact_function_range_boundary_8616(
        surface.project, _LEAF, _LEAF + 1
    )
    assert leaf_boundary is not None
    leaf_artifact = build_x86_16_ir_function_artifact(
        surface.project, leaf_boundary
    )
    theorem = _prove(surface, artifact=leaf_artifact)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
    assert theorem.failure is _FAILURE.FOREIGN_ROOT
    theorem = _prove(surface, artifact=object())
    assert theorem.failure is _FAILURE.FOREIGN_ROOT
    twin_artifact = build_x86_16_ir_function_artifact(
        surface.project, surface.boundary
    )
    theorem = _prove(surface, artifact=twin_artifact)
    assert theorem.failure is _FAILURE.FOREIGN_BLOCK
    theorem = _prove(surface, block=replace(surface.block))
    assert theorem.failure is _FAILURE.FOREIGN_BLOCK
    theorem = _prove(surface, instruction=replace(surface.call))
    assert theorem.failure is _FAILURE.FOREIGN_INSTRUCTION
    theorem = _prove(surface, coordinates=object())
    assert theorem.failure is _FAILURE.FOREIGN_COORDINATES


def test_changed_incoming_call_bytes_refuse() -> None:
    """Mutating the incoming CALL's mapped bytes revokes the context."""
    surface = _surface()
    surface.project.loader.memory.store(_INCOMING, b"\x90\x90\x90")
    theorem = _prove(surface)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
    assert theorem.failure is _FAILURE.CONTEXT_NOT_AUTHENTICATED


@pytest.mark.parametrize("address", [_OUTGOING, _OUTGOING + 3])
def test_changed_root_bytes_refuse(address: int) -> None:
    """Mutating the outgoing CALL or the root's RET breaks the raw rebind."""
    surface = _surface()
    surface.project.loader.memory.store(address, b"\x90")
    theorem = _prove(surface)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
    assert theorem.failure is _FAILURE.ROOT_REIMPORT_MISMATCH


@pytest.mark.parametrize("callsite,next_addr,target,inner", [
    (_OUTGOING + 1, _NEXT + 1, _LEAF,
     DirectNearCallTargetBindingFailure8616.CALLSITE_MISMATCH),
    (_OUTGOING, _NEXT, _LEAF + 2,
     DirectNearCallTargetBindingFailure8616.DISPLACEMENT_MISMATCH),
])
def test_forged_coordinate_surface_refuses(
    callsite: int, next_addr: int, target: int,
    inner: DirectNearCallTargetBindingFailure8616,
) -> None:
    """Coordinates that disagree with the real bytes carry the inner refusal."""
    surface = _surface()
    coordinates = DirectNearCallCoordinates8616(callsite, next_addr, target)
    theorem = _prove(surface, coordinates=coordinates)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
    assert theorem.failure is _FAILURE.PREFLIGHT_REFUSED
    assert theorem.preflight_failure is inner


def test_forged_outgoing_bytes_refuse_target_binding() -> None:
    """Rewriting the outgoing CALL to a forged target is caught at reimport."""
    surface = _surface()
    surface.project.loader.memory.store(
        _OUTGOING, bytes.fromhex("e8f0ff")  # decodes to 0x1003, not 0x1008
    )
    theorem = _prove(surface)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
    assert theorem.failure is _FAILURE.ROOT_REIMPORT_MISMATCH


def test_target_outside_interval_refuses() -> None:
    """A target below the authenticated interval's highest window refuses."""
    image = bytearray(0x114)
    image[0x008] = 0xC3  # leaf RET at 0x1008
    image[0x100:0x103] = bytes.fromhex("e80d00")  # 0x1100: call -> 0x1110
    image[0x110:0x113] = bytes.fromhex("e8f5fe")  # 0x1110: call -> 0x1008
    image[0x113] = 0xC3
    surface = _surface(
        bytes(image), base=_BASE, incoming=0x1100, root=0x1110,
        root_end=0x1114, outgoing=0x1110, next_addr=0x1113, target=_LEAF,
    )
    assert (surface.context.selector_low, surface.context.selector_high) == (0, 0x110)
    theorem = _prove(surface)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
    assert theorem.failure is _FAILURE.TARGET_OUTSIDE_INTERVAL
    assert theorem.stats.classified_fact_count == 1


def test_expired_deadline_refuses() -> None:
    """An elapsed request deadline refuses the theorem and the consumer."""
    surface = _surface()
    theorem = _prove(surface)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.CONDITIONAL
    with direct_evidence_deadline_scope_8616(
        surface.project, time.monotonic() - 1.0
    ):
        expired = _prove(surface)
        assert expired.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
        assert expired.failure is _FAILURE.REQUEST_EXPIRED
        assert not _consume(surface, theorem)
    assert _consume(surface, theorem)


def test_consumer_rejects_forged_omitted_and_stale() -> None:
    """Consumer refuses forged fields, wrong surfaces, and mutated bytes."""
    surface = _surface()
    theorem = _prove(surface)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.CONDITIONAL
    assert not _consume(surface, object())
    assert not _consume(surface, theorem, context=object())
    assert not _consume(surface, theorem, artifact=object())
    assert not _consume(surface, theorem, block=replace(surface.block))
    assert not _consume(surface, theorem, instruction=replace(surface.call))
    twin_artifact = build_x86_16_ir_function_artifact(
        surface.project, surface.boundary
    )
    assert not _consume(surface, theorem, artifact=twin_artifact)
    for field_name in ("callsite_addr", "next_addr", "target_addr",
                       "selector_low", "selector_high"):
        forged = replace(
            theorem, **{field_name: getattr(theorem, field_name) + 1}
        )
        assert not _consume(surface, forged)
    assert theorem.obligation is not None
    forged = replace(
        theorem,
        obligation=replace(theorem.obligation, selector_high=0x101),
    )
    assert not _consume(surface, forged)
    refused = replace(
        theorem, verdict=ConditionalNearCallTargetVerdict8616.REFUSED
    )
    assert not _consume(surface, refused)
    surface.project.loader.memory.store(_INCOMING, b"\x90\x90\x90")
    assert not _consume(surface, theorem)


def test_no_unconditional_verdict_or_publication() -> None:
    """The record exposes conditionality, never a complete/proven surface."""
    surface = _surface()
    theorem = _prove(surface)
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.CONDITIONAL
    assert theorem.verdict is not ConditionalNearCallTargetVerdict8616.REFUSED
    assert not hasattr(theorem, "complete")
    assert not hasattr(theorem, "proven")
    rendered = theorem.to_dict()
    assert rendered["verdict"] == "conditional"
    assert rendered["obligation"] == {
        "condition": "cs_at_callsite_in_interval",
        "callsite_addr": _OUTGOING,
        "selector_low": 0,
        "selector_high": _INCOMING_HIGH,
        "cs_preservation_unproved": True,
    }
