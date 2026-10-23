"""Controls for the conditional near-CALL CS-preservation step.

Layer: tests.
Responsibility: exercise ``prove_conditional_near_call_preservation_8616``
and ``consume_conditional_near_call_preservation_8616`` against the real
tiny 16-bit blob shared with the conditional-target theorem: an incoming
``E8`` at 0x1000 enters a root at 0x1010 whose own ``E8`` reaches backward
to a leaf at 0x1008 external to the root range. The authenticated incoming
interval [0, 0x100] admits the outgoing target; the leaf carries a complete
universal callee closure preserving CS. The step must stay CONDITIONAL,
retain the identical unproved selector obligation, and refuse on wrong,
contextual, incomplete, or CS-changing callee evidence, caller/census
mismatch, forged fields, mutated native bytes, or an expired deadline.
"""
from __future__ import annotations

import time
from dataclasses import replace
from functools import partial
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
from inertia.ir import entry_domain_call_preservation as edcp
from inertia.ir import near_call_preservation as ncp
from inertia.ir.core import IRBlock, IRInstr
from inertia.ir.direct_evidence_deadline import (
    direct_evidence_deadline_scope_8616,
)
from inertia.ir.function_artifact import IRFunctionArtifact
from inertia.ir.near_call_preservation import (
    ConditionalNearCallPreservation8616,
    ConditionalNearCallPreservationFailure8616,
    ConditionalNearCallPreservationStats8616,
    ConditionalNearCallPreservationVerdict8616,
    consume_conditional_near_call_preservation_8616,
    prove_conditional_near_call_preservation_8616,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.lowering.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from inertia.semantics.conditional_near_call_target import (
    ConditionalNearCallTargetTheorem8616,
    ConditionalNearCallTargetVerdict8616,
    prove_conditional_near_call_target_8616,
)
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallCoordinates8616,
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
_CODE_CS_CHANGED = bytes.fromhex(
    "e80d00"  # 0x1000: incoming near CALL -> root 0x1010
    "9090909090"  # 0x1003: filler
    "cb"  # 0x1008: earlier leaf RETF: returns with CS popped, not preserved
    "90909090909090"  # 0x1009: filler
    "e8f5ff"  # 0x1010: outgoing near CALL -> leaf 0x1008
    "c3"  # 0x1013: root RET
)
_CODE_SELF_CALL = bytes.fromhex(
    "e80d00"  # 0x1000: incoming near CALL -> root 0x1010
    "9090909090"  # 0x1003: filler
    "c3"  # 0x1008: earlier leaf RET, unused by this fixture
    "90909090909090"  # 0x1009: filler
    "e8fdff"  # 0x1010: outgoing near CALL -> itself at 0x1010
    "c3"  # 0x1013: root RET
)
_FAILURE = ConditionalNearCallPreservationFailure8616


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


def _surface(
    code: bytes = _CODE, *, base: int = _BASE,
    incoming: int = _INCOMING, root: int = _ROOT, root_end: int = _ROOT_END,
    outgoing: int = _OUTGOING, next_addr: int = _NEXT, target: int = _LEAF,
) -> _Surface:
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


def _resolver(project: angr.Project) -> object:
    """Return the shared decoded direct-target resolver for one project."""
    return partial(resolve_direct_call_target_from_instruction_8616, project)


def _prove_theorem(surface: _Surface) -> ConditionalNearCallTargetTheorem8616:
    """Evaluate the conditional target theorem over the real surface."""
    theorem = prove_conditional_near_call_target_8616(
        surface.project,
        artifact=surface.artifact,
        context=surface.context,
        block=surface.block,
        instruction=surface.call,
        coordinates=surface.coordinates,
    )
    assert theorem.verdict is ConditionalNearCallTargetVerdict8616.CONDITIONAL
    return theorem


def _prove_step(
    surface: _Surface,
    theorem: ConditionalNearCallTargetTheorem8616 | object | None = None,
    **overrides: object,
) -> ConditionalNearCallPreservation8616:
    """Evaluate the conditional step with per-key surface overrides."""
    arguments = {
        "artifact": surface.artifact,
        "context": surface.context,
        "block": surface.block,
        "instruction": surface.call,
        "direct_target_resolver": _resolver(surface.project),
    }
    arguments.update(overrides)
    return prove_conditional_near_call_preservation_8616(
        surface.project,
        _prove_theorem(surface) if theorem is None else theorem,
        **arguments,
    )


def _consume(
    surface: _Surface, step: object, **overrides: object
) -> bool:
    """Consume a retained conditional step with per-key surface overrides."""
    arguments = {
        "artifact": surface.artifact,
        "context": surface.context,
        "block": surface.block,
        "instruction": surface.call,
        "direct_target_resolver": _resolver(surface.project),
    }
    arguments.update(overrides)
    return consume_conditional_near_call_preservation_8616(
        surface.project, step, **arguments
    )


def test_conditional_step_positive() -> None:
    """An authenticated theorem plus a universal leaf closure yields the
    CONDITIONAL step, retaining the identical unproved obligation."""
    surface = _surface()
    step = _prove_step(surface)
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    assert step.failure is None
    assert step.callee_failure is None
    assert step.stats == ConditionalNearCallPreservationStats8616(1, 1, 1, 1, 0)
    assert step.stats.closed
    assert step.callsite_addr == _OUTGOING
    assert step.next_addr == _NEXT
    assert step.target_addr == _LEAF
    assert step.callee_addr == _LEAF
    assert step.theorem is not None and step.theorem.artifact is surface.artifact
    assert step.callee is not None and step.callee.complete
    assert step.callee.coverage.artifact.function_addr == _LEAF
    obligation = step.obligation
    assert obligation is not None and obligation is step.theorem.obligation
    assert obligation.callsite_addr == _OUTGOING
    assert (obligation.selector_low, obligation.selector_high) == (0, _INCOMING_HIGH)
    assert step.conditional_only
    assert step.cs_preservation_required
    assert step.callee_termination_unproved
    assert step.reachability_unproved
    assert not hasattr(step, "complete")
    assert not hasattr(step, "preserved_registers")
    assert _consume(surface, step)


def test_supplied_resolution_session_binds_identically() -> None:
    """A caller-supplied canonical session resolves the same conditional step."""
    surface = _surface()
    resolution = edcp._CalleeResolution8616(resolver=_resolver(surface.project))
    step = _prove_step(surface, resolution=resolution)
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    assert step.callee_addr == _LEAF
    assert resolution.retained_closures.get(_LEAF) is step.callee


def test_missing_or_refused_theorem_refuses() -> None:
    """An omitted or refused theorem can never seed a conditional step."""
    surface = _surface()
    step = _prove_step(surface, theorem=object())
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.REFUSED
    assert step.failure is _FAILURE.THEOREM_ABSENT
    refused = prove_conditional_near_call_target_8616(
        surface.project,
        artifact=surface.artifact,
        context=surface.context,
        block=surface.block,
        instruction=surface.call,
        coordinates=DirectNearCallCoordinates8616(_OUTGOING, _NEXT, _LEAF + 2),
    )
    assert refused.verdict is ConditionalNearCallTargetVerdict8616.REFUSED
    step = _prove_step(surface, theorem=refused)
    assert step.failure is _FAILURE.THEOREM_ABSENT
    forged = replace(_prove_theorem(surface), callsite_addr=_OUTGOING + 1)
    step = _prove_step(surface, theorem=forged)
    assert step.failure is _FAILURE.THEOREM_ABSENT


def test_caller_surface_mismatch_refuses() -> None:
    """Surfaces foreign to the theorem's retained caller refuse typed."""
    surface = _surface()
    theorem = _prove_theorem(surface)
    for key, value in (
        ("artifact", object()),
        ("context", object()),
        ("block", replace(surface.block)),
        ("instruction", replace(surface.call)),
    ):
        step = _prove_step(surface, theorem, **{key: value})
        assert step.verdict is ConditionalNearCallPreservationVerdict8616.REFUSED
        assert step.failure is _FAILURE.CALLER_MISMATCH
    twin_artifact = build_x86_16_ir_function_artifact(
        surface.project, surface.boundary
    )
    step = _prove_step(surface, theorem, artifact=twin_artifact)
    assert step.failure is _FAILURE.CALLER_MISMATCH


def test_theorem_not_authenticated_refuses() -> None:
    """Mutating the incoming CALL's mapped bytes revokes authentication."""
    surface = _surface()
    theorem = _prove_theorem(surface)
    surface.project.loader.memory.store(_INCOMING, b"\x90\x90\x90")
    step = _prove_step(surface, theorem)
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.REFUSED
    assert step.failure is _FAILURE.THEOREM_NOT_AUTHENTICATED
    assert step.stats == ConditionalNearCallPreservationStats8616(1, 1, 0, 0, 1)


def test_changed_outgoing_call_bytes_refuse() -> None:
    """Rewriting the outgoing CALL fails the theorem's raw rebind."""
    surface = _surface()
    theorem = _prove_theorem(surface)
    surface.project.loader.memory.store(
        _OUTGOING, bytes.fromhex("e8f0ff")
    )
    step = _prove_step(surface, theorem)
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.REFUSED
    assert step.failure is _FAILURE.THEOREM_NOT_AUTHENTICATED


def test_cyclic_callee_refuses() -> None:
    """A call into its own in-flight caller keeps the owner's cycle refusal."""
    surface = _surface(_CODE_SELF_CALL, target=_ROOT)
    step = _prove_step(surface)
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.REFUSED
    assert step.failure is _FAILURE.CALLEE_UNRESOLVED
    assert step.callee_failure is (
        edcp.EntryDomainCallPreservationFailure8616.DEPENDENCY_UNPROVEN
    )
    assert step.stats == ConditionalNearCallPreservationStats8616(1, 1, 0, 0, 1)


def test_cs_changing_callee_refuses() -> None:
    """A complete callee whose exits lose the CS identity refuses honestly."""
    surface = _surface(_CODE_CS_CHANGED)
    step = _prove_step(surface)
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.REFUSED
    assert step.failure is _FAILURE.CS_NOT_PRESERVED
    assert step.stats.classified_fact_count == 1
    assert step.callee is not None and step.callee.complete
    assert not _consume(surface, step)


def test_expired_deadline_refuses() -> None:
    """An elapsed request deadline refuses producer and consumer alike."""
    surface = _surface()
    theorem = _prove_theorem(surface)
    step = _prove_step(surface, theorem)
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    with direct_evidence_deadline_scope_8616(
        surface.project, time.monotonic() - 1.0
    ):
        expired = _prove_step(surface, theorem)
        assert expired.verdict is ConditionalNearCallPreservationVerdict8616.REFUSED
        assert expired.failure is _FAILURE.REQUEST_EXPIRED
        assert not _consume(surface, step)
    assert _consume(surface, step)


def test_consumer_rejects_forged_omitted_and_stale() -> None:
    """Consumer refuses forged fields, wrong surfaces, and mutated bytes."""
    surface = _surface()
    step = _prove_step(surface)
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    assert not _consume(surface, object())
    assert not _consume(surface, step, context=object())
    assert not _consume(surface, step, artifact=object())
    assert not _consume(surface, step, block=replace(surface.block))
    assert not _consume(surface, step, instruction=replace(surface.call))
    twin_artifact = build_x86_16_ir_function_artifact(
        surface.project, surface.boundary
    )
    assert not _consume(surface, step, artifact=twin_artifact)
    for field_name in ("callsite_addr", "next_addr", "target_addr", "callee_addr"):
        forged = replace(
            step, **{field_name: getattr(step, field_name) + 1}
        )
        assert not _consume(surface, forged)
    assert step.obligation is not None
    forged = replace(
        step, obligation=replace(step.obligation, selector_high=0x101)
    )
    assert not _consume(surface, forged)
    forged = replace(
        step, verdict=ConditionalNearCallPreservationVerdict8616.REFUSED
    )
    assert not _consume(surface, forged)
    forged = replace(
        step, stats=ConditionalNearCallPreservationStats8616(1, 1, 1, 0, 1)
    )
    assert not _consume(surface, forged)
    surface.project.loader.memory.store(_INCOMING, b"\x90\x90\x90")
    assert not _consume(surface, step)


def test_consumer_rejects_wrong_callee() -> None:
    """A retained closure bound to a different head fails reconciliation."""
    surface = _surface()
    step = _prove_step(surface)
    foreign = _surface()
    foreign_step = _prove_step(foreign)
    assert foreign_step.callee is not None and foreign_step.callee is not step.callee
    assert not _consume(surface, replace(step, callee=foreign_step.callee))
    assert not _consume(surface, replace(step, callee_addr=_ROOT))


def test_consumer_rejects_altered_cs_and_foreign_context() -> None:
    """Altered exit CS identity and contextual callee state stay refused."""
    surface = _surface()
    step = _prove_step(surface)
    callee = step.callee
    assert callee is not None and step.callee_addr is not None
    (return_addr,) = callee.return_block_addrs
    exit_states = {addr: dict(states) for addr, states in callee.state.exit_states.items()}
    altered = replace(exit_states[return_addr]["cs"], source="0xdead")
    exit_states[return_addr]["cs"] = altered
    forged_callee = replace(
        callee, state=replace(callee.state, exit_states=exit_states)
    )
    assert not _consume(surface, replace(step, callee=forged_callee))
    for field_name in ("invocation_scope", "entry_context"):
        forged_state = replace(
            callee.state, **{field_name: object()}
        )
        forged_callee = replace(callee, state=forged_state)
        assert not _consume(surface, replace(step, callee=forged_callee))


def test_seal_rejects_sibling_operand_and_interval_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operand identity and retained interval facts stay sealed end to end."""
    surface = _surface()
    step = _prove_step(surface)
    assert step.theorem is not None and step.obligation is not None
    original = ncp._callee_chain_failure_8616

    def swap_operand(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        object.__setattr__(
            surface.call, "args", (replace(surface.call.args[0]),)
        )
        return result

    monkeypatch.setattr(ncp, "_callee_chain_failure_8616", swap_operand)
    assert not _consume(surface, step)
    sealed = _prove_step(surface, step.theorem)
    assert sealed.verdict is ConditionalNearCallPreservationVerdict8616.REFUSED
    assert sealed.failure is _FAILURE.SEAL_SOURCE_CHANGED
    monkeypatch.undo()
    drifted = _surface()
    drifted_step = _prove_step(drifted)
    assert drifted_step.theorem is not None
    object.__setattr__(
        drifted_step.theorem,
        "selector_high",
        drifted_step.theorem.selector_high + 1,
    )
    assert not _consume(drifted, drifted_step)
    drifted = _surface()
    drifted_step = _prove_step(drifted)
    assert drifted_step.obligation is not None
    object.__setattr__(
        drifted_step.obligation,
        "selector_high",
        drifted_step.obligation.selector_high + 1,
    )
    assert not _consume(drifted, drifted_step)
    drifted = _surface()
    drifted_step = _prove_step(drifted)
    drifted.project.loader.memory.store(_OUTGOING, bytes.fromhex("e8f0ff"))
    assert not _consume(drifted, drifted_step)


def test_no_unconditional_verdict_or_publication() -> None:
    """The record exposes conditionality, never a complete/proven surface."""
    surface = _surface()
    step = _prove_step(surface)
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    assert step.verdict is not ConditionalNearCallPreservationVerdict8616.REFUSED
    assert not hasattr(step, "complete")
    assert not hasattr(step, "proven")
    assert not hasattr(step, "preserved_registers")
    rendered = step.to_dict()
    assert rendered["verdict"] == "conditional"
    assert rendered["statement"] == (
        "cs_preserved_across_call_if_obligation_holds_and_callee_returns"
    )
    assert rendered["obligation"] == {
        "condition": "cs_at_callsite_in_interval",
        "callsite_addr": _OUTGOING,
        "selector_low": 0,
        "selector_high": _INCOMING_HIGH,
        "cs_preservation_unproved": True,
    }
