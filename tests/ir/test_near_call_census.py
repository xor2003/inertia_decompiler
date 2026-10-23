"""Focused controls for the fresh outgoing-CALL census batch.

Layer: tests (private prototype).
Responsibility: prove the batched producer preserves the standalone
per-call semantics — exact coordinates, retained obligations, universal
callee closure, sealed caller/native/dependency facts and deadline — while
caller-graph captures scale with the census instead of the call count.
"""
from __future__ import annotations

import time
from dataclasses import replace

import pytest

import inertia.ir.near_call_jump_scope as ncjs
import inertia.ir.near_call_preservation as ncp
import inertia.ir.source_graph_binding as sgb
import inertia.semantics.conditional_near_call_target as cnt
from inertia.cli.project_loading import _build_project_from_bytes
from inertia.frontend.x86_16 import near_call_entry_context as nec
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from inertia.ir import near_call_census as bp
from inertia.ir import near_call_entry_pipeline as oep
from inertia.ir.direct_evidence_deadline import (
    direct_evidence_deadline_scope_8616,
)
from inertia.ir.near_call_jump_scope import (
    NearCallJumpScope8616,
    authenticate_near_call_jump_scope_8616,
)
from inertia.ir.near_call_preservation import (
    ConditionalNearCallPreservationFailure8616,
    ConditionalNearCallPreservationVerdict8616,
    prove_near_call_preservation_from_coordinates_8616,
)
from inertia.ir.vex_import import (
    build_x86_16_ir_function_artifact,
    prove_scoped_x86_16_ir_function_view_8616,
    raw_x86_16_import_bundle_for_artifact_8616,
)
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallCoordinates8616,
)
from tests.ir.test_near_call_entry_pipeline import _installed
from tests.ir.test_near_call_preservation import (
    _CODE,
    _LEAF,
    _OUTGOING,
    _decode,
    _index,
    _premise,
    _resolver,
    _Surface,
    _surface,
)

pytestmark = pytest.mark.decompiler

_TWO_CALL_CODE = bytes.fromhex(
    "e80d00"  # 0x1000: incoming near CALL -> root 0x1010
    "9090909090"  # 0x1003: filler
    "c3"  # 0x1008: earlier leaf RET, external to the root range
    "90909090909090"  # 0x1009: filler
    "e8f5ff"  # 0x1010: first outgoing near CALL -> leaf 0x1008
    "e8f2ff"  # 0x1013: second outgoing near CALL -> leaf 0x1008
    "c3"  # 0x1016: root RET
)

_ZERO_CALL_CODE = bytes.fromhex(
    "e80d00"  # 0x1000: incoming near CALL -> root 0x1010
    "9090909090"  # 0x1003: filler
    "c3"  # 0x1008: earlier leaf RET, unused by this fixture
    "90909090909090"  # 0x1009: filler
    "c3"  # 0x1010: root RET; the root range holds no outgoing CALL
)


def _zero_call_surface() -> tuple[object, object, object]:
    """Assemble a bound incoming context over a root with zero CALLs."""
    project = _build_project_from_bytes(
        _ZERO_CALL_CODE, base_addr=0x1000, entry_point=0x1000,
    )
    boundary = exact_function_range_boundary_8616(project, 0x1010, 0x1011)
    assert boundary is not None
    row = DecodedDirectCallsite8616(
        caller_start=0x1000,
        instructions=(_decode(_ZERO_CALL_CODE[:3], 0x1000),),
        instruction_index=0,
        callsite_addr=0x1000,
        target_addr=0x1010,
    )
    index = _index(row, 0x1010)
    premise = _premise(row, index, 0x1010)
    context = nec.bind_native_near_call_entry_8616(
        project, boundary, premise, callsite_index=index,
    )
    assert type(context) is nec.NativeNearCallEntry8616
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    assert not any(
        instruction.op == "CALL"
        for block in artifact.blocks
        for instruction in block.instrs
    )
    return project, artifact, context


def _census(
    surface: _Surface,
) -> tuple[bp._CensusCall8616, ...]:
    """Build typed census entries for every CALL in the surface's artifact."""
    entries = []
    for block in surface.artifact.blocks:
        for instruction in block.instrs:
            if instruction.op == "CALL":
                entries.append(bp._CensusCall8616(
                    block, instruction,
                    DirectNearCallCoordinates8616(
                        instruction.addr, instruction.addr + 3, _LEAF,
                    ),
                ))
    return tuple(entries)


def _baseline_steps(
    surface: _Surface,
) -> tuple[object, ...]:
    """Produce steps through the standalone per-call factory."""
    return tuple(
        prove_near_call_preservation_from_coordinates_8616(
            surface.project, artifact=surface.artifact,
            context=surface.context, block=call.block,
            instruction=call.instruction, coordinates=call.coordinates,
            direct_target_resolver=_resolver(surface.project),
        )
        for call in _census(surface)
    )


def _batched_steps(
    surface: _Surface,
) -> object:
    """Produce steps through the batched census producer."""
    return bp.prove_near_call_preservation_census_8616(
        surface.project, _census(surface), artifact=surface.artifact,
        context=surface.context,
        direct_target_resolver=_resolver(surface.project),
    )


def _capture_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, object]]:
    """Count canonical caller-graph captures across every owning module."""
    captured = []

    def wrap(module: object) -> None:
        original = module.capture_immutable_source_graph_facts_8616

        def counted(*args: object, **kwargs: object) -> object:
            captured.append((module.__name__, args[0]))
            return original(*args, **kwargs)

        monkeypatch.setattr(
            module, "capture_immutable_source_graph_facts_8616", counted,
        )

    for module in (sgb, ncp, ncjs, cnt):
        wrap(module)
    return captured


def test_batched_steps_match_standalone_two_call_census() -> None:
    """Batched records equal the standalone factory's evidence exactly."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    baseline = _baseline_steps(surface)
    assert all(
        step.verdict is ConditionalNearCallPreservationVerdict8616.CONDITIONAL
        for step in baseline
    )
    batched = _batched_steps(surface)
    assert not isinstance(
        batched, ConditionalNearCallPreservationFailure8616,
    )
    assert len(batched) == len(baseline) == 2
    for expected, produced in zip(baseline, batched, strict=True):
        assert produced.to_dict() == expected.to_dict()
        assert produced.theorem.to_dict() == expected.theorem.to_dict()
        assert produced.obligation == expected.obligation
        assert produced.callee_addr == expected.callee_addr
        assert produced.callee.coverage.artifact is expected.callee.coverage.artifact


def test_batched_steps_authenticate_in_consumer_scope() -> None:
    """Produced steps feed the canonical jump-scope census and scoped view."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    steps = _batched_steps(surface)
    scope = NearCallJumpScope8616(
        surface.project, surface.artifact, surface.context,
        _resolver(surface.project), steps,
    )
    assert authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
    loop_surface = _surface(
        _CODE[:-1] + b"\x90" * 13 + bytes.fromhex("ebee"), root_end=0x1022,
    )
    loop_steps = _batched_steps(loop_surface)
    loop_scope = NearCallJumpScope8616(
        loop_surface.project, loop_surface.artifact, loop_surface.context,
        _resolver(loop_surface.project), loop_steps,
    )
    bundle = raw_x86_16_import_bundle_for_artifact_8616(
        loop_surface.project, loop_surface.boundary, loop_surface.artifact,
    )
    view = prove_scoped_x86_16_ir_function_view_8616(
        loop_surface.project, bundle, loop_surface.boundary,
        near_call_scope=loop_scope,
    )
    assert view.failure is None, view.detail
    assert view.near_call_scope is loop_scope
    assert view.complete_for(loop_scope)


def test_caller_graph_captures_scale_with_census_not_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """One capture per census phase replaces the per-call capture fan-out."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    captured = _capture_counter(monkeypatch)
    _baseline_steps(surface)
    baseline = [entry for entry in captured
                if entry[1] == surface.artifact.function_addr]
    del captured[:]
    _batched_steps(surface)
    batched = [entry for entry in captured
               if entry[1] == surface.artifact.function_addr]
    # baseline captures the caller graph ~4x per CALL across the target
    # factory, preservation snapshot and both seals (10 measured before the
    # preservation preseal optimization, 8 since, for this two-call
    # fixture); the batched census captures once per phase regardless of
    # call count.
    assert len(baseline) >= 4 * len(batched)
    assert len(batched) == 2


def test_staged_records_reject_boolean_use() -> None:
    """Staged fresh theorems and census calls are never authority."""
    surface = _surface()
    (call,) = _census(surface)
    staged = cnt._staged_fresh_theorem_8616(
        surface.project, artifact=surface.artifact, context=surface.context,
        block=call.block, instruction=call.instruction,
        coordinates=call.coordinates,
    )
    assert staged.status is cnt._ScopedTargetStage8616.STAGED
    with pytest.raises(TypeError, match="final whole-census seal"):
        bool(staged)
    refused = cnt._ScopedFreshTheorem8616(cnt._ScopedTargetStage8616.REFUSED)
    with pytest.raises(TypeError, match="final whole-census seal"):
        bool(refused)


@pytest.mark.parametrize(
    "bad_entry", ["object", "op", "coordinates", "duplicate"],
)
def test_missing_duplicate_or_foreign_census_refuses(bad_entry: str) -> None:
    """Untyped, mismatched or duplicated census entries refuse honestly."""
    surface = _surface()
    (call,) = _census(surface)
    if bad_entry == "object":
        census = (object(),)
    elif bad_entry == "op":
        census = (bp._CensusCall8616(
            call.block, replace(call.instruction, op="MOV"), call.coordinates,
        ),)
    elif bad_entry == "coordinates":
        census = (bp._CensusCall8616(call.block, call.instruction, object()),)
    else:
        census = (call, call)
    result = bp.prove_near_call_preservation_census_8616(
        surface.project, census, artifact=surface.artifact,
        context=surface.context,
        direct_target_resolver=_resolver(surface.project),
    )
    assert result is ConditionalNearCallPreservationFailure8616.CALLER_MISMATCH
    foreign = bp.prove_near_call_preservation_census_8616(
        surface.project, _census(surface), artifact=object(),
        context=surface.context,
        direct_target_resolver=_resolver(surface.project),
    )
    assert foreign is ConditionalNearCallPreservationFailure8616.CALLER_MISMATCH


def test_empty_census_returns_empty_tuple() -> None:
    """A caller with no outgoing CALLs keeps the standalone empty result."""
    project, artifact, context = _zero_call_surface()
    assert bp.prove_near_call_preservation_census_8616(
        project, (), artifact=artifact, context=context,
        direct_target_resolver=_resolver(project),
    ) == ()
    surface = _surface()
    assert bp.prove_near_call_preservation_census_8616(
        surface.project, (), artifact=surface.artifact,
        context=surface.context,
        direct_target_resolver=_resolver(surface.project),
    ) is ConditionalNearCallPreservationFailure8616.CALLER_MISMATCH


def test_subset_reordered_or_extended_census_refuses() -> None:
    """Only the exact artifact CALL census in order may publish steps."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    census = _census(surface)
    assert len(census) == 2
    other = _surface()
    foreign = bp._CensusCall8616(other.block, other.call, other.coordinates)
    for bad in (
        census[:1],
        census[1:],
        census[::-1],
        (*census, foreign),
        (census[0], census[0], census[1]),
    ):
        result = bp.prove_near_call_preservation_census_8616(
            surface.project, bad, artifact=surface.artifact,
            context=surface.context,
            direct_target_resolver=_resolver(surface.project),
        )
        assert result is (
            ConditionalNearCallPreservationFailure8616.CALLER_MISMATCH
        )


def test_expired_deadline_refuses_before_any_work() -> None:
    """An elapsed request deadline refuses the census up front."""
    surface = _surface()
    with direct_evidence_deadline_scope_8616(
        surface.project, time.monotonic() - 1.0,
    ):
        result = bp.prove_near_call_preservation_census_8616(
            surface.project, _census(surface), artifact=surface.artifact,
            context=surface.context,
            direct_target_resolver=_resolver(surface.project),
        )
    assert result is ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED


def test_final_callback_cannot_mutate_caller_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    """A final entry callback cannot hide caller IR drift."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    original = bp.consume_native_near_call_entry_8616
    calls = 0

    def mutate(*args: object, **kwargs: object) -> object:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            instruction = next(
                i for b in surface.artifact.blocks for i in b.instrs
                if i.op != "CALL"
            )
            object.__setattr__(instruction, "op", "CHANGED")
        return result

    monkeypatch.setattr(
        bp, "consume_native_near_call_entry_8616", mutate,
    )
    result = _batched_steps(surface)
    assert result is ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED


def test_final_callback_cannot_mutate_context_scalars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Context scalar drift at the last callback trips the caller seal."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    original = bp.consume_native_near_call_entry_8616
    calls = 0

    def mutate(*args: object, **kwargs: object) -> object:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            object.__setattr__(surface.context, "selector_high", -1)
        return result

    monkeypatch.setattr(
        bp, "consume_native_near_call_entry_8616", mutate,
    )
    result = _batched_steps(surface)
    assert result is ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED


@pytest.mark.parametrize("address", [0x1000, 0x1008, 0x1011])
def test_final_callback_cannot_mutate_native_bytes(monkeypatch: pytest.MonkeyPatch, address: int) -> None:
    """Incoming, callee and caller live bytes stay pinned across callbacks."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    original = bp.consume_native_near_call_entry_8616
    calls = 0

    def mutate(*args: object, **kwargs: object) -> object:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            surface.project.loader.memory.store(address, b"\x90")
        return result

    monkeypatch.setattr(
        bp, "consume_native_near_call_entry_8616", mutate,
    )
    result = _batched_steps(surface)
    assert isinstance(result, ConditionalNearCallPreservationFailure8616)


def test_final_callback_cannot_mutate_callee_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Staged callee projections refuse drift at the final dependency seal."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    original = bp.consume_native_near_call_entry_8616
    steps_holder = []
    staged = bp._stage_census_call_8616

    def seen_stage(*args: object, **kwargs: object) -> object:
        result = staged(*args, **kwargs)
        steps_holder.append(result)
        return result

    monkeypatch.setattr(bp, "_stage_census_call_8616", seen_stage)
    calls = 0

    def mutate(*args: object, **kwargs: object) -> object:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            first = steps_holder[0]
            object.__setattr__(
                first.callee, "raw_fact_count", first.callee.raw_fact_count + 1,
            )
        return result

    monkeypatch.setattr(
        bp, "consume_native_near_call_entry_8616", mutate,
    )
    result = _batched_steps(surface)
    assert result is ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED


@pytest.mark.parametrize("forge_coordinates", [False, True])
def test_final_derivation_rejects_forged_staged_theorem(monkeypatch: pytest.MonkeyPatch, forge_coordinates: bool) -> None:
    """A staged theorem forged after every seal fails pure derivation."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    theorems = []
    staged_theorem = bp._staged_fresh_theorem_8616

    def seen_theorem(*args: object, **kwargs: object) -> object:
        result = staged_theorem(*args, **kwargs)
        theorems.append(result.theorem)
        return result

    monkeypatch.setattr(
        bp, "_staged_fresh_theorem_8616", seen_theorem,
    )
    owned = bp._final_owned_seal_8616
    forged_once = [False]

    def forged(*args: object, **kwargs: object) -> object:
        result = owned(*args, **kwargs)
        if result is None and theorems and not forged_once[0]:
            forged_once[0] = True
            if forge_coordinates:
                object.__setattr__(
                    theorems[0], "target_addr", theorems[0].target_addr ^ 0x10,
                )
            else:
                object.__setattr__(
                    theorems[0].stats, "raw_fact_count", theorems[0].stats.raw_fact_count + 1,
                )
        return result

    monkeypatch.setattr(bp, "_final_owned_seal_8616", forged)
    result = _batched_steps(surface)
    expected = (
        ConditionalNearCallPreservationFailure8616.CALLER_MISMATCH
        if forge_coordinates
        else ConditionalNearCallPreservationFailure8616.THEOREM_NOT_AUTHENTICATED
    )
    assert result is expected


@pytest.mark.parametrize("callback", ["staging", "entry"])
def test_staging_callback_cannot_replace_entry_witness(monkeypatch: pytest.MonkeyPatch, callback: str) -> None:
    """An equal replacement witness cannot reset the initial context identity."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    if callback == "staging":
        owner, name = cnt, "direct_near_call_target_is_bound_8616"
        original = cnt.direct_near_call_target_is_bound_8616
    else:
        owner, name = bp, "consume_native_near_call_entry_8616"
        original = bp.consume_native_near_call_entry_8616
    changed = False

    def replace_witness(*args: object, **kwargs: object) -> object:
        nonlocal changed
        result = original(*args, **kwargs)
        if not changed:
            changed = True
            object.__setattr__(
                surface.context, "callee_witness", replace(surface.context.callee_witness),
            )
        return result

    monkeypatch.setattr(owner, name, replace_witness)
    result = _batched_steps(surface)
    assert changed
    assert result is ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED


@pytest.mark.parametrize("address", [0x1000, 0x1008, 0x1011])
def test_callee_chain_callback_cannot_mutate_native_bytes(monkeypatch: pytest.MonkeyPatch, address: int) -> None:
    """Byte drift inside the final callee seal trips the later seals."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    chain = bp._callee_chain_failure_8616
    fired = [False]

    def mutate(*args: object, **kwargs: object) -> object:
        result = chain(*args, **kwargs)
        if not fired[0]:
            fired[0] = True
            surface.project.loader.memory.store(address, b"\x90")
        return result

    monkeypatch.setattr(bp, "_callee_chain_failure_8616", mutate)
    result = _batched_steps(surface)
    assert fired[0]
    assert isinstance(result, ConditionalNearCallPreservationFailure8616)


def test_callee_chain_callback_cannot_mutate_staged_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Theorem/callee drift inside the final callee seal trips later seals."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    steps_holder = []
    staged = bp._stage_census_call_8616

    def seen_stage(*args: object, **kwargs: object) -> object:
        result = staged(*args, **kwargs)
        steps_holder.append(result)
        return result

    monkeypatch.setattr(bp, "_stage_census_call_8616", seen_stage)
    chain = bp._callee_chain_failure_8616
    fired = [False]

    def mutate(*args: object, **kwargs: object) -> object:
        result = chain(*args, **kwargs)
        if not fired[0] and steps_holder:
            fired[0] = True
            first = steps_holder[0]
            object.__setattr__(
                first.callee, "raw_fact_count", first.callee.raw_fact_count + 1,
            )
            object.__setattr__(
                first.theorem, "target_addr", first.theorem.target_addr ^ 0x10,
            )
        return result

    monkeypatch.setattr(bp, "_callee_chain_failure_8616", mutate)
    result = _batched_steps(surface)
    assert fired[0]
    assert isinstance(result, ConditionalNearCallPreservationFailure8616)


def test_deadline_expiring_after_callbacks_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Expiry surfacing after the last callback still refuses promotion."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    original_deadline = bp.direct_evidence_deadline_expired_8616
    original_consume = bp.consume_native_near_call_entry_8616
    expired = [False]
    consumes = [0]

    def consume(*args: object, **kwargs: object) -> object:
        result = original_consume(*args, **kwargs)
        consumes[0] += 1
        if consumes[0] == 2:
            expired[0] = True
        return result

    def deadline(project: object) -> bool:
        return expired[0] or bool(original_deadline(project))

    monkeypatch.setattr(bp, "consume_native_near_call_entry_8616", consume)
    monkeypatch.setattr(
        bp, "direct_evidence_deadline_expired_8616", deadline,
    )
    result = _batched_steps(surface)
    assert result is ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED


def test_transient_mutation_restored_leaves_admissible_census(monkeypatch: pytest.MonkeyPatch) -> None:
    """Corruption repaired inside one callback is invisible to final derive."""
    surface = _surface(_TWO_CALL_CODE, root_end=0x1017)
    from inertia.ir.core import IRValue, MemSpace

    preflight = cnt.prove_direct_near_call_target_binding_at_coordinates_8616
    other = next(
        i for b in surface.artifact.blocks for i in b.instrs
        if i.op == "CALL" and i.addr != _OUTGOING
    )
    calls = 0

    def corrupt_then_restore(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls != 1:
            return preflight(*args, **kwargs)
        saved = other.args[0]
        object.__setattr__(
            other, "args", (IRValue(MemSpace.CONST, const=0, size=4),),
        )
        try:
            return preflight(*args, **kwargs)
        finally:
            object.__setattr__(other, "args", (saved,))

    monkeypatch.setattr(
        cnt, "prove_direct_near_call_target_binding_at_coordinates_8616",
        corrupt_then_restore,
    )
    steps = _batched_steps(surface)
    assert not isinstance(
        steps, ConditionalNearCallPreservationFailure8616,
    )
    assert len(steps) == 2


def test_pipeline_prepares_conditional_entry() -> None:
    """The patched pipeline composes the batched census end to end."""
    surface, _source = _installed()
    result = oep.prepare_near_call_entry_pipeline_8616(
        surface.project, surface.boundary,
    )
    assert result.status is oep.NearCallEntryPipelineStatus8616.CONDITIONAL, (
        result.to_dict()
    )
    entry = result.entry
    assert entry is not None
    assert entry.authenticates(surface.project)
    assert len(entry.scope.preservations) == 1
    step = entry.scope.preservations[0]
    assert step.verdict is ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    assert step.callsite_addr == _OUTGOING
    assert step.callee_addr == _LEAF
    from inertia.ir.entry_domain_call_preservation import (
        install_real16_invocation_source_8616,
    )
    install_real16_invocation_source_8616(surface.project, None)
    result = oep.prepare_near_call_entry_pipeline_8616(
        surface.project, surface.boundary,
    )
    assert result.status is oep.NearCallEntryPipelineStatus8616.REFUSED


from tests.ir.test_near_call_jump_scope import _scoped_two_call


def test_final_callee_callback_cannot_change_native_caller(monkeypatch):
    surface = _surface()
    census=(bp._CensusCall8616(surface.block,surface.call,surface.coordinates),)
    original=bp._callee_chain_failure_8616
    fired=[]
    def mutate(*args,**kwargs):
        result=original(*args,**kwargs)
        assert result==(None,None)
        surface.project.loader.memory.store(surface.call.addr,b'\x90')
        fired.append(True)
        return result
    monkeypatch.setattr(bp,'_callee_chain_failure_8616',mutate)
    result=bp.prove_near_call_preservation_census_8616(surface.project,census,artifact=surface.artifact,context=surface.context,direct_target_resolver=_resolver(surface.project))
    assert fired
    assert isinstance(result,bp.ConditionalNearCallPreservationFailure8616)

def test_missing_call_in_fresh_census_refuses():
    surface,scope=_scoped_two_call()
    theorem=scope.preservations[0].theorem
    call=bp._CensusCall8616(theorem.block,theorem.instruction,DirectNearCallCoordinates8616(theorem.callsite_addr,theorem.next_addr,theorem.target_addr))
    result=bp.prove_near_call_preservation_census_8616(surface.project,(call,),artifact=surface.artifact,context=surface.context,direct_target_resolver=scope.direct_target_resolver)
    assert isinstance(result,bp.ConditionalNearCallPreservationFailure8616)


def test_callback_cannot_replace_later_census_entry_with_duplicate(monkeypatch):
    surface,scope=_scoped_two_call()
    census=tuple(bp._CensusCall8616(step.theorem.block,step.theorem.instruction,DirectNearCallCoordinates8616(step.theorem.callsite_addr,step.theorem.next_addr,step.theorem.target_addr)) for step in scope.preservations)
    original=bp._stage_census_call_8616
    count=0
    def mutate(*args,**kwargs):
        nonlocal count
        result=original(*args,**kwargs)
        count+=1
        if count==1:
            object.__setattr__(census[1],"block",census[0].block)
            object.__setattr__(census[1],"instruction",census[0].instruction)
            object.__setattr__(census[1],"coordinates",census[0].coordinates)
        return result
    monkeypatch.setattr(bp,"_stage_census_call_8616",mutate)
    result=bp.prove_near_call_preservation_census_8616(surface.project,census,artifact=surface.artifact,context=surface.context,direct_target_resolver=scope.direct_target_resolver)
    assert isinstance(result,bp.ConditionalNearCallPreservationFailure8616)


def test_final_context_expiry_stops_before_owned_graph_capture(monkeypatch):
    surface=_surface()
    census=(bp._CensusCall8616(surface.block,surface.call,surface.coordinates),)
    original=bp.consume_native_near_call_entry_8616
    owned=bp._final_owned_seal_8616
    count=0
    expired=False
    def consume(*args,**kwargs):
        nonlocal count,expired
        result=original(*args,**kwargs)
        count+=1
        if count==2:
            expired=True
        return result
    def capture(*args,**kwargs):
        assert not expired, "owned graph recaptured after final context expired"
        return owned(*args,**kwargs)
    monkeypatch.setattr(bp,'consume_native_near_call_entry_8616',consume)
    monkeypatch.setattr(bp,'direct_evidence_deadline_expired_8616',lambda project: expired)
    monkeypatch.setattr(bp,'_final_owned_seal_8616',capture)
    result=bp.prove_near_call_preservation_census_8616(surface.project,census,artifact=surface.artifact,context=surface.context,direct_target_resolver=_resolver(surface.project))
    assert result is bp.ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED
