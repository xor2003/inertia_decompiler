"""Binary-derived returning-SP proofs and their real Alias consumer."""

import json
from dataclasses import replace

import pytest
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_IP, UC_X86_REG_SP, UC_X86_REG_SS

from inertia.alias import callee_stack_pointer
from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616
from inertia.ir.source_graph_binding import canonical_call_stack_effect_8616
from inertia.semantics.call_stack_effects import materialize_call_stack_effects_8616
from tests.alias.test_x86_16_segment_stack_restore import _solve_stack_states
from tests.semantics.test_call_stack_coordinates import _image, _world

pytestmark = pytest.mark.decompiler


def _effect(callee: str):
    code = _image("6a01e80b00f4", callee)
    project, _function, artifact, summary = _world(code, 0x1002)
    result = materialize_call_stack_effects_8616(artifact, {0x1002: summary}, project=project)
    coordinates = result.facts[0].effect.stack_coordinates
    assert coordinates is not None
    return code, project, result, coordinates


@pytest.mark.parametrize(("callee", "net"), [
    ("c3", 0),
    ("5058c3", 0),
    ("c20200", 2),
    ("5589e583ec0489ec5dc20200", 2),
    ("5883c40250c3", 2),
    ("c2ffff", -1),
    ("c20080", -0x8000),
    ("5889e383eb0489dc50c3", -4),
    ("5889e3eb019083eb0489dc50c3", -4),
])
def test_real_body_transfer_reaches_alias(callee: str, net: int) -> None:
    """Body effects, RET cleanup and return-frame pop are counted once."""
    _code, _project, result, coordinates = _effect(callee)
    assert coordinates.has_proven_sp_delta
    assert coordinates.callee_return_sp_delta == net + 2
    assert coordinates.net_sp_delta == net
    assert result.facts[0].effect.net_stack_delta == net
    assert _solve_stack_states(result.function)[0x1000].sp_delta == -2 + net


def test_manual_cleanup_matches_real_16_bit_execution() -> None:
    """A normal RET can return with changed SP despite a zero RET immediate."""
    code, _project, result, coordinates = _effect("5883c40250c3")
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0x1000, code)
    machine.reg_write(UC_X86_REG_CS, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_SP, 0x8000)
    before: list[int] = []

    def observe(uc, address, _size, _data):
        if address == 0x1002:
            before.append(uc.reg_read(UC_X86_REG_SP))

    machine.hook_add(UC_HOOK_CODE, observe)
    machine.emu_start(0x1000, 0x1005, count=100)
    assert machine.reg_read(UC_X86_REG_IP) == 0x1005
    assert len(before) == 1
    assert machine.reg_read(UC_X86_REG_SP) - before[0] == 2
    assert coordinates.callee_purged_bytes == 0
    assert coordinates.net_sp_delta == 2
    assert _solve_stack_states(result.function)[0x1000].sp_delta == 0


@pytest.mark.parametrize("callee", ["89dcc3", "85c07401c3c20200"])
def test_unknown_or_disagreeing_return_transfers_refuse(callee: str) -> None:
    """A RET spelling does not close unknown or inconsistent SP dataflow."""
    _code, _project, result, coordinates = _effect(callee)
    assert coordinates.closed
    assert coordinates.net_sp_delta is None
    assert not coordinates.has_proven_sp_delta
    assert result.facts[0].effect.net_stack_delta is None
    assert _solve_stack_states(result.function)[0x1000].sp_delta is None


@pytest.mark.parametrize("corruption", ["net", "purge", "census", "source"])
def test_copied_coordinate_cannot_authorize_foreign_projection(corruption: str) -> None:
    """Retained source evidence must agree with every offered projection."""
    _code, _project, result, coordinates = _effect("5883c40250c3")
    if corruption == "net":
        offered = replace(coordinates, net_sp_delta=0)
    elif corruption == "purge":
        offered = replace(coordinates, callee_purged_bytes=2)
    elif corruption == "census":
        offered = replace(coordinates, materialized_count=7, failure_count=0)
    else:
        offered = replace(coordinates, source=None)
    assert not offered.closed
    assert not offered.has_proven_sp_delta
    rewritten = replace(result.function, blocks=tuple(
        replace(block, instrs=tuple(
            replace(row, call_stack_effect=replace(
                row.call_stack_effect, net_stack_delta=offered.net_sp_delta,
                stack_coordinates=offered,
            )) if row.op == "CALL" else row
            for row in block.instrs
        )) for block in result.function.blocks
    ))
    assert _solve_stack_states(rewritten)[0x1000].sp_delta is None


def test_changed_callee_source_invalidates_retained_effect() -> None:
    """An earlier proof cannot survive replacement of its physical RET bytes."""
    _code, project, result, coordinates = _effect("c3")
    assert coordinates.has_proven_sp_delta
    project.loader.memory.store(0x1010, b"\x90")
    assert not coordinates.has_proven_sp_delta
    assert _solve_stack_states(result.function)[0x1000].sp_delta is None


@pytest.mark.parametrize(("callee", "delta"), [("c3", 2), ("5883c40250c3", 4)])
def test_return_projection_checks_the_live_body_once_per_read(
    monkeypatch: pytest.MonkeyPatch, callee: str, delta: int,
) -> None:
    """One projection reuses its body check; a later read must recheck source."""
    _code, project, _result, coordinates = _effect(callee)
    proof = coordinates.callee_sp_proof
    assert proof is not None
    original = callee_stack_pointer._return_transfers_8616
    checks = 0

    def counted(
        coverage: IRBoundaryCoverageResult8616,
    ) -> tuple[callee_stack_pointer.CalleeStackPointerFailure8616 | None, tuple[tuple[int, int], ...]]:
        """Observe the actual Alias proof without replacing any verdict or data."""
        nonlocal checks
        checks += 1
        return original(coverage)

    monkeypatch.setattr(callee_stack_pointer, "_return_transfers_8616", counted)
    assert proof.return_sp_delta == delta
    assert checks == 1
    project.loader.memory.store(0x1010, b"\x90")
    assert proof.return_sp_delta is None
    assert checks == 2


@pytest.mark.parametrize("callee", ["c3", "5883c40250c3"])
def test_canonical_effect_observes_one_coherent_coordinate_projection(
    monkeypatch: pytest.MonkeyPatch, callee: str,
) -> None:
    """One finite serialization bounds proof work and still detects changed bytes."""
    _code, project, result, _coordinates = _effect(callee)
    original = callee_stack_pointer._return_transfers_8616
    checks = 0

    def counted(
        coverage: IRBoundaryCoverageResult8616,
    ) -> tuple[callee_stack_pointer.CalleeStackPointerFailure8616 | None, tuple[tuple[int, int], ...]]:
        """Retain the real current-source proof and count its observations."""
        nonlocal checks
        checks += 1
        return original(coverage)

    monkeypatch.setattr(callee_stack_pointer, "_return_transfers_8616", counted)
    effect = result.facts[0].effect
    before = canonical_call_stack_effect_8616(effect)
    assert 1 <= checks <= 2
    project.loader.memory.store(0x1010, b"\x90")
    after = canonical_call_stack_effect_8616(effect)
    assert before != after
    payload = json.loads(after)
    node = payload["nodes"][payload["root"]]
    assert node["current_net_stack_delta"] is None
    assert json.loads(node["stack_coordinates"])["sp_delta_proven"] is False


def test_invalid_argument_anchor_refuses_without_rendering_it() -> None:
    """A malformed layout is a non-result before diagnostic serialization."""
    _code, _project, _result, coordinates = _effect("c3")
    assert coordinates.argument_top is not None
    malformed = replace(coordinates.argument_top, anchor="unknown")
    changed = replace(coordinates, argument_top=malformed)
    assert not changed.closed
    assert not changed.has_proven_sp_delta
    assert not changed.complete


@pytest.mark.parametrize(("caller", "callee", "delta"), [
    ("9a10100000f4", "cb", 4),
    ("9a10100000f4", "ca0200", 6),
    ("9a10000001f4", "cb", 4),
])
@pytest.mark.parametrize("corruption", ["call", "body"])
def test_immediate_far_call_consumes_the_real_returning_body(
    caller: str, callee: str, delta: int, corruption: str,
) -> None:
    """A mapped word far CALL consumes body SP flow, including explicit purge."""
    code = _image(caller, callee)
    project, _function, artifact, summary = _world(code, 0x1000)
    result = materialize_call_stack_effects_8616(artifact, {0x1000: summary}, project=project)
    coordinates = result.facts[0].effect.stack_coordinates
    assert coordinates is not None
    assert coordinates.return_frame_bytes == 4
    assert coordinates.has_proven_sp_delta
    assert coordinates.callee_return_sp_delta == delta
    assert result.facts[0].effect.current_net_stack_delta == delta - 4
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0x1000, code)
    machine.reg_write(UC_X86_REG_CS, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_SP, 0x8000)
    machine.emu_start(0x1000, 0x1005, count=100)
    assert machine.reg_read(UC_X86_REG_IP) == 0x1005
    assert machine.reg_read(UC_X86_REG_CS) == 0
    assert machine.reg_read(UC_X86_REG_SP) - 0x8000 == delta - 4
    project.loader.memory.store(0x1000 if corruption == "call" else 0x1010, b"\x90")
    assert not coordinates.has_proven_sp_delta
    assert result.facts[0].effect.current_net_stack_delta is None


def test_operand_size_prefixed_call_has_no_word_frame_proof() -> None:
    """A physical CALL32 cannot inherit the summary's word CALL spelling."""
    project, _function, artifact, summary = _world(_image("66e80a000000c3", "c3"), 0x1000)
    result = materialize_call_stack_effects_8616(artifact, {0x1000: summary}, project=project)
    coordinates = result.facts[0].effect.stack_coordinates
    assert coordinates is not None
    assert coordinates.return_frame_bytes is None
    assert coordinates.net_sp_delta is None
    assert not coordinates.has_proven_sp_delta


def test_all_known_slots_require_the_same_source_and_census() -> None:
    """A complete field census is rechecked against every retained projection."""
    code = _image("6a016a02e8090083c402c3", "5589e58b46045dc20200")
    project, _function, artifact, summary = _world(code, 0x1004)
    result = materialize_call_stack_effects_8616(artifact, {0x1004: summary}, project=project)
    coordinates = result.facts[0].effect.stack_coordinates
    assert coordinates is not None and coordinates.complete
    assert coordinates.raw_fact_count == coordinates.materialized_count == 7
    assert not replace(coordinates, caller_cleanup_bytes=4).complete
    assert not replace(coordinates, classified_fact_count=0).closed
    assert not replace(coordinates, net_sp_delta=True).closed


@pytest.mark.parametrize("callee", ["5889e383eb0489dc50c3", "5889e3eb019083eb0489dc50c3"])
@pytest.mark.parametrize("initial_sp", [4, 0x100, 0x8000, 0xfffe])
def test_affine_general_register_stack_transfer_matches_execution(callee, initial_sp):
    """A copied word-SP value remains exact across register arithmetic and CFG edges."""
    code, _project, _result, coordinates = _effect(callee)
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0x1000, code)
    machine.reg_write(UC_X86_REG_CS, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_SP, initial_sp)
    before = []

    def observe(uc, address, _size, _data):
        if address == 0x1002:
            before.append(uc.reg_read(UC_X86_REG_SP))

    machine.hook_add(UC_HOOK_CODE, observe)
    machine.emu_start(0x1000, 0x1005, count=100)
    assert machine.reg_read(UC_X86_REG_IP) == 0x1005
    assert len(before) == 1
    actual = (machine.reg_read(UC_X86_REG_SP) - before[0]) & 0xffff
    assert actual == 0xfffc
    assert coordinates.has_proven_sp_delta
    assert coordinates.net_sp_delta == -4
    assert coordinates.callee_return_sp_delta == -2
