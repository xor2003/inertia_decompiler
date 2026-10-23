"""Producer ownership and conservative capture selection controls."""

from dataclasses import replace

import pytest

from inertia.ir.condition_ir import ConditionIR, ConditionRegisterBindingIR, ConditionSource
from inertia.ir.condition_lift_capture import ConditionLiftCaptureSession8616
from inertia.ir.core import IRAddress, IRBlock, IRInstr, IRValue, MemSpace
from inertia.ir.dead_temporary_capture_inputs import (
    DeadTemporaryCaptureStatus8616 as Status,
)
from inertia.ir.dead_temporary_capture_inputs import (
    select_dead_temporary_capture_inputs_8616 as select,
)
from inertia.ir.logical_memory_capture import IRLogicalMemoryCaptureRecord8616
from inertia.ir.logical_memory_contracts import IRMemoryAccessKind8616
from inertia.ir.vex_terminal_jump import TerminalJumpEvidence8616, TerminalJumpEvidenceStats8616

pytestmark = pytest.mark.decompiler

def block(address: int, instruction: int) -> IRBlock:
    return IRBlock(address, (IRInstr("MOV", None, (), addr=instruction),))


def test_pending_successor_key_does_not_own_source() -> None:
    value = IRValue(MemSpace.REG, name="ax", source_tmp=7)
    source = ConditionSource("cmp", lhs=value, block_addr=100, addr=101)
    capture = ConditionLiftCaptureSession8616({}, {200: source})
    result = select((block(100, 101), block(200, 201)), capture, (), {})
    assert result.status is Status.COMPLETE
    assert result.blocks[0].payloads[0] is value
    assert result.blocks[1].payloads == ()
    assert capture.pending_sources[200] is source


def test_condition_producer_overrides_consumer_cache_location() -> None:
    value = IRValue(MemSpace.REG, name="ax", source_tmp=3)
    cond = ConditionIR("eq", value, producer_insn=101, block_addr=200)
    result = select((block(100, 101), block(200, 201)),
                    ConditionLiftCaptureSession8616({200: [cond]}, {}), (), {})
    assert result.status is Status.COMPLETE
    assert result.blocks[0].payloads[0] is value
    assert result.blocks[1].payloads == ()


def test_ambiguous_instruction_refuses_only_affected_blocks() -> None:
    source = ConditionSource("cmp", addr=101)
    blocks = (block(100, 101), block(200, 101), block(300, 301))
    result = select(blocks, ConditionLiftCaptureSession8616({}, {900: source}), (), {})
    assert [item.status for item in result.blocks] == [Status.UNKNOWN_REFUSE, Status.UNKNOWN_REFUSE, Status.COMPLETE]


def test_foreign_producer_refuses_whole_surface() -> None:
    source = ConditionSource("cmp", block_addr=999, addr=999)
    result = select((block(100, 101), block(200, 201)),
                    ConditionLiftCaptureSession8616({}, {200: source}), (), {})
    assert all(item.status is Status.UNKNOWN_REFUSE for item in result.blocks)


def test_malformed_binding_retains_known_payload_and_refuses_owner() -> None:
    value = IRValue(MemSpace.REG, name="ax", source_tmp=2)
    source = ConditionSource("cmp", lhs=value, block_addr=100, addr=101,
                             register_bindings=(object(),))
    result = select((block(100, 101), block(200, 201)),
                    ConditionLiftCaptureSession8616({}, {200: source}), (), {})
    assert result.blocks[0].status is Status.UNKNOWN_REFUSE
    assert result.blocks[0].payloads[0] is value
    assert result.blocks[1].status is Status.COMPLETE


def test_binding_and_semantics_roots_are_preserved_without_dependency_walk() -> None:
    value = IRValue(MemSpace.REG, name="ax", source_tmp=2)
    semantics = ("opaque-label", value)
    source = ConditionSource("cmp", block_addr=100, addr=101, semantics=semantics,
                             register_bindings=(ConditionRegisterBindingIR("ax", value),))
    result = select((block(100, 101),), ConditionLiftCaptureSession8616({}, {200: source}), (), {})
    assert result.status is Status.COMPLETE
    assert result.blocks[0].payloads[-2] is semantics
    assert result.blocks[0].payloads[-1] is value


def test_address_payload_preserved_and_unknown_capture_refused() -> None:
    address = IRAddress(MemSpace.DS, base_values=(IRValue(MemSpace.REG, name="bx", source_tmp=2),))
    access = IRLogicalMemoryCaptureRecord8616(100, 100, 101, 0,
                                             IRMemoryAccessKind8616.READ, 16, address)
    capture = ConditionLiftCaptureSession8616({}, {})
    result = select((block(100, 101),), capture, (access,), {})
    assert result.status is Status.COMPLETE
    assert result.blocks[0].payloads == (address,)
    bad = replace(access, kind=IRMemoryAccessKind8616.UNKNOWN)
    assert select((block(100, 101),), capture, (bad,), {}).status is Status.UNKNOWN_REFUSE


def test_terminal_metadata_has_no_value_roots_but_rejects_foreign_contract() -> None:
    evidence = TerminalJumpEvidence8616(False, None, (), None, TerminalJumpEvidenceStats8616(0, 0, 0, 0, 0))
    capture = ConditionLiftCaptureSession8616({}, {})
    result = select((block(100, 101),), capture, (), {100: evidence})
    assert result.status is Status.COMPLETE
    assert result.blocks[0].payloads == ()
    bad = replace(evidence, decoded=object())
    assert select((block(100, 101),), capture, (), {100: bad}).status is Status.UNKNOWN_REFUSE


def test_foreign_binding_value_refuses_owner() -> None:
    source = ConditionSource("cmp", block_addr=100, addr=101,
                             register_bindings=(ConditionRegisterBindingIR("ax", object()),))
    result = select((block(100, 101),), ConditionLiftCaptureSession8616({}, {200: source}), (), {})
    assert result.status is Status.UNKNOWN_REFUSE


def test_incomplete_access_coordinates_refuse_owner() -> None:
    access = IRLogicalMemoryCaptureRecord8616(100, 100, None, 0,
                                             IRMemoryAccessKind8616.READ, 16, IRAddress(MemSpace.DS))
    result = select((block(100, 101),), ConditionLiftCaptureSession8616({}, {}), (access,), {})
    assert result.status is Status.UNKNOWN_REFUSE


def test_foreign_terminal_label_refuses_owner() -> None:
    from inertia.frontend.x86_16.relative_control_edge import decode_relative_edge

    decoded = decode_relative_edge(101, b"\xeb\x00", source="opaque")
    assert decoded is not None
    evidence = TerminalJumpEvidence8616(True, None, (), None, TerminalJumpEvidenceStats8616(1, 1, 0, 0, 0),
                                        replace(decoded, source=object()))
    result = select((block(100, 101),), ConditionLiftCaptureSession8616({}, {}), (), {100: evidence})
    assert result.status is Status.UNKNOWN_REFUSE


@pytest.mark.parametrize("field", ["condition_cache", "pending_sources"])
def test_malformed_capture_container_refuses_surface(field: str) -> None:
    capture = ConditionLiftCaptureSession8616({}, {})
    if field == "condition_cache":
        capture.condition_cache = []
    else:
        capture.pending_sources = []
    result = select((block(100, 101),), capture, (), {})
    assert result.status is Status.UNKNOWN_REFUSE


def test_boolean_cache_key_cannot_bound_unknown_condition() -> None:
    capture = ConditionLiftCaptureSession8616({True: [object()]}, {})
    result = select((block(1, 2), block(100, 101)), capture, (), {})
    assert all(item.status is Status.UNKNOWN_REFUSE for item in result.blocks)


@pytest.mark.parametrize("coordinate", [True, "foreign", -1])
def test_invalid_block_coordinate_refuses_surface(coordinate: object) -> None:
    malformed = replace(block(100, 101), addr=coordinate)
    result = select((malformed, block(200, 201)), ConditionLiftCaptureSession8616({}, {}), (), {})
    assert all(item.status is Status.UNKNOWN_REFUSE for item in result.blocks)


@pytest.mark.parametrize("coordinate", [True, "foreign", -1])
def test_invalid_instruction_coordinate_refuses_only_owned_block(coordinate: object) -> None:
    malformed = IRBlock(100, (IRInstr("MOV", None, (), addr=coordinate),))
    result = select((malformed, block(200, 201)), ConditionLiftCaptureSession8616({}, {}), (), {})
    assert result.blocks[0].status is Status.UNKNOWN_REFUSE
    assert result.blocks[1].status is Status.COMPLETE


@pytest.mark.parametrize("changes", [{"insn_addr": True}, {"block_addr": True},
                                     {"function_addr": True}, {"access_ordinal": -1},
                                     {"address_bits": 0}])
def test_invalid_logical_access_coordinate_refuses(changes: dict[str, object]) -> None:
    access = IRLogicalMemoryCaptureRecord8616(100, 100, 101, 0,
                                             IRMemoryAccessKind8616.READ, 16, IRAddress(MemSpace.DS))
    result = select((block(100, 101),), ConditionLiftCaptureSession8616({}, {}),
                    (replace(access, **changes),), {})
    assert result.status is Status.UNKNOWN_REFUSE


@pytest.mark.parametrize("changes", [{"instruction_addr": True}, {"op": object()},
                                     {"target_register": object()}])
def test_malformed_register_update_metadata_refuses(changes: dict[str, object]) -> None:
    from inertia.ir.condition_ir import ConditionRegisterUpdateIR

    value = IRValue(MemSpace.REG, name="ax", source_tmp=2)
    update = ConditionRegisterUpdateIR(101, "ax", "ADD", value)
    source = ConditionSource("cmp", lhs=value, block_addr=100, addr=101,
                             register_bindings=(ConditionRegisterBindingIR("ax", value, replace(update, **changes)),))
    result = select((block(100, 101),), ConditionLiftCaptureSession8616({}, {200: source}), (), {})
    assert result.status is Status.UNKNOWN_REFUSE
