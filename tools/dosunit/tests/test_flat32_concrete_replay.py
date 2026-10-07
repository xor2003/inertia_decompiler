"""Concrete replay controls execute real i386 instructions independently of SSA."""

from tools.dosunit.runtime.flat32_memory_permissions import DeclaredAccess, DeclaredRegion, MappingOrigin
from tools.dosunit.runtime.flat32_replay import (
    MemoryRange,
    ObservationStatus,
    ReplayImage,
    ReplayStatus,
    ReplayVector,
    compare_replays,
    replay,
)


def _image(code: bytes) -> ReplayImage:
    return ReplayImage(((0x10000, code),), (MemoryRange(0x10000, len(code)),))


def _vector() -> ReplayVector:
    return ReplayVector((('eax', 0), ('ecx', 3), ('esp', 0x28000)), (), (MemoryRange(0x30000, 4),),
                        (DeclaredRegion(0x30000, 4, DeclaredAccess.READ | DeclaredAccess.WRITE,
                                        MappingOrigin.VECTOR),))


def test_call_loop_memory_replay_and_corruption():
    # call leaf; dec ecx; jne dec; store eax; ret; leaf: mov eax,7; ret
    good = bytes.fromhex('e809000000 49 75fd a300000300 c3 b807000000 c3')
    bad = bytes.fromhex('e809000000 49 75fd a300000300 c3 b808000000 c3')
    first = replay(_image(good), 0x10000, _vector(), instruction_limit=100)
    second = replay(_image(good), 0x10000, _vector(), instruction_limit=100)
    changed = replay(_image(bad), 0x10000, _vector(), instruction_limit=100)
    assert first.status == ReplayStatus.RETURNED
    assert first == second
    assert dict(first.registers)['eax'] == 7
    observation, = first.observations
    assert observation.address == 0x30000 and observation.size == 4
    assert observation.status is ObservationStatus.CAPTURED
    assert observation.data == bytes.fromhex('07000000')
    assert compare_replays(first, second).value == 'agreed'
    assert compare_replays(first, changed).value == 'mismatched'


def test_replay_budget_is_incomplete_and_external_effects_refuse():
    forever = replay(_image(bytes.fromhex('ebfe')), 0x10000, _vector(), instruction_limit=10)
    interrupt = replay(_image(bytes.fromhex('cd21c3')), 0x10000, _vector(), instruction_limit=10)
    assert forever.status == ReplayStatus.BUDGET_EXHAUSTED
    assert interrupt.status == ReplayStatus.UNSUPPORTED
    assert compare_replays(forever, forever).value == 'incomplete'
    assert compare_replays(interrupt, interrupt).value == 'incomplete'


def test_replay_resets_guest_memory_between_vectors():
    image = _image(bytes.fromhex('ff0500000300 a100000300 c3'))
    first = replay(image, 0x10000, _vector(), instruction_limit=10)
    second = replay(image, 0x10000, _vector(), instruction_limit=10)
    assert first.status == ReplayStatus.RETURNED
    assert first == second
    assert dict(first.registers)['eax'] == 1


def test_changed_return_cleanup_and_fault_cannot_agree():
    ordinary = replay(_image(bytes.fromhex('c3')), 0x10000, _vector(), instruction_limit=10)
    cleanup = replay(_image(bytes.fromhex('c20400')), 0x10000, _vector(), instruction_limit=10)
    fault = replay(_image(bytes.fromhex('31d2 31c9 f7f1 c3')), 0x10000, _vector(), instruction_limit=10)
    assert compare_replays(ordinary, cleanup).value == 'mismatched'
    assert fault.status == ReplayStatus.FAULTED
    assert compare_replays(fault, fault).value == 'incomplete'


def test_callee_pointer_store_can_corrupt_a_real_return_slot() -> None:
    """Replay a mapped alias witness: pointer store redirects the callee RET 4."""
    # push 7; call callee; add eax,2; ret. The call pushes its continuation at
    # initial ESP-8; EAX deliberately points there while both guests start.
    caller = '6a07 e804000000 83c002 c3'
    clean = bytes.fromhex(f'{caller} 8b442404 c20400')
    corrupt = bytes.fromhex(f'{caller} c7002a000000 8b442404 c20400')
    stack = 0x28000
    return_slot = stack - 8
    vector = ReplayVector(
        (('eax', return_slot), ('esp', stack)),
        observations=(MemoryRange(return_slot, 4),),
    )
    good = replay(_image(clean), 0x10000, vector, instruction_limit=20)
    bad = replay(_image(corrupt), 0x10000, vector, instruction_limit=20)
    repeated = replay(_image(corrupt), 0x10000, vector, instruction_limit=20)
    assert good.status is ReplayStatus.RETURNED
    assert dict(good.registers)['eax'] == 9
    assert good.observations[0].status is ObservationStatus.CAPTURED
    assert good.observations[0].data == (0x10007).to_bytes(4, 'little')
    assert bad.status is ReplayStatus.FAULTED
    assert dict(bad.registers)['eip'] == 0x2A
    assert bad.observations[0].status is ObservationStatus.CAPTURED
    assert bad.observations[0].data == (0x2A).to_bytes(4, 'little')
    assert bad == repeated
    assert compare_replays(good, bad).value == 'incomplete'
