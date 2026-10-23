"""Controls for declared vector services over live path memory."""
from dataclasses import replace

import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.real16_declared_interrupt8616 import (
    DeclaredInterruptRefusal8616,
    DeclaredInterruptService8616,
    declared_environment_digest_8616,
    declared_service_arena_8616,
    declared_vector_expectation_8616,
)
from tests.ir import test_x86_16_declared_interrupt_boundary as native
from tools.dosunit.runtime.real16_declared_invocation8616 import declared_int21_vector_service_8616


def _world() -> tuple:
    ivt = bytearray(native._ivt_bytes())
    ivt[0x40:0x44] = bytes.fromhex("34127856")
    boot = native._boot(native._environment(ivt=bytes(ivt)))
    project, _boundary, artifact, _coverage = native._world(boot)
    instruction = next(i for b in artifact.blocks for i in b.instrs if i.op == "CALL" and i.addr == native.INT_ADDR)
    relations = {}
    for function in (0x25, 0x35):
        relation = declared_int21_vector_service_8616(boot.environment, caller_addr=native.MODULE_BASE, callsite_addr=native.INT_ADDR, function=function)
        assert isinstance(relation, DeclaredInterruptService8616)
        relations[function] = relation
    ctx = owner._PathCensusContext8616(
        project=project, selector=native.LOAD_SEGMENT, image=boot.image, boot=boot,
        chain=None, call_preservations=(), entry_call_preservations=(), declared_services=(),
        environment_digest=declared_environment_digest_8616(boot.environment),
        environment=boot.environment, arena=declared_service_arena_8616(boot.environment),
        service_consumptions=[], stop_block_addr=None, callsite_addr=None,
        callsite_call_state=None, callsite_memory=None, manifest=set(), machine_bytes={},
        native_blocks={}, checked_stores=0, censused_callees=set(), raw_facts=set(),
        normalized_facts=set(), classified_facts=set(), materialized_facts=set(),
        failures=0, work_units=0, work_limit=1000, deadline=float("inf"),
    )
    registers = {"eax": 0xABCD3510, "ebx": 0xDEADFFFF, "ecx": 0xCAFEBABE,
                 "edx": 0xBEEF4321, "esi": 0xFACE1234, "edi": 0xBAD01234,
                 "ebp": 0x12345678, "esp": 0x100, "eflags": 0x202,
                 "ds": 0x789A, "es": 0x1234, "ss": native.LOAD_SEGMENT + 0x20,
                 "cs": native.LOAD_SEGMENT, "fs": 3, "gs": 4}
    return ctx, artifact, instruction, relations, registers, owner.PathMemory8616()


def _cross(world: tuple, function: int):
    ctx, artifact, instruction, relations, registers, memory = world
    ctx.declared_services = (relations[function],)
    registers["eax"] = (registers["eax"] & 0xFFFF00FF) | (function << 8)
    return owner._declared_service_crossing_8616(ctx, artifact, instruction, registers, memory)


def test_live_query_update_query_preserves_high_words() -> None:
    world = _world()
    ctx, _artifact, _instruction, _relations, registers, memory = world
    original = dict(registers)
    assert _cross(world, 0x35) is None
    assert registers["ebx"] == 0xDEAD1234
    assert registers["es"] == 0x5678
    for name in ("ecx", "edx", "esi", "edi", "ebp", "esp", "eflags", "ds", "ss", "fs", "gs"):
        assert registers[name] == original[name]
    before_set = dict(registers)
    assert _cross(world, 0x25) is None
    for name, value in before_set.items():
        if name != "eax":
            assert registers[name] == value
    assert bytes(memory.known[0x40+i] for i in range(4)) == bytes.fromhex("21439a78")
    assert _cross(world, 0x35) is None
    assert registers["ebx"] == 0xDEAD4321 and registers["es"] == 0x789A
    assert len(ctx.service_consumptions) == 3
    assert ctx.checked_stores == 4


def test_identical_set_is_a_real_write_and_code_alias_refuses() -> None:
    world = _world()
    ctx, _artifact, _instruction, _relations, registers, memory = world
    registers["ds"] = 0x5678
    registers["edx"] = 0x1234
    assert _cross(world, 0x25) is None
    assert ctx.checked_stores == 2
    assert bytes(memory.known[0x40+i] for i in range(4)) == bytes.fromhex("34127856")
    world = _world()
    ctx, _artifact, _instruction, _relations, registers, _memory = world
    registers["ds"] = 0x5678
    registers["edx"] = 0x1234
    ctx.manifest.add((0x40, 4))
    assert _cross(world, 0x25) is owner.Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    assert not ctx.service_consumptions


@pytest.mark.parametrize("corruption", ["digest", "site", "frame", "unknown", "tainted", "dispatch", "selector"])
def test_unproven_vector_effect_refuses(corruption: str) -> None:
    world = _world()
    ctx, _artifact, _instruction, relations, registers, memory = world
    if corruption == "digest":
        relations[0x35] = replace(relations[0x35], environment_sha256="0"*64)
    elif corruption == "site":
        relations[0x35] = replace(relations[0x35], callsite_addr=native.INT_ADDR+1)
    elif corruption == "frame":
        registers["ss"] = 0
        registers["esp"] = 0x46
    elif corruption == "unknown":
        memory.apply_write(0x40, 1, None)
    elif corruption == "tainted":
        memory.tainted = True
    elif corruption == "dispatch":
        memory.apply_write(0x84, 4, b"\0"*4)
    else:
        del registers["eax"]
    if corruption == "selector":
        ctx.declared_services = (relations[0x35],)
        result = owner._declared_service_crossing_8616(ctx, world[1], world[2], registers, memory)
    else:
        result = _cross(world, 0x35)
    assert result is not None
    assert not ctx.service_consumptions


@pytest.mark.parametrize("function", [True, 0x35 + 0.0, 0x30])
def test_unsupported_or_untyped_function_refuses(function: object) -> None:
    boot = native._boot()
    assert isinstance(declared_vector_expectation_8616(boot.environment, function), DeclaredInterruptRefusal8616)
    assert isinstance(declared_int21_vector_service_8616(boot.environment, caller_addr=native.MODULE_BASE, callsite_addr=native.INT_ADDR, function=function), DeclaredInterruptRefusal8616)


def test_missing_ivt_refuses() -> None:
    """The declared environment rejects incomplete vector policy before mint."""
    with pytest.raises(ValueError, match="complete declared 1024-byte IVT"):
        native._environment(ivt=native._ivt_bytes()[:0x88])


def test_redirected_dos_service_refuses_without_consumption() -> None:
    """AH25 cannot replace the dispatcher whose model grants its authority."""
    world = _world()
    ctx, _artifact, _instruction, _relations, registers, _memory = world
    registers["eax"] = 0x2521
    assert _cross(world, 0x25) is owner.Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    assert not ctx.service_consumptions


def test_unknown_ebx_high_word_is_not_invented() -> None:
    """Word answers do not invent a full register when no high word is proven."""
    world = _world()
    registers = world[4]
    del registers["ebx"]
    assert _cross(world, 0x35) is None
    assert registers["bx"] == 0x1234
    assert "ebx" not in registers


def test_native_vector_query_proves_whole_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Actual lifted movAH35/INT21 reaches the subsequent native near call."""
    monkeypatch.setattr(native, "CALLER_CODE", bytes.fromhex("b435 cd21 e80100 c3"))
    ivt = bytearray(native._ivt_bytes())
    ivt[0x40:0x44] = bytes.fromhex("34127856")
    boot = native._boot(native._environment(eax=0xABCD0010, ivt=bytes(ivt)))
    project, _boundary, _artifact, coverage = native._world(boot)
    relation = declared_int21_vector_service_8616(boot.environment, caller_addr=native.MODULE_BASE, callsite_addr=native.INT_ADDR, function=0x35)
    assert isinstance(relation, DeclaredInterruptService8616)
    domain = native._premise(project, coverage, boot, (relation,))
    assert domain.failure is None
    assert domain.complete
    assert dict(domain.callsite_call_state)["es"] == 0x5678
    assert len(domain.service_consumptions) == 1


def test_native_vector_update_proves_and_serializes_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lifted AH25 uses proven DS/DX and retains the actual IVT write receipt."""
    monkeypatch.setattr(native, "CALLER_CODE", bytes.fromhex("b425 cd21 e80100 c3"))
    boot = native._boot(native._environment(eax=0xABCD0010))
    project, _boundary, _artifact, coverage = native._world(boot)
    relation = declared_int21_vector_service_8616(boot.environment, caller_addr=native.MODULE_BASE, callsite_addr=native.INT_ADDR, function=0x25)
    assert isinstance(relation, DeclaredInterruptService8616)
    domain = native._premise(project, coverage, boot, (relation,))
    assert domain.failure is None
    assert domain.complete
    (receipt,) = domain.service_consumptions
    expected = bytes.fromhex("0000f001")
    assert receipt.slot_after == expected
    assert receipt.request_ds == native.PSP_SEGMENT
    assert receipt.request_dx == 0
    assert domain.checked_store_count >= 2
    report = domain.to_dict()
    (serialized,) = report["service_consumptions"]
    assert serialized["kind"] == "vector"
    assert serialized["function"] == 0x25
    assert serialized["slot_after_hex"] == expected.hex()
    assert serialized["relation_sha256"] == receipt.relation_sha256
