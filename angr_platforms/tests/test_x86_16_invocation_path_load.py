"""Native declared-memory LOADs must preserve current-path source authority."""
from dataclasses import replace

import pytest
import test_x86_16_declared_resize_boundary as native


def test_native_loaded_resize_argument() -> None:
    """A real LOAD from explicit PSP bytes supplies the declared resize request."""
    env = native._environment()
    allocation = bytearray(env.allocation)
    allocation[2:4] = (0x40).to_bytes(2, "little")
    env = replace(env, allocation=bytes(allocation))
    caller = bytes.fromhex("b80001 8ec0 b8004a 8b1e0200 cd21 e80100 c3")
    boot = native._boot(caller, env)
    project, _, coverage = native._world(boot, len(caller))
    relation = native._resize_relation(env, native.MODULE_BASE + 12)
    premise = native._resize_premise(project, coverage, native.MODULE_BASE + 14, boot, (relation,))
    assert premise.complete
    assert len(premise.service_consumptions) == 1
    assert premise.service_consumptions[0].answer_bx == 0x40
    altered = bytearray(env.allocation)
    altered[2] = 0x41
    object.__setattr__(env, "allocation", bytes(altered))
    assert not premise.complete


@pytest.mark.parametrize("defect", ["clean", "written", "unknown", "tainted", "disagree", "foreign", "width", "capture", "stale"])
def test_path_load_authority(defect: str) -> None:
    """Unproven bytes, malformed reads and stale boot identity yield no constant."""
    from angr_platforms.X86_16.ir.core import IRAddress, IRInstr, IRValue, MemSpace
    from angr_platforms.X86_16.ir.real16_declared_interrupt8616 import declared_environment_digest_8616
    from angr_platforms.X86_16.ir.real16_initial_memory8616 import invocation_initial_memory_8616
    from angr_platforms.X86_16.ir.real16_path_memory8616 import (
        PathMemory8616,
        meet_path_memory_8616,
        path_load_value_8616,
    )

    boot = native._boot()
    digest = declared_environment_digest_8616(boot.environment)
    if defect == "stale":
        object.__setattr__(boot.environment, "allocation", bytes([1]) + boot.environment.allocation[1:])
    initial = invocation_initial_memory_8616(boot.environment, digest, boot.image.chunks)
    address = IRAddress(MemSpace.DS, (), 2, size=2)
    dst = IRValue(MemSpace.TMP, name="t1", size=1 if defect == "width" else 2, source_tmp=None if defect == "capture" else 1)
    instruction = IRInstr("LOAD", dst, (address,), size=2)
    memory = PathMemory8616()
    base = 0xA0000 if defect == "foreign" else native.PSP_SEGMENT * 16 + 2
    if defect == "written":
        memory.apply_write(base, 2, b"\x34\x12")
    elif defect == "unknown":
        memory.apply_write(base, 1, None)
    elif defect == "tainted":
        memory.taint()
    elif defect == "disagree":
        other = PathMemory8616()
        other.apply_write(base, 1, b"\x01")
        memory = meet_path_memory_8616((memory, other))
    result = path_load_value_8616(instruction, (base, 2), memory, initial)
    assert result == (0 if defect == "clean" else 0x1234 if defect == "written" else None)
