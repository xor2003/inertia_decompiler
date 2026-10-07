"""Initialized-MZ boot provenance: header state must stay bound to source bytes.

A ``ProgramBoot`` retains the exact serialized MZ bytes it was derived from.
Any field that no longer matches that retained evidence — entry, stack, image
chunks, fingerprints, environment or the published identity — is refused at
construction and again at replay consumption, so a ``dataclasses.replace`` or
``object.__setattr__`` forgery can never execute under a stale boot identity.
Genuine header mutations made through the factory keep working and produce a
distinct identity with the real changed execution result.
"""

from __future__ import annotations

import dataclasses

import pytest

import tools.dosunit.runtime.real16_program_boot as boot_mod
from tools.dosunit.runtime.real16_program_model import ProgramStatus
from tools.dosunit.runtime.real16_program_replay import replay_program
from tools.dosunit.runtime.real16_replay_model import LinearRange, SegOffset

PSP = 0x0100
LOAD = PSP + 0x10
# Real two-exits shape: entry at IP 0 exits 0; entry at IP 8 exits 7.
IMAGE = bytes.fromhex("b8004ccd21909090b8074ccd21")
ARENA_PARAS = 0x10 + 0x01 + 0x0F  # PSP + module + headroom; stack top 0x1200


def _mz(
    image: bytes = IMAGE,
    *,
    relocs: tuple[tuple[int, int], ...] = (),
    minalloc: int = 0,
    maxalloc: int = 0xFFFF,
    entry_cs: int = 0,
    entry_ip: int = 0,
    stack_ss: int = 0,
    stack_sp: int = 0x0100,
) -> bytes:
    """Build a real MZ executable with explicit header boot fields."""
    reloc_pos = 0x1C
    header_size = ((reloc_pos + len(relocs) * 4 + 15) // 16) * 16
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x06:0x08] = len(relocs).to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0A:0x0C] = minalloc.to_bytes(2, "little")
    header[0x0C:0x0E] = maxalloc.to_bytes(2, "little")
    header[0x0E:0x10] = stack_ss.to_bytes(2, "little")
    header[0x10:0x12] = stack_sp.to_bytes(2, "little")
    header[0x14:0x16] = entry_ip.to_bytes(2, "little")
    header[0x16:0x18] = entry_cs.to_bytes(2, "little")
    header[0x18:0x1A] = reloc_pos.to_bytes(2, "little")
    for index, (offset, segment) in enumerate(relocs):
        at = reloc_pos + index * 4
        header[at:at + 2] = offset.to_bytes(2, "little")
        header[at + 2:at + 4] = segment.to_bytes(2, "little")
    return bytes(header) + image


def _arena(paragraphs: int = ARENA_PARAS, *, seed: int = 0xA5) -> bytes:
    """Return distinctive, non-zero initial arena bytes."""
    return bytes(((index + seed) & 0xFF) for index in range(paragraphs * 16))


def _registers(**overrides: int) -> tuple[tuple[str, int], ...]:
    """Complete 32-bit register file declaration for an environment."""
    regs = {
        "eax": 0x11, "ebx": 0x22, "ecx": 0x33, "edx": 0x44,
        "esi": 0x55, "edi": 0x66, "ebp": 0x77,
        "esp": 0x0000, "eflags": 0x0002,
    }
    regs.update(overrides)
    return tuple(sorted(regs.items()))


def _env(
    *,
    psp: int = PSP,
    allocation: bytes = _arena(),
    registers: tuple[tuple[str, int], ...] = _registers(),
    fs: int = 0x1234,
    gs: int = 0x5678,
) -> boot_mod.ProgramEnvironment:
    """Default declared environment for the fixture arena and register file."""
    return boot_mod.ProgramEnvironment(
        psp_segment=psp, allocation=allocation, registers=registers, fs=fs, gs=gs,
    )


def _boot(
    mz: bytes | None = None, env: boot_mod.ProgramEnvironment | None = None, **kwargs: object
) -> boot_mod.ProgramBoot:
    """Derive a boot contract for the fixture MZ and environment."""
    return boot_mod.program_from_mz_bytes(mz or _mz(), env or _env(), **kwargs)  # type: ignore[arg-type]


def test_genuine_header_entry_executes_and_identity_is_stable() -> None:
    """The real audit binary shape: header IP 0 terminates with exit code 0."""
    boot = _boot()
    assert (boot.entry, boot.stack) == (SegOffset(LOAD, 0), SegOffset(LOAD, 0x0100))
    result = replay_program(boot)
    assert result.status is ProgramStatus.TERMINATED
    assert result.exit_code == 0
    assert result.boot_identity == boot.boot_sha256
    assert _boot().boot_sha256 == boot.boot_sha256


def test_forged_entry_under_stale_identity_refuses() -> None:
    """The documented audit forgery: entry+8 must not run under the old ID."""
    boot = _boot()
    with pytest.raises(ValueError, match="stale"):
        dataclasses.replace(boot, entry=SegOffset(boot.entry.segment, 8))


def test_forged_stack_under_stale_identity_refuses() -> None:
    """A shifted SS:SP is equally header-derived state and must rebind."""
    boot = _boot()
    with pytest.raises(ValueError, match="stale"):
        dataclasses.replace(boot, stack=SegOffset(boot.stack.segment, 0x0080))


def test_forged_image_chunks_and_fingerprints_refuse() -> None:
    """Mutated code bytes or claimed digests cannot keep a stale identity."""
    boot = _boot()
    address, data = boot.image.chunks[0]
    forged_chunks = ((address, b"\x90" + data[1:]),)
    with pytest.raises(ValueError, match="stale"):
        dataclasses.replace(boot, image=dataclasses.replace(boot.image, chunks=forged_chunks))
    forged_digest = "0" * 64
    for forged_image in (
        dataclasses.replace(boot.image, file_sha256=forged_digest),
        dataclasses.replace(boot.image, image_sha256=forged_digest),
        dataclasses.replace(boot.image, reloc_sha256=forged_digest),
    ):
        with pytest.raises(ValueError, match="stale"):
            dataclasses.replace(boot, image=forged_image)


def test_forged_code_ranges_scope_and_load_segment_refuse() -> None:
    """Declared code scope, ranges and load paragraph are source-bound too."""
    boot = _boot()
    with pytest.raises(ValueError, match=r"stale|linear ranges|paragraph"):
        dataclasses.replace(
            boot, image=dataclasses.replace(boot.image, code_ranges=(LinearRange(LOAD * 16, 4),))
        )
    with pytest.raises(ValueError, match="stale"):
        dataclasses.replace(boot, image=dataclasses.replace(boot.image, code_scope="declared"))
    with pytest.raises(ValueError, match=r"stale|paragraph"):
        dataclasses.replace(
            boot, image=dataclasses.replace(boot.image, load_segment=boot.image.load_segment + 1)
        )
    with pytest.raises(ValueError):
        dataclasses.replace(boot, image=dataclasses.replace(boot.image, load_segment=True))


def test_forged_environment_and_identity_fields_refuse() -> None:
    """Arena bytes, the published digest and swapped source all refuse."""
    boot = _boot()
    forged_arena = bytes([boot.environment.allocation[0] ^ 0xFF]) + boot.environment.allocation[1:]
    forged_env = dataclasses.replace(boot.environment, allocation=forged_arena)
    with pytest.raises(ValueError, match="stale"):
        dataclasses.replace(boot, environment=forged_env)
    with pytest.raises(ValueError, match="stale"):
        dataclasses.replace(boot, boot_sha256="0" * 64)
    with pytest.raises(ValueError, match=r"stale|fingerprint|source"):
        dataclasses.replace(boot, source=_mz(entry_ip=4))


def test_constructor_bypass_mutation_cannot_execute_under_stale_identity() -> None:
    """object.__setattr__ forgery is re-verified at the consumption boundary."""
    boot = _boot()
    forged = dataclasses.replace(boot)
    object.__setattr__(forged, "entry", SegOffset(boot.entry.segment, 8))
    with pytest.raises(ValueError, match="stale"):
        replay_program(forged)


def test_genuine_header_mutation_gets_distinct_identity_and_real_exit() -> None:
    """A real header IP change is a new boot: distinct identity, exit code 7."""
    oracle = _boot()
    changed = _boot(_mz(entry_ip=8))
    assert changed.entry == SegOffset(LOAD, 8)
    assert changed.boot_sha256 != oracle.boot_sha256
    assert changed.source != oracle.source
    oracle_result = replay_program(oracle)
    changed_result = replay_program(changed)
    assert oracle_result.exit_code == 0
    assert changed_result.status is ProgramStatus.TERMINATED
    assert changed_result.exit_code == 7
    assert changed_result.boot_identity == changed.boot_sha256 != oracle_result.boot_identity


def test_direct_construction_requires_source_bound_state() -> None:
    """Hand-built boots must present real typed source evidence, not claims."""
    boot = _boot()
    with pytest.raises(ValueError, match="source MZ bytes"):
        boot_mod.ProgramBoot(
            image=boot.image, entry=boot.entry, stack=boot.stack,
            environment=boot.environment, boot_sha256=boot.boot_sha256,
            source=b"",  # empty retained evidence
        )
    with pytest.raises(ValueError, match="MZ"):
        boot_mod.ProgramBoot(
            image=boot.image, entry=boot.entry, stack=boot.stack,
            environment=boot.environment, boot_sha256=boot.boot_sha256,
            source=b"not-an-mz-file",
        )


def test_unverifiable_non_mz_source_never_reaches_execution() -> None:
    """A non-MZ retained source refuses before the executor runs."""
    boot = _boot()
    forged = dataclasses.replace(boot)
    object.__setattr__(forged, "source", b"\x00" * 64)
    with pytest.raises(ValueError, match="MZ"):
        replay_program(forged)
