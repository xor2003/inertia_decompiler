"""Whole-program MZ boot contracts derive from actual file bytes only.

These tests build real MZ headers and exact caller-declared arenas; every
refusal case exercises binary-derived bounds, never names or rendered text.
"""

from __future__ import annotations

import pytest

import tools.dosunit.runtime.real16_program_boot as boot_mod
from tools.dosunit.runtime.real16_replay_model import LinearRange, SegOffset

PSP = 0x0500
LOAD = PSP + 0x10
IMAGE = bytes(range(0x20))  # 2 paragraphs of arbitrary module bytes
ARENA_PARAS = 0x10 + 0x02 + 0x10  # PSP + module + default minalloc=0x10


def _mz(
    image: bytes = IMAGE,
    *,
    relocs: tuple[tuple[int, int], ...] = (),
    minalloc: int = 0x10,
    maxalloc: int = 0xFFFF,
    entry_cs: int = 0,
    entry_ip: int = 0,
    stack_ss: int = 0,
    stack_sp: int = 0x0120,
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
        "esp": 0x0120, "eflags": 0x0002,
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


def _boot(mz: bytes | None = None, env: boot_mod.ProgramEnvironment | None = None, **kwargs):
    """Derive a boot contract for the fixture MZ and environment."""
    return boot_mod.program_from_mz_bytes(mz or _mz(), env or _env(), **kwargs)


def test_boot_loads_module_at_psp_plus_16_and_relocates():
    """The image lands at PSP+0x10 and stored words gain that paragraph."""
    image = bytearray(IMAGE)
    image[1:3] = (0x0001).to_bytes(2, "little")
    env = _env()
    boot = _boot(_mz(bytes(image), relocs=((0x0001, 0x0000),)), env)
    assert boot.image.load_segment == LOAD
    assert boot.image.chunks[0][0] == LOAD * 16
    assert int.from_bytes(boot.image.chunks[0][1][1:3], "little") == 0x0001 + LOAD
    assert boot.image.bss_size == 0x10 * 16
    assert boot.environment is env


def test_boot_retains_header_entry_and_stack():
    """Header CS:IP and SS:SP gain the image paragraph without truncation."""
    boot = _boot(_mz(entry_cs=0x0002, entry_ip=0x0010, stack_ss=0x0002, stack_sp=0x00FE))
    assert boot.entry == SegOffset(LOAD + 0x0002, 0x0010)
    assert boot.stack == SegOffset(LOAD + 0x0002, 0x00FE)


def test_environment_keeps_exact_arena_bytes_immutable():
    """The declared arena is copied byte-exact; later mutation cannot leak in."""
    arena = bytearray(_arena())
    snapshot = bytes(arena)
    env = boot_mod.ProgramEnvironment(
        psp_segment=PSP, allocation=arena,  # type: ignore[arg-type]
        registers=_registers(), fs=0, gs=0,
    )
    arena[0] ^= 0xFF
    arena[-1] ^= 0xFF
    assert env.allocation == snapshot
    assert isinstance(env.allocation, bytes)


def test_boot_identity_is_deterministic_and_binds_whole_snapshot():
    """File, arena, registers and declared ranges all move the identity."""
    mz = _mz()
    env = _env()
    base = _boot(mz, env)
    assert _boot(mz, env).boot_sha256 == base.boot_sha256
    changed_file = _boot(_mz(bytes(bytearray(b ^ 0xFF for b in IMAGE))), env)
    changed_arena = _boot(mz, _env(allocation=_arena(seed=0x5A)))
    changed_regs = _boot(mz, _env(registers=_registers(eax=0x99)))
    changed_ranges = _boot(mz, env, code_ranges=(LinearRange(LOAD * 16, 4),))
    for other in (changed_file, changed_arena, changed_regs, changed_ranges):
        assert other.boot_sha256 != base.boot_sha256


def test_declared_code_ranges_stay_inside_loaded_bytes():
    """Declared instruction bytes scope the image; outside ranges refuse."""
    boot = _boot(code_ranges=(LinearRange(LOAD * 16, 4),))
    assert boot.image.code_ranges == (LinearRange(LOAD * 16, 4),)
    assert boot.image.code_scope == "declared"
    with pytest.raises(ValueError, match="inside relocated image"):
        _boot(code_ranges=(LinearRange(LOAD * 16 + len(IMAGE), 4),))


def test_entry_segment_addition_wrap_refuses():
    """A header CS or SS that pushes the segment past 16 bits is refused."""
    env = _env()
    with pytest.raises(ValueError, match="wraps"):
        _boot(_mz(entry_cs=0xFFFF), env)
    with pytest.raises(ValueError, match="wraps"):
        _boot(_mz(stack_ss=0xFFFF), env)


def test_entry_outside_allocated_arena_refuses():
    """An entry past the arena end refuses even without a segment wrap."""
    with pytest.raises(ValueError, match="outside the allocated arena"):
        _boot(_mz(entry_cs=0x0040, entry_ip=0))  # 0x5500 >= arena end 0x5220
    with pytest.raises(ValueError, match="outside the allocated arena"):
        _boot(_mz(entry_cs=0x0000, entry_ip=0x0400))  # 0x5500 >= 0x5220


def test_stack_top_outside_allocated_arena_refuses():
    """A stack whose top exceeds the granted arena is refused."""
    with pytest.raises(ValueError, match="stack top"):
        _boot(_mz(stack_ss=0, stack_sp=0x4000))  # top 0x9100 > 0x5220
    with pytest.raises(ValueError, match="stack top"):
        _boot(_mz(stack_ss=0x0010, stack_sp=0xFFFF))


def test_header_sp_zero_is_top_of_segment_at_exact_arena_end():
    """SP=0 means a 64 KiB stack area; a top exactly at arena end is legal."""
    image = bytes(0x10)
    minalloc = 0x0FFF  # arena = 0x10 + 1 + 0x0FFF = 0x1010 paragraphs
    env = _env(psp=0x0100, allocation=_arena(0x1010))
    boot = _boot(_mz(image, minalloc=minalloc, stack_ss=0, stack_sp=0), env)
    assert boot.stack == SegOffset(0x0100 + 0x10, 0)
    assert dict(boot.initial_registers())["esp"] == 0


def test_header_sp_zero_one_paragraph_past_arena_refuses():
    """The 64 KiB top-of-segment stack may not cross the arena end."""
    image = bytes(0x10)
    env = _env(psp=0x0100, allocation=_arena(0x100F))
    with pytest.raises(ValueError, match="stack top"):
        _boot(_mz(image, minalloc=0x0FFE, stack_ss=0, stack_sp=0), env)


def test_stack_pointer_at_exact_arena_end_is_allowed():
    """A nonzero SP whose exclusive top is the arena end is representable."""
    boot = _boot()  # default fixture: SS:SP top 0x5220 == arena end 0x5220
    assert boot.stack.linear() == PSP * 16 + ARENA_PARAS * 16


def test_insufficient_allocation_for_module_and_minalloc_refuses():
    """The arena must hold PSP + paragraph-rounded module + minalloc."""
    env = _env(allocation=_arena(0x10 + 0x02))  # no room for minalloc=0x10
    with pytest.raises(ValueError, match="does not hold"):
        _boot(_mz(minalloc=0x10), env)


def test_allocation_exceeding_maxalloc_grant_refuses():
    """The granted arena may not claim more than the header allows."""
    env = _env(allocation=_arena(0x10 + 0x02 + 0x01))
    with pytest.raises(ValueError, match="maxalloc"):
        _boot(_mz(minalloc=0, maxalloc=0), env)


def test_arena_exactly_at_conventional_ceiling_is_allowed():
    """An arena ending exactly at 0xA0000 stays inside conventional memory."""
    image = bytes(0x10)
    env = _env(psp=0x9FE0, allocation=_arena(0x20))
    boot = _boot(_mz(image, minalloc=0, stack_sp=0x0020), env)
    assert boot.entry == SegOffset(0x9FF0, 0)


def test_arena_crossing_conventional_ceiling_refuses():
    """The arena may end at, never beyond, the 0xA0000 boundary."""
    with pytest.raises(ValueError, match="conventional-memory ceiling"):
        _env(psp=0x9FE0, allocation=_arena(0x21))


@pytest.mark.parametrize("psp,fs,gs", [
    (True, 0, 0), (0x10000, 0, 0), (-1, 0, 0),
    (PSP, True, 0), (PSP, 0x10000, 0), (PSP, 0, -1),
])
def test_environment_u16_fields_reject_bool_and_range(psp, fs, gs):
    """PSP/FS/GS are exact 16-bit fields, never bool masquerades."""
    with pytest.raises(ValueError, match="16-bit"):
        _env(psp=psp, fs=fs, gs=gs)


@pytest.mark.parametrize("size", [0, 0xF0, 0x111])
def test_environment_allocation_shape_refusals(size):
    """The arena is a positive multiple of 16 covering the whole PSP."""
    with pytest.raises(ValueError, match="multiple of 16"):
        _env(allocation=_arena(1)[:size])


def test_environment_allocation_must_be_bytes():
    """Only exact byte contents may declare the initial arena."""
    with pytest.raises(ValueError, match="arena bytes"):
        _env(allocation="not-bytes")  # type: ignore[arg-type]


def test_environment_registers_must_declare_exact_386_file():
    """Missing, extra or duplicated register names are refused."""
    missing = tuple(pair for pair in _registers() if pair[0] != "eflags")
    extra = (*_registers(), ("cs", 0x0510))
    duplicate = (
        ("eax", 1), ("eax", 2),
        *(pair for pair in _registers() if pair[0] != "eax"),
    )
    for registers in (missing, extra, duplicate):
        with pytest.raises(ValueError, match="exactly once"):
            _env(registers=registers)


@pytest.mark.parametrize("name,value", [
    ("eax", True), ("ebx", -1), ("ecx", 0x1_0000_0000),
    ("edx", 1.5), ("esp", 0x1_0000), ("eflags", -0x8000_0000),
])
def test_environment_register_values_are_full_32bit(name, value):
    """Values must be real 32-bit integers; bool and nonzero esp top refuse."""
    with pytest.raises(ValueError):
        _env(registers=_registers(**{name: value}))


def test_initial_registers_apply_authoritative_header_sp():
    """Only the header SP overrides ESP; every other declared value stays."""
    env = _env(registers=_registers(esp=0xBEEF))
    boot = _boot(_mz(stack_sp=0x0100), env)
    registers = dict(boot.initial_registers())
    assert registers["esp"] == 0x0100
    assert registers["eax"] == 0x11 and registers["eflags"] == 0x0002


def test_program_boot_rejects_untyped_fields():
    """The frozen contract keeps its typed image/entry/stack/environment."""
    boot = _boot()
    with pytest.raises(ValueError, match="typed"):
        boot_mod.ProgramBoot(
            image=boot.image, entry=boot.entry, stack=boot.stack,
            environment="not-an-environment", boot_sha256=boot.boot_sha256,  # type: ignore[arg-type]
            source=boot.source,
        )
    with pytest.raises(ValueError, match="bind"):
        boot_mod.ProgramBoot(
            image=boot.image, entry=boot.entry, stack=boot.stack,
            environment=boot.environment, boot_sha256="",
            source=boot.source,
        )
    with pytest.raises(ValueError, match="ProgramEnvironment"):
        boot_mod.program_from_mz_bytes(_mz(), object())  # type: ignore[arg-type]
