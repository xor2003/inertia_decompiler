"""Whole-program PE32 boot contracts derive from actual file bytes only.

These tests build real serialized PE32 images and exact caller-declared
environments; every refusal case exercises binary-derived bounds and typed
metadata, never names or rendered text.
"""

from __future__ import annotations

import hashlib
import struct

import pytest
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

import tools.dosunit.runtime.pe32_program_boot as boot_mod
from tools.dosunit.runtime.flat32_memory_permissions import DeclaredAccess, MappingOrigin
from tools.dosunit.runtime.flat32_replay_model import ReplayImage

CODE = bytes.fromhex("b807000000c3")  # mov eax,7; ret

BASE = 0x400000
TEXT = BASE + 0x1000
STACK = 0x70000
EXIT = 0x60000

OPT = 0x98  # optional header offset inside the fixture layout
DATA_DIRECTORY = OPT + 96  # PE32 data directory 0 offset
FILE_CHARACTERISTICS = 0x96  # FILE_HEADER.Characteristics
FILE_MACHINE = 0x84  # FILE_HEADER.Machine
ENTRY_RVA = OPT + 16  # OptionalHeader.AddressOfEntryPoint
SECTION_VSIZE = 0x180  # .text VirtualSize

RW = DeclaredAccess.READ | DeclaredAccess.WRITE


def _mutated(data: bytes, offset: int, patch: bytes) -> bytes:
    """Return the serialized image with ``patch`` applied at ``offset``."""
    blob = bytearray(data)
    blob[offset : offset + len(patch)] = patch
    return bytes(blob)


def _with_directory(data: bytes, index: int, rva: int = 0x1800, size: int = 0x28) -> bytes:
    """Return the image with one optional-header data directory populated."""
    return _mutated(data, DATA_DIRECTORY + 8 * index, struct.pack("<II", rva, size))


def _registers(**overrides: int) -> tuple[tuple[str, int], ...]:
    """Complete 32-bit register file declaration for an environment."""
    regs = {
        "eax": 0x11, "ebx": 0x22, "ecx": 0x33, "edx": 0x44,
        "esi": 0x55, "edi": 0x66, "ebp": 0x77,
        "esp": STACK + 0x40, "eflags": 0x202,
    }
    regs.update(overrides)
    return tuple(sorted(regs.items()))


def _stack_bytes(seed: int = 0xA5) -> bytes:
    """Distinctive, non-zero declared allocation bytes."""
    return bytes(((index + seed) & 0xFF) for index in range(0x80))


def _memory(*regions: boot_mod.PeProgramMemory) -> tuple[boot_mod.PeProgramMemory, ...]:
    """Default declared allocations: one readable+writable range hosting ESP."""
    if regions:
        return regions
    return (boot_mod.PeProgramMemory(STACK, _stack_bytes(), RW),)


def _env(
    *,
    registers: tuple[tuple[str, int], ...] = _registers(),
    memory: tuple[boot_mod.PeProgramMemory, ...] = (),
    exit_address: int = EXIT,
) -> boot_mod.PeProgramEnvironment:
    """Default declared environment for the fixture image."""
    return boot_mod.PeProgramEnvironment(
        registers=registers,
        memory=memory or _memory(),
        exit_address=exit_address,
    )


def _boot(
    data: bytes | None = None, env: boot_mod.PeProgramEnvironment | None = None
) -> boot_mod.PeProgramBoot:
    """Derive a boot contract for the fixture image and environment."""
    return boot_mod.pe_program_from_bytes(data or pe32_bytes(CODE), env or _env())


def _chunk_covering(image: ReplayImage, address: int) -> tuple[int, bytes]:
    """Return the admitted loaded chunk containing ``address``."""
    for start, data in image.chunks:
        if start <= address < start + len(data):
            return start, data
    raise AssertionError(f"no admitted chunk covers {address:#x}")


def test_boot_admits_genuine_pe32_and_binds_entry_and_file() -> None:
    """A clean i386 EXE boots with the loaded entry and the exact file hash."""
    data = pe32_bytes(CODE)
    boot = _boot(data)
    assert boot.entry == TEXT
    assert isinstance(boot.image, ReplayImage)
    assert boot.file_sha256 == hashlib.sha256(data).hexdigest()
    assert _boot(data).boot_sha256 == boot.boot_sha256
    assert _boot(data).file_sha256 == boot.file_sha256


def test_only_main_image_bytes_are_admitted() -> None:
    """Synthetic loader backers (externs/TLS objects) never enter the image."""
    boot = _boot()
    assert len(boot.image.chunks) == 1
    start, data = boot.image.chunks[0]
    assert start == BASE
    assert data[0x1000 : 0x1000 + len(CODE)] == CODE
    # CLE maps cle##externs/cle##tls above the image; no admitted byte may
    # come from those initialization-service objects.
    assert all(start + len(data) <= BASE + 0x2000 for start, data in boot.image.chunks)
    assert all(not (start <= 0x500000 < start + len(data)) for start, data in boot.image.chunks)


def test_entry_header_change_moves_loaded_entry() -> None:
    """AddressOfEntryPoint is used as the loaded entry, not a guessed value."""
    data = _mutated(pe32_bytes(CODE), ENTRY_RVA, struct.pack("<I", 0x1001))
    assert _boot(data).entry == TEXT + 1


def test_entry_outside_executable_loaded_bytes_refuses() -> None:
    """An entry outside declared executable bytes is refused."""
    data = _mutated(pe32_bytes(CODE), ENTRY_RVA, struct.pack("<I", 0x0500))
    with pytest.raises(ValueError, match="outside declared executable"):
        _boot(data)


def test_initialized_virtual_tail_is_captured() -> None:
    """Declared virtual zero tail beyond raw bytes stays in admitted bytes."""
    data = _mutated(pe32_bytes(CODE), SECTION_VSIZE, struct.pack("<I", 0x300))
    boot = _boot(data)
    start, chunk = _chunk_covering(boot.image, TEXT + 0x200)
    assert chunk[TEXT + 0x200 - start : TEXT + 0x300 - start] == bytes(0x100)


def test_no_implicit_frame_or_stack_data_is_installed() -> None:
    """Boot state carries only declared bytes: no caller frame, trap or stack."""
    env = _env()
    boot = _boot(env=env)
    registers = dict(boot.environment.registers)
    assert registers["esp"] == STACK + 0x40
    region = boot.environment.memory[0]
    assert region.address == STACK and region.data == _stack_bytes()
    # The bytes at ESP are the declared initial bytes, not a pushed return
    # address or caller frame manufactured by the boot contract.
    assert region.data[0x40:0x44] == _stack_bytes()[0x40:0x44]
    assert region.data[0x40:0x44] != env.exit_address.to_bytes(4, "little")
    # Loaded image bytes are exactly the file-derived span; nothing is
    # written at the exit terminal or the stack location.
    assert all(
        not (start <= env.exit_address < start + len(data))
        for start, data in boot.image.chunks
    )
    assert all(not (start <= STACK < start + len(data)) for start, data in boot.image.chunks)


def test_declared_regions_project_to_shared_permission_plan() -> None:
    """Environment memory projects to typed caller-scratch declarations."""
    env = _env()
    regions = env.declared_regions()
    assert len(regions) == 1
    assert regions[0].address == STACK
    assert regions[0].size == 0x80
    assert regions[0].access == RW
    assert regions[0].origin is MappingOrigin.VECTOR


def test_boot_identity_binds_file_loaded_bytes_and_environment() -> None:
    """Changed file bytes or changed declared state change the boot identity."""
    data = pe32_bytes(CODE)
    env = _env()
    base = _boot(data, env)
    mutated_code = _mutated(data, 0x200, bytes([CODE[0] ^ 0xFF]))
    changed_file = _boot(mutated_code, env)
    assert changed_file.file_sha256 != base.file_sha256
    assert changed_file.boot_sha256 != base.boot_sha256
    changed_registers = _boot(data, _env(registers=_registers(eax=0x99)))
    changed_exit = _boot(data, _env(exit_address=EXIT + 0x100))
    changed_memory = _boot(
        data,
        _env(memory=_memory(boot_mod.PeProgramMemory(STACK, _stack_bytes(seed=0x5A), RW))),
    )
    changed_entry = _boot(_mutated(data, ENTRY_RVA, struct.pack("<I", 0x1001)), env)
    for other in (changed_registers, changed_exit, changed_memory):
        assert other.file_sha256 == base.file_sha256
        assert other.boot_sha256 != base.boot_sha256
    assert changed_entry.boot_sha256 != base.boot_sha256


@pytest.mark.parametrize(
    "offset,patch",
    [
        (OPT, struct.pack("<H", 0x20B)),  # PE32+ magic
        (FILE_MACHINE, struct.pack("<H", 0x8664)),  # AMD64 machine
        (FILE_CHARACTERISTICS, struct.pack("<H", 0x2102)),  # DLL bit set
        (FILE_CHARACTERISTICS, struct.pack("<H", 0x2000)),  # no executable bit
    ],
)
def test_non_genuine_i386_pe32_exe_refuses(offset: int, patch: bytes) -> None:
    """Wrong bitness, wrong machine, DLLs and non-images are refused."""
    with pytest.raises(ValueError):
        _boot(_mutated(pe32_bytes(CODE), offset, patch))


@pytest.mark.parametrize("index", [1, 9, 10, 11, 12, 13, 14])
def test_startup_effect_directories_refuse(index: int) -> None:
    """Import/TLS/load-config/bound/IAT/delay/CLR directories are refused."""
    with pytest.raises(ValueError, match="initialization services"):
        _boot(_with_directory(pe32_bytes(CODE), index))


def test_non_pe_bytes_and_wrong_argument_types_refuse() -> None:
    """Non-PE input, non-bytes input and untyped environments are refused."""
    with pytest.raises(ValueError, match="PE"):
        _boot(b"not a pe image at all")
    with pytest.raises(ValueError, match="exact file bytes"):
        _boot("pe32 bytes as text")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="PeProgramEnvironment"):
        boot_mod.pe_program_from_bytes(pe32_bytes(CODE), object())  # type: ignore[arg-type]


def test_environment_memory_may_not_overlap_loaded_image() -> None:
    """A declared allocation colliding with loaded bytes is refused."""
    env = _env(
        memory=(
            boot_mod.PeProgramMemory(TEXT, b"1234", RW),
            boot_mod.PeProgramMemory(STACK, _stack_bytes(), RW),
        )
    )
    with pytest.raises(ValueError, match="overlap loaded image"):
        _boot(env=env)


def test_exit_address_must_lie_outside_image_and_declared_data() -> None:
    """The terminal boundary is explicit and outside image and allocations."""
    with pytest.raises(ValueError, match="outside declared environment"):
        _env(exit_address=STACK + 0x10)
    with pytest.raises(ValueError, match="outside loaded image"):
        _boot(env=_env(exit_address=TEXT))


def test_environment_registers_must_declare_exact_386_file() -> None:
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


@pytest.mark.parametrize(
    "name,value",
    [
        ("eax", True), ("ebx", -1), ("ecx", 0x1_0000_0000),
        ("edx", 1.5), ("esp", True), ("eflags", -0x8000_0000),
    ],
)
def test_environment_register_values_are_full_32bit(name: str, value: object) -> None:
    """Values must be real 32-bit integers, never bool or float masquerades."""
    with pytest.raises(ValueError):
        _env(registers=_registers(**{name: value}))  # type: ignore[call-arg]


def test_declared_eflags_must_carry_reserved_bit1() -> None:
    """EFLAGS bit 1 is architecturally reserved; absence is refused."""
    with pytest.raises(ValueError, match="reserved bit 1"):
        _env(registers=_registers(eflags=0x200))


def test_esp_must_anchor_declared_read_write_bytes() -> None:
    """ESP must cover at least 4 bytes inside a declared R+W allocation."""
    with pytest.raises(ValueError, match="esp must anchor"):
        _env(registers=_registers(esp=0x90000))
    read_only = (boot_mod.PeProgramMemory(STACK, _stack_bytes(), DeclaredAccess.READ),)
    with pytest.raises(ValueError, match="esp must anchor"):
        _env(memory=read_only)
    with pytest.raises(ValueError, match="esp must anchor"):
        _env(registers=_registers(esp=STACK + 0x7E))  # only 2 bytes remain


@pytest.mark.parametrize("address", [True, -1, 0x1_0000_0000, 1.5])
def test_memory_addresses_are_exact_u32(address: object) -> None:
    """Allocation addresses are 32-bit integers, never bool or float."""
    with pytest.raises(ValueError):
        boot_mod.PeProgramMemory(address, b"x", RW)  # type: ignore[arg-type]


def test_memory_allocation_shape_and_access_refusals() -> None:
    """Empty/non-bytes data, EXECUTE or unknown access bits are refused."""
    with pytest.raises(ValueError, match="exact initial bytes"):
        boot_mod.PeProgramMemory(STACK, "bytes", RW)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive length"):
        boot_mod.PeProgramMemory(STACK, b"", RW)
    with pytest.raises(ValueError, match="data-only"):
        boot_mod.PeProgramMemory(STACK, b"x", DeclaredAccess.READ | DeclaredAccess.EXECUTE)
    with pytest.raises(ValueError, match="outside the declared permission set"):
        boot_mod.PeProgramMemory(STACK, b"x", DeclaredAccess(0x40))
    with pytest.raises(ValueError, match="typed DeclaredAccess"):
        boot_mod.PeProgramMemory(STACK, b"x", 3)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="32-bit flat space"):
        boot_mod.PeProgramMemory(0xFFFFFFF0, bytes(0x20), RW)


def test_environment_memory_regions_may_not_overlap() -> None:
    """Two declared allocations covering the same bytes are ambiguous."""
    overlapping = _memory(
        boot_mod.PeProgramMemory(STACK, bytes(0x80), RW),
        boot_mod.PeProgramMemory(STACK + 0x40, bytes(0x80), RW),
    )
    with pytest.raises(ValueError, match="may not overlap"):
        _env(memory=overlapping)


def test_environment_memory_budgets_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Region count, per-region bytes and aggregate bytes share the budgets."""
    monkeypatch.setattr(boot_mod, "MAX_MAPPED_BYTES", 0x40)
    with pytest.raises(ValueError, match="positive length within"):
        boot_mod.PeProgramMemory(STACK, bytes(0x80), RW)
    small = boot_mod.PeProgramMemory(STACK, bytes(0x40), RW)
    extra = boot_mod.PeProgramMemory(STACK + 0x100, bytes(0x40), RW)
    with pytest.raises(ValueError, match="64 MiB budget"):
        _env(memory=_memory(small, extra))
    monkeypatch.setattr(boot_mod, "MAX_MAPPED_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(boot_mod, "MAX_PAGE_CLAIMS", 1)
    with pytest.raises(ValueError, match="region count"):
        _env(memory=_memory(small, extra))


@pytest.mark.parametrize("exit_address", [True, -1, 0x1_0000_0000])
def test_exit_address_is_an_exact_u32(exit_address: object) -> None:
    """The declared terminal is a 32-bit integer, never a bool masquerade."""
    with pytest.raises(ValueError, match="32-bit"):
        _env(exit_address=exit_address)  # type: ignore[arg-type]


def test_untyped_environment_memory_entries_refuse() -> None:
    """Only typed PeProgramMemory regions may declare allocations."""
    with pytest.raises(ValueError, match="PeProgramMemory"):
        _env(memory=(("address", "data"),))  # type: ignore[arg-type]


def test_program_boot_rejects_untyped_fields() -> None:
    """The frozen contract keeps its typed image/entry/environment/identity."""
    boot = _boot()
    with pytest.raises(ValueError, match="typed"):
        boot_mod.PeProgramBoot(
            image=boot.image, entry=boot.entry,
            environment="not-an-environment",  # type: ignore[arg-type]
            file_sha256=boot.file_sha256, boot_sha256=boot.boot_sha256,
        )
    with pytest.raises(ValueError, match="bind"):
        boot_mod.PeProgramBoot(
            image=boot.image, entry=boot.entry, environment=boot.environment,
            file_sha256=boot.file_sha256, boot_sha256="",
        )
