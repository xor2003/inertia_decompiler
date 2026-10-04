"""Source-bound MZ entry projections reject invented boot fields."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.mz_image import UnpackedMZImage
from angr_platforms.X86_16.mz_invocation_source import MzInvocationSource8616, mz_invocation_source_8616
from angr_platforms.X86_16.mz_load_source import parse_mz, relocate_mz_load_module

from tools.dosunit import real16_mz_load


def _source(*, entry_cs: int = 0, entry_ip: int = 0x10) -> bytes:
    """Serialize an actual header, relocation table and distinctive module."""
    module = bytearray(range(0x80))
    module[2:4] = (0x1234).to_bytes(2, "little")
    return UnpackedMZImage(
        bytes(module), ((0, 2),), entry_cs, entry_ip, 0, 0x100,
        min_alloc=0,
    ).to_mz_bytes()


def test_frontend_and_replay_share_one_mz_parser_and_relocator() -> None:
    """Compatibility exports resolve to the authoritative source functions."""
    assert real16_mz_load.parse_mz is parse_mz
    assert real16_mz_load._relocate is relocate_mz_load_module


def test_entry_and_module_derive_only_from_serialized_source() -> None:
    """The declared load paragraph affects relocation and logical CS together."""
    source = _source(entry_cs=1)
    projection = mz_invocation_source_8616(source, 0x100)
    assert projection.complete
    assert projection.source is source
    assert projection.entry_segment == 0x101
    assert projection.entry_offset == 0x10
    assert projection.entry_linear == 0x1020
    assert projection.module_base == 0x1000
    assert projection.module[2:4] == (0x1334).to_bytes(2, "little")
    assert projection.stack_segment == 0x100
    assert projection.stack_offset == 0x100
    assert real16_mz_load.image_from_mz_bytes(source, load_segment=0x100).chunks == (
        (projection.module_base, projection.module),
    )


@pytest.mark.parametrize("field,value", (
    ("entry_segment", 0x103), ("entry_offset", 2),
    ("stack_segment", 0x200), ("stack_offset", 0),
    ("module", b"\x90" * 0x80), ("minalloc", 1), ("maxalloc", 1),
    ("source", b"not an MZ"), ("load_segment", True),
    ("entry_offset", True),
))
def test_replaced_source_projection_cannot_authenticate_invented_fields(field: str, value: object) -> None:
    """Revalidation rejects stale selectors, bytes, source and Boolean integers."""
    projection = mz_invocation_source_8616(_source(), 0x100)
    corrupted = replace(projection, **{field: value})
    assert not corrupted.complete


def test_consumer_revalidates_bypassed_immutable_projection() -> None:
    """Low-level mutation cannot turn a valid projection into trusted fake CS."""
    projection = mz_invocation_source_8616(_source(), 0x100)
    object.__setattr__(projection, "entry_segment", 0x103)
    assert not projection.complete


def test_projection_subclass_cannot_override_source_equality() -> None:
    """A foreign equality implementation cannot authenticate a fake selector."""

    class ForeignProjection(MzInvocationSource8616):
        """A foreign object whose equality does not describe its stored fields."""

        def __eq__(self, _other: object) -> bool:
            """Return fake agreement independent of source-derived fields."""
            return True

    original = mz_invocation_source_8616(_source(), 0x100)
    forged = ForeignProjection(
        original.source, original.load_segment, original.module, 0x103,
        original.entry_offset, original.stack_segment, original.stack_offset,
        original.minalloc, original.maxalloc,
    )
    assert not forged.complete


def test_real_header_change_creates_new_source_evidence() -> None:
    """Genuinely changed header bytes change entry and source identity together."""
    original = mz_invocation_source_8616(_source(), 0x100)
    changed = mz_invocation_source_8616(_source(entry_cs=1), 0x100)
    assert original.complete and changed.complete
    assert original.entry_linear != changed.entry_linear
    assert original.file_sha256 != changed.file_sha256
    assert original.module == changed.module


@pytest.mark.parametrize("load_segment", (True, -1, 0x10000, "256"))
def test_invalid_load_declaration_refuses(load_segment: object) -> None:
    """Load coordinates are exact word values, not coercible guesses."""
    with pytest.raises(ValueError, match="load segment"):
        mz_invocation_source_8616(_source(), load_segment)


def test_header_entry_outside_source_module_refuses() -> None:
    """An MZ entry declaration does not make unbacked bytes executable."""
    with pytest.raises(ValueError, match="entry must lie"):
        mz_invocation_source_8616(_source(entry_cs=8), 0x100)


def test_outside_module_relocation_refuses() -> None:
    """A malformed relocation table cannot manufacture executable module bytes."""
    source = UnpackedMZImage(b"\xc3", ((0, 1),), 0, 0, 0, 0).to_mz_bytes()
    with pytest.raises(ValueError, match="relocation outside"):
        mz_invocation_source_8616(source, 0x100)


@pytest.mark.parametrize("relative_cs,entry_ip,target", ((0, 0x32, 0x1000), (3, 2, 0x11000)))
def test_header_selected_cs_replays_backward_call_target(relative_cs: int, entry_ip: int, target: int) -> None:
    """The same physical CALL has different realizable header-bound targets."""
    from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
    from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_IP, UC_X86_REG_SP, UC_X86_REG_SS

    module = bytearray(b"\x90" * 0x40)
    module[0x32:0x35] = bytes.fromhex("e8cbff")
    source = UnpackedMZImage(
        bytes(module), (), relative_cs, entry_ip, 0, 0x800, min_alloc=0,
    ).to_mz_bytes()
    projection = mz_invocation_source_8616(source, 0x100)
    assert projection.complete
    guest = Uc(UC_ARCH_X86, UC_MODE_16)
    guest.mem_map(0, 0x20000)
    guest.mem_write(projection.module_base, projection.module)
    guest.reg_write(UC_X86_REG_CS, projection.entry_segment)
    guest.reg_write(UC_X86_REG_IP, projection.entry_offset)
    guest.reg_write(UC_X86_REG_SS, projection.stack_segment)
    guest.reg_write(UC_X86_REG_SP, projection.stack_offset)
    fetched: list[tuple[int, int, int, int]] = []

    def observe_fetch(emu: Uc, address: int, size: int, _data: object) -> None:
        """Record actual physical fetch and logical CS:IP before execution."""
        fetched.append((address, emu.reg_read(UC_X86_REG_CS), emu.reg_read(UC_X86_REG_IP), size))

    guest.hook_add(UC_HOOK_CODE, observe_fetch)
    guest.emu_start(projection.entry_linear, 0, count=1)
    assert fetched == [(0x1032, 0x100 + relative_cs, entry_ip, 3)]
    assert guest.reg_read(UC_X86_REG_CS) * 16 + guest.reg_read(UC_X86_REG_IP) == target
    assert guest.reg_read(UC_X86_REG_SP) == 0x7FE
