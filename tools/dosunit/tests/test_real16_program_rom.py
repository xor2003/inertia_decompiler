"""Read-only firmware declarations preserve exact bytes and bounded coverage."""

import json
from dataclasses import FrozenInstanceError

import pytest

import tools.dosunit.runtime.real16_program_rom as rom
from tools.dosunit.runtime.real16_replay_model import SegOffset

BIOS_BYTES = bytes((0x11, 0x22, 0x33))
TAIL_BYTES = bytes(range(0x10))
BIOS = rom.RomRegion(SegOffset(0xC000, 0x0000), BIOS_BYTES)
TAIL = rom.RomRegion(SegOffset(0xF800, 0x7FF0), TAIL_BYTES)  # ends exactly at 0x100000


@pytest.mark.parametrize("field,value", [("chunks", ((0x10000, b"bad"),)), ("pages", (0x10000,)),
                                         ("ranges", ())])
def test_identity_rejects_forged_derived_projection(field, value):
    policy = rom.ProgramRom((rom.RomRegion(SegOffset(0xC000, 0), b"x"),))
    object.__setattr__(policy, field, value)
    with pytest.raises(ValueError, match="ROM"):
        rom.rom_document(policy)


def region(segment, offset, data):
    return rom.RomRegion(SegOffset(segment, offset), data)


def inventory(*regions: rom.RomRegion):
    return rom.ProgramRom(tuple(regions))


def test_window_constants_bound_the_firmware_domain():
    assert rom.ROM_WINDOW_START == 0xC0000
    assert rom.ROM_WINDOW_END == 0x100000
    assert rom.ROM_WINDOW_BYTES == 0x40000
    assert rom.MAX_ROM_REGIONS == 16


@pytest.mark.parametrize(("segment", "offset", "size"), [
    (0xC000, 0x0000, 1),    # first window byte
    (0xF800, 0x7FF0, 0x10),  # ends exactly at the exclusive 0x100000 ceiling
    (0xFFFF, 0x000F, 1),    # last byte 0xFFFFF
    (0xB2A7, 0xFFF6, 4),    # aliased coordinate resolving to 0xC2A66
    (0xC000, 0x0000, 0x4000),  # whole C segment
])
def test_region_accepts_physical_addresses_inside_firmware_window(segment, offset, size):
    declared = region(segment, offset, bytes(size))
    assert declared.start == SegOffset(segment, offset)
    assert declared.data == bytes(size)


@pytest.mark.parametrize(("segment", "offset", "size"), [
    (0x0000, 0x0000, 1),     # conventional RAM
    (0x9FFF, 0xFFFF, 1),     # last conventional byte 0x9FFFF
    (0xA000, 0x0000, 1),     # video RAM floor
    (0xB000, 0x0000, 1),     # monochrome video RAM
    (0xBFFF, 0x0000, 1),     # last device-window paragraph
    (0xBFFF, 0x0008, 0x10),  # starts below the window, ends inside it
    (0xF800, 0x7FF0, 0x11),  # crosses the exclusive 0x100000 ceiling
    (0xFFFF, 0xFFFF, 1),     # entirely above the window
])
def test_region_rejects_physical_addresses_outside_firmware_window(segment, offset, size):
    with pytest.raises(ValueError):
        region(segment, offset, bytes(size))


def test_region_rejects_logical_offset_wrap_inside_window():
    with pytest.raises(ValueError):
        region(0xC000, 0xFFF0, bytes(0x11))


@pytest.mark.parametrize("data", [b"", bytearray(4), [1, 2], "aa", None, 5])
def test_region_requires_nonempty_immutable_bytes(data):
    with pytest.raises(ValueError):
        rom.RomRegion(SegOffset(0xC000, 0), data)  # type: ignore[arg-type]


@pytest.mark.parametrize("start", [
    None, 5, "c000:0", (0xC000, 0), {"segment": 0xC000, "offset": 0},
    SegOffset(True, 0), SegOffset(0, False), SegOffset(1.5, 0),  # type: ignore[arg-type]
])
def test_region_requires_typed_strict_integer_coordinates(start):
    with pytest.raises(ValueError):
        rom.RomRegion(start, b"xx")  # type: ignore[arg-type]


def test_region_has_no_defaults_and_is_immutable():
    with pytest.raises(TypeError):
        rom.RomRegion()  # type: ignore[call-arg]
    with pytest.raises(FrozenInstanceError):
        BIOS.data = b"changed"  # pyright: ignore[reportAttributeAccessIssue]


def test_inventory_canonicalizes_physical_order_and_exposes_mapping_evidence():
    declared = inventory(TAIL, BIOS)
    assert declared.regions == (BIOS, TAIL)
    assert declared.chunks == ((0xC0000, BIOS_BYTES), (0xFFFF0, TAIL_BYTES))
    assert declared.pages == (0xC0000, 0xFF000)
    assert declared == inventory(BIOS, TAIL)


@pytest.mark.parametrize("regions", [
    (BIOS, rom.RomRegion(SegOffset(0xC000, 0x0001), b"zz")),            # overlapping
    (BIOS, rom.RomRegion(SegOffset(0xBFFF, 0x0010), b"zz")),            # aliased same start
    (BIOS, rom.RomRegion(SegOffset(0xBFFF, 0x0012), b"zzzz")),          # aliased overlap at 0xC0002
    (BIOS, BIOS),                                                      # duplicate
])
def test_inventory_rejects_overlaps_aliases_and_duplicates(regions):
    with pytest.raises(ValueError):
        rom.ProgramRom(regions)


def test_inventory_merges_adjacent_declarations_but_never_gaps():
    seam = rom.RomRegion(SegOffset(0xC000, 0x0003), b"more")
    adjacent = inventory(BIOS, seam)
    assert len(adjacent.ranges) == 1
    assert adjacent.contains(0xC0000, 3 + 4)
    spaced = inventory(BIOS, rom.RomRegion(SegOffset(0xC000, 0x0010), b"x"))
    assert len(spaced.ranges) == 2
    assert not spaced.contains(0xC0003, 0xD)      # the gap is never readable
    assert not spaced.contains(0xC0000, 0x11)     # spanning the gap is refused
    assert spaced.contains(0xC0000, 3) and spaced.contains(0xC0010, 1)


def test_inventory_page_slack_is_never_readable():
    declared = inventory(rom.RomRegion(SegOffset(0xC000, 0x0100), b"x"))
    assert declared.pages == (0xC0000,)
    assert not declared.contains(0xC0000, 0x100)  # slack before the declared byte
    assert not declared.contains(0xC0101, 1)      # slack after the declared byte
    assert not declared.contains(0xC0000, 1)      # page coverage is not byte coverage


@pytest.mark.parametrize("regions", [
    (), None, [], b"bytes", "rom", BIOS,
    (BIOS, "rom"), (BIOS, None), (BIOS, b"raw"),
])
def test_inventory_requires_nonempty_typed_region_tuple(regions):
    with pytest.raises(ValueError):
        rom.ProgramRom(regions)  # type: ignore[arg-type]


def test_inventory_is_bounded_to_sixteen_regions():
    many = tuple(rom.RomRegion(SegOffset(0xC000, index * 0x1000), b"x") for index in range(16))
    assert len(rom.ProgramRom(many).regions) == 16
    with pytest.raises(ValueError):
        rom.ProgramRom((*many, rom.RomRegion(SegOffset(0xD000, 0), b"x")))


def test_inventory_is_immutable():
    declared = inventory(BIOS)
    with pytest.raises(FrozenInstanceError):
        declared.regions = ()  # pyright: ignore[reportAttributeAccessIssue]


@pytest.mark.parametrize(("address", "size", "covered"), [
    (0xC0000, 3, True), (0xC0001, 2, True), (0xC0000, 0, True),
    (0xBFFFF, 1, False), (0xC0003, 1, False), (0xC0000, 4, False),
    (0xC0000, -1, False), (0x100000, 1, False), (0xA0000, 1, False),
])
def test_contains_is_exact_declared_read_coverage(address, size, covered):
    assert inventory(BIOS).contains(address, size) is covered


def test_document_projects_original_coordinates_and_every_byte():
    declared = inventory(TAIL, BIOS)
    assert rom.rom_document(declared) == [
        {"segment": 0xC000, "offset": 0x0000, "data_hex": BIOS_BYTES.hex()},
        {"segment": 0xF800, "offset": 0x7FF0, "data_hex": TAIL_BYTES.hex()},
    ]
    assert rom.rom_document(None) is None
    for bad in (BIOS, "rom", 5, {}):
        with pytest.raises(ValueError):
            rom.rom_document(bad)  # type: ignore[arg-type]


def test_document_binds_segmented_coordinates_not_only_physical_addresses():
    base = rom.rom_document(inventory(rom.RomRegion(SegOffset(0xC000, 0x2A66), b"xy")))
    alias = rom.rom_document(inventory(rom.RomRegion(SegOffset(0xB2A7, 0xFFF6), b"xy")))
    changed = rom.rom_document(inventory(rom.RomRegion(SegOffset(0xC000, 0x2A66), b"xz")))
    assert base != alias      # same physical bytes, different declared coordinates
    assert base != changed    # same coordinates, different byte


def test_parse_round_trips_document_identity_through_json():
    declared = inventory(TAIL, BIOS)
    document = json.loads(json.dumps(rom.rom_document(declared)))
    assert rom.parse_rom(document) == declared
    assert rom.parse_rom(None) is None


@pytest.mark.parametrize("bad", [
    "rom", 5, b"bytes", True, ({"segment": 0xC000, "offset": 0, "data_hex": "ff"},),
    {"segment": 0xC000, "offset": 0, "data_hex": "ff"}, [], [{}],
    [{"segment": 0xC000, "offset": 0, "data_hex": "ff", "extra": 0}],
    [{"segment": 0xC000, "offset": 0}],
    [{"offset": 0, "data_hex": "ff"}],
    [{"segment": 0xC000, "data_hex": "ff"}],
])
def test_parse_rejects_nonlist_shapes_and_wrong_keys(bad):
    with pytest.raises(ValueError):
        rom.parse_rom(bad)


@pytest.mark.parametrize("field", ["segment", "offset"])
@pytest.mark.parametrize("bad", [True, False, -1, 0x10000, 1.5, "0xC000", None])
def test_parse_rejects_loose_coordinates(field, bad):
    item = {"segment": 0xC000, "offset": 0, "data_hex": "ff"}
    item[field] = bad
    with pytest.raises(ValueError):
        rom.parse_rom([item])


@pytest.mark.parametrize("text", [
    "", "f", "fff", "ff ff", " ff", "ff ", "ff\tff", "ff\nff", "gg", "0xff",
    b"ff", None, 5, True, ["ff"], 0x100 * "ff" + "f",
])
def test_parse_rejects_malformed_hex_before_conversion(text):
    with pytest.raises(ValueError):
        rom.parse_rom([{"segment": 0xC000, "offset": 0, "data_hex": text}])


def test_parse_rejects_oversized_hex_before_conversion():
    with pytest.raises(ValueError):
        rom.parse_rom([{"segment": 0xC000, "offset": 0,
                        "data_hex": "ff" * (rom.ROM_WINDOW_BYTES + 1)}])


@pytest.mark.parametrize("document", [
    [{"segment": 0xA000, "offset": 0, "data_hex": "ff"}],          # video RAM
    [{"segment": 0x0000, "offset": 0, "data_hex": "ff"}],          # conventional
    [{"segment": 0xF800, "offset": 0x7FF0, "data_hex": "ff" * 0x11}],  # past ceiling
    [{"segment": 0xC000, "offset": 0, "data_hex": "ff"},
     {"segment": 0xC000, "offset": 0, "data_hex": "aa"}],          # duplicate
])
def test_parse_delegates_domain_refusals_to_the_typed_contract(document):
    with pytest.raises(ValueError):
        rom.parse_rom(document)


def test_parse_accepts_exact_declarations_and_canonicalizes_order():
    document = [
        {"segment": 0xF800, "offset": 0x7FF0, "data_hex": TAIL_BYTES.hex().upper()},
        {"segment": 0xC000, "offset": 0x0000, "data_hex": BIOS_BYTES.hex()},
    ]
    assert rom.parse_rom(document) == inventory(BIOS, TAIL)


def test_parse_accepts_the_sixteen_region_bound():
    document = [
        {"segment": 0xC000, "offset": index * 0x1000, "data_hex": "ff"}
        for index in range(16)
    ]
    assert len(rom.parse_rom(document).regions) == 16
    document.append({"segment": 0xD000, "offset": 0, "data_hex": "ff"})
    with pytest.raises(ValueError):
        rom.parse_rom(document)
