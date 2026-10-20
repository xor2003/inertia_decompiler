# Focused controls for tools/ada_script/data_discovery.py
#
# Layer: disassembly-side recovery tests.  These prove automatic
# data discovery: data refs create sized items, strings are found
# in unreferenced data bytes, lea never creates an item, and offset
# words get `offset` markings.

import struct

from tools.ada_script.data_discovery import DataDiscovery
from tools.ada_script.mz_parser import LOAD_BASE, MZParser

DSEG = LOAD_BASE + 0x200  # data segment starts at image offset 0x200


def _mz(image: bytes, cs: int = 0, ip: int = 0) -> bytes:
    """Minimal MZ wrapper: 32-byte header, no relocations, off-image SS."""
    hdr = bytearray(32)
    hdr[:2] = b'MZ'
    size = len(hdr) + len(image)
    pages, rem = divmod(size, 512)
    if rem:
        pages += 1
    for off, val in ((2, rem or 512), (4, pages), (6, 0), (8, 2),
                     (10, 0x20), (12, 0xFFFF), (14, 0x2000),
                     (16, 0x800), (20, ip), (22, cs), (24, 0x1C)):
        struct.pack_into('<H', hdr, off, val)
    return bytes(hdr) + image


def _image() -> bytes:
    """Synthetic 16-bit image exercising every discovery path."""
    img = bytearray(0x400)
    # code at 0x0000 (entry)
    code = bytes([
        0xA1, 0x00, 0x02,        # mov ax, [0200h]  -> C string
        0xA2, 0x1B, 0x02,        # mov [021Bh], al  -> byte item
        0x8D, 0x1E, 0x12, 0x02,  # lea bx, [0212h]  -> offset ref only
        0xA1, 0x14, 0x02,        # mov ax, [0214h]  -> offset word
        0x8A, 0x0E, 0x16, 0x02,  # mov cl, [0216h]  -> pascal str
        0x8A, 0x26, 0x1C, 0x02,  # mov ah, [021Ch]  -> utf16 str
        0xC3,                    # ret
    ])
    img[:len(code)] = code
    img[len(code):0x200] = b'\xCC' * (0x200 - len(code))  # int3 padding
    img[0x200:0x206] = b'Hello\x00'                        # ref'd C str
    img[0x206:0x20C] = b'WORLD\x00'                        # sweep C str
    img[0x20C:0x212] = b'\x05HELLO'                        # sweep Pascal
    img[0x212:0x214] = b'\x34\x12'                         # lea target
    img[0x214:0x216] = b'\x00\x02'                         # dw 0x0200
    img[0x216:0x21B] = b'\x04N M!'                         # loose Pascal
    img[0x21B] = 0xFF                                      # byte scalar
    img[0x21C:0x22A] = b'W\x00I\x00D\x00E\x00R\x00\x00\x00'  # utf16le "WIDER"
    return bytes(img)


def _analyze(image: bytes, monkeypatch, tmp_path):
    """Parse the synthetic MZ, declare a dseg, and run the Analyzer."""
    from tools.ada_script.analyzer import Analyzer
    monkeypatch.chdir(tmp_path)
    binary = _mz(image)
    db = MZParser(binary).parse()
    db.binary = binary
    img_end = LOAD_BASE + db.image_size
    db.execute("UPDATE segments SET end_addr=? WHERE start_addr=? AND type='code'",
               (DSEG, LOAD_BASE))
    db.execute("INSERT INTO segments (start_addr, end_addr, base, class, type, "
               "executable, name) VALUES (?, ?, ?, 'DATA', 'data', 0, 'dseg')",
               (DSEG, img_end, DSEG >> 4))
    db.execute("INSERT OR REPLACE INTO config (key, value) "
               "VALUES ('default_ds', ?)", (str(LOAD_BASE >> 4),))
    Analyzer(binary, db, xrefs=True).analyze()
    return db


def _items(db):
    return {a: (sz, k, c) for a, sz, k, c in db.conn.execute(
        "SELECT addr, size, kind, count FROM data_items")}


def test_discovery_finds_vars_and_strings(monkeypatch, tmp_path):
    db = _analyze(_image(), monkeypatch, tmp_path)
    items = _items(db)

    # reference-driven items
    assert items[DSEG + 0x000] == (6, 'str', 1)      # 'Hello\0'
    assert items[DSEG + 0x014] == (2, 'word', 1)     # dw 0x0200 -> offset
    assert items[DSEG + 0x016] == (5, 'str', 1)      # Pascal 'N M!'
    assert items[DSEG + 0x01B] == (1, 'byte', 1)     # byte scalar

    # sweep-found items (unreferenced)
    assert items[DSEG + 0x006] == (6, 'str', 1)      # 'WORLD\0'
    assert items[DSEG + 0x00C] == (6, 'str', 1)      # '\x05HELLO' Pascal
    assert items[DSEG + 0x01C] == (12, 'str', 1)     # utf16 'WIDER'

    # lea never creates a data item at its target
    assert DSEG + 0x012 not in items

    # nothing created inside the code segment
    assert all(a >= DSEG for a in items)

    # offset word carries an `offset` operand override + xref
    row = db.conn.execute(
        "SELECT arg FROM op_overrides WHERE addr=? AND kind='offset'",
        (DSEG + 0x014,)).fetchone()
    assert row and row[0] == LOAD_BASE
    xref = db.conn.execute(
        "SELECT type FROM xrefs WHERE from_addr=? AND to_addr=?",
        (DSEG + 0x014, DSEG)).fetchone()
    assert xref and xref[0] == 'o'

    db.close()


def test_validators_direct():
    """Validator boundaries: termination, minimums, encodings."""
    c = DataDiscovery._cstring_len
    assert c(b'Hello\x00junk') == 5
    assert c(b'Hi\x00') == -1                    # too short
    assert c(b'NoTerminator') == -1              # unterminated
    assert c(b'Bad\xffChar\x00') == -1           # high byte rejects
    assert c(b'With\tTab\x00') == 8              # TAB allowed

    p = DataDiscovery._pascal_len
    assert p(b'\x04N M!', ident_only=False) == 4
    assert p(b'\x04N M!', ident_only=True) == -1  # space not ident
    assert p(b'\x05HELLO', ident_only=True) == 5
    assert p(b'\x011', ident_only=False) == -1    # below kernel minimum

    u = DataDiscovery._utf16_len
    assert u(b'W\x00I\x00D\x00\x00\x00') == -1    # 3 chars < minimum
    assert u(b'W\x00I\x00D\x00E\x00R\x00\x00\x00') == 5


def test_sweep_respects_boundaries(monkeypatch, tmp_path):
    """A string must not span a relocation word or a busy item."""
    image = bytearray(0x400)
    image[0x200:0x208] = b'ABCDEFGH'   # unterminated run split by reloc
    img = _mz(bytes(image))
    monkeypatch.chdir(tmp_path)
    db = MZParser(img).parse()
    db.binary = img
    img_end = LOAD_BASE + db.image_size
    db.execute("UPDATE segments SET end_addr=? WHERE start_addr=? AND type='code'",
               (DSEG, LOAD_BASE))
    db.execute("INSERT INTO segments (start_addr, end_addr, base, class, type, "
               "executable, name) VALUES (?, ?, ?, 'DATA', 'data', 0, 'dseg')",
               (DSEG, img_end, DSEG >> 4))
    db.execute("INSERT INTO relocations (addr, offset) VALUES (?, ?)",
               (DSEG + 4, 0))
    from tools.ada_script.analyzer import Analyzer
    Analyzer(img, db).analyze()
    items = _items(db)
    # the reloc word becomes a 'word' item; no string may span it
    assert items[DSEG + 4] == (2, 'word', 1)
    for a, (sz, _k, cnt) in items.items():
        assert a >= DSEG + 4 or a + sz * cnt <= DSEG + 4
    db.close()
