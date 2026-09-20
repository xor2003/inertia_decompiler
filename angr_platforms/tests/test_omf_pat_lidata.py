from __future__ import annotations

from omf_pat import PatPublicName, generate_pat_from_omf_obj, parse_pat_file


def _omf_record(record_type: int, payload: bytes) -> bytes:
    record_length = len(payload) + 1
    return bytes([record_type]) + record_length.to_bytes(2, "little") + payload + b"\x00"


def _omf_counted_name(name: str) -> bytes:
    encoded = name.encode("latin1")
    assert len(encoded) <= 255
    return bytes([len(encoded)]) + encoded


def _build_synthetic_lidata_obj(
    *,
    record_type: int = 0xA2,
    code_offset: int = 0,
    fixup_offset: int | None = None,
    public_name: str = "_lidata_func",
    external_name: str = "_puts",
) -> bytes:
    # LIDATA repeats a 0x42-byte leaf block twice, yielding 0x84 bytes of code.
    # The optional fixup offset is interpreted against the expanded data record.
    chunk = bytearray(b"\x90" * 0x42)
    if fixup_offset is not None:
        chunk_offset = fixup_offset % len(chunk)
        chunk[chunk_offset : chunk_offset + 2] = b"\x00\x00"
    repeat_size = 4 if record_type == 0xA3 else 2
    data_block = (2).to_bytes(repeat_size, "little") + (0).to_bytes(2, "little") + bytes([len(chunk)]) + bytes(chunk)
    offset_bytes = code_offset.to_bytes(4 if record_type == 0xA3 else 2, "little")
    lidata_payload = bytes([1]) + offset_bytes + data_block

    records = [
        _omf_record(0x80, _omf_counted_name("LIDATA.OBJ")),
        _omf_record(0x96, b"\x04CODE\x04CODE"),
        _omf_record(0x98, b"\x00" + (0x84).to_bytes(2, "little") + b"\x01\x02\x00"),
        _omf_record(0x90, b"\x00\x01" + _omf_counted_name(public_name) + b"\x00\x00\x00"),
        _omf_record(0x8C, _omf_counted_name(external_name) + b"\x00"),
        _omf_record(record_type, lidata_payload),
    ]
    if fixup_offset is not None:
        # LOCAT control bits precede the low offset byte; this is not a LE word.
        locat = 0xC400 | fixup_offset
        records.append(_omf_record(0x9C, locat.to_bytes(2, "big") + b"\x46\x01"))
    records.append(_omf_record(0x8A, b""))
    return b"".join(records)


def test_generate_pat_from_omf_obj_expands_lidata_records(tmp_path):
    obj_path = tmp_path / "lidata.obj"
    obj_path.write_bytes(_build_synthetic_lidata_obj())
    pat_path = tmp_path / "lidata.pat"

    count = generate_pat_from_omf_obj(obj_path, pat_path)

    assert count == 1
    modules = parse_pat_file(pat_path)
    assert len(modules) == 1
    module = modules[0]
    assert module.module_name == "_lidata_func"
    assert module.module_length == 0x84
    assert module.pattern_bytes[:8] == (0x90,) * 8
    assert module.tail_bytes[-4:] == (0x90,) * 4


def test_generate_pat_from_omf_obj_masks_fixupp_refs_attached_to_lidata(tmp_path):
    obj_path = tmp_path / "lidata-fixup.obj"
    obj_path.write_bytes(_build_synthetic_lidata_obj(fixup_offset=0x80))
    pat_path = tmp_path / "lidata-fixup.pat"

    count = generate_pat_from_omf_obj(obj_path, pat_path)

    assert count == 1
    module = parse_pat_file(pat_path)[0]
    assert module.referenced_names == (PatPublicName(offset=0x80, name="_puts"),)
    tail_fixup_offset = 0x80 - 32
    assert module.tail_bytes[tail_fixup_offset : tail_fixup_offset + 2] == (None, None)


def test_generate_pat_from_omf_obj_expands_lidata32_records(tmp_path):
    obj_path = tmp_path / "lidata32.obj"
    obj_path.write_bytes(_build_synthetic_lidata_obj(record_type=0xA3))
    pat_path = tmp_path / "lidata32.pat"

    count = generate_pat_from_omf_obj(obj_path, pat_path)

    assert count == 1
    module = parse_pat_file(pat_path)[0]
    assert module.module_length == 0x84
    assert module.pattern_bytes[:4] == (0x90,) * 4


def test_generate_pat_from_omf_obj_rejects_malformed_lidata_without_pattern(tmp_path):
    malformed_lidata = bytes([1]) + (0).to_bytes(2, "little") + (2).to_bytes(2, "little")
    obj_path = tmp_path / "bad-lidata.obj"
    obj_path.write_bytes(
        b"".join(
            [
                _omf_record(0x80, _omf_counted_name("BADLID.OBJ")),
                _omf_record(0x96, b"\x04CODE\x04CODE"),
                _omf_record(0x98, b"\x00" + (0x20).to_bytes(2, "little") + b"\x01\x02\x00"),
                _omf_record(0x90, b"\x00\x01" + _omf_counted_name("_bad_lidata") + b"\x00\x00\x00"),
                _omf_record(0xA2, malformed_lidata),
                _omf_record(0x8A, b""),
            ]
        )
    )
    pat_path = tmp_path / "bad-lidata.pat"

    count = generate_pat_from_omf_obj(obj_path, pat_path)

    assert count == 0
    assert parse_pat_file(pat_path) == ()
