"""Real executable controls for the public flat32 differential replay command."""

import json
import struct
from pathlib import Path

from tools.dosunit.dosunit import main


def _elf32(code: bytes) -> bytes:
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    header = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 3, 1, 0x10000, 52, 0, 0, 52, 32, 1, 40, 0, 0)
    program = struct.pack('<IIIIIIII', 1, 0x1000, 0x10000, 0x10000, len(code), len(code), 5, 0x1000)
    return (header + program).ljust(0x1000, b'\x00') + code


def test_public_replay_command_executes_binary_and_rejects_corruption(tmp_path: Path):
    original = tmp_path / 'original.elf'
    candidate = tmp_path / 'candidate.elf'
    original.write_bytes(_elf32(bytes.fromhex('b807000000 c3')))
    candidate.write_bytes(_elf32(bytes.fromhex('b808000000 c3')))
    vectors = tmp_path / 'vectors.json'
    vectors.write_text(json.dumps({'vectors': [{'id': 'return-value', 'oracle_entry': '0x10000',
                                               'candidate_entry': '0x10000', 'registers': {'esp': '0x28000'}}]}))
    out = tmp_path / 'result.json'
    args = ['replay-flat32', '--oracle-exe', str(original), '--candidate-exe', str(candidate),
            '--vectors', str(vectors), '--out', str(out), '--instruction-limit', '100']
    assert main(args) == 1
    result = json.loads(out.read_text())
    assert result['summary'] == {'total': 1, 'agreed': 0, 'mismatched': 1, 'incomplete': 0}
    assert result['proof_status'] == 'not_established_by_execution'
    assert result['results'][0]['oracle']['status'] == 'returned'
    assert result['results'][0]['differences']['registers'] == [{'name': 'eax', 'oracle': 7, 'candidate': 8}]
    assert result['inputs']['oracle']['sha256'] != result['inputs']['candidate']['sha256']
    candidate.write_bytes(original.read_bytes())
    assert main(args) == 0
    assert json.loads(out.read_text())['summary']['agreed'] == 1


def test_public_replay_empty_selection_cannot_succeed(tmp_path: Path):
    vectors = tmp_path / 'vectors.json'
    vectors.write_text('{"vectors": []}')
    assert main(['replay-flat32', '--oracle-exe', 'missing', '--candidate-exe', 'missing',
                 '--vectors', str(vectors), '--out', str(tmp_path / 'result.json')]) == 2


def test_public_observation_cannot_supply_guest_mapping(tmp_path: Path) -> None:
    """Observing an undeclared store target cannot turn both guest faults into agreement."""
    image = tmp_path / 'store.elf'
    image.write_bytes(_elf32(bytes.fromhex('a300004000 c3')))
    vectors = tmp_path / 'vectors.json'
    vectors.write_text(json.dumps({'vectors': [{'id': 'unmapped-store', 'oracle_entry': '0x10000',
        'candidate_entry': '0x10000', 'registers': {'esp': '0x28000', 'eax': 17},
        'observations': [{'address': '0x400000', 'size': 4}]}]}))
    out = tmp_path / 'result.json'
    assert main(['replay-flat32', '--oracle-exe', str(image), '--candidate-exe', str(image),
                 '--vectors', str(vectors), '--out', str(out)]) == 2
    document = json.loads(out.read_text())
    assert document['summary']['incomplete'] == 1
    for side in ('oracle', 'candidate'):
        result = document['results'][0][side]
        assert result['status'] == 'faulted' and result['detail'] == 'write_unmapped'
        assert result['writes'] == []
        assert result['observations'][0]['status'] == 'unmapped'


def test_public_explicit_scratch_is_separate_from_observations(tmp_path: Path) -> None:
    """The public vector declares scratch access and reports its evidence explicitly."""
    image = tmp_path / 'store.elf'
    image.write_bytes(_elf32(bytes.fromhex('a300004000 c3')))
    vector = {'id': 'explicit-scratch', 'oracle_entry': '0x10000', 'candidate_entry': '0x10000',
        'registers': {'esp': '0x28000', 'eax': 17},
        'observations': [{'address': '0x400000', 'size': 4}],
        'mappings': [{'address': '0x400000', 'size': 4, 'access': ['read', 'write']}]}
    vectors = tmp_path / 'vectors.json'
    vectors.write_text(json.dumps({'vectors': [vector]}))
    out = tmp_path / 'result.json'
    args = ['replay-flat32', '--oracle-exe', str(image), '--candidate-exe', str(image),
            '--vectors', str(vectors), '--out', str(out)]
    assert main(args) == 0
    result = json.loads(out.read_text())['results'][0]['oracle']
    assert result['requested_observations'] == [{'address': '0x400000', 'size': 4}]
    assert result['observations'] == [{'address': '0x400000', 'size': 4, 'status': 'captured',
                                      'bytes': '11000000', 'origins': ['vector']}]
    vector['mappings'][0]['access'] = ['execute']
    vectors.write_text(json.dumps({'vectors': [vector]}))
    assert main(args) == 2


def test_public_replay_loads_pe_header_beyond_autodetection_window(tmp_path: Path) -> None:
    from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

    images = []
    for value in (7, 8):
        source = pe32_bytes(b"\xb8" + struct.pack("<I", value) + b"\xc3")
        raw = bytearray(source[:0x80].ljust(0x1100, b"\0") +
                        source[0x80:0x200].ljust(0x300, b"\0") + source[0x200:])
        struct.pack_into("<I", raw, 0x3c, 0x1100)
        optional = 0x1118
        for offset, number in ((16, 0x2000), (20, 0x2000), (56, 0x3000), (60, 0x1400)):
            struct.pack_into("<I", raw, optional + offset, number)
        section = optional + 0xe0
        struct.pack_into("<I", raw, section + 12, 0x2000)
        struct.pack_into("<I", raw, section + 20, 0x1400)
        path = tmp_path / f"late-{value}.exe"
        path.write_bytes(raw)
        images.append(path)
    vectors = tmp_path / "vectors.json"
    vectors.write_text(json.dumps({"vectors": [{"id": "late-header", "oracle_entry": "0x402000",
        "candidate_entry": "0x402000", "registers": {"esp": "0x80000"}}]}))
    output = tmp_path / "result.json"
    assert main(["replay-flat32", "--oracle-exe", str(images[0]), "--candidate-exe", str(images[1]),
                 "--vectors", str(vectors), "--out", str(output)]) == 1
    row, = json.loads(output.read_text())["results"]
    assert row["oracle"]["status"] == row["candidate"]["status"] == "returned"
    assert row["oracle"]["registers"]["eax"] == 7
    assert row["candidate"]["registers"]["eax"] == 8


def test_public_replay_separates_observed_and_written_memory(tmp_path: Path) -> None:
    """Different stores can leave equal memory; changed bytes must stay visible."""
    original = tmp_path / "original.elf"
    candidate = tmp_path / "candidate.elf"
    # Original writes one word; candidate writes the same two bytes separately.
    original.write_bytes(_elf32(bytes.fromhex("66 c7 05 00004000 1122 c3")))
    candidate.write_bytes(_elf32(bytes.fromhex("c6 05 00004000 11 c6 05 01004000 22 c3")))
    vectors = tmp_path / "vectors.json"
    vectors.write_text(json.dumps({"vectors": [{"id": "stores", "oracle_entry": "0x10000",
        "candidate_entry": "0x10000", "registers": {"esp": "0x28000"},
        "observations": [{"address": "0x400000", "size": 2}],
        "mappings": [{"address": "0x400000", "size": 2, "access": ["read", "write"]}]}]}))
    out = tmp_path / "result.json"
    args = ["replay-flat32", "--oracle-exe", str(original), "--candidate-exe", str(candidate),
            "--vectors", str(vectors), "--out", str(out)]
    assert main(args) == 0
    row, = json.loads(out.read_text())["results"]
    assert row["differences"] == {"registers": [], "observed_memory": [], "written_memory": False}
    # Repeating a write preserves both final observation and written-byte evidence.
    candidate.write_bytes(_elf32(bytes.fromhex("c6 05 00004000 11 c6 05 01004000 22 c6 05 00004000 11 c3")))
    assert main(args) == 0  # Repeated identical writes are not an ordered trace.
    candidate.write_bytes(_elf32(bytes.fromhex("c6 05 00004000 11 c6 05 01004000 23 c3")))
    assert main(args) == 1
    row, = json.loads(out.read_text())["results"]
    assert row["differences"] == {"registers": [],
        "observed_memory": [{"address": "0x400000", "size": 2,
                             "oracle_bytes": "1122", "candidate_bytes": "1123"}],
        "written_memory": True}


def test_public_replay_incomplete_has_no_comparison_diagnostics(tmp_path: Path) -> None:
    """A fault cannot publish apparently complete memory-difference evidence."""
    image = tmp_path / "fault.elf"
    image.write_bytes(_elf32(bytes.fromhex("a3 00004000 c3")))
    vectors = tmp_path / "vectors.json"
    vectors.write_text(json.dumps({"vectors": [{"id": "fault", "oracle_entry": "0x10000",
        "candidate_entry": "0x10000", "registers": {"esp": "0x28000"},
        "observations": [{"address": "0x400000", "size": 4}]}]}))
    out = tmp_path / "result.json"
    assert main(["replay-flat32", "--oracle-exe", str(image), "--candidate-exe", str(image),
                 "--vectors", str(vectors), "--out", str(out)]) == 2
    row, = json.loads(out.read_text())["results"]
    assert row["differences"] is None
