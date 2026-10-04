"""Focused tests for the public real16 replay CLI and manifest boundary.

Layer: tests.
Responsibility: exercise public parser registration, checked manifests and
concrete replay against real MZ fixture bytes without claiming semantic proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tools.dosunit import real16_replay_cli, real16_replay_manifest
from tools.dosunit.dosunit import build_parser
from tools.dosunit.model import DosUnitError

LOAD = 0x1000  # default load paragraph, matches DEFAULT_LOAD_SEGMENT
STACK_SEG = 0x7000
STACK_SP = 0x0100
TRAP_OFF = 0x8000  # near-frame return offset inside entry CS, outside image bytes


@pytest.fixture()
def manifest() -> ModuleType:
    """Expose the production manifest owner."""
    return real16_replay_manifest


@pytest.fixture()
def cli() -> ModuleType:
    """Expose the production CLI owner."""
    return real16_replay_cli


def _mz(image: bytes) -> bytes:
    """Wrap load-module bytes in a minimal valid MZ header (no relocs)."""
    reloc_pos = 0x1C
    header_size = ((reloc_pos + 15) // 16) * 16
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x06:0x08] = (0).to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0A:0x0C] = (0).to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x14:0x16] = (0).to_bytes(2, "little")
    header[0x16:0x18] = (0).to_bytes(2, "little")
    header[0x18:0x1A] = reloc_pos.to_bytes(2, "little")
    return bytes(header) + image


def _vector(**overrides: object) -> dict[str, object]:
    """One checked near-frame JSON vector at the fixture image entry."""
    vector: dict[str, object] = {
        "id": "v1",
        "oracle_entry": {"segment": LOAD, "offset": 0},
        "candidate_entry": {"segment": LOAD, "offset": 0},
        "registers": {"sp": STACK_SP, "flags": "0x2"},
        "segments": {"ds": LOAD, "es": LOAD, "ss": STACK_SEG},
        "frame": {
            "kind": "near16",
            "target": {"segment": LOAD, "offset": TRAP_OFF},
        },
    }
    vector.update(overrides)
    return vector


def _run_cli(
    cli: ModuleType,
    tmp_path: Path,
    oracle_code: bytes,
    candidate_code: bytes,
    vectors: list[dict[str, object]],
    *,
    limit: int = 100000,
    document_extra: dict[str, object] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Write real MZ fixtures, invoke the registered command, read the report."""
    oracle = tmp_path / "oracle.exe"
    candidate = tmp_path / "candidate.exe"
    vectors_path = tmp_path / "vectors.json"
    out = tmp_path / "report.json"
    oracle.write_bytes(_mz(oracle_code))
    candidate.write_bytes(_mz(candidate_code))
    document: dict[str, object] = {"vectors": vectors}
    document.update(document_extra or {})
    vectors_path.write_text(json.dumps(document))
    parser = build_parser()
    args = parser.parse_args(
        [
            "replay-real16",
            "--oracle-exe", str(oracle),
            "--candidate-exe", str(candidate),
            "--vectors", str(vectors_path),
            "--instruction-limit", str(limit),
            "--out", str(out),
        ]
    )
    status = args.func(args)
    report: dict[str, Any] = json.loads(out.read_text()) if out.exists() else {}
    return status, report


def test_identical_mz_images_agree(cli: ModuleType, tmp_path: Path) -> None:
    """mov ax,1234h; ret on both sides: agreement, typed report contract."""
    status, report = _run_cli(
        cli, tmp_path, bytes.fromhex("b8 34 12 c3"), bytes.fromhex("b8 34 12 c3"),
        [_vector()],
    )
    assert status == 0
    assert report["schema"] == "dosunit.real16_replay.v1"
    assert report["proof_status"] == "not_established_by_execution"
    assert report["summary"] == {"total": 1, "agreed": 1, "mismatched": 0, "incomplete": 0}
    assert report["policy"]["high_half_default"] == "zero"
    assert "mapped pages start zero" in report["policy"]["initial_memory"]
    row = report["results"][0]
    assert row["id"] == "v1"
    assert row["status"] == "agreed"
    assert row["oracle"]["status"] == "returned"
    assert row["oracle"]["registers"]["ax"] == "0x1234"
    assert row["comparison"]["observables_source"] == "default"
    assert row["oracle"]["effective_flags_mask"] == "0xfd5"
    assert row["initial_state"]["oracle_entry"] == {"segment": "0x1000", "offset": "0x0"}
    assert row["initial_state"]["frame"]["kind"] == "near16"


def test_mutated_ax_mismatches(cli: ModuleType, tmp_path: Path) -> None:
    """Same shape, different AX constant: known-unequal evidence, exit 1."""
    status, report = _run_cli(
        cli, tmp_path, bytes.fromhex("b8 34 12 c3"), bytes.fromhex("b8 35 12 c3"),
        [_vector()],
    )
    assert status == 1
    assert report["results"][0]["status"] == "mismatched"
    assert report["summary"]["mismatched"] == 1


def test_defined_flag_difference_mismatches(cli: ModuleType, tmp_path: Path) -> None:
    """clc vs stc: identical registers, divergent defined CF bit, exit 1."""
    status, report = _run_cli(
        cli, tmp_path, bytes.fromhex("f8 c3"), bytes.fromhex("f9 c3"),
        [_vector()],
    )
    assert status == 1
    assert report["results"][0]["status"] == "mismatched"


def test_declared_flags_mask_scopes_flag_comparison(cli: ModuleType, tmp_path: Path) -> None:
    """A mask excluding CF makes clc/stc indistinguishable: agreed, exit 0."""
    status, report = _run_cli(
        cli, tmp_path, bytes.fromhex("f8 c3"), bytes.fromhex("f9 c3"),
        [_vector(flags_mask="0xFD4")],
    )
    assert status == 0
    row = report["results"][0]
    assert row["status"] == "agreed"
    assert row["oracle"]["effective_flags_mask"] == "0xfd4"


def test_declared_observables_visible_in_report(cli: ModuleType, tmp_path: Path) -> None:
    """An explicit observable set is published as the scoped comparison set."""
    observables = ["ax", "flags", "bx", "si", "di", "bp", "sp", "ds", "ss"]
    status, report = _run_cli(
        cli, tmp_path, bytes.fromhex("b8 34 12 c3"), bytes.fromhex("b8 34 12 c3"),
        [_vector(observables=observables)],
    )
    assert status == 0
    comparison = report["results"][0]["comparison"]
    assert comparison["observables_source"] == "declared"
    assert sorted(comparison["observables"]) == sorted(observables)


def test_budget_exhaustion_is_incomplete(cli: ModuleType, tmp_path: Path) -> None:
    """jmp $ under a small instruction budget: INCOMPLETE, never mismatch."""
    status, report = _run_cli(
        cli, tmp_path, bytes.fromhex("eb fe"), bytes.fromhex("eb fe"),
        [_vector()], limit=64,
    )
    assert status == 2
    row = report["results"][0]
    assert row["status"] == "incomplete"
    assert row["oracle"]["status"] == "budget_exhausted"


@pytest.mark.parametrize(
    "vectors",
    [
        [],
        [{**_vector(), "id": "v"}, {**_vector(), "id": "v"}],
        [{"id": "v1"}],
        [_vector(frame={"kind": "ring0", "target": {"segment": LOAD, "offset": TRAP_OFF}})],
        [_vector(registers={"ax": True, "sp": STACK_SP})],
        [_vector(registers={"ax": 0x1_0000, "sp": STACK_SP})],
        [_vector(observables=["ax"])],
        [_vector(observables=["ax", "ax", "bx", "si", "di", "bp", "sp", "ds", "ss"])],
    ],
    ids=[
        "empty", "duplicate_ids", "missing_fields", "bad_frame_kind",
        "bool_register", "u16_overflow", "observables_drop_preserved",
        "observables_duplicate",
    ],
)
def test_malformed_selections_refuse(
    cli: ModuleType, tmp_path: Path, vectors: list[dict[str, object]],
) -> None:
    """Empty/duplicate/malformed selections are DosUnitError, no partial report."""
    oracle = tmp_path / "oracle.exe"
    candidate = tmp_path / "candidate.exe"
    vectors_path = tmp_path / "vectors.json"
    out = tmp_path / "report.json"
    oracle.write_bytes(_mz(bytes.fromhex("c3")))
    candidate.write_bytes(_mz(bytes.fromhex("c3")))
    vectors_path.write_text(json.dumps({"vectors": vectors}))
    args = argparse.Namespace(
        oracle_exe=oracle, candidate_exe=candidate, vectors=vectors_path,
        instruction_limit=1000, out=out,
    )
    with pytest.raises(DosUnitError):
        cli.cmd_replay_real16(args)
    assert not out.exists()


def test_late_malformed_vector_never_executes(cli: ModuleType, tmp_path: Path) -> None:
    """A bad second vector fails the whole selection before any guest runs."""
    bad = _vector(id="v2", frame={"kind": "bogus", "target": {"segment": LOAD, "offset": 0}})
    with pytest.raises(DosUnitError):
        _run_cli(
            cli, tmp_path, bytes.fromhex("c3"), bytes.fromhex("c3"),
            [_vector(), bad],
        )
    assert not (tmp_path / "report.json").exists()


def test_binary_unchanged_and_input_fingerprints(cli: ModuleType, tmp_path: Path) -> None:
    """The report binds the exact input file bytes that were executed."""
    code = bytes.fromhex("b8 34 12 c3")
    status, report = _run_cli(cli, tmp_path, code, code, [_vector()])
    assert status == 0
    digest = hashlib.sha256(_mz(code)).hexdigest()
    assert report["inputs"]["oracle"]["sha256"] == digest
    assert report["inputs"]["candidate"]["sha256"] == digest
    assert report["inputs"]["oracle"]["image"]["image_sha256"]


def test_missing_vectors_file_wraps_oserror(cli: ModuleType, tmp_path: Path) -> None:
    """A missing manifest is a DosUnitError whose cause is the OSError."""
    args = argparse.Namespace(
        oracle_exe=tmp_path / "oracle.exe",
        candidate_exe=tmp_path / "candidate.exe",
        vectors=tmp_path / "absent.json",
        instruction_limit=1000,
        out=tmp_path / "report.json",
    )
    with pytest.raises(DosUnitError) as caught:
        cli.cmd_replay_real16(args)
    assert isinstance(caught.value.__cause__, OSError)


def test_missing_binary_wraps_oserror(cli: ModuleType, tmp_path: Path) -> None:
    """A missing MZ input is a DosUnitError whose cause is the OSError."""
    vectors_path = tmp_path / "vectors.json"
    vectors_path.write_text(json.dumps({"vectors": [_vector()]}))
    args = argparse.Namespace(
        oracle_exe=tmp_path / "absent.exe",
        candidate_exe=tmp_path / "candidate.exe",
        vectors=vectors_path,
        instruction_limit=1000,
        out=tmp_path / "report.json",
    )
    with pytest.raises(DosUnitError) as caught:
        cli.cmd_replay_real16(args)
    assert isinstance(caught.value.__cause__, OSError)


def test_non_mz_binary_refuses(cli: ModuleType, tmp_path: Path) -> None:
    """A non-MZ input file is a DosUnitError, never a crash."""
    oracle = tmp_path / "oracle.exe"
    candidate = tmp_path / "candidate.exe"
    vectors_path = tmp_path / "vectors.json"
    oracle.write_bytes(b"not an mz image")
    candidate.write_bytes(b"not an mz image")
    vectors_path.write_text(json.dumps({"vectors": [_vector()]}))
    args = argparse.Namespace(
        oracle_exe=oracle, candidate_exe=candidate, vectors=vectors_path,
        instruction_limit=1000, out=tmp_path / "report.json",
    )
    with pytest.raises(DosUnitError, match="cannot load"):
        cli.cmd_replay_real16(args)


def test_nonpositive_instruction_limit_refuses(cli: ModuleType, tmp_path: Path) -> None:
    """The instruction budget is explicit and positive."""
    vectors_path = tmp_path / "vectors.json"
    vectors_path.write_text(json.dumps({"vectors": [_vector()]}))
    args = argparse.Namespace(
        oracle_exe=tmp_path / "oracle.exe",
        candidate_exe=tmp_path / "candidate.exe",
        vectors=vectors_path,
        instruction_limit=0,
        out=tmp_path / "report.json",
    )
    with pytest.raises(DosUnitError, match="instruction limit"):
        cli.cmd_replay_real16(args)


def test_non_string_register_names_refuse(manifest: ModuleType) -> None:
    """Register maps with non-string keys are checked, not TypeError crashes."""
    document = {"vectors": [_vector(registers={0: 1, "bogus": 2, "sp": STACK_SP})]}
    with pytest.raises(DosUnitError, match="names must be strings"):
        manifest.parse_manifest(document)


def test_bad_frame_kind_carries_valueerror_cause(manifest: ModuleType) -> None:
    """An unknown frame kind is a DosUnitError that keeps the enum's cause."""
    document = {
        "vectors": [
            _vector(
                frame={"kind": "ring0", "target": {"segment": LOAD, "offset": TRAP_OFF}},
            ),
        ],
    }
    with pytest.raises(DosUnitError) as caught:
        manifest.parse_manifest(document)
    assert isinstance(caught.value.__cause__, ValueError)


def test_manifest_parses_all_vectors_typed(manifest: ModuleType) -> None:
    """parse_manifest returns typed entries/vector contracts for the selection."""
    parsed = manifest.parse_manifest(
        {
            "oracle_load_segment": "0x2000",
            "vectors": [_vector(), _vector(id="v2")],
        },
    )
    assert parsed.oracle_load_segment == 0x2000
    assert parsed.candidate_load_segment == 0x1000
    assert len(parsed.vectors) == 2
    assert parsed.vectors[0].vector_id == "v1"
    assert parsed.vectors[1].vector_id == "v2"
    assert parsed.vectors[0].oracle_entry.linear() == 0x10000


def test_report_write_failure_carries_oserror(cli: ModuleType, tmp_path: Path) -> None:
    """A valid run that cannot write its report exposes the filesystem cause."""
    vectors_path = tmp_path / "vectors.json"
    vectors_path.write_text(json.dumps({"vectors": [_vector()]}))
    image_path = tmp_path / "image.exe"
    image_path.write_bytes(_mz(bytes.fromhex("c3")))
    args = argparse.Namespace(
        oracle_exe=image_path, candidate_exe=image_path, vectors=vectors_path,
        instruction_limit=1000, out=tmp_path,
    )
    with pytest.raises(DosUnitError) as caught:
        cli.cmd_replay_real16(args)
    assert isinstance(caught.value.__cause__, OSError)


def test_absent_segments_use_declared_zero_defaults(cli: ModuleType, tmp_path: Path) -> None:
    """Absent SS/DS/ES defaults are usable mapped segments, not setup faults."""
    status, report = _run_cli(cli, tmp_path, bytes.fromhex("a10002c3"),
                              bytes.fromhex("a10002c3"), [_vector(segments={})])
    assert status == 0
    assert report["results"][0]["oracle"]["registers"]["ss"] == "0x0"
    assert report["results"][0]["oracle"]["registers"]["ax"] == "0x0"
