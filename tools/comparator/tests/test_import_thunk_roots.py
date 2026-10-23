"""Verified thunk identities propose roots but never replace semantic proof."""

import json
import struct
import sys
from pathlib import Path

import pytest

from tools.comparator.import_thunk_roots import match_import_thunk_roots
from tools.comparator.msc8_catalog import Symbol
from tools.dosunit.architectures.flat32_loader import load_flat32_project
from tools.dosunit.catalog.pe32_link_map import load_candidate_link_map
from tools.dosunit.tests.test_pe32_import_service import ENTRY, IAT_SLOT, pe32_import_bytes
from tools.dosunit.tests.test_pe32_link_map import _map_text

JUMP = b"\xff\x25" + struct.pack("<I", IAT_SLOT)


def fixture(tmp_path: Path, *, candidate_code: bytes = JUMP, duplicate: bool = False,
            wrong_import: bool = False) -> tuple:
    for side, code in (("oracle", JUMP), ("candidate", candidate_code)):
        raw = pe32_import_bytes(code.ljust(32, b"\x90"))
        if side == "candidate" and wrong_import:
            raw = raw.replace(b"GetTickCount", b"GetTickCounX")
        (tmp_path / f"{side}.exe").write_bytes(raw)
    publics = " 0001:00000000       _different_name          00401000   import.obj\n"
    # Alias spelling does not create a second candidate address.
    publics += " 0001:00000000       _same_address_alias      00401000   import.obj\n"
    if duplicate:
        publics += " 0001:00000010       _other_thunk             00401010   import.obj\n"
    path = tmp_path / "candidate.map"
    path.write_text(_map_text(publics, timestamp=0, segments=" 0001:00000000 00000020H .text CODE\n")
                    .split(" Static symbols")[0])
    oracle = load_flat32_project(tmp_path / "oracle.exe")
    candidate = load_flat32_project(tmp_path / "candidate.exe")
    return oracle, candidate, load_candidate_link_map(path, tmp_path / "candidate.exe")


@pytest.mark.parametrize(("code", "duplicate", "wrong_import", "expected"), [
    (JUMP, False, False, "added"),
    (JUMP.ljust(16, b"\x90") + JUMP, True, False, "ambiguous"),
    (JUMP, False, True, "unmatched"),
    (b"\xff\x15" + struct.pack("<I", IAT_SLOT), False, False, "unmatched"),
    (b"\xc3", False, False, "unmatched"),
])
def test_match_uses_native_identity_and_unique_address(
    tmp_path: Path, code: bytes, duplicate: bool, wrong_import: bool, expected: str,
) -> None:
    oracle, candidate, link = fixture(tmp_path, candidate_code=code, duplicate=duplicate, wrong_import=wrong_import)
    symbols, evidence = match_import_thunk_roots(oracle, candidate, {"root": (ENTRY, ENTRY)}, {}, ["root"], link)
    assert evidence[0]["status"] == expected
    assert ("root" in symbols) == (expected == "added")
    assert not evidence[0]["function_equivalence_proved"]


def test_existing_mapping_has_priority_and_loaded_bytes_are_authoritative(tmp_path: Path) -> None:
    oracle, candidate, link = fixture(tmp_path)
    (tmp_path / "candidate.exe").write_bytes(b"different on-disk file")
    symbols = {"root": Symbol(ENTRY + 16, 1, "T")}
    result, evidence = match_import_thunk_roots(oracle, candidate, {"root": (ENTRY, ENTRY)}, symbols, ["root"], link)
    assert result == symbols and not evidence
    result, evidence = match_import_thunk_roots(oracle, candidate, {"root": (ENTRY, ENTRY)}, {}, ["root"], link)
    assert result["root"] == Symbol(ENTRY, 6, "T")
    assert evidence[0]["status"] == "added"


def test_same_api_name_in_different_dll_does_not_match(tmp_path: Path) -> None:
    oracle, _candidate, link = fixture(tmp_path)
    path = tmp_path / "candidate.exe"
    path.write_bytes(path.read_bytes().replace(b"kernel32.dll", b"kernel33.dll"))
    candidate = load_flat32_project(path)
    symbols, evidence = match_import_thunk_roots(oracle, candidate, {"root": (ENTRY, ENTRY)}, {}, ["root"], link)
    assert not symbols
    assert evidence[0]["status"] == "unmatched"


@pytest.mark.parametrize("declared", [False, True])
def test_cli_admission_requires_independent_external_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, declared: bool,
) -> None:
    from tools.comparator.msc8_cli import main

    fixture(tmp_path)
    (tmp_path / "oracle.lst").write_text(f".text:{ENTRY:08X} root proc\n.text:{ENTRY:08X} root endp\n")
    (tmp_path / "candidate.lst").write_text("")
    catalog = tmp_path / "external.json"
    catalog.write_text(json.dumps({"schema": "dosunit.flat32_external_calls.v1", "functions": {"root": [
        {"dll": "kernel32.dll", "name": "GetTickCount", "argument_count": 0, "cleanup": "callee"}]}}))
    args = ["z3cmp32", "--oracle-exe", str(tmp_path / "oracle.exe"), "--oracle-lst", str(tmp_path / "oracle.lst"),
            "--candidate-exe", str(tmp_path / "candidate.exe"), "--candidate-lst", str(tmp_path / "candidate.lst"),
            "--candidate-code-map", str(tmp_path / "candidate.map"), "--candidate-lst-end-kind", "last-byte",
            "--functions", "root", "--mode", "matched-cfg", "--out-dir", str(tmp_path / "out")]
    if declared:
        args += ["--external-call-catalog", str(catalog)]
    monkeypatch.setattr(sys, "argv", args)
    main()
    baseline = json.loads((tmp_path / "out/compare.json").read_text())
    assert baseline["results"][0]["reason"] == "mapping_missing"
    monkeypatch.setattr(sys, "argv", [*args, "--match-import-thunks"])
    main()
    report = json.loads((tmp_path / "out/compare.json").read_text())
    assert report["import_thunk_correspondence"][0]["status"] == "added"
    assert report["results"][0]["status"] == ("conditional" if declared else "refused")
    assert report["original_function_coverage"]["proved_percent"] == 0
    if declared:
        assert report["results"][0]["reason"] == "declared_external_call_contracts"
        assert report["results"][0]["proof_scope"] == "complete_function"


@pytest.mark.parametrize("prefix", [b"\xe9\x0b\x00\x00\x00", b"\xeb\x0e"])
def test_direct_jump_alias_proposes_import_root(tmp_path: Path, prefix: bytes) -> None:
    _oracle, candidate, link = fixture(tmp_path)
    path = tmp_path / "oracle.exe"
    path.write_bytes(pe32_import_bytes(prefix.ljust(16, b"\x90") + JUMP))
    oracle = load_flat32_project(path)
    symbols, evidence = match_import_thunk_roots(
        oracle, candidate, {"alias": (ENTRY, ENTRY + len(prefix) - 1)}, {}, ["alias"], link)
    assert symbols["alias"] == Symbol(ENTRY, 6, "T")
    assert evidence[0]["original_route"] == [hex(ENTRY), hex(ENTRY + 16)]
    assert evidence[0]["function_equivalence_proved"] is False


@pytest.mark.parametrize("code", [
    b"\xeb\xfe",  # cyclic alias
    b"\x74\x0e".ljust(16, b"\x90") + JUMP,  # conditional jump
    b"\x40" + JUMP,  # observable INC before the import
    b"\xe8\x0b\x00\x00\x00".ljust(16, b"\x90") + JUMP,  # CALL
])
def test_alias_matching_rejects_cycles_and_effectful_routes(tmp_path: Path, code: bytes) -> None:
    _oracle, candidate, link = fixture(tmp_path)
    path = tmp_path / "oracle.exe"
    path.write_bytes(pe32_import_bytes(code))
    symbols, _evidence = match_import_thunk_roots(
        load_flat32_project(path), candidate, {"alias": (ENTRY, ENTRY + len(code) - 1)},
        {}, ["alias"], link)
    assert "alias" not in symbols
