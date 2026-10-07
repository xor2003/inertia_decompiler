"""Whole-function accounting tests for the real16 binary proof wrapper.

Layer: Tests.
Responsibility: prove the public compare-binary16 boundary only reports
``proved`` when a complete leaf block or a closed whole-region backend proof
exists, and that missing selections, changed tails, and empty obligation
sets fail closed. Uses real MZ bytes, real VEX lifting and the Z3 backend.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_catalog, _mz_exe

import tools.dosunit.reporting.ssa_provenance as ssa_provenance
from tools.dosunit.compare.real16_binary_compare import add_binary16_parser, cmd_compare_binary16, compare_binary16

MODULE = "demo.exe"

# test ax,ax; jz +2 -> 0x206; mov bx,cx; ret            (parts at 0, 4, 6)
TWO_BLOCK = "85 c0 74 02 89 cb c3"
# Same shape, but the tail is a far return: entry block is byte-identical.
TAIL_CHANGED = "85 c0 74 02 89 cb cb"
# test ax,ax; jz +3 -> 0x207; dec ax; jmp 0; ret        (back-edge loop)
LOOP = "85 c0 74 03 48 eb f9 c3"
# mov ax,bx; add ax,1; ret   /   add ax,2 variant
LEAF = "89 d8 83 c0 01 c3"
LEAF_CHANGED = "89 d8 83 c0 02 c3"


def _exe(tmp_path: Path, tag: str, code_hex: str, size: int) -> tuple[Path, dict[str, Any]]:
    """Write one MZ image and the catalog that declares its single function."""
    path = tmp_path / f"{tag}.exe"
    path.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(code_hex)))
    return path, _edge_catalog(f"{MODULE}:f", "f", offset=0x0200, size=size)


def _run(
    tmp_path: Path,
    tag: str,
    oracle_hex: str,
    candidate_hex: str,
    size: int,
    *,
    selected: tuple[str, ...] = (),
) -> dict[str, Any]:
    oracle_exe, oracle_catalog = _exe(tmp_path, f"{tag}o", oracle_hex, size)
    candidate_exe, candidate_catalog = _exe(tmp_path, f"{tag}c", candidate_hex, size)
    return _compare(oracle_exe, candidate_exe, oracle_catalog, candidate_catalog, selected=selected)


def _compare(
    oracle_exe: Path,
    candidate_exe: Path,
    oracle_catalog: dict[str, Any],
    candidate_catalog: dict[str, Any],
    *,
    selected: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Run the binary comparison with provenance-seal failure propagation.

    Invalidated binary or semantic-source evidence must fail with its original
    exception. The ownership suite must not record changed evidence as success
    or skip.
    """
    return compare_binary16(oracle_exe, candidate_exe, oracle_catalog, candidate_catalog, selected=selected)


def _verdict(report: dict[str, Any], name: str = f"{MODULE}:f") -> dict[str, Any]:
    """Return the typed proof verdict row for one required function."""
    verdicts = report["proof"]["verdicts"]
    assert len(verdicts) == 1, verdicts
    verdict = verdicts[0]
    assert verdict["id"]["key"] == name
    return verdict


def test_same_binary_leaf_proves(tmp_path: Path) -> None:
    """A complete single-block return body consumes the whole leaf proof."""
    report = _run(tmp_path, "leaf", LEAF, LEAF, 6)
    assert report["status"] == "proved", report["proof"]
    verdict = _verdict(report)
    assert verdict["status"] == "proved"
    assert verdict["reason"] == "discharged"


def test_changed_leaf_is_counterexample(tmp_path: Path) -> None:
    """A one-byte immediate change inside the leaf is a modeled counterexample."""
    report = _run(tmp_path, "leafd", LEAF, LEAF_CHANGED, 6)
    assert report["status"] == "counterexample"
    assert _verdict(report)["status"] == "counterexample"


def test_unused_port_read_requires_environment_contract(tmp_path: Path) -> None:
    """Even identical code cannot prove an undeclared device event harmless."""
    report = _run(tmp_path, "port", "ec 31 c0 c3", "ec 31 c0 c3", 4)
    assert report["status"] != "proved", report
    assert "environment" in _verdict(report)["detail"], report


def test_word_immediate_uses_instruction_mode_not_vex_storage_width(tmp_path: Path) -> None:
    """The real16 storage adapter must decode MOV AX,imm16 as four complete bytes."""
    report = _run(tmp_path, "word_immediate", "b83412c3", "b83412c3", 4)
    assert report["status"] == "proved", report["proof"]["verdicts"]


@pytest.mark.parametrize("code", ["e440c3", "e540c3", "e640c3", "e740c3", "66e540c3", "66e740c3"])
def test_constant_folded_port_event_requires_environment_contract(tmp_path: Path, code: str) -> None:
    """Immediate port events survive admission even when lifting substitutes constants."""
    report = _run(tmp_path, "immediate_port", code, code, len(bytes.fromhex(code)))
    assert report["status"] == "unknown", report["proof"]["verdicts"]
    assert _verdict(report)["detail"] == "external_environment_contract_required"


def test_multi_block_same_binary_proves_whole_region(tmp_path: Path) -> None:
    """Passed parts alone cannot prove; the closed whole-region result must."""
    report = _run(tmp_path, "twob", TWO_BLOCK, TWO_BLOCK, 8)
    verdict = _verdict(report)
    assert report["status"] == "proved", report["proof"]
    assert verdict["status"] == "proved"
    assert verdict["reason"] == "discharged"
    assert verdict["detail"].startswith("region:")


def test_matched_loop_proves_when_region_supports(tmp_path: Path) -> None:
    """An identical real-byte back-edge loop proves under the region gate."""
    report = _run(tmp_path, "loop", LOOP, LOOP, 8)
    verdict = _verdict(report)
    assert report["status"] == "proved", report["proof"]
    assert verdict["status"] == "proved"
    assert verdict["detail"].startswith("region:")


def test_entry_same_tail_changed_cannot_pass(tmp_path: Path) -> None:
    """Identical entry block with a changed tail never yields a whole pass."""
    report = _run(tmp_path, "tail", TWO_BLOCK, TAIL_CHANGED, 8)
    verdict = _verdict(report)
    assert report["status"] != "proved"
    assert verdict["status"] in {"unknown", "counterexample"}


def test_missing_selection_stays_in_denominator(tmp_path: Path) -> None:
    """A requested function absent from the oracle catalog is UNKNOWN."""
    oracle_exe = tmp_path / "o.exe"
    oracle_exe.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(LEAF)))
    candidate_exe = tmp_path / "c.exe"
    candidate_exe.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(LEAF)))
    catalog = _edge_catalog(f"{MODULE}:f", "f", offset=0x0200, size=6)
    report = _compare(oracle_exe, candidate_exe, catalog, catalog, selected=("ghost", f"{MODULE}:f"))
    verdicts = report["proof"]["verdicts"]
    assert report["status"] == "unknown"
    ghost = next(row for row in verdicts if row["id"]["key"] == "ghost")
    assert ghost["status"] == "unknown"
    assert ghost["reason"] == "missing_evidence"


def test_empty_obligation_set_refuses(tmp_path: Path) -> None:
    """No required obligations is a report-level refusal, never a pass."""
    empty_catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:empty",
        "module": MODULE,
        "functions": [],
        "diagnostics": [],
    }
    report = _run_empty(tmp_path, empty_catalog)
    assert report["status"] == "unknown"
    assert report["proof"]["problem"] == "empty_obligations"


def _run_empty(tmp_path: Path, catalog: dict[str, Any]) -> dict[str, Any]:
    exe = tmp_path / "e.exe"
    exe.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(LEAF)))
    return _compare(exe, exe, catalog, catalog)


def test_cli_parser_and_report_file(tmp_path: Path) -> None:
    """The public parser attaches and cmd_compare_binary16 writes the report."""
    parser = argparse.ArgumentParser(prog="dosunit")
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_binary16_parser(subparsers)
    oracle_exe, oracle_catalog = _exe(tmp_path, "co", LEAF, 6)
    candidate_exe, candidate_catalog = _exe(tmp_path, "cc", LEAF, 6)
    oracle_functions = tmp_path / "of.json"
    oracle_functions.write_text(json.dumps(oracle_catalog))
    candidate_functions = tmp_path / "cf.json"
    candidate_functions.write_text(json.dumps(candidate_catalog))
    out = tmp_path / "report.json"
    args = parser.parse_args(
        [
            "compare-binary16",
            "--oracle-exe",
            str(oracle_exe),
            "--candidate-exe",
            str(candidate_exe),
            "--oracle-functions",
            str(oracle_functions),
            "--candidate-functions",
            str(candidate_functions),
            "--out",
            str(out),
        ]
    )
    assert args.func is cmd_compare_binary16
    result = cmd_compare_binary16(args)
    assert result == 0
    report = json.loads(out.read_text())
    assert report["schema"] == "dosunit.binary16_compare.v1"
    assert report["status"] == "proved"
    assert report["proof"]["contract"]["architecture"] == "real16"


_SEAL_MESSAGE = "binary or semantic sources changed during SSA lowering"


def _catch(boundary: Callable[..., object], *args: object) -> BaseException | None:
    """Expose an expected error or forbidden skip for exact identity assertions."""
    try:
        boundary(*args)
    except (RuntimeError, pytest.skip.Exception) as error:
        return error
    return None


def _move_semantic_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate one concurrent semantic-source edit across a seal check."""
    hashes = iter(("stable-hash", "moved-hash"))
    monkeypatch.setattr(ssa_provenance, "_semantic_hash", lambda: next(hashes, "moved-hash"))


def test_compare_helper_propagates_injected_runtime_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provenance-seal RuntimeError crosses ``_compare`` by object identity."""
    injected = RuntimeError(_SEAL_MESSAGE)

    def _raise(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise injected

    monkeypatch.setattr(sys.modules[__name__], "compare_binary16", _raise)
    assert _catch(_compare, tmp_path / "o.exe", tmp_path / "c.exe", {}, {}) is injected


def test_compare_helper_propagates_despite_moved_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A moved semantic fingerprint must never turn the failure into a skip."""
    injected = RuntimeError(_SEAL_MESSAGE)

    def _raise(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise injected

    monkeypatch.setattr(sys.modules[__name__], "compare_binary16", _raise)
    _move_semantic_hash(monkeypatch)
    assert _catch(_compare, tmp_path / "o.exe", tmp_path / "c.exe", {}, {}) is injected


def test_cli_boundary_propagates_injected_runtime_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CLI compare boundary propagates the injected seal error object."""
    injected = RuntimeError(_SEAL_MESSAGE)

    def _raise(_args: argparse.Namespace) -> int:
        raise injected

    monkeypatch.setattr(sys.modules[__name__], "cmd_compare_binary16", _raise)
    monkeypatch.setattr(
        "tools.dosunit.compare.real16_binary_compare.cmd_compare_binary16", _raise
    )
    assert _catch(test_cli_parser_and_report_file, tmp_path) is injected


def test_cli_boundary_propagates_despite_moved_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under a moved fingerprint the CLI boundary still fails loudly."""
    injected = RuntimeError(_SEAL_MESSAGE)

    def _raise(_args: argparse.Namespace) -> int:
        raise injected

    monkeypatch.setattr(sys.modules[__name__], "cmd_compare_binary16", _raise)
    monkeypatch.setattr(
        "tools.dosunit.compare.real16_binary_compare.cmd_compare_binary16", _raise
    )
    _move_semantic_hash(monkeypatch)
    assert _catch(test_cli_parser_and_report_file, tmp_path) is injected
