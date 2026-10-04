"""Public real16 proof-accounting controls over real MZ bytes.

Layer: Tests.
Responsibility: retain conditional layout assumptions, reject ambiguous or
missing mapped counterparts, and distinguish corruption from proof/refusal.
Mappings propose function correspondence; they are not execution CFG edges.
All seven controls run the production lifter, solver and public report boundary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from test_dosunit_tool import _edge_catalog, _edge_function, _mz_exe

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_binary_compare import compare_binary16

MODULE = "demo.exe"

# mov word ptr [0x1000], bx; ret   /   [0x2000] layout-shifted variant   /   cx operand mutation
STORE_BX_1000 = "89 1e 00 10 c3"
STORE_BX_2000 = "89 1e 00 20 c3"
STORE_CX_1000 = "89 0e 00 10 c3"
# mov ax,bx; add ax,1; ret
LEAF = "89 d8 83 c0 01 c3"
# test ax,ax; jz +2 -> 0x206; mov bx,cx; ret   (three lowered parts: 0, 4, 6)
TWO_BLOCK = "85 c0 74 02 89 cb c3"


def _exe(tmp_path: Path, tag: str, code_hex: str, size: int) -> tuple[Path, dict[str, Any]]:
    """Write one MZ image and the catalog declaring its single function."""
    path = tmp_path / f"{tag}.exe"
    path.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(code_hex)))
    return path, _edge_catalog(f"{MODULE}:f", "f", offset=0x0200, size=size)


def _catalog(*functions: dict[str, Any]) -> dict[str, Any]:
    """Build a functions catalog from pre-formed ``_edge_function`` entries."""
    return {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": MODULE,
        "program_kind": "mz_exe",
        "functions": list(functions),
        "diagnostics": [],
    }


def _mapping(*rows: dict[str, Any]) -> dict[str, Any]:
    """Build a dosunit.mapping.v1 document; the compare resolves the last row."""
    return {"schema": "dosunit.mapping.v1", "id": "mapping:test", "functions": list(rows)}


def _mapping_row(oracle: str, candidate: str, ip: int) -> dict[str, Any]:
    """One proposed oracle/candidate correspondence keyed by identity and name."""
    return {
        "oracle_id": f"{MODULE}:{oracle}",
        "oracle_name": oracle,
        "candidate_id": f"{MODULE}:{candidate}",
        "candidate_name": candidate,
        "candidate_entry": {"cs": "0x0000", "ip": f"0x{ip:04x}", "kind": "near"},
    }


def _verdict(report: dict[str, Any], name: str = f"{MODULE}:f") -> dict[str, Any]:
    """Return the typed proof verdict row for the single required function."""
    verdicts = report["proof"]["verdicts"]
    assert len(verdicts) == 1, verdicts
    verdict = verdicts[0]
    assert verdict["id"]["key"] == name
    return verdict


def test_identical_layout_binary_proves(tmp_path: Path) -> None:
    """Positive control: an absolute store operand proves when bytes match."""
    oracle, catalog = _exe(tmp_path, "lo", STORE_BX_1000, 5)
    candidate, _ = _exe(tmp_path, "lc", STORE_BX_1000, 5)
    report = compare_binary16(oracle, candidate, catalog, catalog)
    assert ProofStatus(report["status"]) is ProofStatus.PROVED, report["proof"]
    verdict = _verdict(report)
    assert verdict["status"] == "proved"
    assert verdict["reason"] == "discharged"
    assert verdict["assumptions"] == []
    from tools.dosunit.straightline_ssa import INTERNAL_STATE_REGS

    domain = report["proof_domain"]
    assert domain["architecture"] == "real16"
    assert domain["calling_convention"] == "none_machine_state_projection"
    assert domain["observable"]["registers"] == list(INTERNAL_STATE_REGS)
    assert domain["observable"]["register_source"] == "lowering_contract"
    assert domain["widths"]["operand_bits"] == 16


def test_layout_constant_difference_is_conditional_not_proved(tmp_path: Path) -> None:
    """GAP 2: a passed row normalized by a layout-constant pair is conditional.

    The candidate differs only in an ``absolute_memory_operand`` constant. The
    backend row passes under recorded normalization, so ``_row_assumptions``
    must mark it ``backend_assumptions`` and ``_base_verdict`` must downgrade
    the obligation to CONDITIONAL/UNPROVED_ASSUMPTIONS — a conditional-to-
    proved promotion must not occur.
    """
    oracle, catalog = _exe(tmp_path, "dlo", STORE_BX_1000, 5)
    candidate, candidate_catalog = _exe(tmp_path, "dlc", STORE_BX_2000, 5)
    report = compare_binary16(oracle, candidate, catalog, candidate_catalog)
    assert ProofStatus(report["status"]) is ProofStatus.CONDITIONAL, report["proof"]
    assert report["status"] != "proved"
    verdict = _verdict(report)
    assert verdict["status"] == "conditional"
    assert verdict["reason"] == "unproved_assumptions"
    assert verdict["detail"] == "leaf_block"
    assert verdict["method"] == "ssa_z3_whole_scope"
    assert verdict["assumptions"] == ["backend_assumptions"]
    rows = report["backend"]["results"]
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "passed"
    pairs = row["layout_normalization"]["pairs"]
    assert {"oracle": "0x1000", "candidate": "0x2000", "reason": "absolute_memory_operand"} in pairs


def test_non_layout_mutation_is_counterexample_not_conditional(tmp_path: Path) -> None:
    """Mutation control: a semantic operand change is a real counterexample.

    ``mov [x], bx`` versus ``mov [x], cx`` carries no layout-constant pair, so
    the run must produce a genuine backend failure with no assumption markers —
    the conditional lane is specific to normalization-borne passes, not a
    catch-all for differing binaries.
    """
    oracle, catalog = _exe(tmp_path, "mo", STORE_BX_1000, 5)
    candidate, candidate_catalog = _exe(tmp_path, "mc", STORE_CX_1000, 5)
    report = compare_binary16(oracle, candidate, catalog, candidate_catalog)
    assert ProofStatus(report["status"]) is ProofStatus.COUNTEREXAMPLE
    verdict = _verdict(report)
    assert verdict["status"] == "counterexample"
    assert verdict["reason"] == "backend_verdict"
    assert verdict["detail"] == "observable_mismatch"
    assert verdict["assumptions"] == []


def test_candidate_only_reachable_stays_in_denominator(tmp_path: Path) -> None:
    """GAP 3: mapped-but-unproved candidate parts refuse whole-function proof.

    The candidate contains two separate leaf functions ``g`` and ``h``; the mapping declares
    both as ``f``'s counterparts while the compare resolves the last row (``h``)
    and proves it. ``g``'s lowered part is also proposed by the ambiguous mapping
    but covered by no proof: ``_function_evidence`` must keep the
    obligation ``unknown`` with detail ``candidate_only_reachable``. Retry does
    not rewrite the row — two distinct mapped candidate ids make the
    whole-function retry decline (``function_proofs`` stays empty), which is
    the sound refusal the audit asks to pin.
    """
    oracle = tmp_path / "coro.exe"
    oracle.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(LEAF)))
    candidate = tmp_path / "corc.exe"
    candidate.write_bytes(
        _mz_exe(b"\x00" * 0x200 + bytes.fromhex(LEAF) + b"\x00" * 0x1A + bytes.fromhex(LEAF))
    )
    oracle_catalog = _edge_catalog(f"{MODULE}:f", "f", offset=0x0200, size=6)
    candidate_catalog = _catalog(
        _edge_function(f"{MODULE}:g", "g", offset=0x0200, size=6),
        _edge_function(f"{MODULE}:h", "h", offset=0x0220, size=6),
    )
    mapping = _mapping(_mapping_row("f", "g", 0x0200), _mapping_row("f", "h", 0x0220))
    report = compare_binary16(
        oracle, candidate, oracle_catalog, candidate_catalog, mapping=mapping
    )
    assert ProofStatus(report["status"]) is ProofStatus.UNKNOWN, report["proof"]
    verdict = _verdict(report)
    assert verdict["status"] == "unknown"
    assert verdict["reason"] == "backend_verdict"
    assert verdict["detail"] == "candidate_only_reachable"
    assert verdict["method"] == "ssa_z3_whole_scope"
    gate = report["backend"]["candidate_only_parts"]
    assert gate["enabled"] is True
    assert gate["candidate_parts_total"] == 2
    assert gate["candidate_parts_referenced"] == 1
    assert gate["total"] == 1
    assert {part["function"]["id"] for part in gate["parts"]} == {f"{MODULE}:g"}
    # The reachable-but-unproved part is what refuses; f↔h itself proved.
    rows = report["backend"]["results"]
    assert [row["status"] for row in rows] == ["passed"]
    # Two distinct mapped candidate ids: the whole-function retry chain
    # declined, so no backend retry evidence was substituted for the verdict.
    assert f"{MODULE}:f" not in report["backend"]["function_proofs"]


def test_candidate_only_part_outside_mapping_is_not_counted(tmp_path: Path) -> None:
    """Denominator boundary: unmapped candidate-only code is out of scope.

    Same two-function candidate, but the mapping declares only ``f → h``. The
    unproved ``g`` part is still reported by the backend gate, yet it is not
    proposed by the mapping for the required obligation, so
    candidate-only accounting does not block the proved verdict. This pins
    that the ``candidate_only_reachable`` refusal above is scoped to the required function correspondence. Both functions
    are leaves: this does not excuse an unproved execution successor.
    """
    oracle = tmp_path / "uoo.exe"
    oracle.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(LEAF)))
    candidate = tmp_path / "uoc.exe"
    candidate.write_bytes(
        _mz_exe(b"\x00" * 0x200 + bytes.fromhex(LEAF) + b"\x00" * 0x1A + bytes.fromhex(LEAF))
    )
    oracle_catalog = _edge_catalog(f"{MODULE}:f", "f", offset=0x0200, size=6)
    candidate_catalog = _catalog(
        _edge_function(f"{MODULE}:g", "g", offset=0x0200, size=6),
        _edge_function(f"{MODULE}:h", "h", offset=0x0220, size=6),
    )
    mapping = _mapping(_mapping_row("f", "h", 0x0220))
    report = compare_binary16(
        oracle, candidate, oracle_catalog, candidate_catalog, mapping=mapping
    )
    assert ProofStatus(report["status"]) is ProofStatus.PROVED, report["proof"]
    verdict = _verdict(report)
    assert verdict["status"] == "proved"
    gate = report["backend"]["candidate_only_parts"]
    assert gate["total"] == 1
    assert {part["function"]["id"] for part in gate["parts"]} == {f"{MODULE}:g"}


def test_unresolved_mapped_candidate_refuses_at_region_gate(tmp_path: Path) -> None:
    """Whole-region accounting: a mapped candidate absent from the candidate
    catalog keeps the multi-part obligation unknown through the region gate.

    Oracle ``f`` lowers to three parts (not a leaf), so evidence must come from
    the whole-region equality gate. The mapping declares ``f → g`` but the
    candidate catalog contains only the unrelated ``h``; the region row
    refuses and ``_function_evidence`` surfaces ``region:function_missing``.
    Retry again declines (zero resolved candidate ids), so the refusal detail
    reaches the verdict unmodified.
    """
    oracle = tmp_path / "uro.exe"
    oracle.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(TWO_BLOCK)))
    candidate = tmp_path / "urc.exe"
    candidate.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(LEAF)))
    oracle_catalog = _edge_catalog(f"{MODULE}:f", "f", offset=0x0200, size=7)
    candidate_catalog = _catalog(_edge_function(f"{MODULE}:h", "h", offset=0x0200, size=6))
    mapping = _mapping(_mapping_row("f", "g", 0x0200))
    report = compare_binary16(
        oracle, candidate, oracle_catalog, candidate_catalog, mapping=mapping
    )
    assert ProofStatus(report["status"]) is ProofStatus.UNKNOWN, report["proof"]
    verdict = _verdict(report)
    assert verdict["status"] == "unknown"
    assert verdict["reason"] == "backend_verdict"
    assert verdict["detail"] == "region:function_missing"
    assert verdict["method"] == "ssa_z3_whole_scope"
    region = report["backend"]["region_equality"]
    assert region["total"] == 1
    assert region["results"][0]["status"] == "refused"
    assert f"{MODULE}:f" not in report["backend"]["function_proofs"]


def test_unresolved_mapped_candidate_leaf_is_scope_incomplete(tmp_path: Path) -> None:
    """Leaf-scope accounting: a leaf whose mapped counterpart never lowered
    cannot pass through part-level evidence either.

    Same unresolved ``f → g`` correspondence as the region case, but the oracle is a
    complete single-block leaf. The backend emits a ``candidate_ssa_missing``
    refusal row with no candidate part, so ``_function_evidence`` pins
    ``candidate_leaf_scope_incomplete`` — the leaf-scope counterpart of the
    candidate-only/whole-region denominator accounting.
    """
    oracle = tmp_path / "uso.exe"
    oracle.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(LEAF)))
    candidate = tmp_path / "usc.exe"
    candidate.write_bytes(_mz_exe(b"\x00" * 0x200 + bytes.fromhex(LEAF)))
    oracle_catalog = _edge_catalog(f"{MODULE}:f", "f", offset=0x0200, size=6)
    candidate_catalog = _catalog(_edge_function(f"{MODULE}:h", "h", offset=0x0200, size=6))
    mapping = _mapping(_mapping_row("f", "g", 0x0200))
    report = compare_binary16(
        oracle, candidate, oracle_catalog, candidate_catalog, mapping=mapping
    )
    assert ProofStatus(report["status"]) is ProofStatus.UNKNOWN, report["proof"]
    verdict = _verdict(report)
    assert verdict["status"] == "unknown"
    assert verdict["reason"] == "backend_verdict"
    assert verdict["detail"] == "candidate_leaf_scope_incomplete"
    rows = report["backend"]["results"]
    assert [row["status"] for row in rows] == ["refused"]
    assert rows[0]["reason"] == "candidate_ssa_missing"
    assert rows[0]["candidate_function"] is None
