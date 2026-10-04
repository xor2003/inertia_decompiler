"""Verify public proof-domain publication, identity binding and strict declarations.

Layer: tests.
Responsibility: exercise the production report boundary without changing verdicts.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tools.dosunit.flat32_proof_report import run_bound_comparison

DRIVER = Path(__file__).resolve().parents[2] / "artifacts" / "msc8-z3cmp32" / "z3cmp32.py"


def _write_inputs(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    oracle = tmp_path / "oracle.exe"
    candidate = tmp_path / "candidate.exe"
    oracle.write_bytes(b"MZ-oracle")
    candidate.write_bytes(b"MZ-candidate")
    return oracle, candidate


def _stub(proof_contract: dict[str, Any] | None = None) -> Callable[[Namespace], dict[str, Any]]:
    def comparison(_args: Namespace) -> dict[str, Any]:
        raw: dict[str, Any] = {
            "requested_functions": ["f"],
            "results": [{"function": {"name": "f"}, "status": "refused", "reason": "x"}],
            "summary": {"total": 1, "passed": 0, "failed": 0, "refused": 1, "conditional": 0},
            "function_ranges": {"oracle": {}, "candidate": {}},
            "loaded_images": {},
        }
        if proof_contract is not None:
            raw["proof_contract"] = proof_contract
        return raw

    return comparison


def _run(tmp_path: Path, proof_contract: dict[str, Any] | None = None, *, outputs: str = "eax,esp") -> dict[str, Any]:
    oracle, candidate = _write_inputs(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    args = Namespace(
        oracle_exe=oracle, candidate_exe=candidate, mode="region",
        output_regs=outputs, out_dir=out_dir,
    )
    return run_bound_comparison(_stub(proof_contract), args, DRIVER)


def test_report_publishes_typed_proof_domain(tmp_path: Path) -> None:
    """The sealed report carries all six M1 identifications."""
    report = _run(tmp_path / "a", {"outputs": ("eax", "esp")})
    domain = report["proof_domain"]
    assert domain["schema"] == "dosunit.proof_domain.v1"
    assert domain["architecture"] == "flat32"
    assert domain["widths"] == {
        "operand_bits": 32, "storage_bits": 32, "address_model": "flat",
        "operand_override_bits": [],
    }
    assert domain["calling_convention"] == "none_machine_state_projection"
    assert domain["return_kind"] == "machine_state_projection"
    assert domain["observable"]["registers"] == ["eax", "esp"]
    assert domain["observable"]["register_source"] == "backend_declared"
    admissions = {item["kind"]: item["admission"] for item in domain["outcomes"]}
    assert admissions == {
        "normal_return": "compared",
        "nonreturning": "not_established",
        "fault": "refused",
        "external_effect": "refused",
    }


def test_omitted_backend_declaration_is_caller_sourced(tmp_path: Path) -> None:
    """A backend without an output field must not be reported as its source."""
    report = _run(tmp_path / "a")
    observable = report["proof_domain"]["observable"]
    assert observable["registers"] == ["eax", "esp"]
    assert observable["register_source"] == "caller_declared"


def test_domain_binds_into_contract_identity(tmp_path: Path) -> None:
    """Different declared observable domains must not share contract identity."""
    wide = _run(tmp_path / "a", {"outputs": ("eax", "esp")})
    narrow = _run(tmp_path / "b", {"outputs": ("eax",)})
    assert wide["proof_evidence"]["contract"]["abi_hash"] != narrow["proof_evidence"]["contract"]["abi_hash"]
    assert wide["proof_evidence"]["contract"]["key"] != narrow["proof_evidence"]["contract"]["key"]


def test_domain_asserts_no_invented_convention(tmp_path: Path) -> None:
    """No source-level convention name leaks into the contract."""
    report = _run(tmp_path / "a")
    serialized = str(report["proof_domain"]).lower()
    for invented in ("cdecl", "stdcall", "pascal", "fastcall"):
        assert invented not in serialized


@pytest.mark.parametrize(
    "contract",
    [
        {"outputs": []},
        {"outputs": "eax,esp"},
        {"outputs": [1]},
        {"outputs": ("eax",), "output_regs": ("eax", "ecx")},
        {"output_regs": None},
        "not-a-mapping",
    ],
)
def test_malformed_backend_output_declaration_refuses(tmp_path: Path, contract: object) -> None:
    """A supplied-but-malformed backend declaration refuses; it never falls back."""
    with pytest.raises(ValueError):
        _run(tmp_path / "a", contract)
