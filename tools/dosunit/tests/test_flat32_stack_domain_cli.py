"""CLI wiring regression for the caller-declared flat32 entry-ESP domain.

Layer: tests.
Responsibility: prove both staged PE32 drivers expose ``--entry-esp-range``
with identical validation, that the declared premise reaches checked call
composition as an honest ``conditional`` verdict with serialized assumptions,
that environment admission still gates conditional publication, and that the
sealed contract identity binds the exact interval.  Real i386 bytes are lifted
through angr/PyVEX and proved with real Z3; no fabricated proof success.
"""

from __future__ import annotations

import sys
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.test_flat32_comparator_lane import DRIVER_DIRS, DriverLane, _driver_lane
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

from tools.dosunit.contracts.binary_environment import EnvironmentScan
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.reporting.flat32_proof_domain_cli import (
    entry_domain_from_args,
    parse_entry_esp_range,
    require_pe32_pair,
)
from tools.dosunit.compare.flat32_proof_retry import checked_environment_verdict, retry_function_proof

STACK_LO = 0x0007F000
STACK_HI = 0x00080000
DOMAIN = Flat32ProofDomain(STACK_LO, STACK_HI)
TEXT_BASE = 0x401000

# caller f at TEXT_BASE: mov eax,[esp+4]; call callee(+4); add eax,2; ret (13 bytes)
# callee at TEXT_BASE+0x0d: mov dword [0x5000],0x2a; ret  (11 bytes) — the
# concrete global store sits below the declared stack window, so the return
# proof is conditional on the caller-declared premise.
CALLER = "8b442404 e804000000 83c002 c3"
STORE_CALLEE = "c70500500000" + "2a000000" + " c3"
STORE_CODE = f"{CALLER} {STORE_CALLEE}"
# callee corrupting its own return slot: mov dword [esp],0x2a; ret (8 bytes)
SLOT_CALLEE = "c70424" + "2a000000" + " c3"
SLOT_CODE = f"{CALLER} {SLOT_CALLEE}"

STORE_BOUNDARIES = {"f": (TEXT_BASE, TEXT_BASE + 0x0C), "callee": (TEXT_BASE + 0x0D, TEXT_BASE + 0x17)}
SLOT_BOUNDARIES = {"f": (TEXT_BASE, TEXT_BASE + 0x0C), "callee": (TEXT_BASE + 0x0D, TEXT_BASE + 0x14)}


def _symbols(lane: DriverLane, callee_size: int) -> dict[str, Any]:
    """Symbol table for the caller/callee fixture at the PE .text base."""
    return {
        "f": lane.catalog.Symbol(TEXT_BASE, 0x0D, "T"),
        "callee": lane.catalog.Symbol(TEXT_BASE + 0x0D, callee_size, "T"),
    }


def _write_pair(tmp_path: Path, code: str) -> tuple[Path, Path]:
    """Write identical real PE32 images for the oracle and candidate."""
    raw = bytes.fromhex(code.replace(" ", ""))
    oracle, candidate = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    oracle.write_bytes(pe32_bytes(raw))
    candidate.write_bytes(pe32_bytes(raw))
    return oracle, candidate


def _install_fixture(
    lane: DriverLane,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    code: str,
    boundaries: dict[str, tuple[int, int]],
) -> tuple[Path, Path]:
    """Bind the fixture image to the driver's symbol/boundary sources."""
    oracle, candidate = _write_pair(tmp_path, code)
    driver = lane.z3cmp32
    if lane.name == "msc8":
        monkeypatch.setattr(driver, "lst_functions", lambda _path: dict(boundaries))
        monkeypatch.setattr(driver, "nm_symbols", lambda _path: _symbols(lane, boundaries["callee"][1] - boundaries["callee"][0] + 1))
    else:
        monkeypatch.setattr(
            driver, "load32_verified", lambda path, _cache: lane.adapter.load32(path)
        )
        monkeypatch.setattr(driver, "cached_lst_functions", lambda _path, _cache: dict(boundaries))
        monkeypatch.setattr(
            driver, "nm_symbols",
            lambda _path: _symbols(lane, boundaries["callee"][1] - boundaries["callee"][0] + 1),
        )
    return oracle, candidate


def _driver_args(
    lane: DriverLane, tmp_path: Path, oracle: Path, candidate: Path, domain: Flat32ProofDomain | None
) -> Namespace:
    """Build the driver namespace; absent ``domain`` leaves the field unset."""
    args = Namespace(
        oracle_exe=oracle,
        oracle_lst=tmp_path / "oracle.lst",
        candidate_exe=candidate,
        candidate_lst=None,
        functions="f",
        mode="region",
        normalize_globals=False,
        output_regs="eax,edx,esp",
        scan_limit=0x2000,
        timeout_ms=30000,
        out_dir=tmp_path / "out",
    )
    if lane.name == "bc5":
        args.candidate_syms = None
        args.cache_dir = tmp_path / "cache"
        args.region_max_blocks = 128
        args.assume_paired_calls = False
    if domain is not None:
        args.entry_esp_range = domain
    args.out_dir.mkdir(exist_ok=True)
    return args


def _run_region_compare(
    lane: DriverLane, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    code: str, boundaries: dict[str, tuple[int, int]], domain: Flat32ProofDomain | None,
) -> dict[str, Any]:
    """Drive the real sealed comparison for one fixture pair."""
    oracle, candidate = _install_fixture(lane, monkeypatch, tmp_path, code, boundaries)
    args = _driver_args(lane, tmp_path, oracle, candidate, domain)
    with lane.adapter.installed(region=True):
        return lane.z3cmp32.compare(args)


def _argv(driver: str, tmp_path: Path, *extra: str) -> list[str]:
    """CLI argv covering the shared required arguments of both drivers."""
    argv = [
        "z3cmp32.py",
        "--oracle-exe", str(tmp_path / "oracle.exe"),
        "--oracle-lst", str(tmp_path / "oracle.lst"),
        "--candidate-exe", str(tmp_path / "candidate.exe"),
        "--functions", "f",
        "--out-dir", str(tmp_path / "out"),
    ]
    if driver == "bc5":
        argv += ["--cache-dir", str(tmp_path / "cache")]
    return argv + list(extra)


def _capture_compare(
    monkeypatch: pytest.MonkeyPatch, driver: Any, argv: list[str]
) -> dict[str, Namespace]:
    """Run main() with a stubbed compare and return the parsed namespace."""
    captured: dict[str, Namespace] = {}
    monkeypatch.setattr(sys, "argv", argv)

    def stub(args: Namespace) -> dict[str, Any]:
        captured["args"] = args
        return {"summary": {"total": 0}, "results": []}

    monkeypatch.setattr(driver, "compare", stub)
    driver.main()
    return captured


def test_parse_accepts_base0_bounds() -> None:
    """Decimal and hex base-0 bounds parse into the validated domain."""
    assert parse_entry_esp_range("4096:8192") == Flat32ProofDomain(4096, 8192)
    assert parse_entry_esp_range("0x7f000:0x80000") == DOMAIN
    assert parse_entry_esp_range("0:0xffffffff") == Flat32ProofDomain(0, 0xFFFFFFFF)


@pytest.mark.parametrize(
    "value",
    ["", "4096", "1:2:3", "x:y", "0x80000:0x7f000", "-1:5", "0:0x100000000", "1.5:2"],
    ids=["empty", "single", "extra", "non_integer", "empty_interval", "negative", "over_uint32", "float"],
)
def test_parse_rejects_malformed_bounds(value: str) -> None:
    """Wrong shapes, non-integers, empty and out-of-uint32 intervals refuse."""
    with pytest.raises(ValueError):
        parse_entry_esp_range(value)


def test_namespace_boundary_supports_old_callers() -> None:
    """Namespaces without the field parse to no premise; strings still validate."""
    assert entry_domain_from_args(Namespace()) is None
    assert entry_domain_from_args(Namespace(entry_esp_range=None)) is None
    assert entry_domain_from_args(Namespace(entry_esp_range="0x7f000:0x80000")) == DOMAIN
    assert entry_domain_from_args(Namespace(entry_esp_range=DOMAIN)) is DOMAIN
    with pytest.raises(ValueError):
        entry_domain_from_args(Namespace(entry_esp_range=0x1234))


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_cli_accepts_valid_range(driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both drivers register --entry-esp-range and parse it into the domain."""
    with _driver_lane(driver) as lane:
        captured = _capture_compare(
            monkeypatch, lane.z3cmp32,
            _argv(driver, tmp_path, "--mode", "region", "--entry-esp-range", "0x7f000:0x80000"),
        )
    assert captured["args"].entry_esp_range == DOMAIN


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_cli_rejects_malformed_range(driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A malformed interval is an argument error, never a guessed premise."""
    with _driver_lane(driver) as lane:
        monkeypatch.setattr(lane.z3cmp32, "compare", lambda _args: None)
        monkeypatch.setattr(
            sys, "argv",
            _argv(driver, tmp_path, "--mode", "region", "--entry-esp-range", "0x8000:0x7000"),
        )
        with pytest.raises(SystemExit) as raised:
            lane.z3cmp32.main()
        assert raised.value.code == 2


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_cli_rejects_leaf_mode(driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Leaf mode has no composition path; the premise is rejected not ignored."""
    with _driver_lane(driver) as lane:
        monkeypatch.setattr(lane.z3cmp32, "compare", lambda _args: None)
        monkeypatch.setattr(
            sys, "argv",
            _argv(driver, tmp_path, "--mode", "leaf", "--entry-esp-range", "0x7f000:0x80000"),
        )
        with pytest.raises(SystemExit) as raised:
            lane.z3cmp32.main()
        assert raised.value.code == 2


def test_require_pe32_pair_accepts_pe_and_rejects_other(tmp_path: Path) -> None:
    """The declared-domain feature is PE32-to-PE32 only at the file boundary."""
    pe = tmp_path / "pe.exe"
    pe.write_bytes(pe32_bytes(b"\xc3"))
    not_pe = tmp_path / "elf.bin"
    not_pe.write_bytes(b"\x7fELF" + bytes(60))
    require_pe32_pair(pe, pe)
    with pytest.raises(ValueError):
        require_pe32_pair(pe, not_pe)


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_declared_domain_rejects_non_pe_inputs(
    driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A declared domain plus a non-PE input fails closed inside the driver."""
    not_pe = tmp_path / "candidate.bin"
    not_pe.write_bytes(b"\x7fELF" + bytes(60))
    with _driver_lane(driver) as lane:
        oracle, _candidate = _install_fixture(
            lane, monkeypatch, tmp_path, STORE_CODE, STORE_BOUNDARIES
        )
        args = _driver_args(lane, tmp_path, oracle, not_pe, DOMAIN)
        with pytest.raises(ValueError, match="requires PE32"):
            lane.z3cmp32._compare(args)


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_store_call_becomes_conditional_through_shared_retry(
    driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A global-store callee proves only conditional under the declared premise."""
    with _driver_lane(driver) as lane:
        report = _run_region_compare(
            lane, monkeypatch, tmp_path, STORE_CODE, STORE_BOUNDARIES, DOMAIN
        )
    row = report["results"][0]
    assert row["status"] == "conditional", row
    assert row["reason"] == "unproved_entry_esp_domain"
    assert row["proof_method"] == "checked_direct_call_composition"
    assert row["oracle_inlined_calls"] == 1 and row["candidate_inlined_calls"] == 1
    assumptions = row["assumptions"]
    assert assumptions["kind"] == "caller_supplied_entry_esp_domain"
    assert assumptions["proved"] is False
    assert assumptions["interval"] == {"min": hex(STACK_LO), "max": hex(STACK_HI)}
    assert row["entry_domain_assumptions"] == assumptions
    assert row["input_constraints"] == [
        {"name": "esp", "kind": "unsigned_range", "min": STACK_LO, "max": STACK_HI}
    ]
    # The premise survives the public projection: the typed verdict stays
    # conditional and carries the backend-assumption marker.
    verdict = report["proof_evidence"]["verdicts"][0]
    assert verdict["status"] == "conditional"
    assert verdict["reason"] == "unproved_assumptions"
    assert verdict["assumptions"] == ["backend_assumptions"]
    assert report["input_domain"]["entry_esp_premise"]["interval"] == {
        "min": hex(STACK_LO), "max": hex(STACK_HI)
    }
    assert report["proof_contract"]["entry_esp_premise"]["interval"] == {
        "min": hex(STACK_LO), "max": hex(STACK_HI)
    }
    assert report["summary"]["conditional"] == 1


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_store_call_without_option_keeps_baseline_refusal(
    driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no declared domain the same fixture stays refused, as before."""
    with _driver_lane(driver) as lane:
        report = _run_region_compare(
            lane, monkeypatch, tmp_path, STORE_CODE, STORE_BOUNDARIES, None
        )
    row = report["results"][0]
    assert row["status"] == "refused", row
    assert row["reason"] != "unproved_entry_esp_domain"
    assert "entry_domain_assumptions" not in row
    assert "entry_esp_premise" not in report["input_domain"]
    assert report["summary"]["conditional"] == 0


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_return_slot_overwrite_still_refuses(
    driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A callee corrupting its own return slot refuses even under the premise."""
    with _driver_lane(driver) as lane:
        report = _run_region_compare(
            lane, monkeypatch, tmp_path, SLOT_CODE, SLOT_BOUNDARIES, DOMAIN
        )
    row = report["results"][0]
    assert row["status"] == "refused", row
    # The refused composition retains the declared-premise provenance.
    calls = (row.get("additional_proof_attempts") or {}).get("calls")
    assert isinstance(calls, dict), row
    assert calls["entry_domain_assumptions"]["interval"] == {
        "min": hex(STACK_LO), "max": hex(STACK_HI)
    }


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_incomplete_environment_blocks_conditional(
    driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing environment coverage refuses a call-dependent conditional."""
    def incomplete_scan(*_args: object, io_model: object = None) -> EnvironmentScan:
        """Keep the missing-coverage fixture explicit about the absent I/O model."""
        assert io_model is None
        return EnvironmentScan(False, False, 0)

    monkeypatch.setattr(
        "tools.dosunit.contracts.binary_environment.scan_lowered_parts", incomplete_scan,
    )
    with _driver_lane(driver) as lane:
        report = _run_region_compare(
            lane, monkeypatch, tmp_path, STORE_CODE, STORE_BOUNDARIES, DOMAIN
        )
    row = report["results"][0]
    assert row["status"] == "refused", row
    assert row["reason"] == "environment_effect_coverage_incomplete"


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_conditional_without_retained_assumptions_is_not_admitted(
    driver: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bare conditional composition result cannot replace a refusal."""
    import angr

    monkeypatch.setattr(
        "tools.dosunit.compare.flat32_call_composition.compare_functions_with_calls",
        lambda *_args, **_kwargs: {"status": "conditional", "oracle_inlined_calls": 1},
    )
    monkeypatch.setattr(
        "tools.dosunit.compare.flat32_cfg_regions.compare_reblocked_cfg",
        lambda *_args, **_kwargs: {"status": "refused", "reason": "stub"},
    )
    monkeypatch.setattr(
        "tools.dosunit.compare.flat32_macro_proof.compare_macro_cfg",
        lambda *_args, **_kwargs: {"status": "refused", "reason": "stub"},
    )
    with _driver_lane(driver) as lane:
        project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x1000)
        context = (project, project, {"f": (0x1000, 1)}, {"f": (0x1000, 1)})
        original = {"status": "refused", "reason": "call_or_exception_boundary"}
        result = retry_function_proof(
            "f", original, context, lane.adapter.OUTPUT_REGS, 1000,
            entry_domain=DOMAIN,
        )
        assert result["status"] == "refused", result
        assert "proof_method" not in result


def test_conditional_environment_gate_requires_inlined_calls() -> None:
    """A conditional verdict without composition evidence is not gated.

    This pins the pre-existing behavior for non-composition conditional
    verdicts while the new call-dependent conditional is gated.
    """
    import angr

    project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x1000)
    context = (project, project, {"f": (0x1000, 1)}, {"f": (0x1000, 1)})
    verdict = {"status": "conditional", "reason": "relocation_assumptions",
               "assumptions": {"constant_relocation_count": 1}}
    assert checked_environment_verdict(verdict, context, [], []) is verdict


def test_differing_interval_changes_sealed_contract_identity(tmp_path: Path) -> None:
    """Otherwise-identical runs under different intervals cannot share identity."""
    from tools.dosunit.reporting.flat32_proof_report import run_bound_comparison

    oracle, candidate = _write_pair(tmp_path, "c3")

    def stub(_args: Namespace) -> dict[str, Any]:
        return {
            "requested_functions": ["f"],
            "results": [{"function": {"name": "f"}, "status": "refused", "reason": "x"}],
            "summary": {"total": 1, "passed": 0, "failed": 0, "refused": 1, "conditional": 0},
            "function_ranges": {"oracle": {}, "candidate": {}},
            "loaded_images": {},
        }

    def run(domain: Flat32ProofDomain | None, out_dir: Path) -> dict[str, Any]:
        out_dir.mkdir()
        args = Namespace(
            oracle_exe=oracle, candidate_exe=candidate, mode="region",
            output_regs="eax,esp", out_dir=out_dir,
        )
        if domain is not None:
            args.entry_esp_range = domain
        return run_bound_comparison(stub, args, DRIVER_DIRS["msc8"] / "z3cmp32.py")

    first = run(Flat32ProofDomain(STACK_LO, STACK_HI), tmp_path / "a")
    second = run(Flat32ProofDomain(STACK_LO, STACK_HI + 0x1000), tmp_path / "b")
    undeclared = run(None, tmp_path / "c")
    contracts = [
        report["proof_evidence"]["contract"] for report in (first, second, undeclared)
    ]
    assert len({contract["model_hash"] for contract in contracts}) == 3
    assert len({contract["key"] for contract in contracts}) == 3
    assert first["input_domain"]["entry_esp_premise"]["interval"] == {
        "min": hex(STACK_LO), "max": hex(STACK_HI)
    }
    assert second["input_domain"]["entry_esp_premise"]["interval"] == {
        "min": hex(STACK_LO), "max": hex(STACK_HI + 0x1000)
    }
    assert "entry_esp_premise" not in undeclared["input_domain"]


@pytest.mark.parametrize("kind", ["dos", "pe64", "foreign_machine", "truncated"])
def test_require_pe32_pair_rejects_mz_without_i386_pe32(tmp_path: Path, kind: str) -> None:
    """A DOS signature alone never establishes the flat32 proof architecture."""
    valid = tmp_path / "valid.exe"
    valid.write_bytes(pe32_bytes(b"\xc3"))
    blob = bytearray(valid.read_bytes())
    pe_offset = int.from_bytes(blob[0x3c:0x40], "little")
    if kind == "dos":
        blob[pe_offset:pe_offset + 4] = b"DOS!"
    elif kind == "pe64":
        blob[pe_offset + 24:pe_offset + 26] = (0x20b).to_bytes(2, "little")
    elif kind == "foreign_machine":
        blob[pe_offset + 4:pe_offset + 6] = (0x8664).to_bytes(2, "little")
    else:
        del blob[pe_offset + 25:]
    invalid = tmp_path / "invalid.exe"
    invalid.write_bytes(blob)
    with pytest.raises(ValueError, match="requires PE32"):
        require_pe32_pair(valid, invalid)
