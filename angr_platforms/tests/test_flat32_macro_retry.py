"""Automatic flat32 retries admit only complete unequal-step proofs."""

from pathlib import Path
from typing import cast

import angr
import pytest
from test_flat32_comparator_lane import _driver_lane
from test_flat32_loaded_byte_boundaries import pe32_bytes
from test_macro_step_proof import CANDIDATE32, ORACLE32

from tools.dosunit.flat32_proof_retry import ProofContext, retry_function_proof
from tools.dosunit.proof_scope import ProofScope


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_unequal_step_retry_proves_with_retained_attempts(driver: str) -> None:
    """The production retry reaches the full-state macro proof after CFG refusal."""
    obase, cbase = 0x12345000, 0x23456000
    with _driver_lane(driver) as lane:
        oracle = angr.load_shellcode(ORACLE32, arch="x86", load_address=obase)
        candidate = angr.load_shellcode(CANDIDATE32, arch="x86", load_address=cbase)
        original = {"status": lane.verdict.Status.REFUSED, "reason": "cfg_not_bijective"}
        result = retry_function_proof(
            "loop", original,
            (oracle, candidate, {"loop": (obase, len(ORACLE32))}, {"loop": (cbase, len(CANDIDATE32))}),
            lane.adapter.OUTPUT_REGS, 15000,
        )
        assert result["status"] is lane.verdict.Status.PASSED
        assert result["proof_method"] == "closed_macro_step_induction"
        assert result["proof_scope"] is ProofScope.CUTPOINT_SIMULATION
        assert set(result["additional_proof_attempts"]) == {"calls", "reblocked_cfg", "macro_step"}


def _unused_context() -> ProofContext:
    """Fail loudly if a supposedly skipped retry tries to use either project."""
    return (cast(angr.Project, object()), cast(angr.Project, object()),
            {"loop": (0, 1)}, {"loop": (0, 1)})


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_return_flag_mutation_cannot_be_promoted_by_retry(driver: str) -> None:
    """Automatic fallback preserves the full-state return observation contract."""
    obase, cbase = 0x12345000, 0x23456000
    changed = CANDIDATE32[:-1] + bytes.fromhex("f9c3")
    with _driver_lane(driver) as lane:
        oracle = angr.load_shellcode(ORACLE32, arch="x86", load_address=obase)
        candidate = angr.load_shellcode(changed, arch="x86", load_address=cbase)
        result = retry_function_proof(
            "loop", {"status": lane.verdict.Status.REFUSED, "reason": "cfg_not_bijective"},
            (oracle, candidate, {"loop": (obase, len(ORACLE32))}, {"loop": (cbase, len(changed))}),
            lane.adapter.OUTPUT_REGS, 15000,
        )
        assert result["status"] is not lane.verdict.Status.PASSED


def test_existing_counterexample_is_preserved() -> None:
    """An existing mismatch cannot be overwritten by a later proof attempt."""
    original = {"status": "failed", "reason": "observable_mismatch"}
    assert retry_function_proof("loop", original, _unused_context(), (), 1000) is original


def test_expired_retry_never_starts_new_proof() -> None:
    """A zero budget preserves the original refusal without solver work."""
    original = {"status": "refused", "reason": "cfg_not_bijective"}
    assert retry_function_proof("loop", original, _unused_context(), (), 0) is original


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_actual_pe_images_prove_through_automatic_retry(driver: str, tmp_path: Path) -> None:
    """Native PE loading reaches the retry without using an ELF candidate."""
    oracle_file, candidate_file = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    oracle_file.write_bytes(pe32_bytes(ORACLE32))
    candidate_file.write_bytes(pe32_bytes(CANDIDATE32))
    with _driver_lane(driver) as lane:
        oracle = lane.adapter.load32(oracle_file)
        candidate = lane.adapter.load32(candidate_file)
        result = retry_function_proof(
            "loop", {"status": lane.verdict.Status.REFUSED, "reason": "cfg_not_bijective"},
            (oracle, candidate, {"loop": (oracle.entry, len(ORACLE32))},
             {"loop": (candidate.entry, len(CANDIDATE32))}),
            lane.adapter.OUTPUT_REGS, 15000,
        )
        assert result["status"] is lane.verdict.Status.PASSED
        assert result["proof_method"] == "closed_macro_step_induction"
        assert result["proof_scope"] is ProofScope.CUTPOINT_SIMULATION


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_region_report_checks_environment_after_retry(
    driver: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A newly successful retry must pass the final environment admission gate."""
    from argparse import Namespace

    from tools.dosunit.binary_environment import EnvironmentScan

    with _driver_lane(driver) as lane:
        monkeypatch.setattr(
            "tools.dosunit.flat32_proof_retry.retry_function_proof",
            lambda *_args, **_kwargs: {"status": lane.verdict.Status.PASSED, "reason": "macro_step_induction"},
        )
        seen_models: list[object] = []

        def _scan(_project, _parts, *, io_model=None):
            seen_models.append(io_model)
            return EnvironmentScan(True, True, 1)

        monkeypatch.setattr(
            "tools.dosunit.binary_environment.scan_lowered_parts",
            _scan,
        )
        document = {"functions": [], "refusals": [
            {"detail": {"function_id": "oracle:loop"}, "reason": "incomplete"},
        ]}
        image = tmp_path / "input.exe"
        image.write_bytes(pe32_bytes(ORACLE32))
        args = Namespace(output_regs="eax,esp", timeout_ms=1000, region_max_blocks=128,
                         oracle_exe=image, candidate_exe=image, out_dir=tmp_path)
        kwargs = {"existing_results": [], "loop_context": _unused_context()}
        if driver == "bc5":
            kwargs["relocation"] = {}
        report = lane.z3cmp32.compare_region_mode(args, document, document, ["loop"], **kwargs)
        assert report["results"][0]["status"] == "refused"
        assert report["results"][0]["reason"] == "external_environment_contract_required"
        assert seen_models and all(model is seen_models[0] for model in seen_models)


def test_cfg_retry_cannot_publish_without_environment_coverage() -> None:
    """Missing original block receipts cannot authorize a new retry proof."""
    import angr

    from tools.dosunit.flat32_proof_retry import checked_cfg_environment_verdict

    project = angr.load_shellcode(bytes.fromhex("c3"), arch="x86", load_address=0x1000)
    context = (project, project, {"f": (0x1000, 1)}, {"f": (0x1000, 1)})
    verdict = checked_cfg_environment_verdict({"status": "passed"}, {}, context)
    assert verdict["status"] == "refused"
    assert verdict["reason"] == "environment_effect_coverage_incomplete"


@pytest.mark.parametrize(("code", "expected"), [("c3", "passed"), ("ecc3", "refused")])
def test_cfg_environment_gate_checks_real_binary_blocks(code: str, expected: str) -> None:
    """Retained plain RET coverage passes; a real port read needs a contract."""
    from tools.dosunit.flat32_proof_retry import checked_cfg_environment_verdict

    raw = bytes.fromhex(code)
    project = angr.load_shellcode(raw, arch="x86", load_address=0x1000)
    document = {"functions": [{"entry": {"linear": "0x1000"},
                               "source": {"machine_code_size": len(raw)}}]}
    context = (project, project, {"f": (0x1000, len(raw))}, {"f": (0x1000, len(raw))})
    result = checked_cfg_environment_verdict(
        {"status": "passed"}, {"oracle_ssa": document, "candidate_ssa": document}, context,
    )
    assert result["status"] == expected
    if expected == "refused":
        assert result["reason"] == "external_environment_contract_required"


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_real_matched_cfg_retains_environment_byte_sizes(driver: str) -> None:
    """Production CFG lowering retains enough binary evidence for final admission."""
    from tools.dosunit.flat32_proof_retry import checked_cfg_environment_verdict

    project = angr.load_shellcode(bytes.fromhex("c3"), arch="x86", load_address=0x1000)
    with _driver_lane(driver) as lane:
        result = lane.cfg.compare_cfg(project, project, name="f", oracle_range=(0x1000, 1),
                                      candidate_range=(0x1000, 1), outputs=lane.adapter.OUTPUT_REGS,
                                      timeout_ms=1000)
        assert result["status"] == "passed"
        context = (project, project, {"f": (0x1000, 1)}, {"f": (0x1000, 1)})
        admitted = checked_cfg_environment_verdict(result, result, context)
        assert admitted["status"] == "passed", admitted


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_macro_retry_admits_its_own_complete_binary_coverage(driver: str) -> None:
    """A successful retry retains original member ranges despite initial refusal."""
    from tools.dosunit.flat32_proof_retry import checked_cfg_environment_verdict

    with _driver_lane(driver) as lane:
        oracle = angr.load_shellcode(ORACLE32, arch="x86", load_address=0x1000)
        candidate = angr.load_shellcode(CANDIDATE32, arch="x86", load_address=0x2000)
        context = (oracle, candidate, {"f": (0x1000, len(ORACLE32))},
                   {"f": (0x2000, len(CANDIDATE32))})
        original = {"status": "refused", "reason": "cfg_not_bijective"}
        result = retry_function_proof("f", original, context, lane.adapter.OUTPUT_REGS, 15000)
        assert result["status"] == "passed"
        omitted = {key: value for key, value in result.items() if key != "environment_coverage"}
        assert checked_cfg_environment_verdict(omitted, original, context)["status"] == "refused"
        assert checked_cfg_environment_verdict(result, original, context)["status"] == "passed"
        coverage = result["environment_coverage"]
        assert coverage["oracle"] and coverage["candidate"]
        corrupted = {**result, "environment_coverage": {**coverage, "candidate": []}}
        assert checked_cfg_environment_verdict(corrupted, original, context)["status"] == "refused"


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_call_retry_environment_coverage_includes_unselected_callee(driver: str) -> None:
    """Final admission covers the callee as well as the selected caller."""
    from tools.dosunit.flat32_proof_retry import checked_cfg_environment_verdict

    code = bytes.fromhex("e801000000c3b807000000c3")
    project = angr.load_shellcode(code, arch="x86", load_address=0x1000)
    ranges = {"f": (0x1000, 6), "callee": (0x1006, 6)}
    context = (project, project, ranges, ranges)
    with _driver_lane(driver) as lane:
        original = {"status": "refused", "reason": "call_or_exception_boundary"}
        result = retry_function_proof("f", original, context, lane.adapter.OUTPUT_REGS, 10000)
        assert result["status"] == "passed", result
        coverage = result["environment_coverage"]
        for side in ("oracle", "candidate"):
            addresses = {int(part["entry"]["linear"], 0) for part in coverage[side]}
            assert addresses == {0x1000, 0x1005, 0x1006}
        assert checked_cfg_environment_verdict(result, original, context)["status"] == "passed"
