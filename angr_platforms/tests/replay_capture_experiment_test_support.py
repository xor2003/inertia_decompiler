"""Layer: test support.
Responsibility: own replay capture experiment fixture contracts and evidence.
"""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Any

from replay_capture_emission_test_support import emit_flat32, emit_real16
from replay_capture_fixture_test_support import (
    FUZZ_COUNT,
    INSTRUCTION_LIMIT,
    MAX_COHORT_VECTORS,
    R16_CODE_SIZE,
    R16_LOAD,
    SEED,
    flat32_code_bytes,
    flat32_data_bytes,
    flat32_pe_bytes,
    flat32_pe_image,
    real16_image_bytes,
    real16_load_image,
    real16_mz_bytes,
)
from replay_capture_manifest_test_support import vector_sha256
from replay_capture_setup_test_support import (
    capture_flat32,
    capture_real16,
    flat32_capture_fixture,
    real16_capture_fixture,
)

from tools.dosunit.flat32_replay_model import (
    Flat32CaptureResult,
)
from tools.dosunit.model import write_json
from tools.dosunit.real16_replay_model import (
    Real16CaptureResult,
)


def _capture_summary16(capture: Real16CaptureResult) -> dict[str, Any]:
    """Typed capture summary for the run receipt."""
    return {
        "status": capture.status.value,
        "boundary": f"{capture.boundary.linear():#x}",
        "execution_status": (
            capture.execution_status.value if capture.execution_status is not None else None
        ),
        "instructions": capture.instructions,
        "fetch_trace": [f"{address:#x}" for address in capture.fetch_trace],
        "detail": capture.detail,
        "trap_linear": f"{capture.trap_linear:#x}",
    }


def _capture_summary32(capture: Flat32CaptureResult) -> dict[str, Any]:
    """Typed capture summary for the run receipt."""
    return {
        "status": capture.status.value,
        "boundary": f"{capture.boundary:#x}",
        "execution_status": (
            capture.execution_status.value if capture.execution_status is not None else None
        ),
        "instructions": capture.instructions,
        "fetch_trace": [f"{address:#x}" for address in capture.fetch_trace],
        "detail": capture.detail,
        "trap": f"{capture.trap:#x}",
    }


def run_experiment(out_dir: Path) -> dict[str, Any]:
    """Generate both cohorts, replay orig/orig and orig/mutant, keep receipts."""
    from tools.dosunit.dosunit import main as dosunit_main

    out_dir.mkdir(parents=True, exist_ok=True)
    receipts: dict[str, Any] = {"tracks": {}, "seed": SEED,
                                "instruction_limit": INSTRUCTION_LIMIT,
                                "fuzz_count": FUZZ_COUNT}
    provenance_all: dict[str, dict[str, Any]] = {}

    # ---- real16 track -----------------------------------------------------
    r16_dir = out_dir / "real16"
    r16_dir.mkdir(parents=True, exist_ok=True)
    (r16_dir / "oracle.exe").write_bytes(real16_mz_bytes(mutated=False))
    (r16_dir / "mutant.exe").write_bytes(real16_mz_bytes(mutated=True))

    r16_fixture = real16_capture_fixture(
        image=real16_load_image(real16_image_bytes(mutated=False))
    )
    r16_capture = capture_real16(
        r16_fixture.image, r16_fixture.entry, r16_fixture.boundary, r16_fixture.vector
    )
    rng16 = random.Random(int(SEED, 16))
    r16_vectors, r16_prov = emit_real16(r16_capture, r16_fixture.extents, rng16)
    provenance_all.update(r16_prov)
    if len(r16_vectors) > MAX_COHORT_VECTORS:
        raise ValueError("real16 cohort exceeds the declared vector bound")
    code_ranges = [{"address": f"{R16_LOAD * 16:#x}", "size": R16_CODE_SIZE}]
    write_json(r16_dir / "vectors.json", {
        "vectors": r16_vectors,
        "oracle_code_ranges": code_ranges,
        "candidate_code_ranges": code_ranges,
    })

    # ---- flat32 track -----------------------------------------------------
    f32_dir = out_dir / "flat32"
    f32_dir.mkdir(parents=True, exist_ok=True)
    (f32_dir / "oracle.exe").write_bytes(flat32_pe_bytes(mutated=False))
    (f32_dir / "mutant.exe").write_bytes(flat32_pe_bytes(mutated=True))

    f32_fixture = flat32_capture_fixture(
        image=flat32_pe_image(flat32_code_bytes(mutated=False), flat32_data_bytes())
    )
    f32_capture = capture_flat32(
        f32_fixture.image, f32_fixture.entry, f32_fixture.boundary, f32_fixture.vector
    )
    rng32 = random.Random(int(SEED, 16) + 1)
    f32_vectors, f32_prov = emit_flat32(f32_capture, f32_fixture.extents, rng32)
    provenance_all.update(f32_prov)
    if len(f32_vectors) > MAX_COHORT_VECTORS:
        raise ValueError("flat32 cohort exceeds the declared vector bound")
    write_json(f32_dir / "vectors.json", {"vectors": f32_vectors})

    receipts["captures"] = {
        "real16": _capture_summary16(r16_capture),
        "flat32": _capture_summary32(f32_capture),
    }
    write_json(out_dir / "provenance.json", provenance_all)

    # ---- replay through the public CLIs ------------------------------------
    for track, directory in (("real16", r16_dir), ("flat32", f32_dir)):
        command = "replay-real16" if track == "real16" else "replay-flat32"
        reports: dict[str, Any] = {}
        for label, candidate in (("orig-orig", "oracle.exe"),
                                 ("orig-mut-1", "mutant.exe"),
                                 ("orig-mut-2", "mutant.exe")):
            report_path = directory / f"{label}.json"
            argv = [
                command,
                "--oracle-exe", str(directory / "oracle.exe"),
                "--candidate-exe", str(directory / candidate),
                "--vectors", str(directory / "vectors.json"),
                "--instruction-limit", str(INSTRUCTION_LIMIT),
                "--out", str(report_path),
            ]
            rc = dosunit_main(argv)
            reports[label] = {"rc": rc, "path": report_path.name,
                              "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest()}
        reports["determinism"] = {
            "orig-mut-1_bytes_equal_orig-mut-2":
                (directory / "orig-mut-1.json").read_bytes()
                == (directory / "orig-mut-2.json").read_bytes()
        }
        receipts["tracks"][track] = reports
    write_json(out_dir / "run-summary.json", receipts)
    return receipts


def build_accounting(out_dir: Path) -> dict[str, Any]:
    """Merge reports, provenance and per-vector hashes into one ledger."""
    provenance = json.loads((out_dir / "provenance.json").read_text())
    ledger: dict[str, Any] = {"schema": "m6.replay-vectors.accounting.v1", "tracks": {}}
    for track in ("real16", "flat32"):
        directory = out_dir / track
        vectors = json.loads((directory / "vectors.json").read_text())["vectors"]
        orig_orig = {row["id"]: row for row in
                     json.loads((directory / "orig-orig.json").read_text())["results"]}
        orig_mut = {row["id"]: row for row in
                    json.loads((directory / "orig-mut-1.json").read_text())["results"]}
        rows: list[dict[str, Any]] = []
        for vector in vectors:
            vid = vector["id"]
            def outcome(run: dict[str, Any]) -> dict[str, Any]:
                oracle, candidate = run["oracle"], run["candidate"]

                def side(result: dict[str, Any]) -> dict[str, Any]:
                    return {
                        "status": result["status"], "detail": result["detail"],
                        "instructions": result["instructions"],
                        "events": result.get("events", []),
                        "observations": [
                            {"address": obs.get("linear", obs.get("address")),
                             "status": obs.get("status", "captured")}
                            for obs in result.get("observations", [])
                        ],
                    }
                return {"agreement": run["status"],
                        "oracle": side(oracle), "candidate": side(candidate)}
            rows.append({
                "id": vid,
                "sha256": vector_sha256(vector),
                "provenance": provenance.get(vid, {"kind": "undeclared"}),
                "runs": {"orig-orig": outcome(orig_orig[vid]), "orig-mut": outcome(orig_mut[vid])},
            })
        ledger["tracks"][track] = {"vectors": rows, "vector_count": len(rows)}
    write_json(out_dir / "accounting.json", ledger)
    return ledger
