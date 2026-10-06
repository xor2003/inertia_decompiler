"""Tests for content-addressed serial clean-worker result reuse."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from angr_platforms.X86_16.segment_program_layout_codec import (
    segment_program_function_evidence_from_record_8616,
)

import inertia_decompiler.cache as cache_module
import inertia_decompiler.cli_core as cli_core
import inertia_decompiler.serial_worker_cache as worker_cache
from inertia_decompiler.direct_addr_failure_family import build_failure_family_snapshot


def _stable_tail_validation() -> dict[str, object]:
    return {
        "structuring": {"status": "stable", "mode": "unchanged", "changed": False},
        "postprocess": {"status": "stable", "mode": "unchanged", "changed": False},
    }


def _result_record(payload: str) -> dict[str, object]:
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return {
        "schema": cli_core._SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
        "status": "ok",
        "payload": payload,
        "partial_payload": None,
        "tail_validation": _stable_tail_validation(),
        "elapsed": 12.5,
        "failure_stage": None,
        "block_count": 4,
        "byte_count": 16,
        "skip_heavy_fallbacks": False,
        "same_family_retry_stops": 0,
        "fallback_family_labels": [],
        "failure_family_snapshot": build_failure_family_snapshot(
            status="ok",
            failure_stage=None,
            fallback_kind="direct_addr",
            tail_validation_verdict="passed",
            artifact_path="0x1000:sub_1000",
        ).to_record(),
        "validated_payload_hash": digest,
        "gcc_checked_payload_hash": digest,
        "segment_program_function_evidence": _segment_evidence_record(),
    }


def _segment_evidence_record() -> dict[str, object]:
    return {
        "schema": 1,
        "function_addr": 0x1000,
        "entry_requirements": [],
        "accesses": [],
        "local_clobbered_registers": [],
        "restored_registers": [],
        "control_transfers": [],
        "declared_call_consumptions": [],
        "summary": {
            "raw_fact_count": 0,
            "normalized_fact_count": 0,
            "classified_fact_count": 0,
            "materialized_count": 0,
            "failure_count": 0,
        },
    }


def _cache_inputs(binary: Path, *, addr: int = 0x1000, evidence: str = "evidence") -> worker_cache.SerialWorkerCacheInputs8616:
    return worker_cache.SerialWorkerCacheInputs8616(
        binary_path=binary,
        requested_addr=addr,
        recovery_addr=addr,
        timeout=60,
        window=0x200,
        base_addr=0x1000,
        entry_point=0x1000,
        c_target="portable-flat",
        api_style="modern",
        pat_backend="hyperscan",
        blob=False,
        signature_catalog=None,
        evidence_sha256=hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
        semantic_environment=(),
        result_schema=cli_core._SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
    )


def _redirect_cache(monkeypatch, cache_dir: Path) -> None:
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", cache_dir)
    monkeypatch.setattr(worker_cache, "DECOMPILATION_CACHE_DIR", cache_dir)


def test_serial_worker_cache_reuses_only_closed_acceptance(monkeypatch, tmp_path):
    _redirect_cache(monkeypatch, tmp_path / "cache")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x00\x01")
    inputs = _cache_inputs(binary)
    miss = worker_cache.load_serial_worker_cache_8616(inputs, enabled=True)
    record = _result_record("int sub_1000(void) { return 0; }")

    assert miss.verdict is worker_cache.SerialWorkerCacheVerdict8616.MISS
    assert worker_cache.store_serial_worker_cache_8616(
        miss,
        record,
        result_schema=cli_core._SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
    )
    hit = worker_cache.load_serial_worker_cache_8616(inputs, enabled=True)
    assert hit.verdict is worker_cache.SerialWorkerCacheVerdict8616.HIT
    assert hit.record == record

    missing_evidence = dict(record)
    missing_evidence["segment_program_function_evidence"] = None
    missing_inputs = _cache_inputs(binary, addr=0x1008)
    missing_miss = worker_cache.load_serial_worker_cache_8616(missing_inputs, enabled=True)
    assert not worker_cache.store_serial_worker_cache_8616(
        missing_miss,
        missing_evidence,
        result_schema=cli_core._SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
    )

    mismatched_inputs = _cache_inputs(binary, addr=0x100C)
    mismatched_miss = worker_cache.load_serial_worker_cache_8616(mismatched_inputs, enabled=True)
    assert worker_cache.store_serial_worker_cache_8616(
        mismatched_miss,
        record,
        result_schema=cli_core._SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
    )
    assert worker_cache.load_serial_worker_cache_8616(
        mismatched_inputs,
        enabled=True,
    ).verdict is worker_cache.SerialWorkerCacheVerdict8616.REFUSED

    bad_record = dict(record)
    bad_record["payload"] = "int sub_1000(void) { return 1; }"
    bad_inputs = _cache_inputs(binary, addr=0x1010)
    bad_miss = worker_cache.load_serial_worker_cache_8616(bad_inputs, enabled=True)
    assert not worker_cache.store_serial_worker_cache_8616(
        bad_miss,
        bad_record,
        result_schema=cli_core._SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
    )

    missing_diagnostics = dict(record)
    missing_diagnostics.pop("failure_family_snapshot")
    missing_diagnostics_inputs = _cache_inputs(binary, addr=0x1014)
    missing_diagnostics_miss = worker_cache.load_serial_worker_cache_8616(
        missing_diagnostics_inputs,
        enabled=True,
    )
    assert not worker_cache.store_serial_worker_cache_8616(
        missing_diagnostics_miss,
        missing_diagnostics,
        result_schema=cli_core._SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
    )


def test_serial_worker_cache_key_tracks_evidence_and_semantic_environment(tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x00\x01")
    first = _cache_inputs(binary, evidence="first")
    second = _cache_inputs(binary, evidence="second")
    semantic = replace(first, semantic_environment=(("INERTIA_EXPERIMENT", "1"),))

    assert worker_cache.build_serial_worker_cache_key_8616(first) != worker_cache.build_serial_worker_cache_key_8616(second)
    assert worker_cache.build_serial_worker_cache_key_8616(first) != worker_cache.build_serial_worker_cache_key_8616(semantic)
    assert worker_cache.semantic_worker_environment_8616(
        {
            "INERTIA_EXPERIMENT": "1",
            "INERTIA_ALLOW_PARALLEL_MSC6_WORKERS": "1",
            "INERTIA_OTEL_SPANS": "1",
            "INERTIA_SERIAL_CLEAN_WORKER_RESULT": "/tmp/result.json",
        }
    ) == (("INERTIA_EXPERIMENT", "1"),)


def test_serial_worker_cache_prunes_only_its_namespace(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    _redirect_cache(monkeypatch, cache_dir)
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x00\x01")
    record = _result_record("int sub(void) { return 0; }")
    unrelated = cache_dir / "other" / "keep.json"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text("{}", encoding="utf-8")

    for addr in (0x1000, 0x1010, 0x1020):
        miss = worker_cache.load_serial_worker_cache_8616(_cache_inputs(binary, addr=addr), enabled=True)
        assert worker_cache.store_serial_worker_cache_8616(
            miss,
            record,
            result_schema=cli_core._SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
            max_entries=2,
        )

    assert len(list((cache_dir / worker_cache.SERIAL_WORKER_CACHE_NAMESPACE_8616).glob("*.json"))) == 2
    assert unrelated.exists()


def test_clean_worker_parent_reuses_validated_result_without_second_process(monkeypatch, tmp_path):
    _redirect_cache(monkeypatch, tmp_path / "cache")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x00\x01")
    args = SimpleNamespace(
        binary=binary,
        window=0x200,
        base_addr=0x1000,
        entry_point=0x1000,
        c_target="portable-flat",
        api_style="modern",
        pat_backend="hyperscan",
        blob=False,
        signature_catalog=None,
        trace_c_stages=False,
        declared_call_effects=(),
        dump_layers=False,
        dump_layer_dir=tmp_path / "layers",
        dump_layer_filter="",
    )
    context = SimpleNamespace(args=args, project=SimpleNamespace(), lst_metadata=None)
    item = cli_core.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=SimpleNamespace(addr=0x0FF0),
        recovery_addr=0x0FF0,
    )
    payload = "int sub_1000(void) { return 0; }"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    process_count = 0

    def fake_run(command, **kwargs):
        nonlocal process_count
        process_count += 1
        result_path = Path(kwargs["env"][cli_core._SERIAL_CLEAN_WORKER_RESULT_ENV_8616])
        monkeypatch.setenv(cli_core._SERIAL_CLEAN_WORKER_RESULT_ENV_8616, str(result_path))
        cli_core._write_serial_clean_worker_result_8616(
            cli_core.FunctionWorkResult(
                index=1,
                status="ok",
                payload=payload,
                debug_output="",
                function=None,
                function_cfg=None,
                tail_validation=_stable_tail_validation(),
                validated_payload_hash=digest,
                gcc_checked_payload_hash=digest,
                failure_family_snapshot=build_failure_family_snapshot(
                    status="ok",
                    failure_stage=None,
                    fallback_kind="direct_addr",
                    tail_validation_verdict="passed",
                    artifact_path="0x1000:sub_1000",
                ),
                segment_program_function_evidence=segment_program_function_evidence_from_record_8616(
                    _segment_evidence_record()
                ),
            )
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="child diagnostic\n")

    monkeypatch.setattr(cli_core, "run_captured_subprocess_tree", fake_run)
    monkeypatch.setattr(cli_core, "_ARCHITECTURE_GUARD_STATUS_8616", True)
    monkeypatch.setattr(
        cli_core,
        "_canonicalize_direct_addr_from_sidecar_padding_8616",
        lambda *_args: SimpleNamespace(canonical_addr=0x1000),
    )

    first = cli_core._run_serial_clean_process_work_item_8616(context, item, timeout=60)
    cached_only = cli_core._run_serial_clean_process_work_item_8616(
        context,
        item,
        timeout=60,
        cache_only=True,
    )
    missing_only = cli_core._run_serial_clean_process_work_item_8616(
        context,
        item,
        timeout=61,
        cache_only=True,
    )
    second = cli_core._run_serial_clean_process_work_item_8616(context, item, timeout=60)

    assert first.status == "ok"
    assert not first.from_cache
    assert cached_only is not None
    assert cached_only.from_cache
    assert missing_only is None
    assert second.status == "ok"
    assert second.from_cache
    assert second.payload == first.payload
    assert second.failure_family_snapshot == first.failure_family_snapshot
    assert "cache hit" in second.debug_output
    assert process_count == 1
    assert os.environ[cli_core._SERIAL_CLEAN_WORKER_RESULT_ENV_8616]


def test_serial_worker_cache_capacity_covers_large_whole_binary_sweeps() -> None:
    assert worker_cache.SERIAL_WORKER_CACHE_MAX_ENTRIES_8616 >= 4096


def test_canonical_clean_cache_preflight_refuses_miss_without_emitting(monkeypatch, capsys):
    canonical = cli_core.DirectAddrCanonicalization8616(
        requested_addr=0x10554,
        canonical_addr=0x10560,
        region=(0x10554, 0x10672),
        name="InitBars",
    )
    monkeypatch.setattr(
        cli_core,
        "_run_serial_clean_process_work_item_8616",
        lambda *_args, **_kwargs: None,
    )

    status = cli_core._run_canonicalized_direct_clean_worker_8616(
        SimpleNamespace(),
        SimpleNamespace(timeout=60),
        SimpleNamespace(),
        canonical,
        function_label="InitBars",
        cache_only=True,
    )

    captured = capsys.readouterr()
    assert status is None
    assert captured.out == ""
    assert captured.err == ""


def test_serial_clean_worker_bypasses_parent_owned_direct_lock(monkeypatch):
    lock_key = {"kind": "direct_addr_work", "addr": 0x102E0}
    monkeypatch.delenv(cli_core._SERIAL_CLEAN_WORKER_RESULT_ENV_8616, raising=False)

    assert cli_core._direct_addr_work_requires_parent_lock_8616(lock_key)

    monkeypatch.setenv(cli_core._SERIAL_CLEAN_WORKER_RESULT_ENV_8616, "/tmp/worker-result.json")

    assert not cli_core._direct_addr_work_requires_parent_lock_8616(lock_key)
