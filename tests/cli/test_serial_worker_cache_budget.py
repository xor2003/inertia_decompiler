"""Tests for monotonic serial clean-worker analysis-budget reuse."""

from __future__ import annotations

import json
import os
import pstats
from dataclasses import replace
from pathlib import Path

import inertia.cli.cache as cache_module
import inertia.cli.serial_clean_worker_cli as worker_cli
import inertia.cli.serial_worker_cache as worker_cache
from inertia.cli.cache_runtime_contract import (
    WORKER_IN_PROCESS_PROFILE_ENV_8616,
    timing_diagnostics_requested_8616,
)


def _inputs(binary: Path, *, timeout: int) -> worker_cache.SerialWorkerCacheInputs8616:
    return worker_cache.SerialWorkerCacheInputs8616(
        binary_path=binary,
        requested_addr=0x1000,
        recovery_addr=0x1000,
        timeout=timeout,
        window=0x200,
        base_addr=0x1000,
        entry_point=0x1000,
        c_target="portable-flat",
        api_style="modern",
        pat_backend="hyperscan",
        blob=False,
        signature_catalog=None,
        evidence_sha256="evidence",
        semantic_environment=(),
        result_schema=4,
    )


def _redirect_cache(monkeypatch, cache_dir: Path) -> None:
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", cache_dir)
    monkeypatch.setattr(worker_cache, "DECOMPILATION_CACHE_DIR", cache_dir)


def test_serial_worker_cache_key_excludes_analysis_budget(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    inputs = _inputs(binary, timeout=60)

    assert worker_cache.build_serial_worker_cache_key_8616(inputs) == (
        worker_cache.build_serial_worker_cache_key_8616(replace(inputs, timeout=240))
    )


def test_live_diagnostics_disable_serial_worker_result_reuse(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """A live diagnostic request must execute the worker instead of cached C."""
    diagnostic_requests = (
        ("INERTIA_DEBUG_TIMING", "true"),
        ("INERTIA_OTEL_CPROFILE_PATH", "worker.prof"),
    )
    for name, value in diagnostic_requests:
        monkeypatch.delenv("INERTIA_DEBUG_TIMING", raising=False)
        monkeypatch.delenv("INERTIA_OTEL_CPROFILE_PATH", raising=False)
        monkeypatch.setenv(name, value)
        result = worker_cache.load_serial_worker_cache_8616(
            _inputs(tmp_path / "timing.exe", timeout=60),
            enabled=True,
        )
        assert result.verdict is worker_cache.SerialWorkerCacheVerdict8616.DISABLED
        assert result.reason is worker_cache.SerialWorkerCacheReason8616.DIAGNOSTICS
        assert result.key is None


def test_disabled_timing_values_preserve_cache_reuse(monkeypatch) -> None:
    """Explicit false values must not request live timing diagnostics."""
    for value in ("", "0", "false", "FALSE", "no", "off", " Off "):
        monkeypatch.setenv("INERTIA_DEBUG_TIMING", value)
        assert not timing_diagnostics_requested_8616()


def test_clean_worker_cprofile_writes_explicit_pid_path(monkeypatch, tmp_path: Path) -> None:
    """The opt-in worker profiler must write a readable process-specific file."""
    profile_template = tmp_path / "worker-{pid}.prof"
    monkeypatch.setenv("INERTIA_OTEL_CPROFILE_PATH", str(profile_template))
    monkeypatch.setenv(WORKER_IN_PROCESS_PROFILE_ENV_8616, "0")
    observed_profile_modes: list[str | None] = []

    def core_main(_argv: list[str] | None) -> int:
        """Record whether profiling keeps decompilation inside this process."""
        observed_profile_modes.append(os.environ.get(WORKER_IN_PROCESS_PROFILE_ENV_8616))
        return 7

    monkeypatch.setattr(worker_cli, "_core_main", core_main)

    assert worker_cli.main(["sample.exe"]) == 7
    assert observed_profile_modes == ["1"]
    profile_path = tmp_path / f"worker-{os.getpid()}.prof"
    assert pstats.Stats(str(profile_path)).total_calls > 0


def test_serial_worker_cache_budget_reuse_is_monotonic(monkeypatch, tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    _redirect_cache(monkeypatch, cache_dir)
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(
        worker_cache,
        "_validated_result_record_8616",
        lambda record, **_kwargs: dict(record),
    )
    inputs = _inputs(binary, timeout=60)
    miss = worker_cache.load_serial_worker_cache_8616(inputs, enabled=True)

    assert worker_cache.store_serial_worker_cache_8616(miss, {"payload": "medium"}, result_schema=4)
    weaker = worker_cache.load_serial_worker_cache_8616(replace(inputs, timeout=30), enabled=True)
    stronger = worker_cache.load_serial_worker_cache_8616(replace(inputs, timeout=120), enabled=True)

    assert weaker.verdict is worker_cache.SerialWorkerCacheVerdict8616.HIT
    assert weaker.record == {"payload": "medium"}
    assert stronger.verdict is worker_cache.SerialWorkerCacheVerdict8616.MISS
    assert stronger.reason is worker_cache.SerialWorkerCacheReason8616.INSUFFICIENT_ANALYSIS_BUDGET


def test_stronger_serial_worker_result_cannot_be_downgraded(monkeypatch, tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    _redirect_cache(monkeypatch, cache_dir)
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(
        worker_cache,
        "_validated_result_record_8616",
        lambda record, **_kwargs: dict(record),
    )
    inputs = _inputs(binary, timeout=60)
    initial = worker_cache.load_serial_worker_cache_8616(inputs, enabled=True)
    assert worker_cache.store_serial_worker_cache_8616(initial, {"payload": "medium"}, result_schema=4)

    stronger_inputs = replace(inputs, timeout=120)
    stronger = worker_cache.load_serial_worker_cache_8616(stronger_inputs, enabled=True)
    assert worker_cache.store_serial_worker_cache_8616(stronger, {"payload": "strong"}, result_schema=4)

    weaker_lookup = worker_cache.SerialWorkerCacheLookup8616(
        worker_cache.SerialWorkerCacheVerdict8616.MISS,
        stronger.key,
        None,
        worker_cache.SerialWorkerCacheReason8616.NOT_FOUND,
        30,
    )
    assert worker_cache.store_serial_worker_cache_8616(weaker_lookup, {"payload": "weak"}, result_schema=4)
    key = worker_cache.build_serial_worker_cache_key_8616(inputs)
    assert key is not None
    stored_path = cache_module._cache_json_path(worker_cache.SERIAL_WORKER_CACHE_NAMESPACE_8616, key)
    stored = json.loads(stored_path.read_text(encoding="utf-8"))

    assert stored["payload"] == "strong"
    assert stored[worker_cache.SERIAL_WORKER_CACHE_ANALYSIS_TIMEOUT_FIELD_8616] == 120
