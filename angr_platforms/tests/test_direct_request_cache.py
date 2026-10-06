"""Tests for validated pre-recovery direct-request cache reuse."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from angr_platforms.X86_16.tail_validation import x86_16_tail_validation_snapshot_passed

import decompile as decompile_entrypoint
import inertia_decompiler.cache as cache_module
import inertia_decompiler.cli_core as cli_core
import inertia_decompiler.direct_request_cache as direct_cache
import inertia_decompiler.direct_request_fast_path as direct_fast_path
import inertia_decompiler.direct_request_identity as direct_identity
import inertia_decompiler.function_cache_context as function_cache_context
from inertia_decompiler.cli_arg_parser import CliArguments
from inertia_decompiler.direct_addr_failure_family import build_failure_family_snapshot


def _args(binary: Path) -> CliArguments:
    args = CliArguments()
    args.binary = binary
    args.addr = 0x1000
    args.blob = False
    args.base_addr = 0x1000
    args.entry_point = 0x1000
    args.show_asm = False
    args.alternate_source_c = False
    args.c_target = "portable-flat"
    args.output_c_dir = None
    args.trace_c_stages = False
    args.dump_layers = False
    args.dump_layer_dir = binary.parent / "layers"
    args.dump_layer_filter = ""
    args.proc = None
    args.proc_kind = "NEAR"
    args.declared_call_effects = ()
    args.timeout = 60
    args.window = 0x200
    args.max_memory_mb = 2048
    args.max_functions = 0
    args.include_library_functions = False
    args.ignore_local_sidecar_hints = False
    args.api_style = "modern"
    args.pat_backend = "hyperscan"
    args.function_discovery_backend = "auto"
    args.rizin_timeout = 8
    args.signature_catalog = None
    args.seed_engine = "auto"
    args.brief = True
    args.otel_spans = None
    args.otel_top_n = None
    args.otel_min_ms = None
    args.otel_full_jsonl = None
    args.otel_stderr = None
    args.otel_format = None
    args.otel_text_max_spans = None
    args.otel_export_otlp = None
    args.otel_service_name = None
    args.otel_force_flush_ms = None
    args.otel_endpoint = None
    args.otel_span_file = None
    return args


def _inputs(args: CliArguments) -> direct_identity.DirectRequestCacheInputs8616:
    inputs = direct_identity.DirectRequestCacheInputs8616.from_cli(args, signature_catalog=None)
    assert inputs is not None
    return inputs


def _tail_validation() -> dict[str, object]:
    return {
        "structuring": {"status": "stable", "mode": "unchanged", "changed": False},
        "postprocess": {"status": "stable", "mode": "unchanged", "changed": False},
    }


def _artifact(payload: str = "int sub_1000(void) { return 0; }\n") -> direct_cache.DirectRequestCacheArtifact8616:
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return direct_cache.DirectRequestCacheArtifact8616(
        function_addr=0x1000,
        function_name="sub_1000",
        arch_name="86_16",
        entry_point=0x1000,
        runtime_header="",
        startup_diagnostic_lines=(),
        payload=payload,
        tail_validation=_tail_validation(),
        elapsed=1.0,
        block_count=1,
        byte_count=4,
        validated_payload_hash=digest,
        gcc_checked_payload_hash=digest,
        failure_family_snapshot=build_failure_family_snapshot(
            status="ok",
            failure_stage=None,
            fallback_kind="direct_addr",
            tail_validation_verdict="passed",
            artifact_path="0x1000:sub_1000",
        ),
        diagnostic_output="",
        segment_program_function_evidence_record=None,
    )


def test_direct_request_cache_reuses_only_closed_acceptance(monkeypatch, tmp_path):
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x00\x01")
    inputs = _inputs(_args(binary))

    miss = direct_cache.load_direct_request_cache_8616(inputs, enabled=True)
    assert miss.verdict is direct_cache.DirectRequestCacheVerdict8616.MISS
    assert direct_cache.store_direct_request_cache_8616(miss, _artifact())

    hit = direct_cache.load_direct_request_cache_8616(inputs, enabled=True)
    assert hit.verdict is direct_cache.DirectRequestCacheVerdict8616.HIT
    assert hit.artifact == _artifact()

    corrupt = replace(_artifact(), validated_payload_hash="0" * 64)
    changed_inputs = replace(inputs, requested_addr=0x1010)
    changed_miss = direct_cache.load_direct_request_cache_8616(changed_inputs, enabled=True)
    assert not direct_cache.store_direct_request_cache_8616(changed_miss, corrupt)


def test_direct_request_cache_key_tracks_semantic_inputs(monkeypatch, tmp_path):
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x00\x01")
    inputs = _inputs(_args(binary))
    baseline = direct_identity.build_direct_request_cache_key_8616(inputs)

    assert baseline is not None
    assert direct_identity.build_direct_request_cache_key_8616(replace(inputs, window=0x80)) != baseline
    assert direct_identity.build_direct_request_cache_key_8616(replace(inputs, c_target="msc-dos")) != baseline

    binary.with_suffix(".COD").write_text("sidecar evidence", encoding="ascii")
    assert direct_identity.build_direct_request_cache_key_8616(inputs) != baseline


def test_direct_request_cache_key_refuses_nondeterministic_runtime(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x00\x01")
    inputs = _inputs(_args(binary))

    monkeypatch.delenv("PYTHONHASHSEED", raising=False)
    assert direct_identity.build_direct_request_cache_key_8616(inputs) is None
    monkeypatch.setenv("PYTHONHASHSEED", "9")
    assert direct_identity.build_direct_request_cache_key_8616(inputs) is None


def test_direct_request_cache_key_addresses_sidecars_by_content(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first_binary = first_root / "sample.exe"
    second_binary = second_root / "sample.exe"
    first_binary.write_bytes(b"MZ\x00\x01")
    second_binary.write_bytes(b"MZ\x00\x01")
    first_binary.with_suffix(".COD").write_text("same sidecar evidence", encoding="ascii")
    second_sidecar = second_binary.with_suffix(".COD")
    second_sidecar.write_text("same sidecar evidence", encoding="ascii")

    first_key = direct_identity.build_direct_request_cache_key_8616(_inputs(_args(first_binary)))
    second_key = direct_identity.build_direct_request_cache_key_8616(_inputs(_args(second_binary)))

    assert first_key is not None
    assert second_key == first_key

    second_sidecar.write_text("different sidecar evidence", encoding="ascii")
    assert direct_identity.build_direct_request_cache_key_8616(_inputs(_args(second_binary))) != first_key


def test_direct_request_cache_bypasses_live_diagnostic_modes(tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x00\x01")
    args = _args(binary)

    assert direct_identity.direct_request_cache_enabled_8616(args)
    args.show_asm = True
    assert not direct_identity.direct_request_cache_enabled_8616(args)
    args.show_asm = False
    args.trace_c_stages = True
    assert not direct_identity.direct_request_cache_enabled_8616(args)
    args.trace_c_stages = False
    args.dump_layers = True
    assert not direct_identity.direct_request_cache_enabled_8616(args)


def test_direct_request_hit_precedes_function_recovery(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x00\x01")
    args = _args(binary)
    inputs = _inputs(args)
    lookup = direct_cache.DirectRequestCacheLookup8616(
        verdict=direct_cache.DirectRequestCacheVerdict8616.HIT,
        reason=direct_cache.DirectRequestCacheReason8616.VALIDATED,
        key={"kind": "test"},
        artifact=_artifact(),
    )
    monkeypatch.setattr(cli_core, "load_direct_request_cache_8616", lambda *_args, **_kwargs: lookup)
    monkeypatch.setattr(cli_core, "render_c_runtime_header_8616", lambda _target: "")
    monkeypatch.setattr(
        cli_core,
        "_recover_direct_addr_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("recovery must not run")),
    )
    monkeypatch.setattr(cli_core, "_emit_tail_validation_console_summary", lambda *_args, **_kwargs: None)
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"), entry=0x1000)
    context = cli_core._DirectAddrCliContext8616(
        args=args,
        project=project,
        function_label=None,
        cod_metadata=None,
        synthetic_globals={},
        lst_metadata=None,
        prefer_fast_recovery=False,
        proc_resolved_to_linked_binary=False,
        low_memory_path=False,
        interactive_stdout=False,
        precise_sidecar_regions=False,
        timeout_was_explicit=False,
        request_cache_inputs=inputs,
    )

    assert cli_core._run_direct_addr_cli_8616(context) == 0
    captured = capsys.readouterr()
    assert "int sub_1000(void)" in captured.out
    assert "recovering function" not in captured.out
    assert "direct request cache hit" in captured.err


@pytest.mark.parametrize(
    "snapshot",
    [
        _tail_validation(),
        {"structuring": {"changed": False}, "postprocess": {"changed": False}},
        {"structuring": {"status": "changed"}, "postprocess": {"status": "stable"}},
        {"structuring": {"status": "stable"}},
        None,
    ],
)
def test_lightweight_tail_validation_projection_matches_authoritative_validator(snapshot):
    assert direct_cache._tail_validation_record_passed_8616(snapshot) == x86_16_tail_validation_snapshot_passed(
        snapshot
    )


def test_tail_snapshot_diagnostic_uses_pipeline_order_after_json_sorting():
    sorted_snapshot = {
        "postprocess": {"changed": False},
        "structuring": {"status": "stable", "changed": False},
    }

    diagnostic = direct_cache.render_direct_request_tail_snapshot_diagnostic_8616(sorted_snapshot)

    assert "merged_stages=['structuring', 'postprocess']" in diagnostic
    assert "merged_statuses={'structuring': 'stable', 'postprocess': 'stable'}" in diagnostic


def test_entrypoint_fast_path_emits_without_full_cli(monkeypatch, tmp_path, capsys):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x00\x01")
    startup_diagnostic = (
        "/* no helper metadata (.lst/.map/.cod/debug info) found; using raw binary analysis "
        "and quick function-entry scans. */"
    )
    artifact = replace(
        _artifact(),
        runtime_header="#include <stdint.h>\n",
        startup_diagnostic_lines=(startup_diagnostic,),
    )
    lookup = direct_cache.DirectRequestCacheLookup8616(
        verdict=direct_cache.DirectRequestCacheVerdict8616.HIT,
        reason=direct_cache.DirectRequestCacheReason8616.VALIDATED,
        key={"kind": "test"},
        artifact=artifact,
    )
    monkeypatch.setattr(
        direct_fast_path,
        "load_direct_request_cache_8616",
        lambda *_args, **_kwargs: lookup,
    )

    status = direct_fast_path.try_direct_request_fast_path_8616(
        [str(binary), "--addr", "0x1000", "--no-alternate-source-c"]
    )

    assert status == 0
    captured = capsys.readouterr()
    assert "#include <stdint.h>" in captured.out
    assert startup_diagnostic in captured.out
    assert "int sub_1000(void)" in captured.out
    assert "direct request cache hit" in captured.err
    assert "merged_statuses={'structuring': 'stable', 'postprocess': 'stable'}" in captured.err


def test_entrypoint_cache_hit_does_not_import_full_cli(monkeypatch):
    monkeypatch.setattr(direct_fast_path, "try_direct_request_fast_path_8616", lambda: 0)
    original_ensure_cli = decompile_entrypoint._ensure_cli
    ModuleType.__setattr__(
        decompile_entrypoint,
        "_ensure_cli",
        lambda: (_ for _ in ()).throw(AssertionError("full CLI must stay unloaded")),
    )
    try:
        assert decompile_entrypoint._run_entrypoint() == 0
    finally:
        ModuleType.__setattr__(decompile_entrypoint, "_ensure_cli", original_ensure_cli)


def test_timing_diagnostics_reuse_evidence_but_disable_final_result_caches(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Timing must preserve evidence keys while forcing live decompilation."""
    args = _args(tmp_path / "timing.exe")
    assert direct_identity.direct_request_cache_enabled_8616(args)

    monkeypatch.setenv("INERTIA_DEBUG_TIMING", "1")

    assert "INERTIA_DEBUG_TIMING" not in cache_module._cache_runtime_environment()
    assert not direct_identity.direct_request_cache_enabled_8616(args)
    assert (
        function_cache_context.function_decompilation_cache_key_8616(
            object(),
            binary_path=None,
            api_style="raw",
            cod_metadata=None,
            synthetic_globals=None,
            lst_metadata=None,
            enable_structured_simplify=True,
            enable_postprocess=True,
        )
        is None
    )
