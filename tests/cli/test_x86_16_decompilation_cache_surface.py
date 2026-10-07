import hashlib
import os
from pathlib import Path

import pytest

import inertia.cli.cache as cache_module
import inertia.cli.cache_file_digest as cache_file_digest_module
from inertia.cli.cache import DECOMPILATION_CACHE_SOURCE_FILES, _cache_file_fingerprint
from inertia.cli.cache_file_digest import clear_cache_file_digest_memo_8616
from inertia.cli.cache_source_manifest import (
    FUNCTION_DISCOVERY_CACHE_SOURCE_FILES,
    INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES,
    RecoveryCacheSourceScope8616,
)


def test_decompilation_cache_surface_includes_tail_validation_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "tail_validation.py" in names
    assert "tail_validation_condition_context.py" in names
    assert "tail_validation_fingerprint.py" in names
    assert "tail_validation_routing.py" in names


def test_decompilation_cache_surface_includes_condition_and_induction_rewrite_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "callsite_prototype_declarations.py" in names
    assert "cli_decompilation.py" in names
    assert "condition_ir.py" in names
    assert "flags_cleanup.py" in names
    assert "decompiler_postprocess_jcc.py" in names
    assert "decompiler_postprocess_stage.py" in names
    assert "type_array_matching.py" in names
    assert "object_lowering.py" in names
    assert "cli_access_profiles.py" in names
    assert "cli_access_traits.py" in names


def test_decompilation_cache_surface_includes_postprocess_optimization_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "const_prop.py" in names
    assert "dce.py" in names
    assert "dead_setup.py" in names
    assert "pass_driver.py" in names
    assert "decompiler_postprocess_typed_conditions.py" in names
    assert "decompiler_postprocess_utils.py" in names
    assert "segmented_memory_reasoning.py" in names


def test_function_discovery_cache_surface_excludes_late_semantic_layers():
    import inertia.pipeline.contracts as pipeline_contracts
    import inertia.pipeline.errors as pipeline_errors
    import inertia.pipeline.structured_ast_query_index as structured_ast_query_index

    paths = {
        path.relative_to(Path(__file__).resolve().parents[2]).as_posix()
        for path in FUNCTION_DISCOVERY_CACHE_SOURCE_FILES
    }
    names = {Path(path).name for path in paths}
    source_files = set(FUNCTION_DISCOVERY_CACHE_SOURCE_FILES)

    assert "cli_function_discovery.py" in names
    assert "lift_86_16.py" in names
    assert Path(pipeline_errors.__file__).parent / "errors.py" in source_files
    assert Path(pipeline_contracts.__file__).parent / "contracts.py" in source_files
    assert Path(structured_ast_query_index.__file__).parent / "structured_ast_query_index.py" not in source_files
    assert "tail_validation.py" not in names
    assert "decompiler_postprocess_stage.py" not in names


def test_indexed_alias_program_cache_surface_owns_alias_and_widening_only():
    paths = {
        path.relative_to(Path(__file__).resolve().parents[2]).as_posix()
        for path in INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES
    }

    import inertia.cli.indexed_alias_program_context as indexed_context_module
    import inertia.cli.indexed_alias_program_recovery as indexed_recovery_module
    import inertia.cli.indexed_global_object_cache as indexed_global_object_cache_module

    source_files = set(INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES)

    assert Path(indexed_context_module.__file__).parent / "indexed_alias_program_context.py" in source_files
    assert Path(indexed_recovery_module.__file__).parent / "indexed_alias_program_recovery.py" in source_files
    assert Path(indexed_global_object_cache_module.__file__).parent / "indexed_global_object_cache.py" in source_files
    assert "inertia/alias/indexed_address_program.py" in paths
    assert "inertia/widening/global_object_layout.py" in paths
    assert {
        "inertia/alias/alias_model_impl.py",
        "inertia/alias/domains.py",
        "inertia/alias/indexed_address_access_classification.py",
        "inertia/alias/indexed_address_access_contracts.py",
        "inertia/alias/indexed_address_contracts.py",
        "inertia/alias/indexed_address_copy_contracts.py",
        "inertia/alias/indexed_address_copy_projection.py",
        "inertia/alias/indexed_address_projection.py",
        "inertia/alias/indexed_address_range_contracts.py",
        "inertia/alias/indexed_address_range_projection.py",
        "inertia/alias/storage_fact_join.py",
        "inertia/widening/global_object_layout_codec.py",
        "inertia/widening/indexed_global_object_layout.py",
        "inertia/widening/indexed_global_object_program_range_codec.py",
        "inertia/widening/indexed_global_object_program_ranges.py",
        "inertia/widening/indexed_global_object_range_layouts.py",
        "inertia/widening/indexed_global_object_range_solver.py",
        "inertia/widening/indexed_global_object_ranges.py",
    } <= paths
    assert "inertia/alias/stack_coordinate_projection.py" not in paths
    assert "inertia/widening/stack_subview_projection.py" not in paths
    assert "inertia/lowering/segmented_global_loads.py" not in paths
    assert "inertia/lowering/register_local_declarations.py" not in paths
    assert "inertia/pipeline/structured_ast_generation.py" not in paths
    assert "inertia/pipeline/structured_ast_query_index.py" not in paths
    assert "inertia/validation/tail_validation.py" not in paths
    assert "inertia/postprocess/decompiler_postprocess_stage.py" not in paths


def test_recovery_cache_key_uses_discovery_component_scope(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"MZ-discovery")
    observed_sources: list[tuple[Path, ...]] = []

    def record_sources(paths: tuple[Path, ...]) -> str:
        observed_sources.append(paths)
        return "component-digest"

    monkeypatch.setattr(cache_module, "_cache_source_digest", record_sources)

    key = cache_module._recovery_cache_key(
        binary_path=binary,
        kind="display_catalog_addrs",
        source_scope=RecoveryCacheSourceScope8616.FUNCTION_DISCOVERY,
    )

    assert key is not None
    assert observed_sources == [FUNCTION_DISCOVERY_CACHE_SOURCE_FILES]


def test_recovery_cache_key_uses_indexed_alias_component_scope(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"MZ-indexed-alias")
    observed_sources: list[tuple[Path, ...]] = []

    def record_sources(paths: tuple[Path, ...]) -> str:
        observed_sources.append(paths)
        return "component-digest"

    monkeypatch.setattr(cache_module, "_cache_source_digest", record_sources)

    key = cache_module._recovery_cache_key(
        binary_path=binary,
        kind="indexed_global_object_layout",
        source_scope=RecoveryCacheSourceScope8616.INDEXED_ALIAS_PROGRAM,
    )

    assert key is not None
    assert observed_sources == [INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES]


def test_binary_cache_fingerprint_changes_for_same_size_and_mtime_content(tmp_path: Path):
    binary = tmp_path / "ARGS.EXE"
    binary.write_bytes(b"first-content")
    original_stat = binary.stat()
    first = _cache_file_fingerprint(binary)

    binary.write_bytes(b"other-content")
    os.utime(binary, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    second = _cache_file_fingerprint(binary)

    assert first is not None
    assert second is not None
    assert first["size"] == second["size"]
    assert first["mtime_ns"] == second["mtime_ns"]
    assert first["sha256"] != second["sha256"]


def test_binary_cache_fingerprint_reuses_one_stable_content_read(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"stable-content")
    original_stream_sha256 = cache_file_digest_module._stream_sha256_8616
    physical_reads: list[Path] = []

    def record_stream_sha256(stream):
        physical_reads.append(binary)
        return original_stream_sha256(stream)

    clear_cache_file_digest_memo_8616()
    monkeypatch.setattr(cache_file_digest_module, "_stream_sha256_8616", record_stream_sha256)
    try:
        first = _cache_file_fingerprint(binary)
        second = _cache_file_fingerprint(binary)
    finally:
        clear_cache_file_digest_memo_8616()

    assert first == second
    assert physical_reads == [binary]


def test_binary_cache_fingerprint_retries_content_mutation_during_read(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    first_content = b"first-content"
    final_content = b"other-content"
    binary.write_bytes(first_content)
    original_stat = binary.stat()
    original_stream_sha256 = cache_file_digest_module._stream_sha256_8616
    mutated = False

    def mutate_after_read(stream):
        nonlocal mutated
        sha256 = original_stream_sha256(stream)
        if not mutated:
            mutated = True
            binary.write_bytes(final_content)
            os.utime(binary, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        return sha256

    clear_cache_file_digest_memo_8616()
    monkeypatch.setattr(cache_file_digest_module, "_stream_sha256_8616", mutate_after_read)
    try:
        fingerprint = _cache_file_fingerprint(binary)
    finally:
        clear_cache_file_digest_memo_8616()

    assert fingerprint is not None
    assert fingerprint["sha256"] == hashlib.sha256(final_content).hexdigest()


def test_function_cache_key_reuses_equivalent_binary_at_different_paths(tmp_path: Path):
    first_path = tmp_path / "first" / "SORTD.EXE"
    second_path = tmp_path / "second" / "SORTD.EXE"
    first_path.parent.mkdir()
    second_path.parent.mkdir()
    first_path.write_bytes(b"same-binary")
    second_path.write_bytes(b"same-binary")

    key_args = {
        "function_addr": 0x102E0,
        "active_function_addr": 0x102E0,
        "recovery_addr": None,
        "function_name": "sub_102e0",
        "api_style": "pascal",
        "c_target": "portable-flat",
        "sidecar_metadata_digest": None,
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }
    first_key = cache_module._function_decompilation_cache_key(binary_path=first_path, **key_args)
    second_key = cache_module._function_decompilation_cache_key(binary_path=second_path, **key_args)

    assert first_key == second_key


def test_function_cache_key_separates_semantic_runtime_modes(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")
    key_args = {
        "binary_path": binary,
        "function_addr": 0x102E0,
        "active_function_addr": 0x102E0,
        "recovery_addr": None,
        "function_name": "RunMenu",
        "api_style": "pascal",
        "c_target": "portable-flat",
        "sidecar_metadata_digest": None,
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }

    monkeypatch.delenv("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS", raising=False)
    normal_key = cache_module._function_decompilation_cache_key(**key_args)
    monkeypatch.setenv("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS", "1")
    typed_switch_key = cache_module._function_decompilation_cache_key(**key_args)

    assert normal_key is not None
    assert typed_switch_key is not None
    assert normal_key != typed_switch_key


def test_function_cache_key_ignores_non_semantic_runtime_environment(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")
    key_args = {
        "binary_path": binary,
        "function_addr": 0x102E0,
        "active_function_addr": 0x102E0,
        "recovery_addr": None,
        "function_name": "RunMenu",
        "api_style": "pascal",
        "c_target": "portable-flat",
        "sidecar_metadata_digest": None,
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }
    monkeypatch.setenv("INERTIA_SERIAL_CLEAN_WORKER_RESULT", str(tmp_path / "first.json"))
    monkeypatch.setenv("INERTIA_ARCH_GUARD_VERIFIED_PARENT_PID", "100")
    monkeypatch.setenv("INERTIA_ALLOW_PARALLEL_MSC6_WORKERS", "0")
    monkeypatch.setenv("INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE", "1.5")
    monkeypatch.setenv("INERTIA_OTEL_EXPORT_OTLP", "0")
    monkeypatch.setenv("INERTIA_CORE_CPROFILE_PATH", str(tmp_path / "first.prof"))
    monkeypatch.setenv("INERTIA_DECOMPILE_VENV", "0")
    monkeypatch.setenv("INERTIA_DISABLE_TIMING", "0")
    monkeypatch.setenv("INERTIA_INDEXED_ALIAS_WORKERS", "1")
    first_key = cache_module._function_decompilation_cache_key(**key_args)
    monkeypatch.setenv("INERTIA_SERIAL_CLEAN_WORKER_RESULT", str(tmp_path / "second.json"))
    monkeypatch.setenv("INERTIA_ARCH_GUARD_VERIFIED_PARENT_PID", "200")
    monkeypatch.setenv("INERTIA_ALLOW_PARALLEL_MSC6_WORKERS", "1")
    monkeypatch.setenv("INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE", "4")
    monkeypatch.setenv("INERTIA_OTEL_EXPORT_OTLP", "1")
    monkeypatch.setenv("INERTIA_CORE_CPROFILE_PATH", str(tmp_path / "second.prof"))
    monkeypatch.setenv("INERTIA_DECOMPILE_VENV", "1")
    monkeypatch.setenv("INERTIA_DISABLE_TIMING", "1")
    monkeypatch.setenv("INERTIA_INDEXED_ALIAS_WORKERS", "3")
    second_key = cache_module._function_decompilation_cache_key(**key_args)

    assert first_key is not None
    assert second_key is not None
    assert first_key == second_key


def test_function_cache_key_ignores_sidecar_flag_only_without_sidecar_evidence(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")
    key_args = {
        "binary_path": binary,
        "function_addr": 0x102E0,
        "active_function_addr": 0x102E0,
        "recovery_addr": None,
        "function_name": "RunMenu",
        "api_style": "pascal",
        "c_target": "portable-flat",
        "sidecar_metadata_digest": None,
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }

    monkeypatch.delenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", raising=False)
    no_sidecar_default_key = cache_module._function_decompilation_cache_key(**key_args)
    monkeypatch.setenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", "1")
    no_sidecar_ignored_key = cache_module._function_decompilation_cache_key(**key_args)

    assert no_sidecar_default_key == no_sidecar_ignored_key

    binary.with_suffix(".COD").write_text("sidecar evidence", encoding="ascii")
    sidecar_ignored_key = cache_module._function_decompilation_cache_key(**key_args)
    monkeypatch.delenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616")
    sidecar_default_key = cache_module._function_decompilation_cache_key(**key_args)

    assert sidecar_ignored_key is not None
    assert sidecar_default_key is not None
    assert sidecar_ignored_key != sidecar_default_key


def test_recovery_cache_key_ignores_sidecar_flag_only_without_sidecars(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")

    monkeypatch.delenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", raising=False)
    no_sidecar_default_key = cache_module._recovery_cache_key(
        binary_path=binary,
        kind="direct_addr_work",
        extra={"addr": 0x102E0, "ignore_local_sidecar_hints": False},
    )
    monkeypatch.setenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", "1")
    no_sidecar_ignored_key = cache_module._recovery_cache_key(
        binary_path=binary,
        kind="direct_addr_work",
        extra={"addr": 0x102E0, "ignore_local_sidecar_hints": True},
    )

    assert no_sidecar_default_key == no_sidecar_ignored_key

    binary.with_suffix(".COD").write_text("sidecar evidence", encoding="ascii")
    sidecar_ignored_key = cache_module._recovery_cache_key(
        binary_path=binary,
        kind="direct_addr_work",
        extra={"addr": 0x102E0, "ignore_local_sidecar_hints": True},
    )
    monkeypatch.delenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616")
    sidecar_default_key = cache_module._recovery_cache_key(
        binary_path=binary,
        kind="direct_addr_work",
        extra={"addr": 0x102E0, "ignore_local_sidecar_hints": False},
    )

    assert sidecar_ignored_key is not None
    assert sidecar_default_key is not None
    assert sidecar_ignored_key != sidecar_default_key


def test_function_cache_key_separates_compiler_targets(tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")
    key_args = {
        "binary_path": binary,
        "function_addr": 0x102E0,
        "active_function_addr": 0x102E0,
        "recovery_addr": None,
        "function_name": "RunMenu",
        "api_style": "pascal",
        "sidecar_metadata_digest": None,
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }

    portable_key = cache_module._function_decompilation_cache_key(c_target="portable-flat", **key_args)
    msc_key = cache_module._function_decompilation_cache_key(c_target="msc-dos", **key_args)

    assert portable_key is not None
    assert msc_key is not None
    assert portable_key != msc_key


def test_function_cache_key_separates_recovery_and_sidecar_identity(tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")
    key_args = {
        "binary_path": binary,
        "function_addr": 0x11000,
        "active_function_addr": 0x1000,
        "function_name": "RunMenu",
        "api_style": "pascal",
        "c_target": "portable-flat",
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }

    base_key = cache_module._function_decompilation_cache_key(
        recovery_addr=0x11000,
        sidecar_metadata_digest=None,
        **key_args,
    )
    different_recovery_key = cache_module._function_decompilation_cache_key(
        recovery_addr=0x11010,
        sidecar_metadata_digest=None,
        **key_args,
    )
    sidecar_key = cache_module._function_decompilation_cache_key(
        recovery_addr=0x11000,
        sidecar_metadata_digest="metadata-sha256",
        **key_args,
    )

    assert base_key is not None
    assert different_recovery_key is not None
    assert sidecar_key is not None
    assert base_key != different_recovery_key
    assert base_key != sidecar_key


def test_cache_json_store_replaces_final_path_atomically(monkeypatch, tmp_path: Path):
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", cache_dir)
    replacements: list[tuple[Path, Path]] = []
    original_replace = cache_module.os.replace

    def record_replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        replacements.append((Path(source), Path(destination)))
        original_replace(source, destination)

    monkeypatch.setattr(cache_module.os, "replace", record_replace)
    key = {"binary": "SORTD.EXE", "addr": 0x10060}

    cache_module._store_cache_json("function_decompile", key, {"status": "ok", "payload": "return 0;"})

    assert len(replacements) == 1
    source, destination = replacements[0]
    assert destination == cache_module._cache_json_path("function_decompile", key)
    assert source.parent == destination.parent
    assert not source.exists()
    assert cache_module._load_cache_json("function_decompile", key) == {"status": "ok", "payload": "return 0;"}


def test_cache_key_lock_is_removed_after_producer_finishes(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    key = {"binary": "SORTD.EXE", "addr": 0x102E0}
    lock_path = cache_module._cache_json_path("function_decompile", key).with_suffix(".lock")

    with cache_module._cache_key_lock("function_decompile", key):
        assert lock_path.exists()
    assert not lock_path.exists()

    with cache_module._cache_key_lock("function_decompile", key):
        assert lock_path.exists()


def test_cache_key_lock_times_out_when_another_producer_holds_it(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    key = {"binary": "SORTD.EXE", "addr": 0x102E0}
    lock_path = cache_module._cache_json_path("function_decompile", key).with_suffix(".lock")
    lock_path.parent.mkdir(parents=True)
    lock_path.write_text("other-process\n", encoding="ascii")

    with pytest.raises(TimeoutError, match="cache key lock"):  # noqa: SIM117
        with cache_module._cache_key_lock("function_decompile", key, timeout_seconds=0.1):
            raise AssertionError("lock unexpectedly acquired")
