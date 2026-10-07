from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)

import inertia.cli.cache as cache_module
from inertia.widening.global_object_layout import (
    DirectGlobalObjectLayout8616,
    DirectGlobalObjectLayoutEvidence8616,
)
from inertia.cli.cache_source_manifest import (
    DIRECT_GLOBAL_OBJECT_CACHE_SOURCE_FILES,
    INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES,
    RecoveryCacheSourceScope8616,
)
from inertia.cli.direct_global_object_cache import (
    DIRECT_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
    direct_global_object_cache_key_8616,
    load_direct_global_object_cache_8616,
    store_direct_global_object_cache_8616,
)
from inertia.cli.project_evidence_transport import (
    transfer_project_evidence_8616,
)


def _project(code: bytes) -> angr.Project:
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )


def _evidence() -> DirectGlobalObjectLayoutEvidence8616:
    return DirectGlobalObjectLayoutEvidence8616(
        layouts=(
            DirectGlobalObjectLayout8616(
                address=IRAddress(
                    space=MemSpace.DS,
                    offset=0x0B4C,
                    size=4,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
                proof_function_addrs=(0x109E8,),
            ),
        ),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def test_direct_global_cache_round_trips_closed_evidence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    binary_path = tmp_path / "fixture.exe"
    binary_path.write_bytes(b"direct-global-cache")
    cache_key = direct_global_object_cache_key_8616(
        _project(b"\x90\xc3"),
        binary_path,
    )
    assert cache_key is not None

    store_direct_global_object_cache_8616(cache_key, _evidence())

    assert load_direct_global_object_cache_8616(cache_key) == _evidence()


def test_direct_global_cache_refuses_malformed_accounting(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    cache_key = {"key": "malformed"}
    cache_module._store_cache_json(
        DIRECT_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
        cache_key,
        {
            "schema": 1,
            "evidence": {
                "schema": 1,
                "layouts": [],
                "counts": {
                    "raw": 1,
                    "normalized": 1,
                    "classified": 1,
                    "materialized": 0,
                    "failure": 0,
                },
            },
        },
    )

    assert load_direct_global_object_cache_8616(cache_key) is None


def test_direct_global_cache_uses_independent_source_scope(
    monkeypatch,
    tmp_path: Path,
) -> None:
    binary_path = tmp_path / "fixture.exe"
    binary_path.write_bytes(b"direct-global-scope")
    observed_sources: list[tuple[Path, ...]] = []

    def record_sources(paths: tuple[Path, ...]) -> str:
        observed_sources.append(paths)
        return "component-digest"

    monkeypatch.setattr(cache_module, "_cache_source_digest", record_sources)

    key = cache_module._recovery_cache_key(
        binary_path=binary_path,
        kind=DIRECT_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
        source_scope=RecoveryCacheSourceScope8616.DIRECT_GLOBAL_OBJECT,
    )

    direct_paths = {
        path.relative_to(Path(__file__).resolve().parents[2]).as_posix()
        for path in DIRECT_GLOBAL_OBJECT_CACHE_SOURCE_FILES
    }
    indexed_paths = {
        path.relative_to(Path(__file__).resolve().parents[2]).as_posix()
        for path in INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES
    }
    assert key is not None
    assert observed_sources == [DIRECT_GLOBAL_OBJECT_CACHE_SOURCE_FILES]
    assert "inertia/lowering/segmented_global_loads.py" in direct_paths
    assert "inertia/widening/direct_global_object_layout_codec.py" in direct_paths
    assert "inertia/lowering/register_local_declarations.py" not in direct_paths
    assert "inertia/lowering/segmented_global_loads.py" not in indexed_paths
    assert "inertia/widening/direct_global_object_layout_codec.py" not in indexed_paths


def test_project_transport_copies_direct_global_evidence() -> None:
    evidence = _evidence()
    source = SimpleNamespace(
        arch=SimpleNamespace(_inertia_stack_probe_helper_targets_8616=frozenset()),
        _inertia_project_direct_global_object_layout_evidence_8616=evidence,
    )
    destination = SimpleNamespace(
        arch=SimpleNamespace(_inertia_stack_probe_helper_targets_8616=frozenset())
    )

    result = transfer_project_evidence_8616(source, destination)

    assert result.direct_global_object_layout_artifact_count == 1
    assert destination._inertia_project_direct_global_object_layout_evidence_8616 is evidence
