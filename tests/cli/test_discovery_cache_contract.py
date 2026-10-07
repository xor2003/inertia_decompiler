from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from inertia.semantics.caller_return_use_contracts import (
    AxValueView8616,
    ByteReturnExtensionKind8616,
)
from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
    caller_return_use_evidence_by_addr_8616,
    record_caller_return_use_evidence_8616,
)

import inertia.cli.cache as recovery_cache
import inertia.cli.cli_function_discovery as function_discovery
from inertia.cli.cli_function_discovery import (
    DisplayCatalogCachePolicy8616,
    SourceRegionCatalogEvidence8616,
    _configure_display_catalog_cache_policy_8616,
    _load_catalog_address_cache,
    _recover_cached_function_pairs,
    _source_region_catalog_evidence_8616,
    _store_catalog_address_cache,
    _store_catalog_address_cache_addrs_8616,
    record_direct_target_caller_return_use_evidence_8616,
)
from inertia.cli.discovery_cache_contract import (
    caller_return_use_evidence_record_8616,
    display_catalog_cache_payload_from_record_8616,
    display_catalog_cache_record_8616,
    source_region_catalog_evidence_comment_8616,
)


def _cache_policy() -> DisplayCatalogCachePolicy8616:
    return DisplayCatalogCachePolicy8616.from_runtime(
        ignore_local_sidecar_hints=False,
        include_library_functions=False,
        function_discovery_backend="auto",
        pat_backend="auto",
        max_functions=0,
        timeout=8,
        window=0x400,
        rizin_timeout=8,
        low_memory=False,
        auto_rizin_policy="default",
        signature_catalog=None,
    )


def _return_use_evidence() -> CallerReturnUseEvidence8616:
    return CallerReturnUseEvidence8616(
        target_addr=0x10560,
        verdict=CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=1,
        callsite_addrs=(0x1010, 0x1040),
        excluded_callsite_count=1,
        facts=(
            CallerReturnUseFact8616(
                0x1000,
                0x1010,
                CallerReturnUseVerdict8616.UNUSED,
                CallsiteReturnUseKind8616.CLOBBERED,
                0x1013,
                byte_extension=ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX,
                byte_extension_instruction_addr=0x1011,
                observed_value_view=AxValueView8616.AX,
            ),
            CallerReturnUseFact8616(
                0x1000,
                0x1040,
                CallerReturnUseVerdict8616.UNKNOWN,
                CallsiteReturnUseKind8616.FUNCTION_RETURN,
                0x1043,
                True,
            ),
        ),
    )


def _evidence_digest(project: object) -> str:
    records = [
        {
            "function_addr": addr,
            "evidence": caller_return_use_evidence_record_8616(evidence),
        }
        for addr, evidence in sorted(caller_return_use_evidence_by_addr_8616(project).items())
    ]
    return hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()


def test_display_catalog_cache_restores_exact_discovery_evidence(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    source_project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    destination_project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    pair = (SimpleNamespace(), SimpleNamespace(addr=0x10560))
    source_region = SourceRegionCatalogEvidence8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        failed_addrs=(),
    )
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    evidence = _return_use_evidence()
    record_caller_return_use_evidence_8616(source_project, evidence.target_addr, evidence)
    source_project._inertia_source_region_catalog_evidence = source_region
    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "discovery-digest")
    _configure_display_catalog_cache_policy_8616(source_project, _cache_policy())
    _configure_display_catalog_cache_policy_8616(destination_project, _cache_policy())

    _store_catalog_address_cache(source_project, binary, [pair])

    assert _load_catalog_address_cache(destination_project, binary) == [0x10560]
    assert caller_return_use_evidence_by_addr_8616(destination_project) == {0x10560: evidence}
    assert _source_region_catalog_evidence_8616(destination_project) == source_region
    assert _evidence_digest(destination_project) == _evidence_digest(source_project)


def test_cached_function_recovery_reemits_exact_discovery_evidence(monkeypatch, capsys, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    evidence = SourceRegionCatalogEvidence8616(1, 1, 1, 1, 0, ())
    project = SimpleNamespace(
        entry=0x1100,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=str(binary), linked_base=0x1000, max_addr=0x1200),
        ),
        _inertia_source_region_catalog_evidence=evidence,
    )
    pair = (SimpleNamespace(), SimpleNamespace(addr=0x10560))
    monkeypatch.setattr(function_discovery, "_recover_candidate_with_timeout", lambda *_args, **_kwargs: pair)
    monkeypatch.setattr(function_discovery, "_function_skip_reason", lambda _function: None)

    assert _recover_cached_function_pairs(project, addrs=[0x10560], timeout=2, limit=1) == [pair]
    assert source_region_catalog_evidence_comment_8616(evidence) in capsys.readouterr().out


def test_direct_target_reuses_closed_display_catalog_evidence(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    source_project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    destination_project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    pair = (SimpleNamespace(), SimpleNamespace(addr=0x10560))
    evidence = _return_use_evidence()
    record_caller_return_use_evidence_8616(source_project, evidence.target_addr, evidence)
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "discovery-digest")
    _configure_display_catalog_cache_policy_8616(source_project, _cache_policy())
    _configure_display_catalog_cache_policy_8616(destination_project, _cache_policy())
    _store_catalog_address_cache(source_project, binary, [pair])

    restored = record_direct_target_caller_return_use_evidence_8616(
        destination_project,
        evidence.target_addr,
        binary_path=binary,
    )

    assert restored == evidence
    assert caller_return_use_evidence_by_addr_8616(destination_project) == {
        evidence.target_addr: evidence,
    }


def test_direct_target_publishes_collected_evidence(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace()
    evidence = _return_use_evidence()
    stored: list[tuple[int, ...]] = []
    monkeypatch.setattr(function_discovery, "_load_catalog_address_cache", lambda *_args: [])
    monkeypatch.setattr(
        function_discovery,
        "isolated_discovery_evidence_project_8616",
        lambda source: source,
    )
    monkeypatch.setattr(
        function_discovery,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda _project: [evidence.target_addr],
    )
    monkeypatch.setattr(
        function_discovery,
        "_binary_padding_entry_aliases_8616",
        lambda _project, address: (address,),
    )
    monkeypatch.setattr(
        function_discovery,
        "_pre_entry_source_function_ranges_8616",
        lambda *_args: ((0x1000, 0x1010),),
    )
    monkeypatch.setattr(
        function_discovery,
        "_collect_caller_return_use_for_entry_aliases_8616",
        lambda *_args: evidence,
    )
    monkeypatch.setattr(
        function_discovery,
        "_store_catalog_address_cache_addrs_8616",
        lambda _project, _binary, addrs: stored.append(addrs),
    )

    result = record_direct_target_caller_return_use_evidence_8616(
        project,
        evidence.target_addr,
        binary_path=binary,
    )

    assert result == evidence
    assert stored == [(evidence.target_addr,)]
    assert caller_return_use_evidence_by_addr_8616(project) == {
        evidence.target_addr: evidence,
    }


def test_catalog_store_merges_independent_target_evidence(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    first_project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    second_project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    destination_project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    first = _return_use_evidence()
    second = replace(first, target_addr=0x10570)
    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "discovery-digest")
    for project in (first_project, second_project, destination_project):
        _configure_display_catalog_cache_policy_8616(project, _cache_policy())
    record_caller_return_use_evidence_8616(first_project, first.target_addr, first)
    record_caller_return_use_evidence_8616(second_project, second.target_addr, second)

    _store_catalog_address_cache_addrs_8616(first_project, binary, (first.target_addr,))
    _store_catalog_address_cache_addrs_8616(second_project, binary, (second.target_addr,))

    assert _load_catalog_address_cache(destination_project, binary) == [
        first.target_addr,
        second.target_addr,
    ]
    assert caller_return_use_evidence_by_addr_8616(destination_project) == {
        first.target_addr: first,
        second.target_addr: second,
    }


def test_display_catalog_cache_refuses_legacy_address_only_payload(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "discovery-digest")
    _configure_display_catalog_cache_policy_8616(project, _cache_policy())
    from inertia.cli.cli_function_discovery import _catalog_address_cache_key_8616

    cache_key = _catalog_address_cache_key_8616(project, binary)
    assert cache_key is not None
    recovery_cache._store_cache_json("recovery", cache_key, {"addrs": [0x10560]})

    assert _load_catalog_address_cache(project, binary) == []
    assert caller_return_use_evidence_by_addr_8616(project) == {}


def test_display_catalog_cache_refuses_unclosed_caller_evidence():
    evidence = _return_use_evidence()
    record = display_catalog_cache_record_8616((0x10560,), {0x10560: evidence}, None)
    caller_records = record["caller_return_use"]
    assert isinstance(caller_records, list)
    evidence_record = caller_records[0]["evidence"]
    assert isinstance(evidence_record, dict)
    evidence_record["unused_callsite_count"] = 0

    with pytest.raises(ValueError, match="classifications do not close"):
        display_catalog_cache_payload_from_record_8616(record)


def test_display_catalog_cache_refuses_unmaterialized_classified_evidence():
    evidence = _return_use_evidence()
    record = display_catalog_cache_record_8616((0x10560,), {0x10560: evidence}, None)
    caller_records = record["caller_return_use"]
    assert isinstance(caller_records, list)
    evidence_record = caller_records[0]["evidence"]
    assert isinstance(evidence_record, dict)
    evidence_record["materialized_count"] = 0

    with pytest.raises(ValueError, match="materialized facts do not close"):
        display_catalog_cache_payload_from_record_8616(record)


def test_display_catalog_cache_refuses_counter_only_caller_evidence() -> None:
    """Raw caller facts must survive the persistence boundary as typed facts."""
    evidence = _return_use_evidence()
    record = display_catalog_cache_record_8616((0x10560,), {0x10560: evidence}, None)
    caller_records = record["caller_return_use"]
    assert isinstance(caller_records, list)
    evidence_record = caller_records[0]["evidence"]
    assert isinstance(evidence_record, dict)
    evidence_record["facts"] = []

    with pytest.raises(ValueError, match="retained facts do not close"):
        display_catalog_cache_payload_from_record_8616(record)
