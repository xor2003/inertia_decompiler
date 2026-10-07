from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

import inertia.cli.cache as recovery_cache
import inertia.cli.cli_function_discovery as function_discovery
from inertia.cli.cli_function_discovery import (
    DisplayCatalogCachePolicy8616,
    _configure_display_catalog_cache_policy_8616,
    _derive_lst_exact_region_8616,
    _load_catalog_address_cache,
    _should_replace_function_with_stitched_graph_8616,
    _store_catalog_address_cache,
)
from inertia.cli.lst_extract import LSTMetadata


class _Memory:
    def __init__(self, data: bytes, base: int):
        self._data = data
        self._base = base

    def load(self, addr: int, size: int) -> bytes:
        start = addr - self._base
        return self._data[start : start + size]


def _display_cache_policy() -> DisplayCatalogCachePolicy8616:
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


def test_display_catalog_cache_isolated_by_sidecar_policy(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    pair = (SimpleNamespace(), SimpleNamespace(addr=0x1010))
    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "discovery-digest")

    default_policy = _display_cache_policy()
    _configure_display_catalog_cache_policy_8616(project, default_policy)
    _store_catalog_address_cache(project, binary, [pair])
    assert _load_catalog_address_cache(project, binary) == [0x1010]

    ignored_sidecar_policy = replace(default_policy, ignore_local_sidecar_hints=True)
    _configure_display_catalog_cache_policy_8616(project, ignored_sidecar_policy)
    assert _load_catalog_address_cache(project, binary) == []


def test_recovery_cache_fingerprints_discovery_implementation():
    names = {path.name for path in recovery_cache.RECOVERY_CACHE_SOURCE_FILES}

    assert "cli_core.py" in names
    assert "cli_function_discovery.py" in names


def test_seed_priority_prefers_strong_candidate_in_startup_source_region():
    common = {
        "project_entry": 0x1100,
        "bounded_metadata_spans": {},
        "near_call_targets": {0x1050, 0x1150},
        "far_call_targets": set(),
        "tracer_call_targets": {0x1050, 0x1150},
        "prologue_targets": {0x1050, 0x1150},
        "terminal_next_targets": set(),
        "neighbor_targets": set(),
        "entry_window_targets": {0x1000},
        "relocation_control_targets": set(),
        "relocation_pointer_targets": set(),
        "source_region_start": 0x1000,
    }

    source_priority = function_discovery._final_seed_priority_8616(addr=0x1050, distance=0xB0, **common)
    runtime_priority = function_discovery._final_seed_priority_8616(addr=0x1150, distance=0x50, **common)

    assert source_priority is not None
    assert runtime_priority is not None
    assert source_priority < runtime_priority


def test_fast_catalog_prefers_complete_pre_entry_source_evidence(monkeypatch):
    project = SimpleNamespace(
        entry=0x1100,
        arch=SimpleNamespace(name="86_16"),
        _inertia_include_library_functions=False,
    )
    source_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=0x1000)),
        (SimpleNamespace(), SimpleNamespace(addr=0x1050)),
    ]
    evidence = function_discovery.SourceRegionCatalogEvidence8616(
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        failed_addrs=(),
    )
    monkeypatch.setattr(
        function_discovery,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda _project: [0x1000, 0x1050],
    )
    monkeypatch.setattr(
        function_discovery,
        "_recover_pre_entry_source_catalog_8616",
        lambda *_args, **_kwargs: (source_pairs, evidence),
    )
    monkeypatch.setattr(
        function_discovery,
        "_fallback_entry_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("runtime entry should stay hidden")),
    )
    monkeypatch.setattr(
        function_discovery,
        "_rank_function_cfg_pairs_for_display",
        lambda _project, pairs: pairs,
    )

    recovered = function_discovery._recover_fast_exe_catalog(
        project,
        timeout=30,
        window=0x200,
        low_memory=False,
        limit=None,
    )

    assert recovered == source_pairs
    assert function_discovery._source_region_catalog_evidence_8616(project) == evidence


@pytest.mark.parametrize(
    "recoverable_error",
    [function_discovery._AnalysisTimeout, function_discovery.FuturesTimeoutError, KeyError],
)
def test_source_catalog_retries_only_failed_classified_entries(
    monkeypatch, tmp_path, recoverable_error
):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x1100,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=0x1200,
            )
        ),
    )
    attempts: dict[int, int] = {}
    exact_regions: dict[int, tuple[int, int] | None] = {}
    recovered_functions: dict[int, SimpleNamespace] = {}

    def recover_candidate(_project, *, candidate_addr, exact_region=None, **_kwargs):
        attempts[candidate_addr] = attempts.get(candidate_addr, 0) + 1
        exact_regions[candidate_addr] = exact_region
        if candidate_addr == 0x1050 and attempts[candidate_addr] == 1:
            raise recoverable_error
        function = SimpleNamespace(addr=candidate_addr)
        recovered_functions[candidate_addr] = function
        return SimpleNamespace(), function

    monkeypatch.setattr(function_discovery, "_recover_candidate_with_timeout", recover_candidate)

    recovered, evidence = function_discovery._recover_pre_entry_source_catalog_8616(
        project,
        source_seeds=[0x1000, 0x1050],
        timeout=10,
        per_function_timeout=2,
    )

    assert [function.addr for _cfg, function in recovered] == [0x1000, 0x1050]
    assert attempts == {0x1000: 1, 0x1050: 2}
    assert exact_regions == {0x1000: (0x1000, 0x1050), 0x1050: (0x1050, 0x1100)}
    assert function_discovery._function_binary_exact_region_8616(recovered_functions[0x1000]) == (
        0x1000,
        0x1050,
    )
    assert function_discovery._function_binary_exact_region_8616(recovered_functions[0x1050]) == (
        0x1050,
        0x1100,
    )
    assert evidence.complete is True
    assert evidence.failed_addrs == ()


def test_source_catalog_does_not_silence_unexpected_candidate_error(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x1100,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(binary=binary, linked_base=0x1000, max_addr=0x1200)
        ),
    )

    def recover_candidate(_project, **_kwargs):
        raise RuntimeError("candidate defect")

    monkeypatch.setattr(function_discovery, "_recover_candidate_with_timeout", recover_candidate)

    with pytest.raises(RuntimeError, match="candidate defect"):
        function_discovery._recover_pre_entry_source_catalog_8616(
            project,
            source_seeds=[0x1000],
            timeout=10,
            per_function_timeout=2,
        )


@pytest.mark.parametrize(
    "recoverable_error",
    [function_discovery._AnalysisTimeout, function_discovery.FuturesTimeoutError, KeyError],
)
def test_cached_candidate_refuses_only_known_recovery_errors(monkeypatch, recoverable_error):
    def recover_candidate(_project, **_kwargs):
        raise recoverable_error

    monkeypatch.setattr(function_discovery, "_recover_candidate_with_timeout", recover_candidate)

    assert function_discovery._recover_cached_pair_once_8616(
        SimpleNamespace(entry=0x1100),
        0x1000,
        image_end=0x1200,
        metadata=None,
        region_span=0x100,
        candidate_timeout=2,
        binary_path="sample.exe",
        linked_base=0x1000,
    ) is None


def test_cached_candidate_does_not_silence_unexpected_error(monkeypatch):
    def recover_candidate(_project, **_kwargs):
        raise RuntimeError("cached candidate defect")

    monkeypatch.setattr(function_discovery, "_recover_candidate_with_timeout", recover_candidate)

    with pytest.raises(RuntimeError, match="cached candidate defect"):
        function_discovery._recover_cached_pair_once_8616(
            SimpleNamespace(entry=0x1100),
            0x1000,
            image_end=0x1200,
            metadata=None,
            region_span=0x100,
            candidate_timeout=2,
            binary_path="sample.exe",
            linked_base=0x1000,
        )


def test_binary_padding_entry_aliases_cover_nop_run_before_prologue():
    project = SimpleNamespace(
        loader=SimpleNamespace(
            memory=_Memory(b"\xc3" + b"\x90" * 5 + b"\x55\x8b\xec", 0x1000),
        ),
    )

    assert function_discovery._binary_padding_entry_aliases_8616(project, 0x1006) == (
        0x1001,
        0x1002,
        0x1003,
        0x1004,
        0x1005,
        0x1006,
    )


def test_binary_padding_entry_aliases_clamp_scan_to_mapped_image_start():
    class _StrictMemory(_Memory):
        def load(self, addr: int, size: int) -> bytes:
            if addr < self._base:
                raise KeyError(addr)
            return super().load(addr, size)

    project = SimpleNamespace(
        loader=SimpleNamespace(
            memory=_StrictMemory(b"\xc3" + b"\x90" * 3 + b"\x55\x8b\xec", 0x1000),
            main_object=SimpleNamespace(min_addr=0x1000),
        ),
    )

    assert function_discovery._binary_padding_entry_aliases_8616(project, 0x1004) == (
        0x1001,
        0x1002,
        0x1003,
        0x1004,
    )


def test_direct_target_records_caller_use_from_framed_source_catalog(monkeypatch):
    project = SimpleNamespace()
    evidence = function_discovery.CallerReturnUseEvidence8616(
        target_addr=0x1001,
        verdict=function_discovery.CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=2,
        callsite_addrs=(0x1080, 0x1090),
    )
    collect_calls: list[
        tuple[tuple[int, ...], tuple[tuple[int, int], ...]]
    ] = []
    aliases_by_seed = {
        0x1004: (0x1001, 0x1002, 0x1003, 0x1004),
        0x1050: (0x1050,),
    }
    monkeypatch.setattr(
        function_discovery,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda _project: [0x1004, 0x1050],
    )
    monkeypatch.setattr(
        function_discovery,
        "_binary_padding_entry_aliases_8616",
        lambda _project, seed: aliases_by_seed[seed],
    )
    monkeypatch.setattr(
        function_discovery,
        "_pre_entry_source_function_ranges_8616",
        lambda _project, _seeds: ((0x1001, 0x1050), (0x1050, 0x1100)),
    )

    def collect(
        _project: object,
        aliases: tuple[int, ...],
        ranges: tuple[tuple[int, int], ...],
    ) -> function_discovery.CallerReturnUseEvidence8616:
        collect_calls.append((aliases, ranges))
        return evidence

    monkeypatch.setattr(
        function_discovery,
        "_collect_caller_return_use_for_entry_aliases_8616",
        collect,
    )

    result = function_discovery.record_direct_target_caller_return_use_evidence_8616(
        project,
        0x1004,
    )

    assert result is not None
    assert result.target_addr == 0x1004
    assert collect_calls == [
        (
            (0x1001, 0x1002, 0x1003, 0x1004),
            ((0x1001, 0x1050), (0x1050, 0x1100)),
        )
    ]
    records = function_discovery.caller_return_use_evidence_by_addr_8616(project)
    assert set(records) == {0x1001, 0x1002, 0x1003, 0x1004}
    assert records[0x1004].target_addr == 0x1004

    repeated = function_discovery.record_direct_target_caller_return_use_evidence_8616(
        project,
        0x1004,
    )
    assert repeated == records[0x1004]
    assert len(collect_calls) == 1


def test_external_direct_target_uses_framed_application_callers(monkeypatch):
    project = SimpleNamespace()
    evidence = function_discovery.CallerReturnUseEvidence8616(
        target_addr=0x2200,
        verdict=function_discovery.CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=1,
        callsite_addrs=(0x1080,),
    )
    collect_calls: list[
        tuple[tuple[int, ...], tuple[tuple[int, int], ...]]
    ] = []
    monkeypatch.setattr(
        function_discovery,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda _project: [0x1000, 0x1100],
    )
    monkeypatch.setattr(
        function_discovery,
        "_binary_padding_entry_aliases_8616",
        lambda _project, seed: (seed,),
    )
    monkeypatch.setattr(
        function_discovery,
        "_pre_entry_source_function_ranges_8616",
        lambda _project, _seeds: ((0x1000, 0x1100), (0x1100, 0x1200)),
    )

    def collect(
        _project: object,
        aliases: tuple[int, ...],
        ranges: tuple[tuple[int, int], ...],
    ) -> function_discovery.CallerReturnUseEvidence8616:
        collect_calls.append((aliases, ranges))
        return evidence

    monkeypatch.setattr(
        function_discovery,
        "_collect_caller_return_use_for_entry_aliases_8616",
        collect,
    )

    result = function_discovery.record_direct_target_caller_return_use_evidence_8616(
        project,
        0x2200,
    )

    assert result == evidence
    assert collect_calls == [
        ((0x2200,), ((0x1000, 0x1100), (0x1100, 0x1200)))
    ]
    assert function_discovery.caller_return_use_evidence_by_addr_8616(project)[0x2200] == evidence


def test_entry_linear_caller_range_stops_at_first_return():
    instructions = (
        SimpleNamespace(address=0x1100, size=1, mnemonic="ret", bytes=b"\xc3"),
        SimpleNamespace(address=0x1101, size=3, mnemonic="call", bytes=b"\xe8\x0c\xff"),
        SimpleNamespace(address=0x1104, size=1, mnemonic="ret", bytes=b"\xc3"),
        SimpleNamespace(address=0x1105, size=3, mnemonic="call", bytes=b"\xe8\0\0"),
    )
    project = SimpleNamespace(
        entry=0x1100,
        arch=SimpleNamespace(
            capstone=SimpleNamespace(
                disasm=lambda _code, _addr: iter(instructions),
            ),
        ),
        loader=SimpleNamespace(memory=_Memory(b"\0" * 0x200, 0x1100)),
    )

    assert function_discovery._entry_linear_caller_range_8616(
        project,
        target_addrs=(0x1010,),
    ) == (
        0x1100,
        0x1105,
    )


def test_source_catalog_records_padding_alias_caller_return_evidence(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    image = b"\xc3" + b"\x90" * 3 + b"\x55\x8b\xec\xc3" + b"\x90" * 8
    project = SimpleNamespace(
        entry=0x1010,
        loader=SimpleNamespace(
            memory=_Memory(image, 0x1000),
            main_object=SimpleNamespace(
                binary=binary,
                linked_base=0x1000,
                max_addr=0x1000 + len(image) - 1,
            ),
        ),
    )
    recovered_function = SimpleNamespace(addr=0x1004)
    evidence = function_discovery.CallerReturnUseEvidence8616(
        target_addr=0x1001,
        verdict=function_discovery.CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=1,
        callsite_addrs=(0x1008,),
    )
    observed_aliases: list[tuple[int, ...]] = []
    observed_ranges: list[tuple[tuple[int, int], ...]] = []
    recorded: list[tuple[int, object]] = []
    monkeypatch.setattr(
        function_discovery,
        "_recover_candidate_with_timeout",
        lambda *_args, **_kwargs: (SimpleNamespace(), recovered_function),
    )

    def collect(_project, aliases, ranges):
        observed_aliases.append(aliases)
        observed_ranges.append(ranges)
        return evidence

    monkeypatch.setattr(
        function_discovery,
        "_collect_caller_return_use_for_entry_aliases_8616",
        collect,
    )
    monkeypatch.setattr(
        function_discovery,
        "_record_caller_return_use_evidence_8616",
        lambda _project, addr, item: recorded.append((addr, item)),
    )

    function_discovery._recover_pre_entry_source_catalog_8616(
        project,
        source_seeds=[0x1004],
        timeout=2,
    )

    assert observed_aliases == [(0x1001, 0x1002, 0x1003, 0x1004)]
    assert observed_ranges == [((0x1001, 0x1010),)]
    assert recorded[0][0] == 0x1004
    assert recorded[0][1].target_addr == 0x1004


def test_derive_lst_exact_region_skips_leading_x86_16_padding_to_prologue():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "Func"},
        code_ranges={0x1000: (0x1000, 0x1019)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(max_addr=0x1018),
            memory=_Memory(b"\x90" * 0x15 + b"\x55\x8b\xec\xc3", 0x1000),
        ),
    )

    assert _derive_lst_exact_region_8616(project, metadata, addr=0x1000, name="Func") == (0x1015, 0x1019)


def test_derive_lst_exact_region_skips_long_sidecar_padding_to_prologue():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "Func"},
        code_ranges={0x1000: (0x1000, 0x1030)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(max_addr=0x102F),
            memory=_Memory(b"\x90" * 0x27 + b"\x55\x8b\xec\xc3" + b"\x90" * 5, 0x1000),
        ),
    )

    assert _derive_lst_exact_region_8616(project, metadata, addr=0x1000, name="Func") == (0x1027, 0x1030)


def test_recover_lst_function_keeps_callable_entry_for_rebased_return_use(monkeypatch):
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "Func"},
        code_ranges={0x1000: (0x1000, 0x1010)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(entry=0, arch=SimpleNamespace(name="86_16"))
    recovered = SimpleNamespace(name="recovered")
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        function_discovery,
        "_derive_lst_exact_region_8616",
        lambda *_args, **_kwargs: (0x1003, 0x1010),
    )

    def fake_rebased_recovery(_project, **kwargs):
        observed.update(kwargs)
        return recovered

    monkeypatch.setattr(
        function_discovery,
        "_try_rebased_exact_region_recovery_8616",
        fake_rebased_recovery,
    )

    result = function_discovery._recover_lst_function(
        project,
        metadata,
        0x1000,
        "Func",
        timeout=1,
        window=0x20,
    )

    assert result is recovered
    assert observed["exact_region"] == (0x1003, 0x1010)
    assert observed["caller_target_addrs"] == (0x1000,)


def test_recover_lst_function_passes_only_declared_procedure_ranges_to_rebased_analysis(monkeypatch):
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1000: "Func", 0x2000: "aMessage"},
        code_ranges={0x1000: (0x1000, 0x1010), 0x2000: (0x2000, 0x2080)},
        function_entry_addrs=frozenset({0x1000}),
        absolute_addrs=True,
    )
    project = SimpleNamespace(entry=0, arch=SimpleNamespace(name="86_16"))
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        function_discovery,
        "_derive_lst_exact_region_8616",
        lambda *_args, **_kwargs: (0x1000, 0x1010),
    )

    def fake_rebased_recovery(_project, **kwargs):
        observed.update(kwargs)
        return SimpleNamespace(name="recovered")

    monkeypatch.setattr(
        function_discovery,
        "_try_rebased_exact_region_recovery_8616",
        fake_rebased_recovery,
    )

    function_discovery._recover_lst_function(
        project,
        metadata,
        0x1000,
        "Func",
        timeout=1,
        window=0x20,
    )

    assert observed["function_ranges"] == ((0x1000, 0x1010),)


def test_recover_lst_function_keeps_label_alias_when_recovery_starts_after_padding(monkeypatch):
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x102CC: "RunMenu"},
        code_ranges={0x102CC: (0x102CC, 0x10491)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(entry=0, arch=SimpleNamespace(name="86_16"))
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        function_discovery,
        "_derive_lst_exact_region_8616",
        lambda *_args, **_kwargs: (0x102E0, 0x10491),
    )

    def fake_rebased_recovery(_project, **kwargs):
        observed.update(kwargs)
        return SimpleNamespace(name="recovered")

    monkeypatch.setattr(
        function_discovery,
        "_try_rebased_exact_region_recovery_8616",
        fake_rebased_recovery,
    )

    function_discovery._recover_lst_function(
        project,
        metadata,
        0x102E0,
        "RunMenu",
        timeout=1,
        window=0x200,
    )

    assert observed["caller_target_addrs"] == (0x102E0, 0x102CC)


def test_stitched_graph_replaces_overlapped_cfg_when_unique_coverage_is_preserved():
    current = SimpleNamespace(
        blocks=(
            SimpleNamespace(addr=0x1009, size=0x17),
            SimpleNamespace(addr=0x1010, size=0x10),
        )
    )
    reachable = {
        0x1009: SimpleNamespace(addr=0x1009, size=0x7, bytes=b"\x90" * 0x7),
        0x1010: SimpleNamespace(addr=0x1010, size=0x10, bytes=b"\x90" * 0x10),
    }

    assert _should_replace_function_with_stitched_graph_8616(current, reachable, (0x1009, 0x1020)) is True
