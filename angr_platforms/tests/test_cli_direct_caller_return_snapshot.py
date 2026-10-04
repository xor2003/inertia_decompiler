"""Direct-CLI caller-return evidence snapshot boundary regressions.

Layer: Tests.
Responsibility: prove the direct-address CLI binds one final caller-return
evidence snapshot for clean-worker lanes only after serial hydration,
selected-target recording, and fast-probe neighbor recording, and that the
snapshot stays isolated from later registry mutations. No semantic
classification is exercised here; this is typed metadata transport ordering.
"""

from __future__ import annotations

import typing
from pathlib import Path
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    caller_return_use_evidence_by_addr_8616,
    record_caller_return_use_evidence_8616,
)

from inertia_decompiler import cli_core
from inertia_decompiler.direct_request_cache import DirectRequestCacheVerdict8616
from inertia_decompiler.work_items import WorkItemStatus

_DIRECT_ADDR = 0x1234
_CANONICAL_ADDR = 0x1240
_HYDRATED_ADDR = 0x2000
_NEIGHBOR_ADDR = 0x3000
_LATE_ADDR = 0x4000


def _evidence(
    target_addr: int,
    verdict: CallerReturnUseVerdict8616 = CallerReturnUseVerdict8616.USED,
) -> CallerReturnUseEvidence8616:
    """Build one typed caller-use observation for a direct target."""
    return CallerReturnUseEvidence8616(
        target_addr=target_addr,
        verdict=verdict,
        raw_fact_count=0,
        normalized_fact_count=0,
        classified_fact_count=0,
        materialized_count=0,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=0,
        callsite_addrs=(),
    )


def _drive_parts_0_to_3(
    monkeypatch: pytest.MonkeyPatch,
    *,
    rebased_project: bool,
    hydrated: dict[int, CallerReturnUseEvidence8616],
    selected: CallerReturnUseEvidence8616,
    neighbor: CallerReturnUseEvidence8616,
) -> tuple[cli_core._DirectAddrCliRun8616, object, list[tuple[object, int]]]:
    """Drive the real part0-part3 phase API against a narrow mocked boundary.

    Third-party project/function surfaces are SimpleNamespaces; heavy recovery,
    sidecar canonicalization, and worker emission stay mocked while hydration,
    the project evidence registry, the fast-probe phase, and the
    project-to-project transfer remain real.
    """
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"), entry=0x100)
    func = SimpleNamespace(addr=_DIRECT_ADDR, name="probe")
    if rebased_project:
        func.project = SimpleNamespace(arch=SimpleNamespace(name="86_16"), entry=0x100)
    args = SimpleNamespace(
        addr=_DIRECT_ADDR,
        timeout=30,
        binary=Path("TEST.EXE"),
        window=0x400,
        show_asm=False,
        trace_c_stages=False,
        dump_layers=False,
        dump_layer_dir=None,
        dump_layer_filter=None,
        alternate_source_c=False,
        ignore_local_sidecar_hints=False,
    )
    context = SimpleNamespace(
        args=args,
        project=project,
        function_label="probe",
        cod_metadata=None,
        synthetic_globals=None,
        lst_metadata=SimpleNamespace(code_labels={}),
        prefer_fast_recovery=False,
        proc_resolved_to_linked_binary=False,
        low_memory_path=False,
        interactive_stdout=False,
        precise_sidecar_regions=False,
        timeout_was_explicit=True,
        request_cache_inputs=SimpleNamespace(),
    )
    run = cli_core._DirectAddrCliRun8616(
        context=typing.cast(cli_core._DirectAddrCliContext8616, context)
    )
    run.func = func
    run.cfg = SimpleNamespace()

    monkeypatch.delenv("INERTIA_FAST_DIRECT_PROBE", raising=False)
    monkeypatch.setattr(cli_core, "direct_request_cache_enabled_8616", lambda _args: False)
    monkeypatch.setattr(
        cli_core,
        "load_direct_request_cache_8616",
        lambda _inputs, *, enabled: SimpleNamespace(
            verdict=DirectRequestCacheVerdict8616.DISABLED,
        ),
    )
    monkeypatch.setattr(
        cli_core._DirectAddrCliRun8616, "_phase_direct_header_8616", lambda self: None
    )

    def fake_hydrate(proj: object) -> int:
        for addr, ev in hydrated.items():
            record_caller_return_use_evidence_8616(proj, addr, ev)
        return len(hydrated)

    monkeypatch.setattr(cli_core, "_hydrate_serial_clean_worker_evidence_8616", fake_hydrate)
    monkeypatch.setattr(
        cli_core,
        "_canonicalize_direct_addr_from_sidecar_padding_8616",
        lambda *_a, **_k: cli_core.DirectAddrCanonicalization8616(
            requested_addr=_DIRECT_ADDR,
            canonical_addr=_CANONICAL_ADDR,
            region=(0x1200, 0x1300),
            name="probe",
        ),
    )
    monkeypatch.setattr(
        cli_core._DirectAddrCliRun8616, "_phase_direct_cfg_recovery_8616", lambda self: None
    )
    monkeypatch.setattr(
        cli_core._DirectAddrCliRun8616, "_phase_direct_probe_setup_8616", lambda self: None
    )
    monkeypatch.setattr(
        cli_core._DirectAddrCliRun8616, "_phase_direct_catalog_8616", lambda self: None
    )
    monkeypatch.setattr(
        cli_core, "attach_direct_target_argument_evidence_context_8616", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        cli_core, "prepare_direct_indexed_alias_program_context_8616", lambda *_a, **_k: None
    )
    monkeypatch.setattr(cli_core, "function_original_addr", lambda f: f.addr)
    monkeypatch.setattr(
        cli_core,
        "collect_neighbor_call_targets",
        lambda _func: [SimpleNamespace(target_addr=_NEIGHBOR_ADDR, return_addr=0x3010)],
    )
    monkeypatch.setattr(cli_core, "_apply_binary_specific_annotations", lambda *_a, **_k: None)
    monkeypatch.setattr(cli_core, "_try_emit_known_runtime_helper_c", lambda *, name: None)

    evidence_by_target = {_CANONICAL_ADDR: selected, _NEIGHBOR_ADDR: neighbor}
    record_calls: list[tuple[object, int]] = []

    def fake_record(proj: object, target_addr: int, *, binary_path: object = None) -> object:
        record_calls.append((proj, target_addr))
        ev = evidence_by_target.get(target_addr)
        if ev is not None:
            record_caller_return_use_evidence_8616(proj, target_addr, ev)
        return ev

    monkeypatch.setattr(
        cli_core, "record_direct_target_caller_return_use_evidence_8616", fake_record
    )

    assert run.run_8616_part0_8616() is None
    assert run.run_8616_part1_8616() is None
    assert run.run_8616_part2_8616() is None
    assert run.run_8616_part3_8616() is None
    return run, project, record_calls


def _capture_clean_worker_payload(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Capture the evidence map the canonical clean-worker lane would receive."""
    captured: dict[str, object] = {}

    def fake_worker(
        _project: object,
        _args: object,
        _lst: object,
        _canonical: object,
        *,
        function_label: object,
        caller_return_evidence_by_addr: object = None,
        cache_only: bool = False,
    ) -> int:
        captured["caller_return_evidence_by_addr"] = caller_return_evidence_by_addr
        captured["cache_only"] = cache_only
        return 0

    monkeypatch.setattr(
        cli_core, "_run_canonicalized_direct_clean_worker_8616", fake_worker
    )
    return captured


@pytest.mark.parametrize("rebased_project", [False, True])
def test_snapshot_carries_hydrated_selected_and_neighbor_facts(
    monkeypatch: pytest.MonkeyPatch,
    rebased_project: bool,
) -> None:
    """Late part2/part3 facts must reach the canonical clean-worker payload."""
    hydrated_ev = _evidence(_HYDRATED_ADDR)
    selected_ev = _evidence(_CANONICAL_ADDR)
    neighbor_ev = _evidence(_NEIGHBOR_ADDR)
    run, project, _ = _drive_parts_0_to_3(
        monkeypatch,
        rebased_project=rebased_project,
        hydrated={_HYDRATED_ADDR: hydrated_ev},
        selected=selected_ev,
        neighbor=neighbor_ev,
    )
    snapshot = run.clean_worker_caller_return_evidence_by_addr
    assert snapshot[_HYDRATED_ADDR] is hydrated_ev
    assert snapshot[_CANONICAL_ADDR] is selected_ev
    assert snapshot[_NEIGHBOR_ADDR] is neighbor_ev

    captured = _capture_clean_worker_payload(monkeypatch)
    assert run._phase_direct_known_cache_8616() == 0
    assert captured["cache_only"] is True
    payload = typing.cast(
        dict[int, CallerReturnUseEvidence8616],
        captured["caller_return_evidence_by_addr"],
    )
    assert payload is snapshot
    assert payload[_HYDRATED_ADDR] is hydrated_ev
    assert payload[_CANONICAL_ADDR] is selected_ev
    assert payload[_NEIGHBOR_ADDR] is neighbor_ev

    destination = run.direct_project
    assert (destination is project) is not rebased_project
    transferred = caller_return_use_evidence_by_addr_8616(destination)
    assert transferred[_HYDRATED_ADDR] is hydrated_ev
    assert transferred[_CANONICAL_ADDR] is selected_ev
    assert transferred[_NEIGHBOR_ADDR] is neighbor_ev


def test_snapshot_retains_unknown_evidence_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """UNKNOWN/refused observations must survive the snapshot unchanged."""
    refused_ev = _evidence(_HYDRATED_ADDR, CallerReturnUseVerdict8616.UNKNOWN)
    selected_ev = _evidence(_CANONICAL_ADDR)
    neighbor_ev = _evidence(_NEIGHBOR_ADDR)
    run, _, _ = _drive_parts_0_to_3(
        monkeypatch,
        rebased_project=False,
        hydrated={_HYDRATED_ADDR: refused_ev},
        selected=selected_ev,
        neighbor=neighbor_ev,
    )
    snapshot = run.clean_worker_caller_return_evidence_by_addr
    assert snapshot[_HYDRATED_ADDR] is refused_ev
    assert snapshot[_HYDRATED_ADDR].verdict is CallerReturnUseVerdict8616.UNKNOWN

    captured = _capture_clean_worker_payload(monkeypatch)
    run.direct_result = SimpleNamespace(status=WorkItemStatus.VALIDATION_FAILED.value)
    assert run._phase_direct_light_lanes_8616() == 0
    assert captured["cache_only"] is False
    payload = typing.cast(
        dict[int, CallerReturnUseEvidence8616],
        captured["caller_return_evidence_by_addr"],
    )
    assert payload is snapshot
    assert payload[_HYDRATED_ADDR] is refused_ev
    assert payload[_CANONICAL_ADDR] is selected_ev
    assert payload[_NEIGHBOR_ADDR] is neighbor_ev


def test_snapshot_is_isolated_from_later_registry_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Facts recorded after the boundary cannot leak into the payload."""
    hydrated_ev = _evidence(_HYDRATED_ADDR)
    selected_ev = _evidence(_CANONICAL_ADDR)
    neighbor_ev = _evidence(_NEIGHBOR_ADDR)
    run, project, _ = _drive_parts_0_to_3(
        monkeypatch,
        rebased_project=False,
        hydrated={_HYDRATED_ADDR: hydrated_ev},
        selected=selected_ev,
        neighbor=neighbor_ev,
    )
    snapshot = run.clean_worker_caller_return_evidence_by_addr
    late_ev = _evidence(_LATE_ADDR)
    record_caller_return_use_evidence_8616(project, _LATE_ADDR, late_ev)

    assert _LATE_ADDR not in snapshot
    assert len(snapshot) == 3

    captured = _capture_clean_worker_payload(monkeypatch)
    assert run._phase_direct_known_cache_8616() == 0
    payload = typing.cast(
        dict[int, CallerReturnUseEvidence8616],
        captured["caller_return_evidence_by_addr"],
    )
    assert _LATE_ADDR not in payload
    assert payload[_NEIGHBOR_ADDR] is neighbor_ev
