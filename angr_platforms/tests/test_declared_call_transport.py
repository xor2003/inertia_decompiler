"""Native receipt replay and bounded transport boundary controls.

Every control exercises the real imported implementation; pytest monkeypatch
replaces only the documented module-level seams that the earlier extracted
namespace stubs occupied.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.declared_external_call_evidence import (
    DeclaredCallEffectConsumption8616,
    declared_external_call_registry_8616,
)
from x86_16_declared_call_fixture import BASE, world

from inertia_decompiler import cli_core, direct_request_fast_path
from inertia_decompiler.declared_call_transport import (
    declared_call_receipts_current_8616,
)
from inertia_decompiler.direct_request_cache import DirectRequestCacheVerdict8616
from inertia_decompiler.serial_worker_cache import (
    SerialWorkerCacheInputs8616,
    SerialWorkerCacheReason8616,
    SerialWorkerCacheVerdict8616,
    load_serial_worker_cache_8616,
)
from inertia_decompiler.work_items import WorkItemStatus


@pytest.mark.parametrize("corruption", ["none", "target", "distance", "registers", "foreign", "duplicate", "missing", "source", "registry"])
def test_native_receipt_replay(tmp_path: Path, corruption: str) -> None:
    """Exact native receipts survive; authority or receipt corruption refuses."""
    project, _block, _call, _artifact, admission, _image = world(tmp_path)
    receipt = DeclaredCallEffectConsumption8616.from_admission_8616(admission)
    receipts = (receipt,)
    if corruption == "target":
        receipts = (replace(receipt, target_addr=receipt.target_addr + 1),)
    elif corruption == "distance":
        receipts = (replace(receipt, is_far=not receipt.is_far),)
    elif corruption == "registers":
        receipts = (replace(receipt, retained_registers=("es",)),)
    elif corruption == "foreign":
        receipts = (replace(receipt, caller_addr=BASE + 1),)
    elif corruption == "duplicate":
        receipts = (receipt, receipt)
    elif corruption == "missing":
        receipts = ()
    elif corruption == "source":
        project.loader.memory.store(BASE + 1, b"\xff\x7f")
    elif corruption == "registry":
        registry = declared_external_call_registry_8616(project)
        assert registry is not None
        project._inertia_declared_external_call_registry_8616 = replace(registry, admissions=())
    evidence = SimpleNamespace(function_addr=BASE, declared_call_consumptions=receipts)
    assert cli_core._declared_call_dependency_retained_8616(
        project, SimpleNamespace(addr=BASE), evidence
    ) is (corruption == "none")


@pytest.mark.parametrize("verdict", ["passed", "failed", "unknown"])
def test_diagnostics_never_invent_validation(tmp_path: Path, capsys: pytest.CaptureFixture[str], verdict: str) -> None:
    """Reporting an assumption cannot upgrade any incoming validation status."""
    _project, _block, _call, _artifact, admission, _image = world(tmp_path)
    receipt = DeclaredCallEffectConsumption8616.from_admission_8616(admission)
    result = SimpleNamespace(validation_status=verdict, segment_program_function_evidence=SimpleNamespace(declared_call_consumptions=(receipt,)))
    cli_core._report_declared_call_consumptions_8616(result)
    diagnostic = capsys.readouterr().err
    assert "validation=" not in diagnostic
    assert "assumption_consumed=true" in diagnostic
    assert result.validation_status == verdict


def test_no_registry_cannot_retain_receipt_or_requested_declaration(tmp_path: Path) -> None:
    """A missing authority is tolerated only for an unconditional result."""
    _project, _block, _call, _artifact, admission, _image = world(tmp_path)
    receipt = DeclaredCallEffectConsumption8616.from_admission_8616(admission)
    project = SimpleNamespace()
    assert not declared_call_receipts_current_8616(project, BASE, (receipt,))
    assert not declared_call_receipts_current_8616(project, BASE, (), require_registry=True)
    assert declared_call_receipts_current_8616(project, BASE, ())


def test_fast_path_declared_request_misses_before_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lightweight path lacking a live project never emits declared output."""
    prepared = (SimpleNamespace(declared_call_effects=(Path("contract.json"),)), None)
    monkeypatch.setattr(
        direct_request_fast_path, "_prepare_fast_path_args_8616", lambda argv: prepared
    )
    assert direct_request_fast_path.try_direct_request_fast_path_8616([]) is None


@pytest.mark.parametrize("receipts", [[{"stale": True}], 0, {}, "", None, ()])
def test_fast_path_receipt_hit_misses_even_without_declaration_args(
    monkeypatch: pytest.MonkeyPatch, receipts: object
) -> None:
    """Stale conditional cache records cannot become unconditional output."""
    lookup = SimpleNamespace(
        verdict=DirectRequestCacheVerdict8616.HIT,
        artifact=SimpleNamespace(
            segment_program_function_evidence_record={"declared_call_consumptions": receipts}
        ),
    )
    monkeypatch.setattr(
        direct_request_fast_path,
        "_prepare_fast_path_args_8616",
        lambda argv: (SimpleNamespace(declared_call_effects=()), None),
    )
    monkeypatch.setattr(
        direct_request_fast_path,
        "DirectRequestCacheInputs8616",
        SimpleNamespace(from_cli=lambda *args, **kwargs: object()),
    )
    monkeypatch.setattr(
        direct_request_fast_path, "direct_request_cache_enabled_8616", lambda args: True
    )
    monkeypatch.setattr(
        direct_request_fast_path, "load_direct_request_cache_8616", lambda *args, **kwargs: lookup
    )
    assert direct_request_fast_path.try_direct_request_fast_path_8616([]) is None


def test_worker_declared_request_requires_live_authority() -> None:
    """The serialized worker cache cannot authenticate current admissions."""
    inputs = SerialWorkerCacheInputs8616(
        binary_path=Path("image.bin"),
        requested_addr=BASE,
        recovery_addr=BASE,
        timeout=9,
        window=0,
        base_addr=BASE,
        entry_point=BASE,
        c_target="msdos",
        api_style="watcom",
        pat_backend="auto",
        blob=True,
        signature_catalog=None,
        evidence_sha256="0" * 64,
        semantic_environment=(),
        result_schema=4,
        declared_call_effects=(Path("contract.json"),),
    )
    result = load_serial_worker_cache_8616(inputs, enabled=True)
    assert result.verdict is SerialWorkerCacheVerdict8616.DISABLED
    assert result.key is None and result.record is None
    assert result.reason is SerialWorkerCacheReason8616.LIVE_DECLARATION_AUTHORITY_REQUIRED
    assert result.requested_timeout == 9


class AcceptanceReached(Exception):
    """End the assembly probe at the downstream acceptance boundary."""


@pytest.mark.parametrize("status", [
    WorkItemStatus.TIMEOUT, WorkItemStatus.ERROR, WorkItemStatus.UNKNOWN,
    WorkItemStatus.VALIDATION_FAILED, WorkItemStatus.OK,
])
def test_declared_receipt_gate_preserves_prior_failure(
    monkeypatch: pytest.MonkeyPatch, status: WorkItemStatus,
) -> None:
    """A missing receipt can reject success, but cannot replace an earlier cause."""
    observed = []

    def capture_acceptance(**kwargs: object) -> None:
        observed.append(kwargs["status"])
        raise AcceptanceReached

    monkeypatch.setattr(cli_core, "_validated_generated_c_acceptance_8616", capture_acceptance)
    monkeypatch.setattr(cli_core, "_tail_validation_runtime_enabled", lambda project: True)
    function = SimpleNamespace(addr=0x1000)
    run = SimpleNamespace(
        cfg=None, func=function, status=status.value, payload="", direct_debug_output="",
        partial_payload=None, direct_timeout_stage="native_budget", direct_tail_validation_snapshot={"status": "unknown"},
        _elapsed=20.0, _block_count=1, _byte_count=4, direct_segment_program_evidence=None,
        direct_project=SimpleNamespace(), args=SimpleNamespace(declared_call_effects=("contract.json",)),
    )
    with pytest.raises(AcceptanceReached):
        cli_core._DirectAddrCliRun8616.run_8616_part5_8616_b0(run)
    expected = WorkItemStatus.VALIDATION_FAILED if status is WorkItemStatus.OK else status
    assert observed == [expected.value]
    assert run.direct_result.failure_stage == (
        "declared_call_dependency" if status is WorkItemStatus.OK else "native_budget"
    )
