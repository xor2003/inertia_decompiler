"""Bounded proven near-CALL CFG extension and candidate finalization.

These exercise the production ``proven_call_cfg_extension`` owner and its
``_finalize_candidate_pair_8616`` integration: only complete native
near-CALL bindings seed callees, refused surfaces stay observable in the
typed receipt, the fixed unique-callee cap is accounted (never silently
truncated), caller bounds stay exact, and the extended CFG lives in an
independent candidate-private KB.
"""
from __future__ import annotations

import angr
import pytest

import inertia.frontend.x86_16.frontend_cfg_direct_call as frontend_cfg_direct_call
from inertia.cli import cli_function_discovery as function_discovery
from inertia.cli.project_loading import _build_project_from_bytes
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.frontend_cfg_direct_call import (
    native_direct_call_evidence_8616,
)
from inertia.lowering import proven_call_cfg_extension as pce
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallTargetBinding8616,
    DirectNearCallTargetBindingFailure8616,
    DirectNearCallTargetBindingStats8616,
    DirectNearCallTargetBindingVerdict8616,
    DirectNearCallTargetShape8616,
)
from tests.cli.test_x86_16_cod_samples import _project_from_bytes

pytestmark = pytest.mark.decompiler

CALLER_REGION = (0x1000, 0x1006)
CALLEE_ADDR = 0x100A
# call 0x100A (e8 rel16 -> 0x1003+7); mov es,ax; ret | pad | xor bx,bx; mov es,bx; ret
_IMAGE = bytes.fromhex("e80700" + "8cc0" + "c3") + b"\x90" * 4 + bytes.fromhex("31db8ec3" + "c3")


def _no_evidence(*args: object, **kwargs: object) -> None:
    """Model the real-image failure: no near-CALL proof reaches discovery."""
    return None


def _caller_image(call_count: int) -> tuple[bytes, list[int]]:
    """Build a caller of ``call_count`` near calls + ret over C3 callees."""
    callee_base = 0x1000 + call_count * 3 + 1
    body = bytearray()
    targets: list[int] = []
    for index in range(call_count):
        callsite = 0x1000 + len(body)
        target = callee_base + index
        body += b"\xe8" + ((target - (callsite + 3)) & 0xFFFF).to_bytes(2, "little")
        targets.append(target)
    body += b"\xc3"
    return bytes(body) + b"\xc3" * call_count, targets


def _lean_pair(project: angr.Project, region: tuple[int, int]):
    """Recover one caller through the production lean path (no extension)."""
    return function_discovery._pick_function_lean(
        project,
        region[0],
        regions=[region],
        extend_far_calls=False,
        seed_calling_conventions_enabled=False,
    )


def _lean_pair_without_call_evidence(monkeypatch, project, region):
    """Recover a caller whose near calls stayed unresolved, as in real images."""
    monkeypatch.setattr(
        frontend_cfg_direct_call, "native_direct_call_evidence_8616", _no_evidence
    )
    return _lean_pair(project, region)


def test_proven_near_call_discovers_callee_body_in_private_kb(monkeypatch) -> None:
    """A proven E8 callee gains a body in the extended candidate-private KB."""
    apply_x86_16_bootstrap()
    project = _project_from_bytes(_IMAGE)
    project_kb = project.kb
    cfg, function = _lean_pair_without_call_evidence(
        monkeypatch, project, CALLER_REGION
    )
    assert CALLEE_ADDR not in cfg.functions  # unresolved call: callee is None
    monkeypatch.undo()

    extension = pce.extend_cfg_for_proven_calls_8616(
        project,
        cfg,
        function,
        caller_regions=[CALLER_REGION],
        seed_calling_conventions_enabled=False,
    )

    assert extension is not None and extension.cfg is not None
    new_cfg, caller = extension.cfg, extension.function
    assert new_cfg.kb is not project_kb
    assert new_cfg.functions[0x1000] is caller
    assert CALLEE_ADDR in new_cfg.functions
    callee = new_cfg.functions[CALLEE_ADDR]
    assert sum(block.size for block in callee.blocks) >= 5  # real body, not a stub
    for block in caller.blocks:
        assert CALLER_REGION[0] <= block.addr and block.addr + block.size <= CALLER_REGION[1]
    assert CALLEE_ADDR not in project_kb.functions
    receipt = extension.receipt
    assert receipt.collected_count == 1
    assert receipt.admitted_count == 1 and receipt.refused_count == 0
    assert receipt.admitted_targets() == (CALLEE_ADDR,)
    assert extension.body_targets == (CALLEE_ADDR,)


def test_unsupported_terminal_call_stays_typed_refusal() -> None:
    """``call ax`` remains an observable unsupported refusal, never a callee."""
    apply_x86_16_bootstrap()
    project = _project_from_bytes(bytes.fromhex("ffd0" + "c3") + b"\x90" * 8)
    cfg, function = _lean_pair(project, (0x1000, 0x1003))

    extension = pce.extend_cfg_for_proven_calls_8616(
        project,
        cfg,
        function,
        caller_regions=[(0x1000, 0x1003)],
        seed_calling_conventions_enabled=False,
    )

    assert extension is not None and extension.cfg is None
    receipt = extension.receipt
    assert receipt.collected_count == 1
    assert receipt.proven_count == 0 and receipt.admitted_count == 0
    record = receipt.records[0]
    assert record.status is pce.ProvenCallAdmission8616.REFUSED_UNSUPPORTED
    assert record.callsite_addr == 0x1000


@pytest.mark.parametrize("call_count", [10, 34])
def test_proven_callee_cap_is_bounded_and_accounted(call_count: int) -> None:
    """Unique callees beyond eight are admitted; over-cap stays observable."""
    apply_x86_16_bootstrap()
    image, targets = _caller_image(call_count)
    project = _project_from_bytes(image)
    caller_end = 0x1000 + call_count * 3 + 1
    cfg, function = _lean_pair(project, (0x1000, caller_end))

    extension = pce.extend_cfg_for_proven_calls_8616(
        project,
        cfg,
        function,
        caller_regions=[(0x1000, caller_end)],
        seed_calling_conventions_enabled=False,
    )

    assert extension is not None and extension.cfg is not None
    receipt = extension.receipt
    admitted = min(call_count, pce.PROVEN_CALLEE_MAX_TARGETS_8616)
    assert receipt.collected_count == call_count
    assert receipt.admitted_count == admitted
    assert set(receipt.admitted_targets()) == set(targets[:admitted])
    for target in targets[:admitted]:
        assert target in extension.cfg.functions
    refused_over_cap = call_count - admitted
    assert receipt.cap_refused_count == refused_over_cap
    if refused_over_cap:
        assert receipt.limit_reason is pce.ProvenCallExtensionLimit8616.UNIQUE_TARGET_CAP
    else:
        assert receipt.limit_reason is None


def test_unproven_binding_never_seeds_callee() -> None:
    """Negative control: disabling the proof gate must not admit targets.

    A forged binding that carries a decoded target but a non-complete
    verdict must stay refused; the callee never enters the extended CFG.
    """
    apply_x86_16_bootstrap()
    project = _project_from_bytes(_IMAGE)
    cfg, function = _lean_pair(project, CALLER_REGION)

    def forged_provider(project, *, block_addr, block_size, discovery_irsb):
        return DirectNearCallTargetBinding8616(
            callsite_addr=block_addr,
            target_addr=CALLEE_ADDR,
            verdict=DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE,
            failure=DirectNearCallTargetBindingFailure8616.DECODED_TARGET_MISMATCH,
            stats=DirectNearCallTargetBindingStats8616(1, 0, 0, 0, 1),
        )

    extension = pce.extend_cfg_for_proven_calls_8616(
        project,
        cfg,
        function,
        caller_regions=[CALLER_REGION],
        seed_calling_conventions_enabled=False,
        evidence_provider=forged_provider,
    )

    assert extension is not None and extension.cfg is None
    record = extension.receipt.records[0]
    assert record.status is pce.ProvenCallAdmission8616.REFUSED_UNPROVEN
    assert record.target_addr == CALLEE_ADDR  # refused target stays observable
    assert extension.receipt.proven_count == 0


def test_finalize_candidate_pair_applies_proven_extension(monkeypatch) -> None:
    """Finalization re-binds the caller in the extended KB and keeps marks."""
    apply_x86_16_bootstrap()
    project = _project_from_bytes(_IMAGE)
    cfg, function = _lean_pair_without_call_evidence(
        monkeypatch, project, CALLER_REGION
    )
    monkeypatch.undo()

    new_cfg, caller = function_discovery._finalize_candidate_pair_8616(
        project,
        0x1000,
        (cfg, function),
        False,
        CALLER_REGION,
        CALLER_REGION,
        None,
        seed_calling_conventions_enabled=False,
    )

    assert new_cfg.functions[0x1000] is caller
    assert CALLEE_ADDR in new_cfg.functions
    assert function_discovery._function_binary_exact_region_8616(caller) == CALLER_REGION
    info_receipt = caller.info[function_discovery._PROVEN_CALL_RECEIPT_INFO_KEY_8616]
    assert info_receipt["admitted_count"] == 1 and info_receipt["collected_count"] == 1
    assert info_receipt["records"][0]["status"] == pce.ProvenCallAdmission8616.PROVEN_ADMITTED.value
    assert info_receipt["records"][0]["target_addr"] == CALLEE_ADDR


# ── Parent adversarial controls ──


def test_foreign_callsite_complete_binding_is_refused() -> None:
    """A complete binding for another callsite is never admitted here."""
    apply_x86_16_bootstrap()
    project = _project_from_bytes(bytes.fromhex("e80300c39090c3"))
    _cfg, function = _lean_pair(project, (0x1000, 0x1004))
    evidence = DirectNearCallTargetBinding8616(
        callsite_addr=0x1020,
        target_addr=0x1030,
        verdict=DirectNearCallTargetBindingVerdict8616.PROVEN,
        failure=None,
        stats=DirectNearCallTargetBindingStats8616(1, 1, 1, 1, 0),
        shape=DirectNearCallTargetShape8616("cs", 0x1023, 13, 32),
    )
    assert evidence.complete
    receipt = pce.collect_proven_call_targets_8616(
        project, function, evidence_provider=lambda *args, **kwargs: evidence
    )
    assert receipt is not None
    assert receipt.admitted_targets() == ()
    assert receipt.records[0].status is pce.ProvenCallAdmission8616.REFUSED_FOREIGN_SITE


def test_extension_defect_propagates_with_cause(monkeypatch) -> None:
    """An arbitrary extension failure is never silently swallowed."""
    apply_x86_16_bootstrap()
    project = _project_from_bytes(_IMAGE)
    pair = _lean_pair(project, CALLER_REGION)

    def fail(*args, **kwargs):
        raise RuntimeError("parent review injected extension defect")

    monkeypatch.setattr(
        function_discovery, "extend_cfg_for_proven_calls_8616", fail
    )
    with pytest.raises(RuntimeError, match="parent review injected extension defect"):
        function_discovery._extend_candidate_pair_for_proven_calls_8616(
            project, pair, None, False
        )


@pytest.mark.parametrize("limit", [True, -1, 33, 1.5, "8"])
def test_unique_target_limit_ceiling_is_fixed(limit) -> None:
    """The unique-callee ceiling rejects bool/negative/over-cap/non-int."""
    apply_x86_16_bootstrap()
    project = _project_from_bytes(bytes.fromhex("e80300c39090c3"))
    _cfg, function = _lean_pair(project, (0x1000, 0x1004))
    with pytest.raises(ValueError):
        pce.collect_proven_call_targets_8616(project, function, max_targets=limit)
    with pytest.raises(ValueError):
        pce.extend_cfg_for_proven_calls_8616(
            project, None, function, max_targets=limit
        )


@pytest.mark.parametrize("window", [True, 0, -1, 0x201, 1.5])
def test_callee_window_ceiling_is_fixed(window) -> None:
    """The per-callee byte window rejects bool/nonpositive/oversized."""
    apply_x86_16_bootstrap()
    project = _project_from_bytes(bytes.fromhex("e80300c39090c3"))
    _cfg, function = _lean_pair(project, (0x1000, 0x1004))
    with pytest.raises(ValueError):
        pce.extend_cfg_for_proven_calls_8616(
            project, None, function, callee_window=window
        )


def test_backward_selector_dependent_call_stays_refused() -> None:
    """Backward CS-dependent calls refuse; discovery alone cannot fix them.

    Real MSC ``main``'s backward CALL 0x1c00->0x1a30 refuses
    ``selector_window_unproved`` under two valid fetching selectors; this
    synthetic control locks that refusal in so bounded extension never
    substitutes decoded immediates or weakens the target proof.
    """
    apply_x86_16_bootstrap()
    image = bytearray(b"\x90" * 0x10010)
    image[0xF000:0xF003] = bytes.fromhex("e8f0ff")  # e8@0x10000 -> 0xFFF3
    project = _build_project_from_bytes(bytes(image), base_addr=0x1000, entry_point=0x1000)
    evidence = native_direct_call_evidence_8616(
        project, block_addr=0x10000, block_size=3
    )
    assert isinstance(evidence, DirectNearCallTargetBinding8616)
    assert (
        evidence.failure
        is DirectNearCallTargetBindingFailure8616.SELECTOR_WINDOW_UNPROVED
    )
    assert not evidence.complete
    _cfg, function = _lean_pair(project, (0x10000, 0x10003))
    receipt = pce.collect_proven_call_targets_8616(project, function)
    assert receipt is not None
    assert receipt.admitted_targets() == ()
    assert receipt.records[0].status is pce.ProvenCallAdmission8616.REFUSED_UNPROVEN


@pytest.mark.parametrize("callee", [bytes.fromhex("31db8ec3c3"), bytes.fromhex("558bec31c05dc3")])
def test_extension_does_not_discover_unreachable_neighbor_prologue(monkeypatch, callee) -> None:
    """A callee window bounds reachable code, not speculative neighbor discovery."""
    apply_x86_16_bootstrap()
    neighbor = 0x1030
    image = _IMAGE[:10] + callee
    image += b"\x90" * (neighbor - 0x1000 - len(image))
    image += bytes.fromhex("558bec31c05dc3")
    project = _project_from_bytes(image)
    cfg, function = _lean_pair_without_call_evidence(monkeypatch, project, CALLER_REGION)
    monkeypatch.undo()

    extension = pce.extend_cfg_for_proven_calls_8616(
        project, cfg, function, caller_regions=[CALLER_REGION],
        seed_calling_conventions_enabled=False,
    )

    assert extension is not None and extension.cfg is not None
    assert extension.body_targets == (CALLEE_ADDR,)
    assert neighbor not in extension.cfg.functions
    assert extension.cfg.model.get_any_node(neighbor) is None
