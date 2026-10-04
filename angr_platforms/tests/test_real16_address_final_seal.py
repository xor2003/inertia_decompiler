"""One fresh dependency traversal per final address seal.

Layer: tests.
Responsibility: prove the consolidated final seal keeps freshness and complete
dependency-identity coverage while starting one native source-tree scan per
seal instead of one per overlapping owner. Child-proof stubs test orchestration
only; this cohort never establishes binary equivalence.
"""
from __future__ import annotations

from collections.abc import Callable
from types import ModuleType, SimpleNamespace

import pytest

from tools.dosunit import ssa_provenance
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs import real16_address_model_closure
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
)
from tools.dosunit.recursive_proofs.native_model_hash_snapshot import (
    captured_native_model_hash,
    native_model_hash_snapshot,
    native_model_hash_snapshot_active,
)


@pytest.fixture(autouse=True)
def bounded_source_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use a deterministic source token; real filesystem cost has an ABBA receipt.

    These controls exercise capture lifetimes and full owner composition, not
    filesystem hashing throughput. Mutation tests replace this token explicitly.
    """
    monkeypatch.setattr(ssa_provenance, "_semantic_hash", lambda: "a" * 64)


@pytest.fixture(scope="module")
def owner() -> ModuleType:
    """Use the ordinary production import with no staged replacement."""
    return real16_address_model_closure


def _count_scans(monkeypatch: pytest.MonkeyPatch) -> Callable[[], int]:
    """Count source-digest requests without repeating expensive filesystem IO."""
    real = ssa_provenance._semantic_hash
    calls = 0

    def counted() -> str:
        nonlocal calls
        calls += 1
        return real()

    monkeypatch.setattr(ssa_provenance, "_semantic_hash", counted)
    return lambda: calls


def _current_seals(owner: ModuleType) -> dict[str, str]:
    """Compute every retained owner seal inside one setup traversal."""
    with native_model_hash_snapshot():
        return {
            "closure": owner.address_model_model_hash(),
            "receipt": owner.image_bound_domain_model_hash(),
            "prefixes": owner.code_prefix_model_hash(),
            "operands": owner.bound_operand_model_hash(),
            "addresses": owner.physical_access_model_hash(),
            "controls": owner.bound_control_model_hash(),
            "dispatch": owner.domain_dispatch_model_hash(),
            "entry": owner.entry_frame_model_hash(),
        }


_STAGE_OBLIGATIONS: tuple[tuple[str, str, str], ...] = (
    ("_receipt_ok", "RECEIPT", "receipt"),
    ("_manifest_ok", "MANIFEST", "requests"),
    ("_fetch_ok", "FETCH", "fetch"),
    ("_operand_ok", "OPERAND", "operand"),
    ("_bounds_ok", "BOUNDS", "bounds"),
    ("_control_ok", "CONTROL", "control"),
    ("_frames_ok", "FRAME", "frames"),
    ("_dispatch_ok", "DISPATCH", "dispatch"),
    ("_root_terminal_ok", "ROOT", "root"),
)


def _stage_check(row: object, key: str) -> Callable[..., bool]:
    """Return one stubbed stage that records its own required ledger row."""
    def check(run: object, *_ignored: object) -> bool:
        return run.fact(row, key, True)

    return check


def _stub_stages(owner: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """Discharge only the nine child ledger rows; the final seal stays real."""
    for name, obligation, key in _STAGE_OBLIGATIONS:
        monkeypatch.setattr(owner, name,
                            _stage_check(owner.AddressModelObligation[obligation], key))


def _run_closure(owner: ModuleType, seals: dict[str, str]) -> object:
    """Run the real compositor against controlled retained child seals."""
    return owner._check_address_model_closure(
        SimpleNamespace(), SimpleNamespace(model_hash=seals["receipt"]),
        SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), SimpleNamespace(),
        SimpleNamespace(model_hash=seals["prefixes"]),
        SimpleNamespace(model_hash=seals["operands"]),
        SimpleNamespace(model_hash=seals["addresses"]),
        SimpleNamespace(model_hash=seals["controls"]),
        (),
        SimpleNamespace(model_hash=seals["dispatch"]),
        SimpleNamespace(model_hash=seals["entry"]),
        timeout_ms=120000, limits=LoadedRelationLimits())


def test_closure_seal_uses_one_traversal_per_fresh_check(
        owner: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """One closure run costs two traversals: beginning seal plus final seal."""
    scans = _count_scans(monkeypatch)
    seals = _current_seals(owner)
    start = scans()
    _stub_stages(owner, monkeypatch)
    outcome = _run_closure(owner, seals)
    assert scans() - start == 2
    assert outcome.complete
    assert outcome.status is ProofStatus.PROVED
    assert outcome.reason is owner.AddressModelReason.CLOSED
    assert outcome.counters.failure_count == 0


def test_independent_closure_seals_rescan(owner: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """No capture crosses a seal boundary: two closures cost four traversals."""
    scans = _count_scans(monkeypatch)
    seals = _current_seals(owner)
    _stub_stages(owner, monkeypatch)
    start = scans()
    first = _run_closure(owner, seals)
    second = _run_closure(owner, seals)
    assert scans() - start == 4
    assert first.complete and second.complete


def test_source_change_between_traversals_refuses(
        owner: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """A source mutation after the beginning seal still refuses as MODEL."""
    calls = 0

    def movable() -> str:
        nonlocal calls
        calls += 1
        return "a" * 64 if calls <= 2 else "b" * 64

    monkeypatch.setattr(ssa_provenance, "_semantic_hash", movable)
    seals = _current_seals(owner)
    _stub_stages(owner, monkeypatch)
    outcome = _run_closure(owner, seals)
    assert calls >= 3
    assert not outcome.complete
    assert outcome.status is ProofStatus.UNKNOWN
    assert outcome.reason is owner.AddressModelReason.MODEL
    assert outcome.facts[-1].obligation is owner.AddressModelObligation.MODEL
    assert outcome.facts[-1].status is ProofStatus.UNKNOWN
    assert outcome.counters.failure_count == 1


@pytest.mark.parametrize("field", ["receipt", "prefixes", "operands", "addresses",
                                   "controls", "dispatch", "entry"])
def test_stale_child_seal_refuses(owner: ModuleType, monkeypatch: pytest.MonkeyPatch,
                                  field: str) -> None:
    """Every retained dependency identity is still compared; no skipped owner."""
    seals = _current_seals(owner)
    seals[field] = "0" * 64
    _stub_stages(owner, monkeypatch)
    outcome = _run_closure(owner, seals)
    assert not outcome.complete
    assert outcome.status is ProofStatus.UNKNOWN
    assert outcome.reason is owner.AddressModelReason.MODEL
    assert outcome.facts[-1].obligation is owner.AddressModelObligation.MODEL
    assert outcome.facts[-1].status is ProofStatus.UNKNOWN
    assert outcome.counters.failure_count == 1


def test_digest_exception_resets_capture(owner: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed digest inside the final traversal leaves no retained capture."""
    seals = _current_seals(owner)
    _stub_stages(owner, monkeypatch)

    def fail() -> str:
        raise OSError("controlled unreadable digest dependency")

    original = owner.domain_dispatch_model_hash
    monkeypatch.setattr(owner, "domain_dispatch_model_hash", fail)
    with pytest.raises(OSError, match="controlled unreadable"):
        _run_closure(owner, seals)
    assert captured_native_model_hash() is None
    assert not native_model_hash_snapshot_active()
    monkeypatch.setattr(owner, "domain_dispatch_model_hash", original)
    outcome = _run_closure(owner, seals)
    assert outcome.complete


def test_final_model_seal_helper_single_scan(
        owner: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """The staged helper performs one traversal for all eight comparisons."""
    seals = _current_seals(owner)
    retained = owner._FinalSealInputs(**seals)
    scans = _count_scans(monkeypatch)
    assert owner._final_model_seal(retained) is True
    assert scans() == 1
