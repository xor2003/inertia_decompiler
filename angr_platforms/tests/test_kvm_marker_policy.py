"""Collection controls keep static tests independent of KVM availability."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from scripts.compiler_coverage_provenance import KVMAccessEvidence, KVMAccessStatus


def _collection_policy() -> ModuleType:
    """Load the actual collection hook without running native test bodies."""
    path = Path(__file__).with_name("conftest.py")
    spec = importlib.util.spec_from_file_location("kvm_collection_policy_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _CollectedItem:
    """Expose pytest's closest-marker boundary, including inherited markers."""

    def __init__(self, marked: bool) -> None:
        self.marked = marked
        self.added: list[pytest.MarkDecorator] = []

    def get_closest_marker(self, name: str) -> pytest.Mark | None:
        assert name == "requires_kvm"
        return pytest.mark.requires_kvm.mark if self.marked else None

    def add_marker(self, marker: pytest.MarkDecorator) -> None:
        self.added.append(marker)


def test_static_collection_does_not_probe_kvm(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _collection_policy()

    def forbidden_probe() -> KVMAccessEvidence:
        raise AssertionError("static test collection must not probe KVM")

    monkeypatch.setattr(policy, "kvm_access_evidence", forbidden_probe)
    item = _CollectedItem(False)
    policy.pytest_collection_modifyitems([item])
    assert item.added == []


@pytest.mark.parametrize("status", list(KVMAccessStatus))
def test_kvm_collection_respects_device_evidence(
    monkeypatch: pytest.MonkeyPatch, status: KVMAccessStatus,
) -> None:
    policy = _collection_policy()
    evidence = KVMAccessEvidence(status, None if status is KVMAccessStatus.READ_WRITE else 13)
    monkeypatch.setattr(policy, "kvm_access_evidence", lambda: evidence)
    native, static = _CollectedItem(True), _CollectedItem(False)
    policy.pytest_collection_modifyitems([native, static])
    assert static.added == []
    if status is KVMAccessStatus.READ_WRITE:
        assert native.added == []
    else:
        assert len(native.added) == 1
        assert native.added[0].name == "skip"
        assert status.value in native.added[0].kwargs["reason"]
