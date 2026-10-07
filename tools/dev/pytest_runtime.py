"""Shared pytest setup for the decompiler test suite.

Layer: Test infrastructure.
Responsibility: configure import roots and explicit external-runtime requirements.

Package ownership contract (canonical tools/dev package):
Layer: Tooling.
Owns development infrastructure, gates, and focused test support for repository tooling.
Do not perform decompiler pipeline semantics or CLI/reporting ownership here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT: Path = Path(__file__).resolve().parents[2]

for path in (REPO_ROOT,):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

from tools.compiler_toolchain.compiler_coverage_provenance import KVMAccessStatus, kvm_access_evidence  # noqa: E402


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip tests marked as real KVM runtime gates when /dev/kvm is inaccessible."""
    marked = [item for item in items if item.get_closest_marker("requires_kvm") is not None]
    if not marked:
        return
    evidence = kvm_access_evidence()
    if evidence.status is KVMAccessStatus.READ_WRITE:
        return
    reason = f"requires writable /dev/kvm ({evidence.status.value}, errno={evidence.error_number})"
    for item in marked:
        item.add_marker(pytest.mark.skip(reason=reason))
