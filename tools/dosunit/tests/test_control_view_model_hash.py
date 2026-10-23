"""Control-view model identity binds the canonical owner source bytes.

Layer: integration tests.
Responsibility: prove control_view_model_hash reads every sealed owner under
its canonical path in deterministic order, that substituting any owner's read
bytes changes the fingerprint and that an unreadable owner fails loudly.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.dosunit.recursive_proofs import recursive_joint_identity
from tools.dosunit.recursive_proofs.recursive_joint_identity import control_view_model_hash

pytestmark = pytest.mark.ssa_z3

DOSUNIT_ROOT = Path(recursive_joint_identity.__file__).resolve().parent.parent

# The sealed owner set and its order are part of the identity contract: the
# control-boundary, declared-target and resolver owners live under compare/,
# and any reordered or substituted list is a different fingerprint.
SEALED_OWNERS: tuple[str, ...] = (
    "compare/real16_control_boundary.py",
    "compare/real16_control_targets.py",
    "compare/straightline_ssa.py",
    "contracts/ssa.py",
    "contracts/registers.py",
    "contracts/comparison.py",
    "contracts/scanning.py",
    "ssa/identity.py",
    "ssa/z3_ops.py",
    "ssa/translation.py",
    "ssa/composition.py",
    "ssa/materialization.py",
    "recursive_proofs/recursive_static_control.py",
)


def test_sealed_owner_sources_are_canonical_and_readable(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Every read must hit the canonical owner path in sealed order."""
    read_bytes = Path.read_bytes
    observed: list[Path] = []

    def recording_read_bytes(self: Path) -> bytes:
        observed.append(self)
        return read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", recording_read_bytes)
    digest = control_view_model_hash()
    assert [path.resolve() for path in observed] == [DOSUNIT_ROOT / owner for owner in SEALED_OWNERS]
    assert len(bytes.fromhex(digest)) == 32


def test_digest_is_deterministic() -> None:
    """Unchanged sources produce one fingerprint across repeated calls."""
    assert control_view_model_hash() == control_view_model_hash()


@pytest.mark.parametrize("owner", SEALED_OWNERS)
def test_each_sealed_owner_changes_the_fingerprint(
        monkeypatch: pytest.MonkeyPatch, owner: str) -> None:
    """Substituting one owner's read bytes must produce a different digest."""
    baseline = control_view_model_hash()
    target = DOSUNIT_ROOT / owner
    read_bytes = Path.read_bytes

    def corrupting_read_bytes(self: Path) -> bytes:
        data = read_bytes(self)
        return data + b"\x00" if self.resolve() == target else data

    monkeypatch.setattr(Path, "read_bytes", corrupting_read_bytes)
    assert control_view_model_hash() != baseline


def test_unreadable_sealed_owner_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    """A required owner that cannot be read raises instead of yielding a hash."""
    target = DOSUNIT_ROOT / SEALED_OWNERS[0]
    read_bytes = Path.read_bytes

    def missing_read_bytes(self: Path) -> bytes:
        if self.resolve() == target:
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", missing_read_bytes)
    with pytest.raises(FileNotFoundError):
        control_view_model_hash()
