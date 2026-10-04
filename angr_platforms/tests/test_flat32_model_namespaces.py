"""Flat32 model-fingerprint namespace controls.

Layer: tests.
Responsibility: prove each staged flat32 model hash binds its own complete
source/package/register/semantic dependencies, never the shared real16 native
leaf capture. Covers source mutation, independent snapshot scopes, owner
order reversal, register/semantic context drift and cross-proof reuse.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

import tools.dosunit.ssa_provenance as ssa_provenance
import tools.dosunit.straightline_ssa as straightline_ssa
from tools.dosunit.recursive_proofs import (
    flat32_image_bound_domain,
    flat32_image_bound_joint_proof,
    flat32_native_effect_binding,
    flat32_pe_component,
)
from tools.dosunit.recursive_proofs.flat32_image_bound_domain import flat32_domain_model_hash
from tools.dosunit.recursive_proofs.flat32_image_bound_joint_proof import flat32_joint_model_hash
from tools.dosunit.recursive_proofs.flat32_native_effect_binding import flat32_native_binding_model_hash
from tools.dosunit.recursive_proofs.native_model_hash_snapshot import native_model_hash_snapshot
from tools.dosunit.recursive_proofs.real16_native_effect_binding import native_binding_model_hash

_HASHES = (flat32_domain_model_hash, flat32_native_binding_model_hash, flat32_joint_model_hash)


@pytest.fixture(autouse=True)
def stable_semantic_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate owner identity tests from full-tree scan cost; PE tests use real seals."""
    monkeypatch.setattr(ssa_provenance, "_semantic_hash", lambda: "a" * 64)


def test_owner_fingerprints_are_distinct_and_stable() -> None:
    """Three complete owners return three different deterministic identities."""
    values = [owner() for owner in _HASHES]
    assert len(set(values)) == len(_HASHES)
    assert [owner() for owner in _HASHES] == values
    assert all(len(value) == 64 and set(value) <= set("0123456789abcdef") for value in values)


@pytest.mark.parametrize("first,second", [
    (flat32_domain_model_hash, flat32_native_binding_model_hash),
    (flat32_native_binding_model_hash, flat32_domain_model_hash),
    (flat32_joint_model_hash, flat32_domain_model_hash),
    (flat32_domain_model_hash, flat32_joint_model_hash),
    (native_binding_model_hash, flat32_native_binding_model_hash),
    (flat32_native_binding_model_hash, native_binding_model_hash),
])
def test_no_owner_reuses_a_sibling_fingerprint(first: Callable[[], str], second: Callable[[], str]) -> None:
    """Order reversal inside one snapshot cannot cross owner namespaces."""
    expected_first, expected_second = first(), second()
    assert expected_first != expected_second
    with native_model_hash_snapshot():
        assert first() == expected_first
        assert second() == expected_second
    assert first() == expected_first
    assert second() == expected_second


def test_separate_snapshot_scopes_do_not_leak() -> None:
    """Two traversal scopes see identical uncached flat32 identities."""
    with native_model_hash_snapshot():
        first_scope = (flat32_domain_model_hash(), flat32_native_binding_model_hash())
    with native_model_hash_snapshot():
        second_scope = (flat32_domain_model_hash(), flat32_native_binding_model_hash())
    assert first_scope == second_scope
    assert first_scope == (flat32_domain_model_hash(), flat32_native_binding_model_hash())


def test_composite_binds_subowner_identities_not_theirs_alone() -> None:
    """The joint seal differs from every leaf it composes."""
    joint = flat32_joint_model_hash()
    assert joint not in {flat32_domain_model_hash(), flat32_native_binding_model_hash(),
                       native_binding_model_hash()}


@pytest.mark.parametrize("module", [
    flat32_image_bound_domain,
    flat32_native_effect_binding,
    flat32_image_bound_joint_proof,
])
def test_source_mutation_changes_the_seal(module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A changed owner file must change that owner's own fingerprint."""
    hashers = {flat32_image_bound_domain: flat32_domain_model_hash,
               flat32_native_effect_binding: flat32_native_binding_model_hash,
               flat32_image_bound_joint_proof: flat32_joint_model_hash}
    hasher = hashers[module]
    before = hasher()
    mutated = tmp_path / "mutated_owner.py"
    mutated.write_bytes(Path(module.__file__).read_bytes() + b"\n# mutated\n")
    monkeypatch.setattr(module, "__file__", str(mutated))
    assert hasher() != before


def test_dependency_source_mutation_changes_the_seal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A changed consumed module must change every owner binding it."""
    before = flat32_domain_model_hash()
    mutated = tmp_path / "mutated_component.py"
    mutated.write_bytes(Path(flat32_pe_component.__file__).read_bytes() + b"\n# mutated\n")
    monkeypatch.setattr(flat32_pe_component, "__file__", str(mutated))
    assert flat32_domain_model_hash() != before


def test_register_context_change_changes_the_seal(monkeypatch: pytest.MonkeyPatch) -> None:
    """The sealed register contract is a real dependency of every owner."""
    before = [owner() for owner in _HASHES]
    monkeypatch.setattr(straightline_ssa, "_ssa_register_widths",
                        lambda: {"eax": 32, "ebx": 32, "ecx": 32, "edx": 32, "esi": 32,
                                 "edi": 32, "ebp": 32, "esp": 32, "ip": 32, "cf": 1})
    assert [owner() for owner in _HASHES] != before


def test_semantic_context_change_changes_the_seal(monkeypatch: pytest.MonkeyPatch) -> None:
    """The SSA semantic fingerprint is a real dependency of every owner."""
    before = [owner() for owner in _HASHES]
    monkeypatch.setattr(ssa_provenance, "_semantic_hash", lambda: "b" * 64)
    assert [owner() for owner in _HASHES] != before


def test_native_leaf_keeps_its_own_traversal_memoization() -> None:
    """The real16 leaf remains stable inside one scope and fresh across scopes."""
    with native_model_hash_snapshot():
        leaf = native_binding_model_hash()
        assert native_binding_model_hash() == leaf
        assert flat32_native_binding_model_hash() != leaf
    with native_model_hash_snapshot():
        assert native_binding_model_hash() == leaf
        assert flat32_domain_model_hash() != leaf
