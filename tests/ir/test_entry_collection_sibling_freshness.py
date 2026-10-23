"""Native descendant changes must invalidate later public collection admissions.

Layer: Tests.
Responsibility: prevent dependency verdicts surviving independent sibling checks.
"""
import pytest

from inertia.ir import entry_domain_call_preservation as entry
from inertia.ir.segment_call_preservation import prove_segment_call_preservation_8616
from inertia.ir.segment_effect_closure import prove_segment_effect_closure_8616
from inertia.ir.segment_state import build_x86_16_segment_state_artifact
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_segment_call_binding_regression import _coverage, _program_index, _project

pytestmark = pytest.mark.decompiler


def _native_chain():
    """Two root calls share a real nonleaf proof and its native leaf descendant."""
    image = bytearray(b'\x90' * 0x24)
    image[0:7] = bytes.fromhex('e8 0d 00 e8 0a 00 c3')
    image[0x10:0x14] = bytes.fromhex('e8 0d 00 c3')
    image[0x20:0x24] = bytes.fromhex('90 90 90 c3')
    project = _project(image)
    root = _coverage(project, 0x1000, 0x1007)
    middle = _coverage(project, 0x1010, 0x1014)
    leaf = _coverage(project, 0x1020, 0x1024)
    leaf_closure = prove_segment_effect_closure_8616(leaf, build_x86_16_segment_state_artifact(leaf.artifact))
    inner = prove_segment_call_preservation_8616(
        middle, leaf_closure, _program_index(project, 0x1010, 0x1014), 0x1010,
    )
    assert inner.complete
    closure = prove_segment_effect_closure_8616(
        middle, build_x86_16_segment_state_artifact(middle.artifact, call_preservations=(inner,)),
    )
    assert closure.complete
    return project, root, closure


@pytest.mark.parametrize('boundary', ['sibling', 'public_root'])
def test_public_collection_rechecks_changed_descendant(monkeypatch, boundary):
    """Budget/prefix sharing cannot extend successful dependency verdict lifetime."""
    project, root, closure = _native_chain()
    # Supply genuine retained resolution evidence; all native proof gates run.
    monkeypatch.setattr(entry, '_callee_closure_8616', lambda *_args, **_kwargs: (closure, None))

    def collect():
        return entry.collect_entry_domain_call_preservations_8616(
            project, root.artifact, root.boundary,
            direct_target_resolver=lambda row: resolve_direct_call_target_from_instruction_8616(project, row),
        )

    def corrupt_native():
        project.loader.memory.store(0x1020, bytes.fromhex('8e d8 90'))

    if boundary == 'public_root':
        before = collect()
        assert len(before) == 2 and all(record.failure is None for record in before)
        corrupt_native()
        after = collect()
        assert len(after) == 2 and all(record.failure is not None for record in after)
        return

    original = entry._preservation_failure_8616
    changed = False

    def mutate_between(candidate):
        nonlocal changed
        verdict = original(candidate)
        if candidate.callsite_addr == 0x1000 and verdict is None and not changed:
            corrupt_native()
            changed = True
        return verdict

    monkeypatch.setattr(entry, '_preservation_failure_8616', mutate_between)
    records = collect()
    assert changed and len(records) == 2
    assert records[0].failure is None
    assert records[1].failure is not None
