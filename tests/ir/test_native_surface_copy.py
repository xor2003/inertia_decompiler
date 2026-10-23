"""Native surface cloning preserves isolation and cross-field value identity."""

from copy import deepcopy
from dataclasses import fields, replace

import pytest

from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.ir import vex_import as owner
from inertia.ir.core import IRBlock, IRInstr, IRValue, MemSpace
from tests.ir.test_native_import_surface_cache import _world

pytestmark = pytest.mark.decompiler


def test_native_copy_avoids_generic_leaf_reconstruction(monkeypatch):
    """Common values bypass reflective reconstruction without sharing nodes."""
    import copy

    apply_x86_16_bootstrap()
    project, boundary, _calls, _request = _world()
    surface = owner._lift_x86_16_function_surface_8616(project, boundary)
    value = IRValue(MemSpace.TMP, name="t7", size=2, source_tmp=7,
                    memory_access_insn=0x1032, memory_access_size=2, expr=("read",))
    block = IRBlock(boundary.addr, (IRInstr("MOV", value, (value,)),))
    surface = replace(surface, blocks=(block,), ownership=replace(surface.ownership, blocks=(block,)))
    copied_values = []
    original = copy._reconstruct

    def reconstruct(source, *args, **kwargs):
        if type(source) is IRValue:
            copied_values.append(source)
        return original(source, *args, **kwargs)

    monkeypatch.setattr(copy, "_reconstruct", reconstruct)
    ordinary = deepcopy(surface)
    ordinary_count = len(copied_values)
    copied_values.clear()
    cloned = owner._copy_native_surface_8616(surface)
    assert len(copied_values) < ordinary_count
    copied = cloned.blocks[0].instrs[0].dst
    assert copied is not value
    assert cloned.blocks[0] is cloned.ownership.blocks[0]
    assert copied is cloned.blocks[0].instrs[0].args[0]
    assert [getattr(copied, field.name) for field in fields(IRValue)] == [
        getattr(ordinary.blocks[0].instrs[0].dst, field.name) for field in fields(IRValue)
    ]
    object.__setattr__(copied, "memory_access_insn", 0)
    assert value.memory_access_insn == 0x1032
    object.__setattr__(value, "source_tmp", 99)
    assert copied.source_tmp == 7


def test_changed_leaf_copier_invalidates_native_source_binding(monkeypatch):
    """Replacing a copier helper cannot inherit a retained native source key."""
    from inertia.ir import native_copy_memo as copier
    from inertia.ir.native_import_surface_cache import _source_key_8616

    project, boundary, _calls, _request = _world()
    before = _source_key_8616(project, boundary, owner._native_import_producers_8616())
    assert before is not None
    original = copier._detach_native_leaf_8616
    monkeypatch.setattr(copier, "_detach_native_leaf_8616", lambda value: original(value))
    after = _source_key_8616(project, boundary, owner._native_import_producers_8616())
    assert after is not None and after[0] != before[0]


def test_native_decision_copy_keeps_isolation_and_aliases(monkeypatch):
    """Report decisions avoid generic reconstruction but remain detached."""
    import copy

    from inertia.ir.dead_temporary_normalization import DeadTemporaryDecision8616

    apply_x86_16_bootstrap()
    project, boundary, *_ = _world()
    surface = owner._lift_x86_16_function_surface_8616(project, boundary)
    report = surface.dead_temporary_normalization
    assert report is not None and report.results[0].decisions
    decision = report.results[0].decisions[0]
    result = replace(report.results[0], decisions=(decision, decision))
    surface = replace(surface, dead_temporary_normalization=replace(report, results=(result,)))
    reconstructed = []
    original = copy._reconstruct

    def observe(source, *args, **kwargs):
        if type(source) is DeadTemporaryDecision8616:
            reconstructed.append(source)
        return original(source, *args, **kwargs)

    monkeypatch.setattr(copy, '_reconstruct', observe)
    cloned = owner._copy_native_surface_8616(surface)
    assert not reconstructed
    copied = cloned.dead_temporary_normalization.results[0].decisions
    assert copied[0] is copied[1] and copied[0] is not decision
    assert copied == result.decisions
    object.__setattr__(copied[0], 'instruction_index', -123)
    assert decision.instruction_index != -123


def test_native_decision_seeding_preserves_existing_and_foreign_payloads():
    """Malformed decisions use generic deepcopy; prior memo identities survive."""
    from inertia.ir.dead_temporary_normalization import (
        DeadTemporaryDecision8616,
        DeadTemporaryDecisionKind8616,
    )
    from inertia.ir.native_copy_memo import seed_native_decisions_8616

    decision = DeadTemporaryDecision8616(7, DeadTemporaryDecisionKind8616.KEEP_LIVE)
    detached = deepcopy(decision)
    memo = {id(decision): detached}
    seed_native_decisions_8616((decision,), memo)
    assert memo[id(decision)] is detached
    malformed = DeadTemporaryDecision8616(8, DeadTemporaryDecisionKind8616.UNKNOWN_REFUSE)
    payload = [malformed]
    object.__setattr__(malformed, 'instruction_index', payload)
    seed_native_decisions_8616((malformed,), memo)
    assert id(malformed) not in memo
    copied = deepcopy(malformed, memo)
    assert copied.instruction_index is not payload
    assert copied.instruction_index[0] is copied
