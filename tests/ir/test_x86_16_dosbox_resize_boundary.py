"""Source-bound census consumes complete DOSBox allocator effects."""

from dataclasses import replace

import pytest

from inertia.frontend.real16_dosbox_entry_policy import DosBoxInt21EntryPolicy8616
from inertia.frontend.real16_dosbox_resize import DosboxMcbEntry, DosboxResizePolicy
from inertia.ir.real16_declared_interrupt8616 import DeclaredResizeConsumption8616
from tests.ir import test_x86_16_declared_resize_boundary as fixture

pytestmark = pytest.mark.ssa_z3


def _environment():
    base = fixture._environment(resize=None)
    image = b"Z" + base.psp_segment.to_bytes(2, "little") + (len(base.allocation) // 16).to_bytes(2, "little") + b"\x55" * 11
    policy = DosboxResizePolicy(base.psp_segment, (DosboxMcbEntry(base.psp_segment - 1, image),))
    return replace(base, resize_policy=policy, dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(base.psp_segment))


def test_dosbox_resize_crossing_retains_all_ordered_effects_and_replays():
    env = _environment()
    boot = fixture._boot(env=env)
    project, _, coverage = fixture._world(boot, len(fixture.CALLER_RESIZE))
    relation = fixture._resize_relation(env, fixture.RESIZE_INT_ADDR)
    premise = fixture._resize_premise(project, coverage, fixture.RESIZE_CALL_ADDR, boot, (relation,))
    assert premise.complete
    assert premise.failure_count == 0
    assert premise.classified_fact_count == premise.materialized_count
    effect = premise.service_consumptions[0]
    assert isinstance(effect, DeclaredResizeConsumption8616)
    assert effect.answer_ax == fixture.PSP_SEGMENT
    assert effect.answer_bx == 0x40
    assert effect.carry is False
    assert effect.dosbox_current_chain == (env.resize_policy.final_entry.image,)
    assert effect.dosbox_new_header_before == bytes(16)
    assert len(effect.dosbox_writes) == 6
    assert effect.metadata_after[0] == ord("M")
    assert int.from_bytes(effect.metadata_after[3:5], "little") == 0x40
    serialized = premise.to_dict()["service_consumptions"][0]
    assert len(serialized["dosbox_writes"]) == 6


def test_dosbox_binding_does_not_accept_forged_prefix_metadata():
    env = _environment()
    boot = fixture._boot(env=env)
    project, _, coverage = fixture._world(boot, len(fixture.CALLER_RESIZE))
    relation = fixture._resize_relation(env, fixture.RESIZE_INT_ADDR)
    assert relation.resize is not None
    forged = replace(relation, resize=replace(relation.resize, metadata=b"\x00" * 16))
    premise = fixture._resize_premise(project, coverage, fixture.RESIZE_CALL_ADDR, boot, (forged,))
    assert not premise.complete
    assert premise.failure_count > 0
