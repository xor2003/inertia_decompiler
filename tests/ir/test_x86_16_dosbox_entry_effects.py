"""Explicit DOSBox prologue premise controls at the IR census boundary."""
from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from inertia.frontend.real16_dosbox_entry_policy import DosBoxInt21EntryPolicy8616
from inertia.ir.real16_declared_interrupt8616 import DeclaredInterruptService8616
from inertia.ir.real16_invocation_domain import (
    PathMemory8616,
    Real16InvocationFailure8616,
    _commit_dosbox_entry_writes_8616,
    _declared_dosbox_entry_writes_8616,
    _PathCensusContext8616,
)
from tests.ir.test_x86_16_declared_interrupt_boundary import (
    INT_ADDR,
    MODULE_BASE,
    PSP_SEGMENT,
    _boot,
    _environment,
    _premise,
    _world,
)
from tools.dosunit.runtime.real16_declared_invocation8616 import declared_int21_version_service_8616

pytestmark = pytest.mark.ssa_z3


def test_explicit_policy_crosses_and_counts_all_eleven_writes():
    env = replace(_environment(), dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(PSP_SEGMENT))
    boot = _boot(env)
    project, _, _, coverage = _world(boot)
    relation = declared_int21_version_service_8616(env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR)
    assert isinstance(relation, DeclaredInterruptService8616)
    premise = _premise(project, coverage, boot, (relation,))
    assert premise.complete
    assert premise.raw_fact_count == premise.normalized_fact_count
    assert premise.classified_fact_count == premise.materialized_count
    assert premise.failure_count == 0
    plain_boot = _boot(_environment())
    plain_project, _, _, plain_coverage = _world(plain_boot)
    plain_relation = declared_int21_version_service_8616(plain_boot.environment, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR)
    plain = _premise(plain_project, plain_coverage, plain_boot, (plain_relation,))
    assert plain.complete
    assert premise.checked_store_count == plain.checked_store_count + 10


def test_forged_psp_premise_fails_environment_binding():
    env = replace(_environment(), dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(PSP_SEGMENT))
    boot = _boot(env)
    project, _, _, coverage = _world(boot)
    relation = declared_int21_version_service_8616(env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR)
    assert isinstance(relation, DeclaredInterruptService8616)
    forged = replace(relation, dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(PSP_SEGMENT + 1))
    assert not _premise(project, coverage, boot, (forged,)).complete


def _entry(registers, *, psp=PSP_SEGMENT):
    env = replace(_environment(), dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(psp)) if psp == PSP_SEGMENT else _environment()
    relation = declared_int21_version_service_8616(env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR)
    assert isinstance(relation, DeclaredInterruptService8616)
    ctx = cast(_PathCensusContext8616, SimpleNamespace(environment=env, manifest=set(), checked_stores=0))
    artifact = SimpleNamespace(blocks=[])
    return ctx, _declared_dosbox_entry_writes_8616(ctx, relation, registers, artifact)


def test_unknown_saved_word_revokes_existing_known_bytes():
    ctx, writes = _entry({"ax": 0x3000, "ss": 0x220, "sp": 0x100, "bx": 0x1234})
    assert isinstance(writes, tuple)
    memory = PathMemory8616()
    unknown = writes[3]
    memory.apply_write(unknown.linear, unknown.size, b"\x55\x55")
    _commit_dosbox_entry_writes_8616(ctx, memory, writes)
    assert unknown.linear in memory.unknown
    assert unknown.linear not in memory.known
    assert ctx.checked_stores == 10


@pytest.mark.parametrize("ss,sp", [(0x220, 23), (0xFFFF, 0x100), (0, 0x100)])
def test_wrap_or_ivt_overlap_refuses_without_writes(ss, sp):
    ctx, verdict = _entry({"ax": 0x3000, "ss": ss, "sp": sp})
    assert isinstance(verdict, Real16InvocationFailure8616)
    assert ctx.checked_stores == 0


def test_psp_and_saved_words_alias_in_native_store_order():
    ctx, writes = _entry({"ax": 0x3000, "ss": PSP_SEGMENT - 1, "sp": 0x56, "bx": 0x1234})
    assert isinstance(writes, tuple)
    assert writes[0].linear == writes[1].linear
    memory = PathMemory8616()
    _commit_dosbox_entry_writes_8616(ctx, memory, writes)
    start = writes[0].linear
    assert bytes(memory.known[start + index] for index in range(4)) == bytes.fromhex("00303412")


@pytest.mark.parametrize("explicit_policy", [False, True])
def test_runtime_sp_frame_outside_declared_memory_refuses(monkeypatch, explicit_policy):
    """A valid header stack cannot authorize a later unprovided INT frame."""
    from tests.ir import test_x86_16_declared_interrupt_boundary as fixture

    # Valid boot SP=100h; runtime SP=116h puts the frame at arena end 2310h.
    # DOSBox's eighteen saved bytes still fit exactly below that frame.
    monkeypatch.setattr(fixture, "CALLER_CODE", bytes.fromhex("bc1601b430cd21e80100c3"))
    monkeypatch.setattr(fixture, "INT_ADDR", MODULE_BASE + 5)
    monkeypatch.setattr(fixture, "CALL_ADDR", MODULE_BASE + 7)
    monkeypatch.setattr(fixture, "CALLEE_ADDR", MODULE_BASE + 11)
    env = _environment()
    if explicit_policy:
        env = replace(env, dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(PSP_SEGMENT))
    boot = fixture._boot(env)
    project, _, _, coverage = fixture._world(boot)
    relation = declared_int21_version_service_8616(env, caller_addr=MODULE_BASE, callsite_addr=fixture.INT_ADDR)
    assert isinstance(relation, DeclaredInterruptService8616)
    premise = fixture._premise(project, coverage, boot, (relation,))
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    assert premise.checked_store_count == 0
