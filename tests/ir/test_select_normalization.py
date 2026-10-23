"""Regression for proven selection normalization.

Layer: IR tests.
Responsibility: preserve values, capture identity and conservative refusal.
"""
from dataclasses import replace

import pytest
from pytest import MonkeyPatch

from inertia.ir import real16_invocation_domain as exact
from inertia.ir.core import IRBlock, IRInstr, IRValue, MemSpace
from inertia.ir.instruction_origin import IRInstructionOrigin8616
from inertia.ir.select_normalization import (
    SelectNormalizationStatus8616,
    normalize_selects_8616,
    select_normalization_producers_8616,
)


def block(guard: int | None = 0, bits: int = 1) -> IRBlock:
    """Build captured arms and a guard independent of register state."""
    size = (bits + 7) // 8
    definitions = tuple(
        IRInstr(op="MOV", dst=IRValue(MemSpace.TMP, source_tmp=i, size=width),
                args=(IRValue(MemSpace.CONST, const=value, size=width),), size=width)
        for i, width, value in ((0, 1, guard), (1, size, 0xAA), (2, size, 0xFD))
    )
    if guard is None:
        definitions = (replace(definitions[0], args=(IRValue(MemSpace.REG, name="al", size=1),)), *definitions[1:])
    selection = IRInstr(op=f"SELECT{bits}", dst=IRValue(MemSpace.TMP, source_tmp=9, size=size),
                        args=tuple(row.dst for row in definitions), size=size, addr=0x100,
                        origin=IRInstructionOrigin8616(0x100, 3))
    return IRBlock(addr=0x100, instrs=(*definitions, selection))


@pytest.mark.parametrize("guard", [0, 1, 2, 3])
@pytest.mark.parametrize("bits", [1, 8, 16, 32, 64])
def test_selection_preserves_mask_order_and_fields(guard: int, bits: int) -> None:
    """Width-one selects truncate high bits and retain source capture pins."""
    original = block(guard, bits)
    result = normalize_selects_8616(original).block
    before, after = original.instrs[-1], result.instrs[-1]
    assert after.op == "MOV"
    assert after.dst is before.dst
    assert after.origin is before.origin
    assert replace(after, op=before.op, args=before.args) == before
    assert result.instrs[:-1] == original.instrs[:-1]
    source = after.args[0]
    captured = source.active_unary.operand if bits == 1 else source
    assert captured.source_tmp == (1 if guard & 1 else 2)
    assert captured is before.args[1 if guard & 1 else 2]
    state = {0: guard, 1: 0xAA, 2: 0xFD}
    exact._simulate_tmp_write_8616(after, after.dst, {}, state)
    assert state[9] == ((0xAA if guard & 1 else 0xFD) & ((1 << bits) - 1))


def test_unknown_guard_keeps_select() -> None:
    """No entry-register assumption may resolve a guard."""
    original = block(None)
    assert normalize_selects_8616(original).block == original


def test_control_boundary_keeps_unvisited_suffix() -> None:
    """The straight-line proof never walks through a control transfer."""
    original = block()
    stop = IRInstr(op="JMP", dst=None, args=(IRValue(MemSpace.CONST, const=0x200, size=2),))
    original = replace(original, instrs=(*original.instrs[:-1], stop, original.instrs[-1]))
    assert normalize_selects_8616(original).block is original


def test_malformed_guard_producer_cannot_supply_knowledge() -> None:
    """A contradictory scalar width cannot prove the predicate value."""
    original = block()
    original = replace(original, instrs=(replace(original.instrs[0], size=2), *original.instrs[1:]))
    assert normalize_selects_8616(original).block == original


@pytest.mark.parametrize("fault", ["missing", "duplicate", "shape"])
def test_refusal_keeps_original(fault: str) -> None:
    """Incomplete definitions and malformed selects are never normalized."""
    original = block()
    rows = original.instrs
    if fault == "missing":
        original = replace(original, instrs=rows[1:])
    elif fault == "duplicate":
        original = replace(original, instrs=(rows[0], *rows))
    else:
        original = replace(original, instrs=(*rows[:-1], replace(rows[-1], size=2)))
    assert normalize_selects_8616(original).block == original


def test_captured_register_arm_survives_overwrite() -> None:
    """The chosen arm reads its temporary, not the later register value."""
    original = block(1, 16)
    selected = replace(original.instrs[-1], args=(original.instrs[-1].args[0],
        IRValue(MemSpace.REG, name="ax", size=2, source_tmp=1), original.instrs[-1].args[2]))
    overwrite = IRInstr(op="MOV", dst=IRValue(MemSpace.REG, name="ax", size=2),
                        args=(IRValue(MemSpace.CONST, const=99, size=2),), size=2)
    original = replace(original, instrs=(*original.instrs[:-1], overwrite, selected))
    result = normalize_selects_8616(original).block
    state = {0: 1, 1: 0xAA, 2: 0xFD}
    exact._simulate_tmp_write_8616(result.instrs[-1], result.instrs[-1].dst, {"ax": 99}, state)
    assert state[9] == 0xAA


def test_candidate_free_block_skips_analysis(monkeypatch: MonkeyPatch) -> None:
    """No SELECT means no dependency or numeric work, even on opaque rows."""
    import inertia.ir.select_normalization as owner

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("candidate-free blocks must not replay")

    monkeypatch.setattr(owner, "_collect_block_facts", forbidden)
    monkeypatch.setattr(owner, "_rewrite_prefix_8616", forbidden)
    original = IRBlock(addr=0x100, instrs=(IRInstr(op="opaque", dst=None, args=()),))
    result = normalize_selects_8616(original)
    assert result.block is original
    assert result.status is SelectNormalizationStatus8616.COMPLETE
    assert result.evidence.raw_fact_count == result.evidence.failure_count == 0


def test_evidence_counts_admission_and_materialization() -> None:
    """Known guards rewrite; unknown guards remain honestly admitted and unchanged."""
    result = normalize_selects_8616(block())
    assert result.status is SelectNormalizationStatus8616.COMPLETE
    assert result.evidence.raw_fact_count == result.evidence.normalized_fact_count == 1
    assert result.evidence.classified_fact_count == result.evidence.materialized_count == 1
    assert result.evidence.failure_count == 0
    original = block(None)
    unknown = normalize_selects_8616(original)
    assert unknown.block is original
    assert unknown.evidence.normalized_fact_count == 1
    assert unknown.evidence.classified_fact_count == unknown.evidence.materialized_count == 0
    assert unknown.evidence.failure_count == 0


def test_missing_dependency_has_typed_refusal() -> None:
    """Incomplete temporary ownership keeps all rows and accounts for refusal."""
    original = block()
    original = replace(original, instrs=original.instrs[1:])
    result = normalize_selects_8616(original)
    assert result.block is original
    assert result.status is SelectNormalizationStatus8616.UNKNOWN_REFUSE
    assert result.evidence.raw_fact_count == result.evidence.failure_count == 1
    assert result.evidence.normalized_fact_count == result.evidence.materialized_count == 0


def test_call_does_not_supply_environment_facts() -> None:
    """A call boundary erases guard knowledge; no service hook can restore it."""
    original = block()
    call = IRInstr(op="CALL", dst=None, args=(IRValue(MemSpace.CONST, const=0x1234, size=2),))
    original = replace(original, instrs=(*original.instrs[:-1], call, original.instrs[-1]))
    result = normalize_selects_8616(original)
    assert result.block is original
    assert result.evidence.materialized_count == 0


def test_producer_registry_is_stable_and_binds_numeric_owner() -> None:
    """Repeated queries retain authority identities without import cycles."""
    from inertia.ir import real16_edge_feasibility8616 as kb

    first = select_normalization_producers_8616()
    second = select_normalization_producers_8616()
    assert tuple(map(id, first)) == tuple(map(id, second))
    assert kb._kb_tmp_write_8616 in first
    assert kb._kb_transfer_effect_8616 in first
