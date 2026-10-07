"""Independent corrupt-view and register-evidence controls for parent review."""

from __future__ import annotations

from dataclasses import replace

import pytest
from inertia.ir.core import IRInstr, IRValue, MemSpace
from tests.fixtures.entry_stack_byte_test_support import (
    _artifact,
    _binop,
    _capture,
    _const,
    _load,
    _mov,
    _reg,
    _ss_addr,
    _tmp,
)

from inertia.alias.entry_stack_bytes import prove_entry_stack_bytes_8616
from inertia.widening.entry_stack_word_value_contracts import (
    EntryStackWordProof8616,
    EntryStackWordRefusalKind8616,
)
from inertia.widening.entry_stack_word_values import prove_entry_stack_word_value_8616


def _word() -> list[IRInstr]:
    """Use different descriptive names so TMP identity, not names, is required."""
    low = replace(_tmp(1), name="byte-source-low", expr=("Iop_8Uto16",))
    high = replace(_tmp(3), name="byte-source-high", expr=("Iop_8Uto16",))
    extension = replace(_tmp(4), name="redecorated-extension", expr=("Iop_8Uto16",))
    low_word = replace(_tmp(2), name="low-word", expr=("Iop_8Uto16",))
    shifted = replace(_tmp(5), name="shifted-high", expr=("Iop_Shl16",))
    joined = replace(_tmp(6), name="assembled-word", expr=("Iop_Or16",))
    return [
        _capture(), _load(1, _ss_addr(0, 1)), _mov(_tmp(2), low),
        _load(3, _ss_addr(1, 1)), _mov(_tmp(4), high),
        _binop("Iop_Shl16", 5, extension, _const(8, 1)),
        _binop("Iop_Or16", 6, low_word, shifted), _mov(_reg("cx"), joined),
    ]


def _prove(instructions: list[IRInstr], target: int) -> EntryStackWordProof8616:
    """Keep one canonical Alias witness paired with its exact immutable owner."""
    artifact = _artifact(instructions)
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    assert len(byte_proof.facts) == 2
    return prove_entry_stack_word_value_8616(artifact, byte_proof, target)


def test_current_register_word_is_proven_without_unknown_effects() -> None:
    """An exact full-register definition remains valid without an effect barrier."""
    instructions = [*_word(), _mov(_tmp(7), _reg("cx"))]
    result = _prove(instructions, 8)
    assert result.fact is not None and result.failure_count == 0


@pytest.mark.parametrize("changes", [
    {"offset": 1}, {"index": _const(2)}, {"index_shift": 1}, {"const": 1},
])
def test_displaced_or_contradictory_destination_is_not_a_definition(changes: dict[str, object]) -> None:
    """Malformed storage views must not materialize a word definition."""
    instructions = _word()
    destination = instructions[7].dst
    assert destination is not None
    instructions[7] = replace(instructions[7], dst=replace(destination, **changes))
    result = _prove(instructions, 7)
    assert result.fact is None
    assert result.failure_count == 1 and result.materialized_count == 0


def test_unknown_effect_invalidates_current_register_evidence() -> None:
    """An unmodelled instruction cannot silently preserve register contents."""
    instructions = [*_word(),
        IRInstr("UNKNOWN_EFFECT", None, ()), _mov(_tmp(7), _reg("cx")),
    ]
    result = _prove(instructions, 9)
    assert result.fact is None
    assert result.failure_count == 1 and result.materialized_count == 0


def test_unknown_effect_does_not_rewrite_immutable_captured_temporaries() -> None:
    """Captured TMP values are immutable data, not live architectural registers."""
    source = replace(_tmp(6), expr=("Iop_Or16",))
    instructions = [*_word(), IRInstr("UNKNOWN_EFFECT", None, ()), _mov(_tmp(7), source)]
    result = _prove(instructions, 9)
    assert result.fact is not None and result.failure_count == 0


@pytest.mark.parametrize("space", [MemSpace.SS, MemSpace.DS, MemSpace.REG])
def test_non_tmp_view_cannot_steal_load_temporary_identity(space: MemSpace) -> None:
    """A storage/register view needs more proof than a copied TMP identifier."""
    instructions = _word()
    source = instructions[7].args[0]
    assert isinstance(source, IRValue)
    instructions[7] = replace(instructions[7], args=(replace(source, space=space, name="ax"),))
    result = _prove(instructions, 7)
    assert result.fact is None
    assert result.failure_count == 1 and result.materialized_count == 0


def test_call_target_remains_a_use_and_captured_word_survives() -> None:
    """A CALL input never replaces the immutable TMP producer it consumes."""
    source = replace(_tmp(6), expr=("Iop_Or16",))
    instructions = [*_word(), IRInstr("CALL", source, ()), _mov(_tmp(7), source)]
    result = _prove(instructions, 9)
    assert result.fact is not None and result.failure_count == 0


def test_call_target_is_not_a_word_definition() -> None:
    """Selecting the CALL itself must refuse, not manufacture a target value."""
    instructions = [*_word(), IRInstr("CALL", replace(_tmp(6), expr=("Iop_Or16",)), ())]
    result = _prove(instructions, 8)
    assert result.fact is None and result.materialized_count == 0


def test_call_invalidates_current_register_word() -> None:
    """A current register cannot survive CALL without preservation evidence."""
    instructions = [*_word(), IRInstr("CALL", _const(0x1234), ()), _mov(_tmp(7), _reg("cx"))]
    result = _prove(instructions, 9)
    assert result.fact is None and result.materialized_count == 0
    assert result.refusals[0].kind is EntryStackWordRefusalKind8616.NO_PRODUCER_SITE


def test_instruction_and_destination_widths_must_agree() -> None:
    """Conflicting typed widths refuse even if operand bits form a word."""
    instructions = _word()
    instructions[7] = replace(instructions[7], size=1)
    result = _prove(instructions, 7)
    assert result.fact is None and result.materialized_count == 0


def test_repeated_temporary_producer_identity_refuses() -> None:
    """A repeated producer ID needs additional versioned lineage, not a guess."""
    instructions = [*_word(), _mov(_tmp(6), _reg("cx")), _mov(_tmp(7), _tmp(6))]
    result = _prove(instructions, 9)
    assert result.fact is None and result.materialized_count == 0
    assert result.refusals[0].kind is EntryStackWordRefusalKind8616.AMBIGUOUS_PRODUCER
