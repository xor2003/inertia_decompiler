"""Typed controls for the entry-word bit transport calculus.

Layer: Widening regression tests.
Responsibility: exercise ``entry_stack_word_bits`` public functions over real
typed Alias byte facts — provenance lanes come from an actual
``prove_entry_stack_bytes_8616`` run over canonical fixtures, never from
fabricated statuses. Assertions read typed values, not rendered strings.
Implementation changes are out of scope even if a control fails.
"""

from __future__ import annotations

import pytest
from inertia.ir.scalar_value_projection import (
    ScalarBinaryKind8616 as Kind,
)
from inertia.ir.scalar_value_projection import (
    ScalarProjection8616,
)
from inertia.ir.scalar_value_projection import (
    ScalarProjectionKind8616 as ProjectionKind,
)
from tests.fixtures.entry_stack_byte_test_support import (
    _artifact,
    _capture,
    _load,
    _ss_addr,
)

from inertia.alias.entry_stack_byte_contracts import (
    EntryStackByteRead8616,
)
from inertia.alias.entry_stack_bytes import (
    prove_entry_stack_bytes_8616,
)
from inertia.widening.entry_stack_word_bits import (
    EntryStackWordBit8616,
    binary_entry_bits_8616,
    bit_vector_constant_8616,
    constant_bits_8616,
    project_entry_bits_8616,
)


@pytest.fixture
def byte_facts() -> tuple[EntryStackByteRead8616, EntryStackByteRead8616]:
    """Two real Alias-proven byte captures at entry-SS offsets 0 and 1."""
    artifact = _artifact(
        [_capture(), _load(1, _ss_addr(0, 1)), _load(3, _ss_addr(1, 1))]
    )
    proof = prove_entry_stack_bytes_8616(artifact)
    assert len(proof.facts) == 2
    return proof.facts[0], proof.facts[1]


def _lane(fact: EntryStackByteRead8616, *indexes: int) -> tuple[EntryStackWordBit8616, ...]:
    """Provenance lanes for selected bit indexes of one capture."""
    return tuple(EntryStackWordBit8616(fact, index) for index in indexes)


def test_constant_bits_exact_and_truncated() -> None:
    """Constants are LSB-first and truncated to the declared width."""
    assert constant_bits_8616(0b1011, 4) == (True, True, False, True)
    assert constant_bits_8616(0x1FF, 8) == (True,) * 8
    assert constant_bits_8616(0, 16) == (False,) * 16


def test_bit_vector_constant_roundtrip_and_refusal(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """Only an all-Boolean vector is a constant; provenance/None refuse."""
    assert bit_vector_constant_8616(constant_bits_8616(0xBEEF, 16)) == 0xBEEF
    assert bit_vector_constant_8616(_lane(byte_facts[0], *range(8))) is None
    assert bit_vector_constant_8616((True, None, False)) is None


def test_unsigned_extension_zero_fills_high_lanes(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """8→16 unsigned conversion keeps lanes and zero-fills the extension."""
    low = _lane(byte_facts[0], *range(8))
    result = project_entry_bits_8616(
        low, ScalarProjection8616(ProjectionKind.CONVERSION, 8, 16)
    )
    assert result == low + (False,) * 8


def test_signed_extension_propagates_top_lane(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """8→16 signed conversion repeats the exact top source lane."""
    low = _lane(byte_facts[0], *range(8))
    result = project_entry_bits_8616(
        low, ScalarProjection8616(ProjectionKind.CONVERSION, 8, 16, signed=True)
    )
    assert result == low + (low[7],) * 8
    top_one = constant_bits_8616(0x80, 8)
    assert project_entry_bits_8616(
        top_one,
        ScalarProjection8616(ProjectionKind.CONVERSION, 8, 16, signed=True),
    ) == top_one + (True,) * 8


def test_narrowing_and_identity_projections(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """CONVERSION narrowing keeps low lanes; identity kinds pass through."""
    low, high = _lane(byte_facts[0], *range(8)), _lane(byte_facts[1], *range(8))
    word = low + high
    assert project_entry_bits_8616(
        word, ScalarProjection8616(ProjectionKind.CONVERSION, 16, 8)
    ) == low
    for kind in (ProjectionKind.IDENTITY, ProjectionKind.EARNED_REDECORATION):
        assert project_entry_bits_8616(
            word, ScalarProjection8616(kind, 16, 16)
        ) == word


def test_projection_source_width_mismatch_refused(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """A projection declared for a different source width refuses."""
    low = _lane(byte_facts[0], *range(8))
    assert (
        project_entry_bits_8616(
            low, ScalarProjection8616(ProjectionKind.IDENTITY, 16, 8)
        )
        is None
    )


def test_or_and_boolean_identities(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """OR/AND forcing lanes dominate; identity lanes pass the operand."""
    bits = _lane(byte_facts[0], *range(8))
    zeros = (False,) * 8
    ones = (True,) * 8
    assert binary_entry_bits_8616(Kind.OR, bits, zeros) == bits
    assert binary_entry_bits_8616(Kind.OR, bits, ones) == ones
    assert binary_entry_bits_8616(Kind.AND, bits, ones) == bits
    assert binary_entry_bits_8616(Kind.AND, bits, zeros) == zeros


def test_xor_same_source_identity_and_none_not_self_proving(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """x XOR x of one exact capture is 0; None never proves itself."""
    bits = _lane(byte_facts[0], *range(8))
    assert binary_entry_bits_8616(Kind.XOR, bits, bits) == (False,) * 8
    assert binary_entry_bits_8616(Kind.XOR, (None, None), (None, None)) == (
        None,
        None,
    )
    assert binary_entry_bits_8616(Kind.XOR, bits, (False,) * 8) == bits


def test_different_source_bits_stay_unknown(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """Distinct captures never collapse into a Boolean or each other."""
    low, high = _lane(byte_facts[0], *range(8)), _lane(byte_facts[1], *range(8))
    assert binary_entry_bits_8616(Kind.OR, low, high) == (None,) * 8
    assert binary_entry_bits_8616(Kind.XOR, low, high) == (None,) * 8
    same_lane = (EntryStackWordBit8616(byte_facts[0], 0),)
    other_bit = (EntryStackWordBit8616(byte_facts[0], 1),)
    assert binary_entry_bits_8616(Kind.XOR, same_lane, other_bit) == (None,)


def test_shifts_zero_and_eight(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """SHL 0 is identity; SHL 8 moves low lanes to the high byte."""
    low, high = _lane(byte_facts[0], *range(8)), _lane(byte_facts[1], *range(8))
    word = low + high
    count0 = constant_bits_8616(0, 16)
    count8 = constant_bits_8616(8, 16)
    assert binary_entry_bits_8616(Kind.SHL, word, count0) == word
    assert binary_entry_bits_8616(Kind.SHL, word, count8) == (False,) * 8 + low
    assert binary_entry_bits_8616(Kind.SHR, word, count8) == high + (False,) * 8


def test_unproven_and_out_of_range_shift_counts_refused(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """Symbolic or width-exceeding counts are not composition evidence."""
    word = _lane(byte_facts[0], *range(8)) + _lane(byte_facts[1], *range(8))
    assert (
        binary_entry_bits_8616(Kind.SHL, word, word)
        is None
    )
    assert (
        binary_entry_bits_8616(Kind.SHL, word, constant_bits_8616(16, 16))
        is None
    )


def test_constant_add_sub_wrap() -> None:
    """Constant arithmetic wraps at the operand width."""
    ones = constant_bits_8616(0xFFFF, 16)
    one = constant_bits_8616(1, 16)
    assert binary_entry_bits_8616(Kind.ADD, ones, one) == (False,) * 16
    assert (
        binary_entry_bits_8616(Kind.SUB, (False,) * 16, one)
        == ones
    )


def test_symbolic_add_sub_refused(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """A provenance lane is not a constant; symbolic arithmetic refuses."""
    bits = _lane(byte_facts[0], *range(8))
    one = constant_bits_8616(1, 8)
    assert binary_entry_bits_8616(Kind.ADD, bits, one) is None
    assert binary_entry_bits_8616(Kind.SUB, bits, one) is None


def test_width_mismatched_operands_refused(
    byte_facts: tuple[EntryStackByteRead8616, EntryStackByteRead8616],
) -> None:
    """Boolean operands of unequal width refuse; no implicit widening."""
    low = _lane(byte_facts[0], *range(8))
    word = low + _lane(byte_facts[1], *range(8))
    assert binary_entry_bits_8616(Kind.OR, word, low) is None
    assert binary_entry_bits_8616(Kind.XOR, word, low) is None
