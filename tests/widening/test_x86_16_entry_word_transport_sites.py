"""Independent selected-site geometry and relation-counter controls.

Layer: Widening regression tests.
Responsibility: refuse contradictory target metadata and snapshot views
without weakening the canonical Alias/Word evidence or single-fact census.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from inertia.ir.core import IRBlock, IRInstr, IRValue, MemSpace
import inertia.widening.entry_word_transport as _TRANSPORT
from tests.fixtures.entry_stack_byte_test_support import _artifact
from tests.widening.test_x86_16_entry_stack_word_values import _word_instrs

from inertia.alias.entry_stack_bytes import prove_entry_stack_bytes_8616
from inertia.widening.entry_stack_word_values import prove_entry_stack_word_value_8616


def _target() -> IRInstr:
    """The selected plain full-word register assignment."""
    return IRInstr(
        "MOV", IRValue(MemSpace.REG, name="ip", size=2),
        (IRValue(MemSpace.REG, name="cx", size=2),), size=2,
    )


def _prove(target: IRInstr) -> object:
    """Replay canonical storage and word proofs on one acyclic two-block input."""
    artifact = _artifact(_word_instrs())
    entry = artifact.blocks[0]
    end = entry.addr + 16
    artifact = replace(artifact, blocks=(
        replace(entry, successor_addrs=(end,)), IRBlock(end, (target,)),
    ))
    word = prove_entry_stack_word_value_8616(
        artifact, prove_entry_stack_bytes_8616(artifact), 7,
    )
    assert word.fact is not None
    return _TRANSPORT.prove_entry_word_transport_8616(artifact, word, end, 0)


def test_plain_selected_transport_is_a_single_closed_fact() -> None:
    """A selected word relation counts facts, not unmaterialized instructions."""
    proof = _prove(_target())
    assert proof.verdict is _TRANSPORT.EntryWordTransportVerdict8616.PROVEN
    assert (proof.raw_fact_count, proof.normalized_fact_count,
            proof.classified_fact_count, proof.materialized_count,
            proof.failure_count) == (1, 1, 1, 1, 0)


@pytest.mark.parametrize("case", ["snapshot", "destination_literal", "instruction_width"])
def test_selected_target_metadata_corruption_refuses(case: str) -> None:
    """Each changed field independently contradicts an exact MOV value proof."""
    target = _target()
    if case == "snapshot":
        source = target.args[0]
        assert isinstance(source, IRValue)
        target = replace(target, args=(replace(source, source_tmp=999),))
    elif case == "destination_literal":
        assert target.dst is not None
        target = replace(target, dst=replace(target.dst, const=123))
    else:
        target = replace(target, size=4)
    assert _prove(target).verdict is _TRANSPORT.EntryWordTransportVerdict8616.REFUSED


def test_displaced_source_refuses() -> None:
    """A changed source view cannot be used as the plain current register."""
    target = _target()
    source = target.args[0]
    assert isinstance(source, IRValue)
    assert _prove(replace(target, args=(replace(source, offset=1),))).verdict is (
        _TRANSPORT.EntryWordTransportVerdict8616.REFUSED
    )
