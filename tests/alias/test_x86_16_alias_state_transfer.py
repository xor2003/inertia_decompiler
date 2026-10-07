from __future__ import annotations

from inertia.alias.domains import AX, FULL16, HIGH8, LOW8
from inertia.alias.state import AliasCell, AliasState
from inertia.alias.transfer import (
    RegisterConcatExpr,
    RegisterSliceExpr,
    read_register,
    synthesize_full_register,
    write_register,
)


def test_x86_16_alias_state_tracks_versions_and_ready_cells() -> None:
    state = AliasState()
    token = object()

    assert state.version_of(AX) == 0
    version = state.bump_domain(AX)
    cell = state.set(AX, FULL16, token, version=version)

    assert version == 1
    assert cell == AliasCell(AX, FULL16, token, version=1)
    assert cell.is_ready() is True
    assert state.get(AX, FULL16) is cell


def test_x86_16_alias_state_marks_and_clears_domain_cells() -> None:
    state = AliasState()
    state.set(AX, FULL16, "full")

    state.mark_needs_synthesis(AX, FULL16)

    marked = state.get(AX, FULL16)
    assert marked is not None
    assert marked.needs_synthesis is True
    assert marked.is_ready() is False

    state.clear_domain(AX)
    assert state.get(AX, FULL16) is None


def test_x86_16_alias_transfer_reads_full_write_and_derived_slices() -> None:
    state = AliasState()
    token = object()

    written = write_register(state, "ax", token)

    assert written is not None
    assert read_register(state, "ax") is token
    low = read_register(state, "al")
    high = read_register(state, "ah")
    assert low == RegisterSliceExpr(token, LOW8)
    assert high == RegisterSliceExpr(token, HIGH8)


def test_x86_16_alias_transfer_synthesizes_full_from_byte_writes() -> None:
    state = AliasState()

    write_register(state, "al", 0x34)
    write_register(state, "ah", 0x12)

    assert synthesize_full_register(state, "ax") == RegisterConcatExpr(high=0x12, low=0x34)
    assert read_register(state, "ax") == RegisterConcatExpr(high=0x12, low=0x34)


def test_x86_16_alias_transfer_refuses_unknown_registers() -> None:
    state = AliasState()

    assert write_register(state, "unknown", object()) is None
    assert read_register(state, "unknown") is None
    assert synthesize_full_register(state, "unknown") is None
