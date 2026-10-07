"""Prove bijective SSA byte-permutation roundtrips and typed refusals.

Layer: tests.
Responsibility: exercise ``tools.dosunit.contracts.memory_state_relations`` through real
SSA/Z3 materialization — full-array equality via ``materialize_function`` +
``_compare_functions`` and scalar byte equality via ``prove_terms_equal`` — with
no solver or loader mocks.  Covers real16 ``ss:bp`` templates, flat32 ``esp``
templates, overlapping and equal symbolic addresses, untouched-byte
preservation, typed refusals, and a meaningful one-way negative that must never
prove.
"""

from __future__ import annotations

from typing import Any

import pytest

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.contracts.memory_state_relations import (
    IDENTITY_MEMORY_PERMUTATION,
    MemoryByteSwap,
    MemoryPermutation,
    MemoryRelationReason,
    MemoryRelationRefusal,
)
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.compare.real16_call_contracts import materialize_function, prove_terms_equal

MEM: dict[str, Any] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
TIMEOUT_MS = 10_000


def _input(name: str, width: int) -> dict[str, Any]:
    """Scalar SSA input leaf."""
    return {"op": "input", "name": name, "width": width}


def _const(value: int, width: int) -> dict[str, Any]:
    """Canonical unsigned constant leaf."""
    return {"op": "const", "width": width, "value": hex(value)}


def _zext(term: dict[str, Any]) -> dict[str, Any]:
    """Zero-extend a narrower term to the width-32 address domain."""
    return {"op": "zext", "width": 32, "args": [term]}


def _byte(memory: dict[str, Any], address: dict[str, Any]) -> dict[str, Any]:
    """Width-8 little-endian byte load term."""
    return {"op": "loadle", "width": 8, "args": [memory, address]}


def _ss_bp(offset: int = 0) -> dict[str, Any]:
    """Real16 segmented ``ss:bp + offset`` address template (width 32)."""
    return {
        "op": "add",
        "width": 32,
        "args": [
            {"op": "shl", "width": 32, "args": [_zext(_input("ss", 16)), _const(4, 8)]},
            _zext({"op": "add", "width": 16, "args": [_input("bp", 16), _const(offset, 16)]}),
        ],
    }


def _esp(offset: int = 0) -> dict[str, Any]:
    """Flat32 ``esp + offset`` address template (width 32)."""
    if not offset:
        return _input("esp", 32)
    return {"op": "add", "width": 32, "args": [_input("esp", 32), _const(offset, 32)]}


def _state16() -> dict[str, dict[str, Any]]:
    """Symbolic real16 register state; every template input stays symbolic."""
    return {
        "ss": _input("ss", 16),
        "bp": _input("bp", 16),
        "bx": _input("bx", 16),
        "memory": MEM,
    }


def _state32() -> dict[str, dict[str, Any]]:
    """Symbolic flat32 register state."""
    return {"esp": _input("esp", 32), "memory": MEM}


def _memory_equal(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two full memory arrays through the real SSA/Z3 comparator."""
    oracle = materialize_function("oracle", {"memory": before})
    candidate = materialize_function("candidate", {"memory": after})
    return S._compare_functions(oracle, candidate, timeout_ms=TIMEOUT_MS)


def _prove_bytes_equal(left: dict[str, Any], right: dict[str, Any],
                       constraints: list[dict[str, Any]] | None = None) -> ProofStatus:
    """Prove two byte terms equal for all inputs under optional constraints."""
    return prove_terms_equal(left, right, TIMEOUT_MS, input_constraints=constraints)


# Three transpositions sharing address templates; every consecutive pair
# overlaps, so no disjointness assumption may be made by the implementation.
REAL16_PERMUTATION = MemoryPermutation(
    (
        MemoryByteSwap(_ss_bp(0), _ss_bp(2)),
        MemoryByteSwap(_ss_bp(2), _ss_bp(6)),
        MemoryByteSwap(_ss_bp(0), _ss_bp(4)),
        # ``bx`` is unrelated to ``ss:bp``: the two addresses may coincide or
        # differ depending on inputs; the swap must stay bijective either way.
        MemoryByteSwap(_ss_bp(0), _zext(_input("bx", 16))),
    )
)
FLAT32_PERMUTATION = MemoryPermutation(
    (
        MemoryByteSwap(_esp(0), _esp(8)),
        MemoryByteSwap(_esp(8), _esp(16)),
        MemoryByteSwap(_esp(0), _esp(16)),
    )
)
EQUAL_ADDRESS_PERMUTATION = MemoryPermutation((MemoryByteSwap(_ss_bp(2), _ss_bp(2)),))
CONST_PERMUTATION = MemoryPermutation(
    (
        MemoryByteSwap(_const(0x100, 32), _const(0x104, 32)),
        MemoryByteSwap(_const(0x104, 32), _const(0x108, 32)),
    )
)


@pytest.mark.parametrize(
    ("state", "permutation"),
    [
        (_state16(), REAL16_PERMUTATION),
        (_state16(), EQUAL_ADDRESS_PERMUTATION),
        (_state32(), FLAT32_PERMUTATION),
        ({"memory": MEM}, CONST_PERMUTATION),
    ],
    ids=["real16-ss-bp", "equal-addresses", "flat32-esp", "const-addresses"],
)
@pytest.mark.parametrize("inverse_first", [False, True], ids=["fwd-then-inv", "inv-then-fwd"])
def test_roundtrip_restores_memory(
    state: dict[str, dict[str, Any]], permutation: MemoryPermutation, inverse_first: bool
) -> None:
    """apply then inverse-apply (either order) restores the exact memory array."""
    moved = permutation.apply(MEM, state, inverse=inverse_first)
    restored = permutation.apply(moved, state, inverse=not inverse_first)
    compared = _memory_equal(MEM, restored)
    assert compared["status"] == "passed", compared


def test_inverse_helper_roundtrip() -> None:
    """The ``inverse()`` view applied through the same seam also restores."""
    state = _state16()
    moved = REAL16_PERMUTATION.inverse().apply(MEM, state)
    restored = REAL16_PERMUTATION.apply(moved, state)
    compared = _memory_equal(MEM, restored)
    assert compared["status"] == "passed", compared
    assert REAL16_PERMUTATION.inverse().inverse() == REAL16_PERMUTATION


def test_identity_permutation_preserves_memory() -> None:
    """An empty swap tuple is the identity relation by construction."""
    identity = MemoryPermutation()
    assert identity.is_identity
    assert IDENTITY_MEMORY_PERMUTATION.is_identity
    assert identity.inverse().is_identity
    state = _state16()
    assert identity.apply(MEM, state) is MEM
    compared = _memory_equal(MEM, identity.apply(MEM, state, inverse=True))
    assert compared["status"] == "passed", compared


def test_equal_address_swap_is_semantic_identity() -> None:
    """A self-transposition is structurally present but semantically a no-op."""
    permutation = EQUAL_ADDRESS_PERMUTATION
    assert not permutation.is_identity
    applied = permutation.apply(MEM, _state16())
    compared = _memory_equal(MEM, applied)
    assert compared["status"] == "passed", compared


@pytest.mark.parametrize(
    "constraints",
    [
        pytest.param(
            [{"name": "probe", "kind": "unsigned_range", "min": 0x200, "max": 0x2FF}],
            id="const-addresses",
        ),
        pytest.param(
            [{"name": "probe", "kind": "unsigned_range", "min": 0x10000, "max": 0x1FFFF}],
            id="symbolic-zext16-addresses",
        ),
    ],
)
def test_unswapped_bytes_are_preserved(constraints: list[dict[str, Any]]) -> None:
    """A provably-distinct probe address keeps its byte after the permutation."""
    if constraints[0]["min"] == 0x200:
        permutation = CONST_PERMUTATION
        state: dict[str, dict[str, Any]] = {"memory": MEM}
    else:
        # Symbolic zext16 addresses live in [0, 0xFFFF]; the probe cannot alias.
        permutation = MemoryPermutation(
            (
                MemoryByteSwap(_zext(_input("ax", 16)), _zext(_input("bx", 16))),
                MemoryByteSwap(_zext(_input("bx", 16)), _zext(_input("cx", 16))),
            )
        )
        state = {
            "ax": _input("ax", 16),
            "bx": _input("bx", 16),
            "cx": _input("cx", 16),
            "memory": MEM,
        }
    applied = permutation.apply(MEM, state)
    probe = _input("probe", 32)
    status = _prove_bytes_equal(_byte(applied, probe), _byte(MEM, probe), constraints)
    assert status is ProofStatus.PROVED, status


def test_one_way_swap_never_proves_unchanged_byte() -> None:
    """Meaningful negative: a transposition observably changes a swapped byte."""
    swap_a, swap_b = _const(0x100, 32), _const(0x104, 32)
    permutation = MemoryPermutation((MemoryByteSwap(swap_a, swap_b),))
    applied = permutation.apply(MEM, {"memory": MEM})
    status = _prove_bytes_equal(_byte(applied, swap_a), _byte(MEM, swap_a))
    assert status is not ProofStatus.PROVED, status
    compared = _memory_equal(MEM, applied)
    assert compared["status"] == "failed", compared


def test_refuses_narrow_address_template() -> None:
    """An address template that is not exactly width-32 is rejected."""
    with pytest.raises(MemoryRelationRefusal) as failure:
        MemoryByteSwap(_input("ax", 16), _const(0, 32))
    assert failure.value.reason is MemoryRelationReason.WIDTH


@pytest.mark.parametrize(
    "template",
    [
        pytest.param(
            {"op": "add", "width": 32, "args": [_input("esp", 32), _zext(_byte(MEM, _input("esp", 32)))]},
            id="load-inside-address",
        ),
        pytest.param(
            {"op": "add", "width": 32, "args": [MEM, _const(1, 32)]},
            id="mem-input-inside-address",
        ),
        pytest.param("not-a-term", id="non-dict-template"),
        pytest.param({"op": "add", "width": 32, "args": [_input("esp", 32), 7]}, id="non-dict-arg"),
        pytest.param({"width": 32, "args": []}, id="missing-op"),
    ],
)
def test_refuses_malformed_address_template(template: Any) -> None:
    """Memory-dependent or structurally invalid address templates fail closed."""
    with pytest.raises(MemoryRelationRefusal) as failure:
        MemoryByteSwap(template, _const(0, 32))
    assert failure.value.reason is MemoryRelationReason.MALFORMED


def test_refuses_missing_input_state() -> None:
    """An address template whose input leaf has no state binding refuses."""
    permutation = MemoryPermutation((MemoryByteSwap(_ss_bp(0), _ss_bp(4)),))
    state = {"bp": _input("bp", 16), "memory": MEM}
    with pytest.raises(MemoryRelationRefusal) as failure:
        permutation.apply(MEM, state)
    assert failure.value.reason is MemoryRelationReason.MISSING


def test_refuses_missing_memory_term() -> None:
    """apply over a nonexistent memory term refuses instead of guessing."""
    permutation = MemoryPermutation((MemoryByteSwap(_ss_bp(0), _ss_bp(4)),))
    with pytest.raises(MemoryRelationRefusal) as failure:
        permutation.apply(None, _state16())  # type: ignore[arg-type]
    assert failure.value.reason is MemoryRelationReason.MISSING


def test_refuses_non_memory_root() -> None:
    """A scalar term cannot stand in for the permuted byte array."""
    permutation = MemoryPermutation((MemoryByteSwap(_ss_bp(0), _ss_bp(4)),))
    with pytest.raises(MemoryRelationRefusal) as failure:
        permutation.apply(_input("sp", 16), _state16())
    assert failure.value.reason is MemoryRelationReason.MALFORMED


def test_refuses_substituted_memory_dependent_address() -> None:
    """State may not smuggle a load into an evaluated address template."""
    state = {"ss": _byte(MEM, _const(0, 32)), "bp": _input("bp", 16), "memory": MEM}
    permutation = MemoryPermutation((MemoryByteSwap(_ss_bp(0), _ss_bp(4)),))
    with pytest.raises(MemoryRelationRefusal) as failure:
        permutation.apply(MEM, state)
    assert failure.value.reason is MemoryRelationReason.MALFORMED


def test_refuses_non_swap_element() -> None:
    """A bare term inside the swap tuple is not a typed transposition."""
    with pytest.raises(MemoryRelationRefusal) as failure:
        MemoryPermutation((_ss_bp(0),))  # type: ignore[arg-type]
    assert failure.value.reason is MemoryRelationReason.MALFORMED
