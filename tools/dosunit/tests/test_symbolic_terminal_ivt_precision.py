"""Pure memory-chain controls for source-bound real16 IVT query precision.

Layer: tests.
Responsibility: preserve overlap, wrap, endianness and newest-store evidence.
"""
from __future__ import annotations

from collections.abc import Callable

import tools.dosunit.compare.straightline_ssa as S
import tools.dosunit.compare.symbolic_terminal_real16_services as SERVICES
from tools.dosunit.runtime.real16_program_vectors import VECTOR_BYTES

_ADDRESS = 0x84
"""Synthetic queried vector slot (DOS vector 0x21)."""
_INITIAL = (0x11, 0x22, 0x33, 0x44)
"""Declared initial bytes for the four queried IVT bytes."""
_SYMBOLIC_ADDRESS = S.SsaExpr("input", 32, name="symbolic_store_address")
"""A store destination ``const_eval`` cannot prove."""


def _const(value: int, width: int) -> S.SsaExpr:
    """Return one proved constant term."""
    return S.SsaExpr("const", width, value=value)


def _mem_input() -> S.SsaExpr:
    """Return the shared initial-memory chain root."""
    return S.SsaExpr("mem_input", 0, name="mem")


def _symbolic_data(width: int) -> S.SsaExpr:
    """Return store data ``const_eval`` cannot prove (a memory load term)."""
    return S.SsaExpr("loadle", width, (_mem_input(), _const(0x300, 32)))


def _store(prev: S.SsaExpr, base: int | S.SsaExpr, data: S.SsaExpr, op: str = "storele") -> S.SsaExpr:
    """Apply one store on top of ``prev``; the newest store is outermost."""
    address = base if isinstance(base, S.SsaExpr) else _const(base, 32)
    return S.SsaExpr(op, 0, (prev, address, data))


def _initial_bytes(address: int, size: int) -> bytes | None:
    """Resolve declared initial bytes inside the queried slot only."""
    if address >= _ADDRESS and address + size <= _ADDRESS + VECTOR_BYTES:
        return bytes(_INITIAL[address - _ADDRESS : address - _ADDRESS + size])
    return None


def _no_initial_bytes(address: int, size: int) -> bytes | None:
    """Refuse every initial-byte query (undeclared coverage)."""
    return None


_ZERO_INITIAL = (0xAA, 0xBB, 0xCC, 0xDD)
"""Declared initial bytes for the slot at linear address 0."""


def _initial_bytes_zero(address: int, size: int) -> bytes | None:
    """Resolve declared initial bytes inside the address-0 slot only."""
    if address >= 0 and address + size <= VECTOR_BYTES:
        return bytes(_ZERO_INITIAL[address : address + size])
    return None


def _live(
    mem_version: S.SsaExpr, initial: Callable[[int, int], bytes | None] = _initial_bytes
) -> bytes | None:
    """Call the module under test at the synthetic slot."""
    return SERVICES.live_ivt_bytes(mem_version, _ADDRESS, initial)


# --- Preserved behavior: identical results on baseline and staged ----------


def test_initial_bytes_without_stores() -> None:
    """No stores resolves to the declared initial bytes."""
    assert _live(_mem_input()) == bytes(_INITIAL)


def test_full_cover_storele() -> None:
    """One concrete little-endian store supplies every byte."""
    mem = _store(_mem_input(), _ADDRESS, _const(0xA1B2C3D4, 32))
    assert _live(mem) == bytes((0xD4, 0xC3, 0xB2, 0xA1))


def test_full_cover_storebe() -> None:
    """One concrete big-endian store supplies every byte."""
    mem = _store(_mem_input(), _ADDRESS, _const(0xA1B2C3D4, 32), op="storebe")
    assert _live(mem) == bytes((0xA1, 0xB2, 0xC3, 0xD4))


def test_partial_overlap_storele16() -> None:
    """A concrete 16-bit store covers only the upper two queried bytes."""
    mem = _store(_mem_input(), _ADDRESS + 2, _const(0xBEEF, 16))
    assert _live(mem) == bytes((0x11, 0x22, 0xEF, 0xBE))


def test_partial_overlap_storebe16() -> None:
    """Big-endian byte order applies inside a partial overlap."""
    mem = _store(_mem_input(), _ADDRESS + 2, _const(0xBEEF, 16), op="storebe")
    assert _live(mem) == bytes((0x11, 0x22, 0xBE, 0xEF))


def test_byte_store_partial_cover() -> None:
    """A single-byte concrete store covers one middle byte."""
    mem = _store(_mem_input(), _ADDRESS + 1, _const(0x7E, 8))
    assert _live(mem) == bytes((0x11, 0x7E, 0x33, 0x44))


def test_store_spanning_past_slot() -> None:
    """A wider concrete store starting below the slot covers all bytes."""
    mem = _store(_mem_input(), _ADDRESS - 2, _const(0x010203040506, 48))
    # LE bytes at 0x82..0x87: 06 05 04 03 02 01 -> slot reads 04 03 02 01
    assert _live(mem) == bytes((0x04, 0x03, 0x02, 0x01))


def test_newest_write_wins_overlapping() -> None:
    """A newer partial store shadows the older full store's bytes."""
    mem = _store(
        _store(_mem_input(), _ADDRESS, _const(0x11111111, 32)),
        _ADDRESS + 1,
        _const(0x00FF, 16),
    )
    assert _live(mem) == bytes((0x11, 0xFF, 0x00, 0x11))


def test_newest_write_wins_storebe_over_storele() -> None:
    """Ordering is endian-independent: the newer store shadows bytes."""
    mem = _store(
        _store(_mem_input(), _ADDRESS, _const(0x11111111, 32)),
        _ADDRESS,
        _const(0xCAFE, 16),
        op="storebe",
    )
    assert _live(mem) == bytes((0xCA, 0xFE, 0x11, 0x11))


def test_disjoint_concrete_store_ignored() -> None:
    """A proved disjoint concrete store changes nothing."""
    mem = _store(_mem_input(), 0x200, _const(0xDEADBEEF, 32))
    assert _live(mem) == bytes(_INITIAL)


# --- Preserved refusals: must stay None on both -----------------------------


def test_overlap_symbolic_data_refuses() -> None:
    """Symbolic data covering unresolved bytes stays a refusal."""
    mem = _store(_mem_input(), _ADDRESS, _symbolic_data(32))
    assert _live(mem) is None


def test_partial_overlap_symbolic_data_refuses() -> None:
    """Symbolic data over even one unresolved byte stays a refusal."""
    mem = _store(_mem_input(), _ADDRESS + 2, _symbolic_data(16))
    assert _live(mem) is None


def test_symbolic_address_over_unresolved_refuses() -> None:
    """An unproved store address possibly overlaps unresolved bytes."""
    mem = _store(_mem_input(), _SYMBOLIC_ADDRESS, _const(0x1234, 16))
    assert _live(mem) is None


def test_partial_cover_then_symbolic_address_refuses() -> None:
    """Bytes left unresolved may still be hit by a symbolic-addressed store."""
    mem = _store(
        _store(_mem_input(), _SYMBOLIC_ADDRESS, _const(0x9999, 16)),
        _ADDRESS,
        _const(0x1111, 16),
    )
    assert _live(mem) is None


def test_symbolic_address_between_covers_refuses() -> None:
    """A symbolic store between two partial covers may hit either remainder."""
    mem = _store(
        _store(
            _store(_mem_input(), _ADDRESS, _const(0x1111, 16)),
            _SYMBOLIC_ADDRESS,
            _const(0x9999, 16),
        ),
        _ADDRESS + 2,
        _const(0x2222, 16),
    )
    assert _live(mem) is None


def test_non_mem_input_root_refuses() -> None:
    """A chain not rooted at the shared input is unproved."""
    bad_root = S.SsaExpr("ite", 0, (_mem_input(), _mem_input(), _mem_input()))
    assert _live(bad_root) is None


def test_full_cover_non_mem_input_root_refuses() -> None:
    """Malformed-chain refusal survives even when every byte is covered."""
    bad_root = S.SsaExpr("phi", 0, (_mem_input(), _mem_input()))
    mem = _store(bad_root, _ADDRESS, _const(0x11223344, 32))
    assert _live(mem) is None


def test_full_cover_older_store_bad_root_refuses() -> None:
    """Skipped older stores do not waive the shared-input root check."""
    bad_root = S.SsaExpr("phi", 0, (_mem_input(), _mem_input()))
    mem = _store(
        _store(bad_root, _SYMBOLIC_ADDRESS, _symbolic_data(16)),
        _ADDRESS,
        _const(0x11223344, 32),
    )
    assert _live(mem) is None


def test_undeclared_initial_coverage_refuses() -> None:
    """Unresolved bytes with no declared initializer are unproved."""
    assert _live(_mem_input(), initial=_no_initial_bytes) is None


def test_partial_undeclared_initial_refuses() -> None:
    """Partially declared initial coverage is still a refusal."""

    def partial(address: int, size: int) -> bytes | None:
        if address >= _ADDRESS and address + size <= _ADDRESS + 2:
            return bytes(_INITIAL[address - _ADDRESS : address - _ADDRESS + size])
        return None

    mem = _store(_mem_input(), _ADDRESS, _const(0x1111, 16))
    assert _live(mem, initial=partial) is None


# --- Malformed/wrap refusals: red on before/ and review-baseline/ -----------


def test_wrapping_store_into_query_zero_refuses() -> None:
    """A store wrapping the 32-bit boundary into the queried slot refuses.

    ``_z3_store`` resizes every store address to 32 bits and indexes
    bytes with 32-bit ``BitVecVal`` offsets, so byte positions are
    ``(base + index) mod 2**32``: base 0xFFFFFFFE with width 32 writes
    0xFFFFFFFE..0xFFFFFFFF and 0x0..0x1, reaching the queried slot at
    linear address 0. The plain half-open interval cannot express the
    wrapped tail, so the helper refuses rather than claim disjointness.
    """
    mem = _store(_mem_input(), 0xFFFFFFFE, _symbolic_data(32))
    assert SERVICES.live_ivt_bytes(mem, 0, _initial_bytes_zero) is None


def test_wrapping_store_bounded_refusal() -> None:
    """A wrapping range refuses even when its tail misses the queried slot.

    Base 0xFFFFFFFC with width 64 wraps the modulus boundary; the wrapped
    tail (0x0..0x3) cannot reach the queried slot, but the admitted
    contract is a bounded refusal — coverage is never split across the
    modulus boundary.
    """
    mem = _store(_mem_input(), 0xFFFFFFFC, _symbolic_data(64))
    assert _live(mem) is None


def test_wrapping_store_concrete_data_refuses() -> None:
    """The wrap refusal is about the address range, not data provability.

    Even with proved concrete data the helper refuses rather than model
    modulo-32 coverage, keeping the admitted domain a bounded
    under-approximation.
    """
    mem = _store(_mem_input(), 0xFFFFFFFE, _const(0x11223344, 32))
    assert SERVICES.live_ivt_bytes(mem, 0, _initial_bytes_zero) is None


def test_sub_byte_store_refuses() -> None:
    """Non-byte-addressable store data is a malformed term, not a no-op.

    ``_z3_store`` raises ``DosUnitError`` for ``width % 8 != 0``; such a
    chain is malformed and the live bytes are unproved.
    """
    mem = _store(_mem_input(), _ADDRESS, _const(0xF, 4))
    assert _live(mem) is None


def test_sub_byte_symbolic_store_refuses() -> None:
    """A sub-byte store refuses on width alone, before data provability."""
    mem = _store(_mem_input(), _ADDRESS, _symbolic_data(4))
    assert _live(mem) is None


def test_zero_width_store_refuses() -> None:
    """A zero-width data term is malformed, not a covers-nothing store."""
    mem = _store(_mem_input(), _ADDRESS, S.SsaExpr("const", 0, value=0))
    assert _live(mem) is None


def test_full_cover_older_malformed_store_refuses() -> None:
    """Malformed store terms refuse even under a complete newer cover.

    The width check is unconditional, like the ``mem_input`` root check:
    a malformed chain is unproved no matter how thoroughly newer stores
    would have shadowed the term.
    """
    mem = _store(
        _store(_mem_input(), _ADDRESS, _const(0xF, 4)),
        _ADDRESS,
        _const(0x11223344, 32),
    )
    assert _live(mem) is None


# --- Improved applicability: green on staged, expected red on baseline ------


def test_improved_disjoint_storele_symbolic_data() -> None:
    """A disjoint concrete-address store never needs concrete data."""
    mem = _store(_mem_input(), 0x200, _symbolic_data(32))
    assert _live(mem) == bytes(_INITIAL)


def test_improved_disjoint_storebe_symbolic_data() -> None:
    """The disjointness check is endian-independent."""
    mem = _store(_mem_input(), 0x200, _symbolic_data(16), op="storebe")
    assert _live(mem) == bytes(_INITIAL)


def test_improved_below_adjacent_symbolic_data() -> None:
    """A store ending exactly at the slot is disjoint."""
    mem = _store(_mem_input(), _ADDRESS - 4, _symbolic_data(32))
    assert _live(mem) == bytes(_INITIAL)


def test_improved_above_adjacent_symbolic_data() -> None:
    """A store starting exactly after the slot is disjoint."""
    mem = _store(_mem_input(), _ADDRESS + VECTOR_BYTES, _symbolic_data(16))
    assert _live(mem) == bytes(_INITIAL)


def test_improved_high_address_symbolic_data() -> None:
    """A high 32-bit range that does not wrap the boundary stays disjoint."""
    mem = _store(_mem_input(), 0xFFFFFFF0, _symbolic_data(32))
    assert _live(mem) == bytes(_INITIAL)


def test_improved_disjoint_store_under_partial_cover() -> None:
    """Disjoint symbolic-data stores stay irrelevant with partial cover."""
    mem = _store(
        _store(_mem_input(), 0x400, _symbolic_data(16)),
        _ADDRESS,
        _const(0x2222, 16),
    )
    assert _live(mem) == bytes((0x22, 0x22, 0x33, 0x44))


def test_improved_shadowed_overlap_symbolic_data() -> None:
    """An older store overlapping only covered bytes needs no data."""
    mem = _store(
        _store(_mem_input(), _ADDRESS + 2, _symbolic_data(16)),
        _ADDRESS + 2,
        _const(0xCAFE, 16),
    )
    assert _live(mem) == bytes((0x11, 0x22, 0xFE, 0xCA))


def test_improved_full_cover_hides_older_symbolic_address() -> None:
    """Once every byte is covered an older symbolic address cannot bite."""
    mem = _store(
        _store(_mem_input(), _SYMBOLIC_ADDRESS, _const(0x1234, 16)),
        _ADDRESS,
        _const(0xA1B2C3D4, 32),
    )
    assert _live(mem) == bytes((0xD4, 0xC3, 0xB2, 0xA1))


def test_improved_full_cover_hides_older_unknown_stores() -> None:
    """Symbolic data and symbolic addresses under full cover are skipped."""
    tail = _store(
        _store(_mem_input(), _SYMBOLIC_ADDRESS, _symbolic_data(16)),
        0x400,
        _symbolic_data(16),
        op="storebe",
    )
    mem = _store(tail, _ADDRESS, _const(0x0BADF00D, 32))
    assert _live(mem) == bytes((0x0D, 0xF0, 0xAD, 0x0B))
