"""Distinct protected spans never suppress fresh byte authentication or admission counts."""

import time
from types import SimpleNamespace
from typing import cast

import pytest

from inertia.ir import real16_invocation_domain as owner

pytestmark = pytest.mark.decompiler
from inertia.ir.core import IRBlock, IRInstr


def test_repeated_fetches_bind_fresh_and_keep_public_multiplicity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Repeated ranges remain protective while every decode and native bind repeats."""
    ctx = cast(
        owner._PathCensusContext8616,
        SimpleNamespace(
            selector=0x100, image=None, project=None, chain=None,
            manifest=set(), machine_bytes={}, fetched_span_admissions=0,
        ),
    )
    block = IRBlock(0x1000, instrs=(IRInstr("RET", None, (), addr=0x1000),))
    decoded = [{0x1000: (1, b"\xc3")}, {0x1000: (2, b"\x66\xc3")}, {0x1000: (1, b"\xc3")}]
    calls = []

    def decode(_ctx: owner._PathCensusContext8616, _address: int) -> dict[int, tuple[int, bytes]]:
        return decoded[len(calls)]

    def bind(machine: dict[int, tuple[int, bytes]], scope: set[int], **_kwargs: object) -> None:
        calls.append((machine, scope))

    monkeypatch.setattr(owner, "_machine_census_8616", decode)
    monkeypatch.setattr(owner, "_bind_fetched_bytes_8616", bind)
    for _ in range(3):
        assert owner._census_block_bytes_8616(ctx, block, stop_after=None) is None
    assert len(calls) == 3 and ctx.fetched_span_admissions == 3
    assert ctx.manifest == {(0x1000, 1), (0x1000, 2)}
    # Same address with changed length must keep BOTH protected extents.
    assert ctx.machine_bytes[0x1000] == b"\xc3"

    def revoked(*_args: object, **_kwargs: object) -> owner.Real16InvocationFailure8616:
        return owner.Real16InvocationFailure8616.PATH_DECODE_MISMATCH

    monkeypatch.setattr(owner, "_machine_census_8616", lambda *_args: decoded[0])
    monkeypatch.setattr(owner, "_bind_fetched_bytes_8616", revoked)
    assert (
        owner._census_block_bytes_8616(ctx, block, stop_after=None)
        == owner.Real16InvocationFailure8616.PATH_DECODE_MISMATCH
    )
    assert ctx.fetched_span_admissions == 3


def test_saved_actual_input_shape_charges_every_raw_insert() -> None:
    """Dedup saves downstream checks after all4113 raw insertions remain billed."""
    # Recorded main geometry:4113 inputs,527 unique spans,38 union ranges.
    unique = [(1000 + group * 100 + part, 1) for group in range(38) for part in range(14)]
    unique = unique[:527]
    raw = (unique * 8)[:4113]
    assert len(raw) == 4113 and len(set(raw)) == 527
    ctx = cast(
        owner._PathCensusContext8616,
        SimpleNamespace(
            manifest=set(raw),
            work_units=len(raw),
            accounted_work_units=0,
            work_limit=20000,
            deadline=time.monotonic() + 10,
        ),
    )
    memory = owner.PathMemory8616(dict.fromkeys(range(8), 0), {8, 9})
    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616():
        assert owner._feasibility_code_unmodified_8616(ctx, memory)
    # All original inserts plus ten writes and 527 distinct inputs are billed.
    # Disjoint bounds eliminate merging and searching the 38 union ranges.
    assert ctx.work_units == 4113 + 10 + 527
