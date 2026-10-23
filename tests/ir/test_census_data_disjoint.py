"""Declared-data checks skip only spans proven disjoint from the fetched envelope.

The fetched-byte envelope is accumulated during the mandatory byte-binding
traversal from the authenticated machine census. It covers every bound
in-scope instruction extent, including multi-byte rows and interior holes,
so a declared-data span outside it cannot touch a fetched byte. Spans that
intersect the envelope keep their per-instruction billing and checks.
"""

import time
from types import SimpleNamespace
from typing import cast

import pytest

from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredEntryMemory8616,
    DeclaredFunctionEntryAdmission8616,
    DeclaredFunctionEntrySpec8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from inertia.ir import real16_invocation_domain as owner
from inertia.ir.core import IRFunctionArtifact

pytestmark = pytest.mark.decompiler

_SELECTOR = 0x1000
_BASE = _SELECTOR << 4
_BLOB = bytes(range(0x100))


def _image(blob: bytes = _BLOB, *, in_scope: bool = True) -> object:
    return SimpleNamespace(
        chunks=((_BASE, blob),),
        code_ranges=(
            SimpleNamespace(contains=lambda _addr, _size=1: in_scope),
        ),
    )


def _project(blob: bytes = _BLOB) -> object:
    def load(addr: int, n: int) -> bytes:
        return blob[addr - _BASE: addr - _BASE + n]

    return SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=load))
    )


def _ctx(
    chain: object, *, image: object | None = None, project: object | None = None
) -> owner._PathCensusContext8616:
    return cast(
        owner._PathCensusContext8616,
        SimpleNamespace(
            selector=_SELECTOR,
            image=_image() if image is None else image,
            project=_project() if project is None else project,
            chain=chain,
            work_units=0,
            work_limit=20000,
            deadline=time.monotonic() + 60,
            accounted_work_units=0,
        ),
    )


def _link(*spans: DeclaredEntryMemory8616) -> owner.DeclaredFunctionEntryLink8616:
    admission = DeclaredFunctionEntryAdmission8616(
        spec=cast(
            DeclaredFunctionEntrySpec8616, SimpleNamespace(memory=spans)
        ),
        source=b"",
        loaded_module=b"",
        environment_sha256="",
        declaration_sha256="",
    )
    return owner.DeclaredFunctionEntryLink8616(
        admission=admission,
        artifact=cast(IRFunctionArtifact, None),
        boundary=cast(ExactFunctionRangeBoundary8616, None),
    )


def _machine(count: int) -> dict[int, tuple[int, bytes]]:
    return {_BASE + i: (1, _BLOB[i: i + 1]) for i in range(count)}


def test_envelope_disjoint_span_bills_one_determination() -> None:
    """A span outside the authenticated fetched envelope needs one check."""
    machine = _machine(64)  # fetched envelope [_BASE, _BASE + 0x40)
    ctx = _ctx(_link(DeclaredEntryMemory8616(_BASE + 0x200, b"\x00" * 8)))
    assert (
        owner._bind_census_fetched_bytes_8616(ctx, machine, set(machine)) is None
    )
    assert ctx.work_units == 1


def test_endpoint_touching_spans_are_disjoint() -> None:
    """A span ending at the envelope low or starting at its high cannot overlap."""
    machine = _machine(64)  # fetched envelope [_BASE, _BASE + 0x40)
    ctx = _ctx(
        _link(
            DeclaredEntryMemory8616(_BASE - 0x10, b"\x00" * 0x10),
            DeclaredEntryMemory8616(_BASE + 0x40, b"\x00" * 0x10),
        )
    )
    assert (
        owner._bind_census_fetched_bytes_8616(ctx, machine, set(machine)) is None
    )
    assert ctx.work_units == 2


def test_overlapping_span_still_refuses() -> None:
    """Envelope intersection keeps the refusal for a real code/data overlap."""
    machine = _machine(64)
    ctx = _ctx(_link(DeclaredEntryMemory8616(_BASE + 0x10, b"\x00" * 8)))
    assert owner._bind_census_fetched_bytes_8616(
        ctx, machine, set(machine)
    ) is owner.Real16InvocationFailure8616.CODE_WRITE_VIOLATION


def test_multibyte_tail_overlap_refuses() -> None:
    """The instruction extent, not its start row, delimits the fetched bytes."""
    machine = {_BASE: (6, _BLOB[0:6])}
    ctx = _ctx(_link(DeclaredEntryMemory8616(_BASE + 3, b"\x00" * 2)))
    assert owner._bind_census_fetched_bytes_8616(
        ctx, machine, set(machine)
    ) is owner.Real16InvocationFailure8616.CODE_WRITE_VIOLATION


def test_hole_span_inside_envelope_keeps_pair_checks() -> None:
    """An envelope hole admits only after every pair check runs honestly."""
    machine = {
        _BASE: (4, _BLOB[0:4]),
        _BASE + 0x10: (4, _BLOB[0x10:0x14]),
    }
    # Envelope [_BASE, _BASE + 0x14) covers the hole [_BASE + 4, _BASE + 0x10).
    ctx = _ctx(_link(DeclaredEntryMemory8616(_BASE + 0x8, b"\x00" * 4)))
    assert (
        owner._bind_census_fetched_bytes_8616(ctx, machine, set(machine)) is None
    )
    assert ctx.work_units == 1 + len(machine)


def test_missing_extent_on_nonempty_scope_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing binding result never means a nonempty fetched set is empty."""
    machine = _machine(4)
    ctx = _ctx(_link(DeclaredEntryMemory8616(_BASE, b"\x00")))
    monkeypatch.setattr(owner, "_bind_fetched_bytes_8616", lambda *_args, **_kwargs: None)
    assert owner._bind_census_fetched_bytes_8616(
        ctx, machine, set(machine)
    ) is owner.Real16InvocationFailure8616.PATH_DECODE_MISMATCH


@pytest.mark.parametrize("limit", [0, 1])
def test_disjoint_determination_respects_exact_work_limit(limit: int) -> None:
    """The cheap path bills its operation and refuses at the first excess."""
    machine = _machine(64)
    ctx = _ctx(_link(DeclaredEntryMemory8616(_BASE + 0x200, b"\x00")))
    ctx.work_limit = limit
    result = owner._bind_census_fetched_bytes_8616(ctx, machine, set(machine))
    assert result is (None if limit == 1 else owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED)
    assert ctx.work_units == 1


def test_disjoint_determination_preserves_deadline() -> None:
    """Disjointness does not admit a census whose original deadline expired."""
    machine = _machine(64)
    ctx = _ctx(_link(DeclaredEntryMemory8616(_BASE + 0x200, b"\x00")))
    ctx.deadline = time.monotonic() - 1
    assert owner._bind_census_fetched_bytes_8616(
        ctx, machine, set(machine)
    ) is owner.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED


def test_empty_scope_skips_span_work() -> None:
    """An empty fetched scope stays valid and bills no span determination."""
    ctx = _ctx(_link(DeclaredEntryMemory8616(_BASE, b"\x00" * 8)))
    assert owner._bind_census_fetched_bytes_8616(ctx, {}, set()) is None
    assert ctx.work_units == 0


def test_no_declared_authority_skips_span_work() -> None:
    """A non-declared chain keeps the old no-authority early exit."""
    machine = _machine(8)
    ctx = _ctx(None)
    assert (
        owner._bind_census_fetched_bytes_8616(ctx, machine, set(machine)) is None
    )
    assert ctx.work_units == 0


def test_stale_loader_bytes_still_refuse() -> None:
    """Envelope work never substitutes for the fresh loader byte bind."""
    machine = _machine(4)
    ctx = _ctx(_link(), project=_project(bytes(0x100)))
    assert owner._bind_census_fetched_bytes_8616(
        ctx, machine, set(machine)
    ) is owner.Real16InvocationFailure8616.NATIVE_BYTES_MISMATCH


def test_missing_loader_bytes_still_refuse() -> None:
    """An unreadable loader region still refuses before any span check."""
    machine = _machine(4)

    def load(_addr: int, _n: int) -> bytes:
        raise KeyError

    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=load))
    )
    ctx = _ctx(_link(), project=project)
    assert owner._bind_census_fetched_bytes_8616(
        ctx, machine, set(machine)
    ) is owner.Real16InvocationFailure8616.NATIVE_BYTES_MISMATCH


def test_code_scope_violation_precedes_span_checks() -> None:
    """Bytes outside declared code ranges refuse before the envelope is used."""
    machine = _machine(4)
    ctx = _ctx(_link(), image=_image(in_scope=False))
    assert owner._bind_census_fetched_bytes_8616(
        ctx, machine, set(machine)
    ) is owner.Real16InvocationFailure8616.CODE_SCOPE_VIOLATION
