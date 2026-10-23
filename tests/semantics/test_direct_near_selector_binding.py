"""Declared-selector callsite binding through a mocked producer boundary.

The canonical producer ``inertia.ir.declared_selector_invariant`` is owned by
a concurrent change; these controls install a precise boundary double at that
exact module path so the lazy consumer is exercised against the real
production code. The default and full-invocation paths never resolve it.
"""
from __future__ import annotations

import io
import sys
import types
from dataclasses import dataclass, replace
from typing import NamedTuple, cast

import angr
import pytest

import tests.lowering.test_x86_16_near_return_expression as near_return
import tests.semantics.test_direct_near_call_target_binding as binding_tests
from inertia.ir.core import IRBlock, IRInstr
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallCoordinates8616,
    DirectNearCallTargetBinding8616,
    _retained_binding_fields_equal_8616,
    prove_direct_near_call_target_binding_at_coordinates_8616,
)
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallTargetBindingFailure8616 as Failure,
)
from tools.dosunit.recursive_proofs.real16_loader_arch import real16_loader_arch


@dataclass(frozen=True, slots=True)
class _FakeDeclaredScope8616:
    """Scope double retaining the exact project object per the contract."""

    project: object


@dataclass(frozen=True, slots=True)
class DeclaredSelectorCallsite8616:
    """Boundary double at the exact canonical producer contract shape."""

    scope: _FakeDeclaredScope8616
    block: object
    instruction: object
    callsite_addr: int
    target_addr: int
    next_addr: int
    incoming_cs: int


class _ProducerGate:
    """``consume_declared_selector_callsite_8616`` boundary double."""

    def __init__(self) -> None:
        """Start authenticating with an empty consumption ledger."""
        self.verdict = True
        self.calls: list[tuple[object, object]] = []

    def __call__(self, project: object, projection: object) -> bool:
        """Record one authentication request and return the set verdict."""
        self.calls.append((project, projection))
        return self.verdict


@pytest.fixture
def producer_gate(monkeypatch: pytest.MonkeyPatch) -> _ProducerGate:
    """Install the precise producer surface at its canonical module path."""
    gate = _ProducerGate()
    module = types.ModuleType("inertia.ir.declared_selector_invariant")
    module.DeclaredSelectorCallsite8616 = DeclaredSelectorCallsite8616
    module.consume_declared_selector_callsite_8616 = gate
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return gate


class WrapFixture(NamedTuple):
    """One high-address E8 whose target fits only one selector window."""

    project: angr.Project
    block: IRBlock
    call: IRInstr


def _wrap_fixture() -> WrapFixture:
    """Build a fresh binary-derived callsite outside the universal window."""
    head = 0x10020
    image = bytearray(0x11000)
    image[head:head + 4] = bytes.fromhex("e80001c3")
    image[0x10123] = 0xC3
    project = angr.Project(io.BytesIO(image), auto_load_libs=False, simos="DOS",
                           main_opts={"backend": "blob", "arch": real16_loader_arch(),
                                      "base_addr": 0, "entry_point": head})
    derived = binding_tests._fixture(project, head, head + 4, head)
    return WrapFixture(derived.project, derived.block, derived.call)


WRAP_COORDINATES = DirectNearCallCoordinates8616(0x10020, 0x10023, 0x10123)


def _wrap_projection(fixture: WrapFixture, **changes: object) -> DeclaredSelectorCallsite8616:
    """Construct one boundary projection, optionally mutated per control."""
    projection = DeclaredSelectorCallsite8616(
        scope=_FakeDeclaredScope8616(project=fixture.project),
        block=fixture.block,
        instruction=fixture.call,
        callsite_addr=0x10020,
        target_addr=0x10123,
        next_addr=0x10023,
        incoming_cs=0x1002,
    )
    return replace(projection, **changes) if changes else projection


def _prove(fixture: WrapFixture,
           selector_binding: object = None,
           invocation: Real16InvocationDomain8616 | None = None,
           ) -> DirectNearCallTargetBinding8616:
    """Prove the wrap callsite with optional declared-selector authority."""
    return prove_direct_near_call_target_binding_at_coordinates_8616(
        fixture.project, block=fixture.block, instruction=fixture.call,
        coordinates=WRAP_COORDINATES, invocation=invocation,
        selector_binding=cast(DeclaredSelectorCallsite8616 | None, selector_binding),
    )


def test_declared_selector_projection_binds_wrap_window(producer_gate: _ProducerGate) -> None:
    """An authenticated projection discharges only the selector window."""
    fixture = _wrap_fixture()
    control = _prove(fixture)
    assert control.failure is Failure.SELECTOR_WINDOW_UNPROVED
    assert producer_gate.calls == []
    projection = _wrap_projection(fixture)
    proof = _prove(fixture, projection)
    assert proof.complete, proof.to_dict()
    assert proof.selector_binding is projection and proof.invocation is None
    record = proof.to_dict()["selector_binding"]
    assert record == {
        "declared_premise": "DeclaredSelectorCallsite8616",
        "callsite_addr": 0x10020,
        "target_addr": 0x10123,
        "next_addr": 0x10023,
        "incoming_cs": 0x1002,
    }
    assert producer_gate.calls == [
        (fixture.project, projection), (fixture.project, projection),
    ]
    producer_gate.verdict = False
    assert not proof.complete


def test_retained_projection_revalidates_inside_universal_window(producer_gate: _ProducerGate) -> None:
    """Conditional authority is never laundered into the universal bound."""
    fixture = binding_tests._fixture(near_return._project(), 0x10F1, 0x110D, 0x10F7)
    projection = DeclaredSelectorCallsite8616(
        scope=_FakeDeclaredScope8616(project=fixture.project),
        block=fixture.block, instruction=fixture.call,
        callsite_addr=0x10F7, target_addr=0x15BC, next_addr=0x10FA, incoming_cs=0x10F,
    )
    proof = prove_direct_near_call_target_binding_at_coordinates_8616(
        fixture.project, block=fixture.block, instruction=fixture.call,
        coordinates=DirectNearCallCoordinates8616(0x10F7, 0x10FA, 0x15BC),
        selector_binding=projection,
    )
    assert proof.complete and proof.selector_binding is projection
    producer_gate.verdict = False
    assert not proof.complete


def test_full_invocation_and_selector_authorization_conflict(producer_gate: _ProducerGate) -> None:
    """Competing authorizations refuse instead of silently choosing."""
    fixture = _wrap_fixture()
    projection = _wrap_projection(fixture)
    proof = _prove(fixture, projection,
                   invocation=cast(Real16InvocationDomain8616, object()))
    assert not proof.complete
    assert proof.failure is Failure.SELECTOR_AUTHORIZATION_CONFLICT
    assert producer_gate.calls == []


@pytest.mark.parametrize("field,wrong", [
    ("callsite_addr", 0x10021),
    ("target_addr", 0x10124),
    ("next_addr", 0x10024),
    ("incoming_cs", -1),
    ("incoming_cs", 0x10000),
    ("block", object()),
    ("instruction", object()),
    ("scope", _FakeDeclaredScope8616(project=object())),
])
def test_projection_identity_mismatch_refuses(
    producer_gate: _ProducerGate, field: str, wrong: object,
) -> None:
    """Every retained identity fact must match before the producer is asked."""
    fixture = _wrap_fixture()
    proof = _prove(fixture, _wrap_projection(fixture, **{field: wrong}))
    assert not proof.complete
    assert proof.failure is Failure.SELECTOR_WINDOW_UNPROVED
    assert producer_gate.calls == []


def test_foreign_projection_type_refuses(producer_gate: _ProducerGate) -> None:
    """Only the exact producer callsite type may attempt authentication."""
    fixture = _wrap_fixture()
    proof = _prove(fixture, object())
    assert not proof.complete
    assert proof.failure is Failure.SELECTOR_WINDOW_UNPROVED
    assert producer_gate.calls == []


def test_producer_refusal_keeps_window_unproved(producer_gate: _ProducerGate) -> None:
    """A rejected certificate cannot discharge the selector window."""
    fixture = _wrap_fixture()
    producer_gate.verdict = False
    proof = _prove(fixture, _wrap_projection(fixture))
    assert not proof.complete
    assert proof.failure is Failure.SELECTOR_WINDOW_UNPROVED
    assert len(producer_gate.calls) == 1
    assert producer_gate.calls[0] == (fixture.project, producer_gate.calls[0][1])


def test_target_bytes_run_before_selector_consumption(producer_gate: _ProducerGate) -> None:
    """Native bytes gate first; the producer is never asked on corruption."""
    fixture = _wrap_fixture()
    fixture.project.loader.memory.store(0x10022, b"\xc3")
    proof = _prove(fixture, _wrap_projection(fixture))
    assert not proof.complete
    assert proof.failure is Failure.TARGET_BYTES_MISMATCH
    assert producer_gate.calls == []


def test_retained_reconciliation_requires_projection_identity(producer_gate: _ProducerGate) -> None:
    """Replay reconciliation compares the same projection object."""
    fixture = _wrap_fixture()
    projection = _wrap_projection(fixture)
    proof = _prove(fixture, projection)
    assert proof.complete
    assert _retained_binding_fields_equal_8616(proof, proof)
    twin = replace(proof, selector_binding=_wrap_projection(fixture))
    assert not _retained_binding_fields_equal_8616(proof, twin)


def test_absent_selector_binding_keeps_default_binding(producer_gate: _ProducerGate) -> None:
    """The default all-window path ignores the producer surface entirely."""
    fixture = binding_tests._fixture(near_return._project(), 0x10F1, 0x110D, 0x10F7)
    proof = prove_direct_near_call_target_binding_at_coordinates_8616(
        fixture.project, block=fixture.block, instruction=fixture.call,
        coordinates=DirectNearCallCoordinates8616(0x10F7, 0x10FA, 0x15BC),
    )
    assert proof.complete and proof.selector_binding is None
    assert proof.to_dict()["selector_binding"] is None
    assert producer_gate.calls == []
