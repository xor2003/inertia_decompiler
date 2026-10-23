"""Complete source seals for synchronous, non-proof CALL target analysis."""
from __future__ import annotations

from typing import NoReturn

import pytest

import inertia.semantics.direct_near_call_target_binding as binding
import tests.ir.test_declared_selector_batch as batch_tests
from inertia.ir.core import IRValue

pytestmark = pytest.mark.decompiler


def test_seal_reads_no_native_or_projection_callbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    """After admission the finalizer only reconciles detached owned facts."""
    pending = batch_tests._pending(batch_tests._wrap_fixture())

    def unexpected(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("pure seal invoked an external callback")

    monkeypatch.setattr(binding, "_selector_projection_types_8616", unexpected)
    monkeypatch.setattr(binding, "_target_bytes_bound_8616", unexpected)
    monkeypatch.setattr(binding, "_native_terminal_failure_8616", unexpected)
    sealed = binding._seal_declared_selector_binding_8616(pending, admitted=True)
    assert sealed.verdict is binding.DirectNearCallTargetBindingVerdict8616.PROVEN


def test_seal_reconciles_sibling_compare_excluded_metadata() -> None:
    """Full source reconciliation includes earlier producers' provenance."""
    pending = batch_tests._pending(batch_tests._wrap_fixture())
    sibling = next(instruction for instruction in pending.block.instrs
                   if instruction is not pending.instruction and isinstance(instruction.dst, IRValue))
    assert sibling.dst is not None
    object.__setattr__(sibling.dst, "memory_access_insn", 123)
    sealed = binding._seal_declared_selector_binding_8616(pending, admitted=True)
    assert sealed.verdict is binding.DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE
    assert sealed.failure is binding.DirectNearCallTargetBindingFailure8616.PENDING_SOURCE_CHANGED


def test_prepare_rejects_callback_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loader callbacks cannot redefine the source captured before native gates."""
    fixture = batch_tests._wrap_fixture()

    def mutate(*args: object, **kwargs: object) -> bool:
        object.__setattr__(fixture.call.args[0], "memory_access_insn", 123)
        return True

    monkeypatch.setattr(binding, "_target_bytes_bound_8616", mutate)
    refused = binding.prepare_declared_near_call_target_binding_pending_8616(
        fixture.project, block=fixture.block, instruction=fixture.call,
        coordinates=binding.DirectNearCallCoordinates8616(0x10020, 0x10023, 0x10123),
        selector_binding=batch_tests._wrap_projection(fixture),
    )
    assert type(refused) is binding.DirectNearCallTargetBinding8616
    assert refused.verdict is binding.DirectNearCallTargetBindingVerdict8616.UNKNOWN_REFUSE
    assert refused.failure is binding.DirectNearCallTargetBindingFailure8616.PENDING_SOURCE_CHANGED
