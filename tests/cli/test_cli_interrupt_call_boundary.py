"""Regress checked values at the dynamic interrupt-call reporting boundary."""

from types import SimpleNamespace

import pytest

from inertia.cli.cli_interrupt_modeling import _interrupt_wrapper_call_signature


@pytest.mark.parametrize("target", ["intdos", "_intdos", None, 123])
def test_interrupt_call_target_is_checked_before_classification(target):
    inputs, outputs = object(), object()
    result = _interrupt_wrapper_call_signature(SimpleNamespace(callee_target=target, args=(inputs, outputs)))

    if not isinstance(target, str):
        assert result is None
        return
    assert result is not None
    assert result.kind == "intdos"
    assert result.inregs_arg is inputs
    assert result.outregs_arg is outputs
    assert result.vector_arg is None


def test_interrupt_call_uses_the_checked_dynamic_target_once():
    class Call:
        """Expose a dynamic target that is only available on its first lookup."""

        args = (object(), object())
        reads = 0

        @property
        def callee_target(self):
            self.reads += 1
            return "intdos" if self.reads == 1 else None

    call = Call()

    result = _interrupt_wrapper_call_signature(call)

    assert call.reads == 1
    assert result is not None
    assert result.kind == "intdos"
    assert result.arguments == call.args


def test_interrupt_call_preserves_function_name_precedence():
    node = SimpleNamespace(callee_func=SimpleNamespace(name="intdos"), callee_target="int86", args=(1, 2))

    result = _interrupt_wrapper_call_signature(node)

    assert result is not None
    assert result.kind == "intdos"
    assert result.vector_arg is None
