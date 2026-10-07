"""Direct stack-move expression normalization regression tests."""

from __future__ import annotations

from types import SimpleNamespace

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.real_mode_linear import (
    DirectStackMoveExpressionOp8616,
    DirectStackMoveSourceKind8616,
    _direct_stack_move_instruction_facts_8616,
)


class _BytesMemory:
    def __init__(self, base: int, data: bytes) -> None:
        self.base = base
        self.data = data

    def load(self, addr: int, size: int) -> bytes:
        start = int(addr) - self.base
        return self.data[start : start + int(size)]


def test_direct_stack_instruction_facts_collect_binary_stack_expression_sub() -> None:
    """Prefer stack-stack SUB expressions as binary stack slot source facts."""
    code = bytes.fromhex("8b46042b46068946fe")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_BytesMemory(0x1000, code)),
    )
    function = SimpleNamespace(addr=0x1000, size=len(code), name="subtract_stack_words")

    facts = _direct_stack_move_instruction_facts_8616(project, function)

    assert len(facts) == 1
    fact = facts[0]
    assert fact.dst_offset == -2
    assert fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_BINARY_EXPR
    assert fact.source_offset == 4
    assert fact.source_rhs_offset == 6
    assert fact.source_op is DirectStackMoveExpressionOp8616.SUB
