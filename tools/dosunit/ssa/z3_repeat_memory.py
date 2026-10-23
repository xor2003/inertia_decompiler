"""Layer: dosunit SSA memory semantics.

Responsibility: exact bounded flat32 counted REP memory effects, in execution
order, preserving overlapping-copy behavior and modular address arithmetic.
"""
from __future__ import annotations

from typing import Any

MAX_EXACT_REPEAT_COUNT: int = 16
_SHAPES: dict[str, tuple[bool, int]] = {
    "summary_rep_movs8_memory": (True, 1),
    "summary_rep_movs16_memory": (True, 2),
    "summary_rep_movs32_memory": (True, 4),
    "summary_rep_stos8_memory": (False, 1),
    "summary_rep_stos16_memory": (False, 2),
    "summary_rep_stos32_memory": (False, 4),
}


def exact_repeat_memory(op: str, width: int, args: list[Any], z3: Any) -> Any | None:  # noqa: ANN401
    """Expand only admitted constant-count flat32 summaries; otherwise defer."""
    shape = _SHAPES.get(op)
    if shape is None or width != 0:
        return None
    move, size = shape
    if len(args) != (11 if move else 10):
        return None
    memory = args[0]
    if (not z3.is_array(memory) or memory.sort().domain() != z3.BitVecSort(32)
            or memory.sort().range() != z3.BitVecSort(8)):
        return None
    widths = ([32, 32, 32, 16, 16, 32, 32, 32, 32, 32] if move
              else [32, 32, size * 8, 16, 32, 32, 32, 32, 32])
    if not all(z3.is_bv(arg) and arg.size() == bits for arg, bits in zip(args[1:], widths, strict=True)):
        return None
    count = z3.simplify(args[1])
    if not z3.is_bv_value(count) or count.as_long() > MAX_EXACT_REPEAT_COUNT:
        return None
    destination = args[3] if move else args[2]
    step = args[-1] * z3.BitVecVal(size, 32)
    for iteration in range(count.as_long()):
        offset = step * z3.BitVecVal(iteration, 32)
        # Read a whole element before storing any of its bytes. Subsequent
        # iterations read the updated array, including overlapping writes.
        values = ([z3.Select(memory, args[2] + offset + byte) for byte in range(size)]
                  if move else [z3.Extract(byte * 8 + 7, byte * 8, args[3]) for byte in range(size)])
        for byte, value in enumerate(values):
            memory = z3.Store(memory, destination + offset + byte, value)
    return memory
