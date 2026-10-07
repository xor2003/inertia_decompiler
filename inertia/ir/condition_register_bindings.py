"""Snapshot typed register-value evidence at condition producers.

Layer: IR.
Responsibility: owns exact frontend register-state projections for Condition.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .condition_ir import ConditionRegisterBindingIR
from .core import IRBinaryValue, IRValue


class ConditionRegisterValueStateSurface8616(Protocol):
    """Expose one frontend-proven register value and its first valid address."""

    @property
    def value(self) -> IRValue | IRBinaryValue:
        """Return the exact value proven for this register."""
        ...

    @property
    def next_addr(self) -> int:
        """Return the first instruction address where the value is valid."""
        ...


def snapshot_condition_register_bindings_8616(
    states: Mapping[tuple[int, str], ConditionRegisterValueStateSurface8616],
    block_addr: int | None,
    instruction_addr: int,
) -> tuple[ConditionRegisterBindingIR, ...]:
    """Return deterministic bindings valid at one condition producer."""
    if not isinstance(block_addr, int):
        return ()
    return tuple(
        ConditionRegisterBindingIR(register_name, state.value)
        for (owner, register_name), state in sorted(states.items())
        if owner == block_addr and state.next_addr <= instruction_addr
    )
