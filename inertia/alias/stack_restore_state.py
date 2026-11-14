# cython: language_level=3, infer_types=True
"""Own must-state joins for saved stack bytes and frame-register coordinates.

Layer: Alias.
Responsibility: keep only identical storage identities and SP/BP coordinates
proven on every incoming CFG edge. Unknown is not an arbitrary zero coordinate.
Owns storage identity. Do not perform lowering, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import cython

from dataclasses import dataclass

from .segment_stack_fragments import SegmentStackByteOrigin8616
import dataclasses
import operator
import builtins


@dataclasses.dataclass(frozen=True, )
class StackRestoreState8616:
    """Entry-SP-relative coordinates and exact saved-byte identities."""

    sp_delta: int | None
    stack_bytes: tuple[tuple[cython.longlong, SegmentStackByteOrigin8616], ...] = ()
    bp_delta: int | None = None
    register_offsets: tuple[tuple[str, cython.longlong], ...] = ()
    register_constants: tuple[tuple[str, cython.longlong], ...] = ()

    def byte_map(self) -> dict[cython.longlong, SegmentStackByteOrigin8616]:
        """Return a mutable byte map for one block transfer."""
        return dict(self.stack_bytes)

    def register_offset_map(self) -> dict[str, cython.longlong]:
        """Copy the live general-register coordinates entering one block."""
        return dict(self.register_offsets)

    def register_constant_map(self) -> dict[str, cython.longlong]:
        """Copy proven numeric register values entering one block.

        These are plain constants seeded from authenticated entry evidence or
        propagated by constant flow; they are never SP-relative coordinates.
        """
        return dict(self.register_constants)


@cython.ccall
def stack_restore_state_8616(
    sp_delta: int | None,
    stack_bytes: object,
    bp_delta: int | None = None,
    register_offsets: object = None,
    register_constants: object = None,
) -> StackRestoreState8616:
    """Freeze one deterministic Alias stack state."""
    return StackRestoreState8616(
        sp_delta, tuple(sorted(tuple(stack_bytes.items()))), bp_delta,
        tuple(sorted(tuple(register_offsets.items()))) if register_offsets is not None else (),
        tuple(sorted(tuple(register_constants.items()))) if register_constants is not None else (),
    )


def join_stack_restore_states_8616(states: object) -> StackRestoreState8616:
    """Keep coordinates and byte identities proven on every predecessor."""
    byte_map: object
    if not states:
        return StackRestoreState8616(None)
    first = states[0]
    sp_delta = first.sp_delta if all(operator.eq(state.sp_delta, first.sp_delta) for state in iter(states[1:])) else None
    bp_delta = first.bp_delta if all(operator.eq(state.bp_delta, first.bp_delta) for state in iter(states[1:])) else None
    predecessor_maps = tuple(state.byte_map() for state in iter(states))
    common_offsets = set(predecessor_maps[0])
    for byte_map in predecessor_maps[1:]:
        common_offsets.intersection_update(byte_map)
    common_bytes = {
        offset: predecessor_maps[0][offset]
        for offset in iter(common_offsets)
        if all(operator.eq(byte_map[offset], predecessor_maps[0][offset]) for byte_map in iter(predecessor_maps[1:]))
    }
    register_maps = tuple(state.register_offset_map() for state in iter(states))
    common_registers = {
        register: offset for register, offset in builtins.iter(register_maps[0].items())
        if all(operator.eq(register_map.get(register), offset) for register_map in iter(register_maps[1:]))
    }
    constant_maps = tuple(state.register_constant_map() for state in iter(states))
    common_constants = {
        register: word for register, word in builtins.iter(constant_maps[0].items())
        if all(operator.eq(constant_map.get(register), word) for constant_map in iter(constant_maps[1:]))
    }
    return stack_restore_state_8616(
        sp_delta, common_bytes, bp_delta, common_registers, common_constants,
    )
