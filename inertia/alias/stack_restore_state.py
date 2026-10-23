"""Own must-state joins for saved stack bytes and frame-register coordinates.

Layer: Alias.
Responsibility: keep only identical storage identities and SP/BP coordinates
proven on every incoming CFG edge. Unknown is not an arbitrary zero coordinate.
Owns storage identity. Do not perform lowering, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .segment_stack_fragments import SegmentStackByteOrigin8616


@dataclass(frozen=True, slots=True)
class StackRestoreState8616:
    """Entry-SP-relative coordinates and exact saved-byte identities."""

    sp_delta: int | None
    stack_bytes: tuple[tuple[int, SegmentStackByteOrigin8616], ...] = ()
    bp_delta: int | None = None
    register_offsets: tuple[tuple[str, int], ...] = ()
    register_constants: tuple[tuple[str, int], ...] = ()

    def byte_map(self) -> dict[int, SegmentStackByteOrigin8616]:
        """Return a mutable byte map for one block transfer."""
        return dict(self.stack_bytes)

    def register_offset_map(self) -> dict[str, int]:
        """Copy the live general-register coordinates entering one block."""
        return dict(self.register_offsets)

    def register_constant_map(self) -> dict[str, int]:
        """Copy proven numeric register values entering one block.

        These are plain constants seeded from authenticated entry evidence or
        propagated by constant flow; they are never SP-relative coordinates.
        """
        return dict(self.register_constants)


def stack_restore_state_8616(
    sp_delta: int | None,
    stack_bytes: dict[int, SegmentStackByteOrigin8616],
    bp_delta: int | None = None,
    register_offsets: dict[str, int] | None = None,
    register_constants: dict[str, int] | None = None,
) -> StackRestoreState8616:
    """Freeze one deterministic Alias stack state."""
    return StackRestoreState8616(
        sp_delta, tuple(sorted(stack_bytes.items())), bp_delta,
        tuple(sorted(register_offsets.items())) if register_offsets is not None else (),
        tuple(sorted(register_constants.items())) if register_constants is not None else (),
    )


def join_stack_restore_states_8616(states: tuple[StackRestoreState8616, ...]) -> StackRestoreState8616:
    """Keep coordinates and byte identities proven on every predecessor."""
    if not states:
        return StackRestoreState8616(None)
    first = states[0]
    sp_delta = first.sp_delta if all(state.sp_delta == first.sp_delta for state in states[1:]) else None
    bp_delta = first.bp_delta if all(state.bp_delta == first.bp_delta for state in states[1:]) else None
    predecessor_maps = tuple(state.byte_map() for state in states)
    common_offsets = set(predecessor_maps[0])
    for byte_map in predecessor_maps[1:]:
        common_offsets.intersection_update(byte_map)
    common_bytes = {
        offset: predecessor_maps[0][offset]
        for offset in common_offsets
        if all(byte_map[offset] == predecessor_maps[0][offset] for byte_map in predecessor_maps[1:])
    }
    register_maps = tuple(state.register_offset_map() for state in states)
    common_registers = {
        register: offset for register, offset in register_maps[0].items()
        if all(register_map.get(register) == offset for register_map in register_maps[1:])
    }
    constant_maps = tuple(state.register_constant_map() for state in states)
    common_constants = {
        register: word for register, word in constant_maps[0].items()
        if all(constant_map.get(register) == word for constant_map in constant_maps[1:])
    }
    return stack_restore_state_8616(
        sp_delta, common_bytes, bp_delta, common_registers, common_constants,
    )
