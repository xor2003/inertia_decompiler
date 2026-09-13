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

    def byte_map(self) -> dict[int, SegmentStackByteOrigin8616]:
        """Return a mutable byte map for one block transfer."""
        return dict(self.stack_bytes)


def stack_restore_state_8616(
    sp_delta: int | None,
    stack_bytes: dict[int, SegmentStackByteOrigin8616],
    bp_delta: int | None = None,
) -> StackRestoreState8616:
    """Freeze one deterministic Alias stack state."""
    return StackRestoreState8616(sp_delta, tuple(sorted(stack_bytes.items())), bp_delta)


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
    return stack_restore_state_8616(sp_delta, common_bytes, bp_delta)
