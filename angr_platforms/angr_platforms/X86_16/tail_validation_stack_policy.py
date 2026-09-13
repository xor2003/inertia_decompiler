"""Layer: Tail Validation.

Responsibility: decide which recovered stack writes are observable validation effects.
Forbidden: stack variable recovery, alias ownership, or rewrite-stage stack repair.
"""

from __future__ import annotations

__all__ = ["StackObservedLocations8616", "include_x86_16_tail_validation_stack_write"]


class StackObservedLocations8616(set[str]):
    """Distinguish value observations from addresses exposed at observable uses.

    A by-value argument observation does not itself expose its incoming stack
    storage. Passing its address does: the callee can read initialized bytes.
    This is validation evidence, not an Alias escape or lifetime proof.
    """

    address_exposed_locations: set[str]
    write_values: set[tuple[str, str]]

    def __init__(self) -> None:
        """Start one summary's independent value and address observation sets."""
        super().__init__()
        self.address_exposed_locations = set()
        self.write_values = set()

    def record_write(self, location: str, value: str) -> None:
        """Keep the value as well as the location for address-exposed stores."""
        if location in self.address_exposed_locations:
            self.write_values.add((location, value))

    def write_fingerprints(self) -> tuple[str, ...]:
        """Serialize deterministic exposed-store effects without dropping values."""
        return tuple(f"{location}={value}" for location, value in sorted(self.write_values))


def include_x86_16_tail_validation_stack_write(
    location: str,
    *,
    mode: str,
    observed_locations: set[str],
) -> bool:
    """Return whether a recovered stack write is observable for tail validation."""
    if mode == "coarse":
        return True
    if not location.startswith(("stack:", "stack_slot:")):
        return False
    if isinstance(observed_locations, StackObservedLocations8616) and location in observed_locations.address_exposed_locations:
        return True
    # [bp+0] is not a stable user-visible stack slot in the 16-bit frame model.
    # Postprocess can transiently synthesize carrier writes there while recovering
    # arguments; treating it as a live-out observable produces false deltas.
    if location == "stack:+0x0":
        return False
    if location.startswith("stack_slot:SS:BP+0x0"):
        return False
    if location.startswith("stack:+"):
        return False
    if location.startswith("stack_slot:SS:BP+"):
        return False
    if location.startswith("stack:-"):
        return location in observed_locations
    if location.startswith("stack_slot:SS:BP-"):
        return location in observed_locations
    return location in observed_locations
