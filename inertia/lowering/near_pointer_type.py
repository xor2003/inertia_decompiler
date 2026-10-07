"""Represent fixed-width real-mode near pointers in typed interfaces.

Layer: Types/Lowering.
Responsibility: preserve the 16-bit ABI width of proven near pointers while
retaining angr pointer semantics and the architecture binding of their pointee.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

``Arch86_16`` has a 32-bit address model and a 2-byte ABI word.  Angr's generic
``SimTypePointer`` follows the address width, so it must not be used for stack
parameters proven to be 16-bit near pointers.
"""

from __future__ import annotations

from angr.sim_type import SimType, SimTypeFunction, SimTypePointer
from archinfo import Arch


class SimTypeNearPointer16_8616(SimTypePointer):  # type: ignore[misc]
    """Angr pointer type with the fixed 16-bit width of a real-mode near pointer."""

    @property
    def size(self) -> int:
        """Return the near-pointer width in bits."""
        return 16

    def _with_arch(
        self,
        arch: Arch,
        *,
        memo: dict[str, SimType],
    ) -> SimTypeNearPointer16_8616:
        """Bind this near pointer through angr's recursive type memo contract."""
        out = SimTypeNearPointer16_8616(
            self.pts_to.with_arch(arch, memo=memo),
            self.label,
            self.offset,
            qualifier=self.qualifier,
            disposition=self.disposition,
        )
        out._arch = arch
        return out

    def make(self, pts_to: SimType) -> SimTypeNearPointer16_8616:
        """Create an equivalent near pointer for a replacement pointee type."""
        out = SimTypeNearPointer16_8616(
            pts_to,
            self.label,
            self.offset,
            qualifier=self.qualifier,
            disposition=self.disposition,
        )
        out._arch = self._arch
        return out

    def copy(self) -> SimTypeNearPointer16_8616:
        """Copy this near pointer while preserving its architecture binding."""
        out = SimTypeNearPointer16_8616(
            self.pts_to,
            self.label,
            self.offset,
            qualifier=self.qualifier,
            disposition=self.disposition,
        )
        out._arch = self._arch
        return out


def near_pointer_type_8616(
    pointee: SimType,
    arch: Arch,
) -> SimTypeNearPointer16_8616:
    """Build one architecture-bound 16-bit near-pointer type."""
    pointer = SimTypeNearPointer16_8616(pointee).with_arch(arch)
    if not isinstance(pointer, SimTypeNearPointer16_8616):
        raise TypeError("near-pointer architecture binding changed its type")
    return pointer


def with_near_pointer_parameter_8616(
    prototype: object,
    parameter_index: int,
    pointer_type: SimTypeNearPointer16_8616,
    arch: Arch,
) -> SimTypeFunction | None:
    """Replace one proven parameter type while preserving its function contract."""
    if not isinstance(prototype, SimTypeFunction):
        return None
    arguments = list(prototype.args or ())
    if parameter_index < 0 or parameter_index >= len(arguments):
        return None
    arguments[parameter_index] = pointer_type
    return SimTypeFunction(
        arguments,
        prototype.returnty,
        arg_names=tuple(prototype.arg_names or ()),
        variadic=prototype.variadic,
    ).with_arch(arch)


__all__ = [
    "SimTypeNearPointer16_8616",
    "near_pointer_type_8616",
    "with_near_pointer_parameter_8616",
]
