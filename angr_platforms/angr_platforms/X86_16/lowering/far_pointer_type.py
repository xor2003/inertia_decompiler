"""Represent fixed-width real-mode far pointers in typed interfaces.

Layer: Types/Lowering.
Responsibility: preserve the 32-bit ABI width of proven far pointers
(segment:offset pairs) while retaining angr pointer semantics and the
architecture binding of their pointee.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

``Arch86_16`` has a 32-bit address model and a 2-byte ABI word.  Angr's
generic ``SimTypePointer`` follows the address width, which happens to match
the far-pointer width, but an explicit far-pointer type keeps the proven ABI
classification distinct from guessed generic pointers and from 16-bit near
pointers.
"""

from __future__ import annotations

from angr.sim_type import SimType, SimTypeFunction, SimTypePointer
from archinfo import Arch


class SimTypeFarPointer16_8616(SimTypePointer):  # type: ignore[misc]
    """Angr pointer type with the fixed 32-bit width of a real-mode far pointer."""

    @property
    def size(self) -> int:
        """Return the far-pointer width in bits."""
        return 32

    def _with_arch(
        self,
        arch: Arch,
        *,
        memo: dict[str, SimType],
    ) -> SimTypeFarPointer16_8616:
        """Bind this far pointer through angr's recursive type memo contract."""
        out = SimTypeFarPointer16_8616(
            self.pts_to.with_arch(arch, memo=memo),
            self.label,
            self.offset,
            qualifier=self.qualifier,
            disposition=self.disposition,
        )
        out._arch = arch
        return out

    def make(self, pts_to: SimType) -> SimTypeFarPointer16_8616:
        """Create an equivalent far pointer for a replacement pointee type."""
        out = SimTypeFarPointer16_8616(
            pts_to,
            self.label,
            self.offset,
            qualifier=self.qualifier,
            disposition=self.disposition,
        )
        out._arch = self._arch
        return out

    def copy(self) -> SimTypeFarPointer16_8616:
        """Copy this far pointer while preserving its architecture binding."""
        out = SimTypeFarPointer16_8616(
            self.pts_to,
            self.label,
            self.offset,
            qualifier=self.qualifier,
            disposition=self.disposition,
        )
        out._arch = self._arch
        return out


def far_pointer_type_8616(
    pointee: SimType,
    arch: Arch,
) -> SimTypeFarPointer16_8616:
    """Build one architecture-bound 32-bit far-pointer type."""
    pointer = SimTypeFarPointer16_8616(pointee).with_arch(arch)
    if not isinstance(pointer, SimTypeFarPointer16_8616):
        raise TypeError("far-pointer architecture binding changed its type")
    return pointer


def with_far_pointer_parameter_8616(
    prototype: object,
    parameter_index: int,
    pointer_type: SimTypeFarPointer16_8616,
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
    "SimTypeFarPointer16_8616",
    "far_pointer_type_8616",
    "with_far_pointer_parameter_8616",
]
