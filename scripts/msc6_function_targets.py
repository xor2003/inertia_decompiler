"""Bind fixture names to numeric decompiler targets without semantic hints.

Layer: Tooling/gates.
Responsibility: transport same-build labels for target selection and harness
naming only; never supply signatures, argument values, types or function bodies.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class TargetBindingStatus(StrEnum):
    """Complete target binding or an explicit refusal of insufficient evidence."""

    BOUND = "bound"
    INVALID_NAMES = "invalid_names"
    MISSING_LABEL = "missing_label"
    INVALID_ADDRESS = "invalid_address"
    AMBIGUOUS_ADDRESS = "ambiguous_address"
    PREFIX_UNSUPPORTED = "prefix_unsupported"


@dataclass(frozen=True, slots=True)
class BinaryFunctionTarget:
    """A fixture label selects an address; emitted numeric naming is checked later."""

    name: str
    address: int

    @property
    def emitted_name(self) -> str:
        """Expected numeric identifier, never evidence that a body was emitted."""
        return f"sub_{self.address:x}"


@dataclass(frozen=True, slots=True)
class FunctionTargetBinding:
    """Atomic binding: a refusal contains no partially accepted targets."""

    status: TargetBindingStatus
    targets: tuple[BinaryFunctionTarget, ...] = ()


def bind_function_targets(
    names: tuple[str, ...], labels: Mapping[str, int], *, prefix: str = "",
) -> FunctionTargetBinding:
    """Resolve every selected label, refusing source-provided global/type prefixes."""
    if prefix.strip():
        return FunctionTargetBinding(TargetBindingStatus.PREFIX_UNSUPPORTED)
    if (not names or len(set(names)) != len(names)
            or any(not name.isascii() or not name.isidentifier() or name == "main" for name in names)):
        return FunctionTargetBinding(TargetBindingStatus.INVALID_NAMES)
    targets: list[BinaryFunctionTarget] = []
    addresses: set[int] = set()
    for name in names:
        address = labels.get(name.lower())
        if address is None:
            return FunctionTargetBinding(TargetBindingStatus.MISSING_LABEL)
        if type(address) is not int or address < 0:
            return FunctionTargetBinding(TargetBindingStatus.INVALID_ADDRESS)
        if address in addresses:
            return FunctionTargetBinding(TargetBindingStatus.AMBIGUOUS_ADDRESS)
        addresses.add(address)
        targets.append(BinaryFunctionTarget(name, address))
    if any(target.emitted_name in names and target.emitted_name != target.name for target in targets):
        return FunctionTargetBinding(TargetBindingStatus.INVALID_NAMES)
    return FunctionTargetBinding(TargetBindingStatus.BOUND, tuple(targets))
