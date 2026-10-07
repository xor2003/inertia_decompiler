"""Typed contracts for logical word/register transfer evidence.

Layer: IR.
Responsibility: retain exact logical memory, register, definition-path, and
typed refusal facts without tracing values or assigning Alias ownership.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import IRValue, MemSpace
from .indexed_address_contracts import IndexedAddressDefinitionSite8616
from .logical_memory_contracts import IRLogicalMemoryAccess8616, IRMemoryAccessKind8616


class LogicalMemoryRegisterTransferKind8616(StrEnum):
    """Direction of one exact logical word/register transfer."""

    SPILL = "spill"
    RELOAD = "reload"


class LogicalMemoryRegisterTransferFailure8616(StrEnum):
    """Stable reason a logical word/register transfer was not proven."""

    ACCESS_INCOMPLETE = "access_incomplete"
    ACCESS_WIDTH_UNSUPPORTED = "access_width_unsupported"
    BLOCK_MISSING = "block_missing"
    EXECUTION_SITE_CONFLICT = "execution_site_conflict"
    VALUE_DEFINITION_MISSING = "value_definition_missing"
    VALUE_DEFINITION_CONFLICT = "value_definition_conflict"
    VALUE_OPERATION_UNSUPPORTED = "value_operation_unsupported"
    REGISTER_CONFLICT = "register_conflict"


@dataclass(frozen=True, slots=True)
class LogicalMemoryRegisterTransfer8616:
    """One logical word operand and its exact full-register endpoint."""

    kind: LogicalMemoryRegisterTransferKind8616
    access: IRLogicalMemoryAccess8616
    register: IRValue
    register_site: IndexedAddressDefinitionSite8616
    definition_path: tuple[IndexedAddressDefinitionSite8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether direction, width, register, and path all agree."""
        expected_kind = (
            IRMemoryAccessKind8616.WRITE
            if self.kind is LogicalMemoryRegisterTransferKind8616.SPILL
            else IRMemoryAccessKind8616.READ
        )
        return bool(
            self.access.complete
            and self.access.kind is expected_kind
            and self.access.address.size == self.register.size == 2
            and self.register.space is MemSpace.REG
            and bool(self.register.name)
            and isinstance(self.register.version, int)
            and self.register_site.complete
            and self.register_site in self.definition_path
            and self.definition_path
            and all(site.complete for site in self.definition_path)
        )


@dataclass(frozen=True, slots=True)
class LogicalMemoryRegisterTransferRefusal8616:
    """One typed refusal for a logical word/register transfer candidate."""

    access: IRLogicalMemoryAccess8616
    failure: LogicalMemoryRegisterTransferFailure8616
    detail: str


__all__ = [
    "LogicalMemoryRegisterTransfer8616",
    "LogicalMemoryRegisterTransferFailure8616",
    "LogicalMemoryRegisterTransferKind8616",
    "LogicalMemoryRegisterTransferRefusal8616",
]
