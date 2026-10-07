"""Register access supplied explicitly to expression lowering.

Layer: dosunit contracts.
Responsibility: describe architecture-specific reads without importing an
architecture, VEX or the lowering implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from tools.dosunit.contracts.ssa import LowerFailure, SsaExpr


class RegisterReader(Protocol):
    """Preserve the full architectural register behind a partial read."""

    def __call__(self, reg_versions: dict[str, SsaExpr], offset: int, width: int,
                 *, source: str) -> SsaExpr | LowerFailure:
        """Read an admitted register or return explicit unsupported evidence."""
        ...


class RegisterWriter(Protocol):
    """Architecture-specific full and partial register writes."""

    def __call__(self, reg_versions: dict[str, SsaExpr], offset: int,
                 expr: SsaExpr) -> LowerFailure | None:
        """Update the enclosing register or refuse the write."""
        ...


class RegisterWriteTarget(Protocol):
    """Identify the enclosing register for failed partial writes."""

    def __call__(self, offset: int, width: int | None) -> tuple[str, int] | None:
        """Return the enclosing register name and width when modeled."""
        ...


class ExpressionLowerer(Protocol):
    """Translate an external expression with explicit SSA versions."""

    def __call__(self, expr: object, *, temp_defs: dict[int, SsaExpr],
                 temp_failures: dict[int, LowerFailure], reg_versions: dict[str, SsaExpr],
                 tyenv: object, memory: SsaExpr,
                 register_reader: RegisterReader | None = None) -> SsaExpr | LowerFailure:
        """Preserve architecture expression admission and unsupported evidence."""
        ...


@dataclass(frozen=True)
class RegisterArchitecture:
    """Explicit register state and access rules for one block-lowering call."""

    registers: tuple[tuple[str, int], ...]
    reader: RegisterReader
    writer: RegisterWriter
    write_target: RegisterWriteTarget
    control_register: str
    control_width: int
    retain_all_statements: bool = False
    expression_lowerer: ExpressionLowerer | None = None
