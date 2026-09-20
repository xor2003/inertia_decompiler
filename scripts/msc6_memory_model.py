"""Explicit small/large toolchain settings for DOS round-trip tests.

Layer: Test infrastructure.
Responsibility: keep original, rebuilt and runtime compilation/linkage on the
same memory model. This does not supply decompiler semantic evidence.
"""

from enum import StrEnum


class MSCMemoryModel(StrEnum):
    """The two admitted MS C memory models."""

    SMALL = "small"
    LARGE = "large"

    @property
    def compiler_flag(self) -> str:
        """Select near or far code/data defaults explicitly."""
        return "/AS" if self is MSCMemoryModel.SMALL else "/AL"

    @property
    def runtime_library(self) -> str:
        """Select the matching emulated-floating-point C runtime library."""
        return "SLIBCE.LIB" if self is MSCMemoryModel.SMALL else "LLIBCE.LIB"

    @property
    def default_procedure_kind(self) -> str:
        """Select unqualified fixture procedures, not their recovered ABI."""
        return "NEAR" if self is MSCMemoryModel.SMALL else "FAR"
