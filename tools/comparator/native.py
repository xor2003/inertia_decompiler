"""Layer: validation native model view.

Responsibility: expose authoritative i386 architecture and SSA owners to proof helpers.
"""

from __future__ import annotations

from tools.comparator.abi import DEFAULT_OUTPUT_REGS as OUTPUT_REGS
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.architectures.flat32 import _FLAT32_GPRS as GPRS
from tools.dosunit.architectures.flat32 import _FLAT32_REGS as REG32

__all__ = ["GPRS", "OUTPUT_REGS", "REG32", "S"]
