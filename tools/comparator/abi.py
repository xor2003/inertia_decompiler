"""Layer: validation observation contracts.

Responsibility: declare the shared default native return-observation contract.
"""

from __future__ import annotations

DEFAULT_OUTPUT_REGS: tuple[str, ...] = ('eax', 'edx', 'esp', 'ebx', 'ebp', 'esi', 'edi', 'eip', 'd', 'cs', 'ds', 'es', 'fs', 'gs', 'ss')
