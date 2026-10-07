"""Layer: Frontend/PyVEX compatibility.

Responsibility: retain the checked symbolic-value contract across decorators.
PyVEX's vvifyresults wraps raw expressions in VexValue at runtime; static
inference may still expose the raw expression type. This boundary checks the
actual wrapper, not object shape, and never creates or guesses machine state.
"""

from __future__ import annotations

from pyvex.lifting.util.syntax_wrapper import VexValue


def require_vex_value_8616(value: object) -> VexValue:
    """Require a symbolic PyVEX value for a lifting-only operation."""
    if not isinstance(value, VexValue):
        raise TypeError("symbolic instruction operation requires a VexValue")
    return value
