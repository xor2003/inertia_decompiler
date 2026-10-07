"""Architecture-specific adapters for explicit dosunit lowering state.

Layer: dosunit architecture boundary.
Responsibility: group register, expression and control adapters without
importing them or installing state at package import.
"""

from __future__ import annotations
