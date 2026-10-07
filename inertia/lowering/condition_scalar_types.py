"""Apply scalar type evidence exposed by structured conditions and returns.

Layer: Types/lowering.
Responsibility: provide the pipeline entry point that materializes argument and
return scalar types from typed evidence without owning Structuring or Rewrite.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from .condition_argument_types import apply_condition_argument_types_8616
from .scalar_return_types import materialize_scalar_return_type_8616
from .terminal_register_return_types import materialize_terminal_register_return_type_8616
from .terminal_register_return_values import materialize_terminal_register_return_value_8616

__all__ = ["apply_condition_scalar_types_8616"]


def apply_condition_scalar_types_8616(project: object, codegen: object) -> bool:
    """Apply condition-derived argument types and typed return expressions."""
    argument_result = apply_condition_argument_types_8616(project, codegen)
    terminal_result = materialize_terminal_register_return_type_8616(project, codegen)
    terminal_value_result = materialize_terminal_register_return_value_8616(project, codegen)
    return_result = materialize_scalar_return_type_8616(project, codegen)
    return (
        argument_result.changed
        or terminal_result.changed
        or terminal_value_result.changed
        or return_result.changed
    )
