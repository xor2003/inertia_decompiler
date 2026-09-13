"""Layer: Frontend/runtime.

Responsibility: install x86-16 compatibility, structuring, return, and cleanup bootstrap hooks.
Forbidden: owning decompiler semantics or adding source-backed recovery during startup.
"""

from __future__ import annotations

from .ail_remainder_compat import apply_remainder_compatibility_8616
from .calling_convention_compat import apply_x86_16_calling_convention_compatibility
from .compat import apply_x86_16_compatibility
from .decompiler_postprocess_stage import apply_x86_16_decompiler_postprocess
from .decompiler_return_compat import apply_x86_16_decompiler_return_compatibility
from .decompiler_structuring_stage import apply_x86_16_decompiler_structuring
from .lowering.native_integer_constants import apply_native_integer_constant_values_8616
from .structuring.clinic_option_policy import apply_x86_16_clinic_option_policy_8616
from .variable_recovery_compat import apply_stack_reference_compatibility_8616

__all__ = ["apply_x86_16_bootstrap"]


def describe_x86_16_bootstrap() -> tuple[str, ...]:
    """Return the startup hooks installed by the x86-16 frontend bootstrap."""
    return (
        "apply_x86_16_calling_convention_compatibility",
        "apply_x86_16_compatibility",
        "apply_remainder_compatibility_8616",
        "apply_stack_reference_compatibility_8616",
        "apply_x86_16_decompiler_return_compatibility",
        "apply_native_integer_constant_values_8616",
        "apply_x86_16_clinic_option_policy_8616",
        "apply_x86_16_decompiler_structuring",
        "apply_x86_16_decompiler_postprocess",
    )


def apply_x86_16_bootstrap() -> None:
    """Install x86-16 frontend compatibility, structuring, return, and cleanup hooks."""
    apply_x86_16_calling_convention_compatibility()
    apply_x86_16_compatibility()
    apply_remainder_compatibility_8616()
    apply_stack_reference_compatibility_8616()
    apply_x86_16_decompiler_return_compatibility()
    apply_native_integer_constant_values_8616()
    apply_x86_16_clinic_option_policy_8616()
    apply_x86_16_decompiler_structuring()
    apply_x86_16_decompiler_postprocess()
