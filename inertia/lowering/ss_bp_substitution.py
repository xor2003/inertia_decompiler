"""Substitute `(ss << 4) ± BP ± offset` patterns with named stack variables in C output.

Layer: Types/Lowering.
Responsibility: consumes alias, widening, and typed facts to apply already-proven
stack bindings.
Do not recover semantics from COD, source, assembly, or rendered C text.

AGENTS rule: rewrite must NOT do semantic recovery.
"""

from __future__ import annotations

import re
import typing
from collections.abc import Sequence
from typing import Any

from .stack_variable_binding import StackVariableBinding


def _dynamic_codegen_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic codegen boundary: read optional stack-binding metadata."""
    return getattr(obj, name, default)


def _signed16(value: int) -> int:
    """Convert unsigned 16-bit int to signed."""
    if value >= 0x8000:
        return value - 0x10000
    return value


def substitute_ss_bp_dereferences_with_variables(
    c_text: str,
    bindings: Sequence[StackVariableBinding],
) -> str:
    """Replace all `(ss << 4) + BP ± offset` patterns with named variables."""
    if not bindings:
        return c_text

    offset_map: dict[int, str] = {}
    for binding in bindings:
        offset_map[binding.bp_offset] = binding.var_name

    if not offset_map:
        return c_text

    pattern = re.compile(
        r"\*?\s*"
        r"(?:\(\s*unsigned\s+(?:__)?int\d*\s*\*?\s*\)\s*(?:&?\()?)?"
        r"\(\s*\(\s*ss\s*<<\s*4\s*\)\s*\+\s*BP\s*\)\s*"
        r"([+-])\s*"
        r"(0x[0-9a-fA-F]+|\d+)"
    )

    def replacer(m: re.Match[str]) -> str:
        sign_str = m.group(1).strip()
        offset_str = m.group(2).strip()
        offset_value = int(offset_str, 16 if offset_str.startswith("0x") else 10)
        sign = 1 if sign_str == "+" else -1
        signed_val = _signed16(offset_value * sign)
        if signed_val in offset_map:
            name = offset_map[signed_val]
            full_match = m.group(0)
            leading_space = full_match[: len(full_match) - len(full_match.lstrip())]
            is_deref = full_match.lstrip().startswith("*")
            return f"{leading_space}{name}" if is_deref else f"{leading_space}&{name}"
        return str(m.group(0))

    result = pattern.sub(replacer, c_text)

    pattern2 = re.compile(
        r"\(\s*\(\s*ss\s*<<\s*4\s*\)\s*\+\s*BP\s*\)\s*"
        r"([+-])\s*"
        r"(0x[0-9a-fA-F]+|\d+)"
    )
    result = pattern2.sub(replacer, result)

    return result


def apply_stack_variable_bindings_to_c_text(
    c_text: str,
    codegen: object,
) -> str:
    """Apply fact-based stack variable bindings to C text."""
    bindings = _dynamic_codegen_attr_8616(codegen, "_inertia_stack_variable_bindings", None)
    if not bindings:
        facts = _dynamic_codegen_attr_8616(codegen, "_inertia_semantic_alias_facts", None)
        if facts:
            # Lazy import to avoid bootstrap dependency
            from .stack_lowering_from_facts import build_stack_variable_bindings_from_alias_facts_8616

            bindings = build_stack_variable_bindings_from_alias_facts_8616(facts)
            typing.cast(typing.Any, codegen)._inertia_stack_variable_bindings = bindings
        else:
            return c_text
    if not bindings:
        return c_text
    return substitute_ss_bp_dereferences_with_variables(c_text, bindings)


__all__ = [
    "apply_stack_variable_bindings_to_c_text",
    "substitute_ss_bp_dereferences_with_variables",
]
