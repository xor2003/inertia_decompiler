"""Normalize width-proven and repeated constant masks in condition fingerprints.

Layer: IR.
Responsibility: owns lossless full-width and repeated-mask identities for typed Condition
fingerprints and local Value canonicalization.
Consumes only explicit byte widths already carried by IR-owned tokens. It does
not recover widths from rendered C, names, compiler patterns, or sample data.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import re

__all__ = (
    "is_proven_full_width_mask_8616",
    "normalize_condition_full_width_masks_8616",
)

_EXPLICIT_SIZE_RE_8616 = re.compile(r"(?:^|:)size(?P<size>[1-9][0-9]*)(?=:|$)")
_INTEGER_VIEW_RE_8616 = re.compile(
    r"SimType(?:Char|Short|Int|Long|LongLong):bits=(8|16|32|64):signed=(?:true|false)"
)
_BINARY_ARITY: int = 2
_CONTROL_FLOW_PREFIXES_8616 = (
    "if:",
    "ifbreak:",
    "while:",
    "dowhile:",
    "for:",
    "switch:",
)


def is_proven_full_width_mask_8616(mask: int, width_bytes: int | None) -> bool:
    """Return whether ``mask`` preserves every bit of a proven-width value."""
    if mask == -1:
        return True
    if not isinstance(width_bytes, int) or width_bytes <= 0:
        return False
    return mask == (1 << (width_bytes * 8)) - 1


def normalize_condition_full_width_masks_8616(value: str) -> str:
    """Remove proven full-width masks or an exact repeated constant mask.

    Fingerprints are an internal IR/validation transport contract. An atom such
    as ``stack_slot:SS:BP-0x2:size2`` proves its width; an atom without exactly
    one explicit ``sizeN`` token retains its narrowing mask. Repeating the same
    mask is an identity at every width and does not require a width inference.
    """
    for prefix in _CONTROL_FLOW_PREFIXES_8616:
        if value.startswith(prefix):
            return prefix + normalize_condition_full_width_masks_8616(value[len(prefix) :])

    call = _split_call_8616(value)
    if call is None:
        return value
    op, args_text = call
    args = tuple(normalize_condition_full_width_masks_8616(arg) for arg in _split_args_8616(args_text))
    if op == "And" and len(args) == _BINARY_ARITY:
        for operand, mask_token in ((args[0], args[1]), (args[1], args[0])):
            mask = _constant_value_8616(mask_token)
            width_bytes = _explicit_atom_width_bytes_8616(operand)
            if isinstance(mask, int) and (
                is_proven_full_width_mask_8616(mask, width_bytes)
                or _has_identical_mask_8616(operand, mask)
            ):
                return operand
    if op == "SemanticCast" and len(args) == _BINARY_ARITY:
        args = (args[0], _cast_operand_without_identity_mask_8616(args[0], args[1]))
    return f"{op}({','.join(args)})"


def _cast_operand_without_identity_mask_8616(conversion: str, operand: str) -> str:
    """Drop only an exact destination mask inside a proven integer narrowing.

    The cast itself is retained, including signedness and both widths. This
    normalizes owned semantic tokens, not rendered source or memory accesses.
    """
    source_type, separator, destination_type = conversion.partition("->")
    if not separator:
        return operand
    source = _INTEGER_VIEW_RE_8616.fullmatch(source_type)
    destination = _INTEGER_VIEW_RE_8616.fullmatch(destination_type)
    if source is None or destination is None:
        return operand
    source_bits, destination_bits = int(source[1]), int(destination[1])
    if destination_bits > source_bits:
        return operand
    call = _split_call_8616(operand)
    if call is None or call[0] != "And":
        return operand
    args = _split_args_8616(call[1])
    if len(args) != _BINARY_ARITY:
        return operand
    mask = (1 << destination_bits) - 1
    for value, constant in ((args[0], args[1]), (args[1], args[0])):
        if _constant_value_8616(constant) == mask:
            return value
    return operand


def _has_identical_mask_8616(operand: str, mask: int) -> bool:
    """Prove an immediately nested mask without crossing any conversion."""
    call = _split_call_8616(operand)
    if call is None or call[0] != "And":
        return False
    args = _split_args_8616(call[1])
    return len(args) == _BINARY_ARITY and any(_constant_value_8616(arg) == mask for arg in args)


def _explicit_atom_width_bytes_8616(value: str) -> int | None:
    if _split_call_8616(value) is not None:
        return None
    sizes = tuple(int(match.group("size"), 10) for match in _EXPLICIT_SIZE_RE_8616.finditer(value))
    if len(sizes) != 1:
        return None
    return sizes[0]


def _constant_value_8616(value: str) -> int | None:
    if not value.startswith("const:"):
        return None
    try:
        return int(value[len("const:") :], 0)
    except ValueError:
        return None


def _split_call_8616(value: str) -> tuple[str, str] | None:
    if not value.endswith(")"):
        return None
    open_index = value.find("(")
    if open_index <= 0:
        return None
    return value[:open_index], value[open_index + 1 : -1]


def _split_args_8616(value: str) -> tuple[str, ...]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for character in value:
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        if character == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if current:
        parts.append("".join(current).strip())
    return tuple(parts)
