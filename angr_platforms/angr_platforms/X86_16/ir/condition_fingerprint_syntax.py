"""Lexical structure of owned condition fingerprints.

Layer: IR.
Responsibility: split argument spans without recovering or changing semantics.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations


def split_condition_fingerprint_arguments_8616(value: str) -> list[str]:
    """Split at commas whose running parenthesis balance is zero.

    Preserve negative balance on malformed input, empty interior arguments and
    whitespace-only tails. Drop only an empty final span. Use bounded native
    string scans instead of copying every character into temporary lists.
    While balance is nonzero, skip to the next parenthesis that can move it
    toward zero: no comma in the skipped span can separate arguments.
    """
    if "(" not in value and ")" not in value:
        parts = [part.strip() for part in value.split(",")]
        if not value or value.endswith(","):
            parts.pop()
        return parts
    parts = []
    depth = 0
    start = 0
    pos = 0
    find = value.find
    count = value.count
    while True:
        if depth == 0:
            comma = find(",", pos)
            if comma < 0:
                break
            depth += count("(", pos, comma) - count(")", pos, comma)
            if depth == 0:
                parts.append(value[start:comma].strip())
                start = comma + 1
            pos = comma + 1
        else:
            paren = find("(" if depth < 0 else ")", pos)
            if paren < 0:
                break
            depth += count("(", pos, paren + 1) - count(")", pos, paren + 1)
            pos = paren + 1
    if start < len(value):
        parts.append(value[start:].strip())
    return parts
