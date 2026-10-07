"""Registered VEX operation membership adapter for IR consumers.

Layer: IR backend adapter.
Responsibility: answer whether an ``Iop_*`` operation name is registered in the
VEX operation enum, so Alias-layer proofs never import pyvex directly. This is
an adapter boundary only — membership, never semantics: an unregistered or
misspelled name is reported as absent so callers refuse explicitly.

Owns typed Value, Address, Condition, instruction facts, and lossless normalization
at the operation-membership backend boundary only.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from pyvex.enums import get_int_from_enum


def is_registered_vex_operation_8616(op: str) -> bool:
    """Return whether ``op`` is a registered VEX expression operation."""
    try:
        get_int_from_enum(op)
    except KeyError:
        return False
    return True
