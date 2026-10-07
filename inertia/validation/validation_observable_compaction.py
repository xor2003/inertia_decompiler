"""Provide deterministic size bounds for validation observables.

Layer: Tail Validation.
Responsibility: compact an already normalized observable fingerprint without
discarding its field identity. Semantic canonicalization remains with the
condition and control-flow owners that call this module.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

import contextlib
import hashlib
import os

__all__ = ["compact_normalized_validation_observable_8616"]

_DEFAULT_FINGERPRINT_LIMIT_8616 = 512
_FINGERPRINT_LIMIT_ENV_8616 = "INERTIA_TAIL_VALIDATION_FINGERPRINT_LIMIT"


def _validation_fingerprint_limit_8616() -> int:
    """Return the configured deterministic observable-size limit."""
    limit = _DEFAULT_FINGERPRINT_LIMIT_8616
    raw_limit = os.environ.get(_FINGERPRINT_LIMIT_ENV_8616)
    if isinstance(raw_limit, str) and raw_limit.strip():
        with contextlib.suppress(ValueError):
            limit = max(0, int(raw_limit, 0))
    return limit


def compact_normalized_validation_observable_8616(
    field_name: str,
    value: str,
) -> str:
    """Digest one oversized normalized observable while retaining its owner."""
    if len(value) <= _validation_fingerprint_limit_8616():
        return value
    digest = hashlib.sha256(
        value.encode("utf-8", errors="surrogatepass")
    ).hexdigest()[:16]
    return f"{field_name}:sha256:{digest}:len:{len(value)}"
