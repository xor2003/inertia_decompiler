"""Typed runtime eligibility for semantic decompiler caches.

Layer: CLI/fallback/reporting.
Responsibility: classify deterministic semantic-cache eligibility and live
diagnostics that must execute instead of reusing final generated-C results.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

TIMING_DIAGNOSTIC_ENV_8616: str = "INERTIA_DEBUG_TIMING"
WORKER_CPROFILE_ENV_8616: str = "INERTIA_OTEL_CPROFILE_PATH"
WORKER_IN_PROCESS_PROFILE_ENV_8616: str = "INERTIA_OTEL_PROFILE_IN_PROCESS"
_DISABLED_DIAGNOSTIC_VALUES_8616: frozenset[str] = frozenset({"", "0", "false", "no", "off"})


class CacheRuntimeVerdict8616(StrEnum):
    """Typed reason why semantic cache reuse is allowed or refused."""

    DETERMINISTIC = "deterministic"
    HASH_SEED_UNSET = "hash_seed_unset"
    HASH_SEED_NONZERO = "hash_seed_nonzero"


@dataclass(frozen=True, slots=True)
class CacheRuntimeContract8616:
    """Determinism evidence required before semantic cache reuse."""

    verdict: CacheRuntimeVerdict8616
    python_hash_seed: str | None

    @property
    def allows_semantic_cache(self) -> bool:
        """Return whether this process may read or write semantic cache entries."""
        return self.verdict is CacheRuntimeVerdict8616.DETERMINISTIC


def cache_runtime_contract_8616(
    environment: Mapping[str, str] | None = None,
) -> CacheRuntimeContract8616:
    """Classify the current process from explicit hash-seed evidence."""
    source = os.environ if environment is None else environment
    raw_seed = source.get("PYTHONHASHSEED")
    if raw_seed is None or not raw_seed.strip():
        verdict = CacheRuntimeVerdict8616.HASH_SEED_UNSET
    elif raw_seed.strip() == "0":
        verdict = CacheRuntimeVerdict8616.DETERMINISTIC
    else:
        verdict = CacheRuntimeVerdict8616.HASH_SEED_NONZERO
    return CacheRuntimeContract8616(verdict=verdict, python_hash_seed=raw_seed)


def timing_diagnostics_requested_8616(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Return whether the current request needs live stage timing output."""
    source = os.environ if environment is None else environment
    raw_value = source.get(TIMING_DIAGNOSTIC_ENV_8616)
    return bool(raw_value is not None and raw_value.strip().lower() not in _DISABLED_DIAGNOSTIC_VALUES_8616)


def live_decompilation_diagnostics_requested_8616(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Return whether final-C caches must yield to live diagnostic execution."""
    source = os.environ if environment is None else environment
    profile_path = source.get(WORKER_CPROFILE_ENV_8616, "").strip()
    return timing_diagnostics_requested_8616(source) or bool(profile_path)
