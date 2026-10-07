"""Cheap SSA identity checks with explicit admission policy.

Layer: dosunit SSA comparison.
Responsibility: admit literal identity without interpreting normalized constants.
"""

from __future__ import annotations

from typing import Any

from tools.dosunit.contracts.comparison import DEFAULT_COMPARISON_POLICY, ComparisonPolicy


def semantic_payload(function: dict[str, Any]) -> dict[str, Any]:
    """Return the ordered input, assignment and observable expression payload."""
    return {
        "inputs": function.get("inputs", []),
        "outputs": function.get("outputs", {}),
        "assignments": function.get("assignments", []),
    }


def quick_compare(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    *,
    skip_binary_equal: bool,
    comparison_policy: ComparisonPolicy = DEFAULT_COMPARISON_POLICY,
) -> dict[str, Any] | None:
    """Return an identity verdict, or defer to solving under declared maps.

    The default preserves historical real16 admission. Explicit policies can
    require literal terms so raw identity cannot hide differing normalization.
    No backend, engine state or architecture setup is needed here.
    """
    if comparison_policy.require_literal_identity and (
        oracle.get("_constant_normalization") or candidate.get("_constant_normalization")
    ):
        return None
    oracle_source = oracle.get("source", {}) if isinstance(oracle.get("source"), dict) else {}
    candidate_source = candidate.get("source", {}) if isinstance(candidate.get("source"), dict) else {}
    if skip_binary_equal:
        for hash_key, size_key, reason in (
            ("function_machine_code_sha256", "function_machine_code_size", "binary_equal"),
            ("machine_code_sha256", "machine_code_size", "block_binary_equal"),
        ):
            oracle_hash = oracle_source.get(hash_key)
            candidate_hash = candidate_source.get(hash_key)
            oracle_size = oracle_source.get(size_key)
            candidate_size = candidate_source.get(size_key)
            if oracle_hash and candidate_hash and oracle_hash == candidate_hash and oracle_size == candidate_size:
                return {"status": "passed", "reason": reason, "mismatches": []}
    if semantic_payload(oracle) == semantic_payload(candidate):
        return {"status": "passed", "reason": "ssa_equal", "mismatches": []}
    return None
