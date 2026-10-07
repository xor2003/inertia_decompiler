"""Fingerprint selector-return edge semantics for tail validation.

Layer: Tail Validation.
Responsibility: bind one structured branch condition to its proven true and
false return values so condition polarity cannot change independently of the
selected result. This module validates recovered C AST behavior; it does not
recover or mutate semantics.
Forbidden: source, COD, assembly, sidecar, or rendered-C inference.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import CIfElse, CReturn, CStatements

from inertia.ir.condition_ir import (
    invert_condition_fingerprint_string_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

__all__ = [
    "SelectorReturnFingerprint8616",
    "SelectorReturnFingerprintResult8616",
    "SelectorReturnFingerprintStats8616",
    "collect_selector_return_fingerprints_8616",
    "compact_selector_return_fingerprint_8616",
    "encode_selector_return_fingerprint_8616",
    "parse_selector_return_fingerprint_8616",
]

type FingerprintCallback8616 = Callable[[object], str]
type NormalizeFingerprintCallback8616 = Callable[[str], str]
type CompactObservableCallback8616 = Callable[[str, str], str]


@dataclass(frozen=True, slots=True)
class SelectorReturnFingerprint8616:
    """Typed condition and return-arm fields for one selector observation."""

    condition: str
    true_returns: tuple[str, ...]
    false_returns: tuple[str, ...]
    inverse_condition: str | None = None

    @property
    def arms_identical(self) -> bool:
        """Return whether both non-empty selector arms return the same values."""
        return bool(self.true_returns and self.true_returns == self.false_returns)

    @property
    def condition_candidates(self) -> tuple[str, ...]:
        """Return the exact primary and optional inverse condition identities."""
        return tuple(
            dict.fromkeys(
                candidate
                for candidate in (self.condition, self.inverse_condition)
                if candidate is not None
            )
        )


@dataclass(frozen=True, slots=True)
class SelectorReturnFingerprintStats8616:
    """Closed evidence counters for selector-return validation fingerprints."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class SelectorReturnFingerprintResult8616:
    """Immutable selector-return fingerprints and their evidence census."""

    fingerprints: tuple[str, ...]
    stats: SelectorReturnFingerprintStats8616


def encode_selector_return_fingerprint_8616(
    fingerprint: SelectorReturnFingerprint8616,
) -> str:
    """Encode one typed selector observation in deterministic JSON form."""
    payload: dict[str, object] = {
        "condition": fingerprint.condition,
        "false_returns": sorted(fingerprint.false_returns),
        "true_returns": sorted(fingerprint.true_returns),
    }
    if fingerprint.inverse_condition is not None:
        payload["inverse_condition"] = fingerprint.inverse_condition
    return "selector-return:" + json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )


def parse_selector_return_fingerprint_8616(
    value: str,
) -> SelectorReturnFingerprint8616 | None:
    """Decode only the owned selector-return JSON envelope."""
    prefix = "selector-return:"
    if not isinstance(value, str) or not value.startswith(prefix):
        return None
    try:
        payload = json.loads(value[len(prefix) :])
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or set(payload) - {
        "condition",
        "inverse_condition",
        "false_returns",
        "true_returns",
    }:
        return None
    condition = payload.get("condition")
    inverse_condition = payload.get("inverse_condition")
    true_returns = payload.get("true_returns")
    false_returns = payload.get("false_returns")
    if not isinstance(condition, str) or (
        inverse_condition is not None and not isinstance(inverse_condition, str)
    ):
        return None
    if not isinstance(true_returns, list) or not isinstance(false_returns, list):
        return None
    if not true_returns or not false_returns or any(
        not isinstance(item, str) for item in (*true_returns, *false_returns)
    ):
        return None
    return SelectorReturnFingerprint8616(
        condition=condition,
        inverse_condition=inverse_condition,
        true_returns=tuple(sorted(true_returns)),
        false_returns=tuple(sorted(false_returns)),
    )


def compact_selector_return_fingerprint_8616(
    value: str,
    *,
    canonicalize_condition: NormalizeFingerprintCallback8616,
    compact_observable: CompactObservableCallback8616,
) -> str | None:
    """Compact fields independently so selector identity remains inspectable."""
    fingerprint = parse_selector_return_fingerprint_8616(value)
    if fingerprint is None:
        return None
    condition = canonicalize_condition(fingerprint.condition)
    inverse_source = fingerprint.inverse_condition
    if inverse_source is None:
        inverse_source = invert_condition_fingerprint_string_8616(
            fingerprint.condition
        )
    inverse_condition = (
        canonicalize_condition(inverse_source)
        if isinstance(inverse_source, str)
        else None
    )
    compact_condition = compact_observable("conditions", condition)
    compact_inverse = (
        compact_observable("conditions", inverse_condition)
        if inverse_condition is not None
        else None
    )
    if compact_inverse == compact_condition:
        compact_inverse = None
    return encode_selector_return_fingerprint_8616(
        SelectorReturnFingerprint8616(
            condition=compact_condition,
            inverse_condition=compact_inverse,
            true_returns=tuple(
                compact_observable("returns", item)
                for item in fingerprint.true_returns
            ),
            false_returns=tuple(
                compact_observable("returns", item)
                for item in fingerprint.false_returns
            ),
        )
    )


def _terminal_return_fingerprints_8616(
    body: object,
    return_fingerprint: FingerprintCallback8616,
) -> tuple[str, ...]:
    """Fingerprint a non-void return that terminates one structured arm."""
    if isinstance(body, CReturn):
        return () if body.retval is None else (return_fingerprint(body.retval),)
    if not isinstance(body, CStatements):
        return ()
    statements = tuple(body.statements or ())
    if not statements or not isinstance(statements[-1], CReturn):
        return ()
    terminal = statements[-1]
    return () if terminal.retval is None else (return_fingerprint(terminal.retval),)


def _normalize_condition_8616(condition: str) -> str:
    """Canonicalize one condition without changing branch polarity."""
    return str(
        normalize_condition_fingerprint_algebraic_8616(
            normalize_condition_fingerprint_string_8616(condition)
        )
    )


def _selector_return_token_8616(
    condition: str,
    true_returns: tuple[str, ...],
    false_returns: tuple[str, ...],
) -> str:
    """Encode one selector, canonicalizing exact inverse-and-swapped arms."""

    def encode(
        cond: str,
        inverse_cond: str | None,
        true_values: tuple[str, ...],
        false_values: tuple[str, ...],
    ) -> str:
        return encode_selector_return_fingerprint_8616(
            SelectorReturnFingerprint8616(
                condition=cond,
                inverse_condition=inverse_cond,
                true_returns=true_values,
                false_returns=false_values,
            )
        )

    normalized = _normalize_condition_8616(condition)
    inverted = invert_condition_fingerprint_string_8616(normalized)
    normalized_inverse = (
        _normalize_condition_8616(inverted) if inverted is not None else None
    )
    candidates = [
        encode(normalized, normalized_inverse, true_returns, false_returns)
    ]
    if inverted is not None:
        candidates.append(
            encode(normalized_inverse or inverted, normalized, false_returns, true_returns)
        )
    return min(candidates)


def collect_selector_return_fingerprints_8616(
    root: object,
    *,
    condition_fingerprint: FingerprintCallback8616,
    return_fingerprint: FingerprintCallback8616,
) -> SelectorReturnFingerprintResult8616:
    """Collect exact two-outcome return selectors from structured statements."""
    raw_count = normalized_count = classified_count = materialized_count = 0
    fingerprints: set[str] = set()
    for parent in _iter_c_nodes_deep_8616(root):
        if not isinstance(parent, CStatements):
            continue
        statements = tuple(parent.statements or ())
        for index, statement in enumerate(statements):
            if not isinstance(statement, CIfElse):
                continue
            raw_count += 1
            pairs = tuple(statement.condition_and_nodes or ())
            if len(pairs) != 1 or len(pairs[0]) != 2:
                continue
            normalized_count += 1
            condition, true_body = pairs[0]
            true_returns = _terminal_return_fingerprints_8616(true_body, return_fingerprint)
            if statement.else_node is not None:
                false_body = statement.else_node
            elif index + 1 < len(statements):
                false_body = statements[index + 1]
            else:
                false_body = None
            false_returns = _terminal_return_fingerprints_8616(false_body, return_fingerprint)
            if not true_returns or not false_returns:
                continue
            classified_count += 1
            fingerprints.add(
                _selector_return_token_8616(
                    condition_fingerprint(condition),
                    true_returns,
                    false_returns,
                )
            )
            materialized_count += 1
    failure_count = max(classified_count - materialized_count, 0)
    return SelectorReturnFingerprintResult8616(
        fingerprints=tuple(sorted(fingerprints)),
        stats=SelectorReturnFingerprintStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            classified_fact_count=classified_count,
            materialized_count=materialized_count,
            failure_count=failure_count,
        ),
    )
