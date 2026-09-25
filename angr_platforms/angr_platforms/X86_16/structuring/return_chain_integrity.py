"""Verify materialized return chains on the structured C AST.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
This guard compares Structuring-owned return-chain and mask-accumulator
metadata with returns still present in the authoritative angr C AST.

Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

This module validates typed AST state only. It must not inspect, parse, or
repair rendered C text; rendering and final emission consume this result.
Dynamic boundary: the guard reads initialized extension fields and structured
C nodes carried by third-party angr codegen objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CReturn

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..pipeline.errors import PipelineHardError
from ..pipeline.render_authority import install_codegen_render_integrity_guard_8616
from ..tail_validation_fingerprint import _expr_fingerprint
from .return_chains import const_return_value_8616

__all__ = [
    "MaterializedReturnChainIntegrity8616",
    "MaterializedReturnChainIntegrityVerdict8616",
    "assess_materialized_return_chain_integrity_8616",
    "install_materialized_return_chain_integrity_guard_8616",
    "require_materialized_return_chain_integrity_8616",
]


class MaterializedReturnChainIntegrityVerdict8616(StrEnum):
    """Typed status for the Structuring-owned return-chain AST contract."""

    NOT_APPLICABLE = "not_applicable"
    PASSED = "passed"
    INCOMPLETE_CODEGEN_BOUNDARY = "incomplete_codegen_boundary"
    MISSING_EXPECTED_VALUES = "missing_expected_values"
    MISSING_AST_ROOT = "missing_ast_root"
    MISSING_RETURN_VALUES = "missing_return_values"
    MISSING_RETURN_EXPRESSION = "missing_return_expression"


@dataclass(frozen=True, slots=True)
class MaterializedReturnChainIntegrity8616:
    """Comparison between proven return-chain metadata and the live C AST."""

    verdict: MaterializedReturnChainIntegrityVerdict8616
    expected_values: tuple[int, ...] = ()
    observed_values: tuple[int, ...] = ()
    missing_values: tuple[int, ...] = ()
    expected_return_fingerprint: str = ""
    observed_return_fingerprints: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        """Return whether no active materialized return chain was lost."""
        return self.verdict in {
            MaterializedReturnChainIntegrityVerdict8616.NOT_APPLICABLE,
            MaterializedReturnChainIntegrityVerdict8616.PASSED,
        }

    @property
    def active(self) -> bool:
        """Return whether Structuring claims a materialized return chain."""
        return self.verdict is not MaterializedReturnChainIntegrityVerdict8616.NOT_APPLICABLE

    def diagnostic(self) -> str:
        """Return a stable diagnostic suitable for pipeline hard errors."""
        return (
            f"return-chain AST integrity={self.verdict.value} "
            f"expected={self.expected_values!r} observed={self.observed_values!r} "
            f"missing={self.missing_values!r} expected_return={self.expected_return_fingerprint!r} "
            f"observed_returns={self.observed_return_fingerprints!r}"
        )


class _ReturnChainCFunctionBoundary8616(Protocol):
    """Minimum third-party angr C function surface used by this guard."""

    statements: object


class _ReturnChainCodegenBoundary8616(Protocol):
    """Initialized return-chain metadata carried by an angr codegen object."""

    cfunc: _ReturnChainCFunctionBoundary8616
    _inertia_return_chain_flattened_8616: bool
    _inertia_return_chain_suffix_materialized_8616: bool
    _inertia_return_chain_materialized_values_8616: tuple[int, ...]
    _inertia_return_chain_final_value_8616: int
    _inertia_mask_accumulator_materialized_8616: bool
    _inertia_mask_accumulator_return_fingerprint_8616: str


@dataclass(frozen=True, slots=True)
class _MaterializedReturnChainRenderGuard8616:
    """Pipeline callback that reassesses the live Structuring AST at render time."""

    def verify(self, codegen: object, *, context: str) -> None:
        """Consume the Structuring contract through the Pipeline guard protocol."""
        require_materialized_return_chain_integrity_8616(codegen, context=context)


def _missing_values_8616(expected: tuple[int, ...], observed: tuple[int, ...]) -> tuple[int, ...]:
    """Return distinct proven values absent from the live return surface."""
    observed_values = frozenset(observed)
    return tuple(dict.fromkeys(value for value in expected if value not in observed_values))


def _chain_activity_8616(
    codegen: object,
) -> tuple[bool, bool] | MaterializedReturnChainIntegrity8616:
    """Return (chain_active, mask_active) or an early assessment result."""
    marker_missing = object()
    flattened_marker = getattr(codegen, "_inertia_return_chain_flattened_8616", marker_missing)
    suffix_marker = getattr(codegen, "_inertia_return_chain_suffix_materialized_8616", marker_missing)
    mask_marker = getattr(codegen, "_inertia_mask_accumulator_materialized_8616", False)
    mask_active = mask_marker is True
    chain_metadata_absent = flattened_marker is marker_missing and suffix_marker is marker_missing
    if chain_metadata_absent and not mask_active:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.NOT_APPLICABLE
        )
    if not chain_metadata_absent and (flattened_marker is marker_missing or suffix_marker is marker_missing):
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.INCOMPLETE_CODEGEN_BOUNDARY
        )
    flattened = False if chain_metadata_absent else flattened_marker is True
    suffix_materialized = False if chain_metadata_absent else suffix_marker is True
    chain_active = flattened or suffix_materialized
    if not chain_active and not mask_active:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.NOT_APPLICABLE
        )
    return chain_active, mask_active


def _expected_values_8616(
    typed_codegen: _ReturnChainCodegenBoundary8616,
    chain_active: bool,
) -> tuple[int, ...] | MaterializedReturnChainIntegrity8616:
    """Return the expected constant values or an early assessment result."""
    if not chain_active:
        return ()
    try:
        materialized_values = tuple(
            int(value) for value in typed_codegen._inertia_return_chain_materialized_values_8616
        )
        final_value = int(typed_codegen._inertia_return_chain_final_value_8616)
    except (AttributeError, TypeError, ValueError):
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.INCOMPLETE_CODEGEN_BOUNDARY
        )
    if not materialized_values:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.MISSING_EXPECTED_VALUES
        )
    return (*materialized_values, final_value)


def _expected_fingerprint_8616(
    typed_codegen: _ReturnChainCodegenBoundary8616,
    mask_active: bool,
) -> str | MaterializedReturnChainIntegrity8616:
    """Return the expected return fingerprint or an early assessment result."""
    if not mask_active:
        return ""
    try:
        expected_return_fingerprint = typed_codegen._inertia_mask_accumulator_return_fingerprint_8616
    except AttributeError:
        expected_return_fingerprint = ""
    if not expected_return_fingerprint:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.INCOMPLETE_CODEGEN_BOUNDARY
        )
    return expected_return_fingerprint


def _proven_root_8616(
    typed_codegen: _ReturnChainCodegenBoundary8616,
    expected_values: tuple[int, ...],
    expected_return_fingerprint: str,
) -> object | MaterializedReturnChainIntegrity8616:
    """Return the proven AST root or a missing-root assessment result."""
    try:
        root = typed_codegen.cfunc.statements
    except AttributeError:
        root = None
    if root is None:
        return MaterializedReturnChainIntegrity8616(
            MaterializedReturnChainIntegrityVerdict8616.MISSING_AST_ROOT,
            expected_values=expected_values,
            expected_return_fingerprint=expected_return_fingerprint,
        )
    return root


def assess_materialized_return_chain_integrity_8616(
    codegen: object,
) -> MaterializedReturnChainIntegrity8616:
    """Assess exact constant-return preservation without consulting rendered C."""
    activity = _chain_activity_8616(codegen)
    if isinstance(activity, MaterializedReturnChainIntegrity8616):
        return activity
    chain_active, mask_active = activity
    typed_codegen = cast(_ReturnChainCodegenBoundary8616, codegen)
    values = _expected_values_8616(typed_codegen, chain_active)
    if isinstance(values, MaterializedReturnChainIntegrity8616):
        return values
    expected_values = values
    fingerprint = _expected_fingerprint_8616(typed_codegen, mask_active)
    if isinstance(fingerprint, MaterializedReturnChainIntegrity8616):
        return fingerprint
    expected_return_fingerprint = fingerprint
    root = _proven_root_8616(typed_codegen, expected_values, expected_return_fingerprint)
    if isinstance(root, MaterializedReturnChainIntegrity8616):
        return root
    observed_values = tuple(
        value
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CReturn)
        if (value := const_return_value_8616(node.retval)) is not None
    )
    observed_return_fingerprints = tuple(
        _expr_fingerprint(node.retval, None)
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CReturn)
    )
    missing_values = _missing_values_8616(expected_values, observed_values)
    if missing_values:
        verdict = MaterializedReturnChainIntegrityVerdict8616.MISSING_RETURN_VALUES
    elif expected_return_fingerprint and expected_return_fingerprint not in observed_return_fingerprints:
        verdict = MaterializedReturnChainIntegrityVerdict8616.MISSING_RETURN_EXPRESSION
    else:
        verdict = MaterializedReturnChainIntegrityVerdict8616.PASSED
    return MaterializedReturnChainIntegrity8616(
        verdict,
        expected_values=expected_values,
        observed_values=observed_values,
        missing_values=missing_values,
        expected_return_fingerprint=expected_return_fingerprint,
        observed_return_fingerprints=observed_return_fingerprints,
    )


def require_materialized_return_chain_integrity_8616(
    codegen: object,
    *,
    context: str,
) -> MaterializedReturnChainIntegrity8616:
    """Hard-fail when an active return-chain AST no longer matches its proof."""
    integrity = assess_materialized_return_chain_integrity_8616(codegen)
    if integrity.accepted:
        return integrity
    cfunc = getattr(codegen, "cfunc", None)
    function_addr = getattr(cfunc, "addr", None)
    raise PipelineHardError(
        "authoritative C AST lost CFG-proven return-chain values",
        layer="structuring",
        function_addr=function_addr if isinstance(function_addr, int) else None,
        details={
            "verdict": integrity.verdict.value,
            "expected_values": integrity.expected_values,
            "observed_values": integrity.observed_values,
            "missing_values": integrity.missing_values,
            "expected_return_fingerprint": integrity.expected_return_fingerprint,
            "observed_return_fingerprints": integrity.observed_return_fingerprints,
            "context": context,
        },
    )


def install_materialized_return_chain_integrity_guard_8616(codegen: object) -> None:
    """Install the live return-chain verifier through Pipeline governance."""
    install_codegen_render_integrity_guard_8616(codegen, _MaterializedReturnChainRenderGuard8616())
