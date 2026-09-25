"""Consume exact C arguments projected from machine CALL return frames.

Layer: Types/Lowering.
Responsibility: Consumes alias, widening, and typed facts. Join Semantics-owned
VEX CALL-frame store facts to exact structured-C call arguments and remove
source-invisible return-address values.
Do not recover semantics from COD, source, assembly, or rendered C text.
This module does not infer call semantics, guess arity, use symbol names, or use
address-specific exceptions.

Only the full ``(callsite, VEX block, VEX statement)`` identity plus the typed
fall-through return address is accepted. The final C expression shape is not
evidence because prior Lowering may have transformed it while preserving the
exact semantic key. Address-only matches are explicit refusal cases.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallsiteSummary8616, structured_callsite_addr_8616
from ..pipeline.errors import PipelineHardError
from ..semantics.call_return_frame_effects import (
    CallReturnFrameEffectCollection8616,
    CallReturnFrameEffectKey8616,
    CallReturnFrameEffectRole8616,
    collect_call_return_frame_effects_8616,
)
from ..semantics.call_return_frame_projections import (
    CallReturnFrameProjectionFact8616,
    CallReturnFrameProjectionRole8616,
)

__all__ = (
    "CallReturnFrameArgumentPruneResult8616",
    "CallReturnFrameArgumentPruneStats8616",
    "CallReturnFrameArgumentPruneStatus8616",
    "prune_exact_call_return_frame_arguments_8616",
)

type StructuredAstValue = Any


class CallReturnFrameArgumentPruneStatus8616(StrEnum):
    """Typed result of exact CALL-frame argument projection lowering."""

    NOT_APPLICABLE = "not_applicable"
    MATERIALIZED = "materialized"
    MATERIALIZED_WITH_REFUSAL = "materialized_with_refusal"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(slots=True)
class CallReturnFrameArgumentPruneStats8616:
    """Closed evidence counters for CALL-frame arguments consumed by Lowering."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every observed projection was consumed or refused."""
        return (
            self.materialized_count <= self.classified_fact_count
            <= self.normalized_fact_count
            <= self.raw_fact_count
            and self.materialized_count + self.failure_count == self.raw_fact_count
        )


@dataclass(frozen=True, slots=True)
class CallReturnFrameArgumentPruneResult8616:
    """Typed outcome published after exact CALL-frame argument lowering."""

    status: CallReturnFrameArgumentPruneStatus8616
    stats: CallReturnFrameArgumentPruneStats8616

    @property
    def changed(self) -> bool:
        """Return whether at least one source-invisible argument was removed."""
        return self.stats.materialized_count > 0


class _CFunctionSurface8616(Protocol):
    """Third-party generated function fields consumed by this owner."""

    addr: int
    statements: StructuredAstValue
    variables_in_use: object
    unified_local_vars: object


class _StructuredTagsSurface8616(Protocol):
    """Third-party dict/AIL Tags lookup surface at the structured-C boundary."""

    def get(self, key: str) -> object | None:
        """Return one structured provenance tag when present."""


class _CodegenSurface8616(Protocol):
    """Owned codegen contracts consumed and published by this owner."""

    cfunc: _CFunctionSurface8616
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_call_return_frame_argument_prune_8616: CallReturnFrameArgumentPruneResult8616
    _inertia_call_return_frame_effect_collection_8616: CallReturnFrameEffectCollection8616


def _expression_effect_key_8616(
    expression: StructuredAstValue,
) -> CallReturnFrameEffectKey8616 | None:
    """Read an exact semantic join key from one third-party C expression."""
    try:
        tags = expression.tags
    except AttributeError:
        return None
    surface = cast(_StructuredTagsSurface8616, tags)
    try:
        values = (
            surface.get("ins_addr"),
            surface.get("vex_block_addr"),
            surface.get("vex_stmt_idx"),
        )
    except (AttributeError, TypeError):
        return None
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in values):
        return None
    return CallReturnFrameEffectKey8616(*(cast(int, value) for value in values))


def _function_for_codegen_8616(project: object, cfunc: _CFunctionSurface8616) -> object | None:
    """Resolve the current function at the dynamic angr project boundary."""
    project_dynamic = cast(Any, project)
    try:
        return cast(object, project_dynamic.kb.functions.function(addr=cfunc.addr, create=False))
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def _return_addresses_by_callsite_8616(
    summaries: Mapping[int, CallsiteSummary8616],
) -> dict[int, int]:
    """Retain only callsites whose cloned summaries agree on return identity."""
    candidates: dict[int, set[int]] = {}
    for summary in summaries.values():
        if isinstance(summary.return_addr, int):
            candidates.setdefault(summary.callsite_addr, set()).add(summary.return_addr)
    return {
        callsite_addr: next(iter(return_addrs))
        for callsite_addr, return_addrs in candidates.items()
        if len(return_addrs) == 1
    }


def _status_8616(
    stats: CallReturnFrameArgumentPruneStats8616,
) -> CallReturnFrameArgumentPruneStatus8616:
    """Classify closed counters without parsing diagnostic text."""
    if stats.materialized_count and stats.failure_count:
        return CallReturnFrameArgumentPruneStatus8616.MATERIALIZED_WITH_REFUSAL
    if stats.materialized_count:
        return CallReturnFrameArgumentPruneStatus8616.MATERIALIZED
    if stats.failure_count:
        return CallReturnFrameArgumentPruneStatus8616.UNKNOWN_REFUSE
    return CallReturnFrameArgumentPruneStatus8616.NOT_APPLICABLE


def _empty_result_8616(
    surface: _CodegenSurface8616,
    stats: CallReturnFrameArgumentPruneStats8616,
) -> CallReturnFrameArgumentPruneResult8616:
    """Publish the typed no-candidate result at one dynamic boundary."""
    result = CallReturnFrameArgumentPruneResult8616(
        CallReturnFrameArgumentPruneStatus8616.NOT_APPLICABLE,
        stats,
    )
    surface._inertia_call_return_frame_argument_prune_8616 = result
    return result


def _retire_declaration_only_frame_locals_8616(
    cfunc: _CFunctionSurface8616,
    root: StructuredAstValue,
) -> None:
    """Retire dead negative-BP declarations after exact frame consumption."""
    referenced = tuple(
        node.variable
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CVariable)
        and isinstance(node.variable, SimStackVariable)
    )
    try:
        mappings = (cfunc.variables_in_use, cfunc.unified_local_vars)
    except AttributeError:
        return
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        for variable in tuple(mapping):
            if (
                isinstance(variable, SimStackVariable)
                and variable.base == "bp"
                and variable.offset < 0
                and not any(variable is item or variable == item for item in referenced)
            ):
                mapping.pop(variable, None)


@dataclass(frozen=True, slots=True)
class _CallReturnFrameIndex8616:
    """By-key effect/projection groupings plus refused producer keys."""

    effects_by_key: dict[CallReturnFrameEffectKey8616, list[CallReturnFrameEffectRole8616]]
    projections_by_key: dict[
        CallReturnFrameEffectKey8616,
        list[CallReturnFrameProjectionFact8616],
    ]
    refused_keys: set[CallReturnFrameEffectKey8616]


def _prune_inputs_8616(
    project: object,
    surface: _CodegenSurface8616,
    function: object | None,
) -> tuple[object, dict[int, CallsiteSummary8616], object, dict[int, int]] | None:
    """Return validated (root, summaries, function, return_addrs) or None."""
    try:
        root = surface.cfunc.statements
        summaries = surface._inertia_callsite_summaries
    except AttributeError:
        return None
    if not isinstance(summaries, dict) or any(
        not isinstance(key, int) or not isinstance(summary, CallsiteSummary8616)
        for key, summary in summaries.items()
    ):
        raise TypeError("callsite summary carrier contains an invalid owned contract")
    active_function = function or _function_for_codegen_8616(project, surface.cfunc)
    return_addrs = _return_addresses_by_callsite_8616(summaries)
    if active_function is None or not return_addrs:
        return None
    return root, summaries, active_function, return_addrs


def _effect_index_8616(
    collection: CallReturnFrameEffectCollection8616,
) -> _CallReturnFrameIndex8616:
    """Group effects and projections by key plus refused producer keys."""
    effects_by_key: dict[CallReturnFrameEffectKey8616, list[CallReturnFrameEffectRole8616]] = {}
    for effect in collection.effects:
        effects_by_key.setdefault(effect.key, []).append(effect.role)
    projections_by_key: dict[
        CallReturnFrameEffectKey8616,
        list[CallReturnFrameProjectionFact8616],
    ] = {}
    for projection in collection.projection_collection.projections:
        projections_by_key.setdefault(projection.projection_key, []).append(projection)
    refused_keys = {
        producer_key
        for refusal in collection.projection_collection.refusals
        for producer_key in refusal.producer_keys
    }
    return _CallReturnFrameIndex8616(effects_by_key, projections_by_key, refused_keys)


def _relation_exact_8616(
    key: CallReturnFrameEffectKey8616,
    projection: CallReturnFrameProjectionFact8616,
    effects_by_key: dict[CallReturnFrameEffectKey8616, list[CallReturnFrameEffectRole8616]],
) -> bool:
    """Return whether the projection joins the argument to one stack store."""
    store_roles = tuple(effects_by_key.get(projection.store_key, ()))
    if (
        projection.projection_key != key
        or projection.store_key.callsite_addr != key.callsite_addr
        or len(store_roles) != 1
        or store_roles[0] is not CallReturnFrameEffectRole8616.STACK_STORE
    ):
        return False
    return (
        (
            projection.role is CallReturnFrameProjectionRole8616.STORE_STATEMENT
            and projection.projection_key == projection.store_key
        )
        or (
            projection.role is CallReturnFrameProjectionRole8616.VALUE_PRODUCER
            and projection.projection_key != projection.store_key
        )
    )


@dataclass(slots=True)
class _CallReturnFramePruneScan8616:
    """Per-node prune state: grouped evidence plus the owning stats."""

    stats: CallReturnFrameArgumentPruneStats8616
    index: _CallReturnFrameIndex8616
    return_addrs: dict[int, int]
    callsite_addr: object
    summary: CallsiteSummary8616 | None

    def keep_argument(self, argument: StructuredAstValue) -> bool:
        """Return whether one argument survives the exact-store join."""
        key = _expression_effect_key_8616(argument)
        if key is None:
            return True
        projections = tuple(self.index.projections_by_key.get(key, ()))
        if (
            not projections
            and key not in self.index.refused_keys
            and key.callsite_addr not in self.return_addrs
        ):
            return True
        self.stats.raw_fact_count += 1
        if key in self.index.refused_keys or len(projections) != 1:
            self.stats.failure_count += 1
            return True
        projection = projections[0]
        if not _relation_exact_8616(key, projection, self.index.effects_by_key):
            self.stats.failure_count += 1
            return True
        self.stats.normalized_fact_count += 1
        if not self._callsite_consistent_8616(key, projection):
            self.stats.failure_count += 1
            return True
        self.stats.classified_fact_count += 1
        self.stats.materialized_count += 1
        return False

    def _callsite_consistent_8616(
        self,
        key: CallReturnFrameEffectKey8616,
        projection: CallReturnFrameProjectionFact8616,
    ) -> bool:
        """Return whether the node callsite and summary agree exactly."""
        return (
            self.summary is not None
            and isinstance(self.callsite_addr, int)
            and key.callsite_addr == self.callsite_addr
            and projection.store_key.callsite_addr == self.callsite_addr
            and self.summary.callsite_addr == self.callsite_addr
            and isinstance(self.summary.return_addr, int)
            and self.return_addrs.get(self.callsite_addr) == self.summary.return_addr
        )


def prune_exact_call_return_frame_arguments_8616(
    project: object,
    codegen: object,
    *,
    function: object | None = None,
) -> CallReturnFrameArgumentPruneResult8616:
    """Remove C arguments joined to exact Semantics-owned CALL-frame stores."""
    surface = cast(_CodegenSurface8616, codegen)
    stats = CallReturnFrameArgumentPruneStats8616()
    inputs = _prune_inputs_8616(project, surface, function)
    if inputs is None:
        return _empty_result_8616(surface, stats)
    root, summaries, active_function, return_addrs = inputs
    collection = collect_call_return_frame_effects_8616(
        project,
        active_function,
        return_addrs,
    )
    surface._inertia_call_return_frame_effect_collection_8616 = collection
    if not collection.projection_collection.closed:
        raise PipelineHardError("CALL-frame argument lowering received open projection evidence")
    index = _effect_index_8616(collection)
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, structured_c.CFunctionCall) or not node.args:
            continue
        scan = _CallReturnFramePruneScan8616(
            stats=stats,
            index=index,
            return_addrs=return_addrs,
            callsite_addr=structured_callsite_addr_8616(node),
            summary=summaries.get(id(node)),
        )
        retained = [
            argument for argument in tuple(node.args) if scan.keep_argument(argument)
        ]
        if len(retained) != len(node.args):
            node.args = retained
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "CALL-frame argument lowering classified exact projections without consuming them"
        )
    if not stats.closed:
        raise PipelineHardError("CALL-frame argument lowering did not close its evidence loop")
    if stats.materialized_count:
        _retire_declaration_only_frame_locals_8616(surface.cfunc, root)
    result = CallReturnFrameArgumentPruneResult8616(_status_8616(stats), stats)
    surface._inertia_call_return_frame_argument_prune_8616 = result
    return result
