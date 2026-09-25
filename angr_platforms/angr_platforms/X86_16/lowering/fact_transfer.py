"""Transfer semantic alias facts from lifting into codegen materialization.

Layer: Types/Lowering.
Responsibility: consumes alias, widening, and typed facts by moving normalized
AliasStorageFacts into stack/global materialization state.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
import typing
from collections.abc import Iterable
from typing import Protocol, cast

# Input: AliasStorageFacts from IR lifting
# Output: materialized SimStackVariable/CVariable
# Forbidden:
# - generated-C inspection
# - regex recovery
# - rewrite-only fixes
# Contract:
# classified_count > 0 requires materialized_count > 0
#
# Facts are recorded on the DataAccess emulator during lifting via
# _record_semantic_memory_access().  The emulator is ephemeral (discarded
# after block lifting), so we collect facts by re-lifting blocks through
# a fresh DataAccess with facts recording enabled.

__all__ = [
    "collect_normalized_semantic_alias_facts_from_project_8616",
    "collect_semantic_alias_facts_from_project_8616",
    "transfer_semantic_alias_facts_to_codegen_8616",
]


class _StackSlotIdentityLike(Protocol):
    offset: int
    width: int | None


def _dynamic_boundary_attr_8616(obj: object, name: str, default: object = None) -> object:
    """Dynamic angr/codegen boundary: read optional project, KB, function, or metadata attributes."""
    return getattr(obj, name, default)


def _has_dynamic_codegen_attr_8616(obj: object, name: str) -> bool:
    """Dynamic codegen boundary: check optional semantic fact-transfer metadata."""
    return hasattr(obj, name)


def _stack_slot_identity_from_fact_8616(fact: object) -> _StackSlotIdentityLike | None:
    """Return the owned stack-slot identity carried by an alias fact."""
    from ..alias.alias_model_impl import AliasStorageFacts

    if not isinstance(fact, AliasStorageFacts):
        return None
    identity = fact.identity
    if not isinstance(identity, tuple) or len(identity) < 2 or identity[0] != "stack":
        return None
    return cast(_StackSlotIdentityLike, identity[1])


def _sorted_int_iterable_attr_8616(obj: object, name: str) -> list[int]:
    """Dynamic angr boundary: read and sort optional integer address sets."""
    value = _dynamic_boundary_attr_8616(obj, name, ())
    if not isinstance(value, Iterable):
        return []
    return sorted(item for item in value if isinstance(item, int))


def _lift_block_and_collect_facts(project: object, block_addr: int) -> list[object]:
    """Lift one block and collect semantic alias facts from the MODULE CACHE.

    During VEX lifting, _record_semantic_memory_access() writes AliasStorageFacts
    into the _inertia_module_alias_fact_cache dict in access.py, keyed by block
    address.  This function re-lifts the block (to ensure the cache is populated)
    then reads facts from the module-level cache.

    Returns list of AliasStorageFacts / AliasFailure objects.
    """
    try:
        # Re-lift to populate the module cache (keyed by block_addr)
        factory = _dynamic_boundary_attr_8616(project, "factory")
        block = _dynamic_boundary_attr_8616(factory, "block")
        if callable(block):
            block(block_addr, opt_level=0)
    except Exception as ex:
        import logging

        logging.getLogger(__name__).debug(
            "fact transfer block lift failed block_addr=%#x: %s",
            block_addr,
            ex,
        )

    # Read from module-level cache in access.py
    from ..access import _inertia_module_alias_fact_cache

    facts = _inertia_module_alias_fact_cache.get(block_addr, None)
    if isinstance(facts, list):
        return list(facts)
    return []


def _function_block_addrs_8616(project: object, function_addr: int) -> list[int]:
    """Return the sorted block addresses proven to belong to one function."""
    kb = _dynamic_boundary_attr_8616(project, "kb") if project is not None else None
    if kb is None:
        return []
    functions = _dynamic_boundary_attr_8616(kb, "functions")
    function_for_addr = _dynamic_boundary_attr_8616(functions, "function")
    func = function_for_addr(addr=function_addr, create=False) if callable(function_for_addr) else None
    if func is None:
        return []
    return _sorted_int_iterable_attr_8616(func, "block_addrs_set")


def _relift_function_blocks_8616(project: object, block_addrs: list[int]) -> None:
    """Re-lift each owned block so the collection context records accesses."""
    factory = _dynamic_boundary_attr_8616(project, "factory")
    lift_block = _dynamic_boundary_attr_8616(factory, "block")
    if not callable(lift_block):
        return
    for block_addr in block_addrs:
        try:
            lift_block(block_addr, opt_level=0)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "semantic evidence re-lift failed block_addr=%#x: %s",
                block_addr,
                ex,
            )


def _collected_facts_8616(
    project: object,
    codegen: object,
    func_addr: int,
    allow_legacy: bool,
) -> tuple[list[object], list[object], list[object]]:
    """Collect normalized facts; only the debug flag permits legacy fallback."""
    try:
        return collect_normalized_semantic_alias_facts_from_project_8616(
            project, func_addr
        )
    except Exception as e:
        typing.cast(typing.Any, codegen)._inertia_semantic_fact_transfer_error = repr(e)
        if not allow_legacy:
            raise
        facts = collect_semantic_alias_facts_from_project_8616(project, func_addr)
        typing.cast(typing.Any, codegen)._inertia_semantic_fact_transfer_fallback_used = True
        return facts, [], []


def _init_consumption_counters_8616(codegen: object) -> None:
    """Initialize consumption counters (filled later by materialization passes)."""
    if not _has_dynamic_codegen_attr_8616(codegen, "_inertia_semantic_stack_materialized_count"):
        typing.cast(typing.Any, codegen)._inertia_semantic_stack_materialized_count = 0
    if not _has_dynamic_codegen_attr_8616(codegen, "_inertia_semantic_condition_fact_count"):
        typing.cast(typing.Any, codegen)._inertia_semantic_condition_fact_count = 0
    if not _has_dynamic_codegen_attr_8616(codegen, "_inertia_semantic_condition_materialized_count"):
        typing.cast(typing.Any, codegen)._inertia_semantic_condition_materialized_count = 0


def collect_normalized_semantic_alias_facts_from_project_8616(
    project: object, function_addr: int
) -> tuple[list[object], list[object], list[object]]:
    """Collect normalized facts, failures, and their function-owned raw evidence."""

    def _impl() -> tuple[list[object], list[object], list[object]]:
        """Collect and normalize semantic alias facts AFTER stack-frame recovery.

        Pipeline order:
          1. IR lifting records raw semantic addresses (no alias facts)
          2. This function reads raw accesses
          3. Detects BP frame
          4. Normalizes SS addresses to BP-relative STABLE
          5. Asserts no unresolved STABLE SS reaches alias
          6. Calls alias_facts_for_ir_address_8616() on normalized addresses
          7. Caches results in _inertia_module_alias_fact_cache

        This replaces the old pattern where alias facts were created during lifting
        before frame normalization.
        """
        from ..access import _inertia_module_alias_fact_cache
        from ..alias.alias_model_impl import AliasFailure, alias_facts_for_ir_address_8616
        from ..ir.core import IRAddress
        from ..semantics.evidence_cache import collect_accesses_for_function
        from ..semantics.stack_frame_recovery import (
            StackFrameInfo8616,
            _detect_sp_proven_delta_from_blocks,
            _gather_ir_artifacts_from_function_blocks,
            assert_no_unresolved_stable_ss_before_alias_8616,
            detect_stack_frame_8616,
            normalize_semantic_accesses_8616,
        )

        block_addrs = _function_block_addrs_8616(project, function_addr)

        # Re-lift only blocks proven to belong to this function. The context owns
        # every resulting access, so equal addresses in other projects cannot leak.
        with collect_accesses_for_function(function_addr) as collection:
            _relift_function_blocks_8616(project, block_addrs)
            raw_accesses = list(collection.accesses)

        raw_access_tuples = [
            (access.mode, access.addr)
            for access in raw_accesses
            if isinstance(access.addr, IRAddress)
        ]

        # ── Collect IR artifacts for BP frame detection (VEX blocks, NOT text) ──
        ir_artifacts = _gather_ir_artifacts_from_function_blocks(project, function_addr)

        frame = detect_stack_frame_8616(
            function_addr=function_addr,
            ir_artifacts=ir_artifacts,
            semantic_accesses=raw_access_tuples,
        )

        # ── SP delta: detect proven frame size from VEX ──
        proven_sp_delta = _detect_sp_proven_delta_from_blocks(project, function_addr)
        if proven_sp_delta is not None and frame.uses_bp_frame:
            frame = StackFrameInfo8616(
                function_addr=function_addr,
                uses_bp_frame=True,
                bp_established=True,
                sp_delta_known=True,
                frame_base="bp",
                frame_kind="bp",
                evidence=(*tuple(frame.evidence), f"proven_sp_delta={proven_sp_delta}"),
            )

        normalized = normalize_semantic_accesses_8616(raw_accesses, frame)
        assert_no_unresolved_stable_ss_before_alias_8616(normalized)

        facts: list[object] = []
        failures: list[object] = []

        for acc in normalized:
            addr = acc[1]
            fact = alias_facts_for_ir_address_8616(addr)
            if isinstance(fact, AliasFailure):
                failures.append(fact)
            elif fact is not None:
                facts.append(fact)

        _inertia_module_alias_fact_cache[function_addr] = facts + failures
        return facts, failures, list(raw_accesses)

    return _impl()


def collect_semantic_alias_facts_from_project_8616(project: object, func_addr: int) -> list[object]:
    """Collect semantic alias facts for a function by re-lifting its blocks.

    During VEX→IR lifting, _record_semantic_memory_access() writes facts into
    the _inertia_module_alias_fact_cache dict in access.py, keyed by block
    address.  This function re-lifts every block in the function and aggregates
    facts from the module cache.

    Returns a deduplicated, deterministic list of alias facts.
    """
    kb = _dynamic_boundary_attr_8616(project, "kb") if project is not None else None
    if kb is None:
        return []

    functions = _dynamic_boundary_attr_8616(kb, "functions")
    function_for_addr = _dynamic_boundary_attr_8616(functions, "function")
    func = function_for_addr(addr=func_addr, create=False) if callable(function_for_addr) else None
    if func is None:
        return []

    block_addrs = _sorted_int_iterable_attr_8616(func, "block_addrs_set")
    if not block_addrs:
        return []

    from ..alias.alias_model_impl import AliasStorageFacts

    all_facts: list[object] = []
    for block_addr in block_addrs:
        all_facts.extend(_lift_block_and_collect_facts(project, block_addr))

    # Deduplicate — AliasStorageFacts and AliasFailure are frozen dataclasses
    seen: set[int] = set()
    unique: list[object] = []
    for fact in all_facts:
        try:
            key = hash(fact)
        except TypeError:
            key = id(fact)
        if key not in seen:
            seen.add(key)
            unique.append(fact)

    # Deterministic sort: stack facts by offset, then others
    def _sort_key(fact: object) -> tuple[str, int, int]:
        identity = fact.identity if isinstance(fact, AliasStorageFacts) else None
        if identity is None:
            return ("z", 0, 0)
        kind = identity[0] if isinstance(identity, tuple) and len(identity) >= 2 else "z"
        slot = _stack_slot_identity_from_fact_8616(fact)
        offset = slot.offset if slot is not None else 0
        width = slot.width if slot is not None and slot.width is not None else 0
        order = {"stack": "a", "register": "b", "memory": "c"}.get(kind, "z")
        return (order, offset, width)

    unique.sort(key=_sort_key)
    return unique


def transfer_semantic_alias_facts_to_codegen_8616(project: object, codegen: object) -> int:
    """Transfer normalized semantic alias facts into codegen pipeline diagnostics."""

    def _impl() -> int:
        """Transfer semantic alias facts from project blocks to codegen.

        This bridges the gap between the VEX lifter (which records facts on
        the emulator) and the invariant gate/stack lowering (which consume
        facts from codegen).

        Sets codegen._inertia_stack_lane with a SemanticLaneState for the STACK lane.
        Returns the number of facts transferred.
        """
        from ..alias.alias_model_impl import AliasStorageFacts
        from ..pipeline.contracts import SemanticLaneState

        cfunc = _dynamic_boundary_attr_8616(codegen, "cfunc")
        if cfunc is None:
            typing.cast(typing.Any, codegen)._inertia_semantic_alias_facts = []
            typing.cast(typing.Any, codegen)._inertia_semantic_facts_transferred = True
            return 0

        func_addr = _dynamic_boundary_attr_8616(cfunc, "addr")
        if not isinstance(func_addr, int):
            typing.cast(typing.Any, codegen)._inertia_semantic_alias_facts = []
            typing.cast(typing.Any, codegen)._inertia_semantic_facts_transferred = True
            return 0

        # Only allow legacy fallback if explicitly enabled by debug flag.
        # Silent fallback is FORBIDDEN — it makes regressions invisible.
        allow_legacy = bool(_dynamic_boundary_attr_8616(project, "_inertia_allow_legacy_fact_fallback", False))

        facts, failures, raw_accesses = _collected_facts_8616(
            project, codegen, func_addr, allow_legacy,
        )

        raw_count = len(raw_accesses)

        typing.cast(typing.Any, codegen)._inertia_semantic_alias_facts = facts + failures
        typing.cast(typing.Any, codegen)._inertia_semantic_facts_transferred = True
        typing.cast(typing.Any, codegen)._inertia_semantic_alias_fact_count = len(facts) + len(failures)

        # Count stack facts and normalized accesses for diagnostics
        normalized_count = sum(
            1 for fact in facts if isinstance(fact, AliasStorageFacts) and isinstance(fact.identity, tuple)
        )
        stack_count = sum(
            1
            for fact in facts
            if isinstance(fact, AliasStorageFacts)
            and isinstance(fact.identity, tuple)
            and len(fact.identity) >= 2
            and fact.identity[0] == "stack"
        )

        typing.cast(typing.Any, codegen)._inertia_semantic_raw_access_count = raw_count
        typing.cast(typing.Any, codegen)._inertia_semantic_normalized_access_count = normalized_count
        typing.cast(typing.Any, codegen)._inertia_semantic_stack_fact_count = stack_count
        typing.cast(typing.Any, codegen)._inertia_semantic_failure_count = len(failures)

        _init_consumption_counters_8616(codegen)

        # ── Initialize STACK lane contract ──
        typing.cast(typing.Any, codegen)._inertia_stack_lane = SemanticLaneState(
            name="stack",
            raw=raw_count,
            normalized=normalized_count,
            classified=stack_count,
            bound=0,  # filled by lowering pass
            materialized=0,  # filled by materialization pass
            verified=0,  # filled by validation pass
            failures=len(failures),
        )

        # Compact diagnostic report — single structured line, collected here
        # so downstream failures don't lose the data.
        _diagnostic = {
            "function": f"0x{func_addr:x}",
            "raw_accesses": raw_count,
            "normalized_accesses": normalized_count,
            "alias_facts": len(facts),
            "stack_facts": stack_count,
            "stack_materialized": _dynamic_boundary_attr_8616(codegen, "_inertia_semantic_stack_materialized_count", 0),
            "condition_facts": _dynamic_boundary_attr_8616(codegen, "_inertia_semantic_condition_fact_count", 0),
            "condition_materialized": _dynamic_boundary_attr_8616(
                codegen, "_inertia_semantic_condition_materialized_count", 0
            ),
            "failures": len(failures),
            "primary_blocker": (
                "raw_accesses=0 (check lifter access recording / function context)"
                if raw_count == 0
                else ("stack_materialized=0 (fix lowering/stack_lowering_from_facts.py)" if stack_count > 0 else None)
            ),
        }
        typing.cast(typing.Any, codegen)._inertia_pipeline_diag = _diagnostic
        if os.environ.get("INERTIA_DEBUG_STACK_FACTS"):
            logging.getLogger(__name__).warning(
                "[stack-facts] func=0x%x raw=%d normalized=%d facts=%d stack=%d failures=%d blocker=%s",
                func_addr,
                raw_count,
                normalized_count,
                len(facts),
                stack_count,
                len(failures),
                _diagnostic.get("primary_blocker"),
            )
            for fact in facts[:16]:
                logging.getLogger(__name__).warning("[stack-facts] fact=%r", fact)

        return len(facts) + len(failures)

    return _impl()


def emit_pipeline_diagnostic_8616(codegen: object) -> dict[str, object]:
    """Return the compact pipeline diagnostic dict for this function.

    Callers should print or log this dict.  The dict is already attached
    to codegen._inertia_pipeline_diag after fact transfer.
    """
    diag = _dynamic_boundary_attr_8616(codegen, "_inertia_pipeline_diag", {})
    return diag if isinstance(diag, dict) else {}
