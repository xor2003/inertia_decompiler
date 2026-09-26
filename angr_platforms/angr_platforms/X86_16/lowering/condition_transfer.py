"""Transfer typed branch conditions into codegen before rewrite.

Layer: Types/Lowering.
Responsibility: consumes alias, widening, and typed facts plus ConditionIR
records from lifting to materialize C condition nodes.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import typing

# Input: ConditionIR from IR lifting
# Output: materialized C condition nodes (CBinaryOp/CUnaryOp in C AST)
# Forbidden:
# - semantic recovery
# - text-pattern semantics
# - generated-C inspection
# - regex recovery
# - rewrite-only fixes
# Contract:
# classified_count > 0 requires materialized_count > 0
#
# During lifting, _emit_simple_jcc() records ConditionIR objects onto
# self.emu._inertia_typed_conditions.  This module collects those records
# and transfers them to codegen before the invariant gate runs.

__all__ = [
    "collect_typed_condition_artifacts_8616",
    "collect_typed_conditions_from_emulator_8616",
    "transfer_typed_conditions_from_emulator_8616",
    "transfer_typed_conditions_to_codegen_8616",
]

import logging
import os
from dataclasses import dataclass, replace
from typing import Any

from ..alias.condition_register_bindings import bind_condition_register_sources_8616
from ..alias.condition_register_carriers import normalize_condition_register_carriers_8616
from ..alias.condition_register_liveness import (
    ConditionRegisterTopology8616,
    normalize_condition_register_liveness_8616,
)
from ..condition_trace import record_classified_conditions_trace_8616
from ..frontend_function_boundary import ExactFunctionRangeBoundary8616
from ..ir.condition_cache_relift import (
    ConditionCacheReliftStats8616,
    ConditionReliftBlock8616,
    has_typed_condition_cache_evidence_8616,
    relift_cached_project_blocks_8616,
    relift_function_condition_cache_8616,
    reset_lifter_condition_state_8616,
)
from ..ir.condition_ir import (
    JCC_TO_COND_8616,
    ConditionEdgeEvidence,
    ConditionIR,
    ConditionResult,
    ConditionSource,
    build_condition_from_cmp_8616,
    build_condition_from_test_8616,
    deduplicate_conditions_8616,
)
from ..ir.core import IRValue, MemSpace
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from .condition_fact_arbitration import resolve_condition_fact_conflicts_8616

log: logging.Logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _ConditionBlockOwner8616:
    """Describe the current decoded conditional terminator for one CFG block."""

    block_addr: int
    terminal_insn: int
    mnemonic: str
    taken_target: int | None
    fallthrough_target: int | None


@dataclass(frozen=True, slots=True)
class _ConditionFunctionOwnership8616:
    """Record decoded function blocks and their current conditional terminators."""

    decoded_block_addrs: frozenset[int]
    conditional_owners: dict[int, _ConditionBlockOwner8616]
    register_topology: ConditionRegisterTopology8616
    relift_blocks: tuple[ConditionReliftBlock8616, ...]


@dataclass(frozen=True, slots=True)
class _ConditionOwnershipStats8616:
    """Account for cached conditions classified against current binary blocks."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _dynamic_boundary_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic angr/codegen boundary: read optional project, lifter, or metadata attributes."""
    return getattr(obj, name, default)

_INVERTED_JCC_MNEMONICS_8616: dict[str, str] = {
    "je": "jne",
    "jz": "jnz",
    "jne": "je",
    "jnz": "jz",
    "jb": "jae",
    "jnae": "jae",
    "jc": "jnc",
    "jae": "jb",
    "jnb": "jb",
    "jnc": "jc",
    "jbe": "ja",
    "jna": "ja",
    "ja": "jbe",
    "jnbe": "jbe",
    "jl": "jge",
    "jnge": "jge",
    "jge": "jl",
    "jnl": "jl",
    "jle": "jg",
    "jng": "jg",
    "jg": "jle",
    "jnle": "jle",
}

_DIRECT_COUNTER_CONDITION_OPS_8616: dict[str, str] = {"loop": "nonzero"}
_REP_COUNTER_ONLY_MNEMONICS_8616: frozenset[str] = frozenset(
    {
        "insb",
        "insd",
        "insw",
        "lodsb",
        "lodsd",
        "lodsw",
        "movsb",
        "movsd",
        "movsw",
        "outsb",
        "outsd",
        "outsw",
        "stosb",
        "stosd",
        "stosw",
    }
)


def _direct_counter_condition_op_8616(mnemonic: str) -> str | None:
    """Return the exact counter-only condition implied by LOOP or plain REP."""
    direct = _DIRECT_COUNTER_CONDITION_OPS_8616.get(mnemonic)
    if direct is not None:
        return direct
    parts = mnemonic.split()
    if (
        len(parts) == 2
        and parts[0] in {"rep", "repe", "repz", "repne", "repnz"}
        and parts[1] in _REP_COUNTER_ONLY_MNEMONICS_8616
    ):
        return "nonzero"
    return None


def _current_function_condition_ownership_8616(func: object) -> _ConditionFunctionOwnership8616:
    """Decode exact current-function block terminators for condition ownership."""
    try:
        blocks = tuple(_dynamic_boundary_attr_8616(func, "blocks", ()) or ())
    except (AttributeError, TypeError):
        blocks = ()

    decoded_block_addrs: set[int] = set()
    owners: dict[int, _ConditionBlockOwner8616] = {}
    conflicting_owners: set[int] = set()
    relift_blocks_by_addr: dict[int, ConditionReliftBlock8616] = {}
    for block in blocks:
        block_addr = _dynamic_boundary_attr_8616(block, "addr", None)
        if not isinstance(block_addr, int):
            continue
        block_size = _dynamic_boundary_attr_8616(block, "size", None)
        if isinstance(block_size, int) and block_size > 0:
            relift_blocks_by_addr[block_addr] = ConditionReliftBlock8616(block_addr, block_size)
        decoded, owner = _decode_block_condition_owner_8616(block, block_addr)
        if decoded:
            decoded_block_addrs.add(block_addr)
        if owner is None:
            continue
        existing = owners.get(block_addr)
        if existing is not None and existing != owner:
            conflicting_owners.add(block_addr)
            owners.pop(block_addr, None)
            continue
        if block_addr not in conflicting_owners:
            owners[block_addr] = owner

    graph = _dynamic_boundary_attr_8616(func, "graph", None)
    predecessors_by_block = (
        func.predecessors_by_block
        if isinstance(func, ExactFunctionRangeBoundary8616)
        else {}
    )
    condition_only_blocks = _condition_only_block_addrs_8616(blocks)
    if not isinstance(func, ExactFunctionRangeBoundary8616):
        predecessors_by_block.update(_graph_predecessors_by_block_8616(graph))

    return _ConditionFunctionOwnership8616(
        decoded_block_addrs=frozenset(decoded_block_addrs),
        conditional_owners=owners,
        register_topology=ConditionRegisterTopology8616(
            predecessors_by_block,
            frozenset(condition_only_blocks),
        ),
        relift_blocks=tuple(relift_blocks_by_addr[address] for address in sorted(relift_blocks_by_addr)),
    )


def _decode_block_condition_owner_8616(
    block: object, block_addr: int
) -> tuple[bool, _ConditionBlockOwner8616 | None]:
    """Decode one block's terminal instruction into a condition owner."""
    capstone = _dynamic_boundary_attr_8616(block, "capstone", None)
    wrappers: tuple[object, ...] = tuple(_dynamic_boundary_attr_8616(capstone, "insns", ()) or ())
    if not wrappers:
        return False, None
    terminal = _dynamic_boundary_attr_8616(wrappers[-1], "insn", wrappers[-1])
    terminal_addr = _dynamic_boundary_attr_8616(terminal, "address", None)
    terminal_size = _dynamic_boundary_attr_8616(terminal, "size", None)
    mnemonic = str(_dynamic_boundary_attr_8616(terminal, "mnemonic", "") or "").strip().lower()
    if (
        not isinstance(terminal_addr, int)
        or not isinstance(terminal_size, int)
        or terminal_size <= 0
        or (
            mnemonic not in JCC_TO_COND_8616
            and _direct_counter_condition_op_8616(mnemonic) is None
        )
    ):
        return True, None
    operands = tuple(_dynamic_boundary_attr_8616(terminal, "operands", ()) or ())
    target: int | None
    if mnemonic != "loop" and _direct_counter_condition_op_8616(mnemonic) is not None:
        target = terminal_addr
    else:
        target = _dynamic_boundary_attr_8616(operands[-1], "imm", None) if operands else None
    return True, _ConditionBlockOwner8616(
        block_addr=block_addr,
        terminal_insn=terminal_addr,
        mnemonic=mnemonic,
        taken_target=target if isinstance(target, int) else None,
        fallthrough_target=terminal_addr + terminal_size,
    )


def _condition_only_block_addrs_8616(blocks: tuple[object, ...]) -> set[int]:
    """Collect blocks whose decoded instruction stream is condition-only."""
    condition_only_blocks: set[int] = set()
    for block in blocks:
        block_addr = _dynamic_boundary_attr_8616(block, "addr", None)
        capstone = _dynamic_boundary_attr_8616(block, "capstone", None)
        wrappers = tuple(_dynamic_boundary_attr_8616(capstone, "insns", ()) or ())
        if not isinstance(block_addr, int) or not wrappers:
            continue
        mnemonics = tuple(
            str(
                _dynamic_boundary_attr_8616(
                    _dynamic_boundary_attr_8616(wrapper, "insn", wrapper),
                    "mnemonic",
                    "",
                )
                or ""
            ).strip().lower()
            for wrapper in wrappers
        )
        if _mnemonics_are_condition_only_8616(mnemonics):
            condition_only_blocks.add(block_addr)
    return condition_only_blocks


def _mnemonics_are_condition_only_8616(mnemonics: tuple[str, ...]) -> bool:
    """True when a block's mnemonics form a pure compare/branch sequence."""
    return (
        all(
            item in JCC_TO_COND_8616 or _direct_counter_condition_op_8616(item) is not None
            for item in mnemonics
        )
        or (
            len(mnemonics) >= 2
            and mnemonics[-1] in JCC_TO_COND_8616
            and mnemonics[-2] == "cmp"
            and all(item == "cmp" or item in JCC_TO_COND_8616 for item in mnemonics)
        )
        or (
            len(mnemonics) == 2
            and mnemonics[0] == "dec"
            and mnemonics[1] in JCC_TO_COND_8616
        )
    )


def _graph_predecessors_by_block_8616(graph: Any) -> dict[int, frozenset[int]]:  # noqa: ANN401
    """Build the predecessor map from a networkx-style block graph."""
    predecessors_by_block: dict[int, frozenset[int]] = {}
    try:
        graph_nodes = tuple(graph.nodes())
    except (AttributeError, TypeError):
        graph_nodes = ()
    for node in graph_nodes:
        node_addr = node if isinstance(node, int) else _dynamic_boundary_attr_8616(node, "addr", None)
        if not isinstance(node_addr, int):
            continue
        try:
            predecessor_nodes = tuple(graph.predecessors(node))
        except (AttributeError, TypeError):
            continue
        predecessor_addrs = frozenset(
            predecessor_addr
            for predecessor in predecessor_nodes
            if isinstance(
                predecessor_addr := (
                    predecessor
                    if isinstance(predecessor, int)
                    else _dynamic_boundary_attr_8616(predecessor, "addr", None)
                ),
                int,
            )
        )
        predecessors_by_block[node_addr] = predecessor_addrs
    return predecessors_by_block


def _expected_condition_op_for_owner_8616(
    cond: ConditionIR,
    owner: _ConditionBlockOwner8616,
) -> str | None:
    """Return the condition operator implied by the current decoded JCC."""
    direct = _direct_counter_condition_op_8616(owner.mnemonic)
    if direct is not None:
        return direct
    expected = typing.cast(str | None, JCC_TO_COND_8616.get(owner.mnemonic))
    if expected is None:
        return None
    # Alias may normalize a result test into an input comparison while keeping
    # its original producer provenance. Check the current typed operator.
    if not cond.is_zero_test:
        return expected
    if expected == "eq":
        return "zero"
    if expected == "ne":
        return "nonzero"
    return None


def _condition_matches_current_owner_8616(
    cond: ConditionIR,
    owner: _ConditionBlockOwner8616,
) -> bool:
    """Return whether one cached condition belongs to the current block decode."""
    if cond.block_addr != owner.block_addr or cond.src_insn != owner.terminal_insn:
        return False
    if cond.op != _expected_condition_op_for_owner_8616(cond, owner):
        return False
    if owner.taken_target is not None and cond.taken_target != owner.taken_target:
        return False
    return owner.fallthrough_target is None or cond.fallthrough_target == owner.fallthrough_target


def _filter_conditions_to_current_function_8616(
    conditions: list[ConditionIR],
    ownership: _ConditionFunctionOwnership8616,
) -> tuple[list[ConditionIR], _ConditionOwnershipStats8616]:
    """Retain conditions proven to match the current function's decoded blocks."""
    carrier_resolution = normalize_condition_register_carriers_8616(conditions)
    resolution = resolve_condition_fact_conflicts_8616(carrier_resolution.conditions)
    liveness_resolution = normalize_condition_register_liveness_8616(
        resolution.conditions,
        ownership.register_topology,
    )
    if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
        log.warning(
            "[condition-transfer] register-liveness topology=%s stats=%s",
            ownership.register_topology.predecessors_by_block,
            liveness_resolution.stats,
        )
        log.warning(
            "[condition-transfer] register-liveness conditions=%s",
            tuple(
                (
                    condition.block_addr,
                    condition.src_insn,
                    condition.lhs.space.value if isinstance(condition.lhs, IRValue) else type(condition.lhs).__name__,
                    condition.lhs.offset if isinstance(condition.lhs, IRValue) else None,
                    condition.rhs.space.value if isinstance(condition.rhs, IRValue) else type(condition.rhs).__name__,
                    condition.rhs.offset if isinstance(condition.rhs, IRValue) else None,
                )
                for condition in liveness_resolution.conditions
            ),
        )
    normalized = list(liveness_resolution.conditions)
    if not ownership.decoded_block_addrs:
        return normalized, _ConditionOwnershipStats8616(
            raw_fact_count=len(conditions),
            normalized_fact_count=len(normalized),
            classified_fact_count=0,
            materialized_count=len(normalized),
            failure_count=(
                resolution.failure_count
                + carrier_resolution.stats.failure_count
                + liveness_resolution.stats.failure_count
            ),
        )

    retained: list[ConditionIR] = []
    classified = 0
    failures = (
        resolution.failure_count
        + carrier_resolution.stats.failure_count
        + liveness_resolution.stats.failure_count
    )
    for cond in normalized:
        block_addr = cond.block_addr
        if not isinstance(block_addr, int) or block_addr not in ownership.decoded_block_addrs:
            failures += 1
            continue
        owner = ownership.conditional_owners.get(block_addr)
        if owner is None:
            failures += 1
            continue
        if not _condition_matches_current_owner_8616(cond, owner):
            failures += 1
            continue
        classified += 1
        retained.append(cond)

    return retained, _ConditionOwnershipStats8616(
        raw_fact_count=len(conditions),
        normalized_fact_count=len(normalized),
        classified_fact_count=classified,
        materialized_count=len(retained),
        failure_count=failures,
    )


def _decode_first_insn_at_addr_8616(project: object, addr: int) -> object | None:
    factory = _dynamic_boundary_attr_8616(project, "factory", None) if project is not None else None
    block_lifter = _dynamic_boundary_attr_8616(factory, "block", None)
    if not callable(block_lifter):
        return None

    block = None
    for kwargs in ({"num_inst": 1, "opt_level": 0}, {"size": 2, "opt_level": 0}, {"opt_level": 0}, {}):
        try:
            block = block_lifter(addr, **kwargs)
            break
        except TypeError:
            continue
        except Exception:
            return None
    if block is None:
        return None
    capstone = _dynamic_boundary_attr_8616(block, "capstone", None)
    insns = tuple(_dynamic_boundary_attr_8616(capstone, "insns", ()) or ())
    if not insns:
        return None
    return typing.cast(object, insns[0])


def _condition_from_pending_source_8616(
    source: ConditionSource,
    jcc_mnemonic: str,
    *,
    src_insn: int,
    block_addr: int,
) -> ConditionIR | None:
    if source.kind == "cmp":
        lhs = source.lhs
        rhs = source.rhs
        if source.normalized_lhs is not None and source.normalized_rhs is not None:
            lhs = source.normalized_lhs
            rhs = source.normalized_rhs
        if lhs is None or rhs is None:
            return None
        cond = build_condition_from_cmp_8616(
            lhs,
            rhs,
            jcc_mnemonic,
            width_bits=source.width_bits,
            src_insn=src_insn,
            block_addr=block_addr,
            producer_insn=source.addr,
            producer_semantics=source.semantics,
            register_bindings=source.register_bindings,
        )
    elif source.kind == "test":
        lhs = source.normalized_lhs if source.normalized_lhs is not None else source.lhs
        if lhs is None:
            return None
        cond = build_condition_from_test_8616(
            lhs,
            jcc_mnemonic,
            width_bits=source.width_bits,
            src_insn=src_insn,
            block_addr=block_addr,
            producer_insn=source.addr,
            operand_bind_insn=src_insn if source.bind_operand_at_jcc else None,
            producer_semantics=source.semantics,
            register_bindings=source.register_bindings,
        )
    else:
        return None
    return cond if isinstance(cond, ConditionIR) else None


def _normalized_cmp_semantics_from_source_8616(source: ConditionSource) -> tuple[object, ...] | None:
    """Return source-level comparison semantics when affine lifting proved it."""
    raw_semantics = source.semantics
    if isinstance(raw_semantics, tuple) and raw_semantics and raw_semantics[0] == "dec_reg16":
        return None
    lhs = source.normalized_lhs
    rhs = source.normalized_rhs
    if not isinstance(lhs, IRValue) or not isinstance(rhs, IRValue):
        return None
    if lhs.space != MemSpace.REG or rhs.space != MemSpace.CONST:
        return None
    if not isinstance(lhs.name, str) or not isinstance(rhs.const, int):
        return None
    return ("normalized_cmp_reg_imm16", lhs.name.lower(), int(rhs.const))


def _edge_evidence_from_pending_source_8616(
    source: ConditionSource,
    mnemonic: str | None,
    *,
    edge_block_addr: int,
) -> ConditionEdgeEvidence | None:
    if mnemonic not in {"jmp", "jmpw"}:
        return None
    source_jcc = str(source.fallthrough_from_jcc or "").lower()
    inverted_jcc = _INVERTED_JCC_MNEMONICS_8616.get(source_jcc)
    if inverted_jcc is None:
        return None
    condition = _condition_from_pending_source_8616(source, inverted_jcc, src_insn=edge_block_addr, block_addr=edge_block_addr)
    if condition is None:
        return None
    producer_semantics = source.semantics
    normalized_semantics = _normalized_cmp_semantics_from_source_8616(source)
    if normalized_semantics is not None:
        producer_semantics = (*normalized_semantics, producer_semantics)
    return ConditionEdgeEvidence(
        edge_block_addr=edge_block_addr,
        condition=condition,
        edge_kind="fallthrough_jmp",
        source_jcc=source_jcc,
        producer_insn=source.addr,
        producer_semantics=producer_semantics,
    )


def _collect_pending_fallthrough_conditions_8616(
    project: object,
    block_addrs: list[int],
    pending_sources: dict[int, ConditionSource],
) -> tuple[list[ConditionIR], list[ConditionEdgeEvidence]]:
    """Materialize cached fallthrough JCC facts missed by block lift order.

    The lifter owns operand recovery and records ConditionSource objects.  This
    bridge only proves that a pending function block begins with a supported JCC
    instruction, then converts that already-typed source into ConditionIR. Pending
    sources are single-consumer lifter state; later transfers replay the typed
    evidence already attached to the active codegen contract.
    """
    block_addr_set = set(block_addrs)
    conditions: list[ConditionIR] = []
    edge_evidence: list[ConditionEdgeEvidence] = []
    processed: set[int] = set()
    while True:
        candidates = sorted(
            addr
            for addr, source in pending_sources.items()
            if addr in block_addr_set and addr not in processed and isinstance(source, ConditionSource)
        )
        if not candidates:
            break
        for addr in candidates:
            processed.add(addr)
            _process_pending_fallthrough_source_8616(
                project, pending_sources, addr, conditions, edge_evidence
            )
    return conditions, edge_evidence



def _process_pending_fallthrough_source_8616(
    project: object,
    pending_sources: dict[int, ConditionSource],
    addr: int,
    conditions: list[ConditionIR],
    edge_evidence: list[ConditionEdgeEvidence],
) -> None:
    """Convert one pending lifter source into typed condition evidence."""
    source = pending_sources.get(addr)
    if not isinstance(source, ConditionSource):
        pending_sources.pop(addr, None)
        return
    insn = _decode_first_insn_at_addr_8616(project, addr)
    mnemonic = str(_dynamic_boundary_attr_8616(insn, "mnemonic", "") or "").strip().lower() if insn is not None else None
    pending_sources.pop(addr, None)
    if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
        log.warning(
            "[condition-transfer] pending_decode addr=%#x mnemonic=%r source_kind=%s",
            addr,
            mnemonic,
            source.kind,
        )
    if not isinstance(mnemonic, str) or mnemonic not in JCC_TO_COND_8616:
        edge = _edge_evidence_from_pending_source_8616(source, mnemonic, edge_block_addr=addr)
        if edge is not None:
            edge_evidence.append(edge)
            if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
                log.warning(
                    "[condition-transfer] edge pending src_insn=%#x block=%#x op=%s source_jcc=%s lhs=%r rhs=%r",
                    addr,
                    edge.edge_block_addr,
                    edge.condition.op,
                    edge.source_jcc,
                    edge.condition.lhs,
                    edge.condition.rhs,
                )
        return
    cond = _condition_from_pending_source_8616(source, mnemonic, src_insn=addr, block_addr=addr)
    if isinstance(cond, ConditionIR):
        conditions.append(cond)
        if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
            log.warning(
                "[condition-transfer] cond pending src_insn=%#x block=%#x op=%s source=%s lhs=%r rhs=%r",
                addr,
                addr,
                cond.op,
                cond.source,
                cond.lhs,
                cond.rhs,
            )


def _collect_typed_condition_artifacts_8616(
    project: object,
    func_addr: int,
    *,
    function: object | None = None,
) -> tuple[
    list[ConditionIR],
    list[ConditionEdgeEvidence],
    _ConditionOwnershipStats8616,
    ConditionCacheReliftStats8616 | None,
]:
    def _impl() -> tuple[
        list[ConditionIR],
        list[ConditionEdgeEvidence],
        _ConditionOwnershipStats8616,
        ConditionCacheReliftStats8616 | None,
    ]:
        """Collect function-owned ConditionIR objects from exact lifted bytes.

        The lifter's module cache is keyed only by rebased block address, so it
        cannot prove ownership when separate extracted functions share addresses.
        Real projects therefore use an isolated relift artifact; the ambient
        cache remains only for synthetic fixtures without loader bytes.

        Returns a deduplicated, deterministically sorted list of ConditionIR.
        """
        kb = _dynamic_boundary_attr_8616(project, "kb", None) if project is not None else None
        if kb is None:
            return [], [], _ConditionOwnershipStats8616(0, 0, 0, 0, 0), None

        func = function or kb.functions.function(addr=func_addr, create=False)
        if func is None:
            return [], [], _ConditionOwnershipStats8616(0, 0, 0, 0, 0), None

        block_addrs = sorted(_dynamic_boundary_attr_8616(func, "block_addrs_set", set()) or set())
        if not block_addrs:
            return [], [], _ConditionOwnershipStats8616(0, 0, 0, 0, 0), None
        ownership = _current_function_condition_ownership_8616(func)

        # Seed loader-less fixtures from the ambient lifter compatibility cache.
        module_cache, pending_sources, lifter_available = _seed_lifter_condition_caches_8616()
        condition_block_addrs = sorted(ownership.conditional_owners) or block_addrs

        relift_artifact, relift_stats = _resolve_condition_relift_artifact_8616(
            project, func_addr, ownership, condition_block_addrs
        )
        if relift_artifact is not None:
            module_cache = relift_artifact.condition_cache()
            pending_sources = relift_artifact.pending_source_cache()
        elif any(
            not has_typed_condition_cache_evidence_8616(module_cache, pending_sources, block_addr)
            for block_addr in condition_block_addrs
        ):
            if lifter_available:
                reset_lifter_condition_state_8616()
            relift_cached_project_blocks_8616(project, tuple(block_addrs))
        _debug_condition_transfer_cache_8616(func_addr, block_addrs, module_cache, pending_sources)

        all_conditions = _cached_block_conditions_8616(block_addrs, module_cache)
        edge_evidence: list[ConditionEdgeEvidence] = []
        if isinstance(pending_sources, dict):
            pending_conditions, pending_edges = _collect_pending_fallthrough_conditions_8616(
                project, block_addrs, pending_sources
            )
            all_conditions.extend(pending_conditions)
            edge_evidence.extend(pending_edges)

        conditions, ownership_stats = _bind_and_filter_conditions_8616(
            func, all_conditions, ownership, relift_stats
        )
        return conditions, edge_evidence, ownership_stats, relift_stats

    return _impl()



def _seed_lifter_condition_caches_8616() -> tuple[
    typing.Mapping[int, typing.Sequence[ConditionResult]],
    typing.Mapping[int, ConditionSource] | dict[int, ConditionSource],
    bool,
]:
    """Read the ambient lifter caches, tolerating absent lifter imports."""
    try:
        from ..lift_86_16 import Instruction_ANY

        return (
            Instruction_ANY._inertia_module_condition_cache,
            Instruction_ANY._inertia_pending_condition_sources_by_addr,
            True,
        )
    except Exception as ex:
        import logging

        logging.getLogger(__name__).warning(
            "condition transfer import failed: %s: %s",
            type(ex).__name__,
            ex,
        )
        return {}, {}, False


def _resolve_condition_relift_artifact_8616(
    project: object,
    func_addr: int,
    ownership: _ConditionFunctionOwnership8616,
    condition_block_addrs: list[int],
) -> tuple[Any | None, ConditionCacheReliftStats8616 | None]:
    """Pick the proven registered artifact or relift the condition cache."""
    registered = registered_function_ssa_artifact_8616(project, func_addr)
    registered_condition_evidence = (
        registered.artifact.condition_evidence
        if registered.verdict is FunctionSSAArtifactVerdict8616.PROVEN
        and registered.artifact is not None
        else None
    )
    relift_artifact = (
        registered_condition_evidence.source
        if registered_condition_evidence is not None
        and registered_condition_evidence.complete
        and registered_condition_evidence.function_addr == func_addr
        and registered_condition_evidence.block_ranges == ownership.relift_blocks
        and registered_condition_evidence.expected_condition_blocks
        == tuple(condition_block_addrs)
        else relift_function_condition_cache_8616(
            project,
            ownership.relift_blocks,
            frozenset(condition_block_addrs),
        )
    )
    if relift_artifact is None:
        return None, None
    return relift_artifact, relift_artifact.stats


def _debug_condition_transfer_cache_8616(
    func_addr: int,
    block_addrs: list[int],
    module_cache: typing.Mapping[int, typing.Sequence[ConditionResult]],
    pending_sources: typing.Mapping[int, ConditionSource] | dict[int, ConditionSource],
) -> None:
    """Emit the optional cache-key diagnostic for condition transfer."""
    if not os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
        return
    cache_keys = tuple(sorted(k for k in module_cache if isinstance(k, int)))
    pending_keys = tuple(sorted(k for k in pending_sources if isinstance(k, int)))
    log.warning(
        "[condition-transfer] func=%#x blocks=%s cache_keys=%s pending_keys=%s",
        func_addr,
        tuple(hex(a) for a in block_addrs),
        tuple(hex(a) for a in cache_keys),
        tuple(hex(a) for a in pending_keys),
    )


def _cached_block_conditions_8616(
    block_addrs: list[int],
    module_cache: typing.Mapping[int, typing.Sequence[ConditionResult]],
) -> list[ConditionIR]:
    """Flatten cached ConditionIR entries across the function's blocks."""
    all_conditions: list[ConditionIR] = []
    for block_addr in block_addrs:
        block_conds = module_cache.get(block_addr, None)
        if isinstance(block_conds, list):
            for cond in block_conds:
                if isinstance(cond, ConditionIR):
                    all_conditions.append(cond)
                    if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
                        log.warning(
                            "[condition-transfer] cond cache_block=%#x src_insn=%r block=%r "
                            "taken=%r fallthrough=%r op=%s source=%s lhs=%r rhs=%r",
                            block_addr,
                            cond.src_insn,
                            cond.block_addr,
                            cond.taken_target,
                            cond.fallthrough_target,
                            cond.op,
                            cond.source,
                            cond.lhs,
                            cond.rhs,
                        )
    return all_conditions


def _bind_and_filter_conditions_8616(
    func: object,
    all_conditions: list[ConditionIR],
    ownership: _ConditionFunctionOwnership8616,
    relift_stats: ConditionCacheReliftStats8616 | None,
) -> tuple[list[ConditionIR], _ConditionOwnershipStats8616]:
    """Bind register sources, filter to function ownership, merge failures."""
    binding_resolution = bind_condition_register_sources_8616(func, all_conditions)
    conditions, ownership_stats = _filter_conditions_to_current_function_8616(
        list(binding_resolution.conditions), ownership
    )
    ownership_stats = replace(
        ownership_stats,
        failure_count=(
            ownership_stats.failure_count
            + binding_resolution.stats.failure_count
        ),
    )
    if relift_stats is not None and relift_stats.failure_count:
        ownership_stats = replace(
            ownership_stats,
            failure_count=ownership_stats.failure_count + relift_stats.failure_count,
        )
    if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
        log.warning("[condition-transfer] source-bindings=%s", binding_resolution.stats)
        log.warning("[condition-transfer] ownership=%s", ownership_stats)
    return conditions, ownership_stats

def collect_typed_conditions_from_emulator_8616(
    project: object,
    func_addr: int,
) -> list[ConditionIR]:
    """Collect ConditionIR objects from the module-level lifter cache."""
    conditions, _edge_evidence, _ownership_stats, _relift_stats = _collect_typed_condition_artifacts_8616(
        project, func_addr
    )
    return conditions


def collect_typed_condition_artifacts_8616(
    project: object,
    func_addr: int,
    *,
    function: object | None = None,
) -> tuple[list[ConditionIR], list[ConditionEdgeEvidence]]:
    """Collect typed conditions for an exact boundary or the project function."""
    conditions, edge_evidence, _ownership_stats, _relift_stats = _collect_typed_condition_artifacts_8616(
        project,
        func_addr,
        function=function,
    )
    return conditions, edge_evidence


def transfer_typed_conditions_from_emulator_8616(
    instructions: list[object],
    codegen: object,
) -> int:
    """Transfer typed conditions from lifted instruction emulators to codegen.

    After block lifting, each instruction's emulator may have
    _inertia_typed_conditions recorded.  This function aggregates them
    and sets codegen._inertia_typed_conditions.

    Returns the number of ConditionIR objects transferred.
    """
    all_conditions: list[ConditionIR] = []
    for instr in instructions:
        emu = _dynamic_boundary_attr_8616(instr, "emu", None)
        if emu is not None:
            conds = _dynamic_boundary_attr_8616(emu, "_inertia_typed_conditions", None)
            if isinstance(conds, list):
                for cond in conds:
                    if isinstance(cond, ConditionIR):
                        all_conditions.append(cond)

    unique = deduplicate_conditions_8616(all_conditions)
    typing.cast(typing.Any, codegen)._inertia_typed_conditions = unique
    typing.cast(typing.Any, codegen)._inertia_condition_facts = unique  # compatibility alias
    return len(unique)


def transfer_typed_conditions_to_codegen_8616(
    project: object,
    func_addr: int,
    codegen: object,
) -> int:
    """Full pipeline: collect conditions by re-lifting, then transfer to codegen.

    Sets:
        codegen._inertia_typed_conditions
        codegen._inertia_condition_facts
        codegen._inertia_condition_lane (SemanticLaneState for CONDITION lane)

    Returns the number of ConditionIR objects transferred.
    """
    from ..pipeline.contracts import SemanticLaneState

    conditions, edge_evidence, ownership_stats, relift_stats = _collect_typed_condition_artifacts_8616(
        project, func_addr
    )
    existing_edge_evidence = _dynamic_boundary_attr_8616(codegen, "_inertia_condition_edge_evidence", None)
    if not edge_evidence and isinstance(existing_edge_evidence, (list, tuple)) and existing_edge_evidence:
        edge_evidence = list(existing_edge_evidence)
    typing.cast(typing.Any, codegen)._inertia_typed_conditions = conditions
    typing.cast(typing.Any, codegen)._inertia_condition_facts = conditions  # compatibility alias
    typing.cast(typing.Any, codegen)._inertia_condition_edge_evidence = edge_evidence
    typing.cast(typing.Any, codegen)._inertia_condition_ownership_stats = ownership_stats
    typing.cast(typing.Any, codegen)._inertia_condition_cache_relift_stats_8616 = relift_stats
    record_classified_conditions_trace_8616(project, codegen, conditions)

    # ── Initialize CONDITION lane contract ──
    # classified is filled by consumers once a fact is matched to an AST guard.
    # Transfer owns raw/normalized evidence only; claiming classification here
    # would hard-fail functions whose conditions are collected but not yet
    # consumed by a materializer.
    # materialized = 0 (filled by postprocess typed conditions pass)
    typing.cast(typing.Any, codegen)._inertia_condition_lane = SemanticLaneState(
            name="condition",
            raw=len(conditions),  # raw facts = all ConditionIR from lifting
            normalized=len(conditions),
            classified=0,
            bound=0,
            materialized=0,
            verified=0,
            failures=0,
        )

    return len(conditions)
