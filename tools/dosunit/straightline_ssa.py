from __future__ import annotations  # noqa: D100

import copy
import functools
import hashlib
import os
import pickle
import re
import signal
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from tools.dosunit.data_compare import load_mz_image
from tools.dosunit.ir_edges import _load_lifter_project
from tools.dosunit.model import DosUnitError, canonical_json_bytes, normalize_hex, parse_int, stable_id

REG_BY_OFFSET = {
    0: ("ax", 16),
    4: ("cx", 16),
    8: ("dx", 16),
    12: ("bx", 16),
    16: ("sp", 16),
    20: ("bp", 16),
    24: ("si", 16),
    28: ("di", 16),
    32: ("ip", 16),
    36: ("flags", 16),
    40: ("cs", 16),
    42: ("ds", 16),
    44: ("es", 16),
    46: ("fs", 16),
    48: ("gs", 16),
    50: ("ss", 16),
    52: ("dflag", 32),
}
REG32_BY_OFFSET = {
    0: ("eax_hi", "ax"),
    4: ("ecx_hi", "cx"),
    8: ("edx_hi", "dx"),
    12: ("ebx_hi", "bx"),
    16: ("esp_hi", "sp"),
    20: ("ebp_hi", "bp"),
    24: ("esi_hi", "si"),
    28: ("edi_hi", "di"),
}
REG32_HI16_BY_OFFSET = {
    2: "eax_hi",
    6: "ecx_hi",
    10: "edx_hi",
    14: "ebx_hi",
    18: "esp_hi",
    22: "ebp_hi",
    26: "esi_hi",
    30: "edi_hi",
}
RAW_OUTPUT_REGS = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")
ABI_OUTPUT_REGS = {
    "msc16-near": ("ax", "dx", "sp"),
    "raw-all": RAW_OUTPUT_REGS,
}
DEFAULT_ABI = "msc16-near"
DEFAULT_OUTPUT_REGS = ABI_OUTPUT_REGS[DEFAULT_ABI]
SUPPORTED_SOURCE_IRS = {"vex", "ail"}
LIFTER_CACHE_SCHEMA = "dosunit.lifter_cache.v4"
CALL_TARGET_PREVIEW_INSTRUCTION_LIMIT = 4
BINARY_CALL_TARGET_SIGNATURE_BYTES = 32
CONTROL_MNEMONICS = {
    "call",
    "lcall",
    "int",
    "jmp",
    "ljmp",
    "jo",
    "jno",
    "jb",
    "jnae",
    "jc",
    "jnb",
    "jae",
    "jnc",
    "je",
    "jz",
    "jne",
    "jnz",
    "jbe",
    "jna",
    "ja",
    "jnbe",
    "js",
    "jns",
    "jp",
    "jpe",
    "jnp",
    "jpo",
    "jl",
    "jnge",
    "jge",
    "jnl",
    "jle",
    "jng",
    "jg",
    "jnle",
    "jcxz",
    "loop",
    "loope",
    "loopne",
    "loopz",
    "loopnz",
}
CONDITIONAL_JUMP_MNEMONICS = CONTROL_MNEMONICS - {"call", "lcall", "int", "jmp", "ljmp"}
CONNECTIVITY_IMPLICIT_STATE = {
    "cs",
    "ds",
    "es",
    "ss",
    "flags",
    "mem",
    "memory",
}
CONNECTIVITY_OPTIONALLY_IMPLICIT_STATE = {
    "bp",
}
SUPPORTED_BINOPS = {
    "Add": "add",
    "Sub": "sub",
    "Mul": "mul",
    "MullU": "umull",
    "MullS": "smull",
    "DivU": "udiv",
    "DivS": "sdiv",
    "Mod": "urem",
    "ModU": "urem",
    "ModS": "srem",
    "And": "and",
    "Or": "or",
    "Xor": "xor",
    "Shl": "shl",
    "Shr": "lshr",
    "Sar": "ashr",
    "CmpEQ": "eq",
    "CmpNE": "ne",
    "CmpLTU": "ult",
    "CmpLEU": "ule",
    "CmpGTU": "ugt",
    "CmpGEU": "uge",
    "CmpLTS": "slt",
    "CmpLES": "sle",
    "CmpGTS": "sgt",
    "CmpGES": "sge",
}


@dataclass(frozen=True)
class SsaExpr:  # noqa: D101
    op: str
    width: int
    args: tuple[SsaExpr, ...] = ()
    value: int | None = None
    name: str | None = None

    def key(self) -> tuple[Any, ...]:  # noqa: D102
        return (self.op, self.width, self.value, self.name, tuple(arg.key() for arg in self.args))


@dataclass(frozen=True)
class LowerFailure(Exception):  # noqa: D101
    reason: str
    message: str


@dataclass
class _VexDeps:
    temps: set[int]
    regs: set[str]
    memory: bool = False

    def update(self, other: _VexDeps) -> None:
        self.temps.update(other.temps)
        self.regs.update(other.regs)
        self.memory = self.memory or other.memory


@dataclass(frozen=True)
class LiftedBlock:  # noqa: D101
    irsb: Any
    instructions: list[dict[str, Any]]
    lifted: bool


def lower_straightline_ssa_document(  # noqa: D103
    *,
    exe_path: Path,
    functions_catalog: dict[str, Any],
    output_regs: tuple[str, ...] = DEFAULT_OUTPUT_REGS,
    source_ir: str = "vex",
    max_blocks_per_function: int = 64,
    max_insns_per_function: int = 64,
    max_assignments_per_function: int = 512,
    scan_limit: int = 0x100,
    cache_dir: Path | None = None,
    follow_call_fallthrough: bool = True,
    max_lift_block_ms: int = 10000,
    max_function_ms: int = 60000,
) -> dict[str, Any]:
    if source_ir not in SUPPORTED_SOURCE_IRS:
        raise DosUnitError(f"unsupported SSA source IR: {source_ir}")
    functions = list(functions_catalog.get("functions", []) or [])
    segment_paragraphs = _catalog_segment_paragraphs(functions_catalog)
    project = _load_lifter_project(exe_path)
    linked_base = int(getattr(project.loader.main_object, "linked_base", 0))
    exe_digest = _file_sha256(exe_path)
    cache_document = _load_vex_cache(cache_dir=cache_dir, exe_digest=exe_digest) if cache_dir is not None else None
    cache_stats = {"hits": 0, "misses": 0, "writes": 0, "errors": 0}
    lowered: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    counters = {
        "functions_seen": len(functions),
        "functions_attempted": 0,
        "functions_lowered": 0,
        "functions_refused": 0,
        "ssa_parts_lowered": 0,
        "ssa_parts_refused": 0,
        "lifter_blocks_lifted": 0,
        "lifter_cache_hits": 0,
        "lifter_cache_misses": 0,
        "lifter_cache_writes": 0,
        "lifter_cache_errors": 0,
        "assignments_emitted": 0,
        "refusals_by_reason": {},
    }

    for function in functions:
        counters["functions_attempted"] += 1
        try:
            with _timeout_alarm(max_function_ms, message=f"SSA function lowering exceeded timeout for {function.get('id', '<unknown>')}"):
                results, function_refusals, blocks_lifted = _lower_function(
                    project=project,
                    linked_base=linked_base,
                    exe_path=exe_path,
                    exe_digest=exe_digest,
                    cache_document=cache_document,
                    cache_stats=cache_stats,
                    function=function,
                    segment_paragraphs=segment_paragraphs,
                    output_regs=output_regs,
                    source_ir=source_ir,
                    max_blocks_per_function=max_blocks_per_function,
                    max_insns_per_function=max_insns_per_function,
                    max_assignments_per_function=max_assignments_per_function,
                    scan_limit=scan_limit,
                    follow_call_fallthrough=follow_call_fallthrough,
                    max_lift_block_ms=max_lift_block_ms,
                )
        except TimeoutError as ex:
            results = []
            function_refusals = [_refusal(function, "timeout", f"{ex} after {max_function_ms} ms")]
            blocks_lifted = 0
        counters["lifter_blocks_lifted"] += blocks_lifted
        if not results:
            counters["functions_refused"] += 1
            if function_refusals:
                refusals.extend(function_refusals)
            else:
                refusals.append(_refusal(function, "unsupported_ir", "lowering failed without detail"))
        else:
            counters["functions_lowered"] += 1
            lowered.extend(results)
            counters["ssa_parts_lowered"] += len(results)
            counters["assignments_emitted"] += sum(len(result.get("assignments", []) or []) for result in results)
            if function_refusals:
                refusals.extend(function_refusals)
        counters["ssa_parts_refused"] += len(function_refusals)

    if cache_dir is not None and cache_document is not None and cache_document.pop("_dirty", False):
        try:
            _save_vex_cache(cache_dir=cache_dir, exe_digest=exe_digest, cache_document=cache_document)
        except Exception:
            cache_stats["errors"] += 1

    counters["lifter_cache_hits"] = cache_stats["hits"]
    counters["lifter_cache_misses"] = cache_stats["misses"]
    counters["lifter_cache_writes"] = cache_stats["writes"]
    counters["lifter_cache_errors"] = cache_stats["errors"]
    counters["refusals_by_reason"] = _refusal_counts(refusals)
    document_without_id = {
        "schema": "dosunit.ssa.v1",
        "exe": str(exe_path),
        "source_ir": source_ir,
        "module": str(functions_catalog.get("module", exe_path.name)),
        "parameters": {
            "output_regs": list(output_regs),
            "source_ir": source_ir,
            "max_blocks_per_function": max_blocks_per_function,
            "max_insns_per_function": max_insns_per_function,
            "max_assignments_per_function": max_assignments_per_function,
            "scan_limit": scan_limit,
            "cache_dir": None if cache_dir is None else str(cache_dir),
            "follow_call_fallthrough": follow_call_fallthrough,
        },
        "functions": lowered,
        "refusals": refusals,
        "counters": counters,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("ssa", document_without_id)
    return document


@dataclass(frozen=True)
class _SsaCandidateTables:
    """Lookup tables indexed from the candidate SSA functions."""

    by_key: dict[Any, Any]
    by_id: dict[Any, Any]
    by_key_delta: dict[Any, Any]
    by_id_delta: dict[Any, Any]
    by_key_exact_signature: dict[Any, Any]
    by_id_exact_signature: dict[Any, Any]
    by_key_signature: dict[Any, Any]
    by_id_signature: dict[Any, Any]
    all_by_key_delta: dict[Any, Any]
    all_by_id_delta: dict[Any, Any]
    all_by_key: dict[Any, Any]
    all_by_id: dict[Any, Any]
    all_by_key_exact_signature: dict[Any, Any]
    all_by_id_exact_signature: dict[Any, Any]
    all_by_key_signature: dict[Any, Any]
    all_by_id_signature: dict[Any, Any]


def _build_ssa_candidate_tables(
    candidate_functions: list[dict[str, Any]],
    candidate_functions_all: list[dict[str, Any]],
) -> _SsaCandidateTables:
    """Index candidate functions by name/id and each part discriminator."""
    return _SsaCandidateTables(
        by_key=_functions_by_name_and_part(candidate_functions),
        by_id=_functions_by_id_and_part(candidate_functions),
        by_key_delta=_functions_by_name_and_delta(candidate_functions),
        by_id_delta=_functions_by_id_and_delta(candidate_functions),
        by_key_exact_signature=_functions_by_name_and_exact_block_signature(candidate_functions),
        by_id_exact_signature=_functions_by_id_and_exact_block_signature(candidate_functions),
        by_key_signature=_functions_by_name_and_block_signature(candidate_functions),
        by_id_signature=_functions_by_id_and_block_signature(candidate_functions),
        all_by_key_delta=_functions_by_name_and_delta(candidate_functions_all),
        all_by_id_delta=_functions_by_id_and_delta(candidate_functions_all),
        all_by_key=_functions_by_name_and_part(candidate_functions_all),
        all_by_id=_functions_by_id_and_part(candidate_functions_all),
        all_by_key_exact_signature=_functions_by_name_and_exact_block_signature(candidate_functions_all),
        all_by_id_exact_signature=_functions_by_id_and_exact_block_signature(candidate_functions_all),
        all_by_key_signature=_functions_by_name_and_block_signature(candidate_functions_all),
        all_by_id_signature=_functions_by_id_and_block_signature(candidate_functions_all),
    )


def _resolve_mapped_candidate_by_id(
    oracle_function: dict[str, Any],
    *,
    mapped: dict[str, Any],
    part_index: int,
    part_delta: str,
    tables: _SsaCandidateTables,
) -> dict[str, Any] | None:
    """Resolve a mapped candidate through candidate_id-keyed tables."""
    candidate_function = None
    exact_signature = _ssa_exact_block_signature(oracle_function)
    exact_candidate = (
        tables.by_id_exact_signature.get((str(mapped.get("candidate_id")), exact_signature))
        if exact_signature is not None
        else None
    )
    if part_delta:
        candidate_function = tables.by_id_delta.get((str(mapped.get("candidate_id")), part_delta))
        # An identical byte stream elsewhere in the mapped function is strictly
        # stronger evidence than a coincidental equal entry offset.
        if candidate_function is not None and exact_candidate is not None and exact_candidate is not candidate_function:
            candidate_function = exact_candidate
    if candidate_function is None:
        candidate_function = exact_candidate
    if candidate_function is None:
        signature = _ssa_block_signature(oracle_function)
        if signature is not None:
            candidate_function = tables.by_id_signature.get((str(mapped.get("candidate_id")), signature))
    if candidate_function is None and not part_delta:
        candidate_function = tables.by_id.get((str(mapped.get("candidate_id")), part_index))
    return candidate_function


def _resolve_mapped_candidate_by_name(
    oracle_function: dict[str, Any],
    *,
    mapped: dict[str, Any],
    part_index: int,
    part_delta: str,
    tables: _SsaCandidateTables,
) -> dict[str, Any] | None:
    """Resolve a mapped candidate through candidate_name-keyed tables."""
    candidate_name = str(mapped.get("candidate_name", ""))
    candidate_function = None
    exact_signature = _ssa_exact_block_signature(oracle_function)
    exact_candidate = (
        tables.by_key_exact_signature.get((candidate_name, exact_signature))
        if exact_signature is not None
        else None
    )
    if part_delta:
        candidate_function = tables.by_key_delta.get((candidate_name, part_delta))
        # An identical byte stream elsewhere in the mapped function is strictly
        # stronger evidence than a coincidental equal entry offset.
        if candidate_function is not None and exact_candidate is not None and exact_candidate is not candidate_function:
            candidate_function = exact_candidate
    if candidate_function is None:
        candidate_function = exact_candidate
    if candidate_function is None:
        signature = _ssa_block_signature(oracle_function)
        if signature is not None:
            candidate_function = tables.by_key_signature.get((candidate_name, signature))
    if candidate_function is None and not part_delta:
        candidate_function = tables.by_key.get((candidate_name, part_index))
    return candidate_function


def _resolve_mapped_candidate(
    oracle_function: dict[str, Any],
    *,
    mapped: dict[str, Any],
    tables: _SsaCandidateTables,
) -> dict[str, Any] | None:
    """Resolve the candidate SSA part for a mapped oracle function."""
    part_index = _ssa_part_index(oracle_function)
    part_delta = _ssa_part_delta(oracle_function)
    candidate_function = _resolve_mapped_candidate_by_id(
        oracle_function, mapped=mapped, part_index=part_index, part_delta=part_delta, tables=tables
    )
    if candidate_function is None:
        candidate_function = _resolve_mapped_candidate_by_name(
            oracle_function, mapped=mapped, part_index=part_index, part_delta=part_delta, tables=tables
        )
    if candidate_function is None:
        candidate_function = _candidate_for_mapped_part_across_body_boundary(
            oracle_function,
            mapped=mapped,
            candidate_by_id_delta=tables.all_by_id_delta,
            candidate_by_key_delta=tables.all_by_key_delta,
            candidate_by_id_part=tables.all_by_id,
            candidate_by_key_part=tables.all_by_key,
            candidate_by_id_exact_signature=tables.all_by_id_exact_signature,
            candidate_by_key_exact_signature=tables.all_by_key_exact_signature,
            candidate_by_id_signature=tables.all_by_id_signature,
            candidate_by_key_signature=tables.all_by_key_signature,
        )
    return candidate_function


def _resolve_keyed_candidate(
    oracle_function: dict[str, Any],
    *,
    function_id: str,
    function_name: str,
    ordinals: dict[str, int],
    tables: _SsaCandidateTables,
) -> dict[str, Any] | None:
    """Resolve the candidate SSA part without a mapping document."""
    function_key = function_name or function_id
    part_index = _ssa_part_index(oracle_function)
    part_delta = _ssa_part_delta(oracle_function)
    candidate_function = None
    exact_signature = _ssa_exact_block_signature(oracle_function)
    exact_candidate = (
        tables.by_key_exact_signature.get((function_key, exact_signature))
        if exact_signature is not None
        else None
    )
    if part_delta:
        candidate_function = tables.by_key_delta.get((function_key, part_delta))
        # An identical byte stream elsewhere in the mapped function is strictly
        # stronger evidence than a coincidental equal entry offset.
        if candidate_function is not None and exact_candidate is not None and exact_candidate is not candidate_function:
            candidate_function = exact_candidate
    if candidate_function is None:
        candidate_function = exact_candidate
    if candidate_function is None:
        signature = _ssa_block_signature(oracle_function)
        if signature is not None:
            candidate_function = tables.by_key_signature.get((function_key, signature))
    if candidate_function is None and not part_delta:
        candidate_function = tables.by_key.get((function_key, part_index))
    if candidate_function is None and not part_delta:
        ordinal = ordinals[function_key]
        ordinals[function_key] += 1
        candidate_function = tables.by_key.get((function_key, ordinal))
    if candidate_function is None:
        candidate_function = _candidate_for_mapped_part_across_body_boundary(
            oracle_function,
            mapped={"candidate_id": function_id, "candidate_name": function_key},
            candidate_by_id_delta=tables.all_by_id_delta,
            candidate_by_key_delta=tables.all_by_key_delta,
            candidate_by_id_part=tables.all_by_id,
            candidate_by_key_part=tables.all_by_key,
            candidate_by_id_exact_signature=tables.all_by_id_exact_signature,
            candidate_by_key_exact_signature=tables.all_by_key_exact_signature,
            candidate_by_id_signature=tables.all_by_id_signature,
            candidate_by_key_signature=tables.all_by_key_signature,
        )
    return candidate_function


def _run_callee_proof_fixpoint(
    results: list[dict[str, Any]],
    pending_callee_proofs: list[tuple[int, dict[str, Any]]],
    *,
    semantic_proof_passes: int,
    mapping_document: dict[str, Any] | None,
    oracle_index: dict[str, Any],
    candidate_index: dict[str, Any],
    allow_aliased_call_targets: bool,
    proof_cache: _SemanticEqualityCache | None,
    timeout_ms: int,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
    skip_binary_equal: bool,
    max_rss_mb: int,
) -> tuple[int, list[tuple[int, dict[str, Any]]]]:
    """Re-run callee-dependent pairs until proofs settle; return solver ms and the still-pending list."""
    solver_time_ms = 0
    for _pass_index in range(max(0, int(semantic_proof_passes) - 1)):
        if not pending_callee_proofs:
            break
        changed = False
        still_pending: list[tuple[int, dict[str, Any]]] = []
        for result_index, item in pending_callee_proofs:
            result, elapsed = _compare_ssa_pair_guarded(
                item,
                mapping_document=mapping_document,
                oracle_index=oracle_index,
                candidate_index=candidate_index,
                allow_aliased_call_targets=allow_aliased_call_targets,
                proof_cache=proof_cache,
                timeout_ms=timeout_ms,
                max_solver_assignments=max_solver_assignments,
                max_solver_inputs=max_solver_inputs,
                max_solver_memory_stores=max_solver_memory_stores,
                skip_binary_equal=skip_binary_equal,
                max_rss_mb=max_rss_mb,
            )
            solver_time_ms += elapsed
            results[result_index] = result
            if result.get("reason") == "callee_not_proven":
                still_pending.append((result_index, item))
                continue
            changed = True
            if result.get("status") == "passed" and proof_cache is not None:
                proof_cache.record(
                    item["oracle_function"], item["candidate_function"], proof=str(result.get("reason") or "z3_equal")
                )
        pending_callee_proofs = still_pending
        if not changed:
            break
    return solver_time_ms, pending_callee_proofs


@dataclass(frozen=True)
class _CompareGateOutcome:
    """Post-pair gate reports produced after the main compare loop."""

    connectivity: dict[str, Any]
    external_parts: dict[str, Any]
    loop_scc: dict[str, Any]
    call_scc: dict[str, Any]
    candidate_only_parts: dict[str, Any]
    aborted: dict[str, Any] | None
    solver_time_ms: int


def _finalize_compare_gates(
    results: list[dict[str, Any]],
    *,
    region_equality: dict[str, Any],
    enable_region_equality: bool,
    enable_connectivity: bool,
    aborted: dict[str, Any] | None,
    oracle: dict[str, Any],
    oracle_functions: list[dict[str, Any]],
    oracle_external_functions: list[dict[str, Any]],
    candidate_functions_all: list[dict[str, Any]],
    mapping_document: dict[str, Any] | None,
    oracle_index: dict[str, Any],
    candidate_index: dict[str, Any],
    allow_aliased_call_targets: bool,
    proof_cache: _SemanticEqualityCache | None,
    timeout_ms: int,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
    skip_binary_equal: bool,
    max_rss_mb: int,
) -> _CompareGateOutcome:
    """Apply connectivity/external/SCC gates after the per-pair compare loop."""
    if enable_region_equality:
        _apply_region_equality_gate(results, region_equality)
    connectivity = _empty_connectivity_report(enabled=False)
    if enable_connectivity and aborted is None:
        connectivity = _apply_ssa_connectivity_gate(
            results,
            region_exempt_functions=_region_passed_function_keys(region_equality),
            oracle_functions=oracle_functions,
            candidate_functions=candidate_functions_all,
            timeout_ms=timeout_ms,
            max_rss_mb=max_rss_mb,
        )
        _quarantine_connectivity_broken_parts(results)
        if connectivity.get("aborted"):
            aborted = connectivity.get("aborted") if isinstance(connectivity.get("aborted"), dict) else None
    elif enable_connectivity:
        connectivity = _memory_limited_connectivity_report(aborted)
    if aborted is None:
        external_parts = _compare_external_oracle_parts(
            oracle_external_functions=oracle_external_functions,
            candidate_functions=candidate_functions_all,
            mapping_document=mapping_document,
            oracle_index=oracle_index,
            candidate_index=candidate_index,
            allow_aliased_call_targets=allow_aliased_call_targets,
            proof_cache=proof_cache,
            timeout_ms=timeout_ms,
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
            skip_binary_equal=skip_binary_equal,
            max_rss_mb=max_rss_mb,
        )
        if external_parts.get("aborted"):
            aborted = external_parts.get("aborted") if isinstance(external_parts.get("aborted"), dict) else None
    else:
        external_parts = _memory_limited_external_parts_report(aborted)
    solver_time_ms = int(external_parts.get("solver_time_ms", 0) or 0)
    _apply_external_successor_edge_coverage(connectivity, external_parts)
    if enable_region_equality:
        _apply_connectivity_region_coverage(region_equality, results, connectivity)
        _apply_region_equality_gate(results, region_equality)
    loop_scc = _apply_loop_scc_gate(results, region_exempt_functions=_region_passed_function_keys(region_equality))
    call_scc = _apply_call_scc_gate(results)
    candidate_only_parts = _candidate_only_ssa_parts(
        candidate_functions_all,
        results=results,
        external_parts=external_parts,
        enabled=not _ssa_document_is_batch(oracle),
    )
    return _CompareGateOutcome(
        connectivity=connectivity,
        external_parts=external_parts,
        loop_scc=loop_scc,
        call_scc=call_scc,
        candidate_only_parts=candidate_only_parts,
        aborted=aborted,
        solver_time_ms=solver_time_ms,
    )


@dataclass(frozen=True)
class _SsaPairLoopOutcome:
    """Aggregate outcome of the per-oracle-function pair compare loop."""

    results: list[dict[str, Any]]
    pending_callee_proofs: list[tuple[int, dict[str, Any]]]
    solver_time_ms: int
    skipped_unmapped: int
    aborted: dict[str, Any] | None


def _run_ssa_pair_compare_loop(
    oracle_functions: list[dict[str, Any]],
    *,
    mapping_document: dict[str, Any] | None,
    mapped_candidates: dict[str, Any],
    tables: _SsaCandidateTables,
    include_unmapped: bool,
    oracle_index: dict[str, Any],
    candidate_index: dict[str, Any],
    allow_aliased_call_targets: bool,
    proof_cache: _SemanticEqualityCache | None,
    timeout_ms: int,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
    skip_binary_equal: bool,
    max_rss_mb: int,
    image_context: dict[str, dict[str, Any]] | None = None,
) -> _SsaPairLoopOutcome:
    """Compare each oracle SSA function against its resolved candidate."""
    ordinals: dict[str, int] = defaultdict(int)
    global_constant_normalization = _collect_global_layout_normalization(
        oracle_functions,
        mapping_document=mapping_document,
        mapped_candidates=mapped_candidates,
        tables=tables,
    )
    results: list[dict[str, Any]] = []
    pending_callee_proofs: list[tuple[int, dict[str, Any]]] = []
    solver_time_ms = 0
    skipped_unmapped = 0
    aborted: dict[str, Any] | None = None
    for oracle_function in oracle_functions:
        memory_limit = _compare_memory_limit_status(max_rss_mb)
        if memory_limit is not None:
            aborted = _compare_memory_abort("ssa_pair", memory_limit)
            results.append(_memory_limit_compare_result(aborted))
            break
        function = oracle_function.get("function", {}) if isinstance(oracle_function, dict) else {}
        function_id = str(function.get("id", ""))
        function_name = str(function.get("name", function_id))
        mapped: dict[str, Any] | None = None
        if mapping_document is not None:
            mapped = mapped_candidates.get(function_id) or mapped_candidates.get(function_name)
            if mapped is None:
                skipped_unmapped += 1
                if not include_unmapped:
                    continue
                candidate_function = None
            else:
                candidate_function = _resolve_mapped_candidate(oracle_function, mapped=mapped, tables=tables)
        else:
            candidate_function = _resolve_keyed_candidate(
                oracle_function,
                function_id=function_id,
                function_name=function_name,
                ordinals=ordinals,
                tables=tables,
            )
        if candidate_function is None:
            if mapped is not None and _ssa_part_outside_declared_body(oracle_function):
                skipped_external_oracle_parts += 1  # noqa: F821, F841
                continue
            missing_reason = "mapping_missing" if mapped is None else "candidate_ssa_missing"
            missing_detail = (
                "no candidate mapping for oracle SSA function"
                if mapped is None
                else "mapping exists but candidate function was not lowered to SSA"
            )
            results.append(
                {
                    "status": "refused",
                    "reason": missing_reason,
                    "function": {"id": function_id, "name": function_name},
                    "oracle_function": oracle_function.get("id"),
                    "candidate_function": None,
                    "mapped_candidate": _mapped_candidate_detail(mapped),
                    "oracle_detail": _ssa_function_report_detail(oracle_function),
                    "candidate_detail": None,
                    "mismatches": [{"kind": "function_missing", "detail": missing_detail}],
                }
            )
            continue
        item = {
            "oracle_function": oracle_function,
            "candidate_function": candidate_function,
            "mapped": mapped,
            "function_id": function_id,
            "function_name": function_name,
            "global_constant_normalization": global_constant_normalization,
            "image_context": image_context,
        }
        result, elapsed = _compare_ssa_pair_guarded(
            item,
            mapping_document=mapping_document,
            oracle_index=oracle_index,
            candidate_index=candidate_index,
            allow_aliased_call_targets=allow_aliased_call_targets,
            proof_cache=proof_cache,
            timeout_ms=timeout_ms,
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
            skip_binary_equal=skip_binary_equal,
            max_rss_mb=max_rss_mb,
        )
        solver_time_ms += elapsed
        result_index = len(results)
        results.append(result)
        if result.get("reason") == "callee_not_proven":
            pending_callee_proofs.append((result_index, item))
            continue
        if result.get("status") == "passed" and proof_cache is not None:
            proof_cache.record(oracle_function, candidate_function, proof=str(result.get("reason") or "z3_equal"))
    return _SsaPairLoopOutcome(
        results=results,
        pending_callee_proofs=pending_callee_proofs,
        solver_time_ms=solver_time_ms,
        skipped_unmapped=skipped_unmapped,
        aborted=aborted,
    )


def compare_ssa_documents(  # noqa: D103
    *,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    oracle_index_document: dict[str, Any] | None = None,
    candidate_index_document: dict[str, Any] | None = None,
    mapping_document: dict[str, Any] | None = None,
    include_unmapped: bool = True,
    timeout_ms: int = 60000,
    max_solver_assignments: int = 256,
    max_solver_inputs: int = 16,
    max_solver_memory_stores: int = 32,
    skip_binary_equal: bool = True,
    allow_aliased_call_targets: bool = True,
    enable_callee_lemmas: bool = True,
    semantic_proof_passes: int = 4,
    enable_region_equality: bool = True,
    enable_connectivity: bool = True,
    max_region_loop_unroll: int = 0,
    max_rss_mb: int = 0,
) -> dict[str, Any]:
    oracle_functions_all = list(oracle.get("functions", []) or [])
    candidate_functions_all = list(candidate.get("functions", []) or [])
    oracle_index_source = oracle_index_document if isinstance(oracle_index_document, dict) else oracle
    candidate_index_source = candidate_index_document if isinstance(candidate_index_document, dict) else candidate
    oracle_index_functions_all = list(oracle_index_source.get("functions", []) or [])
    candidate_index_functions_all = list(candidate_index_source.get("functions", []) or [])
    oracle_functions, oracle_external_functions = _partition_declared_body_ssa_parts(oracle_functions_all)
    candidate_functions, candidate_external_functions = _partition_declared_body_ssa_parts(candidate_functions_all)
    tables = _build_ssa_candidate_tables(candidate_functions, candidate_functions_all)
    mapped_candidates = _ssa_candidate_mapping(mapping_document) if mapping_document is not None else {}
    oracle_index = _ssa_function_index(oracle_index_functions_all)
    candidate_index = _ssa_function_index(candidate_index_functions_all)
    _attach_binary_signature_context(oracle_index, oracle_index_source, oracle_index_functions_all)
    _attach_binary_signature_context(candidate_index, candidate_index_source, candidate_index_functions_all)
    proof_cache = _SemanticEqualityCache() if enable_callee_lemmas else None
    image_context = _layout_image_context(oracle, candidate)
    loop = _run_ssa_pair_compare_loop(
        oracle_functions,
        mapping_document=mapping_document,
        mapped_candidates=mapped_candidates,
        tables=tables,
        include_unmapped=include_unmapped,
        oracle_index=oracle_index,
        candidate_index=candidate_index,
        allow_aliased_call_targets=allow_aliased_call_targets,
        proof_cache=proof_cache,
        timeout_ms=timeout_ms,
        max_solver_assignments=max_solver_assignments,
        max_solver_inputs=max_solver_inputs,
        max_solver_memory_stores=max_solver_memory_stores,
        skip_binary_equal=skip_binary_equal,
        max_rss_mb=max_rss_mb,
        image_context=image_context,
    )
    results = loop.results
    pending_callee_proofs = loop.pending_callee_proofs
    solver_time_ms = loop.solver_time_ms
    skipped_unmapped = loop.skipped_unmapped
    aborted = loop.aborted

    region_equality = _empty_region_equality_report(enabled=False)
    if enable_region_equality:
        region_equality = _compare_ssa_region_equality(
            oracle=oracle,
            candidate=candidate,
            mapping_document=mapping_document,
            current_results=results,
            timeout_ms=timeout_ms,
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
            max_loop_unroll=max_region_loop_unroll,
            skip_binary_equal=skip_binary_equal,
            oracle_index=oracle_index,
            candidate_index=candidate_index,
            allow_aliased_call_targets=allow_aliased_call_targets,
            proof_cache=proof_cache,
            max_rss_mb=max_rss_mb,
        )
        solver_time_ms += int(region_equality.get("solver_time_ms", 0))
        _apply_region_equality_gate(results, region_equality)
        if region_equality.get("aborted"):
            aborted = region_equality.get("aborted") if isinstance(region_equality.get("aborted"), dict) else None

    if aborted is None:
        fixpoint_ms, pending_callee_proofs = _run_callee_proof_fixpoint(
            results,
            pending_callee_proofs,
            semantic_proof_passes=semantic_proof_passes,
            mapping_document=mapping_document,
            oracle_index=oracle_index,
            candidate_index=candidate_index,
            allow_aliased_call_targets=allow_aliased_call_targets,
            proof_cache=proof_cache,
            timeout_ms=timeout_ms,
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
            skip_binary_equal=skip_binary_equal,
            max_rss_mb=max_rss_mb,
        )
        solver_time_ms += fixpoint_ms

    gate = _finalize_compare_gates(
        results,
        region_equality=region_equality,
        enable_region_equality=enable_region_equality,
        enable_connectivity=enable_connectivity,
        aborted=aborted,
        oracle=oracle,
        oracle_functions=oracle_functions,
        oracle_external_functions=oracle_external_functions,
        candidate_functions_all=candidate_functions_all,
        mapping_document=mapping_document,
        oracle_index=oracle_index,
        candidate_index=candidate_index,
        allow_aliased_call_targets=allow_aliased_call_targets,
        proof_cache=proof_cache,
        timeout_ms=timeout_ms,
        max_solver_assignments=max_solver_assignments,
        max_solver_inputs=max_solver_inputs,
        max_solver_memory_stores=max_solver_memory_stores,
        skip_binary_equal=skip_binary_equal,
        max_rss_mb=max_rss_mb,
    )
    solver_time_ms += gate.solver_time_ms
    return _build_ssa_compare_document(
        results=results,
        skipped_unmapped=skipped_unmapped,
        proof_cache=proof_cache,
        pending_callee_proofs=pending_callee_proofs,
        oracle_external_functions=oracle_external_functions,
        candidate_external_functions=candidate_external_functions,
        solver_time_ms=solver_time_ms,
        aborted=gate.aborted,
        oracle=oracle,
        candidate=candidate,
        mapping_document=mapping_document,
        include_unmapped=include_unmapped,
        allow_aliased_call_targets=allow_aliased_call_targets,
        enable_callee_lemmas=enable_callee_lemmas,
        semantic_proof_passes=semantic_proof_passes,
        enable_region_equality=enable_region_equality,
        enable_connectivity=enable_connectivity,
        max_solver_assignments=max_solver_assignments,
        max_solver_inputs=max_solver_inputs,
        max_solver_memory_stores=max_solver_memory_stores,
        max_region_loop_unroll=max_region_loop_unroll,
        max_rss_mb=max_rss_mb,
        region_equality=region_equality,
        connectivity=gate.connectivity,
        external_parts=gate.external_parts,
        candidate_only_parts=gate.candidate_only_parts,
        loop_scc=gate.loop_scc,
        call_scc=gate.call_scc,
        skip_binary_equal=skip_binary_equal,
    )


def _build_ssa_compare_document(
    *,
    results: list[dict[str, Any]],
    skipped_unmapped: int,
    proof_cache: _SemanticEqualityCache | None,
    pending_callee_proofs: list[tuple[int, dict[str, Any]]],
    oracle_external_functions: list[dict[str, Any]],
    candidate_external_functions: list[dict[str, Any]],
    solver_time_ms: int,
    aborted: dict[str, Any] | None,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    mapping_document: dict[str, Any] | None,
    include_unmapped: bool,
    allow_aliased_call_targets: bool,
    enable_callee_lemmas: bool,
    semantic_proof_passes: int,
    enable_region_equality: bool,
    enable_connectivity: bool,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
    max_region_loop_unroll: int,
    max_rss_mb: int,
    region_equality: dict[str, Any],
    connectivity: dict[str, Any],
    external_parts: dict[str, Any],
    candidate_only_parts: dict[str, Any],
    loop_scc: dict[str, Any],
    call_scc: dict[str, Any],
    skip_binary_equal: bool,
) -> dict[str, Any]:
    """Assemble the compare summary and versioned document."""
    summary = {
        "total": len(results),
        "passed": sum(1 for result in results if result.get("status") == "passed"),
        "failed": sum(1 for result in results if result.get("status") == "failed"),
        "refused": sum(1 for result in results if result.get("status") == "refused"),
        "skipped_unmapped": skipped_unmapped,
        "semantic_proof_facts": 0 if proof_cache is None else proof_cache.count,
        "pending_callee_proofs": len(pending_callee_proofs),
        "external_oracle_parts_total": len(oracle_external_functions),
        "external_candidate_parts_total": len(candidate_external_functions),
        "external_oracle_parts_checked": external_parts.get("total", 0),
        "external_oracle_parts_passed": external_parts.get("passed", 0),
        "skipped_external_oracle_parts": external_parts.get("unproved", 0),
        "candidate_parts_total": candidate_only_parts.get("candidate_parts_total", 0),
        "candidate_parts_referenced": candidate_only_parts.get("candidate_parts_referenced", 0),
        "candidate_only_parts": candidate_only_parts.get("total", 0),
        "candidate_alias_only_parts": candidate_only_parts.get("alias_total", 0),
        "solver_time_ms": solver_time_ms,
    }
    if aborted is not None:
        summary["aborted"] = aborted
    document_without_id = {
        "schema": "dosunit.ssa_compare.v1",
        "oracle": oracle.get("exe"),
        "candidate": candidate.get("exe"),
        "mapping": None if mapping_document is None else mapping_document.get("id"),
        "include_unmapped": include_unmapped,
        "alias_call_targets": allow_aliased_call_targets,
        "callee_lemmas": enable_callee_lemmas,
        "semantic_proof_passes": semantic_proof_passes,
        "region_equality_enabled": enable_region_equality,
        "connectivity_enabled": enable_connectivity,
        "solver_gates": {
            "max_solver_assignments": max_solver_assignments,
            "max_solver_inputs": max_solver_inputs,
            "max_solver_memory_stores": max_solver_memory_stores,
            "max_region_loop_unroll": max_region_loop_unroll,
            "max_rss_mb": max_rss_mb,
        },
        "region_equality": region_equality,
        "connectivity": connectivity,
        "external_parts": external_parts,
        "candidate_only_parts": candidate_only_parts,
        "loop_scc": loop_scc,
        "call_scc": call_scc,
        "skip_binary_equal": skip_binary_equal,
        "summary": summary,
        "results": results,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("ssa-compare", document_without_id)
    return document


def _ssa_document_is_batch(document: dict[str, Any]) -> bool:
    counters = document.get("counters") if isinstance(document.get("counters"), dict) else {}
    return "functions_in_batch" in counters or "ssa_parts_in_batch" in counters


def _candidate_only_ssa_parts(
    candidate_functions: list[dict[str, Any]],
    *,
    results: list[dict[str, Any]],
    external_parts: dict[str, Any],
    enabled: bool,
) -> dict[str, Any]:
    referenced = _referenced_candidate_ssa_ids(results, external_parts)
    if not enabled:
        return {
            "enabled": False,
            "reason": "batched_child_compare",
            "candidate_parts_total": len(candidate_functions),
            "candidate_parts_referenced": len(referenced),
            "total": 0,
            "alias_total": 0,
            "parts": [],
            "alias_parts": [],
        }
    referenced_alias_keys = {
        key
        for function in candidate_functions
        if str(function.get("id") or "") in referenced
        for key in [_candidate_part_alias_key(function)]
        if key is not None
    }
    parts: list[dict[str, Any]] = []
    alias_parts: list[dict[str, Any]] = []
    for function in candidate_functions:
        function_id = str(function.get("id") or "")
        if not function_id or function_id in referenced:
            continue
        alias_key = _candidate_part_alias_key(function)
        if alias_key is not None and alias_key in referenced_alias_keys:
            alias_parts.append(function)
        else:
            parts.append(function)
    return {
        "enabled": True,
        "candidate_parts_total": len(candidate_functions),
        "candidate_parts_referenced": len(referenced),
        "total": len(parts),
        "alias_total": len(alias_parts),
        "parts": [_candidate_only_ssa_part_detail(function) for function in parts],
        "alias_parts": [_candidate_only_ssa_part_detail(function) for function in alias_parts],
    }


def _referenced_candidate_ssa_ids(results: list[dict[str, Any]], external_parts: dict[str, Any]) -> set[str]:
    referenced: set[str] = set()
    for result in results:
        _add_candidate_reference(referenced, result.get("candidate_function"))
    for result in external_parts.get("results", []) or []:
        if isinstance(result, dict):
            _add_candidate_reference(referenced, result.get("candidate_function"))
    return referenced


def _add_candidate_reference(referenced: set[str], value: Any) -> None:  # noqa: ANN401
    if isinstance(value, str) and value:
        referenced.add(value)


def _candidate_only_ssa_part_detail(function: dict[str, Any]) -> dict[str, Any]:
    info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
    return {
        "id": function.get("id"),
        "function": {"id": info.get("id"), "name": info.get("name")},
        "detail": _ssa_function_report_detail(function),
    }


def _candidate_part_alias_key(function: dict[str, Any]) -> tuple[Any, ...] | None:
    entry = function.get("entry") if isinstance(function.get("entry"), dict) else {}
    part = function.get("part") if isinstance(function.get("part"), dict) else {}
    source = function.get("source") if isinstance(function.get("source"), dict) else {}
    linear = entry.get("linear")
    ip = entry.get("ip")
    if not linear and not ip:
        return None
    return (
        linear,
        ip,
        part.get("index"),
        part.get("delta"),
        source.get("machine_code_sha256"),
        source.get("machine_code_size"),
        source.get("instruction_count"),
    )


def _result_function_key(result: dict[str, Any]) -> str:
    function = result.get("function")
    if isinstance(function, dict):
        return str(function.get("id") or function.get("name") or "")
    return str(function or "")


def _quarantine_connectivity_broken_parts(results: list[dict[str, Any]]) -> None:
    """Downgrade nonterminal-part failures inside functions whose successor graphs are misaligned.

    When connectivity proves the block graphs do not correspond, observable diffs on
    `local_block_outputs` slices are boundary artifacts, not behavioral evidence; the
    region-level comparison remains the arbiter for those functions.
    """
    broken = {
        _result_function_key(result)
        for result in results
        if any(
            isinstance(mismatch, dict) and mismatch.get("kind") == "connectivity_successor_mismatch"
            for mismatch in result.get("mismatches", [])
        )
    }
    if not broken:
        return
    for result in results:
        if _result_function_key(result) not in broken or result.get("status") != "failed":
            continue
        projection = result.get("output_projection") if isinstance(result.get("output_projection"), dict) else {}
        if projection.get("kind") != "local_block_outputs":
            continue
        original = result.get("mismatches", [])
        result["status"] = "refused"
        result["reason"] = "part_boundary_mismatch"
        result["mismatches"] = [
            {
                "kind": "part_boundary_mismatch",
                "detail": "nonterminal block verdict inside a function with misaligned successor graphs; local diff is unreliable",
                "subsumed_mismatches": original,
            }
        ]


def _empty_connectivity_report(*, enabled: bool) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "status": "disabled" if not enabled else "not_applicable",
        "edges_checked": 0,
        "state_edges_checked": 0,
        "state_inputs_checked": 0,
        "state_solver_time_ms": 0,
        "external_successor_edges_skipped": 0,
        "external_successor_edges": [],
        "external_successor_edges_covered": 0,
        "external_successor_edges_unproved": 0,
        "region_exempt_functions": [],
        "failures": [],
        "refusals": [],
    }


def _current_process_rss_kib() -> int | None:
    try:
        with open("/proc/self/status", encoding="ascii") as status_file:
            for line in status_file:
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])
    except (FileNotFoundError, OSError, ValueError):
        return None
    return None


def _compare_soft_rss_limit_kib(max_rss_mb: int) -> int | None:
    if max_rss_mb <= 0:
        return None
    return max(1, max_rss_mb // 2) * 1024


def _compare_memory_limit_status(max_rss_mb: int) -> dict[str, Any] | None:
    soft_limit_kib = _compare_soft_rss_limit_kib(max_rss_mb)
    if soft_limit_kib is None:
        return None
    rss_kib = _current_process_rss_kib()
    if rss_kib is None or rss_kib <= soft_limit_kib:
        return None
    return {
        "kind": "memory_limit",
        "rss_kib": rss_kib,
        "rss_mb": round(rss_kib / 1024, 1),
        "soft_limit_mb": round(soft_limit_kib / 1024, 1),
        "hard_limit_mb": max_rss_mb,
    }


def _compare_memory_abort(phase: str, memory_limit: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase": phase,
        "reason": "memory_limit",
        "memory": memory_limit,
        "detail": (
            "SSA comparison stopped before the hard RSS watchdog killed the process; "
            "rerun with tighter solver gates or a smaller function set"
        ),
    }


def _memory_limit_mismatch(aborted: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "kind": "memory_limit",
        "detail": None if aborted is None else aborted.get("detail"),
        "phase": None if aborted is None else aborted.get("phase"),
        "memory": None if aborted is None else aborted.get("memory"),
    }


def _memory_limit_compare_result(aborted: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "refused",
        "reason": "memory_limit",
        "function": {"id": "<compare>", "name": "<compare>"},
        "oracle_function": None,
        "candidate_function": None,
        "mapped_candidate": None,
        "oracle_detail": None,
        "candidate_detail": None,
        "mismatches": [_memory_limit_mismatch(aborted)],
    }


def _memory_limited_connectivity_report(aborted: dict[str, Any] | None) -> dict[str, Any]:
    report = _empty_connectivity_report(enabled=True)
    report["status"] = "refused"
    report["aborted"] = aborted
    report["refusals"] = [_memory_limit_mismatch(aborted)]
    return report


def _memory_limited_external_parts_report(aborted: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "enabled": True,
        "status": "refused",
        "total": 0,
        "passed": 0,
        "failed": 0,
        "refused": 1,
        "unproved": 0,
        "solver_time_ms": 0,
        "aborted": aborted,
        "results": [_memory_limit_compare_result(aborted or _compare_memory_abort("external_parts", {}))],
    }


def compare_ssa_abi_documents(  # noqa: D103
    *,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    abi_manifest: dict[str, Any],
    mapping_document: dict[str, Any] | None = None,
    timeout_ms: int = 60000,
    max_solver_assignments: int = 512,
    max_solver_inputs: int = 32,
    max_solver_memory_stores: int = 32,
    max_loop_unroll: int = 0,
) -> dict[str, Any]:
    oracle_groups = _ssa_function_groups(list(oracle.get("functions", []) or []))
    candidate_groups = _ssa_function_groups(list(candidate.get("functions", []) or []))
    mapped_candidates = _ssa_candidate_mapping(mapping_document) if mapping_document is not None else {}
    data_segment_para = _abi_data_segment_para(abi_manifest)
    results: list[dict[str, Any]] = []
    solver_time_ms = 0

    for abi_function in _abi_functions(abi_manifest):
        function_name = str(abi_function.get("name") or "")
        oracle_group = _ssa_group_for_abi_function(oracle_groups, abi_function, side="oracle")
        mapped = (
            mapped_candidates.get(str(abi_function.get("oracle_id") or ""))
            or mapped_candidates.get(str(abi_function.get("oracle_name") or ""))
            or mapped_candidates.get(str(abi_function.get("id") or ""))
            or mapped_candidates.get(function_name)
        )
        candidate_group = _ssa_group_for_abi_function(candidate_groups, abi_function, side="candidate", mapped=mapped)
        observables = _abi_observables(abi_function)
        input_constraints = _abi_input_constraints(abi_function)
        base_result = {
            "function": {
                "name": function_name,
                "kind": abi_function.get("kind"),
                "calling_convention": abi_function.get("calling_convention"),
                "inputs": abi_function.get("inputs", []),
                "stack_args": abi_function.get("stack_args", []),
                "returns": abi_function.get("returns", []),
                "preserved": abi_function.get("preserved", []),
                "clobbers": abi_function.get("clobbers", []),
                "effects": abi_function.get("effects", []),
            },
            "mapped_candidate": _mapped_candidate_detail(mapped),
            "observables": observables,
            "input_constraints": input_constraints,
        }
        if not oracle_group or not candidate_group:
            missing = "oracle" if not oracle_group else "candidate"
            results.append(
                {
                    **base_result,
                    "status": "refused",
                    "reason": "function_missing",
                    "mismatches": [{"kind": "function_missing", "side": missing}],
                }
            )
            continue
        if not observables["regs"] and not observables["memory"]:
            results.append(
                {
                    **base_result,
                    "status": "refused",
                    "reason": "no_declared_observables",
                    "mismatches": [{"kind": "no_declared_observables"}],
                }
            )
            continue
        oracle_summary = _summarize_abi_function(
            oracle_group,
            abi_function=abi_function,
            observables=observables,
            data_segment_para=data_segment_para,
            max_loop_unroll=max_loop_unroll,
        )
        candidate_summary = _summarize_abi_function(
            candidate_group,
            abi_function=abi_function,
            observables=observables,
            data_segment_para=data_segment_para,
            max_loop_unroll=max_loop_unroll,
        )
        if oracle_summary.get("status") != "passed" or candidate_summary.get("status") != "passed":
            side = "oracle" if oracle_summary.get("status") != "passed" else "candidate"
            summary = oracle_summary if side == "oracle" else candidate_summary
            mismatches = [item for item in (summary.get("mismatches") or []) if isinstance(item, dict)]
            results.append(
                {
                    **base_result,
                    "status": "refused",
                    "reason": summary.get("reason", "unsupported_ir"),
                    "side": side,
                    "oracle_summary": _summary_detail(oracle_summary),
                    "candidate_summary": _summary_detail(candidate_summary),
                    "mismatches": mismatches,
                }
            )
            continue
        gate = _ssa_solver_gate(
            oracle_summary["function"],
            candidate_summary["function"],
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
        )
        if gate is not None:
            results.append(
                {
                    **base_result,
                    "status": "refused",
                    "reason": gate["reason"],
                    "oracle_summary": _summary_detail(oracle_summary),
                    "candidate_summary": _summary_detail(candidate_summary),
                    "mismatches": [gate],
                }
            )
            continue
        if _semantic_ssa_payload(oracle_summary["function"]) == _semantic_ssa_payload(candidate_summary["function"]):
            results.append(
                {
                    **base_result,
                    "status": "passed",
                    "reason": "ssa_equal",
                    "oracle_summary": _summary_detail(oracle_summary),
                    "candidate_summary": _summary_detail(candidate_summary),
                    "mismatches": [],
                }
            )
            continue
        comparison = _compare_functions(
            oracle_summary["function"],
            candidate_summary["function"],
            timeout_ms=timeout_ms,
            input_constraints=input_constraints,
        )
        solver_time_ms += int(comparison.pop("solver_time_ms", 0))
        results.append(
            {
                **base_result,
                "status": comparison["status"],
                "reason": comparison.get("reason"),
                "oracle_summary": _summary_detail(oracle_summary),
                "candidate_summary": _summary_detail(candidate_summary),
                "mismatches": comparison.get("mismatches", []),
            }
        )

    summary = {
        "total": len(results),
        "passed": sum(1 for result in results if result.get("status") == "passed"),
        "failed": sum(1 for result in results if result.get("status") == "failed"),
        "refused": sum(1 for result in results if result.get("status") == "refused"),
        "solver_time_ms": solver_time_ms,
    }
    document_without_id = {
        "schema": "dosunit.ssa_abi_compare.v1",
        "oracle": oracle.get("exe"),
        "candidate": candidate.get("exe"),
        "mapping": None if mapping_document is None else mapping_document.get("id"),
        "abi_manifest": abi_manifest.get("schema"),
        "data_segment_para": normalize_hex(data_segment_para, width=4),
        "solver_gates": {
            "max_solver_assignments": max_solver_assignments,
            "max_solver_inputs": max_solver_inputs,
            "max_solver_memory_stores": max_solver_memory_stores,
            "max_loop_unroll": max_loop_unroll,
        },
        "summary": summary,
        "results": results,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("ssa-abi-compare", document_without_id)
    return document


def _function_linear_ranges(
    *,
    function: dict[str, Any],
    function_base: int,
    start: int,
    end: int,
    scan_limit: int,
) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = [(start, end)]
    for item in function.get("ranges", ()) or ():
        if not isinstance(item, dict):
            continue
        try:
            offset = parse_int(item.get("offset"), field="function.ranges.offset")
        except DosUnitError:
            continue
        size_value = item.get("size")
        if isinstance(size_value, int):
            size = size_value
        else:
            try:
                end_offset = parse_int(item.get("end_offset"), field="function.ranges.end_offset")
            except DosUnitError:
                continue
            size = end_offset - offset + 1
        if size <= 0:
            continue
        bounded_size = max(1, min(size, scan_limit))
        linear = function_base + offset
        ranges.append((linear, linear + bounded_size))
    return _merge_linear_ranges(ranges)


def _merge_linear_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted((start, end) for start, end in ranges if end > start):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def _linear_range_end(ranges: list[tuple[int, int]], address: int) -> int | None:
    for start, end in ranges:
        if start <= address < end:
            return end
    return None


def _can_add_dynamic_successor_range(*, project: Any, function_base: int, successor: int) -> bool:  # noqa: ANN401
    if successor < function_base or successor >= function_base + 0x10000:
        return False
    probe = _loader_bytes(project, successor, 1)
    return probe is not None and len(probe) == 1


def _lower_function(
    *,
    project: Any,  # noqa: ANN401
    linked_base: int,
    exe_path: Path,
    exe_digest: str,
    cache_document: dict[str, Any] | None,
    cache_stats: dict[str, int],
    function: dict[str, Any],
    segment_paragraphs: dict[str, int],
    output_regs: tuple[str, ...],
    source_ir: str,
    max_blocks_per_function: int,
    max_insns_per_function: int,
    max_assignments_per_function: int,
    scan_limit: int,
    follow_call_fallthrough: bool,
    max_lift_block_ms: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    function_id = str(function.get("id", "<unknown>"))
    names = function.get("names", []) if isinstance(function.get("names"), list) else []
    function_name = str(names[0]) if names else function_id
    entry = function.get("entry", {})
    if not isinstance(entry, dict):
        return [], [_refusal(function, "unsupported_ir", "function entry is missing")], 0
    try:
        segment_para = _entry_segment_para(entry, segment_paragraphs=segment_paragraphs)
        entry_ip = parse_int(entry.get("offset"), field="function.entry.offset")
    except DosUnitError as ex:
        return [], [_refusal(function, "unsupported_ir", str(ex))], 0
    function_base = linked_base + (segment_para << 4)
    start = function_base + entry_ip
    size = function.get("size")
    limit = int(size) if isinstance(size, int) and size > 0 else scan_limit
    allow_dynamic_successor_ranges = True
    limit = max(1, min(limit, scan_limit))
    end = start + limit
    allowed_ranges = _function_linear_ranges(
        function=function,
        function_base=function_base,
        start=start,
        end=end,
        scan_limit=scan_limit,
    )
    function_machine_code = _loader_bytes(project, start, limit)
    ctx = _LowerScanCtx(
        project=project,
        exe_path=exe_path,
        exe_digest=exe_digest,
        cache_document=cache_document,
        cache_stats=cache_stats,
        function=function,
        function_id=function_id,
        function_name=function_name,
        function_base=function_base,
        segment_para=segment_para,
        entry_ip=entry_ip,
        start=start,
        function_machine_code=function_machine_code,
        source_ir=source_ir,
        output_regs=output_regs,
        max_insns_per_function=max_insns_per_function,
        max_assignments_per_function=max_assignments_per_function,
        scan_limit=scan_limit,
        follow_call_fallthrough=follow_call_fallthrough,
        max_lift_block_ms=max_lift_block_ms,
        allow_dynamic_successor_ranges=allow_dynamic_successor_ranges,
    )
    state = _LowerScanState(
        pending=[start],
        allowed_ranges=allowed_ranges,
    )
    _lower_block_scan(ctx, state, max_blocks_per_function=max_blocks_per_function)
    if state.pending and len(state.seen) >= max_blocks_per_function:
        state.refusals.append(_refusal(function, "unsupported_ir", f"block limit reached: {max_blocks_per_function}"))
    if not state.lowered_parts and not state.refusals:
        state.refusals.append(_refusal(function, "unsupported_ir", "no SSA blocks lowered"))
    return state.lowered_parts, state.refusals, state.blocks_lifted


@dataclass(frozen=True)
class _LowerScanCtx:
    """Immutable context for the per-block SSA lowering scan."""

    project: Any
    exe_path: Path
    exe_digest: str
    cache_document: dict[str, Any] | None
    cache_stats: dict[str, int]
    function: dict[str, Any]
    function_id: str
    function_name: str
    function_base: int
    segment_para: int
    entry_ip: int
    start: int
    function_machine_code: bytes | None
    source_ir: str
    output_regs: tuple[str, ...]
    max_insns_per_function: int
    max_assignments_per_function: int
    scan_limit: int
    follow_call_fallthrough: bool
    max_lift_block_ms: int
    allow_dynamic_successor_ranges: bool


@dataclass
class _LowerScanState:
    """Mutable worklist state for the per-block SSA lowering scan."""

    pending: list[int]
    allowed_ranges: list[tuple[int, int]]
    seen: set[int] = field(default_factory=set)
    boundary_extensions: set[int] = field(default_factory=set)
    lowered_parts: list[dict[str, Any]] = field(default_factory=list)
    refusals: list[dict[str, Any]] = field(default_factory=list)
    blocks_lifted: int = 0

    def extend_range_and_retry(self, at: int, range_end: int, scan_limit: int) -> None:
        """Widen the allowed ranges past `range_end` and requeue `at`."""
        self.boundary_extensions.add(at)
        self.seen.discard(at)
        self.allowed_ranges = _merge_linear_ranges([*self.allowed_ranges, (range_end, range_end + scan_limit)])
        self.pending.insert(0, at)


def _lower_block_scan(ctx: _LowerScanCtx, state: _LowerScanState, *, max_blocks_per_function: int) -> None:
    """Worklist loop over reachable blocks, lowering each into SSA parts."""
    while state.pending and len(state.seen) < max_blocks_per_function:
        at = state.pending.pop(0)
        range_end = _linear_range_end(state.allowed_ranges, at)
        if range_end is None or at in state.seen:
            continue
        state.seen.add(at)
        _lower_scanned_block(ctx, state, at=at, range_end=range_end)


def _lower_scanned_block(ctx: _LowerScanCtx, state: _LowerScanState, *, at: int, range_end: int) -> None:
    """Lift and lower one block at `at`, recording parts or refusals into `state`."""
    function = ctx.function
    try:
        lifted = _lift_vex_block_cached(
            project=ctx.project,
            exe_path=ctx.exe_path,
            exe_digest=ctx.exe_digest,
            start=at,
            size=max(1, min(ctx.scan_limit, range_end - at)),
            opt_level=0,
            cache_document=ctx.cache_document,
            cache_stats=ctx.cache_stats,
            max_lift_block_ms=ctx.max_lift_block_ms,
        )
        irsb = lifted.irsb
    except TimeoutError as ex:
        state.refusals.append(
            _refusal(
                function,
                "timeout",
                f"lifter block timed out at {normalize_hex(at)} after {ctx.max_lift_block_ms} ms: {ex}",
                extra={"address": {"linear": normalize_hex(at)}},
            )
        )
        return
    except Exception as ex:
        state.refusals.append(
            _refusal(
                function,
                "unsupported_ir",
                f"lifter block failed at {normalize_hex(at)}: {type(ex).__name__}: {ex}",
                extra={"address": {"linear": normalize_hex(at)}},
            )
        )
        return
    state.blocks_lifted += int(lifted.lifted)

    instructions = [
        _instruction_text_from_record(record, function_base=ctx.function_base)
        for record in lifted.instructions
        if _linear_range_end(
            state.allowed_ranges,
            parse_int(record.get("linear", 0), field="instruction.linear"),
        )
        is not None
    ]
    lifted_size = int(getattr(irsb, "size", 0) or 0)
    if lifted_size > 0:
        lifted_end = at + lifted_size
        instructions = [
            instruction
            for instruction in instructions
            if (_optional_int((instruction.get("address") or {}).get("linear")) or 0) < lifted_end
        ]
    if not instructions:
        if (
            ctx.allow_dynamic_successor_ranges
            and at not in state.boundary_extensions
            and range_end - at < 16
            and _can_add_dynamic_successor_range(project=ctx.project, function_base=ctx.function_base, successor=range_end)
        ):
            state.extend_range_and_retry(at, range_end, ctx.scan_limit)
            return
        state.refusals.append(
            _refusal(function, "unsupported_ir", f"lifter produced no instructions at {normalize_hex(at)}")
        )
        return
    if len(instructions) > ctx.max_insns_per_function:
        state.refusals.append(
            _refusal(
                function,
                "unsupported_ir",
                f"instruction limit reached at {normalize_hex(at)}: {len(instructions)} > {ctx.max_insns_per_function}",
            )
        )
        return
    if _scan_block_retried_or_refused(ctx, state, at=at, range_end=range_end, irsb=irsb, instructions=instructions):
        return

    transfer = (
        _repeat_string_transfer(instructions)
        or _nonreturning_interrupt_transfer(instructions)
        or _transfer_info(irsb, instructions)
    )
    block_output_regs = _with_control_output_regs(ctx.output_regs, transfer)
    lowered = _lower_scanned_block_ir(ctx, state, at=at, irsb=irsb, instructions=instructions, block_output_regs=block_output_regs)
    if lowered is None:
        return
    if isinstance(lowered, LowerFailure):
        state.refusals.append(
            _refusal(
                function,
                lowered.reason,
                f"{lowered.message} at {normalize_hex(at)}",
                extra={"address": {"linear": normalize_hex(at)}},
            )
        )
        return

    _record_lowered_part(
        ctx,
        state,
        at=at,
        irsb=irsb,
        instructions=instructions,
        transfer=transfer,
        lowered=lowered,
    )


def _scan_block_retried_or_refused(
    ctx: _LowerScanCtx,
    state: _LowerScanState,
    *,
    at: int,
    range_end: int,
    irsb: Any,  # noqa: ANN401
    instructions: list[dict[str, Any]],
) -> bool:
    """Handle boring-fallthrough and incomplete-block lanes; return True when the block is consumed."""
    boring_fallthrough = _boring_fallthrough_successor(irsb, instructions)
    if (
        boring_fallthrough == range_end
        and ctx.allow_dynamic_successor_ranges
        and at not in state.boundary_extensions
        and _can_add_dynamic_successor_range(project=ctx.project, function_base=ctx.function_base, successor=range_end)
    ):
        state.extend_range_and_retry(at, range_end, ctx.scan_limit)
        return True
    if _is_incomplete_noncontrol_block(irsb, instructions):
        if (
            ctx.allow_dynamic_successor_ranges
            and at not in state.boundary_extensions
            and _incomplete_block_reaches_range_end(instructions, range_end)
            and _can_add_dynamic_successor_range(project=ctx.project, function_base=ctx.function_base, successor=range_end)
        ):
            state.extend_range_and_retry(at, range_end, ctx.scan_limit)
            return True
        last = instructions[-1]
        state.refusals.append(
            _refusal(
                ctx.function,
                "incomplete_block",
                f"lifter stopped before a control transfer at {last.get('address', {}).get('linear')}: {last.get('disassembly')}",
                extra={"address": last.get("address", {}) if isinstance(last.get("address"), dict) else {}},
            )
        )
        return True
    return False


def _record_lowered_part(
    ctx: _LowerScanCtx,
    state: _LowerScanState,
    *,
    at: int,
    irsb: Any,  # noqa: ANN401
    instructions: list[dict[str, Any]],
    transfer: dict[str, Any] | None,
    lowered: dict[str, Any],
) -> None:
    """Append the SSA part body for a lowered block and enqueue its successors."""
    part_index = len(state.lowered_parts)
    body_without_id = {
        "function": {"id": ctx.function_id, "name": ctx.function_name},
        "part": {
            "kind": "block",
            "index": part_index,
            "entry_delta": normalize_hex((at - ctx.start) & 0xFFFF, width=4),
        },
        "function_entry": {
            "cs": normalize_hex(ctx.segment_para, width=4),
            "ip": normalize_hex(ctx.entry_ip, width=4),
            "linear": normalize_hex(ctx.start),
        },
        "entry": {
            "cs": normalize_hex(ctx.segment_para, width=4),
            "ip": normalize_hex((at - ctx.function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(at),
        },
        "source": {
            "ir": ctx.source_ir,
            "jumpkind": str(irsb.jumpkind),
            "instruction_count": len(instructions),
            "instructions": instructions,
            "function_machine_code_sha256": _bytes_sha256(ctx.function_machine_code),
            "function_machine_code_size": len(ctx.function_machine_code) if ctx.function_machine_code is not None else None,
            "machine_code_sha256": _machine_code_sha256(instructions),
            "machine_code_size": _machine_code_size(instructions),
            "transfer": transfer,
        },
        **lowered,
    }
    body = dict(body_without_id)
    body["id"] = stable_id("ssa-function", body_without_id)
    state.lowered_parts.append(body)

    successors = (
        _transfer_successor_linears(transfer)
        if isinstance(transfer, dict) and transfer.get("summary") == "repeat_string"
        else _ssa_block_successors(
            irsb,
            instructions,
            follow_call_fallthrough=ctx.follow_call_fallthrough,
            transfer=transfer,
        )
    )
    for successor in successors:
        if _linear_range_end(state.allowed_ranges, successor) is None:
            if not ctx.allow_dynamic_successor_ranges or not _can_add_dynamic_successor_range(
                project=ctx.project,
                function_base=ctx.function_base,
                successor=successor,
            ):
                continue
            state.allowed_ranges = _merge_linear_ranges([*state.allowed_ranges, (successor, successor + ctx.scan_limit)])
        if successor not in state.seen and successor not in state.pending:
            state.pending.append(successor)


def _lower_scanned_block_ir(
    ctx: _LowerScanCtx,
    state: _LowerScanState,
    *,
    at: int,
    irsb: Any,  # noqa: ANN401
    instructions: list[dict[str, Any]],
    block_output_regs: tuple[str, ...],
) -> dict[str, Any] | LowerFailure | None:
    """Lower one block's IR into SSA; return the lowered doc, a failure, or None when a refusal was recorded."""
    function = ctx.function
    try:
        with _timeout_alarm(
            ctx.max_lift_block_ms,
            message=f"SSA block lowering exceeded timeout at {normalize_hex(at)}",
        ):
            return _lower_block_ir_source(
                ctx,
                state,
                at=at,
                irsb=irsb,
                instructions=instructions,
                block_output_regs=block_output_regs,
            )
    except TimeoutError as ex:
        state.refusals.append(
            _refusal(
                function,
                "timeout",
                f"SSA block lowering timed out at {normalize_hex(at)} after {ctx.max_lift_block_ms} ms: {ex}",
                extra={"address": {"linear": normalize_hex(at)}},
            )
        )
        return None


def _lower_block_ir_source(
    ctx: _LowerScanCtx,
    state: _LowerScanState,
    *,
    at: int,
    irsb: Any,  # noqa: ANN401
    instructions: list[dict[str, Any]],
    block_output_regs: tuple[str, ...],
) -> dict[str, Any] | LowerFailure | None:
    """Dispatch block lowering to the repeat-string, VEX, or AIL path."""
    function = ctx.function
    string_summary = _lower_repeat_string_summary(
        instructions,
        output_regs=block_output_regs,
        max_assignments_per_function=ctx.max_assignments_per_function,
    )
    if string_summary is not None:
        return string_summary
    if ctx.source_ir == "vex":
        return _lower_irsb(
            irsb, output_regs=block_output_regs, max_assignments_per_function=ctx.max_assignments_per_function
        )
    if ctx.source_ir == "ail":
        try:
            ail_block = _vex_irsb_to_ail_block(project=ctx.project, irsb=irsb)
        except Exception as ex:
            state.refusals.append(
                _refusal(
                    function,
                    "unsupported_ir",
                    f"AIL conversion failed at {normalize_hex(at)}: {type(ex).__name__}: {ex}",
                )
            )
            return None
        return _lower_ail_block(
            ail_block,
            output_regs=block_output_regs,
            max_assignments_per_function=ctx.max_assignments_per_function,
        )
    state.refusals.append(_refusal(function, "unsupported_ir", f"unsupported SSA source IR: {ctx.source_ir}"))
    return None


def _with_control_output_regs(output_regs: tuple[str, ...], transfer: dict[str, Any] | None) -> tuple[str, ...]:
    if not isinstance(transfer, dict) or transfer.get("kind") != "direct_successors":
        return output_regs
    return tuple(dict.fromkeys((*output_regs, *RAW_OUTPUT_REGS, "ip")))


def _catalog_segment_paragraphs(functions_catalog: dict[str, Any]) -> dict[str, int]:
    paragraphs: dict[str, int] = {}
    for item in functions_catalog.get("segments", ()) or ():
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        paragraph = _optional_int(item.get("paragraph"))
        if not isinstance(name, str) or paragraph is None:
            continue
        normalized = name.strip()
        if not normalized:
            continue
        paragraphs[normalized] = paragraph
        paragraphs[normalized.lower()] = paragraph
    return paragraphs


def _entry_segment_para(entry: dict[str, Any], *, segment_paragraphs: dict[str, int] | None = None) -> int:
    segment_para = _optional_int(entry.get("segment_para"))
    if segment_para is not None:
        return segment_para
    segment = entry.get("segment")
    if isinstance(segment, str):
        text_raw = segment.strip()
        text = text_raw.lower()
        if segment_paragraphs:
            mapped = segment_paragraphs.get(text_raw)
            if mapped is None:
                mapped = segment_paragraphs.get(text)
            if mapped is not None:
                return mapped
        parsed = _optional_int(text)
        if parsed is not None:
            return parsed
    if entry.get("kind") == "module_relative" and entry.get("offset") is not None:
        return 0
    raise DosUnitError("function.entry.segment_para must be an integer or hex string")


def _repeat_string_transfer(instructions: list[dict[str, Any]]) -> dict[str, Any] | None:
    info = _repeat_string_info(instructions)
    if info is None:
        return None
    fallthrough = _call_fallthrough_linear_from_instructions(instructions)
    if fallthrough is None:
        return None
    return {
        "kind": "direct_successors",
        "jumpkind": "Ijk_Boring",
        "summary": "repeat_string",
        "successors": [
            {
                "linear": normalize_hex(fallthrough),
                "low16": normalize_hex(fallthrough & 0xFFFF, width=4),
            }
        ],
    }


def _transfer_successor_linears(transfer: dict[str, Any] | None) -> list[int]:
    if not isinstance(transfer, dict):
        return []
    successors = transfer.get("successors")
    if not isinstance(successors, list):
        return []
    linears: list[int] = []
    for successor in successors:
        if not isinstance(successor, dict):
            continue
        linear = _optional_int(successor.get("linear"))
        if linear is not None:
            linears.append(linear)
    return _unique_ints(linears)


def _repeat_string_info(instructions: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not _last_instruction_is_repeat_string(instructions):
        return None
    instruction = instructions[-1]
    text = str(instruction.get("disassembly") or instruction.get("mnemonic") or "").lower()
    tokens = text.replace(",", " ").split()
    if len(tokens) < 2 or tokens[0] not in {"rep", "repe", "repz", "repne", "repnz"}:
        return None
    base = tokens[1]
    if base.startswith("movs"):
        family = "movs"
    elif base.startswith("stos"):
        family = "stos"
    elif base.startswith("scas"):
        family = "scas"
    elif base.startswith("cmps"):
        family = "cmps"
    else:
        return None
    suffix = base[-1:]
    width = 1 if suffix == "b" else 2 if suffix == "w" else 4 if suffix == "d" else None
    if width is None:
        return None
    return {"repeat": tokens[0], "family": family, "width": width, "mnemonic": base}


def _repeat_string_family_versions(
    family: str,
    *,
    tag: str,
    reg_versions: dict[str, SsaExpr],
    mem_input: SsaExpr,
    cx: SsaExpr,
    si: SsaExpr,
    di: SsaExpr,
    ax_value: SsaExpr,
    ds: SsaExpr,
    es: SsaExpr,
    flags: SsaExpr,
) -> tuple[SsaExpr, bool] | None:
    """Apply the repeat-string family's output versions; return (mem_version, memory_touched) or None."""
    if family == "movs":
        args = (mem_input, cx, si, di, ds, es, flags)
        reg_versions["cx"] = SsaExpr(f"{tag}_cx", 16, args)
        reg_versions["si"] = SsaExpr(f"{tag}_si", 16, args)
        reg_versions["di"] = SsaExpr(f"{tag}_di", 16, args)
        return SsaExpr(f"{tag}_memory", 0, args), True
    if family == "stos":
        args = (mem_input, cx, di, ax_value, es, flags)
        reg_versions["cx"] = SsaExpr(f"{tag}_cx", 16, args)
        reg_versions["di"] = SsaExpr(f"{tag}_di", 16, args)
        return SsaExpr(f"{tag}_memory", 0, args), True
    if family == "scas":
        args = (mem_input, cx, di, ax_value, es, flags)
        reg_versions["cx"] = SsaExpr(f"{tag}_cx", 16, args)
        reg_versions["di"] = SsaExpr(f"{tag}_di", 16, args)
        reg_versions["flags"] = SsaExpr(f"{tag}_flags", 16, args)
        return mem_input, False
    if family == "cmps":
        args = (mem_input, cx, si, di, ds, es, flags)
        reg_versions["cx"] = SsaExpr(f"{tag}_cx", 16, args)
        reg_versions["si"] = SsaExpr(f"{tag}_si", 16, args)
        reg_versions["di"] = SsaExpr(f"{tag}_di", 16, args)
        reg_versions["flags"] = SsaExpr(f"{tag}_flags", 16, args)
        return mem_input, False
    return None


def _lower_repeat_string_summary(
    instructions: list[dict[str, Any]],
    *,
    output_regs: tuple[str, ...],
    max_assignments_per_function: int,
) -> dict[str, Any] | None:
    info = _repeat_string_info(instructions)
    if info is None:
        return None
    family = str(info["family"])
    width = int(info["width"])
    repeat = str(info["repeat"])
    tag = f"summary_{repeat}_{family}{width * 8}"
    reg_versions: dict[str, SsaExpr] = {
        name: SsaExpr("input", reg_width, name=name) for name, reg_width in REG_BY_OFFSET.values()
    }
    mem_input = SsaExpr("mem_input", 0, name="mem")
    cx = reg_versions["cx"]
    si = reg_versions["si"]
    di = reg_versions["di"]
    ax_value = _coerce_width(reg_versions["ax"], 8 if width == 1 else 16)
    flags = reg_versions["flags"]
    ds = reg_versions["ds"]
    es = reg_versions["es"]

    family_state = _repeat_string_family_versions(
        family,
        tag=tag,
        reg_versions=reg_versions,
        mem_input=mem_input,
        cx=cx,
        si=si,
        di=di,
        ax_value=ax_value,
        ds=ds,
        es=es,
        flags=flags,
    )
    if family_state is None:
        return None
    mem_version, memory_touched = family_state

    fallthrough = _call_fallthrough_linear_from_instructions(instructions)
    if fallthrough is not None:
        reg_versions["ip"] = SsaExpr("const", 16, value=fallthrough & 0xFFFF)
    if family in {"scas", "cmps"} and "flags" not in output_regs:
        output_regs = tuple(dict.fromkeys((*output_regs, "flags")))

    requested: dict[str, SsaExpr] = {}
    for reg in output_regs:
        if reg not in reg_versions:
            return None
        requested[reg] = reg_versions[reg]

    assignments: list[dict[str, Any]] = []
    memo: dict[tuple[Any, ...], str] = {}
    object_memo: dict[int, dict[str, Any]] = {}
    try:
        outputs = {
            reg: _materialize(
                expr,
                assignments=assignments,
                memo=memo,
                object_memo=object_memo,
                max_assignments_per_function=max_assignments_per_function,
            )
            for reg, expr in requested.items()
        }
        if memory_touched:
            outputs["memory"] = _materialize(
                mem_version,
                assignments=assignments,
                memo=memo,
                object_memo=object_memo,
                max_assignments_per_function=max_assignments_per_function,
            )
    except LowerFailure:
        return None
    inputs = _collect_inputs(requested.values())
    if memory_touched:
        inputs.update(_collect_inputs((mem_version,)))
    return {
        "inputs": _input_items(inputs),
        "outputs": outputs,
        "assignments": assignments,
        "summary": {"kind": "repeat_string", **info},
    }


def _vex_live_statement_indices(irsb: Any, output_regs: tuple[str, ...]) -> set[int]:  # noqa: ANN401
    statements = list(getattr(irsb, "statements", []) or [])
    tyenv = getattr(irsb, "tyenv", None)
    needed_regs = set(output_regs)
    needed_tmps: set[int] = set()
    need_memory = any(getattr(statement, "tag", None) == "Ist_Store" for statement in statements)
    live: set[int] = set()

    next_deps = _vex_expr_deps(getattr(irsb, "next", None), tyenv)
    needed_tmps.update(next_deps.temps)
    needed_regs.update(next_deps.regs)
    need_memory = need_memory or next_deps.memory

    for index in range(len(statements) - 1, -1, -1):
        need_memory = _vex_live_statement_step(
            statements[index],
            index,
            tyenv=tyenv,
            live=live,
            needed_tmps=needed_tmps,
            needed_regs=needed_regs,
            need_memory=need_memory,
        )

    return live


def _vex_live_wrtmp_step(
    statement: Any,  # noqa: ANN401
    index: int,
    *,
    tyenv: Any,  # noqa: ANN401
    live: set[int],
    needed_tmps: set[int],
    needed_regs: set[str],
    need_memory: bool,
) -> bool:
    """Backward liveness for Ist_WrTmp; return updated memory liveness."""
    tmp = int(getattr(statement, "tmp", -1))
    if tmp not in needed_tmps:
        return need_memory
    live.add(index)
    needed_tmps.discard(tmp)
    deps = _vex_expr_deps(getattr(statement, "data", None), tyenv)
    needed_tmps.update(deps.temps)
    needed_regs.update(deps.regs)
    return need_memory or deps.memory


def _vex_live_put_step(
    statement: Any,  # noqa: ANN401
    index: int,
    *,
    tyenv: Any,  # noqa: ANN401
    live: set[int],
    needed_tmps: set[int],
    needed_regs: set[str],
    need_memory: bool,
) -> bool:
    """Backward liveness for Ist_Put; return updated memory liveness."""
    target = _vex_put_target(statement, tyenv)
    if target is None or target[0] not in needed_regs:
        return need_memory
    live.add(index)
    needed_regs.discard(target[0])
    deps = _vex_expr_deps(getattr(statement, "data", None), tyenv)
    needed_tmps.update(deps.temps)
    needed_regs.update(deps.regs)
    return need_memory or deps.memory


def _vex_live_store_step(
    statement: Any,  # noqa: ANN401
    index: int,
    *,
    tyenv: Any,  # noqa: ANN401
    live: set[int],
    needed_tmps: set[int],
    needed_regs: set[str],
    need_memory: bool,
) -> bool:
    """Backward liveness for Ist_Store; return updated memory liveness."""
    if not need_memory:
        return need_memory
    live.add(index)
    addr_deps = _vex_expr_deps(getattr(statement, "addr", None), tyenv)
    data_deps = _vex_expr_deps(getattr(statement, "data", None), tyenv)
    needed_tmps.update(addr_deps.temps)
    needed_tmps.update(data_deps.temps)
    needed_regs.update(addr_deps.regs)
    needed_regs.update(data_deps.regs)
    return True


def _vex_live_exit_step(
    statement: Any,  # noqa: ANN401
    index: int,
    *,
    tyenv: Any,  # noqa: ANN401
    live: set[int],
    needed_tmps: set[int],
    needed_regs: set[str],
    need_memory: bool,
) -> bool:
    """Backward liveness for Ist_Exit; return updated memory liveness."""
    if "ip" not in needed_regs:
        return need_memory
    live.add(index)
    guard_deps = _vex_expr_deps(getattr(statement, "guard", None), tyenv)
    dst_deps = _vex_expr_deps(getattr(statement, "dst", None), tyenv)
    needed_tmps.update(guard_deps.temps)
    needed_tmps.update(dst_deps.temps)
    needed_regs.update(guard_deps.regs)
    needed_regs.update(dst_deps.regs)
    return need_memory or guard_deps.memory or dst_deps.memory


_VEX_LIVE_STEP_HANDLERS = {
    "Ist_WrTmp": _vex_live_wrtmp_step,
    "Ist_Put": _vex_live_put_step,
    "Ist_Store": _vex_live_store_step,
    "Ist_Exit": _vex_live_exit_step,
}


def _vex_live_statement_step(
    statement: Any,  # noqa: ANN401
    index: int,
    *,
    tyenv: Any,  # noqa: ANN401
    live: set[int],
    needed_tmps: set[int],
    needed_regs: set[str],
    need_memory: bool,
) -> bool:
    """Apply one backward liveness step for a VEX statement; return updated memory liveness."""
    tag = getattr(statement, "tag", None)
    handler = _VEX_LIVE_STEP_HANDLERS.get(str(tag))
    if handler is not None:
        return handler(
            statement,
            index,
            tyenv=tyenv,
            live=live,
            needed_tmps=needed_tmps,
            needed_regs=needed_regs,
            need_memory=need_memory,
        )
    if tag in {"Ist_IMark", "Ist_NoOp", "Ist_AbiHint", "Ist_MBE"}:
        return need_memory
    if tag == "Ist_Dirty":
        live.add(index)
        deps = _vex_dirty_deps(statement, tyenv)
        needed_tmps.update(deps.temps)
        needed_regs.update(deps.regs)
        return need_memory or deps.memory
    live.add(index)
    return need_memory


def _vex_put_target(statement: Any, tyenv: Any) -> tuple[str, int] | None:  # noqa: ANN401
    width = _vex_expr_width(getattr(statement, "data", None), tyenv)
    return _register_write_target(int(getattr(statement, "offset", -1)), width)


def _vex_expr_width(expr: Any, tyenv: Any) -> int | None:  # noqa: ANN401
    if expr is None:
        return None
    if hasattr(expr, "result_size"):
        try:
            return int(expr.result_size(tyenv))
        except Exception:
            return None
    if hasattr(expr, "size"):
        try:
            return int(expr.size)
        except Exception:
            return None
    if hasattr(expr, "con") and hasattr(expr.con, "size"):
        try:
            return int(expr.con.size)
        except Exception:
            return None
    return None


def _vex_expr_deps(expr: Any, tyenv: Any) -> _VexDeps:  # noqa: ANN401
    deps = _VexDeps(set(), set())
    _collect_vex_expr_deps(expr, tyenv, deps, set())
    return deps


def _vex_dirty_deps(statement: Any, tyenv: Any) -> _VexDeps:  # noqa: ANN401
    deps = _VexDeps(set(), set())
    for expr in getattr(statement, "args", ()) or ():
        deps.update(_vex_expr_deps(expr, tyenv))
    deps.update(_vex_expr_deps(getattr(statement, "guard", None), tyenv))
    return deps


def _collect_vex_expr_dep_tag(
    expr: Any,  # noqa: ANN401
    tag: Any,  # noqa: ANN401
    tyenv: Any,  # noqa: ANN401
    deps: _VexDeps,
    seen: set[int],
) -> bool:
    """Collect dependencies for leaf/structured VEX expr tags; return True when handled."""
    if tag == "Iex_RdTmp":
        deps.temps.add(int(expr.tmp))
        return True
    if tag == "Iex_Get":
        width = _vex_expr_width(expr, tyenv)
        target = _register_write_target(int(getattr(expr, "offset", -1)), width)
        if target is not None:
            deps.regs.add(target[0])
        return True
    if tag == "Iex_Load":
        deps.memory = True
        _collect_vex_expr_deps(getattr(expr, "addr", None), tyenv, deps, seen)
        return True
    if tag == "Iex_ITE":
        _collect_vex_expr_deps(getattr(expr, "cond", None), tyenv, deps, seen)
        _collect_vex_expr_deps(getattr(expr, "iftrue", None), tyenv, deps, seen)
        _collect_vex_expr_deps(getattr(expr, "iffalse", None), tyenv, deps, seen)
        return True
    return tag in {"Iex_Const"} or (str(tag).startswith("Ico_") if tag is not None else False)


def _collect_vex_expr_deps(expr: Any, tyenv: Any, deps: _VexDeps, seen: set[int]) -> None:  # noqa: ANN401
    if expr is None:
        return
    marker = id(expr)
    if marker in seen:
        return
    seen.add(marker)
    if _collect_vex_expr_dep_tag(expr, getattr(expr, "tag", None), tyenv, deps, seen):
        return
    for attr in ("args", "arg", "arg1", "arg2", "arg3", "arg4", "cond", "iftrue", "iffalse", "addr"):
        value = getattr(expr, attr, None)
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            for item in value:
                _collect_vex_expr_deps(item, tyenv, deps, seen)
        else:
            _collect_vex_expr_deps(value, tyenv, deps, seen)


@dataclass
class _IrsbLowerState:
    """Mutable SSA version state while lowering one IRSB."""

    reg_versions: dict[str, SsaExpr]
    mem_version: SsaExpr
    io_version: SsaExpr
    temp_defs: dict[int, SsaExpr] = field(default_factory=dict)
    temp_failures: dict[int, LowerFailure] = field(default_factory=dict)
    memory_touched: bool = False
    io_touched: bool = False
    io_event_index: int = 0
    exits: list[tuple[SsaExpr, SsaExpr]] = field(default_factory=list)
    ip_expr: SsaExpr | None = None


def _lower_irsb_wrtmp(statement: Any, state: _IrsbLowerState, *, tyenv: Any) -> None:  # noqa: ANN401
    """Lower Ist_WrTmp into temp_defs or temp_failures."""
    expr = _lower_expr(
        statement.data,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=tyenv,
        memory=state.mem_version,
    )
    if isinstance(expr, LowerFailure):
        state.temp_failures[int(statement.tmp)] = expr
    else:
        state.temp_defs[int(statement.tmp)] = expr


def _lower_irsb_put(
    statement: Any,  # noqa: ANN401
    state: _IrsbLowerState,
    *,
    tyenv: Any,  # noqa: ANN401
    output_regs: tuple[str, ...],
) -> LowerFailure | None:
    """Lower Ist_Put into reg_versions; return a failure when unsupported."""
    if _is_unobserved_flags_write(int(statement.offset), output_regs):
        return None
    expr = _lower_expr(
        statement.data,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=tyenv,
        memory=state.mem_version,
    )
    if isinstance(expr, LowerFailure):
        access = _register_write_target(int(statement.offset), None)
        if access is None:
            return LowerFailure("unsupported_ir", f"unsupported VEX register offset {statement.offset}")
        state.reg_versions[access[0]] = SsaExpr("unsupported", access[1], name=f"{expr.reason}|{expr.message}")
        return None
    return _write_register(state.reg_versions, int(statement.offset), expr)


def _lower_irsb_store(
    statement: Any,  # noqa: ANN401
    state: _IrsbLowerState,
    *,
    tyenv: Any,  # noqa: ANN401
) -> LowerFailure | None:
    """Lower Ist_Store, advancing the memory version; return a failure when unsupported."""
    addr = _lower_expr(
        statement.addr,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=tyenv,
        memory=state.mem_version,
    )
    if isinstance(addr, LowerFailure):
        return addr
    data = _lower_expr(
        statement.data,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=tyenv,
        memory=state.mem_version,
    )
    if isinstance(data, LowerFailure):
        return data
    endness = str(getattr(statement, "endness", "Iend_LE"))
    if endness not in {"Iend_LE", "Iend_BE"}:
        return LowerFailure("unsupported_ir", f"unsupported VEX store endness: {endness}")
    op = "storele" if endness == "Iend_LE" else "storebe"
    state.mem_version = SsaExpr(op, 0, (state.mem_version, _coerce_width(addr, 32), data))
    state.memory_touched = True
    return None


def _lower_irsb_exit(
    statement: Any,  # noqa: ANN401
    state: _IrsbLowerState,
    *,
    tyenv: Any,  # noqa: ANN401
) -> LowerFailure | None:
    """Lower Ist_Exit into the pending-exit list; return a failure when unsupported."""
    guard = _lower_expr(
        statement.guard,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=tyenv,
        memory=state.mem_version,
    )
    if isinstance(guard, LowerFailure):
        return guard
    dst = _lower_expr(
        statement.dst,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=tyenv,
        memory=state.mem_version,
    )
    if isinstance(dst, LowerFailure):
        return dst
    state.exits.append((_coerce_width(guard, 1), _coerce_width(dst, 16 if dst.width <= 16 else dst.width)))
    return None


def _lower_irsb_dirty(
    statement: Any,  # noqa: ANN401
    state: _IrsbLowerState,
    *,
    tyenv: Any,  # noqa: ANN401
) -> LowerFailure | None:
    """Lower Ist_Dirty io summaries, advancing io state; return a failure when unsupported."""
    lowered_dirty = _lower_dirty_io_statement(
        statement,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=tyenv,
        memory=state.mem_version,
        io=state.io_version,
        event_index=state.io_event_index,
    )
    if isinstance(lowered_dirty, LowerFailure):
        return lowered_dirty
    if lowered_dirty is not None and lowered_dirty.op == "summary_io_out":
        state.io_version = lowered_dirty
        state.io_touched = True
        state.io_event_index += 1
        return None
    if lowered_dirty is not None and lowered_dirty.op == "summary_io_in":
        tmp = int(getattr(statement, "tmp", -1))
        if tmp >= 0:
            state.temp_defs[tmp] = lowered_dirty
        state.io_event_index += 1
    return None


def _lower_irsb_statement(
    statement: Any,  # noqa: ANN401
    state: _IrsbLowerState,
    *,
    tyenv: Any,  # noqa: ANN401
    output_regs: tuple[str, ...],
) -> LowerFailure | None:
    """Dispatch one IRSB statement to its lowering step; return a failure when unsupported."""
    tag = statement.tag
    if tag == "Ist_WrTmp":
        _lower_irsb_wrtmp(statement, state, tyenv=tyenv)
        return None
    if tag == "Ist_Put":
        return _lower_irsb_put(statement, state, tyenv=tyenv, output_regs=output_regs)
    if tag == "Ist_Store":
        return _lower_irsb_store(statement, state, tyenv=tyenv)
    if tag == "Ist_Exit":
        return _lower_irsb_exit(statement, state, tyenv=tyenv)
    if tag in {"Ist_NoOp", "Ist_AbiHint", "Ist_MBE"}:
        return None
    if tag == "Ist_Dirty":
        return _lower_irsb_dirty(statement, state, tyenv=tyenv)
    return LowerFailure("unsupported_ir", f"unsupported VEX statement: {tag}")


def _lower_irsb(
    irsb: Any, *, output_regs: tuple[str, ...], max_assignments_per_function: int  # noqa: ANN401
) -> dict[str, Any] | LowerFailure:
    live_statements = _vex_live_statement_indices(irsb, output_regs)
    state = _IrsbLowerState(
        reg_versions={
            name: SsaExpr("input", width, name=name) for name, width in REG_BY_OFFSET.values()
        },
        mem_version=SsaExpr("mem_input", 0, name="mem"),
        io_version=SsaExpr("mem_input", 0, name="io"),
    )

    for statement_index, statement in enumerate(irsb.statements):
        if statement.tag == "Ist_IMark" or statement_index not in live_statements:
            continue
        failure = _lower_irsb_statement(statement, state, tyenv=irsb.tyenv, output_regs=output_regs)
        if failure is not None:
            return failure
    return _finish_irsb_lowering(
        state,
        irsb=irsb,
        output_regs=output_regs,
        max_assignments_per_function=max_assignments_per_function,
    )


def _finish_irsb_lowering(
    state: _IrsbLowerState,
    *,
    irsb: Any,  # noqa: ANN401
    output_regs: tuple[str, ...],
    max_assignments_per_function: int,
) -> dict[str, Any] | LowerFailure:
    """Fold exits into ip, materialize requested outputs, and build the SSA doc."""
    next_expr = _lower_expr(
        irsb.next,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=irsb.tyenv,
        memory=state.mem_version,
    )
    if isinstance(next_expr, LowerFailure):
        return next_expr
    ip_expr = _coerce_width(next_expr, 16)
    for guard, dst in reversed(state.exits):
        ip_expr = SsaExpr("ite", 16, (_coerce_width(guard, 1), _coerce_width(dst, 16), ip_expr))
    state.reg_versions["ip"] = ip_expr

    requested: dict[str, SsaExpr] = {}
    for reg in output_regs:
        if reg not in state.reg_versions:
            return LowerFailure("unsupported_ir", f"unsupported output register: {reg}")
        expr = state.reg_versions[reg]
        failure = _expr_failure(expr)
        if failure is not None:
            return failure
        requested[reg] = expr

    materialized = _materialize_irsb_outputs(state, requested, max_assignments_per_function=max_assignments_per_function)
    if isinstance(materialized, LowerFailure):
        return materialized
    outputs, assignments = materialized
    if max_assignments_per_function > 0 and len(assignments) > max_assignments_per_function:
        return LowerFailure(
            "slice_too_large", f"SSA assignment limit reached: {len(assignments)} > {max_assignments_per_function}"
        )
    inputs = _collect_inputs(requested.values())
    if state.memory_touched:
        inputs.update(_collect_inputs((state.mem_version,)))
    if state.io_touched:
        inputs.update(_collect_inputs((state.io_version,)))
    return {
        "inputs": _input_items(inputs),
        "outputs": outputs,
        "assignments": assignments,
    }


def _materialize_irsb_outputs(
    state: _IrsbLowerState,
    requested: dict[str, SsaExpr],
    *,
    max_assignments_per_function: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]] | LowerFailure:
    """Materialize requested register/memory/io outputs into the assignment list."""
    assignments: list[dict[str, Any]] = []
    memo: dict[tuple[Any, ...], str] = {}
    object_memo: dict[int, dict[str, Any]] = {}
    try:
        outputs = {
            reg: _materialize(
                expr,
                assignments=assignments,
                memo=memo,
                object_memo=object_memo,
                max_assignments_per_function=max_assignments_per_function,
            )
            for reg, expr in requested.items()
        }
        if state.memory_touched:
            outputs["memory"] = _materialize(
                state.mem_version,
                assignments=assignments,
                memo=memo,
                object_memo=object_memo,
                max_assignments_per_function=max_assignments_per_function,
            )
        if state.io_touched:
            outputs["io"] = _materialize(
                state.io_version,
                assignments=assignments,
                memo=memo,
                object_memo=object_memo,
                max_assignments_per_function=max_assignments_per_function,
            )
    except LowerFailure as ex:
        return ex
    return outputs, assignments


def _lower_dirty_io_statement(
    statement: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
    memory: SsaExpr,
    io: SsaExpr,
    event_index: int,
) -> SsaExpr | LowerFailure | None:
    callee = getattr(statement, "cee", None)
    name = str(getattr(callee, "name", "") or callee or "")
    if name == "x86g_dirtyhelper_IN":
        return _lower_dirty_in(
            statement,
            temp_defs=temp_defs,
            temp_failures=temp_failures,
            reg_versions=reg_versions,
            tyenv=tyenv,
            memory=memory,
            io=io,
            event_index=event_index,
        )
    if name != "x86g_dirtyhelper_OUT":
        return LowerFailure("unsupported_ir", f"unsupported VEX dirty helper: {name or '<unknown>'}")
    return _lower_dirty_out(
        statement,
        temp_defs=temp_defs,
        temp_failures=temp_failures,
        reg_versions=reg_versions,
        tyenv=tyenv,
        memory=memory,
        io=io,
        event_index=event_index,
    )


def _dirty_io_guard(
    statement: Any,  # noqa: ANN401
    *,
    kind: str,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
    memory: SsaExpr,
) -> LowerFailure | None:
    """Verify the dirty io guard is unguarded (const 1); return a failure otherwise."""
    guard = _lower_expr(
        getattr(statement, "guard", None),
        temp_defs=temp_defs,
        temp_failures=temp_failures,
        reg_versions=reg_versions,
        tyenv=tyenv,
        memory=memory,
    )
    if isinstance(guard, LowerFailure):
        return guard
    if _const_value(guard) != 1:
        return LowerFailure("unsupported_ir", f"guarded port {kind} is not modeled")
    return None


def _dirty_io_args(
    statement: Any,  # noqa: ANN401
    *,
    kind: str,
    minimum: int,
) -> list[Any] | LowerFailure:
    """Read the dirty io arg list, enforcing minimum arity."""
    args = list(getattr(statement, "args", ()) or ())
    if len(args) < minimum:
        return LowerFailure("unsupported_ir", f"unsupported port {kind} arity: {len(args)}")
    return args


def _dirty_io_lowered(
    arg_exprs: list[Any],
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
    memory: SsaExpr,
) -> list[SsaExpr] | LowerFailure:
    """Lower each dirty io arg expr; fail on the first lowering failure."""
    lowered: list[SsaExpr] = []
    for arg in arg_exprs:
        expr = _lower_expr(
            arg,
            temp_defs=temp_defs,
            temp_failures=temp_failures,
            reg_versions=reg_versions,
            tyenv=tyenv,
            memory=memory,
        )
        if isinstance(expr, LowerFailure):
            return expr
        lowered.append(expr)
    return lowered


def _dirty_io_value_width(width: SsaExpr, *, kind: str) -> int | LowerFailure:
    """Resolve the port io value width from its width operand."""
    width_value = _const_value(width)
    if width_value == 8:
        return 8
    if width_value == 16:
        return 16
    if width_value == 32:
        return 32
    if width_value is not None:
        return LowerFailure("unsupported_ir", f"unsupported port {kind} width: {width_value}")
    return 16


def _lower_dirty_in(
    statement: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
    memory: SsaExpr,
    io: SsaExpr,
    event_index: int,
) -> SsaExpr | LowerFailure | None:
    """Lower x86g_dirtyhelper_IN into a summary_io_in expr."""
    failure = _dirty_io_guard(
        statement,
        kind="input",
        temp_defs=temp_defs,
        temp_failures=temp_failures,
        reg_versions=reg_versions,
        tyenv=tyenv,
        memory=memory,
    )
    if failure is not None:
        return failure
    args = _dirty_io_args(statement, kind="input", minimum=2)
    if isinstance(args, LowerFailure):
        return args
    lowered = _dirty_io_lowered(
        args[:2],
        temp_defs=temp_defs,
        temp_failures=temp_failures,
        reg_versions=reg_versions,
        tyenv=tyenv,
        memory=memory,
    )
    if isinstance(lowered, LowerFailure):
        return lowered
    port, width = lowered
    value_width = _dirty_io_value_width(width, kind="input")
    if isinstance(value_width, LowerFailure):
        return value_width
    return SsaExpr(
        "summary_io_in",
        value_width,
        (
            io,
            SsaExpr("const", 16, value=event_index & 0xFFFF),
            _coerce_width(port, 16),
            _coerce_width(width, 16),
        ),
    )


def _lower_dirty_out(
    statement: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
    memory: SsaExpr,
    io: SsaExpr,
    event_index: int,
) -> SsaExpr | LowerFailure | None:
    """Lower x86g_dirtyhelper_OUT into a summary_io_out expr."""
    failure = _dirty_io_guard(
        statement,
        kind="output",
        temp_defs=temp_defs,
        temp_failures=temp_failures,
        reg_versions=reg_versions,
        tyenv=tyenv,
        memory=memory,
    )
    if failure is not None:
        return failure
    args = _dirty_io_args(statement, kind="output", minimum=3)
    if isinstance(args, LowerFailure):
        return args
    lowered = _dirty_io_lowered(
        args[:3],
        temp_defs=temp_defs,
        temp_failures=temp_failures,
        reg_versions=reg_versions,
        tyenv=tyenv,
        memory=memory,
    )
    if isinstance(lowered, LowerFailure):
        return lowered
    port, value, width = lowered
    value_width = _dirty_io_value_width(width, kind="output")
    if isinstance(value_width, LowerFailure):
        return value_width
    return SsaExpr(
        "summary_io_out",
        0,
        (
            io,
            SsaExpr("const", 16, value=event_index & 0xFFFF),
            _coerce_width(port, 16),
            _coerce_width(value, value_width),
            _coerce_width(width, 16),
        ),
    )


BYTE_REGISTER_ACCESS = {
    0: ("ax", False),
    1: ("ax", True),
    4: ("cx", False),
    5: ("cx", True),
    8: ("dx", False),
    9: ("dx", True),
    12: ("bx", False),
    13: ("bx", True),
}


def _vex_irsb_to_ail_block(*, project: Any, irsb: Any) -> Any:  # noqa: ANN401
    from angr.ailment.converter_vex import VEXIRSBConverter
    from angr.ailment.manager import Manager

    return VEXIRSBConverter.convert(irsb, Manager(arch=project.arch))


def _lower_ail_block(
    block: Any, *, output_regs: tuple[str, ...], max_assignments_per_function: int  # noqa: ANN401
) -> dict[str, Any] | LowerFailure:
    state = _IrsbLowerState(
        reg_versions={
            name: SsaExpr("input", width, name=name) for name, width in REG_BY_OFFSET.values()
        },
        mem_version=SsaExpr("mem_input", 0, name="mem"),
        io_version=SsaExpr("mem_input", 0, name="io"),
    )

    for statement in getattr(block, "statements", []) or []:
        failure = _lower_ail_statement(statement, state, output_regs=output_regs)
        if failure is not None:
            return failure

    if state.ip_expr is not None:
        ip_expr = state.ip_expr
        for guard, dst in reversed(state.exits):
            ip_expr = SsaExpr("ite", 16, (_coerce_width(guard, 1), _coerce_width(dst, 16), ip_expr))
        state.reg_versions["ip"] = ip_expr

    return _finish_ail_lowering(state, output_regs, max_assignments_per_function=max_assignments_per_function)


def _finish_ail_lowering(
    state: _IrsbLowerState,
    output_regs: tuple[str, ...],
    *,
    max_assignments_per_function: int,
) -> dict[str, Any] | LowerFailure:
    """Materialize requested AIL outputs into the assignment list and result dict."""
    requested: dict[str, SsaExpr] = {}
    for reg in output_regs:
        if reg not in state.reg_versions:
            return LowerFailure("unsupported_ir", f"unsupported output register: {reg}")
        expr = state.reg_versions[reg]
        failure = _expr_failure(expr)
        if failure is not None:
            return failure
        requested[reg] = expr

    materialized = _materialize_irsb_outputs(
        state,
        requested,
        max_assignments_per_function=max_assignments_per_function,
    )
    if isinstance(materialized, LowerFailure):
        return materialized
    outputs, assignments = materialized
    if max_assignments_per_function > 0 and len(assignments) > max_assignments_per_function:
        return LowerFailure(
            "slice_too_large", f"SSA assignment limit reached: {len(assignments)} > {max_assignments_per_function}"
        )
    inputs = _collect_inputs(requested.values())
    if state.memory_touched:
        inputs.update(_collect_inputs((state.mem_version,)))
    return {
        "inputs": _input_items(inputs),
        "outputs": outputs,
        "assignments": assignments,
    }


def _lower_ail_assignment(
    statement: Any,  # noqa: ANN401
    state: _IrsbLowerState,
    *,
    output_regs: tuple[str, ...],
) -> LowerFailure | None:
    """Lower an AIL Assignment/WeakAssignment into temp or register versions."""
    dst = statement.dst
    dst_kind = str(getattr(dst, "kind_name", dst.__class__.__name__))
    if dst_kind == "Register" and _is_unobserved_flags_write(int(dst.reg_offset), output_regs):
        return None
    src = _lower_ail_expr(
        statement.src,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        memory=state.mem_version,
    )
    if dst_kind == "Tmp":
        if isinstance(src, LowerFailure):
            state.temp_failures[int(dst.tmp_idx)] = src
        else:
            state.temp_defs[int(dst.tmp_idx)] = src
        return None
    if dst_kind == "Register":
        if isinstance(src, LowerFailure):
            access = _register_write_target(int(dst.reg_offset), None)
            if access is None:
                return LowerFailure("unsupported_ir", f"unsupported AIL register offset {dst.reg_offset}")
            state.reg_versions[access[0]] = SsaExpr("unsupported", access[1], name=f"{src.reason}|{src.message}")
            return None
        return _write_register(state.reg_versions, int(dst.reg_offset), src)
    return LowerFailure("unsupported_ir", f"unsupported AIL assignment destination: {dst_kind}")


def _lower_ail_store(
    statement: Any,  # noqa: ANN401
    state: _IrsbLowerState,
) -> LowerFailure | None:
    """Lower an AIL Store, advancing the memory version; return a failure when unsupported."""
    guard = getattr(statement, "guard", None)
    if guard is not None:
        lowered_guard = _lower_ail_expr(
            guard,
            temp_defs=state.temp_defs,
            temp_failures=state.temp_failures,
            reg_versions=state.reg_versions,
            memory=state.mem_version,
        )
        if isinstance(lowered_guard, LowerFailure):
            return lowered_guard
        if _const_value(lowered_guard) != 1:
            return LowerFailure("unsupported_ir", "guarded AIL store is not modeled")
    addr = _lower_ail_expr(
        statement.addr,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        memory=state.mem_version,
    )
    if isinstance(addr, LowerFailure):
        return addr
    data = _lower_ail_expr(
        statement.data,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        memory=state.mem_version,
    )
    if isinstance(data, LowerFailure):
        return data
    endness = str(getattr(statement, "endness", "Iend_LE"))
    if endness not in {"Iend_LE", "Iend_BE"}:
        return LowerFailure("unsupported_ir", f"unsupported AIL store endness: {endness}")
    width = int(getattr(statement, "size", 0)) * 8
    if width <= 0:
        return LowerFailure("unsupported_ir", "AIL store has invalid width")
    op = "storele" if endness == "Iend_LE" else "storebe"
    state.mem_version = SsaExpr(op, 0, (state.mem_version, _coerce_width(addr, 32), _coerce_width(data, width)))
    state.memory_touched = True
    return None


def _lower_ail_condjump(
    statement: Any,  # noqa: ANN401
    state: _IrsbLowerState,
) -> LowerFailure | None:
    """Lower an AIL ConditionalJump into the pending-exit list."""
    guard = _lower_ail_expr(
        statement.condition,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        memory=state.mem_version,
    )
    if isinstance(guard, LowerFailure):
        return guard
    dst = _lower_ail_expr(
        statement.true_target,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        memory=state.mem_version,
    )
    if isinstance(dst, LowerFailure):
        return dst
    false_target = getattr(statement, "false_target", None)
    if false_target is not None:
        false_expr = _lower_ail_expr(
            false_target,
            temp_defs=state.temp_defs,
            temp_failures=state.temp_failures,
            reg_versions=state.reg_versions,
            memory=state.mem_version,
        )
        if isinstance(false_expr, LowerFailure):
            return false_expr
        state.ip_expr = _coerce_width(false_expr, 16)
    state.exits.append((_coerce_width(guard, 1), _coerce_width(dst, 16 if dst.width <= 16 else dst.width)))
    return None


def _lower_ail_jump(
    statement: Any,  # noqa: ANN401
    state: _IrsbLowerState,
) -> LowerFailure | None:
    """Lower an AIL Jump into the ip version."""
    target = _lower_ail_expr(
        statement.target,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        memory=state.mem_version,
    )
    if isinstance(target, LowerFailure):
        return target
    state.ip_expr = _coerce_width(target, 16)
    return None


def _lower_ail_statement(
    statement: Any,  # noqa: ANN401
    state: _IrsbLowerState,
    *,
    output_regs: tuple[str, ...],
) -> LowerFailure | None:
    """Dispatch one AIL statement to its lowering step; return a failure when unsupported."""
    kind = str(getattr(statement, "kind_name", statement.__class__.__name__))
    if kind in {"Assignment", "WeakAssignment"}:
        return _lower_ail_assignment(statement, state, output_regs=output_regs)
    if kind == "Store":
        return _lower_ail_store(statement, state)
    if kind == "ConditionalJump":
        return _lower_ail_condjump(statement, state)
    if kind == "Jump":
        return _lower_ail_jump(statement, state)
    if kind in {"Return", "Label"}:
        return None
    if kind == "SideEffectStatement":
        expr = getattr(statement, "expr", None)
        if getattr(expr, "op", None) == "call":
            return None
        return LowerFailure("unsupported_ir", f"unsupported AIL side-effect statement: {expr}")
    return LowerFailure("unsupported_ir", f"unsupported AIL statement: {kind}")


def _lower_ail_expr(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    if expr is None:
        return LowerFailure("unsupported_ir", "AIL expression is missing")
    kind = str(getattr(expr, "kind_name", expr.__class__.__name__))
    leaf = _ail_leaf_expr(
        kind, expr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions
    )
    if leaf is not None:
        return leaf
    structural = _ail_structural_expr(
        kind, expr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if structural is not None:
        return structural
    return _ail_expr_unsupported(kind, expr)


def _ail_leaf_expr(
    kind: str,
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
) -> SsaExpr | LowerFailure | None:
    """Lower leaf AIL kinds (Const/Tmp/Register); None when not a leaf kind."""
    if kind == "Const":
        return _ail_const_expr(expr)
    if kind == "Tmp":
        return _ail_tmp_expr(expr, temp_defs=temp_defs, temp_failures=temp_failures)
    if kind == "Register":
        return _read_register(reg_versions, int(expr.reg_offset), int(expr.bits), source="AIL")
    return None


def _ail_structural_expr(
    kind: str,
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure | None:
    """Lower structural AIL kinds; None when the kind is not structural."""
    kwargs = {
        "temp_defs": temp_defs,
        "temp_failures": temp_failures,
        "reg_versions": reg_versions,
        "memory": memory,
    }
    if kind == "BinaryOp":
        return _lower_ail_binop(expr, **kwargs)
    if kind == "UnaryOp":
        return _lower_ail_unop(expr, **kwargs)
    if kind == "Convert":
        return _lower_ail_convert(expr, **kwargs)
    if kind == "Load":
        return _lower_ail_load(expr, **kwargs)
    if kind == "ITE":
        return _lower_ail_ite(expr, **kwargs)
    if kind == "Extract":
        return _lower_ail_extract(expr, **kwargs)
    if kind == "Insert":
        return _lower_ail_insert(expr, **kwargs)
    return None


def _ail_expr_unsupported(kind: str, expr: Any) -> LowerFailure:  # noqa: ANN401
    """Build the unsupported-AIL-expression failure for non-value kinds."""
    if kind == "Call":
        return LowerFailure("unsupported_ir", "AIL call expression is not modeled inside value slice")
    if kind in {"DirtyExpression", "VEXCCallExpression"}:
        callee = str(getattr(expr, "callee", kind))
        return LowerFailure("unsupported_ir", f"unsupported AIL helper expression: {callee}")
    if kind == "MultiStatementExpression":
        return LowerFailure("unsupported_ir", "AIL multi-statement expression is not modeled")
    return LowerFailure("unsupported_ir", f"unsupported AIL expression: {kind}")


def _ail_const_expr(expr: Any) -> SsaExpr | LowerFailure:  # noqa: ANN401
    """Lower an AIL Const leaf to an SsaExpr."""
    bits = int(getattr(expr, "bits", 0))
    value = getattr(expr, "value", None)
    if not isinstance(value, int) or bits <= 0:
        return LowerFailure("unsupported_ir", f"unsupported AIL constant: {expr}")
    return SsaExpr("const", bits, value=value & _mask(bits))


def _ail_tmp_expr(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
) -> SsaExpr | LowerFailure:
    """Resolve an AIL Tmp read through temp defs/failures."""
    tmp = int(expr.tmp_idx)
    if tmp in temp_failures:
        return temp_failures[tmp]
    if tmp not in temp_defs:
        return LowerFailure("unsupported_ir", f"read of undefined AIL tmp t{tmp}")
    return temp_defs[tmp]


def _lower_ail_convert(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    """Lower an AIL Convert (extension/truncation) expr."""
    operand = _lower_ail_expr(
        expr.operand, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(operand, LowerFailure):
        return operand
    width = int(expr.to_bits)
    if width == operand.width:
        return operand
    if width > operand.width:
        return SsaExpr("sext" if bool(expr.is_signed) else "zext", width, (operand,))
    return SsaExpr("trunc", width, (operand,))


def _lower_ail_load(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    """Lower an AIL Load against the current memory version."""
    guard = getattr(expr, "guard", None)
    if guard is not None:
        lowered_guard = _lower_ail_expr(
            guard, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
        )
        if isinstance(lowered_guard, LowerFailure):
            return lowered_guard
        if _const_value(lowered_guard) != 1:
            return LowerFailure("unsupported_ir", "guarded AIL load is not modeled")
    addr = _lower_ail_expr(
        expr.addr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(addr, LowerFailure):
        return addr
    endness = str(getattr(expr, "endness", "Iend_LE"))
    if endness not in {"Iend_LE", "Iend_BE"}:
        return LowerFailure("unsupported_ir", f"unsupported AIL load endness: {endness}")
    op = "loadle" if endness == "Iend_LE" else "loadbe"
    return SsaExpr(op, int(expr.size) * 8, (memory, _coerce_width(addr, 32)))


def _lower_ail_ite(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    """Lower an AIL ITE into an ite SsaExpr."""
    cond = _lower_ail_expr(
        expr.cond, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(cond, LowerFailure):
        return cond
    iftrue = _lower_ail_expr(
        expr.iftrue, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(iftrue, LowerFailure):
        return iftrue
    iffalse = _lower_ail_expr(
        expr.iffalse, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(iffalse, LowerFailure):
        return iffalse
    return SsaExpr(
        "ite",
        int(expr.bits),
        (_coerce_width(cond, 1), _coerce_width(iftrue, int(expr.bits)), _coerce_width(iffalse, int(expr.bits))),
    )


def _lower_ail_binop(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    args: list[SsaExpr] = []
    for operand in expr.operands:
        lowered = _lower_ail_expr(
            operand, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
        )
        if isinstance(lowered, LowerFailure):
            return lowered
        args.append(lowered)
    if len(args) != 2:
        return LowerFailure("unsupported_ir", f"unsupported AIL binop arity: {expr.op}")
    op = str(expr.op)
    width = int(expr.bits)
    signed = bool(getattr(expr, "signed", False))
    if op == "Concat":
        return SsaExpr("concat", width, tuple(args))
    op_map = {
        "Add": "add",
        "Sub": "sub",
        "Mul": "mul",
        "Mull": "smull" if signed else "umull",
        "Div": "sdiv" if signed else "udiv",
        "Mod": "srem" if signed else "urem",
        "And": "and",
        "LogicalAnd": "and",
        "Or": "or",
        "LogicalOr": "or",
        "Xor": "xor",
        "Shl": "shl",
        "Shr": "lshr",
        "Sar": "ashr",
        "CmpEQ": "eq",
        "CmpNE": "ne",
        "CmpLT": "slt" if signed else "ult",
        "CmpLE": "sle" if signed else "ule",
        "CmpGT": "sgt" if signed else "ugt",
        "CmpGE": "sge" if signed else "uge",
    }
    lowered_op = op_map.get(op)
    if lowered_op is None:
        return LowerFailure("unsupported_ir", f"unsupported AIL binop: {op}")
    if lowered_op in {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}:
        return SsaExpr(lowered_op, 1, (_coerce_width(args[0], args[1].width), args[1]))
    if lowered_op in {"shl", "lshr", "ashr"}:
        return SsaExpr(lowered_op, width, (_coerce_width(args[0], width), args[1]))
    if lowered_op in {"umull", "smull"}:
        return SsaExpr(lowered_op, width, tuple(args))
    if lowered_op in {"udiv", "sdiv", "urem", "srem"}:
        return SsaExpr(lowered_op, width, tuple(_coerce_width(arg, width) for arg in args))
    return SsaExpr(lowered_op, width, tuple(_coerce_width(arg, width) for arg in args))


def _lower_ail_unop(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    operand = _lower_ail_expr(
        expr.operand, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(operand, LowerFailure):
        return operand
    op = str(expr.op)
    width = int(expr.bits)
    if op in {"BitwiseNeg", "Not"}:
        return SsaExpr("not", width, (_coerce_width(operand, width),))
    if op == "Neg":
        return SsaExpr("sub", width, (SsaExpr("const", width, value=0), _coerce_width(operand, width)))
    return LowerFailure("unsupported_ir", f"unsupported AIL unop: {op}")


def _lower_ail_extract(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    base = _lower_ail_expr(
        expr.base, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(base, LowerFailure):
        return base
    offset = _lower_ail_expr(
        expr.offset, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(offset, LowerFailure):
        return offset
    offset_value = _const_value(offset)
    if offset_value is None:
        return LowerFailure("unsupported_ir", "AIL dynamic bit extract offset is not modeled")
    shifted = SsaExpr(
        "lshr", base.width, (_coerce_width(base, base.width), SsaExpr("const", 8, value=offset_value & 0xFF))
    )
    return _coerce_width(shifted, int(expr.bits))


def _lower_ail_insert(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    base = _lower_ail_expr(
        expr.base, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(base, LowerFailure):
        return base
    value = _lower_ail_expr(
        expr.value, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(value, LowerFailure):
        return value
    offset = _lower_ail_expr(
        expr.offset, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory
    )
    if isinstance(offset, LowerFailure):
        return offset
    offset_value = _const_value(offset)
    if offset_value is None:
        return LowerFailure("unsupported_ir", "AIL dynamic bit insert offset is not modeled")
    width = int(expr.bits)
    value_width = int(value.width)
    mask = ((_mask(value_width) << offset_value) ^ _mask(width)) & _mask(width)
    cleared = SsaExpr("and", width, (_coerce_width(base, width), SsaExpr("const", width, value=mask)))
    shifted = SsaExpr("shl", width, (_coerce_width(value, width), SsaExpr("const", 8, value=offset_value & 0xFF)))
    return SsaExpr("or", width, (cleared, shifted))


def _read_register(reg_versions: dict[str, SsaExpr], offset: int, width: int, *, source: str) -> SsaExpr | LowerFailure:
    reg = REG_BY_OFFSET.get(offset)
    if reg is not None and width == reg[1]:
        if reg[0] == "flags":
            return SsaExpr("input", width, name="flags")
        return reg_versions.get(reg[0], SsaExpr("input", width, name=reg[0]))
    byte_access = BYTE_REGISTER_ACCESS.get(offset)
    if byte_access is not None and width == 8:
        base_name, high = byte_access
        full = reg_versions.get(base_name, SsaExpr("input", 16, name=base_name))
        if high:
            shifted = SsaExpr("lshr", 16, (_coerce_width(full, 16), SsaExpr("const", 8, value=8)))
            return _coerce_width(shifted, 8)
        return _coerce_width(full, 8)
    reg32 = REG32_BY_OFFSET.get(offset)
    if reg32 is not None and width == 32:
        hi_name, low_name = reg32
        low = reg_versions.get(low_name, SsaExpr("input", 16, name=low_name))
        hi = reg_versions.get(hi_name, SsaExpr("input", 16, name=hi_name))
        shifted_hi = SsaExpr(
            "shl",
            32,
            (_coerce_width(hi, 32), SsaExpr("const", 8, value=16)),
        )
        return SsaExpr("or", 32, (shifted_hi, _coerce_width(low, 32)))
    hi_name = REG32_HI16_BY_OFFSET.get(offset)
    if hi_name is not None and width == 16:
        return reg_versions.get(hi_name, SsaExpr("input", 16, name=hi_name))
    if reg is None:
        return LowerFailure("unsupported_ir", f"unsupported {source} register offset {offset}")
    return LowerFailure("unsupported_ir", f"unsupported {source} register access: offset {offset} width {width}")


def _register_write_target(offset: int, width: int | None) -> tuple[str, int] | None:
    reg = REG_BY_OFFSET.get(offset)
    if reg is not None and (width is None or width == reg[1]):
        return reg
    byte_access = BYTE_REGISTER_ACCESS.get(offset)
    if byte_access is not None and (width is None or width == 8):
        return byte_access[0], 16
    reg32 = REG32_BY_OFFSET.get(offset)
    if reg32 is not None and (width is None or width == 32):
        return reg32[0].removesuffix("_hi"), 32
    hi_name = REG32_HI16_BY_OFFSET.get(offset)
    if hi_name is not None and (width is None or width == 16):
        return hi_name, 16
    return None


def _write_register(reg_versions: dict[str, SsaExpr], offset: int, expr: SsaExpr) -> LowerFailure | None:
    reg = REG_BY_OFFSET.get(offset)
    if reg is not None and expr.width == reg[1]:
        reg_versions[reg[0]] = _coerce_width(expr, reg[1])
        return None
    byte_access = BYTE_REGISTER_ACCESS.get(offset)
    if byte_access is not None and expr.width == 8:
        base_name, high = byte_access
        full = reg_versions.get(base_name, SsaExpr("input", 16, name=base_name))
        data = _coerce_width(expr, 8)
        if high:
            cleared = SsaExpr("and", 16, (_coerce_width(full, 16), SsaExpr("const", 16, value=0x00FF)))
            shifted = SsaExpr("shl", 16, (_coerce_width(data, 16), SsaExpr("const", 8, value=8)))
            masked = SsaExpr("and", 16, (shifted, SsaExpr("const", 16, value=0xFF00)))
            reg_versions[base_name] = SsaExpr("or", 16, (cleared, masked))
            return None
        cleared = SsaExpr("and", 16, (_coerce_width(full, 16), SsaExpr("const", 16, value=0xFF00)))
        reg_versions[base_name] = SsaExpr("or", 16, (cleared, _coerce_width(data, 16)))
        return None
    reg32 = REG32_BY_OFFSET.get(offset)
    if reg32 is not None and expr.width == 32:
        hi_name, low_name = reg32
        reg_versions[low_name] = _coerce_width(expr, 16)
        shifted = SsaExpr("lshr", 32, (expr, SsaExpr("const", 8, value=16)))
        reg_versions[hi_name] = _coerce_width(shifted, 16)
        return None
    hi_name = REG32_HI16_BY_OFFSET.get(offset)
    if hi_name is not None and expr.width == 16:
        reg_versions[hi_name] = expr
        return None
    if reg is None and byte_access is None:
        return LowerFailure("unsupported_ir", f"unsupported register offset {offset}")
    return LowerFailure("unsupported_ir", f"unsupported register write: offset {offset} width {expr.width}")


def _const_value(expr: SsaExpr) -> int | None:
    return expr.value if expr.op == "const" else None


def _is_unobserved_flags_write(offset: int, output_regs: tuple[str, ...]) -> bool:
    reg = REG_BY_OFFSET.get(offset)
    return reg is not None and reg[0] == "flags" and "flags" not in output_regs


def _lower_expr(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    const = _vex_const_leaf(expr)
    if const is not None:
        return const
    tag = expr.tag
    leaf = _vex_leaf_expr(
        tag,
        expr,
        temp_defs=temp_defs,
        temp_failures=temp_failures,
        reg_versions=reg_versions,
        tyenv=tyenv,
    )
    if leaf is not None:
        return leaf
    kwargs = {
        "temp_defs": temp_defs,
        "temp_failures": temp_failures,
        "reg_versions": reg_versions,
        "tyenv": tyenv,
        "memory": memory,
    }
    if tag == "Iex_Binop":
        return _lower_binop(expr, **kwargs)
    if tag == "Iex_Unop":
        return _lower_unop(expr, **kwargs)
    if tag == "Iex_ITE":
        return _lower_vex_ite(expr, **kwargs)
    if tag == "Iex_Load":
        return _lower_vex_load(expr, **kwargs)
    return LowerFailure("unsupported_ir", f"unsupported VEX expression: {tag}")


def _vex_const_leaf(expr: Any) -> SsaExpr | None:  # noqa: ANN401
    """Lower const-like VEX leaves (untagged consts and Ico_ constants)."""
    if not hasattr(expr, "tag") and hasattr(expr, "size") and hasattr(expr, "value"):
        return SsaExpr("const", int(expr.size), value=int(expr.value) & _mask(int(expr.size)))
    if str(expr.tag).startswith("Ico_") and hasattr(expr, "size") and hasattr(expr, "value"):
        return SsaExpr("const", int(expr.size), value=int(expr.value) & _mask(int(expr.size)))
    return None


def _vex_leaf_expr(
    tag: Any,  # noqa: ANN401
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
) -> SsaExpr | LowerFailure | None:
    """Lower leaf VEX tags (RdTmp/Get/Const); None for structural tags."""
    if tag == "Iex_RdTmp":
        tmp = int(expr.tmp)
        if tmp in temp_failures:
            return temp_failures[tmp]
        if tmp not in temp_defs:
            return LowerFailure("unsupported_ir", f"read of undefined VEX tmp t{tmp}")
        return temp_defs[tmp]
    if tag == "Iex_Get":
        width = int(expr.result_size(tyenv))
        return _read_register(reg_versions, int(expr.offset), width, source="VEX")
    if tag == "Iex_Const":
        return SsaExpr("const", int(expr.con.size), value=int(expr.con.value) & _mask(int(expr.con.size)))
    return None


def _lower_vex_ite(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    """Lower Iex_ITE into an ite SsaExpr."""
    kwargs = {
        "temp_defs": temp_defs,
        "temp_failures": temp_failures,
        "reg_versions": reg_versions,
        "tyenv": tyenv,
        "memory": memory,
    }
    cond = _lower_expr(expr.cond, **kwargs)
    if isinstance(cond, LowerFailure):
        return cond
    iftrue = _lower_expr(expr.iftrue, **kwargs)
    if isinstance(iftrue, LowerFailure):
        return iftrue
    iffalse = _lower_expr(expr.iffalse, **kwargs)
    if isinstance(iffalse, LowerFailure):
        return iffalse
    return SsaExpr("ite", int(expr.result_size(tyenv)), (_coerce_width(cond, 1), iftrue, iffalse))


def _lower_vex_load(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    """Lower Iex_Load against the current memory version."""
    addr = _lower_expr(
        expr.addr,
        temp_defs=temp_defs,
        temp_failures=temp_failures,
        reg_versions=reg_versions,
        tyenv=tyenv,
        memory=memory,
    )
    if isinstance(addr, LowerFailure):
        return addr
    endness = str(getattr(expr, "endness", "Iend_LE"))
    if endness not in {"Iend_LE", "Iend_BE"}:
        return LowerFailure("unsupported_ir", f"unsupported VEX load endness: {endness}")
    op = "loadle" if endness == "Iend_LE" else "loadbe"
    return SsaExpr(op, int(expr.result_size(tyenv)), (memory, _coerce_width(addr, 32)))


def _lower_binop(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    op = _strip_iop(str(expr.op))
    base = _normalize_binop(op)
    lowered_op = SUPPORTED_BINOPS.get(base)
    if lowered_op is None:
        return LowerFailure("unsupported_ir", f"unsupported VEX binop: {op}")
    args: list[SsaExpr] = []
    for arg in expr.args:
        lowered = _lower_expr(
            arg, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=tyenv, memory=memory
        )
        if isinstance(lowered, LowerFailure):
            return lowered
        args.append(lowered)
    width = int(expr.result_size(tyenv))
    if lowered_op in {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}:
        return SsaExpr(lowered_op, 1, (_coerce_width(args[0], args[1].width), args[1]))
    if lowered_op in {"shl", "lshr", "ashr"}:
        return SsaExpr(lowered_op, width, (_coerce_width(args[0], width), args[1]))
    if lowered_op in {"umull", "smull"}:
        return SsaExpr(lowered_op, width, tuple(args))
    if lowered_op in {"udiv", "sdiv", "urem", "srem"}:
        return SsaExpr(lowered_op, width, tuple(_coerce_width(arg, width) for arg in args))
    return SsaExpr(lowered_op, width, tuple(_coerce_width(arg, width) for arg in args))


def _lower_unop(
    expr: Any,  # noqa: ANN401
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,  # noqa: ANN401
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    op = _strip_iop(str(expr.op))
    if len(expr.args) != 1:
        return LowerFailure("unsupported_ir", f"unsupported VEX unop arity: {op}")
    arg = _lower_expr(
        expr.args[0],
        temp_defs=temp_defs,
        temp_failures=temp_failures,
        reg_versions=reg_versions,
        tyenv=tyenv,
        memory=memory,
    )
    if isinstance(arg, LowerFailure):
        return arg
    width = int(expr.result_size(tyenv))
    if op.startswith("Not"):
        return SsaExpr("not", width, (_coerce_width(arg, width),))
    if "Uto" in op:
        return SsaExpr("zext", width, (arg,))
    if "Sto" in op:
        return SsaExpr("sext", width, (arg,))
    if "to" in op:
        return SsaExpr("trunc", width, (arg,))
    return LowerFailure("unsupported_ir", f"unsupported VEX unop: {op}")


def _materialize(
    expr: SsaExpr,
    *,
    assignments: list[dict[str, Any]],
    memo: dict[tuple[Any, ...], str],
    object_memo: dict[int, dict[str, Any]],
    max_assignments_per_function: int,
) -> dict[str, Any]:
    if expr.op == "input":
        return {"op": "input", "name": expr.name, "width": expr.width}
    if expr.op == "mem_input":
        return {"op": "mem_input", "name": expr.name, "addr_width": 32, "value_width": 8}
    if expr.op == "const":
        return {"op": "const", "value": normalize_hex(expr.value or 0), "width": expr.width}
    ident = id(expr)
    cached = object_memo.get(ident)
    if cached is not None:
        return dict(cached)
    if max_assignments_per_function > 0 and len(assignments) >= max_assignments_per_function:
        raise LowerFailure(
            "slice_too_large",
            f"SSA assignment limit reached before materializing {expr.op}: {len(assignments)} >= {max_assignments_per_function}",
        )
    args = [
        _materialize(
            arg,
            assignments=assignments,
            memo=memo,
            object_memo=object_memo,
            max_assignments_per_function=max_assignments_per_function,
        )
        for arg in expr.args
    ]
    key = _materialized_expr_key(expr, args)
    if key in memo:
        result = {"ref": memo[key]}
        object_memo[ident] = result
        return dict(result)
    if max_assignments_per_function > 0 and len(assignments) >= max_assignments_per_function:
        raise LowerFailure(
            "slice_too_large",
            f"SSA assignment limit reached: {len(assignments)} >= {max_assignments_per_function}",
        )
    assignment_id = f"v{len(assignments)}"
    memo[key] = assignment_id
    assignments.append({"id": assignment_id, "op": expr.op, "width": expr.width, "args": args})
    result = {"ref": assignment_id}
    object_memo[ident] = result
    return dict(result)


def _materialized_expr_key(expr: SsaExpr, args: list[dict[str, Any]]) -> tuple[Any, ...]:
    return (expr.op, expr.width, expr.value, expr.name, tuple(_freeze_json_like(arg) for arg in args))


def _freeze_json_like(value: Any) -> Any:  # noqa: ANN401
    if isinstance(value, dict):
        return tuple((key, _freeze_json_like(value[key])) for key in sorted(value))
    if isinstance(value, list):
        return tuple(_freeze_json_like(item) for item in value)
    return value


def _expr_key(expr: SsaExpr, key_cache: dict[int, tuple[Any, ...]]) -> tuple[Any, ...]:
    ident = id(expr)
    cached = key_cache.get(ident)
    if cached is not None:
        return cached
    key = (expr.op, expr.width, expr.value, expr.name, tuple(_expr_key(arg, key_cache) for arg in expr.args))
    key_cache[ident] = key
    return key


def _ssa_solver_gate(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    *,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
) -> dict[str, Any] | None:
    sides = (("oracle", oracle), ("candidate", candidate))
    for violation in (
        _solver_count_gate(sides, "assignments", max_solver_assignments, _ssa_assignment_count),
        _solver_count_gate(sides, "inputs", max_solver_inputs, _ssa_input_count),
        _solver_count_gate(sides, "memory_stores", max_solver_memory_stores, _ssa_memory_store_gate_count),
    ):
        if violation is not None:
            return violation
    return None


def _ssa_assignment_count(function: dict[str, Any]) -> int | None:
    """Count SSA assignments for solver gating."""
    return len(function.get("assignments", []) or [])


def _ssa_input_count(function: dict[str, Any]) -> int | None:
    """Count SSA inputs for solver gating."""
    return len(function.get("inputs", []) or [])


def _ssa_memory_store_gate_count(function: dict[str, Any]) -> int | None:
    """Count memory stores only when the function has a memory output."""
    outputs = function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}
    if "memory" not in outputs:
        return None
    return _ssa_store_count(function)


def _solver_count_gate(
    sides: tuple[tuple[str, dict[str, Any]], ...],
    metric: str,
    limit: int,
    count_fn: Callable[[dict[str, Any]], int | None],
) -> dict[str, Any] | None:
    """Apply one solver budget metric across oracle/candidate; return the violation dict."""
    if limit <= 0:
        return None
    for side, function in sides:
        count = count_fn(function)
        if count is None:
            continue
        if count > limit:
            return {
                "kind": "solver_gate",
                "reason": "slice_too_large",
                "detail": f"{side} SSA {_solver_metric_label(metric)} {count} exceeds solver gate {limit}",
                "side": side,
                "metric": metric,
                "value": count,
                "limit": limit,
            }
    return None


def _solver_metric_label(metric: str) -> str:
    """Human-readable metric label for solver gate details."""
    return {
        "assignments": "assignment count",
        "inputs": "input count",
        "memory_stores": "memory store count",
    }[metric]


def _ssa_store_count(function: dict[str, Any]) -> int:
    return sum(
        1
        for item in function.get("assignments", []) or []
        if isinstance(item, dict) and item.get("op") in {"storele", "storebe"}
    )


def _prepare_local_block_output_projection(
    oracle_function: dict[str, Any],
    candidate_function: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    if not _has_direct_successor_transfer(oracle_function) or not _has_direct_successor_transfer(candidate_function):
        return oracle_function, candidate_function, None
    oracle_outputs = set((oracle_function.get("outputs", {}) or {}).keys())
    candidate_outputs = set((candidate_function.get("outputs", {}) or {}).keys())
    keep = sorted((oracle_outputs | candidate_outputs) & {"ip", "memory", "sp"})
    if not keep:
        return oracle_function, candidate_function, None
    if set(keep) == oracle_outputs and set(keep) == candidate_outputs:
        return oracle_function, candidate_function, None
    return (
        _project_ssa_outputs(oracle_function, keep),
        _project_ssa_outputs(candidate_function, keep),
        {
            "kind": "local_block_outputs",
            "reason": "nonterminal direct-successor block; register state is checked by connectivity liveness",
            "outputs": keep,
            "oracle_dropped": sorted(oracle_outputs - set(keep)),
            "candidate_dropped": sorted(candidate_outputs - set(keep)),
        },
    )


def _has_direct_successor_transfer(function: dict[str, Any]) -> bool:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else {}
    return transfer.get("kind") == "direct_successors"


def _compare_ssa_pair(
    item: dict[str, Any],
    *,
    mapping_document: dict[str, Any] | None,
    oracle_index: dict[str, dict[Any, dict[str, Any]]],
    candidate_index: dict[str, dict[Any, dict[str, Any]]],
    allow_aliased_call_targets: bool,
    proof_cache: _SemanticEqualityCache | None,
    timeout_ms: int,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
    skip_binary_equal: bool,
    max_rss_mb: int = 0,
) -> tuple[dict[str, Any], int]:
    oracle_function = item["oracle_function"]
    candidate_function = item["candidate_function"]
    mapped = item.get("mapped")
    function_id = str(item.get("function_id") or "")
    function_name = str(item.get("function_name") or function_id)
    call_compare = _compare_call_targets(
        oracle_function,
        candidate_function,
        mapping_document=mapping_document,
        oracle_index=oracle_index,
        candidate_index=candidate_index,
        allow_aliased_call_targets=allow_aliased_call_targets,
        proof_cache=proof_cache,
        require_proven_call_targets=proof_cache is not None,
    )
    base = {
        "function": {"id": function_id, "name": function_name},
        "oracle_function": oracle_function.get("id"),
        "candidate_function": candidate_function.get("id"),
        "mapped_candidate": _mapped_candidate_detail(mapped),
        "oracle_detail": _ssa_function_report_detail(oracle_function),
        "candidate_detail": _ssa_function_report_detail(candidate_function),
        "call_compare": call_compare,
    }
    oracle_jumpkind = str(
        (oracle_function.get("source") if isinstance(oracle_function.get("source"), dict) else {}).get("jumpkind")
        or ""
    )
    candidate_jumpkind = str(
        (candidate_function.get("source") if isinstance(candidate_function.get("source"), dict) else {}).get(
            "jumpkind"
        )
        or ""
    )
    boundary_detail: dict[str, Any] | None = None
    if oracle_jumpkind and candidate_jumpkind and oracle_jumpkind != candidate_jumpkind:
        boundary_detail = {
            "oracle_jumpkind": oracle_jumpkind,
            "candidate_jumpkind": candidate_jumpkind,
        }
    else:
        oracle_stack_ops = _stack_op_sequence(oracle_function)
        candidate_stack_ops = _stack_op_sequence(candidate_function)
        if oracle_stack_ops != candidate_stack_ops:
            boundary_detail = {
                "oracle_stack_ops": oracle_stack_ops,
                "candidate_stack_ops": candidate_stack_ops,
            }
    if boundary_detail is not None:
        return (
            {
                **base,
                "status": "refused",
                "reason": "part_boundary_mismatch",
                "layout_normalization": None,
                "output_projection": None,
                "mismatches": [
                    {
                        "kind": "part_boundary_mismatch",
                        "detail": "oracle and candidate SSA parts do not cover corresponding instruction slices; region-level comparison must decide",
                        **boundary_detail,
                    }
                ],
            },
            0,
        )
    if isinstance(call_compare, dict) and call_compare.get("reason") == "callee_not_proven":
        return (
            {
                **base,
                "status": "refused",
                "reason": "callee_not_proven",
                "layout_normalization": None,
                "mismatches": [
                    {
                        "kind": "callee_not_proven",
                        "detail": "direct call targets are only mapped/name-equivalent; caller proof waits for a callee equality fact",
                        "unproven_reason": call_compare.get("unproven_reason"),
                    }
                ],
            },
            0,
        )
    if isinstance(call_compare, dict) and call_compare.get("equivalent") is False:
        oracle_target = call_compare.get("oracle") or {}
        candidate_target = call_compare.get("candidate") or {}
        oracle_resolved = oracle_target.get("resolved") or {}
        candidate_resolved = candidate_target.get("resolved") or {}
        oracle_lib = str(oracle_resolved.get("id") or "").startswith("library-signature:")
        candidate_lib = str(candidate_resolved.get("id") or "").startswith("library-signature:")
        both_unresolved = not oracle_target.get("resolved") and not candidate_target.get("resolved")
        both_resolved = bool(oracle_target.get("resolved")) and bool(candidate_target.get("resolved"))
        divergent = call_compare.get("reason") == "direct call targets resolve to different mapped functions"
        if divergent:
            detail = None
        elif (oracle_lib and candidate_lib) or both_unresolved:
            detail = "direct call resolves to unmapped runtime stubs in both binaries; equivalence cannot be proven"
        elif both_resolved:
            detail = "direct calls resolve to functions whose equivalence is unproven; callee-level compare owns the verdict"
        else:
            detail = "one direct call target resolved and the other did not; equivalence cannot be proven"
        if detail is not None:
            return (
                {
                    **base,
                    "status": "refused",
                    "reason": "call_target_unproven",
                    "layout_normalization": None,
                    "output_projection": None,
                    "mismatches": [
                        {
                            "kind": "call_target_unproven",
                            "detail": detail,
                            "oracle_target": oracle_resolved.get("id") or oracle_target.get("raw"),
                            "candidate_target": candidate_resolved.get("id") or candidate_target.get("raw"),
                            "call_reason": call_compare.get("reason"),
                        }
                    ],
                },
                0,
            )
    oracle_for_z3, candidate_for_z3, call_compare = _prepare_call_normalized_functions(
        oracle_function,
        candidate_function,
        call_compare=call_compare,
    )
    base["call_compare"] = call_compare
    oracle_for_z3, candidate_for_z3, layout_normalization = _prepare_layout_normalized_functions(
        oracle_for_z3,
        candidate_for_z3,
        global_map=item.get("global_constant_normalization")
        if isinstance(item.get("global_constant_normalization"), dict)
        else None,
        image_context=item.get("image_context")
        if isinstance(item.get("image_context"), dict)
        else None,
    )
    oracle_for_z3, candidate_for_z3, output_projection = _prepare_local_block_output_projection(
        oracle_for_z3,
        candidate_for_z3,
    )
    quick = _quick_compare_functions(oracle_for_z3, candidate_for_z3, skip_binary_equal=skip_binary_equal)
    if quick is not None:
        return (
            {
                **base,
                "status": quick["status"],
                "reason": quick.get("reason"),
                "layout_normalization": layout_normalization,
                "output_projection": output_projection,
                "mismatches": quick.get("mismatches", []),
            },
            0,
        )
    gate = _ssa_solver_gate(
        oracle_for_z3,
        candidate_for_z3,
        max_solver_assignments=max_solver_assignments,
        max_solver_inputs=max_solver_inputs,
        max_solver_memory_stores=max_solver_memory_stores,
    )
    if gate is not None:
        return (
            {
                **base,
                "status": "refused",
                "reason": gate["reason"],
                "layout_normalization": layout_normalization,
                "output_projection": output_projection,
                "mismatches": [gate],
            },
            0,
        )
    memory_limit = _compare_memory_limit_status(max_rss_mb)
    if memory_limit is not None:
        aborted = _compare_memory_abort("ssa_pair", memory_limit)
        return (
            {
                **base,
                "status": "refused",
                "reason": "memory_limit",
                "layout_normalization": layout_normalization,
                "output_projection": output_projection,
                "mismatches": [_memory_limit_mismatch(aborted)],
            },
            0,
        )
    comparison = _compare_functions(oracle_for_z3, candidate_for_z3, timeout_ms=timeout_ms)
    elapsed = int(comparison.pop("solver_time_ms", 0))
    return (
        {
            **base,
            "status": comparison["status"],
            "reason": comparison.get("reason"),
            "layout_normalization": layout_normalization,
            "output_projection": output_projection,
            "mismatches": comparison.get("mismatches", []),
            "skipped_layout_outputs": comparison.get("skipped_layout_outputs", []),
        },
        elapsed,
    )


def _compare_ssa_pair_guarded(
    item: dict[str, Any],
    *,
    mapping_document: dict[str, Any],
    oracle_index: dict[str, Any],
    candidate_index: dict[str, Any],
    allow_aliased_call_targets: bool,
    proof_cache: Any,
    timeout_ms: int,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
    skip_binary_equal: bool,
    max_rss_mb: int,
) -> tuple[dict[str, Any], int]:
    """Run one SSA pair compare; typed evaluator errors become explicit refusals.

    One bad pair must not kill a whole batch: TypeError/ValueError/KeyError surface
    as `refused/evaluator_error` rows carrying the exception detail. All other
    exception types still propagate.
    """
    try:
        return _compare_ssa_pair(
            item,
            mapping_document=mapping_document,
            oracle_index=oracle_index,
            candidate_index=candidate_index,
            allow_aliased_call_targets=allow_aliased_call_targets,
            proof_cache=proof_cache,
            timeout_ms=timeout_ms,
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
            skip_binary_equal=skip_binary_equal,
            max_rss_mb=max_rss_mb,
        )
    except (TypeError, ValueError, KeyError) as error:
        oracle_function = item.get("oracle_function") if isinstance(item.get("oracle_function"), dict) else {}
        candidate_function = item.get("candidate_function") if isinstance(item.get("candidate_function"), dict) else None
        return (
            {
                "status": "refused",
                "reason": "evaluator_error",
                "function": {"id": item.get("function_id"), "name": item.get("function_name")},
                "oracle_function": oracle_function.get("id"),
                "candidate_function": candidate_function.get("id") if candidate_function else None,
                "mapped_candidate": _mapped_candidate_detail(item.get("mapped")),
                "oracle_detail": _ssa_function_report_detail(oracle_function),
                "candidate_detail": _ssa_function_report_detail(candidate_function) if candidate_function else None,
                "mismatches": [
                    {
                        "kind": "evaluator_error",
                        "error_type": type(error).__name__,
                        "detail": str(error),
                    }
                ],
            },
            0,
        )


def _compare_external_oracle_parts(
    *,
    oracle_external_functions: list[dict[str, Any]],
    candidate_functions: list[dict[str, Any]],
    mapping_document: dict[str, Any] | None,
    oracle_index: dict[str, dict[Any, dict[str, Any]]],
    candidate_index: dict[str, dict[Any, dict[str, Any]]],
    allow_aliased_call_targets: bool,
    proof_cache: _SemanticEqualityCache | None,
    timeout_ms: int,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
    skip_binary_equal: bool,
    max_rss_mb: int = 0,
) -> dict[str, Any]:
    mapped_candidates = _ssa_candidate_mapping(mapping_document) if mapping_document is not None else {}
    candidate_by_id_delta = _functions_by_id_and_delta(candidate_functions)
    candidate_by_key_delta = _functions_by_name_and_delta(candidate_functions)
    candidate_by_id_part = _functions_by_id_and_part(candidate_functions)
    candidate_by_key_part = _functions_by_name_and_part(candidate_functions)
    candidate_by_id_exact_signature = _functions_by_id_and_exact_block_signature(candidate_functions)
    candidate_by_key_exact_signature = _functions_by_name_and_exact_block_signature(candidate_functions)
    candidate_by_id_signature = _functions_by_id_and_block_signature(candidate_functions)
    candidate_by_key_signature = _functions_by_name_and_block_signature(candidate_functions)
    candidate_by_exact_signature = _functions_by_exact_block_signature(candidate_functions)
    candidate_by_signature = _functions_by_block_signature(candidate_functions)
    candidate_by_id_delta_any = _functions_by_id_and_delta(candidate_functions)
    candidate_by_key_delta_any = _functions_by_name_and_delta(candidate_functions)
    results: list[dict[str, Any]] = []
    solver_time_ms = 0
    matched_by_oracle_id: dict[str, dict[str, Any]] = {}

    for oracle_function in oracle_external_functions:
        memory_limit = _compare_memory_limit_status(max_rss_mb)
        if memory_limit is not None:
            aborted = _compare_memory_abort("external_parts", memory_limit)
            results.append(_memory_limit_compare_result(aborted))
            solver_time_ms = 0
            status = "refused"
            return {
                "enabled": True,
                "status": status,
                "total": len(results),
                "passed": sum(1 for result in results if result.get("status") == "passed"),
                "failed": sum(1 for result in results if result.get("status") == "failed"),
                "refused": sum(1 for result in results if result.get("status") == "refused"),
                "unproved": sum(1 for result in results if result.get("status") != "passed"),
                "solver_time_ms": solver_time_ms,
                "aborted": aborted,
                "results": results,
            }
        function = oracle_function.get("function", {}) if isinstance(oracle_function, dict) else {}
        function_id = str(function.get("id", ""))
        function_name = str(function.get("name", function_id))
        mapped = mapped_candidates.get(function_id) or mapped_candidates.get(function_name)
        candidate_function, match_reason = _candidate_for_external_part(
            oracle_function,
            mapped=mapped,
            candidate_by_id_delta=candidate_by_id_delta,
            candidate_by_key_delta=candidate_by_key_delta,
            candidate_by_id_part=candidate_by_id_part,
            candidate_by_key_part=candidate_by_key_part,
            candidate_by_id_exact_signature=candidate_by_id_exact_signature,
            candidate_by_key_exact_signature=candidate_by_key_exact_signature,
            candidate_by_id_signature=candidate_by_id_signature,
            candidate_by_key_signature=candidate_by_key_signature,
            candidate_by_exact_signature=candidate_by_exact_signature,
            candidate_by_signature=candidate_by_signature,
            prior_matches=matched_by_oracle_id,
            oracle_external_functions=oracle_external_functions,
            candidate_by_id_delta_any=candidate_by_id_delta_any,
            candidate_by_key_delta_any=candidate_by_key_delta_any,
            candidate_functions=candidate_functions,
        )
        if candidate_function is None:
            stream_match = _external_part_covered_by_candidate_instruction_stream(
                oracle_function,
                mapped=mapped,
                candidate_functions=candidate_functions,
            )
            if stream_match is not None:
                results.append(
                    {
                        "status": "passed",
                        "reason": "covered_by_candidate_instruction_stream",
                        "function": {"id": function_id, "name": function_name},
                        "oracle_function": oracle_function.get("id"),
                        "candidate_function": stream_match.get("candidate_function"),
                        "mapped_candidate": _mapped_candidate_detail(mapped),
                        "oracle_detail": _ssa_function_report_detail(oracle_function),
                        "candidate_detail": stream_match.get("candidate_detail"),
                        "external_part": {
                            "kind": "external_or_shared_tail",
                            "match_reason": "candidate_instruction_stream_contains_oracle_slice",
                        },
                        "instruction_stream_match": stream_match.get("instruction_stream_match"),
                        "mismatches": [],
                    }
                )
                continue
            results.append(
                {
                    "status": "refused",
                    "reason": "candidate_external_part_missing",
                    "function": {"id": function_id, "name": function_name},
                    "oracle_function": oracle_function.get("id"),
                    "candidate_function": None,
                    "mapped_candidate": _mapped_candidate_detail(mapped),
                    "oracle_detail": _ssa_function_report_detail(oracle_function),
                    "candidate_detail": None,
                    "external_part": {
                        "kind": "external_or_shared_tail",
                        "match_reason": match_reason,
                    },
                    "mismatches": [
                        {
                            "kind": "external_part_unmatched",
                            "detail": "out-of-body oracle SSA part has no unique candidate block by delta or block signature",
                        }
                    ],
                }
            )
            continue
        item = {
            "oracle_function": oracle_function,
            "candidate_function": candidate_function,
            "mapped": mapped,
            "function_id": function_id,
            "function_name": function_name,
        }
        result, elapsed = _compare_ssa_pair_guarded(
            item,
            mapping_document=mapping_document,
            oracle_index=oracle_index,
            candidate_index=candidate_index,
            allow_aliased_call_targets=allow_aliased_call_targets,
            proof_cache=proof_cache,
            timeout_ms=timeout_ms,
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
            skip_binary_equal=skip_binary_equal,
            max_rss_mb=max_rss_mb,
        )
        solver_time_ms += elapsed
        result["external_part"] = {
            "kind": "external_or_shared_tail",
            "match_reason": match_reason,
        }
        results.append(result)
        if result.get("status") == "passed":
            matched_by_oracle_id[str(oracle_function.get("id"))] = candidate_function

    failed = sum(1 for result in results if result.get("status") == "failed")
    refused = sum(1 for result in results if result.get("status") == "refused")
    passed = sum(1 for result in results if result.get("status") == "passed")
    status = "not_applicable"
    if failed:
        status = "failed"
    elif refused:
        status = "refused"
    elif results:
        status = "passed"
    return {
        "enabled": True,
        "status": status,
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "refused": refused,
        "unproved": failed + refused,
        "solver_time_ms": solver_time_ms,
        "results": results,
    }


def _candidate_for_mapped_part_across_body_boundary(
    oracle_function: dict[str, Any],
    *,
    mapped: dict[str, Any] | None,
    candidate_by_id_delta: dict[tuple[str, str], dict[str, Any]],
    candidate_by_key_delta: dict[tuple[str, str], dict[str, Any]],
    candidate_by_id_part: dict[tuple[str, int], dict[str, Any]],
    candidate_by_key_part: dict[tuple[str, int], dict[str, Any]],
    candidate_by_id_exact_signature: dict[tuple[str, tuple[int, ...]], dict[str, Any]],
    candidate_by_key_exact_signature: dict[tuple[str, tuple[int, ...]], dict[str, Any]],
    candidate_by_id_signature: dict[tuple[str, tuple[int | None, ...]], dict[str, Any]],
    candidate_by_key_signature: dict[tuple[str, tuple[int | None, ...]], dict[str, Any]],
) -> dict[str, Any] | None:
    if not isinstance(mapped, dict):
        return None
    candidate_id = str(mapped.get("candidate_id") or "")
    candidate_name = str(mapped.get("candidate_name") or "")
    sig_match = functools.partial(_ssa_block_signatures_match, oracle_function)

    part_delta = _ssa_part_delta(oracle_function)
    if part_delta:
        hit = _scan_candidate_index_pair(
            candidate_id, candidate_name, part_delta, candidate_by_id_delta, candidate_by_key_delta, (sig_match,)
        )
        if hit is not None:
            return hit

    hit = _scan_candidate_index_pair(
        candidate_id,
        candidate_name,
        _ssa_part_index(oracle_function),
        candidate_by_id_part,
        candidate_by_key_part,
        (sig_match,),
    )
    if hit is not None:
        return hit

    hit = _scan_candidate_index_pair(
        candidate_id,
        candidate_name,
        _ssa_exact_block_signature(oracle_function),
        candidate_by_id_exact_signature,
        candidate_by_key_exact_signature,
        (),
    )
    if hit is not None:
        return hit

    return _scan_candidate_index_pair(
        candidate_id,
        candidate_name,
        _ssa_block_signature(oracle_function),
        candidate_by_id_signature,
        candidate_by_key_signature,
        (),
    )


def _scan_candidate_index_pair(
    candidate_id: str,
    candidate_name: str,
    value: Any,  # noqa: ANN401
    id_index: dict[tuple[Any, ...], dict[str, Any]],
    key_index: dict[tuple[Any, ...], dict[str, Any]],
    predicates: tuple[Callable[[dict[str, Any]], bool], ...],
) -> dict[str, Any] | None:
    """Scan the (id, value) and (name, value) indexes, requiring every predicate on the hit."""
    for key, index in (
        ((candidate_id, value), id_index),
        ((candidate_name, value), key_index),
    ):
        hit = index.get(key) if key[0] else None
        if hit is not None and all(pred(hit) for pred in predicates):
            return hit
    return None


def _external_same_function_candidate(
    oracle_function: dict[str, Any],
    *,
    candidate_id: str,
    candidate_name: str,
    candidate_by_id_delta: dict[tuple[str, str], dict[str, Any]],
    candidate_by_key_delta: dict[tuple[str, str], dict[str, Any]],
    candidate_by_id_part: dict[tuple[str, int], dict[str, Any]],
    candidate_by_key_part: dict[tuple[str, int], dict[str, Any]],
    candidate_by_id_exact_signature: dict[tuple[str, tuple[int, ...]], dict[str, Any]],
    candidate_by_key_exact_signature: dict[tuple[str, tuple[int, ...]], dict[str, Any]],
    candidate_by_id_signature: dict[tuple[str, tuple[int | None, ...]], dict[str, Any]],
    candidate_by_key_signature: dict[tuple[str, tuple[int | None, ...]], dict[str, Any]],
) -> tuple[dict[str, Any] | None, str]:
    """Scan the same-function candidate indexes in priority order; return (hit, reason)."""
    sig_match = functools.partial(_ssa_block_signatures_match, oracle_function)
    part_delta = _ssa_part_delta(oracle_function)
    if part_delta:
        hit = _scan_candidate_index_pair(
            candidate_id, candidate_name, part_delta, candidate_by_id_delta, candidate_by_key_delta, (sig_match,)
        )
        if hit is not None:
            return hit, "same_function_delta"
    hit = _scan_candidate_index_pair(
        candidate_id,
        candidate_name,
        _ssa_part_index(oracle_function),
        candidate_by_id_part,
        candidate_by_key_part,
        (_ssa_part_outside_declared_body, sig_match),
    )
    if hit is not None:
        return hit, "same_function_part_index"
    hit = _scan_candidate_index_pair(
        candidate_id,
        candidate_name,
        _ssa_exact_block_signature(oracle_function),
        candidate_by_id_exact_signature,
        candidate_by_key_exact_signature,
        (),
    )
    if hit is not None:
        return hit, "same_function_exact_block_signature"
    hit = _scan_candidate_index_pair(
        candidate_id,
        candidate_name,
        _ssa_block_signature(oracle_function),
        candidate_by_id_signature,
        candidate_by_key_signature,
        (),
    )
    if hit is not None:
        return hit, "same_function_normalized_block_signature"
    return None, ""


def _candidate_for_external_part(
    oracle_function: dict[str, Any],
    *,
    mapped: dict[str, Any] | None,
    candidate_by_id_delta: dict[tuple[str, str], dict[str, Any]],
    candidate_by_key_delta: dict[tuple[str, str], dict[str, Any]],
    candidate_by_id_part: dict[tuple[str, int], dict[str, Any]],
    candidate_by_key_part: dict[tuple[str, int], dict[str, Any]],
    candidate_by_id_exact_signature: dict[tuple[str, tuple[int, ...]], dict[str, Any]],
    candidate_by_key_exact_signature: dict[tuple[str, tuple[int, ...]], dict[str, Any]],
    candidate_by_id_signature: dict[tuple[str, tuple[int | None, ...]], dict[str, Any]],
    candidate_by_key_signature: dict[tuple[str, tuple[int | None, ...]], dict[str, Any]],
    candidate_by_exact_signature: dict[tuple[int, ...], dict[str, Any]],
    candidate_by_signature: dict[tuple[int | None, ...], dict[str, Any]],
    prior_matches: dict[str, dict[str, Any]],
    oracle_external_functions: list[dict[str, Any]],
    candidate_by_id_delta_any: dict[tuple[str, str], dict[str, Any]],
    candidate_by_key_delta_any: dict[tuple[str, str], dict[str, Any]],
    candidate_functions: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    function = oracle_function.get("function", {}) if isinstance(oracle_function, dict) else {}
    oracle_id = str(function.get("id", ""))
    oracle_name = str(function.get("name", oracle_id))
    candidate_id = str(mapped.get("candidate_id") or "") if isinstance(mapped, dict) else oracle_id
    candidate_name = str(mapped.get("candidate_name") or "") if isinstance(mapped, dict) else oracle_name
    exact_signature = _ssa_exact_block_signature(oracle_function)
    signature = _ssa_block_signature(oracle_function)

    hit, reason = _external_same_function_candidate(
        oracle_function,
        candidate_id=candidate_id,
        candidate_name=candidate_name,
        candidate_by_id_delta=candidate_by_id_delta,
        candidate_by_key_delta=candidate_by_key_delta,
        candidate_by_id_part=candidate_by_id_part,
        candidate_by_key_part=candidate_by_key_part,
        candidate_by_id_exact_signature=candidate_by_id_exact_signature,
        candidate_by_key_exact_signature=candidate_by_key_exact_signature,
        candidate_by_id_signature=candidate_by_id_signature,
        candidate_by_key_signature=candidate_by_key_signature,
    )
    if hit is not None:
        return hit, reason
    if exact_signature is not None and exact_signature in candidate_by_exact_signature:
        return candidate_by_exact_signature[exact_signature], "global_exact_block_signature"
    if signature is not None and signature in candidate_by_signature:
        return candidate_by_signature[signature], "global_normalized_block_signature"
    chained = _candidate_for_external_part_by_matched_predecessor(
        oracle_function,
        prior_matches=prior_matches,
        oracle_external_functions=oracle_external_functions,
        candidate_by_id_delta=candidate_by_id_delta_any,
        candidate_by_key_delta=candidate_by_key_delta_any,
    )
    if chained is not None:
        return chained, "matched_predecessor_successor"
    ordinal = _candidate_for_external_part_by_signature_ordinal(
        oracle_function,
        mapped=mapped,
        oracle_external_functions=oracle_external_functions,
        candidate_functions=candidate_functions or [],
    )
    if ordinal is not None:
        return ordinal, "same_function_signature_ordinal"
    return None, "no_unique_candidate_by_delta_or_signature"


def _external_part_covered_by_candidate_instruction_stream(
    oracle_function: dict[str, Any],
    *,
    mapped: dict[str, Any] | None,
    candidate_functions: list[dict[str, Any]],
) -> dict[str, Any] | None:
    oracle_signature = _region_linear_instruction_signature([oracle_function])
    if oracle_signature is None or not oracle_signature["pattern"]:
        return None
    function = oracle_function.get("function", {}) if isinstance(oracle_function, dict) else {}
    oracle_id = str(function.get("id", ""))
    oracle_name = str(function.get("name", oracle_id))
    candidate_id = str(mapped.get("candidate_id") or "") if isinstance(mapped, dict) else oracle_id
    candidate_name = str(mapped.get("candidate_name") or "") if isinstance(mapped, dict) else oracle_name
    grouped = _group_stream_candidates(candidate_functions, candidate_id, candidate_name)
    for key in (candidate_id, candidate_name):
        match = _group_stream_match(grouped.get(key) or [], key, oracle_signature)
        if match is not None:
            return match
    return _global_stream_match(candidate_functions, oracle_signature)


def _group_stream_candidates(
    candidate_functions: list[dict[str, Any]],
    candidate_id: str,
    candidate_name: str,
) -> dict[str, list[dict[str, Any]]]:
    """Group candidate parts by the mapped candidate id/name keys."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidate_functions:
        info = candidate.get("function", {}) if isinstance(candidate.get("function"), dict) else {}
        keys = {str(info.get("id") or ""), str(info.get("name") or "")}
        if candidate_id and candidate_id in keys:
            grouped.setdefault(candidate_id, []).append(candidate)
        if candidate_name and candidate_name in keys:
            grouped.setdefault(candidate_name, []).append(candidate)
    return grouped


def _group_stream_match(
    group: list[dict[str, Any]],
    key: str,
    oracle_signature: dict[str, Any],
) -> dict[str, Any] | None:
    """Match the oracle instruction pattern inside one same-function candidate group."""
    if not group:
        return None
    candidate_signature = _region_linear_instruction_signature(group)
    if candidate_signature is None:
        return None
    offset = _pattern_subsequence_offset(candidate_signature["pattern"], oracle_signature["pattern"])
    if offset is None:
        return None
    first = min(group, key=_ssa_part_index)
    return {
        "candidate_function": first.get("id"),
        "candidate_detail": _ssa_region_report_detail(group),
        "instruction_stream_match": {
            "candidate_key": key,
            "oracle_signature_size": len(oracle_signature["pattern"]),
            "candidate_signature_size": len(candidate_signature["pattern"]),
            "pattern_offset": offset,
            "signature_sha256": _block_signature_digest(oracle_signature["pattern"]),
        },
    }


def _global_stream_match(
    candidate_functions: list[dict[str, Any]],
    oracle_signature: dict[str, Any],
) -> dict[str, Any] | None:
    """Match the oracle pattern against every candidate; accept only a unique global hit."""
    global_matches: list[dict[str, Any]] = []
    for candidate in candidate_functions:
        candidate_signature = _region_linear_instruction_signature([candidate])
        if candidate_signature is None:
            continue
        offset = _pattern_subsequence_offset(candidate_signature["pattern"], oracle_signature["pattern"])
        if offset is None:
            continue
        info = candidate.get("function", {}) if isinstance(candidate.get("function"), dict) else {}
        global_matches.append(
            {
                "candidate": candidate,
                "offset": offset,
                "candidate_key": str(info.get("id") or info.get("name") or ""),
                "candidate_signature_size": len(candidate_signature["pattern"]),
            }
        )
    if len(global_matches) != 1:
        return None
    match = global_matches[0]
    candidate = match["candidate"]
    return {
        "candidate_function": candidate.get("id"),
        "candidate_detail": _ssa_function_report_detail(candidate),
        "instruction_stream_match": {
            "candidate_key": match["candidate_key"],
            "oracle_signature_size": len(oracle_signature["pattern"]),
            "candidate_signature_size": match["candidate_signature_size"],
            "pattern_offset": match["offset"],
            "signature_sha256": _block_signature_digest(oracle_signature["pattern"]),
            "scope": "global_unique_candidate_block",
        },
    }


def _pattern_subsequence_offset(
    haystack: tuple[int | None, ...], needle: tuple[int | None, ...]
) -> int | None:
    if not needle or len(needle) > len(haystack):
        return None
    for offset in range(len(haystack) - len(needle) + 1):
        matched = True
        for index, expected in enumerate(needle):
            actual = haystack[offset + index]
            if expected is not None and actual is not None and expected != actual:
                matched = False
                break
        if matched:
            return offset
    return None


def _ssa_block_signatures_match(oracle_function: dict[str, Any], candidate_function: dict[str, Any]) -> bool:
    oracle_exact = _ssa_exact_block_signature(oracle_function)
    candidate_exact = _ssa_exact_block_signature(candidate_function)
    if oracle_exact is not None and oracle_exact == candidate_exact:
        return True
    oracle_signature = _ssa_block_signature(oracle_function)
    candidate_signature = _ssa_block_signature(candidate_function)
    return oracle_signature is not None and oracle_signature == candidate_signature


def _candidate_for_external_part_by_matched_predecessor(
    oracle_function: dict[str, Any],
    *,
    prior_matches: dict[str, dict[str, Any]],
    oracle_external_functions: list[dict[str, Any]],
    candidate_by_id_delta: dict[tuple[str, str], dict[str, Any]],
    candidate_by_key_delta: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any] | None:
    target_delta = _ssa_detail_entry_delta(oracle_function)
    if target_delta is None:
        return None
    for predecessor in oracle_external_functions:
        predecessor_id = str(predecessor.get("id"))
        matched_predecessor = prior_matches.get(predecessor_id)
        if matched_predecessor is None:
            continue
        if target_delta not in _direct_successor_delta_set(predecessor):
            continue
        candidate_successors = sorted(_direct_successor_delta_set(matched_predecessor))
        if len(candidate_successors) != 1:
            continue
        candidate_delta = _format_ssa_delta(candidate_successors[0])
        candidate_info = matched_predecessor.get("function", {}) if isinstance(matched_predecessor.get("function"), dict) else {}
        candidate_id = str(candidate_info.get("id") or "")
        candidate_name = str(candidate_info.get("name") or "")
        for key, index in (
            ((candidate_id, candidate_delta), candidate_by_id_delta),
            ((candidate_name, candidate_delta), candidate_by_key_delta),
        ):
            if key[0] and key in index and _ssa_block_signatures_match(oracle_function, index[key]):
                return index[key]
    return None


def _candidate_for_external_part_by_signature_ordinal(
    oracle_function: dict[str, Any],
    *,
    mapped: dict[str, Any] | None,
    oracle_external_functions: list[dict[str, Any]],
    candidate_functions: list[dict[str, Any]],
) -> dict[str, Any] | None:
    function = oracle_function.get("function", {}) if isinstance(oracle_function, dict) else {}
    oracle_id = str(function.get("id", ""))
    oracle_name = str(function.get("name", oracle_id))
    candidate_id = str(mapped.get("candidate_id") or "") if isinstance(mapped, dict) else oracle_id
    candidate_name = str(mapped.get("candidate_name") or "") if isinstance(mapped, dict) else oracle_name
    for signature_kind in ("exact", "normalized", "shape"):
        signature = _ssa_signature_for_kind(oracle_function, signature_kind)
        if signature is None:
            continue
        oracle_group = _external_signature_group(
            oracle_external_functions,
            function_ids={oracle_id, oracle_name},
            signature=signature,
            signature_kind=signature_kind,
        )
        candidate_group = _external_signature_group(
            candidate_functions,
            function_ids={candidate_id, candidate_name},
            signature=signature,
            signature_kind=signature_kind,
        )
        if not oracle_group or not candidate_group:
            continue
        oracle_ids = [str(item.get("id")) for item in oracle_group]
        try:
            ordinal = oracle_ids.index(str(oracle_function.get("id")))
        except ValueError:
            continue
        if ordinal < len(candidate_group):
            return candidate_group[ordinal]
    return None


def _external_signature_group(
    functions: list[dict[str, Any]],
    *,
    function_ids: set[str],
    signature: tuple[Any, ...],
    signature_kind: str,
) -> list[dict[str, Any]]:
    group: list[dict[str, Any]] = []
    for function in functions:
        if not isinstance(function, dict) or not _ssa_part_outside_declared_body(function):
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        if str(info.get("id", "")) not in function_ids and str(info.get("name", "")) not in function_ids:
            continue
        current = _ssa_signature_for_kind(function, signature_kind)
        if current == signature:
            group.append(function)
    return sorted(group, key=lambda item: (_ssa_detail_entry_linear(item) or 0, str(item.get("id", ""))))


def _ssa_signature_for_kind(function: dict[str, Any], signature_kind: str) -> tuple[Any, ...] | None:
    if signature_kind == "exact":
        return _ssa_exact_block_signature(function)
    if signature_kind == "normalized":
        return _ssa_block_signature(function)
    if signature_kind == "shape":
        return _ssa_instruction_shape_signature(function)
    return None


def _ssa_instruction_shape_signature(function: dict[str, Any]) -> tuple[Any, ...] | None:
    source = function.get("source") if isinstance(function.get("source"), dict) else {}
    instructions = source.get("instructions") if isinstance(source.get("instructions"), list) else []
    instructions = _strip_leading_nop_instructions(instructions)
    blob = _machine_code_bytes(instructions)
    entry = function.get("entry") if isinstance(function.get("entry"), dict) else {}
    linear = _optional_int(entry.get("linear"))
    if linear is not None:
        linear += _leading_nop_size(source.get("instructions") if isinstance(source.get("instructions"), list) else [])
    if blob is None or linear is None:
        return None
    try:
        import capstone  # type: ignore
    except Exception:
        return None
    try:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        md.detail = True
        items: list[Any] = []
        for insn in md.disasm(blob, linear):
            operands: list[Any] = []
            for operand in getattr(insn, "operands", []) or []:
                operand_type = getattr(operand, "type", None)
                size = int(getattr(operand, "size", 0) or 0)
                if operand_type == capstone.x86.X86_OP_REG:
                    operands.append(("reg", size, int(getattr(operand, "reg", 0) or 0)))
                elif operand_type == capstone.x86.X86_OP_IMM:
                    operands.append(("imm", size))
                elif operand_type == capstone.x86.X86_OP_MEM:
                    mem = getattr(operand, "mem", None)
                    operands.append(
                        (
                            "mem",
                            size,
                            int(getattr(mem, "segment", 0) or 0),
                            int(getattr(mem, "base", 0) or 0),
                            int(getattr(mem, "index", 0) or 0),
                            int(getattr(mem, "scale", 0) or 0),
                        )
                    )
                else:
                    operands.append(("other", size, int(operand_type or 0)))
            items.append((str(insn.mnemonic).lower(), tuple(operands)))
        return tuple(items) if items else None
    except Exception:
        return None


def _empty_region_equality_report(*, enabled: bool) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "status": "disabled" if not enabled else "not_applicable",
        "total": 0,
        "passed": 0,
        "failed": 0,
        "refused": 0,
        "covered_results": 0,
        "skipped_passed_functions": 0,
        "solver_time_ms": 0,
        "results": [],
    }


def _compare_ssa_region_equality(
    *,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    mapping_document: dict[str, Any] | None,
    current_results: list[dict[str, Any]],
    timeout_ms: int,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
    oracle_index: dict[str, dict[Any, dict[str, Any]]],
    candidate_index: dict[str, dict[Any, dict[str, Any]]],
    allow_aliased_call_targets: bool,
    max_loop_unroll: int,
    skip_binary_equal: bool,
    proof_cache: _SemanticEqualityCache | None,
    max_rss_mb: int = 0,
) -> dict[str, Any]:
    oracle_groups = _unique_ssa_function_groups(list(oracle.get("functions", []) or []))
    candidate_groups = _ssa_function_groups(list(candidate.get("functions", []) or []))
    mapped_candidates = _ssa_candidate_mapping(mapping_document) if mapping_document is not None else {}
    status_by_function = _raw_result_status_by_function(current_results)
    results: list[dict[str, Any]] = []
    solver_time_ms = 0
    skipped_passed_functions = 0
    document_output_regs = _ssa_document_output_regs(oracle) or _ssa_document_output_regs(candidate)
    aborted: dict[str, Any] | None = None

    ctx = _RegionCompareCtx(
        oracle=oracle,
        candidate=candidate,
        mapping_document=mapping_document,
        oracle_index=oracle_index,
        candidate_index=candidate_index,
        allow_aliased_call_targets=allow_aliased_call_targets,
        timeout_ms=timeout_ms,
        max_solver_assignments=max_solver_assignments,
        max_solver_inputs=max_solver_inputs,
        max_solver_memory_stores=max_solver_memory_stores,
        max_loop_unroll=max_loop_unroll,
        skip_binary_equal=skip_binary_equal,
        proof_cache=proof_cache,
        max_rss_mb=max_rss_mb,
        mapped_candidates=mapped_candidates,
        candidate_groups=candidate_groups,
        status_by_function=status_by_function,
        document_output_regs=document_output_regs,
    )
    for oracle_id, oracle_name, oracle_group in oracle_groups:
        outcome = _region_group_compare(ctx, oracle_id, oracle_name, oracle_group)
        solver_time_ms += outcome.solver_ms
        skipped_passed_functions += outcome.skipped_passed
        if outcome.result is not None:
            results.append(outcome.result)
        if outcome.abort is not None:
            aborted = outcome.abort
            break


    status = "not_applicable"
    if any(result.get("status") == "failed" for result in results):
        status = "failed"
    elif any(result.get("status") == "refused" for result in results):
        status = "refused"
    elif any(result.get("status") == "passed" for result in results):
        status = "passed"
    return {
        "enabled": True,
        "status": status,
        "total": len(results),
        "passed": sum(1 for result in results if result.get("status") == "passed"),
        "failed": sum(1 for result in results if result.get("status") == "failed"),
        "refused": sum(1 for result in results if result.get("status") == "refused"),
        "covered_results": 0,
        "skipped_passed_functions": skipped_passed_functions,
        "solver_time_ms": solver_time_ms,
        "aborted": aborted,
        "results": results,
    }



@dataclass(frozen=True)
class _RegionCompareCtx:
    """Immutable environment shared across per-group region comparisons."""

    oracle: dict[str, Any]
    candidate: dict[str, Any]
    mapping_document: dict[str, Any] | None
    oracle_index: dict[str, dict[Any, dict[str, Any]]]
    candidate_index: dict[str, dict[Any, dict[str, Any]]]
    allow_aliased_call_targets: bool
    timeout_ms: int
    max_solver_assignments: int
    max_solver_inputs: int
    max_solver_memory_stores: int
    max_loop_unroll: int
    skip_binary_equal: bool
    proof_cache: _SemanticEqualityCache | None
    max_rss_mb: int
    mapped_candidates: dict[str, dict[str, Any]]
    candidate_groups: dict[str, list[dict[str, Any]]]
    status_by_function: dict[str, list[str]]
    document_output_regs: tuple[str, ...]


@dataclass
class _RegionGroupRun:
    """Mutable per-group state shared between region compare phases."""

    oracle_id: str
    oracle_name: str
    oracle_group: list[dict[str, Any]]
    mapped: dict[str, Any] | None = None
    candidate_group: list[dict[str, Any]] = field(default_factory=list)
    base_result: dict[str, Any] = field(default_factory=dict)
    contract: dict[str, Any] = field(default_factory=dict)
    observables: dict[str, Any] = field(default_factory=dict)
    oracle_group_for_compare: list[dict[str, Any]] = field(default_factory=list)
    candidate_group_for_compare: list[dict[str, Any]] = field(default_factory=list)
    call_normalizations: list[dict[str, Any]] = field(default_factory=list)
    oracle_summary: dict[str, Any] = field(default_factory=dict)
    candidate_summary: dict[str, Any] = field(default_factory=dict)
    oracle_function: dict[str, Any] = field(default_factory=dict)
    candidate_function: dict[str, Any] = field(default_factory=dict)


@dataclass
class _RegionStepOutcome:
    """Outcome of one region compare phase: optional result, abort, and counters."""

    result: dict[str, Any] | None = None
    solver_ms: int = 0
    skipped_passed: int = 0
    abort: dict[str, Any] | None = None


def _region_group_compare(
    ctx: _RegionCompareCtx,
    oracle_id: str,
    oracle_name: str,
    oracle_group: list[dict[str, Any]],
) -> _RegionStepOutcome:
    """Run all region-compare phases for one oracle group."""
    run = _RegionGroupRun(oracle_id=oracle_id, oracle_name=oracle_name, oracle_group=oracle_group)
    for phase in (
        _region_step_preamble,
        _region_step_prepare,
        _region_step_linear_signature,
        _region_step_transition,
        _region_step_summaries,
        _region_step_memory_gate,
        _region_step_quick,
        _region_step_solver_gate,
    ):
        outcome = phase(ctx, run)
        if outcome is not None:
            return outcome
    return _region_step_final(ctx, run)


def _region_step_preamble(ctx: _RegionCompareCtx, run: _RegionGroupRun) -> _RegionStepOutcome | None:
    """Resolve the candidate group and apply early refusal gates."""
    memory_limit = _compare_memory_limit_status(ctx.max_rss_mb)
    if memory_limit is not None:
        abort = _compare_memory_abort("region_equality", memory_limit)
        return _RegionStepOutcome(
            result={
                "function": {"id": run.oracle_id, "name": run.oracle_name},
                "mapped_candidate": _mapped_candidate_detail(
                    ctx.mapped_candidates.get(run.oracle_id) or ctx.mapped_candidates.get(run.oracle_name)
                ),
                "oracle_region_detail": _ssa_region_report_detail(run.oracle_group),
                "candidate_region_detail": None,
                "status": "refused",
                "reason": "memory_limit",
                "mismatches": [_memory_limit_mismatch(abort)],
            },
            abort=abort,
        )
    run.mapped = ctx.mapped_candidates.get(run.oracle_id) or ctx.mapped_candidates.get(run.oracle_name)
    run.candidate_group = _candidate_group_for_region(
        ctx.candidate_groups,
        oracle_id=run.oracle_id,
        oracle_name=run.oracle_name,
        mapped=run.mapped,
    )
    if not _should_attempt_region_equality(
        run.oracle_id, run.oracle_name, run.oracle_group, run.candidate_group, ctx.status_by_function
    ):
        return _RegionStepOutcome(
            skipped_passed=1
            if _region_function_already_passed(run.oracle_id, run.oracle_name, ctx.status_by_function)
            else 0
        )
    run.base_result = {
        "function": {"id": run.oracle_id, "name": run.oracle_name},
        "mapped_candidate": _mapped_candidate_detail(run.mapped),
        "oracle_region_detail": _ssa_region_report_detail(run.oracle_group),
        "candidate_region_detail": _ssa_region_report_detail(run.candidate_group),
    }
    if not run.candidate_group:
        return _RegionStepOutcome(
            result={
                **run.base_result,
                "status": "refused",
                "reason": "function_missing",
                "mismatches": [{"kind": "function_missing", "side": "candidate"}],
            }
        )
    run.contract = _synthetic_region_contract(
        run.oracle_id,
        run.oracle_name,
        run.oracle_group,
        run.candidate_group,
        default_output_regs=ctx.document_output_regs,
    )
    run.observables = run.contract["observables"]
    run.base_result["observables"] = run.observables
    run.base_result["input_constraints"] = run.contract["input_constraints"]
    if not run.observables["regs"] and not run.observables.get("whole_memory"):
        return _RegionStepOutcome(
            result={
                **run.base_result,
                "status": "refused",
                "reason": "no_declared_observables",
                "mismatches": [{"kind": "no_declared_observables"}],
            }
        )
    precompose_gate = _region_precompose_memory_gate(
        run.oracle_group,
        run.candidate_group,
        max_rss_mb=ctx.max_rss_mb,
    )
    if precompose_gate is not None:
        return _RegionStepOutcome(
            result={
                **run.base_result,
                "status": "refused",
                "reason": precompose_gate["reason"],
                "mismatches": [precompose_gate],
            }
        )
    return None


def _region_step_prepare(ctx: _RegionCompareCtx, run: _RegionGroupRun) -> _RegionStepOutcome | None:
    """Normalize call targets and reject incomplete regions."""
    run.oracle_group_for_compare, run.candidate_group_for_compare, run.call_normalizations = (
        _prepare_region_call_normalized_groups(
            run.oracle_group,
            run.candidate_group,
            mapping_document=ctx.mapping_document,
            oracle_index=ctx.oracle_index,
            candidate_index=ctx.candidate_index,
            allow_aliased_call_targets=ctx.allow_aliased_call_targets,
        )
    )
    if run.call_normalizations:
        run.base_result["call_normalizations"] = run.call_normalizations
    incomplete = _region_incomplete_successors(
        run.oracle_group_for_compare,
        run.candidate_group_for_compare,
        oracle_refusals=[item for item in ctx.oracle.get("refusals", []) or [] if isinstance(item, dict)],
        candidate_refusals=[item for item in ctx.candidate.get("refusals", []) or [] if isinstance(item, dict)],
    )
    if incomplete is not None:
        return _RegionStepOutcome(
            result={
                **run.base_result,
                "status": "refused",
                "reason": "region_incomplete",
                "mismatches": [incomplete],
            }
        )
    return None


def _record_region_proof(ctx: _RegionCompareCtx, run: _RegionGroupRun, proof: str) -> None:
    """Record a function-scope equality proof in the semantic cache when enabled."""
    if ctx.proof_cache is not None:
        ctx.proof_cache.record(
            run.oracle_group_for_compare[0],
            run.candidate_group_for_compare[0],
            proof=proof,
            scope="function",
        )


def _region_step_linear_signature(ctx: _RegionCompareCtx, run: _RegionGroupRun) -> _RegionStepOutcome | None:
    """Pass early when the normalized linear instruction signatures match."""
    linear_signature_result = None
    if _linear_region_call_normalizations_are_safe(run.call_normalizations):
        linear_signature_result = _compare_region_linear_instruction_signature(
            run.oracle_group_for_compare,
            run.candidate_group_for_compare,
        )
    if linear_signature_result is None:
        return None
    result = {
        **run.base_result,
        "status": "passed",
        "reason": "linear_instruction_signature_equal",
        "oracle_summary": linear_signature_result["oracle_summary"],
        "candidate_summary": linear_signature_result["candidate_summary"],
        "mismatches": [],
        "linear_instruction_signature": linear_signature_result["linear_instruction_signature"],
    }
    _record_region_proof(ctx, run, "linear_instruction_signature_equal")
    return _RegionStepOutcome(result=result)


def _region_step_transition(ctx: _RegionCompareCtx, run: _RegionGroupRun) -> _RegionStepOutcome | None:
    """Compare cyclic regions via the transition-system prover."""
    if not (
        _region_has_direct_cycle(run.oracle_group_for_compare)
        or _region_has_direct_cycle(run.candidate_group_for_compare)
    ):
        return None
    transition_result = _compare_region_transition_system(
        run.oracle_group_for_compare,
        run.candidate_group_for_compare,
        timeout_ms=ctx.timeout_ms,
        max_solver_assignments=ctx.max_solver_assignments,
        max_solver_inputs=ctx.max_solver_inputs,
        max_solver_memory_stores=ctx.max_solver_memory_stores,
        skip_binary_equal=ctx.skip_binary_equal,
        max_rss_mb=ctx.max_rss_mb,
    )
    if transition_result is None:
        return None
    result = {
        **run.base_result,
        "status": "passed",
        "reason": "transition_system_equal",
        "oracle_summary": transition_result["oracle_summary"],
        "candidate_summary": transition_result["candidate_summary"],
        "mismatches": [],
        "transition_system": transition_result["transition_system"],
    }
    _record_region_proof(ctx, run, "transition_system_equal")
    return _RegionStepOutcome(result=result, solver_ms=int(transition_result.get("solver_time_ms", 0)))


def _region_step_summaries(ctx: _RegionCompareCtx, run: _RegionGroupRun) -> _RegionStepOutcome | None:
    """Build ABI summaries for both groups and refuse when either fails."""
    run.oracle_summary = _summarize_abi_function(
        run.oracle_group_for_compare,
        abi_function=run.contract["abi_function"],
        observables=run.observables,
        data_segment_para=0x0100,
        max_loop_unroll=ctx.max_loop_unroll,
        require_complete_paths=True,
        enable_constant_branch_pruning=True,
    )
    run.candidate_summary = _summarize_abi_function(
        run.candidate_group_for_compare,
        abi_function=run.contract["abi_function"],
        observables=run.observables,
        data_segment_para=0x0100,
        max_loop_unroll=ctx.max_loop_unroll,
        require_complete_paths=True,
        enable_constant_branch_pruning=True,
    )
    if run.oracle_summary.get("status") == "passed" and run.candidate_summary.get("status") == "passed":
        return None
    side = "oracle" if run.oracle_summary.get("status") != "passed" else "candidate"
    summary = run.oracle_summary if side == "oracle" else run.candidate_summary
    mismatches = _attach_run_call_compare(ctx, run, summary)
    return _RegionStepOutcome(
        result={
            **run.base_result,
            "status": "refused",
            "reason": summary.get("reason", "unsupported_ir"),
            "side": side,
            "oracle_summary": _summary_detail(run.oracle_summary),
            "candidate_summary": _summary_detail(run.candidate_summary),
            "mismatches": mismatches,
        }
    )


def _region_step_memory_gate(ctx: _RegionCompareCtx, run: _RegionGroupRun) -> _RegionStepOutcome | None:
    """Abort the region compare when the post-summary memory limit is exceeded."""
    memory_limit = _compare_memory_limit_status(ctx.max_rss_mb)
    if memory_limit is None:
        return None
    abort = _compare_memory_abort("region_equality", memory_limit)
    return _RegionStepOutcome(
        result={
            **run.base_result,
            "status": "refused",
            "reason": "memory_limit",
            "oracle_summary": _summary_detail(run.oracle_summary),
            "candidate_summary": _summary_detail(run.candidate_summary),
            "mismatches": [_memory_limit_mismatch(abort)],
        },
        abort=abort,
    )


def _attach_run_call_compare(
    ctx: _RegionCompareCtx,
    run: _RegionGroupRun,
    summary: dict[str, Any],
) -> list[dict[str, Any]]:
    """Attach call-compare diagnostics for the normalized compare groups."""
    return _attach_region_call_compare(
        summary=summary,
        oracle_group=run.oracle_group_for_compare,
        candidate_group=run.candidate_group_for_compare,
        mapping_document=ctx.mapping_document,
        oracle_index=ctx.oracle_index,
        candidate_index=ctx.candidate_index,
        allow_aliased_call_targets=ctx.allow_aliased_call_targets,
    )


def _region_step_quick(ctx: _RegionCompareCtx, run: _RegionGroupRun) -> _RegionStepOutcome | None:
    """Resolve via the cheap structural comparison before invoking the solver."""
    run.oracle_function = run.oracle_summary["function"]
    run.candidate_function = run.candidate_summary["function"]
    quick = _quick_compare_functions(
        run.oracle_function, run.candidate_function, skip_binary_equal=ctx.skip_binary_equal
    )
    if quick is None:
        return None
    result = {
        **run.base_result,
        "status": quick["status"],
        "reason": _region_reason(quick.get("reason")),
        "oracle_summary": _summary_detail(run.oracle_summary),
        "candidate_summary": _summary_detail(run.candidate_summary),
        "mismatches": _attach_run_call_compare(ctx, run, quick),
    }
    if result["status"] == "passed":
        _record_region_proof(ctx, run, str(result.get("reason") or "region_equal"))
    return _RegionStepOutcome(result=result)


def _region_step_solver_gate(ctx: _RegionCompareCtx, run: _RegionGroupRun) -> _RegionStepOutcome | None:
    """Apply solver budget gates before the full comparison."""
    gate = _ssa_solver_gate(
        run.oracle_function,
        run.candidate_function,
        max_solver_assignments=ctx.max_solver_assignments,
        max_solver_inputs=ctx.max_solver_inputs,
        max_solver_memory_stores=ctx.max_solver_memory_stores,
    )
    if gate is None:
        return None
    return _RegionStepOutcome(
        result={
            **run.base_result,
            "status": "refused",
            "reason": gate["reason"],
            "oracle_summary": _summary_detail(run.oracle_summary),
            "candidate_summary": _summary_detail(run.candidate_summary),
            "mismatches": _attach_run_call_compare(ctx, run, {"mismatches": [gate]}),
        }
    )


def _region_step_final(ctx: _RegionCompareCtx, run: _RegionGroupRun) -> _RegionStepOutcome:
    """Run the full solver comparison and shape the final result."""
    comparison = _compare_functions(
        run.oracle_function,
        run.candidate_function,
        timeout_ms=ctx.timeout_ms,
        input_constraints=run.contract["input_constraints"],
    )
    solver_ms = int(comparison.pop("solver_time_ms", 0))
    mismatches = _attach_run_call_compare(ctx, run, comparison)
    result_status = comparison["status"]
    result_reason = _region_reason(comparison.get("reason"))
    if result_status == "failed" and _region_mismatches_blocked_by_unproven_call(mismatches):
        result_status = "refused"
        result_reason = "callee_not_proven"
    result = {
        **run.base_result,
        "status": result_status,
        "reason": result_reason,
        "oracle_summary": _summary_detail(run.oracle_summary),
        "candidate_summary": _summary_detail(run.candidate_summary),
        "mismatches": mismatches,
    }
    if result["status"] == "passed":
        _record_region_proof(ctx, run, str(result.get("reason") or "region_equal"))
    return _RegionStepOutcome(result=result, solver_ms=solver_ms)
def _region_reason(reason: Any) -> str:  # noqa: ANN401
    if not reason:
        return "region_equal"
    if reason == "ssa_equal":
        return "region_ssa_equal"
    if reason in {"binary_equal", "block_binary_equal"}:
        return "region_binary_equal"
    return str(reason)


def _region_precompose_memory_gate(
    oracle_group: list[dict[str, Any]],
    candidate_group: list[dict[str, Any]],
    *,
    max_rss_mb: int,
) -> dict[str, Any] | None:
    if max_rss_mb <= 0:
        return None
    oracle_metrics = _region_precompose_metrics(oracle_group)
    candidate_metrics = _region_precompose_metrics(candidate_group)
    assignment_limit = max(1024, max_rss_mb * 2)
    part_limit = max(64, max_rss_mb // 16)
    store_limit = max(128, max_rss_mb // 8)
    conditional_block_limit = max(32, max_rss_mb // 128)
    successor_edge_limit = conditional_block_limit * 3
    checks = [
        ("assignments", assignment_limit),
        ("parts", part_limit),
        ("stores", store_limit),
        ("conditional_blocks", conditional_block_limit),
        ("successor_edges", successor_edge_limit),
    ]
    for metric, limit in checks:
        oracle_value = int(oracle_metrics.get(metric, 0))
        candidate_value = int(candidate_metrics.get(metric, 0))
        value = max(oracle_value, candidate_value)
        if value <= limit:
            continue
        return {
            "kind": "solver_gate",
            "reason": "slice_too_large",
            "detail": (
                f"region {metric} {value} exceeds memory-capped pre-compose gate {limit}; "
                "block-level SSA and connectivity can still prove smaller parts"
            ),
            "metric": f"region_{metric}",
            "value": value,
            "limit": limit,
            "oracle_metrics": oracle_metrics,
            "candidate_metrics": candidate_metrics,
            "memory_cap": {
                "hard_limit_mb": max_rss_mb,
                "soft_limit_mb": None if _compare_soft_rss_limit_kib(max_rss_mb) is None else _compare_soft_rss_limit_kib(max_rss_mb) // 1024,
            },
        }
    return None


def _region_precompose_metrics(group: list[dict[str, Any]]) -> dict[str, int]:
    successor_edges = 0
    successor_blocks = 0
    conditional_blocks = 0
    call_blocks = 0
    terminal_blocks = 0
    for part in group:
        if not isinstance(part, dict):
            continue
        source = part.get("source") if isinstance(part.get("source"), dict) else {}
        transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else {}
        successors = transfer.get("successors") if isinstance(transfer.get("successors"), list) else []
        if successors:
            successor_blocks += 1
            successor_edges += len(successors)
        if len(successors) > 1:
            conditional_blocks += 1
        jumpkind = str(source.get("jumpkind") or "")
        if jumpkind == "Ijk_Call":
            call_blocks += 1
        if jumpkind.startswith(("Ijk_Ret", "Ijk_Sig")):
            terminal_blocks += 1
    return {
        "parts": len(group),
        "assignments": sum(len(part.get("assignments", []) or []) for part in group if isinstance(part, dict)),
        "inputs": sum(len(part.get("inputs", []) or []) for part in group if isinstance(part, dict)),
        "stores": sum(_ssa_store_count(part) for part in group if isinstance(part, dict)),
        "successor_blocks": successor_blocks,
        "conditional_blocks": conditional_blocks,
        "successor_edges": successor_edges,
        "call_blocks": call_blocks,
        "terminal_blocks": terminal_blocks,
    }


def _prepare_region_call_normalized_groups(
    oracle_group: list[dict[str, Any]],
    candidate_group: list[dict[str, Any]],
    *,
    mapping_document: dict[str, Any] | None,
    oracle_index: dict[str, dict[Any, dict[str, Any]]],
    candidate_index: dict[str, dict[Any, dict[str, Any]]],
    allow_aliased_call_targets: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    candidate_by_delta = {_ssa_detail_entry_delta(part): part for part in candidate_group}
    normalized_oracle: list[dict[str, Any]] = []
    normalized_candidate_by_delta = dict(candidate_by_delta)
    normalizations: list[dict[str, Any]] = []
    for oracle_part in oracle_group:
        delta = _ssa_detail_entry_delta(oracle_part)
        candidate_part = candidate_by_delta.get(delta)
        if (
            delta is None
            or candidate_part is None
            or _ssa_source_jumpkind(oracle_part) != "Ijk_Call"
            or _ssa_source_jumpkind(candidate_part) != "Ijk_Call"
        ):
            normalized_oracle.append(oracle_part)
            continue
        call_compare = _compare_call_targets(
            oracle_part,
            candidate_part,
            mapping_document=mapping_document,
            oracle_index=oracle_index,
            candidate_index=candidate_index,
            allow_aliased_call_targets=allow_aliased_call_targets,
            proof_cache=None,
            require_proven_call_targets=False,
        )
        oracle_normalized, candidate_normalized, normalized_compare = _prepare_call_normalized_functions(
            oracle_part,
            candidate_part,
            call_compare=call_compare,
        )
        normalized_oracle.append(oracle_normalized)
        normalized_candidate_by_delta[delta] = candidate_normalized
        if isinstance(normalized_compare, dict) and normalized_compare.get("normalizations"):
            normalizations.append(
                {
                    "delta": _format_ssa_delta(delta),
                    "call_compare": normalized_compare,
                }
            )
    normalized_candidate: list[dict[str, Any]] = []
    for candidate_part in candidate_group:
        delta = _ssa_detail_entry_delta(candidate_part)
        normalized_candidate.append(normalized_candidate_by_delta.get(delta, candidate_part))
    return normalized_oracle, normalized_candidate, normalizations


def _region_incomplete_successors(
    oracle_group: list[dict[str, Any]],
    candidate_group: list[dict[str, Any]],
    *,
    oracle_refusals: list[dict[str, Any]],
    candidate_refusals: list[dict[str, Any]],
) -> dict[str, Any] | None:
    oracle_missing = _missing_region_successors(oracle_group, refusals=oracle_refusals)
    candidate_missing = _missing_region_successors(candidate_group, refusals=candidate_refusals)
    if not oracle_missing and not candidate_missing:
        return None
    return {
        "kind": "region_incomplete",
        "reason": "missing_successor_blocks",
        "detail": "SSA region has direct successors that were not lowered; regenerate SSA with a larger block/scan limit or inspect the listed transfer",
        "oracle_missing_successors": oracle_missing,
        "candidate_missing_successors": candidate_missing,
    }


def _missing_region_successors(group: list[dict[str, Any]], *, refusals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocks = _region_blocks_by_delta(group)
    if not blocks:
        return []
    refusal_index = _lowering_refusals_by_address(refusals)
    missing: list[dict[str, Any]] = []
    for delta, block in sorted(blocks.items()):
        source = block.get("source", {}) if isinstance(block.get("source"), dict) else {}
        transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else {}
        if transfer.get("kind") != "direct_successors":
            continue
        function_entry = block.get("function_entry") if isinstance(block.get("function_entry"), dict) else {}
        function_linear = _optional_int(function_entry.get("linear"))
        for successor in sorted(_direct_successor_delta_set(block)):
            if successor in blocks:
                continue
            successor_linear = None if function_linear is None else function_linear + successor
            lowering_refusal = None if successor_linear is None else refusal_index.get(successor_linear)
            missing.append(
                {
                    "from_delta": _format_ssa_delta(delta),
                    "missing_successor_delta": _format_ssa_delta(successor),
                    "jumpkind": _ssa_source_jumpkind(block),
                    "entry": block.get("entry") if isinstance(block.get("entry"), dict) else None,
                    "last_instruction": _last_instruction_detail(block),
                    "lowering_refusal": lowering_refusal,
                }
            )
    return missing


def _lowering_refusals_by_address(refusals: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    indexed: dict[int, dict[str, Any]] = {}
    for refusal in refusals:
        detail = refusal.get("detail") if isinstance(refusal.get("detail"), dict) else {}
        address = detail.get("address") if isinstance(detail.get("address"), dict) else {}
        linear = _optional_int(address.get("linear"))
        if linear is None:
            continue
        indexed[linear] = {
            "reason": refusal.get("reason"),
            "message": detail.get("message"),
            "address": address,
            "metrics": detail.get("metrics") if isinstance(detail.get("metrics"), dict) else None,
        }
    return indexed


def _last_instruction_detail(function: dict[str, Any]) -> dict[str, Any] | None:
    instructions = _ssa_instructions(function)
    if not instructions:
        return None
    instruction = instructions[-1]
    return {
        "address": instruction.get("address") if isinstance(instruction.get("address"), dict) else None,
        "disassembly": instruction.get("disassembly"),
        "bytes": instruction.get("bytes"),
    }


def _compare_region_transition_system(
    oracle_group: list[dict[str, Any]],
    candidate_group: list[dict[str, Any]],
    *,
    timeout_ms: int,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
    skip_binary_equal: bool,
    max_rss_mb: int = 0,
) -> dict[str, Any] | None:
    oracle_by_delta = _region_blocks_by_delta(oracle_group)
    candidate_by_delta = _region_blocks_by_delta(candidate_group)
    if not oracle_by_delta or set(oracle_by_delta) != set(candidate_by_delta):
        return None
    if not all(_ssa_has_machine_code(block) for block in [*oracle_group, *candidate_group]):
        return None

    deltas = set(oracle_by_delta)
    solver_time_ms = 0
    block_results: list[dict[str, Any]] = []
    for delta in sorted(deltas):
        block_result, step_ms = _transition_block_compare(
            delta,
            oracle_by_delta[delta],
            candidate_by_delta[delta],
            deltas,
            timeout_ms=timeout_ms,
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
            skip_binary_equal=skip_binary_equal,
            max_rss_mb=max_rss_mb,
        )
        solver_time_ms += step_ms
        if block_result is None:
            return None
        block_results.append(block_result)

    summary = {
        "status": "passed",
        "reason": "transition_system_equal",
        "part_count": len(deltas),
        "terminal_count": sum(
            1 for block in oracle_group if _ssa_source_jumpkind(block).startswith(("Ijk_Ret", "Ijk_Sig"))
        ),
        "blocks_composed": len(deltas),
        "branches": sum(1 for block in oracle_group if _direct_successor_delta_set(block)),
        "branch_prunes": 0,
        "branch_merges": 0,
        "loop_cuts": 0,
    }
    return {
        "oracle_summary": dict(summary),
        "candidate_summary": dict(summary),
        "solver_time_ms": solver_time_ms,
        "transition_system": {
            "kind": "block_graph_equal",
            "block_count": len(deltas),
            "block_results": block_results,
        },
    }


def _transition_block_compare(
    delta: int,
    oracle_block: dict[str, Any],
    candidate_block: dict[str, Any],
    deltas: set[int],
    *,
    timeout_ms: int,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
    skip_binary_equal: bool,
    max_rss_mb: int,
) -> tuple[dict[str, Any] | None, int]:
    """Compare one matched delta pair; return (block_result, solver_ms) or (None, 0)."""
    if _compare_memory_limit_status(max_rss_mb) is not None:
        return None, 0
    if _ssa_source_jumpkind(oracle_block) != _ssa_source_jumpkind(candidate_block):
        return None, 0
    oracle_successors = _direct_successor_delta_set(oracle_block)
    candidate_successors = _direct_successor_delta_set(candidate_block)
    if oracle_successors != candidate_successors:
        return None, 0
    if not oracle_successors <= deltas or not candidate_successors <= deltas:
        return None, 0
    if (len(oracle_successors) > 1 or len(candidate_successors) > 1) and (
        "ip" not in _ssa_output_names(oracle_block) or "ip" not in _ssa_output_names(candidate_block)
    ):
        return None, 0

    oracle_for_z3, candidate_for_z3, layout_normalization = _prepare_layout_normalized_functions(
        oracle_block,
        candidate_block,
    )
    quick = _quick_compare_functions(oracle_for_z3, candidate_for_z3, skip_binary_equal=skip_binary_equal)
    if quick is not None:
        if quick.get("status") != "passed":
            return None, 0
        return {
            "delta": _format_ssa_delta(delta),
            "reason": quick.get("reason"),
            "layout_normalization": layout_normalization,
        }, 0
    gate = _ssa_solver_gate(
        oracle_for_z3,
        candidate_for_z3,
        max_solver_assignments=max_solver_assignments,
        max_solver_inputs=max_solver_inputs,
        max_solver_memory_stores=max_solver_memory_stores,
    )
    if gate is not None:
        return None, 0
    comparison = _compare_functions(oracle_for_z3, candidate_for_z3, timeout_ms=timeout_ms)
    solver_ms = int(comparison.pop("solver_time_ms", 0) or 0)
    if comparison.get("status") != "passed":
        return None, solver_ms
    return {
        "delta": _format_ssa_delta(delta),
        "reason": comparison.get("reason"),
        "layout_normalization": layout_normalization,
    }, solver_ms


def _region_has_direct_cycle(parts: list[dict[str, Any]]) -> bool:
    blocks = _region_blocks_by_delta(parts)
    graph = {
        delta: {successor for successor in _direct_successor_delta_set(block) if successor in blocks}
        for delta, block in blocks.items()
    }
    for component in _strongly_connected_components(graph):
        if len(component) > 1:
            return True
        if component and component[0] in graph.get(component[0], set()):
            return True
    return False


def _region_blocks_by_delta(parts: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    blocks: dict[int, dict[str, Any]] = {}
    for part in parts:
        delta = _ssa_detail_entry_delta(
            {"part": part.get("part"), "entry": part.get("entry"), "function_entry": part.get("function_entry")}
        )
        if delta is not None:
            blocks[delta & 0xFFFF] = part
    return blocks


def _direct_successor_delta_set(function: dict[str, Any]) -> set[int]:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else {}
    function_entry = function.get("function_entry", {}) if isinstance(function.get("function_entry"), dict) else {}
    function_linear = _optional_int(function_entry.get("linear"))
    if function_linear is None:
        return set()
    if transfer.get("kind") == "direct_call":
        fallthrough = transfer.get("fallthrough") if isinstance(transfer.get("fallthrough"), dict) else {}
        linear = _optional_int(fallthrough.get("linear"))
        return set() if linear is None else {(linear - function_linear) & 0xFFFF}
    if transfer.get("kind") != "direct_successors":
        return set()
    deltas: set[int] = set()
    for successor in transfer.get("successors", []) or []:
        if not isinstance(successor, dict):
            continue
        linear = _optional_int(successor.get("linear"))
        if linear is not None:
            deltas.add((linear - function_linear) & 0xFFFF)
    return deltas


def _attach_region_call_compare(
    *,
    summary: dict[str, Any],
    oracle_group: list[dict[str, Any]],
    candidate_group: list[dict[str, Any]],
    mapping_document: dict[str, Any] | None,
    oracle_index: dict[str, dict[Any, dict[str, Any]]],
    candidate_index: dict[str, dict[Any, dict[str, Any]]],
    allow_aliased_call_targets: bool,
) -> list[dict[str, Any]]:
    mismatches = [dict(item) for item in (summary.get("mismatches") or []) if isinstance(item, dict)]
    if not mismatches or mapping_document is None:
        return mismatches
    call_compare = _region_call_compare(
        oracle_group=oracle_group,
        candidate_group=candidate_group,
        mapping_document=mapping_document,
        oracle_index=oracle_index,
        candidate_index=candidate_index,
        allow_aliased_call_targets=allow_aliased_call_targets,
    )
    if call_compare is None:
        return mismatches
    # Only add target analysis once unless it is already present in all entries.
    for mismatch in mismatches:
        if "call_compare" in mismatch:
            break
    else:
        for mismatch in mismatches:
            mismatch["call_compare"] = call_compare
    return mismatches


def _region_mismatches_blocked_by_unproven_call(mismatches: list[dict[str, Any]]) -> bool:
    if not mismatches:
        return False
    for mismatch in mismatches:
        call_compare = mismatch.get("call_compare") if isinstance(mismatch, dict) else None
        if not isinstance(call_compare, dict):
            return False
        if call_compare.get("equivalent") is not False:
            return False
    return True


def _region_call_compare(
    oracle_group: list[dict[str, Any]],
    candidate_group: list[dict[str, Any]],
    mapping_document: dict[str, Any] | None,
    oracle_index: dict[str, dict[Any, dict[str, Any]]],
    candidate_index: dict[str, dict[Any, dict[str, Any]]],
    allow_aliased_call_targets: bool,
) -> dict[str, Any] | None:
    oracle_calls: dict[int, dict[str, Any]] = {}
    for part in oracle_group:
        if part and _ssa_source_jumpkind(part) == "Ijk_Call":
            delta = _ssa_detail_entry_delta(part)
            if delta is not None:
                oracle_calls[delta & 0xFFFF] = part
    candidate_calls: dict[int, dict[str, Any]] = {}
    for part in candidate_group:
        if part and _ssa_source_jumpkind(part) == "Ijk_Call":
            delta = _ssa_detail_entry_delta(part)
            if delta is not None:
                candidate_calls[delta & 0xFFFF] = part
    deltas = sorted(set(oracle_calls.keys()) & set(candidate_calls.keys()))
    for delta in deltas:
        oracle_part = oracle_calls.get(delta)
        candidate_part = candidate_calls.get(delta)
        if not oracle_part or not candidate_part:
            continue
        call_compare = _compare_call_targets(
            oracle_part,
            candidate_part,
            mapping_document=mapping_document,
            oracle_index=oracle_index,
            candidate_index=candidate_index,
            allow_aliased_call_targets=allow_aliased_call_targets,
            proof_cache=None,
            require_proven_call_targets=False,
        )
        if call_compare is not None:
            return call_compare
    return None


def _compare_region_linear_instruction_signature(
    oracle_group: list[dict[str, Any]],
    candidate_group: list[dict[str, Any]],
) -> dict[str, Any] | None:
    oracle_signature = _region_linear_instruction_signature(oracle_group)
    candidate_signature = _region_linear_instruction_signature(candidate_group)
    if oracle_signature is None or candidate_signature is None:
        return None
    if oracle_signature["pattern"] != candidate_signature["pattern"]:
        return None
    summary = {
        "status": "passed",
        "reason": "linear_instruction_signature_equal",
        "terminal_count": None,
        "blocks_composed": None,
        "branches": None,
        "branch_prunes": 0,
        "branch_merges": 0,
        "loop_cuts": 0,
        "instruction_count": oracle_signature["instruction_count"],
    }
    return {
        "oracle_summary": {**summary, "part_count": len(oracle_group)},
        "candidate_summary": {**summary, "part_count": len(candidate_group)},
        "linear_instruction_signature": {
            "kind": "layout_normalized_linear_instruction_stream",
            "instruction_count": oracle_signature["instruction_count"],
            "signature_size": len(oracle_signature["pattern"]),
            "signature_sha256": _block_signature_digest(oracle_signature["pattern"]),
        },
    }


def _region_linear_instruction_signature(parts: list[dict[str, Any]]) -> dict[str, Any] | None:
    instructions_by_linear: dict[int, dict[str, Any]] = {}
    for part in parts:
        source = part.get("source", {}) if isinstance(part.get("source"), dict) else {}
        for instruction in source.get("instructions", []) or []:
            if not isinstance(instruction, dict):
                continue
            if str(instruction.get("mnemonic") or "").lower() == "nop":
                continue
            address = instruction.get("address") if isinstance(instruction.get("address"), dict) else {}
            linear = _optional_int(address.get("linear"))
            if linear is None:
                return None
            instructions_by_linear.setdefault(linear, instruction)
    if not instructions_by_linear:
        return None
    ordered = [instructions_by_linear[key] for key in sorted(instructions_by_linear)]
    blob = _machine_code_bytes(ordered)
    if blob is None:
        return None
    pattern = _layout_binary_signature_pattern(blob, min(instructions_by_linear))
    return {"pattern": pattern, "instruction_count": len(ordered)}


def _linear_region_call_normalizations_are_safe(call_normalizations: list[dict[str, Any]]) -> bool:
    unsafe_reasons = {
        "direct call targets are equivalent through function mapping",
        "direct call targets have the same function id",
        "direct call targets have the same function name",
        "direct call targets have equivalent normalized symbol names",
    }
    for item in call_normalizations:
        call_compare = item.get("call_compare") if isinstance(item, dict) else None
        if not isinstance(call_compare, dict):
            continue
        if call_compare.get("equivalent") is not True:
            return False
        reason = str(call_compare.get("reason") or "")
        if reason in unsafe_reasons and not isinstance(call_compare.get("proof_fact"), dict):
            return False
    return True


def _ssa_source_jumpkind(function: dict[str, Any]) -> str:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    return str(source.get("jumpkind") or "")


def _ssa_output_names(function: dict[str, Any]) -> set[str]:
    outputs = function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}
    return {str(name) for name in outputs}


def _ssa_has_machine_code(function: dict[str, Any]) -> bool:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    size = source.get("machine_code_size")
    digest = source.get("machine_code_sha256")
    return isinstance(size, int) and size > 0 and isinstance(digest, str) and bool(digest)


def _unique_ssa_function_groups(functions: list[dict[str, Any]]) -> list[tuple[str, str, list[dict[str, Any]]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id") or "")
        function_name = str(info.get("name") or function_id)
        key = (function_id, function_name)
        grouped.setdefault(key, []).append(function)
    return [
        (function_id, function_name, sorted(group, key=_ssa_part_index))
        for (function_id, function_name), group in sorted(grouped.items(), key=lambda item: (item[0][1], item[0][0]))
    ]


def _candidate_group_for_region(
    groups: dict[str, list[dict[str, Any]]],
    *,
    oracle_id: str,
    oracle_name: str,
    mapped: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if isinstance(mapped, dict):
        for key in (str(mapped.get("candidate_id") or ""), str(mapped.get("candidate_name") or "")):
            if key and key in groups:
                return sorted(groups[key], key=_ssa_part_index)
    for key in (oracle_id, oracle_name):
        if key and key in groups:
            return sorted(groups[key], key=_ssa_part_index)
    return []


def _raw_result_status_by_function(results: list[dict[str, Any]]) -> dict[str, list[str]]:
    statuses: dict[str, list[str]] = defaultdict(list)
    for result in results:
        function = result.get("function") if isinstance(result.get("function"), dict) else {}
        for key in (str(function.get("id") or ""), str(function.get("name") or "")):
            if key:
                statuses[key].append(str(result.get("status") or ""))
    return statuses


def _should_attempt_region_equality(
    oracle_id: str,
    oracle_name: str,
    oracle_group: list[dict[str, Any]],
    candidate_group: list[dict[str, Any]],
    status_by_function: dict[str, list[str]],
) -> bool:
    if len(oracle_group) <= 1 and len(candidate_group) <= 1:
        return False
    if _region_status_count(status_by_function) <= 64:
        return True
    return not _region_function_already_passed(oracle_id, oracle_name, status_by_function)


def _region_function_already_passed(
    oracle_id: str, oracle_name: str, status_by_function: dict[str, list[str]]
) -> bool:
    statuses = [*status_by_function.get(oracle_id, []), *status_by_function.get(oracle_name, [])]
    return bool(statuses) and all(status == "passed" for status in statuses)


def _region_status_count(status_by_function: dict[str, list[str]]) -> int:
    return sum(len(statuses) for statuses in status_by_function.values())


def _ssa_document_output_regs(document: dict[str, Any]) -> tuple[str, ...]:
    params = document.get("parameters", {}) if isinstance(document.get("parameters"), dict) else {}
    regs = params.get("output_regs", [])
    if not isinstance(regs, (list, tuple)):
        return ()
    reg_widths = {name for name, _width in REG_BY_OFFSET.values()}
    return tuple(str(name).lower() for name in regs if str(name).lower() in reg_widths)


def _synthetic_region_contract(
    oracle_id: str,
    oracle_name: str,
    oracle_group: list[dict[str, Any]],
    candidate_group: list[dict[str, Any]],
    default_output_regs: Iterable[str] | None = None,
) -> dict[str, Any]:
    reg_widths = dict(REG_BY_OFFSET.values())
    declared_outputs = {
        str(name).lower()
        for name in (default_output_regs or [])
        if str(name).lower() in reg_widths
    }
    output_regs, whole_memory = _synthetic_region_outputs(
        [*oracle_group, *candidate_group], declared_outputs, reg_widths
    )
    input_regs = _synthetic_region_inputs([*oracle_group, *candidate_group], reg_widths)
    abi_function = {
        "id": oracle_id,
        "name": oracle_name,
        "kind": "near",
        "calling_convention": "region-ssa",
        "ssa_call_policy": "ignore_balanced",
        "inputs": [{"location": name, "width": reg_widths[name]} for name in sorted(input_regs)],
        "returns": [{"location": name, "width": reg_widths[name]} for name in sorted(output_regs)],
        "preserved": [],
        "clobbers": [],
        "effects": [],
    }
    observables = {"regs": sorted(output_regs), "memory": [], "whole_memory": whole_memory}
    return {"abi_function": abi_function, "observables": observables, "input_constraints": []}


def _synthetic_region_outputs(
    parts: list[dict[str, Any]],
    declared_outputs: set[str],
    reg_widths: dict[str, int],
) -> tuple[set[str], bool]:
    """Collect region output regs and whole-memory flag from part outputs."""
    output_regs: set[str] = set(declared_outputs)
    whole_memory = False
    for part in parts:
        outputs = part.get("outputs", {}) if isinstance(part.get("outputs"), dict) else {}
        for name in outputs:
            key = str(name).lower()
            if key == "memory":
                whole_memory = True
                continue
            if key in {"ip", "call_target"}:
                continue
            if not declared_outputs and key in reg_widths:
                output_regs.add(key)
    return output_regs, whole_memory


def _synthetic_region_inputs(parts: list[dict[str, Any]], reg_widths: dict[str, int]) -> set[str]:
    """Collect region input registers from part input items."""
    input_regs: set[str] = set()
    for part in parts:
        for item in part.get("inputs", []) or []:
            if not isinstance(item, dict):
                continue
            if item.get("kind") == "memory":
                continue
            name = str(item.get("name") or "").lower()
            if name in reg_widths:
                input_regs.add(name)
    return input_regs


def _region_passed_function_keys(region_equality: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for result in region_equality.get("results", []) or []:
        if not isinstance(result, dict) or result.get("status") != "passed":
            continue
        function = result.get("function") if isinstance(result.get("function"), dict) else {}
        for key in (str(function.get("id") or ""), str(function.get("name") or "")):
            if key:
                keys.add(key)
    return keys


def _apply_region_equality_gate(results: list[dict[str, Any]], region_equality: dict[str, Any]) -> None:
    passed_by_key: dict[str, dict[str, Any]] = {}
    for region_result in region_equality.get("results", []) or []:
        if not isinstance(region_result, dict) or region_result.get("status") != "passed":
            continue
        function = region_result.get("function") if isinstance(region_result.get("function"), dict) else {}
        for key in (str(function.get("id") or ""), str(function.get("name") or "")):
            if key:
                passed_by_key[key] = region_result
    if not passed_by_key:
        return
    covered = 0
    for result in results:
        function = result.get("function") if isinstance(result.get("function"), dict) else {}
        region_result = passed_by_key.get(str(function.get("id") or "")) or passed_by_key.get(
            str(function.get("name") or "")
        )
        if region_result is not None and _cover_result_by_region(result, region_result):
            covered += 1
    region_equality["covered_results"] = max(int(region_equality.get("covered_results", 0) or 0), covered)


def _cover_result_by_region(result: dict[str, Any], region_result: dict[str, Any]) -> bool:
    """Promote a failed compare result to region-covered when the gate allows it."""
    call_compare = result.get("call_compare")
    if (
        isinstance(call_compare, dict)
        and call_compare.get("equivalent") is False
        and region_result.get("reason") != "linear_instruction_signature_equal"
    ):
        return False
    if result.get("status") == "passed" and result.get("reason") == "covered_by_region_equal":
        return False
    if result.get("status") == "passed":
        return False
    previous = {
        "status": result.get("status"),
        "reason": result.get("reason"),
        "mismatches": result.get("mismatches", []),
    }
    result["status"] = "passed"
    result["reason"] = "covered_by_region_equal"
    result["region_equality"] = {
        "status": "passed",
        "reason": region_result.get("reason"),
        "oracle_summary": region_result.get("oracle_summary"),
        "candidate_summary": region_result.get("candidate_summary"),
        "previous": previous,
    }
    result["mismatches"] = []
    return True


def _apply_connectivity_region_coverage(
    region_equality: dict[str, Any],
    results: list[dict[str, Any]],
    connectivity: dict[str, Any],
) -> None:
    if not isinstance(region_equality, dict) or not region_equality.get("enabled"):
        return
    if not isinstance(connectivity, dict) or connectivity.get("status") != "passed":
        return
    status_by_function = _raw_result_status_by_function(results)
    covered = 0
    for region_result in region_equality.get("results", []) or []:
        if not isinstance(region_result, dict) or region_result.get("status") == "passed":
            continue
        if region_result.get("reason") != "slice_too_large":
            continue
        mismatches = [item for item in region_result.get("mismatches", []) or [] if isinstance(item, dict)]
        if not mismatches or any(item.get("kind") != "solver_gate" for item in mismatches):
            continue
        function = region_result.get("function") if isinstance(region_result.get("function"), dict) else {}
        function_id = str(function.get("id") or "")
        function_name = str(function.get("name") or function_id)
        if not _region_function_already_passed(function_id, function_name, status_by_function):
            continue
        previous = {
            "status": region_result.get("status"),
            "reason": region_result.get("reason"),
            "mismatches": mismatches,
        }
        region_result["status"] = "passed"
        region_result["reason"] = "covered_by_block_connectivity"
        region_result["mismatches"] = []
        region_result["connectivity_coverage"] = {
            "reason": "all compared SSA blocks passed and the connectivity gate proved successor state equivalence",
            "previous": previous,
            "edges_checked": connectivity.get("edges_checked", 0),
            "state_edges_checked": connectivity.get("state_edges_checked", 0),
            "state_inputs_checked": connectivity.get("state_inputs_checked", 0),
            "external_successor_edges_skipped": connectivity.get("external_successor_edges_skipped", 0),
        }
        covered += 1
    if covered:
        region_equality["connectivity_covered_regions"] = (
            int(region_equality.get("connectivity_covered_regions", 0) or 0) + covered
        )
        _refresh_region_equality_summary(region_equality)


def _apply_external_successor_edge_coverage(connectivity: dict[str, Any], external_parts: dict[str, Any]) -> None:
    if not isinstance(connectivity, dict) or not isinstance(external_parts, dict):
        return
    edges = [edge for edge in connectivity.get("external_successor_edges", []) or [] if isinstance(edge, dict)]
    if not edges:
        connectivity["external_successor_edges_covered"] = 0
        connectivity["external_successor_edges_unproved"] = 0
        return
    oracle_passed: set[tuple[str, str]] = set()
    candidate_passed: set[tuple[str, str]] = set()
    for result in external_parts.get("results", []) or []:
        if not isinstance(result, dict) or result.get("status") != "passed":
            continue
        function = result.get("function") if isinstance(result.get("function"), dict) else {}
        function_id = str(function.get("id") or function.get("name") or "")
        if not function_id:
            continue
        oracle_delta = _ssa_detail_entry_delta(result.get("oracle_detail"))
        candidate_delta = _ssa_detail_entry_delta(result.get("candidate_detail"))
        if oracle_delta is not None:
            oracle_passed.add((function_id, _external_edge_delta_key(_format_ssa_delta(oracle_delta))))
        if candidate_delta is not None:
            candidate_passed.add((function_id, _external_edge_delta_key(_format_ssa_delta(candidate_delta))))
    covered = 0
    unproved = 0
    for edge in edges:
        side = str(edge.get("side") or "")
        key = (str(edge.get("function") or ""), _external_edge_delta_key(edge.get("successor_delta")))
        is_covered = key in (oracle_passed if side == "oracle" else candidate_passed)
        edge["target_proof"] = "passed" if is_covered else "unproved"
        if is_covered:
            covered += 1
        else:
            unproved += 1
    connectivity["external_successor_edges_covered"] = covered
    connectivity["external_successor_edges_unproved"] = unproved


def _external_edge_delta_key(value: Any) -> str:  # noqa: ANN401
    try:
        parsed = parse_int(value, field="external_successor_delta")
    except DosUnitError:
        return str(value or "")
    return normalize_hex(parsed & 0xFFFF, width=4)


def _refresh_region_equality_summary(region_equality: dict[str, Any]) -> None:
    results = [item for item in region_equality.get("results", []) or [] if isinstance(item, dict)]
    region_equality["total"] = len(results)
    region_equality["passed"] = sum(1 for result in results if result.get("status") == "passed")
    region_equality["failed"] = sum(1 for result in results if result.get("status") == "failed")
    region_equality["refused"] = sum(1 for result in results if result.get("status") == "refused")
    if region_equality["failed"]:
        region_equality["status"] = "failed"
    elif region_equality["refused"]:
        region_equality["status"] = "refused"
    elif region_equality["passed"]:
        region_equality["status"] = "passed"
    else:
        region_equality["status"] = "not_applicable" if region_equality.get("enabled") else "disabled"


def _apply_ssa_connectivity_gate(
    results: list[dict[str, Any]],
    *,
    region_exempt_functions: set[str] | None = None,
    oracle_functions: list[dict[str, Any]] | None = None,
    candidate_functions: list[dict[str, Any]] | None = None,
    timeout_ms: int = 60000,
    max_rss_mb: int = 0,
) -> dict[str, Any]:
    region_exempt_functions = region_exempt_functions or set()
    oracle_body_by_id = _ssa_body_by_id(oracle_functions or [])
    candidate_body_by_id = _ssa_body_by_id(candidate_functions or [])
    tables = _connectivity_pair_tables(results, region_exempt_functions)
    block_pairs = tables.block_pairs
    block_pairs_by_linear = tables.block_pairs_by_linear
    inverse_pairs = tables.inverse_pairs
    inverse_pairs_by_linear = tables.inverse_pairs_by_linear
    candidate_deltas_by_function = tables.candidate_deltas_by_function
    candidate_linears_by_function = tables.candidate_linears_by_function

    gate = _ConnectivityGate(
        results=results,
        region_exempt_functions=region_exempt_functions,
        oracle_body_by_id=oracle_body_by_id,
        candidate_body_by_id=candidate_body_by_id,
        block_pairs=block_pairs,
        block_pairs_by_linear=block_pairs_by_linear,
        inverse_pairs=inverse_pairs,
        inverse_pairs_by_linear=inverse_pairs_by_linear,
        candidate_deltas_by_function=candidate_deltas_by_function,
        candidate_linears_by_function=candidate_linears_by_function,
        timeout_ms=timeout_ms,
        max_rss_mb=max_rss_mb,
    )
    gate.run()
    checked_edges = gate.checked_edges
    external_successor_edges_skipped = gate.external_successor_edges_skipped
    state_edges_checked = gate.state_edges_checked
    state_inputs_checked = gate.state_inputs_checked
    state_solver_time_ms = gate.state_solver_time_ms
    failures = gate.failures
    refusals = gate.refusals
    external_successor_edges = gate.external_successor_edges
    failed_result_indexes = gate.failed_result_indexes
    refused_result_indexes = gate.refused_result_indexes
    aborted = gate.aborted


    for index in failed_result_indexes:
        result = results[index]
        result["status"] = "failed"
        result["reason"] = "connectivity_mismatch"
        mismatches = list(result.get("mismatches", []) or [])
        mismatches.extend(failure for failure in failures if failure.get("result_index") == index)
        result["mismatches"] = mismatches
    for index in refused_result_indexes:
        if index in failed_result_indexes:
            continue
        result = results[index]
        result["status"] = "refused"
        mismatches = list(result.get("mismatches", []) or [])
        result_refusals = [refusal for refusal in refusals if refusal.get("result_index") == index]
        result["reason"] = _connectivity_refusal_reason(result_refusals)
        mismatches.extend(result_refusals)
        result["mismatches"] = mismatches

    status = "not_applicable"
    if failures:
        status = "failed"
    elif refusals:
        status = "refused"
    elif checked_edges:
        status = "passed"
    return {
        "status": status,
        "edges_checked": checked_edges,
        "external_successor_edges_skipped": external_successor_edges_skipped,
        "external_successor_edges": external_successor_edges,
        "external_successor_edges_covered": 0,
        "external_successor_edges_unproved": external_successor_edges_skipped,
        "state_edges_checked": state_edges_checked,
        "state_inputs_checked": state_inputs_checked,
        "state_solver_time_ms": state_solver_time_ms,
        "region_exempt_functions": sorted(region_exempt_functions),
        "aborted": aborted,
        "failures": failures,
        "refusals": refusals,
    }


@dataclass
class _ConnectivityPairTables:
    """Forward/inverse delta and linear pair tables used by the connectivity gate."""

    block_pairs: dict[tuple[str, int], tuple[int, int]] = field(default_factory=dict)
    block_pairs_by_linear: dict[tuple[str, int], tuple[int, int, int | None]] = field(default_factory=dict)
    inverse_pairs: dict[tuple[str, int], int] = field(default_factory=dict)
    inverse_pairs_by_linear: dict[tuple[str, int], int] = field(default_factory=dict)
    candidate_deltas_by_function: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))
    candidate_linears_by_function: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))


def _connectivity_pair_tables(
    results: list[dict[str, Any]], region_exempt_functions: set[str]
) -> _ConnectivityPairTables:
    """Build the delta/linear successor pair tables from passed results."""
    tables = _ConnectivityPairTables()
    for index, result in enumerate(results):
        if result.get("status") != "passed":
            continue
        function = result.get("function") if isinstance(result.get("function"), dict) else {}
        function_id = str(function.get("id") or function.get("name") or "")
        if not function_id:
            continue
        if function_id in region_exempt_functions or str(function.get("name") or "") in region_exempt_functions:
            continue
        oracle_delta = _ssa_detail_entry_delta(result.get("oracle_detail"))
        candidate_delta = _ssa_detail_entry_delta(result.get("candidate_detail"))
        if oracle_delta is None or candidate_delta is None:
            continue
        tables.block_pairs[(function_id, oracle_delta)] = (index, candidate_delta)
        tables.inverse_pairs[(function_id, candidate_delta)] = oracle_delta
        tables.candidate_deltas_by_function[function_id].add(candidate_delta)
        oracle_linear = _ssa_detail_entry_linear(result.get("oracle_detail"))
        candidate_linear = _ssa_detail_entry_linear(result.get("candidate_detail"))
        if oracle_linear is not None and candidate_linear is not None:
            tables.block_pairs_by_linear[(function_id, oracle_linear)] = (index, candidate_delta, candidate_linear)
            tables.inverse_pairs_by_linear[(function_id, candidate_linear)] = oracle_delta
            tables.candidate_linears_by_function[function_id].add(candidate_linear)
    return tables


@dataclass
class _ConnectivityGate:
    """Connectivity-gate state: pair tables, counters, and failure/refusal records."""

    results: list[dict[str, Any]]
    region_exempt_functions: set[str]
    oracle_body_by_id: dict[str, dict[str, Any]]
    candidate_body_by_id: dict[str, dict[str, Any]]
    block_pairs: dict[tuple[str, int], tuple[int, int]]
    block_pairs_by_linear: dict[tuple[str, int], tuple[int, int, int | None]]
    inverse_pairs: dict[tuple[str, int], int]
    inverse_pairs_by_linear: dict[tuple[str, int], int]
    candidate_deltas_by_function: dict[str, set[int]]
    candidate_linears_by_function: dict[str, set[int]]
    timeout_ms: int
    max_rss_mb: int
    checked_edges: int = 0
    external_successor_edges_skipped: int = 0
    state_edges_checked: int = 0
    state_inputs_checked: int = 0
    state_solver_time_ms: int = 0
    failures: list[dict[str, Any]] = field(default_factory=list)
    refusals: list[dict[str, Any]] = field(default_factory=list)
    external_successor_edges: list[dict[str, Any]] = field(default_factory=list)
    failed_result_indexes: set[int] = field(default_factory=set)
    refused_result_indexes: set[int] = field(default_factory=set)
    aborted: dict[str, Any] | None = None
    index: int = -1
    result: dict[str, Any] = field(default_factory=dict)
    function_id: str = ""
    oracle_delta: int = 0
    candidate_delta: int = 0
    oracle_successor_linears: list[int] = field(default_factory=list)
    candidate_successor_linears: list[int] = field(default_factory=list)
    oracle_successor_set: set[int] = field(default_factory=set)
    candidate_successor_set: set[int] = field(default_factory=set)
    candidate_successor_linear_set: set[int] = field(default_factory=set)

    def run(self) -> None:
        """Walk all results, applying the connectivity check per passed result."""
        for index, result in enumerate(self.results):
            memory_limit = _compare_memory_limit_status(self.max_rss_mb)
            if memory_limit is not None:
                self.aborted = _compare_memory_abort("connectivity", memory_limit)
                self.refusals.append(_memory_limit_mismatch(self.aborted))
                break
            if result.get("status") != "passed":
                continue
            self.check_result(index, result)
            if self.aborted is not None:
                break

    def check_result(self, index: int, result: dict[str, Any]) -> None:
        """Check oracle/candidate direct-successor edges for one passed result."""
        function = result.get("function") if isinstance(result.get("function"), dict) else {}
        function_id = str(function.get("id") or function.get("name") or "")
        if not function_id:
            return
        if function_id in self.region_exempt_functions or str(function.get("name") or "") in self.region_exempt_functions:
            return
        oracle_delta = _ssa_detail_entry_delta(result.get("oracle_detail"))
        candidate_delta = _ssa_detail_entry_delta(result.get("candidate_detail"))
        oracle_successors = _ssa_detail_direct_successor_deltas(result.get("oracle_detail"))
        candidate_successors = _ssa_detail_direct_successor_deltas(result.get("candidate_detail"))
        oracle_successor_linears = _ssa_detail_direct_successor_linears(result.get("oracle_detail"))
        candidate_successor_linears = _ssa_detail_direct_successor_linears(result.get("candidate_detail"))
        if self._skip_or_refuse(
            index,
            result,
            function_id,
            oracle_delta,
            candidate_delta,
            oracle_successors,
            candidate_successors,
        ):
            return

        self.index = index
        self.result = result
        self.function_id = function_id
        self.oracle_delta = oracle_delta
        self.candidate_delta = candidate_delta
        self.oracle_successor_linears = oracle_successor_linears
        self.candidate_successor_linears = candidate_successor_linears
        self.candidate_successor_set = set(candidate_successors)
        self.candidate_successor_linear_set = set(candidate_successor_linears)
        self.oracle_successor_set = set(oracle_successors)
        for ordinal, successor_delta in enumerate(oracle_successors):
            self.check_oracle_successor(ordinal, successor_delta)
            if self.aborted is not None:
                break
        if self.aborted is not None:
            return
        for ordinal, successor_delta in enumerate(candidate_successors):
            self.check_candidate_successor(ordinal, successor_delta)

    def _skip_or_refuse(
        self,
        index: int,
        result: dict[str, Any],
        function_id: str,
        oracle_delta: int | None,
        candidate_delta: int | None,
        oracle_successors: list[int],
        candidate_successors: list[int],
    ) -> bool:
        """Apply the skip/refusal gates for a block; True when it must be skipped."""
        if oracle_delta is None or candidate_delta is None:
            if oracle_successors or candidate_successors:
                self.refusals.append(
                    {
                        "kind": "connectivity_refused",
                        "reason": "missing_block_delta",
                        "function": function_id,
                        "result_index": index,
                    }
                )
            return True
        if not oracle_successors and not candidate_successors:
            return True
        if (len(oracle_successors) > 1 or len(candidate_successors) > 1) and (
            "ip" not in _ssa_detail_outputs(result.get("oracle_detail"))
            or "ip" not in _ssa_detail_outputs(result.get("candidate_detail"))
        ):
            refusal = {
                "kind": "branch_predicate_unobserved",
                "detail": "conditional direct-successor block does not expose ip, so branch predicate equivalence was not proved",
                "function": function_id,
                "oracle_from_delta": _format_ssa_delta(oracle_delta),
                "candidate_from_delta": _format_ssa_delta(candidate_delta),
                "result_index": index,
            }
            self.refusals.append(refusal)
            self.refused_result_indexes.add(index)
            return True
        return False

    def check_oracle_successor(self, ordinal: int, successor_delta: int) -> None:
        """Verify one oracle successor edge maps to a candidate successor."""
        mapped = self.block_pairs.get((self.function_id, successor_delta))
        expected_candidate_linear: int | None = None
        if mapped is None and ordinal < len(self.oracle_successor_linears):
            linear_mapped = self.block_pairs_by_linear.get((self.function_id, self.oracle_successor_linears[ordinal]))
            if linear_mapped is not None:
                successor_index, expected_candidate_delta, expected_candidate_linear = linear_mapped
                mapped = (successor_index, expected_candidate_delta)
        if mapped is None:
            if not _ssa_detail_delta_inside_function(self.result.get("oracle_detail"), successor_delta):
                self.external_successor_edges_skipped += 1
                self.external_successor_edges.append(
                    {
                        "side": "oracle",
                        "function": self.function_id,
                        "from_delta": _format_ssa_delta(self.oracle_delta),
                        "successor_delta": _format_ssa_delta(successor_delta),
                        "result_index": self.index,
                    }
                )
                return
            self.refusals.append(
                {
                    "kind": "connectivity_refused",
                    "reason": "oracle_successor_not_paired",
                    "function": self.function_id,
                    "from_delta": _format_ssa_delta(self.oracle_delta),
                    "successor_delta": _format_ssa_delta(successor_delta),
                    "result_index": self.index,
                }
            )
            return
        self.checked_edges += 1
        successor_index, expected_candidate_delta = mapped
        candidate_has_successor = _delta_in_set_mod16(expected_candidate_delta, self.candidate_successor_set) or (
            expected_candidate_linear is not None and expected_candidate_linear in self.candidate_successor_linear_set
        )
        if not candidate_has_successor:
            failure = {
                "kind": "connectivity_successor_mismatch",
                "detail": "oracle direct successor maps to a candidate block that is not a direct successor",
                "function": self.function_id,
                "oracle_from_delta": _format_ssa_delta(self.oracle_delta),
                "oracle_successor_delta": _format_ssa_delta(successor_delta),
                "candidate_from_delta": _format_ssa_delta(self.candidate_delta),
                "expected_candidate_successor_delta": _format_ssa_delta(expected_candidate_delta),
                "candidate_successor_deltas": [
                    _format_ssa_delta(value) for value in sorted(self.candidate_successor_set)
                ],
                "result_index": self.index,
            }
            self.failures.append(failure)
            self.failed_result_indexes.add(self.index)
            return
        self.check_edge_state(successor_index, successor_delta, expected_candidate_delta)

    def check_edge_state(self, successor_index: int, successor_delta: int, expected_candidate_delta: int) -> None:
        """Run the per-edge state check over paired predecessor/successor bodies."""
        oracle_predecessor = _ssa_body_for_result(self.result, self.oracle_body_by_id, side="oracle")
        oracle_successor = _ssa_body_for_result(self.results[successor_index], self.oracle_body_by_id, side="oracle")
        candidate_predecessor = _ssa_body_for_result(self.result, self.candidate_body_by_id, side="candidate")
        candidate_successor = _ssa_body_for_result(
            self.results[successor_index], self.candidate_body_by_id, side="candidate"
        )
        if (
            oracle_predecessor is not None
            and oracle_successor is not None
            and candidate_predecessor is not None
            and candidate_successor is not None
        ):
            # Keep control-flow layout constants aligned for successor-state checks (e.g. IP offsets).
            oracle_predecessor, candidate_predecessor, _ = _prepare_layout_normalized_functions(
                oracle_predecessor,
                candidate_predecessor,
            )
            oracle_successor, candidate_successor, _ = _prepare_layout_normalized_functions(
                oracle_successor,
                candidate_successor,
            )

        memory_limit = _compare_memory_limit_status(self.max_rss_mb)
        if memory_limit is not None:
            self.aborted = _compare_memory_abort("connectivity", memory_limit)
            self.refusals.append(_memory_limit_mismatch(self.aborted))
            self.refused_result_indexes.add(self.index)
            return
        state_check = _connectivity_state_check(
            predecessor=self.result,
            successor=self.results[successor_index],
            oracle_predecessor=oracle_predecessor,
            oracle_successor=oracle_successor,
            candidate_predecessor=candidate_predecessor,
            candidate_successor=candidate_successor,
            function_id=self.function_id,
            oracle_from_delta=self.oracle_delta,
            candidate_from_delta=self.candidate_delta,
            oracle_successor_delta=successor_delta,
            candidate_successor_delta=expected_candidate_delta,
            result_index=self.index,
            timeout_ms=self.timeout_ms,
        )
        self.state_edges_checked += int(state_check.get("edges_checked", 0) or 0)
        self.state_inputs_checked += int(state_check.get("inputs_checked", 0) or 0)
        self.state_solver_time_ms += int(state_check.get("solver_time_ms", 0) or 0)
        if state_check.get("status") == "failed":
            self.failures.append(state_check["mismatch"])
            self.failed_result_indexes.add(self.index)
        elif state_check.get("status") == "refused":
            self.refusals.append(state_check["mismatch"])
            self.refused_result_indexes.add(self.index)

    def check_candidate_successor(self, ordinal: int, successor_delta: int) -> None:
        """Verify one candidate successor edge maps back to an oracle successor."""
        oracle_successor_delta = self.inverse_pairs.get((self.function_id, successor_delta))
        if oracle_successor_delta is None and ordinal < len(self.candidate_successor_linears):
            oracle_successor_delta = self.inverse_pairs_by_linear.get(
                (self.function_id, self.candidate_successor_linears[ordinal])
            )
        if oracle_successor_delta is None:
            candidate_successor_linear = (
                self.candidate_successor_linears[ordinal]
                if ordinal < len(self.candidate_successor_linears)
                else None
            )
            if not _ssa_detail_delta_inside_function(self.result.get("candidate_detail"), successor_delta):
                self.external_successor_edges_skipped += 1
                self.external_successor_edges.append(
                    {
                        "side": "candidate",
                        "function": self.function_id,
                        "from_delta": _format_ssa_delta(self.candidate_delta),
                        "successor_delta": _format_ssa_delta(successor_delta),
                        "result_index": self.index,
                    }
                )
                return
            if _delta_in_set_mod16(successor_delta, self.candidate_deltas_by_function.get(self.function_id, set())) or (
                candidate_successor_linear is not None
                and candidate_successor_linear in self.candidate_linears_by_function.get(self.function_id, set())
            ):
                failure = {
                    "kind": "connectivity_successor_mismatch",
                    "detail": "candidate has a direct successor to a paired block with no oracle successor",
                    "function": self.function_id,
                    "oracle_from_delta": _format_ssa_delta(self.oracle_delta),
                    "candidate_from_delta": _format_ssa_delta(self.candidate_delta),
                    "candidate_successor_delta": _format_ssa_delta(successor_delta),
                    "oracle_successor_deltas": [
                        _format_ssa_delta(value) for value in sorted(self.oracle_successor_set)
                    ],
                    "result_index": self.index,
                }
                self.failures.append(failure)
                self.failed_result_indexes.add(self.index)
            return
        if not _delta_in_set_mod16(oracle_successor_delta, self.oracle_successor_set):
            self.checked_edges += 1
            failure = {
                "kind": "connectivity_successor_mismatch",
                "detail": "candidate direct successor maps back to a block that is not an oracle direct successor",
                "function": self.function_id,
                "oracle_from_delta": _format_ssa_delta(self.oracle_delta),
                "candidate_from_delta": _format_ssa_delta(self.candidate_delta),
                "candidate_successor_delta": _format_ssa_delta(successor_delta),
                "mapped_oracle_successor_delta": _format_ssa_delta(oracle_successor_delta),
                "oracle_successor_deltas": [_format_ssa_delta(value) for value in sorted(self.oracle_successor_set)],
                "result_index": self.index,
            }
            self.failures.append(failure)
            self.failed_result_indexes.add(self.index)


def _ssa_body_by_id(functions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(function.get("id")): function for function in functions if isinstance(function, dict) and function.get("id")
    }


def _ssa_body_for_result(
    result: dict[str, Any], body_by_id: dict[str, dict[str, Any]], *, side: str
) -> dict[str, Any] | None:
    key = result.get(f"{side}_function")
    if key is None:
        return None
    return body_by_id.get(str(key))


def _connectivity_state_check(
    *,
    predecessor: dict[str, Any],
    successor: dict[str, Any],
    oracle_predecessor: dict[str, Any] | None,
    oracle_successor: dict[str, Any] | None,
    candidate_predecessor: dict[str, Any] | None,
    candidate_successor: dict[str, Any] | None,
    function_id: str,
    oracle_from_delta: int,
    candidate_from_delta: int,
    oracle_successor_delta: int,
    candidate_successor_delta: int,
    result_index: int,
    timeout_ms: int,
) -> dict[str, Any]:
    oracle_successor_inputs = _successor_required_inputs(successor.get("oracle_detail"), oracle_successor)
    candidate_successor_inputs = _successor_required_inputs(successor.get("candidate_detail"), candidate_successor)
    oracle_missing = _missing_successor_inputs_from_sets(
        _ssa_detail_outputs(predecessor.get("oracle_detail")),
        oracle_successor_inputs,
    )
    candidate_missing = _missing_successor_inputs_from_sets(
        _ssa_detail_outputs(predecessor.get("candidate_detail")),
        candidate_successor_inputs,
    )
    oracle_ignored_missing = sorted(
        name
        for name in oracle_missing
        if name in CONNECTIVITY_IMPLICIT_STATE or name in CONNECTIVITY_OPTIONALLY_IMPLICIT_STATE
    )
    candidate_ignored_missing = sorted(
        name
        for name in candidate_missing
        if name in CONNECTIVITY_IMPLICIT_STATE or name in CONNECTIVITY_OPTIONALLY_IMPLICIT_STATE
    )
    ignored = set(oracle_ignored_missing + candidate_ignored_missing)
    oracle_missing = sorted(name for name in oracle_missing if name not in ignored)
    candidate_missing = sorted(name for name in candidate_missing if name not in ignored)
    if not oracle_missing and not candidate_missing:
        ignored_inputs = CONNECTIVITY_IMPLICIT_STATE | CONNECTIVITY_OPTIONALLY_IMPLICIT_STATE
        checked = sorted((oracle_successor_inputs - ignored_inputs) & (candidate_successor_inputs - ignored_inputs))
        if not checked:
            return {"status": "passed", "edges_checked": 1, "inputs_checked": 0, "solver_time_ms": 0}
        if (
            oracle_predecessor is None
            or candidate_predecessor is None
            or oracle_successor is None
            or candidate_successor is None
        ):
            return {
                "status": "refused",
                "edges_checked": 1,
                "inputs_checked": 0,
                "solver_time_ms": 0,
                "mismatch": {
                    "kind": "connectivity_state_refused",
                    "reason": "edge_state_body_missing",
                    "detail": "direct successor state proof needs predecessor and successor SSA bodies",
                    "function": function_id,
                    "oracle_from_delta": _format_ssa_delta(oracle_from_delta),
                    "oracle_successor_delta": _format_ssa_delta(oracle_successor_delta),
                    "candidate_from_delta": _format_ssa_delta(candidate_from_delta),
                    "candidate_successor_delta": _format_ssa_delta(candidate_successor_delta),
                    "checked_inputs": checked,
                    "result_index": result_index,
                },
            }
        oracle_projection = _project_ssa_outputs(oracle_predecessor, checked)
        candidate_projection = _project_ssa_outputs(candidate_predecessor, checked)
        oracle_projection, candidate_projection, _ = _prepare_layout_normalized_functions(
            oracle_projection, candidate_projection
        )
        comparison = _compare_functions(oracle_projection, candidate_projection, timeout_ms=timeout_ms)
        solver_time_ms = int(comparison.pop("solver_time_ms", 0) or 0)
        if comparison.get("status") == "passed":
            return {
                "status": "passed",
                "edges_checked": 1,
                "inputs_checked": len(checked),
                "solver_time_ms": solver_time_ms,
            }
        mismatch_kind = (
            "connectivity_state_mismatch" if comparison.get("status") == "failed" else "connectivity_state_refused"
        )
        status = "failed" if comparison.get("status") == "failed" else "refused"
        reason = "edge_state_mismatch" if status == "failed" else f"edge_state_{comparison.get('reason', 'refused')}"
        return {
            "status": status,
            "edges_checked": 1,
            "inputs_checked": len(checked),
            "solver_time_ms": solver_time_ms,
            "mismatch": {
                "kind": mismatch_kind,
                "reason": reason,
                "detail": "direct successor required state is not equivalent at the paired edge",
                "function": function_id,
                "oracle_from_delta": _format_ssa_delta(oracle_from_delta),
                "oracle_successor_delta": _format_ssa_delta(oracle_successor_delta),
                "candidate_from_delta": _format_ssa_delta(candidate_from_delta),
                "candidate_successor_delta": _format_ssa_delta(candidate_successor_delta),
                "checked_inputs": checked,
                "edge_mismatches": comparison.get("mismatches", []),
                "result_index": result_index,
            },
        }
    return {
        "status": "refused",
        "edges_checked": 1,
        "inputs_checked": 0,
        "solver_time_ms": 0,
        "mismatch": {
            "kind": "connectivity_state_unobserved",
            "reason": "successor_state_unobserved",
            "detail": "direct successor reads state that the predecessor block did not expose as an output",
            "function": function_id,
            "oracle_from_delta": _format_ssa_delta(oracle_from_delta),
            "oracle_successor_delta": _format_ssa_delta(oracle_successor_delta),
            "candidate_from_delta": _format_ssa_delta(candidate_from_delta),
            "candidate_successor_delta": _format_ssa_delta(candidate_successor_delta),
            "oracle_missing_inputs": oracle_missing,
            "candidate_missing_inputs": candidate_missing,
            "oracle_ignored_inputs": oracle_ignored_missing,
            "candidate_ignored_inputs": candidate_ignored_missing,
            "result_index": result_index,
        },
    }


def _project_ssa_outputs(function: dict[str, Any], names: list[str]) -> dict[str, Any]:
    outputs = function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}
    source_assignments = {
        str(item["id"]): item
        for item in function.get("assignments", []) or []
        if isinstance(item, dict) and "id" in item
    }
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    term_cache: dict[int, dict[str, Any]] = {}
    projected_outputs: dict[str, dict[str, Any]] = {}
    inline_cache: dict[str, dict[str, Any]] = {}
    for name in names:
        if name not in outputs:
            continue
        inlined = _inline_ssa_json_term(outputs[name], assignments=source_assignments, cache=inline_cache)
        projected_outputs[name] = _materialize_json_term(
            inlined,
            assignments=assignments,
            memo=memo,
            term_cache=term_cache,
        )
    projected = dict(function)
    projected["outputs"] = projected_outputs
    projected["assignments"] = assignments
    projected["inputs"] = _term_input_items(projected_outputs.values(), assignments)
    projected["id"] = f"{function.get('id', 'ssa-function')}:edge-state:{','.join(names)}"
    return projected


def _ssa_missing_successor_inputs(predecessor_detail: Any, successor_detail: Any) -> set[str]:  # noqa: ANN401
    predecessor_outputs = _ssa_detail_outputs(predecessor_detail)
    successor_inputs = _ssa_detail_inputs(successor_detail)
    return _missing_successor_inputs_from_sets(predecessor_outputs, successor_inputs)


def _missing_successor_inputs_from_sets(predecessor_outputs: set[str], successor_inputs: set[str]) -> set[str]:
    return {name for name in successor_inputs if name not in predecessor_outputs}


def _successor_required_inputs(successor_detail: Any, successor_body: dict[str, Any] | None) -> set[str]:  # noqa: ANN401
    if successor_body is None:
        return _ssa_detail_inputs(successor_detail)
    outputs = successor_body.get("outputs", {}) if isinstance(successor_body.get("outputs"), dict) else {}
    assignments = {
        str(item.get("id")): item
        for item in successor_body.get("assignments", []) or []
        if isinstance(item, dict) and item.get("id") is not None
    }
    semantic_outputs = []
    may_defer_passthrough = _has_direct_successor_transfer(successor_body)
    for name, term in outputs.items():
        output_name = str(name)
        if may_defer_passthrough and output_name in RAW_OUTPUT_REGS and isinstance(term, dict) and _term_is_identity_input(
            term, output_name, assignments
        ):
            continue
        if isinstance(term, dict):
            semantic_outputs.append(term)
    return {
        str(item.get("name"))
        for item in _term_input_items(semantic_outputs, list(assignments.values()))
        if isinstance(item, dict) and item.get("name")
    }


def _term_is_identity_input(
    term: dict[str, Any],
    name: str,
    assignments: dict[str, dict[str, Any]],
    seen: set[str] | None = None,
) -> bool:
    if term.get("op") == "input" and str(term.get("name") or "") == name:
        return True
    ref = term.get("ref")
    if not isinstance(ref, str):
        return False
    if seen is None:
        seen = set()
    if ref in seen:
        return False
    seen.add(ref)
    assignment = assignments.get(ref)
    return isinstance(assignment, dict) and _term_is_identity_input(assignment, name, assignments, seen)


def _connectivity_refusal_reason(refusals: list[dict[str, Any]]) -> str:
    if any(refusal.get("kind") == "branch_predicate_unobserved" for refusal in refusals):
        return "branch_predicate_unobserved"
    for refusal in refusals:
        reason = str(refusal.get("reason") or refusal.get("kind") or "")
        if reason:
            return reason
    return "connectivity_refused"


def _delta_in_set_mod16(delta: int, values: set[int]) -> bool:
    return any(((delta - value) & 0xFFFF) == 0 for value in values)


def _ssa_detail_entry_delta(detail: Any) -> int | None:  # noqa: ANN401
    if not isinstance(detail, dict):
        return None
    part = detail.get("part") if isinstance(detail.get("part"), dict) else {}
    delta = _optional_int(part.get("entry_delta"))
    if delta is not None:
        return delta
    entry = detail.get("entry") if isinstance(detail.get("entry"), dict) else {}
    function_entry = detail.get("function_entry") if isinstance(detail.get("function_entry"), dict) else {}
    entry_linear = _optional_int(entry.get("linear"))
    function_linear = _optional_int(function_entry.get("linear"))
    if entry_linear is None or function_linear is None:
        return None
    return entry_linear - function_linear


def _ssa_detail_entry_linear(detail: Any) -> int | None:  # noqa: ANN401
    if not isinstance(detail, dict):
        return None
    entry = detail.get("entry") if isinstance(detail.get("entry"), dict) else {}
    return _optional_int(entry.get("linear"))


def _ssa_detail_direct_successor_deltas(detail: Any) -> list[int]:  # noqa: ANN401
    if not isinstance(detail, dict):
        return []
    transfer = detail.get("transfer") if isinstance(detail.get("transfer"), dict) else {}
    if transfer.get("kind") != "direct_successors":
        return []
    function_entry = detail.get("function_entry") if isinstance(detail.get("function_entry"), dict) else {}
    function_linear = _optional_int(function_entry.get("linear"))
    if function_linear is None:
        return []
    deltas: list[int] = []
    for successor in transfer.get("successors", []) or []:
        if not isinstance(successor, dict):
            continue
        linear = _optional_int(successor.get("linear"))
        if linear is None:
            continue
        deltas.append(linear - function_linear)
    return _unique_ints(deltas)


def _ssa_detail_direct_successor_linears(detail: Any) -> list[int]:  # noqa: ANN401
    if not isinstance(detail, dict):
        return []
    transfer = detail.get("transfer") if isinstance(detail.get("transfer"), dict) else {}
    if transfer.get("kind") != "direct_successors":
        return []
    linears: list[int] = []
    for successor in transfer.get("successors", []) or []:
        if not isinstance(successor, dict):
            continue
        linear = _optional_int(successor.get("linear"))
        if linear is not None:
            linears.append(linear)
    return _unique_ints(linears)


def _ssa_detail_delta_inside_function(detail: Any, delta: int) -> bool:  # noqa: ANN401
    if not isinstance(detail, dict):
        return True
    source = detail.get("source") if isinstance(detail.get("source"), dict) else detail
    size = source.get("function_machine_code_size") if isinstance(source, dict) else None
    if not isinstance(size, int) or size <= 0:
        return True
    return 0 <= delta < size


def _ssa_part_outside_declared_body(function: dict[str, Any]) -> bool:
    delta = _ssa_detail_entry_delta(function)
    if delta is None:
        return False
    return not _ssa_detail_delta_inside_function(function, delta)


def _partition_declared_body_ssa_parts(
    functions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    kept: list[dict[str, Any]] = []
    external: list[dict[str, Any]] = []
    for function in functions:
        if isinstance(function, dict) and _ssa_part_outside_declared_body(function):
            external.append(function)
            continue
        kept.append(function)
    return kept, external


def _incomplete_block_reaches_range_end(instructions: list[dict[str, Any]], range_end: int) -> bool:
    if not instructions:
        return False
    last = instructions[-1]
    address = last.get("address") if isinstance(last.get("address"), dict) else {}
    linear = _optional_int(address.get("linear"))
    size = _optional_int(last.get("size"))
    if linear is None or size is None or size <= 0:
        return False
    return linear + size >= range_end


def _format_ssa_delta(delta: int) -> str:
    if delta < 0:
        return f"-0x{-delta:04x}"
    return normalize_hex(delta, width=4)


def _ssa_detail_outputs(detail: Any) -> set[str]:  # noqa: ANN401
    if not isinstance(detail, dict):
        return set()
    return {str(name) for name in detail.get("outputs", []) or []}


def _ssa_detail_inputs(detail: Any) -> set[str]:  # noqa: ANN401
    if not isinstance(detail, dict):
        return set()
    return {str(name) for name in detail.get("inputs", []) or []}


def _apply_loop_scc_gate(
    results: list[dict[str, Any]], *, region_exempt_functions: set[str] | None = None
) -> dict[str, Any]:
    region_exempt_functions = region_exempt_functions or set()
    by_function: dict[str, dict[int, tuple[int, dict[str, Any]]]] = defaultdict(dict)
    for index, result in enumerate(results):
        function = result.get("function") if isinstance(result.get("function"), dict) else {}
        function_id = str(function.get("id") or function.get("name") or "")
        if not function_id:
            continue
        if function_id in region_exempt_functions or str(function.get("name") or "") in region_exempt_functions:
            continue
        delta = _ssa_detail_entry_delta(result.get("oracle_detail"))
        if delta is None:
            continue
        by_function[function_id][delta] = (index, result)

    loop_results: list[dict[str, Any]] = []
    for function_id, nodes in sorted(by_function.items()):
        loop_results.extend(_loop_scc_function_results(function_id, nodes))

    return _scc_gate_summary(loop_results)


def _loop_scc_function_results(
    function_id: str,
    nodes: dict[int, tuple[int, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Compute loop-SCC results for one function's delta nodes."""
    graph: dict[int, set[int]] = {delta: set() for delta in nodes}
    for delta, (_index, result) in nodes.items():
        for successor in _ssa_detail_direct_successor_deltas(result.get("oracle_detail")):
            if successor in nodes:
                graph[delta].add(successor)
    component_results: list[dict[str, Any]] = []
    for component in _strongly_connected_components(graph):
        result = _loop_scc_component_result(function_id, component, graph, nodes)
        if result is not None:
            component_results.append(result)
    return component_results


def _loop_scc_component_result(
    function_id: str,
    component: list[int],
    graph: dict[int, set[int]],
    nodes: dict[int, tuple[int, dict[str, Any]]],
) -> dict[str, Any] | None:
    """Build one loop-SCC result for a non-trivial component."""
    has_self_loop = len(component) == 1 and component[0] in graph.get(component[0], set())
    if len(component) <= 1 and not has_self_loop:
        return None
    member_results = [nodes[delta][1] for delta in component]
    statuses = Counter(str(result.get("status") or "unknown") for result in member_results)
    status = "passed"
    if statuses.get("failed"):
        status = "failed"
    elif statuses.get("refused") or statuses.get("unknown"):
        status = "refused"
    return {
        "function": function_id,
        "status": status,
        "block_deltas": [_format_ssa_delta(delta) for delta in component],
        "block_count": len(component),
        "edge_count": sum(
            1 for source in component for target in graph.get(source, set()) if target in component
        ),
        "member_statuses": dict(sorted(statuses.items())),
    }


def _scc_gate_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize SCC gate results into the shared status/counts shape."""
    status = "not_applicable"
    if any(result["status"] == "failed" for result in results):
        status = "failed"
    elif any(result["status"] == "refused" for result in results):
        status = "refused"
    elif results:
        status = "passed"
    return {
        "status": status,
        "total": len(results),
        "passed": sum(1 for result in results if result.get("status") == "passed"),
        "failed": sum(1 for result in results if result.get("status") == "failed"),
        "refused": sum(1 for result in results if result.get("status") == "refused"),
        "results": results,
    }


def _apply_call_scc_gate(results: list[dict[str, Any]]) -> dict[str, Any]:
    graph: dict[str, set[str]] = defaultdict(set)
    statuses_by_function: dict[str, Counter[str]] = defaultdict(Counter)
    names_by_function: dict[str, str] = {}
    for result in results:
        function = result.get("function") if isinstance(result.get("function"), dict) else {}
        function_id = str(function.get("id") or function.get("name") or "")
        if not function_id:
            continue
        names_by_function[function_id] = str(function.get("name") or function_id)
        graph.setdefault(function_id, set())
        statuses_by_function[function_id][str(result.get("status") or "unknown")] += 1
        target_id = _call_compare_oracle_target_id(result.get("call_compare"))
        if target_id:
            graph[function_id].add(target_id)
            graph.setdefault(target_id, set())

    call_results: list[dict[str, Any]] = []
    for component in _strongly_connected_components(
        {key: {target for target in value if target in graph} for key, value in graph.items()}
    ):
        result = _call_scc_component_result(component, graph, statuses_by_function, names_by_function)
        if result is not None:
            call_results.append(result)

    return _scc_gate_summary(call_results)


def _call_scc_component_result(
    component: list[str],
    graph: dict[str, set[str]],
    statuses_by_function: dict[str, Counter[str]],
    names_by_function: dict[str, str],
) -> dict[str, Any] | None:
    """Build one call-SCC result for a non-trivial call-cycle component."""
    has_self_call = len(component) == 1 and component[0] in graph.get(component[0], set())
    if len(component) <= 1 and not has_self_call:
        return None
    status_counts: Counter[str] = Counter()
    for function_id in component:
        status_counts.update(statuses_by_function.get(function_id, Counter({"unknown": 1})))
    status = "passed"
    reason = "call_cycle_proven_by_member_results"
    if status_counts.get("failed"):
        status = "failed"
        reason = "call_cycle_member_failed"
    elif status_counts.get("refused") or status_counts.get("unknown"):
        status = "refused"
        reason = "call_cycle_unproven"
    return {
        "status": status,
        "reason": reason,
        "functions": [
            {"id": function_id, "name": names_by_function.get(function_id, function_id)}
            for function_id in component
        ],
        "function_count": len(component),
        "edge_count": sum(
            1 for source in component for target in graph.get(source, set()) if target in component
        ),
        "member_statuses": dict(sorted(status_counts.items())),
    }


def _call_compare_oracle_target_id(call_compare: Any) -> str | None:  # noqa: ANN401
    if not isinstance(call_compare, dict):
        return None
    oracle = call_compare.get("oracle") if isinstance(call_compare.get("oracle"), dict) else {}
    resolved = oracle.get("resolved") if isinstance(oracle.get("resolved"), dict) else {}
    target_id = str(resolved.get("id") or "")
    return target_id or None


def _strongly_connected_components(graph: dict[Any, set[Any]]) -> list[list[Any]]:
    index = 0
    stack: list[Any] = []
    on_stack: set[Any] = set()
    indexes: dict[Any, int] = {}
    lowlinks: dict[Any, int] = {}
    components: list[list[Any]] = []

    def visit(node: Any) -> None:  # noqa: ANN401
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for successor in sorted(graph.get(node, set())):
            if successor not in indexes:
                visit(successor)
                lowlinks[node] = min(lowlinks[node], lowlinks[successor])
            elif successor in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[successor])
        if lowlinks[node] != indexes[node]:
            return
        component: list[Any] = []
        while stack:
            item = stack.pop()
            on_stack.discard(item)
            component.append(item)
            if item == node:
                break
        components.append(sorted(component))

    for node in sorted(graph):
        if node not in indexes:
            visit(node)
    return components


def _compare_functions(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    *,
    timeout_ms: int,
    input_constraints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    try:
        import z3  # type: ignore
    except Exception:
        return {
            "status": "refused",
            "reason": "unsupported_ir",
            "mismatches": [{"kind": "z3_unavailable"}],
            "solver_time_ms": 0,
        }

    import time

    started = time.monotonic()
    oracle_outputs = oracle.get("outputs", {}) if isinstance(oracle.get("outputs"), dict) else {}
    candidate_outputs = candidate.get("outputs", {}) if isinstance(candidate.get("outputs"), dict) else {}
    oracle_output_names = set(oracle_outputs)
    candidate_output_names = set(candidate_outputs)
    if oracle_output_names != candidate_output_names:
        return {
            "status": "failed",
            "reason": "observable_mismatch",
            "mismatches": [
                {
                    "kind": "output_set_changed",
                    "oracle_only": sorted(oracle_output_names - candidate_output_names),
                    "candidate_only": sorted(candidate_output_names - oracle_output_names),
                }
            ],
            "solver_time_ms": 0,
        }
    output_regs = sorted(oracle_output_names)
    if not output_regs:
        return {
            "status": "refused",
            "reason": "unsupported_ir",
            "mismatches": [{"kind": "no_common_outputs"}],
            "solver_time_ms": 0,
        }

    inputs = _z3_inputs(oracle, candidate, z3)
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    _add_z3_input_constraints(solver, inputs, input_constraints or [], z3)
    pairs, skipped_layout_outputs = _z3_output_pairs(
        output_regs,
        oracle=oracle,
        candidate=candidate,
        oracle_outputs=oracle_outputs,
        candidate_outputs=candidate_outputs,
        inputs=inputs,
        z3=z3,
    )
    if not pairs:
        return {
            "status": "passed",
            "reason": "layout_only_outputs",
            "mismatches": [],
            "solver_time_ms": 0,
            "skipped_layout_outputs": skipped_layout_outputs,
        }
    solver.add(z3.Or(*[oracle_expr != candidate_expr for _reg, oracle_expr, candidate_expr in pairs]))
    status = solver.check()
    elapsed = int((time.monotonic() - started) * 1000)
    if status == z3.unknown:
        return {
            "status": "refused",
            "reason": "timeout",
            "mismatches": [{"kind": "z3_unknown", "detail": solver.reason_unknown()}],
            "solver_time_ms": elapsed,
            "skipped_layout_outputs": skipped_layout_outputs,
        }
    if status != z3.sat:
        return {
            "status": "passed",
            "reason": None,
            "mismatches": [],
            "solver_time_ms": elapsed,
            "skipped_layout_outputs": skipped_layout_outputs,
        }
    model = solver.model()
    counterexample = {
        name: normalize_hex(model.eval(value, model_completion=True).as_long(), width=width // 4)
        for name, (value, width) in inputs.items()
        if width > 0
    }
    mismatches = _z3_mismatch_list(pairs, model=model, counterexample=counterexample, z3=z3)
    return {
        "status": "failed",
        "reason": "observable_mismatch",
        "mismatches": mismatches,
        "solver_time_ms": elapsed,
        "skipped_layout_outputs": skipped_layout_outputs,
    }


def _ip_term_is_layout(
    term: dict[str, Any] | None, assignments: dict[str, dict[str, Any]], depth: int = 0
) -> bool:
    """True when every value leaf of an `ip` output term is a relocated code address.

    `ite` condition arguments are not address values; they select between successors
    and are verified by the connectivity/transition checks, so they are ignored here.
    Any input/memory/arithmetic leaf means the ip output is genuinely symbolic.
    """
    if not isinstance(term, dict) or depth > 64:
        return False
    ref = term.get("ref")
    if isinstance(ref, str):
        target = assignments.get(ref)
        return target is not None and _ip_term_is_layout(target, assignments, depth + 1)
    op = str(term.get("op") or "")
    if op == "const":
        return True
    args = term.get("args") or []
    if op == "ite":
        return len(args) >= 3 and all(_ip_term_is_layout(arg, assignments, depth + 1) for arg in args[1:3])
    return bool(args) and all(_ip_term_is_layout(arg, assignments, depth + 1) for arg in args)


def _layout_const_hex(
    term: dict[str, Any] | None, assignments: dict[str, dict[str, Any]], depth: int = 0
) -> str | None:
    """Hex value when a term resolves to a single `const`; None for structured terms."""
    if not isinstance(term, dict) or depth > 64:
        return None
    value = _term_const_int(term)
    if value is not None:
        return normalize_hex(value)
    ref = term.get("ref")
    if isinstance(ref, str) and ref in assignments:
        return _layout_const_hex(assignments[ref], assignments, depth + 1)
    return None


def _z3_output_pairs(
    output_regs: list[str],
    *,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    oracle_outputs: dict[str, Any],
    candidate_outputs: dict[str, Any],
    inputs: dict[str, tuple[Any, int]],
    z3: Any,  # noqa: ANN401
) -> tuple[list[tuple[str, Any, Any]], list[dict[str, Any]]]:
    """Build aligned (reg, oracle_expr, candidate_expr) triples for the solver."""
    oracle_assignments = {
        item["id"]: item for item in oracle.get("assignments", []) or [] if isinstance(item, dict) and "id" in item
    }
    candidate_assignments = {
        item["id"]: item for item in candidate.get("assignments", []) or [] if isinstance(item, dict) and "id" in item
    }
    oracle_cache: dict[str, Any] = {}
    candidate_cache: dict[str, Any] = {}
    pairs: list[tuple[str, Any, Any]] = []
    skipped: list[dict[str, Any]] = []
    for reg in output_regs:
        if (
            reg == "ip"
            and _ip_term_is_layout(oracle_outputs[reg], oracle_assignments)
            and _ip_term_is_layout(candidate_outputs[reg], candidate_assignments)
        ):
            skipped.append(
                {
                    "kind": "layout_ip",
                    "reg": "ip",
                    "oracle_value": _layout_const_hex(oracle_outputs[reg], oracle_assignments),
                    "candidate_value": _layout_const_hex(candidate_outputs[reg], candidate_assignments),
                    "detail": "ip output produces only relocated code addresses; edge equivalence is checked by connectivity",
                }
            )
            continue
        oracle_expr = _z3_term(
            oracle_outputs[reg],
            document=oracle,
            inputs=inputs,
            z3=z3,
            assignments=oracle_assignments,
            cache=oracle_cache,
            output_name=reg,
        )
        candidate_expr = _z3_term(
            candidate_outputs[reg],
            document=candidate,
            inputs=inputs,
            z3=z3,
            assignments=candidate_assignments,
            cache=candidate_cache,
            output_name=reg,
        )
        if not (_is_z3_array(oracle_expr, z3) or _is_z3_array(candidate_expr, z3)):
            oracle_expr, candidate_expr = _align_z3_widths(oracle_expr, candidate_expr, z3)
            oracle_expr = z3.simplify(oracle_expr)
            candidate_expr = z3.simplify(candidate_expr)
        pairs.append((reg, oracle_expr, candidate_expr))
    return pairs, skipped


def _z3_mismatch_list(
    pairs: list[tuple[str, Any, Any]],
    *,
    model: Any,  # noqa: ANN401
    counterexample: dict[str, Any],
    z3: Any,  # noqa: ANN401
) -> list[dict[str, Any]]:
    """Collect concrete output mismatches from a satisfying model."""
    mismatches: list[dict[str, Any]] = []
    for reg, oracle_expr, candidate_expr in pairs:
        if _is_z3_array(oracle_expr, z3) or _is_z3_array(candidate_expr, z3):
            if z3.is_true(model.eval(oracle_expr != candidate_expr, model_completion=True)):
                mismatches.append(
                    {
                        "kind": "memory_expr_changed",
                        "reg": reg,
                        "counterexample": counterexample,
                    }
                )
            continue
        oracle_value = model.eval(oracle_expr, model_completion=True).as_long()
        candidate_value = model.eval(candidate_expr, model_completion=True).as_long()
        if oracle_value != candidate_value:
            mismatches.append(
                {
                    "kind": "output_expr_changed",
                    "reg": reg,
                    "oracle_value": normalize_hex(oracle_value),
                    "candidate_value": normalize_hex(candidate_value),
                    "counterexample": counterexample,
                }
            )
    return mismatches


def _is_z3_array(expr: Any, z3: Any) -> bool:  # noqa: ANN401
    try:
        return expr.sort().kind() == z3.Z3_ARRAY_SORT
    except Exception:
        return False


def _mapped_candidate_detail(mapped: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(mapped, dict):
        return None
    return {
        "id": mapped.get("candidate_id"),
        "name": mapped.get("candidate_name"),
        "entry": mapped.get("candidate_entry"),
        "sources": list(mapped.get("sources", []) or []),
    }


def _ssa_function_report_detail(function: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(function, dict):
        return None
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    outputs = function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}
    inputs = function.get("inputs", []) if isinstance(function.get("inputs"), list) else []
    return {
        "part": function.get("part") if isinstance(function.get("part"), dict) else None,
        "function_entry": function.get("function_entry") if isinstance(function.get("function_entry"), dict) else None,
        "entry": function.get("entry"),
        "jumpkind": source.get("jumpkind"),
        "transfer": source.get("transfer")
        if isinstance(source.get("transfer"), dict)
        else _transfer_info_from_instructions(source),
        "instruction_count": source.get("instruction_count", len(instructions)),
        "instructions": instructions,
        "instructions_truncated": 0,
        "function_machine_code_sha256": source.get("function_machine_code_sha256"),
        "function_machine_code_size": source.get("function_machine_code_size"),
        "machine_code_sha256": source.get("machine_code_sha256"),
        "machine_code_size": source.get("machine_code_size"),
        "inputs": _ssa_input_names(inputs),
        "outputs": sorted(str(name) for name in outputs),
        "input_count": len(inputs),
        "assignment_count": len(function.get("assignments", []) or []),
    }


def _ssa_region_report_detail(group: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    if not group:
        return None
    ordered = sorted(
        [part for part in group if isinstance(part, dict)],
        key=lambda part: int((part.get("part", {}) if isinstance(part.get("part"), dict) else {}).get("index", 0)),
    )
    if not ordered:
        return None
    first = _ssa_function_report_detail(ordered[0])
    if first is None:
        return None
    instructions: list[dict[str, Any]] = []
    for part in ordered:
        source = part.get("source", {}) if isinstance(part.get("source"), dict) else {}
        for instruction in source.get("instructions", []) or []:
            if isinstance(instruction, dict):
                instructions.append(instruction)
            if len(instructions) >= 8:
                break
        if len(instructions) >= 8:
            break
    return {
        "part_count": len(ordered),
        "entry": first.get("entry"),
        "function_entry": first.get("function_entry"),
        "jumpkind": first.get("jumpkind"),
        "instructions": instructions,
        "instructions_truncated": max(
            0,
            sum(
                len(
                    (part.get("source", {}) if isinstance(part.get("source"), dict) else {}).get("instructions", [])
                    or []
                )
                for part in ordered
            )
            - len(instructions),
        ),
    }


def _ssa_input_names(inputs: list[Any]) -> list[str]:
    names: set[str] = set()
    for item in inputs:
        if isinstance(item, dict):
            kind = str(item.get("kind") or "").lower()
            name = str(item.get("name") or "").lower()
            if kind == "memory" or name in {"mem", "memory"}:
                names.add("memory")
            elif name:
                names.add(name)
        elif isinstance(item, str):
            name = item.lower()
            names.add("memory" if name in {"mem", "memory"} else name)
    return sorted(names)


def _summary_detail(summary: dict[str, Any]) -> dict[str, Any]:
    if summary.get("status") != "passed":
        return {key: summary.get(key) for key in ("status", "reason", "mismatches") if key in summary}
    function = summary.get("function", {}) if isinstance(summary.get("function"), dict) else {}
    return {
        "status": summary.get("status"),
        "part_count": summary.get("part_count"),
        "terminal_count": summary.get("terminal_count"),
        "loop_unroll_bound": summary.get("loop_unroll_bound"),
        "blocks_composed": summary.get("blocks_composed"),
        "branch_merges": summary.get("branch_merges"),
        "branch_prunes": summary.get("branch_prunes"),
        "loop_cuts": summary.get("loop_cuts"),
        "outputs": sorted((function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}).keys()),
        "input_count": len(function.get("inputs", []) or []),
        "assignment_count": len(function.get("assignments", []) or []),
    }


def _abi_functions(abi_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in abi_manifest.get("functions", []) or [] if isinstance(item, dict)]


def _abi_data_segment_para(abi_manifest: dict[str, Any]) -> int:
    contract = (
        abi_manifest.get("data_segment_contract") if isinstance(abi_manifest.get("data_segment_contract"), dict) else {}
    )
    for key in ("static_data_segment", "link_data_segment", "data_segment"):
        value = _optional_int(contract.get(key))
        if value is not None:
            return value & 0xFFFF
    return 0x0100


def _abi_observables(abi_function: dict[str, Any]) -> dict[str, Any]:
    return_regs: set[str] = set()
    preserved_regs: set[str] = set()
    for item in abi_function.get("returns", []) or []:
        if isinstance(item, dict) and item.get("location"):
            return_regs.add(str(item["location"]).lower())
        elif isinstance(item, str):
            return_regs.add(item.lower())
    for item in abi_function.get("preserved", []) or []:
        preserved_regs.add(str(item).lower())
    preserved_regs -= {str(item).lower() for item in abi_function.get("clobbers", []) or []}
    explicit_regs = abi_function.get("ssa_observe_regs")
    if explicit_regs is not None:
        regs = {str(item).lower() for item in explicit_regs or []}
    else:
        regs = {"sp"} | return_regs | preserved_regs
    memory = [item for item in abi_function.get("effects", []) or [] if isinstance(item, dict)]
    return {"regs": sorted(regs), "memory": memory}


def _abi_input_constraints(abi_function: dict[str, Any]) -> list[dict[str, Any]]:
    constraints = [item for item in abi_function.get("input_constraints", []) or [] if isinstance(item, dict)]
    convention = str(abi_function.get("calling_convention") or "").lower()
    has_sp_constraint = any(str(item.get("name") or "").lower() == "sp" for item in constraints)
    if convention.startswith("msc16") and not has_sp_constraint:
        constraints.append({"name": "sp", "kind": "unsigned_range", "min": "0x0100", "max": "0xfffe"})
    return constraints


def _ssa_function_groups(functions: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        keys = {str(info.get("id") or ""), str(info.get("name") or "")}
        for key in keys:
            if key:
                groups.setdefault(key, []).append(function)
    return groups


def _ssa_group_for_abi_function(
    groups: dict[str, list[dict[str, Any]]],
    abi_function: dict[str, Any],
    *,
    side: str,
    mapped: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if side == "candidate" and isinstance(mapped, dict):
        for key in (str(mapped.get("candidate_id") or ""), str(mapped.get("candidate_name") or "")):
            if key and key in groups:
                return groups[key]
    prefixes = ("oracle_", "candidate_") if side == "oracle" else ("candidate_", "oracle_")
    for key_name in (f"{prefixes[0]}id", f"{prefixes[0]}name", "id", "name"):
        key = str(abi_function.get(key_name) or "")
        if key and key in groups:
            return groups[key]
    name = str(abi_function.get("name") or "")
    return groups.get(name, [])


def _summarize_abi_function(
    parts: list[dict[str, Any]],
    *,
    abi_function: dict[str, Any],
    observables: dict[str, Any],
    data_segment_para: int,
    max_loop_unroll: int = 0,
    require_complete_paths: bool = False,
    enable_constant_branch_pruning: bool = False,
) -> dict[str, Any]:
    if not parts:
        return {"status": "refused", "reason": "function_missing", "mismatches": [{"kind": "function_missing"}]}
    block_by_key: dict[int, dict[str, Any]] = {}
    for part in parts:
        entry = part.get("entry", {}) if isinstance(part.get("entry"), dict) else {}
        for value in (_optional_int(entry.get("linear")), _optional_int(entry.get("ip"))):
            if value is not None:
                block_by_key[value & 0xFFFF] = part
    callsite_ordinals = _abi_callsite_ordinals(parts)
    start = min(
        parts,
        key=lambda item: int((item.get("part", {}) if isinstance(item.get("part"), dict) else {}).get("index", 0)),
    )
    state = _initial_abi_state(abi_function, observables=observables, data_segment_para=data_segment_para)
    compose_stats = {"blocks_composed": 0, "branch_merges": 0, "branch_prunes": 0, "loop_cuts": 0}
    try:
        final_state, terminal_count = _compose_abi_state(
            start,
            state,
            abi_function=abi_function,
            block_by_key=block_by_key,
            path=[],
            max_loop_unroll=max_loop_unroll,
            data_segment_para=data_segment_para,
            callsite_ordinals=callsite_ordinals,
            compose_stats=compose_stats,
            enable_constant_branch_pruning=enable_constant_branch_pruning,
        )
        if terminal_count <= 0:
            raise LowerFailure("loop_bound_no_terminal", "bounded loop summary did not reach a return path")
        if require_complete_paths and compose_stats["loop_cuts"] > 0:
            raise LowerFailure(
                "loop_bound_incomplete", f"bounded loop summary cut {compose_stats['loop_cuts']} path(s)"
            )
        summary_function = _materialize_abi_summary(
            start,
            final_state,
            abi_function=abi_function,
            observables=observables,
            data_segment_para=data_segment_para,
        )
    except LowerFailure as ex:
        return {"status": "refused", "reason": ex.reason, "mismatches": [{"kind": ex.reason, "detail": ex.message}]}
    except RecursionError:
        return {
            "status": "refused",
            "reason": "loop_bound_incomplete",
            "mismatches": [
                {
                    "kind": "loop_bound_incomplete",
                    "detail": "bounded loop summary exceeded Python recursion depth",
                }
            ],
        }
    return {
        "status": "passed",
        "part_count": len(parts),
        "terminal_count": terminal_count,
        "loop_unroll_bound": max_loop_unroll,
        "blocks_composed": compose_stats["blocks_composed"],
        "branch_merges": compose_stats["branch_merges"],
        "branch_prunes": compose_stats["branch_prunes"],
        "loop_cuts": compose_stats["loop_cuts"],
        "function": summary_function,
    }


def _initial_abi_state(
    abi_function: dict[str, Any] | None = None,
    *,
    observables: dict[str, Any] | None = None,
    data_segment_para: int = 0x0100,
) -> dict[str, dict[str, Any]]:
    if abi_function is None:
        state = {
            name: {"op": "input", "name": name, "width": width} for name, width in REG_BY_OFFSET.values()
        }
        state["memory"] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
        return state

    reg_widths = dict(REG_BY_OFFSET.values())
    preserved = {str(item).lower() for item in abi_function.get("preserved", []) or []}
    observed_regs = {str(item).lower() for item in (observables or {}).get("regs", []) or []}
    symbolic_regs = {"sp"} | (preserved & observed_regs)
    for item in abi_function.get("inputs", []) or []:
        if isinstance(item, dict) and item.get("location"):
            symbolic_regs.add(str(item["location"]).lower())
        elif isinstance(item, str):
            symbolic_regs.add(item.lower())

    defaults = {
        "flags": 0x0202,
        "sp": 0xFF00,
        "ds": data_segment_para,
        "es": data_segment_para,
        "ss": 0x3000,
    }
    state: dict[str, dict[str, Any]] = {}
    for name, width in reg_widths.items():
        if name in symbolic_regs:
            state[name] = {"op": "input", "name": name, "width": width}
        else:
            state[name] = {
                "op": "const",
                "value": normalize_hex(defaults.get(name, 0), width=max(1, width // 4)),
                "width": width,
            }
    state["memory"] = _initial_abi_memory(abi_function, state)
    return state


def _initial_abi_memory(abi_function: dict[str, Any], state: dict[str, dict[str, Any]]) -> dict[str, Any]:
    memory: dict[str, Any] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    stack_args = [item for item in abi_function.get("stack_args", []) or [] if isinstance(item, dict)]
    if not stack_args:
        return memory
    return_bytes = 4 if str(abi_function.get("kind") or "").lower() == "far" else 2
    next_offset = return_bytes
    for index, item in enumerate(stack_args):
        width = int(_optional_int(item.get("width")) or 16)
        size = max(1, (width + 7) // 8)
        entry_offset = _optional_int(item.get("entry_sp_offset"))
        if entry_offset is None:
            entry_offset = next_offset
        next_offset = int(entry_offset) + size
        name = re.sub(r"[^A-Za-z0-9_]+", "_", str(item.get("name") or f"arg{index}")).strip("_") or f"arg{index}"
        memory = {
            "op": "storele",
            "width": 0,
            "args": [
                memory,
                _stack_address_term(state["ss"], state["sp"], int(entry_offset)),
                {"op": "input", "name": f"arg_{name}", "width": width},
            ],
        }
    return memory


def _stack_address_term(ss_term: dict[str, Any], sp_term: dict[str, Any], offset: int) -> dict[str, Any]:
    return {
        "op": "add",
        "width": 32,
        "args": [
            {
                "op": "shl",
                "width": 32,
                "args": [
                    {"op": "zext", "width": 32, "args": [copy.deepcopy(ss_term)]},
                    {"op": "const", "value": "0x04", "width": 8},
                ],
            },
            {
                "op": "zext",
                "width": 32,
                "args": [
                    {
                        "op": "add",
                        "width": 16,
                        "args": [
                            copy.deepcopy(sp_term),
                            {"op": "const", "value": normalize_hex(offset & 0xFFFF, width=4), "width": 16},
                        ],
                    }
                ],
            },
        ],
    }


def _compose_abi_state(
    block: dict[str, Any],
    incoming_state: dict[str, dict[str, Any]],
    *,
    abi_function: dict[str, Any],
    block_by_key: dict[int, dict[str, Any]],
    path: list[int],
    max_loop_unroll: int = 0,
    data_segment_para: int = 0x0100,
    callsite_ordinals: dict[int, dict[str, int]] | None = None,
    compose_stats: dict[str, int] | None = None,
    enable_constant_branch_pruning: bool = False,
) -> tuple[dict[str, dict[str, Any]], int]:
    entry = block.get("entry", {}) if isinstance(block.get("entry"), dict) else {}
    key = (_optional_int(entry.get("linear")) or _optional_int(entry.get("ip")) or 0) & 0xFFFF
    if compose_stats is not None:
        compose_stats["blocks_composed"] = compose_stats.get("blocks_composed", 0) + 1
    if _compose_loop_cut(block_key=key, path=path, max_loop_unroll=max_loop_unroll, compose_stats=compose_stats):
        return incoming_state, 0
    source = block.get("source", {}) if isinstance(block.get("source"), dict) else {}
    block_outputs = block.get("outputs", {}) if isinstance(block.get("outputs"), dict) else {}
    state = _compose_block_outputs(block, block_outputs, incoming_state)
    if source.get("jumpkind") == "Ijk_Call":
        state = _compose_abi_call(
            block,
            state,
            abi_function=abi_function,
            data_segment_para=data_segment_para,
            callsite_ordinals=callsite_ordinals or {},
        )
    if str(source.get("jumpkind") or "").startswith(("Ijk_Ret", "Ijk_Sig")):
        return state, 1
    transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else {}
    if transfer.get("kind") == "direct_successors" and "ip" not in block_outputs:
        raise LowerFailure(
            "branch_predicate_unobserved",
            "direct-successor block requires `ip` in SSA outputs for function-level composition",
        )
    ip_term = state.get("ip")
    if ip_term is None:
        raise LowerFailure("unsupported_ir", "function-level ABI summary requires `ip` in SSA outputs")
    branch = _direct_branch_targets(ip_term, block_by_key)
    next_path = [*path, key]
    if branch is not None:
        return _compose_branch_step(
            branch,
            state,
            next_path,
            abi_function=abi_function,
            block_by_key=block_by_key,
            max_loop_unroll=max_loop_unroll,
            data_segment_para=data_segment_para,
            callsite_ordinals=callsite_ordinals,
            compose_stats=compose_stats,
            enable_constant_branch_pruning=enable_constant_branch_pruning,
        )
    direct = _direct_successor_target(ip_term, block_by_key)
    if direct is not None:
        return _compose_abi_state(
            direct,
            state,
            abi_function=abi_function,
            block_by_key=block_by_key,
            path=next_path,
            max_loop_unroll=max_loop_unroll,
            data_segment_para=data_segment_para,
            callsite_ordinals=callsite_ordinals,
            compose_stats=compose_stats,
            enable_constant_branch_pruning=enable_constant_branch_pruning,
        )
    return state, 1


def _compose_loop_cut(
    *,
    block_key: int,
    path: list[int],
    max_loop_unroll: int,
    compose_stats: dict[str, int] | None,
) -> bool:
    """Enforce the loop visit budget; True when the path is cut at the limit."""
    visits = path.count(block_key)
    if visits:
        if max_loop_unroll <= 0:
            raise LowerFailure(
                "unsupported_ir", f"loop or repeated block reached at {normalize_hex(block_key, width=4)}"
            )
        if visits > max_loop_unroll:
            if compose_stats is not None:
                compose_stats["loop_cuts"] = compose_stats.get("loop_cuts", 0) + 1
            return True
    if block_key in path and max_loop_unroll <= 0:
        raise LowerFailure(
            "unsupported_ir", f"loop or repeated block reached at {normalize_hex(block_key, width=4)}"
        )
    return False


def _compose_block_outputs(
    block: dict[str, Any],
    block_outputs: dict[str, Any],
    incoming_state: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Compose block outputs into the state by inlining assignments and substituting inputs."""
    assignments = {
        str(item["id"]): item for item in block.get("assignments", []) or [] if isinstance(item, dict) and "id" in item
    }
    state = dict(incoming_state)
    inline_cache: dict[str, dict[str, Any]] = {}
    for name, term in block_outputs.items():
        if not isinstance(term, dict):
            continue
        inlined = _inline_ssa_json_term(term, assignments=assignments, cache=inline_cache)
        state[str(name)] = _substitute_abi_inputs(inlined, incoming_state)
    return state


def _compose_branch_step(
    branch: tuple[Any, Any, Any],
    state: dict[str, dict[str, Any]],
    next_path: list[int],
    *,
    abi_function: dict[str, Any],
    block_by_key: dict[int, dict[str, Any]],
    max_loop_unroll: int,
    data_segment_para: int,
    callsite_ordinals: dict[int, dict[str, int]] | None,
    compose_stats: dict[str, Any] | None,
    enable_constant_branch_pruning: bool,
) -> tuple[dict[str, dict[str, Any]], int]:
    """Compose both branch arms, pruning constant conditions and merging live arms."""
    cond, true_target, false_target = branch
    cond_value = _const_json_term_value(cond) if enable_constant_branch_pruning else None
    if cond_value is not None:
        if compose_stats is not None:
            compose_stats["branch_prunes"] = compose_stats.get("branch_prunes", 0) + 1
        return _compose_or_terminal(
            true_target if cond_value else false_target,
            state,
            abi_function=abi_function,
            block_by_key=block_by_key,
            path=next_path,
            max_loop_unroll=max_loop_unroll,
            data_segment_para=data_segment_para,
            callsite_ordinals=callsite_ordinals,
            compose_stats=compose_stats,
            enable_constant_branch_pruning=enable_constant_branch_pruning,
        )
    if compose_stats is not None:
        compose_stats["branch_merges"] = compose_stats.get("branch_merges", 0) + 1
    true_state, true_terminals = _compose_or_terminal(
        true_target,
        state,
        abi_function=abi_function,
        block_by_key=block_by_key,
        path=next_path,
        max_loop_unroll=max_loop_unroll,
        data_segment_para=data_segment_para,
        callsite_ordinals=callsite_ordinals,
        compose_stats=compose_stats,
        enable_constant_branch_pruning=enable_constant_branch_pruning,
    )
    false_state, false_terminals = _compose_or_terminal(
        false_target,
        state,
        abi_function=abi_function,
        block_by_key=block_by_key,
        path=next_path,
        max_loop_unroll=max_loop_unroll,
        data_segment_para=data_segment_para,
        callsite_ordinals=callsite_ordinals,
        compose_stats=compose_stats,
        enable_constant_branch_pruning=enable_constant_branch_pruning,
    )
    if true_terminals <= 0 and false_terminals <= 0:
        return state, 0
    if true_terminals <= 0:
        return false_state, false_terminals
    if false_terminals <= 0:
        return true_state, true_terminals
    return _merge_abi_states(cond, true_state, false_state), true_terminals + false_terminals


def _compose_abi_call(
    block: dict[str, Any],
    state: dict[str, dict[str, Any]],
    *,
    abi_function: dict[str, Any],
    data_segment_para: int,
    callsite_ordinals: dict[int, dict[str, int]],
) -> dict[str, dict[str, Any]]:
    policy = str(abi_function.get("ssa_call_policy") or "ignore_balanced").strip().lower()
    if policy in {"summary", "summaries", "callee_summary", "call_summary"}:
        return _compose_abi_summary_call(
            block,
            state,
            abi_function=abi_function,
            data_segment_para=data_segment_para,
            callsite_ordinals=callsite_ordinals,
        )
    return _compose_abi_balanced_ignored_call(block, state, abi_function=abi_function)


def _compose_abi_summary_call(
    block: dict[str, Any],
    state: dict[str, dict[str, Any]],
    *,
    abi_function: dict[str, Any],
    data_segment_para: int,
    callsite_ordinals: dict[int, dict[str, int]],
) -> dict[str, dict[str, Any]]:
    summary = _abi_call_summary_for_block(block, abi_function, callsite_ordinals=callsite_ordinals)
    if summary is None:
        context = _callsite_error_context(block, label="no matching callee summary")
        raise LowerFailure(
            "callee_summary_missing", f"function summary stops at a call with no matching callee summary; {context}"
        )
    source = block.get("source", {}) if isinstance(block.get("source"), dict) else {}
    transfer = source.get("transfer", {}) if isinstance(source.get("transfer"), dict) else {}
    fallthrough = transfer.get("fallthrough", {}) if isinstance(transfer.get("fallthrough"), dict) else {}
    fallthrough_ip = _optional_int(fallthrough.get("low16") or fallthrough.get("linear"))
    if fallthrough_ip is None:
        context = _callsite_error_context(block, label="missing fallthrough")
        raise LowerFailure("call_boundary", f"callee summary requires a concrete fallthrough address; {context}")

    call_state = dict(state)
    call_key = _abi_call_summary_key(summary, block)
    return_bytes = _abi_call_return_bytes(summary)
    post_call_sp = call_state.get("sp")
    if not isinstance(post_call_sp, dict):
        context = _callsite_error_context(block, label="missing post-call sp")
        raise LowerFailure("call_boundary", f"callee summary requires `sp` in SSA outputs; {context}")

    _record_abi_call_arguments(
        call_state, summary, call_key=call_key, post_call_sp=post_call_sp, return_bytes=return_bytes
    )
    _apply_abi_call_returns_and_clobbers(call_state, summary, call_key=call_key)
    _apply_abi_call_memory_effects(call_state, summary, call_key=call_key, data_segment_para=data_segment_para)

    cleanup = _optional_int(summary.get("callee_stack_cleanup")) or _optional_int(summary.get("stack_cleanup")) or 0
    call_state["sp"] = {
        "op": "add",
        "width": 16,
        "args": [
            copy.deepcopy(post_call_sp),
            {"op": "const", "value": normalize_hex((return_bytes + cleanup) & 0xFFFF, width=4), "width": 16},
        ],
    }
    call_state["ip"] = {"op": "const", "value": normalize_hex(fallthrough_ip & 0xFFFF, width=4), "width": 16}
    return call_state


def _compose_abi_balanced_ignored_call(
    block: dict[str, Any],
    state: dict[str, dict[str, Any]],
    *,
    abi_function: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    policy = str(abi_function.get("ssa_call_policy") or "ignore_balanced").strip().lower()
    if policy not in {"ignore", "ignore_balanced", "ignore-call", "balanced_ignore", "msc_prologue_stack_check"}:
        context = _callsite_error_context(block, label="no callee summary policy")
        raise LowerFailure(
            "call_boundary", f"function summary stops at a call; callee summaries are required; {context}"
        )
    if policy == "msc_prologue_stack_check" and not _is_msc_stack_check_prologue_call(block):
        context = _callsite_error_context(block, label="msc stack check policy mismatch")
        raise LowerFailure(
            "call_boundary", f"msc_prologue_stack_check only applies to the entry prologue helper call; {context}"
        )
    source = block.get("source", {}) if isinstance(block.get("source"), dict) else {}
    transfer = source.get("transfer", {}) if isinstance(source.get("transfer"), dict) else {}
    fallthrough = transfer.get("fallthrough", {}) if isinstance(transfer.get("fallthrough"), dict) else {}
    fallthrough_ip = _optional_int(fallthrough.get("low16") or fallthrough.get("linear"))
    if fallthrough_ip is None:
        context = _callsite_error_context(block, label="missing fallthrough")
        raise LowerFailure("call_boundary", f"balanced ignored call requires a concrete fallthrough address; {context}")
    call_state = dict(state)
    sp_term = call_state.get("sp")
    if not isinstance(sp_term, dict):
        context = _callsite_error_context(block, label="missing pre-call sp")
        raise LowerFailure("call_boundary", f"balanced ignored call requires `sp` in SSA outputs; {context}")
    call_state["sp"] = {
        "op": "add",
        "width": 16,
        "args": [copy.deepcopy(sp_term), {"op": "const", "value": "0x0002", "width": 16}],
    }
    call_state["ip"] = {"op": "const", "value": normalize_hex(fallthrough_ip & 0xFFFF, width=4), "width": 16}
    return call_state


def _callsite_error_context(block: dict[str, Any], *, label: str) -> str:
    source = block.get("source", {}) if isinstance(block.get("source"), dict) else {}
    entry = block.get("entry", {}) if isinstance(block.get("entry"), dict) else {}
    transfer = source.get("transfer", {}) if isinstance(source.get("transfer"), dict) else {}
    target = transfer.get("target", {}) if isinstance(transfer.get("target"), dict) else {}
    fallthrough = transfer.get("fallthrough", {}) if isinstance(transfer.get("fallthrough"), dict) else {}
    target_low16 = _optional_int(target.get("low16") or target.get("raw"))
    target_linear = _optional_int(target.get("linear"))
    fallthrough_low16 = _optional_int(fallthrough.get("low16") or fallthrough.get("linear"))
    cs = entry.get("cs")
    ip = entry.get("ip")
    linear = entry.get("linear")
    if cs is not None or ip is not None or linear is not None:
        parts = []
        if cs is not None or ip is not None:
            parts.append(f"{cs if cs is not None else '????'}:{ip if ip is not None else '????'}")
        if linear is not None:
            parts.append(f"{linear}")
        callsite_ip = " / ".join(parts)
    else:
        callsite_ip = "<unknown>"
    target_text = f"target=0x{target_low16:04x}" if target_low16 is not None else "target=<unknown>"
    if target_linear is not None:
        target_text = f"{target_text} linear=0x{target_linear:04x}"
    if fallthrough_low16 is not None:
        target_text += f", fallthrough=0x{fallthrough_low16:04x}"
    return f"{label} at {callsite_ip} ({target_text})"


def _abi_callsite_ordinals(parts: list[dict[str, Any]]) -> dict[int, dict[str, int]]:
    result: dict[int, dict[str, int]] = {}
    per_target: dict[int, int] = defaultdict(int)
    global_ordinal = 0
    sorted_parts = sorted(
        parts,
        key=lambda part: (
            int((part.get("part", {}) if isinstance(part.get("part"), dict) else {}).get("index", 0)),
            _optional_int((part.get("entry", {}) if isinstance(part.get("entry"), dict) else {}).get("linear")) or 0,
        ),
    )
    for part in sorted_parts:
        source = part.get("source", {}) if isinstance(part.get("source"), dict) else {}
        if source.get("jumpkind") != "Ijk_Call":
            continue
        transfer = source.get("transfer", {}) if isinstance(source.get("transfer"), dict) else {}
        target = transfer.get("target") if isinstance(transfer.get("target"), dict) else {}
        target_low16 = _optional_int(target.get("low16") or target.get("raw"))
        if target_low16 is None:
            continue
        entry = part.get("entry", {}) if isinstance(part.get("entry"), dict) else {}
        key = (_optional_int(entry.get("linear")) or _optional_int(entry.get("ip")) or 0) & 0xFFFF
        target_key = target_low16 & 0xFFFF
        result[key] = {
            "global_ordinal": global_ordinal,
            "target_ordinal": per_target[target_key],
            "target_low16": target_key,
        }
        per_target[target_key] += 1
        global_ordinal += 1
    return result


def _abi_call_summaries(abi_function: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("call_summaries", "callee_summaries", "calls", "callees"):
        values = abi_function.get(key)
        if isinstance(values, list):
            return [item for item in values if isinstance(item, dict)]
    return []


def _abi_call_summary_for_block(
    block: dict[str, Any],
    abi_function: dict[str, Any],
    *,
    callsite_ordinals: dict[int, dict[str, int]],
) -> dict[str, Any] | None:
    summaries = _abi_call_summaries(abi_function)
    if not summaries:
        return None
    source = block.get("source", {}) if isinstance(block.get("source"), dict) else {}
    transfer = source.get("transfer", {}) if isinstance(source.get("transfer"), dict) else {}
    target_values = _abi_call_target_values_for_block(transfer)
    callsite_info = _abi_callsite_info(block, callsite_ordinals)
    matching_target = [
        summary
        for summary in summaries
        if any(_abi_call_summary_matches_target(summary, raw=raw, low16=low16) for raw, low16 in target_values)
        or not _abi_call_summary_has_target(summary)
    ]
    explicit_matches = [
        summary
        for summary in matching_target
        if _abi_call_summary_matches_callsite(summary, block=block, callsite_info=callsite_info)
    ]
    if len(explicit_matches) == 1:
        return explicit_matches[0]
    ordinal_matches = [
        summary for summary in matching_target if _abi_call_summary_matches_ordinal(summary, callsite_info)
    ]
    if len(ordinal_matches) == 1:
        return ordinal_matches[0]
    if len(matching_target) == 1 and not _abi_call_summary_has_callsite_selector(matching_target[0]):
        return matching_target[0]
    if len(summaries) == 1 and not _abi_call_summary_has_target(summaries[0]):
        return summaries[0]
    return None


def _abi_callsite_info(block: dict[str, Any], callsite_ordinals: dict[int, dict[str, int]]) -> dict[str, int]:
    entry = block.get("entry", {}) if isinstance(block.get("entry"), dict) else {}
    key = (_optional_int(entry.get("linear")) or _optional_int(entry.get("ip")) or 0) & 0xFFFF
    return callsite_ordinals.get(key, {})


def _abi_call_summary_has_target(summary: dict[str, Any]) -> bool:
    return any(
        key in summary
        for key in (
            "target",
            "targets",
            "target_set",
            "target_candidates",
            "target_raw",
            "target_raws",
            "target_linear",
            "target_linears",
            "target_low16",
            "target_low16s",
            "raw",
            "linear",
            "ip",
            "ips",
            "offset",
            "offsets",
        )
    )


def _abi_call_summary_has_callsite_selector(summary: dict[str, Any]) -> bool:
    return any(
        key in summary
        for key in (
            "callsite",
            "callsite_linear",
            "callsite_low16",
            "callsite_ip",
            "callsite_delta",
            "callsite_entry_delta",
            "block_delta",
            "entry_delta",
            "callsite_ordinal",
            "call_ordinal",
            "global_ordinal",
            "target_ordinal",
            "ordinal",
        )
    )


def _abi_call_summary_matches_callsite(
    summary: dict[str, Any],
    *,
    block: dict[str, Any],
    callsite_info: dict[str, int],
) -> bool:
    entry = block.get("entry", {}) if isinstance(block.get("entry"), dict) else {}
    part = block.get("part", {}) if isinstance(block.get("part"), dict) else {}
    linear = _optional_int(entry.get("linear"))
    ip = _optional_int(entry.get("ip"))
    delta = _optional_int(part.get("entry_delta"))
    matched, saw_selector = _callsite_scalar_selectors_match(summary, linear=linear, ip=ip, delta=delta)
    if not matched:
        return False
    if _abi_call_summary_matches_ordinal(summary, callsite_info):
        saw_selector = True
    return saw_selector


def _callsite_scalar_selectors_match(
    summary: dict[str, Any],
    *,
    linear: int | None,
    ip: int | None,
    delta: int | None,
) -> tuple[bool, bool]:
    """Check the scalar callsite selectors; return (all_match, saw_selector)."""
    saw_selector = False
    for key in ("callsite", "callsite_linear"):
        expected = _optional_int(summary.get(key))
        if expected is not None:
            saw_selector = True
            if linear != expected:
                return False, saw_selector
    for key in ("callsite_low16", "callsite_ip"):
        expected = _optional_int(summary.get(key))
        if expected is not None:
            saw_selector = True
            if ip is None or (ip & 0xFFFF) != (expected & 0xFFFF):
                return False, saw_selector
    for key in ("callsite_delta", "callsite_entry_delta", "block_delta", "entry_delta"):
        expected = _optional_int(summary.get(key))
        if expected is not None:
            saw_selector = True
            if delta is None or (delta & 0xFFFF) != (expected & 0xFFFF):
                return False, saw_selector
    return True, saw_selector


def _abi_call_summary_matches_ordinal(summary: dict[str, Any], callsite_info: dict[str, int]) -> bool:
    for key in ("callsite_ordinal", "call_ordinal", "global_ordinal"):
        expected = _optional_int(summary.get(key))
        if expected is not None:
            return callsite_info.get("global_ordinal") == expected
    for key in ("target_ordinal", "ordinal"):
        expected = _optional_int(summary.get(key))
        if expected is not None:
            return callsite_info.get("target_ordinal") == expected
    return False


def _abi_call_summary_matches_target(summary: dict[str, Any], *, raw: int | None, low16: int | None) -> bool:
    if _scalar_target_keys_match(summary, raw=raw, low16=low16):
        return True
    if _list_target_keys_match(summary, raw=raw, low16=low16):
        return True
    return _candidate_target_items_match(summary, raw=raw, low16=low16)


def _scalar_target_keys_match(summary: dict[str, Any], *, raw: int | None, low16: int | None) -> bool:
    """Match scalar target selector keys against the raw/low16 pair."""
    for key in ("target", "target_raw", "target_linear", "raw", "linear"):
        expected = _optional_int(summary.get(key))
        if expected is not None and raw is not None and expected == raw:
            return True
        if expected is not None and low16 is not None and (expected & 0xFFFF) == low16:
            return True
    for key in ("target_low16", "ip", "offset"):
        expected = _optional_int(summary.get(key))
        if expected is not None and low16 is not None and (expected & 0xFFFF) == low16:
            return True
    return False


def _list_target_keys_match(summary: dict[str, Any], *, raw: int | None, low16: int | None) -> bool:
    """Match list-valued target selector keys against the raw/low16 pair."""
    for key in ("target_raws", "target_linears"):
        for expected in _iter_optional_ints(summary.get(key)):
            if raw is not None and expected == raw:
                return True
            if low16 is not None and (expected & 0xFFFF) == low16:
                return True
    for key in ("target_low16s", "ips", "offsets"):
        for expected in _iter_optional_ints(summary.get(key)):
            if low16 is not None and (expected & 0xFFFF) == low16:
                return True
    return False


def _candidate_target_items_match(summary: dict[str, Any], *, raw: int | None, low16: int | None) -> bool:
    """Match structured target candidate items against the raw/low16 pair."""
    for key in ("targets", "target_set", "target_candidates"):
        for item in summary.get(key, []) or []:
            item_raw, item_low16 = _abi_target_value_pair(item)
            if item_raw is not None and raw is not None and item_raw == raw:
                return True
            if item_low16 is not None and low16 is not None and (item_low16 & 0xFFFF) == (low16 & 0xFFFF):
                return True
            if item_raw is not None and low16 is not None and (item_raw & 0xFFFF) == (low16 & 0xFFFF):
                return True
    return False


def _abi_call_target_values_for_block(transfer: dict[str, Any]) -> list[tuple[int | None, int | None]]:
    values: list[tuple[int | None, int | None]] = []
    target = transfer.get("target") if isinstance(transfer.get("target"), dict) else None
    if target is not None:
        values.append(_abi_target_value_pair(target))
    for key in ("target_candidates", "targets", "candidate_targets", "recovered_targets"):
        for item in transfer.get(key, []) or []:
            values.append(_abi_target_value_pair(item))
    unique: list[tuple[int | None, int | None]] = []
    seen: set[tuple[int | None, int | None]] = set()
    for raw, low16 in values:
        if raw is None and low16 is None:
            continue
        key = (raw, None if low16 is None else low16 & 0xFFFF)
        if key in seen:
            continue
        seen.add(key)
        unique.append(key)
    return unique


def _abi_target_value_pair(item: Any) -> tuple[int | None, int | None]:  # noqa: ANN401
    if isinstance(item, dict):
        raw = None
        for key in ("target", "target_raw", "raw", "linear", "target_linear"):
            raw = _optional_int(item.get(key))
            if raw is not None:
                break
        low16 = None
        for key in ("target_low16", "low16", "ip", "offset"):
            low16 = _optional_int(item.get(key))
            if low16 is not None:
                break
        if low16 is None and raw is not None:
            low16 = raw & 0xFFFF
        return raw, low16
    value = _optional_int(item)
    if value is None:
        return None, None
    return value, value & 0xFFFF


def _iter_optional_ints(value: Any) -> list[int]:  # noqa: ANN401
    values = value if isinstance(value, list) else [value]
    result: list[int] = []
    for item in values:
        parsed = _optional_int(item)
        if parsed is not None:
            result.append(parsed)
    return result


def _abi_call_summary_key(summary: dict[str, Any], block: dict[str, Any]) -> str:
    for key in ("id", "name", "target_name", "callee", "callee_name"):
        value = str(summary.get(key) or "")
        if value:
            return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_") or "call"
    source = block.get("source", {}) if isinstance(block.get("source"), dict) else {}
    transfer = source.get("transfer", {}) if isinstance(source.get("transfer"), dict) else {}
    target = transfer.get("target") if isinstance(transfer.get("target"), dict) else {}
    low16 = _optional_int(target.get("low16") or target.get("raw"))
    if low16 is not None:
        return f"target_{low16 & 0xFFFF:04x}"
    part = block.get("part", {}) if isinstance(block.get("part"), dict) else {}
    delta = _optional_int(part.get("entry_delta")) or 0
    return f"call_{delta & 0xFFFF:04x}"


def _abi_call_return_bytes(summary: dict[str, Any]) -> int:
    explicit = _optional_int(summary.get("return_bytes"))
    if explicit is not None:
        return max(0, explicit)
    return 4 if str(summary.get("kind") or "").lower() == "far" else 2


def _record_abi_call_arguments(
    state: dict[str, dict[str, Any]],
    summary: dict[str, Any],
    *,
    call_key: str,
    post_call_sp: dict[str, Any],
    return_bytes: int,
) -> None:
    ss_term = state.get("ss")
    memory = state.get("memory")
    if not isinstance(ss_term, dict) or not isinstance(memory, dict):
        raise LowerFailure(
            "callee_summary_missing", "callee summary argument capture requires `ss` and memory in SSA state"
        )
    next_stack_offset = return_bytes
    for index, arg in enumerate(_abi_call_argument_descriptors(summary)):
        name = _abi_call_argument_name(arg, index)
        width = int(_optional_int(arg.get("width")) or 16)
        location = str(arg.get("location") or arg.get("reg") or "").lower()
        if location:
            value = state.get(location)
            if not isinstance(value, dict):
                raise LowerFailure(
                    "callee_summary_missing", f"callee summary register argument `{location}` is unavailable"
                )
        else:
            offset = _optional_int(arg.get("entry_sp_offset") or arg.get("sp_offset") or arg.get("offset"))
            if offset is None:
                offset = next_stack_offset
            size = max(1, (width + 7) // 8)
            next_stack_offset = int(offset) + size
            value = {
                "op": "loadle",
                "width": width,
                "args": [
                    memory,
                    _stack_address_term(ss_term, post_call_sp, int(offset)),
                ],
            }
        state[f"callarg:{call_key}:{name}"] = value


def _abi_call_argument_descriptors(summary: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key in ("arguments", "args", "stack_args"):
        for item in summary.get(key, []) or []:
            if isinstance(item, dict):
                copied = dict(item)
                if key == "stack_args" and not any(name in copied for name in ("location", "reg")):
                    copied.setdefault("stack", True)
                items.append(copied)
    return items


def _abi_call_argument_name(arg: dict[str, Any], index: int) -> str:
    raw = str(arg.get("name") or arg.get("id") or arg.get("location") or arg.get("reg") or f"arg{index}")
    return re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_") or f"arg{index}"


def _apply_abi_call_returns_and_clobbers(
    state: dict[str, dict[str, Any]], summary: dict[str, Any], *, call_key: str
) -> None:
    reg_widths = dict(REG_BY_OFFSET.values())
    returns = {_abi_location_name(item) for item in summary.get("returns", []) or []}
    returns.discard("")
    preserved = {_abi_location_name(item) for item in summary.get("preserved", []) or []}
    preserved.discard("")
    clobbers = {_abi_location_name(item) for item in summary.get("clobbers", []) or []}
    clobbers.discard("")
    for reg in sorted(returns):
        width = reg_widths.get(reg)
        if width is not None:
            state[reg] = {"op": "input", "name": f"callret_{call_key}_{reg}", "width": width}
    for reg in sorted(clobbers - returns - preserved):
        width = reg_widths.get(reg)
        if width is not None:
            state[reg] = {"op": "input", "name": f"callclobber_{call_key}_{reg}", "width": width}


def _abi_location_name(item: Any) -> str:  # noqa: ANN401
    if isinstance(item, dict):
        return str(item.get("location") or item.get("reg") or item.get("name") or "").lower()
    return str(item or "").lower()


def _apply_abi_call_memory_effects(
    state: dict[str, dict[str, Any]],
    summary: dict[str, Any],
    *,
    call_key: str,
    data_segment_para: int,
) -> None:
    memory = state.get("memory")
    if not isinstance(memory, dict):
        return
    for index, effect in enumerate(summary.get("effects", []) or []):
        if not isinstance(effect, dict):
            continue
        if _abi_call_effect_is_broad_memory(effect):
            name = (
                re.sub(r"[^A-Za-z0-9_]+", "_", str(effect.get("name") or f"memory{index}")).strip("_")
                or f"memory{index}"
            )
            memory = {
                "op": "mem_input",
                "name": f"calleffect_{call_key}_{name}_memory",
                "addr_width": 32,
                "value_width": 8,
            }
            continue
        offset = _optional_int(effect.get("offset"))
        size = _optional_int(effect.get("size"))
        if offset is None or size is None or size <= 0:
            raise LowerFailure("callee_summary_missing", f"invalid callee memory effect descriptor: {effect}")
        value = _abi_call_effect_value(effect, state, call_key=call_key, index=index, width=size * 8)
        memory = {
            "op": "storele",
            "width": 0,
            "args": [
                memory,
                _effect_address_term(effect, data_segment_para, offset, state=state),
                value,
            ],
        }
    state["memory"] = memory


def _abi_call_effect_is_broad_memory(effect: dict[str, Any]) -> bool:
    kind = str(effect.get("kind") or effect.get("type") or "").lower()
    scope = str(effect.get("scope") or effect.get("range") or "").lower()
    offset = str(effect.get("offset") or "").strip().lower()
    if scope in {
        "broad",
        "all",
        "unknown",
    } or offset in {"*", "any", "unknown"}:
        return True
    if kind in {"broad_memory", "unknown_memory", "clobber_all"}:
        return True
    if kind in {"memory_clobber", "memory"}:
        return not _abi_call_effect_has_concrete_range(effect)
    return False


def _abi_call_effect_has_concrete_range(effect: dict[str, Any]) -> bool:
    offset = _optional_int(effect.get("offset"))
    size = _optional_int(effect.get("size"))
    return offset is not None and size is not None and size > 0


def _abi_call_effect_value(
    effect: dict[str, Any], state: dict[str, dict[str, Any]], *, call_key: str, index: int, width: int
) -> dict[str, Any]:
    if "value" in effect:
        value = _optional_int(effect.get("value"))
        if value is None:
            raise LowerFailure("callee_summary_missing", f"invalid callee memory effect value: {effect.get('value')}")
        return {"op": "const", "value": normalize_hex(value & _mask(width), width=max(1, width // 4)), "width": width}
    arg_name = str(effect.get("arg") or effect.get("argument") or "")
    if arg_name:
        matches = [
            value
            for key, value in state.items()
            if key.startswith(f"callarg:{call_key}:") and key.rsplit(":", 1)[-1] == arg_name
        ]
        if len(matches) == 1:
            return _coerce_json_width(matches[0], width)
        raise LowerFailure("callee_summary_missing", f"callee memory effect references unknown argument `{arg_name}`")
    reg = str(effect.get("reg") or effect.get("location") or "").lower()
    if reg:
        value = state.get(reg)
        if isinstance(value, dict):
            return _coerce_json_width(value, width)
        raise LowerFailure("callee_summary_missing", f"callee memory effect references unavailable register `{reg}`")
    name = re.sub(r"[^A-Za-z0-9_]+", "_", str(effect.get("name") or f"effect{index}")).strip("_") or f"effect{index}"
    return {"op": "input", "name": f"calleffect_{call_key}_{name}", "width": width}


def _coerce_json_width(term: dict[str, Any], width: int) -> dict[str, Any]:
    current = _term_width(term)
    if current == width:
        return term
    op = "zext" if current < width else "trunc"
    return {"op": op, "width": width, "args": [term]}


def _is_msc_stack_check_prologue_call(block: dict[str, Any]) -> bool:
    part = block.get("part", {}) if isinstance(block.get("part"), dict) else {}
    if _optional_int(part.get("entry_delta")) != 0:
        return False
    source = block.get("source", {}) if isinstance(block.get("source"), dict) else {}
    instructions = source.get("instructions", []) if isinstance(source.get("instructions"), list) else []
    if len(instructions) < 4:
        return False
    first_four = [item for item in instructions[:4] if isinstance(item, dict)]
    mnemonics = [str(item.get("mnemonic") or "").lower() for item in first_four]
    if mnemonics != ["push", "mov", "mov", "call"]:
        return False
    third = first_four[2]
    return str(third.get("op_str") or "").lower().replace(" ", "").startswith("ax,")


def _compose_or_terminal(
    target: dict[str, Any],
    state: dict[str, dict[str, Any]],
    *,
    abi_function: dict[str, Any],
    block_by_key: dict[int, dict[str, Any]],
    path: list[int],
    max_loop_unroll: int = 0,
    data_segment_para: int = 0x0100,
    callsite_ordinals: dict[int, dict[str, int]] | None = None,
    compose_stats: dict[str, int] | None = None,
    enable_constant_branch_pruning: bool = False,
) -> tuple[dict[str, dict[str, Any]], int]:
    successor = _successor_for_target(target, block_by_key)
    if successor is None:
        return state, 1
    return _compose_abi_state(
        successor,
        state,
        abi_function=abi_function,
        block_by_key=block_by_key,
        path=path,
        max_loop_unroll=max_loop_unroll,
        data_segment_para=data_segment_para,
        callsite_ordinals=callsite_ordinals,
        compose_stats=compose_stats,
        enable_constant_branch_pruning=enable_constant_branch_pruning,
    )


def _direct_branch_targets(
    term: dict[str, Any], block_by_key: dict[int, dict[str, Any]]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    if term.get("op") != "ite":
        return None
    args = [arg for arg in term.get("args", []) or [] if isinstance(arg, dict)]
    if len(args) != 3:
        return None
    if _target_key(args[1]) is None and _target_key(args[2]) is None:
        return None
    if _target_key(args[1]) not in block_by_key and _target_key(args[2]) not in block_by_key:
        return None
    return args[0], args[1], args[2]


def _direct_successor_target(term: dict[str, Any], block_by_key: dict[int, dict[str, Any]]) -> dict[str, Any] | None:
    return _successor_for_target(term, block_by_key)


def _successor_for_target(term: dict[str, Any], block_by_key: dict[int, dict[str, Any]]) -> dict[str, Any] | None:
    key = _target_key(term)
    if key is None:
        return None
    return block_by_key.get(key)


def _target_key(term: dict[str, Any]) -> int | None:
    if not isinstance(term, dict) or term.get("op") != "const":
        return None
    value = _optional_int(term.get("value"))
    if value is None:
        return None
    return value & 0xFFFF


def _merge_abi_states(
    condition: dict[str, Any],
    true_state: dict[str, dict[str, Any]],
    false_state: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for key in sorted(set(true_state) | set(false_state)):
        left = true_state.get(key)
        right = false_state.get(key)
        if left is None:
            merged[key] = right
            continue
        if right is None:
            merged[key] = left
            continue
        if left is right or left == right:
            merged[key] = left
            continue
        merged[key] = {"op": "ite", "width": _term_width(left), "args": [condition, left, right]}
    return merged


def _materialize_abi_summary(
    start: dict[str, Any],
    final_state: dict[str, dict[str, Any]],
    *,
    abi_function: dict[str, Any],
    observables: dict[str, Any],
    data_segment_para: int,
) -> dict[str, Any]:
    outputs: dict[str, dict[str, Any]] = {}
    for reg in observables.get("regs", []) or []:
        if reg == "sp":
            canonical_sp = _abi_canonical_return_sp(abi_function)
            if canonical_sp is not None:
                outputs[reg] = canonical_sp
                continue
        if reg not in final_state:
            raise LowerFailure("unsupported_ir", f"observable register {reg} is not available in the SSA summary")
        outputs[reg] = final_state[reg]
    memory_term = final_state.get("memory", {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8})
    if observables.get("whole_memory"):
        outputs["memory"] = memory_term
    for effect in observables.get("memory", []) or []:
        offset = _optional_int(effect.get("offset"))
        size = _optional_int(effect.get("size"))
        if offset is None or size is None or size <= 0:
            raise LowerFailure("unsupported_ir", f"invalid memory effect descriptor: {effect}")
        name = str(effect.get("name") or f"mem_{offset:04x}_{size}")
        outputs[f"memory:{offset:04x}:{size}:{name}"] = {
            "op": "loadle",
            "width": size * 8,
            "args": [memory_term, _effect_address_term(effect, data_segment_para, offset, state=final_state)],
        }
    for name in sorted(key for key in final_state if key.startswith("callarg:")):
        outputs[name] = final_state[name]
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    term_cache: dict[int, dict[str, Any]] = {}
    materialized_outputs = {
        name: _materialize_json_term(term, assignments=assignments, memo=memo, term_cache=term_cache)
        for name, term in outputs.items()
    }
    body_without_id = {
        "function": start.get("function", {}),
        "part": {"kind": "function_abi", "index": 0, "entry_delta": "0x0000"},
        "function_entry": start.get("function_entry"),
        "entry": start.get("function_entry") or start.get("entry"),
        "source": {
            "ir": (start.get("source", {}) if isinstance(start.get("source"), dict) else {}).get("ir"),
            "jumpkind": "Ijk_FunctionSummary",
            "instruction_count": sum(
                int(
                    (part.get("source", {}) if isinstance(part.get("source"), dict) else {}).get("instruction_count", 0)
                )
                for part in [start]
            ),
            "instructions": [],
        },
        "inputs": _term_input_items(materialized_outputs.values(), assignments),
        "outputs": materialized_outputs,
        "assignments": assignments,
    }
    body = dict(body_without_id)
    body["id"] = _stable_abi_summary_id(body_without_id)
    return body


def _abi_canonical_return_sp(abi_function: dict[str, Any]) -> dict[str, Any] | None:
    convention = str(abi_function.get("calling_convention") or "").lower()
    if not (abi_function.get("canonicalize_return_sp") or convention.startswith("far_stack")):
        return None
    return_bytes = 4 if str(abi_function.get("kind") or "").lower() == "far" else 2
    cleanup = _optional_int(abi_function.get("callee_stack_cleanup")) or 0
    return {
        "op": "add",
        "width": 16,
        "args": [
            {"op": "input", "name": "sp", "width": 16},
            {"op": "const", "value": normalize_hex((return_bytes + cleanup) & 0xFFFF, width=4), "width": 16},
        ],
    }


def _data_address_term(data_segment_para: int, offset: int) -> dict[str, Any]:
    return {
        "op": "add",
        "width": 32,
        "args": [
            {
                "op": "shl",
                "width": 32,
                "args": [
                    {"op": "const", "value": normalize_hex(data_segment_para, width=4), "width": 32},
                    {"op": "const", "value": "0x04", "width": 8},
                ],
            },
            {"op": "const", "value": normalize_hex(offset & 0xFFFF, width=4), "width": 32},
        ],
    }


def _effect_address_term(
    effect: dict[str, Any],
    data_segment_para: int,
    offset: int,
    *,
    state: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    segment = str(effect.get("segment") or effect.get("segment_reg") or "").lower()
    if segment == "ds":
        segment_term = _effect_segment_term(state, "ds", fallback={"op": "input", "name": "ds", "width": 16})
    elif segment == "ss":
        segment_term = _effect_segment_term(state, "ss", fallback={"op": "input", "name": "ss", "width": 16})
    elif segment == "input_ds":
        segment_term = {"op": "input", "name": "ds", "width": 16}
    elif segment == "input_ss":
        segment_term = {"op": "input", "name": "ss", "width": 16}
    else:
        segment_value = _optional_int(segment)
        if segment_value is None:
            segment_value = data_segment_para
        segment_term = {"op": "const", "value": normalize_hex(segment_value & 0xFFFF, width=4), "width": 16}
    segment_term = _coerce_json_width(segment_term, 32)
    return {
        "op": "add",
        "width": 32,
        "args": [
            {
                "op": "shl",
                "width": 32,
                "args": [
                    segment_term,
                    {"op": "const", "value": "0x04", "width": 8},
                ],
            },
            {"op": "const", "value": normalize_hex(offset & 0xFFFF, width=4), "width": 32},
        ],
    }


def _effect_segment_term(
    state: dict[str, dict[str, Any]] | None,
    name: str,
    *,
    fallback: dict[str, Any],
) -> dict[str, Any]:
    if state is not None:
        term = state.get(name)
        if isinstance(term, dict):
            return copy.deepcopy(term)
    return copy.deepcopy(fallback)


def _inline_ssa_json_term(
    term: dict[str, Any], *, assignments: dict[str, dict[str, Any]], cache: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if "ref" in term:
        ident = str(term["ref"])
        if ident in cache:
            return cache[ident]
        item = assignments.get(ident)
        if item is None:
            raise LowerFailure("unsupported_ir", f"SSA ref {ident} was not found")
        inlined = {
            "op": str(item.get("op")),
            "width": int(item.get("width", 16)),
            "args": [
                _inline_ssa_json_term(arg, assignments=assignments, cache=cache)
                for arg in item.get("args", []) or []
                if isinstance(arg, dict)
            ],
        }
        cache[ident] = inlined
        return inlined
    copied = dict(term)
    if isinstance(term.get("args"), list):
        copied["args"] = [
            _inline_ssa_json_term(arg, assignments=assignments, cache=cache)
            for arg in term.get("args", []) or []
            if isinstance(arg, dict)
        ]
    return copied


def _substitute_abi_inputs(
    term: dict[str, Any],
    state: dict[str, dict[str, Any]],
    *,
    cache: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if cache is None:
        cache = {}
    key = id(term)
    if key in cache:
        return cache[key]
    op = term.get("op")
    if op == "input" and str(term.get("name")) in state:
        result = state[str(term["name"])]
        cache[key] = result
        return result
    if op == "mem_input":
        result = state.get("memory", term)
        cache[key] = result
        return result
    copied = dict(term)
    cache[key] = copied
    if isinstance(term.get("args"), list):
        copied["args"] = [
            _substitute_abi_inputs(arg, state, cache=cache) for arg in term["args"] if isinstance(arg, dict)
        ]
    return copied


def _materialize_json_term(
    term: dict[str, Any],
    *,
    assignments: list[dict[str, Any]],
    memo: dict[str, str],
    term_cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    if term_cache is None:
        term_cache = {}
    cache_key = id(term)
    cached = term_cache.get(cache_key)
    if cached is not None and cached[0] is term:
        return cached[1]
    op = term.get("op")
    if op in {"input", "mem_input", "const"}:
        result = copy.deepcopy(term)
        term_cache[cache_key] = (term, result)
        return result
    args = [
        _materialize_json_term(arg, assignments=assignments, memo=memo, term_cache=term_cache)
        for arg in term.get("args", []) or []
        if isinstance(arg, dict)
    ]
    shallow = {"op": str(op), "width": _term_width(term), "args": args}
    key = _materialized_term_key(shallow)
    if key in memo:
        result = {"ref": memo[key]}
        term_cache[cache_key] = (term, result)
        return result
    ident = f"v{len(assignments)}"
    memo[key] = ident
    assignments.append({"id": ident, **shallow})
    result = {"ref": ident}
    term_cache[cache_key] = (term, result)
    return result


def _materialized_term_key(term: dict[str, Any]) -> str:
    parts: list[tuple[Any, ...]] = []
    for arg in term.get("args", []) or []:
        if not isinstance(arg, dict):
            continue
        if "ref" in arg:
            parts.append(("ref", str(arg["ref"])))
            continue
        op = str(arg.get("op"))
        if op == "input":
            parts.append(("input", str(arg.get("name")), int(arg.get("width", 16))))
        elif op == "mem_input":
            parts.append(
                ("mem_input", str(arg.get("name")), int(arg.get("addr_width", 32)), int(arg.get("value_width", 8)))
            )
        elif op == "const":
            parts.append(("const", str(arg.get("value")), int(arg.get("width", 16))))
        else:
            parts.append(("term", _term_identity(arg)))
    return repr((str(term.get("op")), _term_width(term), tuple(parts)))


def _stable_abi_summary_id(body_without_id: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    shallow = {
        "function": body_without_id.get("function"),
        "part": body_without_id.get("part"),
        "function_entry": body_without_id.get("function_entry"),
        "entry": body_without_id.get("entry"),
        "source": body_without_id.get("source"),
        "inputs": body_without_id.get("inputs"),
        "outputs": body_without_id.get("outputs"),
    }
    digest.update(canonical_json_bytes(shallow))
    for assignment in body_without_id.get("assignments", []) or []:
        digest.update(b"\n")
        digest.update(canonical_json_bytes(assignment))
    return f"ssa-function-abi:{digest.hexdigest()}"


@dataclass
class _TermInputScan:
    """Mutable scan state for collecting input items from SSA terms."""

    widths: dict[str, int] = field(default_factory=dict)
    memory_inputs: set[str] = field(default_factory=set)
    assignment_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    seen_terms: set[int] = field(default_factory=set)
    seen_refs: set[str] = field(default_factory=set)

    def visit(self, term: dict[str, Any]) -> None:
        """Visit terms iteratively, deduping by identity and ref name."""
        pending: list[Any] = [term]
        while pending:
            item = pending.pop()
            if not isinstance(item, dict):
                continue
            term_key = id(item)
            if term_key in self.seen_terms:
                continue
            self.seen_terms.add(term_key)
            if "ref" in item:
                ref = str(item["ref"])
                if ref in self.seen_refs:
                    continue
                self.seen_refs.add(ref)
                assignment = self.assignment_by_id.get(ref)
                if assignment is not None:
                    pending.extend(assignment.get("args", []) or [])
                continue
            if self._visit_leaf(str(item.get("op") or ""), item):
                continue
            pending.extend(item.get("args", []) or [])

    def _visit_leaf(self, op: str, term: dict[str, Any]) -> bool:
        """Record input/mem_input leaves; True when the term is a leaf."""
        if op == "input" and term.get("name"):
            name = str(term["name"])
            self.widths[name] = max(self.widths.get(name, 0), int(term.get("width", 16)))
            return True
        if op == "mem_input" and term.get("name"):
            self.memory_inputs.add(str(term["name"]))
            return True
        return False


def _term_input_items(terms: Any, assignments: list[dict[str, Any]]) -> list[dict[str, Any]]:  # noqa: ANN401
    scan = _TermInputScan(
        assignment_by_id={
            str(item.get("id")): item
            for item in assignments
            if isinstance(item, dict) and item.get("id") is not None
        }
    )
    for term in terms:
        if isinstance(term, dict):
            scan.visit(term)
    items = [
        {"kind": "memory", "name": name, "addr_width": 32, "value_width": 8}
        for name in sorted(scan.memory_inputs)
    ]
    items.extend({"name": name, "width": width} for name, width in sorted(scan.widths.items()))
    return items


def _term_width(term: dict[str, Any]) -> int:
    if term.get("op") == "mem_input":
        return 0
    return int(term.get("width", 16))


def _term_identity(term: dict[str, Any]) -> str:
    import json

    return json.dumps(term, sort_keys=True, separators=(",", ":"))


def _ssa_function_index(functions: list[dict[str, Any]]) -> dict[str, dict[Any, dict[str, Any]]]:
    indexed: dict[str, dict[Any, dict[str, Any]]] = {
        "by_id": {},
        "by_name": {},
        "by_linear": {},
        "by_linear_all": {},
        "by_linear_low16": {},
        "by_linear_low16_all": {},
        "by_ip": {},
        "by_ip_all": {},
    }
    for function in functions:
        if not isinstance(function, dict):
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        if function_id:
            indexed["by_id"].setdefault(function_id, function)
        if function_name:
            indexed["by_name"].setdefault(function_name, function)
        entry = function.get("entry", {}) if isinstance(function.get("entry"), dict) else {}
        linear = _optional_int(entry.get("linear"))
        ip = _optional_int(entry.get("ip"))
        if linear is not None:
            indexed["by_linear"].setdefault(linear, function)
            _append_index(indexed["by_linear_all"], linear, function)
            _set_unique_index(indexed["by_linear_low16"], linear & 0xFFFF, function)
            _append_index(indexed["by_linear_low16_all"], linear & 0xFFFF, function)
        if ip is not None:
            _set_unique_index(indexed["by_ip"], ip & 0xFFFF, function)
            _append_index(indexed["by_ip_all"], ip & 0xFFFF, function)
    return indexed


def _append_index(table: dict[Any, list[dict[str, Any]]], key: Any, function: dict[str, Any]) -> None:  # noqa: ANN401
    table.setdefault(key, []).append(function)


def _set_unique_index(table: dict[Any, dict[str, Any] | None], key: Any, function: dict[str, Any]) -> None:  # noqa: ANN401
    if key not in table:
        table[key] = function
        return
    if table[key] is not function:
        table[key] = None


def _attach_binary_signature_context(
    index: dict[str, dict[Any, dict[str, Any]]],
    document: dict[str, Any],
    functions: list[dict[str, Any]],
) -> None:
    exe = document.get("exe")
    if not exe:
        return
    try:
        image = load_mz_image(Path(str(exe))).memory
    except Exception:
        return
    linked_base = _ssa_document_linked_base(functions)
    if linked_base is None:
        return
    index["_binary_signature_context"] = {
        "image": image,
        "linked_base": linked_base,
        "exe": str(exe),
    }


def _ssa_document_linked_base(functions: list[dict[str, Any]]) -> int | None:
    bases: Counter[int] = Counter()
    for function in functions:
        if not isinstance(function, dict):
            continue
        entry = function.get("entry", {}) if isinstance(function.get("entry"), dict) else {}
        linear = _optional_int(entry.get("linear"))
        ip = _optional_int(entry.get("ip"))
        if linear is None or ip is None:
            continue
        bases[(linear - (ip & 0xFFFF)) & 0xFFFFFFFF] += 1
    if not bases:
        return None
    return bases.most_common(1)[0][0]


def _binary_signature_target_for_call_raw(
    raw: int, index: dict[str, dict[Any, dict[str, Any]]]
) -> tuple[dict[str, Any] | None, str | None]:
    context = index.get("_binary_signature_context")
    if not isinstance(context, dict):
        return None, None
    image = context.get("image")
    linked_base = context.get("linked_base")
    if not isinstance(image, (bytes, bytearray)) or not isinstance(linked_base, int):
        return None, None
    for linear, offset in _candidate_linear_offsets_for_low16(raw, len(image), linked_base):
        blob = bytes(image[offset : offset + BINARY_CALL_TARGET_SIGNATURE_BYTES])
        if len(blob) < 8 or not any(blob):
            continue
        signature_fields = _binary_call_signature_fields(blob, linear)
        signature = str(signature_fields["signature_sha256"])
        target_without_id = {
            "id": f"library-signature:{signature[:16]}",
            "name": f"library_signature_{signature[:12]}",
            "entry": {
                "linear": normalize_hex(linear, width=8),
                "ip": normalize_hex(offset & 0xFFFF, width=4),
                "image_offset": normalize_hex(offset, width=8),
            },
            "signature_kind": "binary_local",
            **signature_fields,
        }
        return target_without_id, (
            "resolved through binary-local call-target signature "
            f"at loaded offset {normalize_hex(offset, width=8)}"
        )
    return None, None


def _candidate_linear_offsets_for_low16(raw: int, image_size: int, linked_base: int) -> list[tuple[int, int]]:
    low16 = raw & 0xFFFF
    seen: set[int] = set()
    candidates: list[tuple[int, int]] = []
    max_linear = linked_base + max(0, image_size - 1)
    high = 0
    while high <= max_linear + 0x10000:
        linear = high + low16
        offset = linear - linked_base
        if 0 <= offset < image_size and offset not in seen:
            seen.add(offset)
            candidates.append((linear, offset))
        high += 0x10000
    return candidates


def _binary_call_signature_fields(blob: bytes, linear: int) -> dict[str, Any]:
    signature_blob = _binary_signature_prefix(blob, linear)
    normalized_pattern = _normalized_binary_signature_pattern(signature_blob, linear)
    normalized_text = "".join("??" if byte is None else f"{byte:02x}" for byte in normalized_pattern)
    layout_pattern = _layout_binary_signature_pattern(signature_blob, linear)
    layout_text = "".join("??" if byte is None else f"{byte:02x}" for byte in layout_pattern)
    return {
        "signature_sha256": hashlib.sha256(signature_blob).hexdigest(),
        "signature_size": len(signature_blob),
        "signature_preview": signature_blob[: min(8, len(signature_blob))].hex(),
        "normalized_signature_sha256": hashlib.sha256(normalized_text.encode("ascii")).hexdigest(),
        "normalized_signature_size": len(normalized_pattern),
        "normalized_signature_masked_bytes": sum(1 for byte in normalized_pattern if byte is None),
        "normalized_signature_preview": normalized_text[:32],
        "layout_signature_sha256": hashlib.sha256(layout_text.encode("ascii")).hexdigest(),
        "layout_signature_size": len(layout_pattern),
        "layout_signature_masked_bytes": sum(1 for byte in layout_pattern if byte is None),
        "layout_signature_preview": layout_text[:32],
    }


def _binary_signature_prefix(blob: bytes, linear: int) -> bytes:
    try:
        import capstone  # type: ignore
    except Exception:
        return blob
    try:
        consumed = 0
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        for insn in md.disasm(blob, linear):
            consumed += len(insn.bytes)
            mnemonic = str(insn.mnemonic).lower()
            if consumed >= 8 and mnemonic in {"ret", "retf", "iret", "jmp", "ljmp"}:
                return blob[:consumed]
    except Exception:
        return blob
    return blob


def _normalized_binary_signature_pattern(blob: bytes, linear: int) -> tuple[int | None, ...]:
    try:
        import capstone  # type: ignore
    except Exception:
        return tuple(blob)
    try:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        md.detail = True
        pattern: list[int | None] = []
        for insn in md.disasm(blob, linear):
            encoded = list(insn.bytes)
            mask = [False] * len(encoded)
            encoding = getattr(insn, "encoding", None)
            mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
            is_control = mnemonic in CONTROL_MNEMONICS and mnemonic != "int"
            for offset_name, size_name in (("imm_offset", "imm_size"), ("disp_offset", "disp_size")):
                offset = int(getattr(encoding, offset_name, 0) or 0)
                size = int(getattr(encoding, size_name, 0) or 0)
                if offset <= 0 or size <= 0:
                    continue
                # Control-transfer targets are position-dependent; mask them.
                # 8-bit immediates on non-control instructions are literals
                # (relocatable operands are always encoded as imm16), so they
                # must stay visible or semantically different parts collide.
                if offset_name == "imm_offset" and not is_control and size < 2:
                    continue
                for idx in range(offset, min(offset + size, len(mask))):
                    mask[idx] = True
            pattern.extend(None if masked else byte for byte, masked in zip(encoded, mask, strict=False))
            if len(pattern) >= len(blob):
                break
        if len(pattern) < len(blob):
            pattern.extend(blob[len(pattern) :])
        return tuple(pattern[: len(blob)])
    except Exception:
        return tuple(blob)


def _layout_binary_signature_pattern(blob: bytes, linear: int) -> tuple[int | None, ...]:
    try:
        import capstone  # type: ignore
    except Exception:
        return tuple(blob)
    try:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        md.detail = True
        pattern: list[int | None] = []
        pending_reg_immediates: dict[str, list[int]] = {}
        for insn in md.disasm(blob, linear):
            encoded = list(insn.bytes)
            mask = [False] * len(encoded)
            mnemonic = str(insn.mnemonic).lower()
            encoding = getattr(insn, "encoding", None)
            list(getattr(insn, "operands", []) or [])
            if mnemonic in CONTROL_MNEMONICS:
                _mask_control_immediates(mask, encoding)
            else:
                _mask_non_control_insn(mask, pattern, pending_reg_immediates, insn, encoding, mnemonic)
            pattern.extend(None if masked else byte for byte, masked in zip(encoded, mask, strict=False))
            if len(pattern) >= len(blob):
                break
        if len(pattern) < len(blob):
            pattern.extend(blob[len(pattern) :])
        return tuple(pattern[: len(blob)])
    except Exception:
        return tuple(blob)


def _mask_control_immediates(mask: list[bool], encoding: Any) -> None:  # noqa: ANN401
    """Mask immediate/displacement bytes of a control-transfer instruction."""
    for offset_name, size_name in (("imm_offset", "imm_size"), ("disp_offset", "disp_size")):
        offset = int(getattr(encoding, offset_name, 0) or 0)
        size = int(getattr(encoding, size_name, 0) or 0)
        if offset <= 0 or size <= 0:
            continue
        for idx in range(offset, min(offset + size, len(mask))):
            mask[idx] = True


def _clear_pending_reg_immediates(
    pattern: list[int | None], pending_reg_immediates: dict[str, list[int]], insn: Any  # noqa: ANN401
) -> None:
    """Clear pattern slots for immediates previously bound to registers this insn reads."""
    for reg_name in _insn_source_register_names(insn):
        for pattern_index in pending_reg_immediates.get(reg_name, []):
            if 0 <= pattern_index < len(pattern):
                pattern[pattern_index] = None


def _mask_non_control_insn(
    mask: list[bool],
    pattern: list[int | None],
    pending_reg_immediates: dict[str, list[int]],
    insn: Any,  # noqa: ANN401
    encoding: Any,  # noqa: ANN401
    mnemonic: str,
) -> None:
    """Mask displacement/immediate bytes of a non-control instruction."""
    disp_offset = int(getattr(encoding, "disp_offset", 0) or 0)
    disp_size = int(getattr(encoding, "disp_size", 0) or 0)
    if disp_offset > 0 and disp_size > 0 and _insn_has_layout_memory_operand(insn):
        for idx in range(disp_offset, min(disp_offset + disp_size, len(mask))):
            mask[idx] = True
        _clear_pending_reg_immediates(pattern, pending_reg_immediates, insn)
    if _insn_has_ivt_vector_memory_operand(insn):
        _clear_pending_reg_immediates(pattern, pending_reg_immediates, insn)
        imm_offset = int(getattr(encoding, "imm_offset", 0) or 0)
        imm_size = int(getattr(encoding, "imm_size", 0) or 0)
        if imm_offset > 0 and imm_size > 0:
            for idx in range(imm_offset, min(imm_offset + imm_size, len(mask))):
                mask[idx] = True
    imm_offset = int(getattr(encoding, "imm_offset", 0) or 0)
    imm_size = int(getattr(encoding, "imm_size", 0) or 0)
    reg_imm = _insn_register_immediate(insn)
    if imm_offset > 0 and imm_size > 0 and reg_imm is not None:
        _mask_or_pending_reg_imm(mask, pattern, pending_reg_immediates, mnemonic, imm_offset, imm_size, reg_imm)


def _mask_or_pending_reg_imm(
    mask: list[bool],
    pattern: list[int | None],
    pending_reg_immediates: dict[str, list[int]],
    mnemonic: str,
    imm_offset: int,
    imm_size: int,
    reg_imm: tuple[str, int],
) -> None:
    """Mask a register-bound immediate, or record it pending when its use is not yet proven."""
    reg_name, imm_value = reg_imm
    if mnemonic == "mov" and reg_name in {"bx", "bp", "si", "di"} and (imm_value & 0xFFFF) >= 0x1000:
        for idx in range(imm_offset, min(imm_offset + imm_size, len(mask))):
            mask[idx] = True
    elif mnemonic == "mov" and (imm_value & 0xFFFF) >= 0x1000:
        pending_reg_immediates[reg_name] = [
            len(pattern) + idx for idx in range(imm_offset, min(imm_offset + imm_size, len(mask)))
        ]
    elif mnemonic in {"add", "sub", "cmp"} and (imm_value & 0xFFFF) >= 0x1000:
        for idx in range(imm_offset, min(imm_offset + imm_size, len(mask))):
            mask[idx] = True


def _insn_has_layout_memory_operand(insn: Any) -> bool:  # noqa: ANN401
    try:
        import capstone  # type: ignore
    except Exception:
        return False
    for operand in getattr(insn, "operands", []) or []:
        if getattr(operand, "type", None) != capstone.x86.X86_OP_MEM:
            continue
        mem = getattr(operand, "mem", None)
        if mem is None:
            continue
        base = int(getattr(mem, "base", 0) or 0)
        index = int(getattr(mem, "index", 0) or 0)
        disp = int(getattr(mem, "disp", 0) or 0) & 0xFFFF
        segment = int(getattr(mem, "segment", 0) or 0)
        if segment == capstone.x86.X86_REG_CS:
            return True
        if base == 0 and index == 0 and disp >= 0x1000:
            return True
    return False


def _insn_has_ivt_vector_memory_operand(insn: Any) -> bool:  # noqa: ANN401
    try:
        import capstone  # type: ignore
    except Exception:
        return False
    for operand in getattr(insn, "operands", []) or []:
        if getattr(operand, "type", None) != capstone.x86.X86_OP_MEM:
            continue
        mem = getattr(operand, "mem", None)
        if mem is None:
            continue
        base = int(getattr(mem, "base", 0) or 0)
        index = int(getattr(mem, "index", 0) or 0)
        disp = int(getattr(mem, "disp", 0) or 0)
        segment = int(getattr(mem, "segment", 0) or 0)
        if segment == capstone.x86.X86_REG_ES and base == 0 and index == 0 and disp in {0, 2}:
            return True
    return False


def _insn_register_immediate(insn: Any) -> tuple[str, int] | None:  # noqa: ANN401
    try:
        import capstone  # type: ignore
    except Exception:
        return None
    operands = list(getattr(insn, "operands", []) or [])
    if len(operands) < 2:
        return None
    if getattr(operands[0], "type", None) != capstone.x86.X86_OP_REG:
        return None
    if getattr(operands[1], "type", None) != capstone.x86.X86_OP_IMM:
        return None
    reg_name = str(insn.reg_name(getattr(operands[0], "reg", 0)) or "").lower()
    if not reg_name:
        return None
    return reg_name, int(getattr(operands[1], "imm", 0) or 0)


def _insn_source_register_names(insn: Any) -> list[str]:  # noqa: ANN401
    try:
        import capstone  # type: ignore
    except Exception:
        return []
    result: list[str] = []
    operands = list(getattr(insn, "operands", []) or [])
    for operand in operands[1:]:
        if getattr(operand, "type", None) != capstone.x86.X86_OP_REG:
            continue
        reg_name = str(insn.reg_name(getattr(operand, "reg", 0)) or "").lower()
        if reg_name:
            result.append(reg_name)
    return result


class _SemanticEqualityCache:
    def __init__(self) -> None:
        self._facts: dict[tuple[str, str], dict[str, Any]] = {}

    @property
    def count(self) -> int:
        return len({id(fact) for fact in self._facts.values()})

    def record(
        self, oracle_function: dict[str, Any], candidate_function: dict[str, Any], *, proof: str, scope: str = "block"
    ) -> None:
        fact_without_id = {
            "kind": "semantic_equality_fact",
            "scope": scope,
            "proof": proof,
            "oracle": _ssa_function_brief(oracle_function),
            "candidate": _ssa_function_brief(candidate_function),
        }
        fact = dict(fact_without_id)
        fact["id"] = stable_id("semantic-equality-fact", fact_without_id)
        oracle_keys = _semantic_cache_keys(_ssa_function_brief(oracle_function))
        candidate_keys = _semantic_cache_keys(_ssa_function_brief(candidate_function))
        for oracle_key in oracle_keys:
            for candidate_key in candidate_keys:
                self._facts[(oracle_key, candidate_key)] = fact

    def lookup_call_targets(
        self, oracle_targets: list[dict[str, Any]], candidate_targets: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        for oracle_target in oracle_targets:
            for candidate_target in candidate_targets:
                for oracle_key in _semantic_cache_keys(oracle_target):
                    for candidate_key in _semantic_cache_keys(candidate_target):
                        fact = self._facts.get((oracle_key, candidate_key))
                        if fact is not None:
                            return fact
        return None


def _semantic_cache_keys(function_brief: dict[str, Any] | None) -> list[str]:
    if not isinstance(function_brief, dict):
        return []
    keys: list[str] = []
    for key_field in ("id", "name"):
        value = str(function_brief.get(key_field) or "")
        if value:
            keys.append(f"{key_field}:{value}")
            if key_field == "name":
                normalized = _normalized_symbol_name(value)
                if normalized and normalized != value:
                    keys.append(f"normalized_name:{normalized}")
    keys.extend(_entry_cache_keys(function_brief.get("entry")))
    for prefix, hash_key, size_key in _SEMANTIC_SIGNATURE_KEY_FIELDS:
        signature_hash = str(function_brief.get(hash_key) or "")
        signature_size = _optional_int(function_brief.get(size_key))
        if signature_hash and signature_size is not None:
            keys.append(f"{prefix}:{signature_size}:{signature_hash}")
    return sorted(set(keys))


_SEMANTIC_SIGNATURE_KEY_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("signature", "signature_sha256", "signature_size"),
    ("normalized_signature", "normalized_signature_sha256", "normalized_signature_size"),
    ("layout_signature", "layout_signature_sha256", "layout_signature_size"),
    ("exact_block_signature", "exact_block_signature_sha256", "exact_block_signature_size"),
    ("normalized_block_signature", "normalized_block_signature_sha256", "normalized_block_signature_size"),
    ("layout_block_signature", "layout_block_signature_sha256", "layout_block_signature_size"),
)


def _entry_cache_keys(entry: Any) -> list[str]:  # noqa: ANN401
    """Build cache keys from a function brief entry (linear/low16/ip)."""
    entry = entry if isinstance(entry, dict) else {}
    keys: list[str] = []
    linear = _optional_int(entry.get("linear"))
    ip = _optional_int(entry.get("ip"))
    if linear is not None:
        keys.append(f"linear:{linear & 0xFFFFFFFF:08x}")
        keys.append(f"low16:{linear & 0xFFFF:04x}")
    if ip is not None:
        keys.append(f"ip:{ip & 0xFFFF:04x}")
    return keys


def _compare_call_targets(
    oracle_function: dict[str, Any],
    candidate_function: dict[str, Any],
    *,
    mapping_document: dict[str, Any] | None,
    oracle_index: dict[str, dict[Any, dict[str, Any]]],
    candidate_index: dict[str, dict[Any, dict[str, Any]]],
    allow_aliased_call_targets: bool,
    proof_cache: _SemanticEqualityCache | None = None,
    require_proven_call_targets: bool = False,
) -> dict[str, Any] | None:
    oracle_call = _resolve_call_target(
        oracle_function, oracle_index, allow_aliased_call_targets=allow_aliased_call_targets
    )
    candidate_call = _resolve_call_target(
        candidate_function, candidate_index, allow_aliased_call_targets=allow_aliased_call_targets
    )
    if oracle_call is None and candidate_call is None:
        return None
    equivalent, reason, proof_fact, unproven_reason = _call_targets_equivalent(
        oracle_call,
        candidate_call,
        mapping_document=mapping_document,
        proof_cache=proof_cache,
        require_proven_call_targets=require_proven_call_targets,
    )
    return {
        "kind": "direct_call",
        "oracle": oracle_call,
        "candidate": candidate_call,
        "equivalent": equivalent,
        "reason": reason,
        "proof_fact": proof_fact,
        "unproven_reason": unproven_reason,
        "allow_aliased_call_targets": allow_aliased_call_targets,
        "normalizations": [],
    }


def _resolve_call_target(
    function: dict[str, Any],
    index: dict[str, dict[Any, dict[str, Any]]],
    *,
    allow_aliased_call_targets: bool,
) -> dict[str, Any] | None:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    if source.get("jumpkind") != "Ijk_Call":
        return None
    raw = _direct_call_target(function)
    if raw is None:
        return {"kind": "unresolved", "reason": "call target is not a direct constant"}
    target, aliases, alias_reason = _function_for_call_target(
        raw,
        index,
        allow_aliased_call_targets=allow_aliased_call_targets,
        rendered_linear=_rendered_call_target_linear(function),
    )
    detail = {
        "kind": "direct",
        "raw": normalize_hex(raw),
        "low16": normalize_hex(raw & 0xFFFF, width=4),
        "resolved": _ssa_call_target_brief(target, index),
    }
    if aliases:
        detail["aliases"] = [_ssa_call_target_brief(function, index) for function in aliases]
    if target is None:
        detail["reason"] = alias_reason or "no SSA function starts at the direct call target"
    elif alias_reason:
        detail["resolution_note"] = alias_reason
    return detail


def _ssa_call_target_brief(
    function: dict[str, Any] | None, index: dict[str, dict[Any, dict[str, Any]]]
) -> dict[str, Any] | None:
    brief = _ssa_function_brief(function)
    if not isinstance(brief, dict) or brief.get("signature_kind") == "binary_local":
        return brief
    context = index.get("_binary_signature_context")
    if not isinstance(context, dict):
        return brief
    image = context.get("image")
    linked_base = context.get("linked_base")
    entry = brief.get("entry") if isinstance(brief.get("entry"), dict) else {}
    linear = _optional_int(entry.get("linear"))
    if not isinstance(image, (bytes, bytearray)) or not isinstance(linked_base, int) or linear is None:
        return brief
    offset = linear - linked_base
    if offset < 0 or offset >= len(image):
        return brief
    blob = bytes(image[offset : offset + BINARY_CALL_TARGET_SIGNATURE_BYTES])
    if len(blob) < 8 or not any(blob):
        return brief
    augmented = dict(brief)
    augmented["signature_kind"] = "binary_local"
    augmented.update(_binary_call_signature_fields(blob, linear))
    return augmented


def _direct_call_target(function: dict[str, Any]) -> int | None:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else None
    if transfer:
        target = transfer.get("target") if isinstance(transfer.get("target"), dict) else None
        if target is not None:
            raw = _optional_int(target.get("raw"))
            if raw is not None:
                return raw
    return _direct_call_target_from_instructions(source)


def _direct_call_target_from_instructions(source: dict[str, Any]) -> int | None:
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    if not instructions:
        return None
    instruction = instructions[-1]
    mnemonic = str(instruction.get("mnemonic") or _mnemonic_from_disassembly(instruction)).lower()
    if mnemonic not in {"call", "lcall"}:
        return None
    operand = str(instruction.get("op_str") or _operand_from_disassembly(instruction)).strip().lower()
    if not operand or any(token in operand for token in ("[", "]", ",", ":")):
        return None
    if operand.startswith("far "):
        operand = operand[4:].strip()
    return _optional_int(operand)


def _rendered_call_target_linear(function: dict[str, Any]) -> int | None:
    """Absolute target linear rendered in the final instruction's operand text.

    The lifter renders ``call``/``jmp`` immediates as the computed absolute
    linear (``call 0x116c8``), which is authoritative when it exceeds 16 bits.
    """
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    if not instructions:
        return None
    operand = str(instructions[-1].get("op_str") or _operand_from_disassembly(instructions[-1])).strip().lower()
    if not operand or any(token in operand for token in ("[", "]", ",", ":")):
        return None
    if operand.startswith("far "):
        operand = operand[4:].strip()
    value = _optional_int(operand)
    return value if value is not None and value > 0xFFFF else None


def _function_for_call_target(
    raw: int,
    index: dict[str, dict[Any, dict[str, Any]]],
    *,
    allow_aliased_call_targets: bool,
    rendered_linear: int | None = None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str | None]:
    low16 = raw & 0xFFFF
    if rendered_linear is not None:
        hit = _call_target_lookup(
            index, "by_linear", "by_linear_all", rendered_linear,
            allow_aliased=allow_aliased_call_targets,
        )
        if hit is not None:
            return hit
    for unique_table, all_table, key in (
        ("by_linear", "by_linear_all", raw),
        ("by_linear_low16", "by_linear_low16_all", low16),
        ("by_linear", "by_linear_all", low16),
    ):
        hit = _call_target_lookup(
            index, unique_table, all_table, key, allow_aliased=allow_aliased_call_targets
        )
        if hit is not None:
            return hit
    signature_target, signature_reason = _binary_signature_target_for_call_raw(raw, index)
    if signature_target is not None:
        return signature_target, [], signature_reason
    for unique_table, all_table, key in (
        ("by_ip", "by_ip_all", raw),
        ("by_ip", "by_ip_all", low16),
    ):
        hit = _call_target_lookup(
            index, unique_table, all_table, key, allow_aliased=allow_aliased_call_targets
        )
        if hit is not None:
            return hit
    return None, [], "no SSA function starts at the direct call target"


def _call_target_lookup(
    index: dict[str, dict[Any, dict[str, Any]]],
    unique_table: str,
    all_table: str,
    key: Any,  # noqa: ANN401
    *,
    allow_aliased: bool,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str | None] | None:
    """Probe one unique/all index pair; None on a clean miss."""
    if allow_aliased:
        candidates = [item for item in index.get(all_table, {}).get(key, []) or [] if isinstance(item, dict)]
        if len(candidates) > 1:
            aliases = _same_entry_aliases(candidates)
            if aliases:
                return aliases[0], aliases, f"resolved through same-entry aliases by {all_table}"
            return None, [], f"direct call target matched multiple non-equivalent SSA functions by {all_table}"
    table = index.get(unique_table, {})
    if key in table and table.get(key) is not None:
        return table[key], [], None
    if allow_aliased:
        candidates = [item for item in index.get(all_table, {}).get(key, []) or [] if isinstance(item, dict)]
        if candidates:
            aliases = _same_entry_aliases(candidates)
            if aliases:
                return aliases[0], aliases, f"resolved through same-entry aliases by {all_table}"
            return None, [], f"direct call target matched multiple non-equivalent SSA functions by {all_table}"
    if key in table:
        return None, [], f"direct call target matched multiple non-equivalent SSA functions by {unique_table}"
    return None


def _same_entry_aliases(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not functions:
        return []
    groups: dict[tuple[int | None, int | None], list[dict[str, Any]]] = {}
    for function in functions:
        entry = function.get("entry", {}) if isinstance(function.get("entry"), dict) else {}
        key = (_optional_int(entry.get("linear")), _optional_int(entry.get("ip")))
        groups.setdefault(key, []).append(function)
    if len(groups) != 1:
        return []
    return sorted(
        functions,
        key=lambda item: str(
            (item.get("function", {}) if isinstance(item.get("function"), dict) else {}).get("name", "")
        ),
    )


def _ssa_function_brief(
    function: dict[str, Any] | None, *, instruction_limit: int = CALL_TARGET_PREVIEW_INSTRUCTION_LIMIT
) -> dict[str, Any] | None:
    if not isinstance(function, dict):
        return None
    if function.get("signature_kind") == "binary_local":
        return {
            "id": function.get("id"),
            "name": function.get("name"),
            "entry": function.get("entry"),
            "signature_kind": function.get("signature_kind"),
            "signature_sha256": function.get("signature_sha256"),
            "signature_size": function.get("signature_size"),
            "signature_preview": function.get("signature_preview"),
            "normalized_signature_sha256": function.get("normalized_signature_sha256"),
            "normalized_signature_size": function.get("normalized_signature_size"),
            "normalized_signature_masked_bytes": function.get("normalized_signature_masked_bytes"),
            "normalized_signature_preview": function.get("normalized_signature_preview"),
            "layout_signature_sha256": function.get("layout_signature_sha256"),
            "layout_signature_size": function.get("layout_signature_size"),
            "layout_signature_masked_bytes": function.get("layout_signature_masked_bytes"),
            "layout_signature_preview": function.get("layout_signature_preview"),
        }
    info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    exact_block_signature = _ssa_exact_block_signature(function)
    normalized_block_signature = _ssa_block_signature(function)
    layout_block_signature = _ssa_layout_block_signature(function)
    return {
        "id": info.get("id"),
        "name": info.get("name"),
        "entry": function.get("entry"),
        "instruction_count": source.get("instruction_count", len(instructions)),
        "instructions": instructions[:instruction_limit],
        "machine_code_sha256": source.get("machine_code_sha256"),
        "machine_code_size": source.get("machine_code_size"),
        "exact_block_signature_sha256": _block_signature_digest(exact_block_signature),
        "exact_block_signature_size": None if exact_block_signature is None else len(exact_block_signature),
        "normalized_block_signature_sha256": _block_signature_digest(normalized_block_signature),
        "normalized_block_signature_size": None if normalized_block_signature is None else len(normalized_block_signature),
        "layout_block_signature_sha256": _block_signature_digest(layout_block_signature),
        "layout_block_signature_size": None if layout_block_signature is None else len(layout_block_signature),
        "semantic_ssa_id": _semantic_ssa_id(function),
    }


def _semantic_ssa_id(function: dict[str, Any]) -> str:
    return stable_id("ssa-semantic", _semantic_ssa_payload(function))


def _call_targets_equivalent(
    oracle_call: dict[str, Any] | None,
    candidate_call: dict[str, Any] | None,
    *,
    mapping_document: dict[str, Any] | None,
    proof_cache: _SemanticEqualityCache | None = None,
    require_proven_call_targets: bool = False,
) -> tuple[bool, str, dict[str, Any] | None, str | None]:
    head_verdict = _call_target_head_verdict(oracle_call, candidate_call)
    if head_verdict is not None:
        return head_verdict

    oracle_targets = _call_target_briefs(oracle_call)
    candidate_targets = _call_target_briefs(candidate_call)
    if proof_cache is not None:
        fact = proof_cache.lookup_call_targets(oracle_targets, candidate_targets)
        if fact is not None:
            return True, "direct call targets are equivalent through proven callee equality", fact, None
    semantic_reason = _call_target_semantic_equivalence_reason(oracle_targets, candidate_targets)
    mapped_signature_reason = _call_target_layout_signature_equivalence_reason(oracle_targets, candidate_targets)

    mapped_mismatch_seen = False
    for oracle_target in oracle_targets:
        verdict, mismatch = _mapped_call_target_verdict(
            oracle_target,
            oracle_targets=oracle_targets,
            candidate_targets=candidate_targets,
            mapping_document=mapping_document,
            semantic_reason=semantic_reason,
            mapped_signature_reason=mapped_signature_reason,
            require_proven_call_targets=require_proven_call_targets,
        )
        if verdict is not None:
            return verdict
        mapped_mismatch_seen = mapped_mismatch_seen or mismatch
    if mapped_mismatch_seen:
        return False, "direct call targets resolve to different mapped functions", None, None
    for oracle_target in oracle_targets:
        verdict = _unmapped_call_target_verdict(
            oracle_target,
            candidate_targets=candidate_targets,
            semantic_reason=semantic_reason,
            mapped_signature_reason=mapped_signature_reason,
            require_proven_call_targets=require_proven_call_targets,
        )
        if verdict is not None:
            return verdict
    if semantic_reason is not None:
        return True, semantic_reason, None, None
    return False, "no mapping proves direct call target equivalence", None, None


def _call_target_head_verdict(
    oracle_call: dict[str, Any] | None, candidate_call: dict[str, Any] | None
) -> tuple[bool, str, dict[str, Any] | None, str | None] | None:
    """Early verdict for missing calls or unresolved targets; None to continue."""
    if oracle_call is None and candidate_call is None:
        return True, "neither block ends in a direct call", None, None
    if oracle_call is None or candidate_call is None:
        return False, "only one block ends in a direct call", None, None
    oracle_target = oracle_call.get("resolved") if isinstance(oracle_call.get("resolved"), dict) else None
    candidate_target = candidate_call.get("resolved") if isinstance(candidate_call.get("resolved"), dict) else None
    if oracle_target is None or candidate_target is None:
        if (
            oracle_call.get("kind") == "unresolved"
            and candidate_call.get("kind") == "unresolved"
            and oracle_call.get("reason") == "call target is not a direct constant"
            and candidate_call.get("reason") == "call target is not a direct constant"
        ):
            return True, "both call targets are indirect expressions", None, None
        return False, "one or both direct call targets did not resolve to SSA functions", None, None
    return None


def _call_target_verdict(
    unproven_reason: str,
    *,
    semantic_reason: str | None,
    mapped_signature_reason: str | None,
    require_proven_call_targets: bool,
    prefer_semantic_reason: bool = False,
) -> tuple[bool, str, dict[str, Any] | None, str | None]:
    """Apply the semantic/mapped-signature/proven requirement chain to a matched target."""
    if prefer_semantic_reason and semantic_reason is not None:
        return True, semantic_reason, None, None
    if semantic_reason is not None:
        return True, unproven_reason, None, None
    if mapped_signature_reason is not None:
        return True, mapped_signature_reason, None, None
    if require_proven_call_targets:
        return False, "callee_not_proven", None, unproven_reason
    return True, unproven_reason, None, None


def _mapped_call_target_verdict(
    oracle_target: dict[str, Any],
    *,
    oracle_targets: list[dict[str, Any]],
    candidate_targets: list[dict[str, Any]],
    mapping_document: dict[str, Any] | None,
    semantic_reason: str | None,
    mapped_signature_reason: str | None,
    require_proven_call_targets: bool,
) -> tuple[tuple[bool, str, dict[str, Any] | None, str | None] | None, bool]:
    """Resolve one oracle target through the function map; (verdict|None, mapped_mismatch)."""
    oracle_id = str(oracle_target.get("id") or "")
    oracle_name = str(oracle_target.get("name") or "")
    mapped = _mapped_call_target(oracle_id, oracle_name, mapping_document)
    if mapped is None:
        return None, False
    if any(
        str(mapped.get("candidate_id") or "") == str(candidate_target.get("id") or "")
        or str(mapped.get("candidate_name") or "") == str(candidate_target.get("name") or "")
        for candidate_target in candidate_targets
    ):
        return _call_target_verdict(
            "direct call targets are equivalent through function mapping",
            semantic_reason=semantic_reason,
            mapped_signature_reason=mapped_signature_reason,
            require_proven_call_targets=require_proven_call_targets,
        ), False
    if semantic_reason is not None and _has_signature_only_target_pair(oracle_targets, candidate_targets):
        return (True, semantic_reason, None, None), False
    return None, True


def _unmapped_call_target_verdict(
    oracle_target: dict[str, Any],
    *,
    candidate_targets: list[dict[str, Any]],
    semantic_reason: str | None,
    mapped_signature_reason: str | None,
    require_proven_call_targets: bool,
) -> tuple[bool, str, dict[str, Any] | None, str | None] | None:
    """Match one oracle target by id/name/normalized-name; verdict or None."""
    oracle_id = str(oracle_target.get("id") or "")
    oracle_name = str(oracle_target.get("name") or "")
    if any(
        oracle_id and oracle_id == str(candidate_target.get("id") or "") for candidate_target in candidate_targets
    ):
        return _call_target_verdict(
            "direct call targets have the same function id",
            semantic_reason=semantic_reason,
            mapped_signature_reason=mapped_signature_reason,
            require_proven_call_targets=require_proven_call_targets,
            prefer_semantic_reason=semantic_reason == "direct call targets have identical binary-local signatures",
        )
    if any(
        oracle_name and oracle_name == str(candidate_target.get("name") or "")
        for candidate_target in candidate_targets
    ):
        return _call_target_verdict(
            "direct call targets have the same function name",
            semantic_reason=semantic_reason,
            mapped_signature_reason=mapped_signature_reason,
            require_proven_call_targets=require_proven_call_targets,
        )
    oracle_normalized_name = _normalized_symbol_name(oracle_name)
    if oracle_normalized_name and any(
        oracle_normalized_name == _normalized_symbol_name(str(candidate_target.get("name") or ""))
        for candidate_target in candidate_targets
    ):
        return _call_target_verdict(
            "direct call targets have equivalent normalized symbol names",
            semantic_reason=semantic_reason,
            mapped_signature_reason=mapped_signature_reason,
            require_proven_call_targets=require_proven_call_targets,
        )
    return None


def _call_target_briefs(call: dict[str, Any]) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    resolved = call.get("resolved") if isinstance(call.get("resolved"), dict) else None
    if resolved is not None:
        targets.append(resolved)
    for alias in call.get("aliases", []) or []:
        if isinstance(alias, dict) and alias not in targets:
            targets.append(alias)
    return targets


def _normalized_symbol_name(name: str) -> str:
    return name.lstrip("_").lower()


def _call_target_semantic_equivalence_reason(
    oracle_targets: list[dict[str, Any]], candidate_targets: list[dict[str, Any]]
) -> str | None:
    for oracle_target in oracle_targets:
        for candidate_target in candidate_targets:
            oracle_block_hash = oracle_target.get("machine_code_sha256")
            candidate_block_hash = candidate_target.get("machine_code_sha256")
            oracle_block_size = oracle_target.get("machine_code_size")
            candidate_block_size = candidate_target.get("machine_code_size")
            if (
                oracle_block_hash
                and oracle_block_hash == candidate_block_hash
                and oracle_block_size == candidate_block_size
            ):
                return "direct call target entry blocks have identical machine code"
            oracle_exact_block = oracle_target.get("exact_block_signature_sha256")
            candidate_exact_block = candidate_target.get("exact_block_signature_sha256")
            oracle_exact_block_size = oracle_target.get("exact_block_signature_size")
            candidate_exact_block_size = candidate_target.get("exact_block_signature_size")
            if (
                oracle_exact_block
                and oracle_exact_block == candidate_exact_block
                and oracle_exact_block_size == candidate_exact_block_size
            ):
                return "direct call target entry blocks have identical exact block signatures"
            oracle_layout_block = oracle_target.get("layout_block_signature_sha256")
            candidate_layout_block = candidate_target.get("layout_block_signature_sha256")
            oracle_layout_block_size = oracle_target.get("layout_block_signature_size")
            candidate_layout_block_size = candidate_target.get("layout_block_signature_size")
            if (
                oracle_layout_block
                and oracle_layout_block == candidate_layout_block
                and oracle_layout_block_size == candidate_layout_block_size
            ):
                return "direct call target entry blocks have identical layout-normalized block signatures"
            oracle_signature = oracle_target.get("signature_sha256")
            candidate_signature = candidate_target.get("signature_sha256")
            oracle_signature_size = oracle_target.get("signature_size")
            candidate_signature_size = candidate_target.get("signature_size")
            if (
                oracle_signature
                and oracle_signature == candidate_signature
                and oracle_signature_size == candidate_signature_size
            ):
                return "direct call targets have identical binary-local signatures"
            oracle_normalized_signature = oracle_target.get("normalized_signature_sha256")
            candidate_normalized_signature = candidate_target.get("normalized_signature_sha256")
            oracle_normalized_size = oracle_target.get("normalized_signature_size")
            candidate_normalized_size = candidate_target.get("normalized_signature_size")
            if (
                oracle_normalized_signature
                and oracle_normalized_signature == candidate_normalized_signature
                and oracle_normalized_size == candidate_normalized_size
                and (_is_signature_only_target(oracle_target) or _is_signature_only_target(candidate_target))
            ):
                return "direct call targets have identical normalized binary-local signatures"
            oracle_semantic = oracle_target.get("semantic_ssa_id")
            candidate_semantic = candidate_target.get("semantic_ssa_id")
            if oracle_semantic and oracle_semantic == candidate_semantic:
                return "direct call target entry blocks have identical compact SSA"
    return None


def _call_target_layout_signature_equivalence_reason(
    oracle_targets: list[dict[str, Any]], candidate_targets: list[dict[str, Any]]
) -> str | None:
    for oracle_target in oracle_targets:
        for candidate_target in candidate_targets:
            oracle_layout_signature = oracle_target.get("layout_signature_sha256")
            candidate_layout_signature = candidate_target.get("layout_signature_sha256")
            oracle_layout_size = oracle_target.get("layout_signature_size")
            candidate_layout_size = candidate_target.get("layout_signature_size")
            if (
                oracle_layout_signature
                and oracle_layout_signature == candidate_layout_signature
                and oracle_layout_size == candidate_layout_size
            ):
                return "direct call targets have identical layout-normalized binary-local signatures"
    return None


def _is_signature_only_target(target: dict[str, Any]) -> bool:
    return str(target.get("id") or "").startswith("library-signature:")


def _has_signature_only_target_pair(
    oracle_targets: list[dict[str, Any]], candidate_targets: list[dict[str, Any]]
) -> bool:
    return any(_is_signature_only_target(target) for target in [*oracle_targets, *candidate_targets])


def _mapped_call_target(
    oracle_id: str, oracle_name: str, mapping_document: dict[str, Any] | None
) -> dict[str, Any] | None:
    if not isinstance(mapping_document, dict) or mapping_document.get("schema") != "dosunit.mapping.v1":
        return None
    for item in mapping_document.get("functions", []) or []:
        if not isinstance(item, dict):
            continue
        if oracle_id and str(item.get("oracle_id") or "") == oracle_id:
            return item
        if oracle_name and str(item.get("oracle_name") or "") == oracle_name:
            return item
    return None


def _prepare_call_normalized_functions(
    oracle_function: dict[str, Any],
    candidate_function: dict[str, Any],
    *,
    call_compare: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    if not isinstance(call_compare, dict):
        return oracle_function, candidate_function, call_compare
    oracle_call = call_compare.get("oracle") if isinstance(call_compare.get("oracle"), dict) else None
    candidate_call = call_compare.get("candidate") if isinstance(call_compare.get("candidate"), dict) else None
    oracle_raw = _optional_int(oracle_call.get("raw")) if oracle_call is not None else None
    candidate_raw = _optional_int(candidate_call.get("raw")) if candidate_call is not None else None

    normalized = copy.deepcopy(call_compare)
    equivalent = bool(normalized.get("equivalent"))
    if equivalent:
        target_token = _canonical_call_target_token(normalized)
        target_value = _semantic_token_value(target_token)
        normalized["semantic_target"] = {
            "token": target_token,
            "value": normalize_hex(target_value & 0xFFFFFFFF, width=8),
            "source": "proof_fact" if isinstance(normalized.get("proof_fact"), dict) else "resolved_target",
        }
    else:
        target_value = None

    if oracle_raw is not None and candidate_raw is not None:
        oracle_copy = _with_call_target_output(
            oracle_function, target_value if target_value is not None else oracle_raw
        )
        candidate_copy = _with_call_target_output(
            candidate_function, target_value if target_value is not None else candidate_raw
        )
    else:
        oracle_copy = copy.deepcopy(oracle_function)
        candidate_copy = copy.deepcopy(candidate_function)
    if equivalent:
        oracle_copy, oracle_return = _normalize_call_return_store(oracle_copy)
        candidate_copy, candidate_return = _normalize_call_return_store(candidate_copy)
        oracle_copy, oracle_stack = _normalize_call_stack_store_addresses(oracle_copy)
        candidate_copy, candidate_stack = _normalize_call_stack_store_addresses(candidate_copy)
        normalized["normalizations"] = [
            {"side": "oracle", **oracle_return},
            {"side": "candidate", **candidate_return},
            {"side": "oracle", **oracle_stack},
            {"side": "candidate", **candidate_stack},
        ]
    oracle_copy = _drop_call_boundary_volatile_outputs(oracle_copy)
    candidate_copy = _drop_call_boundary_volatile_outputs(candidate_copy)
    return oracle_copy, candidate_copy, normalized


def _drop_call_boundary_volatile_outputs(function: dict[str, Any]) -> dict[str, Any]:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    if source.get("jumpkind") != "Ijk_Call":
        return function
    outputs = function.get("outputs") if isinstance(function.get("outputs"), dict) else None
    if not outputs:
        return function
    removable = {"ax", "dx", "sp"}
    if not any(key in outputs for key in removable):
        return function
    copied = copy.deepcopy(function)
    copied_outputs = copied.get("outputs") if isinstance(copied.get("outputs"), dict) else {}
    for key in removable:
        copied_outputs.pop(key, None)
    return copied


def _prepare_layout_normalized_functions(
    oracle_function: dict[str, Any],
    candidate_function: dict[str, Any],
    *,
    global_map: dict[int, int] | None = None,
    image_context: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    pairs = _layout_constant_pairs(oracle_function, candidate_function, image_context=image_context)
    if not pairs and not global_map:
        return oracle_function, candidate_function, None
    candidate_map: dict[int, int] = dict(global_map or {})
    candidate_reasons: dict[int, str] = {key: "global_reloc" for key in candidate_map}
    notes: list[dict[str, Any]] = []
    for pair in pairs:
        oracle_value = int(pair["oracle"])
        candidate_value = int(pair["candidate"])
        for candidate_key, oracle_replacement in _layout_constant_normalization_entries(pair):
            if candidate_key in candidate_map and candidate_map[candidate_key] != oracle_replacement:
                continue
            candidate_map[candidate_key] = oracle_replacement
            candidate_reasons[candidate_key] = str(pair.get("reason") or "")
        notes.append(
            {
                "oracle": normalize_hex(oracle_value, width=4),
                "candidate": normalize_hex(candidate_value, width=4),
                "reason": pair.get("reason"),
            }
        )
    _extend_normalization_with_residual_constants(
        oracle_function, candidate_function, candidate_map, candidate_reasons, notes
    )
    if not candidate_map:
        return oracle_function, candidate_function, None
    candidate_copy = dict(candidate_function)
    candidate_copy["_constant_normalization"] = candidate_map
    candidate_copy["_constant_normalization_reasons"] = candidate_reasons
    return_address_keys = _call_return_address_normalization_keys(
        oracle_function, pairs, notes
    )
    if return_address_keys:
        candidate_copy["_call_return_address_keys"] = return_address_keys
    return (
        oracle_function,
        candidate_copy,
        {"kind": "layout_constants", "pairs": notes, "global_pair_count": len(global_map or {})},
    )


def _call_return_address_normalization_keys(
    oracle_function: dict[str, Any],
    pairs: list[dict[str, Any]],
    notes: list[dict[str, Any]],
) -> set[int]:
    """Candidate keys that hold a pushed call return address, not data.

    A ``control_target``/``control_fallthrough`` constant is normally kept
    literal outside the ``ip`` output so genuine stored-code diffs surface.
    In an ``Ijk_Call`` part, the value pushed on the stack as the call's
    return is provably layout-derived when the oracle constant equals the
    oracle fallthrough linear low16; those candidate keys may normalize.
    """
    source = oracle_function.get("source") if isinstance(oracle_function.get("source"), dict) else {}
    transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else {}
    jumpkind = str(source.get("jumpkind") or transfer.get("jumpkind") or "")
    if jumpkind != "Ijk_Call":
        return set()
    fallthrough = transfer.get("fallthrough") if isinstance(transfer.get("fallthrough"), dict) else {}
    return_low16 = _optional_int(fallthrough.get("low16", fallthrough.get("linear")))
    if return_low16 is None:
        return set()
    return_low16 &= 0xFFFF
    keys: set[int] = set()
    for pair in pairs:
        if str(pair.get("reason")) not in {"control_target", "control_fallthrough"}:
            continue
        if (int(pair["oracle"]) & 0xFFFF) != return_low16:
            continue
        for candidate_key, _oracle_replacement in _layout_constant_normalization_entries(pair):
            keys.add(candidate_key)
    return keys


def _term_constant_leaves(function: dict[str, Any]) -> set[int]:
    """All 16-bit constant leaves reachable from a part's outputs/assignments (ref-resolved)."""
    assignments = {
        str(item["id"]): item
        for item in function.get("assignments", []) or []
        if isinstance(item, dict) and "id" in item
    }
    leaves: set[int] = set()
    pending: list[Any] = [v for v in (function.get("outputs") or {}).values() if isinstance(v, dict)]
    pending.extend(assignments.values())
    seen: set[int] = set()
    while pending:
        term = pending.pop()
        if isinstance(term, list):
            pending.extend(term)
            continue
        if not isinstance(term, dict) or id(term) in seen:
            continue
        seen.add(id(term))
        ref = term.get("ref")
        if isinstance(ref, str) and ref in assignments:
            pending.append(assignments[ref])
            continue
        if str(term.get("op", "")).lower() == "const":
            value = term.get("value")
            try:
                leaves.add((int(value, 0) if isinstance(value, str) else int(value)) & 0xFFFF)
            except (TypeError, ValueError):
                pass
            continue
        pending.extend(term.get("args") or [])
    return leaves


def _extend_normalization_with_residual_constants(
    oracle_function: dict[str, Any],
    candidate_function: dict[str, Any],
    candidate_map: dict[int, int],
    candidate_reasons: dict[int, str],
    notes: list[dict[str, Any]],
) -> None:
    """Map term-only constants belonging to an established relocated delta group.

    A relocated constant can appear inside an expression (e.g. a byte field of a
    relocated datum) without ever being an instruction immediate, so positional
    pairing misses it. When at least two pairs share one 16-bit delta, an unmapped
    candidate leaf `c` is adopted when `c - delta` is itself an oracle term leaf and
    `c` sits within +-8 of an already-mapped candidate constant (same datum).
    """
    delta_support: dict[int, int] = {}
    for candidate_value, oracle_value in candidate_map.items():
        delta = (int(candidate_value) - int(oracle_value)) & 0xFFFF
        delta_support[delta] = delta_support.get(delta, 0) + 1
    established = {delta for delta, count in delta_support.items() if count >= 2}
    if not established:
        return
    oracle_leaves = _term_constant_leaves(oracle_function)
    candidate_leaves = _term_constant_leaves(candidate_function)
    mapped_candidates = set(candidate_map)
    for candidate_value in sorted(candidate_leaves - mapped_candidates):
        for delta in sorted(established):
            oracle_value = (candidate_value - delta) & 0xFFFF
            if oracle_value not in oracle_leaves:
                continue
            if not any(abs(candidate_value - mapped) <= 8 for mapped in mapped_candidates):
                continue
            candidate_map[candidate_value] = oracle_value
            candidate_reasons[candidate_value] = "residual_same_delta"
            notes.append(
                {
                    "oracle": normalize_hex(oracle_value, width=4),
                    "candidate": normalize_hex(candidate_value, width=4),
                    "reason": "residual_same_delta",
                }
            )
            mapped_candidates.add(candidate_value)
            break


def _layout_constant_pairs(
    oracle_function: dict[str, Any],
    candidate_function: dict[str, Any],
    *,
    image_context: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    oracle_instructions = _ssa_instructions(oracle_function)
    candidate_instructions = _ssa_instructions(candidate_function)
    if not oracle_instructions or len(oracle_instructions) != len(candidate_instructions):
        return []
    has_ivt_segment_store = any(
        _is_ivt_segment_store(oracle) and _is_ivt_segment_store(candidate)
        for oracle, candidate in zip(oracle_instructions, candidate_instructions, strict=False)
    )
    data_segment_immediate_indexes = _data_segment_immediate_indexes(oracle_instructions, candidate_instructions)
    far_pointer_offset_indexes, far_pointer_segment_indexes = _far_pointer_pair_indexes(
        oracle_instructions, candidate_instructions
    )
    pairs: list[dict[str, Any]] = []
    memory_pairs: list[tuple[int, int]] = []
    absolute_memory_pairs: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    pointer_arithmetic_by_index = _pointer_arithmetic_evidence_by_index(oracle_instructions, candidate_instructions)
    for instruction_index, (oracle, candidate) in enumerate(zip(oracle_instructions, candidate_instructions, strict=False)):
        instruction_pairs = _instruction_layout_constant_pairs(
            oracle,
            candidate,
            has_ivt_segment_store=has_ivt_segment_store,
            data_segment_immediate=instruction_index in data_segment_immediate_indexes,
            pointer_arithmetic_regs=pointer_arithmetic_by_index.get(instruction_index, set()),
            far_pointer_offset=instruction_index in far_pointer_offset_indexes,
            far_pointer_segment=instruction_index in far_pointer_segment_indexes,
        )
        for pair in instruction_pairs:
            if pair.get("reason") == "absolute_memory_operand":
                absolute_memory_pairs.append(pair)
            elif pair.get("reason") == "code_segment_memory_operand" or pair.get("reason") == "memory_operand":
                memory_pairs.append((int(pair["oracle"]), int(pair["candidate"])))
                pairs.append(pair)
            elif pair.get("reason") in {
                "pointer_immediate",
                "pointer_arithmetic",
                "ivt_segment",
                "data_segment_immediate",
                "control_target",
                "control_fallthrough",
                "pointer_bound",
                "far_pointer_offset",
                "far_pointer_segment",
            }:
                pairs.append(pair)
            else:
                deferred.append(pair)
    _group_layout_constant_pairs(pairs, absolute_memory_pairs, memory_pairs, deferred)
    pairs.extend(_call_argument_immediate_layout_pairs(oracle_instructions, candidate_instructions))
    pairs.extend(_call_far_pointer_push_pairs(oracle_instructions, candidate_instructions, image_context))
    pairs.extend(_relocated_immediate_pairs(oracle_instructions, candidate_instructions, image_context))
    pairs.extend(_seg_register_far_pointer_pairs(oracle_instructions, candidate_instructions, image_context))
    pairs.extend(_entry_shift_immediate_pairs(oracle_function, candidate_function))
    pairs.extend(_stored_pointer_immediate_pairs(oracle_instructions, candidate_instructions))
    pairs.extend(_call_return_address_pairs(oracle_function, candidate_function))
    pairs.extend(_control_transfer_layout_constant_pairs(oracle_function, candidate_function))
    return _unique_layout_pairs(pairs)


def _aligned_immediate_pairs(
    oracle_function: dict[str, Any], candidate_function: dict[str, Any]
) -> list[tuple[int, int]]:
    """All differing (candidate, oracle) 16-bit immediates between aligned instruction streams."""
    oracle_instructions = _ssa_instructions(oracle_function)
    candidate_instructions = _ssa_instructions(candidate_function)
    if not oracle_instructions or len(oracle_instructions) != len(candidate_instructions):
        return []
    pairs: list[tuple[int, int]] = []
    for oracle, candidate in zip(oracle_instructions, candidate_instructions, strict=False):
        if str(oracle.get("mnemonic", "")).lower() != str(candidate.get("mnemonic", "")).lower():
            continue
        oracle_op = str(oracle.get("op_str", "")).lower()
        candidate_op = str(candidate.get("op_str", "")).lower()
        if _number_template(oracle_op) != _number_template(candidate_op):
            continue
        oracle_numbers = _number_tokens(oracle_op)
        candidate_numbers = _number_tokens(candidate_op)
        if len(oracle_numbers) != len(candidate_numbers):
            continue
        for oracle_value, candidate_value in zip(oracle_numbers, candidate_numbers, strict=False):
            oracle_low = oracle_value & 0xFFFF
            candidate_low = candidate_value & 0xFFFF
            if oracle_low != candidate_low:
                pairs.append((candidate_low, oracle_low))
    return pairs


def _collect_global_layout_normalization(
    oracle_functions: list[dict[str, Any]],
    *,
    mapping_document: dict[str, Any] | None,
    mapped_candidates: dict[str, Any],
    tables: Any,  # noqa: ANN401
) -> dict[int, int]:
    """Candidate→oracle constant map for immediates that recur as layout pairs across functions."""
    if mapping_document is None:
        return {}
    support: dict[tuple[int, int], set[str]] = defaultdict(set)
    for oracle_function in oracle_functions:
        function = oracle_function.get("function", {}) if isinstance(oracle_function, dict) else {}
        function_id = str(function.get("id", ""))
        function_name = str(function.get("name", function_id))
        mapped = mapped_candidates.get(function_id) or mapped_candidates.get(function_name)
        if mapped is None:
            continue
        candidate_function = _resolve_mapped_candidate(oracle_function, mapped=mapped, tables=tables)
        if candidate_function is None:
            continue
        for candidate_value, oracle_value in _aligned_immediate_pairs(oracle_function, candidate_function):
            if oracle_value < 0x100 or candidate_value < 0x100:
                continue
            support[(candidate_value, oracle_value)].add(function_id or function_name)
    promoted: dict[int, int] = {}
    banned: set[int] = set()
    for (candidate_value, oracle_value), functions in support.items():
        if len(functions) < 2 or candidate_value in banned:
            continue
        if candidate_value in promoted and promoted[candidate_value] != oracle_value:
            banned.add(candidate_value)
            del promoted[candidate_value]
            continue
        promoted[candidate_value] = oracle_value
    return promoted


def _group_layout_constant_pairs(
    pairs: list[dict[str, Any]],
    absolute_memory_pairs: list[dict[str, Any]],
    memory_pairs: list[tuple[int, int]],
    deferred: list[dict[str, Any]],
) -> None:
    """Promote absolute-memory and deferred pairs into `pairs` via shared deltas."""
    absolute_deltas = {((int(pair["candidate"]) - int(pair["oracle"])) & 0xFFFF) for pair in absolute_memory_pairs}
    if len(absolute_memory_pairs) == 1 or len(absolute_deltas) == 1:
        for pair in absolute_memory_pairs:
            memory_pairs.append((int(pair["oracle"]), int(pair["candidate"])))
            pairs.append(pair)
    deltas = {((int(pair["candidate"]) - int(pair["oracle"])) & 0xFFFF) for pair in pairs}
    deltas |= {((candidate - oracle) & 0xFFFF) for oracle, candidate in memory_pairs}
    deferred_by_delta: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for pair in deferred:
        oracle = int(pair["oracle"])
        candidate = int(pair["candidate"])
        delta = (candidate - oracle) & 0xFFFF
        if delta in deltas:
            pair = dict(pair)
            pair["reason"] = "same_delta_address_base"
            pairs.append(pair)
        else:
            deferred_by_delta[delta].append(pair)
    for grouped in deferred_by_delta.values():
        if len(grouped) < 2:
            continue
        for pair in grouped:
            pair = dict(pair)
            pair["reason"] = "same_delta_constant_set"
            pairs.append(pair)


def _mov_reg_imm(instruction: dict[str, Any]) -> tuple[str | None, int | None]:
    op_str = str(instruction.get("op_str", "")).strip().lower()
    if "," not in op_str:
        return None, None
    lhs, rhs = (part.strip() for part in op_str.split(",", 1))
    if not lhs or not re.fullmatch(r"[a-z][a-z0-9]*", lhs):
        return None, None
    try:
        return lhs, int(rhs, 0)
    except ValueError:
        return None, None


def _pushes_register(instruction: dict[str, Any], register: str) -> bool:
    return str(instruction.get("mnemonic", "")).lower() == "push" and str(
        instruction.get("op_str", "")
    ).strip().lower() == register


def _call_argument_immediate_layout_pairs(
    oracle_instructions: list[dict[str, Any]], candidate_instructions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not any(str(item.get("mnemonic", "")).lower() in {"call", "lcall"} for item in oracle_instructions):
        return []
    if not any(str(item.get("mnemonic", "")).lower() in {"call", "lcall"} for item in candidate_instructions):
        return []
    pairs: list[dict[str, Any]] = []
    for index in range(min(len(oracle_instructions), len(candidate_instructions)) - 1):
        oracle = oracle_instructions[index]
        candidate = candidate_instructions[index]
        oracle_next = oracle_instructions[index + 1]
        candidate_next = candidate_instructions[index + 1]
        if str(oracle.get("mnemonic", "")).lower() != "mov" or str(candidate.get("mnemonic", "")).lower() != "mov":
            continue
        oracle_reg, oracle_value = _mov_reg_imm(oracle)
        candidate_reg, candidate_value = _mov_reg_imm(candidate)
        if oracle_reg is None or oracle_reg != candidate_reg or oracle_value is None or candidate_value is None:
            continue
        if (oracle_value & 0xFFFF) == (candidate_value & 0xFFFF):
            continue
        if not _looks_layout_constant(oracle_value & 0xFFFF, candidate_value & 0xFFFF):
            continue
        if not _pushes_register(oracle_next, oracle_reg) or not _pushes_register(candidate_next, candidate_reg):
            continue
        pairs.append(
            {
                "oracle": oracle_value & 0xFFFF,
                "candidate": candidate_value & 0xFFFF,
                "oracle_raw": oracle_value,
                "candidate_raw": candidate_value,
                "reason": "call_argument_immediate",
            }
        )
    return pairs


def _push_immediate(instruction: dict[str, Any]) -> int | None:
    if str(instruction.get("mnemonic", "")).lower() != "push":
        return None
    op_str = str(instruction.get("op_str", "")).strip().lower()
    try:
        return int(op_str, 0)
    except ValueError:
        return None


def _cstring_at(image: bytes, byte_off: int, limit: int = 256) -> bytes | None:
    """NUL-terminated byte string at ``byte_off`` (terminator included)."""
    if byte_off < 0 or byte_off >= len(image):
        return None
    end = image.find(b"\x00", byte_off)
    if end < 0 or end - byte_off > limit:
        return None
    return image[byte_off : end + 1]


def _mz_reloc_segment_targets(image: bytes, relocs: tuple[tuple[int, int], ...]) -> list[int]:
    """Distinct unrelocated segment-paragraph values stored at relocation sites."""
    targets: set[int] = set()
    for off, seg in relocs:
        linear = (seg << 4) + off
        if linear + 2 <= len(image):
            targets.add(int.from_bytes(image[linear : linear + 2], "little"))
    return sorted(targets)


def _layout_image_context(
    oracle: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, dict[str, Any]] | None:
    """Load each document's ``exe`` image and segment targets for data-content proofs.

    A ``push ds; push off`` far-pointer argument references the runtime data
    segment; the MZ relocation table records every segment paragraph the
    image materializes, so ``para*16 + off`` candidates can be enumerated and
    the referenced bytes compared across the two binaries.
    """
    context: dict[str, dict[str, Any]] = {}
    for label, document in (("oracle", oracle), ("candidate", candidate)):
        exe = document.get("exe") if isinstance(document, dict) else None
        if not isinstance(exe, str) or not exe:
            return None
        try:
            loaded = load_mz_image(Path(exe))
        except (OSError, DosUnitError):
            return None
        image = loaded.memory[: loaded.image_size]
        context[label] = {
            "image": image,
            "seg_targets": _mz_reloc_segment_targets(image, loaded.relocs),
            "reloc_positions": frozenset((seg << 4) + off for off, seg in loaded.relocs),
        }
    return context


def _relocated_immediate_pairs(
    oracle_instructions: list[dict[str, Any]],
    candidate_instructions: list[dict[str, Any]],
    image_context: dict[str, dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Normalize immediates whose bytes occupy an MZ relocation site.

    ``mov dx, DGROUP`` / ``mov ax, seg segNN`` encode a paragraph patched by the
    loader; the relocation table names every such word in the image.  A
    differing immediate is a proven relocation when the instruction's imm
    operand bytes coincide with a reloc entry in its own binary — independent
    of instruction kind or call context.
    """
    if image_context is None:
        return []
    try:
        import capstone  # type: ignore
    except Exception:
        return []
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    md.detail = True

    def _reloc_imm_values(
        instructions: list[dict[str, Any]], reloc_positions: frozenset[int]
    ) -> dict[int, int]:
        values: dict[int, int] = {}
        for index, instruction in enumerate(instructions):
            raw = instruction.get("bytes")
            address = instruction.get("address") if isinstance(instruction.get("address"), dict) else {}
            linear = _optional_int(address.get("linear"))
            if not isinstance(raw, str) or linear is None:
                continue
            try:
                blob = bytes.fromhex(raw)
            except ValueError:
                continue
            insn = next(md.disasm(blob, linear), None)
            if insn is None:
                continue
            encoding = getattr(insn, "encoding", None)
            imm_offset = int(getattr(encoding, "imm_offset", 0) or 0)
            imm_size = int(getattr(encoding, "imm_size", 0) or 0)
            if imm_offset <= 0 or imm_size != 2:
                continue
            site = (linear - 0x1000) + imm_offset
            if site in reloc_positions:
                values[index] = int.from_bytes(blob[imm_offset : imm_offset + 2], "little")
        return values

    oracle_sites = _reloc_imm_values(
        oracle_instructions, image_context.get("oracle", {}).get("reloc_positions") or frozenset()
    )
    candidate_sites = _reloc_imm_values(
        candidate_instructions, image_context.get("candidate", {}).get("reloc_positions") or frozenset()
    )
    pairs: list[dict[str, Any]] = []
    for index, oracle_value in oracle_sites.items():
        candidate_value = candidate_sites.get(index)
        if candidate_value is None or oracle_value == candidate_value:
            continue
        pairs.append(
            {
                "oracle": oracle_value,
                "candidate": candidate_value,
                "reason": "relocated_segment_immediate",
            }
        )
    return pairs


_SEGMENT_PUSH_REGS = ("ds", "es", "ss", "cs")


def _seg_pointer_string_matches(
    context: dict[str, dict[str, Any]] | None,
    oracle_off: int,
    candidate_off: int,
    *,
    min_len: int,
) -> list[tuple[int, int]]:
    """Paragraph pairs under which both pushed offsets hold the same string.

    For every segment paragraph each image's relocation table materializes,
    ``para*16 + off`` is a plausible data-string address.  Returns every
    ``(para_o, para_c)`` combination yielding byte-identical NUL-terminated
    strings of at least ``min_len`` bytes including the terminator.
    """
    if not context:
        return []
    oracle_side = context.get("oracle") or {}
    candidate_side = context.get("candidate") or {}
    oracle_image = oracle_side.get("image")
    candidate_image = candidate_side.get("image")
    if not isinstance(oracle_image, bytes) or not isinstance(candidate_image, bytes):
        return []
    matches: list[tuple[int, int]] = []
    for para_o in oracle_side.get("seg_targets") or []:
        s_o = _cstring_at(oracle_image, para_o * 16 + oracle_off)
        if s_o is None or len(s_o) < min_len or not any(0x20 <= b <= 0x7E for b in s_o):
            continue
        for para_c in candidate_side.get("seg_targets") or []:
            if _cstring_at(candidate_image, para_c * 16 + candidate_off) == s_o:
                matches.append((para_o, para_c))
    return matches


def _seg_pointer_string_equal(
    context: dict[str, dict[str, Any]] | None, oracle_off: int, candidate_off: int
) -> bool:
    """Prove two pushed data-segment offsets reference byte-identical strings."""
    return bool(
        _seg_pointer_string_matches(context, oracle_off, candidate_off, min_len=4)
    )


def _seg_register_far_pointer_pairs(
    oracle_instructions: list[dict[str, Any]],
    candidate_instructions: list[dict[str, Any]],
    image_context: dict[str, dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Normalize ``push segr`` + ``push off`` far-pointer args with proven-equal strings.

    ``play_sound("swish", 15)`` pushes the volume, ``ds``, then the string
    offset — the offset differs across layouts while the segment register is
    identical.  A lone differing push is only normalized when the bytes it
    addresses in each image are proven equal via the relocation-table segment
    targets (see ``_seg_pointer_string_equal``); a genuinely different string
    stays compared.
    """
    if image_context is None:
        return []
    differing: list[tuple[int, int]] = []
    for index, (oracle, candidate) in enumerate(zip(oracle_instructions, candidate_instructions, strict=False)):
        oracle_value = _push_immediate(oracle)
        candidate_value = _push_immediate(candidate)
        if oracle_value is None or candidate_value is None:
            continue
        oracle_off = oracle_value & 0xFFFF
        candidate_off = candidate_value & 0xFFFF
        if oracle_off == candidate_off:
            continue
        seg_adjacent = False
        for neighbor in (index - 1, index + 1):
            if not (0 <= neighbor < len(oracle_instructions)):
                continue
            for reg in _SEGMENT_PUSH_REGS:
                if _pushes_register(oracle_instructions[neighbor], reg) and _pushes_register(
                    candidate_instructions[neighbor], reg
                ):
                    seg_adjacent = True
        if not seg_adjacent:
            continue
        differing.append((oracle_off, candidate_off))
    pairs: list[dict[str, Any]] = []
    witnessed_paras: set[tuple[int, int]] = set()
    # Strings of >=4 bytes are self-proving; record their paragraph witnesses
    # so 3-byte strings can borrow the established cross-binary relocation.
    for oracle_off, candidate_off in differing:
        matches = _seg_pointer_string_matches(
            image_context, oracle_off, candidate_off, min_len=4
        )
        if not matches:
            continue
        witnessed_paras.update(matches)
        pairs.append(
            {
                "oracle": oracle_off,
                "candidate": candidate_off,
                "reason": "data_string_arg",
            }
        )
    for oracle_off, candidate_off in differing:
        if any(item["oracle"] == oracle_off and item["candidate"] == candidate_off for item in pairs):
            continue
        matches = _seg_pointer_string_matches(
            image_context, oracle_off, candidate_off, min_len=3
        )
        if not matches:
            continue
        # A 3-byte string is weak evidence alone; accept it only under a
        # paragraph pair already witnessed by a longer string, or when the
        # match is unique across the whole relocation table.
        if not (set(matches) & witnessed_paras or len(matches) == 1):
            continue
        pairs.append(
            {
                "oracle": oracle_off,
                "candidate": candidate_off,
                "reason": "data_string_arg",
            }
        )
    return pairs


def _call_far_pointer_push_pairs(
    oracle_instructions: list[dict[str, Any]],
    candidate_instructions: list[dict[str, Any]],
    image_context: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Normalize far-pointer call arguments built via consecutive push immediates.

    `setvect(n, isr)` / `atexit(func)` pass far function pointers as `push seg` +
    `push offset` — relocated code addresses that differ across layouts. A maximal
    run of >=2 consecutive *differing* push immediates is normalized when the run
    contains a proven segment-paragraph push (the pushed value appears among the
    relocation-table segment targets of its own image) or a segment-like pair
    (both >=0x1000); a lone differing push without provenance could be a real
    argument change and stays compared.
    """
    call_mnemonics = {"call", "lcall"}
    if not any(str(item.get("mnemonic", "")).lower() in call_mnemonics for item in oracle_instructions):
        return []
    if not any(str(item.get("mnemonic", "")).lower() in call_mnemonics for item in candidate_instructions):
        return []
    oracle_seg_targets = frozenset((image_context or {}).get("oracle", {}).get("seg_targets") or ())
    candidate_seg_targets = frozenset((image_context or {}).get("candidate", {}).get("seg_targets") or ())

    def _proven_segment(index: int) -> bool:
        oracle_value, candidate_value = pushed_values[index]
        # Relocated segment pushes carry the +0x1000 image-load bias as +0x100
        # paragraphs; relocation-table targets store the unrelocated paragraph.
        oracle_hit = oracle_value in oracle_seg_targets or (oracle_value - 0x100) in oracle_seg_targets
        candidate_hit = candidate_value in candidate_seg_targets or (candidate_value - 0x100) in candidate_seg_targets
        return oracle_hit and candidate_hit

    differing_push_indexes: list[int] = []
    pushed_values: dict[int, tuple[int, int]] = {}
    for index, (oracle, candidate) in enumerate(zip(oracle_instructions, candidate_instructions, strict=False)):
        oracle_value = _push_immediate(oracle)
        candidate_value = _push_immediate(candidate)
        if oracle_value is None or candidate_value is None:
            continue
        if (oracle_value & 0xFFFF) == (candidate_value & 0xFFFF):
            continue
        differing_push_indexes.append(index)
        pushed_values[index] = (oracle_value & 0xFFFF, candidate_value & 0xFFFF)
    pairs: list[dict[str, Any]] = []

    def _emit(run: list[int]) -> None:
        if not run:
            return
        run_set = set(run)
        indexes: set[int] = set()
        for i in run:
            if not _proven_segment(i):
                continue
            indexes.add(i)
            # A relocated segment paragraph is the high word of a far pointer;
            # the push immediately after it carries the relocated offset.
            if i + 1 in run_set:
                indexes.add(i + 1)
        if len(run) >= 2 and any(o >= 0x1000 and c >= 0x1000 for o, c in (pushed_values[i] for i in run)):
            indexes.update(run)
        if not indexes:
            return
        for i in sorted(indexes):
            oracle_value, candidate_value = pushed_values[i]
            pairs.append(
                {
                    "oracle": oracle_value,
                    "candidate": candidate_value,
                    "reason": "far_pointer_push_arg",
                }
            )

    run: list[int] = []
    for index in differing_push_indexes:
        if run and index == run[-1] + 1:
            run.append(index)
            continue
        _emit(run)
        run = [index]
    _emit(run)
    return pairs


def _entry_shift_immediate_pairs(
    oracle_function: dict[str, Any], candidate_function: dict[str, Any]
) -> list[dict[str, Any]]:
    """Normalize within-segment offset immediates shifted in lockstep with the block.

    When a part's own entry offset shifted by `S` between binaries, an embedded
    within-segment code offset (case/dispatch targets) shifts by the same `S`.
    A differing immediate whose delta equals the entry shift is relocation, not a
    changed argument. Immediate >=0x100 required so small enum constants stay compared.
    """
    oracle_instructions = _ssa_instructions(oracle_function)
    candidate_instructions = _ssa_instructions(candidate_function)
    if not oracle_instructions or len(oracle_instructions) != len(candidate_instructions):
        return []
    oracle_entry = oracle_instructions[0].get("address") if isinstance(oracle_instructions[0], dict) else None
    candidate_entry = candidate_instructions[0].get("address") if isinstance(candidate_instructions[0], dict) else None
    try:
        oracle_ip = int((oracle_entry or {}).get("ip"), 0) & 0xFFFF
        candidate_ip = int((candidate_entry or {}).get("ip"), 0) & 0xFFFF
    except (TypeError, ValueError):
        return []
    shift = (candidate_ip - oracle_ip) & 0xFFFF
    if shift == 0:
        return []
    pairs: list[dict[str, Any]] = []
    for oracle, candidate in zip(oracle_instructions, candidate_instructions, strict=False):
        if str(oracle.get("mnemonic", "")).lower() != str(candidate.get("mnemonic", "")).lower():
            continue
        oracle_op = str(oracle.get("op_str", "")).lower()
        candidate_op = str(candidate.get("op_str", "")).lower()
        if _number_template(oracle_op) != _number_template(candidate_op):
            continue
        oracle_numbers = _number_tokens(oracle_op)
        candidate_numbers = _number_tokens(candidate_op)
        if len(oracle_numbers) != len(candidate_numbers):
            continue
        for oracle_value, candidate_value in zip(oracle_numbers, candidate_numbers, strict=False):
            oracle_low = oracle_value & 0xFFFF
            candidate_low = candidate_value & 0xFFFF
            if oracle_low == candidate_low or oracle_low < 0x100 or candidate_low < 0x100:
                continue
            if (candidate_low - oracle_low) & 0xFFFF != shift:
                continue
            pairs.append(
                {
                    "oracle": oracle_low,
                    "candidate": candidate_low,
                    "reason": "entry_shift_relocated",
                }
            )
    return pairs


def _stored_pointer_immediate_pairs(
    oracle_instructions: list[dict[str, Any]], candidate_instructions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Normalize relocated pointer values stored into equal absolute cells.

    `mov word ptr cs:[K], imm` writes a code offset into a code-segment param
    block; `mov word ptr [K], imm` writes a handler/vector pointer into a fixed
    DGROUP cell. Equal destinations on both sides plus an address-like stored
    immediate (>=0x100 cs-dest / >=0x1000 ds-dest) identify relocated constants.
    """
    pairs: list[dict[str, Any]] = []
    pattern = re.compile(r"^word ptr\s+(cs:)?\[(0x[0-9a-f]+|\d+)\]\s*,\s*(0x[0-9a-f]+|\d+)$")
    for oracle, candidate in zip(oracle_instructions, candidate_instructions, strict=False):
        if str(oracle.get("mnemonic", "")).lower() != "mov" or str(candidate.get("mnemonic", "")).lower() != "mov":
            continue
        oracle_op = str(oracle.get("op_str", "")).strip().lower()
        candidate_op = str(candidate.get("op_str", "")).strip().lower()
        oracle_match = pattern.match(oracle_op)
        candidate_match = pattern.match(candidate_op)
        if not oracle_match or not candidate_match:
            continue
        if oracle_match.group(1) != candidate_match.group(1) or oracle_match.group(2) != candidate_match.group(2):
            continue
        oracle_value = int(oracle_match.group(3), 0) & 0xFFFF
        candidate_value = int(candidate_match.group(3), 0) & 0xFFFF
        if oracle_value == candidate_value:
            continue
        minimum = 0x100 if oracle_match.group(1) == "cs:" else 0x1000
        if oracle_value < minimum or candidate_value < minimum:
            continue
        pairs.append(
            {
                "oracle": oracle_value,
                "candidate": candidate_value,
                "reason": "code_segment_stored_immediate"
                if oracle_match.group(1) == "cs:"
                else "absolute_memory_stored_pointer",
            }
        )
    return pairs


def _call_return_address_pairs(
    oracle_function: dict[str, Any], candidate_function: dict[str, Any]
) -> list[dict[str, Any]]:
    """Normalize the return-address constants a call stores before transferring.

    The last call instruction pushes `{seg,ip}` where `ip` = the post-call
    address (call_ip + size). Those constants are relocated by definition; they
    only differ because the layouts differ. A term constant leaf equal to each
    side's post-call address identifies the pair.
    """
    pairs: list[dict[str, Any]] = []
    oracle_instructions = _ssa_instructions(oracle_function)
    candidate_instructions = _ssa_instructions(candidate_function)
    oracle_leaves = _term_constant_leaves(oracle_function)
    candidate_leaves = _term_constant_leaves(candidate_function)
    for oracle, candidate in zip(oracle_instructions, candidate_instructions, strict=False):
        if str(oracle.get("mnemonic", "")).lower() not in {"call", "lcall"}:
            continue
        if str(candidate.get("mnemonic", "")).lower() not in {"call", "lcall"}:
            continue
        post_ips: list[int | None] = []
        for instruction in (oracle, candidate):
            address = instruction.get("address") if isinstance(instruction.get("address"), dict) else {}
            try:
                ip = int(address.get("ip"), 0) & 0xFFFF
            except (TypeError, ValueError):
                ip = None
            size = instruction.get("size")
            post_ips.append((ip + int(size)) & 0xFFFF if ip is not None and isinstance(size, int) else None)
        oracle_post, candidate_post = post_ips
        if oracle_post is None or candidate_post is None or oracle_post == candidate_post:
            continue
        if oracle_post in oracle_leaves and candidate_post in candidate_leaves:
            pairs.append(
                {
                    "oracle": oracle_post,
                    "candidate": candidate_post,
                    "reason": "call_return_address",
                }
            )
    return pairs


def _control_transfer_layout_constant_pairs(
    oracle_function: dict[str, Any], candidate_function: dict[str, Any]
) -> list[dict[str, Any]]:
    oracle_successors = _successor_low16_by_delta(oracle_function)
    candidate_successors = _successor_low16_by_delta(candidate_function)
    oracle_fallthrough_delta = _control_fallthrough_delta(oracle_function)
    candidate_fallthrough_delta = _control_fallthrough_delta(candidate_function)
    pairs: list[dict[str, Any]] = []
    for delta in sorted(set(oracle_successors) & set(candidate_successors)):
        if (
            oracle_fallthrough_delta is not None
            and candidate_fallthrough_delta is not None
            and delta == oracle_fallthrough_delta
            and delta == candidate_fallthrough_delta
        ):
            continue
        oracle_value = oracle_successors[delta]
        candidate_value = candidate_successors[delta]
        if oracle_value == candidate_value:
            continue
        pairs.append({"oracle": oracle_value, "candidate": candidate_value, "reason": "control_target"})
    oracle_fallthrough = _control_fallthrough_low16(oracle_function)
    candidate_fallthrough = _control_fallthrough_low16(candidate_function)
    if (
        oracle_fallthrough is not None
        and candidate_fallthrough is not None
        and oracle_fallthrough != candidate_fallthrough
    ):
        pairs.append(
            {
                "oracle": oracle_fallthrough,
                "candidate": candidate_fallthrough,
                "reason": "control_fallthrough",
            }
        )
    return pairs


def _control_fallthrough_low16(function: dict[str, Any]) -> int | None:
    fallthrough = _control_fallthrough_linear(function)
    return None if fallthrough is None else fallthrough & 0xFFFF


def _control_fallthrough_delta(function: dict[str, Any]) -> int | None:
    fallthrough = _control_fallthrough_linear(function)
    if fallthrough is None:
        return None
    function_entry = function.get("function_entry", {}) if isinstance(function.get("function_entry"), dict) else {}
    function_linear = _optional_int(function_entry.get("linear"))
    if function_linear is None:
        return None
    return (fallthrough - function_linear) & 0xFFFF


def _control_fallthrough_linear(function: dict[str, Any]) -> int | None:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else {}
    if transfer.get("summary") == "repeat_string":
        successors = transfer.get("successors") if isinstance(transfer.get("successors"), list) else []
        linears = [
            _optional_int(successor.get("linear"))
            for successor in successors
            if isinstance(successor, dict) and _optional_int(successor.get("linear")) is not None
        ]
        if len(linears) == 1:
            return linears[0]
    instructions = _ssa_instructions(function)
    if not instructions:
        return None
    last = instructions[-1]
    mnemonic = str(last.get("mnemonic", "")).lower()
    if mnemonic not in CONDITIONAL_JUMP_MNEMONICS:
        return None
    address = last.get("address") if isinstance(last.get("address"), dict) else {}
    linear = _optional_int(address.get("linear"))
    size = _optional_int(last.get("size"))
    if linear is None or size is None:
        return None
    return linear + size


def _successor_low16_by_delta(function: dict[str, Any]) -> dict[int, int]:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else {}
    function_entry = function.get("function_entry", {}) if isinstance(function.get("function_entry"), dict) else {}
    function_linear = _optional_int(function_entry.get("linear"))
    if function_linear is None:
        return {}
    result: dict[int, int] = {}
    if transfer.get("kind") == "direct_call":
        fallthrough = transfer.get("fallthrough") if isinstance(transfer.get("fallthrough"), dict) else {}
        linear = _optional_int(fallthrough.get("linear"))
        if linear is None:
            return {}
        result[(linear - function_linear) & 0xFFFF] = linear & 0xFFFF
        return result
    if transfer.get("kind") == "direct_successors":
        for successor in transfer.get("successors", []) or []:
            if not isinstance(successor, dict):
                continue
            linear = _optional_int(successor.get("linear"))
            if linear is None:
                continue
            result[(linear - function_linear) & 0xFFFF] = linear & 0xFFFF
    return result


def _ssa_instructions(function: dict[str, Any]) -> list[dict[str, Any]]:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    return [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]


def _stack_op_sequence(function: dict[str, Any]) -> list[str]:
    """Ordered stack-structure mnemonics; differing sequences mean different slice coverage."""
    stack_mnemonics = {"push", "pop", "enter", "leave"}
    return [
        mnemonic
        for mnemonic in (str(item.get("mnemonic", "")).lower() for item in _ssa_instructions(function))
        if mnemonic in stack_mnemonics
    ]


def _instruction_layout_constant_pairs(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    *,
    has_ivt_segment_store: bool,
    data_segment_immediate: bool,
    pointer_arithmetic_regs: set[str],
    far_pointer_offset: bool = False,
    far_pointer_segment: bool = False,
) -> list[dict[str, Any]]:
    if str(oracle.get("mnemonic", "")).lower() != str(candidate.get("mnemonic", "")).lower():
        return []
    oracle_op = str(oracle.get("op_str", "")).lower()
    candidate_op = str(candidate.get("op_str", "")).lower()
    if _number_template(oracle_op) != _number_template(candidate_op):
        return []
    oracle_numbers = _number_tokens(oracle_op)
    candidate_numbers = _number_tokens(candidate_op)
    if len(oracle_numbers) != len(candidate_numbers):
        return []
    pairs: list[dict[str, Any]] = []
    for index, (oracle_number, candidate_number) in enumerate(zip(oracle_numbers, candidate_numbers, strict=False)):
        oracle_value = oracle_number & 0xFFFF
        candidate_value = candidate_number & 0xFFFF
        if oracle_value == candidate_value:
            continue
        reason = _layout_pair_reason(
            oracle_op,
            candidate_op,
            mnemonic=str(oracle.get("mnemonic", "")).lower(),
            index=index,
            has_ivt_segment_store=has_ivt_segment_store,
            data_segment_immediate=data_segment_immediate,
            pointer_arithmetic_regs=pointer_arithmetic_regs,
            far_pointer_offset=far_pointer_offset,
            far_pointer_segment=far_pointer_segment,
        )
        if reason not in {
            "absolute_memory_operand",
            "data_segment_immediate",
            "control_target",
            "far_pointer_offset",
            "far_pointer_segment",
        } and not _looks_layout_constant(oracle_value, candidate_value):
            continue
        if reason is None:
            pairs.append(
                {
                    "oracle": oracle_value,
                    "candidate": candidate_value,
                    "oracle_raw": oracle_number,
                    "candidate_raw": candidate_number,
                    "reason": "deferred",
                }
            )
        else:
            pairs.append(
                {
                    "oracle": oracle_value,
                    "candidate": candidate_value,
                    "oracle_raw": oracle_number,
                    "candidate_raw": candidate_number,
                    "reason": reason,
                }
            )
    return pairs


NUMBER_RE = re.compile(r"(?P<sign>[+-])?\s*(?P<body>0x[0-9a-f]+|\d+)", re.IGNORECASE)


def _number_tokens(text: str) -> list[int]:
    values: list[int] = []
    for match in NUMBER_RE.finditer(text):
        body = match.group("body")
        value = int(body, 0)
        if match.group("sign") == "-":
            value = -value
        values.append(value)
    return values


def _number_template(text: str) -> str:
    template = NUMBER_RE.sub("#", text.lower())
    template = re.sub(r"([+-])\s*#", "#", template)
    template = re.sub(r"\s+", " ", template)
    return template.strip()


def _looks_layout_constant(oracle_value: int, candidate_value: int) -> bool:
    return oracle_value >= 0x1000 and candidate_value >= 0x1000


def _layout_pair_reason(
    oracle_op: str,
    candidate_op: str,
    *,
    mnemonic: str,
    index: int,
    has_ivt_segment_store: bool,
    data_segment_immediate: bool,
    pointer_arithmetic_regs: set[str],
    far_pointer_offset: bool = False,
    far_pointer_segment: bool = False,
) -> str | None:
    memory_reason = _layout_memory_pair_reason(oracle_op, candidate_op, index=index)
    if memory_reason is not None:
        return memory_reason
    return _layout_mnemonic_pair_reason(
        oracle_op,
        candidate_op,
        mnemonic=mnemonic,
        has_ivt_segment_store=has_ivt_segment_store,
        data_segment_immediate=data_segment_immediate,
        pointer_arithmetic_regs=pointer_arithmetic_regs,
        far_pointer_offset=far_pointer_offset,
        far_pointer_segment=far_pointer_segment,
    )


def _layout_memory_pair_reason(oracle_op: str, candidate_op: str, *, index: int) -> str | None:
    """Classify operand pairs whose differing number sits inside a memory operand."""
    if not (
        _number_is_inside_memory_operand(oracle_op, index)
        and _number_is_inside_memory_operand(candidate_op, index)
    ):
        return None
    if _memory_operand_has_register(oracle_op) or _memory_operand_has_register(candidate_op):
        return "memory_operand"
    if _memory_operand_has_explicit_segment(oracle_op, "cs") and _memory_operand_has_explicit_segment(
        candidate_op, "cs"
    ):
        return "code_segment_memory_operand"
    return "absolute_memory_operand"


def _layout_mnemonic_pair_reason(
    oracle_op: str,
    candidate_op: str,
    *,
    mnemonic: str,
    has_ivt_segment_store: bool,
    data_segment_immediate: bool,
    pointer_arithmetic_regs: set[str],
    far_pointer_offset: bool = False,
    far_pointer_segment: bool = False,
) -> str | None:
    """Classify operand pairs by mnemonic-specific tolerable reasons."""
    oracle_first = oracle_op.split(",", 1)[0].strip()
    candidate_first = candidate_op.split(",", 1)[0].strip()
    if mnemonic == "mov" and far_pointer_offset:
        return "far_pointer_offset"
    if mnemonic == "mov" and far_pointer_segment:
        return "far_pointer_segment"
    if (
        mnemonic == "mov"
        and data_segment_immediate
        and oracle_first == candidate_first
        and oracle_first in {"ax", "bx", "cx", "dx"}
    ):
        return "data_segment_immediate"
    if mnemonic in {"add", "sub"} and oracle_first == candidate_first and oracle_first in pointer_arithmetic_regs:
        return "pointer_arithmetic"
    if mnemonic == "cmp" and oracle_first == candidate_first and oracle_first in {"si", "di", "bx", "bp"}:
        return "pointer_bound"
    if mnemonic in {"mov", "lea"} and oracle_first == candidate_first and oracle_first in {"si", "di", "bx", "bp"}:
        return "pointer_immediate"
    if mnemonic == "mov" and has_ivt_segment_store and oracle_first == candidate_first and oracle_first == "ax":
        return "ivt_segment"
    if _is_ivt_segment_store_operand(oracle_op) and _is_ivt_segment_store_operand(candidate_op):
        return "ivt_segment"
    if mnemonic in (CONTROL_MNEMONICS - {"call", "lcall", "int"}):
        return "control_target"
    return None


def _number_is_inside_memory_operand(text: str, index: int) -> bool:
    match = list(NUMBER_RE.finditer(text))[index]
    before = text[: match.start()]
    after = text[match.end() :]
    return before.rfind("[") > before.rfind("]") and after.find("]") != -1


def _is_ivt_segment_store(instruction: dict[str, Any]) -> bool:
    return _is_ivt_segment_store_operand(str(instruction.get("op_str", "")).lower())


def _is_ivt_segment_store_operand(op_str: str) -> bool:
    compact = op_str.replace(" ", "")
    return compact.startswith("wordptr") and "es:[2]" in compact


def _data_segment_immediate_indexes(
    oracle_instructions: list[dict[str, Any]],
    candidate_instructions: list[dict[str, Any]],
) -> set[int]:
    indexes: set[int] = set()
    for index in range(min(len(oracle_instructions), len(candidate_instructions)) - 1):
        oracle = oracle_instructions[index]
        candidate = candidate_instructions[index]
        if str(oracle.get("mnemonic", "")).lower() != "mov" or str(candidate.get("mnemonic", "")).lower() != "mov":
            continue
        oracle_operands = _split_operands(str(oracle.get("op_str", "")).lower())
        candidate_operands = _split_operands(str(candidate.get("op_str", "")).lower())
        if len(oracle_operands) != 2 or oracle_operands[0] != candidate_operands[0]:
            continue
        if oracle_operands[0] not in {"ax", "bx", "cx", "dx"}:
            continue
        if not _number_tokens(oracle_operands[1]) or not _number_tokens(candidate_operands[1]):
            continue
        if any(
            _is_mov_segment_from_register(oracle_instructions[index + 1], segment, oracle_operands[0])
            and _is_mov_segment_from_register(candidate_instructions[index + 1], segment, candidate_operands[0])
            for segment in ("ds", "es")
        ):
            indexes.add(index)
    return indexes


def _is_mov_segment_from_register(instruction: dict[str, Any], segment: str, reg: str) -> bool:
    if str(instruction.get("mnemonic", "")).lower() != "mov":
        return False
    operands = _split_operands(str(instruction.get("op_str", "")).lower())
    return len(operands) == 2 and operands[0] == segment and operands[1] == reg


def _mem_base_offset(op_str: str) -> tuple[str, int] | None:
    """Return (base_text, displacement) of the first memory operand in an operand string."""
    match = re.search(r"\[([^\]]+)\]", op_str)
    if match is None:
        return None
    inside = match.group(1).strip()
    disp_match = re.match(r"^(?P<base>.*?)\s*(?P<sign>[+-])\s*(?P<num>0x[0-9a-f]+|\d+)\s*$", inside)
    if disp_match is not None:
        base = re.sub(r"\s+", "", disp_match.group("base"))
        offset = int(disp_match.group("num"), 0)
        if disp_match.group("sign") == "-":
            offset = -offset
        return base, offset
    if re.fullmatch(r"0x[0-9a-f]+|\d+", inside):
        return "", int(inside, 0)
    if NUMBER_RE.search(inside):
        return None
    return re.sub(r"\s+", "", inside), 0


def _far_pointer_pair_indexes(
    oracle_instructions: list[dict[str, Any]],
    candidate_instructions: list[dict[str, Any]],
) -> tuple[set[int], set[int]]:
    """Instruction indexes where instr i/i+1 store the offset/segment halves of a far pointer."""
    offset_indexes: set[int] = set()
    segment_indexes: set[int] = set()
    limit = min(len(oracle_instructions), len(candidate_instructions)) - 1
    for index in range(limit):
        group = [
            oracle_instructions[index],
            candidate_instructions[index],
            oracle_instructions[index + 1],
            candidate_instructions[index + 1],
        ]
        if any(str(item.get("mnemonic", "")).lower() != "mov" for item in group):
            continue
        first = [_mem_base_offset(str(item.get("op_str", "")).lower()) for item in group[:2]]
        second = [_mem_base_offset(str(item.get("op_str", "")).lower()) for item in group[2:]]
        if any(item is None for item in first + second):
            continue
        base_o, off_o = first[0]  # type: ignore[misc]
        base_c, off_c = first[1]  # type: ignore[misc]
        base_o2, off_o2 = second[0]  # type: ignore[misc]
        base_c2, off_c2 = second[1]  # type: ignore[misc]
        if not base_o or base_o != base_c or base_o != base_o2 or base_o != base_c2:
            continue
        if off_o2 - off_o != 2 or off_c2 - off_c != 2:
            continue
        seg_o = _number_tokens(str(group[2].get("op_str", "")).lower())
        seg_c = _number_tokens(str(group[3].get("op_str", "")).lower())
        if not seg_o or not seg_c:
            continue
        seg_o_value = seg_o[-1] & 0xFFFF
        seg_c_value = seg_c[-1] & 0xFFFF
        if seg_o_value == seg_c_value or seg_o_value < 0x100 or seg_c_value < 0x100:
            continue
        offset_indexes.add(index)
        segment_indexes.add(index + 1)
    return offset_indexes, segment_indexes


def _memory_operand_has_register(op_str: str) -> bool:
    for reg in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
        if _register_used_inside_memory_operand(op_str, reg):
            return True
    return False


def _memory_operand_has_explicit_segment(op_str: str, segment: str) -> bool:
    compact = re.sub(r"\s+", "", op_str.lower())
    return f"{segment.lower()}:[" in compact


def _pointer_arithmetic_evidence_by_index(
    oracle_instructions: list[dict[str, Any]],
    candidate_instructions: list[dict[str, Any]],
) -> dict[int, set[str]]:
    evidence: dict[int, set[str]] = {}
    for index, (oracle, candidate) in enumerate(zip(oracle_instructions, candidate_instructions, strict=False)):
        oracle_reg = _pointer_arithmetic_destination_register(oracle)
        candidate_reg = _pointer_arithmetic_destination_register(candidate)
        if oracle_reg is None or oracle_reg != candidate_reg:
            continue
        if _register_used_as_memory_base_later(
            oracle_instructions, index + 1, oracle_reg
        ) and _register_used_as_memory_base_later(
            candidate_instructions,
            index + 1,
            candidate_reg,
        ):
            evidence.setdefault(index, set()).add(oracle_reg)
    return evidence


def _pointer_arithmetic_destination_register(instruction: dict[str, Any]) -> str | None:
    mnemonic = str(instruction.get("mnemonic", "")).lower()
    if mnemonic not in {"add", "sub"}:
        return None
    operands = _split_operands(str(instruction.get("op_str", "")).lower())
    if len(operands) != 2:
        return None
    destination = operands[0].strip()
    source = operands[1].strip()
    if destination not in {"bx", "bp", "si", "di"}:
        return None
    if "[" in source or "]" in source or not _number_tokens(source):
        return None
    return destination


def _register_used_as_memory_base_later(instructions: list[dict[str, Any]], start_index: int, reg: str) -> bool:
    for instruction in instructions[start_index:]:
        op_str = str(instruction.get("op_str", "")).lower()
        if _register_used_inside_memory_operand(op_str, reg):
            return True
        if _instruction_overwrites_register(instruction, reg):
            return False
    return False


def _register_used_inside_memory_operand(op_str: str, reg: str) -> bool:
    pattern = re.compile(rf"\[[^\]]*\b{re.escape(reg)}\b[^\]]*\]")
    return pattern.search(op_str) is not None


def _instruction_overwrites_register(instruction: dict[str, Any], reg: str) -> bool:
    mnemonic = str(instruction.get("mnemonic", "")).lower()
    operands = _split_operands(str(instruction.get("op_str", "")).lower())
    if not operands:
        return False
    destination = operands[0].strip()
    if destination != reg:
        return False
    return mnemonic not in {"cmp", "test", "push"}


def _split_operands(op_str: str) -> list[str]:
    operands: list[str] = []
    current: list[str] = []
    bracket_depth = 0
    for char in op_str:
        if char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth > 0:
            bracket_depth -= 1
        if char == "," and bracket_depth == 0:
            operands.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current or op_str:
        operands.append("".join(current).strip())
    return operands


def _unique_layout_pairs(pairs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[int, int]] = set()
    unique: list[dict[str, Any]] = []
    for pair in pairs:
        key = (int(pair["oracle"]), int(pair["candidate"]))
        if key in seen:
            continue
        seen.add(key)
        unique.append(pair)
    return unique


def _layout_constant_normalization_entries(pair: dict[str, Any]) -> list[tuple[int, int]]:
    oracle_raw = int(pair.get("oracle_raw", pair["oracle"]))
    candidate_raw = int(pair.get("candidate_raw", pair["candidate"]))
    oracle_low = oracle_raw & 0xFFFF
    candidate_low = candidate_raw & 0xFFFF
    entries = [(candidate_low, oracle_low)]
    if candidate_raw < 0 or candidate_low >= 0x8000:
        signed_candidate = candidate_raw & 0xFFFFFFFF if candidate_raw < 0 else (candidate_low | 0xFFFF0000)
        signed_oracle = (oracle_raw & 0xFFFFFFFF) if oracle_raw < 0 else oracle_low
        entries.append((signed_candidate, signed_oracle))
    return _unique_int_pairs(entries)


def _unique_int_pairs(values: list[tuple[int, int]]) -> list[tuple[int, int]]:
    seen: set[tuple[int, int]] = set()
    unique: list[tuple[int, int]] = []
    for left, right in values:
        pair = (int(left), int(right))
        if pair in seen:
            continue
        seen.add(pair)
        unique.append(pair)
    return unique


def _with_call_target_output(function: dict[str, Any], target_value: int) -> dict[str, Any]:
    document = copy.deepcopy(function)
    outputs = dict(document.get("outputs", {}) if isinstance(document.get("outputs"), dict) else {})
    outputs["call_target"] = {"op": "const", "value": normalize_hex(target_value & 0xFFFFFFFF, width=8), "width": 32}
    document["outputs"] = outputs
    return document


def _canonical_call_target_value(call_compare: dict[str, Any]) -> int:
    return _semantic_token_value(_canonical_call_target_token(call_compare))


def _canonical_call_target_token(call_compare: dict[str, Any]) -> str:
    proof_fact = call_compare.get("proof_fact") if isinstance(call_compare.get("proof_fact"), dict) else None
    if proof_fact is not None:
        proof_id = str(proof_fact.get("id") or "")
        oracle = proof_fact.get("oracle") if isinstance(proof_fact.get("oracle"), dict) else {}
        candidate = proof_fact.get("candidate") if isinstance(proof_fact.get("candidate"), dict) else {}
        oracle_key = str(oracle.get("semantic_ssa_id") or oracle.get("id") or oracle.get("name") or "unknown-oracle")
        candidate_key = str(
            candidate.get("semantic_ssa_id") or candidate.get("id") or candidate.get("name") or "unknown-candidate"
        )
        if proof_id:
            return f"callee-proof:{proof_id}"
        return f"callee-proof:{proof_fact.get('proof')}:{oracle_key}:{candidate_key}"
    oracle = call_compare.get("oracle") if isinstance(call_compare.get("oracle"), dict) else {}
    resolved = oracle.get("resolved") if isinstance(oracle.get("resolved"), dict) else {}
    key = str(resolved.get("id") or resolved.get("name") or oracle.get("raw") or "unknown-call-target")
    return f"call-target:{key}"


def _semantic_token_value(token: str) -> int:
    return int(hashlib.sha256(token.encode("utf-8")).hexdigest()[:8], 16)


def _final_store_lookup(
    function: dict[str, Any],
) -> tuple[list[dict[str, Any]], int, dict[str, Any], list[Any], str, dict[str, Any] | None]:
    """Locate the final memory store referenced by the memory output ref."""
    outputs = function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}
    memory = outputs.get("memory") if isinstance(outputs.get("memory"), dict) else None
    ref = memory.get("ref") if isinstance(memory, dict) else None
    if not isinstance(ref, str):
        return [], 0, {}, [], "", {"applied": False, "reason": "no memory output store to normalize"}
    assignments = list(function.get("assignments", []) or [])
    index = next(
        (idx for idx, item in enumerate(assignments) if isinstance(item, dict) and item.get("id") == ref), None
    )
    if index is None:
        return [], 0, {}, [], "", {"applied": False, "reason": "memory output assignment was not found"}
    store = assignments[index]
    if store.get("op") not in {"storele", "storebe"}:
        return [], 0, {}, [], "", {"applied": False, "reason": "memory output is not a final store"}
    args = list(store.get("args", []) or [])
    if len(args) < 3:
        return [], 0, {}, [], "", {"applied": False, "reason": "final store has no stored value operand"}
    return assignments, index, store, args, ref, None


def _call_store_chain_attempt(
    function: dict[str, Any],
    *,
    assignments: list[dict[str, Any]],
    memory_ref: str,
    fallthrough: int,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Try the multi-store return-address chain; (None, result) when not applied."""
    normalized, result = _normalize_call_return_store_chain(
        function, assignments=assignments, memory_ref=memory_ref, fallthrough=fallthrough
    )
    if result.get("applied"):
        return normalized, result
    return None, result


def _normalize_call_return_store(function: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    assignments, index, store, args, ref, failure = _final_store_lookup(function)
    if failure is not None:
        return function, failure
    value = _term_const_int(args[2])
    fallthrough = _call_fallthrough_linear(function)
    if value is None or fallthrough is None:
        if fallthrough is not None:
            chain_fn, _chain_result = _call_store_chain_attempt(
                function, assignments=assignments, memory_ref=ref, fallthrough=fallthrough
            )
            if chain_fn is not None:
                return chain_fn, _chain_result
        return function, {"applied": False, "reason": "final store value or call fall-through was not constant"}
    width = int(args[2].get("width", 16)) if isinstance(args[2], dict) else 16
    if width <= 8:
        chain_fn, chain_result = _call_store_chain_attempt(
            function, assignments=assignments, memory_ref=ref, fallthrough=fallthrough
        )
        if chain_fn is not None:
            return chain_fn, chain_result
        return function, {
            "applied": False,
            "reason": "single-byte final store did not match a far-call return byte chain",
            "stored": normalize_hex(value, width=2),
            "fallthrough": normalize_hex(fallthrough),
            "chain_reason": chain_result.get("reason"),
        }
    mask = _mask(width)
    if (value & mask) != (fallthrough & mask):
        chain_fn, chain_result = _call_store_chain_attempt(
            function, assignments=assignments, memory_ref=ref, fallthrough=fallthrough
        )
        if chain_fn is not None:
            return chain_fn, chain_result
        return function, {
            "applied": False,
            "reason": "final store constant did not match the call fall-through address",
            "stored": normalize_hex(value),
            "fallthrough": normalize_hex(fallthrough),
            "chain_reason": chain_result.get("reason"),
        }
    normalized_store = dict(store)
    args[2] = {"op": "const", "value": normalize_hex(0, width=max(1, width // 4)), "width": width}
    normalized_store["args"] = args
    assignments[index] = normalized_store
    function = dict(function)
    function["assignments"] = assignments
    return function, {
        "applied": True,
        "reason": "normalized layout-dependent call return address store",
        "stored": normalize_hex(value),
        "fallthrough": normalize_hex(fallthrough),
    }


def _normalize_call_return_store_chain(
    function: dict[str, Any],
    *,
    assignments: list[dict[str, Any]],
    memory_ref: str,
    fallthrough: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    by_id = {str(item["id"]): item for item in assignments if isinstance(item, dict) and "id" in item}
    current_ref: str | None = memory_ref
    normalized_assignments = list(assignments)
    normalized_indexes: list[int] = []
    normalized_values: list[str] = []
    expected_words = {fallthrough & 0xFFFF}
    call_return_ip = _call_return_ip_from_instruction(function)
    if call_return_ip is not None:
        expected_words.add(call_return_ip & 0xFFFF)
    ip_bytes = {(word >> shift) & 0xFF for word in expected_words for shift in (0, 8)}
    cs_para = _own_code_segment_para(function)
    cs_bytes = (
        {(cs_para >> shift) & 0xFF for shift in (0, 8)} if cs_para is not None else set()
    )
    far_call = _call_instruction_is_far(function)
    max_bytes = 4 if far_call else 2
    while current_ref:
        index = next(
            (
                idx
                for idx, item in enumerate(normalized_assignments)
                if isinstance(item, dict) and item.get("id") == current_ref
            ),
            None,
        )
        if index is None:
            break
        store = normalized_assignments[index]
        if store.get("op") not in {"storele", "storebe"}:
            break
        args = list(store.get("args", []) or [])
        if len(args) < 3:
            break
        stored_value = (
            _call_return_store_byte_value(args[2], assignments=by_id, function=function)
            if isinstance(args[2], dict)
            else None
        )
        position = len(normalized_indexes)
        allowed = ip_bytes if position < 2 else cs_bytes
        if (
            position >= max_bytes
            or stored_value is None
            or stored_value < 0
            or stored_value > 0xFF
            or (stored_value & 0xFF) not in allowed
        ):
            if normalized_indexes:
                break
            return function, {
                "applied": False,
                "reason": "final store chain does not start with call return-address bytes",
            }
        normalized_store = dict(store)
        args[2] = {"op": "const", "value": "0x00", "width": 8}
        normalized_store["args"] = args
        normalized_assignments[index] = normalized_store
        normalized_indexes.append(index)
        normalized_values.append(normalize_hex(stored_value & 0xFF, width=2))
        previous = args[0]
        current_ref = previous.get("ref") if isinstance(previous, dict) else None
    if not normalized_indexes:
        return function, {"applied": False, "reason": "no call return-address byte stores found"}
    normalized = dict(function)
    normalized["assignments"] = normalized_assignments
    return normalized, {
        "applied": True,
        "reason": "normalized layout-dependent far-call return address byte stores",
        "stored_bytes": normalized_values,
        "fallthrough": normalize_hex(fallthrough),
        "return_ip": None if call_return_ip is None else normalize_hex(call_return_ip & 0xFFFF, width=4),
        "store_count": len(normalized_indexes),
    }


def _normalize_call_stack_store_addresses(function: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    outputs = function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}
    memory = outputs.get("memory") if isinstance(outputs.get("memory"), dict) else None
    ref = memory.get("ref") if isinstance(memory, dict) else None
    if not isinstance(ref, str):
        return function, {"applied": False, "reason": "no memory output store chain"}
    assignments = list(function.get("assignments", []) or [])
    by_id = {str(item["id"]): item for item in assignments if isinstance(item, dict) and "id" in item}
    current_ref: str | None = ref
    normalized = list(assignments)
    normalized_indexes: list[int] = []
    slot = 0
    while current_ref:
        index = next(
            (idx for idx, item in enumerate(normalized) if isinstance(item, dict) and item.get("id") == current_ref),
            None,
        )
        if index is None:
            break
        store = normalized[index]
        if store.get("op") not in {"storele", "storebe"}:
            break
        args = list(store.get("args", []) or [])
        if len(args) < 3:
            break
        if isinstance(args[1], dict) and _term_depends_on_input(args[1], "ss", by_id):
            rewritten = dict(store)
            args[1] = {"op": "const", "value": normalize_hex(0xF0000000 + slot, width=8), "width": 32}
            rewritten["args"] = args
            normalized[index] = rewritten
            normalized_indexes.append(index)
            slot += 1
        previous = args[0]
        current_ref = previous.get("ref") if isinstance(previous, dict) else None
    if not normalized_indexes:
        return function, {"applied": False, "reason": "no stack-segment store addresses found"}
    copied = dict(function)
    copied["assignments"] = normalized
    return copied, {
        "applied": True,
        "reason": "normalized call-boundary stack store addresses",
        "store_count": len(normalized_indexes),
    }


def _term_depends_on_input(
    term: dict[str, Any], name: str, assignments: dict[str, dict[str, Any]], seen: set[str] | None = None
) -> bool:
    if seen is None:
        seen = set()
    if term.get("op") == "input" and term.get("name") == name:
        return True
    ref = term.get("ref")
    if isinstance(ref, str):
        if ref in seen:
            return False
        seen.add(ref)
        assignment = assignments.get(ref)
        if isinstance(assignment, dict):
            return _term_depends_on_input(assignment, name, assignments, seen)
    for arg in term.get("args", []) or []:
        if isinstance(arg, dict) and _term_depends_on_input(arg, name, assignments, seen):
            return True
    return False


def _own_code_segment_para(function: dict[str, Any]) -> int | None:
    """The part's own code segment para — the value ``lcall`` pushes as CS."""
    entry = function.get("entry") if isinstance(function.get("entry"), dict) else {}
    return _optional_int(entry.get("cs"))


def _call_instruction_is_far(function: dict[str, Any]) -> bool:
    """Whether the part's final instruction is a far call (``lcall``/``call far``)."""
    instructions = _ssa_instructions(function)
    if not instructions:
        return False
    last = instructions[-1]
    mnemonic = str(last.get("mnemonic") or "").lower()
    text = str(last.get("disassembly") or "").lower()
    if mnemonic == "lcall" or text.startswith("lcall"):
        return True
    data = last.get("bytes") or ""
    return mnemonic == "call" and isinstance(data, str) and data[:2].lower() == "9a"


def _call_return_ip_from_instruction(function: dict[str, Any]) -> int | None:
    instructions = _ssa_instructions(function)
    if not instructions:
        return None
    instruction = instructions[-1]
    address = instruction.get("address") if isinstance(instruction.get("address"), dict) else {}
    ip = _optional_int(address.get("ip"))
    size = _optional_int(instruction.get("size"))
    if ip is None or size is None:
        return None
    return (ip + size) & 0xFFFF


def _call_return_store_byte_value(
    term: dict[str, Any],
    *,
    assignments: dict[str, dict[str, Any]],
    function: dict[str, Any],
) -> int | None:
    instructions = _ssa_instructions(function)
    last_instruction = instructions[-1] if instructions else {}
    last_address = last_instruction.get("address") if isinstance(last_instruction.get("address"), dict) else {}
    ip_value = _optional_int(last_address.get("ip"))
    entry = function.get("entry") if isinstance(function.get("entry"), dict) else {}
    cs_value = _optional_int(entry.get("cs"))
    constants = {"ip": ip_value, "cs": cs_value}
    return _eval_call_return_term(term, assignments=assignments, input_constants=constants)


def _eval_call_return_term(
    term: dict[str, Any] | None,
    *,
    assignments: dict[str, dict[str, Any]],
    input_constants: dict[str, int | None],
) -> int | None:
    if not isinstance(term, dict):
        return None
    width = max(1, _term_width(term))
    mask = _mask(width)
    if "ref" in term:
        return _eval_call_return_term(
            assignments.get(str(term.get("ref"))), assignments=assignments, input_constants=input_constants
        )
    op = str(term.get("op") or "")
    if op == "const":
        value = _optional_int(term.get("value"))
        return None if value is None else value & mask
    if op == "input":
        value = input_constants.get(str(term.get("name") or "").lower())
        return None if value is None else value & mask
    args = [arg for arg in term.get("args", []) or [] if isinstance(arg, dict)]
    values = [_eval_call_return_term(arg, assignments=assignments, input_constants=input_constants) for arg in args]
    if any(value is None for value in values):
        return None
    concrete = [int(value) for value in values if value is not None]
    return _eval_call_return_op(op, concrete, mask)


def _eval_call_return_op(op: str, concrete: list[int], mask: int) -> int | None:
    """Evaluate one concrete call-return op over its argument values."""
    if op in {"trunc", "zext"} and len(concrete) == 1:
        return concrete[0] & mask
    if len(concrete) != 2:
        return None
    if op == "lshr":
        return (concrete[0] >> concrete[1]) & mask
    if op == "add":
        return (concrete[0] + concrete[1]) & mask
    if op == "sub":
        return (concrete[0] - concrete[1]) & mask
    if op == "or":
        return (concrete[0] | concrete[1]) & mask
    if op == "and":
        return (concrete[0] & concrete[1]) & mask
    return None


def _call_fallthrough_linear(function: dict[str, Any]) -> int | None:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else None
    if transfer:
        fallthrough = transfer.get("fallthrough") if isinstance(transfer.get("fallthrough"), dict) else None
        value = _optional_int(fallthrough.get("linear")) if fallthrough is not None else None
        if value is not None:
            return value
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    if not instructions:
        return None
    instruction = instructions[-1]
    address = instruction.get("address", {}) if isinstance(instruction.get("address"), dict) else {}
    linear = _optional_int(address.get("linear"))
    size = _optional_int(instruction.get("size"))
    if linear is None or size is None:
        return None
    return linear + size


def _term_const_int(term: dict[str, Any] | None) -> int | None:
    if not isinstance(term, dict) or term.get("op") != "const":
        return None
    return _optional_int(term.get("value"))


def _const_json_term_value(term: dict[str, Any] | None) -> int | None:
    if not isinstance(term, dict):
        return None
    op = str(term.get("op") or "")
    width = max(1, _term_width(term))
    mask = _mask(width)
    if op == "const":
        value = _optional_int(term.get("value"))
        return None if value is None else value & mask
    if op in {"input", "mem_input", "loadle", "loadbe", "storele", "storebe"}:
        return None
    args = [arg for arg in term.get("args", []) or [] if isinstance(arg, dict)]
    values = [_const_json_term_value(arg) for arg in args]
    if any(value is None for value in values):
        return None
    concrete = [int(value) for value in values if value is not None]
    try:
        simple = _const_json_simple_op(op, concrete, mask)
        if simple is not None:
            return simple
        structural = _const_json_structural_op(op, args, concrete, width, mask)
        if structural is not None:
            return structural
        if op in {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"} and len(concrete) == 2:
            return _const_json_cmp_op(op, args, concrete)
    except (ArithmeticError, ValueError, OverflowError):
        return None
    return None


def _const_json_structural_op(
    op: str, args: list[dict[str, Any]], concrete: list[int], width: int, mask: int
) -> int | None:
    """Evaluate ashr/sext/concat/ite over concrete argument values."""
    if op == "ashr" and len(concrete) == 2:
        shift = concrete[1]
        sign_bit = 1 << (width - 1)
        signed = concrete[0] - (1 << width) if concrete[0] & sign_bit else concrete[0]
        return (signed >> shift) & mask
    if op == "sext" and len(concrete) == 1 and args:
        from_width = max(1, _term_width(args[0]))
        from_mask = _mask(from_width)
        raw = concrete[0] & from_mask
        sign_bit = 1 << (from_width - 1)
        signed = raw - (1 << from_width) if raw & sign_bit else raw
        return signed & mask
    if op == "concat" and concrete:
        value = 0
        for arg, arg_value in zip(args, concrete, strict=False):
            arg_width = max(1, _term_width(arg))
            value = (value << arg_width) | (arg_value & _mask(arg_width))
        return value & mask
    if op == "ite" and len(concrete) == 3:
        return concrete[1] & mask if concrete[0] != 0 else concrete[2] & mask
    return None


_CONST_JSON_BINOPS: dict[str, Callable[[int, int], int]] = {
    "add": lambda left, right: left + right,
    "sub": lambda left, right: left - right,
    "mul": lambda left, right: left * right,
    "and": lambda left, right: left & right,
    "or": lambda left, right: left | right,
    "xor": lambda left, right: left ^ right,
    "shl": lambda left, right: left << right,
    "lshr": lambda left, right: left >> right,
}


def _const_json_simple_op(op: str, concrete: list[int], mask: int) -> int | None:
    """Evaluate the purely masked binary/unary ops."""
    if op in {"not", "trunc", "zext"}:
        if len(concrete) != 1:
            return None
        return concrete[0] & mask if op != "not" else (~concrete[0]) & mask
    if len(concrete) != 2 or op not in _CONST_JSON_BINOPS:
        return None
    return _CONST_JSON_BINOPS[op](concrete[0], concrete[1]) & mask


def _const_json_cmp_op(op: str, args: list[dict[str, Any]], concrete: list[int]) -> int:
    """Evaluate the comparison ops (eq/ne/ult/...); returns 1 or 0."""
    left_width = max(1, _term_width(args[0]))
    right_width = max(1, _term_width(args[1]))
    cmp_width = max(left_width, right_width)
    cmp_mask = _mask(cmp_width)
    left = concrete[0] & cmp_mask
    right = concrete[1] & cmp_mask
    if op == "eq":
        result = left == right
    elif op == "ne":
        result = left != right
    elif op == "ult":
        result = left < right
    elif op == "ule":
        result = left <= right
    elif op == "ugt":
        result = left > right
    elif op == "uge":
        result = left >= right
    else:
        signed_left = _signed_value(left, cmp_width)
        signed_right = _signed_value(right, cmp_width)
        if op == "slt":
            result = signed_left < signed_right
        elif op == "sle":
            result = signed_left <= signed_right
        elif op == "sgt":
            result = signed_left > signed_right
        else:
            result = signed_left >= signed_right
    return 1 if result else 0


def _signed_value(value: int, width: int) -> int:
    sign_bit = 1 << (width - 1)
    value &= _mask(width)
    return value - (1 << width) if value & sign_bit else value


def _optional_int(value: Any) -> int | None:  # noqa: ANN401
    if value is None:
        return None
    try:
        return parse_int(value, field="value")
    except DosUnitError:
        return None
    except (TypeError, ValueError):
        return None


def _z3_inputs(oracle: dict[str, Any], candidate: dict[str, Any], z3: Any) -> dict[str, tuple[Any, int]]:  # noqa: ANN401
    widths: dict[str, int] = {}
    memory_inputs: set[str] = set()
    for document in (oracle, candidate):
        for item in document.get("inputs", []) or []:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            if item.get("kind") == "memory":
                memory_inputs.add(str(item["name"]))
            else:
                widths[str(item["name"])] = max(int(item.get("width", 16)), widths.get(str(item["name"]), 0))
    inputs = {name: (z3.BitVec(name, width), width) for name, width in sorted(widths.items())}
    for name in sorted(memory_inputs):
        inputs[name] = (z3.Array(name, z3.BitVecSort(32), z3.BitVecSort(8)), 0)
    return inputs


def _add_z3_input_constraints(
    solver: Any, inputs: dict[str, tuple[Any, int]], constraints: list[dict[str, Any]], z3: Any  # noqa: ANN401
) -> None:
    for item in constraints:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").lower()
        if name not in inputs:
            continue
        value, width = inputs[name]
        if width <= 0:
            continue
        kind = str(item.get("kind") or "unsigned_range").lower()
        if kind in {"unsigned_range", "range"}:
            minimum = _optional_int(item.get("min"))
            maximum = _optional_int(item.get("max"))
            if minimum is not None:
                solver.add(z3.UGE(value, z3.BitVecVal(minimum & ((1 << width) - 1), width)))
            if maximum is not None:
                solver.add(z3.ULE(value, z3.BitVecVal(maximum & ((1 << width) - 1), width)))
        elif kind == "eq":
            expected = _optional_int(item.get("value"))
            if expected is not None:
                solver.add(value == z3.BitVecVal(expected & ((1 << width) - 1), width))


def _z3_term(
    term: dict[str, Any],
    *,
    document: dict[str, Any],
    inputs: dict[str, tuple[Any, int]],
    z3: Any,  # noqa: ANN401
    assignments: dict[str, dict[str, Any]] | None = None,
    cache: dict[str, Any] | None = None,
    output_name: str | None = None,
) -> Any:  # noqa: ANN401
    if "ref" in term:
        if assignments is None:
            assignments = {
                item["id"]: item
                for item in document.get("assignments", []) or []
                if isinstance(item, dict) and "id" in item
            }
        if cache is None:
            cache = {}
        return _z3_assignment(
            str(term["ref"]),
            assignments=assignments,
            document=document,
            inputs=inputs,
            z3=z3,
            cache=cache,
            output_name=output_name,
        )
    op = term.get("op")
    width = int(term.get("width", 16))
    if op == "input":
        return _resize_z3(inputs[str(term["name"])][0], inputs[str(term["name"])][1], width, signed=False, z3=z3)
    if op == "mem_input":
        return inputs[str(term["name"])][0]
    if op == "const":
        value = parse_int(term.get("value"), field="ssa.const")
        value = _normalized_constant_value(value, width=width, document=document, output_name=output_name)
        return z3.BitVecVal(value, width)
    raise DosUnitError(f"unsupported SSA term: {term}")


def _z3_assignment(
    ident: str,
    *,
    assignments: dict[str, dict[str, Any]],
    document: dict[str, Any],
    inputs: dict[str, tuple[Any, int]],
    z3: Any,  # noqa: ANN401
    cache: dict[str, Any],
    output_name: str | None = None,
) -> Any:  # noqa: ANN401
    if ident in cache:
        return cache[ident]
    item = assignments[ident]
    op = str(item.get("op"))
    width = int(item.get("width", 16))
    args = [
        _z3_term(
            arg,
            document=document,
            inputs=inputs,
            z3=z3,
            assignments=assignments,
            cache=cache,
            output_name=output_name,
        )
        for arg in item.get("args", []) or []
    ]
    result = _z3_apply(op, width, args, z3)
    cache[ident] = result
    return result


_Z3_UNSIGNED_BINOPS: dict[str, Callable[[Any, Any, Any], Any]] = {
    "add": lambda left, right, _z3: left + right,
    "sub": lambda left, right, _z3: left - right,
    "mul": lambda left, right, _z3: left * right,
    "udiv": lambda left, right, z3: z3.UDiv(left, right),
    "urem": lambda left, right, z3: z3.URem(left, right),
    "and": lambda left, right, _z3: left & right,
    "or": lambda left, right, _z3: left | right,
    "xor": lambda left, right, _z3: left ^ right,
}
_Z3_SIGNED_BINOPS: dict[str, Callable[[Any, Any, Any], Any]] = {
    "sdiv": lambda left, right, _z3: left / right,
    "srem": lambda left, right, z3: z3.SRem(left, right),
}
_Z3_UNSIGNED_CMPS: dict[str, Callable[[Any, Any, Any], Any]] = {
    "eq": lambda left, right, _z3: left == right,
    "ne": lambda left, right, _z3: left != right,
    "ult": lambda left, right, z3: z3.ULT(left, right),
    "ule": lambda left, right, z3: z3.ULE(left, right),
    "ugt": lambda left, right, z3: z3.UGT(left, right),
    "uge": lambda left, right, z3: z3.UGE(left, right),
}
_Z3_SIGNED_CMPS: dict[str, Callable[[Any, Any, Any], Any]] = {
    "slt": lambda left, right, _z3: left < right,
    "sle": lambda left, right, _z3: left <= right,
    "sgt": lambda left, right, _z3: left > right,
    "sge": lambda left, right, _z3: left >= right,
}


def _z3_apply(op: str, width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    if op.startswith("summary_"):
        return _z3_uninterpreted_summary(op, width, args, z3)
    if op in _Z3_UNSIGNED_BINOPS:
        return _z3_aligned_binop(_Z3_UNSIGNED_BINOPS[op], width, args, signed=False, z3=z3)
    if op in _Z3_SIGNED_BINOPS:
        return _z3_aligned_binop(_Z3_SIGNED_BINOPS[op], width, args, signed=True, z3=z3)
    if op in {"umull", "smull"}:
        return _z3_mul_wide(args, width, signed=op == "smull", z3=z3)
    if op in _Z3_UNSIGNED_CMPS:
        return _z3_comparison(_Z3_UNSIGNED_CMPS[op], args, signed=False, z3=z3)
    if op in _Z3_SIGNED_CMPS:
        return _z3_comparison(_Z3_SIGNED_CMPS[op], args, signed=True, z3=z3)
    if op in {"loadle", "loadbe", "storele", "storebe"}:
        return _z3_memory_op(op, width, args, z3)
    return _z3_leaf_op(op, width, args, z3)


def _z3_aligned_binop(
    apply: Callable[[Any, Any, Any], Any], width: int, args: list[Any], *, signed: bool, z3: Any  # noqa: ANN401
) -> Any:  # noqa: ANN401
    """Apply a z3 binary op over width-aligned operands and resize to `width`."""
    left, right, op_width = _align_z3_pair(args[0], args[1], width, signed=signed, z3=z3)
    return _resize_z3(apply(left, right, z3), op_width, width, signed=signed, z3=z3)


def _z3_mul_wide(args: list[Any], width: int, *, signed: bool, z3: Any) -> Any:  # noqa: ANN401
    """Apply umull/smull by widening each operand to `width` first."""
    return _resize_z3(args[0], args[0].size(), width, signed=signed, z3=z3) * _resize_z3(
        args[1], args[1].size(), width, signed=signed, z3=z3
    )


def _z3_comparison(
    predicate: Callable[[Any, Any, Any], Any], args: list[Any], *, signed: bool, z3: Any  # noqa: ANN401
) -> Any:  # noqa: ANN401
    """Apply a z3 comparison predicate and produce a 1-bit result."""
    left, right, _op_width = _align_z3_pair(
        args[0], args[1], max(args[0].size(), args[1].size()), signed=signed, z3=z3
    )
    return z3.If(predicate(left, right, z3), z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))


def _z3_memory_op(op: str, width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Apply a z3 load/store op."""
    if op == "loadle":
        return _z3_load(args[0], args[1], width=width, little_endian=True, z3=z3)
    if op == "loadbe":
        return _z3_load(args[0], args[1], width=width, little_endian=False, z3=z3)
    if op == "storele":
        return _z3_store(args[0], args[1], args[2], little_endian=True, z3=z3)
    return _z3_store(args[0], args[1], args[2], little_endian=False, z3=z3)


def _z3_leaf_op(op: str, width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Apply the remaining z3 leaf ops (not/concat/shift/extend/ite)."""
    if op == "not":
        return ~args[0]
    if op == "concat":
        return z3.Concat(*args)
    if op == "shl":
        return _resize_z3(
            args[0] << _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3),
            args[0].size(),
            width,
            signed=False,
            z3=z3,
        )
    if op == "lshr":
        return z3.LShR(args[0], _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3))
    if op == "ashr":
        return args[0] >> _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3)
    if op == "zext":
        return _resize_z3(args[0], args[0].size(), width, signed=False, z3=z3)
    if op == "sext":
        return _resize_z3(args[0], args[0].size(), width, signed=True, z3=z3)
    if op == "trunc":
        return _resize_z3(args[0], args[0].size(), width, signed=False, z3=z3)
    if op == "ite":
        return z3.If(args[0] != z3.BitVecVal(0, args[0].size()), args[1], args[2])
    raise DosUnitError(f"unsupported SSA op: {op}")


def _z3_uninterpreted_summary(op: str, width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    domain = [arg.sort() for arg in args]
    range_sort = z3.ArraySort(z3.BitVecSort(32), z3.BitVecSort(8)) if width == 0 else z3.BitVecSort(width)
    name = re.sub(r"[^A-Za-z0-9_]", "_", op)
    fn = z3.Function(name, *domain, range_sort)
    return fn(*args)


def _align_z3_pair(left: Any, right: Any, width: int, *, signed: bool, z3: Any) -> tuple[Any, Any, int]:  # noqa: ANN401
    target_width = max(1, int(width), int(left.size()), int(right.size()))
    return (
        _resize_z3(left, left.size(), target_width, signed=signed, z3=z3),
        _resize_z3(right, right.size(), target_width, signed=signed, z3=z3),
        target_width,
    )


def _z3_load(memory: Any, address: Any, *, width: int, little_endian: bool, z3: Any) -> Any:  # noqa: ANN401
    if width % 8 != 0:
        raise DosUnitError(f"memory load width must be byte-addressable: {width}")
    address = _resize_z3(address, address.size(), 32, signed=False, z3=z3)
    bytes_ = [z3.Select(memory, address + z3.BitVecVal(index, 32)) for index in range(width // 8)]
    ordered = list(reversed(bytes_)) if little_endian else bytes_
    if len(ordered) == 1:
        return ordered[0]
    return z3.Concat(*ordered)


def _z3_store(memory: Any, address: Any, value: Any, *, little_endian: bool, z3: Any) -> Any:  # noqa: ANN401
    width = int(value.size())
    if width % 8 != 0:
        raise DosUnitError(f"memory store width must be byte-addressable: {width}")
    address = _resize_z3(address, address.size(), 32, signed=False, z3=z3)
    stored = memory
    byte_count = width // 8
    for index in range(byte_count):
        source_index = index if little_endian else byte_count - index - 1
        byte = z3.Extract(source_index * 8 + 7, source_index * 8, value)
        stored = z3.Store(stored, address + z3.BitVecVal(index, 32), byte)
    return stored


def _resize_z3(value: Any, from_width: int, to_width: int, *, signed: bool, z3: Any) -> Any:  # noqa: ANN401
    if from_width == to_width:
        return value
    if from_width > to_width:
        return z3.Extract(to_width - 1, 0, value)
    extend = z3.SignExt if signed else z3.ZeroExt
    return extend(to_width - from_width, value)


def _align_z3_widths(left: Any, right: Any, z3: Any) -> tuple[Any, Any]:  # noqa: ANN401
    left_width = int(left.size())
    right_width = int(right.size())
    width = max(left_width, right_width)
    return _resize_z3(left, left_width, width, signed=False, z3=z3), _resize_z3(
        right, right_width, width, signed=False, z3=z3
    )


def _normalized_constant_value(
    value: int, *, width: int, document: dict[str, Any], output_name: str | None = None
) -> int:
    normalization = document.get("_constant_normalization")
    if not isinstance(normalization, dict):
        return value
    reasons = document.get("_constant_normalization_reasons")
    if not isinstance(reasons, dict):
        reasons = {}
    return_address_keys = document.get("_call_return_address_keys")
    if not isinstance(return_address_keys, set):
        return_address_keys = set()
    mask = _mask(width)
    key = value & mask
    if key not in normalization:
        if width > 16:
            low_key = key & 0xFFFF
            if low_key in normalization:
                if (
                    reasons.get(low_key) in {"control_target", "control_fallthrough"}
                    and low_key not in return_address_keys
                    and output_name != "ip"
                ):
                    return value
                return ((key & ~0xFFFF) | (int(normalization[low_key]) & 0xFFFF)) & mask
        return value
    if (
        reasons.get(key) in {"control_target", "control_fallthrough"}
        and key not in return_address_keys
        and output_name != "ip"
    ):
        return value
    return int(normalization[key]) & mask


def _coerce_width(expr: SsaExpr, width: int) -> SsaExpr:
    if expr.width == width:
        return expr
    if expr.width < width:
        return SsaExpr("zext", width, (expr,))
    return SsaExpr("trunc", width, (expr,))


def _expr_failure(expr: SsaExpr, seen: set[int] | None = None) -> LowerFailure | None:
    if seen is None:
        seen = set()
    ident = id(expr)
    if ident in seen:
        return None
    seen.add(ident)
    if expr.op == "unsupported":
        if expr.name and "|" in expr.name:
            reason, message = expr.name.split("|", 1)
            return LowerFailure(reason, message)
        return LowerFailure("unsupported_ir", expr.name or "unsupported expression reached output slice")
    for arg in expr.args:
        failure = _expr_failure(arg, seen)
        if failure is not None:
            return failure
    return None


def _collect_inputs(expressions: Any, seen: set[int] | None = None) -> set[str]:  # noqa: ANN401
    if seen is None:
        seen = set()
    found: set[str] = set()
    for expr in expressions:
        ident = id(expr)
        if ident in seen:
            continue
        seen.add(ident)
        if expr.op in {"input", "mem_input"} and expr.name:
            found.add(expr.name)
        found.update(_collect_inputs(expr.args, seen))
    return found


def _input_items(inputs: set[str]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    reg_widths = dict(REG_BY_OFFSET.values())
    for name in sorted(inputs):
        if name in {"mem", "io"}:
            items.append({"kind": "memory", "name": name, "addr_width": 32, "value_width": 8})
            continue
        width = reg_widths.get(name)
        if width is not None:
            items.append({"name": name, "width": width})
    return items


def _strip_iop(op: str) -> str:
    return op[4:] if op.startswith("Iop_") else op


def _strip_width_suffix(op: str) -> str:
    while op and op[-1].isdigit():
        op = op[:-1]
    return op


def _normalize_binop(op: str) -> str:
    if op.startswith("CmpLT") and op.endswith("U"):
        return "CmpLTU"
    if op.startswith("CmpLE") and op.endswith("U"):
        return "CmpLEU"
    if op.startswith("CmpGT") and op.endswith("U"):
        return "CmpGTU"
    if op.startswith("CmpGE") and op.endswith("U"):
        return "CmpGEU"
    if op.startswith("CmpLT") and op.endswith("S"):
        return "CmpLTS"
    if op.startswith("CmpLE") and op.endswith("S"):
        return "CmpLES"
    if op.startswith("CmpGT") and op.endswith("S"):
        return "CmpGTS"
    if op.startswith("CmpGE") and op.endswith("S"):
        return "CmpGES"
    return _strip_width_suffix(op)


def _mask(width: int) -> int:
    return (1 << width) - 1


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _vex_cache_file(*, cache_dir: Path, exe_digest: str) -> Path:
    return cache_dir / "vex" / f"{exe_digest}.pickle"


def _new_vex_cache(exe_digest: str) -> dict[str, Any]:
    return {
        "schema": LIFTER_CACHE_SCHEMA,
        "flavor": "vex",
        "exe_sha256": exe_digest,
        "entries": {},
    }


def _load_vex_cache(*, cache_dir: Path, exe_digest: str) -> dict[str, Any]:
    path = _vex_cache_file(cache_dir=cache_dir, exe_digest=exe_digest)
    if not path.exists():
        return _new_vex_cache(exe_digest)
    try:
        with path.open("rb") as handle:
            document = pickle.load(handle)
    except Exception:
        return _new_vex_cache(exe_digest)
    if not isinstance(document, dict):
        return _new_vex_cache(exe_digest)
    if (
        document.get("schema") != LIFTER_CACHE_SCHEMA
        or document.get("flavor") != "vex"
        or document.get("exe_sha256") != exe_digest
    ):
        return _new_vex_cache(exe_digest)
    if not isinstance(document.get("entries"), dict):
        document["entries"] = {}
    return document


def _save_vex_cache(*, cache_dir: Path, exe_digest: str, cache_document: dict[str, Any]) -> None:
    path = _vex_cache_file(cache_dir=cache_dir, exe_digest=exe_digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(cache_document)
    payload.pop("_dirty", None)
    tmp = path.with_name(f"{path.name}.tmp")
    with tmp.open("wb") as handle:
        pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(tmp, path)


def _vex_cache_key(*, start: int, size: int, opt_level: int) -> str:
    return f"{start:08x}:{size:04x}:opt{opt_level}"


def _lift_vex_block_cached(
    *,
    project: Any,  # noqa: ANN401
    exe_path: Path,
    exe_digest: str,
    start: int,
    size: int,
    opt_level: int,
    cache_document: dict[str, Any] | None,
    cache_stats: dict[str, int],
    max_lift_block_ms: int,
) -> LiftedBlock:
    del exe_path
    key = _vex_cache_key(start=start, size=size, opt_level=opt_level)
    entries = cache_document.get("entries", {}) if isinstance(cache_document, dict) else {}
    if isinstance(entries, dict) and key in entries:
        entry = entries.get(key)
        if (
            isinstance(entry, dict)
            and entry.get("exe_sha256") == exe_digest
            and "irsb" in entry
            and isinstance(entry.get("instructions"), list)
        ):
            cache_stats["hits"] += 1
            return LiftedBlock(irsb=entry["irsb"], instructions=list(entry["instructions"]), lifted=False)
        cache_stats["errors"] += 1

    if cache_document is not None:
        cache_stats["misses"] += 1
    with _block_lift_timeout(max_lift_block_ms, start=start):
        block = project.factory.block(start, size=size, opt_level=opt_level)
    lifted = LiftedBlock(
        irsb=block.vex,
        instructions=[_instruction_record(item.insn) for item in block.capstone.insns],
        lifted=True,
    )
    if cache_document is not None:
        cache_document.setdefault("entries", {})[key] = {
            "exe_sha256": exe_digest,
            "start": start,
            "size": size,
            "opt_level": opt_level,
            "irsb": lifted.irsb,
            "instructions": lifted.instructions,
        }
        cache_document["_dirty"] = True
        cache_stats["writes"] += 1
    return lifted


class _BlockLiftTimeout:
    def __init__(self, timeout_ms: int, *, message: str) -> None:
        self.timeout_ms = max(0, int(timeout_ms))
        self.message = message
        self.previous_handler: Any = None
        self.previous_timer: tuple[float, float] | None = None
        self.enabled = False

    def __enter__(self) -> _BlockLiftTimeout:
        if self.timeout_ms <= 0 or not hasattr(signal, "setitimer"):
            return self
        self.previous_handler = signal.getsignal(signal.SIGALRM)
        self.previous_timer = signal.getitimer(signal.ITIMER_REAL)
        signal.signal(signal.SIGALRM, self._handle_timeout)
        signal.setitimer(signal.ITIMER_REAL, self.timeout_ms / 1000.0)
        self.enabled = True
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Literal[False]:  # noqa: ANN401
        if self.enabled:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if self.previous_handler is not None:
                signal.signal(signal.SIGALRM, self.previous_handler)
            if self.previous_timer is not None:
                delay, interval = self.previous_timer
                if delay > 0 or interval > 0:
                    signal.setitimer(signal.ITIMER_REAL, delay, interval)
        return False

    def _handle_timeout(self, _signum: int, _frame: Any) -> None:  # noqa: ANN401
        raise TimeoutError(self.message)


def _block_lift_timeout(timeout_ms: int, *, start: int) -> _BlockLiftTimeout:
    return _timeout_alarm(timeout_ms, message=f"VEX lift exceeded block timeout at {normalize_hex(start)}")


def _timeout_alarm(timeout_ms: int, *, message: str) -> _BlockLiftTimeout:
    return _BlockLiftTimeout(timeout_ms, message=message)


def _functions_by_name_and_ordinal(functions: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    counts: dict[str, int] = defaultdict(int)
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for function in functions:
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        key = function_name or function_id
        ordinal = counts[key]
        counts[key] += 1
        indexed[(key, ordinal)] = function
    return indexed


def _ssa_part_index(function: dict[str, Any]) -> int:
    part = function.get("part") if isinstance(function.get("part"), dict) else {}
    value = part.get("index")
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _ssa_part_delta(function: dict[str, Any]) -> str:
    part = function.get("part") if isinstance(function.get("part"), dict) else {}
    value = part.get("entry_delta")
    if value is None:
        return ""
    try:
        return normalize_hex(parse_int(value, field="ssa.part.entry_delta") & 0xFFFF, width=4)
    except DosUnitError:
        return str(value)


def _functions_by_name_and_part(functions: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        key = function_name or function_id
        indexed.setdefault((key, _ssa_part_index(function)), function)
    return indexed


def _functions_by_name_and_delta(functions: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        delta = _ssa_part_delta(function)
        if not delta:
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        key = function_name or function_id
        indexed.setdefault((key, delta), function)
    return indexed


def _ssa_block_signature(function: dict[str, Any]) -> tuple[int | None, ...] | None:
    source = function.get("source") if isinstance(function.get("source"), dict) else {}
    instructions = source.get("instructions") if isinstance(source.get("instructions"), list) else []
    instructions = _strip_leading_nop_instructions(instructions)
    blob = _machine_code_bytes(instructions)
    entry = function.get("entry") if isinstance(function.get("entry"), dict) else {}
    linear = _optional_int(entry.get("linear"))
    if linear is not None:
        linear += _leading_nop_size(source.get("instructions") if isinstance(source.get("instructions"), list) else [])
    if blob is None or linear is None:
        return None
    return _normalized_binary_signature_pattern(blob, linear)


def _ssa_layout_block_signature(function: dict[str, Any]) -> tuple[int | None, ...] | None:
    source = function.get("source") if isinstance(function.get("source"), dict) else {}
    instructions = source.get("instructions") if isinstance(source.get("instructions"), list) else []
    instructions = _strip_leading_nop_instructions(instructions)
    blob = _machine_code_bytes(instructions)
    entry = function.get("entry") if isinstance(function.get("entry"), dict) else {}
    linear = _optional_int(entry.get("linear"))
    if linear is not None:
        linear += _leading_nop_size(source.get("instructions") if isinstance(source.get("instructions"), list) else [])
    if blob is None or linear is None:
        return None
    return _layout_binary_signature_pattern(blob, linear)


def _ssa_exact_block_signature(function: dict[str, Any]) -> tuple[int, ...] | None:
    source = function.get("source") if isinstance(function.get("source"), dict) else {}
    instructions = source.get("instructions") if isinstance(source.get("instructions"), list) else []
    instructions = _strip_leading_nop_instructions(instructions)
    blob = _machine_code_bytes(instructions)
    return None if blob is None else tuple(blob)


def _block_signature_digest(signature: tuple[int | None, ...] | None) -> str | None:
    if signature is None:
        return None
    text = "".join("??" if byte is None else f"{byte:02x}" for byte in signature)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _strip_leading_nop_instructions(instructions: list[Any]) -> list[Any]:
    index = 0
    while index < len(instructions):
        instruction = instructions[index]
        if not isinstance(instruction, dict) or str(instruction.get("mnemonic") or "").lower() != "nop":
            break
        index += 1
    return instructions[index:]


def _leading_nop_size(instructions: list[Any]) -> int:
    size = 0
    for instruction in instructions:
        if not isinstance(instruction, dict) or str(instruction.get("mnemonic") or "").lower() != "nop":
            break
        size += int(instruction.get("size") or 0)
    return size


def _functions_by_name_and_exact_block_signature(
    functions: list[dict[str, Any]],
) -> dict[tuple[str, tuple[int, ...]], dict[str, Any]]:
    indexed: dict[tuple[str, tuple[int, ...]], dict[str, Any] | None] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        signature = _ssa_exact_block_signature(function)
        if signature is None:
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        key = (function_name or function_id, signature)
        indexed[key] = function if key not in indexed else None
    return {key: value for key, value in indexed.items() if value is not None}


def _functions_by_exact_block_signature(functions: list[dict[str, Any]]) -> dict[tuple[int, ...], dict[str, Any]]:
    indexed: dict[tuple[int, ...], dict[str, Any] | None] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        signature = _ssa_exact_block_signature(function)
        if signature is None:
            continue
        indexed[signature] = function if signature not in indexed else None
    return {key: value for key, value in indexed.items() if value is not None}


def _functions_by_id_and_exact_block_signature(
    functions: list[dict[str, Any]],
) -> dict[tuple[str, tuple[int, ...]], dict[str, Any]]:
    indexed: dict[tuple[str, tuple[int, ...]], dict[str, Any] | None] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        signature = _ssa_exact_block_signature(function)
        if signature is None:
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        if not function_id:
            continue
        key = (function_id, signature)
        indexed[key] = function if key not in indexed else None
    return {key: value for key, value in indexed.items() if value is not None}


def _functions_by_block_signature(functions: list[dict[str, Any]]) -> dict[tuple[int | None, ...], dict[str, Any]]:
    indexed: dict[tuple[int | None, ...], dict[str, Any] | None] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        signature = _ssa_block_signature(function)
        if signature is None:
            continue
        indexed[signature] = function if signature not in indexed else None
    return {key: value for key, value in indexed.items() if value is not None}


def _functions_by_name_and_block_signature(
    functions: list[dict[str, Any]],
) -> dict[tuple[str, tuple[int | None, ...]], dict[str, Any]]:
    indexed: dict[tuple[str, tuple[int | None, ...]], dict[str, Any] | None] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        signature = _ssa_block_signature(function)
        if signature is None:
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        key = (function_name or function_id, signature)
        indexed[key] = function if key not in indexed else None
    return {key: value for key, value in indexed.items() if value is not None}


def _functions_by_id_and_block_signature(
    functions: list[dict[str, Any]],
) -> dict[tuple[str, tuple[int | None, ...]], dict[str, Any]]:
    indexed: dict[tuple[str, tuple[int | None, ...]], dict[str, Any] | None] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        signature = _ssa_block_signature(function)
        if signature is None:
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        if not function_id:
            continue
        key = (function_id, signature)
        indexed[key] = function if key not in indexed else None
    return {key: value for key, value in indexed.items() if value is not None}


def _functions_by_id_and_part(functions: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        if function_id:
            indexed.setdefault((function_id, _ssa_part_index(function)), function)
    return indexed


def _functions_by_id_and_delta(functions: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        delta = _ssa_part_delta(function)
        if not delta:
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        if function_id:
            indexed.setdefault((function_id, delta), function)
    return indexed


def _functions_by_id(functions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for function in functions:
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        if function_id:
            indexed[function_id] = function
    return indexed


def _ssa_candidate_mapping(mapping_document: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(mapping_document, dict) or mapping_document.get("schema") != "dosunit.mapping.v1":
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for item in mapping_document.get("functions", []) or []:
        if not isinstance(item, dict):
            continue
        oracle_id = item.get("oracle_id")
        oracle_name = item.get("oracle_name")
        if oracle_id is not None:
            indexed[str(oracle_id)] = item
        if oracle_name is not None:
            indexed[str(oracle_name)] = item
    return indexed


def _instruction_disassembly(insn: Any) -> str:  # noqa: ANN401
    mnemonic = str(insn.mnemonic).lower()
    op_str = str(insn.op_str).lower()
    return mnemonic if not op_str else f"{mnemonic} {op_str}"


def _instruction_record(insn: Any) -> dict[str, Any]:  # noqa: ANN401
    mnemonic = str(insn.mnemonic).lower()
    op_str = str(insn.op_str).lower()
    machine_code = bytes(getattr(insn, "bytes", b""))
    return {
        "linear": int(insn.address),
        "size": int(insn.size),
        "mnemonic": mnemonic,
        "op_str": op_str,
        "bytes": machine_code.hex(),
    }


def _instruction_text_from_record(record: dict[str, Any], *, function_base: int) -> dict[str, Any]:
    linear = parse_int(record.get("linear", 0), field="instruction.linear")
    mnemonic = str(record.get("mnemonic", "")).lower()
    op_str = str(record.get("op_str", "")).lower()
    display_op_str = _display_op_str(mnemonic, op_str, linear=linear, function_base=function_base)
    return {
        "address": {
            "ip": normalize_hex((linear - function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(linear),
        },
        "size": parse_int(record.get("size", 0), field="instruction.size"),
        "mnemonic": mnemonic,
        "op_str": op_str,
        "disassembly": mnemonic if not display_op_str else f"{mnemonic} {display_op_str}",
        "bytes": str(record.get("bytes", "")),
    }


def _instruction_text(insn: Any, *, function_base: int) -> dict[str, Any]:  # noqa: ANN401
    mnemonic = str(insn.mnemonic).lower()
    op_str = str(insn.op_str).lower()
    display_op_str = _display_op_str(mnemonic, op_str, linear=int(insn.address), function_base=function_base)
    return {
        "address": {
            "ip": normalize_hex((int(insn.address) - function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(int(insn.address)),
        },
        "size": int(insn.size),
        "mnemonic": mnemonic,
        "op_str": op_str,
        "disassembly": mnemonic if not display_op_str else f"{mnemonic} {display_op_str}",
    }


def _transfer_info(irsb: Any, instructions: list[dict[str, Any]]) -> dict[str, Any] | None:  # noqa: ANN401
    nonreturning = _nonreturning_interrupt_transfer(instructions)
    if nonreturning is not None:
        return nonreturning
    jumpkind = str(getattr(irsb, "jumpkind", ""))
    if jumpkind == "Ijk_Call":
        info: dict[str, Any] = {"kind": "direct_call", "jumpkind": jumpkind}
        target = _const_expr_value(getattr(irsb, "next", None))
        if target is None:
            target = _direct_call_target_from_instructions({"instructions": instructions})
        if target is not None:
            info["target"] = {
                "raw": normalize_hex(target),
                "low16": normalize_hex(target & 0xFFFF, width=4),
            }
        fallthrough = _call_fallthrough_linear_from_instructions(instructions)
        if fallthrough is not None:
            info["fallthrough"] = {
                "linear": normalize_hex(fallthrough),
                "low16": normalize_hex(fallthrough & 0xFFFF, width=4),
            }
        return info
    if jumpkind == "Ijk_Boring":
        successors = _ssa_block_successors(irsb, instructions)
        if successors:
            return {
                "kind": "direct_successors",
                "jumpkind": jumpkind,
                "successors": [
                    {
                        "linear": normalize_hex(successor),
                        "low16": normalize_hex(successor & 0xFFFF, width=4),
                    }
                    for successor in successors
                ],
            }
    return None


def _transfer_info_from_instructions(source: dict[str, Any]) -> dict[str, Any] | None:
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    nonreturning = _nonreturning_interrupt_transfer(instructions)
    if nonreturning is not None:
        return nonreturning
    if source.get("jumpkind") != "Ijk_Call":
        return None
    target = _direct_call_target_from_instructions(source)
    fallthrough = _call_fallthrough_linear_from_instructions(instructions)
    if target is None and fallthrough is None:
        return None
    info: dict[str, Any] = {"kind": "direct_call", "jumpkind": "Ijk_Call"}
    if target is not None:
        info["target"] = {
            "raw": normalize_hex(target),
            "low16": normalize_hex(target & 0xFFFF, width=4),
        }
    if fallthrough is not None:
        info["fallthrough"] = {
            "linear": normalize_hex(fallthrough),
            "low16": normalize_hex(fallthrough & 0xFFFF, width=4),
        }
    return info


def _nonreturning_interrupt_transfer(instructions: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not _is_dos_process_terminate_interrupt(instructions):
        return None
    return {
        "kind": "nonreturning_interrupt",
        "jumpkind": "Ijk_Call",
        "interrupt": "0x21",
        "dos_function": "0x4c",
        "effect": "process_terminate",
    }


def _is_dos_process_terminate_interrupt(instructions: list[dict[str, Any]]) -> bool:
    if not instructions:
        return False
    last = instructions[-1]
    if str(last.get("mnemonic", "")).lower() != "int":
        return False
    operand = str(last.get("op_str") or _operand_from_disassembly(last)).strip().lower()
    if _optional_int(operand) != 0x21:
        return False
    for instruction in reversed(instructions[:-1]):
        mnemonic = str(instruction.get("mnemonic", "")).lower()
        operands = _instruction_operands(instruction)
        if not operands:
            continue
        dest = operands[0].lower()
        if mnemonic == "mov" and len(operands) >= 2:
            value = _optional_int(operands[1])
            if dest == "ah":
                return value == 0x4C
            if dest == "ax" and value is not None:
                return ((value >> 8) & 0xFF) == 0x4C
        if dest in {"ah", "ax"}:
            return False
    return False


def _instruction_operands(instruction: dict[str, Any]) -> list[str]:
    operand = str(instruction.get("op_str") or _operand_from_disassembly(instruction)).strip()
    if not operand:
        return []
    return [part.strip() for part in operand.split(",")]


def _call_fallthrough_linear_from_instructions(instructions: list[dict[str, Any]]) -> int | None:
    if not instructions:
        return None
    instruction = instructions[-1]
    address = instruction.get("address", {}) if isinstance(instruction.get("address"), dict) else {}
    linear = _optional_int(address.get("linear"))
    size = _optional_int(instruction.get("size"))
    if linear is None or size is None:
        return None
    return linear + size


def _reference_linear_from_instructions(instructions: list[dict[str, Any]]) -> int | None:
    if not instructions:
        return None
    address = instructions[-1].get("address", {}) if isinstance(instructions[-1].get("address"), dict) else {}
    return _optional_int(address.get("linear"))


def _canonical_near_linear_target(target: int, *, reference_linear: int | None) -> int:
    if target < 0 or target > 0xFFFF or reference_linear is None:
        return target
    page = reference_linear & ~0xFFFF
    candidates = [page + target, page + 0x10000 + target]
    if page >= 0x10000:
        candidates.append(page - 0x10000 + target)
    return min(candidates, key=lambda candidate: (abs(candidate - reference_linear), candidate))


def _display_op_str(mnemonic: str, op_str: str, *, linear: int, function_base: int) -> str:
    if mnemonic not in CONTROL_MNEMONICS or mnemonic in {"call", "lcall", "int"}:
        return op_str
    target = _direct_control_target_from_operand(op_str)
    if target is None:
        return op_str
    target_linear = _canonical_near_linear_target(target, reference_linear=linear)
    target_ip = (target_linear - function_base) & 0xFFFF
    linear_text = normalize_hex(target_linear)
    ip_text = normalize_hex(target_ip, width=4)
    return ip_text if linear_text == ip_text else f"{ip_text} ({linear_text})"


def _ssa_block_successors(
    irsb: Any,  # noqa: ANN401
    instructions: list[dict[str, Any]],
    *,
    follow_call_fallthrough: bool = False,
    transfer: dict[str, Any] | None = None,
) -> list[int]:
    if isinstance(transfer, dict) and transfer.get("kind") == "nonreturning_interrupt":
        return []
    if _is_dos_process_terminate_interrupt(instructions):
        return []
    early = _jumpkind_successors(
        str(getattr(irsb, "jumpkind", "")),
        instructions,
        follow_call_fallthrough=follow_call_fallthrough,
    )
    if early is not None:
        return early
    if not _last_instruction_is_control(instructions) and not _last_instruction_is_repeat_string(instructions):
        fallthrough = _boring_fallthrough_successor(irsb, instructions)
        return [] if fallthrough is None else [fallthrough]
    reference_linear = _reference_linear_from_instructions(instructions)
    successors: list[int] = []
    successors.extend(_direct_instruction_successors(instructions))
    successors.extend(_irsb_exit_successors(irsb, reference_linear))
    next_target = _const_expr_value(getattr(irsb, "next", None))
    if next_target is not None:
        successors.append(_canonical_near_linear_target(next_target, reference_linear=reference_linear))
    return _unique_ints(successors)


def _jumpkind_successors(
    jumpkind: str,
    instructions: list[dict[str, Any]],
    *,
    follow_call_fallthrough: bool,
) -> list[int] | None:
    """Successors for non-boring jumpkinds; None when the block is boring."""
    if jumpkind == "Ijk_Call":
        if not follow_call_fallthrough:
            return []
        fallthrough = _call_fallthrough_linear_from_instructions(instructions)
        return [] if fallthrough is None else [fallthrough]
    if jumpkind.startswith(("Ijk_Ret", "Ijk_Sig")):
        return []
    if jumpkind != "Ijk_Boring":
        return []
    return None


def _irsb_exit_successors(irsb: Any, reference_linear: int | None) -> list[int]:  # noqa: ANN401
    """Collect canonical successors from Ist_Exit statements."""
    successors: list[int] = []
    for statement in getattr(irsb, "statements", []) or []:
        if getattr(statement, "tag", None) != "Ist_Exit":
            continue
        target = _const_expr_value(getattr(statement, "dst", None))
        if target is not None:
            successors.append(_canonical_near_linear_target(target, reference_linear=reference_linear))
    return successors


def _is_incomplete_noncontrol_block(irsb: Any, instructions: list[dict[str, Any]]) -> bool:  # noqa: ANN401
    if str(getattr(irsb, "jumpkind", "")) != "Ijk_Boring":
        return False
    if _last_instruction_is_repeat_string(instructions):
        return False
    if _boring_fallthrough_successor(irsb, instructions) is not None:
        return False
    return not _last_instruction_is_control(instructions)


def _boring_fallthrough_successor(irsb: Any, instructions: list[dict[str, Any]]) -> int | None:  # noqa: ANN401
    if str(getattr(irsb, "jumpkind", "")) != "Ijk_Boring" or not instructions:
        return None
    last = instructions[-1]
    address = last.get("address") if isinstance(last.get("address"), dict) else {}
    linear = _optional_int(address.get("linear"))
    size = _optional_int(last.get("size"))
    if linear is None or size is None or size <= 0:
        return None
    fallthrough = linear + size
    next_target = _const_expr_value(getattr(irsb, "next", None))
    if next_target is None:
        return None
    reference_linear = _reference_linear_from_instructions(instructions)
    canonical_next = _canonical_near_linear_target(next_target, reference_linear=reference_linear)
    return fallthrough if canonical_next == fallthrough else None


def _last_instruction_is_control(instructions: list[dict[str, Any]]) -> bool:
    if not instructions:
        return False
    return str(instructions[-1].get("mnemonic", "")).lower() in CONTROL_MNEMONICS


def _last_instruction_is_repeat_string(instructions: list[dict[str, Any]]) -> bool:
    if not instructions:
        return False
    instruction = instructions[-1]
    mnemonic = str(instruction.get("mnemonic", "")).lower()
    disassembly = str(instruction.get("disassembly", "")).lower()
    text = f"{mnemonic} {disassembly}".strip()
    return text.startswith(("rep ", "repe ", "repz ", "repne ", "repnz "))


def _direct_instruction_successors(instructions: list[dict[str, Any]]) -> list[int]:
    if not instructions:
        return []
    instruction = instructions[-1]
    mnemonic = str(instruction.get("mnemonic", "")).lower()
    if mnemonic not in CONTROL_MNEMONICS:
        return []
    if mnemonic in {"call", "lcall", "int"}:
        return []
    address = instruction.get("address", {}) if isinstance(instruction.get("address"), dict) else {}
    linear = _optional_int(address.get("linear"))
    size = _optional_int(instruction.get("size"))
    target = _direct_control_target_from_instruction(instruction)
    if target is not None:
        target = _canonical_near_linear_target(target, reference_linear=linear)
    if mnemonic in {"jmp", "ljmp"}:
        return [] if target is None else [target]
    if mnemonic in CONDITIONAL_JUMP_MNEMONICS:
        successors: list[int] = []
        if target is not None:
            successors.append(target)
        if linear is not None and size is not None:
            successors.append(linear + size)
        return successors
    return []


def _direct_control_target_from_instruction(instruction: dict[str, Any]) -> int | None:
    operand = str(instruction.get("op_str") or _operand_from_disassembly(instruction)).strip().lower()
    return _direct_control_target_from_operand(operand)


def _direct_control_target_from_operand(operand: str) -> int | None:
    if not operand or any(token in operand for token in ("[", "]")):
        return None
    normalized = operand.strip().lower()
    for prefix in ("short ", "near ", "far "):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :].strip()
    if not normalized:
        return None
    if ":" in normalized:
        return _split_target_low16(normalized, ":")
    if "," in normalized:
        return _split_target_low16(normalized, ",")
    return _optional_int(normalized)


def _split_target_low16(normalized: str, separator: str) -> int | None:
    """Parse a `seg:off`-style operand part into a canonical low16 target."""
    parts = [part.strip() for part in normalized.split(separator, 1)]
    if len(parts) != 2:
        return None
    target = _optional_int(parts[1]) if _optional_int(parts[1]) is not None else _optional_int(parts[0])
    if target is None:
        return None
    return target & 0xFFFF


def _machine_code_bytes(instructions: list[dict[str, Any]]) -> bytes | None:
    chunks: list[bytes] = []
    for instruction in instructions:
        raw = instruction.get("bytes") if isinstance(instruction, dict) else None
        if not isinstance(raw, str) or not raw:
            return None
        try:
            chunks.append(bytes.fromhex(raw))
        except ValueError:
            return None
    return b"".join(chunks)


def _machine_code_sha256(instructions: list[dict[str, Any]]) -> str | None:
    return _bytes_sha256(_machine_code_bytes(instructions))


def _machine_code_size(instructions: list[dict[str, Any]]) -> int | None:
    data = _machine_code_bytes(instructions)
    return None if data is None else len(data)


def _loader_bytes(project: Any, start: int, size: int) -> bytes | None:  # noqa: ANN401
    try:
        return bytes(project.loader.memory.load(start, size))
    except Exception:
        return None


def _bytes_sha256(data: bytes | None) -> str | None:
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


def _unique_ints(values: list[int]) -> list[int]:
    seen: set[int] = set()
    unique: list[int] = []
    for value in values:
        value = int(value)
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _quick_compare_functions(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    *,
    skip_binary_equal: bool,
) -> dict[str, Any] | None:
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
    if _semantic_ssa_payload(oracle) == _semantic_ssa_payload(candidate):
        return {"status": "passed", "reason": "ssa_equal", "mismatches": []}
    return None


def _semantic_ssa_payload(function: dict[str, Any]) -> dict[str, Any]:
    return {
        "inputs": function.get("inputs", []),
        "outputs": function.get("outputs", {}),
        "assignments": function.get("assignments", []),
    }


def _const_expr_value(expr: Any) -> int | None:  # noqa: ANN401
    if expr is None:
        return None
    if not hasattr(expr, "tag") and hasattr(expr, "size") and hasattr(expr, "value"):
        return int(expr.value)
    if getattr(expr, "tag", None) == "Iex_Const" and hasattr(expr, "con"):
        return int(expr.con.value)
    return None


def _mnemonic_from_disassembly(instruction: dict[str, Any]) -> str:
    disassembly = str(instruction.get("disassembly", "")).strip()
    return disassembly.split(None, 1)[0] if disassembly else ""


def _operand_from_disassembly(instruction: dict[str, Any]) -> str:
    disassembly = str(instruction.get("disassembly", "")).strip()
    parts = disassembly.split(None, 1)
    return parts[1] if len(parts) == 2 else ""


def _refusal(function: dict[str, Any], reason: str, message: str, *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    detail = {
        "function_id": function.get("id"),
        "strategy": "straightline_ssa",
        "message": message,
    }
    if extra:
        detail.update(extra)
    return {
        "status": "refused",
        "reason": reason,
        "detail": detail,
    }


def _refusal_counts(refusals: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in refusals:
        reason = str(item.get("reason", "unknown"))
        counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))
