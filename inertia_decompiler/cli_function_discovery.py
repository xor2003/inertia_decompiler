# AUTO-GENERATED split from cli_runtime_shared.py
"""Layer: CLI/fallback/reporting.

Responsibility: discover and select function work items for orchestrated decompilation.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import builtins
import contextlib
import importlib
import logging
import os
import sys
import threading
import time
import typing
import weakref
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, Self, cast

import angr
from angr_platforms.X86_16.analysis_helpers import (
    collect_neighbor_call_targets,
    extend_cfg_for_far_calls,
    extend_cfg_for_neighbor_calls,
    infer_com_region,
    patch_interrupt_service_call_sites,
    seed_calling_conventions,
)
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    caller_return_use_evidence_by_addr_8616,
    caller_return_use_program_scope_8616,
    collect_caller_return_use_evidence_8616,
    record_caller_return_use_evidence_8616,
)
from angr_platforms.X86_16.exact_region_diagnostics import (
    build_exact_region_diagnostics_8616,
    classify_region_split_8616,
    format_exact_region_diagnostics_8616,
)
from angr_platforms.X86_16.frontend_indirect_jump_targets import (
    collect_constant_indirect_jump_edges_8616,
)
from angr_platforms.X86_16.frontend_instruction_reachability import (
    collect_decoded_block_evidence_8616 as _collect_block_8616,
)
from angr_platforms.X86_16.frontend_instruction_reachability import (
    x86_16_block_successors_from_capstone_8616 as _x86_16_block_successors_from_capstone_8616,
)
from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler.cache import (
    _cache_key_lock,
    _load_cache_json,
    _recovery_cache_key,
    _store_cache_json,
)
from inertia_decompiler.cache_source_manifest import RecoveryCacheSourceScope8616
from inertia_decompiler.catalog_policy import DEFAULT_CATALOG_TIMEOUT
from inertia_decompiler.cli_output import (
    _timestamped_print,
)
from inertia_decompiler.disassembly_helpers import (
    _linear_disassembly,
)
from inertia_decompiler.discovery_cache_contract import (
    SourceRegionCatalogEvidence8616,
    display_catalog_cache_payload_from_record_8616,
    display_catalog_cache_record_8616,
    source_region_catalog_evidence_comment_8616,
)
from inertia_decompiler.discovery_candidate_ranges import pre_entry_candidate_ranges
from inertia_decompiler.discovery_evidence_project import isolated_discovery_evidence_project_8616
from inertia_decompiler.function_graph_extent_repair import enforce_covered_transition_sources_8616
from inertia_decompiler.project_loading import (
    _build_project_cached,
    _build_project_from_bytes,
)
from inertia_decompiler.runtime_support import (
    AnalysisTimeout as _AnalysisTimeout,
)
from inertia_decompiler.runtime_support import (
    analysis_timeout as _analysis_timeout,
)
from inertia_decompiler.runtime_support import (
    run_with_timeout_in_daemon_thread as _run_with_timeout_in_daemon_thread,
)
from inertia_decompiler.runtime_support import (
    run_with_timeout_in_fork as _run_with_timeout_in_fork,
)
from inertia_decompiler.sidecar_metadata import (
    _lst_code_label,
    _lst_code_region,
    _recovery_code_labels,
    _signature_matched_code_addrs,
    _visible_code_labels,
)
from inertia_decompiler.tail_validation import (
    inherit_tail_validation_runtime_policy as _inherit_tail_validation_runtime_policy,
)
from inertia_decompiler.telemetry import trace_function
from inertia_decompiler.work_items import (
    FunctionWorkResult,
)
from inertia_decompiler.x86_16_exact_slice import (
    X86ExactSlicePlan,
    mark_function_original_addr,
    plan_x86_16_exact_slice,
)

# Pseudo-callee DOS helper addresses (when materialized) live in a synthetic
# high-address range, well above real 16-bit image code.
DOS_SERVICE_BASE_ADDR: int = 0xF000_0000

type _AngrCfg = Any
type _AngrFunction = Any
type _AngrBlock = Any
type _AngrObject = Any
_FunctionCfgPair = tuple[_AngrCfg, _AngrFunction]
_SeededRecoveryResult = list[_FunctionCfgPair] | tuple[list[_FunctionCfgPair], list[int]]
_CandidateRecoveryCacheValue = tuple[Literal["ok"], _FunctionCfgPair] | tuple[Literal["keyerror"], str]


def _cache_key_object(value: object) -> dict[str, object] | None:
    """Narrow a cache helper result at the JSON/object boundary."""
    if not isinstance(value, dict):
        return None
    return {str(key): item for key, item in value.items()}


def _function_cfg_pair_object(value: object) -> _FunctionCfgPair:
    """Narrow a dynamically returned ``(CFG, function)`` pair."""
    if isinstance(value, tuple) and len(value) == 2:
        return value[0], value[1]
    raise TypeError("function recovery did not return a CFG/function pair")
_DISPLAY_CATALOG_CACHE_POLICY_SCHEMA_8616 = 3
_BINARY_EXACT_REGION_INFO_KEY_8616 = "x86_16_binary_exact_region"


def _dynamic_attr(obj: object, name: str, default: object = None) -> _AngrObject:
    """Read dynamic angr/third-party attributes at the CLI recovery boundary."""
    return builtins.getattr(obj, name, default)


@dataclass(frozen=True, slots=True)
class DisplayCatalogCachePolicy8616:
    """Runtime inputs that may change sidecar-free function discovery results."""

    ignore_local_sidecar_hints: bool
    include_library_functions: bool
    function_discovery_backend: str
    pat_backend: str
    max_functions: int
    timeout: int
    window: int
    rizin_timeout: int
    low_memory: bool
    auto_rizin_policy: str
    signature_catalog_path: str | None
    signature_catalog_size: int | None
    signature_catalog_mtime_ns: int | None
    catalog_timeout: int = DEFAULT_CATALOG_TIMEOUT

    @classmethod
    def from_runtime(
        cls,
        *,
        ignore_local_sidecar_hints: bool,
        include_library_functions: bool,
        function_discovery_backend: str,
        pat_backend: str,
        max_functions: int,
        timeout: int,
        window: int,
        rizin_timeout: int,
        low_memory: bool,
        auto_rizin_policy: str,
        signature_catalog: Path | None,
        catalog_timeout: int = DEFAULT_CATALOG_TIMEOUT,
    ) -> Self:
        """Build a stable cache policy from the effective CLI discovery inputs."""
        catalog_path: str | None = None
        catalog_size: int | None = None
        catalog_mtime_ns: int | None = None
        if signature_catalog is not None:
            try:
                resolved_catalog = signature_catalog.resolve()
                catalog_stat = resolved_catalog.stat()
            except OSError:
                catalog_path = str(signature_catalog)
            else:
                catalog_path = str(resolved_catalog)
                catalog_size = catalog_stat.st_size
                catalog_mtime_ns = catalog_stat.st_mtime_ns
        return cls(
            ignore_local_sidecar_hints=bool(ignore_local_sidecar_hints),
            include_library_functions=bool(include_library_functions),
            function_discovery_backend=function_discovery_backend.strip().lower(),
            pat_backend=pat_backend.strip().lower(),
            max_functions=max(0, int(max_functions)),
            timeout=max(1, int(timeout)),
            window=max(1, int(window)),
            rizin_timeout=max(1, int(rizin_timeout)),
            low_memory=bool(low_memory),
            auto_rizin_policy=auto_rizin_policy.strip().lower() or "default",
            signature_catalog_path=catalog_path,
            signature_catalog_size=catalog_size,
            signature_catalog_mtime_ns=catalog_mtime_ns,
            catalog_timeout=catalog_timeout,
        )

    def cache_fields(self) -> dict[str, object]:
        """Return JSON-safe fields included in the display-catalog cache key."""
        return {
            "schema": _DISPLAY_CATALOG_CACHE_POLICY_SCHEMA_8616,
            "ignore_local_sidecar_hints": self.ignore_local_sidecar_hints,
            "include_library_functions": self.include_library_functions,
            "function_discovery_backend": self.function_discovery_backend,
            "pat_backend": self.pat_backend,
            "max_functions": self.max_functions,
            "timeout": self.timeout,
            "window": self.window,
            "rizin_timeout": self.rizin_timeout,
            "low_memory": self.low_memory,
            "auto_rizin_policy": self.auto_rizin_policy,
            "signature_catalog_path": self.signature_catalog_path,
            "signature_catalog_size": self.signature_catalog_size,
            "signature_catalog_mtime_ns": self.signature_catalog_mtime_ns,
            "catalog_timeout": self.catalog_timeout,
        }


def _configure_display_catalog_cache_policy_8616(
    project: angr.Project,
    policy: DisplayCatalogCachePolicy8616,
) -> None:
    """Attach typed CLI cache policy to the dynamic third-party angr project."""
    cast(Any, project)._inertia_display_catalog_cache_policy = policy


def _display_catalog_cache_policy_8616(project: angr.Project) -> DisplayCatalogCachePolicy8616:
    """Return configured policy or a conservative legacy-compatible default."""
    policy = _dynamic_attr(project, "_inertia_display_catalog_cache_policy", None)
    if isinstance(policy, DisplayCatalogCachePolicy8616):
        return policy
    return DisplayCatalogCachePolicy8616.from_runtime(
        ignore_local_sidecar_hints=False,
        include_library_functions=bool(_dynamic_attr(project, "_inertia_include_library_functions", False)),
        function_discovery_backend="auto",
        pat_backend="auto",
        max_functions=0,
        timeout=8,
        window=0x400,
        rizin_timeout=8,
        low_memory=False,
        auto_rizin_policy="default",
        signature_catalog=None,
    )


def _source_region_catalog_evidence_8616(
    project: angr.Project,
) -> SourceRegionCatalogEvidence8616 | None:
    """Read typed source-region evidence from the dynamic angr project boundary."""
    evidence = _dynamic_attr(project, "_inertia_source_region_catalog_evidence", None)
    return evidence if isinstance(evidence, SourceRegionCatalogEvidence8616) else None


def _record_caller_return_use_evidence_8616(
    project: object,
    function_addr: int,
    evidence: CallerReturnUseEvidence8616,
) -> None:
    """Store typed caller-use evidence on the exact-slice project contract."""
    record_caller_return_use_evidence_8616(project, function_addr, evidence)


def _caller_target_aliases_for_lst_function_8616(
    lst_metadata: LSTMetadata,
    *,
    recovered_addr: int,
    name: str,
) -> tuple[int, ...]:
    """Return proven sidecar label aliases for one adjusted function entry."""
    normalized_name = name.lstrip("_")
    label_aliases = tuple(
        label_addr
        for label_addr, label_name in _visible_code_labels(lst_metadata).items()
        if label_name.lstrip("_") == normalized_name
    )
    return tuple(dict.fromkeys((recovered_addr, *label_aliases)))


def _collect_caller_return_use_for_entry_aliases_8616(
    project: object,
    target_addrs: tuple[int, ...],
    function_ranges: tuple[tuple[int, int], ...],
) -> CallerReturnUseEvidence8616 | None:
    """Collect caller-use evidence across proven label and prologue aliases.

    Sidecar labels may point at entry padding while direct calls target the
    adjusted prologue.  The recovery summary owns one complete alias census.
    """
    unique_targets = tuple(dict.fromkeys(target_addrs))
    if not unique_targets:
        return None
    evidence = collect_caller_return_use_evidence_8616(
        project,
        unique_targets[0],
        function_ranges,
        target_aliases=unique_targets,
    )
    if os.environ.get("INERTIA_DEBUG_RETURN_TYPE_EVIDENCE") == "1":
        logging.getLogger(__name__).warning(
            "entry-alias return-use evidence: targets=%r facts=%r",
            tuple(hex(target_addr) for target_addr in unique_targets),
            (
                evidence.verdict.value,
                evidence.callsite_addrs,
                evidence.used_callsite_count,
                evidence.unused_callsite_count,
                evidence.excluded_callsite_count,
                evidence.failure_count,
            ),
        )
    return evidence if evidence.verdict is not CallerReturnUseVerdict8616.UNKNOWN else None


def _binary_padding_entry_aliases_8616(
    project: object,
    function_addr: int,
    *,
    max_padding: int | None = None,
) -> tuple[int, ...]:
    """Return callable addresses in the contiguous NOP run before a prologue.

    MS C may expose a public entry at the beginning of alignment padding while
    binary function recovery intentionally selects the framed prologue. Every
    address in the contiguous NOP suffix reaches that prologue without side
    effects, so each is a valid alias for caller-use evidence.
    """
    padding_limit = (
        _X86_16_EXACT_REGION_PADDING_SCAN_LIMIT
        if max_padding is None
        else max_padding
    )
    loader = _dynamic_attr(project, "loader", None)
    memory = _dynamic_attr(loader, "memory", None)
    if memory is None or not hasattr(memory, "load") or padding_limit <= 0:
        return (function_addr,)
    main_object = _dynamic_attr(loader, "main_object", None)
    mapped_start = _dynamic_attr(main_object, "min_addr", None)
    if not isinstance(mapped_start, int):
        mapped_start = _dynamic_attr(main_object, "linked_base", None)
    scan_floor = mapped_start if isinstance(mapped_start, int) and mapped_start <= function_addr else 0
    scan_start = max(scan_floor, function_addr - padding_limit)
    try:
        prefix = bytes(memory.load(scan_start, function_addr - scan_start))
    except Exception:
        return (function_addr,)
    suffix_length = 0
    for byte in reversed(prefix):
        if byte != 0x90:
            break
        suffix_length += 1
    if suffix_length == 0:
        return (function_addr,)
    padding_start = function_addr - suffix_length
    return tuple(range(padding_start, function_addr + 1))


def _entry_linear_caller_range_8616(
    project: object,
    *,
    target_addrs: tuple[int, ...] = (),
    max_scan: int = 0x200,
) -> tuple[int, int] | None:
    """Return an entry range ending after a direct call into the source region."""
    entry = _dynamic_attr(project, "entry", None)
    loader = _dynamic_attr(project, "loader", None)
    memory = _dynamic_attr(loader, "memory", None)
    arch = _dynamic_attr(project, "arch", None)
    disassembler = _dynamic_attr(arch, "capstone", None)
    if (
        not isinstance(entry, int)
        or memory is None
        or not hasattr(memory, "load")
        or disassembler is None
        or max_scan <= 0
    ):
        return None
    try:
        code = bytes(memory.load(entry, max_scan))
        instructions = tuple(disassembler.disasm(code, entry))
    except Exception:
        return None
    normalized_targets = {target_addr & 0xFFFF for target_addr in target_addrs}
    saw_target_call = not normalized_targets
    for instruction in instructions:
        address = _dynamic_attr(instruction, "address", None)
        size = _dynamic_attr(instruction, "size", None)
        mnemonic = _dynamic_attr(instruction, "mnemonic", None)
        instruction_bytes = _dynamic_attr(instruction, "bytes", b"")
        encoded = bytes(instruction_bytes) if isinstance(instruction_bytes, (bytes, bytearray)) else b""
        if isinstance(address, int) and encoded[:1] == b"\xe8" and len(encoded) >= 3:
            relative = int.from_bytes(encoded[1:3], "little", signed=True)
            saw_target_call = saw_target_call or ((address + 3 + relative) & 0xFFFF) in normalized_targets
        if (
            saw_target_call
            and
            isinstance(address, int)
            and isinstance(size, int)
            and size > 0
            and _is_return_mnemonic_8616(mnemonic)
        ):
            return entry, address + size
    return None


def _is_return_mnemonic_8616(mnemonic: object) -> bool:
    """Check whether a dynamic mnemonic value is a return instruction."""
    return isinstance(mnemonic, str) and mnemonic.lower() in {"ret", "retf", "iret"}


def _collect_direct_callee_return_use_evidence_8616(
    project: object,
    function: object,
    function_ranges: tuple[tuple[int, int], ...],
) -> dict[int, CallerReturnUseEvidence8616]:
    """Collect whole-program return-use evidence for direct outgoing callees."""
    existing = caller_return_use_evidence_by_addr_8616(project)
    direct_targets = tuple(
        dict.fromkeys(
            target.target_addr
            for target in collect_neighbor_call_targets(function)
            if target.return_addr is not None
        )
    )
    collected: dict[int, CallerReturnUseEvidence8616] = {}
    for target_addr in direct_targets:
        if target_addr in existing:
            continue
        boundary_aliases = tuple(
            start
            for start, end in function_ranges
            if start <= target_addr < end
        )
        evidence = _collect_caller_return_use_for_entry_aliases_8616(
            project,
            tuple(dict.fromkeys((target_addr, *boundary_aliases))),
            function_ranges,
        )
        if evidence is not None:
            collected[target_addr] = replace(evidence, target_addr=target_addr)
    if os.environ.get("INERTIA_DEBUG_RETURN_TYPE_EVIDENCE") == "1":
        logger = logging.getLogger(__name__)
        for target_addr in direct_targets:
            evidence = existing.get(target_addr) or collected.get(target_addr)
            logger.warning(
                "direct-callee return-use evidence: target=%#x verdict=%s raw=%d classified=%d "
                "materialized=%d failures=%d",
                target_addr,
                evidence.verdict.value if evidence is not None else "missing",
                evidence.raw_fact_count if evidence is not None else 0,
                evidence.classified_fact_count if evidence is not None else 0,
                evidence.materialized_count if evidence is not None else 0,
                evidence.failure_count if evidence is not None else 0,
            )
    return collected


print: Callable[..., object] = _timestamped_print
__all__ = [
    "DisplayCatalogCachePolicy8616",
    "SourceRegionCatalogEvidence8616",
    "_addr_in_ranges",
    "_candidate_recovery_cache_key",
    "_candidate_recovery_regions",
    "_catalog_address_cache_key_8616",
    "_configure_display_catalog_cache_policy_8616",
    "_count_region_local_functions",
    "_direct_recovery_inventory_count",
    "_entry_window_seed_targets",
    "_exact_region_recovery_looks_truncated",
    "_expanded_exe_discovery_limit",
    "_fallback_entry_function",
    "_format_sidecar_function_catalog",
    "_function_binary_exact_region_8616",
    "_function_covered_ranges",
    "_function_recovery_score",
    "_function_recovery_truncated",
    "_function_skip_reason",
    "_infer_x86_16_linear_region",
    "_interesting_functions",
    "_is_zero_filled_region",
    "_linear_function_seed_targets",
    "_load_catalog_address_cache",
    "_looks_like_x86_16_entry_byte",
    "_looks_like_x86_16_function_prologue",
    "_lookup_candidate_recovery_cache",
    "_lookup_persistent_recovery_timeout",
    "_make_placeholder_function",
    "_mark_function_recovery_truncated",
    "_needs_pre_entry_body_supplement",
    "_persistent_recovery_attempt_cache_key",
    "_pick_function",
    "_pick_function_lean",
    "_prioritized_pre_entry_follow_on_targets",
    "_rank_exe_function_seeds",
    "_rank_function_cfg_pairs_for_display",
    "_rank_gap_scan_candidate_addrs",
    "_rank_hidden_sidecar_pairs_for_display_throughput",
    "_rank_labeled_function_entries",
    "_rank_labeled_function_entries_cached",
    "_rank_prologue_scan_candidate_addrs",
    "_recover_blob_entry_function",
    "_recover_cached_function_pairs",
    "_recover_candidate_function_pair",
    "_recover_candidate_with_timeout",
    "_recover_cfg",
    "_recover_direct_addr_function",
    "_recover_fast_exe_catalog",
    "_recover_fast_seed_functions",
    "_recover_hidden_sidecar_display_pairs",
    "_recover_lst_function",
    "_recover_partial_cfg",
    "_recover_ranked_binary_function",
    "_recover_seeded_exe_functions",
    "_recovery_score_good_enough",
    "_relocation_seed_targets",
    "_resolve_x86_16_call_target",
    "_resolve_x86_16_function_start",
    "_richest_bounded_recovery_region",
    "_seed_scan_windows",
    "_select_sidecar_showcase_entries",
    "_sidecar_label_ranking_cache_key",
    "_source_region_catalog_evidence_8616",
    "_store_candidate_recovery_cache",
    "_store_catalog_address_cache",
    "_supplement_cached_seeded_recovery",
    "_supplement_functions_from_prologue_scan",
    "_x86_16_fast_recovery_windows",
    "_x86_16_recovery_windows",
    "record_direct_target_caller_return_use_evidence_8616",
]


@dataclass(frozen=True, slots=True)
class _RankedBinaryPreviewItem:
    function_cfg: _AngrCfg | None
    function: _AngrFunction | None


def _metadata_code_windows(project: angr.Project, linked_base: int, image_end: int) -> list[tuple[int, int]]:
    """Collect labelled LST code ranges clamped to the image window."""
    windows: list[tuple[int, int]] = []
    metadata = _dynamic_attr(project, "_inertia_lst_metadata", None)
    if metadata is None:
        return windows
    for start, end in sorted(_dynamic_attr(metadata, "code_ranges", {}).values()):
        if start >= end:
            continue
        if _lst_code_label(metadata, start, project.entry) is None:
            continue
        windows.append((max(linked_base, start), min(image_end, end)))
    return windows


def _mz_segment_windows(main_object: object, linked_base: int, image_end: int) -> list[tuple[int, int]]:
    """Collect MZ segment spans clamped to the image window."""
    windows: list[tuple[int, int]] = []
    for span in _dynamic_attr(main_object, "mz_segment_spans", ()):
        start = max(linked_base, _dynamic_attr(span, "start_linear", linked_base))
        end = min(image_end, _dynamic_attr(span, "end_linear", image_end))
        if start < end:
            windows.append((start, end))
    return windows


def _merge_scan_windows(windows: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge sorted overlapping scan windows."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(windows):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def _seed_scan_windows(project: angr.Project) -> list[tuple[int, int]]:
    main_object = _dynamic_attr(project.loader, "main_object", None)
    if main_object is None:
        return []
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    if not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return []

    image_end = linked_base + max_addr + 1
    windows = _metadata_code_windows(project, linked_base, image_end)
    windows += _mz_segment_windows(main_object, linked_base, image_end)
    if not windows:
        return [(linked_base, image_end)]
    return _merge_scan_windows(windows)


def _entry_window_seed_targets(
    project: angr.Project,
    code: bytes,
    *,
    linked_base: int,
    entry_window: int = 0x200,
) -> set[int]:
    def _impl() -> set[int]:
        start = max(linked_base, project.entry)
        end = min(linked_base + len(code), project.entry + max(1, entry_window))
        if start >= end:
            return set()

        entry_targets: set[int] = set()
        start_offset = start - linked_base
        end_offset = end - linked_base
        for offset in range(start_offset, end_offset):
            opcode = code[offset]
            callsite = linked_base + offset
            if opcode == 0xE8 and offset + 2 < len(code):
                rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
                entry_targets.add(callsite + 3 + rel)
            elif opcode == 0x9A and offset + 4 < len(code):
                off = int.from_bytes(code[offset + 1 : offset + 3], "little")
                seg = int.from_bytes(code[offset + 3 : offset + 5], "little")
                entry_targets.add(linked_base + (seg << 4) + off)
            elif opcode == 0xE9 and offset + 2 < len(code):
                rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
                entry_targets.add(callsite + 3 + rel)
            elif opcode == 0xEB and offset + 1 < len(code):
                rel = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
                entry_targets.add(callsite + 2 + rel)
        return entry_targets

    return _impl()


def _linear_function_seed_targets(
    project: angr.Project,
    start_addr: int,
    *,
    max_scan: int = 0x200,
    include_jumps: bool = True,
) -> set[int]:
    try:
        code = bytes(project.loader.memory.load(start_addr, max_scan))
    except Exception:
        return set()
    if not code:
        return set()

    targets: set[int] = set()
    offset = 0
    while offset < len(code):
        window = code[offset : offset + 16]
        if not window:
            break
        insn = next(project.arch.capstone.disasm(window, start_addr + offset, 1), None)
        if insn is None or insn.size <= 0:
            break
        target = _linear_seed_target_8616(project, code, offset, insn, include_jumps)
        if target is not None:
            targets.add(target)
        offset += insn.size
        if insn.mnemonic.lower() in {"ret", "retf", "iret"}:
            break
    return targets


def _linear_seed_target_8616(
    project: angr.Project, code: bytes, offset: int, insn: _AngrObject, include_jumps: bool
) -> int | None:
    """Resolve the call/jump target encoded at ``offset``, if any."""
    opcode = code[offset]
    if opcode == 0xE8 and offset + 2 < len(code):
        rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
        return cast(int, insn.address) + 3 + rel
    if opcode == 0x9A and offset + 4 < len(code):
        off = int.from_bytes(code[offset + 1 : offset + 3], "little")
        seg = int.from_bytes(code[offset + 3 : offset + 5], "little")
        linked_base = _dynamic_attr(_dynamic_attr(project.loader, "main_object", None), "linked_base", 0)
        return int(linked_base) + (seg << 4) + off
    if include_jumps and opcode == 0xE9 and offset + 2 < len(code):
        rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
        return cast(int, insn.address) + 3 + rel
    if include_jumps and opcode == 0xEB and offset + 1 < len(code):
        rel = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
        return cast(int, insn.address) + 2 + rel
    return None


def _looks_like_x86_16_function_prologue(code: bytes, offset: int) -> bool:
    window = code[offset : offset + 4]
    return window.startswith(b"\x55\x8b\xec")


def _looks_like_x86_16_entry_byte(code: bytes, offset: int) -> bool:
    if offset < 0 or offset >= len(code):
        return False
    return code[offset] not in {0x00, 0x90, 0xCC}


_X86_16_EXACT_REGION_PADDING_SCAN_LIMIT = 0x80


def _resolve_x86_16_function_start(code: bytes, offset: int, *, max_padding: int = 0x20) -> int | None:
    if offset < 0 or offset >= len(code):
        return None
    if _looks_like_x86_16_function_prologue(code, offset):
        return offset
    padded = offset
    limit = min(len(code), offset + max_padding)
    while padded < limit and code[padded] in {0x00, 0x90, 0xCC}:
        padded += 1
    if padded < len(code) and _looks_like_x86_16_function_prologue(code, padded):
        return padded
    return None


def _resolve_x86_16_call_target(code: bytes, offset: int) -> int | None:
    canonical = _resolve_x86_16_function_start(code, offset)
    if canonical is not None:
        return canonical
    if _looks_like_x86_16_entry_byte(code, offset):
        return offset
    return None


def _track_ah_value_8616(text: str, ah: int | None) -> int | None:
    """Track the last known AH value from mov ah/ax instructions."""
    if text.startswith("mov ah, "):
        try:
            return int(text.split(", ", 1)[1], 0)
        except ValueError:
            return None
    if text.startswith("mov ax, "):
        try:
            ax = int(text.split(", ", 1)[1], 0)
        except ValueError:
            ax = None
        if ax is not None:
            return (ax >> 8) & 0xFF
    return ah


def _region_terminator_reached_8616(project: angr.Project, insn: _AngrObject, current: int, end_limit: int, ah: int | None) -> bool:
    """Check a ret/int terminator ends the linear region scan."""
    if insn.mnemonic in {"ret", "retf", "iret"}:
        if current >= end_limit:
            return True
        try:
            lookahead = bytes(project.loader.memory.load(current, min(16, end_limit - current)))
        except Exception:
            return True
        return bool(lookahead) and all(byte in {0x00, 0x90, 0xCC} for byte in lookahead)
    if insn.mnemonic == "int":
        op = insn.op_str.lower()
        return op == "0x20" or op == "0x27" or (op == "0x21" and ah == 0x4C)
    return False


def _infer_x86_16_linear_region(project: angr.Project, start_addr: int, *, window: int) -> tuple[int, int]:
    end_limit = start_addr + max(window, 1)
    current = start_addr
    ah = None

    while current < end_limit:
        try:
            chunk = bytes(project.loader.memory.load(current, 16))
        except Exception:
            break
        if not chunk:
            break

        insn = next(project.arch.capstone.disasm(chunk, current, 1), None)
        if insn is None or insn.size <= 0:
            break

        text = f"{insn.mnemonic} {insn.op_str}".strip().lower()
        ah = _track_ah_value_8616(text, ah)

        current += insn.size

        if _region_terminator_reached_8616(project, insn, current, end_limit, ah):
            break

    return start_addr, max(start_addr + 1, current)


def _pick_function(
    project: angr.Project,
    addr: int | None,
    *,
    regions: Sequence[tuple[int, int]] | None = None,
    data_references: bool | None = None,
    force_smart_scan: bool | None = None,
    seed_calling_conventions_enabled: bool = True,
) -> _FunctionCfgPair:
    """Recover a CFG while preserving the caller's convention-analysis policy."""
    target_addr = project.entry if addr is None else addr
    data_refs = True if data_references is None else data_references
    if force_smart_scan is None and project.arch.name == "86_16" and regions is not None:
        smart_scan_modes: tuple[bool | None, ...] = (False, True)
    else:
        smart_scan_modes = (force_smart_scan,)

    cfg = _recover_target_cfg_8616(project, target_addr, regions, data_refs, smart_scan_modes)
    if cfg is None or target_addr not in cfg.functions:
        raise KeyError(f"Function {target_addr:#x} was not recovered by CFGFast.")
    function = cfg.functions[target_addr]

    if project.arch.name == "86_16":
        cfg, function = _extend_cfg_86_16_8616(project, cfg, function, target_addr, regions)
    if seed_calling_conventions_enabled:
        seed_calling_conventions(cfg)

    return cfg, function


def _recover_target_cfg_8616(
    project: angr.Project,
    target_addr: int,
    regions: Sequence[tuple[int, int]] | None,
    data_refs: bool,
    smart_scan_modes: tuple[bool | None, ...],
) -> _AngrCfg | None:
    """Try CFGFast across complete/smart scan modes until the target lands."""
    cfg = None
    for complete_scan in (False, True) if project.arch.name == "86_16" else (False,):
        for smart_scan in smart_scan_modes:
            try:
                cfg = project.analyses.CFGFast(
                    start_at_entry=False,
                    function_starts=[target_addr],
                    regions=regions,
                    normalize=True,
                    data_references=data_refs,
                    force_smart_scan=smart_scan,
                    force_complete_scan=complete_scan,
                )
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "CFGFast recovery attempt failed for %s (complete=%s smart=%s): %s",
                    hex(target_addr),
                    complete_scan,
                    smart_scan,
                    ex,
                )
                continue
            if target_addr in cfg.functions:
                break
        if cfg is not None and target_addr in cfg.functions:
            break
    return cfg


def _extend_cfg_86_16_8616(
    project: angr.Project,
    cfg: _AngrCfg,
    function: _AngrFunction,
    target_addr: int,
    regions: Sequence[tuple[int, int]] | None,
) -> tuple[_AngrCfg, _AngrFunction]:
    """Extend a recovered x86-16 CFG across far and neighbor calls."""
    entry_window = (regions[0][1] - regions[0][0]) if regions else 0x200
    for extend in (extend_cfg_for_far_calls, extend_cfg_for_neighbor_calls):
        extended_cfg = cast(_AngrCfg, extend(project, function, entry_window=entry_window))
        if extended_cfg is not None and target_addr in extended_cfg.functions:
            cfg = extended_cfg
            function = cfg.functions[target_addr]
    patch_interrupt_service_call_sites(function, _dynamic_attr(project.loader.main_object, "binary", None))
    return cfg, function


def _pick_function_lean(
    project: angr.Project,
    addr: int | None,
    *,
    regions: Sequence[tuple[int, int]] | None = None,
    data_references: bool = False,
    extend_far_calls: bool = True,
    seed_calling_conventions_enabled: bool = True,
) -> _FunctionCfgPair:
    def _impl() -> _FunctionCfgPair:
        """Recover a known entry point with a deliberately cheap CFGFast pass.

        This is used as an early fast path for COD procedures that are dominated by
        helper calls. For those procedures, indirect-jump resolution and cross-
        reference discovery are often unnecessary and can dominate the recovery
        budget before the function is even identified.
        """
        target_addr = project.entry if addr is None else addr
        cfg = project.analyses.CFGFast(
            start_at_entry=False,
            function_starts=[target_addr],
            regions=regions,
            normalize=False,
            data_references=data_references,
            force_smart_scan=False,
            force_complete_scan=False,
            resolve_indirect_jumps=False,
            function_prologues=False,
            symbols=False,
            cross_references=False,
        )
        if target_addr not in cfg.functions:
            raise KeyError(f"Function {target_addr:#x} was not recovered by CFGFast.")

        function = cfg.functions[target_addr]
        if project.arch.name == "86_16":
            if extend_far_calls:
                extended_cfg = cast(
                    _AngrCfg,
                    extend_cfg_for_far_calls(
                        project,
                        function,
                        entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
                    ),
                )
                if extended_cfg is not None and target_addr in extended_cfg.functions:
                    cfg = extended_cfg
                    function = cfg.functions[target_addr]
                extended_cfg = cast(
                    _AngrCfg,
                    extend_cfg_for_neighbor_calls(
                        project,
                        function,
                        entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
                    ),
                )
                if extended_cfg is not None and target_addr in extended_cfg.functions:
                    cfg = extended_cfg
                    function = cfg.functions[target_addr]
            patch_interrupt_service_call_sites(function, _dynamic_attr(project.loader.main_object, "binary", None))
        if seed_calling_conventions_enabled:
            seed_calling_conventions(cfg)
        return cfg, function

    return _impl()


_DEFAULT_PICK_FUNCTION_LEAN = _pick_function_lean


def _normalized_x86_16_recovery_window(window: int | None, *, low_memory: bool = False) -> int:
    floor = 0x80 if low_memory else 0x200
    if not isinstance(window, int):
        return floor
    return max(window, floor)


def _x86_16_recovery_windows(window: int | None, *, low_memory: bool = False) -> tuple[int, ...]:
    base_window = _normalized_x86_16_recovery_window(window, low_memory=low_memory)
    return tuple(base_window * factor for factor in (1, 2, 4, 8, 16))


def _x86_16_fast_recovery_windows(window: int | None, *, low_memory: bool = False) -> tuple[int, ...]:
    effective_window = _normalized_x86_16_recovery_window(window, low_memory=low_memory)
    candidate_windows = (0x40, 0x80, 0x100) if low_memory else (0x80, 0x100, 0x200)
    windows: list[int] = []
    for candidate in candidate_windows:
        current_window = effective_window if effective_window <= candidate else candidate
        if current_window not in windows:
            windows.append(current_window)
    if not windows:
        windows.append(effective_window)
    return tuple(windows)


@cast(Callable[..., Any], trace_function(name="discovery.recover_cfg"))
def _recover_cfg(
    project: angr.Project,
    binary_path: Path,
    *,
    base_addr: int,
    window: int,
    low_memory: bool = False,
) -> _AngrCfg:
    print(
        f"[dbg] recover_cfg: entry={hex(project.entry)} base_addr={hex(base_addr)} window={hex(window)} binary={binary_path}"
    )
    sys.stdout.flush()
    if binary_path.suffix.lower() == ".com":
        force_smart_scan = False if project.arch.name == "86_16" else None
        regions = [infer_com_region(binary_path, base_addr=base_addr, window=window, arch=project.arch)]
        cfg = project.analyses.CFGFast(
            start_at_entry=False,
            function_starts=[project.entry],
            regions=regions,
            normalize=True,
            force_complete_scan=False,
            data_references=not low_memory,
            force_smart_scan=force_smart_scan,
        )
    else:
        print("[dbg] calling CFGFast (non-COM path)")
        sys.stdout.flush()
        cfg = project.analyses.CFGFast(
            normalize=True,
            force_complete_scan=False,
            data_references=not low_memory,
        )
        print("[dbg] CFGFast returned")
        sys.stdout.flush()

    if project.arch.name == "86_16" and project.entry in cfg.functions:
        extended_cfg = cast(
            _AngrCfg, extend_cfg_for_far_calls(project, cfg.functions[project.entry], entry_window=window)
        )
        if extended_cfg is not None and project.entry in extended_cfg.functions:
            cfg = extended_cfg
        extended_cfg = cast(
            _AngrCfg, extend_cfg_for_neighbor_calls(project, cfg.functions[project.entry], entry_window=window)
        )
        if extended_cfg is not None and project.entry in extended_cfg.functions:
            cfg = extended_cfg
        patch_interrupt_service_call_sites(cfg.functions[project.entry], binary_path)
    seed_calling_conventions(cfg)
    return cfg


@cast(Callable[..., Any], trace_function(name="discovery.recover_partial_cfg"))
def _recover_partial_cfg(
    project: angr.Project,
    *,
    window: int,
    low_memory: bool = False,
) -> _AngrCfg:
    def _impl() -> _AngrCfg:
        """Recover a bounded x86-16 catalog around the entry point.

        This is the whole-binary fallback for awkward real-mode executables such as
        packed startup stubs. It keeps CFGFast inside narrow entry windows instead
        of asking angr to recover the entire executable at once.
        """
        candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
        last_error: Exception | None = None
        for candidate_window in candidate_windows:
            cast(_AngrObject, project)._inertia_decompiler_stage = f"catalog:narrow:{candidate_window:#x}"
            try:
                return _try_partial_cfg_window_8616(project, candidate_window)
            except Exception as ex:
                last_error = ex
        if last_error is not None:
            raise last_error
        raise KeyError(f"Function {project.entry:#x} was not recovered by bounded CFGFast.")

    return _impl()


def _try_partial_cfg_window_8616(project: angr.Project, candidate_window: int) -> _AngrCfg:
    """Attempt one bounded CFGFast recovery inside a candidate window."""
    if project.arch.name == "86_16":
        regions = [_infer_x86_16_linear_region(project, project.entry, window=candidate_window)]
    else:
        regions = [(project.entry, project.entry + candidate_window)]
    last_error: Exception | None = None
    for data_refs in (False, True) if project.arch.name == "86_16" else (False,):
        try:
            cfg = project.analyses.CFGFast(
                start_at_entry=False,
                function_starts=[project.entry],
                regions=regions,
                normalize=True,
                force_complete_scan=False,
                data_references=data_refs,
                force_smart_scan=False if project.arch.name == "86_16" else None,
            )
        except Exception as ex:
            last_error = ex
            continue
        if project.entry not in cfg.functions:
            last_error = KeyError(f"Function {project.entry:#x} was not recovered by CFGFast.")
            continue
        if project.arch.name == "86_16":
            entry_window = (regions[0][1] - regions[0][0]) if regions else candidate_window
            for extend in (extend_cfg_for_far_calls, extend_cfg_for_neighbor_calls):
                extended_cfg = cast(
                    _AngrCfg,
                    extend(project, cfg.functions[project.entry], entry_window=entry_window),
                )
                if extended_cfg is not None and project.entry in extended_cfg.functions:
                    cfg = extended_cfg
            patch_interrupt_service_call_sites(
                cfg.functions[project.entry],
                _dynamic_attr(project.loader.main_object, "binary", None),
            )
        seed_calling_conventions(cfg)
        return cfg
    assert last_error is not None
    raise last_error


def _function_skip_reason(function: _AngrFunction) -> str | None:
    if _dynamic_attr(function, "is_simprocedure", False):
        return "SimProcedure (DOS helper)"
    addr = _dynamic_attr(function, "addr", None)
    if isinstance(addr, int) and addr >= DOS_SERVICE_BASE_ADDR:
        return "DOS service address"
    return None


def _function_recovery_score(function: _AngrFunction) -> tuple[int, int]:
    """Score coverage from a dynamic angr function object."""
    blocks = tuple(_dynamic_attr(function, "blocks", ()) or ())
    if not blocks:
        return (0, 0)
    total_bytes = sum(max(0, int(_dynamic_attr(block, "size", 0) or 0)) for block in blocks)
    return (len(blocks), total_bytes)


def _block_ranges_for_overlap_8616(
    blocks: Sequence[_AngrBlock] | None,
    exact_region: tuple[int, int] | None = None,
) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for block in tuple(blocks or ()):
        addr = _dynamic_attr(block, "addr", None)
        size = max(0, _dynamic_attr(block, "size", 0))
        if not isinstance(addr, int) or size <= 0:
            continue
        end = addr + size
        if exact_region is not None:
            region_start, region_end = exact_region
            if end <= region_start or addr >= region_end:
                continue
            addr = max(addr, region_start)
            end = min(end, region_end)
            if addr >= end:
                continue
        ranges.append((addr, end))
    return sorted(ranges)


def _block_overlap_count_8616(blocks: Sequence[_AngrBlock] | None, exact_region: tuple[int, int] | None = None) -> int:
    ranges = _block_ranges_for_overlap_8616(blocks, exact_region)
    overlap_count = 0
    last_end: int | None = None
    for start, end in ranges:
        if last_end is not None and start < last_end:
            overlap_count += 1
        last_end = max(last_end or end, end)
    return overlap_count


def _block_unique_covered_bytes_8616(
    blocks: Sequence[_AngrBlock] | None,
    exact_region: tuple[int, int] | None = None,
) -> int:
    ranges = _block_ranges_for_overlap_8616(blocks, exact_region)
    if not ranges:
        return 0
    merged: list[list[int]] = []
    for start, end in ranges:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
            continue
        merged[-1][1] = max(merged[-1][1], end)
    return sum(end - start for start, end in merged)


def _function_block_overlap_count_8616(function: _AngrFunction, exact_region: tuple[int, int] | None = None) -> int:
    return _block_overlap_count_8616(tuple(_dynamic_attr(function, "blocks", ()) or ()), exact_region)


def _should_replace_exact_region_candidate_8616(
    current: _AngrFunction,
    candidate: _AngrFunction,
    exact_region: tuple[int, int] | None,
) -> bool:
    current_score = _function_recovery_score(current)
    candidate_score = _function_recovery_score(candidate)
    if candidate_score <= current_score:
        return False
    if exact_region is not None:
        current_overlap = _function_block_overlap_count_8616(current, exact_region)
        candidate_overlap = _function_block_overlap_count_8616(candidate, exact_region)
        if current_overlap == 0 and candidate_overlap > 0:
            return False
    return True


def _function_covered_ranges(function: _AngrFunction) -> list[tuple[int, int]]:
    def _impl() -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for block in tuple(_dynamic_attr(function, "blocks", ()) or ()):
            addr = _dynamic_attr(block, "addr", None)
            size = max(0, _dynamic_attr(block, "size", 0))
            if not isinstance(addr, int) or size <= 0:
                continue
            ranges.append((addr, addr + size))
        if not ranges:
            addr = _dynamic_attr(function, "addr", None)
            score = _function_recovery_score(function)
            if isinstance(addr, int) and score[1] > 0:
                ranges.append((addr, addr + score[1]))
        if not ranges:
            return []
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if not merged or start > merged[-1][1]:
                merged.append((start, end))
            else:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        return merged

    return _impl()


def _mark_function_binary_exact_region_8616(
    function: _AngrFunction,
    exact_region: tuple[int, int],
) -> None:
    """Attach binary-derived function bounds at the dynamic angr boundary."""
    info = _dynamic_attr(function, "info", None)
    if not isinstance(info, dict):
        with contextlib.suppress(Exception):
            function.info = {}
        info = _dynamic_attr(function, "info", None)
    if isinstance(info, dict):
        info[_BINARY_EXACT_REGION_INFO_KEY_8616] = exact_region


def _function_binary_exact_region_8616(function: object) -> tuple[int, int] | None:
    """Return validated binary-derived bounds attached during discovery."""
    info = _dynamic_attr(function, "info", None)
    if not isinstance(info, dict):
        return None
    region = info.get(_BINARY_EXACT_REGION_INFO_KEY_8616)
    if (
        isinstance(region, tuple)
        and len(region) == 2
        and isinstance(region[0], int)
        and isinstance(region[1], int)
        and region[0] < region[1]
    ):
        return region
    return None


def _addr_in_ranges(addr: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= addr < end for start, end in ranges)


def _candidate_recovery_regions(
    metadata: LSTMetadata | None,
    addr: int,
    *,
    image_end: int,
    region_span: int,
    project_entry: int,
) -> list[tuple[int, int]]:
    exact_region = _lst_code_region(metadata, addr)
    if exact_region is not None:
        return [exact_region]
    regions: list[tuple[int, int]] = []
    candidate_windows = _x86_16_fast_recovery_windows(region_span)
    if addr < project_entry:
        candidate_windows = (region_span,)
    for candidate_window in candidate_windows:
        region = (addr, min(addr + candidate_window, image_end))
        if region not in regions:
            regions.append(region)
    return regions


def _richest_bounded_recovery_region(
    addr: int,
    *,
    image_end: int,
    region_span: int,
) -> tuple[int, int]:
    return (addr, min(addr + _x86_16_recovery_windows(region_span)[-1], image_end))


def _x86_16_region_image_end_8616(project: angr.Project | None) -> int | None:
    """Resolve the loaded image end address for region extension."""
    if project is None:
        return None
    main_object = _dynamic_attr(project.loader, "main_object", None)
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    if not isinstance(max_addr, int):
        return None
    return max_addr + 1


def _extended_terminator_region_8616(
    start: int, end: int, trailer: bytes, image_end: int
) -> tuple[int, int]:
    """Extend a coarse region to cover a nearby return terminator."""
    op0 = trailer[0]
    if op0 in {0xC3, 0xCB}:  # ret / retf
        return (start, end + 1)
    if op0 in {0xC2, 0xCA}:  # ret imm16 / retf imm16
        return (start, min(image_end, end + 3))
    # Coarse sidecar regions for tiny functions can stop at a branch target
    # right before the epilogue bytes. If a nearby return exists, extend to
    # include it so control-flow/condition recovery can see full tail shape.
    for idx, byte in enumerate(trailer):
        if byte in {0xC3, 0xCB}:  # ret / retf
            return (start, min(image_end, end + idx + 1))
        if byte in {0xC2, 0xCA}:  # ret imm16 / retf imm16
            return (start, min(image_end, end + idx + 3))
    return (start, end)


def _maybe_extend_x86_16_exact_region_terminator(
    project: angr.Project,
    exact_region: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if exact_region is None:
        return None
    start, end = exact_region
    size = max(0, end - start)
    if size <= 0 or size > 0x40:
        return exact_region
    image_end = _x86_16_region_image_end_8616(project)
    if image_end is None or end >= image_end:
        return exact_region
    lookahead = min(0x10, image_end - end)
    try:
        trailer = bytes(project.loader.memory.load(end, lookahead))
    except Exception:
        return exact_region
    if not trailer:
        return exact_region
    return _extended_terminator_region_8616(start, end, trailer, image_end)


def _x86_16_exact_region_has_terminator(
    project: angr.Project,
    exact_region: tuple[int, int] | None,
) -> bool:
    if exact_region is None:
        return False
    start, end = exact_region
    size = max(0, end - start)
    if size <= 0:
        return False
    main_object = _dynamic_attr(project.loader, "main_object", None)
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    if not isinstance(max_addr, int):
        return False
    image_end = max_addr + 1
    if start >= image_end:
        return False
    read_size = min(size, image_end - start)
    if read_size <= 0:
        return False
    try:
        raw = bytes(project.loader.memory.load(start, read_size))
    except Exception:
        return False
    if not raw:
        return False
    # Accept plain returns, iret, and direct near/far jumps as explicit block terminators.
    terminators = {0xC2, 0xC3, 0xCA, 0xCB, 0xCF, 0xE9, 0xEA, 0xEB}
    return any(byte in terminators for byte in raw)


def _recovery_score_good_enough(score: tuple[int, int]) -> bool:
    blocks, total_bytes = score
    return total_bytes >= 0x40 or blocks >= 4


def _exact_region_recovery_looks_truncated(
    function: _AngrFunction,
    exact_region: tuple[int, int] | None,
) -> bool:
    if exact_region is None:
        return False
    region_size = max(0, exact_region[1] - exact_region[0])
    if region_size < 0x40:
        return False
    _blocks, total_bytes = _function_recovery_score(function)
    return total_bytes < max(0x20, region_size // 3)


def _stitch_x86_16_exact_function_8616(
    project: angr.Project,
    function: _AngrFunction,
    exact_region: tuple[int, int] | None,
) -> tuple[_AngrFunction, bool]:
    if exact_region is None:
        return function, False
    start, end = exact_region
    if not (isinstance(start, int) and isinstance(end, int) and start < end):
        return function, False

    entry = _dynamic_attr(function, "addr", None)
    if not isinstance(entry, int) or not (start <= entry < end):
        return function, False

    reachable, edges = _collect_stitched_blocks_and_edges_8616(project, entry, start, end)

    if len(reachable) <= 1:
        return function, False

    if not _should_replace_function_with_stitched_graph_8616(function, reachable, exact_region):
        return function, False

    _reset_function_graph_state_8616(function)
    _rebuild_function_transition_graph_8616(function, reachable, edges)
    _mark_stitched_return_sites_8616(function, reachable)

    function.normalized = False
    return function, True


def _collect_stitched_blocks_and_edges_8616(
    project: angr.Project, entry: int, start: int, end: int
) -> tuple[dict[int, object], set[tuple[int, int]]]:
    reachable: dict[int, _AngrBlock] = {}
    edges: set[tuple[int, int]] = set()
    queue: list[int] = [entry]
    visited: set[int] = set()
    while queue:
        block_addr = queue.pop(0)
        if block_addr in visited or not (start <= block_addr < end):
            continue
        visited.add(block_addr)
        try:
            block = _collect_block_8616(project, block_addr, opt_level=0).block
        except Exception:
            visited.remove(block_addr)
            continue
        if len(_dynamic_attr(block, "bytes", b"")) <= 0:
            visited.remove(block_addr)
            continue
        reachable[block_addr] = block
        successors, _ = _x86_16_block_successors_from_capstone_8616(block, region_start=start, region_end=end)
        for succ in successors:
            if start <= succ < end and succ not in visited:
                queue.append(succ)
            edges.add((block_addr, succ))
    reachable = _cap_stitched_blocks_to_leaders_8616(project, reachable, region_end=end)
    edges = _recompute_stitched_edges_8616(reachable, start, end)
    return reachable, edges


def _cap_stitched_blocks_to_leaders_8616(
    project: angr.Project,
    reachable: dict[int, _AngrBlock],
    *,
    region_end: int | None = None,
) -> dict[int, object]:
    """Cap stitched blocks at the next leader and the authoritative region end."""
    if len(reachable) <= 1:
        return reachable
    leaders = sorted(reachable)
    capped: dict[int, object] = {}
    for block_addr in leaders:
        block = reachable[block_addr]
        block_size = int(_dynamic_attr(block, "size", 0) or 0)
        if block_size <= 0:
            capped[block_addr] = block
            continue
        block_end = block_addr + block_size
        cap_end = next((leader for leader in leaders if block_addr < leader < block_end), block_end)
        if isinstance(region_end, int):
            cap_end = min(cap_end, region_end)
        if cap_end >= block_end:
            capped[block_addr] = block
            continue
        capped_size = cap_end - block_addr
        if capped_size <= 0:
            capped[block_addr] = block
            continue
        try:
            capped_block = project.factory.block(block_addr, size=capped_size, opt_level=0)
        except Exception:
            capped[block_addr] = block
            continue
        if int(_dynamic_attr(capped_block, "size", 0) or 0) > 0:
            capped[block_addr] = capped_block
        else:
            capped[block_addr] = block
    return capped


def _recompute_stitched_edges_8616(
    reachable: dict[int, _AngrBlock],
    start: int,
    end: int,
) -> set[tuple[int, int]]:
    edges: set[tuple[int, int]] = set()
    for block_addr, block in reachable.items():
        successors, _ = _x86_16_block_successors_from_capstone_8616(block, region_start=start, region_end=end)
        for succ in successors:
            edges.add((block_addr, succ))
    return edges


def _should_replace_function_with_stitched_graph_8616(
    function: _AngrFunction,
    reachable: dict[int, _AngrBlock],
    exact_region: tuple[int, int] | None = None,
) -> bool:
    current_block_count, current_block_bytes = _function_recovery_score(function)
    stitched_bytes = sum(len(_dynamic_attr(block, "bytes", b"")) for block in reachable.values())
    current_blocks = tuple(_dynamic_attr(function, "blocks", ()) or ())
    stitched_blocks = tuple(reachable.values())
    if exact_region is not None and stitched_blocks:
        region_start, region_end = exact_region
        current_escapes_region = any(
            isinstance(_dynamic_attr(block, "addr", None), int)
            and (
                block.addr < region_start
                or block.addr + max(0, int(_dynamic_attr(block, "size", 0) or 0)) > region_end
            )
            for block in current_blocks
        )
        if current_escapes_region:
            return True
    current_overlap = _block_overlap_count_8616(current_blocks, exact_region)
    stitched_overlap = _block_overlap_count_8616(stitched_blocks, exact_region)
    if current_overlap > stitched_overlap:
        current_unique = _block_unique_covered_bytes_8616(current_blocks, exact_region)
        stitched_unique = _block_unique_covered_bytes_8616(stitched_blocks, exact_region)
        if stitched_unique >= current_unique:
            return True
    return stitched_bytes > current_block_bytes or len(reachable) > current_block_count


def _reset_function_graph_state_8616(function: _AngrFunction) -> None:
    """Clear recovered nodes and invalidate angr's derived local CFG together."""
    try:
        function._addr_to_block_node.clear()
        function._block_sizes.clear()
        function._local_block_addrs.clear()
        function._local_blocks.clear()
        function._call_sites.clear()
        function._ret_sites.clear()
        function._jumpout_sites.clear()
        function._callout_sites.clear()
        function._retout_sites.clear()
        function._endpoints.clear()
        if hasattr(function, "transition_graph"):
            function.transition_graph.clear()
            function._local_transition_graph = None
        if hasattr(function, "startpoint"):
            function.startpoint = None
    except Exception:
        pass


def _rebuild_function_transition_graph_8616(
    function: _AngrFunction,
    reachable: dict[int, _AngrBlock],
    edges: set[tuple[int, int]],
) -> None:
    """Rebuild graph nodes through dynamic angr function internals."""
    BlockNode = cast(
        _AngrObject, _dynamic_attr(importlib.import_module("angr.knowledge_plugins.cfg.cfg_node"), "BlockNode")
    )

    for block_addr in sorted(reachable):
        block = reachable[block_addr]
        node = BlockNode(block_addr, block.size, bytestr=_dynamic_attr(block, "bytes", None))
        function._register_node(True, node)
    for source_addr, target_addr in edges:
        source_node = function.get_node(source_addr)
        target_node = function.get_node(target_addr)
        if source_node is None or target_node is None:
            continue
        source_capstone = _dynamic_attr(reachable[source_addr], "capstone", None)
        insns = _dynamic_attr(source_capstone, "insns", ())
        ins_addr = int(_dynamic_attr(insns[-1], "address", source_addr)) if insns else source_addr
        try:
            function._transit_to(source_node, target_node, ins_addr=ins_addr)
        except Exception:
            continue


def _mark_stitched_return_sites_8616(function: _AngrFunction, reachable: dict[int, _AngrBlock]) -> None:
    for block_addr in sorted(reachable):
        source_node = function.get_node(block_addr)
        if source_node is None:
            continue
        last_insns = tuple(_dynamic_attr(_dynamic_attr(reachable[block_addr], "capstone", None), "insns", ()) or ())
        if not last_insns:
            continue
        last_mnemonic = str(_dynamic_attr(last_insns[-1], "mnemonic", "")).lower()
        if last_mnemonic in {"ret", "retf", "iret", "retw", "iretq"}:
            function._add_return_site(source_node)
        if last_mnemonic.startswith("j") and not tuple(function.transition_graph.edges(source_node)):
            function._add_return_site(source_node)


def _mark_x86_16_stitched_recovery_8616(function: _AngrFunction) -> None:
    info = _dynamic_attr(function, "info", None)
    if not isinstance(info, dict):
        with contextlib.suppress(Exception):
            function.info = {}
        info = _dynamic_attr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_stitched_recovery"] = True
    with contextlib.suppress(Exception):
        typing.cast(typing.Any, function)._inertia_x86_16_stitched_recovery = True


def _commit_exact_region_function_to_kb_8616(
    project: angr.Project,
    cfg: _AngrCfg,
    function: _AngrFunction,
    exact_region: tuple[int, int] | None,
) -> bool:
    """Commit a selected exact-region function into later function managers.

    CFGFast can leave smaller region-local pseudo-functions in the project KB
    even after the recovery layer stitches the full exact-region body. Leaving
    those stale entries visible makes later decompiler stages treat internal
    block leaders as independent functions. The recovery layer owns this handoff:
    it has the exact-region evidence and the selected bounded graph.
    """
    if _dynamic_attr(_dynamic_attr(project, "arch", None), "name", None) != "86_16":
        return False
    if exact_region is None:
        return False
    entry_addr = _dynamic_attr(function, "addr", None)
    if not isinstance(entry_addr, int):
        return False
    start, end = exact_region
    if not (isinstance(start, int) and isinstance(end, int) and start <= entry_addr < end):
        return False

    managers: list[_AngrObject] = []
    project_functions = _dynamic_attr(_dynamic_attr(project, "kb", None), "functions", None)
    cfg_functions = _dynamic_attr(cfg, "functions", None)
    for manager in (project_functions, cfg_functions):
        if manager is not None and all(id(manager) != id(existing) for existing in managers):
            managers.append(manager)

    changed = False
    for manager in managers:
        changed = _commit_region_to_manager_8616(manager, function, entry_addr, start, end) or changed

    if project_functions is not None:
        with contextlib.suppress(Exception):
            function._function_manager = weakref.proxy(project_functions)
    with contextlib.suppress(Exception):
        function._local_transition_graph = None
    info = _dynamic_attr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_exact_region_committed"] = True
    return changed


def _commit_region_to_manager_8616(
    manager: _AngrObject,
    function: _AngrFunction,
    entry_addr: int,
    start: int,
    end: int,
) -> bool:
    """Evict stale region-local entries and install the committed function."""
    changed = False
    keys = tuple(_dynamic_attr(manager, "keys", lambda: ())() or ())
    for candidate_addr in keys:
        if not isinstance(candidate_addr, int):
            continue
        if start < candidate_addr < end:
            with contextlib.suppress(Exception):
                del manager[candidate_addr]
                changed = True

    existing = None
    with contextlib.suppress(Exception):
        existing = manager.function(addr=entry_addr, create=False)
    if existing is not function:
        with contextlib.suppress(Exception):
            del manager[entry_addr]
        function_map = _dynamic_attr(manager, "_function_map", None)
        if function_map is None:
            return changed
        try:
            function_map[entry_addr] = function
            changed = True
        except Exception:
            return changed

    with contextlib.suppress(Exception):
        manager.function_addrs_set.add(entry_addr)
    name = _dynamic_attr(function, "name", None)
    if isinstance(name, str) and name:
        with contextlib.suppress(Exception):
            manager._func_name_to_addrs[name].add(entry_addr)
    with contextlib.suppress(Exception):
        manager._func_block_counts.pop(entry_addr, None)
    return changed


def _repair_x86_16_function_graph_8616(
    project: angr.Project,
    function: _AngrFunction,
    *,
    exact_region: tuple[int, int] | None = None,
) -> None:
    """Best-effort CFG completion through dynamic angr function internals.

    The recovery layer should own this because missing return sites here are
    usually a graph-completion issue from bounded CFGFast extraction, not an
    IR/lowering defect.
    """
    debug_indirect = os.environ.get("INERTIA_DEBUG_INDIRECT_JUMP") == "1"
    if debug_indirect:
        logging.getLogger(__name__).warning(
            "x86-16 graph repair start function=%r exact_region=%r",
            _dynamic_attr(function, "addr", None),
            exact_region,
        )
    entry_addr = _graph_repair_entry_addr_8616(project, function)
    if entry_addr is None:
        return

    enforce_covered_transition_sources_8616(project, function, exact_region=exact_region)

    gates = _graph_repair_block_addrs_8616(function, debug_indirect)
    if gates is None:
        return
    block_addrs, seed_max_byte = gates

    bounds = _graph_repair_scan_bounds_8616(entry_addr, exact_region, block_addrs, seed_max_byte)
    discovery = _discover_graph_repair_region_8616(project, entry_addr, bounds, debug_indirect)

    if discovery.indirect_artifact is not None:
        function_info = _dynamic_attr(function, "info", None)
        if isinstance(function_info, dict):
            function_info["x86_16_indirect_jump_artifact"] = discovery.indirect_artifact

    if not discovery.blocks:
        return

    BlockNode = cast(
        _AngrObject, _dynamic_attr(importlib.import_module("angr.knowledge_plugins.cfg.cfg_node"), "BlockNode")
    )
    _seed_graph_repair_node_cache_8616(function, BlockNode)

    for block_addr in sorted(discovery.blocks):
        _ensure_repair_block_node_8616(function, BlockNode, discovery.blocks, block_addr, debug_indirect)

    _install_repair_edges_8616(function, BlockNode, discovery, debug_indirect)

    enforce_covered_transition_sources_8616(project, function, exact_region=exact_region)

    discovered_returns = _install_repair_return_sites_8616(function, discovery.blocks)
    if discovered_returns > 0:
        with contextlib.suppress(Exception):
            typing.cast(typing.Any, function)._inertia_x86_16_return_repair_applied = True
    if debug_indirect:
        _debug_graph_repair_finish_8616(function, discovery.blocks)


def _debug_graph_repair_finish_8616(function: _AngrFunction, discovered: dict[int, _AngrBlock]) -> None:
    """Emit the graph-repair finish diagnostics for a function."""
    transition_graph = _dynamic_attr(function, "transition_graph", None)
    graph_nodes = tuple(_dynamic_attr(transition_graph, "nodes", ()) or ())
    logging.getLogger(__name__).warning(
        "x86-16 graph repair finish discovered=%r local_blocks=%r graph_nodes=%r function_blocks=%r",
        tuple(hex(address) for address in sorted(discovered)),
        tuple(sorted((_dynamic_attr(function, "_local_blocks", {}) or {}).keys())),
        tuple(sorted(_dynamic_attr(node, "addr", -1) for node in graph_nodes)),
        tuple(sorted(_dynamic_attr(block, "addr", -1) for block in tuple(_dynamic_attr(function, "blocks", ()) or ()))),
    )


@dataclass
class _GraphRepairScanBounds8616:
    """Resolved linear-scan window for x86-16 graph repair."""

    start_bound: int
    end_bound: int
    scan_limit: int

    def contains(self, addr: int) -> bool:
        """Return whether an address lies inside the repair scan window."""
        return isinstance(addr, int) and self.start_bound <= addr < self.end_bound


@dataclass
class _GraphRepairDiscovery8616:
    """Discovered blocks, edges, and indirect-jump evidence for graph repair."""

    blocks: dict[int, _AngrBlock]
    edges: set[tuple[int, int]]
    indirect_artifact: object | None


def _graph_repair_entry_addr_8616(project: angr.Project, function: _AngrFunction) -> int | None:
    """Apply the arch/entry/graph entry gates and return the entry address."""
    if _dynamic_attr(project, "arch", None) is None or _dynamic_attr(project.arch, "name", None) != "86_16":
        return None
    entry_addr = _dynamic_attr(function, "addr", None)
    if not isinstance(entry_addr, int):
        return None
    # Dynamic angr boundary: synthetic recovery candidates may not own a graph.
    if _dynamic_attr(function, "transition_graph", None) is None:
        return None
    return entry_addr


def _graph_repair_block_addrs_8616(
    function: _AngrFunction, debug_indirect: bool
) -> tuple[list[int], int] | None:
    """Apply the repair gates and collect sorted existing block addresses."""
    if bool(_dynamic_attr(function, "returning", None)):
        if debug_indirect:
            logging.getLogger(__name__).warning("x86-16 graph repair refused: function already returning")
        return None

    existing_ret_sites = tuple(_dynamic_attr(function, "ret_sites", ()) or ())
    if existing_ret_sites:
        if debug_indirect:
            logging.getLogger(__name__).warning("x86-16 graph repair refused: existing return sites")
        return None

    existing_blocks = tuple(_dynamic_attr(function, "blocks", ()) or ())
    if not existing_blocks:
        if debug_indirect:
            logging.getLogger(__name__).warning("x86-16 graph repair refused: no existing blocks")
        return None

    block_addrs = sorted(
        addr for addr in (_dynamic_attr(block, "addr", None) for block in existing_blocks) if isinstance(addr, int)
    )
    if not block_addrs:
        return None

    seed_max_byte = sum(max(0, int(_dynamic_attr(block, "size", 0) or 0)) for block in existing_blocks)
    return block_addrs, seed_max_byte


def _graph_repair_scan_bounds_8616(
    entry_addr: int,
    exact_region: tuple[int, int] | None,
    block_addrs: list[int],
    seed_max_byte: int,
) -> _GraphRepairScanBounds8616:
    """Resolve the linear-scan window for graph repair traversal."""
    if exact_region is not None and exact_region[0] <= entry_addr < exact_region[1]:
        start_bound = exact_region[0]
        exact_size = max(1, exact_region[1] - exact_region[0])
        scan_limit = max(0x200, min(0x2000, exact_size * 4))
        end_bound = start_bound + scan_limit
    else:
        scan_limit = max(0x200, min(0x2000, max(0x200, seed_max_byte * 4)))
        start_bound = max(min(block_addrs), entry_addr - 0x100)
        end_bound = max(block_addrs) + scan_limit
    return _GraphRepairScanBounds8616(start_bound, end_bound, scan_limit)


def _discover_graph_repair_region_8616(
    project: angr.Project,
    entry_addr: int,
    bounds: _GraphRepairScanBounds8616,
    debug_indirect: bool,
) -> _GraphRepairDiscovery8616:
    """BFS over the scan window to discover repair blocks and edges."""
    discovered: dict[int, _AngrBlock] = {}
    edges: set[tuple[int, int]] = set()
    queue: list[int] = [entry_addr]
    visited: set[int] = set()
    visited_bytes = 0
    limit_nodes = 512
    seen_targets: set[int] = set()

    indirect_artifact = None
    while True:
        while queue and len(visited) < limit_nodes and visited_bytes <= bounds.scan_limit:
            visited_bytes = _scan_repair_block_8616(
                project, queue, visited, visited_bytes, bounds, discovered, edges, seen_targets
            )

        indirect_artifact = collect_constant_indirect_jump_edges_8616(
            project,
            blocks=tuple(discovered.values()),
            successor_edges=tuple(edges),
            region_start=bounds.start_bound,
            region_end=bounds.end_bound,
        )
        if debug_indirect:
            logging.getLogger(__name__).warning(
                "x86-16 indirect jump artifact function=%#x records=%r edges=%r",
                entry_addr,
                indirect_artifact.records,
                indirect_artifact.resolved_edges,
            )
        queued_indirect_target = False
        for source_addr, target_addr in indirect_artifact.resolved_edges:
            edges.add((source_addr, target_addr))
            if target_addr not in visited and target_addr not in seen_targets:
                queue.append(target_addr)
                seen_targets.add(target_addr)
                queued_indirect_target = True
        if not queued_indirect_target:
            break
    return _GraphRepairDiscovery8616(discovered, edges, indirect_artifact)


def _scan_repair_block_8616(
    project: angr.Project,
    queue: list[int],
    visited: set[int],
    visited_bytes: int,
    bounds: _GraphRepairScanBounds8616,
    discovered: dict[int, _AngrBlock],
    edges: set[tuple[int, int]],
    seen_targets: set[int],
) -> int:
    """Pop and scan one repair block, queueing successors; returns new byte count."""
    block_addr = queue.pop(0)
    if block_addr in visited or not bounds.contains(block_addr):
        return visited_bytes
    visited.add(block_addr)
    try:
        block = project.factory.block(block_addr, opt_level=0)
    except Exception:
        return visited_bytes
    block_size = int(_dynamic_attr(block, "size", 0))
    if block_size <= 0:
        return visited_bytes
    visited_bytes += block_size
    if visited_bytes > bounds.scan_limit:
        return visited_bytes
    discovered[block_addr] = block
    insns = tuple(_dynamic_attr(_dynamic_attr(block, "capstone", None), "insns", ()) or ())
    if not insns:
        return visited_bytes
    successors, _is_direct_exit = _x86_16_block_successors_from_capstone_8616(
        block,
        region_start=bounds.start_bound,
        region_end=bounds.end_bound,
    )
    for succ in successors:
        if bounds.contains(succ) and succ not in seen_targets:
            queue.append(succ)
            seen_targets.add(succ)
        edges.add((block_addr, succ))
    return visited_bytes


def _seed_graph_repair_node_cache_8616(function: _AngrFunction, block_node_cls: _AngrObject) -> None:
    """Pre-seed the function's addr→BlockNode cache from local blocks."""
    try:
        local_blocks = _dynamic_attr(function, "_local_blocks", None)
        if isinstance(local_blocks, dict):
            for node in local_blocks.values():
                if isinstance(node, block_node_cls):
                    function._update_addr_to_block_cache(node)
    except Exception:
        return


def _ensure_repair_block_node_8616(
    function: _AngrFunction,
    block_node_cls: _AngrObject,
    discovered: dict[int, _AngrBlock],
    block_addr: int,
    debug_indirect: bool,
) -> object | None:
    """Resolve or register a BlockNode for one discovered repair block."""
    if not isinstance(block_addr, int):
        return None

    node = function.get_node(block_addr)
    if node is not None:
        node_object: object = node
        return node_object

    local_blocks = _dynamic_attr(function, "_local_blocks", None)
    if isinstance(local_blocks, dict):
        candidate = local_blocks.get(block_addr)
        if isinstance(candidate, block_node_cls):
            function._update_addr_to_block_cache(candidate)
            resolved_node: object = function.get_node(block_addr) or candidate
            return resolved_node

    discovered_block = discovered.get(block_addr)
    if discovered_block is None:
        return None

    block_size = int(_dynamic_attr(discovered_block, "size", 0))
    if block_size <= 0:
        return None

    try:
        new_node = block_node_cls(
            block_addr,
            block_size,
            bytestr=_dynamic_attr(discovered_block, "bytes", None),
        )
        function._register_node(True, new_node)
        function._update_addr_to_block_cache(new_node)
        new_node_object: object = new_node
        return new_node_object
    except Exception as ex:
        if debug_indirect:
            logging.getLogger(__name__).warning(
                "x86-16 graph repair could not register block=%#x: %s",
                block_addr,
                ex,
            )
        return None


def _install_repair_edges_8616(
    function: _AngrFunction,
    block_node_cls: _AngrObject,
    discovery: _GraphRepairDiscovery8616,
    debug_indirect: bool,
) -> None:
    """Install discovered edges into the function transition graph."""
    for source_addr, target_addr in sorted(discovery.edges):
        source_node = _ensure_repair_block_node_8616(
            function, block_node_cls, discovery.blocks, source_addr, debug_indirect
        )
        target_node = _ensure_repair_block_node_8616(
            function, block_node_cls, discovery.blocks, target_addr, debug_indirect
        )
        if source_node is None:
            continue
        if target_node is None:
            continue
        try:
            source_capstone = _dynamic_attr(discovery.blocks[source_addr], "capstone", None)
            insns = tuple(_dynamic_attr(source_capstone, "insns", ()) or ())
            ins_addr = int(_dynamic_attr(insns[-1], "address", source_addr))
        except Exception:
            ins_addr = source_addr
        try:
            function._transit_to(source_node, target_node, ins_addr=ins_addr)
        except Exception:
            continue


def _install_repair_return_sites_8616(
    function: _AngrFunction, discovered: dict[int, _AngrBlock]
) -> int:
    """Mark discovered blocks ending in a return as function return sites."""
    discovered_returns = 0
    for block_addr in sorted(discovered):
        source_node = function.get_node(block_addr)
        if source_node is None:
            continue
        block = discovered[block_addr]
        block_insns = tuple(_dynamic_attr(_dynamic_attr(block, "capstone", None), "insns", ()) or ())
        if not block_insns:
            continue
        last_mnemonic = str(_dynamic_attr(block_insns[-1], "mnemonic", "")).lower()
        if last_mnemonic in {"ret", "retf", "iret", "retw", "iretq"}:
            with contextlib.suppress(Exception):
                function._add_return_site(source_node)
                discovered_returns += 1
    return discovered_returns


def _count_region_local_functions(cfg: _AngrCfg, exact_region: tuple[int, int] | None) -> int:
    if exact_region is None or cfg is None:
        return 0
    functions = _dynamic_attr(cfg, "functions", None)
    if functions is None:
        return 0
    start, end = exact_region
    return sum(1 for addr in functions if isinstance(addr, int) and start <= addr < end)


def _best_region_function_candidate(
    cfg: _AngrCfg,
    *,
    exact_region: tuple[int, int] | None,
    preferred_addr: int | None,
) -> _AngrFunction | None:
    def _impl() -> _AngrFunction | None:
        if cfg is None or exact_region is None:
            return None
        functions = _dynamic_attr(cfg, "functions", None)
        if functions is None:
            return None
        start, end = exact_region
        best: _AngrFunction | None = None
        best_rank: tuple[int, int, int, int] | None = None
        for candidate in functions.values():
            caddr = _dynamic_attr(candidate, "addr", None)
            if not isinstance(caddr, int) or not (start <= caddr < end):
                continue
            c_blocks, c_bytes = _function_recovery_score(candidate)
            c_truncated = _function_recovery_truncated(candidate)
            # Prefer non-truncated, semantically richer region-local bodies.
            distance = abs(caddr - preferred_addr) if isinstance(preferred_addr, int) else 0
            rank = (0 if not c_truncated else 1, -c_bytes, -c_blocks, distance)
            if best is None or best_rank is None or rank < best_rank:
                best = candidate
                best_rank = rank
        return best

    return _impl()


def _function_recovery_truncated(function: _AngrFunction) -> bool:
    info = _dynamic_attr(function, "info", None)
    return isinstance(info, dict) and bool(info.get("x86_16_recovery_truncated"))


def _needs_pre_entry_body_supplement(function: _AngrFunction, project_entry: int) -> bool:
    addr = _dynamic_attr(function, "addr", None)
    if not isinstance(addr, int) or addr >= project_entry:
        return False
    return _function_recovery_truncated(function) or _function_recovery_score(function)[1] <= 0x20


def _prioritized_pre_entry_follow_on_targets(
    project: angr.Project,
    function_cfg_pairs: list[_FunctionCfgPair],
    *,
    covered_ranges: list[tuple[int, int]],
    existing_addrs: set[int],
    image_end: int,
) -> list[int]:
    main_object = _dynamic_attr(project.loader, "main_object", None)
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    if not isinstance(linked_base, int):
        return []

    prioritized: list[int] = []
    queued = set(existing_addrs)

    def _record(target_addrs: Iterable[object]) -> None:
        _record_follow_on_targets_8616(
            prioritized, queued, target_addrs, covered_ranges, linked_base, image_end
        )

    gap_candidates = _rank_gap_scan_candidate_addrs(
        project,
        function_cfg_pairs,
        covered_ranges,
        queued,
        image_end=image_end,
    )
    _record(gap_candidates)

    pre_entry_functions = [
        function
        for _cfg, function in function_cfg_pairs
        if _needs_pre_entry_body_supplement(function, _dynamic_attr(project, "entry", 0))
    ]
    for function in pre_entry_functions:
        _record(_linear_function_seed_targets(project, function.addr, include_jumps=False))

    for function in pre_entry_functions:
        neighbor_targets: list[int] = []
        for target in collect_neighbor_call_targets(function):
            target_addr = _dynamic_attr(target, "target_addr", None)
            if isinstance(target_addr, int):
                neighbor_targets.append(target_addr)
        _record(neighbor_targets)

    return prioritized


def _record_follow_on_targets_8616(
    prioritized: list[int],
    queued: set[int],
    target_addrs: Iterable[object],
    covered_ranges: list[tuple[int, int]],
    linked_base: int,
    image_end: int,
) -> None:
    """Append novel in-image follow-on targets to the prioritized list."""
    for target_addr in target_addrs:
        if not isinstance(target_addr, int):
            continue
        if target_addr in queued or _addr_in_ranges(target_addr, covered_ranges):
            continue
        if not (linked_base <= target_addr < image_end):
            continue
        prioritized.append(target_addr)
        queued.add(target_addr)


def _mark_function_recovery_truncated(function: _AngrFunction, truncated: bool) -> None:
    info = _dynamic_attr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_recovery_truncated"] = truncated


@cast(Callable[..., Any], trace_function(name="discovery.recover_candidate"))
def _recover_candidate_function_pair(
    candidate_project: angr.Project,
    *,
    candidate_addr: int,
    image_end: int,
    metadata: LSTMetadata | None,
    project_entry: int,
    region_span: int,
    exact_region: tuple[int, int] | None = None,
    seed_calling_conventions_enabled: bool = True,
) -> _FunctionCfgPair:
    """Recover one candidate without widening explicit function boundaries."""
    def _impl() -> _FunctionCfgPair:
        block = candidate_project.factory.block(candidate_addr, size=8, opt_level=0)
        insns = block.capstone.insns
        if len(insns) < 1:
            raise KeyError(f"Function {candidate_addr:#x} does not have a valid first instruction.")
        bounded_exact_region = exact_region or _lst_code_region(metadata, candidate_addr)
        candidate_regions = (
            [bounded_exact_region]
            if bounded_exact_region is not None
            else _candidate_recovery_regions(
                metadata,
                candidate_addr,
                image_end=image_end,
                region_span=region_span,
                project_entry=project_entry,
            )
        )
        best_pair, best_score, last_error = _scan_candidate_regions_8616(
            candidate_project,
            candidate_addr,
            candidate_regions,
            project_entry,
            seed_calling_conventions_enabled,
        )
        best_pair, best_score, _ = _stitch_candidate_pair_8616(
            candidate_project, best_pair, exact_region, best_score, candidate_addr
        )
        truncated = False
        if (
            best_pair is not None
            and bounded_exact_region is not None
            and _exact_region_recovery_looks_truncated(best_pair[1], bounded_exact_region)
        ):
            truncated = True
            best_pair, best_score, stitched = _stitch_candidate_pair_8616(
                candidate_project, best_pair, bounded_exact_region, best_score, candidate_addr
            )
            if stitched:
                truncated = False
            bounded_region = (
                bounded_exact_region
                if exact_region is not None
                else _richest_bounded_recovery_region(
                    candidate_addr,
                    image_end=image_end,
                    region_span=region_span,
                )
            )
            richer = _recover_richer_bounded_pair_8616(
                candidate_project,
                candidate_addr,
                bounded_region,
                best_score,
                seed_calling_conventions_enabled,
                last_error,
            )
            richer_best_pair, richer_best_score, last_error = richer
            if richer_best_pair is not None:
                best_pair = richer_best_pair
                best_score = richer_best_score
                truncated = False
        small_unbounded_candidate = bounded_exact_region is None and best_score[1] <= 0x20
        if best_pair is not None and candidate_addr < project_entry and small_unbounded_candidate and candidate_regions:
            truncated = True
            best_pair, best_score, last_error = _recover_small_unbounded_pair_8616(
                candidate_project,
                candidate_addr,
                best_pair,
                best_score,
                image_end,
                region_span,
                seed_calling_conventions_enabled,
                last_error,
            )
        return _finalize_candidate_pair_8616(
            candidate_project,
            candidate_addr,
            best_pair,
            truncated,
            bounded_exact_region,
            exact_region,
            last_error,
        )

    return _impl()


def _scan_candidate_regions_8616(
    candidate_project: angr.Project,
    candidate_addr: int,
    candidate_regions: list[tuple[int, int]],
    project_entry: int,
    seed_calling_conventions_enabled: bool,
) -> tuple[_FunctionCfgPair | None, tuple[int, int], Exception | None]:
    """Scan candidate regions and return the best-scoring recovered pair."""
    best_pair: _FunctionCfgPair | None = None
    best_score = (-1, -1)
    last_error: Exception | None = None
    for candidate_region in candidate_regions:
        try:
            recovered_pair = _pick_function_lean(
                candidate_project,
                candidate_addr,
                regions=[candidate_region],
                data_references=False,
                extend_far_calls=False,
                seed_calling_conventions_enabled=seed_calling_conventions_enabled,
            )
            score = _function_recovery_score(recovered_pair[1])
            if score > best_score:
                best_pair = recovered_pair
                best_score = score
            if _recovery_score_good_enough(score) and not (
                candidate_addr < project_entry and score[1] <= 0x20 and candidate_region != candidate_regions[-1]
            ):
                break
        except Exception as exc:
            last_error = exc
            continue
    return best_pair, best_score, last_error


def _stitch_candidate_pair_8616(
    candidate_project: angr.Project,
    best_pair: _FunctionCfgPair | None,
    region: tuple[int, int] | None,
    best_score: tuple[int, int],
    candidate_addr: int,
) -> tuple[_FunctionCfgPair | None, tuple[int, int], bool]:
    """Attempt an exact-region stitch and refresh the pair/score on success."""
    if best_pair is None or region is None:
        return best_pair, best_score, False
    try:
        stitched_func, stitched = _stitch_x86_16_exact_function_8616(
            candidate_project,
            best_pair[1],
            region,
        )
        if stitched:
            best_pair = (best_pair[0], stitched_func)
            _mark_x86_16_stitched_recovery_8616(stitched_func)
            best_score = _function_recovery_score(stitched_func)
            return best_pair, best_score, True
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "x86-16 explicit candidate-pair stitching failed for %s: %s",
            hex(candidate_addr),
            ex,
        )
    return best_pair, best_score, False


def _recover_richer_bounded_pair_8616(
    candidate_project: angr.Project,
    candidate_addr: int,
    bounded_region: tuple[int, int],
    best_score: tuple[int, int],
    seed_calling_conventions_enabled: bool,
    last_error: Exception | None,
) -> tuple[_FunctionCfgPair | None, tuple[int, int], Exception | None]:
    """Retry recovery inside a bounded region across data-reference modes."""
    richer_best_pair: _FunctionCfgPair | None = None
    richer_best_score = best_score
    for data_references in (False, True):
        try:
            richer_pair = _pick_function(
                candidate_project,
                candidate_addr,
                regions=[bounded_region],
                data_references=data_references,
                force_smart_scan=False,
                seed_calling_conventions_enabled=seed_calling_conventions_enabled,
            )
        except Exception as exc:
            last_error = exc
            continue
        richer_score = _function_recovery_score(richer_pair[1])
        if richer_score > richer_best_score:
            richer_best_pair = richer_pair
            richer_best_score = richer_score
    return richer_best_pair, richer_best_score, last_error


def _recover_small_unbounded_pair_8616(
    candidate_project: angr.Project,
    candidate_addr: int,
    best_pair: _FunctionCfgPair | None,
    best_score: tuple[int, int],
    image_end: int,
    region_span: int,
    seed_calling_conventions_enabled: bool,
    last_error: Exception | None,
) -> tuple[_FunctionCfgPair | None, tuple[int, int], Exception | None]:
    """Retry a small unbounded pre-entry candidate inside the richest region."""
    try:
        richer_pair = _pick_function(
            candidate_project,
            candidate_addr,
            regions=[
                _richest_bounded_recovery_region(candidate_addr, image_end=image_end, region_span=region_span)
            ],
            data_references=True,
            force_smart_scan=False,
            seed_calling_conventions_enabled=seed_calling_conventions_enabled,
        )
        richer_score = _function_recovery_score(richer_pair[1])
        if richer_score > best_score:
            best_pair = richer_pair
            best_score = richer_score
    except Exception as exc:
        last_error = exc
    return best_pair, best_score, last_error


def _finalize_candidate_pair_8616(
    candidate_project: angr.Project,
    candidate_addr: int,
    best_pair: _FunctionCfgPair | None,
    truncated: bool,
    bounded_exact_region: tuple[int, int] | None,
    exact_region: tuple[int, int] | None,
    last_error: Exception | None,
) -> _FunctionCfgPair:
    """Repair, mark, and return the best pair; otherwise raise the last error."""
    if best_pair is not None:
        _repair_x86_16_function_graph_8616(
            candidate_project,
            best_pair[1],
            exact_region=bounded_exact_region or exact_region,
        )
        if bounded_exact_region is not None:
            _mark_function_binary_exact_region_8616(best_pair[1], bounded_exact_region)
        _mark_function_recovery_truncated(best_pair[1], truncated)
        return best_pair
    if last_error is not None:
        raise last_error
    raise KeyError(f"Function {candidate_addr:#x} was not recovered.")


def _interesting_functions(cfg: _AngrCfg, *, limit: int | None) -> tuple[list[object], int]:
    functions = []
    skipped = 0
    for function in sorted(cfg.functions.values(), key=lambda function: function.addr):
        if function.is_plt or function.name.startswith("Unresolvable"):
            continue
        reason = _function_skip_reason(function)
        if reason is not None:
            print(f"[dbg] skipping {function.addr:#x} {function.name}: {reason}")
            skipped += 1
            continue
        functions.append(function)
    total = len(functions) + skipped
    if limit is not None and limit > 0:
        functions = functions[:limit]
    return functions, total


def _function_complexity_local(function: _AngrFunction) -> tuple[int, int]:
    """Best-effort complexity from dynamic angr function fields."""
    blocks = tuple(_dynamic_attr(function, "blocks", ()) or ())
    if blocks:
        count = len(blocks)
        total = 0
        for block in blocks:
            size = _dynamic_attr(block, "size", 0)
            if isinstance(size, int) and size > 0:
                total += size
        return count, total
    block_addrs = tuple(_dynamic_attr(function, "block_addrs_set", ()) or ())
    if block_addrs:
        return len(block_addrs), 0
    return 0, 0


_function_complexity = _function_complexity_local


def _rank_function_cfg_pairs_for_display(
    project: angr.Project,
    function_cfg_pairs: list[_FunctionCfgPair],
) -> list[_FunctionCfgPair]:
    if not function_cfg_pairs:
        return []
    entry_addr = _dynamic_attr(project, "entry", None)
    if not isinstance(entry_addr, int):
        return function_cfg_pairs
    direct_entry_targets = _linear_function_seed_targets(project, entry_addr, max_scan=0x180, include_jumps=False)

    body_seed_candidates = [
        item
        for item in function_cfg_pairs
        if isinstance(_dynamic_attr(item[1], "addr", None), int) and item[1].addr < entry_addr
    ]
    state = _DisplayRankState8616(entry_addr, direct_entry_targets, None, set())
    primary_body_seed = (
        min(body_seed_candidates, key=state.body_seed_rank)[1].addr if body_seed_candidates else None
    )
    state.primary_body_seed = primary_body_seed
    state.body_targets = (
        _linear_function_seed_targets(project, primary_body_seed, include_jumps=False)
        if isinstance(primary_body_seed, int)
        else set()
    )

    return sorted(function_cfg_pairs, key=state.priority)


@dataclass
class _DisplayRankState8616:
    """Rank inputs shared by the display-ordering key functions."""

    entry_addr: int
    direct_entry_targets: set[int]
    primary_body_seed: int | None
    body_targets: set[int]

    def display_metrics(self, function: _AngrFunction) -> tuple[int, int]:
        """Merge complexity and recovery metrics for display ranking."""
        complexity_blocks, complexity_bytes = _function_complexity_local(function)
        recovery_blocks, recovery_bytes = _function_recovery_score(function)
        return (max(complexity_blocks, recovery_blocks), max(complexity_bytes, recovery_bytes))

    def body_seed_rank(self, item: _FunctionCfgPair) -> tuple[int, int, int, int, int]:
        """Rank a candidate for the primary pre-entry body seed."""
        _cfg, function = item
        addr = _dynamic_attr(function, "addr", None)
        block_count, byte_count = self.display_metrics(function)
        tiny_wrapper_like = int(block_count <= 3 and byte_count <= 0x20 and not _function_recovery_truncated(function))
        direct_entry_rank = 0 if isinstance(addr, int) and addr in self.direct_entry_targets else 1
        truncation_rank = 0 if _function_recovery_truncated(function) else 1
        distance = abs(addr - self.entry_addr) if isinstance(addr, int) else 0
        return (tiny_wrapper_like, truncation_rank, direct_entry_rank, -byte_count, distance)

    def meaningful_pre_entry_body(self, addr: int | None, byte_count: int, truncated: bool) -> bool:
        """Check whether a pre-entry function body is meaningful enough to rank early."""
        return (
            isinstance(addr, int)
            and addr < self.entry_addr
            and (truncated or byte_count > 0x20)
        )

    def priority(self, item: _FunctionCfgPair) -> tuple[int, int, int, int, int]:
        """Compute the display sort key for one recovered pair."""
        _cfg, function = item
        addr = _dynamic_attr(function, "addr", 0)
        block_count, byte_count = self.display_metrics(function)
        truncated = _function_recovery_truncated(function)
        tiny_wrapper_like = int(block_count <= 3 and byte_count <= 0x20 and not truncated)
        meaningful_pre_entry_body = self.meaningful_pre_entry_body(addr, byte_count, truncated)
        if addr == self.entry_addr:
            bucket = 0
        elif isinstance(self.primary_body_seed, int) and addr == self.primary_body_seed:
            bucket = 1
        elif meaningful_pre_entry_body and addr in self.body_targets:
            bucket = 2
        elif meaningful_pre_entry_body:
            bucket = 3
        elif addr in self.body_targets:
            bucket = 4
        elif addr in self.direct_entry_targets:
            bucket = 5
        elif isinstance(addr, int) and addr < self.entry_addr:
            bucket = 6
        else:
            bucket = 7
        distance = abs(addr - self.entry_addr) if isinstance(addr, int) else 0
        return (bucket, tiny_wrapper_like, block_count, byte_count, distance)


def _expanded_exe_discovery_limit(limit: int | None) -> int | None:
    if limit is None or limit <= 0:
        return None
    return max(limit * 2, limit + 4)


def _supplement_cached_seeded_recovery(
    project: angr.Project,
    cached_recovered: list[_FunctionCfgPair],
    cached_addrs: list[int],
    *,
    region_span: int,
    per_function_timeout: int,
    limit: int | None,
    cache_key: dict[str, object] | None,
) -> tuple[list[_FunctionCfgPair], list[int]]:
    def _impl() -> tuple[list[_FunctionCfgPair], list[int]]:
        nonlocal cached_recovered, cached_addrs
        cached_seen = {
            function.addr
            for _cfg, function in cached_recovered
            if isinstance(_dynamic_attr(function, "addr", None), int)
        }
        cached_covered_ranges: list[tuple[int, int]] = []
        for _cfg, function in cached_recovered:
            cached_covered_ranges.extend(_function_covered_ranges(function))
        cached_pre_entry = [
            function
            for _cfg, function in cached_recovered
            if isinstance(_dynamic_attr(function, "addr", None), int) and function.addr < project.entry
        ]
        needs_body_supplement = not cached_pre_entry or all(
            _function_recovery_truncated(function) or _function_recovery_score(function)[1] <= 0x20
            for function in cached_pre_entry
        )
        if not needs_body_supplement:
            return cached_recovered, cached_addrs

        supplemental_pairs = _collect_supplement_pairs_8616(
            project,
            cached_recovered,
            cached_addrs,
            cached_covered_ranges,
            region_span=region_span,
            limit=limit,
            per_function_timeout=per_function_timeout,
        )
        if not supplemental_pairs:
            return cached_recovered, cached_addrs

        return _merge_supplement_pairs_8616(
            project,
            cached_recovered,
            cached_addrs,
            cached_seen,
            supplemental_pairs,
            cache_key,
        )

    return _impl()


def _collect_supplement_pairs_8616(
    project: angr.Project,
    cached_recovered: list[_FunctionCfgPair],
    cached_addrs: list[int],
    cached_covered_ranges: list[tuple[int, int]],
    *,
    region_span: int,
    limit: int | None,
    per_function_timeout: int,
) -> list[_FunctionCfgPair]:
    """Collect supplemental pairs via prioritized targets, else prologue scan."""
    main_object = _dynamic_attr(project.loader, "main_object", None)
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    image_end = linked_base + max_addr + 1 if isinstance(linked_base, int) and isinstance(max_addr, int) else None
    supplemental_pairs: list[_FunctionCfgPair] = []
    if image_end is not None:
        prioritized_candidates = _prioritized_pre_entry_follow_on_targets(
            project,
            cached_recovered,
            covered_ranges=cached_covered_ranges,
            existing_addrs=set(cached_addrs) | {project.entry},
            image_end=image_end,
        )
        if prioritized_candidates:
            supplemental_pairs = _supplement_functions_from_prologue_scan(
                project,
                set(cached_addrs),
                candidate_addrs=prioritized_candidates,
                region_span=region_span,
                recover_limit=1 if limit is None else max(1, min(limit, 2)),
                per_function_timeout=per_function_timeout,
            )
    if not supplemental_pairs:
        supplemental_pairs = _supplement_functions_from_prologue_scan(
            project,
            set(cached_addrs),
            region_span=region_span,
            recover_limit=1 if limit is None else max(1, min(limit, 2)),
            per_function_timeout=per_function_timeout,
        )
    return supplemental_pairs


def _merge_supplement_pairs_8616(
    project: angr.Project,
    cached_recovered: list[_FunctionCfgPair],
    cached_addrs: list[int],
    cached_seen: set[int],
    supplemental_pairs: list[_FunctionCfgPair],
    cache_key: dict[str, object] | None,
) -> tuple[list[_FunctionCfgPair], list[int]]:
    """Merge novel supplemental pairs and refresh the ranked catalog."""
    for function_cfg, function in supplemental_pairs:
        if function.addr in cached_seen:
            continue
        cached_recovered.append((function_cfg, function))
        cached_addrs.append(function.addr)
        cached_seen.add(function.addr)
    cached_recovered = _rank_function_cfg_pairs_for_display(project, cached_recovered)
    cached_addrs = [function.addr for _cfg, function in cached_recovered]
    if cache_key is not None:
        _store_cache_json("recovery", cache_key, {"addrs": cached_addrs})
    return cached_recovered, cached_addrs


def _catalog_address_cache_key_8616(
    project: angr.Project,
    binary_path: Path,
) -> dict[str, object] | None:
    """Build a display-catalog key from binary identity and discovery policy."""
    policy = _display_catalog_cache_policy_8616(project)
    return _cache_key_object(_recovery_cache_key(
        binary_path=binary_path,
        kind="display_catalog_addrs",
        source_scope=RecoveryCacheSourceScope8616.FUNCTION_DISCOVERY,
        extra={
            "entry": _dynamic_attr(project, "entry", None),
            "arch": _dynamic_attr(_dynamic_attr(project, "arch", None), "name", None),
            "display_catalog_policy": policy.cache_fields(),
        },
    ))


def _store_catalog_address_cache_addrs_8616(
    project: angr.Project,
    binary_path: Path,
    addrs: tuple[int, ...],
) -> None:
    """Persist exact catalog addresses and their currently closed evidence."""
    cache_key = _catalog_address_cache_key_8616(project, binary_path)
    if cache_key is None:
        return
    with _cache_key_lock("recovery", cache_key):
        merged_addrs = addrs
        merged_evidence = caller_return_use_evidence_by_addr_8616(project)
        source_region = _source_region_catalog_evidence_8616(project)
        cached = _load_cache_json("recovery", cache_key)
        try:
            cached_payload = display_catalog_cache_payload_from_record_8616(cached)
        except ValueError:
            pass
        else:
            merged_addrs = tuple(dict.fromkeys((*cached_payload.addrs, *addrs)))
            merged_evidence = {
                **cached_payload.caller_return_use_by_addr(),
                **merged_evidence,
            }
            if source_region is None:
                source_region = cached_payload.source_region
        try:
            payload = display_catalog_cache_record_8616(
                merged_addrs,
                merged_evidence,
                source_region,
            )
        except ValueError:
            return
        _store_cache_json("recovery", cache_key, payload)


def _store_catalog_address_cache(
    project: angr.Project,
    binary_path: Path,
    function_cfg_pairs: list[_FunctionCfgPair],
) -> None:
    """Persist recovered function addresses with their exact typed evidence."""
    addrs = tuple(
        function_addr
        for _cfg, function in function_cfg_pairs
        if isinstance((function_addr := _dynamic_attr(function, "addr", None)), int)
    )
    _store_catalog_address_cache_addrs_8616(project, binary_path, addrs)


def _load_catalog_address_cache(project: angr.Project, binary_path: Path) -> list[int]:
    """Restore a display catalog only when its typed evidence contract validates."""
    cache_key = _catalog_address_cache_key_8616(project, binary_path)
    cached = _load_cache_json("recovery", cache_key) if cache_key is not None else None
    try:
        payload = display_catalog_cache_payload_from_record_8616(cached)
    except ValueError:
        return []
    for function_addr, evidence in payload.caller_return_use:
        _record_caller_return_use_evidence_8616(project, function_addr, evidence)
    if payload.source_region is not None:
        cast(Any, project)._inertia_source_region_catalog_evidence = payload.source_region
    return list(payload.addrs)


def _supplement_functions_from_prologue_scan(
    project: angr.Project,
    existing_addrs: set[int],
    *,
    candidate_addrs: list[int] | None = None,
    search_span: int = 0x2000,
    region_span: int = 0x120,
    scan_limit: int = 8,
    recover_limit: int = 1,
    per_function_timeout: int = 2,
) -> list[_FunctionCfgPair]:
    def _impl() -> list[_FunctionCfgPair]:
        if project.arch.name != "86_16":
            return []

        ranked_candidates = (
            candidate_addrs
            if candidate_addrs is not None
            else _rank_prologue_scan_candidate_addrs(
                project,
                existing_addrs,
                search_span=search_span,
            )
        )
        ctx = _prologue_scan_context_8616(project, ranked_candidates)
        if ctx is None:
            return []

        supplemental = _scan_prologue_candidates_8616(
            project,
            ctx,
            existing_addrs,
            region_span=region_span,
            scan_limit=scan_limit,
            recover_limit=recover_limit,
            per_function_timeout=per_function_timeout,
        )
        if supplemental:
            print(f"/* supplemental prologue scan recovered {len(supplemental)} additional function(s) near entry. */")
        return supplemental

    return _impl()


@dataclass
class _PrologueScanCtx8616:
    """Resolved inputs for the supplemental prologue scan."""

    ranked_candidates: list[int]
    linked_base: int
    binary_path: _AngrObject
    code: bytes


def _prologue_scan_context_8616(
    project: angr.Project, ranked_candidates: list[int] | None
) -> _PrologueScanCtx8616 | None:
    """Resolve ranked candidates, image base, and loaded code for the scan."""
    if not ranked_candidates:
        return None
    main_object = _dynamic_attr(project.loader, "main_object", None)
    if main_object is None:
        return None
    main_object = cast(_AngrObject, main_object)
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    binary_path = _dynamic_attr(main_object, "binary", None)
    if not isinstance(linked_base, int):
        return None
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    if not isinstance(max_addr, int):
        return None
    try:
        code = bytes(main_object.memory.load(0, max_addr + 1))
    except Exception:
        return None
    return _PrologueScanCtx8616(list(ranked_candidates), linked_base, binary_path, code)


def _recover_prologue_candidate_8616(
    project: angr.Project,
    ctx: _PrologueScanCtx8616,
    candidate_addr: int,
    region_span: int,
) -> _FunctionCfgPair:
    """Recover one prologue candidate in a bounded region."""
    candidate_project = project
    if ctx.binary_path is not None:
        candidate_project = _build_project_cached(
            str(Path(ctx.binary_path)),
            force_blob=False,
            base_addr=ctx.linked_base,
            entry_point=project.entry,
        )
    return _pick_function_lean(
        candidate_project,
        candidate_addr,
        regions=[
            (
                candidate_addr,
                min(candidate_addr + region_span, ctx.linked_base + len(ctx.code)),
            )
        ],
        data_references=False,
        extend_far_calls=False,
    )


def _scan_prologue_candidates_8616(
    project: angr.Project,
    ctx: _PrologueScanCtx8616,
    existing_addrs: set[int],
    *,
    region_span: int,
    scan_limit: int,
    recover_limit: int,
    per_function_timeout: int,
) -> list[_FunctionCfgPair]:
    """Try each ranked candidate with a per-candidate timeout."""
    supplemental: list[_FunctionCfgPair] = []
    scanned = 0
    for addr in ctx.ranked_candidates:
        if len(supplemental) >= recover_limit or scanned >= scan_limit:
            break
        scanned += 1
        try:
            function_cfg, function = _run_with_timeout_in_daemon_thread(
                lambda addr=addr: _recover_prologue_candidate_8616(project, ctx, addr, region_span),
                timeout=per_function_timeout,
                thread_name_prefix="supplement",
            )
        except FuturesTimeoutError:
            continue
        except Exception:
            continue

        if function.addr in existing_addrs:
            continue
        reason = _function_skip_reason(function)
        if reason is not None:
            continue
        existing_addrs.add(function.addr)
        supplemental.append((function_cfg, function))
    return supplemental


def _rank_gap_scan_candidate_addrs(
    project: angr.Project,
    recovered_function_pairs: list[_FunctionCfgPair],
    covered_ranges: list[tuple[int, int]],
    existing_addrs: set[int],
    *,
    image_end: int,
    search_span: int = 0x2000,
) -> list[int]:
    if project.arch.name != "86_16":
        return []
    if _dynamic_attr(_dynamic_attr(project, "arch", None), "capstone", None) is None:
        return []

    main_object = _dynamic_attr(project.loader, "main_object", None)
    if main_object is None:
        return []

    max_addr = _dynamic_attr(main_object, "max_addr", None)
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    if not isinstance(max_addr, int) or not isinstance(linked_base, int):
        return []

    merged_ranges = _normalize_and_merge_ranges_8616(covered_ranges, linked_base, image_end)
    gap_ranges = _compute_gap_ranges_8616(merged_ranges, linked_base, image_end)

    ranked_candidates: dict[int, tuple[int, int, int]] = {}

    def _record(addr: int, source_rank: int, gap_start: int, subrank: int) -> None:
        if not (linked_base <= addr < image_end):
            return
        if addr in existing_addrs or _addr_in_ranges(addr, merged_ranges):
            return
        current = ranked_candidates.get(addr)
        candidate = (source_rank, gap_start, subrank)
        if current is None or candidate < current:
            ranked_candidates[addr] = candidate

    _record_recovered_block_targets_8616(
        project,
        recovered_function_pairs,
        search_span=search_span,
        record=_record,
    )

    _record_gap_scan_candidates_8616(
        project,
        main_object,
        linked_base=linked_base,
        gap_ranges=gap_ranges,
        search_span=search_span,
        record=_record,
    )

    return [addr for addr, _meta in sorted(ranked_candidates.items(), key=lambda item: (*item[1], item[0]))]


def _normalize_and_merge_ranges_8616(
    covered_ranges: list[tuple[int, int]], linked_base: int, image_end: int
) -> list[tuple[int, int]]:
    merged_ranges: list[tuple[int, int]] = []
    for start, end in sorted(covered_ranges):
        start = max(linked_base, min(start, image_end))
        end = max(linked_base, min(end, image_end))
        if start >= end:
            continue
        if not merged_ranges or start > merged_ranges[-1][1]:
            merged_ranges.append((start, end))
        else:
            merged_ranges[-1] = (merged_ranges[-1][0], max(merged_ranges[-1][1], end))
    return merged_ranges


def _compute_gap_ranges_8616(
    merged_ranges: list[tuple[int, int]], linked_base: int, image_end: int
) -> list[tuple[int, int]]:
    gap_ranges: list[tuple[int, int]] = []
    cursor = linked_base
    for start, end in merged_ranges:
        if cursor < start:
            gap_ranges.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < image_end:
        gap_ranges.append((cursor, image_end))
    return gap_ranges


def _record_recovered_block_targets_8616(
    project: angr.Project,
    recovered_function_pairs: list[_FunctionCfgPair],
    *,
    search_span: int,
    record: Callable[[int, int, int, int], None],
) -> None:
    for _cfg, function in recovered_function_pairs:
        for block in tuple(_dynamic_attr(function, "blocks", ()) or ()):
            block_addr = _dynamic_attr(block, "addr", None)
            block_size = max(0, _dynamic_attr(block, "size", 0))
            if not isinstance(block_addr, int) or block_size <= 0:
                continue
            try:
                block_targets = _linear_function_seed_targets(
                    project,
                    block_addr,
                    max_scan=min(block_size, search_span),
                    include_jumps=False,
                )
            except Exception:
                continue
            for target_addr in block_targets:
                record(target_addr, 1, block_addr, target_addr)


def _looks_like_86_16_frame_prologue_8616(project: angr.Project, addr: int) -> bool:
    try:
        block = project.factory.block(addr, size=16, opt_level=0)
    except Exception:
        return False
    insns = block.capstone.insns
    return (
        len(insns) >= 2
        and insns[0].mnemonic == "push"
        and insns[0].op_str == "bp"
        and insns[1].mnemonic == "mov"
        and insns[1].op_str == "bp, sp"
    )


def _record_gap_scan_candidates_8616(
    project: angr.Project,
    main_object: _AngrObject,
    *,
    linked_base: int,
    gap_ranges: list[tuple[int, int]],
    search_span: int,
    record: Callable[[int, int, int, int], None],
) -> None:
    def _impl() -> None:
        for gap_start, gap_end in gap_ranges:
            _scan_gap_for_candidates_8616(
                project, main_object, linked_base, gap_start, gap_end, search_span, record
            )

    return _impl()


def _scan_gap_for_candidates_8616(
    project: angr.Project,
    main_object: _AngrObject,
    linked_base: int,
    gap_start: int,
    gap_end: int,
    search_span: int,
    record: Callable[[int, int, int, int], None],
) -> None:
    """Scan one gap region for prologue and post-return seed candidates."""
    align_bytes = {0x00, 0x90, 0xCC}
    scan_end = min(gap_end, gap_start + search_span)
    if scan_end - gap_start < 3:
        return
    try:
        gap_code = bytes(main_object.memory.load(gap_start - linked_base, scan_end - gap_start))
    except Exception:
        return
    offset = 0
    while offset <= len(gap_code) - 3:
        if gap_code[offset : offset + 3] == b"\x55\x8b\xec":
            addr = gap_start + offset
            if _looks_like_86_16_frame_prologue_8616(project, addr):
                record(addr, 0, gap_start, offset)
        window = gap_code[offset : offset + 16]
        insn = next(project.arch.capstone.disasm(window, gap_start + offset, 1), None)
        if insn is None or insn.size <= 0:
            break
        if insn.mnemonic.lower() in {"ret", "retf", "iret"}:
            _record_post_return_candidate_8616(gap_code, gap_start, offset + insn.size, align_bytes, record)
        offset += insn.size


def _record_post_return_candidate_8616(
    gap_code: bytes,
    gap_start: int,
    start_offset: int,
    align_bytes: set[int],
    record: Callable[[int, int, int, int], None],
) -> None:
    """Record a candidate following a return plus any alignment padding."""
    next_offset = start_offset
    skipped_alignment = False
    while next_offset < len(gap_code) and gap_code[next_offset] in align_bytes:
        skipped_alignment = True
        next_offset += 1
    if next_offset < len(gap_code):
        candidate_addr = gap_start + next_offset
        if skipped_alignment or gap_code[next_offset : next_offset + 3] == b"\x55\x8b\xec":
            record(candidate_addr, 2, gap_start, next_offset)


def _rank_prologue_scan_candidate_addrs(
    project: angr.Project,
    existing_addrs: set[int],
    *,
    search_span: int = 0x2000,
) -> list[int]:
    def _impl() -> list[int]:
        if project.arch.name != "86_16":
            return []

        loaded = _load_main_object_code_8616(project)
        if loaded is None:
            return []
        linked_base, code = loaded

        upper_bound = min(project.entry + search_span, linked_base + len(code))
        ranked_candidates: list[tuple[int, int, int]] = []
        for offset in range(len(code) - 2):
            entry = _prologue_rank_entry_8616(
                project, code, offset, linked_base, upper_bound, existing_addrs
            )
            if entry is not None:
                ranked_candidates.append(entry)
        return [addr for _priority, _offset, addr in sorted(ranked_candidates)]

    return _impl()


def _load_main_object_code_8616(project: angr.Project) -> tuple[int, bytes] | None:
    """Resolve linked base and loaded image bytes for the main object."""
    main_object = _dynamic_attr(project.loader, "main_object", None)
    if main_object is None:
        return None

    max_addr = _dynamic_attr(main_object, "max_addr", None)
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    if not isinstance(max_addr, int) or not isinstance(linked_base, int):
        return None

    try:
        code = bytes(main_object.memory.load(0, max_addr + 1))
    except Exception:
        return None
    return linked_base, code


def _prologue_rank_entry_8616(
    project: angr.Project,
    code: bytes,
    offset: int,
    linked_base: int,
    upper_bound: int,
    existing_addrs: set[int],
) -> tuple[int, int, int] | None:
    """Rank one push bp/mov bp,sp prologue candidate offset."""
    if code[offset : offset + 3] != b"\x55\x8b\xec":
        return None
    addr = linked_base + offset
    if not (project.entry <= addr < upper_bound) or addr in existing_addrs:
        return None
    try:
        block = project.factory.block(addr, size=16, opt_level=0)
    except Exception:
        return None
    insns = block.capstone.insns
    if (
        len(insns) < 2
        or insns[0].mnemonic != "push"
        or insns[0].op_str != "bp"
        or insns[1].mnemonic != "mov"
        or insns[1].op_str != "bp, sp"
    ):
        return None
    has_dos_interrupt = any(insn.mnemonic == "int" and insn.op_str == "0x21" for insn in insns[:8])
    return (0 if has_dos_interrupt else 1, offset, addr)


def _relocation_seed_targets(
    project: angr.Project,
    code: bytes,
    *,
    linked_base: int,
) -> tuple[set[int], set[int]]:
    def _impl() -> tuple[set[int], set[int]]:
        main_object = _dynamic_attr(project.loader, "main_object", None)
        relocation_entries = _dynamic_attr(main_object, "mz_relocation_entries", ()) if main_object is not None else ()
        if not relocation_entries:
            return set(), set()

        strong_targets: set[int] = set()
        weak_targets: set[int] = set()
        image_end = linked_base + len(code)

        for reloc_offset, reloc_segment in relocation_entries:
            if not isinstance(reloc_offset, int) or not isinstance(reloc_segment, int):
                continue
            reloc_addr = linked_base + (reloc_segment << 4) + reloc_offset
            seg_index = reloc_addr - linked_base
            if seg_index < 0 or seg_index + 1 >= len(code):
                continue
            seg = int.from_bytes(code[seg_index : seg_index + 2], "little")
            if seg_index >= 2:
                off = int.from_bytes(code[seg_index - 2 : seg_index], "little")
                target = linked_base + (seg << 4) + off
                if linked_base <= target < image_end:
                    weak_targets.add(target)
                    opcode_index = seg_index - 3
                    if opcode_index >= 0 and code[opcode_index] in {0x9A, 0xEA}:
                        strong_targets.add(target)
        weak_targets.difference_update(strong_targets)
        return strong_targets, weak_targets

    return _impl()


@dataclass(frozen=True, slots=True)
class _SeedTrace16:
    call_targets: frozenset[int]
    jump_targets: frozenset[int]


def trace_16bit_seed_candidates(
    project: angr.Project,
    code: bytes,
    *,
    linked_base: int,
    windows: Sequence[tuple[int, int]],
) -> _SeedTrace16:
    """Collect lightweight call/jump seed candidates from 16-bit code bytes."""

    def _impl() -> _SeedTrace16:
        def _window_contains(addr: int) -> bool:
            return any(start <= addr < end for start, end in windows)

        call_targets: set[int] = set()
        jump_targets: set[int] = set()

        # near call rel16 / near jmp rel16
        for off in range(max(0, len(code) - 2)):
            _record_near_transfer_seed_8616(code, off, linked_base, _window_contains, call_targets, jump_targets)

        # far call ptr16:16
        for off in range(max(0, len(code) - 4)):
            _record_far_call_seed_8616(code, off, linked_base, _window_contains, call_targets, jump_targets)

        return _SeedTrace16(frozenset(call_targets), frozenset(jump_targets))

    return _impl()


def _record_near_transfer_seed_8616(
    code: bytes,
    off: int,
    linked_base: int,
    window_contains: Callable[[int], bool],
    call_targets: set[int],
    jump_targets: set[int],
) -> None:
    """Record a near call/jmp rel16 seed target if it resolves inside a window."""
    op = code[off]
    if op not in {0xE8, 0xE9}:
        return
    rel = int.from_bytes(code[off + 1 : off + 3], "little", signed=True)
    target = linked_base + off + 3 + rel
    if op == 0xE8:
        canonical = _resolve_x86_16_call_target(code, target - linked_base)
    else:
        canonical = _resolve_x86_16_function_start(code, target - linked_base)
    if canonical is None:
        return
    resolved = linked_base + canonical
    if not window_contains(resolved):
        return
    if op == 0xE8:
        call_targets.add(resolved)
    jump_targets.add(resolved)


def _record_far_call_seed_8616(
    code: bytes,
    off: int,
    linked_base: int,
    window_contains: Callable[[int], bool],
    call_targets: set[int],
    jump_targets: set[int],
) -> None:
    """Record a far call ptr16:16 seed target if it resolves inside a window."""
    if code[off] != 0x9A:
        return
    tgt_off = int.from_bytes(code[off + 1 : off + 3], "little")
    seg = int.from_bytes(code[off + 3 : off + 5], "little")
    target = linked_base + (seg << 4) + tgt_off
    canonical = _resolve_x86_16_call_target(code, target - linked_base)
    if canonical is None:
        return
    resolved = linked_base + canonical
    if not window_contains(resolved):
        return
    call_targets.add(resolved)
    jump_targets.add(resolved)


def _seed_ranking_metadata_context(
    project: angr.Project,
) -> tuple[LSTMetadata | None, Mapping[int, str], frozenset[int], bool, dict[str, object] | None]:
    """Read seed ranking context from dynamic angr project metadata."""
    metadata = cast(LSTMetadata | None, _dynamic_attr(project, "_inertia_lst_metadata", None))
    recovery_labels = {}
    metadata_fingerprint = None
    include_library_functions = bool(_dynamic_attr(project, "_inertia_include_library_functions", False))
    if metadata is not None:
        recovery_labels = _recovery_code_labels(metadata)
        signature_matched_addrs = _signature_matched_code_addrs(metadata)
        signature_source = _dynamic_attr(metadata, "source_format", "")
        allow_signature_seed = include_library_functions or (
            "signature_catalog" not in signature_source and "flair_sig" not in signature_source
        )
        code_ranges = _dynamic_attr(metadata, "code_ranges", None) or {}
        metadata_fingerprint = {
            "source_format": _dynamic_attr(metadata, "source_format", None),
            "recovery_code_addrs": sorted(recovery_labels),
            "signature_code_addrs": sorted(signature_matched_addrs),
            "bounded_code_range_count": sum(
                1 for span in code_ranges.values() if span is not None and span[1] > span[0]
            ),
        }
    else:
        signature_matched_addrs = frozenset()
        allow_signature_seed = False
    return metadata, recovery_labels, signature_matched_addrs, allow_signature_seed, metadata_fingerprint


def _seed_ranking_cache_key(
    binary_path: object,
    project: angr.Project,
    linked_base: int,
    max_addr: int,
    metadata_fingerprint: dict[str, object] | None,
    include_library_functions: bool,
) -> dict[str, object] | None:
    return _cache_key_object(_recovery_cache_key(
        binary_path=Path(binary_path) if isinstance(binary_path, (str, Path)) else None,
        kind="exe_seed_ranking",
        source_scope=RecoveryCacheSourceScope8616.FUNCTION_DISCOVERY,
        extra={
            "entry": _dynamic_attr(project, "entry", None),
            "linked_base": linked_base,
            "max_addr": max_addr,
            "ranking_policy": "strong-non-library-v2",
            "include_library_functions": bool(include_library_functions),
            "metadata": metadata_fingerprint,
        },
    ))


def _load_seed_ranking_cache(cache_key: dict[str, object] | None) -> list[int] | None:
    cached_ranking = _load_cache_json("recovery", cache_key) if cache_key is not None else None
    if isinstance(cached_ranking, dict):
        cached_addrs = cached_ranking.get("addrs")
        if isinstance(cached_addrs, list) and all(isinstance(addr, int) for addr in cached_addrs):
            return cached_addrs
    return None


def _collect_neighbor_targets_for_seed_ranking(project: angr.Project, code: bytes, linked_base: int) -> set[int]:
    """Collect bounded entry-call targets without mutating the parent angr project."""

    def _collect_in_child() -> tuple[int, ...]:
        """Return the picklable target-address projection from isolated recovery."""
        _entry_cfg, entry_function = _pick_function_lean(
            project,
            project.entry,
            regions=[(project.entry, min(project.entry + 0x200, linked_base + len(code)))],
            data_references=False,
            extend_far_calls=True,
        )
        return tuple(sorted({target.target_addr for target in collect_neighbor_call_targets(entry_function)}))

    try:
        return set(_run_with_timeout_in_fork(
            _collect_in_child,
            timeout=1,
        ))
    except Exception:
        return set()


def _scan_opcode_seed_targets_8616(
    code: bytes,
    *,
    linked_base: int,
    consider: Callable[[int, int], None],
) -> tuple[set[int], set[int], set[int]]:
    near_call_targets: set[int] = set()
    far_call_targets: set[int] = set()
    prologue_targets: set[int] = set()
    for offset in range(len(code) - 2):
        opcode = code[offset]
        if opcode == 0xE8:
            rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
            callsite = linked_base + offset
            target = callsite + 3 + rel
            canonical = _resolve_x86_16_call_target(code, target - linked_base)
            if canonical is not None:
                resolved = linked_base + canonical
                near_call_targets.add(resolved)
                consider(resolved, 0)
        if code[offset : offset + 3] == b"\x55\x8b\xec":
            target = linked_base + offset
            prologue_targets.add(target)
            consider(target, 1)
    for offset in range(len(code) - 4):
        if code[offset] != 0x9A:
            continue
        off = int.from_bytes(code[offset + 1 : offset + 3], "little")
        seg = int.from_bytes(code[offset + 3 : offset + 5], "little")
        target = linked_base + (seg << 4) + off
        canonical = _resolve_x86_16_call_target(code, target - linked_base)
        if canonical is not None:
            resolved = linked_base + canonical
            far_call_targets.add(resolved)
            consider(resolved, 0)
    return near_call_targets, far_call_targets, prologue_targets


def _collect_terminal_next_targets_8616(
    project: angr.Project,
    code: bytes,
    linked_base: int,
    consider: Callable[[int, int], None],
) -> set[int]:
    try:
        insns = _linear_disassembly(project, linked_base, linked_base + len(code))
    except Exception:
        insns = []
    terminal_next_targets: set[int] = set()
    for insn in insns:
        mnemonic = insn.mnemonic.lower()
        if not (mnemonic.startswith("ret") or mnemonic == "iret"):
            continue
        target = insn.address + insn.size
        if not (linked_base <= target < linked_base + len(code)):
            continue
        next_offset = target - linked_base
        while next_offset < len(code) and code[next_offset] in {0x00, 0x90, 0xCC}:
            next_offset += 1
        if next_offset >= len(code):
            continue
        if not _looks_like_x86_16_function_prologue(code, next_offset):
            continue
        next_target = linked_base + next_offset
        terminal_next_targets.add(next_target)
        consider(next_target, 2)
    return terminal_next_targets


def _final_seed_priority_8616(
    *,
    addr: int,
    distance: int,
    project_entry: int,
    bounded_metadata_spans: dict[int, int],
    near_call_targets: set[int],
    far_call_targets: set[int],
    tracer_call_targets: set[int],
    prologue_targets: set[int],
    terminal_next_targets: set[int],
    neighbor_targets: set[int],
    entry_window_targets: set[int],
    relocation_control_targets: set[int],
    relocation_pointer_targets: set[int],
    source_region_start: int | None,
) -> tuple[int, int, int] | None:
    def _impl() -> tuple[int, int, int] | None:
        ev = _SeedEvidence8616(
            metadata_span_len=bounded_metadata_spans.get(addr),
            near_call=addr in near_call_targets,
            far_call=addr in far_call_targets,
            tracer_call=addr in tracer_call_targets,
            prologue=addr in prologue_targets,
            terminal_next=addr in terminal_next_targets,
            neighbor=addr in neighbor_targets,
            entry_window=addr in entry_window_targets,
            relocation_control=addr in relocation_control_targets,
            relocation_pointer=addr in relocation_pointer_targets,
            entry_descends_from_stub=addr in entry_window_targets and addr < project_entry,
            in_source_region=source_region_start is not None and source_region_start <= addr < project_entry,
        )
        final_priority = _final_seed_priority_decision_8616(ev)
        size_rank = -ev.metadata_span_len if ev.metadata_span_len is not None else 0
        return (final_priority, size_rank, distance)

    return _impl()


@dataclass(frozen=True, slots=True)
class _SeedEvidence8616:
    """Membership evidence used by the final seed-priority decision."""

    metadata_span_len: int | None
    near_call: bool
    far_call: bool
    tracer_call: bool
    prologue: bool
    terminal_next: bool
    neighbor: bool
    entry_window: bool
    relocation_control: bool
    relocation_pointer: bool
    entry_descends_from_stub: bool
    in_source_region: bool


_SEED_PRIORITY_RULES_8616: tuple[tuple[Callable[[_SeedEvidence8616], bool], int], ...] = (
    (lambda e: e.metadata_span_len is not None
        or (e.entry_descends_from_stub and (e.neighbor or e.near_call or e.far_call)), 0),
    (lambda e: e.entry_descends_from_stub, 1),
    (lambda e: e.in_source_region and e.prologue, 0),
    (lambda e: e.in_source_region and (e.neighbor or e.near_call or e.far_call or e.tracer_call), 1),
    (lambda e: e.in_source_region, 2),
    (lambda e: e.entry_window and (e.neighbor or e.near_call or e.far_call), 1),
    (lambda e: e.relocation_control and (e.prologue or e.near_call or e.far_call), 2),
    (lambda e: e.relocation_control, 3),
    (lambda e: (e.neighbor and e.prologue) or e.entry_window, 2),
    (lambda e: e.neighbor, 3),
    (lambda e: e.prologue and (e.near_call or e.far_call), 2),
    (lambda e: e.prologue, 3),
    (lambda e: e.relocation_pointer and (e.near_call or e.far_call or e.prologue), 4),
    (lambda e: e.relocation_pointer, 5),
    (lambda e: e.terminal_next and (e.near_call or e.far_call), 4),
    (lambda e: e.terminal_next, 5),
    (lambda e: e.far_call or (e.near_call and e.tracer_call), 6),
    (lambda e: e.near_call, 8),
)


def _final_seed_priority_decision_8616(ev: _SeedEvidence8616) -> int:
    """Resolve the final seed priority from ordered evidence rules."""
    for predicate, priority in _SEED_PRIORITY_RULES_8616:
        if predicate(ev):
            return priority
    return 9


def _rank_exe_function_seeds(
    project: angr.Project,
    include_library_functions: bool | None = None,
) -> list[int]:
    def _impl() -> list[int]:
        ctx = _exe_seed_context_8616(project, include_library_functions)
        if ctx is None:
            return []
        if ctx.cached_addrs is not None:
            return ctx.cached_addrs

        state = _collect_ranked_seed_state_8616(project, ctx)
        ranked_addrs = _rerank_seed_candidates_8616(project, ctx, state)
        if ctx.cache_key is not None:
            _store_cache_json("recovery", ctx.cache_key, {"addrs": ranked_addrs})
        return ranked_addrs

    return _impl()


@dataclass
class _ExeSeedCtx8616:
    """Resolved inputs for EXE function-seed ranking."""

    binary_path: object
    max_addr: int
    linked_base: int
    code: bytes
    seed_windows: list[tuple[int, int]]
    entry_window_targets: set[int]
    source_region_start: int | None
    metadata: LSTMetadata | None
    recovery_labels: Mapping[int, str]
    signature_matched_addrs: frozenset[int]
    allow_signature_seed: bool
    lib_functions: bool
    cache_key: dict[str, object] | None
    cached_addrs: list[int] | None


@dataclass
class _SeedCandidateState8616:
    """Ranked candidates plus the evidence sets gathered while collecting them."""

    ranked: dict[int, tuple[int, int]]
    bounded_metadata_spans: dict[int, int]
    near_call_targets: set[int]
    far_call_targets: set[int]
    tracer_call_targets: set[int]
    prologue_targets: set[int]
    terminal_next_targets: set[int]
    neighbor_targets: set[int]
    relocation_control_targets: set[int]
    relocation_pointer_targets: set[int]


def _exe_seed_context_8616(
    project: angr.Project, include_library_functions: bool | None
) -> _ExeSeedCtx8616 | None:
    """Resolve image, metadata, cache, and window inputs for seed ranking."""
    main_object = _dynamic_attr(project.loader, "main_object", None)
    if main_object is None:
        return None
    lib_functions = include_library_functions
    if lib_functions is None:
        lib_functions = bool(_dynamic_attr(project, "_inertia_include_library_functions", False))
    binary_path = _dynamic_attr(main_object, "binary", None)
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    if not isinstance(max_addr, int) or not isinstance(linked_base, int):
        return None
    metadata, recovery_labels, signature_matched_addrs, allow_signature_seed, metadata_fingerprint = (
        _seed_ranking_metadata_context(project)
    )
    cache_key = _seed_ranking_cache_key(
        binary_path,
        project,
        linked_base,
        max_addr,
        metadata_fingerprint,
        bool(lib_functions),
    )
    cached_addrs = _load_seed_ranking_cache(cache_key)

    try:
        code = bytes(main_object.memory.load(0, max_addr + 1))
    except Exception:
        return None
    seed_windows = _seed_scan_windows(project)
    entry_window_targets = _entry_window_seed_targets(project, code, linked_base=linked_base)
    pre_entry_start_targets = tuple(
        target
        for target in entry_window_targets
        if linked_base <= target < project.entry
    )
    source_region_start = min(pre_entry_start_targets) if pre_entry_start_targets else None
    return _ExeSeedCtx8616(
        binary_path,
        max_addr,
        linked_base,
        code,
        seed_windows,
        entry_window_targets,
        source_region_start,
        metadata,
        recovery_labels,
        signature_matched_addrs,
        allow_signature_seed,
        bool(lib_functions),
        cache_key,
        cached_addrs,
    )


def _collect_ranked_seed_state_8616(project: angr.Project, ctx: _ExeSeedCtx8616) -> _SeedCandidateState8616:
    """Collect ranked seed candidates and the evidence sets used to rerank them."""
    def _window_contains(addr: int) -> bool:
        return any(start <= addr < end for start, end in ctx.seed_windows)

    ranked: dict[int, tuple[int, int]] = {}
    bounded_metadata_spans: dict[int, int] = {}

    def _consider(addr: int, priority: int) -> None:
        if not (ctx.linked_base <= addr < ctx.linked_base + len(ctx.code)):
            return
        if addr in ctx.signature_matched_addrs and not ctx.allow_signature_seed:
            return
        if not _window_contains(addr):
            return
        if addr == project.entry:
            return
        distance = abs(addr - project.entry)
        existing = ranked.get(addr)
        candidate = (priority, distance)
        if existing is None or candidate < existing:
            ranked[addr] = candidate

    _consider_metadata_and_tracer_seeds_8616(project, ctx, bounded_metadata_spans, _consider)
    tracer = trace_16bit_seed_candidates(
        project,
        ctx.code,
        linked_base=ctx.linked_base,
        windows=ctx.seed_windows,
    )
    _consider_tracer_targets_8616(ctx, tracer, _consider)

    near_call_targets, far_call_targets, prologue_targets = _scan_opcode_seed_targets_8616(
        ctx.code,
        linked_base=ctx.linked_base,
        consider=_consider,
    )

    relocation_control_targets, relocation_pointer_targets = _relocation_seed_targets(
        project,
        ctx.code,
        linked_base=ctx.linked_base,
    )
    for target in relocation_control_targets:
        _consider(target, 1)
    for target in relocation_pointer_targets:
        _consider(target, 4)

    neighbor_targets = _collect_neighbor_targets_for_seed_ranking(project, ctx.code, ctx.linked_base)
    terminal_next_targets = _collect_terminal_next_targets_8616(project, ctx.code, ctx.linked_base, _consider)

    return _SeedCandidateState8616(
        ranked,
        bounded_metadata_spans,
        near_call_targets,
        far_call_targets,
        set(tracer.call_targets),
        prologue_targets,
        terminal_next_targets,
        neighbor_targets,
        relocation_control_targets,
        relocation_pointer_targets,
    )


def _consider_metadata_and_tracer_seeds_8616(
    project: angr.Project,
    ctx: _ExeSeedCtx8616,
    bounded_metadata_spans: dict[int, int],
    consider: Callable[[int, int], None],
) -> None:
    """Consider metadata-labelled and entry-window seed targets."""
    metadata = ctx.metadata
    metadata_labels: Mapping[int, str] = _visible_code_labels(metadata) if metadata is not None else {}
    if ctx.lib_functions and metadata is not None:
        metadata_labels = ctx.recovery_labels
    if not metadata_labels and metadata is not None:
        metadata_labels = ctx.recovery_labels
    for addr in metadata_labels:
        if (span := _lst_code_region(metadata, addr)) is None:
            continue
        span_len = span[1] - span[0]
        if span_len > 0:
            bounded_metadata_spans[addr] = span_len
        consider(addr, 0)

    for target in ctx.entry_window_targets:
        consider(target, 0)


def _consider_tracer_targets_8616(
    ctx: _ExeSeedCtx8616,
    tracer: _SeedTrace16,
    consider: Callable[[int, int], None],
) -> None:
    """Consider canonicalized tracer call/jump targets."""
    for target in tracer.call_targets:
        canonical = _resolve_x86_16_call_target(ctx.code, target - ctx.linked_base)
        if canonical is not None:
            consider(ctx.linked_base + canonical, 0 if target in ctx.entry_window_targets else 1)
    for target in tracer.jump_targets:
        if target not in tracer.call_targets:
            canonical = _resolve_x86_16_function_start(ctx.code, target - ctx.linked_base)
            if canonical is not None:
                consider(ctx.linked_base + canonical, 2)


def _rerank_seed_candidates_8616(
    project: angr.Project, ctx: _ExeSeedCtx8616, state: _SeedCandidateState8616
) -> list[int]:
    """Apply the final evidence priority to each ranked candidate."""
    reranked: list[tuple[tuple[int, int, int], int]] = []
    for addr, (_priority, distance) in state.ranked.items():
        priority = _final_seed_priority_8616(
            addr=addr,
            distance=distance,
            project_entry=project.entry,
            bounded_metadata_spans=state.bounded_metadata_spans,
            near_call_targets=state.near_call_targets,
            far_call_targets=state.far_call_targets,
            tracer_call_targets=state.tracer_call_targets,
            prologue_targets=state.prologue_targets,
            terminal_next_targets=state.terminal_next_targets,
            neighbor_targets=state.neighbor_targets,
            entry_window_targets=ctx.entry_window_targets,
            relocation_control_targets=state.relocation_control_targets,
            relocation_pointer_targets=state.relocation_pointer_targets,
            source_region_start=ctx.source_region_start,
        )
        if priority is not None:
            reranked.append((priority, addr))
    return [addr for _meta, addr in sorted(reranked)]


def _rank_pre_entry_source_function_seeds_8616(project: angr.Project) -> list[int]:
    """Rank framed pre-startup candidates without assuming main is linked first."""
    if project.arch.name != "86_16":
        return []
    main_object = _dynamic_attr(project.loader, "main_object", None)
    if main_object is None:
        return []
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    if not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return []
    try:
        code = bytes(main_object.memory.load(0, max_addr + 1))
    except Exception:
        return []

    entry_targets = _entry_window_seed_targets(project, code, linked_base=linked_base)
    framed_pre_entry_targets = tuple(
        target
        for target in entry_targets
        if linked_base <= target < project.entry
        and _looks_like_x86_16_function_prologue(code, target - linked_base)
    )
    if not framed_pre_entry_targets:
        return []
    source_region_start = min(framed_pre_entry_targets)
    ranked_seeds = _rank_exe_function_seeds(project)
    source_seeds = [
        addr
        for addr in ranked_seeds
        # A startup call locates a root, not the first function in its object.
        if linked_base <= addr < project.entry
        and _looks_like_x86_16_function_prologue(code, addr - linked_base)
    ]
    if source_region_start not in source_seeds:
        return []
    return source_seeds


def _pre_entry_source_function_ranges_8616(
    project: angr.Project,
    source_seeds: Sequence[int],
) -> tuple[tuple[int, int], ...]:
    """Build independently framed caller ranges from the startup-bounded catalog."""
    main_object = _dynamic_attr(project.loader, "main_object", None)
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    if not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return ()
    ordered_seeds = tuple(sorted(dict.fromkeys(source_seeds)))
    if not ordered_seeds:
        return ()
    image_end = linked_base + max_addr + 1
    final_end = min(project.entry, image_end)
    if ordered_seeds[-1] >= final_end:
        return ()
    metadata = cast(LSTMetadata | None, _dynamic_attr(project, "_inertia_lst_metadata", None))
    candidate_ranges = pre_entry_candidate_ranges(
        ordered_seeds, _signature_matched_code_addrs(metadata), end=final_end,
    )
    function_ranges = tuple(
        (
            _binary_padding_entry_aliases_8616(project, start)[0],
            candidate_ranges[start][1],
        )
        for start in ordered_seeds
    )
    entry_caller_range = _entry_linear_caller_range_8616(
        project,
        target_addrs=ordered_seeds,
    )
    if entry_caller_range is not None:
        return (*function_ranges, entry_caller_range)
    return function_ranges


def record_direct_target_caller_return_use_evidence_8616(
    project: angr.Project,
    target_addr: int,
    *,
    binary_path: Path | None = None,
) -> CallerReturnUseEvidence8616 | None:
    """Record closed caller-use evidence for one sidecar-free direct target.

    Caller discovery is bounded to framed functions in the startup-proven
    application region. An exact direct callee may live outside that catalog.
    When available, the exact display-catalog cache restores the same typed
    evidence before binary analysis is repeated.
    """
    existing = caller_return_use_evidence_by_addr_8616(project).get(target_addr)
    if isinstance(existing, CallerReturnUseEvidence8616):
        return existing
    if binary_path is not None:
        _load_catalog_address_cache(project, binary_path)
        existing = caller_return_use_evidence_by_addr_8616(project).get(target_addr)
        if isinstance(existing, CallerReturnUseEvidence8616):
            return existing
    evidence_project = isolated_discovery_evidence_project_8616(project)
    source_seeds = tuple(_rank_pre_entry_source_function_seeds_8616(evidence_project))
    canonical_target = next(
        (
            seed
            for seed in source_seeds
            if target_addr in _binary_padding_entry_aliases_8616(evidence_project, seed)
        ),
        None,
    )
    function_ranges = _pre_entry_source_function_ranges_8616(evidence_project, source_seeds)
    if not function_ranges:
        return None
    target_aliases = (
        (target_addr,)
        if canonical_target is None
        else _binary_padding_entry_aliases_8616(evidence_project, canonical_target)
    )
    evidence = _collect_caller_return_use_for_entry_aliases_8616(
        evidence_project,
        target_aliases,
        function_ranges,
    )
    if evidence is None:
        return None
    for evidence_target in dict.fromkeys((*target_aliases, target_addr)):
        _record_caller_return_use_evidence_8616(
            project,
            evidence_target,
            replace(evidence, target_addr=evidence_target),
        )
    if binary_path is not None:
        _store_catalog_address_cache_addrs_8616(
            project,
            binary_path,
            source_seeds,
        )
    return replace(evidence, target_addr=target_addr)


def attach_direct_target_argument_evidence_context_8616(
    source_project: angr.Project,
    target_project: angr.Project,
    target_addr: int,
) -> bool:
    """Attach independently framed caller ranges for callee-interface Lowering."""
    evidence_project = isolated_discovery_evidence_project_8616(source_project)
    source_seeds = tuple(_rank_pre_entry_source_function_seeds_8616(evidence_project))
    canonical_target = next(
        (
            seed
            for seed in source_seeds
            if target_addr in _binary_padding_entry_aliases_8616(evidence_project, seed)
        ),
        None,
    )
    caller_evidence = caller_return_use_evidence_by_addr_8616(source_project).get(
        target_addr
    )
    if canonical_target is None and not (
        caller_evidence is not None
        and caller_evidence.verdict is not CallerReturnUseVerdict8616.UNKNOWN
        and caller_evidence.raw_fact_count > 0
        and caller_evidence.fact_census_complete
    ):
        return False
    function_ranges = _pre_entry_source_function_ranges_8616(evidence_project, source_seeds)
    if not function_ranges:
        return False
    target_aliases = (
        (target_addr,)
        if canonical_target is None
        else _binary_padding_entry_aliases_8616(evidence_project, canonical_target)
    )
    dynamic_target = cast(_AngrObject, target_project)
    dynamic_target._inertia_caller_function_ranges_8616 = function_ranges
    dynamic_target._inertia_caller_target_aliases_8616 = target_aliases
    return True


def _recover_pre_entry_source_catalog_8616(
    project: angr.Project,
    *,
    source_seeds: Sequence[int],
    timeout: int,
    per_function_timeout: int = 2,
    region_span: int = 0x120,
    raw_fact_count: int | None = None,
    seed_calling_conventions_enabled: bool = True,
) -> tuple[list[_FunctionCfgPair], SourceRegionCatalogEvidence8616]:
    """Materialize each independently framed entry in a startup-bounded region."""
    main_object = _dynamic_attr(project.loader, "main_object", None)
    binary_path = _dynamic_attr(main_object, "binary", None)
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    normalized_seeds = tuple(dict.fromkeys(addr for addr in source_seeds if isinstance(addr, int)))
    raw_count = len(source_seeds) if raw_fact_count is None else max(len(source_seeds), raw_fact_count)
    if (
        main_object is None
        or binary_path is None
        or not isinstance(linked_base, int)
        or not isinstance(max_addr, int)
    ):
        evidence = SourceRegionCatalogEvidence8616(
            raw_fact_count=raw_count,
            normalized_fact_count=len(normalized_seeds),
            classified_fact_count=len(normalized_seeds),
            materialized_count=0,
            failure_count=len(normalized_seeds),
            failed_addrs=normalized_seeds,
        )
        return [], evidence

    deadline = time.monotonic() + max(1, timeout)
    image_end = linked_base + max_addr + 1
    ordered_seeds = tuple(sorted(normalized_seeds))
    metadata = cast(LSTMetadata | None, _dynamic_attr(project, "_inertia_lst_metadata", None))
    exact_region_by_addr = pre_entry_candidate_ranges(
        ordered_seeds, _signature_matched_code_addrs(metadata), end=min(project.entry, image_end),
    )
    recovered: list[_FunctionCfgPair] = []
    recovered_addrs: set[int] = set()
    failed_addrs = _recover_source_seed_attempts_8616(
        project,
        normalized_seeds,
        deadline,
        recovered,
        recovered_addrs,
        image_end=image_end,
        metadata=metadata,
        exact_region_by_addr=exact_region_by_addr,
        binary_path=binary_path,
        linked_base=linked_base,
        region_span=region_span,
        per_function_timeout=per_function_timeout,
        seed_calling_conventions_enabled=seed_calling_conventions_enabled,
    )

    evidence = SourceRegionCatalogEvidence8616(
        raw_fact_count=raw_count,
        normalized_fact_count=len(normalized_seeds),
        classified_fact_count=len(normalized_seeds),
        materialized_count=len(recovered),
        failure_count=len(failed_addrs),
        failed_addrs=tuple(failed_addrs),
    )
    function_ranges = _pre_entry_source_function_ranges_8616(project, ordered_seeds)
    _record_source_region_caller_evidence_8616(project, recovered, function_ranges)
    print(source_region_catalog_evidence_comment_8616(evidence))
    if evidence.classified_fact_count > 0 and evidence.materialized_count == 0:
        raise RuntimeError("source-region discovery classified entries but materialized none")
    return recovered, evidence


def _recover_source_seed_once_8616(
    project: angr.Project,
    addr: int,
    candidate_timeout: int,
    *,
    image_end: int,
    metadata: LSTMetadata | None,
    exact_region_by_addr: Mapping[int, tuple[int, int]],
    binary_path: _AngrObject,
    linked_base: int,
    region_span: int,
    seed_calling_conventions_enabled: bool,
) -> _FunctionCfgPair | None:
    """Attempt one bounded candidate recovery with exact-region marking."""
    try:
        recovered_pair = _recover_candidate_with_timeout(
            project,
            candidate_addr=addr,
            image_end=image_end,
            metadata=metadata,
            project_entry=project.entry,
            region_span=region_span,
            timeout=max(1, candidate_timeout),
            binary_path=Path(binary_path),
            linked_base=linked_base,
            exact_region=exact_region_by_addr.get(addr),
            seed_calling_conventions_enabled=seed_calling_conventions_enabled,
        )
        exact_region = exact_region_by_addr.get(addr)
        if exact_region is not None:
            _mark_function_binary_exact_region_8616(recovered_pair[1], exact_region)
        return recovered_pair
    except (_AnalysisTimeout, Exception):
        return None


def _record_recovered_pair_8616(
    recovered_pair: _FunctionCfgPair | None,
    recovered: list[_FunctionCfgPair],
    recovered_addrs: set[int],
) -> bool:
    """Record a novel, non-skipped recovered pair."""
    if recovered_pair is None:
        return False
    function_cfg, function = recovered_pair
    function_addr = _dynamic_attr(function, "addr", None)
    if not isinstance(function_addr, int) or function_addr in recovered_addrs:
        return False
    if _function_skip_reason(function) is not None:
        return False
    recovered_addrs.add(function_addr)
    recovered.append((function_cfg, function))
    return True


def _recover_source_seed_pass_8616(
    seeds: Iterable[int],
    deadline: float,
    timeout_for: Callable[[float], int],
    recover_one: Callable[[int, int], _FunctionCfgPair | None],
    recovered: list[_FunctionCfgPair],
    recovered_addrs: set[int],
) -> list[int]:
    """Run one timed recovery pass over seeds, returning the failed addresses."""
    failed_addrs: list[int] = []
    for addr in seeds:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            failed_addrs.append(addr)
            continue
        candidate_timeout = timeout_for(remaining)
        if not _record_recovered_pair_8616(
            recover_one(addr, candidate_timeout), recovered, recovered_addrs
        ):
            failed_addrs.append(addr)
    return failed_addrs


def _recover_source_seed_attempts_8616(
    project: angr.Project,
    normalized_seeds: tuple[int, ...],
    deadline: float,
    recovered: list[_FunctionCfgPair],
    recovered_addrs: set[int],
    *,
    image_end: int,
    metadata: LSTMetadata | None,
    exact_region_by_addr: Mapping[int, tuple[int, int]],
    binary_path: object,
    linked_base: int,
    region_span: int,
    per_function_timeout: int,
    seed_calling_conventions_enabled: bool,
) -> list[int]:
    """Run the initial and retry recovery passes over normalized seeds."""
    def recover_one(addr: int, candidate_timeout: int) -> _FunctionCfgPair | None:
        return _recover_source_seed_once_8616(
            project,
            addr,
            candidate_timeout,
            image_end=image_end,
            metadata=metadata,
            exact_region_by_addr=exact_region_by_addr,
            binary_path=binary_path,
            linked_base=linked_base,
            region_span=region_span,
            seed_calling_conventions_enabled=seed_calling_conventions_enabled,
        )

    failed_addrs = _recover_source_seed_pass_8616(
        normalized_seeds,
        deadline,
        lambda remaining: min(max(1, per_function_timeout), max(1, int(remaining))),
        recover_one,
        recovered,
        recovered_addrs,
    )
    return _recover_source_seed_pass_8616(
        failed_addrs,
        deadline,
        lambda remaining: min(max(4, per_function_timeout * 2), max(1, int(remaining))),
        recover_one,
        recovered,
        recovered_addrs,
    )


def _record_source_region_caller_evidence_8616(
    project: angr.Project,
    recovered: list[_FunctionCfgPair],
    function_ranges: tuple[tuple[int, int], ...],
) -> None:
    """Record caller return-use evidence for each recovered source function."""
    with caller_return_use_program_scope_8616(project, function_ranges):
        for _function_cfg, function in recovered:
            function_addr = _dynamic_attr(function, "addr", None)
            if not isinstance(function_addr, int):
                continue
            caller_return_use = _collect_caller_return_use_for_entry_aliases_8616(
                project,
                _binary_padding_entry_aliases_8616(project, function_addr),
                function_ranges,
            )
            if caller_return_use is not None:
                _record_caller_return_use_evidence_8616(
                    project,
                    function_addr,
                    replace(caller_return_use, target_addr=function_addr),
                )


def _recover_fast_seed_functions(
    project: angr.Project,
    *,
    timeout: int,
    limit: int | None,
) -> list[_FunctionCfgPair]:
    if project.arch.name != "86_16":
        return []
    recovered = cast(
        list[_FunctionCfgPair],
        _recover_seeded_exe_functions(project, timeout=timeout, limit=limit),
    )
    if recovered:
        print(
            "/* quick function-entry scan found likely functions using call/prologue/epilogue patterns without helper metadata. */"
        )
    return recovered


def _recover_fast_exe_catalog(
    project: angr.Project,
    *,
    timeout: int,
    window: int,
    low_memory: bool,
    limit: int | None,
    seed_calling_conventions_enabled: bool = True,
    catalog_timeout: int = DEFAULT_CATALOG_TIMEOUT,
) -> list[_FunctionCfgPair]:
    """Recover catalog candidates with an independent bounded recovery budget."""
    recovered: list[_FunctionCfgPair] = []
    seen_addrs: set[int] = set()
    source_seeds = _rank_pre_entry_source_function_seeds_8616(project)
    selected_source_seeds = source_seeds if limit is None else source_seeds[:limit]
    include_library_functions = bool(_dynamic_attr(project, "_inertia_include_library_functions", False))

    if not selected_source_seeds or include_library_functions:
        entry_start = time.perf_counter()
        try:
            entry_pair = _run_with_timeout_in_daemon_thread(
                lambda: _fallback_entry_function(
                    project,
                    timeout=max(1, min(timeout, 6)),
                    window=window,
                    low_memory=low_memory,
                    prefer_fast_recovery=True,
                ),
                timeout=max(1, min(timeout, 6)),
                thread_name_prefix="fast-entry",
            )
        except Exception:
            entry_pair = None
        print(f"[dbg] quick EXE function-list pass: entry-function recovery {time.perf_counter() - entry_start:.2f}s")
        sys.stdout.flush()
        if entry_pair is not None:
            entry_cfg, entry_function = entry_pair
            if _function_skip_reason(entry_function) is None:
                recovered.append((entry_cfg, entry_function))
                seen_addrs.add(entry_function.addr)

    seed_start = time.perf_counter()
    if selected_source_seeds:
        source_budget = catalog_timeout
        seeded, source_evidence = _recover_pre_entry_source_catalog_8616(
            project,
            source_seeds=selected_source_seeds,
            timeout=source_budget,
            per_function_timeout=2,
            raw_fact_count=len(source_seeds),
            seed_calling_conventions_enabled=seed_calling_conventions_enabled,
        )
        cast(Any, project)._inertia_source_region_catalog_evidence = source_evidence
        seed_limit: int | None = len(selected_source_seeds)
    else:
        seed_limit = None if limit is None else max(limit * 2, limit + 4)
        seeded = _recover_fast_seed_functions(
            project,
            timeout=catalog_timeout,
            limit=seed_limit,
        )
    print(
        f"[dbg] quick EXE function-list pass: candidate-function recovery {time.perf_counter() - seed_start:.2f}s "
        f"(seed limit {seed_limit if seed_limit is not None else 'all'})"
    )
    sys.stdout.flush()
    for function_cfg, function in seeded:
        if function.addr in seen_addrs:
            continue
        recovered.append((function_cfg, function))
        seen_addrs.add(function.addr)

    if recovered:
        recovered = _rank_function_cfg_pairs_for_display(project, recovered)
        if limit is not None:
            recovered = recovered[:limit]
        print(
            "/* quick EXE function discovery found entry/body functions without needing whole-program control-flow recovery. */"
        )
    return recovered


def _recover_hidden_sidecar_display_pairs(
    project: angr.Project,
    ranked_binary_offsets: Sequence[int],
    *,
    timeout: int,
    window: int,
    low_memory: bool,
    limit: int,
) -> list[_FunctionCfgPair]:
    def _impl() -> list[_FunctionCfgPair]:
        if limit <= 0 or not ranked_binary_offsets:
            return []

        recovered: list[_FunctionCfgPair] = []
        seen_addrs: set[int] = set()

        try:
            entry_pair = _run_with_timeout_in_daemon_thread(
                lambda: _fallback_entry_function(
                    project,
                    timeout=max(1, min(timeout, 4)),
                    window=window,
                    low_memory=low_memory,
                    prefer_fast_recovery=True,
                ),
                timeout=max(2, min(timeout, 5)),
                thread_name_prefix="hidden-sidecar-entry",
            )
        except Exception:
            entry_pair = None
        if entry_pair is not None:
            entry_cfg, entry_function = entry_pair
            if _function_skip_reason(entry_function) is None:
                recovered.append((entry_cfg, entry_function))
                seen_addrs.add(entry_function.addr)

        remaining_slots = max(0, limit - len(recovered))
        if remaining_slots <= 0:
            return recovered[:limit]

        preview_probe_count = min(max(remaining_slots * 2, remaining_slots + 2), max(remaining_slots, 8))
        preview_items = _prepare_ranked_binary_preview_items(
            project,
            ranked_binary_offsets,
            max_count=preview_probe_count,
            timeout=timeout,
            window=window,
            low_memory=low_memory,
        )
        for item in preview_items:
            addr = _dynamic_attr(item.function, "addr", None)
            if item.function_cfg is None or not isinstance(addr, int) or addr in seen_addrs:
                continue
            recovered.append((item.function_cfg, item.function))
            seen_addrs.add(addr)

        if recovered:
            recovered = _rank_hidden_sidecar_pairs_for_display_throughput(
                project,
                recovered,
                limit=limit,
            )
            print(
                "/* hidden-sidecar EXE: using ranked direct-binary preview for the capped display set before broad CFG recovery. */"
            )
        return recovered

    return _impl()


def _prepare_ranked_binary_preview_items(
    project: angr.Project,
    ranked_binary_offsets: Sequence[int],
    *,
    max_count: int,
    timeout: int,
    window: int,
    low_memory: bool,
) -> tuple[_RankedBinaryPreviewItem, ...]:
    def _impl() -> tuple[_RankedBinaryPreviewItem, ...]:
        """Preview ranked entries across a dynamic angr loader/project boundary."""
        if max_count <= 0 or not ranked_binary_offsets:
            return ()
        main_object = _dynamic_attr(project.loader, "main_object", None)
        linked_base = _dynamic_attr(main_object, "linked_base", None)
        max_addr = _dynamic_attr(main_object, "max_addr", None)
        binary_path = _dynamic_attr(main_object, "binary", None)
        if not isinstance(linked_base, int) or not isinstance(max_addr, int) or binary_path is None:
            return ()

        image_end = linked_base + max_addr + 1
        metadata = _dynamic_attr(project, "_inertia_lst_metadata", None)
        project_entry = _dynamic_attr(project, "entry", linked_base)
        region_span = max(0x120, int(window or 0x120))
        per_candidate_timeout = max(1, min(int(timeout or 1), 4))
        items: list[_RankedBinaryPreviewItem] = []
        for addr in ranked_binary_offsets:
            if len(items) >= max_count:
                break
            if not isinstance(addr, int):
                continue
            try:
                function_cfg, function = _recover_candidate_with_timeout(
                    project,
                    candidate_addr=addr,
                    image_end=image_end,
                    metadata=metadata,
                    project_entry=project_entry,
                    region_span=region_span,
                    timeout=per_candidate_timeout,
                    binary_path=Path(binary_path),
                    linked_base=linked_base,
                )
            except (_AnalysisTimeout, FuturesTimeoutError, KeyError):
                continue
            except Exception:
                continue
            if _function_skip_reason(function) is not None:
                continue
            items.append(_RankedBinaryPreviewItem(function_cfg=function_cfg, function=function))
        return tuple(items)

    return _impl()


def _rank_hidden_sidecar_pairs_for_display_throughput(
    project: angr.Project,
    function_cfg_pairs: list[_FunctionCfgPair],
    *,
    limit: int,
) -> list[_FunctionCfgPair]:
    def _impl() -> list[_FunctionCfgPair]:
        if not function_cfg_pairs:
            return []

        entry_addr = _dynamic_attr(project, "entry", None)
        indexed_pairs = list(enumerate(function_cfg_pairs))
        entry_pair: tuple[int, _FunctionCfgPair] | None = None
        non_entry_pairs: list[tuple[int, _FunctionCfgPair]] = []

        for original_index, pair in indexed_pairs:
            _cfg, function = pair
            addr = _dynamic_attr(function, "addr", None)
            if isinstance(entry_addr, int) and addr == entry_addr and entry_pair is None:
                entry_pair = (original_index, pair)
                continue
            non_entry_pairs.append((original_index, pair))

        def _throughput_priority(
            indexed_pair: tuple[int, _FunctionCfgPair],
        ) -> tuple[int, int, int, int, int, int, int]:
            original_index, (_cfg, function) = indexed_pair
            addr = _dynamic_attr(function, "addr", None)
            block_count, byte_count = _function_complexity(function)
            truncated = _function_recovery_truncated(function)
            far_pre_entry = int(
                isinstance(addr, int)
                and isinstance(entry_addr, int)
                and addr < entry_addr
                and (entry_addr - addr) > 0x200
            )
            pre_entry = int(isinstance(addr, int) and isinstance(entry_addr, int) and addr < entry_addr)
            tiny_wrapper_like = int(block_count <= 1 and byte_count <= 8 and not truncated)
            distance = abs(addr - entry_addr) if isinstance(addr, int) and isinstance(entry_addr, int) else 0
            return (far_pre_entry, pre_entry, tiny_wrapper_like, block_count, byte_count, distance, original_index)

        ordered_non_entry = [pair for _index, pair in sorted(non_entry_pairs, key=_throughput_priority)]
        if entry_pair is None:
            return ordered_non_entry[:limit] if limit > 0 else ordered_non_entry

        if limit <= 1:
            return [entry_pair[1]]

        if limit == 2:
            ordered = list(ordered_non_entry[:1])
            ordered.append(entry_pair[1])
            return ordered[:limit]

        ordered_all = list(ordered_non_entry)
        ordered_all.append(entry_pair[1])
        return ordered_all[:limit]

    return _impl()


def _recover_cached_function_pairs(
    project: angr.Project,
    *,
    addrs: list[int],
    timeout: int,
    limit: int | None,
    region_span: int = 0x120,
    per_function_timeout: int = 1,
) -> list[_FunctionCfgPair]:
    def _impl() -> list[_FunctionCfgPair]:
        main_object = _dynamic_attr(project.loader, "main_object", None)
        if main_object is None:
            return []
        binary_path = _dynamic_attr(main_object, "binary", None)
        linked_base = _dynamic_attr(main_object, "linked_base", None)
        max_addr = _dynamic_attr(main_object, "max_addr", None)
        if binary_path is None or not isinstance(linked_base, int) or not isinstance(max_addr, int):
            return []

        deadline = time.monotonic() + max(1, timeout)
        metadata = _dynamic_attr(project, "_inertia_lst_metadata", None)
        image_end = linked_base + max_addr + 1
        recovered: list[_FunctionCfgPair] = []
        seen_addrs: set[int] = set()

        for addr in addrs:
            if limit is not None and len(recovered) >= limit:
                break
            if not isinstance(addr, int) or addr in seen_addrs:
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            candidate_timeout = min(per_function_timeout, max(1, int(remaining)))
            if isinstance(_dynamic_attr(project, "entry", None), int) and addr < project.entry:
                candidate_timeout = min(max(2, per_function_timeout), max(1, int(remaining)))

            pair = _recover_cached_pair_once_8616(
                project,
                addr,
                image_end=image_end,
                metadata=metadata,
                region_span=region_span,
                candidate_timeout=candidate_timeout,
                binary_path=binary_path,
                linked_base=linked_base,
            )
            _record_recovered_pair_8616(pair, recovered, seen_addrs)

        _report_cached_recovery_8616(project, recovered)
        return recovered

    return _impl()


def _report_cached_recovery_8616(project: angr.Project, recovered: list[_FunctionCfgPair]) -> None:
    """Report restored cached functions and any source-region evidence."""
    if not recovered:
        return
    print(
        f"/* restored {len(recovered)} previously recovered function entr{'y' if len(recovered) == 1 else 'ies'} from recovery cache. */"
    )
    source_region_evidence = _source_region_catalog_evidence_8616(project)
    if source_region_evidence is not None:
        print(source_region_catalog_evidence_comment_8616(source_region_evidence))


def _recover_cached_pair_once_8616(
    project: angr.Project,
    addr: int,
    *,
    image_end: int,
    metadata: LSTMetadata | None,
    region_span: int,
    candidate_timeout: int,
    binary_path: _AngrObject,
    linked_base: int,
) -> _FunctionCfgPair | None:
    """Attempt one cached recovery, returning None on failure."""
    try:
        return _recover_candidate_with_timeout(
            project,
            candidate_addr=addr,
            image_end=image_end,
            metadata=metadata,
            project_entry=project.entry,
            region_span=region_span,
            timeout=candidate_timeout,
            binary_path=Path(binary_path),
            linked_base=linked_base,
        )
    except (_AnalysisTimeout, KeyError, Exception):
        return None


def _candidate_recovery_cache_key(
    *,
    candidate_addr: int,
    image_end: int,
    project_entry: int,
    region_span: int,
    exact_region: tuple[int, int] | None = None,
) -> tuple[int, int, int, int, tuple[int, int] | None]:
    return (candidate_addr, image_end, project_entry, region_span, exact_region)


def _lookup_candidate_recovery_cache(
    project: angr.Project,
    *,
    candidate_addr: int,
    image_end: int,
    project_entry: int,
    region_span: int,
    exact_region: tuple[int, int] | None = None,
) -> _CandidateRecoveryCacheValue | None:
    cache = _dynamic_attr(project, "_inertia_candidate_recovery_cache", None)
    if not isinstance(cache, dict):
        return None
    return cache.get(
        _candidate_recovery_cache_key(
            candidate_addr=candidate_addr,
            image_end=image_end,
            project_entry=project_entry,
            region_span=region_span,
            exact_region=exact_region,
        )
    )


def _store_candidate_recovery_cache(
    project: angr.Project,
    *,
    candidate_addr: int,
    image_end: int,
    project_entry: int,
    region_span: int,
    exact_region: tuple[int, int] | None = None,
    value: _CandidateRecoveryCacheValue,
) -> None:
    cache = _dynamic_attr(project, "_inertia_candidate_recovery_cache", None)
    if not isinstance(cache, dict):
        cache = {}
        typing.cast(typing.Any, project)._inertia_candidate_recovery_cache = cache
    cache[
        _candidate_recovery_cache_key(
            candidate_addr=candidate_addr,
            image_end=image_end,
            project_entry=project_entry,
            region_span=region_span,
            exact_region=exact_region,
        )
    ] = value


def _persistent_recovery_attempt_cache_key(
    *,
    binary_path: Path | None,
    addr: int,
    mode: str,
    window: int,
    low_memory: bool,
) -> dict[str, object] | None:
    return _cache_key_object(_recovery_cache_key(
        binary_path=binary_path,
        kind="function_recovery_attempt",
        source_scope=RecoveryCacheSourceScope8616.FUNCTION_DISCOVERY,
        extra={
            "addr": addr,
            "mode": mode,
            "window": window,
            "low_memory": bool(low_memory),
            "recovery_policy": "lazy-candidate-timeout-v1",
        },
    ))


def _lookup_persistent_recovery_timeout(
    *,
    binary_path: Path | None,
    addr: int,
    mode: str,
    window: int,
    low_memory: bool,
    timeout: int,
) -> tuple[FunctionWorkResult | None, str, dict[str, object] | None]:
    cache_key = _persistent_recovery_attempt_cache_key(
        binary_path=binary_path,
        addr=addr,
        mode=mode,
        window=window,
        low_memory=low_memory,
    )
    cached = _load_cache_json("function_recovery_attempt", cache_key) if cache_key is not None else None
    if not isinstance(cached, dict) or cached.get("status") is None:
        return None, "", cache_key
    name = str(cached.get("name") or f"sub_{addr:x}")
    return (
        None,
        (
            f"[dbg] ignoring cached failed recovery for {addr:#x} {name} "
            f"mode={mode}; only successful decompilation results are cached\n"
        ),
        cache_key,
    )


def _recover_candidate_with_timeout(
    project: angr.Project,
    *,
    candidate_addr: int,
    image_end: int,
    metadata: LSTMetadata | None,
    project_entry: int,
    region_span: int,
    timeout: int,
    binary_path: Path,
    linked_base: int,
    exact_region: tuple[int, int] | None = None,
    seed_calling_conventions_enabled: bool = True,
) -> _FunctionCfgPair:
    """Recover one candidate once under the timeout lane available to this thread."""
    cached_result = (
        _lookup_candidate_recovery_cache(
            project,
            candidate_addr=candidate_addr,
            image_end=image_end,
            project_entry=project_entry,
            region_span=region_span,
            exact_region=exact_region,
        )
        if seed_calling_conventions_enabled
        else None
    )
    if isinstance(cached_result, tuple):
        cache_status = cached_result[0]
        if cache_status == "ok":
            return cast(_FunctionCfgPair, cached_result[1])
        if cache_status == "keyerror":
            raise KeyError(cached_result[1])

    ctx = _CandidateRecoveryCtx8616(
        candidate_addr=candidate_addr,
        image_end=image_end,
        metadata=metadata,
        project_entry=project_entry,
        region_span=region_span,
        exact_region=exact_region,
        seed_calling_conventions_enabled=seed_calling_conventions_enabled,
    )

    def _recover_once() -> _FunctionCfgPair:
        return _recover_once_with_cache_8616(project, ctx, binary_path, linked_base)

    timeout = max(1, int(timeout))
    if threading.current_thread() is threading.main_thread():
        with _analysis_timeout(timeout):
            return _recover_once()
    return _function_cfg_pair_object(_run_with_timeout_in_daemon_thread(
        _recover_once,
        timeout=timeout,
        thread_name_prefix="recover-candidate",
    ))


@dataclass(frozen=True, slots=True)
class _CandidateRecoveryCtx8616:
    """Inputs shared by the cached candidate-recovery attempts."""

    candidate_addr: int
    image_end: int
    metadata: LSTMetadata | None
    project_entry: int
    region_span: int
    exact_region: tuple[int, int] | None
    seed_calling_conventions_enabled: bool


def _recover_pair_in_project_8616(
    candidate_project: angr.Project, ctx: _CandidateRecoveryCtx8616
) -> _FunctionCfgPair:
    """Recover the candidate pair inside the given project."""
    return _function_cfg_pair_object(_recover_candidate_function_pair(
        candidate_project,
        candidate_addr=ctx.candidate_addr,
        image_end=ctx.image_end,
        metadata=ctx.metadata,
        project_entry=ctx.project_entry,
        region_span=ctx.region_span,
        exact_region=ctx.exact_region,
        seed_calling_conventions_enabled=ctx.seed_calling_conventions_enabled,
    ))


def _store_recovery_cache_value_8616(
    project: angr.Project, ctx: _CandidateRecoveryCtx8616, value: _CandidateRecoveryCacheValue
) -> None:
    """Store a recovery result in the candidate cache when enabled."""
    if not ctx.seed_calling_conventions_enabled:
        return
    _store_candidate_recovery_cache(
        project,
        candidate_addr=ctx.candidate_addr,
        image_end=ctx.image_end,
        project_entry=ctx.project_entry,
        region_span=ctx.region_span,
        exact_region=ctx.exact_region,
        value=value,
    )


def _recover_once_with_cache_8616(
    project: angr.Project,
    ctx: _CandidateRecoveryCtx8616,
    binary_path: Path,
    linked_base: int,
) -> _FunctionCfgPair:
    """Recover the candidate once, caching ok/keyerror outcomes."""
    try:
        recovered_pair = _recover_pair_in_project_8616(project, ctx)
        _store_recovery_cache_value_8616(project, ctx, ("ok", recovered_pair))
        return recovered_pair
    except KeyError as exc:
        _store_recovery_cache_value_8616(project, ctx, ("keyerror", str(exc)))
        raise
    except Exception:
        candidate_project = _build_project_cached(
            str(binary_path),
            force_blob=False,
            base_addr=linked_base,
            entry_point=ctx.project_entry,
        )
        recovered_pair = _recover_pair_in_project_8616(candidate_project, ctx)
        _store_recovery_cache_value_8616(project, ctx, ("ok", recovered_pair))
        return recovered_pair


def _seeded_recovery_empty_result(return_addrs: bool) -> _SeededRecoveryResult:
    return ([], []) if return_addrs else []


def _load_seeded_recovery_from_cache(
    *,
    project: angr.Project,
    timeout: int,
    limit: int | None,
    region_span: int,
    per_function_timeout: int,
    return_addrs: bool,
    cache_key: dict[str, object] | None,
) -> _SeededRecoveryResult | None:
    if cache_key is None:
        return None
    cached_payload = _load_cache_json("recovery", cache_key)
    if not isinstance(cached_payload, dict):
        return None
    raw_cached_addrs = cached_payload.get("addrs")
    if not (isinstance(raw_cached_addrs, list) and all(isinstance(addr, int) for addr in raw_cached_addrs)):
        return None
    cached_addrs = cast(list[int], raw_cached_addrs)
    cached_recovered = _recover_cached_function_pairs(
        project,
        addrs=cached_addrs,
        timeout=timeout,
        limit=limit,
        region_span=region_span,
        per_function_timeout=per_function_timeout,
    )
    if not cached_recovered:
        return None
    with contextlib.suppress(FuturesTimeoutError):
        cached_recovered, cached_addrs = _run_with_timeout_in_daemon_thread(
            lambda: _supplement_cached_seeded_recovery(
                project,
                cached_recovered,
                list(cached_addrs),
                region_span=region_span,
                per_function_timeout=per_function_timeout,
                limit=limit,
                cache_key=cache_key,
            ),
            timeout=min(max(2, timeout), 4),
            thread_name_prefix="cached-supplement",
        )
    return (cached_recovered, cached_addrs) if return_addrs else cached_recovered


def _queue_new_seed_targets_8616(
    target_addrs: list[int],
    *,
    seen_addrs: set[int],
    queued_addrs: set[int],
    covered_ranges: list[tuple[int, int]],
    linked_base: int,
    image_end: int,
    queue_name: str,
    pending_gap_addrs: list[int],
    pending_neighbor_addrs: list[int],
) -> None:
    queued_targets: list[int] = []
    for target_addr in target_addrs:
        if target_addr in seen_addrs or target_addr in queued_addrs:
            continue
        if _addr_in_ranges(target_addr, covered_ranges):
            continue
        if not (linked_base <= target_addr < image_end):
            continue
        queued_targets.append(target_addr)
    if not queued_targets:
        return
    if queue_name == "gap":
        pending_gap_addrs.extend(queued_targets)
    else:
        pending_neighbor_addrs.extend(queued_targets)
    queued_addrs.update(queued_targets)


def _recover_seeded_exe_functions(
    project: angr.Project,
    *,
    timeout: int,
    limit: int | None,
    region_span: int = 0x120,
    per_function_timeout: int = 1,
    return_addrs: bool = False,
    include_library_functions: bool | None = None,
) -> _SeededRecoveryResult:
    def _impl() -> _SeededRecoveryResult:
        image = _seeded_image_context_8616(project)
        if image is None:
            return _seeded_recovery_empty_result(return_addrs)
        binary_path, linked_base, max_addr = image

        ranked_seeds = _rank_exe_function_seeds(
            project,
            include_library_functions=include_library_functions,
        )
        if not ranked_seeds:
            return _seeded_recovery_empty_result(return_addrs)

        deadline = time.monotonic() + max(1, timeout)
        state = _SeededRecoveryState8616(
            seen_addrs={project.entry},
            queued_addrs=set(ranked_seeds),
            pending_seed_addrs=list(ranked_seeds),
        )
        metadata = _dynamic_attr(project, "_inertia_lst_metadata", None)
        image_end = linked_base + max_addr + 1
        cache_key = _recovery_cache_key(
            binary_path=Path(binary_path),
            kind="seeded_function_catalog",
            source_scope=RecoveryCacheSourceScope8616.FUNCTION_DISCOVERY,
            extra={
                "entry": _dynamic_attr(project, "entry", None),
                "linked_base": linked_base,
                "max_addr": max_addr,
                "region_span": region_span,
            },
        )
        cached_result = _load_seeded_recovery_from_cache(
            project=project,
            timeout=timeout,
            limit=limit,
            region_span=region_span,
            per_function_timeout=per_function_timeout,
            return_addrs=return_addrs,
            cache_key=cache_key,
        )
        if cached_result is not None:
            return cached_result

        _inject_prologue_seed_targets_8616(project, state, linked_base, image_end)

        ctx = _SeededExeCtx8616(
            metadata=metadata,
            image_end=image_end,
            binary_path=Path(binary_path),
            linked_base=linked_base,
            region_span=region_span,
            per_function_timeout=per_function_timeout,
            limit=limit,
            return_addrs=return_addrs,
        )
        while True:
            addr = _pop_pending_seed_addr_8616(state)
            if addr is None:
                break
            if _addr_in_ranges(addr, state.covered_ranges):
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if not _process_seeded_addr_8616(project, ctx, state, addr, remaining):
                break

        _finalize_seeded_recovery_8616(state, cache_key)
        return (state.recovered, state.recovered_addrs) if return_addrs else state.recovered

    return _impl()


def _seeded_image_context_8616(project: angr.Project) -> tuple[_AngrObject, int, int] | None:
    """Resolve binary path, linked base, and max addr for seeded recovery."""
    main_object = _dynamic_attr(project.loader, "main_object", None)
    if main_object is None:
        return None
    binary_path = _dynamic_attr(main_object, "binary", None)
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    if binary_path is None or not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return None
    return binary_path, linked_base, max_addr


@dataclass
class _SeededRecoveryState8616:
    """Mutable queue/range state for seeded EXE recovery."""

    recovered: list[_FunctionCfgPair] = field(default_factory=list)
    recovered_addrs: list[int] = field(default_factory=list)
    seen_addrs: set[int] = field(default_factory=set)
    queued_addrs: set[int] = field(default_factory=set)
    pending_seed_addrs: list[int] = field(default_factory=list)
    pending_gap_addrs: list[int] = field(default_factory=list)
    pending_neighbor_addrs: list[int] = field(default_factory=list)
    covered_ranges: list[tuple[int, int]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _SeededExeCtx8616:
    """Shared inputs for seeded EXE candidate processing."""

    metadata: LSTMetadata | None
    image_end: int
    binary_path: Path
    linked_base: int
    region_span: int
    per_function_timeout: int
    limit: int | None
    return_addrs: bool


def _inject_prologue_seed_targets_8616(
    project: angr.Project,
    state: _SeededRecoveryState8616,
    linked_base: int,
    image_end: int,
) -> None:
    """Prepend early prologue candidates to the seed queue when available."""
    prologue_candidates = _rank_prologue_scan_candidate_addrs(
        project, state.seen_addrs | state.queued_addrs
    )
    if not prologue_candidates:
        return
    initial_prologue_targets = [
        addr
        for addr in prologue_candidates[:8]
        if addr not in state.seen_addrs
        and addr not in state.queued_addrs
        and linked_base <= addr < image_end
    ]
    if initial_prologue_targets:
        state.pending_seed_addrs[:0] = initial_prologue_targets
        state.queued_addrs.update(initial_prologue_targets)


def _pop_pending_seed_addr_8616(state: _SeededRecoveryState8616) -> int | None:
    """Pop the next queued address in seed→gap→neighbor order."""
    if state.pending_seed_addrs:
        return state.pending_seed_addrs.pop(0)
    if state.pending_gap_addrs:
        return state.pending_gap_addrs.pop(0)
    if state.pending_neighbor_addrs:
        return state.pending_neighbor_addrs.pop(0)
    return None


def _queue_follow_on_targets_8616(
    project: angr.Project,
    ctx: _SeededExeCtx8616,
    state: _SeededRecoveryState8616,
    function_cfg: _AngrCfg,
    function: _AngrFunction,
) -> None:
    """Queue gap or neighbor follow-on targets for a recovered function."""
    if _needs_pre_entry_body_supplement(function, project.entry):
        _queue_new_seed_targets_8616(
            _prioritized_pre_entry_follow_on_targets(
                project,
                [(function_cfg, function)],
                covered_ranges=state.covered_ranges,
                existing_addrs=state.seen_addrs | state.queued_addrs,
                image_end=ctx.image_end,
            ),
            seen_addrs=state.seen_addrs,
            queued_addrs=state.queued_addrs,
            covered_ranges=state.covered_ranges,
            linked_base=ctx.linked_base,
            image_end=ctx.image_end,
            queue_name="gap",
            pending_gap_addrs=state.pending_gap_addrs,
            pending_neighbor_addrs=state.pending_neighbor_addrs,
        )
        return
    neighbor_targets: list[int] = []
    for target in collect_neighbor_call_targets(function):
        target_addr = _dynamic_attr(target, "target_addr", None)
        if isinstance(target_addr, int):
            neighbor_targets.append(target_addr)
    _queue_new_seed_targets_8616(
        neighbor_targets,
        seen_addrs=state.seen_addrs,
        queued_addrs=state.queued_addrs,
        covered_ranges=state.covered_ranges,
        linked_base=ctx.linked_base,
        image_end=ctx.image_end,
        queue_name="neighbor",
        pending_gap_addrs=state.pending_gap_addrs,
        pending_neighbor_addrs=state.pending_neighbor_addrs,
    )


def _process_seeded_addr_8616(
    project: angr.Project,
    ctx: _SeededExeCtx8616,
    state: _SeededRecoveryState8616,
    addr: int,
    remaining: float,
) -> bool:
    """Recover one queued address; return False when the scan should stop."""
    try:
        function_cfg, function = _recover_candidate_with_timeout(
            project,
            candidate_addr=addr,
            image_end=ctx.image_end,
            metadata=ctx.metadata,
            project_entry=project.entry,
            region_span=ctx.region_span,
            timeout=min(ctx.per_function_timeout, max(1, int(remaining))),
            binary_path=ctx.binary_path,
            linked_base=ctx.linked_base,
        )
    except (_AnalysisTimeout, KeyError):
        return True
    except Exception:
        return True

    if function.addr in state.seen_addrs:
        return True
    reason = _function_skip_reason(function)
    if reason is not None:
        return True
    state.seen_addrs.add(function.addr)
    state.recovered_addrs.append(function.addr)
    if ctx.limit is None or len(state.recovered) < ctx.limit:
        state.recovered.append((function_cfg, function))
    state.covered_ranges.extend(_function_covered_ranges(function))

    if ctx.limit is not None and not ctx.return_addrs and len(state.recovered) >= ctx.limit:
        return False

    _queue_follow_on_targets_8616(project, ctx, state, function_cfg, function)
    return True


def _finalize_seeded_recovery_8616(
    state: _SeededRecoveryState8616,
    cache_key: dict[str, object] | None,
) -> None:
    """Persist recovered addrs and report the seeded scan outcome."""
    if not state.recovered_addrs:
        return
    if cache_key is not None:
        _store_cache_json(
            "recovery",
            cache_key,
            {"addrs": state.recovered_addrs},
        )
    print(f"/* quick function-entry scan recovered {len(state.recovered_addrs)} additional function(s). */")


def _direct_recovery_inventory_count(project: angr.Project) -> int | None:
    try:
        ranked_seeds = _rank_exe_function_seeds(project)
    except Exception:
        return None
    return len(ranked_seeds) if ranked_seeds else None


def _fallback_entry_function(
    project: angr.Project,
    *,
    timeout: int,
    window: int,
    low_memory: bool = False,
    prefer_fast_recovery: bool = False,
) -> _FunctionCfgPair:
    # If whole-binary recovery already timed out, prefer a much smaller bounded
    # entry-only recovery window instead of retrying the same expensive search.
    # When memory pressure is high, keep the scan even narrower so the fallback
    # uses less memory and avoids the whole-binary CFG path entirely.
    def _impl() -> _FunctionCfgPair:
        dynamic_project = cast(_AngrObject, project)
        dynamic_project._inertia_decompiler_stage = "recovery"
        candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
        recovery_timeout = max(1, timeout if prefer_fast_recovery else min(timeout, 10))

        with _analysis_timeout(recovery_timeout):
            if prefer_fast_recovery:
                pair = _try_fast_entry_recovery_8616(project, dynamic_project, window, low_memory)
                if pair is not None:
                    return pair

            pair = _try_narrow_entry_recovery_8616(project, dynamic_project, candidate_windows)
            if pair is not None:
                return pair
            raise _AnalysisTimeout

    return _impl()


def _repair_recovered_entry_function_8616(
    project: angr.Project,
    result: _FunctionCfgPair,
    regions: Sequence[tuple[int, int]],
) -> _FunctionCfgPair:
    """Stitch and repair a recovered entry function inside its region."""
    if project.arch.name != "86_16":
        return result
    if not isinstance(result, tuple) or len(result) != 2:
        return result
    if not regions:
        return result
    cfg, function = result
    region = regions[0]
    try:
        stitched_func, stitched = _stitch_x86_16_exact_function_8616(
            project,
            function,
            region,
        )
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "x86-16 fallback entry stitching failed for %s: %s",
            hex(project.entry),
            ex,
        )
        stitched_func, stitched = function, False
    if stitched:
        _mark_x86_16_stitched_recovery_8616(stitched_func)
        function = stitched_func
    _repair_x86_16_function_graph_8616(project, function, exact_region=region)
    return cfg, function


def _try_fast_entry_recovery_8616(
    project: angr.Project,
    dynamic_project: _AngrObject,
    window: int,
    low_memory: bool,
) -> _FunctionCfgPair | None:
    """Try the small fast-recovery windows before the narrow fallback."""
    dynamic_project._inertia_decompiler_stage = "recovery:fast"
    for fast_window in _x86_16_fast_recovery_windows(window, low_memory=low_memory):
        try:
            if project.arch.name == "86_16":
                fast_regions = [_infer_x86_16_linear_region(project, project.entry, window=fast_window)]
            else:
                fast_regions = [(project.entry, project.entry + fast_window)]
            return _repair_recovered_entry_function_8616(
                project,
                _pick_function_lean(
                    project,
                    project.entry,
                    regions=fast_regions,
                    data_references=False,
                    extend_far_calls=False,
                ),
                fast_regions,
            )
        except (KeyError, _AnalysisTimeout):
            continue
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Skipping fast x86-16 recovery for %s after %s",
                hex(project.entry),
                ex,
            )
            continue
    return None


def _try_narrow_entry_recovery_8616(
    project: angr.Project,
    dynamic_project: _AngrObject,
    candidate_windows: tuple[int, ...],
) -> _FunctionCfgPair | None:
    """Try bounded narrow-window entry recovery, lean then data-referenced."""
    for candidate_window in candidate_windows:
        try:
            dynamic_project._inertia_decompiler_stage = f"recovery:narrow:{candidate_window:#x}"
            if project.arch.name == "86_16":
                regions = [_infer_x86_16_linear_region(project, project.entry, window=candidate_window)]
            else:
                regions = [(project.entry, project.entry + candidate_window)]
            try:
                return _repair_recovered_entry_function_8616(
                    project,
                    _pick_function(
                        project,
                        project.entry,
                        regions=regions,
                        data_references=False,
                        force_smart_scan=False,
                    ),
                    regions,
                )
            except KeyError:
                pass
            return _repair_recovered_entry_function_8616(
                project,
                _pick_function(
                    project,
                    project.entry,
                    regions=regions,
                    data_references=True if project.arch.name == "86_16" else None,
                ),
                regions,
            )
        except _AnalysisTimeout:
            raise
        except KeyError:
            continue
    return None


def _derive_lst_exact_region_8616(
    project: angr.Project,
    lst_metadata: LSTMetadata,
    *,
    addr: int,
    name: str,
) -> tuple[int, int] | None:
    def _impl() -> tuple[int, int] | None:
        exact_region = _lst_code_region(lst_metadata, addr)
        if exact_region is None and isinstance(name, str) and name:
            exact_region = _lst_region_by_label_name_8616(lst_metadata, addr, name)
        exact_region = _adjust_region_to_inner_prologue_8616(project, exact_region, addr, name)
        exact_region = _adjust_region_past_padding_8616(project, exact_region, name)
        if project.arch.name == "86_16" and exact_region is not None:
            exact_region = _extend_and_validate_exact_region_8616(project, exact_region)
        if (
            isinstance(exact_region, tuple)
            and len(exact_region) == 2
            and all(isinstance(value, int) for value in exact_region)
        ):
            return exact_region[0], exact_region[1]
        return None

    return _impl()


def _lst_region_by_label_name_8616(
    lst_metadata: LSTMetadata, addr: int, name: str
) -> tuple[int, int] | None:
    """Recover an exact region by matching a visible sidecar label name."""
    target_names = {name, name.lstrip("_")}
    label_candidates: list[tuple[int, tuple[int, int]]] = []
    for label_addr, label_name in (_visible_code_labels(lst_metadata) or {}).items():
        if not isinstance(label_name, str) or label_name not in target_names:
            continue
        span = _lst_code_region(lst_metadata, label_addr)
        if span is None:
            continue
        label_candidates.append((abs(int(label_addr) - int(addr)), span))
    if not label_candidates:
        return None
    label_candidates.sort(key=lambda item: item[0])
    exact_region = label_candidates[0][1]
    print(
        f"[dbg] recovered exact-region by sidecar name for {name}: "
        f"{exact_region[0]:#x}-{exact_region[1]:#x}",
        file=sys.stderr,
        flush=True,
    )
    return exact_region


def _adjust_region_to_inner_prologue_8616(
    project: angr.Project,
    exact_region: tuple[int, int] | None,
    addr: int,
    name: str,
) -> tuple[int, int] | None:
    """Shrink a containing sidecar span to the addr's own prologue."""
    if (
        project.arch.name != "86_16"
        or exact_region is None
        or not isinstance(addr, int)
        or not (exact_region[0] < addr < exact_region[1])
    ):
        return exact_region
    try:
        probe = bytes(project.loader.memory.load(addr, min(4, max(0, exact_region[1] - addr))))
    except Exception:
        probe = b""
    if _looks_like_x86_16_function_prologue(probe, 0):
        exact_region = (addr, exact_region[1])
        print(
            f"[dbg] adjusted exact-region start for {name}: "
            f"{addr:#x}-{exact_region[1]:#x} (from containing sidecar span)"
        )
    return exact_region


def _adjust_region_past_padding_8616(
    project: angr.Project,
    exact_region: tuple[int, int] | None,
    name: str,
) -> tuple[int, int] | None:
    """Advance the region start past leading sidecar padding."""
    if project.arch.name != "86_16" or exact_region is None:
        return exact_region
    start, end = exact_region
    try:
        probe = bytes(
            project.loader.memory.load(
                start,
                min(_X86_16_EXACT_REGION_PADDING_SCAN_LIMIT, max(0, end - start)),
            )
        )
    except Exception:
        probe = b""
    resolved_start = _resolve_x86_16_function_start(
        probe,
        0,
        max_padding=_X86_16_EXACT_REGION_PADDING_SCAN_LIMIT,
    )
    if isinstance(resolved_start, int) and resolved_start > 0:
        adjusted_start = start + resolved_start
        if adjusted_start < end:
            exact_region = (adjusted_start, end)
            print(
                f"[dbg] adjusted exact-region start for {name}: "
                f"{adjusted_start:#x}-{end:#x} (from sidecar padding)"
            )
    return exact_region


def _extend_and_validate_exact_region_8616(
    project: angr.Project, exact_region: tuple[int, int]
) -> tuple[int, int] | None:
    """Extend to cover a terminator and refuse tiny terminator-less regions."""
    extended_region = _maybe_extend_x86_16_exact_region_terminator(project, exact_region)
    if extended_region is None:
        return None
    exact_region = extended_region
    exact_size = max(0, exact_region[1] - exact_region[0])
    if exact_size <= 0x20 and not _x86_16_exact_region_has_terminator(project, exact_region):
        return None
    return exact_region


def _try_rebased_exact_region_recovery_8616(
    project: angr.Project,
    *,
    exact_region: tuple[int, int] | None,
    caller_target_addrs: tuple[int, ...] = (),
    function_ranges: tuple[tuple[int, int], ...] = (),
    timeout: int,
    name: str,
) -> _FunctionCfgPair | None:
    """Recover an adjusted exact slice while preserving its callable-entry evidence identity."""
    if project.arch.name != "86_16" or exact_region is None:
        return None
    exact_region_size = max(0, exact_region[1] - exact_region[0])
    loader = _dynamic_attr(project, "loader", None)
    project_memory = _dynamic_attr(loader, "memory", None)
    if project_memory is None or not hasattr(project_memory, "load"):
        return None
    slice_plan = plan_x86_16_exact_slice(*exact_region)
    enable_rebased_exact_slice = _env_flag_enabled_8616("INERTIA_ENABLE_REBASED_EXACT_SLICE", "1")
    use_rebased_exact_slice = (
        enable_rebased_exact_slice and slice_plan.needs_rebased_slice and 0x20 <= exact_region_size <= 0x280
    )
    if not use_rebased_exact_slice:
        return None
    code = bytes(
        project.loader.memory.load(slice_plan.original_start, slice_plan.original_end - slice_plan.original_start)
    )
    if code:
        nop_ratio = float(code.count(0x90)) / float(len(code))
        if nop_ratio > 0.30:
            return None
    slice_project = _build_rebased_slice_project_8616(
        project, code, slice_plan, exact_region, function_ranges, caller_target_addrs, exact_region_size
    )
    slice_region = (slice_plan.slice_start, slice_plan.slice_end)
    cfg, func = _recover_rebased_slice_func_8616(slice_project, slice_plan, slice_region, timeout, name)
    _commit_exact_region_function_to_kb_8616(slice_project, cfg, func, slice_region)
    mark_function_original_addr(func, exact_region[0])
    _repair_x86_16_function_graph_8616(slice_project, func, exact_region=slice_region)
    _record_rebased_slice_evidence_8616(
        project, slice_project, func, slice_region, exact_region, caller_target_addrs, function_ranges
    )
    print(
        f"[dbg] rebased exact-region recovery for {name}: "
        f"{exact_region[0]:#x}-{exact_region[1]:#x} -> {slice_region[0]:#x}-{slice_region[1]:#x}"
    )
    return cfg, func


def _build_rebased_slice_project_8616(
    project: angr.Project,
    code: bytes,
    slice_plan: X86ExactSlicePlan,
    exact_region: tuple[int, int],
    function_ranges: tuple[tuple[int, int], ...],
    caller_target_addrs: tuple[int, ...],
    exact_region_size: int,
) -> angr.Project:
    """Build the rebased slice project and inherit caller policy."""
    slice_project = _build_project_from_bytes(
        code,
        base_addr=slice_plan.slice_base,
        entry_point=slice_plan.slice_start,
    )
    dynamic_slice_project = cast(_AngrObject, slice_project)
    dynamic_slice_project._inertia_original_project = project
    dynamic_slice_project._inertia_original_linear_delta = exact_region[0] - slice_plan.slice_start
    dynamic_slice_project._inertia_caller_function_ranges_8616 = function_ranges
    dynamic_slice_project._inertia_caller_target_aliases_8616 = caller_target_addrs
    c_target = _dynamic_attr(project, "_inertia_c_target", None)
    if isinstance(c_target, str):
        dynamic_slice_project._inertia_c_target = c_target
    tiny_rebased_core = exact_region_size <= 0x30
    dynamic_slice_project._inertia_disable_ail_narrowing = tiny_rebased_core
    dynamic_slice_project._inertia_disable_complex_expr_scan = tiny_rebased_core
    dynamic_slice_project._inertia_fast_block_peephole = tiny_rebased_core
    _inherit_tail_validation_runtime_policy(slice_project, project)
    return slice_project


def _recover_rebased_slice_func_8616(
    slice_project: angr.Project,
    slice_plan: X86ExactSlicePlan,
    slice_region: tuple[int, int],
    timeout: int,
    name: str,
) -> _FunctionCfgPair:
    """Recover and stitch the rebased slice function."""
    with _analysis_timeout(max(1, timeout)):
        try:
            cfg, func = _pick_function_lean(
                slice_project,
                slice_plan.slice_start,
                regions=[slice_region],
                data_references=False,
                extend_far_calls=False,
            )
        except KeyError:
            cfg, func = _pick_function(
                slice_project,
                slice_plan.slice_start,
                regions=[slice_region],
                data_references=False,
                force_smart_scan=False,
            )
    try:
        stitched_func, stitched = _stitch_x86_16_exact_function_8616(
            slice_project,
            func,
            slice_region,
        )
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "x86-16 rebased exact function stitching failed for %s: %s",
            hex(slice_plan.slice_start),
            ex,
        )
        stitched_func, stitched = func, False
    if stitched:
        func = stitched_func
        _mark_x86_16_stitched_recovery_8616(func)
    func.name = name
    return cfg, func


def _record_rebased_slice_evidence_8616(
    project: angr.Project,
    slice_project: angr.Project,
    func: _AngrFunction,
    slice_region: tuple[int, int],
    exact_region: tuple[int, int],
    caller_target_addrs: tuple[int, ...],
    function_ranges: tuple[tuple[int, int], ...],
) -> None:
    """Record caller/callee return-use evidence and inherit source info."""
    caller_evidence_targets = tuple(dict.fromkeys((*caller_target_addrs, exact_region[0])))
    caller_return_use = _collect_caller_return_use_for_entry_aliases_8616(
        project,
        caller_evidence_targets,
        function_ranges,
    )
    if caller_return_use is not None:
        _record_caller_return_use_evidence_8616(slice_project, slice_region[0], caller_return_use)
        for caller_evidence_target in caller_evidence_targets:
            _record_caller_return_use_evidence_8616(project, caller_evidence_target, caller_return_use)
    direct_callee_return_use = _collect_direct_callee_return_use_evidence_8616(
        project,
        func,
        function_ranges,
    )
    for target_addr, evidence in direct_callee_return_use.items():
        _record_caller_return_use_evidence_8616(project, target_addr, evidence)
        _record_caller_return_use_evidence_8616(slice_project, target_addr, evidence)
    with contextlib.suppress(Exception):
        source_func = project.kb.functions.function(addr=exact_region[0], create=False)
        source_info = _dynamic_attr(source_func, "info", None) if source_func is not None else None
        if isinstance(source_info, dict):
            func_info = _dynamic_attr(func, "info", None)
            if not isinstance(func_info, dict):
                func_info = {}
                func.info = func_info
            for key, value in source_info.items():
                func_info.setdefault(key, value)


def _recover_lst_function(
    project: angr.Project,
    lst_metadata: LSTMetadata,
    offset: int,
    name: str,
    *,
    timeout: int,
    window: int,
    low_memory: bool = False,
    allow_rebased_exact_slice: bool = True,
) -> _FunctionCfgPair:
    """Recover one metadata-bounded function with an explicit slice policy."""
    function_entry_addrs = lst_metadata.function_entry_addrs
    function_ranges = tuple(
        lst_metadata.code_ranges[entry_addr]
        for entry_addr in sorted(function_entry_addrs)
        if entry_addr in lst_metadata.code_ranges
    ) if function_entry_addrs else tuple(lst_metadata.code_ranges.values())

    def _impl() -> _FunctionCfgPair:
        addr = offset if lst_metadata.absolute_addrs else project.entry + offset
        exact_region = _derive_lst_exact_region_8616(project, lst_metadata, addr=addr, name=name)
        caller_target_addrs = _caller_target_aliases_for_lst_function_8616(
            lst_metadata,
            recovered_addr=addr,
            name=name,
        )
        rebased = (
            _try_rebased_exact_region_recovery_8616(
                project,
                exact_region=exact_region,
                caller_target_addrs=caller_target_addrs,
                function_ranges=function_ranges,
                timeout=timeout,
                name=name,
            )
            if allow_rebased_exact_slice
            else None
        )
        if rebased is not None:
            return rebased
        with _analysis_timeout(max(1, timeout)):
            if project.arch.name == "86_16":
                cfg, func = _recover_lst_bounded_pair_8616(
                    project, lst_metadata, addr, exact_region, window, low_memory, name
                )
            else:
                regions = [(addr, addr + window)]
                cfg, func = _pick_function(project, addr, regions=regions)

        func = _promote_region_function_8616(cfg, func, exact_region, addr, name)

        func.name = name
        if exact_region is not None:
            _commit_exact_region_function_to_kb_8616(project, cfg, func, exact_region)
        return cfg, func

    return _impl()


def _lst_recovery_regions_8616(
    project: angr.Project,
    addr: int,
    exact_region: tuple[int, int] | None,
    candidate_window: int,
) -> list[tuple[int, int]]:
    """Resolve recovery regions for one candidate window."""
    if exact_region is not None:
        return [exact_region]
    return [_infer_x86_16_linear_region(project, addr, window=candidate_window)]


def _try_lean_lst_windows_8616(
    project: angr.Project,
    addr: int,
    exact_region: tuple[int, int] | None,
    fast_windows: tuple[int, ...],
) -> _FunctionCfgPair | None:
    """Try the lean CFGFast path across fast recovery windows."""
    for candidate_window in fast_windows:
        regions = _lst_recovery_regions_8616(project, addr, exact_region, candidate_window)
        try:
            return _pick_function_lean(
                project,
                addr,
                regions=regions,
                data_references=False,
                extend_far_calls=False,
            )
        except KeyError:
            continue
        except _AnalysisTimeout:
            raise
        except Exception:
            # Lean CFGFast is a best-effort acceleration path.
            # If a lightweight test/project stub cannot support it,
            # fall back to regular bounded recovery windows.
            continue
    return None


def _report_region_split_diagnostics_8616(
    cfg: _AngrCfg,
    func: _AngrFunction,
    exact_region: tuple[int, int],
    name: str,
) -> None:
    """Report region-split diagnostics for a truncated exact-region recovery."""
    block_addrs = tuple(
        int(_dynamic_attr(block, "addr"))
        for block in tuple(_dynamic_attr(func, "blocks", ()) or ())
        if isinstance(_dynamic_attr(block, "addr", None), int)
    )
    cfg_functions = _dynamic_attr(_dynamic_attr(cfg, "kb", None), "functions", None)
    diagnostics = build_exact_region_diagnostics_8616(
        name,
        requested_start=exact_region[0],
        requested_end=exact_region[1],
        covered_block_addrs=block_addrs,
        cfg_functions=cfg_functions,
        proc_identity=name,
    )
    split = classify_region_split_8616(diagnostics)
    if split.is_split:
        print(
            f"[dbg] {format_exact_region_diagnostics_8616(diagnostics)}",
            file=sys.stderr,
            flush=True,
        )


def _stitch_best_lst_func_8616(
    project: angr.Project,
    best_func: _AngrFunction,
    exact_region: tuple[int, int],
    addr: int,
) -> _AngrFunction:
    """Attempt an exact-region stitch over the current best function."""
    try:
        stitched_func, stitched = _stitch_x86_16_exact_function_8616(
            project,
            best_func,
            exact_region,
        )
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "x86-16 exact function stitching failed for %s: %s",
            hex(addr),
            ex,
        )
        return best_func
    if stitched:
        _mark_x86_16_stitched_recovery_8616(stitched_func)
        return stitched_func
    return best_func


def _retry_exact_region_pairs_8616(
    project: angr.Project,
    addr: int,
    best_cfg: _AngrCfg,
    best_func: _AngrFunction,
    exact_region: tuple[int, int],
) -> _FunctionCfgPair:
    """Retry recovery across data-reference modes, keeping the better candidate."""
    for data_refs in (False, True):
        try:
            retried_cfg, retried_func = _pick_function(
                project,
                addr,
                regions=[exact_region],
                data_references=data_refs,
                force_smart_scan=False,
            )
        except KeyError:
            continue
        if _should_replace_exact_region_candidate_8616(
            best_func,
            retried_func,
            exact_region,
        ):
            best_cfg = retried_cfg
            best_func = retried_func
    return best_cfg, best_func


def _escalate_truncated_lst_pair_8616(
    project: angr.Project,
    lst_metadata: LSTMetadata,
    addr: int,
    best_cfg: _AngrCfg,
    best_func: _AngrFunction,
    exact_region: tuple[int, int],
    window: int,
) -> _FunctionCfgPair:
    """Escalate to richer candidate-pair recovery for a truncated region."""
    if not _exact_region_recovery_looks_truncated(best_func, exact_region):
        return best_cfg, best_func
    main_object = _dynamic_attr(project.loader, "main_object", None)
    linked_base = _dynamic_attr(main_object, "linked_base", None)
    max_addr = _dynamic_attr(main_object, "max_addr", None)
    if isinstance(linked_base, int) and isinstance(max_addr, int):
        try:
            cand_cfg, cand_func = _recover_candidate_function_pair(
                project,
                candidate_addr=addr,
                image_end=linked_base + max_addr + 1,
                metadata=lst_metadata,
                project_entry=project.entry,
                region_span=max(
                    window,
                    max(0x180, exact_region[1] - exact_region[0]),
                ),
            )
            if _should_replace_exact_region_candidate_8616(
                best_func,
                cand_func,
                exact_region,
            ):
                best_cfg = cand_cfg
                best_func = cand_func
        except Exception:
            pass
    return best_cfg, best_func


def _pick_lst_fallback_pair_8616(
    project: angr.Project,
    addr: int,
    exact_region: tuple[int, int] | None,
    candidate_windows: tuple[int, ...],
) -> _FunctionCfgPair:
    """Fallback bounded recovery over the regular candidate windows."""
    last_error: Exception | None = None
    for candidate_window in candidate_windows:
        regions = _lst_recovery_regions_8616(project, addr, exact_region, candidate_window)
        try:
            return _pick_function(
                project,
                addr,
                regions=regions,
            )
        except KeyError as ex:
            last_error = ex
    if last_error is not None:
        raise last_error
    raise KeyError(f"Function {addr:#x} was not recovered by CFGFast.")


def _recover_lst_bounded_pair_8616(
    project: angr.Project,
    lst_metadata: LSTMetadata,
    addr: int,
    exact_region: tuple[int, int] | None,
    window: int,
    low_memory: bool,
    name: str,
) -> _FunctionCfgPair:
    """Recover an LST-bounded pair via lean, enriched, and fallback lanes."""
    can_run_default_lean = (
        hasattr(project, "analyses") or _pick_function_lean is not _DEFAULT_PICK_FUNCTION_LEAN
    )
    fast_windows = (
        _x86_16_fast_recovery_windows(window, low_memory=low_memory) if can_run_default_lean else ()
    )
    candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)

    lean_pair = _try_lean_lst_windows_8616(project, addr, exact_region, fast_windows)
    if lean_pair is None:
        return _pick_lst_fallback_pair_8616(project, addr, exact_region, candidate_windows)

    cfg, func = lean_pair
    if exact_region is not None and _exact_region_recovery_looks_truncated(func, exact_region):
        _report_region_split_diagnostics_8616(cfg, func, exact_region, name)
        best_func = _stitch_best_lst_func_8616(project, func, exact_region, addr)
        best_cfg, best_func = _retry_exact_region_pairs_8616(project, addr, cfg, best_func, exact_region)
        best_cfg, best_func = _escalate_truncated_lst_pair_8616(
            project, lst_metadata, addr, best_cfg, best_func, exact_region, window
        )
        cfg, func = best_cfg, best_func
    return cfg, func


def _promote_region_function_8616(
    cfg: _AngrCfg,
    func: _AngrFunction,
    exact_region: tuple[int, int] | None,
    addr: int,
    name: str,
) -> _AngrFunction:
    """Promote a richer region-local candidate over a tiny recovered function."""
    if exact_region is None:
        return func
    selected_blocks, selected_bytes = _function_recovery_score(func)
    selected_tiny = selected_blocks <= 2 and selected_bytes <= 0x20 and not _function_recovery_truncated(func)
    if not selected_tiny:
        return func
    promoted = _best_region_function_candidate(
        cfg,
        exact_region=exact_region,
        preferred_addr=addr,
    )
    if promoted is None:
        return func
    promoted_blocks, promoted_bytes = _function_recovery_score(promoted)
    if (promoted_bytes, promoted_blocks) > (selected_bytes, selected_blocks):
        print(
            f"[dbg] promoted exact-region candidate for {name}: "
            f"{func.addr:#x}({selected_blocks}/{selected_bytes}) -> "
            f"{promoted.addr:#x}({promoted_blocks}/{promoted_bytes})",
            file=sys.stderr,
            flush=True,
        )
        return promoted
    return func


def _recover_ranked_binary_function(
    project: angr.Project,
    addr: int,
    name: str,
    *,
    timeout: int,
    window: int,
    low_memory: bool = False,
) -> _FunctionCfgPair:
    def _impl() -> _FunctionCfgPair:
        with _analysis_timeout(max(1, timeout)):
            if project.arch.name == "86_16":
                fast_windows = _x86_16_fast_recovery_windows(window, low_memory=low_memory)
                candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
                last_error: Exception | None = None
                for candidate_window in fast_windows:
                    try:
                        cfg, func = _pick_function_lean(
                            project,
                            addr,
                            regions=[_infer_x86_16_linear_region(project, addr, window=candidate_window)],
                            data_references=False,
                            extend_far_calls=False,
                        )
                        break
                    except KeyError as ex:
                        last_error = ex
                else:
                    cfg = None
                    func = None

                if cfg is None or func is None:
                    last_error = None
                    for candidate_window in candidate_windows:
                        try:
                            cfg, func = _pick_function(
                                project,
                                addr,
                                regions=[_infer_x86_16_linear_region(project, addr, window=candidate_window)],
                            )
                            break
                        except KeyError as ex:
                            last_error = ex
                    else:
                        if last_error is not None:
                            raise last_error
                        raise KeyError(f"Function {addr:#x} was not recovered by CFGFast.")
            else:
                cfg, func = _pick_function(project, addr, regions=[(addr, addr + window)])

        func.name = name
        return cfg, func

    return _impl()


def _make_placeholder_function(project: angr.Project, addr: int, name: str) -> SimpleNamespace:
    return SimpleNamespace(
        addr=addr,
        name=name,
        project=project,
        is_plt=False,
        is_simprocedure=False,
    )


def _is_zero_filled_region(project: angr.Project, addr: int, *, size: int = 8) -> bool:
    try:
        data = bytes(project.loader.memory.load(addr, size))
    except Exception:
        return False
    return bool(data) and all(byte == 0x00 for byte in data)


def _is_plausible_code_seed(
    project: angr.Project,
    addr: int,
    *,
    metadata: LSTMetadata | None = None,
) -> bool:
    def _impl() -> bool:
        """Probe dynamic angr block/capstone data for plausible code bytes."""
        region = _lst_code_region(metadata, addr)
        probe_size = 16
        if region is not None:
            region_size = max(0, region[1] - region[0])
            if region_size == 0:
                return False
            probe_size = min(probe_size, region_size)
        if probe_size <= 0:
            return False
        try:
            data = bytes(project.loader.memory.load(addr, probe_size))
        except Exception:
            return True
        if not data or _bytes_uniform_8616(data):
            return False
        if region is not None and not _tiny_region_has_terminator_8616(project, addr, region):
            return False
        # If sidecar does not provide an exact code region and the seed begins with
        # a null-padded stream, treat it as data-like unless proven otherwise.
        if region is None:
            head = data[:8]
            if len(head) >= 4 and head[:2] == b"\x00\x00" and sum(1 for b in head if b == 0x00) >= 4:
                return False
        return True

    return _impl()


def _bytes_uniform_8616(data: bytes) -> bool:
    """Check whether probed bytes are uniformly 0x00 or 0xFF."""
    return all(byte == 0x00 for byte in data) or all(byte == 0xFF for byte in data)


def _tiny_region_has_terminator_8616(
    project: angr.Project, addr: int, region: tuple[int, int]
) -> bool:
    """Check a tiny exact region decodes to insns ending in a terminator."""
    region_size = max(0, region[1] - region[0])
    if not (0 < region_size <= 8):
        return True
    try:
        block = project.factory.block(addr, size=region_size, opt_level=0)
        insns: tuple[_AngrObject, ...] = tuple(
            _dynamic_attr(_dynamic_attr(block, "capstone", None), "insns", ()) or ()
        )
    except Exception:
        insns = ()
    if not insns:
        return False
    terminators = {"ret", "retn", "retf", "jmp", "ljmp", "call", "lcall", "int", "iret"}
    return any(_dynamic_attr(insn, "mnemonic", "").lower() in terminators for insn in insns)


def _filter_noncode_labeled_entries(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None = None,
) -> list[tuple[int, str]]:
    explicit_function_entries = metadata.function_entry_addrs if metadata is not None else frozenset()
    filtered: list[tuple[int, str]] = []
    for addr, name in labeled_entries:
        if addr in explicit_function_entries or _is_plausible_code_seed(project, addr, metadata=metadata):
            filtered.append((addr, name))
    return filtered


def _rank_labeled_function_entries(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None = None,
) -> list[tuple[int, str]]:
    entry_addr = _dynamic_attr(project, "entry", None)
    if not isinstance(entry_addr, int):
        entry_addr = 0
    preferred_app_prefix_buckets = (
        ("init_", 1),
        ("draw_", 2),
        ("clear_", 3),
        ("proc_", 4),
        ("generation", 5),
        ("pause_", 6),
        ("rand_", 7),
        ("timer", 8),
        ("refresh", 9),
    )
    runtime_helper_names = {
        "astart",
        "_astart",
        "start",
        "_start",
        "anchkstk",
        "_anchkstk",
        "__anchkstk",
        "analloca_probe",
        "_analloca_probe",
        "__analloca_probe",
        "chkstk",
        "_chkstk",
        "__chkstk",
        "atol",
        "_atol",
        "strlen",
        "_strlen",
        "srand",
        "_srand",
        "exit",
        "_exit",
        "amsg_exit",
        "_amsg_exit",
        "nullcheck",
        "_nullcheck",
        "cintdiv",
        "_cintdiv",
        "dosret0",
        "_dosret0",
        "dosretax",
        "_dosretax",
    }

    def _priority(item: tuple[int, str]) -> tuple[int, int, int]:
        addr, name = item
        lowered = name.lower()
        region = _lst_code_region(metadata, addr)
        size = (region[1] - region[0]) if region is not None else None
        bucket = _labeled_entry_bucket_8616(
            project, addr, lowered, size, entry_addr,
            preferred_app_prefix_buckets, runtime_helper_names,
        )
        return (bucket, abs(addr - entry_addr), addr)

    return sorted(labeled_entries, key=_priority)


def _labeled_entry_bucket_early_8616(
    addr: int,
    lowered: str,
    size: int | None,
    entry_addr: int,
    preferred_app_prefix_buckets: tuple[tuple[str, int], ...],
    runtime_helper_names: set[str],
) -> int | None:
    """Resolve the early priority buckets for a labeled entry name."""
    if addr == entry_addr:
        return 0
    if lowered in {"main", "_main"} or lowered.endswith("main"):
        return 1
    for prefix, bucket in preferred_app_prefix_buckets:
        if lowered.startswith(prefix):
            return bucket + 1
    if lowered in {"start", "_start"} or lowered.endswith("_start"):
        return 11
    if lowered in runtime_helper_names:
        return 15 if size is not None and size <= 0x20 else 16
    if "padding" in lowered or lowered.startswith("align_"):
        return 18
    return None


def _labeled_entry_bucket_8616(
    project: angr.Project,
    addr: int,
    lowered: str,
    size: int | None,
    entry_addr: int,
    preferred_app_prefix_buckets: tuple[tuple[str, int], ...],
    runtime_helper_names: set[str],
) -> int:
    """Resolve the sort bucket for a labeled entry name."""
    early = _labeled_entry_bucket_early_8616(
        addr, lowered, size, entry_addr, preferred_app_prefix_buckets, runtime_helper_names
    )
    if early is not None:
        return early
    if size is not None and size <= 0x20:
        return 12
    if size is not None and size <= 0x80:
        return 13
    if _is_zero_filled_region(project, addr):
        return 17
    return 14


def _sidecar_label_ranking_cache_key(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None,
) -> dict[str, object] | None:
    """Build a sidecar label cache key from dynamic angr loader metadata."""
    main_object = _dynamic_attr(project.loader, "main_object", None)
    binary_path = _dynamic_attr(main_object, "binary", None)
    if not isinstance(binary_path, (str, Path)):
        return None
    code_ranges = cast(Mapping[int, Sequence[int] | None], _dynamic_attr(metadata, "code_ranges", None) or {})

    def _code_range_tuple(addr: int) -> tuple[int, ...] | None:
        span = code_ranges.get(addr)
        return tuple(span) if span is not None else None

    cache_key = _recovery_cache_key(
        binary_path=Path(binary_path),
        kind="sidecar_label_ranking",
        source_scope=RecoveryCacheSourceScope8616.FUNCTION_DISCOVERY,
        extra={
            "entry": _dynamic_attr(project, "entry", None),
            "source_format": _dynamic_attr(metadata, "source_format", None),
            "entries": [
                (
                    addr,
                    name,
                    _code_range_tuple(addr),
                )
                for addr, name in labeled_entries
            ],
        },
    )
    return _cache_key_object(cache_key)


def _rank_labeled_function_entries_cached(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None = None,
) -> tuple[list[tuple[int, str]], bool]:
    def _impl() -> tuple[list[tuple[int, str]], bool]:
        filtered_entries = _filter_noncode_labeled_entries(project, labeled_entries, metadata)
        cache_key = _sidecar_label_ranking_cache_key(project, filtered_entries, metadata)
        cached = _load_cache_json("recovery", cache_key) if cache_key is not None else None
        if isinstance(cached, dict):
            entries = cached.get("entries")
            if isinstance(entries, list) and all(
                isinstance(item, list | tuple)
                and len(item) == 2
                and isinstance(item[0], int)
                and isinstance(item[1], str)
                for item in entries
            ):
                return [(item[0], item[1]) for item in entries], True

        ranked = _rank_labeled_function_entries(project, filtered_entries, metadata)
        if cache_key is not None:
            _store_cache_json("recovery", cache_key, {"entries": ranked})
        return ranked, False

    return _impl()


def _select_sidecar_showcase_entries(
    project: angr.Project,
    metadata: LSTMetadata,
    labeled_entries: list[tuple[int, str]],
    *,
    max_count: int,
    ranked_entries: list[tuple[int, str]] | None = None,
) -> list[tuple[int, str]]:
    def _impl() -> list[tuple[int, str]]:
        ranked = (
            ranked_entries
            if ranked_entries is not None
            else _rank_labeled_function_entries(project, labeled_entries, metadata)
        )
        if max_count <= 0 or not ranked:
            return []
        state = _SidecarShowcaseState8616(
            project=project,
            metadata=metadata,
            by_addr=dict(ranked),
            max_count=max_count,
        )
        state.add(_dynamic_attr(project, "entry", None))
        tiny_candidates = state.collect_tiny_candidates(ranked)
        if tiny_candidates:
            state.add(tiny_candidates[0][0])
        for addr, _name in tiny_candidates[1:3]:
            state.add(addr)
        main_candidates = [
            addr for addr, name in ranked if name.lower() in {"main", "_main"} or name.lower().endswith("main")
        ]
        if main_candidates:
            state.add(main_candidates[0])
        for addr, _name in ranked:
            state.add(addr)
            if len(state.selected) >= max_count:
                break
        return state.selected

    return _impl()


@dataclass
class _SidecarShowcaseState8616:
    """Mutable selection state for sidecar showcase entry selection."""

    project: angr.Project
    metadata: LSTMetadata
    by_addr: dict[int, str]
    max_count: int
    selected: list[tuple[int, str]] = field(default_factory=list)
    seen: set[int] = field(default_factory=set)

    def add(self, addr: int | None) -> None:
        """Append one ranked entry if it is new and capacity remains."""
        if addr is None or addr in self.seen or addr not in self.by_addr or len(self.selected) >= self.max_count:
            return
        self.selected.append((addr, self.by_addr[addr]))
        self.seen.add(addr)

    def tiny_candidate_priority(self, item: tuple[int, str]) -> tuple[int, int, int]:
        """Rank tiny showcase candidates by name class and region size."""
        addr, name = item
        lowered = name.lower()
        region = _lst_code_region(self.metadata, addr)
        size = (region[1] - region[0]) if region is not None else 0xFFFF
        bucket = _tiny_showcase_bucket_8616(lowered)
        return (bucket, size, abs(addr - _dynamic_attr(self.project, "entry", 0)))

    def collect_tiny_candidates(self, ranked: list[tuple[int, str]]) -> list[tuple[int, str]]:
        """Collect and rank tiny region candidates for showcase selection."""
        tiny_candidates = [
            (addr, name)
            for addr, name in ranked
            if addr not in self.seen
            and (span := _lst_code_region(self.metadata, addr)) is not None
            and (span[1] - span[0]) <= 0x20
            and "padding" not in name.lower()
            and name.lower() not in {"main", "_main", "start", "_start"}
        ]
        tiny_candidates.sort(key=self.tiny_candidate_priority)
        return tiny_candidates


def _tiny_showcase_bucket_8616(lowered: str) -> int:
    """Bucket tiny showcase candidates by name class."""
    if lowered.startswith("nullsub"):
        return 0
    if lowered.startswith("sub_"):
        return 1
    if "exit" in lowered or "amsg" in lowered:
        return 4
    return 2


def _format_sidecar_function_catalog(
    metadata: LSTMetadata,
    *,
    limit: int | None = None,
    code_labels: Mapping[int, str] | None = None,
) -> str:
    lines: list[str] = []
    entries = sorted((code_labels if code_labels is not None else _visible_code_labels(metadata)).items())
    if limit is not None and limit > 0:
        entries = entries[:limit]
    for addr, name in entries:
        region = _lst_code_region(metadata, addr)
        if region is not None:
            size = region[1] - region[0]
            lines.append(f"/* {addr:#x} {name} size={size:#x} range=[{region[0]:#x}, {region[1]:#x}) */")
        else:
            lines.append(f"/* {addr:#x} {name} */")
    return "\n".join(lines)


def _recover_blob_entry_function(project: angr.Project, entry_addr: int, *, timeout: int) -> _FunctionCfgPair:
    cast(_AngrObject, project)._inertia_decompiler_stage = "recovery:full"
    with _analysis_timeout(timeout):
        cfg = project.analyses.CFGFast(
            start_at_entry=False,
            function_starts=[entry_addr],
            normalize=True,
            force_complete_scan=False,
            data_references=False,
        )
        if entry_addr not in cfg.functions:
            cfg = project.analyses.CFGFast(
                start_at_entry=False,
                function_starts=[entry_addr],
                normalize=True,
                force_complete_scan=False,
                data_references=True,
            )
        if entry_addr not in cfg.functions and project.arch.name == "86_16":
            cfg = project.analyses.CFGFast(
                start_at_entry=False,
                function_starts=[entry_addr],
                normalize=True,
                force_complete_scan=True,
                data_references=True,
            )

    if entry_addr not in cfg.functions:
        raise KeyError(f"Function {entry_addr:#x} was not recovered by CFGFast.")
    return cfg, cfg.functions[entry_addr]


def _env_flag_enabled_8616(name: str, default: str = "") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _try_recover_direct_addr_from_sidecar_region(
    *,
    project: angr.Project,
    addr: int,
    timeout: int,
    window: int,
    low_memory_path: bool,
    lst_metadata: LSTMetadata | None,
    function_label: str | None,
    strict_direct_addr: bool,
) -> _FunctionCfgPair | None:
    def _impl() -> _FunctionCfgPair | None:
        if lst_metadata is None or project.arch.name != "86_16":
            return None
        sidecar_region_for_addr = _lst_code_region(lst_metadata, addr)
        if sidecar_region_for_addr is None:
            return None
        effective_label = function_label or _lst_code_label(lst_metadata, addr, project.entry)
        sidecar_addr = _sidecar_label_addr_8616(
            lst_metadata, addr, effective_label, sidecar_region_for_addr[0]
        )
        recover_addr = addr if strict_direct_addr else sidecar_addr
        code_name = _lst_code_label(lst_metadata, recover_addr, project.entry) or f"sub_{recover_addr:x}"
        try:
            recovered = _recover_lst_function(
                project,
                lst_metadata,
                recover_addr if lst_metadata.absolute_addrs else recover_addr - project.entry,
                code_name,
                timeout=timeout,
                window=window,
                low_memory=low_memory_path,
            )
            recovered_cfg, recovered_function = recovered
            recovered_project = _dynamic_attr(recovered_cfg, "project", None)
            if recovered_project is None:
                recovered_project = _dynamic_attr(recovered_cfg, "_project", project)
            _repair_x86_16_function_graph_8616(
                recovered_project,
                recovered_function,
                exact_region=_project_region_on_recovered_8616(
                    recovered_project, sidecar_region_for_addr
                ),
            )
            return recovered
        except _AnalysisTimeout:
            return None
        except Exception as ex:
            log_method = (
                logging.getLogger(__name__).warning
                if os.environ.get("INERTIA_DEBUG_INDIRECT_JUMP") == "1"
                else logging.getLogger(__name__).debug
            )
            log_method("sidecar region lst recovery failed for %s: %s", hex(recover_addr), ex)
            return None

    return _impl()


def _sidecar_label_addr_8616(
    lst_metadata: LSTMetadata,
    addr: int,
    effective_label: str | None,
    default_addr: int,
) -> int:
    """Resolve the nearest sidecar label addr matching the effective label."""
    if not effective_label:
        return default_addr
    target_names = {effective_label, effective_label.lstrip("_")}
    label_matches = [
        label_addr
        for label_addr, label_name in (_visible_code_labels(lst_metadata) or {}).items()
        if isinstance(label_addr, int) and isinstance(label_name, str) and label_name in target_names
    ]
    if not label_matches:
        return default_addr
    return min(label_matches, key=lambda la: abs(la - addr))


def _project_region_on_recovered_8616(
    recovered_project: object,
    sidecar_region: tuple[int, int],
) -> tuple[int, int]:
    """Project a sidecar region onto the recovered project's original base."""
    original_delta = _dynamic_attr(recovered_project, "_inertia_original_linear_delta", 0)
    if isinstance(original_delta, int) and original_delta:
        return (sidecar_region[0] - original_delta, sidecar_region[1] - original_delta)
    return sidecar_region


def _try_recover_direct_addr_from_sidecar_label(
    *,
    project: angr.Project,
    addr: int,
    timeout: int,
    window: int,
    low_memory_path: bool,
    lst_metadata: LSTMetadata | None,
    function_label: str | None,
) -> _FunctionCfgPair | None:
    def _impl() -> _FunctionCfgPair | None:
        if lst_metadata is None or project.arch.name != "86_16":
            return None
        effective_label = function_label or _lst_code_label(lst_metadata, addr, project.entry)
        if not isinstance(effective_label, str) or not effective_label:
            return None
        target_names = {effective_label, effective_label.lstrip("_")}
        label_matches = [
            label_addr
            for label_addr, label_name in (_visible_code_labels(lst_metadata) or {}).items()
            if isinstance(label_addr, int) and isinstance(label_name, str) and label_name in target_names
        ]
        if not label_matches:
            return None
        recover_addr = min(label_matches, key=lambda la: abs(la - addr))
        try:
            return _recover_lst_function(
                project,
                lst_metadata,
                recover_addr if lst_metadata.absolute_addrs else recover_addr - project.entry,
                effective_label,
                timeout=timeout,
                window=window,
                low_memory=low_memory_path,
            )
        except _AnalysisTimeout:
            return None
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "sidecar label lst recovery failed for %s: %s",
                hex(recover_addr),
                ex,
            )
            return None

    return _impl()


@cast(Callable[..., Any], trace_function(name="discovery.recover_direct_addr"))
def _recover_direct_addr_function(
    project: angr.Project,
    addr: int,
    *,
    timeout: int,
    window: int,
    function_label: str | None,
    lst_metadata: LSTMetadata | None,
    low_memory_path: bool,
    prefer_fast_recovery: bool,
    exact_region: tuple[int, int] | None = None,
) -> _FunctionCfgPair:
    def _impl() -> _FunctionCfgPair:
        nonlocal addr
        addr = _rebase_addr_on_sidecar_start_8616(project, addr, lst_metadata)
        prefer_lst_direct = _env_flag_enabled_8616("INERTIA_DIRECT_ADDR_PREFER_LST", "1")
        if prefer_lst_direct:
            recovered = _try_sidecar_direct_lanes_8616(
                project=project,
                addr=addr,
                timeout=timeout,
                window=window,
                low_memory_path=low_memory_path,
                lst_metadata=lst_metadata,
                function_label=function_label,
            )
            if recovered is not None:
                return recovered
        fallback = _direct_addr_fallback_8616(
            project, addr, exact_region, function_label,
            timeout=timeout, window=window,
            low_memory_path=low_memory_path, prefer_fast_recovery=prefer_fast_recovery,
        )
        if fallback is not None:
            return fallback
        candidate_addr = _direct_addr_candidate_8616(
            project, addr, lst_metadata, prefer_lst_direct
        )
        return _recover_direct_addr_bounded_8616(
            project, addr, candidate_addr, exact_region,
            timeout=timeout, window=window,
            lst_metadata=lst_metadata, prefer_lst_direct=prefer_lst_direct,
        )

    return _impl()


def _rebase_addr_on_sidecar_start_8616(
    project: angr.Project,
    addr: int,
    lst_metadata: LSTMetadata | None,
) -> int:
    """Rebase the direct addr to the sidecar region start when enabled."""
    use_sidecar_start = _env_flag_enabled_8616("INERTIA_DIRECT_ADDR_USE_SIDECAR_START")
    if project.arch.name != "86_16" or lst_metadata is None or not use_sidecar_start:
        return addr
    sidecar_region = _lst_code_region(lst_metadata, addr)
    if sidecar_region is None:
        return addr
    sidecar_addr = sidecar_region[0]
    if isinstance(sidecar_addr, int) and sidecar_addr >= 0 and sidecar_addr != addr:
        return sidecar_addr
    return addr


def _try_sidecar_direct_lanes_8616(
    *,
    project: angr.Project,
    addr: int,
    timeout: int,
    window: int,
    low_memory_path: bool,
    lst_metadata: LSTMetadata | None,
    function_label: str | None,
) -> _FunctionCfgPair | None:
    """Try the sidecar region and label recovery lanes in order."""
    strict_direct_addr = _env_flag_enabled_8616("INERTIA_DIRECT_ADDR_STRICT")
    recovered = _try_recover_direct_addr_from_sidecar_region(
        project=project,
        addr=addr,
        timeout=timeout,
        window=window,
        low_memory_path=low_memory_path,
        lst_metadata=lst_metadata,
        function_label=function_label,
        strict_direct_addr=strict_direct_addr,
    )
    if recovered is not None:
        return recovered
    return _try_recover_direct_addr_from_sidecar_label(
        project=project,
        addr=addr,
        timeout=timeout,
        window=window,
        low_memory_path=low_memory_path,
        lst_metadata=lst_metadata,
        function_label=function_label,
    )


def _direct_addr_fallback_8616(
    project: angr.Project,
    addr: int,
    exact_region: tuple[int, int] | None,
    function_label: str | None,
    *,
    timeout: int,
    window: int,
    low_memory_path: bool,
    prefer_fast_recovery: bool,
) -> _FunctionCfgPair | None:
    """Resolve the entry-function fallback lanes for direct recovery."""
    if exact_region is not None or function_label is None or addr != project.entry:
        return None
    if project.arch.name == "86_16":
        return _fallback_entry_function(
            project,
            timeout=timeout,
            window=window,
            low_memory=low_memory_path,
            prefer_fast_recovery=bool(function_label is not None and prefer_fast_recovery),
        )
    return _recover_blob_entry_function(project, addr, timeout=timeout)


def _direct_addr_candidate_8616(
    project: angr.Project,
    addr: int,
    lst_metadata: LSTMetadata | None,
    prefer_lst_direct: bool,
) -> int:
    """Resolve the candidate addr for the bounded direct recovery lane."""
    if prefer_lst_direct and project.arch.name == "86_16" and lst_metadata is not None:
        sidecar_region = _lst_code_region(lst_metadata, addr)
        if sidecar_region is not None and isinstance(sidecar_region[0], int):
            return sidecar_region[0]
    return addr


def _recover_direct_addr_bounded_8616(
    project: angr.Project,
    addr: int,
    candidate_addr: int,
    exact_region: tuple[int, int] | None,
    *,
    timeout: int,
    window: int,
    lst_metadata: LSTMetadata | None,
    prefer_lst_direct: bool,
) -> _FunctionCfgPair:
    """Recover the direct addr through the bounded CFG lanes."""
    with _analysis_timeout(timeout):
        if project.arch.name == "86_16":
            main_object = _dynamic_attr(project.loader, "main_object", None)
            linked_base = _dynamic_attr(main_object, "linked_base", None)
            max_addr = _dynamic_attr(main_object, "max_addr", None)
            if isinstance(linked_base, int) and isinstance(max_addr, int):
                return _function_cfg_pair_object(_recover_candidate_function_pair(
                    project,
                    candidate_addr=candidate_addr,
                    image_end=linked_base + max_addr + 1,
                    metadata=lst_metadata if prefer_lst_direct else None,
                    project_entry=project.entry,
                    region_span=max(window, 0x180),
                    exact_region=exact_region,
                ))
            regions = [exact_region or _infer_x86_16_linear_region(project, addr, window=window)]
        else:
            regions = [(addr, addr + window)]
        recovered = _pick_function(project, addr, regions=regions)
        _repair_x86_16_function_graph_8616(
            project,
            recovered[1],
            exact_region=regions[0],
        )
        return recovered
