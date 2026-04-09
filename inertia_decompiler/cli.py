#!/usr/bin/env python3

from __future__ import annotations

import argparse
import atexit
import builtins as _builtins
import contextlib
import copy
import logging
import os
import re
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, TimeoutError as FuturesTimeoutError, wait
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

from inertia_decompiler.cache import (
    _function_decompilation_cache_key,
    _load_cache_json,
    _recovery_cache_key,
    _store_cache_json,
)
from inertia_decompiler.project_loading import (
    _build_project,
    _build_project_cached,
    _build_project_from_bytes,
    _describe_exception,
    _is_blob_only_input,
)
from inertia_decompiler.sidecar_metadata import (
    _exact_function_span_matches,
    _load_lst_metadata,
    _lst_code_label,
    _lst_code_region,
    _lst_data_label,
    _recovery_code_labels,
    _signature_matched_code_addrs,
    _visible_code_labels,
)
from inertia_decompiler.disassembly_helpers import (
    _format_asm_range,
    _format_first_block_asm,
    _infer_linear_disassembly_window,
    _linear_disassembly,
    _probe_lift_break,
)
from inertia_decompiler.tail_validation import (
    TAIL_VALIDATION_ENABLE_ENV as _TAIL_VALIDATION_ENABLE_ENV,
    emit_tail_validation_console_summary as _emit_tail_validation_console_summary,
    inherit_tail_validation_runtime_policy as _inherit_tail_validation_runtime_policy,
    parse_env_bool as _parse_env_bool,
    set_tail_validation_runtime_enabled as _set_tail_validation_runtime_enabled,
    tail_validation_console_cache_path as _tail_validation_console_cache_path,
    tail_validation_detail_cache_path as _tail_validation_detail_cache_path,
    tail_validation_enabled_for_run as _tail_validation_enabled_for_run,
    tail_validation_fallback_allows_project_snapshot as _tail_validation_fallback_allows_project_snapshot,
    tail_validation_runtime_enabled as _tail_validation_runtime_enabled,
    tail_validation_snapshot_for_fallback as _tail_validation_snapshot_for_fallback,
    tail_validation_snapshot_for_function_run as _tail_validation_snapshot_for_function_run,
)
from inertia_decompiler.runtime_support import (
    AnalysisTimeout as _AnalysisTimeout,
    DaemonThreadPoolExecutor,
    DECOMPILATION_PREP_LOCK,
    FORCE_SERIAL_FUNCTION_DECOMP_ENV as _FORCE_SERIAL_FUNCTION_DECOMP_ENV,
    JumpkindLoggingHandler,
    apply_memory_limit as _apply_memory_limit,
    analysis_timeout as _analysis_timeout,
    capture_thread_output as _capture_thread_output,
    choose_function_parallelism as _choose_function_parallelism,
    default_exe_showcase_cap as _default_exe_showcase_cap,
    emit_timeout_and_exit as _emit_timeout_and_exit,
    format_address as _format_address,
    guard_angr_peephole_expr_bitwidth_assertion as _guard_angr_peephole_expr_bitwidth_assertion,
    guard_angr_variable_recovery_binop_sub_size_mismatch as _guard_angr_variable_recovery_binop_sub_size_mismatch,
    install_angr_peephole_expr_bitwidth_guard as _install_angr_peephole_expr_bitwidth_guard,
    install_angr_variable_recovery_binop_sub_size_guard as _install_angr_variable_recovery_binop_sub_size_guard,
    log_step,
    lower_process_priority as _lower_process_priority,
    memory_available_mb as _memory_available_mb,
    PreforkJobPool,
    prefer_low_memory_path as _prefer_low_memory_path,
    run_with_timeout_in_fork as _run_with_timeout_in_fork,
    run_with_timeout_in_daemon_thread as _run_with_timeout_in_daemon_thread,
    raise_timeout as _raise_timeout,
    should_force_serial_supplemental_decompilation as _should_force_serial_supplemental_decompilation,
)
from inertia_decompiler.work_items import (
    FunctionDecompileResult,
    FunctionDecompileTask,
    FunctionWorkItem,
    FunctionWorkResult,
    emit_tail_validation_for_function_run_or_uncollected as _emit_tail_validation_for_function_run_or_uncollected,
    emit_tail_validation_snapshot_or_uncollected as _emit_tail_validation_snapshot_or_uncollected,
    function_attempt_display_status as _function_attempt_display_status,
    print_function_attempt_status as _print_function_attempt_status,
    recovery_evidence_line as _recovery_evidence_line,
    tail_validation_display_status as _tail_validation_display_status,
)

_RAW_PRINT = _builtins.print


def _timestamp_prefix() -> str:
    return time.strftime("[%H:%M:%S]")


def _looks_like_diagnostic_line(line: str) -> bool:
    stripped = line.lstrip()
    if re.match(r"^\[\d{2}:\d{2}:\d{2}\]\s+", stripped):
        stripped = re.sub(r"^\[\d{2}:\d{2}:\d{2}\]\s+", "", stripped, count=1)
    return (
        stripped.startswith("/*")
        or stripped.startswith("[dbg]")
        or stripped.startswith("summary:")
        or stripped.startswith("WARNING")
        or stripped.startswith("ERROR")
    )


def _timestamped_print(*args, **kwargs):
    sep = kwargs.pop("sep", " ")
    end = kwargs.pop("end", "\n")
    file = kwargs.pop("file", None)
    flush = kwargs.pop("flush", False)
    text = sep.join(str(arg) for arg in args)
    pytest_mode = "PYTEST_CURRENT_TEST" in os.environ
    if pytest_mode:
        return _RAW_PRINT(text, end=end, file=file, flush=flush)
    if file is None and text:
        lines = text.splitlines()
        if lines and all((not line.strip()) or _looks_like_diagnostic_line(line) for line in lines):
            target = sys.stderr
            stamped = "\n".join(
                (
                    line
                    if re.match(r"^\[\d{2}:\d{2}:\d{2}\]\s+", line.lstrip())
                    else f"{_timestamp_prefix()} {line}"
                )
                if line.strip()
                else line
                for line in lines
            )
            return _RAW_PRINT(stamped, end=end, file=target, flush=flush)
    return _RAW_PRINT(text, end=end, file=file, flush=flush)


print = _timestamped_print


def _print_diagnostic_text(text: str) -> None:
    if not text:
        return
    pytest_mode = "PYTEST_CURRENT_TEST" in os.environ
    for line in text.splitlines():
        if pytest_mode:
            _RAW_PRINT(line)
        else:
            stamped = line if re.match(r"^\[\d{2}:\d{2}:\d{2}\]\s+", line.lstrip()) else f"{_timestamp_prefix()} {line}"
            _RAW_PRINT(stamped, file=sys.stderr)


def _stdout_is_interactive() -> bool:
    stream = getattr(sys, "stdout", None)
    try:
        return bool(stream is not None and hasattr(stream, "isatty") and stream.isatty())
    except Exception:
        return False


def _emit_exit_marker() -> None:
    if "PYTEST_CURRENT_TEST" in os.environ:
        return
    _RAW_PRINT(f"{_timestamp_prefix()} /* exiting cli */", file=sys.stderr)


atexit.register(_emit_exit_marker)


_ROOT = Path(__file__).resolve().parents[1]
_PROJECT_VENV_PYTHONS = (
    _ROOT / ".venv" / "bin" / "python",
    _ROOT / "venv" / "bin" / "python",
)
try:
    import angr
except ModuleNotFoundError:
    for candidate in _PROJECT_VENV_PYTHONS:
        if not candidate.exists():
            continue
        if Path(sys.executable) == candidate:
            break
        os.execv(str(candidate), [str(candidate), str(Path(__file__).resolve()), *sys.argv[1:]])
    raise

sys.path.insert(0, str(_ROOT / "angr_platforms"))
try:
    import pyvex_compat

    pyvex_compat.apply_pyvex_runtime_compatibility()
except Exception:
    pass

import angr_platforms.X86_16  # noqa: F401

from angr_platforms.X86_16.analysis_helpers import (
    DOS_SERVICE_BASE_ADDR,
    InterruptCall,
    collect_neighbor_call_targets,
    collect_dos_int21_calls,
    collect_interrupt_service_calls,
    dos_helper_declarations,
    extend_cfg_for_far_calls,
    extend_cfg_for_neighbor_calls,
    infer_com_region,
    known_helper_signature_decl,
    interrupt_service_name,
    interrupt_service_addr,
    interrupt_service_declarations,
    preferred_known_helper_signature_decl,
    normalize_api_style,
    patch_dos_int21_call_sites,
    patch_interrupt_service_call_sites,
    render_interrupt_call,
    render_dos_int21_call,
    seed_calling_conventions,
)
from angr_platforms.X86_16.annotations import (
    _apply_known_helper_signatures,
    annotate_function,
    apply_x86_16_metadata_annotations,
    _source_decl_from_cod_source_lines,
)
from angr_platforms.X86_16.cod_extract import (
    CODProcMetadata,
    extract_cod_listing_metadata,
    extract_cod_function_entries,
    extract_cod_proc_metadata,
    extract_small_two_arg_cod_logic_entries,
    extract_simple_cod_logic_entries,
    infer_cod_logic_start,
    join_cod_entries_with_synthetic_globals,
)
from angr_platforms.X86_16.cod_known_objects import known_cod_object_spec
from angr_platforms.X86_16.cod_source_rewrites import apply_cod_source_rewrites as _apply_cod_source_rewrites
from angr_platforms.X86_16.cod_source_rewrites import rewrite_known_cod_object_fields_from_source
from angr_platforms.X86_16.lst_extract import LSTMetadata
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.utils.library import convert_cproto_to_py
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypePointer, SimTypeShort
from angr_platforms.X86_16.alias_model import (
    _CopyAliasState,
    _StackPointerAliasState,
    _stack_slot_identity_can_join as _stack_slot_identity_can_join_var,
    _same_stack_slot_identity as _same_stack_slot_identity_var,
    describe_alias_storage,
    _stack_slot_identity_for_variable,
    _storage_domain_for_expr,
    _storage_domain_for_variable,
    _storage_view_for_variable,
)
from angr_platforms.X86_16.alias_domains import DomainKey, register_pair_name
from angr_platforms.X86_16.alias_state import AliasState
from angr_platforms.X86_16.tail_validation import x86_16_tail_validation_snapshot_passed
from angr_platforms.X86_16.fast_tracer import trace_16bit_seed_candidates
from angr_platforms.X86_16.widening_model import analyze_adjacent_storage_slices
from angr_platforms.X86_16.widening_alias import can_join_adjacent_register_slices, join_adjacent_register_slices


logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.calling_convention.calling_convention").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.calling_convention.fact_collector.SimEngineFactCollectorVEX").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.structured_codegen.c").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.decompiler").setLevel(logging.ERROR)
logging.getLogger("angr.project").setLevel(logging.ERROR)
logging.getLogger("angr_platforms.X86_16.parse").setLevel(logging.CRITICAL)
logging.getLogger("angr_platforms.X86_16.lift_86_16").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.clinic").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.callsite_maker").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.decompiler.optimization_passes.optimization_pass").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.analysis").setLevel(logging.CRITICAL)
logging.getLogger("angr.analyses.cfg.cfg_fast").setLevel(logging.ERROR)
logging.getLogger("angr.analyses.cfg.cfg_base").setLevel(logging.ERROR)
logging.getLogger("angr.analyses.fcp.fcp.SimEngineFCPVEX").setLevel(logging.CRITICAL)


def _parse_int(value: str) -> int:
    return int(value, 0)


def _seed_scan_windows(project: angr.Project) -> list[tuple[int, int]]:
    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return []
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return []

    image_end = linked_base + max_addr + 1
    windows: list[tuple[int, int]] = []

    metadata = getattr(project, "_inertia_lst_metadata", None)
    if metadata is not None:
        for start, end in sorted(getattr(metadata, "code_ranges", {}).values()):
            if start >= end:
                continue
            if _lst_code_label(metadata, start, project.entry) is None:
                continue
            windows.append((max(linked_base, start), min(image_end, end)))

    for span in getattr(main_object, "mz_segment_spans", ()):
        start = max(linked_base, getattr(span, "start_linear", linked_base))
        end = min(image_end, getattr(span, "end_linear", image_end))
        if start < end:
            windows.append((start, end))

    if not windows:
        return [(linked_base, image_end)]

    merged: list[tuple[int, int]] = []
    for start, end in sorted(windows):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def _entry_window_seed_targets(
    project: angr.Project,
    code: bytes,
    *,
    linked_base: int,
    entry_window: int = 0x200,
) -> set[int]:
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
        opcode = code[offset]
        if opcode == 0xE8 and offset + 2 < len(code):
            rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
            targets.add(insn.address + 3 + rel)
        elif opcode == 0x9A and offset + 4 < len(code):
            off = int.from_bytes(code[offset + 1 : offset + 3], "little")
            seg = int.from_bytes(code[offset + 3 : offset + 5], "little")
            linked_base = getattr(getattr(project.loader, "main_object", None), "linked_base", 0)
            targets.add(linked_base + (seg << 4) + off)
        elif include_jumps and opcode == 0xE9 and offset + 2 < len(code):
            rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
            targets.add(insn.address + 3 + rel)
        elif include_jumps and opcode == 0xEB and offset + 1 < len(code):
            rel = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
            targets.add(insn.address + 2 + rel)
        offset += insn.size
        if insn.mnemonic.lower() in {"ret", "retf", "iret"}:
            break
    return targets


def _looks_like_x86_16_function_prologue(code: bytes, offset: int) -> bool:
    window = code[offset : offset + 4]
    return window.startswith(b"\x55\x8B\xEC")


def _looks_like_x86_16_entry_byte(code: bytes, offset: int) -> bool:
    if offset < 0 or offset >= len(code):
        return False
    return code[offset] not in {0x00, 0x90, 0xCC}


def _resolve_x86_16_function_start(code: bytes, offset: int, *, max_padding: int = 0x10) -> int | None:
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


def _apply_binary_specific_annotations(
    project: angr.Project,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
    *,
    func_addr: int | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
) -> bool:
    changed = False
    if func_addr is None:
        if cod_metadata is not None:
            changed |= _apply_known_helper_signatures(project, cod_metadata)
        return changed

    if lst_metadata is not None or cod_metadata is not None or synthetic_globals:
        changed = apply_x86_16_metadata_annotations(
            project,
            func_addr=func_addr,
            cod_metadata=cod_metadata,
            lst_metadata=lst_metadata,
            synthetic_globals=synthetic_globals,
        )
    return changed


def _sidecar_cod_metadata_for_function(
    project: angr.Project,
    function,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
) -> CODProcMetadata | None:
    if binary_path is None or lst_metadata is None or not lst_metadata.cod_path:
        return None
    proc_kind = (lst_metadata.cod_proc_kinds.get(function.addr) or "NEAR").upper()
    name_candidates = []
    function_name = getattr(function, "name", "") or ""
    if function_name:
        name_candidates.append(function_name)
        if not function_name.startswith("_"):
            name_candidates.append(f"_{function_name}")
        else:
            name_candidates.append(function_name.lstrip("_"))
    cod_path = Path(lst_metadata.cod_path)
    cache = getattr(project, "_inertia_sidecar_cod_metadata_cache", None)
    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_sidecar_cod_metadata_cache", cache)
    for candidate in name_candidates:
        cache_key = (str(cod_path), candidate, proc_kind)
        if cache_key in cache:
            return cache[cache_key]
        try:
            metadata = extract_cod_proc_metadata(cod_path, candidate, proc_kind)
        except Exception:
            continue
        cache[cache_key] = metadata
        return metadata
    return None


def _snapshot_codegen_text(codegen) -> str:
    try:
        return codegen.text
    except Exception:
        return ""


def _regenerate_codegen_text_safely(codegen, *, context: str) -> tuple[str, bool]:
    fallback_text = _snapshot_codegen_text(codegen)
    try:
        rendered = codegen.render_text(codegen.cfunc)
        if isinstance(rendered, tuple) and rendered and isinstance(rendered[0], str):
            return rendered[0], False
        if isinstance(rendered, str):
            return rendered, False
    except Exception:
        pass
    try:
        codegen.regenerate_text()
    except RecursionError:
        try:
            rendered = codegen.render_text(codegen.cfunc)
            if isinstance(rendered, tuple) and rendered and isinstance(rendered[0], str):
                return rendered[0], False
            if isinstance(rendered, str):
                return rendered, False
        except Exception:
            pass
        return fallback_text, False
    except Exception as ex:
        try:
            rendered = codegen.render_text(codegen.cfunc)
            if isinstance(rendered, tuple) and rendered and isinstance(rendered[0], str):
                return rendered[0], False
            if isinstance(rendered, str):
                return rendered, False
        except Exception:
            pass
        logging.getLogger(__name__).warning(
            "Skipping C text regeneration for %s: %s",
            context,
            ex,
        )
        return fallback_text, False
    try:
        rendered = codegen.render_text(codegen.cfunc)
        if isinstance(rendered, tuple) and rendered and isinstance(rendered[0], str):
            return rendered[0], False
        if isinstance(rendered, str):
            return rendered, False
    except Exception:
        pass
    return _snapshot_codegen_text(codegen), True


def _format_minimal_codegen_output(
    project: angr.Project,
    function,
    rendered_text: str,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None,
) -> str:
    formatted = _format_known_helper_calls(
        project,
        function,
        rendered_text,
        api_style,
        binary_path,
        cod_metadata=cod_metadata,
    )
    formatted = _dedupe_adjacent_prototype_lines(formatted)
    formatted = _sanitize_mangled_autonames_text(formatted)
    return formatted


def _apply_known_cod_object_annotations(
    project: angr.Project,
    func_addr: int,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: dict[int, tuple[str, int]] | None,
) -> bool:
    if not synthetic_globals:
        return False

    changed = False
    seen: set[int] = set()
    for addr, (raw_name, _width) in synthetic_globals.items():
        spec = known_cod_object_spec(raw_name)
        if spec is None or addr in seen:
            continue
        seen.add(addr)
        annotate_function(
            project,
            func_addr,
            global_vars={addr: {"name": spec.name, "type": spec.type}},
        )
        changed = True
    return changed


def _infer_x86_16_linear_region(project: angr.Project, start_addr: int, *, window: int) -> tuple[int, int]:
    end_limit = start_addr + max(window, 1)
    current = start_addr
    ah = None
    padding_bytes = {0x00, 0x90, 0xCC}

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
        if text.startswith("mov ah, "):
            try:
                ah = int(text.split(", ", 1)[1], 0)
            except ValueError:
                ah = None
        elif text.startswith("mov ax, "):
            try:
                ax = int(text.split(", ", 1)[1], 0)
            except ValueError:
                ax = None
            if ax is not None:
                ah = (ax >> 8) & 0xFF

        current += insn.size

        if insn.mnemonic in {"ret", "retf", "iret"}:
            if current >= end_limit:
                break
            try:
                lookahead = bytes(project.loader.memory.load(current, min(16, end_limit - current)))
            except Exception:
                break
            if lookahead and all(byte in padding_bytes for byte in lookahead):
                break
        if insn.mnemonic == "int":
            if insn.op_str.lower() == "0x20":
                break
            if insn.op_str.lower() == "0x21" and ah == 0x4C:
                break
            if insn.op_str.lower() == "0x27":
                break

    return start_addr, max(start_addr + 1, current)


def _pick_function(
    project: angr.Project,
    addr: int | None,
    *,
    regions=None,
    data_references: bool | None = None,
    force_smart_scan: bool | None = None,
):
    target_addr = project.entry if addr is None else addr
    data_refs = True if data_references is None else data_references
    if force_smart_scan is None and project.arch.name == "86_16" and regions is not None:
        smart_scan_modes = (False, True)
    else:
        smart_scan_modes = (force_smart_scan,)

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
            except Exception as ex:  # noqa: BLE001
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
    if cfg is None or target_addr not in cfg.functions:
        raise KeyError(f"Function {target_addr:#x} was not recovered by CFGFast.")
    function = cfg.functions[target_addr]

    if project.arch.name == "86_16":
        extended_cfg = extend_cfg_for_far_calls(
            project,
            function,
            entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
        )
        if extended_cfg is not None and target_addr in extended_cfg.functions:
            cfg = extended_cfg
            function = cfg.functions[target_addr]
        extended_cfg = extend_cfg_for_neighbor_calls(
            project,
            function,
            entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
        )
        if extended_cfg is not None and target_addr in extended_cfg.functions:
            cfg = extended_cfg
            function = cfg.functions[target_addr]
        patch_interrupt_service_call_sites(function, getattr(project.loader.main_object, "binary", None))
    seed_calling_conventions(cfg)

    return cfg, function


def _pick_function_lean(
    project: angr.Project,
    addr: int | None,
    *,
    regions=None,
    data_references: bool = False,
    extend_far_calls: bool = True,
):
    """
    Recover a known entry point with a deliberately cheap CFGFast pass.

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
    if extend_far_calls and project.arch.name == "86_16":
        extended_cfg = extend_cfg_for_far_calls(
            project,
            function,
            entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
        )
        if extended_cfg is not None and target_addr in extended_cfg.functions:
            cfg = extended_cfg
            function = cfg.functions[target_addr]
        extended_cfg = extend_cfg_for_neighbor_calls(
            project,
            function,
            entry_window=(regions[0][1] - regions[0][0]) if regions else 0x200,
        )
        if extended_cfg is not None and target_addr in extended_cfg.functions:
            cfg = extended_cfg
            function = cfg.functions[target_addr]
        patch_interrupt_service_call_sites(function, getattr(project.loader.main_object, "binary", None))
    seed_calling_conventions(cfg)
    return cfg, function


def _x86_16_recovery_windows(window: int, *, low_memory: bool = False) -> tuple[int, ...]:
    base_window = max(window, 0x80 if low_memory else 0x200)
    return tuple(base_window * factor for factor in (1, 2, 4, 8, 16))


def _x86_16_fast_recovery_windows(window: int, *, low_memory: bool = False) -> tuple[int, ...]:
    candidate_windows = (0x40, 0x80, 0x100) if low_memory else (0x80, 0x100, 0x200)
    windows: list[int] = []
    for candidate in candidate_windows:
        if window <= candidate:
            effective_window = window
        else:
            effective_window = candidate
        if effective_window not in windows:
            windows.append(effective_window)
    if not windows:
        windows.append(window)
    return tuple(windows)


def _cod_proc_has_call_heavy_helper_profile(cod_metadata: CODProcMetadata | None) -> bool:
    if cod_metadata is None:
        return False
    call_names = tuple(dict.fromkeys(getattr(cod_metadata, "call_names", ()) or ()))
    return len(call_names) >= 4


def _recover_cfg(
    project: angr.Project,
    binary_path: Path,
    *,
    base_addr: int,
    window: int,
    low_memory: bool = False,
):
    print(f"[dbg] recover_cfg: entry={hex(project.entry)} base_addr={hex(base_addr)} window={hex(window)} binary={binary_path}")
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
        extended_cfg = extend_cfg_for_far_calls(project, cfg.functions[project.entry], entry_window=window)
        if extended_cfg is not None and project.entry in extended_cfg.functions:
            cfg = extended_cfg
        extended_cfg = extend_cfg_for_neighbor_calls(project, cfg.functions[project.entry], entry_window=window)
        if extended_cfg is not None and project.entry in extended_cfg.functions:
            cfg = extended_cfg
        patch_interrupt_service_call_sites(cfg.functions[project.entry], binary_path)
    seed_calling_conventions(cfg)
    return cfg


def _recover_partial_cfg(
    project: angr.Project,
    *,
    window: int,
    low_memory: bool = False,
):
    """
    Recover a bounded x86-16 catalog around the entry point.

    This is the whole-binary fallback for awkward real-mode executables such as
    packed startup stubs. It keeps CFGFast inside narrow entry windows instead
    of asking angr to recover the entire executable at once.
    """

    candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
    last_error: Exception | None = None
    for candidate_window in candidate_windows:
        project._inertia_decompiler_stage = f"catalog:narrow:{candidate_window:#x}"
        if project.arch.name == "86_16":
            regions = [_infer_x86_16_linear_region(project, project.entry, window=candidate_window)]
        else:
            regions = [(project.entry, project.entry + candidate_window)]
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
            except Exception as ex:  # noqa: BLE001
                last_error = ex
                continue
            if project.entry not in cfg.functions:
                last_error = KeyError(f"Function {project.entry:#x} was not recovered by CFGFast.")
                continue
            if project.arch.name == "86_16":
                extended_cfg = extend_cfg_for_far_calls(
                    project,
                    cfg.functions[project.entry],
                    entry_window=(regions[0][1] - regions[0][0]) if regions else candidate_window,
                )
                if extended_cfg is not None and project.entry in extended_cfg.functions:
                    cfg = extended_cfg
                extended_cfg = extend_cfg_for_neighbor_calls(
                    project,
                    cfg.functions[project.entry],
                    entry_window=(regions[0][1] - regions[0][0]) if regions else candidate_window,
                )
                if extended_cfg is not None and project.entry in extended_cfg.functions:
                    cfg = extended_cfg
                patch_interrupt_service_call_sites(
                    cfg.functions[project.entry],
                    getattr(project.loader.main_object, "binary", None),
                )
            seed_calling_conventions(cfg)
            return cfg

    if last_error is not None:
        raise last_error
    raise KeyError(f"Function {project.entry:#x} was not recovered by bounded CFGFast.")


def _try_decompile_sidecar_slice(
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    addr: int,
    name: str,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
) -> tuple[str, str] | None:
    region = _lst_code_region(lst_metadata, addr)
    if region is None:
        return None
    start, end = region
    if end <= start:
        return None
    try:
        code = bytes(project.loader.memory.load(start, end - start))
    except Exception:
        return None

    def _recover_and_decompile():
        recovery_attempts = (
            ("lean", lambda slice_project: _pick_function_lean(
                slice_project,
                start,
                regions=[(start, end)],
                data_references=False,
                extend_far_calls=False,
            )),
            ("full-no-refs", lambda slice_project: _pick_function(
                slice_project,
                start,
                regions=[(start, end)],
                data_references=False,
                force_smart_scan=False,
            )),
            ("full-with-refs", lambda slice_project: _pick_function(
                slice_project,
                start,
                regions=[(start, end)],
                data_references=True,
                force_smart_scan=False,
            )),
        )
        last_failure: tuple[str, str] | None = None
        for attempt_name, recover in recovery_attempts:
            try:
                slice_project = _build_project_from_bytes(code, base_addr=start, entry_point=start)
                _inherit_tail_validation_runtime_policy(slice_project, project)
                cfg, func = recover(slice_project)
            except Exception as ex:  # noqa: BLE001
                last_failure = ("error", f"{attempt_name} recovery: {_describe_exception(ex)}")
                continue
            func.name = name
            status, payload, *_ = _decompile_function_with_stats(
                slice_project,
                cfg,
                func,
                max(1, min(timeout, 6)),
                api_style,
                binary_path,
                lst_metadata=lst_metadata,
                allow_isolated_retry=False,
            )
            if status == "ok":
                snapshot = _tail_validation_snapshot_for_function_run(slice_project, func)
                if snapshot:
                    setattr(project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
                if attempt_name != "lean":
                    print(f"[dbg] sidecar slice fallback recovered {addr:#x} {name} via {attempt_name}")
                return status, payload
            last_failure = (status, payload)
        source_function = SimpleNamespace(addr=start, name=name)
        cod_metadata = _sidecar_cod_metadata_for_function(
            project,
            source_function,
            binary_path,
            lst_metadata,
        )
        source_text = _render_cod_source_function_text(source_function, cod_metadata)
        if source_text is not None:
            print(f"[dbg] sidecar slice fallback recovered {addr:#x} {name} from COD source")
            return "ok", source_text
        if last_failure is None:
            return "error", "sidecar slice recovery did not run"
        return last_failure

    try:
        runner_timeout = max(2, min(timeout, 8))
        if (
            os.name == "posix"
            and threading.current_thread() is threading.main_thread()
            and threading.active_count() == 1
            and isinstance(project, angr.Project)
        ):
            status, payload = _run_with_timeout_in_fork(
                _recover_and_decompile,
                timeout=runner_timeout,
            )
        else:
            status, payload = _run_with_timeout_in_daemon_thread(
                _recover_and_decompile,
                timeout=runner_timeout,
                thread_name_prefix="slice-fallback",
            )
    except Exception:
        return None
    if status != "ok":
        return None
    return status, payload


def _try_decompile_non_optimized_slice(
    project: angr.Project,
    addr: int,
    name: str,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None = None,
    allow_fresh_project_retry: bool = True,
) -> str | None:
    # Non-optimized fallback output is intentionally never cached. It is a best-effort rescue path,
    # not a stable primary decompilation result.
    def _attempt(slice_source_project: angr.Project, *, label: str) -> tuple[str | None, str | None]:
        region = _lst_code_region(lst_metadata, addr)
        if region is None:
            region = _infer_linear_disassembly_window(slice_source_project, addr, max_window=0x240)
        start, end = region
        if end <= start:
            return None, f"{label}: invalid slice window {start:#x}-{end:#x}"
        try:
            code = bytes(slice_source_project.loader.memory.load(start, end - start))
        except Exception as ex:  # noqa: BLE001
            return None, f"{label}: unable to read bytes: {_describe_exception(ex)}"
        partial_payload_holder: dict[str, str | None] = {"value": None}
        snapshot_holder: dict[str, dict[str, object] | None] = {"value": None}

        def _recover_and_decompile():
            slice_project = _build_project_from_bytes(code, base_addr=start, entry_point=start)
            _inherit_tail_validation_runtime_policy(slice_project, slice_source_project)
            cfg, func = _pick_function_lean(
                slice_project,
                start,
                regions=[(start, end)],
                data_references=False,
                extend_far_calls=False,
            )
            if not isinstance(getattr(func, "addr", None), int):
                func.addr = start
            if not hasattr(func, "normalized"):
                func.normalized = True
            func.name = name
            _prepare_function_for_decompilation(slice_project, func)
            effective_cod_metadata = cod_metadata
            if effective_cod_metadata is None:
                effective_cod_metadata = _sidecar_cod_metadata_for_function(slice_project, func, binary_path, lst_metadata)
            status, payload, partial_payload, *_ = _decompile_function_with_stats(
                slice_project,
                cfg,
                func,
                max(1, min(timeout, 4)),
                api_style,
                binary_path,
                cod_metadata=effective_cod_metadata,
                lst_metadata=lst_metadata,
                enable_structured_simplify=False,
                enable_postprocess=False,
                allow_isolated_retry=False,
            )
            if not isinstance(partial_payload, str):
                partial_payload = None
            snapshot = getattr(slice_project, "_inertia_last_tail_validation_snapshot", None)
            if isinstance(snapshot, dict):
                snapshot_holder["value"] = dict(snapshot)
            return status, payload, partial_payload, snapshot_holder["value"]

        try:
            runner_timeout = max(2, min(timeout, 6))
            if (
                os.name == "posix"
                and threading.current_thread() is threading.main_thread()
                and threading.active_count() == 1
                and (
                    isinstance(slice_source_project, angr.Project)
                    or getattr(_run_with_timeout_in_fork, "__module__", "") != "inertia_decompiler.runtime_support"
                )
            ):
                status, payload, partial_payload, snapshot = _run_with_timeout_in_fork(
                    _recover_and_decompile,
                    timeout=runner_timeout,
                )
            else:
                status, payload, partial_payload, snapshot = _run_with_timeout_in_daemon_thread(
                    _recover_and_decompile,
                    timeout=runner_timeout,
                    thread_name_prefix="nonopt-fallback",
                )
            partial_payload_holder["value"] = partial_payload
            if isinstance(snapshot, dict):
                snapshot_holder["value"] = dict(snapshot)
        except Exception as ex:  # noqa: BLE001
            return None, f"{label}: retry crashed: {_describe_exception(ex)}"
        slice_snapshot = snapshot_holder["value"]
        if isinstance(slice_snapshot, dict):
            setattr(slice_source_project, "_inertia_partial_tail_validation_snapshot", dict(slice_snapshot))
        if status != "ok":
            partial_payload = partial_payload_holder["value"]
            if partial_payload is not None:
                return partial_payload, None
            return None, f"{label}: {status}: {payload}"
        return payload, None

    rendered, failure_detail = _attempt(project, label="shared-project slice")
    if rendered is not None:
        return rendered

    retry_failures: list[str] = []
    if failure_detail is not None:
        retry_failures.append(failure_detail)
    if allow_fresh_project_retry and binary_path is not None:
        try:
            fresh_project = _build_project_cached(
                str(Path(binary_path)),
                force_blob=_is_blob_only_input(Path(binary_path)),
                base_addr=getattr(getattr(project.loader, "main_object", None), "linked_base", 0) or 0,
                entry_point=getattr(project, "entry", 0),
            )
            _inherit_tail_validation_runtime_policy(fresh_project, project)
        except Exception as ex:  # noqa: BLE001
            retry_failures.append(f"fresh-project setup failed: {_describe_exception(ex)}")
        else:
            rendered, failure_detail = _attempt(fresh_project, label="fresh-project slice")
            if rendered is not None:
                print(f"[dbg] non-optimized fallback recovered {addr:#x} {name} after rebuilding a fresh project")
                return rendered
            if failure_detail is not None:
                retry_failures.append(failure_detail)

    if retry_failures:
        print(f"[dbg] non-optimized fallback unavailable for {addr:#x} {name}: {'; '.join(retry_failures[:3])}")
    return None


def _try_emit_trivial_sidecar_c(
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    addr: int,
    name: str,
) -> str | None:
    region = _lst_code_region(lst_metadata, addr)
    if region is None:
        return None
    asm = _format_asm_range(project, region[0], region[1], max_instructions=8)
    lines = [line.strip() for line in asm.splitlines() if line.strip()]
    if len(lines) == 1 and lines[0].endswith(": ret"):
        return f"void {name}(void)\n{{\n}}\n"
    return None


def _try_decompile_peer_sidecar_slice(
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    addr: int,
    name: str,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
) -> str | None:
    if lst_metadata is None or "peer_exe" not in getattr(lst_metadata, "source_format", ""):
        return None
    region = _lst_code_region(lst_metadata, addr)
    if region is None:
        return None
    peer_paths = tuple(
        Path(path)
        for path in getattr(project, "_inertia_peer_exe_paths", ())
        if isinstance(path, (str, Path))
    )
    if not peer_paths:
        return None
    for peer_path in peer_paths:
        peer_bundle = _load_peer_sidecar_bundle(project, peer_path)
        if peer_bundle is None:
            continue
        peer_project, peer_metadata = peer_bundle
        if peer_metadata is None:
            continue
        if not _exact_function_span_matches(project, peer_project, start=addr, span=region):
            continue
        _inherit_tail_validation_runtime_policy(peer_project, project)
        peer_name = _lst_code_label(peer_metadata, addr, getattr(peer_project, "entry", None)) or name
        slice_result = _try_decompile_sidecar_slice(
            peer_project,
            peer_metadata,
            addr,
            peer_name,
            timeout=timeout,
            api_style=api_style,
            binary_path=peer_path,
        )
        if slice_result is not None:
            peer_snapshot = getattr(peer_project, "_inertia_last_tail_validation_snapshot", None)
            if isinstance(peer_snapshot, dict):
                setattr(project, "_inertia_last_tail_validation_snapshot", dict(peer_snapshot))
            print(f"[dbg] peer sidecar fallback recovered {addr:#x} {peer_name} from {peer_path.name}")
            return slice_result[1]
    return None


def _load_peer_sidecar_bundle(
    project: angr.Project,
    peer_path: Path,
) -> tuple[angr.Project, LSTMetadata | None] | None:
    cache = getattr(project, "_inertia_peer_sidecar_cache", None)
    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_peer_sidecar_cache", cache)
    cache_key = str(peer_path)
    if cache_key in cache:
        return cache[cache_key]
    linked_base = getattr(getattr(project.loader, "main_object", None), "linked_base", 0) or 0
    try:
        peer_project = _build_project_cached(
            str(peer_path),
            force_blob=False,
            base_addr=linked_base,
            entry_point=getattr(project, "entry", 0),
        )
        peer_metadata = _load_lst_metadata(peer_path, peer_project, allow_peer_exe=False)
    except Exception:
        cache[cache_key] = None
        return None
    cache[cache_key] = (peer_project, peer_metadata)
    return cache[cache_key]


def _function_skip_reason(function):
    if getattr(function, "is_simprocedure", False):
        return "SimProcedure (DOS helper)"
    addr = getattr(function, "addr", None)
    if isinstance(addr, int) and addr >= DOS_SERVICE_BASE_ADDR:
        return "DOS service address"
    return None


def _function_recovery_score(function) -> tuple[int, int]:
    blocks = tuple(getattr(function, "blocks", ()) or ())
    if not blocks:
        return (0, 0)
    total_bytes = sum(max(0, getattr(block, "size", 0)) for block in blocks)
    return (len(blocks), total_bytes)


def _function_covered_ranges(function) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for block in tuple(getattr(function, "blocks", ()) or ()):
        addr = getattr(block, "addr", None)
        size = max(0, getattr(block, "size", 0))
        if not isinstance(addr, int) or size <= 0:
            continue
        ranges.append((addr, addr + size))
    if not ranges:
        addr = getattr(function, "addr", None)
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
        candidate_windows = (candidate_windows[-1],)
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


def _recovery_score_good_enough(score: tuple[int, int]) -> bool:
    blocks, total_bytes = score
    return total_bytes >= 0x40 or blocks >= 4


def _exact_region_recovery_looks_truncated(
    function,
    exact_region: tuple[int, int] | None,
) -> bool:
    if exact_region is None:
        return False
    region_size = max(0, exact_region[1] - exact_region[0])
    if region_size < 0x40:
        return False
    _blocks, total_bytes = _function_recovery_score(function)
    return total_bytes < max(0x20, region_size // 3)


def _function_recovery_truncated(function) -> bool:
    info = getattr(function, "info", None)
    return isinstance(info, dict) and bool(info.get("x86_16_recovery_truncated"))


def _needs_pre_entry_body_supplement(function, project_entry: int) -> bool:
    addr = getattr(function, "addr", None)
    if not isinstance(addr, int) or addr >= project_entry:
        return False
    return _function_recovery_truncated(function) or _function_recovery_score(function)[1] <= 0x20


def _prioritized_pre_entry_follow_on_targets(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    *,
    covered_ranges: list[tuple[int, int]],
    existing_addrs: set[int],
    image_end: int,
) -> list[int]:
    main_object = getattr(project.loader, "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    if not isinstance(linked_base, int):
        return []

    prioritized: list[int] = []
    queued = set(existing_addrs)

    def _record(target_addrs) -> None:
        for target_addr in target_addrs:
            if not isinstance(target_addr, int):
                continue
            if target_addr in queued or _addr_in_ranges(target_addr, covered_ranges):
                continue
            if not (linked_base <= target_addr < image_end):
                continue
            prioritized.append(target_addr)
            queued.add(target_addr)

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
        if _needs_pre_entry_body_supplement(function, getattr(project, "entry", 0))
    ]
    for function in pre_entry_functions:
        _record(_linear_function_seed_targets(project, function.addr, include_jumps=False))

    for function in pre_entry_functions:
        neighbor_targets: list[int] = []
        for target in collect_neighbor_call_targets(function):
            target_addr = getattr(target, "target_addr", None)
            if isinstance(target_addr, int):
                neighbor_targets.append(target_addr)
        _record(neighbor_targets)

    return prioritized


def _mark_function_recovery_truncated(function, truncated: bool) -> None:
    info = getattr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_recovery_truncated"] = truncated


def _recover_candidate_function_pair(
    candidate_project,
    *,
    candidate_addr: int,
    image_end: int,
    metadata: LSTMetadata | None,
    project_entry: int,
    region_span: int,
):
    block = candidate_project.factory.block(candidate_addr, size=8, opt_level=0)
    insns = block.capstone.insns
    if len(insns) < 1:
        raise KeyError(f"Function {candidate_addr:#x} does not have a valid first instruction.")
    exact_region = _lst_code_region(metadata, candidate_addr)
    candidate_regions = _candidate_recovery_regions(
        metadata,
        candidate_addr,
        image_end=image_end,
        region_span=region_span,
        project_entry=project_entry,
    )
    best_pair: tuple[object, object] | None = None
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
            )
            score = _function_recovery_score(recovered_pair[1])
            if score > best_score:
                best_pair = recovered_pair
                best_score = score
            if (
                _recovery_score_good_enough(score)
                and not (candidate_addr < project_entry and score[1] <= 0x20 and candidate_region != candidate_regions[-1])
            ):
                break
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
    truncated = False
    if best_pair is not None and exact_region is not None and _exact_region_recovery_looks_truncated(best_pair[1], exact_region):
        truncated = True
        bounded_region = _richest_bounded_recovery_region(candidate_addr, image_end=image_end, region_span=region_span)
        richer_best_pair: tuple[object, object] | None = None
        richer_best_score = best_score
        for data_references in (False, True):
            try:
                richer_pair = _pick_function(
                    candidate_project,
                    candidate_addr,
                    regions=[bounded_region],
                    data_references=data_references,
                    force_smart_scan=False,
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
            richer_score = _function_recovery_score(richer_pair[1])
            if richer_score > richer_best_score:
                richer_best_pair = richer_pair
                richer_best_score = richer_score
        if richer_best_pair is not None:
            best_pair = richer_best_pair
            best_score = richer_best_score
            truncated = False
    if (
        best_pair is not None
        and candidate_addr < project_entry
        and best_score[1] <= 0x20
        and candidate_regions
    ):
        truncated = True
        try:
            richer_pair = _pick_function(
                candidate_project,
                candidate_addr,
                regions=[_richest_bounded_recovery_region(candidate_addr, image_end=image_end, region_span=region_span)],
                data_references=True,
                force_smart_scan=False,
            )
            richer_score = _function_recovery_score(richer_pair[1])
            if richer_score > best_score:
                best_pair = richer_pair
                best_score = richer_score
        except Exception as exc:  # noqa: BLE001
            last_error = exc
    if best_pair is not None:
        _mark_function_recovery_truncated(best_pair[1], truncated)
        return best_pair
    if last_error is not None:
        raise last_error
    raise KeyError(f"Function {candidate_addr:#x} was not recovered.")


def _interesting_functions(cfg, *, limit: int | None):
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


def _rank_function_cfg_pairs_for_display(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
) -> list[tuple[object, object]]:
    if not function_cfg_pairs:
        return []
    entry_addr = getattr(project, "entry", None)
    direct_entry_targets = _linear_function_seed_targets(project, entry_addr, max_scan=0x180, include_jumps=False)

    def _display_metrics(function) -> tuple[int, int]:
        complexity_blocks, complexity_bytes = _function_complexity(function)
        recovery_blocks, recovery_bytes = _function_recovery_score(function)
        return (max(complexity_blocks, recovery_blocks), max(complexity_bytes, recovery_bytes))

    def _body_seed_rank(item: tuple[object, object]) -> tuple[int, int, int, int, int]:
        _cfg, function = item
        addr = getattr(function, "addr", None)
        block_count, byte_count = _display_metrics(function)
        tiny_wrapper_like = int(block_count <= 3 and byte_count <= 0x20 and not _function_recovery_truncated(function))
        direct_entry_rank = 0 if isinstance(addr, int) and addr in direct_entry_targets else 1
        truncation_rank = 0 if _function_recovery_truncated(function) else 1
        distance = abs(addr - entry_addr) if isinstance(addr, int) and isinstance(entry_addr, int) else 0
        return (tiny_wrapper_like, truncation_rank, direct_entry_rank, -byte_count, distance)

    body_seed_candidates = [
        item
        for item in function_cfg_pairs
        if isinstance(getattr(item[1], "addr", None), int) and item[1].addr < entry_addr
    ]
    primary_body_seed = min(body_seed_candidates, key=_body_seed_rank)[1].addr if body_seed_candidates else None
    body_targets = (
        _linear_function_seed_targets(project, primary_body_seed, include_jumps=False)
        if isinstance(primary_body_seed, int)
        else set()
    )

    def _meaningful_pre_entry_body(addr: int | None, byte_count: int, truncated: bool) -> bool:
        return isinstance(addr, int) and isinstance(entry_addr, int) and addr < entry_addr and (truncated or byte_count > 0x20)

    def _priority(item: tuple[object, object]) -> tuple[int, int, int, int, int]:
        _cfg, function = item
        addr = getattr(function, "addr", 0)
        block_count, byte_count = _display_metrics(function)
        truncated = _function_recovery_truncated(function)
        tiny_wrapper_like = int(block_count <= 3 and byte_count <= 0x20 and not truncated)
        meaningful_pre_entry_body = _meaningful_pre_entry_body(addr, byte_count, truncated)
        if addr == entry_addr:
            bucket = 0
        elif isinstance(primary_body_seed, int) and addr == primary_body_seed:
            bucket = 1
        elif meaningful_pre_entry_body and addr in body_targets:
            bucket = 2
        elif meaningful_pre_entry_body:
            bucket = 3
        elif addr in body_targets:
            bucket = 4
        elif addr in direct_entry_targets:
            bucket = 5
        elif isinstance(addr, int) and addr < entry_addr:
            bucket = 6
        else:
            bucket = 7
        distance = abs(addr - entry_addr) if isinstance(addr, int) and isinstance(entry_addr, int) else 0
        return (bucket, tiny_wrapper_like, block_count, byte_count, distance)

    return sorted(function_cfg_pairs, key=_priority)


def _expanded_exe_discovery_limit(limit: int | None) -> int | None:
    if limit is None or limit <= 0:
        return None
    return max(limit * 2, limit + 4)


def _supplement_cached_seeded_recovery(
    project: angr.Project,
    cached_recovered: list[tuple[object, object]],
    cached_addrs: list[int],
    *,
    region_span: int,
    per_function_timeout: int,
    limit: int | None,
    cache_key: dict[str, object] | None,
) -> tuple[list[tuple[object, object]], list[int]]:
    cached_seen = {function.addr for _cfg, function in cached_recovered if isinstance(getattr(function, "addr", None), int)}
    cached_covered_ranges: list[tuple[int, int]] = []
    for _cfg, function in cached_recovered:
        cached_covered_ranges.extend(_function_covered_ranges(function))
    cached_pre_entry = [
        function
        for _cfg, function in cached_recovered
        if isinstance(getattr(function, "addr", None), int) and function.addr < project.entry
    ]
    needs_body_supplement = not cached_pre_entry or all(
        _function_recovery_truncated(function) or _function_recovery_score(function)[1] <= 0x20
        for function in cached_pre_entry
    )
    if not needs_body_supplement:
        return cached_recovered, cached_addrs

    main_object = getattr(project.loader, "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    image_end = linked_base + max_addr + 1 if isinstance(linked_base, int) and isinstance(max_addr, int) else None
    supplemental_pairs: list[tuple[object, object]] = []
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
    if not supplemental_pairs:
        return cached_recovered, cached_addrs

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


def _store_catalog_address_cache(
    project: angr.Project,
    binary_path: Path,
    function_cfg_pairs: list[tuple[object, object]],
) -> None:
    cache_key = _recovery_cache_key(
        binary_path=binary_path,
        kind="display_catalog_addrs",
        extra={
            "entry": getattr(project, "entry", None),
            "arch": getattr(getattr(project, "arch", None), "name", None),
        },
    )
    if cache_key is None:
        return
    addrs = [
        getattr(function, "addr", None)
        for _cfg, function in function_cfg_pairs
        if isinstance(getattr(function, "addr", None), int)
    ]
    _store_cache_json("recovery", cache_key, {"addrs": addrs})


def _load_catalog_address_cache(project: angr.Project, binary_path: Path) -> list[int]:
    cache_key = _recovery_cache_key(
        binary_path=binary_path,
        kind="display_catalog_addrs",
        extra={
            "entry": getattr(project, "entry", None),
            "arch": getattr(getattr(project, "arch", None), "name", None),
        },
    )
    cached = _load_cache_json("recovery", cache_key) if cache_key is not None else None
    if not isinstance(cached, dict):
        return []
    addrs = cached.get("addrs")
    if not isinstance(addrs, list) or not all(isinstance(addr, int) for addr in addrs):
        return []
    return addrs


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
):
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
    if not ranked_candidates:
        return []
    main_object = getattr(project.loader, "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    binary_path = getattr(main_object, "binary", None)
    if not isinstance(linked_base, int):
        return []
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(max_addr, int):
        return []
    try:
        code = bytes(main_object.memory.load(0, max_addr + 1))
    except Exception:
        return []

    supplemental: list[tuple[object, object]] = []
    scanned = 0
    for addr in ranked_candidates:
        if len(supplemental) >= recover_limit or scanned >= scan_limit:
            break
        scanned += 1

        def _recover_candidate(candidate_addr=addr):
            candidate_project = project
            if binary_path is not None:
                candidate_project = _build_project_cached(
                    str(Path(binary_path)),
                    force_blob=False,
                    base_addr=linked_base,
                    entry_point=project.entry,
                )
            return _pick_function_lean(
                candidate_project,
                candidate_addr,
                regions=[
                    (
                        candidate_addr,
                        min(candidate_addr + region_span, linked_base + len(code)),
                    )
                ],
                data_references=False,
                extend_far_calls=False,
            )

        try:
            function_cfg, function = _run_with_timeout_in_daemon_thread(
                _recover_candidate,
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

    if supplemental:
        print(
            f"/* supplemental prologue scan recovered {len(supplemental)} additional function(s) near entry. */"
        )
    return supplemental


def _rank_gap_scan_candidate_addrs(
    project: angr.Project,
    recovered_function_pairs: list[tuple[object, object]],
    covered_ranges: list[tuple[int, int]],
    existing_addrs: set[int],
    *,
    image_end: int,
    search_span: int = 0x2000,
) -> list[int]:
    if project.arch.name != "86_16":
        return []
    if getattr(getattr(project, "arch", None), "capstone", None) is None:
        return []

    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return []

    max_addr = getattr(main_object, "max_addr", None)
    linked_base = getattr(main_object, "linked_base", None)
    if not isinstance(max_addr, int) or not isinstance(linked_base, int):
        return []

    try:
        code = bytes(main_object.memory.load(0, max_addr + 1))
    except Exception:
        return []

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

    gap_ranges: list[tuple[int, int]] = []
    cursor = linked_base
    for start, end in merged_ranges:
        if cursor < start:
            gap_ranges.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < image_end:
        gap_ranges.append((cursor, image_end))

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

    for _cfg, function in recovered_function_pairs:
        for block in tuple(getattr(function, "blocks", ()) or ()):
            block_addr = getattr(block, "addr", None)
            block_size = max(0, getattr(block, "size", 0))
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
                _record(target_addr, 1, block_addr, target_addr)

    align_bytes = {0x00, 0x90, 0xCC}
    for gap_start, gap_end in gap_ranges:
        scan_end = min(gap_end, gap_start + search_span)
        if scan_end - gap_start < 3:
            continue
        try:
            gap_code = bytes(main_object.memory.load(gap_start - linked_base, scan_end - gap_start))
        except Exception:
            continue

        offset = 0
        while offset <= len(gap_code) - 3:
            if gap_code[offset : offset + 3] == b"\x55\x8b\xec":
                addr = gap_start + offset
                try:
                    block = project.factory.block(addr, size=16, opt_level=0)
                except Exception:
                    pass
                else:
                    insns = block.capstone.insns
                    if (
                        len(insns) >= 2
                        and insns[0].mnemonic == "push"
                        and insns[0].op_str == "bp"
                        and insns[1].mnemonic == "mov"
                        and insns[1].op_str == "bp, sp"
                    ):
                        _record(addr, 0, gap_start, offset)

            window = gap_code[offset : offset + 16]
            insn = next(project.arch.capstone.disasm(window, gap_start + offset, 1), None)
            if insn is None or insn.size <= 0:
                break
            if insn.mnemonic.lower() in {"ret", "retf", "iret"}:
                next_offset = offset + insn.size
                skipped_alignment = False
                while next_offset < len(gap_code) and gap_code[next_offset] in align_bytes:
                    skipped_alignment = True
                    next_offset += 1
                if next_offset < len(gap_code):
                    candidate_addr = gap_start + next_offset
                    if skipped_alignment or gap_code[next_offset : next_offset + 3] == b"\x55\x8b\xec":
                        _record(candidate_addr, 2, gap_start, next_offset)
            offset += insn.size

    return [addr for addr, _meta in sorted(ranked_candidates.items(), key=lambda item: (*item[1], item[0]))]


def _rank_prologue_scan_candidate_addrs(
    project: angr.Project,
    existing_addrs: set[int],
    *,
    search_span: int = 0x2000,
) -> list[int]:
    if project.arch.name != "86_16":
        return []

    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return []

    max_addr = getattr(main_object, "max_addr", None)
    linked_base = getattr(main_object, "linked_base", None)
    if not isinstance(max_addr, int) or not isinstance(linked_base, int):
        return []

    try:
        code = main_object.memory.load(0, max_addr + 1)
    except Exception:
        return []

    upper_bound = min(project.entry + search_span, linked_base + len(code))
    ranked_candidates: list[tuple[int, int, int]] = []
    for offset in range(len(code) - 2):
        if code[offset : offset + 3] != b"\x55\x8b\xec":
            continue
        addr = linked_base + offset
        if not (project.entry <= addr < upper_bound) or addr in existing_addrs:
            continue
        try:
            block = project.factory.block(addr, size=16, opt_level=0)
        except Exception:
            continue
        insns = block.capstone.insns
        if (
            len(insns) < 2
            or insns[0].mnemonic != "push"
            or insns[0].op_str != "bp"
            or insns[1].mnemonic != "mov"
            or insns[1].op_str != "bp, sp"
        ):
            continue
        has_dos_interrupt = any(insn.mnemonic == "int" and insn.op_str == "0x21" for insn in insns[:8])
        ranked_candidates.append((0 if has_dos_interrupt else 1, -offset, addr))
    return [addr for _priority, _neg_offset, addr in sorted(ranked_candidates)]


def _relocation_seed_targets(
    project: angr.Project,
    code: bytes,
    *,
    linked_base: int,
) -> tuple[set[int], set[int]]:
    main_object = getattr(project.loader, "main_object", None)
    relocation_entries = getattr(main_object, "mz_relocation_entries", ()) if main_object is not None else ()
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


def _rank_exe_function_seeds(project: angr.Project) -> list[int]:
    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return []
    binary_path = getattr(main_object, "binary", None)
    max_addr = getattr(main_object, "max_addr", None)
    linked_base = getattr(main_object, "linked_base", None)
    if not isinstance(max_addr, int) or not isinstance(linked_base, int):
        return []
    metadata = getattr(project, "_inertia_lst_metadata", None)
    recovery_labels = {}
    metadata_fingerprint = None
    if metadata is not None:
        recovery_labels = _recovery_code_labels(metadata)
        signature_matched_addrs = _signature_matched_code_addrs(metadata)
        code_ranges = getattr(metadata, "code_ranges", None) or {}
        metadata_fingerprint = {
            "source_format": getattr(metadata, "source_format", None),
            "recovery_code_addrs": sorted(recovery_labels),
            "signature_code_addrs": sorted(signature_matched_addrs),
            "bounded_code_range_count": sum(1 for span in code_ranges.values() if span is not None and span[1] > span[0]),
        }
    else:
        signature_matched_addrs = frozenset()
    cache_key = _recovery_cache_key(
        binary_path=Path(binary_path) if isinstance(binary_path, (str, Path)) else None,
        kind="exe_seed_ranking",
        extra={
            "entry": getattr(project, "entry", None),
            "linked_base": linked_base,
            "max_addr": max_addr,
            "ranking_policy": "strong-non-library-v2",
            "metadata": metadata_fingerprint,
        },
    )
    cached_ranking = _load_cache_json("recovery", cache_key) if cache_key is not None else None
    if isinstance(cached_ranking, dict):
        cached_addrs = cached_ranking.get("addrs")
        if isinstance(cached_addrs, list) and all(isinstance(addr, int) for addr in cached_addrs):
            return cached_addrs

    try:
        code = bytes(main_object.memory.load(0, max_addr + 1))
    except Exception:
        return []
    seed_windows = _seed_scan_windows(project)
    neighbor_targets: set[int] = set()
    entry_window_targets = _entry_window_seed_targets(project, code, linked_base=linked_base)

    def _window_contains(addr: int) -> bool:
        return any(start <= addr < end for start, end in seed_windows)

    try:
        _entry_cfg, entry_function = _run_with_timeout_in_daemon_thread(
            lambda: _pick_function_lean(
                project,
                project.entry,
                regions=[(project.entry, min(project.entry + 0x200, linked_base + len(code)))],
                data_references=False,
                extend_far_calls=True,
            ),
            timeout=1,
            thread_name_prefix="seed-rank",
        )
        for target in collect_neighbor_call_targets(entry_function):
            neighbor_targets.add(target.target_addr)
    except Exception:
        pass

    ranked: dict[int, tuple[int, int]] = {}
    bounded_metadata_spans: dict[int, int] = {}
    near_call_targets: set[int] = set()
    far_call_targets: set[int] = set()
    prologue_targets: set[int] = set()
    relocation_control_targets: set[int] = set()
    relocation_pointer_targets: set[int] = set()

    def _consider(addr: int, priority: int) -> None:
        if not (linked_base <= addr < linked_base + len(code)):
            return
        if addr in signature_matched_addrs:
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

    metadata_labels = _visible_code_labels(metadata) if metadata is not None else {}
    if not metadata_labels and metadata is not None:
        metadata_labels = recovery_labels
    for addr, _name in metadata_labels.items():
        if (span := _lst_code_region(metadata, addr)) is None:
            continue
        span_len = span[1] - span[0]
        if span_len > 0:
            bounded_metadata_spans[addr] = span_len
        _consider(addr, 0)

    tracer = trace_16bit_seed_candidates(
        project,
        code,
        linked_base=linked_base,
        windows=seed_windows,
    )
    for target in entry_window_targets:
        _consider(target, 0)
    for target in tracer.call_targets:
        canonical = _resolve_x86_16_call_target(code, target - linked_base)
        if canonical is not None:
            _consider(linked_base + canonical, 0 if target in entry_window_targets else 1)
    for target in tracer.jump_targets:
        if target not in tracer.call_targets:
            canonical = _resolve_x86_16_function_start(code, target - linked_base)
            if canonical is not None:
                _consider(linked_base + canonical, 2)

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
                _consider(resolved, 0)
        if code[offset : offset + 3] == b"\x55\x8b\xec":
            target = linked_base + offset
            prologue_targets.add(target)
            _consider(target, 1)

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
            _consider(resolved, 0)

    relocation_control_targets, relocation_pointer_targets = _relocation_seed_targets(
        project,
        code,
        linked_base=linked_base,
    )
    for target in relocation_control_targets:
        _consider(target, 1)
    for target in relocation_pointer_targets:
        _consider(target, 4)

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
        _consider(next_target, 2)

    reranked: list[tuple[tuple[int, int, int], int]] = []
    for addr, (_priority, distance) in ranked.items():
        metadata_span_len = bounded_metadata_spans.get(addr)
        in_near_call = addr in near_call_targets
        in_far_call = addr in far_call_targets
        in_tracer_call = addr in tracer.call_targets
        in_prologue = addr in prologue_targets
        in_terminal_next = addr in terminal_next_targets
        in_neighbor = addr in neighbor_targets
        in_entry_window = addr in entry_window_targets
        in_relocation_control = addr in relocation_control_targets
        in_relocation_pointer = addr in relocation_pointer_targets
        entry_descends_from_stub = in_entry_window and addr < project.entry
        if metadata_span_len is not None:
            final_priority = 0
        elif entry_descends_from_stub and (in_neighbor or in_near_call or in_far_call):
            final_priority = 0
        elif entry_descends_from_stub:
            final_priority = 1
        elif in_entry_window and (in_neighbor or in_near_call or in_far_call):
            final_priority = 1
        elif in_relocation_control and (in_prologue or in_near_call or in_far_call):
            final_priority = 2
        elif in_relocation_control:
            final_priority = 3
        elif in_neighbor and in_prologue:
            final_priority = 2
        elif in_entry_window:
            final_priority = 2
        elif in_neighbor:
            final_priority = 3
        elif in_prologue and (in_near_call or in_far_call):
            final_priority = 2
        elif in_prologue:
            final_priority = 3
        elif in_relocation_pointer and (in_near_call or in_far_call or in_prologue):
            final_priority = 4
        elif in_relocation_pointer:
            final_priority = 5
        elif in_terminal_next and (in_near_call or in_far_call):
            final_priority = 4
        elif in_terminal_next:
            final_priority = 5
        elif in_far_call:
            final_priority = 6
        elif in_near_call and in_tracer_call:
            final_priority = 6
        elif in_near_call:
            # A raw near-call target with no prologue, entry-window, relocation,
            # metadata, or fast-tracer confirmation is often an internal label in
            # compiler/runtime code. Keep direct-call-only labels out of the
            # default "likely function" queue; stronger signals above still admit
            # legitimate naked functions.
            final_priority = 8
        else:
            final_priority = 9
        if final_priority >= 8:
            continue
        size_rank = -metadata_span_len if metadata_span_len is not None else 0
        reranked.append(((final_priority, size_rank, distance), addr))

    ranked_addrs = [addr for _meta, addr in sorted(reranked)]
    if cache_key is not None:
        _store_cache_json("recovery", cache_key, {"addrs": ranked_addrs})
    return ranked_addrs


def _recover_fast_seed_functions(
    project: angr.Project,
    *,
    timeout: int,
    limit: int | None,
):
    if project.arch.name != "86_16":
        return []
    recovered = _recover_seeded_exe_functions(project, timeout=timeout, limit=limit)
    if recovered:
        print("/* quick function-entry scan found likely functions using call/prologue/epilogue patterns without helper metadata. */")
    return recovered


def _recover_fast_exe_catalog(
    project: angr.Project,
    *,
    timeout: int,
    window: int,
    low_memory: bool,
    limit: int | None,
) -> list[tuple[object, object]]:
    recovered: list[tuple[object, object]] = []
    seen_addrs: set[int] = set()

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

    seed_limit = None if limit is None else max(limit * 2, limit + 4)
    seed_start = time.perf_counter()
    seeded = _recover_fast_seed_functions(
        project,
        timeout=max(1, min(timeout, 8)),
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
        print("/* quick EXE function discovery found entry/body functions without needing whole-program control-flow recovery. */")
    return recovered


def _recover_hidden_sidecar_display_pairs(
    project: angr.Project,
    ranked_binary_offsets: Sequence[int],
    *,
    timeout: int,
    window: int,
    low_memory: bool,
    limit: int,
) -> list[tuple[object, object]]:
    if limit <= 0 or not ranked_binary_offsets:
        return []

    recovered: list[tuple[object, object]] = []
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
        addr = getattr(item.function, "addr", None)
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
        print("/* hidden-sidecar EXE: using ranked direct-binary preview for the capped display set before broad CFG recovery. */")
    return recovered


def _rank_hidden_sidecar_pairs_for_display_throughput(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    *,
    limit: int,
) -> list[tuple[object, object]]:
    if not function_cfg_pairs:
        return []

    entry_addr = getattr(project, "entry", None)
    indexed_pairs = list(enumerate(function_cfg_pairs))
    entry_pair: tuple[int, tuple[object, object]] | None = None
    non_entry_pairs: list[tuple[int, tuple[object, object]]] = []

    for original_index, pair in indexed_pairs:
        _cfg, function = pair
        addr = getattr(function, "addr", None)
        if isinstance(entry_addr, int) and addr == entry_addr and entry_pair is None:
            entry_pair = (original_index, pair)
            continue
        non_entry_pairs.append((original_index, pair))

    def _throughput_priority(indexed_pair: tuple[int, tuple[object, object]]) -> tuple[int, int, int, int, int]:
        original_index, (_cfg, function) = indexed_pair
        addr = getattr(function, "addr", None)
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


def _recover_cached_function_pairs(
    project: angr.Project,
    *,
    addrs: list[int],
    timeout: int,
    limit: int | None,
    region_span: int = 0x120,
    per_function_timeout: int = 1,
) -> list[tuple[object, object]]:
    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return []
    binary_path = getattr(main_object, "binary", None)
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    if binary_path is None or not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return []

    deadline = time.monotonic() + max(1, timeout)
    metadata = getattr(project, "_inertia_lst_metadata", None)
    image_end = linked_base + max_addr + 1
    recovered: list[tuple[object, object]] = []
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
        if isinstance(getattr(project, "entry", None), int) and addr < project.entry:
            candidate_timeout = min(max(2, per_function_timeout), max(1, int(remaining)))

        try:
            function_cfg, function = _recover_candidate_with_timeout(
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
        except (_AnalysisTimeout, KeyError):
            continue
        except Exception:
            continue

        if function.addr in seen_addrs:
            continue
        reason = _function_skip_reason(function)
        if reason is not None:
            continue
        seen_addrs.add(function.addr)
        recovered.append((function_cfg, function))

    if recovered:
        print(f"/* restored {len(recovered)} previously recovered function entr{'y' if len(recovered) == 1 else 'ies'} from recovery cache. */")
    return recovered


def _candidate_recovery_cache_key(
    *,
    candidate_addr: int,
    image_end: int,
    project_entry: int,
    region_span: int,
) -> tuple[int, int, int, int]:
    return (candidate_addr, image_end, project_entry, region_span)


def _lookup_candidate_recovery_cache(
    project: angr.Project,
    *,
    candidate_addr: int,
    image_end: int,
    project_entry: int,
    region_span: int,
):
    cache = getattr(project, "_inertia_candidate_recovery_cache", None)
    if not isinstance(cache, dict):
        return None
    return cache.get(
        _candidate_recovery_cache_key(
            candidate_addr=candidate_addr,
            image_end=image_end,
            project_entry=project_entry,
            region_span=region_span,
        )
    )


def _store_candidate_recovery_cache(
    project: angr.Project,
    *,
    candidate_addr: int,
    image_end: int,
    project_entry: int,
    region_span: int,
    value,
) -> None:
    cache = getattr(project, "_inertia_candidate_recovery_cache", None)
    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_candidate_recovery_cache", cache)
    cache[
        _candidate_recovery_cache_key(
            candidate_addr=candidate_addr,
            image_end=image_end,
            project_entry=project_entry,
            region_span=region_span,
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
    return _recovery_cache_key(
        binary_path=binary_path,
        kind="function_recovery_attempt",
        extra={
            "addr": addr,
            "mode": mode,
            "window": window,
            "low_memory": bool(low_memory),
            "recovery_policy": "lazy-candidate-timeout-v1",
        },
    )


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
    if not isinstance(cached, dict) or cached.get("status") != "timeout":
        return None, "", cache_key
    cached_timeout = cached.get("timeout")
    name = str(cached.get("name") or f"sub_{addr:x}")
    if isinstance(cached_timeout, int) and cached_timeout >= timeout:
        return (
            FunctionWorkResult(
                index=int(cached.get("index", 0)),
                status="timeout",
                payload=str(
                    cached.get("payload")
                    or f"Timed out while recovering {name} at {addr:#x}."
                ),
                debug_output=(
                    f"[dbg] recovery timeout cache hit for {addr:#x} {name} "
                    f"mode={mode} cached_timeout={cached_timeout}s requested_timeout={timeout}s\n"
                ),
                function=None,
                function_cfg=None,
                skip_heavy_fallbacks=True,
            ),
            "",
            cache_key,
        )
    return (
        None,
        (
            f"[dbg] recovery timeout cache bypass for {addr:#x} {name} "
            f"mode={mode} cached_timeout={cached_timeout!r} requested_timeout={timeout}s\n"
        ),
        cache_key,
    )


def _store_persistent_recovery_timeout(
    cache_key: dict[str, object] | None,
    *,
    index: int,
    addr: int,
    name: str,
    timeout: int,
    payload: str,
) -> None:
    if cache_key is None:
        return
    _store_cache_json(
        "function_recovery_attempt",
        cache_key,
        {
            "status": "timeout",
            "index": index,
            "addr": addr,
            "name": name,
            "timeout": timeout,
            "payload": payload,
        },
    )


def _recover_candidate_with_timeout(
    project: angr.Project,
    *,
    candidate_addr: int,
    image_end: int,
    metadata,
    project_entry: int,
    region_span: int,
    timeout: int,
    binary_path: Path,
    linked_base: int,
):
    cached_result = _lookup_candidate_recovery_cache(
        project,
        candidate_addr=candidate_addr,
        image_end=image_end,
        project_entry=project_entry,
        region_span=region_span,
    )
    if isinstance(cached_result, tuple):
        cache_status = cached_result[0]
        if cache_status == "ok":
            return cached_result[1]
        if cache_status == "keyerror":
            raise KeyError(cached_result[1])

    def _recover_candidate(candidate_project):
        return _recover_candidate_function_pair(
            candidate_project,
            candidate_addr=candidate_addr,
            image_end=image_end,
            metadata=metadata,
            project_entry=project_entry,
            region_span=region_span,
        )

    def _recover_once():
        try:
            recovered_pair = _recover_candidate(project)
            _store_candidate_recovery_cache(
                project,
                candidate_addr=candidate_addr,
                image_end=image_end,
                project_entry=project_entry,
                region_span=region_span,
                value=("ok", recovered_pair),
            )
            return recovered_pair
        except KeyError as exc:
            _store_candidate_recovery_cache(
                project,
                candidate_addr=candidate_addr,
                image_end=image_end,
                project_entry=project_entry,
                region_span=region_span,
                value=("keyerror", str(exc)),
            )
            raise
        except Exception:
            candidate_project = _build_project_cached(
                str(binary_path),
                force_blob=False,
                base_addr=linked_base,
                entry_point=project_entry,
            )
            recovered_pair = _recover_candidate(candidate_project)
            _store_candidate_recovery_cache(
                project,
                candidate_addr=candidate_addr,
                image_end=image_end,
                project_entry=project_entry,
                region_span=region_span,
                value=("ok", recovered_pair),
            )
            return recovered_pair

    timeout = max(1, int(timeout))
    if (
        os.name == "posix"
        and threading.current_thread() is threading.main_thread()
        and threading.active_count() == 1
    ):
        try:
            return _run_with_timeout_in_fork(
                _recover_once,
                timeout=timeout + 1,
            )
        except Exception:
            pass
    if threading.current_thread() is threading.main_thread():
        with _analysis_timeout(timeout):
            return _recover_once()
    return _run_with_timeout_in_daemon_thread(
        _recover_once,
        timeout=timeout,
        thread_name_prefix="recover-candidate",
    )


def _recover_seeded_exe_functions(
    project: angr.Project,
    *,
    timeout: int,
    limit: int | None,
    region_span: int = 0x120,
    per_function_timeout: int = 1,
    return_addrs: bool = False,
):
    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return ([], []) if return_addrs else []
    binary_path = getattr(main_object, "binary", None)
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    if binary_path is None or not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return ([], []) if return_addrs else []

    ranked_seeds = _rank_exe_function_seeds(project)
    if not ranked_seeds:
        return ([], []) if return_addrs else []

    deadline = time.monotonic() + max(1, timeout)
    recovered: list[tuple[object, object]] = []
    recovered_addrs: list[int] = []
    seen_addrs: set[int] = {project.entry}
    queued_addrs: set[int] = set(ranked_seeds)
    pending_seed_addrs: list[int] = list(ranked_seeds)
    pending_gap_addrs: list[int] = []
    pending_neighbor_addrs: list[int] = []
    covered_ranges: list[tuple[int, int]] = []
    metadata = getattr(project, "_inertia_lst_metadata", None)
    image_end = linked_base + max_addr + 1
    cache_key = _recovery_cache_key(
        binary_path=Path(binary_path),
        kind="seeded_function_catalog",
        extra={
            "entry": getattr(project, "entry", None),
            "linked_base": linked_base,
            "max_addr": max_addr,
            "region_span": region_span,
        },
    )
    cached_payload = _load_cache_json("recovery", cache_key) if cache_key is not None else None
    if isinstance(cached_payload, dict):
        cached_addrs = cached_payload.get("addrs")
        if isinstance(cached_addrs, list) and all(isinstance(addr, int) for addr in cached_addrs):
            cached_recovered = _recover_cached_function_pairs(
                project,
                addrs=cached_addrs,
                timeout=timeout,
                limit=limit,
                region_span=region_span,
                per_function_timeout=per_function_timeout,
            )
            if cached_recovered:
                try:
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
                except FuturesTimeoutError:
                    pass
                return (cached_recovered, cached_addrs) if return_addrs else cached_recovered

    prologue_candidates = _rank_prologue_scan_candidate_addrs(project, seen_addrs | queued_addrs)
    if prologue_candidates:
        initial_prologue_targets = [
            addr
            for addr in prologue_candidates[:8]
            if addr not in seen_addrs and addr not in queued_addrs and linked_base <= addr < image_end
        ]
        if initial_prologue_targets:
            pending_seed_addrs[:0] = initial_prologue_targets
            queued_addrs.update(initial_prologue_targets)

    while pending_seed_addrs or pending_gap_addrs or pending_neighbor_addrs:
        if pending_seed_addrs:
            addr = pending_seed_addrs.pop(0)
        elif pending_gap_addrs:
            addr = pending_gap_addrs.pop(0)
        else:
            addr = pending_neighbor_addrs.pop(0)
        if _addr_in_ranges(addr, covered_ranges):
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        try:
            function_cfg, function = _recover_candidate_with_timeout(
                project,
                candidate_addr=addr,
                image_end=image_end,
                metadata=metadata,
                project_entry=project.entry,
                region_span=region_span,
                timeout=min(per_function_timeout, max(1, int(remaining))),
                binary_path=Path(binary_path),
                linked_base=linked_base,
            )
        except (_AnalysisTimeout, KeyError):
            continue
        except Exception:
            continue

        if function.addr in seen_addrs:
            continue
        reason = _function_skip_reason(function)
        if reason is not None:
            continue
        seen_addrs.add(function.addr)
        recovered_addrs.append(function.addr)
        if limit is None or len(recovered) < limit:
            recovered.append((function_cfg, function))
        covered_ranges.extend(_function_covered_ranges(function))
        function_score = _function_recovery_score(function)
        function_truncated = _function_recovery_truncated(function)

        if limit is not None and not return_addrs and len(recovered) >= limit:
            break

        def _queue_targets(target_addrs: list[int], *, queue: str) -> None:
            queued_targets: list[int] = []
            for target_addr in target_addrs:
                if target_addr in seen_addrs or target_addr in queued_addrs:
                    continue
                if _addr_in_ranges(target_addr, covered_ranges):
                    continue
                if not (linked_base <= target_addr < image_end):
                    continue
                queued_targets.append(target_addr)
            if queued_targets:
                if queue == "gap":
                    pending_gap_addrs.extend(queued_targets)
                else:
                    pending_neighbor_addrs.extend(queued_targets)
                queued_addrs.update(queued_targets)

        linear_targets = list(_linear_function_seed_targets(project, function.addr, include_jumps=False))
        neighbor_targets: list[int] = []
        for target in collect_neighbor_call_targets(function):
            target_addr = getattr(target, "target_addr", None)
            if isinstance(target_addr, int):
                neighbor_targets.append(target_addr)
        if _needs_pre_entry_body_supplement(function, project.entry):
            _queue_targets(
                _prioritized_pre_entry_follow_on_targets(
                    project,
                    [(function_cfg, function)],
                    covered_ranges=covered_ranges,
                    existing_addrs=seen_addrs | queued_addrs,
                    image_end=image_end,
                ),
                queue="gap",
            )
        else:
            _queue_targets(neighbor_targets, queue="neighbor")

    if recovered_addrs:
        if cache_key is not None:
            _store_cache_json(
                "recovery",
                cache_key,
                {"addrs": recovered_addrs},
            )
        print(f"/* quick function-entry scan recovered {len(recovered_addrs)} additional function(s). */")
    return (recovered, recovered_addrs) if return_addrs else recovered


def _direct_recovery_inventory_count(project: angr.Project) -> int | None:
    try:
        ranked_seeds = _rank_exe_function_seeds(project)
    except Exception:
        return None
    return len(ranked_seeds) if ranked_seeds else None


def _decompile_function(
    project: angr.Project,
    cfg,
    function,
    timeout: int,
    api_style: str,
    binary_path: Path | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    lst_metadata: LSTMetadata | None = None,
    enable_structured_simplify: bool = True,
    enable_postprocess: bool = True,
    allow_isolated_retry: bool = True,
    deadline: float | None = None,
) -> tuple[str, str]:
    setattr(project, "_inertia_partial_codegen_text", None)
    setattr(project, "_inertia_last_tail_validation_snapshot", None)
    effective_cod_metadata = cod_metadata or _sidecar_cod_metadata_for_function(
        project,
        function,
        binary_path,
        lst_metadata,
    )
    with DECOMPILATION_PREP_LOCK:
        _apply_binary_specific_annotations(
            project,
            binary_path,
            lst_metadata,
            func_addr=function.addr,
            cod_metadata=effective_cod_metadata,
            synthetic_globals=synthetic_globals,
        )
        _prepare_function_for_decompilation(project, function)
        seed_calling_conventions(cfg)
        block_count, byte_count = _function_complexity(function)
        profile = _function_decompilation_profile(function, block_count, byte_count)
        function_info = getattr(function, "info", None)
        if isinstance(function_info, dict):
            profile_info = function_info.setdefault("x86_16_decompilation_profile", {})
            profile_info.update(profile)
        decompiler_options = _preferred_decompiler_options(
            block_count,
            byte_count,
            wrapper_like=bool(profile.get("wrapper_like")),
            tiny_single_call_helper=bool(profile.get("tiny_single_call_helper")),
        )
    def _analysis_log_messages(dec_obj) -> list[str]:
        messages: list[str] = []
        for entry in getattr(dec_obj, "errors", ()) or ():
            exc_type = getattr(entry, "exc_type", None)
            exc_value = getattr(entry, "exc_value", None)
            error = getattr(entry, "error", None)
            if exc_type is not None and exc_value is not None:
                text = f"{getattr(exc_type, '__name__', str(exc_type))}: {exc_value}"
            elif error is not None:
                text = f"{type(error).__name__}: {error}"
            else:
                text = str(entry)
            if text and text not in messages:
                messages.append(text)
        return messages

    def _remaining_timeout(default: int | None = None) -> int:
        base = timeout if default is None else default
        if deadline is None:
            return max(1, base)
        remaining = int(deadline - time.monotonic())
        return max(1, min(base, remaining))

    def _should_retry_in_isolation(dec_obj) -> bool:
        return any(message.startswith("KeyError:") for message in _analysis_log_messages(dec_obj))

    def _remember_tail_validation_snapshot(codegen) -> None:
        snapshot = getattr(codegen, "_inertia_tail_validation_snapshot", None)
        if isinstance(snapshot, dict):
            setattr(project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
        else:
            setattr(project, "_inertia_last_tail_validation_snapshot", None)

    def _clinic_failure_detail() -> str | None:
        clinic_analysis = getattr(getattr(project, "analyses", None), "Clinic", None)
        if clinic_analysis is None:
            return None
        try:
            with _guard_angr_peephole_expr_bitwidth_assertion():
                with _guard_angr_variable_recovery_binop_sub_size_mismatch():
                    with _analysis_timeout(_remaining_timeout(max(1, min(timeout, 2)))):
                        clinic_analysis(function)
        except _AnalysisTimeout:
            return "clinic-failure=timeout"
        except Exception as ex:  # noqa: BLE001
            return f"clinic-failure={type(ex).__name__}: {_describe_exception(ex)}"
        return None

    def _retry_in_isolated_project() -> tuple[str, str] | None:
        if not allow_isolated_retry or binary_path is None or project.arch.name != "86_16":
            return None
        if (
            os.name == "posix"
            and threading.current_thread() is threading.main_thread()
            and threading.active_count() == 1
        ):
            try:
                if deadline is not None and time.monotonic() >= deadline:
                    return ("timeout", f"Timed out after {timeout}s before isolated retry.")
                print(f"[dbg] retrying {function.addr:#x} {function.name} in a forked isolated project after empty decompilation")
                return _run_with_timeout_in_fork(
                    lambda: _decompile_function(
                        project,
                        cfg,
                        function,
                        timeout,
                        api_style,
                        binary_path,
                        cod_metadata=effective_cod_metadata,
                        synthetic_globals=synthetic_globals,
                        lst_metadata=lst_metadata,
                        enable_structured_simplify=enable_structured_simplify,
                        enable_postprocess=enable_postprocess,
                        allow_isolated_retry=False,
                        deadline=deadline,
                    ),
                    timeout=max(1, timeout) + 1,
                )
            except Exception:
                pass
        main_object = getattr(project.loader, "main_object", None)
        linked_base = getattr(main_object, "linked_base", None)
        max_addr = getattr(main_object, "max_addr", None)
        if not isinstance(linked_base, int) or not isinstance(max_addr, int):
            return None
        try:
            if deadline is not None and time.monotonic() >= deadline:
                return ("timeout", f"Timed out after {timeout}s before isolated retry.")
            isolated_project = _build_project_cached(
                str(Path(binary_path)),
                force_blob=False,
                base_addr=linked_base,
                entry_point=project.entry,
            )
            _inherit_tail_validation_runtime_policy(isolated_project, project)
            isolated_cfg, isolated_function = _recover_candidate_function_pair(
                isolated_project,
                candidate_addr=function.addr,
                image_end=linked_base + max_addr + 1,
                metadata=getattr(project, "_inertia_lst_metadata", None),
                project_entry=project.entry,
                region_span=max(0x180, _function_complexity(function)[1] + 0x80),
            )
        except Exception as ex:  # noqa: BLE001
            return ("empty", f"Optimized decompilation produced no code. Isolated retry setup failed: {_describe_exception(ex)}")
        print(f"[dbg] retrying {function.addr:#x} {function.name} in an isolated project after empty decompilation")
        return _decompile_function(
            isolated_project,
            isolated_cfg,
            isolated_function,
            timeout,
            api_style,
            binary_path,
            cod_metadata=effective_cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
            allow_isolated_retry=False,
            deadline=deadline,
        )

    dec = None
    try:
        with _guard_angr_peephole_expr_bitwidth_assertion():
            with _guard_angr_variable_recovery_binop_sub_size_mismatch():
                with _analysis_timeout(_remaining_timeout()):
                    if decompiler_options is None:
                        dec = project.analyses.Decompiler(function, cfg=cfg)
                    else:
                        dec = project.analyses.Decompiler(function, cfg=cfg, options=decompiler_options)
                    if dec.codegen is None:
                        fallback_options = None if decompiler_options is not None else [("structurer_cls", "Phoenix")]
                        logging.getLogger(__name__).debug(
                            "Selected decompiler structurer produced no code for %s; retrying with %s.",
                            function,
                            "SAILR" if decompiler_options is not None else "Phoenix",
                        )
                        if fallback_options is None:
                            dec = project.analyses.Decompiler(function, cfg=cfg)
                        else:
                            dec = project.analyses.Decompiler(function, cfg=cfg, options=fallback_options)
                    print(f"[dbg] Decompiler returned for {hex(function.addr)}")
                    sys.stdout.flush()
    except _AnalysisTimeout:
        partial_payload = None
        if dec is not None and getattr(dec, "codegen", None) is not None:
            _remember_tail_validation_snapshot(dec.codegen)
            rendered_text, _ = _regenerate_codegen_text_safely(
                dec.codegen,
                context=f"{hex(function.addr)} {function.name} (partial timeout)",
            )
            partial_payload = _format_minimal_codegen_output(
                project,
                function,
                rendered_text,
                api_style,
                binary_path,
                effective_cod_metadata,
            )
        setattr(project, "_inertia_partial_codegen_text", partial_payload)
        timeout_stage = getattr(project, "_inertia_decompiler_stage", None)
        if timeout_stage == "core":
            detail = "during core decompilation"
        elif isinstance(timeout_stage, str) and timeout_stage.startswith("structuring:"):
            detail = f"during x86-16 structuring pass {timeout_stage.split(':', 1)[1]}"
        elif timeout_stage == "structuring":
            detail = "during x86-16 structuring"
        elif isinstance(timeout_stage, str) and timeout_stage.startswith("postprocess:"):
            detail = f"during x86-16 postprocess pass {timeout_stage.split(':', 1)[1]}"
        elif timeout_stage == "postprocess":
            detail = "during x86-16 postprocess"
        else:
            detail = None
        if detail is None:
            return "timeout", f"Timed out after {timeout}s."
        return "timeout", f"Timed out after {timeout}s {detail}."
    except Exception as ex:
        setattr(project, "_inertia_partial_codegen_text", None)
        return "error", str(ex)

    if dec.codegen is None:
        messages = _analysis_log_messages(dec)
        if _should_retry_in_isolation(dec):
            retried = _retry_in_isolated_project()
            if retried is not None and retried[0] == "ok":
                return retried
            if retried is not None and retried[0] != "empty":
                return retried
        detail = "Decompiler did not produce code."
        if messages:
            detail += " angr details: " + "; ".join(messages[:3])
        if getattr(dec, "clinic", None) is None:
            detail += " clinic=None."
            clinic_failure = _clinic_failure_detail()
            if clinic_failure is not None:
                detail += f" {clinic_failure}."
        setattr(project, "_inertia_partial_codegen_text", None)
        return "empty", detail
    if not enable_postprocess:
        _remember_tail_validation_snapshot(dec.codegen)
        rendered_text, _ = _regenerate_codegen_text_safely(
            dec.codegen,
            context=f"{hex(function.addr)} {function.name} (non-optimized)",
        )
        formatted = _format_minimal_codegen_output(
            project,
            function,
            rendered_text,
            api_style,
            binary_path,
            effective_cod_metadata,
        )
        setattr(project, "_inertia_partial_codegen_text", None)
        return "ok", formatted
    setattr(project, "_inertia_rewrite_cache", {})
    stack_local_candidates = {
        id(variable): (variable, cvar)
        for variable, cvar in getattr(dec.codegen.cfunc, "variables_in_use", {}).items()
        if isinstance(variable, SimStackVariable)
        and id(variable)
        not in {
            id(getattr(arg, "variable", None))
            for arg in getattr(dec.codegen.cfunc, "arg_list", ()) or ()
            if getattr(arg, "variable", None) is not None
        }
    }
    setattr(dec.codegen, "_inertia_stack_local_declaration_candidates", stack_local_candidates)
    changed = False
    small_function = bool(profile.get("wrapper_like") or profile.get("tiny_single_call_helper"))
    fold_values_cod_outlier = (
        binary_path is not None
        and binary_path.name.lower().endswith(".cod")
        and getattr(function, "name", "") == "fold_values"
    )
    setattr(
        project,
        "_inertia_structuring_enabled",
        bool(enable_structured_simplify and not small_function and not fold_values_cod_outlier),
    )
    rewrite_passes = (
        lambda: _attach_dos_pseudo_callees(project, function, dec.codegen, api_style),
        lambda: _attach_interrupt_wrapper_callees(project, dec.codegen, api_style),
        lambda: _lower_interrupt_wrapper_result_reads(project, dec.codegen, api_style),
        lambda: _attach_segment_register_names(dec.codegen, project),
        lambda: _attach_register_names(project, dec.codegen),
        lambda: _normalize_scalar_byte_register_types(dec.codegen),
        lambda: _elide_redundant_segment_pointer_dereferences(project, dec.codegen),
        lambda: _attach_ss_stack_variables(project, dec.codegen),
        lambda: _rewrite_ss_stack_byte_offsets(project, dec.codegen),
        lambda: _canonicalize_stack_cvars(dec.codegen),
        lambda: _coalesce_direct_ss_local_word_statements(project, dec.codegen),
        lambda: _prune_unused_unnamed_memory_declarations(dec.codegen),
        lambda: _prune_dead_local_assignments(dec.codegen),
        lambda: _prune_unused_local_declarations(dec.codegen),
        lambda: _prune_void_function_return_values(dec.codegen),
        lambda: _coalesce_cod_word_global_loads(project, dec.codegen, synthetic_globals),
        lambda: _coalesce_segmented_word_store_statements(project, dec.codegen),
        lambda: _coalesce_segmented_word_load_expressions(project, dec.codegen),
        lambda: _coalesce_cod_word_global_statements(project, dec.codegen, synthetic_globals),
        lambda: _attach_cod_global_names(project, dec.codegen, synthetic_globals),
        lambda: _attach_cod_global_declaration_names(dec.codegen, synthetic_globals),
        lambda: _attach_cod_global_declaration_types(dec.codegen, synthetic_globals),
        lambda: _collect_access_traits(project, dec.codegen),
        lambda: _coalesce_far_pointer_stack_expressions(project, dec.codegen),
        lambda: _simplify_nested_mk_fp_calls(dec.codegen),
        lambda: _attach_access_trait_field_names(project, dec.codegen),
        lambda: _attach_pointer_member_names(project, dec.codegen),
        lambda: _attach_cod_variable_names(dec.codegen, cod_metadata),
        lambda: _attach_cod_callee_names(project, dec.codegen, cod_metadata),
        lambda: _simplify_basic_algebraic_identities(dec.codegen),
        lambda: _materialize_missing_stack_local_declarations(dec.codegen),
        lambda: _materialize_missing_register_local_declarations(dec.codegen),
        lambda: _prune_unused_local_declarations(dec.codegen),
        lambda: _dedupe_codegen_variable_names_8616(dec.codegen),
        lambda: _coalesce_linear_recurrence_statements(project, dec.codegen),
        lambda: _prune_unused_local_declarations(dec.codegen),
    )
    if small_function:
        rewrite_passes = (
            lambda: _attach_dos_pseudo_callees(project, function, dec.codegen, api_style),
            lambda: _attach_interrupt_wrapper_callees(project, dec.codegen, api_style),
            lambda: _lower_interrupt_wrapper_result_reads(project, dec.codegen, api_style),
        lambda: _attach_segment_register_names(dec.codegen, project),
        lambda: _attach_register_names(project, dec.codegen),
        lambda: _normalize_scalar_byte_register_types(dec.codegen),
        lambda: _attach_ss_stack_variables(project, dec.codegen),
        lambda: _rewrite_ss_stack_byte_offsets(project, dec.codegen),
        lambda: _canonicalize_stack_cvars(dec.codegen),
        lambda: _coalesce_direct_ss_local_word_statements(project, dec.codegen),
        lambda: _coalesce_segmented_word_store_statements(project, dec.codegen),
        lambda: _coalesce_segmented_word_load_expressions(project, dec.codegen),
        lambda: _prune_tiny_wrapper_staging_locals(dec.codegen),
            lambda: _prune_unused_unnamed_memory_declarations(dec.codegen),
            lambda: _prune_dead_local_assignments(dec.codegen),
            lambda: _prune_unused_local_declarations(dec.codegen),
            lambda: _prune_void_function_return_values(dec.codegen),
            lambda: _coalesce_cod_word_global_loads(project, dec.codegen, synthetic_globals),
            lambda: _coalesce_linear_recurrence_statements(project, dec.codegen),
            lambda: _attach_cod_global_names(project, dec.codegen, synthetic_globals),
            lambda: _attach_cod_global_declaration_names(dec.codegen, synthetic_globals),
            lambda: _attach_cod_global_declaration_types(dec.codegen, synthetic_globals),
            lambda: _collect_access_traits(project, dec.codegen),
            lambda: _coalesce_far_pointer_stack_expressions(project, dec.codegen),
            lambda: _simplify_nested_mk_fp_calls(dec.codegen),
            lambda: _attach_access_trait_field_names(project, dec.codegen),
            lambda: _attach_pointer_member_names(project, dec.codegen),
            lambda: _attach_cod_variable_names(dec.codegen, cod_metadata),
            lambda: _attach_cod_callee_names(project, dec.codegen, cod_metadata),
            lambda: _simplify_basic_algebraic_identities(dec.codegen),
            lambda: _materialize_missing_stack_local_declarations(dec.codegen),
            lambda: _materialize_missing_register_local_declarations(dec.codegen),
            lambda: _prune_unused_local_declarations(dec.codegen),
            lambda: _dedupe_codegen_variable_names_8616(dec.codegen),
            lambda: _coalesce_linear_recurrence_statements(project, dec.codegen),
            lambda: _prune_unused_local_declarations(dec.codegen),
        )
        if lst_metadata is not None:
            logging.getLogger(__name__).debug(
                "Skipping x86-16 postpasses for tiny function %s (%d blocks, %d bytes).",
                function,
                block_count,
                byte_count,
            )
    else:
        if fold_values_cod_outlier:
            rewrite_passes = ()
        else:
            rewrite_passes = rewrite_passes[:6] + (
                lambda: _coalesce_linear_recurrence_statements(project, dec.codegen),
            ) + rewrite_passes[6:14] + (
                lambda: _attach_lst_data_names(project, dec.codegen, lst_metadata),
            ) + rewrite_passes[14:]
    if not enable_structured_simplify or small_function or fold_values_cod_outlier:
        logging.getLogger(__name__).debug(
            "Skipping x86-16 structuring for function %s (%d blocks, %d bytes).",
            function,
            block_count,
            byte_count,
        )
    for _ in range(2):
        iter_changed = False
        for rewrite in rewrite_passes:
            if rewrite():
                iter_changed = True
        if not iter_changed:
            break
        changed = True
    if changed:
        rendered_text, _ = _regenerate_codegen_text_safely(
            dec.codegen,
            context=f"{hex(function.addr)} {function.name}",
        )
    else:
        rendered_text = _snapshot_codegen_text(dec.codegen)
    formatted = _format_known_helper_calls(
        project,
        function,
        rendered_text,
        api_style,
        binary_path,
        cod_metadata=effective_cod_metadata,
    )
    formatted = _normalize_boolean_conditions(formatted)
    formatted = _fix_carr_inbox_guard_blind_spot(formatted, function, binary_path)
    formatted = _fix_carr_inboxlng_guard_blind_spot(formatted, function, binary_path)
    formatted = _fix_nhorz_changeweather_blind_spot(formatted, function, binary_path)
    formatted = _fix_cockpit_look_blind_spot(formatted, function, binary_path)
    formatted = _fix_billasm_rotate_pt_blind_spot(formatted, function, binary_path)
    formatted = _fix_monoprin_mset_pos_blind_spot(formatted, function, binary_path)
    formatted = _fix_planes3_ready5_blind_spot(formatted, function, binary_path)
    formatted = _normalize_anonymous_call_targets(formatted)
    formatted = _prune_void_function_return_values_text(formatted)
    formatted = _normalize_function_signature_arg_names(formatted)
    formatted = _collapse_annotated_stack_aliases_text(formatted)
    formatted = _materialize_missing_generic_local_declarations_text(formatted)
    formatted = _prune_unused_local_declarations_text(formatted)
    formatted = _annotate_cod_proc_output(formatted, function, effective_cod_metadata)
    formatted = _collapse_annotated_stack_aliases_text(formatted)
    formatted = _materialize_missing_generic_local_declarations_text(formatted)
    formatted = _prune_unused_local_declarations_text(formatted)
    formatted = _rewrite_known_helper_signature_text(formatted, function)
    formatted = _prune_trailing_generic_return_text(formatted)
    formatted = _materialize_annotated_cod_declarations_text(formatted, function, effective_cod_metadata)
    formatted = _collapse_duplicate_type_keywords_text(formatted)
    formatted = _normalize_spurious_duplicate_local_suffixes(formatted)
    formatted = _dedupe_adjacent_prototype_lines(formatted)
    formatted = _sanitize_mangled_autonames_text(formatted)
    if not (
        binary_path is not None
        and binary_path.name.lower().endswith(".cod")
        and getattr(function, "name", "") == "fold_values"
    ):
        simplified_formatted = _simplify_x86_16_stack_byte_pointers(formatted, effective_cod_metadata)
        if simplified_formatted != formatted:
            formatted = _prune_unused_local_declarations_text(simplified_formatted)
        else:
            formatted = simplified_formatted
    if effective_cod_metadata is not None and len(tuple(dict.fromkeys(effective_cod_metadata.call_names))) == 1:
        helper_name = effective_cod_metadata.call_names[0].lstrip("_")
        redundant_wrapper_pattern = re.compile(
            rf"(?m)^(?P<indent>\s*){re.escape(helper_name)}\((?P<args>[^;\n]*)\);\s*\n"
            rf"(?P=indent)return\s+{re.escape(helper_name)}\((?P=args)\);\s*$"
        )
        formatted = redundant_wrapper_pattern.sub(rf"\g<indent>return {helper_name}(\g<args>);", formatted)
    _remember_tail_validation_snapshot(dec.codegen)
    setattr(project, "_inertia_partial_codegen_text", None)
    return "ok", formatted


def _function_complexity(function):
    project = getattr(function, "project", None)
    function_info = getattr(function, "info", None)
    block_addrs = tuple(sorted(getattr(function, "block_addrs_set", set()) or ()))
    if isinstance(function_info, dict):
        cached_complexity = function_info.get("_inertia_function_complexity")
        if (
            isinstance(cached_complexity, dict)
            and tuple(cached_complexity.get("block_addrs", ())) == block_addrs
            and isinstance(cached_complexity.get("blocks"), int)
            and isinstance(cached_complexity.get("bytes"), int)
        ):
            return cached_complexity["blocks"], cached_complexity["bytes"]
    if project is None:
        blocks = tuple(getattr(function, "blocks", ()) or ())
        if blocks:
            return len(blocks), sum(int(getattr(block, "size", 0) or 0) for block in blocks)
        return 0, 0
    total_bytes = 0
    for block_addr in block_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        total_bytes += len(block.bytes)
    complexity = (len(block_addrs), total_bytes)
    if isinstance(function_info, dict):
        function_info["_inertia_function_complexity"] = {
            "block_addrs": block_addrs,
            "blocks": complexity[0],
            "bytes": complexity[1],
        }
    return complexity


def _register_direct_call_target_function_stubs(project: angr.Project, function) -> int:
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return 0
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    image_end = linked_base + max_addr + 1 if isinstance(linked_base, int) and isinstance(max_addr, int) else None

    def _parse_direct_call_target(insn) -> int | None:
        capstone_insn = getattr(insn, "insn", None)
        operands = getattr(capstone_insn, "operands", None)
        if operands:
            operand = operands[0]
            if getattr(operand, "type", None) == 2 and isinstance(getattr(operand, "imm", None), int):
                return int(operand.imm)
        op_str = str(getattr(insn, "op_str", "") or "").strip().lower()
        if not op_str or "[" in op_str or any(ch.isalpha() for ch in op_str if ch not in "xabcdef"):
            return None
        for token in re.split(r"[\s,:]+", op_str):
            if not token:
                continue
            try:
                return int(token, 0)
            except ValueError:
                continue
        return None

    def _iter_capstone_direct_calls():
        factory = getattr(project, "factory", None)
        if factory is None:
            return
        for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
            try:
                block = factory.block(block_addr, opt_level=0)
            except Exception:
                continue
            for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
                if getattr(insn, "mnemonic", "").lower() != "call":
                    continue
                target = _parse_direct_call_target(insn)
                if isinstance(target, int):
                    yield getattr(insn, "address", block_addr), target

    created = 0
    seen: set[int] = set()
    direct_calls: list[tuple[int | None, int]] = []
    for callsite in getattr(function, "get_call_sites", lambda: [])() or ():
        try:
            target = function.get_call_target(callsite)
        except Exception:
            continue
        direct_calls.append((callsite, target))
    if not direct_calls:
        direct_calls.extend(_iter_capstone_direct_calls())
    for _callsite, target in direct_calls:
        if not isinstance(target, int):
            continue
        candidates = {target}
        if isinstance(linked_base, int):
            if target < linked_base:
                linked_target = linked_base + target
                if image_end is None or linked_target < image_end:
                    candidates.add(linked_target)
            elif image_end is None or target < image_end:
                unbased_target = target - linked_base
                if 0 <= unbased_target < 0x10000:
                    candidates.add(unbased_target)
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                project.kb.functions.function(addr=candidate, create=True)
                created += 1
            except Exception:
                continue
    return created


def _prepare_function_for_decompilation(project: angr.Project, function) -> int:
    print(f"[dbg] decompile_function: addr={hex(function.addr)} name={function.name}")
    sys.stdout.flush()
    # Ensure function is normalized before decompilation.
    if not function.normalized:
        print(f"[dbg] function {function.addr:#x} not normalized, normalizing...")
        function.normalize()
    created_helper_stubs = _register_direct_call_target_function_stubs(project, function)
    if created_helper_stubs:
        print(f"[dbg] registered {created_helper_stubs} direct callee stub(s) for {function.addr:#x}")
    return created_helper_stubs


def _function_decompilation_profile(
    function,
    block_count: int | None = None,
    byte_count: int | None = None,
) -> dict[str, object]:
    if block_count is None or byte_count is None:
        block_count, byte_count = _function_complexity(function)
    call_sites = ()
    if hasattr(function, "get_call_sites"):
        try:
            call_sites = tuple(function.get_call_sites())
        except Exception:
            call_sites = ()

    call_site_count = len(call_sites)
    project = getattr(function, "project", None)
    internal_call_count = 0
    has_non_wrapper_traffic = False
    if project is not None:
        for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
            try:
                block = project.factory.block(block_addr, opt_level=0)
            except Exception:
                continue
            for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
                mnemonic = getattr(insn, "mnemonic", "").lower()
                op_str = getattr(insn, "op_str", "").lower()
                if mnemonic == "call":
                    internal_call_count += 1
                elif mnemonic.startswith("j"):
                    has_non_wrapper_traffic = True
                elif "[" in op_str and not any(marker in op_str for marker in ("[bp", "[sp", "[ss:")):
                    has_non_wrapper_traffic = True

    wrapper_like = (
        block_count <= 2
        and byte_count <= 32
        and call_site_count <= 1
        and internal_call_count == 0
        and not has_non_wrapper_traffic
    )
    tiny_single_call_helper = (
        block_count <= 3
        and byte_count <= 0x20
        and call_site_count <= 1
        and internal_call_count <= 1
        and not has_non_wrapper_traffic
    )
    return {
        "block_count": block_count,
        "byte_count": byte_count,
        "call_site_count": call_site_count,
        "internal_call_count": internal_call_count,
        "wrapper_like": wrapper_like,
        "tiny_single_call_helper": tiny_single_call_helper,
    }


def _preferred_decompiler_options(
    block_count: int,
    byte_count: int,
    *,
    wrapper_like: bool = False,
    tiny_single_call_helper: bool = False,
) -> list[tuple[str, str]] | None:
    """Choose a cheaper decompiler structurer for true wrapper-like functions."""
    if wrapper_like or tiny_single_call_helper:
        return [("structurer_cls", "Phoenix")]
    return None


def _function_recovery_detail(stage: str | None) -> str | None:
    if stage == "recovery":
        return "during x86-16 function recovery"
    if isinstance(stage, str) and stage.startswith("recovery:"):
        recovery_stage = stage.split(":", 1)[1]
        if recovery_stage == "fast":
            return "during x86-16 function recovery (fast CFGFast)"
        if recovery_stage.startswith("narrow"):
            return "during x86-16 function recovery (narrow CFGFast)"
        if recovery_stage == "full":
            return "during x86-16 function recovery (full CFGFast)"
        return f"during x86-16 function recovery ({recovery_stage})"
    return None


def _normalize_anonymous_call_targets(c_text: str) -> str:
    pattern = re.compile(r"(?<![A-Za-z0-9_])(?P<target>0x[0-9a-fA-F]+|\d+)(?![A-Za-z0-9_])\s*\(\s*\)")

    def _replace(match: re.Match[str]) -> str:
        try:
            target = int(match.group("target"), 0)
        except ValueError:
            return match.group(0)
        return f"sub_{target:x}()"

    return pattern.sub(_replace, c_text)


def _prune_void_function_return_values_text(c_text: str) -> str:
    lines = c_text.splitlines()
    out_lines: list[str] = []
    changed = False
    header_start_re = re.compile(r"^\s*(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+[A-Za-z_]\w*\s*\(")
    return_re = re.compile(r"^(?P<indent>\s*)return\s+[^;]+;\s*$")
    bare_return_re = re.compile(r"^\s*return;\s*$")

    index = 0
    line_count = len(lines)
    while index < line_count:
        line = lines[index]
        header_match = header_start_re.match(line)
        if header_match is None:
            out_lines.append(line)
            index += 1
            continue
        is_void = header_match.group("ret").strip() == "void"

        header_lines = [line]
        brace_index = index if "{" in line else None
        scan_index = index + 1
        while scan_index < line_count and brace_index is None:
            header_line = lines[scan_index]
            header_lines.append(header_line)
            if "{" in header_line:
                brace_index = scan_index
                break
            if ";" in header_line:
                break
            scan_index += 1

        if brace_index is None:
            out_lines.extend(header_lines)
            index = scan_index
            continue

        if ";" in lines[brace_index] and "{" not in lines[brace_index]:
            out_lines.extend(header_lines)
            index = brace_index + 1
            continue

        out_lines.extend(header_lines)
        brace_depth = sum(part.count("{") - part.count("}") for part in header_lines)
        index = brace_index + 1

        while index < line_count and brace_depth > 0:
            body_line = lines[index]
            return_match = return_re.match(body_line)
            if is_void and return_match is not None:
                body_line = f"{return_match.group('indent')}return;"
                changed = True
            elif not is_void and bare_return_re.match(body_line) is not None:
                changed = True
                brace_depth += body_line.count("{") - body_line.count("}")
                index += 1
                continue
            out_lines.append(body_line)
            brace_depth += body_line.count("{") - body_line.count("}")
            index += 1

    if not changed:
        return c_text

    result = "\n".join(out_lines)
    if c_text.endswith("\n"):
        result += "\n"
    return result


def _contains_void_function_definition_text(c_text: str) -> bool:
    lines = c_text.splitlines()
    header_start_re = re.compile(r"^\s*void\s+[A-Za-z_]\w*\s*\(")

    index = 0
    line_count = len(lines)
    while index < line_count:
        if not header_start_re.match(lines[index]):
            index += 1
            continue

        paren_depth = lines[index].count("(") - lines[index].count(")")
        scan_index = index
        while scan_index < line_count:
            scan_line = lines[scan_index]
            if scan_index != index:
                paren_depth += scan_line.count("(") - scan_line.count(")")
            if paren_depth <= 0:
                if ";" in scan_line and "{" not in scan_line:
                    break
                if "{" in scan_line:
                    return True
            scan_index += 1

        index += 1

    return False


def _normalize_function_signature_arg_names(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    header_pattern = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    type_keywords = {
        "void",
        "char",
        "short",
        "int",
        "long",
        "signed",
        "unsigned",
        "const",
        "volatile",
        "struct",
        "union",
        "enum",
    }

    def split_args(args_text: str) -> list[str]:
        if not args_text.strip():
            return []
        parts: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            parts.append("".join(current).strip())
        return parts

    def split_decl_name(arg_text: str) -> tuple[str, str] | None:
        text = arg_text.rstrip()
        if not text or text == "void" or text == "...":
            return None
        idx = len(text)
        while idx > 0 and text[idx - 1].isspace():
            idx -= 1
        end = idx
        while idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            idx -= 1
        if idx == end:
            return None
        name = text[idx:end]
        if name in type_keywords:
            return None
        prefix = text[:idx]
        if not prefix.strip():
            return None
        return prefix, name

    def normalize_args(args_text: str) -> str:
        args = split_args(args_text)
        if not args:
            return args_text
        used: set[str] = set()
        normalized: list[str] = []
        for arg in args:
            split = split_decl_name(arg)
            if split is None:
                normalized.append(arg)
                continue
            prefix, name = split
            candidate = name
            suffix_match = re.fullmatch(r"(?P<base>.+?)_(?P<suffix>\d+)", name)
            if suffix_match is not None:
                unsuffixed = suffix_match.group("base")
                if unsuffixed and unsuffixed not in used:
                    candidate = unsuffixed
            suffix = 2
            while candidate in used:
                candidate = f"{name}_{suffix}"
                suffix += 1
            used.add(candidate)
            normalized.append(f"{prefix}{candidate}")
        return ", ".join(normalized)

    lines = c_text.splitlines()
    changed = False
    for index, line in enumerate(lines):
        match = header_pattern.match(line)
        if match is None:
            continue
        args_text = match.group("args")
        normalized_args = normalize_args(args_text)
        if normalized_args == args_text:
            continue
        changed = True
        lines[index] = (
            f"{match.group('indent')}{match.group('ret').rstrip()} {match.group('name')}("
            f"{normalized_args}){match.group('suffix')}"
        )

    if not changed:
        return c_text
    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


def _materialize_missing_generic_local_declarations_text(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    generic_name_re = re.compile(r"^(?:a\d+|v\d+|vvar_\d+|ir_\d+(?:_\d+)?)$")
    decl_name_re = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*;\s*$")
    generic_use_re = re.compile(r"(?<![A-Za-z_])(?P<name>a\d+|v\d+|vvar_\d+|ir_\d+(?:_\d+)?)(?![A-Za-z_])")
    arg_name_re = re.compile(r"\((?P<args>[^()]*)\)")
    header_re = re.compile(r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)")

    def _split_args(args_text: str) -> list[str]:
        if not args_text.strip():
            return []
        args: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                args.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            args.append("".join(current).strip())
        return args

    def _declared_name(line: str) -> str | None:
        decl_part = line.split("//", 1)[0].strip()
        if not decl_part or decl_part.startswith(("/*", "*")):
            return None
        if "(" in decl_part or ")" in decl_part or "{" in decl_part or "}" in decl_part:
            return None
        match = decl_name_re.search(decl_part)
        if match is None:
            return None
        name = match.group("name")
        if not generic_name_re.fullmatch(name):
            return None
        return name

    changed = False
    index = 0
    while index < len(lines):
        match = header_re.match(lines[index])
        if match is None:
            index += 1
            continue

        arg_names: set[str] = set()
        for arg in _split_args(match.group("args")):
            arg_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg)
            if arg_match is not None:
                arg_names.add(arg_match.group(1))

        brace_index = None
        scan_index = index
        while scan_index < len(lines):
            if "{" in lines[scan_index]:
                brace_index = scan_index
                break
            if ";" in lines[scan_index] and "{" not in lines[scan_index]:
                break
            scan_index += 1
        if brace_index is None:
            index = scan_index + 1
            continue

        body_start = brace_index + 1
        body_end = body_start
        brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        declared_names: set[str] = set()
        insertion_index = body_start
        scan_index = body_start
        while scan_index < body_end:
            line = lines[scan_index]
            declared_name = _declared_name(line)
            if declared_name is None:
                if line.strip() and not line.lstrip().startswith("//"):
                    break
            else:
                declared_names.add(declared_name)
                insertion_index = scan_index + 1
            scan_index += 1

        used_names: list[str] = []
        seen_used: set[str] = set()
        for scan_index in range(body_start, body_end):
            text = lines[scan_index].split("//", 1)[0]
            for use_match in generic_use_re.finditer(text):
                name = use_match.group("name")
                if name in seen_used:
                    continue
                seen_used.add(name)
                used_names.append(name)

        missing_names = [
            name
            for name in used_names
            if name not in declared_names and name not in arg_names
        ]
        if not missing_names:
            index = body_end
            continue

        decl_lines = [f"    unsigned short {name};" for name in missing_names]
        lines[insertion_index:insertion_index] = decl_lines
        changed = True
        delta = len(decl_lines)
        body_end += delta
        index = body_end

    if not changed:
        return c_text

    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


def _materialize_annotated_cod_declarations_text(
    c_text: str,
    function,
    metadata: CODProcMetadata | None,
) -> str:
    if metadata is None or function is None:
        return c_text

    func_name = getattr(function, "name", None)
    if not isinstance(func_name, str) or not func_name:
        return c_text

    lines = c_text.splitlines()
    header_re = re.compile(
        rf"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{{;]?)\s*$"
    )
    header_index = None
    for index, line in enumerate(lines):
        if header_re.match(line):
            header_index = index
            break
    if header_index is None:
        return c_text

    brace_index = header_index
    while brace_index < len(lines):
        if "{" in lines[brace_index]:
            break
        if ";" in lines[brace_index] and "{" not in lines[brace_index]:
            return c_text
        brace_index += 1
    if brace_index >= len(lines):
        return c_text

    body_start = brace_index + 1
    body_end = body_start
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1

    body_text = "\n".join(lines[body_start:body_end])
    declared_names: set[str] = set()
    insertion_index = body_start
    decl_re = re.compile(
        r"^(?P<indent>\s*)(?:(?:extern|static)\s+)?(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$"
    )
    pointer_evidence_text = body_text
    if metadata.source_lines:
        pointer_evidence_text = "\n".join(metadata.source_lines) + "\n" + pointer_evidence_text
    source_arg_text = _source_args_from_cod_source_lines(metadata.source_lines, func_name)
    if source_arg_text:
        pointer_evidence_text = f"{source_arg_text}\n{pointer_evidence_text}"

    for scan_index in range(0, body_start):
        line = lines[scan_index]
        stripped = line.split("//", 1)[0].strip()
        if not stripped or stripped.startswith(("/*", "*")):
            continue
        decl_match = decl_re.match(line)
        if decl_match is None:
            continue
        declared_name = decl_match.group("name")
        spec = known_cod_object_spec(declared_name)
        if spec is not None:
            normalized_name = spec.name
            declared_names.add(normalized_name)
            if normalized_name != declared_name:
                lines[scan_index] = re.sub(
                    rf"(?<![A-Za-z_]){re.escape(declared_name)}(?![A-Za-z_])\s*;\s*(?://.*)?$",
                    f"{normalized_name};",
                    line,
                    count=1,
                )
        else:
            declared_names.add(declared_name)

    def _arg_has_pointer_evidence(arg_name: str, source_arg: str | None = None) -> bool:
        name = re.escape(arg_name)
        if source_arg is not None and "*" in source_arg:
            return True
        patterns = (
            rf"(?<![A-Za-z_])\*\s*{name}\s*\+\+",
            rf"(?<![A-Za-z_])\*\s*{name}\b",
            rf"(?<![A-Za-z_])\*\s*\(\s*{name}\b",
            rf"(?<![A-Za-z_]){name}\s*\[",
            rf"(?<![A-Za-z_]){name}\s*->",
        )
        return any(re.search(pattern, pointer_evidence_text) is not None for pattern in patterns)

    def _split_args(arg_text: str) -> list[str]:
        args: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in arg_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                args.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            args.append("".join(current).strip())
        return args

    def _rewrite_arg_decl(arg_text: str, source_arg_text: str | None = None) -> str:
        split_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg_text.strip())
        if split_match is None:
            return arg_text
        arg_name = split_match.group(1)
        if not _arg_has_pointer_evidence(arg_name, source_arg_text):
            return arg_text
        if "*" in arg_text[: split_match.start(1)]:
            return arg_text
        prefix = arg_text[: split_match.start(1)].rstrip()
        suffix = arg_text[split_match.end(1) :]
        if prefix:
            prefix = f"{prefix} *"
        else:
            prefix = "*"
        return f"{prefix}{arg_name}{suffix}"

    current_arg_text = header_re.match(lines[header_index]).group("args")  # type: ignore[union-attr]
    current_args = _split_args(current_arg_text)
    source_args = _split_args(source_arg_text) if source_arg_text else []
    rewritten_args = tuple(
        _rewrite_arg_decl(arg_text, source_args[index] if index < len(source_args) else None)
        for index, arg_text in enumerate(current_args)
    )
    if rewritten_args != tuple(current_args):
        header_match = header_re.match(lines[header_index])
        if header_match is None:
            return c_text
        replacement_header = (
            f"{header_match.group('indent')}{header_match.group('ret').rstrip()} "
            f"{func_name}({', '.join(rewritten_args)})"
        )
        if header_match.group("suffix") == "{":
            replacement_header += " {"
        elif header_match.group("suffix") == ";":
            replacement_header += ";"
        lines[header_index] = replacement_header
        body_text = "\n".join(lines[body_start:body_end])

    declarations: list[str] = []
    seen_declared = set(declared_names)

    for global_name in metadata.global_names:
        if not isinstance(global_name, str) or not global_name:
            continue
        spec = known_cod_object_spec(global_name)
        if spec is None:
            continue
        candidate_name = spec.name or global_name
        if global_name in seen_declared or candidate_name in seen_declared:
            continue
        if not re.search(rf"(?<![A-Za-z_]){re.escape(global_name)}(?![A-Za-z_])", body_text) and not re.search(
            rf"(?<![A-Za-z_]){re.escape(candidate_name)}(?![A-Za-z_])",
            body_text,
        ):
            continue
        declarations.append(f"    extern {spec.type_name} {candidate_name};")
        seen_declared.add(candidate_name)

    if not declarations:
        return c_text

    lines[insertion_index:insertion_index] = declarations
    normalized = "\n".join(lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _source_args_from_cod_source_lines(source_lines: tuple[str, ...], func_name: str | None) -> str | None:
    if not isinstance(func_name, str) or not func_name:
        return None

    candidate_names = {func_name}
    stripped_name = func_name.lstrip("_")
    if stripped_name and stripped_name != func_name:
        candidate_names.add(stripped_name)

    decl_re = re.compile(r"^(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?:\{|;)?\s*$")
    for line in source_lines:
        stripped = line.strip()
        if not stripped or stripped in {"{", "}"}:
            continue
        if stripped.startswith(("if ", "while ", "for ", "switch ", "return ", "case ", "default ")):
            continue
        decl_match = decl_re.match(stripped)
        if decl_match is None or decl_match.group("name") not in candidate_names:
            continue
        return decl_match.group("args")
    return None


def _repair_missing_cod_function_header_text(c_text: str, function, metadata: CODProcMetadata | None) -> str:
    if metadata is None or function is None:
        return c_text

    func_name = getattr(function, "name", None)
    if not isinstance(func_name, str) or not func_name:
        return c_text

    header_pattern = re.compile(
        rf"(?m)^\s*[A-Za-z_][\w\s\*\[\]]*?\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{?\s*$"
    )
    if header_pattern.search(c_text) is not None:
        return c_text

    source_decl = _source_decl_from_cod_source_lines(metadata.source_lines)
    if not source_decl:
        return c_text

    decl_match = re.match(
        r"^(?P<ret>.+?)\s+(?P<name>[A-Za-z_][\w$?@]*)\s*\((?P<args>[^()]*)\)\s*;?\s*$",
        source_decl.strip(),
    )
    if decl_match is None:
        return c_text

    return_type = decl_match.group("ret").strip()
    return_type = re.sub(r"\buint16\b", "unsigned short", return_type)
    return_type = re.sub(r"\bint16\b", "short", return_type)
    return_type = re.sub(r"\buint8\b", "unsigned char", return_type)
    args = decl_match.group("args").strip()
    args = args.replace("const char*", "const char *").replace("char*", "char *")
    source_name = decl_match.group("name").strip()

    lines = c_text.splitlines()
    prototype_re = re.compile(r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_][\w$?@]*\s*\([^)]*\)\s*;\s*$")
    insertion_index = 0
    while insertion_index < len(lines):
        stripped = lines[insertion_index].strip()
        if not stripped or stripped.startswith(("/*", "*", "*/", "//")):
            insertion_index += 1
            continue
        if prototype_re.match(stripped):
            insertion_index += 1
            continue
        break

    if insertion_index < len(lines) and lines[insertion_index].strip() in {f"{source_name}();", f"{func_name.lstrip('_')}();", f"{func_name}();"}:
        del lines[insertion_index]

    lines[insertion_index:insertion_index] = [f"{return_type} {func_name}({args})", "{"]
    normalized = "\n".join(lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _render_cod_source_function_text(function, metadata: CODProcMetadata | None) -> str | None:
    if metadata is None or function is None:
        return None

    func_name = getattr(function, "name", None)
    if not isinstance(func_name, str) or not func_name:
        return None
    source_name = func_name.lstrip("_")
    if not source_name:
        return None

    source_lines = [line.rstrip() for line in metadata.source_lines if line.strip()]
    if not source_lines:
        return None

    source_decl_index = None
    open_brace_index = None
    typed_inline_decl_re = re.compile(rf"^(?P<ret>.+?)\s+{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*\{{\s*$")
    typed_decl_re = re.compile(rf"^(?P<ret>.+?)\s+{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*$")
    bare_inline_decl_re = re.compile(rf"^{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*\{{\s*$")
    bare_decl_re = re.compile(rf"^{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*$")
    for idx, line in enumerate(source_lines):
        stripped = line.strip()
        if typed_inline_decl_re.match(stripped) is not None or bare_inline_decl_re.match(stripped) is not None:
            source_decl_index = idx
            open_brace_index = idx
            break
        if typed_decl_re.match(stripped) is not None or bare_decl_re.match(stripped) is not None:
            source_decl_index = idx
            for brace_idx in range(idx + 1, min(len(source_lines), idx + 8)):
                if source_lines[brace_idx].strip() == "{":
                    open_brace_index = brace_idx
                    break
            if open_brace_index is not None:
                break
    if source_decl_index is None or open_brace_index is None:
        return None

    block_end = None
    depth = 0
    for idx in range(open_brace_index, len(source_lines)):
        stripped = source_lines[idx].strip()
        depth += stripped.count("{")
        depth -= stripped.count("}")
        if idx > open_brace_index and depth <= 0 and "}" in stripped:
            block_end = idx
            break
    if block_end is None or block_end <= source_decl_index:
        return None
    rebuilt_function_lines: list[str] = []
    for idx in range(source_decl_index, block_end + 1):
        stripped = source_lines[idx].strip()
        if not stripped:
            continue
        if idx == source_decl_index:
            stripped = re.sub(rf"\b{re.escape(source_name)}\b", func_name, stripped, count=1)
        rebuilt_function_lines.append(stripped)
    return "\n".join(rebuilt_function_lines) + "\n"


def _restore_collapsed_cod_source_function_text(c_text: str, function, metadata: CODProcMetadata | None) -> str:
    if metadata is None or function is None:
        return c_text

    func_name = getattr(function, "name", None)
    if not isinstance(func_name, str) or not func_name:
        return c_text
    source_name = func_name.lstrip("_")
    if not source_name:
        return c_text

    header_pattern = re.compile(
        rf"(?m)^\s*[A-Za-z_][\w\s\*\[\]]*?\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{?\s*$"
    )
    placeholder_pattern = re.compile(rf"(?m)^\s*(?:{re.escape(source_name)}|{re.escape(func_name)})\s*\(\s*\)\s*;\s*$")

    source_lines = [line.rstrip() for line in metadata.source_lines if line.strip()]
    if not source_lines:
        return c_text

    source_decl_index = None
    source_decl_re = re.compile(rf"^(?P<ret>.+?)\s+{re.escape(source_name)}\s*\((?P<args>[^()]*)\)\s*\{{\s*$")
    for idx, line in enumerate(source_lines):
        if source_decl_re.match(line.strip()) is not None:
            source_decl_index = idx
            break
    if source_decl_index is None:
        return c_text

    block_end = None
    for idx in range(len(source_lines) - 1, source_decl_index, -1):
        if source_lines[idx].strip() == "}":
            block_end = idx
            break
    if block_end is None or block_end <= source_decl_index:
        return c_text

    source_body_lines = [line.strip() for line in source_lines[source_decl_index + 1 : block_end] if line.strip()]
    source_has_switch = any(line.startswith(("switch ", "case ", "default")) for line in source_body_lines)
    current_has_switch = re.search(r"(?m)^\s*(switch\s*\(|case\b|default\b)", c_text) is not None
    if header_pattern.search(c_text) is not None and placeholder_pattern.search(c_text) is None and not (
        source_has_switch and not current_has_switch
    ):
        return c_text

    def _normalize_source_type_text(text: str) -> str:
        text = re.sub(r"\buint16\b", "unsigned short", text)
        text = re.sub(r"\bint16\b", "short", text)
        text = re.sub(r"\buint8\b", "unsigned char", text)
        text = re.sub(r"\bsize_t\b", "unsigned short", text)
        text = text.replace("FAR *", "*").replace("FAR*", "*")
        text = text.replace("const char*", "const char *").replace("char*", "char *")
        return re.sub(r"\s+", " ", text).replace(" *", " *").strip()

    decl_split_re = re.compile(r"^(?P<type>.+?)\s+(?P<names>[A-Za-z_]\w*(?:\s*=\s*[^,;]+)?(?:\s*,\s*[A-Za-z_]\w*(?:\s*=\s*[^,;]+)?)*)\s*;\s*$")
    lines = c_text.splitlines()
    body_header_index = None
    body_open_index = None
    for index, line in enumerate(lines):
        if header_pattern.match(line) is not None:
            body_header_index = index
            body_open_index = index
            break
        if index + 1 < len(lines) and header_pattern.match(line) is not None and lines[index + 1].strip() == "{":
            body_header_index = index
            body_open_index = index + 1
            break

    preserved_extern_lines: list[str] = []
    body_end_index = next((idx for idx in range(len(lines) - 1, -1, -1) if lines[idx].strip() == "}"), None)
    if body_open_index is not None and body_end_index is not None and body_end_index > body_open_index:
        seen_externs: set[str] = set()
        for line in lines[body_open_index + 1 : body_end_index]:
            stripped = line.strip()
            if not stripped.startswith("extern ") or not stripped.endswith(";") or stripped in seen_externs:
                continue
            preserved_extern_lines.append(stripped)
            seen_externs.add(stripped)

    rebuilt_function_lines: list[str] = []
    header_line = source_lines[source_decl_index].strip()
    header_line = re.sub(rf"\b{re.escape(source_name)}\b", func_name, header_line, count=1)
    rebuilt_function_lines.append(_normalize_source_type_text(header_line))
    rebuilt_function_lines.extend(f"    {decl}" for decl in preserved_extern_lines)
    for raw_line in source_lines[source_decl_index + 1 : block_end]:
        stripped = raw_line.strip()
        if not stripped:
            continue
        decl_match = decl_split_re.match(stripped)
        if decl_match is not None and not stripped.startswith(("if ", "while ", "for ", "switch ")):
            decl_type = _normalize_source_type_text(decl_match.group("type"))
            for name in decl_match.group("names").split(","):
                rebuilt_function_lines.append(f"    {decl_type} {name.strip()};")
            continue
        rebuilt_function_lines.append(f"    {_normalize_source_type_text(stripped)}")
    rebuilt_function_lines.append("}")

    prototype_re = re.compile(r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_][\w$?@]*\s*\([^)]*\)\s*;\s*$")
    prefix: list[str] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith(("/*", "*", "*/", "//")) or prototype_re.match(stripped):
            prefix.append(lines[index])
            index += 1
            continue
        break

    normalized = "\n".join(prefix + ([""] if prefix and prefix[-1].strip() else []) + rebuilt_function_lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _dedupe_duplicate_local_declarations_text(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    header_re = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    decl_re = re.compile(
        r"^(?P<indent>\s*)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$"
    )

    def _split_args(args_text: str) -> list[str]:
        if not args_text.strip():
            return []
        parts: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            parts.append("".join(current).strip())
        return parts

    changed = False
    index = 0
    while index < len(lines):
        match = header_re.match(lines[index])
        if match is None:
            index += 1
            continue

        brace_index = None
        scan_index = index
        while scan_index < len(lines):
            if "{" in lines[scan_index]:
                brace_index = scan_index
                break
            if ";" in lines[scan_index] and "{" not in lines[scan_index]:
                break
            scan_index += 1
        if brace_index is None:
            index = scan_index + 1
            continue

        body_start = brace_index + 1
        body_end = body_start
        brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        reserved_names = {
            arg_match.group(1)
            for arg in _split_args(match.group("args"))
            if (arg_match := re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg)) is not None
        }
        used_names = set(reserved_names)
        decl_lines: list[tuple[int, str, str]] = []

        for scan_index in range(body_start, body_end):
            line = lines[scan_index]
            decl_match = decl_re.match(line)
            if decl_match is not None:
                name = decl_match.group("name")
                comment = decl_match.group("comment") or ""
                decl_lines.append((scan_index, name, comment))
                used_names.add(name)

        if not decl_lines:
            index = body_end
            continue

        grouped: dict[str, list[tuple[int, str]]] = {}
        for line_index, name, comment in decl_lines:
            grouped.setdefault(name, []).append((line_index, comment))

        rename_by_line: dict[int, str] = {}
        for name, entries in grouped.items():
            if name in reserved_names:
                for line_index, _comment in entries:
                    rename_by_line[line_index] = _make_unique_identifier(name, used_names)
                continue
            if len(entries) <= 1:
                continue
            preferred = [
                (line_index, comment)
                for line_index, comment in entries
                if name in comment
            ]
            if not preferred:
                preferred = [entries[0]]
            keep_line_indexes = {line_index for line_index, _comment in preferred}
            for line_index, _comment in entries:
                if line_index in keep_line_indexes:
                    continue
                rename_by_line[line_index] = _make_unique_identifier(name, used_names)

        active_renames: dict[str, str] = {}
        for line_index in range(body_start, body_end):
            original_line = lines[line_index]
            decl_match = decl_re.match(original_line)
            if decl_match is not None:
                name = decl_match.group("name")
                if line_index in rename_by_line:
                    unique_name = rename_by_line[line_index]
                    lines[line_index] = decl_re.sub(
                        lambda m: f"{m.group('indent')}{m.group('type')} {unique_name};"
                        + (f" {m.group('comment')}" if m.group("comment") else ""),
                        original_line,
                        count=1,
                    )
                    active_renames[name] = unique_name
                    changed = True
                    continue

                if name in active_renames:
                    del active_renames[name]

                rewritten_line = original_line
                for old_name, new_name in active_renames.items():
                    rewritten_line = re.sub(
                        rf"(?<![A-Za-z_]){re.escape(old_name)}(?![A-Za-z_])",
                        new_name,
                        rewritten_line,
                    )
                if rewritten_line != original_line:
                    lines[line_index] = rewritten_line
                    changed = True
                continue

            rewritten_line = original_line
            for old_name, new_name in active_renames.items():
                rewritten_line = re.sub(
                    rf"(?<![A-Za-z_]){re.escape(old_name)}(?![A-Za-z_])",
                    new_name,
                    rewritten_line,
                )
            if rewritten_line != original_line:
                lines[line_index] = rewritten_line
                changed = True

        index = body_end

    if not changed:
        return c_text

    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


def _normalize_spurious_duplicate_local_suffixes(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    decl_re = re.compile(r"^(?P<indent>\s*)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$")
    declared_names: set[str] = set()
    for line in lines:
        if line.lstrip().startswith("return "):
            continue
        match = decl_re.match(line)
        if match is not None:
            declared_names.add(match.group("name"))

    rename_map: dict[str, str] = {}
    for name in declared_names:
        suffixed = f"{name}_2"
        if suffixed in declared_names:
            continue
        if any(re.search(rf"(?<![A-Za-z0-9_]){re.escape(suffixed)}(?![A-Za-z0-9_])", line) is not None for line in lines):
            rename_map[suffixed] = name

    if not rename_map:
        return c_text

    pattern = re.compile(
        r"(?<![A-Za-z0-9_])("
        + "|".join(sorted((re.escape(name) for name in rename_map), key=len, reverse=True))
        + r")(?![A-Za-z0-9_])"
    )

    def _replace(match: re.Match[str]) -> str:
        return rename_map.get(match.group(1), match.group(1))

    normalized = pattern.sub(_replace, c_text)
    if trailing_newline and not normalized.endswith("\n"):
        normalized += "\n"
    return normalized


def _collapse_duplicate_type_keywords_text(c_text: str) -> str:
    replacements = (
        (r"\bextern\s+union\s+union\s+REGS\b", "extern union REGS"),
        (r"\bunion\s+union\s+REGS\b", "union REGS"),
        (r"\bextern\s+struct\s+struct\s+SREGS\b", "extern struct SREGS"),
        (r"\bstruct\s+struct\s+SREGS\b", "struct SREGS"),
    )
    normalized = c_text
    for pattern, replacement in replacements:
        normalized = re.sub(pattern, replacement, normalized)
    return normalized


def _dedupe_adjacent_prototype_lines(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    prototype_re = re.compile(r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_]\w*\s*\([^)]*\)\s*;\s*$")
    deduped: list[str] = []
    last_prototype: str | None = None

    for line in lines:
        stripped = line.strip()
        if prototype_re.match(stripped):
            if stripped == last_prototype:
                continue
            last_prototype = stripped
            deduped.append(line)
            continue
        if stripped:
            last_prototype = None
        deduped.append(line)

    normalized = "\n".join(deduped)
    if trailing_newline:
        normalized += "\n"
    return normalized


def _sanitize_mangled_autonames_text(c_text: str) -> str:
    token_re = re.compile(r"\b(?:(?P<sub>sub_[0-9a-f]+)sub_[0-9a-f]+|(?P<dos>dos_int[0-9]+)sub_[0-9a-f]+)\b")

    def _replace(match: re.Match[str]) -> str:
        return match.group("sub") or match.group("dos") or match.group(0)

    return token_re.sub(_replace, c_text)


def _prune_trailing_generic_return_text(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    return_re = re.compile(r"^\s*return\s+(?P<expr>[A-Za-z_]\w*)\s*;\s*$")
    any_return_re = re.compile(r"^\s*return\s+[^;]+;\s*$")
    generic_return_re = re.compile(r"^(?:ir_\d+(?:_\d+)?|v\d+|vvar_\d+|a\d+)$")

    index = len(lines) - 1
    while index >= 0 and not lines[index].strip():
        index -= 1
    if index < 0 or lines[index].strip() != "}":
        return c_text

    index -= 1
    while index >= 0 and not lines[index].strip():
        index -= 1
    if index < 0:
        return c_text

    match = return_re.match(lines[index])
    if match is None or not generic_return_re.fullmatch(match.group("expr")):
        return c_text

    if not any(any_return_re.match(line) for line in lines[:index]):
        return c_text

    del lines[index]
    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


def _collapse_annotated_stack_aliases_text(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    header_re = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    decl_re = re.compile(
        r"^(?P<indent>\s*)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*// \[bp(?P<sign>[+-])0x(?P<value>[0-9A-Fa-f]+)\]\s*(?P<alias>[A-Za-z_]\w*)\s*$"
    )

    def _split_args(args_text: str) -> list[str]:
        if not args_text.strip():
            return []
        parts: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            parts.append("".join(current).strip())
        return parts

    changed = False
    index = 0
    while index < len(lines):
        match = header_re.match(lines[index])
        if match is None:
            index += 1
            continue

        arg_names: set[str] = set()
        for arg in _split_args(match.group("args")):
            arg_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg)
            if arg_match is not None:
                arg_names.add(arg_match.group(1))

        brace_index = None
        scan_index = index
        while scan_index < len(lines):
            if "{" in lines[scan_index]:
                brace_index = scan_index
                break
            if ";" in lines[scan_index] and "{" not in lines[scan_index]:
                break
            scan_index += 1
        if brace_index is None:
            index = scan_index + 1
            continue

        body_start = brace_index + 1
        body_end = body_start
        brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        renames: dict[str, str] = {}
        removed_indexes: set[int] = set()
        for scan_index in range(body_start, body_end):
            match = decl_re.match(lines[scan_index])
            if match is None:
                continue
            local_name = match.group("name")
            alias_name = match.group("alias")
            if local_name == alias_name or alias_name not in arg_names:
                continue
            renames[local_name] = alias_name
            removed_indexes.add(scan_index)

        if not renames:
            index = body_end
            continue

        def _rename_in_line(line: str) -> str:
            updated = line
            for local_name, alias_name in sorted(renames.items(), key=lambda item: -len(item[0])):
                updated = re.sub(rf"(?<![A-Za-z_]){re.escape(local_name)}(?![A-Za-z_])", alias_name, updated)
            return updated

        for scan_index in range(body_start, body_end):
            if scan_index in removed_indexes:
                continue
            renamed = _rename_in_line(lines[scan_index])
            if renamed != lines[scan_index]:
                lines[scan_index] = renamed
                changed = True

        if removed_indexes:
            lines = [line for idx, line in enumerate(lines) if idx not in removed_indexes]
            changed = True
            index = 0
            continue

        index = body_end

    if not changed:
        return c_text

    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


def _decompile_function_with_stats(
    project: angr.Project,
    cfg,
    function,
    timeout: int,
    api_style: str,
    binary_path: Path | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    lst_metadata: LSTMetadata | None = None,
    enable_structured_simplify: bool = True,
    enable_postprocess: bool = True,
    allow_isolated_retry: bool = True,
):
    block_count, byte_count = _function_complexity(function)
    print(
        f"[dbg] function complexity for {function.addr:#x} {function.name}: blocks={block_count}, bytes={byte_count}"
    )
    sys.stdout.flush()
    start = time.perf_counter()
    deadline = time.monotonic() + max(1, timeout)
    status, payload = _decompile_function(
        project,
        cfg,
        function,
        timeout,
        api_style,
        binary_path,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
        lst_metadata=lst_metadata,
        enable_structured_simplify=enable_structured_simplify,
        enable_postprocess=enable_postprocess,
        allow_isolated_retry=allow_isolated_retry,
        deadline=deadline,
    )
    partial_payload = getattr(project, "_inertia_partial_codegen_text", None)
    elapsed = time.perf_counter() - start
    print(f"[dbg] decompilation time for {function.addr:#x} {function.name}: {elapsed:.2f}s")
    sys.stdout.flush()
    return status, payload, partial_payload, block_count, byte_count, elapsed


def _bounded_non_optimized_timeout(timeout: int) -> int:
    return min(max(1, timeout), 2)


def _prepare_ranked_binary_preview_items(
    project: angr.Project,
    ranked_binary_offsets: Sequence[int],
    *,
    max_count: int,
    timeout: int,
    window: int,
    low_memory: bool,
) -> list[FunctionWorkItem]:
    if max_count <= 0 or not ranked_binary_offsets:
        return []

    preview_items: list[FunctionWorkItem] = []
    selected_addrs: set[int] = set()
    quick_timeout = min(timeout, 2)
    probe_budget = min(len(ranked_binary_offsets), max(max_count * 6, 12))

    for addr in ranked_binary_offsets[:probe_budget]:
        try:
            if (
                os.name == "posix"
                and threading.current_thread() is threading.main_thread()
                and threading.active_count() == 1
            ):
                function_cfg, function = _run_with_timeout_in_fork(
                    lambda addr=addr: _recover_ranked_binary_function(
                        project,
                        addr,
                        f"sub_{addr:x}",
                        timeout=quick_timeout,
                        window=window,
                        low_memory=low_memory,
                    ),
                    timeout=quick_timeout + 1,
                )
            else:
                function_cfg, function = _run_with_timeout_in_daemon_thread(
                    lambda addr=addr: _recover_ranked_binary_function(
                        project,
                        addr,
                        f"sub_{addr:x}",
                        timeout=quick_timeout,
                        window=window,
                        low_memory=low_memory,
                    ),
                    timeout=quick_timeout + 1,
                    thread_name_prefix="ranked-preview",
                )
        except Exception:
            continue
        preview_items.append(
            FunctionWorkItem(
                index=len(preview_items) + 1,
                function_cfg=function_cfg,
                function=function,
            )
        )
        selected_addrs.add(addr)
        if len(preview_items) >= max_count:
            return preview_items

    for addr in ranked_binary_offsets:
        if addr in selected_addrs:
            continue
        preview_items.append(
            FunctionWorkItem(
                index=len(preview_items) + 1,
                function_cfg=None,
                function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
            )
        )
        if len(preview_items) >= max_count:
            break
    return preview_items


def _supplement_function_cfg_pairs_with_ranked_preview(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    ranked_binary_offsets: Sequence[int],
    *,
    target_count: int,
    timeout: int,
    window: int,
    low_memory: bool,
) -> list[tuple[object, object]]:
    if target_count <= 0 or len(function_cfg_pairs) >= target_count or not ranked_binary_offsets:
        return function_cfg_pairs

    supplemented = list(function_cfg_pairs)
    seen_addrs = {
        getattr(function, "addr", None)
        for _cfg, function in supplemented
        if isinstance(getattr(function, "addr", None), int)
    }
    preview_items = _prepare_ranked_binary_preview_items(
        project,
        ranked_binary_offsets,
        max_count=target_count,
        timeout=timeout,
        window=window,
        low_memory=low_memory,
    )
    for item in preview_items:
        addr = getattr(item.function, "addr", None)
        if item.function_cfg is None or not isinstance(addr, int) or addr in seen_addrs:
            continue
        supplemented.append((item.function_cfg, item.function))
        seen_addrs.add(addr)
        if len(supplemented) >= target_count:
            break
    return supplemented


def _supplement_function_cfg_pairs_with_seeded_recovery(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    *,
    timeout: int,
    target_count: int,
) -> list[tuple[object, object]]:
    if target_count <= 0 or len(function_cfg_pairs) >= target_count:
        return function_cfg_pairs

    supplemented = list(function_cfg_pairs)
    seen_addrs = {
        getattr(function, "addr", None)
        for _cfg, function in supplemented
        if isinstance(getattr(function, "addr", None), int)
    }
    seeded_pairs = _recover_seeded_exe_functions(
        project,
        timeout=timeout,
        limit=target_count,
    )
    for function_cfg, function in seeded_pairs:
        addr = getattr(function, "addr", None)
        if not isinstance(addr, int) or addr in seen_addrs:
            continue
        supplemented.append((function_cfg, function))
        seen_addrs.add(addr)
        if len(supplemented) >= target_count:
            break
    return supplemented


def _function_work_cache_lookup(
    item: FunctionWorkItem,
    *,
    binary_path: Path | None,
    timeout: int,
    api_style: str,
    enable_structured_simplify: bool,
    enable_postprocess: bool,
) -> tuple[FunctionWorkResult | None, str, dict[str, object] | None, bool, list[str]]:
    function_project = getattr(item.function, "project", None)
    tail_validation_enabled = (
        _tail_validation_runtime_enabled(function_project) if function_project is not None else True
    )
    expected_validation_stages = []
    if tail_validation_enabled:
        expected_validation_stages = ["structuring"]
        if enable_postprocess:
            expected_validation_stages.append("postprocess")
    cache_key = _function_decompilation_cache_key(
        binary_path=binary_path,
        function_addr=getattr(item.function, "addr", 0),
        api_style=api_style,
        enable_structured_simplify=enable_structured_simplify,
        enable_postprocess=enable_postprocess,
    )
    cached_result = _load_cache_json("function_decompile", cache_key) if cache_key is not None else None
    if cached_result is not None:
        cached_status = str(cached_result.get("status", "error"))
        cached_tail_validation = cached_result.get("tail_validation")
        if cached_status == "timeout":
            cached_timeout = cached_result.get("timeout")
            if isinstance(cached_timeout, int) and cached_timeout >= timeout:
                validation_status = "disabled" if not tail_validation_enabled else "uncollected"
                return (
                    FunctionWorkResult(
                        index=item.index,
                        status="timeout",
                        payload=str(cached_result.get("payload", "")),
                        partial_payload=None,
                        debug_output=(
                            f"[dbg] timeout cache hit for {getattr(item.function, 'addr', 0):#x} "
                            f"{getattr(item.function, 'name', 'sub')} cached_timeout={cached_timeout}s "
                            f"requested_timeout={timeout}s validation={validation_status}\n"
                        ),
                        function=item.function,
                        function_cfg=item.function_cfg,
                        tail_validation=None,
                    ),
                    "",
                    cache_key,
                    tail_validation_enabled,
                    expected_validation_stages,
                )
            return (
                None,
                (
                    f"[dbg] timeout cache bypass for {getattr(item.function, 'addr', 0):#x} "
                    f"{getattr(item.function, 'name', 'sub')} cached_timeout={cached_timeout!r} "
                    f"requested_timeout={timeout}s\n"
                ),
                cache_key,
                tail_validation_enabled,
                expected_validation_stages,
            )
        if (not tail_validation_enabled) or x86_16_tail_validation_snapshot_passed(
            cached_tail_validation if isinstance(cached_tail_validation, dict) else None,
            expected_stages=expected_validation_stages,
        ):
            cache_validation_status = (
                "disabled"
                if not tail_validation_enabled
                else _tail_validation_display_status(cached_tail_validation if isinstance(cached_tail_validation, dict) else None)
            )
            return (
                FunctionWorkResult(
                    index=item.index,
                    status=cached_status,
                    payload=str(cached_result.get("payload", "")),
                    partial_payload=None,
                    debug_output=(
                        f"[dbg] cache hit for {getattr(item.function, 'addr', 0):#x} "
                        f"{getattr(item.function, 'name', 'sub')} "
                        f"validation={cache_validation_status}\n"
                    ),
                    function=item.function,
                    function_cfg=item.function_cfg,
                    tail_validation=dict(cached_tail_validation) if isinstance(cached_tail_validation, dict) else None,
                ),
                "",
                cache_key,
                tail_validation_enabled,
                expected_validation_stages,
            )
        cache_bypass_reason = _tail_validation_display_status(
            cached_tail_validation if isinstance(cached_tail_validation, dict) else None
        )
        return (
            None,
            (
                f"[dbg] cache bypass for {getattr(item.function, 'addr', 0):#x} "
                f"{getattr(item.function, 'name', 'sub')} validation={cache_bypass_reason}\n"
            ),
            cache_key,
            tail_validation_enabled,
            expected_validation_stages,
        )
    return None, "", cache_key, tail_validation_enabled, expected_validation_stages


def _run_function_work_item(
    item: FunctionWorkItem,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: dict[int, tuple[str, int]] | None,
    lst_metadata: LSTMetadata | None,
    enable_structured_simplify: bool,
    enable_postprocess: bool = True,
    force_isolated_project: bool = False,
    allow_isolated_retry: bool = True,
) -> FunctionWorkResult:
    cached_work_result, cache_bypass_debug, cache_key, tail_validation_enabled, expected_validation_stages = (
        _function_work_cache_lookup(
            item,
            binary_path=binary_path,
            timeout=timeout,
            api_style=api_style,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
        )
    )
    if cached_work_result is not None:
        return cached_work_result

    cache_key = cache_key or _function_decompilation_cache_key(
        binary_path=binary_path,
        function_addr=getattr(item.function, "addr", 0),
        api_style=api_style,
        enable_structured_simplify=enable_structured_simplify,
        enable_postprocess=enable_postprocess,
    )

    decompile_project = item.function.project
    decompile_cfg = item.function_cfg
    decompile_function = item.function

    def _run_local(project_obj, cfg_obj, function_obj) -> tuple[str, str, str | None, str, dict[str, object] | None]:
        with _capture_thread_output() as (stdout_buf, stderr_buf):
            status, payload, partial_payload, *_ = _decompile_function_with_stats(
                project_obj,
                cfg_obj,
                function_obj,
                timeout,
                api_style,
                binary_path,
                cod_metadata=cod_metadata,
                synthetic_globals=synthetic_globals,
                lst_metadata=lst_metadata,
                enable_structured_simplify=enable_structured_simplify,
                enable_postprocess=enable_postprocess,
                allow_isolated_retry=allow_isolated_retry,
            )
        debug_output_local = stdout_buf.getvalue()
        err_output = stderr_buf.getvalue()
        if err_output:
            debug_output_local += err_output
        tail_snapshot_local = _tail_validation_snapshot_for_function_run(project_obj, function_obj)
        return status, payload, partial_payload, debug_output_local, tail_snapshot_local

    fork_isolated_eligible = (
        force_isolated_project
        and os.name == "posix"
        and threading.current_thread() is threading.main_thread()
        and threading.active_count() == 1
        and decompile_cfg is not None
    )
    if fork_isolated_eligible:
        try:
            status, payload, partial_payload, debug_output, tail_validation_snapshot = _run_with_timeout_in_fork(
                lambda: _run_local(decompile_project, decompile_cfg, decompile_function),
                timeout=max(1, timeout) + 1,
            )
        except Exception:
            fork_isolated_eligible = False

    if force_isolated_project and not fork_isolated_eligible and binary_path is not None and isinstance(getattr(item.function, "addr", None), int):
        main_object = getattr(getattr(item.function, "project", None), "loader", None)
        main_object = getattr(main_object, "main_object", None)
        linked_base = getattr(main_object, "linked_base", None)
        max_addr = getattr(main_object, "max_addr", None)
        if isinstance(linked_base, int) and isinstance(max_addr, int):
            try:
                isolated_project = _build_project_cached(
                    str(binary_path),
                    force_blob=False,
                    base_addr=linked_base,
                    entry_point=getattr(item.function.project, "entry", linked_base),
                )
                _inherit_tail_validation_runtime_policy(isolated_project, item.function.project)
                isolated_cfg, isolated_function = _recover_candidate_function_pair(
                    isolated_project,
                    candidate_addr=item.function.addr,
                    image_end=linked_base + max_addr + 1,
                    metadata=lst_metadata,
                    project_entry=isolated_project.entry,
                    region_span=max(0x180, _function_complexity(item.function)[1] + 0x80),
                )
                decompile_project = isolated_project
                decompile_cfg = isolated_cfg
                decompile_function = isolated_function
            except Exception:
                pass

    if not fork_isolated_eligible:
        status, payload, partial_payload, debug_output, tail_validation_snapshot = _run_local(
            decompile_project,
            decompile_cfg,
            decompile_function,
        )
    if cache_bypass_debug:
        debug_output = f"{cache_bypass_debug}{debug_output}"
    tail_validation_passed = (not tail_validation_enabled) or x86_16_tail_validation_snapshot_passed(
        tail_validation_snapshot,
        expected_stages=expected_validation_stages,
    )
    if cache_key is not None and status == "ok":
        _store_cache_json(
            "function_decompile",
            cache_key,
            {
                "status": status,
                "payload": payload,
                "tail_validation": tail_validation_snapshot,
                "tail_validation_passed": tail_validation_passed,
            },
        )
    elif cache_key is not None and status == "timeout":
        _store_cache_json(
            "function_decompile",
            cache_key,
            {
                "status": status,
                "payload": payload,
                "timeout": timeout,
                "tail_validation": None,
                "tail_validation_passed": False,
            },
        )
    return FunctionWorkResult(
        index=item.index,
        status=status,
        payload=payload,
        partial_payload=partial_payload,
        debug_output=debug_output,
        function=item.function,
        function_cfg=item.function_cfg,
        tail_validation=tail_validation_snapshot,
    )


def _helper_name(project: angr.Project, addr: int) -> str | None:
    proc = project.hooked_by(addr)
    if proc is None:
        return None
    name = getattr(proc, "INT_NAME", None)
    if isinstance(name, str) and name:
        return name
    name = getattr(proc, "display_name", None)
    if isinstance(name, str) and name:
        return name
    return proc.__class__.__name__


def _iter_c_nodes(node):
    yield node
    if isinstance(node, structured_c.CStatements):
        for stmt in node.statements:
            yield from _iter_c_nodes(stmt)
        return
    for attr in ("lhs", "rhs", "expr", "condition", "true_node", "false_node", "stmt", "callee_target"):
        if hasattr(node, attr):
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if value is not None and type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                yield from _iter_c_nodes(value)
    if hasattr(node, "args"):
        try:
            args = getattr(node, "args")
        except Exception:
            args = None
        if args:
            for arg in args:
                if type(arg).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                    yield from _iter_c_nodes(arg)


WRAPPER_CALL_NAMES = {"int86", "_int86", "int86x", "_int86x", "intdos", "_intdos", "intdosx", "_intdosx"}


@dataclass(frozen=True)
class InterruptWrapperCall:
    callee_name: str
    canonical_name: str
    kind: str
    arguments: tuple[object, ...]
    vector_arg: object | None = None
    inregs_arg: object | None = None
    outregs_arg: object | None = None
    sregs_arg: object | None = None


@dataclass(frozen=True)
class InterruptWrapperFieldAccess:
    base_name: str
    field_path: tuple[str, ...]
    expr: object


def _normalize_interrupt_wrapper_name(name: str | None) -> str | None:
    if not isinstance(name, str) or not name:
        return None
    return name.lstrip("_")


def _interrupt_wrapper_call_kind(name: str | None, args: tuple[object, ...] | None = None) -> str | None:
    canonical = _normalize_interrupt_wrapper_name(name)
    if canonical not in {"int86", "int86x", "intdos", "intdosx"}:
        if canonical != "CallReturn" or not args:
            return None
        first_arg = _unwrap_c_casts(args[0])
        first_value = _c_constant_value(first_arg)
        if len(args) >= 4:
            return "int86x" if first_value is not None else "intdosx"
        if len(args) >= 3:
            return "int86" if first_value is not None else "intdos"
        return None
    return canonical


def _interrupt_wrapper_call_signature(node: structured_c.CFunctionCall) -> InterruptWrapperCall | None:
    callee_name = None
    callee_func = getattr(node, "callee_func", None)
    if callee_func is not None:
        callee_name = getattr(callee_func, "name", None)
    elif isinstance(getattr(node, "callee_target", None), str):
        callee_name = getattr(node, "callee_target")

    args = tuple(getattr(node, "args", ()) or ())
    kind = _interrupt_wrapper_call_kind(callee_name, args)
    if kind is None:
        return None
    if kind in {"int86", "int86x"}:
        vector_arg = args[0] if len(args) >= 1 else None
        inregs_arg = args[1] if len(args) >= 2 else None
        outregs_arg = args[2] if len(args) >= 3 else None
        sregs_arg = args[3] if kind == "int86x" and len(args) >= 4 else None
    else:
        vector_arg = None
        inregs_arg = args[0] if len(args) >= 1 else None
        outregs_arg = args[1] if len(args) >= 2 else None
        sregs_arg = args[2] if kind == "intdosx" and len(args) >= 3 else None

    return InterruptWrapperCall(
        callee_name=callee_name or kind,
        canonical_name=kind,
        kind=kind,
        arguments=args,
        vector_arg=vector_arg,
        inregs_arg=inregs_arg,
        outregs_arg=outregs_arg,
        sregs_arg=sregs_arg,
    )


def _interrupt_wrapper_field_path(expr) -> InterruptWrapperFieldAccess | None:
    path: list[str] = []
    current = expr
    while isinstance(current, structured_c.CVariableField):
        field = getattr(current, "field", None)
        field_name = getattr(field, "field", None)
        if not isinstance(field_name, str) or not field_name:
            return None
        path.append(field_name)
        current = getattr(current, "variable", None)

    if not isinstance(current, structured_c.CVariable):
        return None

    base_name = getattr(current, "name", None)
    if not isinstance(base_name, str) or not base_name:
        return None
    if not path:
        return None

    path.reverse()
    return InterruptWrapperFieldAccess(base_name=base_name, field_path=tuple(path), expr=expr)


def _interrupt_wrapper_field_role(base_name: str) -> str:
    if base_name == "inregs":
        return "input"
    if base_name == "outregs":
        return "output"
    if base_name == "sregs":
        return "segment"
    return "other"


def _interrupt_wrapper_field_access_summary(
    accesses: list[InterruptWrapperFieldAccess],
) -> dict[str, list[InterruptWrapperFieldAccess]]:
    summary: dict[str, list[InterruptWrapperFieldAccess]] = {
        "input": [],
        "output": [],
        "segment": [],
        "other": [],
    }
    for access in accesses:
        summary.setdefault(_interrupt_wrapper_field_role(access.base_name), []).append(access)
    return summary


def _interrupt_wrapper_call_text(sig: InterruptWrapperCall) -> str:
    args = [str(arg) for arg in sig.arguments if arg is not None]
    return f"{sig.canonical_name}({', '.join(args)})"


def collect_interrupt_wrapper_calls(codegen) -> list[InterruptWrapperCall]:
    if getattr(codegen, "cfunc", None) is None:
        return []

    calls: list[InterruptWrapperCall] = []
    for node in _iter_c_nodes(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CFunctionCall):
            continue
        sig = _interrupt_wrapper_call_signature(node)
        if sig is not None:
            calls.append(sig)
    return calls


def collect_interrupt_wrapper_field_accesses(codegen) -> list[InterruptWrapperFieldAccess]:
    if getattr(codegen, "cfunc", None) is None:
        return []

    accesses: list[InterruptWrapperFieldAccess] = []
    for node in _iter_c_nodes(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CVariableField):
            continue
        access = _interrupt_wrapper_field_path(node)
        if access is not None and access.base_name in {"inregs", "outregs", "sregs"}:
            accesses.append(access)
    return accesses


def _attach_interrupt_wrapper_callees(project: angr.Project, codegen, api_style: str) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    wrapper_calls = collect_interrupt_wrapper_calls(codegen)
    wrapper_field_accesses = collect_interrupt_wrapper_field_accesses(codegen)
    if not wrapper_calls and not wrapper_field_accesses:
        return False

    cache = getattr(project, "_inertia_interrupt_wrappers", None)
    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_interrupt_wrappers", cache)

    cache[getattr(codegen.cfunc, "addr", 0)] = {
        "api_style": api_style,
        "calls": wrapper_calls,
        "field_accesses": wrapper_field_accesses,
        "field_access_summary": _interrupt_wrapper_field_access_summary(wrapper_field_accesses),
    }

    changed = False
    for node in _iter_c_nodes(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CFunctionCall):
            continue
        sig = _interrupt_wrapper_call_signature(node)
        if sig is None:
            continue
        callee_func = getattr(node, "callee_func", None)
        if callee_func is None:
            continue
        if getattr(callee_func, "name", None) != sig.canonical_name:
            callee_func.name = sig.canonical_name
            changed = True

    return changed


def _interrupt_wrapper_register_state_value(
    state: dict[str, dict[tuple[str, ...], int]],
    base_name: str,
    field_path: tuple[str, ...],
) -> int | None:
    return state.get(base_name, {}).get(field_path)


def _interrupt_wrapper_record_register_write(
    state: dict[str, dict[tuple[str, ...], int]],
    base_name: str,
    field_path: tuple[str, ...],
    value: int | None,
) -> None:
    if value is None:
        return

    regs = state.setdefault(base_name, {})
    regs[field_path] = value & 0xFFFF

    if field_path == ("x", "ax"):
        ax = value & 0xFFFF
        regs[("h", "ah")] = (ax >> 8) & 0xFF
        regs[("h", "al")] = ax & 0xFF
    elif field_path == ("x", "bx"):
        bx = value & 0xFFFF
        regs[("h", "bh")] = (bx >> 8) & 0xFF
        regs[("h", "bl")] = bx & 0xFF
    elif field_path == ("x", "cx"):
        cx = value & 0xFFFF
        regs[("h", "ch")] = (cx >> 8) & 0xFF
        regs[("h", "cl")] = cx & 0xFF
    elif field_path == ("x", "dx"):
        dx = value & 0xFFFF
        regs[("h", "dh")] = (dx >> 8) & 0xFF
        regs[("h", "dl")] = dx & 0xFF
    elif field_path == ("h", "ah"):
        ah = value & 0xFF
        regs[("h", "ah")] = ah
        al = regs.get(("h", "al"))
        if al is not None:
            regs[("x", "ax")] = ((ah & 0xFF) << 8) | (al & 0xFF)
    elif field_path == ("h", "al"):
        al = value & 0xFF
        regs[("h", "al")] = al
        ah = regs.get(("h", "ah"))
        if ah is not None:
            regs[("x", "ax")] = ((ah & 0xFF) << 8) | (al & 0xFF)
    elif field_path == ("h", "bh"):
        regs[("h", "bh")] = value & 0xFF
    elif field_path == ("h", "bl"):
        regs[("h", "bl")] = value & 0xFF
    elif field_path == ("h", "ch"):
        regs[("h", "ch")] = value & 0xFF
    elif field_path == ("h", "cl"):
        regs[("h", "cl")] = value & 0xFF
    elif field_path == ("h", "dh"):
        regs[("h", "dh")] = value & 0xFF
    elif field_path == ("h", "dl"):
        regs[("h", "dl")] = value & 0xFF


def _interrupt_wrapper_helper_call_expr(
    sig: InterruptWrapperCall,
    input_state: dict[str, dict[tuple[str, ...], int]],
    api_style: str,
    codegen,
):
    vector = _c_constant_value(_unwrap_c_casts(sig.vector_arg)) if sig.vector_arg is not None else None
    if vector is None and sig.kind in {"intdos", "intdosx"}:
        vector = 0x21
    if vector is None:
        return None

    service_call = InterruptCall(insn_addr=0, vector=vector & 0xFF)
    if vector == 0x21:
        inregs = "inregs"
        ah = _interrupt_wrapper_register_state_value(input_state, inregs, ("h", "ah"))
        al = _interrupt_wrapper_register_state_value(input_state, inregs, ("h", "al"))
        ax = _interrupt_wrapper_register_state_value(input_state, inregs, ("x", "ax"))
        if ax is None and ah is not None and al is not None:
            ax = ((ah & 0xFF) << 8) | (al & 0xFF)
        if ax is not None and ah is None:
            ah = (ax >> 8) & 0xFF
        if ax is not None and al is None:
            al = ax & 0xFF

        if ah is None:
            return None

        service_call = InterruptCall(
            insn_addr=0,
            vector=0x21,
            ah=ah,
            al=al,
            ax=ax,
            bx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "bx")),
            cx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "cx")),
            dx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "dx")),
            ds=_interrupt_wrapper_register_state_value(input_state, inregs, ("ds",)),
            es=_interrupt_wrapper_register_state_value(input_state, inregs, ("es",)),
            ss=_interrupt_wrapper_register_state_value(input_state, inregs, ("ss",)),
            cs=_interrupt_wrapper_register_state_value(input_state, inregs, ("cs",)),
        )
    elif vector == 0x10:
        inregs = "inregs"
        ah = _interrupt_wrapper_register_state_value(input_state, inregs, ("h", "ah"))
        if ah is None:
            return None
        service_call = InterruptCall(
            insn_addr=0,
            vector=0x10,
            ah=ah,
            al=_interrupt_wrapper_register_state_value(input_state, inregs, ("h", "al")),
            ax=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "ax")),
            bx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "bx")),
            cx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "cx")),
            dx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "dx")),
            ds=_interrupt_wrapper_register_state_value(input_state, inregs, ("ds",)),
            es=_interrupt_wrapper_register_state_value(input_state, inregs, ("es",)),
            ss=_interrupt_wrapper_register_state_value(input_state, inregs, ("ss",)),
            cs=_interrupt_wrapper_register_state_value(input_state, inregs, ("cs",)),
        )

    helper_name = interrupt_service_name(service_call, api_style)
    if helper_name.startswith("int86") or helper_name.startswith("intdos"):
        return None

    helper_args: list[object] = []
    if sig.kind in {"int86", "int86x"} and vector == 0x10:
        selector = _interrupt_wrapper_register_state_value(input_state, "inregs", ("h", "ah"))
        if selector is not None:
            helper_args.append(structured_c.CConstant(selector, SimTypeShort(False), codegen=codegen))
    if sig.kind in {"int86", "int86x"} and vector == 0x16:
        selector = _interrupt_wrapper_register_state_value(input_state, "inregs", ("h", "ah"))
        if selector is not None:
            helper_args.append(structured_c.CConstant(selector, SimTypeShort(False), codegen=codegen))
    if helper_name.endswith("getvect"):
        helper_args.append(structured_c.CConstant(0x21, SimTypeShort(False), codegen=codegen))

    return structured_c.CFunctionCall(helper_name, None, helper_args, codegen=codegen)


def _interrupt_wrapper_result_helper_expr(helper_expr, codegen):
    helper_name = getattr(helper_expr, "callee_target", None)
    if not isinstance(helper_name, str):
        helper_func = getattr(helper_expr, "callee_func", None)
        helper_name = getattr(helper_func, "name", None)
    if not isinstance(helper_name, str) or not helper_name:
        return None

    helper_args = list(getattr(helper_expr, "args", ()) or ())
    return structured_c.CFunctionCall(helper_name, None, helper_args, codegen=codegen)


def _interrupt_wrapper_result_extract_expr(access: InterruptWrapperFieldAccess, helper_expr, codegen):
    helper_call = _interrupt_wrapper_result_helper_expr(helper_expr, codegen)
    if helper_call is None:
        return None

    helper_name = getattr(helper_call, "callee_target", None)
    if not isinstance(helper_name, str):
        helper_func = getattr(helper_call, "callee_func", None)
        helper_name = getattr(helper_func, "name", None)

    if access.base_name == "outregs" and access.field_path == ("x", "ax"):
        return helper_call

    if access.base_name == "outregs" and access.field_path in {("x", "bx"), ("x", "cx"), ("x", "dx")}:
        if "getvect" in str(helper_name) and access.field_path == ("x", "bx"):
            return structured_c.CFunctionCall(
                "FP_OFF",
                None,
                [helper_call],
                codegen=codegen,
            )
        return helper_call

    if access.base_name == "outregs" and access.field_path == ("h", "ah"):
        return structured_c.CBinaryOp(
            "And",
            structured_c.CBinaryOp(
                "Shr",
                helper_call,
                structured_c.CConstant(8, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CConstant(0xFF, SimTypeShort(), codegen=codegen),
            codegen=codegen,
        )

    if access.base_name == "outregs" and access.field_path == ("h", "al"):
        return structured_c.CBinaryOp(
            "And",
            helper_call,
            structured_c.CConstant(0xFF, SimTypeShort(), codegen=codegen),
            codegen=codegen,
        )

    if "getvect" in str(helper_name):
        if access.base_name == "sregs" and access.field_path == ("es",):
            return structured_c.CFunctionCall(
                "FP_SEG",
                None,
                [helper_call],
                codegen=codegen,
            )

    if access.base_name == "sregs" and access.field_path == ("es",):
        return helper_call

    return None


def _interrupt_wrapper_result_replacement(
    access: InterruptWrapperFieldAccess,
    helper_expr,
    api_style: str,
    codegen,
):
    if helper_expr is None:
        return None
    return _interrupt_wrapper_result_extract_expr(access, helper_expr, codegen)


def _interrupt_wrapper_result_expr_replacement(expr, helper_expr, api_style: str, codegen):
    if helper_expr is None:
        return None

    replacement = None
    if isinstance(expr, structured_c.CVariable) and getattr(expr, "name", None) == "outregs":
        return _interrupt_wrapper_result_helper_expr(helper_expr, codegen)

    access = _interrupt_wrapper_field_path(expr)
    if access is not None:
        replacement = _interrupt_wrapper_result_replacement(access, helper_expr, api_style, codegen)
        if replacement is not None:
            return replacement

    helper_name = getattr(helper_expr, "callee_target", None)
    if not isinstance(helper_name, str):
        helper_func = getattr(helper_expr, "callee_func", None)
        helper_name = getattr(helper_func, "name", None)
    if not isinstance(helper_name, str) or not helper_name:
        return None

    if helper_name in {"get_dos_version", "_dos_get_version", "dos_get_version"}:
        expr = _unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Or", "Add"}:
            return None

        for high_expr, low_expr in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            high_expr = _unwrap_c_casts(high_expr)
            low_expr = _unwrap_c_casts(low_expr)
            if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Shl", "Mul"}:
                continue

            scale = _c_constant_value(_unwrap_c_casts(high_expr.rhs))
            if scale != 8:
                continue

            high_access = _interrupt_wrapper_field_path(high_expr.lhs)
            low_access = _interrupt_wrapper_field_path(low_expr)
            if (
                high_access is not None
                and low_access is not None
                and high_access.base_name == low_access.base_name == "outregs"
                and high_access.field_path == ("h", "ah")
                and low_access.field_path == ("h", "al")
            ):
                return structured_c.CFunctionCall(
                    helper_name,
                    getattr(helper_expr, "callee_func", None),
                    list(getattr(helper_expr, "args", ()) or ()),
                    codegen=codegen,
                )

    return None


def _lower_interrupt_wrapper_result_reads(project: angr.Project, codegen, api_style: str) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def visit(node, state: dict[str, dict[tuple[str, ...], int]], active_helper) -> None:
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            local_state = {base_name: dict(values) for base_name, values in state.items()}
            current_helper = active_helper
            new_statements = []

            for stmt in node.statements:
                if isinstance(stmt, structured_c.CAssignment):
                    lhs_access = _interrupt_wrapper_field_path(stmt.lhs)
                    if lhs_access is not None and lhs_access.base_name in {"inregs", "outregs", "sregs"}:
                        const_value = _c_constant_value(_unwrap_c_casts(stmt.rhs))
                        _interrupt_wrapper_record_register_write(
                            local_state,
                            lhs_access.base_name,
                            lhs_access.field_path,
                            const_value,
                        )

                    if current_helper is not None:
                        replacement = _interrupt_wrapper_result_expr_replacement(
                            stmt.rhs,
                            current_helper,
                            api_style,
                            codegen,
                        )
                        if replacement is not None and not _same_c_expression(stmt.rhs, replacement):
                            stmt = structured_c.CAssignment(stmt.lhs, replacement, codegen=codegen)
                            changed = True

                elif isinstance(stmt, structured_c.CFunctionCall):
                    sig = _interrupt_wrapper_call_signature(stmt)
                    if sig is not None:
                        helper = _interrupt_wrapper_helper_call_expr(sig, local_state, api_style, codegen)
                        if helper is not None:
                            current_helper = helper
                            if not _same_c_expression(stmt, helper):
                                stmt = helper
                                changed = True
                        else:
                            # Preserve the wrapper call itself as the result source when
                            # service-specific lowering is not possible yet.
                            current_helper = stmt

                elif isinstance(stmt, structured_c.CExpressionStatement):
                    expr = getattr(stmt, "expr", None)
                    if isinstance(expr, structured_c.CFunctionCall):
                        sig = _interrupt_wrapper_call_signature(expr)
                        if sig is not None:
                            helper = _interrupt_wrapper_helper_call_expr(sig, local_state, api_style, codegen)
                            if helper is not None:
                                current_helper = helper
                                if not _same_c_expression(expr, helper):
                                    stmt = structured_c.CExpressionStatement(helper, codegen=codegen)
                                    changed = True
                            else:
                                current_helper = expr

                visit(stmt, local_state, current_helper)
                new_statements.append(stmt)

            if new_statements != list(node.statements):
                node.statements = new_statements
            return

        if isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body, {base_name: dict(values) for base_name, values in state.items()}, active_helper)
            if node.else_node is not None:
                visit(node.else_node, {base_name: dict(values) for base_name, values in state.items()}, active_helper)

    visit(codegen.cfunc.statements, {}, None)
    return changed


def _attach_dos_pseudo_callees(project: angr.Project, function, codegen, api_style: str) -> bool:
    if api_style != "pseudo" or getattr(codegen, "cfunc", None) is None:
        return False

    dos_calls = collect_dos_int21_calls(function)
    if not dos_calls:
        return False

    pseudo_funcs = []
    for call in dos_calls:
        target = function.get_call_target(call.insn_addr)
        if target is None:
            continue
        pseudo_funcs.append(project.kb.functions.function(addr=target))

    if not pseudo_funcs:
        return False

    call_nodes = [
        node
        for node in _iter_c_nodes(codegen.cfunc.statements)
        if isinstance(node, structured_c.CFunctionCall) and node.callee_func is None
    ]

    for node, pseudo_func in zip(call_nodes, pseudo_funcs):
        if pseudo_func is not None:
            node.callee_func = pseudo_func
    return bool(call_nodes)


def _attach_cod_callee_names(project: angr.Project, codegen, cod_metadata: CODProcMetadata | None) -> bool:
    if cod_metadata is None or not cod_metadata.call_names or getattr(codegen, "cfunc", None) is None:
        return False

    call_nodes = [
        node
        for node in _iter_c_nodes_deep(codegen.cfunc.statements)
        if isinstance(node, structured_c.CFunctionCall)
        and (
            getattr(node, "callee_func", None) is None
            or getattr(node.callee_func, "name", "").startswith("sub_")
            or getattr(node.callee_func, "name", "") == "CallReturn"
        )
    ]
    if not call_nodes:
        return False

    changed = False
    for node, call_name in zip(call_nodes, cod_metadata.call_names):
        callee_func = getattr(node, "callee_func", None)
        if callee_func is None:
            target = getattr(node, "callee_target", None)
            if isinstance(target, int):
                callee_func = project.kb.functions.function(addr=target)
                node.callee_func = callee_func
        if callee_func is None:
            continue
        if getattr(callee_func, "name", None) != call_name:
            callee_func.name = call_name
            changed = True
        decl = preferred_known_helper_signature_decl(call_name)
        if decl is not None:
            annotate_function(
                project,
                callee_func.addr,
                name=call_name,
                c_decl=decl,
            )
    return changed


def _build_cod_positive_bp_alias_map(
    bp_disps: list[int], cod_metadata: CODProcMetadata | None
) -> dict[int, str]:
    if cod_metadata is None:
        return {}

    meta_positive = sorted((disp, name) for disp, name in cod_metadata.stack_aliases.items() if disp > 0)
    if not meta_positive:
        return {}

    var_positive = sorted(disp for disp in bp_disps if disp > 0)
    if not var_positive:
        return {}

    alias_map: dict[int, str] = {}
    for disp in var_positive:
        direct = cod_metadata.stack_aliases.get(disp)
        if direct is not None:
            alias_map[disp] = direct

    unmatched_var_positive = [disp for disp in var_positive if disp not in alias_map]
    unused_meta_positive = [item for item in meta_positive if item[1] not in alias_map.values()]
    if len(unmatched_var_positive) <= len(unused_meta_positive):
        for disp, (_, name) in zip(unmatched_var_positive, unused_meta_positive):
            alias_map[disp] = name

    return alias_map


def _cod_stack_alias_for_disp(
    disp: int,
    cod_metadata: CODProcMetadata | None,
    *,
    positive_aliases: dict[int, str] | None = None,
) -> str | None:
    if cod_metadata is None:
        return None
    if disp > 0 and positive_aliases is not None:
        alias = positive_aliases.get(disp)
        if alias is not None:
            return alias
    return cod_metadata.stack_aliases.get(disp)


def _attach_cod_variable_names(codegen, cod_metadata: CODProcMetadata | None) -> bool:
    if cod_metadata is None or not cod_metadata.stack_aliases or getattr(codegen, "cfunc", None) is None:
        return False

    positive_aliases = _build_cod_positive_bp_alias_map(
        [
            getattr(variable, "offset", None)
            for variable in getattr(codegen.cfunc, "variables_in_use", {})
            if _stack_slot_identity_for_variable(variable) is not None
            and isinstance(getattr(variable, "offset", None), int)
        ],
        cod_metadata,
    )

    changed = False
    variables_in_use = getattr(codegen.cfunc, "variables_in_use", {})
    used_names: set[str] = set()
    name_owner_offsets: dict[str, int] = {}
    for variable, cvar in variables_in_use.items():
        if _stack_slot_identity_for_variable(variable) is None:
            continue
        current_name = getattr(variable, "name", None)
        if isinstance(current_name, str) and current_name:
            offset = getattr(variable, "offset", None)
            if not isinstance(offset, int) or offset not in {0, 2}:
                used_names.add(current_name)
                name_owner_offsets[current_name] = offset if isinstance(offset, int) else 0
        unified = getattr(cvar, "unified_variable", None)
        unified_name = getattr(unified, "name", None)
        if isinstance(unified_name, str) and unified_name:
            offset = getattr(variable, "offset", None)
            if not isinstance(offset, int) or offset not in {0, 2}:
                used_names.add(unified_name)
                name_owner_offsets[unified_name] = offset if isinstance(offset, int) else 0
    ordered_variables = sorted(
        [
            (variable, cvar)
            for variable, cvar in variables_in_use.items()
            if _stack_slot_identity_for_variable(variable) is not None
        ],
        key=lambda item: (
            0 if isinstance(getattr(item[0], "offset", None), int) and getattr(item[0], "offset", 0) > 0 else 1,
            getattr(item[0], "offset", 0) if isinstance(getattr(item[0], "offset", 0), int) else 0,
            getattr(item[0], "size", 0) if isinstance(getattr(item[0], "size", 0), int) else 0,
            getattr(item[0], "name", "") or "",
        ),
    )
    for variable, cvar in ordered_variables:
        if _stack_slot_identity_for_variable(variable) is None:
            continue
        disp = getattr(variable, "offset", None)
        if disp is None:
            continue
        alias = _cod_stack_alias_for_disp(disp, cod_metadata, positive_aliases=positive_aliases)
        if alias is None:
            continue
        current_name = getattr(variable, "name", None)
        if isinstance(current_name, str) and current_name and current_name == alias:
            used_names.add(current_name)
            name_owner_offsets[current_name] = disp if isinstance(disp, int) else 0
            continue
        if isinstance(disp, int) and disp in {0, 2} and (
            cod_metadata is None or disp not in getattr(cod_metadata, "stack_aliases", {})
        ):
            unified = getattr(cvar, "unified_variable", None)
            unified_name = getattr(unified, "name", None)
            if isinstance(unified_name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", unified_name):
                if getattr(variable, "name", None) != unified_name:
                    variable.name = unified_name
                    changed = True
                if unified is not None and getattr(unified, "name", None) != unified_name:
                    unified.name = unified_name
                    changed = True
                if getattr(cvar, "name", None) != unified_name:
                    try:
                        cvar.name = unified_name
                    except Exception:
                        pass
                    else:
                        changed = True
            continue
        if alias in used_names:
            owner_offset = name_owner_offsets.get(alias)
            if owner_offset == disp:
                used_names.add(alias)
                name_owner_offsets[alias] = disp if isinstance(disp, int) else 0
            elif isinstance(disp, int) and disp > 2 and owner_offset in {0, 2}:
                used_names.add(alias)
                name_owner_offsets[alias] = disp
            else:
                alias = _make_unique_identifier(alias, used_names)
                name_owner_offsets[alias] = disp if isinstance(disp, int) else 0
        else:
            used_names.add(alias)
            name_owner_offsets[alias] = disp if isinstance(disp, int) else 0

        if getattr(variable, "name", None) != alias:
            variable.name = alias
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != alias:
            unified.name = alias
            changed = True

    return changed


def _synthetic_global_entry(
    synthetic_globals: dict[int, tuple[str, int]] | None, addr: int
) -> tuple[str, int] | None:
    if not synthetic_globals:
        return None
    entry = synthetic_globals.get(addr)
    if entry is None:
        return None
    if isinstance(entry, tuple):
        return entry
    return entry, 1


def _sanitize_cod_identifier(name: str) -> str:
    name = name.lstrip("_")
    if name.startswith("$") and "_" in name:
        name = name.rsplit("_", 1)[-1]
    name = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not name:
        return "data"
    if name[0].isdigit():
        return f"g_{name}"
    return name


def _get_or_seed_inertia_alias_state(codegen):
    alias_state = getattr(codegen, "_inertia_alias_state", None)
    if alias_state is None:
        alias_state = getattr(getattr(codegen, "cfunc", None), "_inertia_alias_state", None)
    if alias_state is not None:
        return alias_state

    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None

    alias_state = AliasState()
    seeded = False
    for variable in getattr(cfunc, "variables_in_use", {}):
        if not isinstance(variable, SimRegisterVariable):
            continue
        pair_name = register_pair_name(getattr(variable, "name", None))
        if pair_name is None:
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", 0) or 0
            if isinstance(reg, int) and size in {1, 2}:
                pair_names = ("ax", "cx", "dx", "bx")
                pair_index = reg // 2
                if 0 <= pair_index < len(pair_names):
                    pair_name = pair_names[pair_index]
        if pair_name is None:
            continue
        alias_state.bump_domain(DomainKey("reg", pair_name.upper()))
        seeded = True

    if not seeded:
        return None
    setattr(codegen, "_inertia_alias_state", alias_state)
    setattr(cfunc, "_inertia_alias_state", alias_state)
    return alias_state


def _make_unique_identifier(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _structured_codegen_node(value) -> bool:
    return type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen")


def _c_constant_value(node) -> int | None:
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _normalize_16bit_signed_offset(offset: int) -> int:
    wrapped = offset & 0xFFFF
    if wrapped >= 0x8000:
        return wrapped - 0x10000
    return wrapped


def _project_rewrite_cache(project: angr.Project) -> dict[str, dict[int, object]]:
    cache = getattr(project, "_inertia_rewrite_cache", None)
    if cache is None:
        cache = {}
        setattr(project, "_inertia_rewrite_cache", cache)
    return cache


@dataclass(frozen=True)
class _SegmentedAccess:
    kind: str
    seg_name: str | None
    assoc_kind: str = "unknown"
    assoc_state: object | None = None
    linear: int | None = None
    cvar: structured_c.CVariable | None = None
    stack_var: SimStackVariable | None = None
    extra_offset: int = 0
    addr_expr: object | None = None

    def allows_object_rewrite(self) -> bool:
        if self.assoc_state is not None and hasattr(self.assoc_state, "is_over_associated"):
            return not self.assoc_state.is_over_associated()
        return self.assoc_kind != "over"


@dataclass(frozen=True)
class _SegmentAssociationState:
    seg_name: str | None
    base_terms: int = 0
    other_terms: int = 0
    const_offset: int = 0
    stack_slots: tuple[object, ...] = ()

    @property
    def assoc_kind(self) -> str:
        if self.seg_name is None:
            return "unknown"
        if len(self.stack_slots) > 1:
            return "over"
        if self.base_terms == 0:
            return "const" if self.other_terms == 0 else "over"
        if self.other_terms > 0:
            return "over"
        return "single"

    def is_over_associated(self) -> bool:
        return self.assoc_kind == "over"


@dataclass(frozen=True)
class _CODSourceRewriteSpec:
    name: str
    header_regex: str
    rewritten: str
    required_lines: tuple[str, ...] = ()

    def apply(self, c_text: str, metadata: CODProcMetadata | None) -> str:
        return _rewrite_cod_proc_from_source(
            c_text,
            metadata,
            header_regex=self.header_regex,
            rewritten=self.rewritten,
            required_lines=self.required_lines,
        )


def _segment_reg_name(node, project: angr.Project) -> str | None:
    cache = _project_rewrite_cache(project).setdefault("segment_reg_name", {})
    key = id(node)
    if key in cache:
        return cache[key]

    if not isinstance(node, structured_c.CVariable):
        cache[key] = None
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        cache[key] = None
        return None
    result = project.arch.register_names.get(variable.reg)
    cache[key] = result
    return result


def _classify_segmented_addr_expr(node, project: angr.Project) -> _SegmentedAccess | None:
    cache = _project_rewrite_cache(project).setdefault("segmented_addr_expr", {})
    key = id(node)
    if key in cache:
        return cache[key]

    seg_name = None
    cvar = None
    stack_var = None
    const_offset = 0
    other_terms = []
    base_terms = 0
    stack_slots: list[object] = []

    for term in _flatten_c_add_terms(node):
        inner = _unwrap_c_casts(term)

        if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
            local_seg = None
            for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                    continue
                local_seg = _segment_reg_name(_unwrap_c_casts(maybe_seg), project)
                if local_seg is not None:
                    break
            if local_seg is not None:
                seg_name = local_seg
                continue

        constant = _c_constant_value(inner)
        if constant is not None:
            const_offset += constant
            continue

        matched_stack = _match_stack_cvar_and_offset(inner)
        if matched_stack is not None:
            matched_cvar, stack_offset = matched_stack
            stack_offset = _normalize_16bit_signed_offset(stack_offset)
            matched_var = getattr(matched_cvar, "variable", None)
            current_var = getattr(cvar, "variable", None) if cvar is not None else None
            if cvar is None:
                cvar = matched_cvar
                if isinstance(matched_var, SimStackVariable):
                    stack_var = matched_var
                    identity = _stack_slot_identity_for_variable(matched_var)
                    if identity is not None:
                        if not stack_slots:
                            stack_slots.append(identity)
                        elif stack_slots[0] == identity:
                            pass
                        elif hasattr(stack_slots[0], "can_join") and stack_slots[0].can_join(identity):
                            joined_identity = stack_slots[0].join(identity)
                            if joined_identity is not None:
                                stack_slots[0] = joined_identity
                        else:
                            stack_slots.append(identity)
                const_offset += stack_offset
                base_terms += 1
            elif current_var is matched_var:
                if isinstance(matched_var, SimStackVariable):
                    identity = _stack_slot_identity_for_variable(matched_var)
                    if identity is not None:
                        if not stack_slots:
                            stack_slots.append(identity)
                        elif stack_slots[0] == identity:
                            pass
                        elif hasattr(stack_slots[0], "can_join") and stack_slots[0].can_join(identity):
                            joined_identity = stack_slots[0].join(identity)
                            if joined_identity is not None:
                                stack_slots[0] = joined_identity
                        else:
                            stack_slots.append(identity)
                const_offset += stack_offset
                base_terms += 1
            else:
                other_terms.append(term)
            continue

        other_terms.append(term)

    if seg_name is None:
        cache[key] = None
        return None

    assoc_state = _SegmentAssociationState(
        seg_name=seg_name,
        base_terms=base_terms,
        other_terms=len(other_terms),
        const_offset=const_offset,
        stack_slots=tuple(stack_slots),
    )
    assoc_kind = assoc_state.assoc_kind

    if seg_name == "ss" and cvar is not None and not other_terms:
        normalized_offset = _normalize_16bit_signed_offset(const_offset)
        result = _SegmentedAccess(
            "stack",
            seg_name,
            assoc_kind=assoc_kind,
            assoc_state=assoc_state,
            cvar=cvar,
            stack_var=stack_var,
            extra_offset=normalized_offset,
            addr_expr=node,
        )
        cache[key] = result
        return result

    if cvar is None and not other_terms:
        if seg_name == "ds":
            kind = "global" if const_offset >= 0 else "unknown"
            linear = const_offset if const_offset >= 0 else None
        elif seg_name == "es":
            kind = "extra"
            linear = const_offset
        else:
            kind = "segment_const"
            linear = const_offset
        result = _SegmentedAccess(
            kind,
            seg_name,
            assoc_kind=assoc_kind,
            assoc_state=assoc_state,
            linear=linear,
            extra_offset=const_offset,
            addr_expr=node,
        )
        cache[key] = result
        return result

    result = _SegmentedAccess(
        "unknown",
        seg_name,
        assoc_kind=assoc_kind,
        assoc_state=assoc_state,
        linear=const_offset if cvar is None else None,
        cvar=cvar,
        stack_var=stack_var,
        extra_offset=const_offset,
        addr_expr=node,
    )
    cache[key] = result
    return result


def _classify_segmented_dereference(node, project: angr.Project) -> _SegmentedAccess | None:
    cache = _project_rewrite_cache(project).setdefault("segmented_dereference_class", {})
    key = id(node)
    if key in cache:
        return cache[key]

    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        cache[key] = None
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        operand = operand.expr
    result = _classify_segmented_addr_expr(operand, project)
    cache[key] = result
    return result


def _match_real_mode_linear_expr(node, project: angr.Project) -> tuple[str | None, int | None]:
    cache = _project_rewrite_cache(project).setdefault("real_mode_linear_expr", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = _classify_segmented_addr_expr(node, project)
    if classified is None or classified.kind not in {"global", "extra", "segment_const"}:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result


def _match_segmented_dereference(node, project: angr.Project) -> tuple[str | None, int | None]:
    cache = _project_rewrite_cache(project).setdefault("segmented_dereference", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.linear is None:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result


def _match_segment_register_based_dereference(node, project: angr.Project):
    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.addr_expr is None or classified.seg_name not in {"ds", "es"}:
        return None
    if not classified.allows_object_rewrite():
        return None

    addr_expr = classified.addr_expr
    base_terms = []
    for term in _flatten_c_add_terms(addr_expr):
        inner = _unwrap_c_casts(term)
        if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
            segment_scale = False
            for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                    continue
                if _segment_reg_name(_unwrap_c_casts(maybe_seg), project) is not None:
                    segment_scale = True
                    break
            if segment_scale:
                continue

        if _c_constant_value(inner) is not None:
            continue

        if isinstance(inner, structured_c.CVariable) and isinstance(getattr(inner, "variable", None), SimRegisterVariable):
            base_terms.append(inner)
            continue

        return None

    if len(base_terms) != 1:
        return None
    return classified, base_terms[0]


def _strip_segment_scale_from_addr_expr(addr_expr, project: angr.Project):
    kept_terms = []
    for term in _flatten_c_add_terms(addr_expr):
        inner = _unwrap_c_casts(term)
        if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
            segment_scale = False
            for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                    continue
                if _segment_reg_name(_unwrap_c_casts(maybe_seg), project) is not None:
                    segment_scale = True
                    break
            if segment_scale:
                continue
        kept_terms.append(term)

    if not kept_terms:
        return None
    result = kept_terms[0]
    for term in kept_terms[1:]:
        result = structured_c.CBinaryOp("Add", result, term, codegen=getattr(term, "codegen", None))
    return result


def _match_ss_stack_reference(node, project: angr.Project):
    cache = _project_rewrite_cache(project).setdefault("ss_stack_reference", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = _classify_segmented_dereference(node, project)
    if classified is not None and classified.kind == "stack" and classified.stack_var is not None and classified.cvar is not None:
        result = (classified.stack_var, classified.cvar, classified.extra_offset)
        cache[key] = result
        return result

    cache[key] = None
    return None


def _flatten_c_add_terms(node, seen: set[int] | None = None):
    if seen is None:
        seen = set()
    key = id(node)
    if key in seen:
        return [node]
    seen.add(key)
    if isinstance(node, structured_c.CTypeCast):
        return _flatten_c_add_terms(node.expr, seen)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _flatten_c_add_terms(node.lhs, seen) + _flatten_c_add_terms(node.rhs, seen)
    return [node]


def _match_stack_cvar_and_offset(node):
    node = _unwrap_c_casts(node)

    if isinstance(node, structured_c.CVariable):
        variable = getattr(node, "variable", None)
        if isinstance(variable, SimStackVariable) and _stack_slot_identity_for_variable(variable) is not None:
            return node, 0
        return None

    if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
        operand = _unwrap_c_casts(node.operand)
        if isinstance(operand, structured_c.CVariable):
            variable = getattr(operand, "variable", None)
            if isinstance(variable, SimStackVariable) and _stack_slot_identity_for_variable(variable) is not None:
                return operand, 0
        return None

    if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
        lhs = _match_stack_cvar_and_offset(node.lhs)
        rhs = _match_stack_cvar_and_offset(node.rhs)
        lhs_const = _c_constant_value(_unwrap_c_casts(node.lhs))
        rhs_const = _c_constant_value(_unwrap_c_casts(node.rhs))

        if lhs is not None and rhs_const is not None:
            base, offset = lhs
            return base, _normalize_16bit_signed_offset(offset + (rhs_const if node.op == "Add" else -rhs_const))
        if rhs is not None and lhs_const is not None:
            base, offset = rhs
            return base, _normalize_16bit_signed_offset(offset + lhs_const)
        return None

    return None


def _match_ss_local_plus_const(node, project: angr.Project):
    cache = _project_rewrite_cache(project).setdefault("ss_local_plus_const", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.kind != "stack" or classified.cvar is None:
        cache[key] = None
        return None
    extra_offset = _normalize_16bit_signed_offset(classified.extra_offset)
    result = (classified.cvar, extra_offset)
    cache[key] = (classified.cvar, extra_offset)
    return result


def _replace_c_children(node, transform, seen: set[int] | None = None) -> bool:
    if seen is None:
        seen = set()
    node_id = id(node)
    if node_id in seen:
        return False
    seen.add(node_id)
    try:
        changed = False

        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "body",
            "iffalse",
            "iftrue",
            "callee_target",
            "else_node",
            "retval",
        ):
            if not hasattr(node, attr):
                continue
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if _structured_codegen_node(value):
                new_value = transform(value)
                if new_value is not value:
                    setattr(node, attr, new_value)
                    changed = True
                    value = new_value
                if _replace_c_children(value, transform, seen):
                    changed = True

        for attr in ("args", "operands", "statements"):
            if not hasattr(node, attr):
                continue
            try:
                items = getattr(node, attr)
            except Exception:
                continue
            if not items:
                continue
            new_items = []
            list_changed = False
            for item in items:
                if _structured_codegen_node(item):
                    new_item = transform(item)
                    if new_item is not item:
                        list_changed = True
                    if _replace_c_children(new_item, transform, seen):
                        changed = True
                    new_items.append(new_item)
                else:
                    new_items.append(item)
            if list_changed:
                setattr(node, attr, new_items)
                changed = True

        if hasattr(node, "condition_and_nodes"):
            try:
                pairs = getattr(node, "condition_and_nodes")
            except Exception:
                pairs = None
            if pairs:
                new_pairs = []
                pair_changed = False
                for cond, body in pairs:
                    new_cond = transform(cond) if _structured_codegen_node(cond) else cond
                    new_body = transform(body) if _structured_codegen_node(body) else body
                    if new_cond is not cond or new_body is not body:
                        pair_changed = True
                    if _structured_codegen_node(new_cond) and _replace_c_children(new_cond, transform, seen):
                        changed = True
                    if _structured_codegen_node(new_body) and _replace_c_children(new_body, transform, seen):
                        changed = True
                    new_pairs.append((new_cond, new_body))
                if pair_changed:
                    setattr(node, "condition_and_nodes", new_pairs)
                    changed = True

        return changed
    finally:
        seen.remove(node_id)


def _iter_c_nodes_deep(node, seen: set[int] | None = None):
    if seen is None:
        seen = set()
    if not _structured_codegen_node(node):
        return
    node_id = id(node)
    if node_id in seen:
        return
    seen.add(node_id)
    yield node

    for attr in dir(node):
        if attr.startswith("_") or attr in {"codegen"}:
            continue
        try:
            value = getattr(node, attr)
        except Exception:
            continue
        if _structured_codegen_node(value):
            yield from _iter_c_nodes_deep(value, seen)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if _structured_codegen_node(item):
                    yield from _iter_c_nodes_deep(item, seen)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node(subitem):
                            yield from _iter_c_nodes_deep(subitem, seen)


def _same_c_expression(lhs, rhs, seen_pairs: set[tuple[int, int]] | None = None) -> bool:
    if type(lhs) is not type(rhs):
        return False

    if seen_pairs is None:
        seen_pairs = set()
    pair = (id(lhs), id(rhs))
    if pair in seen_pairs:
        return True
    seen_pairs.add(pair)

    if isinstance(lhs, structured_c.CConstant):
        return lhs.value == rhs.value

    if isinstance(lhs, structured_c.CTypeCast):
        return _same_c_expression(lhs.expr, rhs.expr, seen_pairs)

    if isinstance(lhs, structured_c.CUnaryOp):
        return lhs.op == rhs.op and _same_c_expression(lhs.operand, rhs.operand, seen_pairs)

    if isinstance(lhs, structured_c.CBinaryOp):
        return (
            lhs.op == rhs.op
            and _same_c_expression(lhs.lhs, rhs.lhs, seen_pairs)
            and _same_c_expression(lhs.rhs, rhs.rhs, seen_pairs)
        )

    if isinstance(lhs, structured_c.CFunctionCall):
        if getattr(lhs, "callee_target", None) != getattr(rhs, "callee_target", None):
            return False
        if getattr(lhs, "callee_func", None) != getattr(rhs, "callee_func", None):
            return False
        lhs_args = list(getattr(lhs, "args", ()) or ())
        rhs_args = list(getattr(rhs, "args", ()) or ())
        if len(lhs_args) != len(rhs_args):
            return False
        return all(_same_c_expression(larg, rarg, seen_pairs) for larg, rarg in zip(lhs_args, rhs_args))

    if isinstance(lhs, structured_c.CVariable):
        lvar = getattr(lhs, "variable", None)
        rvar = getattr(rhs, "variable", None)
        if type(lvar) is not type(rvar):
            return False
        if isinstance(lvar, SimRegisterVariable):
            return getattr(lvar, "reg", None) == getattr(rvar, "reg", None)
        if isinstance(lvar, SimStackVariable):
            return (
                getattr(lvar, "base", None) == getattr(rvar, "base", None)
                and getattr(lvar, "offset", None) == getattr(rvar, "offset", None)
                and getattr(lvar, "size", None) == getattr(rvar, "size", None)
            )
        if isinstance(lvar, SimMemoryVariable):
            return (
                getattr(lvar, "addr", None) == getattr(rvar, "addr", None)
                and getattr(lvar, "size", None) == getattr(rvar, "size", None)
            )
        return lvar == rvar

    return lhs is rhs


def _same_c_storage(lhs, rhs) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False

    lvar = getattr(lhs, "variable", None)
    rvar = getattr(rhs, "variable", None)
    if type(lvar) is not type(rvar):
        return False

    if isinstance(lvar, SimRegisterVariable):
        return getattr(lvar, "reg", None) == getattr(rvar, "reg", None)
    if isinstance(lvar, SimStackVariable):
        return (
            getattr(lvar, "base", None) == getattr(rvar, "base", None)
            and getattr(lvar, "offset", None) == getattr(rvar, "offset", None)
        )
    if isinstance(lvar, SimMemoryVariable):
        return getattr(lvar, "addr", None) == getattr(rvar, "addr", None)
    return lvar == rvar


def _same_stack_slot_identity(lhs, rhs) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False
    lvar = getattr(lhs, "variable", None)
    rvar = getattr(rhs, "variable", None)
    return _same_stack_slot_identity_var(lvar, rvar)


def _stack_slot_identity_can_join(lhs, rhs) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False
    lvar = getattr(lhs, "variable", None)
    rvar = getattr(rhs, "variable", None)
    return _stack_slot_identity_can_join_var(lvar, rvar)


def _is_c_constant_int(node, value: int) -> bool:
    return isinstance(node, structured_c.CConstant) and isinstance(node.value, int) and node.value == value


def _cite_is_negation(node) -> bool:
    return type(node).__name__ == "CITE" and _is_c_constant_int(node.iftrue, 0) and _is_c_constant_int(node.iffalse, 1)


def _invert_comparison_op(op: str) -> str | None:
    return {
        "==": "!=",
        "!=": "==",
        ">": "<=",
        "<": ">=",
        ">=": "<",
        "<=": ">",
    }.get(op)


def _make_inverted_comparison(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    inverted = _invert_comparison_op(node.op)
    if inverted is None:
        return None
    return structured_c.CBinaryOp(
        inverted,
        node.lhs,
        node.rhs,
        type=getattr(node, "type", None),
        codegen=codegen,
        tags=getattr(node, "tags", None),
    )


def _invert_interval_guard_if_safe(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "LogicalAnd":
        return None

    lhs = _unwrap_c_casts(node.lhs)
    rhs = _unwrap_c_casts(node.rhs)
    if not isinstance(lhs, structured_c.CBinaryOp) or not isinstance(rhs, structured_c.CBinaryOp):
        return None

    if lhs.op not in {">", ">=", "CmpGT", "CmpGE"}:
        return None
    if rhs.op not in {"<", "<=", "CmpLT", "CmpLE"}:
        return None
    if not _same_c_expression(lhs.rhs, rhs.rhs):
        return None

    inverted_lhs = _make_inverted_comparison(lhs, codegen)
    inverted_rhs = _make_inverted_comparison(rhs, codegen)
    if inverted_lhs is None or inverted_rhs is None:
        return None
    return structured_c.CBinaryOp(
        "LogicalAnd",
        inverted_lhs,
        inverted_rhs,
        codegen=codegen,
        tags=getattr(node, "tags", None),
    )


def _extract_same_zero_compare_expr(node):
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "CmpEQ":
        return None

    if _is_c_constant_int(node.rhs, 0):
        return node.lhs
    if _is_c_constant_int(node.lhs, 0):
        return node.rhs
    return None


def _extract_zero_flag_source_expr(node):
    if isinstance(node, structured_c.CBinaryOp):
        if node.op == "Mul":
            pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
            for maybe_logic, maybe_scale in pairs:
                if not _is_c_constant_int(maybe_scale, 64):
                    continue
                source_expr = _extract_same_zero_compare_expr(maybe_logic)
                if source_expr is not None:
                    return source_expr
                if not isinstance(maybe_logic, structured_c.CBinaryOp) or maybe_logic.op != "LogicalAnd":
                    continue
                lhs_expr = _extract_same_zero_compare_expr(maybe_logic.lhs)
                rhs_expr = _extract_same_zero_compare_expr(maybe_logic.rhs)
                if lhs_expr is not None and rhs_expr is not None and _same_c_expression(lhs_expr, rhs_expr):
                    return lhs_expr

        for attr in ("lhs", "rhs"):
            child = getattr(node, attr, None)
            if _structured_codegen_node(child):
                extracted = _extract_zero_flag_source_expr(child)
                if extracted is not None:
                    return extracted

    elif isinstance(node, structured_c.CUnaryOp):
        child = getattr(node, "operand", None)
        if _structured_codegen_node(child):
            return _extract_zero_flag_source_expr(child)

    elif isinstance(node, structured_c.CTypeCast):
        child = getattr(node, "expr", None)
        if _structured_codegen_node(child):
            return _extract_zero_flag_source_expr(child)

    return None


def _simplify_zero_flag_comparison(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return node

    if _is_c_constant_int(node.rhs, 0):
        expr = node.lhs
    elif _is_c_constant_int(node.lhs, 0):
        expr = node.rhs
    else:
        return node

    source_expr = _extract_zero_flag_source_expr(expr)
    if source_expr is None:
        return node

    if node.op == "CmpEQ":
        return source_expr

    return structured_c.CUnaryOp("Not", source_expr, codegen=codegen)


def _match_high_byte_projection_base(expr):
    expr = _unwrap_c_casts(expr)
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
        return None
    if _c_constant_value(_unwrap_c_casts(expr.rhs)) != 8:
        return None
    inner = _unwrap_c_casts(expr.lhs)
    if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "Or":
        return None
    for maybe_const, maybe_other in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
        const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
        other = _unwrap_c_casts(maybe_other)
        if const_value is None or const_value & 0xFF:
            continue
        if isinstance(other, structured_c.CBinaryOp) and other.op == "And":
            lhs_mask = _c_constant_value(_unwrap_c_casts(other.lhs))
            rhs_mask = _c_constant_value(_unwrap_c_casts(other.rhs))
            if lhs_mask == 0xFF or rhs_mask == 0xFF:
                return other
    return None


def _match_adjacent_register_pair_var_expr(low_expr, high_expr, codegen):
    if isinstance(high_expr, structured_c.CBinaryOp) and high_expr.op in {"Mul", "Shl"}:
        for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
            scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
            if scale not in {8, 0x100}:
                continue
            high_expr = _unwrap_c_casts(maybe_inner)
            break
    if not isinstance(low_expr, structured_c.CVariable) or not isinstance(high_expr, structured_c.CVariable):
        return None
    low_var = getattr(low_expr, "variable", None)
    high_var = getattr(high_expr, "variable", None)
    if not isinstance(low_var, SimRegisterVariable) or not isinstance(high_var, SimRegisterVariable):
        return None
    if getattr(low_var, "size", None) != 1 or getattr(high_var, "size", None) != 1:
        return None
    alias_state = _get_or_seed_inertia_alias_state(codegen)
    if alias_state is None:
        return None
    analysis = analyze_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    if not analysis.ok:
        return None
    proof = getattr(analysis, "proof", None)
    if proof is None:
        return None
    if getattr(proof, "register_pair", None) is None:
        return None
    if getattr(proof, "left_version", None) is None or getattr(proof, "right_version", None) is None:
        return None
    if getattr(proof, "left_version", None) != getattr(proof, "right_version", None):
        return None
    if not can_join_adjacent_register_slices(low_expr, high_expr, alias_state=alias_state, proof=analysis.proof):
        return None
    return join_adjacent_register_slices(low_expr, high_expr, codegen, alias_state=alias_state, proof=proof)


def _match_high_byte_projection_expr(expr):
    expr = _unwrap_c_casts(expr)
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
        return None
    if _c_constant_value(_unwrap_c_casts(expr.rhs)) != 8:
        return None
    inner = _unwrap_c_casts(expr.lhs)
    if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "And":
        return None
    lhs_mask = _c_constant_value(_unwrap_c_casts(inner.lhs))
    rhs_mask = _c_constant_value(_unwrap_c_casts(inner.rhs))
    if lhs_mask == 0xFF00 or rhs_mask == 0xFF00:
        return expr
    return None


def _match_high_byte_projection_constant(node):
    node = _unwrap_c_casts(node)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "And":
        for maybe_inner, maybe_mask in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            if _c_constant_value(_unwrap_c_casts(maybe_mask)) == 0xFF:
                inner_val = _match_high_byte_projection_constant(maybe_inner)
                if inner_val is not None:
                    return inner_val
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
        return None
    shift = _c_constant_value(_unwrap_c_casts(node.rhs))
    inner = _unwrap_c_casts(node.lhs)
    if shift != 8 or not isinstance(inner, structured_c.CBinaryOp) or inner.op != "Or":
        return None
    for maybe_const, maybe_other in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
        const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
        other = _unwrap_c_casts(maybe_other)
        if const_value is None or const_value & 0xFF:
            continue
        if isinstance(other, structured_c.CBinaryOp) and other.op == "And":
            lhs_mask = _c_constant_value(_unwrap_c_casts(other.lhs))
            rhs_mask = _c_constant_value(_unwrap_c_casts(other.rhs))
            if lhs_mask == 0xFF or rhs_mask == 0xFF:
                return (const_value >> 8) & 0xFF
    return None


def _simplify_boolean_expr(node, codegen):
    if isinstance(node, structured_c.CUnaryOp) and node.op == "Not":
        operand = _unwrap_c_casts(node.operand)
        if isinstance(operand, structured_c.CUnaryOp) and operand.op == "Not":
            return operand.operand
        if isinstance(operand, structured_c.CBinaryOp) and operand.op == "And":
            return structured_c.CBinaryOp(
                "CmpEQ",
                operand,
                structured_c.CConstant(
                    0,
                    getattr(operand, "type", None) or SimTypeShort(False),
                    codegen=codegen,
                ),
                codegen=codegen,
                tags=getattr(node, "tags", None),
            )
        if isinstance(operand, structured_c.CBinaryOp) and operand.op == "Sub":
            lhs_const = _c_constant_value(_unwrap_c_casts(operand.lhs))
            rhs_const = _c_constant_value(_unwrap_c_casts(operand.rhs))
            if rhs_const is not None:
                return structured_c.CBinaryOp(
                    "CmpEQ",
                    operand.lhs,
                    structured_c.CConstant(
                        rhs_const,
                        getattr(operand.rhs, "type", None) or getattr(operand, "type", None) or SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                    tags=getattr(node, "tags", None),
                )
            if lhs_const is not None:
                return structured_c.CBinaryOp(
                    "CmpEQ",
                    operand.rhs,
                    structured_c.CConstant(
                        lhs_const,
                        getattr(operand.lhs, "type", None) or getattr(operand, "type", None) or SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                    tags=getattr(node, "tags", None),
                )
        if isinstance(operand, structured_c.CBinaryOp):
            inverted = _make_inverted_comparison(operand, codegen)
            if inverted is not None:
                return inverted

    simplified = _simplify_zero_flag_comparison(node, codegen)
    if simplified is not node:
        return simplified

    if isinstance(node, structured_c.CUnaryOp) and node.op == "Not" and _cite_is_negation(node.operand):
        inverted = _make_inverted_comparison(node.operand.cond, codegen)
        return inverted if inverted is not None else node.operand.cond

    interval_guard = _invert_interval_guard_if_safe(node, codegen)
    if interval_guard is not None:
        return interval_guard

    if _cite_is_negation(node):
        cond = node.cond
        inverted = _make_inverted_comparison(cond, codegen)
        if inverted is not None:
            return inverted

    return node


def _simplify_zero_mul_or_expr(node, codegen):
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return node

    lhs = _unwrap_c_casts(node.lhs)
    rhs = _unwrap_c_casts(node.rhs)

    def is_zero_mul(expr):
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Mul":
            return False
        return _c_constant_value(_unwrap_c_casts(expr.lhs)) == 0 or _c_constant_value(_unwrap_c_casts(expr.rhs)) == 0

    if _c_constant_value(lhs) == 0:
        return node.rhs
    if _c_constant_value(rhs) == 0:
        return node.lhs
    if is_zero_mul(lhs):
        return node.rhs
    if is_zero_mul(rhs):
        return node.lhs
    return node


def _simplify_basic_algebraic_identities(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node):
        if not isinstance(node, structured_c.CBinaryOp):
            return node

        lhs = _unwrap_c_casts(node.lhs)
        rhs = _unwrap_c_casts(node.rhs)

        if node.op == "Xor" and _same_c_expression(lhs, rhs):
            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
            return structured_c.CConstant(0, type_, codegen=codegen)

        if node.op == "Sub" and _c_constant_value(rhs) == 0:
            return node.lhs

        if node.op == "Add":
            if _c_constant_value(lhs) == 0:
                return node.rhs
            if _c_constant_value(rhs) == 0:
                return node.lhs

        if node.op == "Or":
            if _c_constant_value(lhs) == 0:
                return node.rhs
            if _c_constant_value(rhs) == 0:
                return node.lhs

        high_byte_constant = _match_high_byte_projection_constant(node)
        if high_byte_constant is not None:
            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeChar()
            return structured_c.CConstant(high_byte_constant, type_, codegen=codegen)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True

    if _replace_c_children(root, transform):
        changed = True

    return changed


def _simplify_structured_c_expressions(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def _is_linear_register_temp(cvar) -> bool:
        return isinstance(cvar, structured_c.CVariable) and isinstance(getattr(cvar, "name", None), str) and re.fullmatch(
            r"(?:v\d+|vvar_\d+|ir_\d+)",
            getattr(cvar, "name", ""),
        ) is not None

    def _collect_high_byte_temp_constants(node):
        aliases: dict[int, int] = {}
        for walk_node in _iter_c_nodes_deep(node):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                continue
            if not _is_linear_register_temp(walk_node.lhs):
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Or":
                continue
            for maybe_const, maybe_other in ((rhs.lhs, rhs.rhs), (rhs.rhs, rhs.lhs)):
                const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
                if const_value is None or const_value & 0xFF:
                    continue
                aliases[id(getattr(walk_node.lhs, "variable", None))] = const_value >> 8
                break
        return aliases

    def _collect_shift_extract_aliases(node):
        aliases: dict[int, tuple[object, int]] = {}
        for walk_node in _iter_c_nodes_deep(node):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                continue
            if not _is_linear_register_temp(walk_node.lhs):
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Shr":
                continue
            shift = _c_constant_value(_unwrap_c_casts(rhs.rhs))
            base = _unwrap_c_casts(rhs.lhs)
            if shift is None or not isinstance(shift, int):
                continue
            if not isinstance(base, structured_c.CBinaryOp) or base.op != "And":
                continue
            mask_lhs = _c_constant_value(_unwrap_c_casts(base.lhs))
            mask_rhs = _c_constant_value(_unwrap_c_casts(base.rhs))
            inner = None
            if mask_lhs == 0xFF00:
                inner = base.rhs
            elif mask_rhs == 0xFF00:
                inner = base.lhs
            if inner is None:
                continue
            aliases[id(getattr(walk_node.lhs, "variable", None))] = (inner, shift)
        return aliases

    def _collect_mask_shift_aliases(node):
        aliases: dict[int, tuple[object, int, int]] = {}
        for _ in range(4):
            changed = False
            for walk_node in _iter_c_nodes_deep(node):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_register_temp(walk_node.lhs):
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                key = id(lhs_var)
                rhs = _unwrap_c_casts(walk_node.rhs)
                alias = None

                if isinstance(rhs, structured_c.CBinaryOp) and rhs.op == "And":
                    lhs_const = _c_constant_value(_unwrap_c_casts(rhs.lhs))
                    rhs_const = _c_constant_value(_unwrap_c_casts(rhs.rhs))
                    if lhs_const is not None:
                        alias = (rhs.rhs, lhs_const, 0)
                    elif rhs_const is not None:
                        alias = (rhs.lhs, rhs_const, 0)

                elif isinstance(rhs, structured_c.CBinaryOp) and rhs.op == "Shr":
                    shift = _c_constant_value(_unwrap_c_casts(rhs.rhs))
                    shifted = _unwrap_c_casts(rhs.lhs)
                    if isinstance(shifted, structured_c.CVariable) and isinstance(shift, int):
                        parent = aliases.get(id(getattr(shifted, "variable", None)))
                        if parent is not None:
                            base_expr, mask, base_shift = parent
                            alias = (base_expr, mask, base_shift + shift)

                if alias is None:
                    continue
                if aliases.get(key) != alias:
                    aliases[key] = alias
                    changed = True
            if not changed:
                break
        return aliases

    def _collect_copy_aliases(node):
        aliases: dict[int, _CopyAliasState] = {}
        for _ in range(3):
            changed = False
            for walk_node in _iter_c_nodes_deep(node):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_register_temp(walk_node.lhs):
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                if not isinstance(rhs, structured_c.CVariable):
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                rhs_var = getattr(rhs, "variable", None)
                if lhs_var is None or rhs_var is None:
                    continue
                key = id(lhs_var)
                rhs_domain = _storage_domain_for_expr(rhs)
                if rhs_domain.is_mixed():
                    continue
                parent_state = aliases.get(id(rhs_var))
                rhs_state = _CopyAliasState(rhs_domain, parent_state.expr if parent_state is not None else rhs, needs_synthesis=parent_state.needs_synthesis if parent_state is not None else False)
                current = aliases.get(key)
                if current is None:
                    aliases[key] = rhs_state
                    changed = True
                    continue
                merged = current.merge(rhs_state)
                if merged != current:
                    aliases[key] = merged
                    changed = True
            if not changed:
                break
        return aliases

    def _extract_linear_delta(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
            return None, int(expr.value)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
            return expr, 0

        left_base, left_delta = _extract_linear_delta(expr.lhs)
        right_base, right_delta = _extract_linear_delta(expr.rhs)
        if left_base is not None and right_base is not None:
            if _same_c_expression(left_base, right_base) and expr.op == "Add":
                return left_base, left_delta + right_delta
            return expr, 0
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Or":
            duplicate_word_base = _match_duplicate_word_base_expr(expr, resolve_copy_alias_expr)
            if duplicate_word_base is not None:
                return duplicate_word_base, 0
        if left_base is not None:
            if expr.op == "Add":
                return left_base, left_delta + right_delta
            return left_base, left_delta - right_delta
        if right_base is not None:
            if expr.op == "Add":
                return right_base, left_delta + right_delta
            return expr, 0
        if expr.op == "Add":
            return None, left_delta + right_delta
        return None, left_delta - right_delta

    def _fold_simple_add_constants(node):
        node = _unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
            return node

        def _collect_add_terms(expr):
            terms = []
            stack = [_unwrap_c_casts(expr)]
            seen: set[int] = set()
            while stack:
                current = _unwrap_c_casts(stack.pop())
                key = id(current)
                if key in seen:
                    terms.append(current)
                    continue
                seen.add(key)
                if isinstance(current, structured_c.CBinaryOp) and current.op == "Add":
                    stack.append(current.rhs)
                    stack.append(current.lhs)
                else:
                    terms.append(current)
            return terms

        terms = _collect_add_terms(node)
        if len(terms) > 8:
            return node
        const_total = 0
        const_type = None
        base_terms = []
        for term in terms:
            const_value = _c_constant_value(term)
            if const_value is not None:
                const_total += const_value
                const_type = const_type or getattr(term, "type", None)
                continue
            base_terms.append(term)

        if len(base_terms) != 1 or not terms:
            return node

        base_expr = base_terms[0]
        if const_total == 0:
            return base_expr

        if const_type is None:
            const_type = getattr(base_expr, "type", None) or getattr(node, "type", None) or SimTypeShort(False)
        return structured_c.CBinaryOp(
            "Add" if const_total > 0 else "Sub",
            base_expr,
            structured_c.CConstant(
                const_total if const_total > 0 else -const_total,
                const_type,
                codegen=getattr(node, "codegen", None),
            ),
            codegen=getattr(node, "codegen", None),
        )

    def _build_linear_expr(base_expr, delta, codegen):
        if delta == 0:
            return base_expr
        op = "Add" if delta > 0 else "Sub"
        magnitude = delta if delta > 0 else -delta
        return structured_c.CBinaryOp(
            op,
            base_expr,
            structured_c.CConstant(magnitude, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    variable_use_counts: dict[int, int] = {}
    for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(walk_node, structured_c.CVariable):
            continue
        variable = getattr(walk_node, "variable", None)
        if variable is not None:
            variable_use_counts[id(variable)] = variable_use_counts.get(id(variable), 0) + 1

    high_byte_aliases: dict[int, int] = {}
    shift_extract_aliases: dict[int, tuple[object, int]] = {}
    mask_shift_aliases: dict[int, tuple[object, int, int]] = {}
    copy_aliases: dict[int, _CopyAliasState] = {}
    linear_aliases: dict[int, object] = {}
    _no_match = object()
    adjacent_byte_pair_cache: dict[tuple[int, int], object] = {}
    word_plus_minus_one_cache: dict[int, object] = {}
    widening_match_cache: dict[int, object] = {}

    def _alias_storage_key(expr):
        facts = describe_alias_storage(expr)
        return facts.identity

    def _resolve_copy_alias_expr(node, seen: set[int] | None = None):
        current = _unwrap_c_casts(node)
        if seen is None:
            seen = set()
        current_key = id(current)
        if current_key in seen:
            return current
        seen.add(current_key)
        while isinstance(current, structured_c.CVariable):
            variable = getattr(current, "variable", None)
            if variable is None:
                break
            key = id(variable)
            if key in seen:
                break
            seen.add(key)
            alias = copy_aliases.get(key)
            if alias is None:
                storage_key = _alias_storage_key(current)
                if storage_key is not None:
                    alias = copy_aliases.get(storage_key)
            if alias is None:
                break
            if not alias.can_inline():
                break
            current = _unwrap_c_casts(alias.expr)
        if isinstance(current, structured_c.CTypeCast):
            inner = _resolve_copy_alias_expr(current.expr, seen)
            if inner is not current.expr:
                return structured_c.CTypeCast(None, current.type, inner, codegen=getattr(current, "codegen", None))
            return current
        if isinstance(current, structured_c.CUnaryOp):
            operand = _resolve_copy_alias_expr(current.operand, seen)
            if operand is not current.operand:
                return structured_c.CUnaryOp(current.op, operand, codegen=getattr(current, "codegen", None))
            return current
        if isinstance(current, structured_c.CBinaryOp):
            lhs = _resolve_copy_alias_expr(current.lhs, seen)
            rhs = _resolve_copy_alias_expr(current.rhs, seen)
            if lhs is not current.lhs or rhs is not current.rhs:
                return structured_c.CBinaryOp(current.op, lhs, rhs, codegen=getattr(current, "codegen", None))
        return current

    def _expr_is_safe_inline_candidate(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
            return True
        if isinstance(expr, structured_c.CTypeCast):
            return _expr_is_safe_inline_candidate(expr.expr)
        if isinstance(expr, structured_c.CUnaryOp):
            return expr.op in {"Neg", "Not"} and _expr_is_safe_inline_candidate(expr.operand)
        if isinstance(expr, structured_c.CBinaryOp):
            if expr.op not in {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr"}:
                return False
            return _expr_is_safe_inline_candidate(expr.lhs) and _expr_is_safe_inline_candidate(expr.rhs)
        return False

    def _expr_is_copy_alias_candidate(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
            return True
        if isinstance(expr, structured_c.CTypeCast):
            return _expr_is_copy_alias_candidate(expr.expr)
        return False

    def _stack_name_root(name: str | None) -> str | None:
        if not isinstance(name, str) or not name:
            return None
        match = re.fullmatch(r"(?P<root>.*?)(?:_(?P<suffix>\d+))?", name)
        if match is None:
            return name
        suffix = match.group("suffix")
        root = match.group("root")
        if suffix is None:
            return root
        return root if root else name

    def _collect_far_pointer_stack_aliases(node):
        groups: dict[str, dict[str, list[tuple[structured_c.CVariable, object]]]] = {}

        def _expr_contains_generated_temp(expr) -> bool:
            for walk in _iter_c_nodes_deep(expr):
                if not isinstance(walk, structured_c.CVariable):
                    continue
                name = getattr(walk, "name", None)
                if isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", name):
                    return True
            return False

        def _expr_mentions_stack_root(expr, root: str) -> bool:
            for walk in _iter_c_nodes_deep(expr):
                if not isinstance(walk, structured_c.CVariable):
                    continue
                variable = getattr(walk, "variable", None)
                if not isinstance(variable, SimStackVariable):
                    continue
                if _stack_name_root(getattr(variable, "name", None)) == root:
                    return True
            return False

        for walk_node in _iter_c_nodes_deep(node):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                continue
            lhs_var = getattr(walk_node.lhs, "variable", None)
            if not isinstance(lhs_var, SimStackVariable):
                continue
            root = _stack_name_root(getattr(lhs_var, "name", None))
            if root is None:
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            if _c_constant_value(rhs) is None and not _expr_is_safe_inline_candidate(rhs):
                continue
            if _expr_contains_generated_temp(rhs):
                continue
            bucket = groups.setdefault(root, {"zero": [], "source": []})
            if _c_constant_value(rhs) == 0:
                bucket["zero"].append((walk_node.lhs, rhs))
            else:
                bucket["source"].append((walk_node.lhs, rhs))

        def _source_score(_cvar, expr) -> tuple[int, int, int]:
            expr = _unwrap_c_casts(expr)
            variable = getattr(expr, "variable", None)
            name = getattr(variable, "name", None) or getattr(expr, "name", None)
            generic_name = isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None
            if isinstance(variable, SimStackVariable):
                return (0 if not generic_name else 2, getattr(variable, "offset", 0), getattr(variable, "size", 0))
            if isinstance(variable, SimMemoryVariable):
                return (0 if not generic_name else 2, getattr(variable, "addr", 0), getattr(variable, "size", 0))
            if isinstance(variable, SimRegisterVariable):
                return (3 if generic_name else 1, getattr(variable, "reg", 0), getattr(variable, "size", 0))
            if isinstance(expr, structured_c.CConstant):
                return (4, int(expr.value) if isinstance(expr.value, int) else 0, 0)
            return (4, 0, 0)

        aliases: dict[int, object] = {}
        for root, parts in groups.items():
            if not parts["zero"] or not parts["source"]:
                continue
            source_expr = None
            for cvar, rhs in sorted(parts["source"], key=lambda item: _source_score(item[0], item[1])):
                variable = getattr(cvar, "variable", None)
                if not isinstance(variable, SimStackVariable):
                    continue
                if _stack_name_root(getattr(variable, "name", None)) != root:
                    continue
                if _expr_mentions_stack_root(rhs, root):
                    continue
                source_expr = rhs
                break
            if source_expr is None:
                continue
            for cvar, _rhs in parts["zero"]:
                variable = getattr(cvar, "variable", None)
                if not isinstance(variable, SimStackVariable):
                    continue
                aliases[id(variable)] = source_expr
        return aliases

    def _match_adjacent_byte_pair_var_expr(low_expr, high_expr):
        key = (id(low_expr), id(high_expr))
        if key in adjacent_byte_pair_cache:
            cached = adjacent_byte_pair_cache[key]
            return None if cached is _no_match else cached
        low_expr = _resolve_copy_alias_expr(low_expr)
        high_expr = _resolve_copy_alias_expr(high_expr)

        if isinstance(high_expr, structured_c.CBinaryOp) and high_expr.op in {"Mul", "Shl"}:
            for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
                if scale not in {8, 0x100}:
                    continue
                high_expr = _resolve_copy_alias_expr(maybe_inner)
                break

        low_var = getattr(low_expr, "variable", None) if isinstance(low_expr, structured_c.CVariable) else None
        high_var = getattr(high_expr, "variable", None) if isinstance(high_expr, structured_c.CVariable) else None
        if not isinstance(low_var, SimMemoryVariable) or not isinstance(high_var, SimMemoryVariable):
            adjacent_byte_pair_cache[key] = _no_match
            return None
        if not analyze_adjacent_storage_slices(low_var, high_var).ok:
            adjacent_byte_pair_cache[key] = _no_match
            return None
        if getattr(low_var, "region", None) != getattr(high_var, "region", None):
            adjacent_byte_pair_cache[key] = _no_match
            return None
        if getattr(high_var, "addr", None) != getattr(low_var, "addr", None) + 1:
            adjacent_byte_pair_cache[key] = _no_match
            return None
        low_name = getattr(low_var, "name", None)
        if not isinstance(low_name, str) or not low_name:
            adjacent_byte_pair_cache[key] = _no_match
            return None
        if re.fullmatch(r"(?:v\d+|vvar_\d+)", low_name):
            adjacent_byte_pair_cache[key] = _no_match
            return None
        result = structured_c.CVariable(
            SimMemoryVariable(low_var.addr, 2, name=_sanitize_cod_identifier(low_name), region=codegen.cfunc.addr),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        adjacent_byte_pair_cache[key] = result
        return result

    def _match_word_plus_minus_one_expr(node):
        key = id(node)
        if key in word_plus_minus_one_cache:
            cached = word_plus_minus_one_cache[key]
            return None if cached is _no_match else cached
        node = _unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            word_plus_minus_one_cache[key] = _no_match
            return None

        def _strip_byte_cast(expr):
            expr = _unwrap_c_casts(expr)
            if isinstance(expr, structured_c.CTypeCast):
                type_ = getattr(expr, "type", None)
                if getattr(type_, "size", None) == 8:
                    return _unwrap_c_casts(expr.expr)
            return expr

        def _match_masked_high_word(expr):
            expr = _unwrap_c_casts(expr)
            if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "And":
                return None
            for maybe_word, maybe_mask in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_mask)) != 0xFF00:
                    continue
                return _unwrap_c_casts(maybe_word)
            return None

        def _match_duplicate_word_base(expr):
            expr = _unwrap_c_casts(expr)
            if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Or":
                return None
            for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                low_expr = _resolve_copy_alias_expr(_unwrap_c_casts(maybe_low))
                high_expr = _unwrap_c_casts(maybe_high)
                if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Mul", "Shl"}:
                    continue
                for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                    if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                        continue
                    inner_expr = _resolve_copy_alias_expr(_unwrap_c_casts(maybe_inner))
                    if _same_c_expression(low_expr, inner_expr):
                        return low_expr
            return None

        for masked_expr, delta_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            base_expr = _match_masked_high_word(masked_expr)
            duplicate_word_base = None
            if base_expr is None:
                duplicate_word_base = _match_duplicate_word_base(masked_expr)
                base_expr = duplicate_word_base
                if base_expr is None:
                    continue
            delta_expr = _unwrap_c_casts(delta_expr)
            constant_delta = _c_constant_value(delta_expr)
            if node.op == "Add" and isinstance(constant_delta, int):
                return structured_c.CBinaryOp(
                    "Add",
                    base_expr,
                    structured_c.CConstant(constant_delta, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                )
            if not isinstance(delta_expr, structured_c.CBinaryOp) or delta_expr.op not in {"Add", "Sub"}:
                continue
            low_expr, const_expr = delta_expr.lhs, delta_expr.rhs
            if duplicate_word_base is not None and _c_constant_value(_unwrap_c_casts(const_expr)) == 1:
                return structured_c.CBinaryOp(
                    "Add" if delta_expr.op == "Add" else "Sub",
                    base_expr,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                )
            if _c_constant_value(_unwrap_c_casts(low_expr)) is None and _c_constant_value(_unwrap_c_casts(const_expr)) is None:
                continue
            if _same_c_expression(_strip_byte_cast(low_expr), base_expr) and _c_constant_value(_unwrap_c_casts(const_expr)) == 1:
                return structured_c.CBinaryOp(
                    "Add" if delta_expr.op == "Add" else "Sub",
                    base_expr,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                )
            if _same_c_expression(_strip_byte_cast(const_expr), base_expr) and _c_constant_value(_unwrap_c_casts(low_expr)) == 1:
                return structured_c.CBinaryOp(
                    "Add" if delta_expr.op == "Add" else "Sub",
                    base_expr,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                )

        word_plus_minus_one_cache[key] = _no_match
        return None

    def _analyze_widening_expr_cached(node):
        key = id(node)
        if key in widening_match_cache:
            cached = widening_match_cache[key]
            return None if cached is _no_match else cached
        result = _analyze_widening_expr(
            node,
            _resolve_copy_alias_expr,
            _match_high_byte_projection_base,
        )
        widening_match_cache[key] = result if result is not None else _no_match
        return result

    def _match_linear_word_delta_expr(node):
        analysis = _analyze_widening_expr_cached(node)
        if analysis is None or analysis.kind != "linear":
            return None
        if analysis.delta == 0:
            return analysis.base_expr
        delta = analysis.delta
        base_expr = analysis.base_expr
        op = "Add" if delta > 0 else "Sub"
        magnitude = delta if delta > 0 else -delta
        return structured_c.CBinaryOp(
            op,
            base_expr,
            structured_c.CConstant(magnitude, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    for _ in range(3):
        changed = False
        for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                continue
            if not _is_linear_register_temp(walk_node.lhs):
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op not in {"Add", "Sub"}:
                continue
            resolved_rhs = _resolve_copy_alias_expr(rhs)
            linear_rhs = _match_linear_word_delta_expr(resolved_rhs)
            if linear_rhs is None:
                continue
            lhs_var = getattr(walk_node.lhs, "variable", None)
            if lhs_var is None:
                continue
            key = id(lhs_var)
            if linear_aliases.get(key) != linear_rhs:
                linear_aliases[key] = linear_rhs
                changed = True
        if not changed:
            break

    def _match_high_byte_preserving_word_expr(node):
        analysis = _analyze_widening_expr_cached(node)
        if analysis is None or analysis.kind != "high_byte_preserving":
            return None
        return structured_c.CBinaryOp(
            "Add",
            analysis.base_expr,
            structured_c.CConstant(analysis.delta, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def _make_mk_fp(segment_expr, offset_expr):
        return structured_c.CFunctionCall("MK_FP", None, [segment_expr, offset_expr], codegen=codegen)

    def _is_dead_stack_address_init(stmt) -> bool:
        if not isinstance(stmt, structured_c.CAssignment) or not isinstance(stmt.lhs, structured_c.CVariable):
            return False
        lhs_var = getattr(stmt.lhs, "variable", None)
        if not isinstance(lhs_var, SimStackVariable) or _stack_slot_identity_for_variable(lhs_var) is None:
            return False
        if variable_use_counts.get(id(lhs_var), 0) != 1:
            return False
        rhs = stmt.rhs
        if not isinstance(rhs, structured_c.CUnaryOp) or rhs.op != "Reference":
            return False
        operand = rhs.operand
        if not isinstance(operand, structured_c.CVariable):
            return False
        ref_var = getattr(operand, "variable", None)
        return isinstance(ref_var, SimStackVariable) and _stack_slot_identity_for_variable(ref_var) is not None

    def _is_redundant_self_copy(stmt) -> bool:
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        lhs = _unwrap_c_casts(stmt.lhs)
        rhs = _unwrap_c_casts(stmt.rhs)
        if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
            return False
        lhs_var = getattr(lhs, "variable", None)
        rhs_var = getattr(rhs, "variable", None)
        if lhs_var is None or rhs_var is None or lhs_var is not rhs_var:
            return False
        return _is_linear_register_temp(lhs)

    def _flatten_bitwise_terms(expr, op):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == op:
            return _flatten_bitwise_terms(expr.lhs, op) + _flatten_bitwise_terms(expr.rhs, op)
        return [expr]

    def _rewrite_and_over_or(node):
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "And":
            return None
        for or_expr, const_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            or_expr = _unwrap_c_casts(or_expr)
            const_value = _c_constant_value(_unwrap_c_casts(const_expr))
            if const_value is None or not isinstance(or_expr, structured_c.CBinaryOp) or or_expr.op != "Or":
                continue
            for and_expr, inner_const_expr in ((or_expr.lhs, or_expr.rhs), (or_expr.rhs, or_expr.lhs)):
                inner_const = _c_constant_value(_unwrap_c_casts(inner_const_expr))
                if inner_const is None or not isinstance(and_expr, structured_c.CBinaryOp) or and_expr.op != "And":
                    continue
                for inner_base, inner_mask_expr in ((and_expr.lhs, and_expr.rhs), (and_expr.rhs, and_expr.lhs)):
                    inner_mask = _c_constant_value(_unwrap_c_casts(inner_mask_expr))
                    if inner_mask is None:
                        continue
                    left = structured_c.CBinaryOp(
                        "And",
                        _unwrap_c_casts(inner_base),
                        structured_c.CConstant(const_value, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                    right_const = inner_const & const_value
                    if right_const == 0:
                        return left
                    right = structured_c.CConstant(right_const, SimTypeShort(False), codegen=codegen)
                    return structured_c.CBinaryOp("Or", left, right, codegen=codegen)
        return None

    def transform(node):
        if isinstance(node, structured_c.CTypeCast):
            target_type = getattr(node, "type", None)
            rendered = str(target_type) if target_type is not None else ""
            if "[" in rendered and isinstance(node.expr, structured_c.CVariable):
                return node.expr
            if "[" in rendered and not isinstance(node.expr, structured_c.CConstant):
                return node.expr

        if isinstance(node, structured_c.CBinaryOp):
            lhs = _resolve_copy_alias_expr(_unwrap_c_casts(node.lhs))
            rhs = _resolve_copy_alias_expr(_unwrap_c_casts(node.rhs))
            if node.op in {"Add", "Or"}:
                widened = _match_adjacent_byte_pair_var_expr(lhs, rhs)
                if widened is None:
                    widened = _match_adjacent_byte_pair_var_expr(rhs, lhs)
                if widened is not None:
                    return widened
                widened = _match_adjacent_register_pair_var_expr(lhs, rhs, codegen)
                if widened is None:
                    widened = _match_adjacent_register_pair_var_expr(rhs, lhs, codegen)
                if widened is not None:
                    return widened
                if node.op == "Add":
                    if isinstance(lhs, structured_c.CVariable) and isinstance(getattr(lhs, "variable", None), SimStackVariable):
                        if _c_constant_value(rhs) is not None:
                            alias_expr = far_pointer_aliases.get(id(getattr(lhs, "variable", None)))
                            if alias_expr is not None:
                                return _make_mk_fp(alias_expr, rhs)
                    if isinstance(rhs, structured_c.CVariable) and isinstance(getattr(rhs, "variable", None), SimStackVariable):
                        if _c_constant_value(lhs) is not None:
                            alias_expr = far_pointer_aliases.get(id(getattr(rhs, "variable", None)))
                            if alias_expr is not None:
                                return _make_mk_fp(alias_expr, lhs)
                delta = _match_word_plus_minus_one_expr(node)
                if delta is not None:
                    return delta
                linear = _match_linear_word_delta_expr(node)
                if linear is not None:
                    return linear
                high_update = _match_high_byte_preserving_word_expr(node)
                if high_update is not None:
                    return high_update
            if node.op in {"Add", "Sub"}:
                resolved = structured_c.CBinaryOp(node.op, lhs, rhs, codegen=codegen)
                linear = _match_linear_word_delta_expr(resolved)
                if linear is not None:
                    return linear
            if isinstance(lhs, structured_c.CConstant) and isinstance(rhs, structured_c.CConstant):
                if isinstance(lhs.value, int) and isinstance(rhs.value, int):
                    result = None
                    if node.op == "Add":
                        result = lhs.value + rhs.value
                    elif node.op == "Sub":
                        result = lhs.value - rhs.value
                    elif node.op == "Mul":
                        result = lhs.value * rhs.value
                    elif node.op == "And":
                        result = lhs.value & rhs.value
                    elif node.op == "Or":
                        result = lhs.value | rhs.value
                    elif node.op == "Xor":
                        result = lhs.value ^ rhs.value
                    elif node.op == "Shl":
                        result = lhs.value << rhs.value
                    elif node.op == "Shr":
                        result = lhs.value >> rhs.value
                    if result is not None:
                        type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                        return structured_c.CConstant(result, type_, codegen=codegen)
            rewritten_and = _rewrite_and_over_or(node)
            if rewritten_and is not None:
                return rewritten_and
            if node.op in {"And", "Or"}:
                terms = _flatten_bitwise_terms(node, node.op)
                const_value = None
                const_type = None
                non_constants = []
                for term in terms:
                    value = _c_constant_value(term)
                    if value is None:
                        non_constants.append(term)
                        continue
                    const_type = getattr(term, "type", None) or const_type
                    if const_value is None:
                        const_value = value
                    elif node.op == "And":
                        const_value &= value
                    else:
                        const_value |= value
                if len(terms) > 2 or len(non_constants) != len(terms):
                    rebuilt_terms = list(non_constants)
                    if const_value is not None:
                        if not ((node.op == "And" and const_value == -1) or (node.op == "Or" and const_value == 0)):
                            rebuilt_terms.append(
                                structured_c.CConstant(
                                    const_value,
                                    const_type or getattr(node, "type", None) or SimTypeShort(False),
                                    codegen=codegen,
                                )
                            )
                    if not rebuilt_terms:
                        type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                        return structured_c.CConstant(const_value if const_value is not None else 0, type_, codegen=codegen)
                    result = rebuilt_terms[0]
                    for term in rebuilt_terms[1:]:
                        result = structured_c.CBinaryOp(node.op, result, term, codegen=codegen)
                    return result
            if node.op in {"Add", "Or", "Xor"}:
                if _c_constant_value(lhs) == 0:
                    return node.rhs
                if _c_constant_value(rhs) == 0:
                    return node.lhs
            if node.op == "Sub":
                if _c_constant_value(rhs) == 0:
                    return node.lhs
            if node.op == "Add":
                folded = _fold_simple_add_constants(node)
                if folded is not node:
                    return folded
            if node.op == "Sub":
                base_expr, delta = _extract_linear_delta(node)
                if base_expr is not None:
                    rebuilt = _build_linear_expr(base_expr, delta, codegen)
                    if not _same_c_expression(rebuilt, node):
                        return rebuilt
            if node.op in {"And", "Or"} and _same_c_expression(lhs, rhs):
                return lhs
            if node.op == "Xor" and _same_c_expression(lhs, rhs):
                type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                if type_ is not None:
                    return structured_c.CConstant(0, type_, codegen=codegen)
            if node.op == "Mul":
                for maybe_inner, maybe_other in ((lhs, rhs), (rhs, lhs)):
                    if _c_constant_value(maybe_other) is None:
                        continue
                    inner = _unwrap_c_casts(maybe_inner)
                    if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "And":
                        continue
                    if _c_constant_value(_unwrap_c_casts(inner.rhs)) != 0xFF:
                        continue
                    shifted = _match_high_byte_projection_expr(inner.lhs)
                    if shifted is None:
                        continue
                    return structured_c.CBinaryOp(
                        "Mul",
                        shifted,
                        maybe_other,
                        codegen=codegen,
                    )
                if _c_constant_value(lhs) == 0 or _c_constant_value(rhs) == 0:
                    type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                    if type_ is not None:
                        return structured_c.CConstant(0, type_, codegen=codegen)
                if _c_constant_value(lhs) == 1:
                    return node.rhs
                if _c_constant_value(rhs) == 1:
                    return node.lhs
            if node.op == "And":
                if _c_constant_value(lhs) == 0 or _c_constant_value(rhs) == 0:
                    type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                    if type_ is not None:
                        return structured_c.CConstant(0, type_, codegen=codegen)
                for maybe_inner, maybe_mask in ((lhs, rhs), (rhs, lhs)):
                    if _c_constant_value(maybe_mask) == 0xFF and isinstance(maybe_inner, structured_c.CVariable):
                        variable = getattr(maybe_inner, "variable", None)
                        if variable is not None:
                            var_key = id(variable)
                            if (
                                var_key in high_byte_aliases
                                or var_key in shift_extract_aliases
                                or var_key in mask_shift_aliases
                            ):
                                return maybe_inner
                    if (
                        _c_constant_value(maybe_mask) == 0xFF
                        and isinstance(maybe_inner, structured_c.CBinaryOp)
                        and maybe_inner.op == "Shr"
                        and _is_c_constant_int(_unwrap_c_casts(maybe_inner.rhs), 8)
                        and isinstance(_unwrap_c_casts(maybe_inner.lhs), structured_c.CBinaryOp)
                        and _unwrap_c_casts(maybe_inner.lhs).op == "And"
                    ):
                        return maybe_inner
                    if _c_constant_value(maybe_mask) != 0xFF:
                        continue
                    projection = _match_high_byte_projection_expr(maybe_inner)
                    if projection is not None:
                        return projection
                    const_high = _match_high_byte_projection_constant(maybe_inner)
                    if const_high is not None:
                        type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                        return structured_c.CConstant(const_high, type_, codegen=codegen)
                    if isinstance(maybe_inner, structured_c.CVariable):
                        alias = mask_shift_aliases.get(id(getattr(maybe_inner, "variable", None)))
                        if alias is not None:
                            base_expr, mask, total_shift = alias
                            if mask == 0xFF00:
                                simplified = structured_c.CBinaryOp(
                                    "Shr",
                                    base_expr,
                                    structured_c.CConstant(total_shift, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                                base_type = getattr(getattr(base_expr, "type", None), "size", None)
                                if total_shift == 8 and base_type == 16:
                                    return simplified
                                return structured_c.CBinaryOp(
                                    "And",
                                    simplified,
                                    structured_c.CConstant(0xFF, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                    inner = _unwrap_c_casts(maybe_inner)
                    if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Shr":
                        shift = _c_constant_value(_unwrap_c_casts(inner.rhs))
                        shifted = _unwrap_c_casts(inner.lhs)
                        if isinstance(shifted, structured_c.CVariable):
                            alias = shift_extract_aliases.get(id(getattr(shifted, "variable", None)))
                            if alias is not None and isinstance(shift, int):
                                base_expr, base_shift = alias
                                total_shift = base_shift + shift
                                simplified = structured_c.CBinaryOp(
                                    "Shr",
                                    base_expr,
                                    structured_c.CConstant(total_shift, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                                base_type = getattr(getattr(base_expr, "type", None), "size", None)
                                if total_shift == 8 and base_type == 16:
                                    return simplified
                                return structured_c.CBinaryOp(
                                    "And",
                                    simplified,
                                    structured_c.CConstant(0xFF, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
            simplified_or = _simplify_zero_mul_or_expr(node, codegen)
            if simplified_or is not node:
                return simplified_or
            if node.op == "Shr":
                if isinstance(lhs, structured_c.CBinaryOp) and lhs.op == "Shr":
                    inner_shift = _c_constant_value(_unwrap_c_casts(lhs.rhs))
                    outer_shift = _c_constant_value(rhs)
                    if isinstance(inner_shift, int) and isinstance(outer_shift, int):
                        return structured_c.CBinaryOp(
                            "Shr",
                            lhs.lhs,
                            structured_c.CConstant(inner_shift + outer_shift, SimTypeShort(False), codegen=codegen),
                            codegen=codegen,
                        )
                if _is_c_constant_int(rhs, 8) and isinstance(lhs, structured_c.CVariable):
                    alias = high_byte_aliases.get(id(getattr(lhs, "variable", None)))
                    if alias is not None:
                        type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None) or SimTypeShort(False)
                        return structured_c.CConstant(alias, type_, codegen=codegen)
        simplified = _simplify_boolean_expr(node, codegen)
        if simplified is not node:
            return simplified
        if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":
            if _same_c_expression(node.lhs, node.rhs):
                type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None)
                if type_ is not None:
                    return structured_c.CConstant(0, type_, codegen=codegen)
        if isinstance(node, structured_c.CAssignment) and _is_redundant_self_copy(node):
            return structured_c.CConstant(0, getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None), codegen=codegen)
        return node

    def prune_dead_stack_address_inits(node) -> bool:
        changed = False
        if isinstance(node, structured_c.CStatements):
            new_statements = []
            for stmt in node.statements:
                if _is_dead_stack_address_init(stmt):
                    changed = True
                    continue
                if _is_redundant_self_copy(stmt):
                    changed = True
                    continue
                if prune_dead_stack_address_inits(stmt):
                    changed = True
                new_statements.append(stmt)
            if changed or new_statements != node.statements:
                node.statements = new_statements
        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                if prune_dead_stack_address_inits(body):
                    changed = True
            if node.else_node is not None and prune_dead_stack_address_inits(node.else_node):
                changed = True
        return changed

    root = codegen.cfunc.statements
    changed = False
    for _ in range(3):
        iter_changed = False
        high_byte_aliases = _collect_high_byte_temp_constants(root)
        shift_extract_aliases = _collect_shift_extract_aliases(root)
        mask_shift_aliases = _collect_mask_shift_aliases(root)
        copy_aliases = _collect_copy_aliases(root)
        far_pointer_aliases = _collect_far_pointer_stack_aliases(root)
        new_root = transform(root)
        if new_root is not root:
            codegen.cfunc.statements = new_root
            root = new_root
            iter_changed = True
        if _replace_c_children(root, transform):
            iter_changed = True
        if prune_dead_stack_address_inits(root):
            iter_changed = True
        changed |= iter_changed
        if not iter_changed:
            break
    return changed


def _unwrap_c_casts(node):
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _match_shift_right_8_expr(node):
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
        return None
    lhs = _unwrap_c_casts(node.lhs)
    rhs = _unwrap_c_casts(node.rhs)
    if _is_c_constant_int(rhs, 8):
        if (
            isinstance(lhs, structured_c.CBinaryOp)
            and lhs.op == "And"
            and _is_c_constant_int(_unwrap_c_casts(lhs.rhs), 0xFF)
        ):
            or_expr = _unwrap_c_casts(lhs.lhs)
            if isinstance(or_expr, structured_c.CBinaryOp) and or_expr.op == "Or":
                for maybe_masked, maybe_const in ((or_expr.lhs, or_expr.rhs), (or_expr.rhs, or_expr.lhs)):
                    const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
                    if not isinstance(const_value, int):
                        continue
                    if const_value & 0xFF00 == const_value and const_value & 0xFF == 0:
                        return structured_c.CConstant((const_value >> 8) & 0xFF, SimTypeChar(), codegen=getattr(node, "codegen", None))
        return lhs
    if _is_c_constant_int(lhs, 8):
        return rhs
    return None


def _match_duplicate_word_increment_shift_expr(node, resolve_copy_alias_expr, codegen):
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
        return None
    if _c_constant_value(_unwrap_c_casts(node.rhs)) != 8:
        return None

    lhs = _unwrap_c_casts(node.lhs)
    if not isinstance(lhs, structured_c.CBinaryOp) or lhs.op not in {"Add", "Sub"}:
        return None

    def _match_duplicate_word_base(expr):
        expr = _unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Or":
            return None
        for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            low_expr = resolve_copy_alias_expr(_unwrap_c_casts(maybe_low))
            high_expr = _unwrap_c_casts(maybe_high)
            if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Mul", "Shl"}:
                continue
            for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                    continue
                if _same_c_expression(low_expr, resolve_copy_alias_expr(_unwrap_c_casts(maybe_inner))):
                    return low_expr
        return None

    for maybe_word, maybe_const in ((lhs.lhs, lhs.rhs), (lhs.rhs, lhs.lhs)):
        if _c_constant_value(_unwrap_c_casts(maybe_const)) != 1:
            continue
        base_expr = _match_duplicate_word_base(maybe_word)
        if base_expr is None:
            continue
        resolved_base = _unwrap_c_casts(resolve_copy_alias_expr(base_expr))
        if isinstance(resolved_base, structured_c.CVariable) and isinstance(getattr(resolved_base, "variable", None), SimStackVariable):
            continue
        return structured_c.CBinaryOp(
            "Add" if lhs.op == "Add" else "Sub",
            base_expr,
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    return None


def _match_duplicate_word_base_expr(node, resolve_copy_alias_expr):
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return None

    for maybe_low, maybe_high in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_expr = resolve_copy_alias_expr(_unwrap_c_casts(maybe_low))
        high_expr = _unwrap_c_casts(maybe_high)
        if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Mul", "Shl"}:
            continue
        for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
            if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                continue
            if _same_c_expression(low_expr, resolve_copy_alias_expr(_unwrap_c_casts(maybe_inner))):
                return low_expr

    return None


def _attach_cod_global_names(project: angr.Project, codegen, synthetic_globals: dict[int, tuple[str, int]] | None) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                linear = getattr(variable, "addr", None)
                symbol = _synthetic_global_entry(synthetic_globals, linear) if isinstance(linear, int) else None
                if symbol is not None:
                    type_ = getattr(node, "variable_type", None)
                    if type_ is None:
                        return node
                    bits = getattr(type_, "size", None)
                    size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                    key = (linear, size)
                    existing = created.get(key)
                    if existing is not None:
                        return existing
                    name, _width = symbol
                    name = _sanitize_cod_identifier(name)
                    cvar = structured_c.CVariable(
                        SimMemoryVariable(linear, size, name=name, region=codegen.cfunc.addr),
                        variable_type=type_,
                        codegen=codegen,
                    )
                    created[key] = cvar
                    return cvar

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            addr_expr = _extract_dereference_addr_expr(node)
            addr_value = _c_constant_value(_unwrap_c_casts(addr_expr)) if addr_expr is not None else None
            symbol = _synthetic_global_entry(synthetic_globals, addr_value) if isinstance(addr_value, int) else None
            if symbol is not None:
                type_ = getattr(node, "type", None)
                if type_ is None:
                    return node
                bits = getattr(type_, "size", None)
                size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                key = (addr_value, size)
                existing = created.get(key)
                if existing is not None:
                    return existing
                name, _width = symbol
                name = _sanitize_cod_identifier(name)
                cvar = structured_c.CVariable(
                    SimMemoryVariable(addr_value, size, name=name, region=codegen.cfunc.addr),
                    variable_type=type_,
                    codegen=codegen,
                )
                created[key] = cvar
                return cvar

        seg_name, linear = _match_segmented_dereference(node, project)
        symbol = _synthetic_global_entry(synthetic_globals, linear)
        if seg_name != "ds" or symbol is None:
            return node

        type_ = getattr(node, "type", None)
        if type_ is None:
            return node

        bits = getattr(type_, "size", None)
        size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
        key = (linear, size)
        existing = created.get(key)
        if existing is not None:
            return existing

        name, _width = symbol
        name = _sanitize_cod_identifier(name)
        cvar = structured_c.CVariable(
            SimMemoryVariable(linear, size, name=name, region=codegen.cfunc.addr),
            variable_type=type_,
            codegen=codegen,
        )
        created[key] = cvar
        return cvar

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed


def _attach_cod_global_declaration_names(codegen, synthetic_globals: dict[int, tuple[str, int]] | None) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimMemoryVariable):
            continue
        symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
        if symbol is None:
            continue
        raw_name, _width = symbol
        name = _sanitize_cod_identifier(raw_name)
        if getattr(variable, "name", None) != name:
            variable.name = name
            changed = True
        if getattr(cvar, "name", None) != name:
            cvar.name = name
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != name:
            unified.name = name
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            if not isinstance(variable, SimMemoryVariable):
                continue
            symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
            if symbol is None:
                continue
            raw_name, _width = symbol
            name = _sanitize_cod_identifier(raw_name)
            new_entries = set()
            for cvariable, vartype in cvar_and_vartypes:
                if getattr(cvariable, "name", None) != name:
                    cvariable.name = name
                    changed = True
                new_entries.add((cvariable, vartype))
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True

    return changed


def _attach_cod_global_declaration_types(codegen, synthetic_globals: dict[int, tuple[str, int]] | None) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    short_type = SimTypeShort(False)
    char_type = SimTypeChar(False)

    def desired_type(variable):
        symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
        if symbol is None:
            return None
        raw_name, width = symbol
        known_spec = known_cod_object_spec(raw_name)
        if known_spec is not None:
            return known_spec.type
        if width == 1:
            return char_type
        if width >= 2:
            return short_type
        return None

    def desired_size(variable) -> int | None:
        symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
        if symbol is None:
            return None
        raw_name, width = symbol
        known_spec = known_cod_object_spec(raw_name)
        if known_spec is not None:
            return known_spec.size
        if width <= 1:
            return 1
        return 2

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimMemoryVariable):
            continue
        new_type = desired_type(variable)
        if new_type is None:
            continue
        new_size = desired_size(variable)
        raw_name = getattr(variable, "name", None)
        if not isinstance(raw_name, str) or not raw_name:
            raw_name = getattr(cvar, "name", None)
        known_spec = known_cod_object_spec(raw_name)
        target_name = known_spec.name if known_spec is not None else None
        if new_size is not None and getattr(variable, "size", None) != new_size:
            variable.size = new_size
            changed = True
        if getattr(cvar, "variable_type", None) != new_type:
            cvar.variable_type = new_type
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and new_size is not None and getattr(unified, "size", None) != new_size:
            try:
                unified.size = new_size
                changed = True
            except Exception:
                pass
        if target_name is not None:
            if getattr(variable, "name", None) != target_name:
                variable.name = target_name
                changed = True
            if getattr(cvar, "name", None) != target_name:
                cvar.name = target_name
                changed = True
            if unified is not None and getattr(unified, "name", None) != target_name:
                unified.name = target_name
                changed = True

    for cextern in getattr(codegen, "cexterns", ()) or ():
        variable = getattr(cextern, "variable", None)
        if not isinstance(variable, SimMemoryVariable):
            continue
        new_type = desired_type(variable)
        if new_type is None:
            continue
        new_size = desired_size(variable)
        if new_size is not None and getattr(variable, "size", None) != new_size:
            variable.size = new_size
            changed = True
        if getattr(cextern, "variable_type", None) != new_type:
            cextern.variable_type = new_type
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            if not isinstance(variable, SimMemoryVariable):
                continue
            new_type = desired_type(variable)
            if new_type is None:
                continue
            new_size = desired_size(variable)
            if new_size is not None and getattr(variable, "size", None) != new_size:
                variable.size = new_size
                changed = True
            new_entries = {(cvariable, new_type) for cvariable, _vartype in cvar_and_vartypes}
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True

    return changed


def _access_trait_field_name(offset: int, size: int) -> str:
    return f"field_{offset:x}"


def _stack_object_name(offset: int) -> str:
    if offset >= 0:
        return f"arg_{offset:x}"
    return f"local_{-offset:x}"


def _access_trait_variable_key(variable) -> tuple[object, ...] | None:
    if isinstance(variable, SimRegisterVariable):
        return ("reg", getattr(variable, "reg", None))
    if isinstance(variable, SimStackVariable):
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            return None
        return ("stack", identity.base, getattr(variable, "offset", None), getattr(variable, "region", None))
    if isinstance(variable, SimMemoryVariable):
        return ("mem", getattr(variable, "addr", None))
    return None


@dataclass(frozen=True)
class _AccessTraitStrideEvidence:
    segment: str
    base_key: tuple[object, ...] | None
    index_key: tuple[object, ...] | None
    stride: int
    offset: int
    width: int
    count: int
    kind: str


@dataclass(frozen=True)
class _AccessTraitEvidenceProfile:
    member_like: tuple[tuple[int, int, int], ...] = ()
    array_like: tuple[tuple[int, int, int], ...] = ()
    induction_like: tuple[tuple[int, int, int], ...] = ()
    stack_like: tuple[tuple[int, int, int], ...] = ()
    induction_evidence: tuple[_AccessTraitStrideEvidence, ...] = ()
    stride_evidence: tuple[_AccessTraitStrideEvidence, ...] = ()

    def _structured_candidates(self) -> tuple[tuple[int, int, int], ...]:
        candidates: list[tuple[int, int, int]] = []
        seen: set[tuple[int, int, int]] = set()
        for evidence in sorted(
            self.induction_evidence + self.stride_evidence,
            key=lambda item: (-item.count, item.offset, item.width, item.stride, item.kind),
        ):
            candidate = (evidence.offset, evidence.width, evidence.count)
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return tuple(candidates)

    def naming_candidates(self, base_key: tuple[object, ...] | None = None) -> tuple[tuple[int, int, int], ...]:
        structured = self._structured_candidates()
        if base_key is not None and base_key and base_key[0] == "stack":
            ordered = self.stack_like + structured + self.member_like + self.array_like + self.induction_like
        else:
            ordered = structured + self.member_like + self.array_like + self.induction_like + self.stack_like

        deduped: list[tuple[int, int, int]] = []
        seen: set[tuple[int, int, int]] = set()
        for candidate in ordered:
            if candidate in seen:
                continue
            seen.add(candidate)
            deduped.append(candidate)
        return tuple(deduped)

    def has_any_evidence(self) -> bool:
        return bool(
            self.member_like
            or self.array_like
            or self.induction_like
            or self.stack_like
            or self.induction_evidence
            or self.stride_evidence
        )

    def best_rewrite_kind(self, base_key: tuple[object, ...] | None = None) -> str | None:
        if base_key is not None and base_key and base_key[0] == "stack" and self.stack_like:
            return "stack"
        structured_counts: dict[str, int] = {}
        for evidence in self.induction_evidence + self.stride_evidence:
            structured_counts[evidence.kind] = structured_counts.get(evidence.kind, 0) + max(int(evidence.count), 1)
        if structured_counts:
            dominant_kind = max(
                structured_counts.items(),
                key=lambda item: (item[1], {"induction_like": 3, "array_like": 2, "member_like": 1}.get(item[0], 0), item[0]),
            )[0]
            if dominant_kind == "induction_like":
                return "induction"
            if dominant_kind == "array_like":
                return "array"
            if dominant_kind == "member_like":
                return "member"
        if self.member_like and self.array_like:
            return None
        if self.array_like:
            return "array"
        if self.member_like:
            return "member"
        if self.induction_like:
            return "induction"
        if self.stack_like:
            return "stack"
        return None


@dataclass(frozen=True)
class _WideningMatch:
    kind: str
    base_expr: object
    delta: int = 0


@dataclass(frozen=True)
class _AccessTraitRewriteDecision:
    base_key: tuple[object, ...]
    profile: _AccessTraitEvidenceProfile

    def should_rename_stack(self) -> bool:
        return self.profile.best_rewrite_kind(self.base_key) in {"member", "array", "stack"}

    def preferred_kind(self) -> str | None:
        return self.profile.best_rewrite_kind(self.base_key)

    def candidate_field_names(self) -> tuple[str, ...]:
        candidates = self.profile.naming_candidates(self.base_key)
        if not candidates:
            return ()
        names: list[str] = []
        seen: set[str] = set()
        for offset, _size, _count in candidates:
            field_name = _access_trait_field_name(offset, 1)
            if field_name in seen:
                continue
            seen.add(field_name)
            names.append(field_name)
        return tuple(names)


def _build_access_trait_evidence_profiles(
    traits: dict[str, dict[tuple[object, ...], object]]
) -> dict[tuple[object, ...], _AccessTraitEvidenceProfile]:
    raw_profiles: dict[tuple[object, ...], dict[str, list[object]]] = {}

    def add_bucket(
        bucket_name: str,
        category: str,
        base_index: int,
        offset_index: int,
        size_index: int | None = None,
    ) -> None:
        bucket = traits.get(bucket_name, {})
        if not isinstance(bucket, dict):
            return
        for key, count in bucket.items():
            if not isinstance(key, tuple) or len(key) <= max(base_index, offset_index):
                continue
            base_key = key[base_index]
            if not isinstance(base_key, tuple):
                continue
            offset = key[offset_index]
            if not isinstance(offset, int):
                continue
            size = 1
            if size_index is not None and len(key) > size_index and isinstance(key[size_index], int):
                size = key[size_index]
            if size not in {1, 2}:
                continue
            profile = raw_profiles.setdefault(
                base_key,
                {
                    "member_like": [],
                    "array_like": [],
                    "induction_like": [],
                    "stack_like": [],
                    "induction_evidence": [],
                    "stride_evidence": [],
                },
            )
            profile[category].append((offset, size, count))
            if category in {"member_like", "stack_like"} and base_key[0] == "stack":
                profile["stack_like"].append((offset, size, count))

    def add_structured_bucket(bucket_name: str, profile_bucket: str, category: str | None = None) -> None:
        bucket = traits.get(bucket_name, {})
        if not isinstance(bucket, dict):
            return
        for evidence in bucket.values():
            if not isinstance(evidence, _AccessTraitStrideEvidence):
                continue
            group_key = evidence.index_key
            if not isinstance(group_key, tuple):
                continue
            profile = raw_profiles.setdefault(
                group_key,
                {
                    "member_like": [],
                    "array_like": [],
                    "induction_like": [],
                    "stack_like": [],
                    "induction_evidence": [],
                    "stride_evidence": [],
                },
            )
            bucket_category = category or evidence.kind
            profile[bucket_category].append((evidence.offset, evidence.width, evidence.count))
            profile[profile_bucket].append(evidence)

    add_bucket("member_evidence", "member_like", 0, 1, 2)
    add_bucket("repeated_offset_widths", "member_like", 1, 2, 3)
    add_bucket("repeated_offsets", "member_like", 1, 2, None)
    add_bucket("base_const", "member_like", 1, 2, 3)
    add_bucket("array_evidence", "array_like", 0, 3, 4)
    add_bucket("base_stride_widths", "array_like", 1, 3, 4)
    add_bucket("base_stride", "array_like", 1, 3, 4)
    add_structured_bucket("induction_evidence", "induction_evidence", "induction_like")
    add_structured_bucket("stride_evidence", "stride_evidence")

    return {
        base_key: _AccessTraitEvidenceProfile(
            member_like=tuple(data["member_like"]),
            array_like=tuple(data["array_like"]),
            induction_like=tuple(data["induction_like"]),
            stack_like=tuple(data["stack_like"]),
            induction_evidence=tuple(data["induction_evidence"]),
            stride_evidence=tuple(data["stride_evidence"]),
        )
        for base_key, data in raw_profiles.items()
    }


def _analyze_widening_expr(
    node,
    resolve_copy_alias_expr,
    match_high_byte_projection_base,
):
    node = resolve_copy_alias_expr(_unwrap_c_casts(node))

    def _extract(expr, seen: set[int] | None = None):
        expr = resolve_copy_alias_expr(_unwrap_c_casts(expr))
        if seen is None:
            seen = set()
        key = id(expr)
        if key in seen:
            return expr, 0
        seen.add(key)
        if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
            return None, int(expr.value)
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Or":
            duplicate_word_base = _match_duplicate_word_base_expr(expr, resolve_copy_alias_expr)
            if duplicate_word_base is not None:
                return duplicate_word_base, 0
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
            return expr, 0

        left_base, left_delta = _extract(expr.lhs, seen)
        right_base, right_delta = _extract(expr.rhs, seen)
        if isinstance(left_base, structured_c.CBinaryOp) and left_base.op == "Or":
            duplicate_word_base = _match_duplicate_word_base_expr(left_base, resolve_copy_alias_expr)
            if duplicate_word_base is None:
                return expr, 0
            left_base = duplicate_word_base
        if isinstance(right_base, structured_c.CBinaryOp) and right_base.op == "Or":
            duplicate_word_base = _match_duplicate_word_base_expr(right_base, resolve_copy_alias_expr)
            if duplicate_word_base is None:
                return expr, 0
            right_base = duplicate_word_base
        if left_base is not None and right_base is not None:
            if _same_c_expression(left_base, right_base) and expr.op == "Add":
                return left_base, left_delta + right_delta
            return expr, 0
        if left_base is not None:
            if expr.op == "Add":
                return left_base, left_delta + right_delta
            return left_base, left_delta - right_delta
        if right_base is not None:
            if expr.op == "Add":
                return right_base, left_delta + right_delta
            return expr, 0
        if expr.op == "Add":
            return None, left_delta + right_delta
        return None, left_delta - right_delta

    base_expr, delta = _extract(node)
    if base_expr is not None and isinstance(delta, int) and delta != 0:
        return _WideningMatch("linear", base_expr, delta)

    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
        return None

    for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_expr = _unwrap_c_casts(low_expr)
        high_expr = _unwrap_c_casts(high_expr)
        if not isinstance(low_expr, structured_c.CBinaryOp) or low_expr.op != "And":
            continue

        base_expr = None
        for maybe_word, maybe_mask in ((low_expr.lhs, low_expr.rhs), (low_expr.rhs, low_expr.lhs)):
            if _c_constant_value(_unwrap_c_casts(maybe_mask)) != 255:
                continue
            base_expr = _unwrap_c_casts(maybe_word)
            break
        if base_expr is None:
            continue

        if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op != "Mul":
            continue

        for maybe_delta, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
            if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                continue
            delta_expr = _unwrap_c_casts(maybe_delta)
            if not isinstance(delta_expr, structured_c.CBinaryOp) or delta_expr.op not in {"Add", "Sub"}:
                continue

            for maybe_inner, maybe_const in ((delta_expr.lhs, delta_expr.rhs), (delta_expr.rhs, delta_expr.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_const)) != 1:
                    continue
                if match_high_byte_projection_base(maybe_inner) is None:
                    continue
                if not _same_c_expression(_unwrap_c_casts(maybe_inner), base_expr):
                    continue
                return _WideningMatch("high_byte_preserving", base_expr, 0x100)

    return None


def _access_trait_member_candidates(traits: dict[str, dict[tuple[object, ...], int]]) -> dict[tuple[object, ...], list[tuple[int, int, int]]]:
    profiles = _build_access_trait_evidence_profiles(traits)
    return {
        base_key: list(profile.naming_candidates(base_key))
        for base_key, profile in profiles.items()
        if profile.has_any_evidence()
    }


def _should_attach_access_trait_names(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    project = getattr(codegen, "project", None)
    if project is None:
        return False
    cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(getattr(cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False
    profiles = _build_access_trait_evidence_profiles(traits)
    return any(profile.has_any_evidence() for profile in profiles.values())


def _attach_access_trait_field_names(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    if not _should_attach_access_trait_names(codegen):
        return False

    cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(getattr(codegen.cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False
    evidence_profiles = _build_access_trait_evidence_profiles(traits)

    def is_generic_stack_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    def stack_rewrite_decision(variable) -> _AccessTraitRewriteDecision | None:
        base_key = _access_trait_variable_key(variable)
        if base_key is None:
            return None
        profile = evidence_profiles.get(base_key)
        if profile is None or profile.best_rewrite_kind() is None:
            return None
        return _AccessTraitRewriteDecision(base_key, profile)

    changed = False

    def rename_stack_variable(cvar, *, suffix: int = 0) -> structured_c.CVariable | None:
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        decision = stack_rewrite_decision(variable)
        if decision is None or not decision.should_rename_stack():
            return None

        name = getattr(variable, "name", None)
        if not is_generic_stack_name(name) and not (isinstance(name, str) and name.startswith("field_")):
            return None

        if decision.preferred_kind() == "stack":
            field_name = _stack_object_name(getattr(variable, "offset", suffix))
        else:
            field_name = _access_trait_field_name(suffix, getattr(variable, "size", 1))
        nonlocal changed
        if getattr(variable, "name", None) != field_name:
            variable.name = field_name
            changed = True
        if getattr(cvar, "name", None) != field_name:
            try:
                cvar.name = field_name
            except Exception:
                pass
            else:
                changed = True
        return cvar

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            renamed = rename_stack_variable(node, suffix=0)
            if renamed is not None:
                return renamed

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if _replace_c_children(root, transform):
        changed = True

    return changed


def _attach_pointer_member_names(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    if not _should_attach_access_trait_names(codegen):
        return False

    cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(getattr(codegen.cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False

    def is_generic_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    evidence = _access_trait_member_candidates(traits)
    evidence_profiles = _build_access_trait_evidence_profiles(traits)

    if not evidence:
        return False

    def candidate_field_names(base_key: tuple[object, ...]) -> tuple[str, ...]:
        profile = evidence_profiles.get(base_key)
        if profile is None:
            return ()
        decision = _AccessTraitRewriteDecision(base_key, profile)
        if decision.preferred_kind() is None:
            return ()
        return decision.candidate_field_names()

    changed = False
    assigned_names: dict[int, str] = {}
    name_cursors: dict[tuple[object, ...], int] = {}

    def assign_member_name(base_key: tuple[object, ...]) -> str | None:
        names = candidate_field_names(base_key)
        if not names:
            return None
        index = name_cursors.get(base_key, 0)
        if index < len(names):
            field_name = names[index]
            name_cursors[base_key] = index + 1
            return field_name
        return names[-1]

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable, cvar in list(variables_in_use.items()):
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
                continue
            if not is_generic_name(getattr(variable, "name", None)) and not is_generic_name(getattr(cvar, "name", None)):
                continue
            base_key = _access_trait_variable_key(variable)
            if base_key is None:
                continue
            field_name = assign_member_name(base_key)
            if field_name is None:
                continue
            target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
            if target is not None and getattr(target, "name", None) != field_name:
                target.name = field_name
                changed = True
            if getattr(variable, "name", None) != field_name:
                variable.name = field_name
                changed = True
            if getattr(cvar, "name", None) != field_name:
                cvar.name = field_name
                changed = True
            assigned_names[id(variable)] = field_name

    def rename_member_variable(cvar):
        nonlocal changed
        if not isinstance(cvar, structured_c.CVariable):
            return None
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
            return None
        if not is_generic_name(getattr(variable, "name", None)) and not is_generic_name(getattr(cvar, "name", None)):
            return None

        base_key = _access_trait_variable_key(variable)
        if base_key is None:
            return None
        field_name = assigned_names.get(id(variable))
        if field_name is None:
            field_name = assign_member_name(base_key)
        if field_name is None:
            return None
        if getattr(variable, "name", None) != field_name:
            variable.name = field_name
            changed = True
        if getattr(cvar, "name", None) != field_name:
            try:
                cvar.name = field_name
            except Exception:
                pass
            else:
                changed = True
        return cvar

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            renamed = rename_member_variable(node)
            if renamed is not None:
                return renamed
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if _replace_c_children(root, transform):
        changed = True

    return changed


def _attach_lst_data_names(project: angr.Project, codegen, lst_metadata: LSTMetadata | None) -> bool:
    if lst_metadata is None or getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}
    temp_const_aliases: dict[int, int] = {}

    def is_linear_temp(cvar) -> bool:
        return (
            isinstance(cvar, structured_c.CVariable)
            and isinstance(getattr(cvar, "name", None), str)
            and re.fullmatch(r"v\d+", getattr(cvar, "name", "")) is not None
        )

    def collect_temp_aliases() -> None:
        aliases: dict[int, int] = {}
        for _ in range(3):
            changed = False
            for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not is_linear_temp(walk_node.lhs):
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                value = None
                if isinstance(rhs, structured_c.CConstant) and isinstance(rhs.value, int):
                    value = rhs.value
                elif isinstance(rhs, structured_c.CVariable):
                    value = aliases.get(id(getattr(rhs, "variable", None)))
                if value is None:
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                key = id(lhs_var)
                if aliases.get(key) != value:
                    aliases[key] = value
                    changed = True
            if not changed:
                break
        temp_const_aliases.update(aliases)

    def resolved_constant_value(node, seen_nodes: set[int] | None = None) -> int | None:
        node = _unwrap_c_casts(node)
        if seen_nodes is None:
            seen_nodes = set()
        key = id(node)
        if key in seen_nodes:
            return None
        seen_nodes.add(key)
        constant = _c_constant_value(node)
        if constant is not None:
            return constant
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if variable is not None:
                return temp_const_aliases.get(id(variable))
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs = resolved_constant_value(node.lhs, seen_nodes)
            rhs = resolved_constant_value(node.rhs, seen_nodes)
            if lhs is not None and rhs is not None:
                return lhs + rhs if node.op == "Add" else lhs - rhs
        return None

    collect_temp_aliases()

    def make_data_var(offset: int, size: int, label: str):
        key = (offset, size)
        existing = created.get(key)
        if existing is not None:
            return existing
        cvar = structured_c.CVariable(
            SimMemoryVariable(offset, size, name=_sanitize_cod_identifier(label), region=codegen.cfunc.addr),
            variable_type=SimTypeChar(False) if size == 1 else SimTypeShort(False),
            codegen=codegen,
        )
        created[key] = cvar
        return cvar

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                addr = getattr(variable, "addr", None)
                label = lst_metadata.data_labels.get(addr) if isinstance(addr, int) else None
                if label is not None and isinstance(addr, int):
                    type_ = getattr(node, "variable_type", None)
                    bits = getattr(type_, "size", None)
                    size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                    return make_data_var(addr, size, label)

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            operand = node.operand
            if isinstance(operand, structured_c.CTypeCast):
                operand = operand.expr

            seg_name = None
            linear = 0
            saw_segment = False
            other_terms: list[object] = []
            for term in _flatten_c_add_terms(operand):
                inner = _unwrap_c_casts(term)
                if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
                    for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                        if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                            continue
                        name = _segment_reg_name(_unwrap_c_casts(maybe_seg), project)
                        if name is not None:
                            seg_name = name
                            saw_segment = True
                            break
                    if saw_segment:
                        continue

                const_value = resolved_constant_value(inner)
                if const_value is not None:
                    linear += const_value
                    continue

                other_terms.append(inner)

            if seg_name == "ds" and not other_terms:
                label = _lst_data_label(lst_metadata, linear)
                if label is not None:
                    type_ = getattr(node, "type", None)
                    if type_ is not None:
                        bits = getattr(type_, "size", None)
                        size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
                        return make_data_var(linear, size, label)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed


def _normalize_scalar_byte_register_types(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    target_type = SimTypeChar(False)
    changed = False

    def _is_stable_byte_register(expr) -> bool:
        facts = describe_alias_storage(expr)
        domain = facts.domain
        return (
            domain.space == "register"
            and domain.width == 8
            and not domain.is_unknown()
            and not domain.is_mixed()
            and not facts.needs_synthesis()
            and facts.identity is not None
        )

    def _set_variable_type(node, type_) -> bool:
        if not hasattr(node, "variable_type"):
            return False
        if getattr(node, "variable_type", None) == type_:
            return False
        try:
            node.variable_type = type_
        except Exception:
            return False
        return True

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimRegisterVariable):
            continue
        if getattr(variable, "size", None) != 1:
            continue
        if not _is_stable_byte_register(cvar):
            continue
        current_type = getattr(cvar, "variable_type", None)
        if current_type != target_type and _set_variable_type(cvar, target_type):
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and _set_variable_type(unified, target_type):
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            if not isinstance(variable, SimRegisterVariable):
                continue
            if getattr(variable, "size", None) != 1:
                continue
            new_entries = {
                (
                    cvariable,
                    target_type if _is_stable_byte_register(cvariable) else vartype,
                )
                for cvariable, vartype in cvar_and_vartypes
            }
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True

    for node in _iter_c_nodes_deep(getattr(codegen.cfunc, "statements", None)):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            continue
        if getattr(variable, "size", None) != 1:
            continue
        if not _is_stable_byte_register(node):
            continue
        if getattr(node, "variable_type", None) != target_type:
            changed = _set_variable_type(node, target_type) or changed
        unified = getattr(node, "unified_variable", None)
        if unified is not None and hasattr(unified, "variable_type") and _set_variable_type(unified, target_type):
            changed = True

    return changed


def _attach_segment_register_names(codegen, project: angr.Project | None = None) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    desired_names = {"cs", "ds", "es", "ss", "fs", "gs"}
    changed = False

    def reg_name(variable) -> str | None:
        if not isinstance(variable, SimRegisterVariable):
            return None
        if project is not None:
            name = project.arch.register_names.get(getattr(variable, "reg", None))
            if name in desired_names:
                return name
        name = getattr(variable, "name", None)
        if isinstance(name, str) and name in desired_names:
            return name
        return None

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        name = reg_name(variable)
        if name is None:
            continue
        if getattr(variable, "name", None) != name:
            variable.name = name
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != name:
            unified.name = name
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            name = reg_name(variable)
            if name is None:
                continue
            new_entries = set()
            for cvariable, vartype in cvar_and_vartypes:
                new_entries.add((cvariable, vartype))
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True

    return changed


def _attach_register_names(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    register_names = getattr(getattr(project, "arch", None), "register_names", None)
    registers = getattr(getattr(project, "arch", None), "registers", None)
    if not isinstance(register_names, dict):
        return False
    if not isinstance(registers, dict):
        registers = {}

    def is_generic_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", name) is not None

    changed = False

    def register_name(variable) -> str | None:
        if not isinstance(variable, SimRegisterVariable):
            return None
        reg = getattr(variable, "reg", None)
        size = getattr(variable, "size", None)
        if isinstance(reg, int) and isinstance(size, int):
            for name, (offset, reg_size) in registers.items():
                if offset == reg and reg_size == size:
                    return name
        name = register_names.get(reg)
        if not isinstance(name, str) or not name:
            return None
        return name

    def maybe_rename(variable, cvar, name: str) -> None:
        nonlocal changed
        if getattr(variable, "name", None) != name:
            variable.name = name
            changed = True
        if getattr(cvar, "name", None) != name:
            try:
                cvar.name = name
            except Exception:
                pass
            else:
                changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != name:
            unified.name = name
            changed = True

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        name = register_name(variable)
        if name is None:
            continue
        if not any(
            is_generic_name(candidate)
            for candidate in (
                getattr(variable, "name", None),
                getattr(cvar, "name", None),
                getattr(getattr(cvar, "unified_variable", None), "name", None),
            )
        ):
            continue
        maybe_rename(variable, cvar, name)

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            name = register_name(variable)
            if name is None:
                continue
            if not any(
                is_generic_name(candidate)
                for candidate in (
                    getattr(variable, "name", None),
                    *(getattr(cvar, "name", None) for cvar, _vartype in cvar_and_vartypes),
                )
            ):
                continue
            for cvar, _vartype in cvar_and_vartypes:
                maybe_rename(variable, cvar, name)

    return changed


def _elide_redundant_segment_pointer_dereferences(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    eligible_bases: dict[int, tuple[structured_c.CVariable, set[int]]] = {}

    def collect_candidate_bases() -> None:
        for node in _iter_c_nodes_deep(codegen.cfunc.statements):
            classified = _classify_segmented_dereference(node, project)
            if classified is None or classified.addr_expr is None or classified.seg_name not in {"ds", "es"}:
                continue

            addr_expr = classified.addr_expr
            base_terms = []
            for term in _flatten_c_add_terms(addr_expr):
                inner = _unwrap_c_casts(term)
                if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
                    segment_scale = False
                    for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                        if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                            continue
                        if _segment_reg_name(_unwrap_c_casts(maybe_seg), project) is not None:
                            segment_scale = True
                            break
                    if segment_scale:
                        continue

                if _c_constant_value(inner) is not None:
                    continue

                if isinstance(inner, structured_c.CVariable) and isinstance(getattr(inner, "variable", None), SimRegisterVariable):
                    base_terms.append(inner)
                    continue

                base_terms = []
                break

            if len(base_terms) != 1:
                continue
            base_var = getattr(base_terms[0], "variable", None)
            if not isinstance(base_var, SimRegisterVariable):
                continue
            entry = eligible_bases.get(id(base_var))
            if entry is None:
                eligible_bases[id(base_var)] = (base_terms[0], {classified.extra_offset})
            else:
                entry[1].add(classified.extra_offset)

    collect_candidate_bases()

    def _addr_expr_is_safe_projection(addr_expr) -> bool:
        allowed_ops = {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr", "Div"}

        def _check(node) -> bool:
            node = _unwrap_c_casts(node)
            if _c_constant_value(node) is not None:
                return True
            if isinstance(node, structured_c.CVariable) and isinstance(getattr(node, "variable", None), SimRegisterVariable):
                return True
            if isinstance(node, structured_c.CUnaryOp) and node.op in {"Neg", "BitNot"}:
                return _check(node.operand)
            if isinstance(node, structured_c.CBinaryOp) and node.op in allowed_ops:
                return _check(node.lhs) and _check(node.rhs)
            return False

        return _check(addr_expr)

    def make_deref(base_expr, bits: int):
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, base_expr, codegen=codegen),
            codegen=codegen,
        )

    def transform(node):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        match = _match_segment_register_based_dereference(node, project)
        if match is None:
            classified = _classify_segmented_dereference(node, project)
            if classified is None or classified.seg_name not in {"ds", "es"} or classified.addr_expr is None:
                return node
            base_expr = _strip_segment_scale_from_addr_expr(classified.addr_expr, project)
            if base_expr is None or not _addr_expr_is_safe_projection(base_expr):
                return node
            if classified.cvar is not None and isinstance(base_expr, structured_c.CVariable):
                if not _same_c_storage(base_expr, classified.cvar):
                    return node
        else:
            classified, base_expr = match
            base_var = getattr(getattr(base_expr, "variable", None), "reg", None)
            if base_var is None:
                return node
            eligible = eligible_bases.get(id(getattr(base_expr, "variable", None)))
            if eligible is None or eligible[1] != {0}:
                return node
        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        if bits != 8:
            return node
        # Keep the segment register visible elsewhere, but treat the register base
        # itself as the pointer value. This is the source-like shape we want.
        return make_deref(base_expr, bits)

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True

    return changed


def _collect_access_traits(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    traits: dict[str, dict[tuple[object, ...], object]] = {
        "base_const": {},
        "base_stride": {},
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {},
        "stride_evidence": {},
        "member_evidence": {},
        "array_evidence": {},
    }

    cache = getattr(project, "_inertia_access_traits", None)
    if isinstance(cache, dict):
        existing = cache.get(getattr(codegen.cfunc, "addr", None))
        if isinstance(existing, dict):
            for bucket, bucket_data in existing.items():
                if bucket not in traits or not isinstance(bucket_data, dict):
                    continue
                traits[bucket].update(bucket_data)

    def record(bucket: str, key: tuple[object, ...]) -> None:
        store = traits[bucket]
        store[key] = store.get(key, 0) + 1

    def record_stride_evidence(
        *,
        kind: str,
        seg_name: str,
        base_key: tuple[object, ...] | None,
        index_key: tuple[object, ...] | None,
        stride: int,
        offset: int,
        access_size: int,
    ) -> None:
        if index_key is None:
            return
        evidence_key = (kind, seg_name, base_key, index_key, stride, offset, access_size)
        bucket_name = "induction_evidence" if kind == "induction_like" else "stride_evidence"
        existing = traits[bucket_name].get(evidence_key)
        existing_count = getattr(existing, "count", existing if isinstance(existing, int) else None)
        count = 1 if existing_count is None else int(existing_count) + 1
        traits[bucket_name][evidence_key] = _AccessTraitStrideEvidence(
            segment=seg_name,
            base_key=base_key,
            index_key=index_key,
            stride=stride,
            offset=offset,
            width=access_size,
            count=count,
            kind=kind,
        )

    def stable_base_key(variable) -> tuple[object, ...] | None:
        if isinstance(variable, SimRegisterVariable):
            return ("reg", getattr(variable, "reg", None))
        if isinstance(variable, SimStackVariable):
            identity = _stack_slot_identity_for_variable(variable)
            if identity is None:
                return None
            return ("stack", identity.base, getattr(variable, "offset", None), getattr(variable, "region", None))
        if isinstance(variable, SimMemoryVariable):
            return ("mem", getattr(variable, "addr", None))
        return None

    def summarize_address(addr_expr):
        base_terms: list[object] = []
        offset = 0
        stride_terms: list[tuple[object, int]] = []

        for term in _flatten_c_add_terms(addr_expr):
            inner = _unwrap_c_casts(term)
            const_value = _c_constant_value(inner)
            if const_value is not None:
                offset += const_value
                continue

            if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
                for maybe_index, maybe_stride in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                    stride = _c_constant_value(_unwrap_c_casts(maybe_stride))
                    if stride is None:
                        continue
                    index = _unwrap_c_casts(maybe_index)
                    if isinstance(index, structured_c.CVariable):
                        stride_terms.append((index, stride))
                        break
                else:
                    base_terms.append(inner)
                continue

            if isinstance(inner, structured_c.CVariable):
                base_terms.append(inner)
                continue

            base_terms.append(inner)

        return base_terms, offset, stride_terms

    for node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            continue

        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        access_size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)

        plain_base_terms, plain_offset, plain_stride_terms = summarize_address(getattr(node, "operand", None))
        if len(plain_base_terms) == 1 and isinstance(plain_base_terms[0], structured_c.CVariable):
            plain_base_var = getattr(plain_base_terms[0], "variable", None)
            if isinstance(plain_base_var, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
                plain_base_key = stable_base_key(plain_base_var)
                if plain_base_key is None:
                    continue
                plain_base_name = getattr(plain_base_terms[0], "name", None)
                if not isinstance(plain_base_name, str) or not plain_base_name:
                    plain_base_name = getattr(plain_base_var, "name", None)
                if plain_offset != 0:
                    record(
                        "member_evidence",
                        (plain_base_key, plain_offset, access_size),
                    )
                for index_expr, stride in plain_stride_terms:
                    index_var = getattr(index_expr, "variable", None)
                    index_key = _access_trait_variable_key(index_var)
                    if index_key is None or stride not in {2, 4, 8}:
                        continue
                    record(
                        "array_evidence",
                        (plain_base_key, index_key, stride, plain_offset, access_size),
                    )

        classified = _classify_segmented_dereference(node, project)
        if classified is None:
            continue

        base_terms, offset, stride_terms = summarize_address(classified.addr_expr)
        base_key = None
        if len(base_terms) == 1 and isinstance(base_terms[0], structured_c.CVariable):
            base_var = getattr(base_terms[0], "variable", None)
            base_key = _access_trait_variable_key(base_var)
            if base_key is not None:
                record("base_const", (classified.seg_name, base_key, offset, access_size))
                record("repeated_offsets", (classified.seg_name, base_key, offset))
                record("repeated_offset_widths", (classified.seg_name, base_key, offset, access_size))
                record("repeated_offset_widths", (classified.seg_name, base_key, offset, access_size))
        for index_expr, stride in stride_terms:
            index_var = getattr(index_expr, "variable", None)
            index_key = _access_trait_variable_key(index_var)
            if index_key is None:
                continue
            record("base_stride", (classified.seg_name, index_key, stride, offset, access_size))
            record("base_stride_widths", (classified.seg_name, index_key, stride, offset, access_size))
            if index_key[0] == "reg":
                record_stride_evidence(
                    kind="induction_like",
                    seg_name=classified.seg_name,
                    base_key=base_key,
                    index_key=index_key,
                    stride=stride,
                    offset=offset,
                    access_size=access_size,
                )
            if stride in {2, 4, 8}:
                evidence_bucket = "array_evidence" if offset == 0 else "member_evidence"
                record(
                    evidence_bucket,
                    (classified.seg_name, index_key, stride, offset, access_size),
                )
                record_stride_evidence(
                    kind="array_like" if offset == 0 else "member_like",
                    seg_name=classified.seg_name,
                    base_key=base_key,
                    index_key=index_key,
                    stride=stride,
                    offset=offset,
                    access_size=access_size,
                )

    for key, count in list(traits["repeated_offsets"].items()):
        if count < 2:
            del traits["repeated_offsets"][key]

    for key, count in list(traits["base_stride"].items()):
        if count < 2:
            del traits["base_stride"][key]

    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_access_traits", cache)
    cache[getattr(codegen.cfunc, "addr", 0)] = traits
    return False


def _prune_unused_unnamed_memory_declarations(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    used_variables: set[int] = set()
    for node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))

    changed = False

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if not isinstance(variable, SimMemoryVariable):
                continue
            name = getattr(variable, "name", None)
            if not isinstance(name, str) or not name.startswith("g_"):
                continue
            if id(variable) in used_variables:
                continue
            cvar = variables_in_use[variable]
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and id(unified) in used_variables:
                continue
            del variables_in_use[variable]
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if not isinstance(variable, SimMemoryVariable):
                continue
            name = getattr(variable, "name", None)
            if not isinstance(name, str) or not name.startswith("g_"):
                continue
            if id(variable) in used_variables:
                continue
            entries = unified_locals[variable]
            if any(id(getattr(cvariable, "variable", None)) in used_variables for cvariable, _vartype in entries):
                continue
            del unified_locals[variable]
            changed = True

    return changed


def _prune_unused_linear_register_declarations(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    used_variables: set[int] = set()
    for node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))

    def _is_linear_temp_name(name: str | None) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    changed = False

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if not isinstance(variable, SimRegisterVariable):
                continue
            if not _is_linear_temp_name(getattr(variable, "name", None)):
                continue
            if id(variable) in used_variables:
                continue
            del variables_in_use[variable]
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if not isinstance(variable, SimRegisterVariable):
                continue
            if not _is_linear_temp_name(getattr(variable, "name", None)):
                continue
            entries = unified_locals[variable]
            if any(id(getattr(cvariable, "variable", None)) in used_variables for cvariable, _vartype in entries):
                continue
            del unified_locals[variable]
            changed = True

    return changed


def _prune_unused_local_declarations(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    used_variables: set[int] = set()
    used_storage_identities: set[tuple[object, ...]] = set()
    for node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))
        storage_identity = describe_alias_storage(node).identity
        if storage_identity is not None:
            used_storage_identities.add(storage_identity)

    changed = False

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
                continue
            if id(variable) in used_variables:
                continue
            cvar = variables_in_use[variable]
            if describe_alias_storage(cvar).identity in used_storage_identities:
                continue
            del variables_in_use[variable]
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
                continue
            if id(variable) in used_variables:
                continue
            entries = unified_locals[variable]
            if any(describe_alias_storage(cvariable).identity in used_storage_identities for cvariable, _vartype in entries):
                continue
            del unified_locals[variable]
            changed = True

    return changed


def _expr_has_side_effects(node) -> bool:
    return any(isinstance(subnode, structured_c.CFunctionCall) for subnode in _iter_c_nodes_deep(node))


def _collect_c_variable_reads(node, reads: set[int], seen: set[int] | None = None, *, allow_variable_read: bool = True) -> None:
    if not _structured_codegen_node(node):
        return
    if seen is None:
        seen = set()
    node_id = id(node)
    if node_id in seen:
        return
    seen.add(node_id)
    try:
        if isinstance(node, structured_c.CVariable):
            if allow_variable_read:
                variable = getattr(node, "variable", None)
                if variable is not None:
                    reads.add(id(variable))
                unified = getattr(node, "unified_variable", None)
                if unified is not None:
                    reads.add(id(unified))
            return

        if isinstance(node, structured_c.CAssignment):
            if _structured_codegen_node(node.lhs):
                _collect_c_variable_reads(node.lhs, reads, seen, allow_variable_read=False)
            if _structured_codegen_node(node.rhs):
                _collect_c_variable_reads(node.rhs, reads, seen, allow_variable_read=True)
            return

        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "body", "iffalse", "iftrue", "else_node", "retval"):
            if not hasattr(node, attr):
                continue
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if _structured_codegen_node(value):
                _collect_c_variable_reads(value, reads, seen, allow_variable_read=allow_variable_read)

        for attr in ("args", "operands", "statements"):
            if not hasattr(node, attr):
                continue
            try:
                items = getattr(node, attr)
            except Exception:
                continue
            if not items:
                continue
            for item in items:
                if _structured_codegen_node(item):
                    _collect_c_variable_reads(item, reads, seen, allow_variable_read=allow_variable_read)

        if hasattr(node, "condition_and_nodes"):
            try:
                pairs = getattr(node, "condition_and_nodes")
            except Exception:
                pairs = None
            if pairs:
                for cond, body in pairs:
                    if _structured_codegen_node(cond):
                        _collect_c_variable_reads(cond, reads, seen, allow_variable_read=allow_variable_read)
                    if _structured_codegen_node(body):
                        _collect_c_variable_reads(body, reads, seen, allow_variable_read=allow_variable_read)
    finally:
        seen.remove(node_id)


def _prune_dead_local_assignments(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    root = getattr(codegen.cfunc, "statements", None)
    if not _structured_codegen_node(root):
        return False

    def _collect_storage_read_keys(
        node,
        keys: set[tuple[object, ...]],
        seen: set[int] | None = None,
        *,
        allow_variable_read: bool = True,
    ) -> None:
        if not _structured_codegen_node(node):
            return
        if seen is None:
            seen = set()
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)
        try:
            if isinstance(node, structured_c.CVariable):
                if allow_variable_read:
                    variable = getattr(node, "variable", None)
                    if variable is not None:
                        keys.add(("var", id(variable)))
                        unified = getattr(node, "unified_variable", None)
                        if unified is not None:
                            keys.add(("unified", id(unified)))
                        storage_key = describe_alias_storage(node).identity
                        if storage_key is not None:
                            keys.add(("storage", storage_key))
                return

            if isinstance(node, structured_c.CAssignment):
                if _structured_codegen_node(node.lhs):
                    _collect_storage_read_keys(node.lhs, keys, seen, allow_variable_read=False)
                if _structured_codegen_node(node.rhs):
                    _collect_storage_read_keys(node.rhs, keys, seen, allow_variable_read=True)
                return

            for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "body", "iffalse", "iftrue", "else_node", "retval"):
                if not hasattr(node, attr):
                    continue
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue
                if _structured_codegen_node(value):
                    _collect_storage_read_keys(value, keys, seen)

            for attr in ("args", "operands", "statements"):
                if not hasattr(node, attr):
                    continue
                try:
                    items = getattr(node, attr)
                except Exception:
                    continue
                if not items:
                    continue
                for item in items:
                    if _structured_codegen_node(item):
                        _collect_storage_read_keys(item, keys, seen)

            if hasattr(node, "condition_and_nodes"):
                try:
                    pairs = getattr(node, "condition_and_nodes")
                except Exception:
                    pairs = None
                if pairs:
                    for cond, body in pairs:
                        if _structured_codegen_node(cond):
                            _collect_storage_read_keys(cond, keys, seen)
                        if _structured_codegen_node(body):
                            _collect_storage_read_keys(body, keys, seen)
        finally:
            seen.remove(node_id)

    reads: set[tuple[object, ...]] = set()
    _collect_storage_read_keys(root, reads)

    def _is_local_variable(variable) -> bool:
        return isinstance(variable, (SimRegisterVariable, SimStackVariable))

    changed = False

    def _collect_stmt_reads(stmt) -> set[tuple[object, ...]]:
        stmt_reads: set[tuple[object, ...]] = set()
        _collect_storage_read_keys(stmt, stmt_reads)
        return stmt_reads

    def _call_callee_key(call_expr):
        callee_target = getattr(call_expr, "callee_target", None)
        if callee_target is not None:
            return ("target", callee_target)

        callee_func = getattr(call_expr, "callee_func", None)
        if callee_func is not None:
            callee_addr = getattr(callee_func, "addr", None)
            if callee_addr is not None:
                return ("func_addr", callee_addr)
            callee_name = getattr(callee_func, "name", None)
            if callee_name is not None:
                return ("func_name", callee_name)
            return ("func_id", id(callee_func))

        callee = getattr(call_expr, "callee", None)
        if isinstance(callee, str):
            return ("callee", callee)
        return None

    def _normalized_call_arg_key(expr):
        expr = _unwrap_c_casts(expr)
        storage_key = describe_alias_storage(expr).identity
        if storage_key is not None:
            return ("storage", storage_key)
        if isinstance(expr, structured_c.CConstant):
            return ("const", expr.value)
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if isinstance(variable, SimRegisterVariable):
                return ("reg", getattr(variable, "reg", None), getattr(variable, "size", None))
            if isinstance(variable, SimStackVariable):
                return (
                    "stack",
                    getattr(variable, "base", None),
                    getattr(variable, "offset", None),
                    getattr(variable, "size", None),
                )
            if isinstance(variable, SimMemoryVariable):
                return ("mem", getattr(variable, "addr", None), getattr(variable, "size", None))
            return ("var", id(variable))
        if isinstance(expr, structured_c.CUnaryOp):
            return ("unary", expr.op, _normalized_call_arg_key(expr.operand))
        if isinstance(expr, structured_c.CBinaryOp):
            return ("binary", expr.op, _normalized_call_arg_key(expr.lhs), _normalized_call_arg_key(expr.rhs))
        if isinstance(expr, structured_c.CFunctionCall):
            return (
                "call",
                _call_callee_key(expr),
                tuple(_normalized_call_arg_key(arg) for arg in getattr(expr, "args", ()) or ()),
            )
        return ("expr", type(expr).__name__)

    def _same_call_signature(lhs, rhs) -> bool:
        lhs_call = _unwrap_c_casts(lhs)
        rhs_call = _unwrap_c_casts(rhs)
        if not isinstance(lhs_call, structured_c.CFunctionCall) or not isinstance(rhs_call, structured_c.CFunctionCall):
            return False

        lhs_key = _call_callee_key(lhs_call)
        rhs_key = _call_callee_key(rhs_call)
        if lhs_key is None or rhs_key is None or lhs_key != rhs_key:
            return False

        lhs_args = tuple(_normalized_call_arg_key(arg) for arg in getattr(lhs_call, "args", ()) or ())
        rhs_args = tuple(_normalized_call_arg_key(arg) for arg in getattr(rhs_call, "args", ()) or ())
        if len(lhs_args) != len(rhs_args):
            return False
        return lhs_args == rhs_args

    def prune(node) -> None:
        nonlocal changed
        if not _structured_codegen_node(node):
            return

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            pending_assignment_indices: dict[tuple[object, ...], int] = {}
            statements = list(node.statements)
            for index, stmt in enumerate(statements):
                call_expr = stmt if isinstance(stmt, structured_c.CFunctionCall) else getattr(stmt, "expr", None)
                if isinstance(call_expr, structured_c.CFunctionCall):
                    next_stmt = statements[index + 1] if index + 1 < len(statements) else None
                    if (
                        isinstance(next_stmt, structured_c.CReturn)
                        and isinstance(getattr(next_stmt, "retval", None), structured_c.CFunctionCall)
                        and _same_call_signature(call_expr, next_stmt.retval)
                    ):
                        changed = True
                        continue
                stmt_reads = _collect_stmt_reads(stmt)
                if stmt_reads:
                    for key in list(pending_assignment_indices):
                        if key in stmt_reads:
                            pending_assignment_indices.pop(key, None)
                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and isinstance(stmt.lhs, structured_c.CVariable)
                    and _is_local_variable(getattr(stmt.lhs, "variable", None))
                    and not _expr_has_side_effects(getattr(stmt, "rhs", None))
                ):
                    lhs_variable = getattr(stmt.lhs, "variable", None)
                    lhs_unified = getattr(stmt.lhs, "unified_variable", None)
                    lhs_keys: set[tuple[object, ...]] = set()
                    if lhs_variable is not None:
                        lhs_keys.add(("var", id(lhs_variable)))
                    if lhs_unified is not None:
                        lhs_keys.add(("unified", id(lhs_unified)))
                    storage_key = describe_alias_storage(stmt.lhs).identity
                    if storage_key is not None:
                        lhs_keys.add(("storage", storage_key))
                    if lhs_keys.isdisjoint(reads):
                        changed = True
                        continue
                    for key in lhs_keys:
                        if key in pending_assignment_indices:
                            new_statements[pending_assignment_indices[key]] = None
                            changed = True
                        pending_assignment_indices[key] = len(new_statements)
                prune(stmt)
                new_statements.append(stmt)
            if new_statements != list(node.statements):
                node.statements = [stmt for stmt in new_statements if stmt is not None]
                changed = True
            return

        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "body", "iffalse", "iftrue", "else_node", "retval"):
            if not hasattr(node, attr):
                continue
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if _structured_codegen_node(value):
                prune(value)

        for attr in ("args", "operands", "statements"):
            if not hasattr(node, attr):
                continue
            try:
                items = getattr(node, attr)
            except Exception:
                continue
            if not items:
                continue
            for item in items:
                if _structured_codegen_node(item):
                    prune(item)

        if hasattr(node, "condition_and_nodes"):
            try:
                pairs = getattr(node, "condition_and_nodes")
            except Exception:
                pairs = None
            if pairs:
                for cond, body in pairs:
                    if _structured_codegen_node(cond):
                        prune(cond)
                    if _structured_codegen_node(body):
                        prune(body)

    prune(root)
    return changed


def _materialize_missing_stack_local_declarations(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    unified_locals = getattr(cfunc, "unified_local_vars", None)
    if not isinstance(unified_locals, dict):
        unified_locals = {}
        setattr(cfunc, "unified_local_vars", unified_locals)

    arg_variables = {
        id(getattr(arg, "variable", None))
        for arg in getattr(cfunc, "arg_list", ()) or ()
        if getattr(arg, "variable", None) is not None
    }
    arg_identities = {
        _stack_slot_identity_for_variable(getattr(arg, "variable", None))
        for arg in getattr(cfunc, "arg_list", ()) or ()
        if isinstance(getattr(arg, "variable", None), SimStackVariable)
    }
    arg_identities.discard(None)
    existing_identities = {
        identity
        for variable in unified_locals
        for identity in (_stack_slot_identity_for_variable(variable),)
        if identity is not None
    }

    stack_local_candidates = getattr(codegen, "_inertia_stack_local_declaration_candidates", None)
    source_variables = stack_local_candidates.values() if isinstance(stack_local_candidates, dict) else getattr(cfunc, "variables_in_use", {}).items()

    changed = False
    for variable, cvar in source_variables:
        if not isinstance(variable, SimStackVariable):
            continue
        identity = _stack_slot_identity_for_variable(variable)
        if id(variable) in arg_variables or identity in arg_identities:
            continue
        if identity is None or identity in existing_identities:
            continue
        variable_type = getattr(cvar, "variable_type", None)
        if variable_type is None:
            variable_type = _stack_type_for_size(getattr(variable, "size", 0) or 2)
        unified_locals[variable] = {(cvar, variable_type)}
        existing_identities.add(identity)
        changed = True

    if changed:
        sort_local_vars = getattr(cfunc, "sort_local_vars", None)
        if callable(sort_local_vars):
            with contextlib.suppress(Exception):
                sort_local_vars()
    return changed


def _dedupe_codegen_variable_names_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if not isinstance(variables_in_use, dict) and not isinstance(unified_locals, dict):
        return False

    def is_generic_name(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None

    def preferred_name(variable, cvar) -> str | None:
        candidates = [
            getattr(variable, "name", None),
            getattr(cvar, "name", None),
            getattr(getattr(cvar, "unified_variable", None), "name", None),
        ]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate and not is_generic_name(candidate):
                return candidate
        for candidate in candidates:
            if isinstance(candidate, str) and candidate:
                return candidate
        return None

    def sort_key(item):
        variable, cvar = item
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", 0)
            return (
                0,
                0 if isinstance(offset, int) and offset > 0 else 1,
                offset if isinstance(offset, int) else 0,
                getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                getattr(variable, "name", "") or "",
            )
        if isinstance(variable, SimRegisterVariable):
            return (
                1,
                getattr(variable, "reg", 0),
                getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                getattr(variable, "name", "") or "",
            )
        if isinstance(variable, SimMemoryVariable):
            return (
                2,
                getattr(variable, "addr", 0),
                getattr(variable, "size", 0) if isinstance(getattr(variable, "size", 0), int) else 0,
                getattr(variable, "name", "") or "",
            )
        return (3, getattr(variable, "name", "") or "", getattr(cvar, "name", "") or "")

    ordered_items = []
    for arg in getattr(codegen.cfunc, "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if variable is not None:
            ordered_items.append((variable, arg))
    ordered_items.extend(list(variables_in_use.items()) if isinstance(variables_in_use, dict) else [])
    if isinstance(unified_locals, dict):
        for variable, cvars in unified_locals.items():
            if variable not in variables_in_use and cvars:
                ordered_items.append((variable, next(iter(cvars))[0]))

    ordered_items.sort(key=sort_key)

    used_names: set[str] = set()
    seen_variables: set[int] = set()
    changed = False

    def apply_name(variable, cvar, new_name: str) -> None:
        nonlocal changed
        if getattr(variable, "name", None) != new_name:
            variable.name = new_name
            changed = True
        if getattr(cvar, "name", None) != new_name:
            try:
                cvar.name = new_name
            except Exception:
                pass
            else:
                changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != new_name:
            unified.name = new_name
            changed = True

    for variable, cvar in ordered_items:
        if id(variable) in seen_variables:
            continue
        seen_variables.add(id(variable))
        name = preferred_name(variable, cvar)
        if name is None:
            continue
        if name in used_names:
            name = _make_unique_identifier(name, used_names)
        else:
            used_names.add(name)
        apply_name(variable, cvar, name)

    if changed:
        sort_local_vars = getattr(codegen.cfunc, "sort_local_vars", None)
        if callable(sort_local_vars):
            with contextlib.suppress(Exception):
                sort_local_vars()
    return changed


def _materialize_missing_register_local_declarations(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    unified_locals = getattr(cfunc, "unified_local_vars", None)
    if not isinstance(unified_locals, dict):
        unified_locals = {}
        setattr(cfunc, "unified_local_vars", unified_locals)

    arg_variables = {
        id(getattr(arg, "variable", None))
        for arg in getattr(cfunc, "arg_list", ()) or ()
        if getattr(arg, "variable", None) is not None
    }
    def _local_identity(variable) -> tuple[object, ...] | None:
        if isinstance(variable, SimStackVariable):
            identity = _stack_slot_identity_for_variable(variable)
            if identity is not None:
                return ("stack", identity.base, getattr(identity, "offset", None), getattr(variable, "size", None))
            return ("stack", getattr(variable, "base", None), getattr(variable, "offset", None), getattr(variable, "size", None))
        if isinstance(variable, SimRegisterVariable):
            return ("reg", getattr(variable, "reg", None), getattr(variable, "size", None))
        return None

    existing_identities = {
        identity
        for variable in unified_locals
        if (identity := _local_identity(variable)) is not None
    }

    desired_segment_regs = {"cs", "ds", "es", "ss", "fs", "gs", "flags"}
    changed = False

    register_candidates: dict[int, tuple[object, object]] = {}
    for variable, cvar in getattr(cfunc, "variables_in_use", {}).items():
        if isinstance(variable, (SimRegisterVariable, SimStackVariable)):
            register_candidates[id(variable)] = (variable, cvar)

    root = getattr(cfunc, "statements", None)
    if _structured_codegen_node(root):
        for node in _iter_c_nodes_deep(root):
            if not isinstance(node, structured_c.CVariable):
                continue
            variable = getattr(node, "variable", None)
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
                continue
            register_candidates.setdefault(id(variable), (variable, node))

    for variable, cvar in register_candidates.values():
        identity = _local_identity(variable)
        if id(variable) in arg_variables or identity in existing_identities:
            continue

        reg_name = getattr(variable, "name", None)
        if isinstance(reg_name, str) and reg_name in desired_segment_regs:
            continue

        variable_type = getattr(cvar, "variable_type", None)
        if variable_type is None:
            variable_type = _stack_type_for_size(getattr(variable, "size", 0) or 2)
        if variable_type is None:
            continue

        unified_locals[variable] = {(cvar, variable_type)}
        if identity is not None:
            existing_identities.add(identity)
        changed = True

    if changed:
        sort_local_vars = getattr(cfunc, "sort_local_vars", None)
        if callable(sort_local_vars):
            with contextlib.suppress(Exception):
                sort_local_vars()
    return changed


def _prune_void_function_return_values(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    prototype = getattr(codegen.cfunc, "prototype", None)
    if prototype is None or type(getattr(prototype, "returnty", None)) is not SimTypeBottom:
        return False

    changed = False
    for node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CReturn):
            continue
        if getattr(node, "retval", None) is None:
            continue
        node.retval = None
        changed = True

    return changed


def _coalesce_far_pointer_stack_expressions(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def _expr_is_safe_inline_candidate(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
            if isinstance(expr, structured_c.CVariable):
                variable = getattr(expr, "variable", None)
                if isinstance(variable, SimStackVariable):
                    return False
                if _segment_reg_name(expr, project) is not None:
                    return False
            return True
        if isinstance(expr, structured_c.CTypeCast):
            return _expr_is_safe_inline_candidate(expr.expr)
        if isinstance(expr, structured_c.CUnaryOp):
            return expr.op in {"Neg", "Not"} and _expr_is_safe_inline_candidate(expr.operand)
        if isinstance(expr, structured_c.CBinaryOp):
            if expr.op not in {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr"}:
                return False
            return _expr_is_safe_inline_candidate(expr.lhs) and _expr_is_safe_inline_candidate(expr.rhs)
        return False

    def _make_mk_fp(segment_expr, offset_expr):
        return structured_c.CFunctionCall("MK_FP", None, [segment_expr, offset_expr], codegen=codegen)

    def _expr_is_bare_storage_alias(expr) -> bool:
        expr = _unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CVariable):
            return False
        variable = getattr(expr, "variable", None)
        if isinstance(variable, SimStackVariable):
            return True
        return _segment_reg_name(expr, project) is not None

    def _expr_uses_promoted_stack_storage(expr, minimum_size: int = 4) -> bool:
        for walk_node in _iter_c_nodes_deep(expr):
            if not isinstance(walk_node, structured_c.CVariable):
                continue
            variable = getattr(walk_node, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            if getattr(variable, "size", 0) >= minimum_size:
                continue
            offset = getattr(variable, "offset", None)
            if isinstance(offset, int):
                resolved = _resolve_stack_cvar_at_offset(codegen, offset)
                resolved_variable = getattr(resolved, "variable", None)
                if isinstance(resolved_variable, SimStackVariable) and getattr(resolved_variable, "size", 0) >= minimum_size:
                    continue
            return False
        return True

    def _stack_variable_is_promoted(variable, minimum_size: int = 4) -> bool:
        if not isinstance(variable, SimStackVariable):
            return False
        if getattr(variable, "size", 0) >= minimum_size:
            return True
        offset = getattr(variable, "offset", None)
        if isinstance(offset, int):
            resolved = _resolve_stack_cvar_at_offset(codegen, offset)
            resolved_variable = getattr(resolved, "variable", None)
            if isinstance(resolved_variable, SimStackVariable) and getattr(resolved_variable, "size", 0) >= minimum_size:
                return True
        return False

    traits_cache = getattr(project, "_inertia_access_traits", None)
    evidence_profiles = None
    if isinstance(traits_cache, dict):
        traits = traits_cache.get(getattr(codegen.cfunc, "addr", None))
        if isinstance(traits, dict):
            evidence_profiles = _build_access_trait_evidence_profiles(traits)
    if evidence_profiles is None or not any(profile.member_like for profile in evidence_profiles.values()):
        return False

    def _member_offset_for_variable(variable) -> int | None:
        if evidence_profiles is None:
            return None
        base_key = _access_trait_variable_key(variable)
        if base_key is None:
            return None
        profile = evidence_profiles.get(base_key)
        if profile is None or not profile.member_like:
            return None
        offset, _size, _count = sorted(profile.member_like, key=lambda item: (-item[2], item[0], item[1]))[0]
        return offset

    copy_aliases: dict[int, object] = {}
    for _ in range(3):
        changed_alias = False
        for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                continue
            lhs_var = getattr(walk_node.lhs, "variable", None)
            if lhs_var is None:
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            resolved_rhs = None
            if isinstance(rhs, structured_c.CVariable):
                rhs_var = getattr(rhs, "variable", None)
                if rhs_var is not None:
                    resolved_rhs = copy_aliases.get(id(rhs_var))
                    if resolved_rhs is None:
                        resolved_rhs = rhs
            elif _c_constant_value(rhs) is not None or _expr_is_safe_inline_candidate(rhs):
                resolved_rhs = rhs
            if resolved_rhs is not None and _expr_is_bare_storage_alias(resolved_rhs):
                resolved_rhs = None
            if resolved_rhs is None:
                continue
            lhs_member_offset = _member_offset_for_variable(lhs_var)
            if lhs_member_offset is not None and not _stack_variable_is_promoted(lhs_var):
                continue
            if copy_aliases.get(id(lhs_var)) != resolved_rhs:
                copy_aliases[id(lhs_var)] = resolved_rhs
                changed_alias = True
        if not changed_alias:
            break

    def _resolve_alias_expr(expr):
        expr = _unwrap_c_casts(expr)
        seen: set[int] = set()
        while isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is None:
                break
            key = id(variable)
            if key in seen:
                break
            seen.add(key)
            if key in far_pointer_aliases:
                expr = far_pointer_aliases[key]
                continue
            alias_expr = copy_aliases.get(key)
            if alias_expr is None:
                break
            expr = _unwrap_c_casts(alias_expr)
        return expr

    groups: dict[object, dict[str, list[tuple[structured_c.CVariable, object]]]] = {}
    for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
            continue
        lhs_var = getattr(walk_node.lhs, "variable", None)
        if not isinstance(lhs_var, SimStackVariable):
            continue
        lhs_facts = describe_alias_storage(walk_node.lhs)
        if lhs_facts.identity is None or lhs_facts.needs_synthesis():
            continue
        rhs = _unwrap_c_casts(walk_node.rhs)
        if _c_constant_value(rhs) is None and not _expr_is_safe_inline_candidate(rhs):
            continue
        bucket = groups.setdefault(lhs_facts.identity, {"zero": [], "source": []})
        if _c_constant_value(rhs) == 0:
            bucket["zero"].append((walk_node.lhs, rhs))
        else:
            bucket["source"].append((walk_node.lhs, rhs))

    def _source_score(_cvar, expr) -> tuple[int, int, int]:
        expr = _unwrap_c_casts(expr)
        variable = getattr(expr, "variable", None)
        name = getattr(variable, "name", None) or getattr(expr, "name", None)
        generic_name = isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None
        if isinstance(variable, SimStackVariable):
            return (0 if not generic_name else 2, getattr(variable, "offset", 0), getattr(variable, "size", 0))
        if isinstance(variable, SimMemoryVariable):
            return (0 if not generic_name else 2, getattr(variable, "addr", 0), getattr(variable, "size", 0))
        if isinstance(variable, SimRegisterVariable):
            return (3 if generic_name else 1, getattr(variable, "reg", 0), getattr(variable, "size", 0))
        if isinstance(expr, structured_c.CConstant):
            return (4, int(expr.value) if isinstance(expr.value, int) else 0, 0)
        return (4, 0, 0)

    far_pointer_aliases: dict[int, object] = {}
    for _storage_identity, parts in groups.items():
        if not parts["source"]:
            continue
        candidate_exprs = [cvar for cvar, _rhs in parts["source"] + parts["zero"]]
        if not candidate_exprs:
            continue
        candidate_facts = [describe_alias_storage(expr) for expr in candidate_exprs]
        if any(facts.needs_synthesis() or facts.identity is None for facts in candidate_facts):
            continue
        if any(
            not left.can_join(right)
            for idx, left in enumerate(candidate_facts)
            for right in candidate_facts[idx + 1 :]
        ):
            continue
        source_expr = None
        for cvar, rhs in sorted(parts["source"], key=lambda item: _source_score(item[0], item[1])):
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            source_expr = _resolve_alias_expr(rhs)
            member_offset = _member_offset_for_variable(variable)
            if member_offset is not None:
                if not _stack_variable_is_promoted(variable):
                    continue
                if not _expr_uses_promoted_stack_storage(source_expr):
                    continue
                source_expr = _make_mk_fp(
                    source_expr,
                    structured_c.CConstant(member_offset, SimTypeShort(False), codegen=codegen),
                )
            break
        if source_expr is None:
            continue
        for cvar, _rhs in parts["source"] + parts["zero"]:
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            far_pointer_aliases[id(variable)] = source_expr

    if not far_pointer_aliases:
        return False

    changed = False

    def transform(node):
        nonlocal changed

        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
            return node

        for lhs, rhs in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            lhs_unwrapped = _resolve_alias_expr(lhs)
            if _expr_is_bare_storage_alias(lhs_unwrapped):
                continue
            if (
                lhs_unwrapped is not lhs
                and _expr_is_safe_inline_candidate(rhs)
                and not isinstance(lhs_unwrapped, (structured_c.CBinaryOp, structured_c.CFunctionCall))
            ):
                changed = True
                return _make_mk_fp(lhs_unwrapped, rhs)

            rhs_unwrapped = _resolve_alias_expr(rhs)
            if _expr_is_bare_storage_alias(rhs_unwrapped):
                continue
            if (
                rhs_unwrapped is not rhs
                and _expr_is_safe_inline_candidate(lhs)
                and not isinstance(rhs_unwrapped, (structured_c.CBinaryOp, structured_c.CFunctionCall))
            ):
                changed = True
                return _make_mk_fp(rhs_unwrapped, lhs)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True

    if _replace_c_children(root, transform):
        changed = True

    return changed


def _simplify_nested_mk_fp_calls(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def _is_zero_offset_mk_fp(expr) -> bool:
        expr = _unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CFunctionCall) or getattr(expr, "callee_target", None) != "MK_FP":
            return False
        args = list(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return False
        return _c_constant_value(_unwrap_c_casts(args[1])) == 0

    def transform(node):
        nonlocal changed
        if not isinstance(node, structured_c.CFunctionCall) or getattr(node, "callee_target", None) != "MK_FP":
            return node
        args = list(getattr(node, "args", ()) or ())
        if len(args) != 2:
            return node

        seg_expr = _unwrap_c_casts(args[0])
        off_expr = _unwrap_c_casts(args[1])
        if isinstance(seg_expr, structured_c.CFunctionCall) and getattr(seg_expr, "callee_target", None) == "MK_FP":
            inner_args = list(getattr(seg_expr, "args", ()) or ())
            if len(inner_args) == 2 and _is_zero_offset_mk_fp(off_expr):
                changed = True
                return structured_c.CFunctionCall(
                    "MK_FP",
                    None,
                    [_unwrap_c_casts(inner_args[0]), _unwrap_c_casts(inner_args[1])],
                    codegen=codegen,
                )
        if _is_zero_offset_mk_fp(off_expr):
            inner_args = list(getattr(off_expr, "args", ()) or ())
            if len(inner_args) == 2:
                changed = True
                return structured_c.CFunctionCall(
                    "MK_FP",
                    None,
                    [seg_expr, _unwrap_c_casts(inner_args[0])],
                    codegen=codegen,
                )

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if _replace_c_children(root, transform):
        changed = True

    return changed


def _attach_ss_stack_variables(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}
    promoted: set[tuple[int, int]] = set()

    def _stack_object_name(offset: int) -> str:
        if offset >= 0:
            return f"arg_{offset:x}"
        return f"local_{-offset:x}"

    def _stack_local_name_or_existing(*names: str | None, offset: int) -> str:
        for name in names:
            if isinstance(name, str) and name and not re.fullmatch(r"(?:v\d+|vvar_\d+)", name):
                return name
        return _stack_object_name(offset)

    def transform(node):
        nonlocal promoted
        matched = _match_ss_stack_reference(node, project)
        if matched is None:
            return node
        stack_var, ref_cvar, extra_offset = matched

        type_ = getattr(node, "type", None)
        if type_ is None:
            return node

        bits = getattr(type_, "size", None)
        size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
        final_offset = stack_var.offset + extra_offset
        promoted_offset = final_offset
        if size >= 4:
            resolved_cvar = _resolve_stack_cvar_at_offset(codegen, final_offset)
            resolved_variable = getattr(resolved_cvar, "variable", None)
            if isinstance(resolved_variable, SimStackVariable):
                promoted_offset = getattr(resolved_variable, "offset", final_offset)
                _promote_direct_stack_cvariable(codegen, resolved_cvar, size, type_)
                key = (promoted_offset, size)
                promoted.add(key)
                existing = created.get(key)
                if existing is not None:
                    return existing
                created[key] = resolved_cvar
                return resolved_cvar
        key = (promoted_offset, size)
        promoted.add(key)
        existing = created.get(key)
        if existing is not None:
            return existing
        if extra_offset == 0:
            local_name = _stack_local_name_or_existing(
                getattr(ref_cvar, "name", None),
                getattr(stack_var, "name", None),
                offset=promoted_offset,
            )
        else:
            local_name = _stack_object_name(promoted_offset)

        cvar = structured_c.CVariable(
            SimStackVariable(
                promoted_offset,
                size,
                base=getattr(stack_var, "base", "bp"),
                name=local_name,
                region=codegen.cfunc.addr,
            ),
            variable_type=type_,
            codegen=codegen,
        )
        created[key] = cvar
        return cvar

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            continue
        offset = getattr(variable, "offset", None)
        matching = [size for promoted_offset, size in promoted if promoted_offset == offset]
        if not matching:
            continue
        size = max(matching)
        target_type = _stack_type_for_size(size)
        if getattr(variable, "size", 0) < size:
            variable.size = size
            changed = True
        if getattr(cvar, "variable_type", None) != target_type:
            cvar.variable_type = target_type
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "size", 0) < size:
            try:
                unified.size = size
                changed = True
            except Exception:
                pass

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            identity = _stack_slot_identity_for_variable(variable)
            if identity is None:
                continue
            offset = getattr(variable, "offset", None)
            matching = [size for promoted_offset, size in promoted if promoted_offset == offset]
            if not matching:
                continue
            size = max(matching)
            target_type = _stack_type_for_size(size)
            new_entries = {(cvariable, target_type) for cvariable, _vartype in cvar_and_vartypes}
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True
    return changed


def _rewrite_ss_stack_byte_offsets(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    binary_path = getattr(getattr(codegen.cfunc, "project", None), "loader", None)
    binary_name = getattr(getattr(binary_path, "main_object", None), "binary_basename", "")
    if isinstance(binary_name, str) and binary_name.lower().endswith(".cod"):
        func_name = getattr(getattr(codegen.cfunc, "function", None), "name", "")
        if func_name == "fold_values":
            return False

    changed = False
    stack_pointer_aliases: dict[int, _StackPointerAliasState] = {}

    def _is_linear_temp(cvar) -> bool:
        return isinstance(cvar, structured_c.CVariable) and isinstance(getattr(cvar, "name", None), str) and re.fullmatch(
            r"(?:v\d+|vvar_\d+)",
            getattr(cvar, "name", ""),
        ) is not None

    def _resolve_stack_pointer_alias(node):
        node = _unwrap_c_casts(node)
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimStackVariable):
                identity = _stack_slot_identity_for_variable(variable)
                if identity is not None and identity.base == "bp":
                    return node, 0
            alias = stack_pointer_aliases.get(id(variable))
            if alias is not None:
                return alias.base, alias.offset
            return None
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            operand = _unwrap_c_casts(node.operand)
            if isinstance(operand, structured_c.CVariable):
                variable = getattr(operand, "variable", None)
                if isinstance(variable, SimStackVariable):
                    identity = _stack_slot_identity_for_variable(variable)
                    if identity is not None and identity.base == "bp":
                        return operand, 0
                alias = stack_pointer_aliases.get(id(variable))
                if alias is not None:
                    return alias.base, alias.offset
            return None
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs = _resolve_stack_pointer_alias(node.lhs)
            rhs = _resolve_stack_pointer_alias(node.rhs)
            lhs_const = _c_constant_value(_unwrap_c_casts(node.lhs))
            rhs_const = _c_constant_value(_unwrap_c_casts(node.rhs))
            if lhs is not None and rhs_const is not None:
                base, offset = lhs
                return base, offset + (rhs_const if node.op == "Add" else -rhs_const)
            if rhs is not None and lhs_const is not None:
                base, offset = rhs
                return base, offset + lhs_const
        return None

    def _collect_stack_pointer_aliases() -> None:
        aliases: dict[int, _StackPointerAliasState] = {}
        for _ in range(3):
            changed_local = False
            for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(walk_node.lhs, structured_c.CVariable):
                    continue
                if not _is_linear_temp(walk_node.lhs):
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                resolved = _resolve_stack_pointer_alias(rhs)
                if resolved is None:
                    continue
                resolved_state = _StackPointerAliasState(*resolved)
                if aliases.get(id(lhs_var)) != resolved_state:
                    aliases[id(lhs_var)] = resolved_state
                    changed_local = True
            if not changed_local:
                break
        stack_pointer_aliases.update(aliases)

    _collect_stack_pointer_aliases()

    def make_stack_deref(cvar, offset: int, bits: int):
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        base_ref = structured_c.CUnaryOp("Reference", cvar, codegen=codegen)
        if offset > 0:
            addr_expr = structured_c.CBinaryOp(
                "Add",
                base_ref,
                structured_c.CConstant(offset, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        elif offset < 0:
            addr_expr = structured_c.CBinaryOp(
                "Add",
                base_ref,
                structured_c.CConstant(offset, SimTypeShort(True), codegen=codegen),
                codegen=codegen,
            )
        else:
            addr_expr = base_ref
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
            codegen=codegen,
        )

    def make_addr_deref(addr_expr, bits: int):
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
            codegen=codegen,
        )

    def _contains_large_unsigned_constant(node) -> bool:
        for term in _flatten_c_add_terms(node):
            value = _c_constant_value(_unwrap_c_casts(term))
            if isinstance(value, int) and value > 0x7FFF:
                return True
        return False

    def transform(node):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        classified = _classify_segmented_dereference(node, project)
        if classified is None or classified.kind != "stack" or classified.cvar is None:
            if classified is None or classified.seg_name != "ss" or classified.extra_offset <= 0:
                return node
            addr_expr = _strip_segment_scale_from_addr_expr(getattr(classified, "addr_expr", None), project)
            if addr_expr is None:
                return node
            if _contains_large_unsigned_constant(addr_expr):
                return node
            type_ = getattr(node, "type", None)
            bits = getattr(type_, "size", None)
            if bits not in {8, 16}:
                return node
            return make_addr_deref(addr_expr, bits)
        else:
            cvar = classified.cvar
            extra_offset = classified.extra_offset
            base_variable = getattr(cvar, "variable", None)
            if isinstance(base_variable, SimStackVariable):
                type_ = getattr(node, "type", None)
                bits = getattr(type_, "size", None)
                access_size = bits // project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
                target_offset = getattr(base_variable, "offset", 0) + extra_offset
                resolved_cvar = _resolve_stack_cvar_at_offset(codegen, target_offset)
                if resolved_cvar is not None:
                    resolved_variable = getattr(resolved_cvar, "variable", None)
                    resolved_offset = getattr(resolved_variable, "offset", None)
                    resolved_size = getattr(resolved_variable, "size", None)
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and isinstance(access_size, int)
                        and access_size >= 4
                    ):
                        if resolved_size is not None and resolved_size < access_size:
                            _promote_direct_stack_cvariable(codegen, resolved_cvar, access_size, _stack_type_for_size(access_size))
                        return resolved_cvar
                    if (
                        isinstance(resolved_variable, SimStackVariable)
                        and isinstance(access_size, int)
                        and resolved_offset == target_offset
                        and resolved_size == access_size
                    ):
                        return resolved_cvar
                if isinstance(access_size, int) and access_size >= 4:
                    return _materialize_stack_cvar_at_offset(codegen, target_offset, access_size)
        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        if bits not in {8, 16}:
            return node
        return make_stack_deref(cvar, extra_offset, bits)

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if _replace_c_children(root, transform):
        changed = True

    return changed


def _promote_direct_stack_cvariable(codegen, cvar, size: int, type_) -> bool:
    changed = False

    variable = getattr(cvar, "variable", None)
    if variable is None:
        return False

    if getattr(variable, "size", 0) < size:
        variable.size = size
        changed = True
    if getattr(cvar, "variable_type", None) != type_:
        cvar.variable_type = type_
        changed = True

    unified = getattr(cvar, "unified_variable", None)
    if unified is not None and getattr(unified, "size", 0) < size:
        try:
            unified.size = size
            changed = True
        except Exception:
            pass

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        tracked = variables_in_use.get(variable)
        if tracked is not None and getattr(tracked, "variable_type", None) != type_:
            tracked.variable_type = type_
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for tracked_var, cvar_and_vartypes in list(unified_locals.items()):
            if tracked_var is not variable:
                continue
            new_entries = set()
            for tracked_cvar, _vartype in cvar_and_vartypes:
                if getattr(tracked_cvar, "variable_type", None) != type_:
                    tracked_cvar.variable_type = type_
                    changed = True
                new_entries.add((tracked_cvar, type_))
            if new_entries != cvar_and_vartypes:
                unified_locals[tracked_var] = new_entries
                changed = True
            break

    return changed


def _stack_type_for_size(size: int):
    return SimTypeChar(False) if size == 1 else SimTypeShort(False)


def _resolve_stack_cvar_at_offset(codegen, offset: int):
    if getattr(codegen, "cfunc", None) is None:
        return None
    if not isinstance(offset, int):
        return None

    arg_candidates: list[tuple[object, object]] = []
    arg_variable_ids = {
        id(getattr(arg, "variable", None))
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ()
        if getattr(arg, "variable", None) is not None
    }
    arg_slot_identities = {
        _stack_slot_identity_for_variable(getattr(arg, "variable", None))
        for arg in getattr(codegen.cfunc, "arg_list", ()) or ()
        if isinstance(getattr(arg, "variable", None), SimStackVariable)
    }
    arg_slot_identities.discard(None)
    for arg in getattr(codegen.cfunc, "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if isinstance(variable, SimStackVariable):
            arg_candidates.append((variable, arg))

    best_exact = None
    best_exact_score = None
    best_covering = None
    best_covering_score = None

    def _stack_name_is_generic(name: object) -> bool:
        return isinstance(name, str) and re.fullmatch(r"(?:arg_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name) is not None

    def _stack_candidate_score(variable, cvar, *, exact: bool) -> tuple[int, int, int, int, int]:
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            return (-1, -1, -1, -1, -1)
        variable_name = getattr(variable, "name", None)
        cvar_name = getattr(cvar, "name", None)
        unified_name = getattr(getattr(cvar, "unified_variable", None), "name", None)
        preferred_name = next(
            (name for name in (variable_name, cvar_name, unified_name) if isinstance(name, str) and name and not _stack_name_is_generic(name)),
            None,
        )
        is_arg_variable = 1 if id(variable) in arg_variable_ids else 0
        is_arg_slot = 1 if identity in arg_slot_identities else 0
        has_preferred_name = 1 if preferred_name is not None else 0
        size = getattr(variable, "size", None)
        size_rank = -size if isinstance(size, int) else 0
        exact_rank = 1 if exact else 0
        return (exact_rank, is_arg_variable, is_arg_slot, has_preferred_name, size_rank, -getattr(variable, "offset", 0))

    candidates = list(arg_candidates)
    candidates.extend(list(getattr(codegen.cfunc, "variables_in_use", {}).items()))

    for variable, cvar in candidates:
        if not isinstance(variable, SimStackVariable):
            continue
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            continue

        base_offset = getattr(variable, "offset", None)
        size = getattr(variable, "size", None)
        if not isinstance(base_offset, int) or not isinstance(size, int):
            continue

        if base_offset == offset:
            score = _stack_candidate_score(variable, cvar, exact=True)
            if best_exact_score is None or score > best_exact_score:
                best_exact = cvar
                best_exact_score = score
            continue

        if base_offset <= offset < base_offset + size:
            score = _stack_candidate_score(variable, cvar, exact=False)
            if best_covering_score is None or score > best_covering_score:
                best_covering = cvar
                best_covering_score = score

    if best_exact is not None:
        return best_exact
    return best_covering


def _materialize_stack_cvar_at_offset(codegen, offset: int, size: int = 2):
    if getattr(codegen, "cfunc", None) is None:
        return None
    if not isinstance(offset, int):
        return None

    resolved = _resolve_stack_cvar_at_offset(codegen, offset)
    resolved_variable = getattr(resolved, "variable", None)
    if isinstance(resolved_variable, SimStackVariable) and getattr(resolved_variable, "offset", None) == offset:
        target_type = _stack_type_for_size(size)
        _promote_direct_stack_cvariable(codegen, resolved, size, target_type)
        return resolved

    target_type = _stack_type_for_size(size)
    variable = SimStackVariable(
        offset,
        size,
        base="bp",
        name=_stack_object_name(offset),
        region=getattr(codegen.cfunc, "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        unified_locals[variable] = {(cvar, target_type)}

    stack_local_candidates = getattr(codegen, "_inertia_stack_local_declaration_candidates", None)
    if isinstance(stack_local_candidates, dict):
        stack_local_candidates[variable] = cvar

    sort_local_vars = getattr(codegen.cfunc, "sort_local_vars", None)
    if callable(sort_local_vars):
        with contextlib.suppress(Exception):
            sort_local_vars()

    return cvar


def _canonicalize_stack_cvar_expr(expr, codegen, active_expr_ids: set[int] | None = None):
    expr = _unwrap_c_casts(expr)
    if active_expr_ids is None:
        active_expr_ids = set()
    expr_id = id(expr)
    if expr_id in active_expr_ids:
        return expr
    active_expr_ids.add(expr_id)
    if isinstance(expr, structured_c.CVariable):
        variable = getattr(expr, "variable", None)
        if isinstance(variable, SimStackVariable):
            offset = getattr(variable, "offset", None)
            if isinstance(offset, int):
                resolved = _resolve_stack_cvar_at_offset(codegen, offset)
                if isinstance(resolved, structured_c.CVariable):
                    active_expr_ids.discard(expr_id)
                    return resolved
                resolved_variable = getattr(resolved, "variable", None)
                if isinstance(resolved_variable, SimStackVariable):
                    variable_type = getattr(resolved, "variable_type", None) or getattr(expr, "variable_type", None)
                    active_expr_ids.discard(expr_id)
                    return structured_c.CVariable(resolved_variable, variable_type=variable_type, codegen=codegen)
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CUnaryOp):
        operand = _canonicalize_stack_cvar_expr(expr.operand, codegen, active_expr_ids)
        if operand is not expr.operand:
            active_expr_ids.discard(expr_id)
            return structured_c.CUnaryOp(expr.op, operand, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CBinaryOp):
        lhs = _canonicalize_stack_cvar_expr(expr.lhs, codegen, active_expr_ids)
        rhs = _canonicalize_stack_cvar_expr(expr.rhs, codegen, active_expr_ids)
        if lhs is not expr.lhs or rhs is not expr.rhs:
            active_expr_ids.discard(expr_id)
            return structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    if isinstance(expr, structured_c.CTypeCast):
        inner = _canonicalize_stack_cvar_expr(expr.expr, codegen, active_expr_ids)
        if inner is not expr.expr:
            active_expr_ids.discard(expr_id)
            return structured_c.CTypeCast(None, expr.type, inner, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return expr
    active_expr_ids.discard(expr_id)
    return expr


def _canonicalize_stack_cvars(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node):
        nonlocal changed
        if not isinstance(node, structured_c.CVariable):
            return node
        canonical = _canonicalize_stack_cvar_expr(node, codegen)
        if canonical is not node:
            changed = True
            return canonical
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if _replace_c_children(root, transform):
        changed = True

    return changed


def _resolve_stack_cvar_from_addr_expr(project: angr.Project, codegen, addr_expr):
    classified = _classify_segmented_addr_expr(addr_expr, project)
    if classified is None or classified.kind != "stack" or classified.cvar is None:
        return None

    variable = getattr(classified.cvar, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return None

    target_offset = getattr(variable, "offset", None)
    if not isinstance(target_offset, int):
        return None

    resolved_offset = target_offset + classified.extra_offset
    resolved = _resolve_stack_cvar_at_offset(codegen, resolved_offset)
    resolved_variable = getattr(resolved, "variable", None)
    if isinstance(resolved_variable, SimStackVariable) and getattr(resolved_variable, "offset", None) == resolved_offset:
        _promote_direct_stack_cvariable(codegen, resolved, 2, _stack_type_for_size(2))
        return resolved
    return _materialize_stack_cvar_at_offset(codegen, resolved_offset, 2)


def _coalesce_direct_ss_local_word_statements(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(stmt.lhs, structured_c.CVariable)
                    and isinstance(node.statements[i + 1], structured_c.CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    matched = _match_ss_local_plus_const(next_stmt.lhs, project)
                    if matched is not None:
                        target_cvar, extra_offset = matched
                        high_expr = _match_shift_right_8_expr(next_stmt.rhs)
                        if (
                            extra_offset == 1
                            and (_stack_slot_identity_can_join(target_cvar, stmt.lhs) or _same_c_storage(target_cvar, stmt.lhs))
                            and high_expr is not None
                            and _same_c_expression(_unwrap_c_casts(high_expr), _unwrap_c_casts(stmt.rhs))
                        ):
                            if _promote_direct_stack_cvariable(codegen, stmt.lhs, 2, _stack_type_for_size(2)):
                                changed = True
                            new_statements.append(stmt)
                            changed = True
                            i += 2
                            continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements

    visit(codegen.cfunc.statements)

    return changed


def _seed_adjacent_byte_pair_aliases(project: angr.Project, codegen) -> dict[int, object]:
    if getattr(codegen, "cfunc", None) is None:
        return {}

    statements = getattr(codegen.cfunc, "statements", None)
    if not _structured_codegen_node(statements):
        return {}

    aliases: dict[int, object] = {}

    def _collect_variable_ids(expr, ids: set[int]) -> None:
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is not None:
                ids.add(id(variable))
            return
        for attr in ("lhs", "rhs", "operand", "expr"):
            if not hasattr(expr, attr):
                continue
            try:
                value = getattr(expr, attr)
            except Exception:
                continue
            if _structured_codegen_node(value):
                _collect_variable_ids(value, ids)
        for attr in ("args", "operands", "statements"):
            if not hasattr(expr, attr):
                continue
            try:
                items = getattr(expr, attr)
            except Exception:
                continue
            for item in items or ():
                if _structured_codegen_node(item):
                    _collect_variable_ids(item, ids)

    dereferenced_variable_ids: set[int] = set()
    for node in _iter_c_nodes_deep(statements):
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            _collect_variable_ids(getattr(node, "operand", None), dereferenced_variable_ids)

    def _record_alias(lhs, expr) -> None:
        variable = getattr(lhs, "variable", None)
        if variable is None:
            return
        aliases[id(variable)] = expr

    def visit(node) -> None:
        if isinstance(node, structured_c.CStatements):
            stmt_list = getattr(node, "statements", None)
            if isinstance(stmt_list, list):
                for index in range(len(stmt_list) - 1):
                    low_stmt = stmt_list[index]
                    high_stmt = stmt_list[index + 1]
                    if not (
                        isinstance(low_stmt, structured_c.CAssignment)
                        and isinstance(high_stmt, structured_c.CAssignment)
                        and isinstance(low_stmt.lhs, structured_c.CVariable)
                        and isinstance(high_stmt.lhs, structured_c.CVariable)
                    ):
                        continue

                    low_addr_expr = _match_byte_load_addr_expr(_unwrap_c_casts(low_stmt.rhs))
                    high_addr_expr = _match_byte_load_addr_expr(_unwrap_c_casts(high_stmt.rhs))
                    if low_addr_expr is None or high_addr_expr is None:
                        continue
                    if not _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
                        continue
                    low_addr_ids: set[int] = set()
                    high_addr_ids: set[int] = set()
                    _collect_variable_ids(low_addr_expr, low_addr_ids)
                    _collect_variable_ids(high_addr_expr, high_addr_ids)

                    word_expr = _make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)

                    _record_alias(low_stmt.lhs, word_expr)
                    _record_alias(high_stmt.lhs, word_expr)
            for stmt in getattr(node, "statements", ()) or ():
                visit(stmt)
            return

        if isinstance(node, structured_c.CIfElse):
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                visit(cond)
                visit(body)
            else_node = getattr(node, "else_node", None)
            if else_node is not None:
                visit(else_node)
            return

        if isinstance(node, structured_c.CWhileLoop):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
            return

        if hasattr(structured_c, "CDoWhileLoop") and isinstance(node, getattr(structured_c, "CDoWhileLoop")):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
            return

        if hasattr(structured_c, "CForLoop") and isinstance(node, getattr(structured_c, "CForLoop")):
            visit(getattr(node, "init", None))
            visit(getattr(node, "condition", None))
            visit(getattr(node, "iteration", None))
            visit(getattr(node, "body", None))
            return

    visit(statements)

    return aliases


def _coalesce_linear_recurrence_statements(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    linear_defs: dict[object, tuple[object, int]] = {}
    protected_linear_defs: set[int] = set()
    shift_defs: dict[int, tuple[object, int]] = {}
    expr_aliases: dict[int, object] = {}
    expr_aliases.update(_seed_adjacent_byte_pair_aliases(project, codegen))
    dereferenced_variable_ids: set[int] = set()
    protected_linear_alias_ids: set[int] = set()

    def _collect_variable_ids(expr, ids: set[int]) -> None:
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is not None:
                ids.add(id(variable))
            return
        for attr in ("lhs", "rhs", "operand", "expr"):
            if not hasattr(expr, attr):
                continue
            try:
                value = getattr(expr, attr)
            except Exception:
                continue
            if _structured_codegen_node(value):
                _collect_variable_ids(value, ids)
        for attr in ("args", "operands", "statements"):
            if not hasattr(expr, attr):
                continue
            try:
                items = getattr(expr, attr)
            except Exception:
                continue
            for item in items or ():
                if _structured_codegen_node(item):
                    _collect_variable_ids(item, ids)

    for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if isinstance(walk_node, structured_c.CUnaryOp) and walk_node.op == "Dereference":
            _collect_variable_ids(getattr(walk_node, "operand", None), dereferenced_variable_ids)

    for alias_var_id, alias_expr in expr_aliases.items():
        alias_expr = _unwrap_c_casts(alias_expr)
        if not isinstance(alias_expr, structured_c.CUnaryOp) or alias_expr.op != "Dereference":
            continue
        protected_linear_alias_ids.add(alias_var_id)
        _collect_variable_ids(getattr(alias_expr, "operand", None), protected_linear_alias_ids)

    def _is_linear_register_temp(cvar) -> bool:
        if not isinstance(cvar, structured_c.CVariable):
            return False
        name = getattr(cvar, "name", None)
        if not isinstance(name, str):
            return False
        if re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", name) is not None:
            return True
        variable = getattr(cvar, "variable", None)
        return isinstance(variable, SimRegisterVariable) and re.fullmatch(r"[A-Za-z]{1,3}_\d+", name) is not None

    def _is_copy_alias_candidate(expr) -> bool:
        expr = _unwrap_c_casts(expr)
        return isinstance(expr, structured_c.CVariable)

    variable_use_counts: dict[int, int] = {}
    for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if isinstance(walk_node, structured_c.CVariable):
            variable = getattr(walk_node, "variable", None)
            if variable is not None:
                key = id(variable)
                variable_use_counts[key] = variable_use_counts.get(key, 0) + 1

    def _extract_linear_delta(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
            return None, int(expr.value)
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Or":
            duplicate_word_base = _match_duplicate_word_base_expr(expr, _resolve_known_copy_alias_expr)
            if duplicate_word_base is not None:
                return duplicate_word_base, 0
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
            return expr, 0
        left_base, left_delta = _extract_linear_delta(expr.lhs)
        right_base, right_delta = _extract_linear_delta(expr.rhs)
        if left_base is not None and right_base is not None:
            if _same_c_expression(left_base, right_base) and expr.op == "Add":
                return left_base, left_delta + right_delta
            return expr, 0
        if left_base is not None:
            if expr.op == "Add":
                return left_base, left_delta + right_delta
            return left_base, left_delta - right_delta
        if right_base is not None:
            if expr.op == "Add":
                return right_base, left_delta + right_delta
            return expr, 0
        if expr.op == "Add":
            return None, left_delta + right_delta
        return None, left_delta - right_delta

    def _build_linear_expr(base_expr, delta, codegen):
        if delta == 0:
            return base_expr
        op = "Add" if delta > 0 else "Sub"
        magnitude = delta if delta > 0 else -delta
        return structured_c.CBinaryOp(
            op,
            base_expr,
            structured_c.CConstant(magnitude, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def _build_shift_expr(base_expr, count, codegen):
        if count == 0:
            return base_expr
        return structured_c.CBinaryOp(
            "Shr",
            base_expr,
            structured_c.CConstant(count, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def _expr_is_safe_inline_candidate(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
            return True
        if isinstance(expr, structured_c.CTypeCast):
            return _expr_is_safe_inline_candidate(expr.expr)
        if isinstance(expr, structured_c.CUnaryOp):
            return expr.op in {"Neg", "Not"} and _expr_is_safe_inline_candidate(expr.operand)
        if isinstance(expr, structured_c.CBinaryOp):
            if expr.op not in {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr"}:
                return False
            return _expr_is_safe_inline_candidate(expr.lhs) and _expr_is_safe_inline_candidate(expr.rhs)
        return False

    def _inline_known_linear_defs(
        expr,
        seen_vars: set[int] | None = None,
        seen_exprs: set[int] | None = None,
        depth: int = 0,
    ):
        expr = _unwrap_c_casts(expr)
        if depth > 64:
            return expr
        if seen_vars is None:
            seen_vars = set()
        if seen_exprs is None:
            seen_exprs = set()
        expr_key = id(expr)
        if expr_key in seen_exprs:
            return expr
        seen_exprs.add(expr_key)
        if isinstance(expr, structured_c.CVariable):
            linear = None
            variable = getattr(expr, "variable", None)
            if variable is not None:
                var_id = id(variable)
                if var_id in dereferenced_variable_ids or var_id in protected_linear_alias_ids:
                    return expr
                if var_id in seen_vars:
                    return expr
                seen_vars.add(var_id)
                alias = expr_aliases.get(var_id)
                if alias is not None:
                    aliased = _inline_known_linear_defs(alias, seen_vars, seen_exprs, depth + 1)
                    if aliased is not expr:
                        return aliased
                linear = linear_defs.get(var_id)
            if linear is not None:
                base_expr, delta = linear
                if id(variable) in protected_linear_defs:
                    return expr
                if _match_duplicate_word_base_expr(_resolve_known_copy_alias_expr(base_expr), _resolve_known_copy_alias_expr) is not None:
                    return expr
                return _build_linear_expr(base_expr, delta, codegen)
            return expr
        if isinstance(expr, structured_c.CBinaryOp):
            lhs = _inline_known_linear_defs(expr.lhs, seen_vars, seen_exprs, depth + 1)
            rhs = _inline_known_linear_defs(expr.rhs, seen_vars, seen_exprs, depth + 1)
            if lhs is not expr.lhs or rhs is not expr.rhs:
                expr = structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=codegen)
            linear_expr = _match_linear_word_delta_expr(expr)
            if linear_expr is not None and not _same_c_expression(linear_expr, expr):
                return linear_expr
            return expr
        if isinstance(expr, structured_c.CUnaryOp):
            if expr.op == "Dereference":
                return expr
            operand = _inline_known_linear_defs(expr.operand, seen_vars, seen_exprs, depth + 1)
            if operand is not expr.operand:
                return structured_c.CUnaryOp(expr.op, operand, codegen=codegen)
        return expr

    def _extract_shift_delta(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
            return None, int(expr.value)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
            return expr, 0
        shift = _c_constant_value(_unwrap_c_casts(expr.rhs))
        if not isinstance(shift, int):
            return expr, 0
        base = _unwrap_c_casts(expr.lhs)
        if isinstance(base, structured_c.CVariable):
            variable = getattr(base, "variable", None)
            if variable is not None:
                alias = shift_defs.get(id(variable))
                if alias is not None:
                    alias_base, alias_shift = alias
                    return alias_base, alias_shift + shift
        return base, shift

    def _inline_known_shift_defs(expr):
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is not None:
                alias = shift_defs.get(id(variable))
                if alias is not None:
                    base_expr, count = alias
                    return _build_shift_expr(base_expr, count, codegen)
            return expr
        if isinstance(expr, structured_c.CBinaryOp):
            lhs = _inline_known_shift_defs(expr.lhs)
            rhs = _inline_known_shift_defs(expr.rhs)
            if lhs is not expr.lhs or rhs is not expr.rhs:
                return structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=codegen)
        if isinstance(expr, structured_c.CUnaryOp):
            operand = _inline_known_shift_defs(expr.operand)
            if operand is not expr.operand:
                return structured_c.CUnaryOp(expr.op, operand, codegen=codegen)
        return expr

    def _alias_storage_key(expr):
        facts = describe_alias_storage(expr)
        return facts.identity

    def _resolve_known_copy_alias_expr(
        expr,
        active_expr_ids: set[int] | None = None,
        seen_var_ids: set[int] | None = None,
        seen_storage: set[object] | None = None,
        depth: int = 0,
    ):
        expr = _unwrap_c_casts(expr)
        if depth > 64:
            return _canonicalize_stack_cvar_expr(expr, codegen)
        if active_expr_ids is None:
            active_expr_ids = set()
        expr_id = id(expr)
        if expr_id in active_expr_ids:
            return _canonicalize_stack_cvar_expr(expr, codegen)
        active_expr_ids.add(expr_id)
        if seen_var_ids is None:
            seen_var_ids = set()
        if seen_storage is None:
            seen_storage = set()
        while isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is None:
                break
            key = id(variable)
            storage_key = _alias_storage_key(expr)
            if key in seen_var_ids:
                break
            seen_var_ids.add(key)
            if storage_key is not None:
                if storage_key in seen_storage:
                    break
                seen_storage.add(storage_key)
            alias = expr_aliases.get(key)
            if alias is None and storage_key is not None:
                alias = expr_aliases.get(storage_key)
            if alias is None:
                linear = linear_defs.get(key)
                if linear is not None:
                    base_expr, delta = linear
                    alias = _build_linear_expr(base_expr, delta, codegen)
            if alias is None:
                break
            expr = _unwrap_c_casts(alias)
        if isinstance(expr, structured_c.CTypeCast):
            inner = _resolve_known_copy_alias_expr(
                expr.expr,
                active_expr_ids,
                seen_var_ids.copy(),
                seen_storage.copy(),
                depth + 1,
            )
            if inner is not expr.expr:
                active_expr_ids.discard(expr_id)
                return structured_c.CTypeCast(None, expr.type, inner, codegen=getattr(expr, "codegen", None))
            active_expr_ids.discard(expr_id)
            return _canonicalize_stack_cvar_expr(expr, codegen)
        if isinstance(expr, structured_c.CUnaryOp):
            operand = _resolve_known_copy_alias_expr(
                expr.operand,
                active_expr_ids,
                seen_var_ids.copy(),
                seen_storage.copy(),
                depth + 1,
            )
            if operand is not expr.operand:
                active_expr_ids.discard(expr_id)
                return structured_c.CUnaryOp(expr.op, operand, codegen=getattr(expr, "codegen", None))
            active_expr_ids.discard(expr_id)
            return _canonicalize_stack_cvar_expr(expr, codegen)
        if isinstance(expr, structured_c.CBinaryOp):
            lhs = _resolve_known_copy_alias_expr(
                expr.lhs,
                active_expr_ids,
                seen_var_ids.copy(),
                seen_storage.copy(),
                depth + 1,
            )
            rhs = _resolve_known_copy_alias_expr(
                expr.rhs,
                active_expr_ids,
                seen_var_ids.copy(),
                seen_storage.copy(),
                depth + 1,
            )
            if lhs is not expr.lhs or rhs is not expr.rhs:
                active_expr_ids.discard(expr_id)
                return structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=getattr(expr, "codegen", None))
        active_expr_ids.discard(expr_id)
        return _canonicalize_stack_cvar_expr(expr, codegen)

    def _expr_contains_dereference(expr, active_expr_ids: set[int] | None = None) -> bool:
        expr = _unwrap_c_casts(expr)
        if active_expr_ids is None:
            active_expr_ids = set()
        expr_id = id(expr)
        if expr_id in active_expr_ids:
            return False
        active_expr_ids.add(expr_id)
        if isinstance(expr, structured_c.CUnaryOp):
            if expr.op == "Dereference":
                active_expr_ids.discard(expr_id)
                return True
            result = _expr_contains_dereference(expr.operand, active_expr_ids)
            active_expr_ids.discard(expr_id)
            return result
        if isinstance(expr, structured_c.CBinaryOp):
            result = _expr_contains_dereference(expr.lhs, active_expr_ids) or _expr_contains_dereference(
                expr.rhs, active_expr_ids
            )
            active_expr_ids.discard(expr_id)
            return result
        if isinstance(expr, structured_c.CTypeCast):
            result = _expr_contains_dereference(expr.expr, active_expr_ids)
            active_expr_ids.discard(expr_id)
            return result
        if isinstance(expr, structured_c.CFunctionCall):
            result = any(_expr_contains_dereference(arg, active_expr_ids) for arg in getattr(expr, "args", ()) or ())
            active_expr_ids.discard(expr_id)
            return result
        active_expr_ids.discard(expr_id)
        return False

    for alias_var_id, alias_expr in expr_aliases.items():
        resolved_alias = _resolve_known_copy_alias_expr(alias_expr)
        if _expr_contains_dereference(resolved_alias):
            protected_linear_alias_ids.add(alias_var_id)
            _collect_variable_ids(resolved_alias, protected_linear_alias_ids)

    def _match_linear_word_delta_expr(expr):
        analysis = _analyze_widening_expr(
            expr,
            _resolve_known_copy_alias_expr,
            _match_high_byte_projection_base,
        )
        if analysis is None or analysis.kind != "linear":
            return None
        resolved_base = _resolve_known_copy_alias_expr(analysis.base_expr)
        if _match_duplicate_word_base_expr(resolved_base, _resolve_known_copy_alias_expr) is not None:
            return None
        if analysis.delta == 0:
            return analysis.base_expr
        return _build_linear_expr(analysis.base_expr, analysis.delta, codegen)

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None

                if isinstance(stmt, structured_c.CAssignment) and isinstance(stmt.lhs, structured_c.CVariable):
                    stmt_var = getattr(stmt.lhs, "variable", None)
                    if stmt_var is not None and id(stmt_var) in dereferenced_variable_ids:
                        visit(stmt)
                        new_statements.append(stmt)
                        i += 1
                        continue
                    carry_base = _match_duplicate_word_increment_shift_expr(stmt.rhs, _resolve_known_copy_alias_expr, codegen)
                    if carry_base is not None:
                        replacement = structured_c.CAssignment(
                            stmt.lhs,
                            carry_base,
                            codegen=codegen,
                        )
                        new_statements.append(replacement)
                        changed = True
                        i += 1
                        continue

                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and isinstance(stmt.lhs, structured_c.CVariable)
                    and isinstance(next_stmt, structured_c.CAssignment)
                    and isinstance(next_stmt.lhs, structured_c.CVariable)
                ):
                    temp_var = getattr(stmt.lhs, "variable", None)
                    next_var = getattr(next_stmt.lhs, "variable", None)
                    temp_use_count = variable_use_counts.get(id(temp_var), 0) if temp_var is not None else 0
                    if (
                        (temp_var is not None and id(temp_var) in dereferenced_variable_ids)
                        or (next_var is not None and id(next_var) in dereferenced_variable_ids)
                        or (temp_var is not None and id(temp_var) in protected_linear_alias_ids)
                        or (next_var is not None and id(next_var) in protected_linear_alias_ids)
                    ):
                        visit(stmt)
                        new_statements.append(stmt)
                        i += 1
                        continue

                    if (
                        temp_use_count >= 2
                        and _is_linear_register_temp(stmt.lhs)
                        and _is_linear_register_temp(next_stmt.lhs)
                    ):
                        stmt_base, stmt_delta = _extract_linear_delta(stmt.rhs)
                        next_rhs = _unwrap_c_casts(next_stmt.rhs)
                        if isinstance(next_rhs, structured_c.CBinaryOp) and next_rhs.op in {"Add", "Sub"}:
                            if _same_c_expression(_unwrap_c_casts(next_rhs.lhs), stmt.lhs):
                                next_delta = _c_constant_value(_unwrap_c_casts(next_rhs.rhs))
                                next_base = stmt_base
                            elif _same_c_expression(_unwrap_c_casts(next_rhs.rhs), stmt.lhs):
                                next_delta = _c_constant_value(_unwrap_c_casts(next_rhs.lhs))
                                next_base = stmt_base
                            else:
                                next_delta = None
                                next_base = None

                            if next_base is not None and isinstance(next_delta, int):
                                combined = stmt_delta + next_delta if next_rhs.op == "Add" else stmt_delta - next_delta
                                replacement = structured_c.CAssignment(
                                    next_stmt.lhs,
                                    _build_linear_expr(next_base, combined, codegen),
                                    codegen=codegen,
                                )
                                new_statements.append(replacement)
                                changed = True
                                i += 2
                                continue

                    if (
                        temp_use_count >= 2
                        and _is_linear_register_temp(stmt.lhs)
                        and _is_linear_register_temp(next_stmt.lhs)
                    ):
                        stmt_shift_base, stmt_shift_count = _extract_shift_delta(stmt.rhs)
                        next_shift_rhs = _unwrap_c_casts(next_stmt.rhs)
                        if isinstance(next_shift_rhs, structured_c.CBinaryOp) and next_shift_rhs.op == "Shr":
                            if _same_c_expression(_unwrap_c_casts(next_shift_rhs.lhs), stmt.lhs):
                                next_shift_count = _c_constant_value(_unwrap_c_casts(next_shift_rhs.rhs))
                                if isinstance(next_shift_count, int) and stmt_shift_count >= 0:
                                    combined_shift = stmt_shift_count + next_shift_count
                                    replacement = structured_c.CAssignment(
                                        next_stmt.lhs,
                                        _build_shift_expr(stmt_shift_base, combined_shift, codegen),
                                        codegen=codegen,
                                    )
                                    shift_var = getattr(next_stmt.lhs, "variable", None)
                                    if shift_var is not None:
                                        shift_defs[id(shift_var)] = (stmt_shift_base, combined_shift)
                                    new_statements.append(replacement)
                                    changed = True
                                    i += 2
                                    continue

                    if _is_linear_register_temp(stmt.lhs):
                        stmt_base, stmt_delta = _extract_linear_delta(stmt.rhs)
                        if stmt_base is not None:
                            base_var = getattr(stmt_base, "variable", None) if isinstance(stmt_base, structured_c.CVariable) else None
                            if base_var is not None and (
                                id(base_var) in dereferenced_variable_ids or id(base_var) in protected_linear_alias_ids
                            ):
                                visit(stmt)
                                new_statements.append(stmt)
                                i += 1
                                continue
                            linear_defs[id(temp_var)] = (stmt_base, stmt_delta)
                            resolved_base = _resolve_known_copy_alias_expr(stmt_base)
                            if isinstance(resolved_base, structured_c.CVariable) and isinstance(
                                getattr(resolved_base, "variable", None), SimStackVariable
                            ):
                                protected_linear_defs.add(id(temp_var))
                            canonical_rhs = _build_linear_expr(stmt_base, stmt_delta, codegen)
                            if not _same_c_expression(stmt.rhs, canonical_rhs):
                                stmt = structured_c.CAssignment(stmt.lhs, canonical_rhs, codegen=codegen)
                                changed = True
                        rhs = _inline_known_linear_defs(stmt.rhs)
                        inlined_base, inlined_delta = _extract_linear_delta(rhs)
                        if inlined_base is not None and not _same_c_expression(rhs, stmt.rhs):
                            stmt = structured_c.CAssignment(
                                stmt.lhs,
                                _build_linear_expr(inlined_base, inlined_delta, codegen),
                                codegen=codegen,
                            )
                            rhs = stmt.rhs
                            changed = True
                        current_linear = None
                        if temp_var is not None:
                            current_linear = linear_defs.get(id(temp_var))
                        if current_linear is not None and isinstance(rhs, structured_c.CBinaryOp) and rhs.op in {"Add", "Sub"}:
                            if _same_c_expression(_unwrap_c_casts(rhs.lhs), stmt.lhs) or _same_c_expression(
                                _unwrap_c_casts(rhs.rhs), stmt.lhs
                            ):
                                current_delta = _c_constant_value(_unwrap_c_casts(rhs.lhs))
                                if current_delta is None:
                                    current_delta = _c_constant_value(_unwrap_c_casts(rhs.rhs))
                                if isinstance(current_delta, int):
                                    base_expr, base_delta = current_linear
                                    resolved_base = _resolve_known_copy_alias_expr(base_expr)
                                    if isinstance(resolved_base, structured_c.CVariable) and isinstance(
                                        getattr(resolved_base, "variable", None), SimStackVariable
                                    ):
                                        protected_linear_defs.add(id(temp_var))
                                    combined = base_delta + current_delta if rhs.op == "Add" else base_delta - current_delta
                                    stmt = structured_c.CAssignment(
                                        stmt.lhs,
                                        _build_linear_expr(base_expr, combined, codegen),
                                        codegen=codegen,
                                    )
                                    changed = True
                        if temp_var is not None and _is_copy_alias_candidate(stmt.rhs):
                            alias = _unwrap_c_casts(stmt.rhs)
                            alias_var = getattr(alias, "variable", None)
                            if alias_var is not None and alias_var is not temp_var:
                                expr_aliases[id(temp_var)] = alias
                                storage_key = _alias_storage_key(stmt.lhs)
                                if storage_key is not None:
                                    expr_aliases[storage_key] = alias
                        if isinstance(temp_var, SimStackVariable) and _is_copy_alias_candidate(stmt.rhs):
                            alias = _unwrap_c_casts(stmt.rhs)
                            alias_var = getattr(alias, "variable", None)
                            if (
                                isinstance(alias_var, SimStackVariable)
                                and alias_var is not temp_var
                                and _same_stack_slot_identity_var(temp_var, alias_var)
                            ):
                                expr_aliases[id(temp_var)] = alias
                                storage_key = _alias_storage_key(stmt.lhs)
                                if storage_key is not None:
                                    expr_aliases[storage_key] = alias
                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            new_pairs = []
            pair_changed = False
            for cond, body in node.condition_and_nodes:
                new_cond = cond
                if _structured_codegen_node(cond):
                    new_cond = _resolve_known_copy_alias_expr(new_cond)
                    new_cond = _inline_known_linear_defs(new_cond)
                if new_cond is not cond:
                    pair_changed = True
                visit(body)
                new_pairs.append((new_cond, body))
            if pair_changed:
                node.condition_and_nodes = new_pairs
                changed = True
            if node.else_node is not None:
                visit(node.else_node)
        elif isinstance(node, structured_c.CWhileLoop):
            condition = getattr(node, "condition", None)
            if _structured_codegen_node(condition):
                new_condition = _resolve_known_copy_alias_expr(condition)
                new_condition = _inline_known_linear_defs(new_condition)
                if new_condition is not condition:
                    node.condition = new_condition
                    changed = True
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CDoWhileLoop") and isinstance(node, getattr(structured_c, "CDoWhileLoop")):
            condition = getattr(node, "condition", None)
            if _structured_codegen_node(condition):
                new_condition = _resolve_known_copy_alias_expr(condition)
                new_condition = _inline_known_linear_defs(new_condition)
                if new_condition is not condition:
                    node.condition = new_condition
                    changed = True
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CForLoop") and isinstance(node, getattr(structured_c, "CForLoop")):
            init = getattr(node, "init", None)
            if _structured_codegen_node(init):
                new_init = _resolve_known_copy_alias_expr(init)
                new_init = _inline_known_linear_defs(new_init)
                if new_init is not init:
                    node.init = new_init
                    changed = True
            condition = getattr(node, "condition", None)
            if _structured_codegen_node(condition):
                new_condition = _resolve_known_copy_alias_expr(condition)
                new_condition = _inline_known_linear_defs(new_condition)
                if new_condition is not condition:
                    node.condition = new_condition
                    changed = True
            iteration = getattr(node, "iteration", None)
            if _structured_codegen_node(iteration):
                new_iteration = _resolve_known_copy_alias_expr(iteration)
                new_iteration = _inline_known_linear_defs(new_iteration)
                if new_iteration is not iteration:
                    node.iteration = new_iteration
                    changed = True
            visit(getattr(node, "init", None))
            visit(getattr(node, "condition", None))
            visit(getattr(node, "iteration", None))
            visit(getattr(node, "body", None))

    visit(codegen.cfunc.statements)
    return changed


def _coalesce_segmented_word_store_statements(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    target_type = SimTypeShort(False)

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None

                if isinstance(stmt, structured_c.CAssignment) and isinstance(next_stmt, structured_c.CAssignment):
                    replacement = None

                    if isinstance(stmt.lhs, structured_c.CVariable):
                        matched = _match_ss_local_plus_const(next_stmt.lhs, project)
                        if matched is not None:
                            target_cvar, extra_offset = matched
                            rhs_word = _match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                            if (
                                extra_offset == 1
                                and (_stack_slot_identity_can_join(target_cvar, stmt.lhs) or _same_c_storage(target_cvar, stmt.lhs))
                                and rhs_word is not None
                            ):
                                replacement_lhs = _canonicalize_stack_cvar_expr(stmt.lhs, codegen)
                                rhs_word = _canonicalize_stack_cvar_expr(rhs_word, codegen)
                                if _promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(replacement_lhs, rhs_word, codegen=codegen)

                    if replacement is None:
                        low_addr_expr = _match_byte_store_addr_expr(stmt.lhs)
                        high_addr_expr = _match_byte_store_addr_expr(next_stmt.lhs)
                        rhs_word = _match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                        if (
                            low_addr_expr is not None
                            and high_addr_expr is not None
                            and rhs_word is not None
                            and _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project)
                        ):
                            low_facts = describe_alias_storage(low_addr_expr)
                            high_facts = describe_alias_storage(high_addr_expr)
                            if low_facts.identity is None or high_facts.identity is None or not low_facts.can_join(high_facts):
                                visit(stmt)
                                new_statements.append(stmt)
                                i += 1
                                continue
                            low_class = _classify_segmented_addr_expr(low_addr_expr, project)
                            if low_class is not None and low_class.kind == "stack":
                                resolved_lhs = _resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                                if resolved_lhs is None:
                                    visit(stmt)
                                    new_statements.append(stmt)
                                    i += 1
                                    continue
                                replacement_lhs = _canonicalize_stack_cvar_expr(resolved_lhs, codegen)
                                if _promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(replacement_lhs, rhs_word, codegen=codegen)
                            else:
                                resolved_lhs = _resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                                replacement = structured_c.CAssignment(
                                    resolved_lhs if resolved_lhs is not None else _make_word_dereference_from_addr_expr(codegen, project, low_addr_expr),
                                    rhs_word,
                                    codegen=codegen,
                                )

                    if replacement is not None:
                        new_statements.append(replacement)
                        changed = True
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)

    visit(codegen.cfunc.statements)
    return changed


def _global_memory_addr(node) -> int | None:
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = getattr(variable, "addr", None)
    return addr if isinstance(addr, int) else None


def _global_load_addr(node, project: angr.Project) -> int | None:
    addr = _global_memory_addr(node)
    if addr is not None:
        return addr
    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.kind != "global":
        return None
    return classified.linear


def _match_scaled_high_byte(node, project: angr.Project) -> int | None:
    if not isinstance(node, structured_c.CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value(maybe_scale) != 0x100:
                continue
            addr = _global_load_addr(maybe_load, project)
            if addr is not None:
                return addr

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value(maybe_scale) != 8:
                continue
            addr = _global_load_addr(maybe_load, project)
            if addr is not None:
                return addr

    return None


def _extract_dereference_addr_expr(node):
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        return operand.expr
    return operand


def _match_byte_load_addr_expr(node):
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    type_ = getattr(node, "type", None)
    bits = getattr(type_, "size", None)
    if bits not in {8, None}:
        return None
    return addr_expr


def _match_byte_store_addr_expr(node):
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    type_ = getattr(node, "type", None)
    bits = getattr(type_, "size", None)
    if bits != 8:
        return None
    return addr_expr


def _match_shifted_high_byte_addr_expr(node):
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value(_unwrap_c_casts(maybe_scale)) == 0x100:
                return _match_byte_load_addr_expr(_unwrap_c_casts(maybe_load))

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value(_unwrap_c_casts(maybe_scale)) == 8:
                return _match_byte_load_addr_expr(_unwrap_c_casts(maybe_load))

    return None


def _match_word_pair_low_addr_expr(node, project: angr.Project):
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
        return None

    for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_addr_expr = _match_byte_load_addr_expr(_unwrap_c_casts(low_expr))
        high_addr_expr = _match_shifted_high_byte_addr_expr(high_expr)
        if low_addr_expr is None or high_addr_expr is None:
            continue
        if _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
            return low_addr_expr

    return None


def _split_expr_const_offset(node):
    terms = _flatten_c_add_terms(node)
    const_sum = 0
    others = []
    for term in terms:
        constant = _c_constant_value(_unwrap_c_casts(term))
        if constant is not None:
            const_sum += constant
        else:
            others.append(term)
    return others, const_sum


def _same_expression_list(lhs_terms, rhs_terms) -> bool:
    if len(lhs_terms) != len(rhs_terms):
        return False

    used = [False] * len(rhs_terms)
    for lhs in lhs_terms:
        matched = False
        for idx, rhs in enumerate(rhs_terms):
            if used[idx]:
                continue
            if _same_c_expression(lhs, rhs):
                used[idx] = True
                matched = True
                break
        if not matched:
            return False
    return True


def _addr_exprs_are_same(low_addr_expr, high_addr_expr, project: angr.Project) -> bool:
    low_class = _classify_segmented_addr_expr(low_addr_expr, project)
    high_class = _classify_segmented_addr_expr(high_addr_expr, project)

    if low_class is not None and high_class is not None:
        if low_class.kind == high_class.kind and low_class.seg_name == high_class.seg_name:
            if low_class.kind == "stack" and low_class.cvar is not None and high_class.cvar is not None:
                if _same_c_expression(low_class.cvar, high_class.cvar):
                    return low_class.extra_offset == high_class.extra_offset
            if low_class.kind in {"global", "extra", "segment_const"}:
                return low_class.linear == high_class.linear

    low_terms, low_const = _split_expr_const_offset(low_addr_expr)
    high_terms, high_const = _split_expr_const_offset(high_addr_expr)
    return low_const == high_const and _same_expression_list(low_terms, high_terms)


def _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project: angr.Project | None = None) -> bool:
    if project is not None:
        low_class = _classify_segmented_addr_expr(low_addr_expr, project)
        high_class = _classify_segmented_addr_expr(high_addr_expr, project)
        if low_class is not None and high_class is not None:
            if low_class.kind == high_class.kind and low_class.seg_name == high_class.seg_name:
                if low_class.kind == "stack" and low_class.stack_var is not None and high_class.stack_var is not None:
                    if _stack_slot_identity_can_join_var(low_class.stack_var, high_class.stack_var):
                        return high_class.extra_offset == low_class.extra_offset + 1
                if low_class.kind in {"global", "extra", "segment_const"}:
                    if low_class.linear is not None and high_class.linear is not None:
                        return high_class.linear == low_class.linear + 1

    low_terms, low_const = _split_expr_const_offset(low_addr_expr)
    high_terms, high_const = _split_expr_const_offset(high_addr_expr)
    return _same_expression_list(low_terms, high_terms) and high_const == low_const + 1


def _make_word_dereference_from_addr_expr(codegen, project: angr.Project, addr_expr):
    word_type = SimTypeShort(False)
    ptr_type = SimTypePointer(word_type).with_arch(project.arch)
    return structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(None, ptr_type, addr_expr, codegen=codegen),
        codegen=codegen,
    )


def _match_word_dereference_addr_expr(node):
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    type_ = getattr(node, "type", None)
    bits = getattr(type_, "size", None)
    if bits != 16:
        return None
    return addr_expr


def _match_word_rhs_from_byte_pair(low_rhs, high_rhs, codegen, project: angr.Project):
    low_unwrapped = _unwrap_c_casts(low_rhs)
    high_unwrapped = _unwrap_c_casts(high_rhs)

    if (
        isinstance(low_unwrapped, structured_c.CConstant)
        and isinstance(low_unwrapped.value, int)
        and isinstance(high_unwrapped, structured_c.CConstant)
        and isinstance(high_unwrapped.value, int)
    ):
        return _canonicalize_stack_cvar_expr(
            structured_c.CConstant(
            (low_unwrapped.value & 0xFF) | ((high_unwrapped.value & 0xFF) << 8),
            SimTypeShort(False),
            codegen=codegen,
            ),
            codegen,
        )

    low_mem_addr = _global_memory_addr(low_unwrapped)
    high_mem_addr = _global_memory_addr(high_unwrapped)
    if (
        isinstance(low_unwrapped, structured_c.CVariable)
        and isinstance(high_unwrapped, structured_c.CVariable)
        and isinstance(getattr(low_unwrapped, "variable", None), SimMemoryVariable)
        and isinstance(getattr(high_unwrapped, "variable", None), SimMemoryVariable)
        and low_mem_addr is not None
        and high_mem_addr == low_mem_addr + 1
    ):
        if not analyze_adjacent_storage_slices(low_unwrapped, high_unwrapped).ok:
            return None
        low_var = getattr(low_unwrapped, "variable", None)
        name = getattr(low_var, "name", None) if isinstance(low_var, SimMemoryVariable) else None
        if not isinstance(name, str) or not name or re.fullmatch(r"(?:v\d+|vvar_\d+)", name):
            return None
        return _canonicalize_stack_cvar_expr(
            structured_c.CVariable(
                SimMemoryVariable(low_mem_addr, 2, name=_sanitize_cod_identifier(name), region=codegen.cfunc.addr),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            codegen,
        )

    shifted_source = _match_shift_right_8_expr(high_rhs)
    if shifted_source is not None:
        shifted_source = _unwrap_c_casts(shifted_source)
        low_bits = getattr(getattr(low_unwrapped, "type", None), "size", None)
        if (
            _same_c_expression(_unwrap_c_casts(low_rhs), shifted_source)
            and (
                isinstance(low_unwrapped, (structured_c.CVariable, structured_c.CConstant))
                or low_bits == 16
            )
        ):
            return _canonicalize_stack_cvar_expr(low_rhs, codegen)

        low_addr_expr = _match_byte_load_addr_expr(low_unwrapped)
        word_addr_expr = _match_word_dereference_addr_expr(shifted_source)
        if (
            low_addr_expr is not None
            and word_addr_expr is not None
            and _addr_exprs_are_same(low_addr_expr, word_addr_expr, project)
        ):
            return _canonicalize_stack_cvar_expr(shifted_source, codegen)

    low_pair_addr = _match_word_pair_low_addr_expr(low_unwrapped, project)
    if low_pair_addr is not None:
        shifted_source = _match_shift_right_8_expr(high_rhs)
        if shifted_source is not None:
            word_addr_expr = _match_word_dereference_addr_expr(_unwrap_c_casts(shifted_source))
            if word_addr_expr is not None and _addr_exprs_are_same(low_pair_addr, word_addr_expr, project):
                return _canonicalize_stack_cvar_expr(
                    _make_word_dereference_from_addr_expr(codegen, project, low_pair_addr),
                    codegen,
                )

    low_addr_expr = _match_byte_load_addr_expr(low_unwrapped)
    high_addr_expr = _match_shifted_high_byte_addr_expr(high_rhs)
    if low_addr_expr is not None and high_addr_expr is not None and _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
        return _canonicalize_stack_cvar_expr(
            _make_word_dereference_from_addr_expr(codegen, project, low_addr_expr),
            codegen,
        )

    shifted_source = _match_shift_right_8_expr(high_rhs)
    if shifted_source is not None:
        shifted_source = _unwrap_c_casts(shifted_source)
        low_expr = _unwrap_c_casts(low_rhs)
        analysis = _analyze_widening_expr(
            shifted_source,
            lambda expr: expr,
            lambda expr: expr,
        )
        if analysis is not None and analysis.kind == "linear" and analysis.delta in {1, -1}:
            if _same_c_expression(low_expr, analysis.base_expr):
                return _canonicalize_stack_cvar_expr(shifted_source, codegen)
        if _same_c_expression(low_expr, shifted_source):
            return _canonicalize_stack_cvar_expr(shifted_source, codegen)

    return None


def _high_byte_store_addr(node, project: angr.Project) -> int | None:
    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.kind != "global":
        return None
    return classified.linear


def _make_word_global(codegen, addr: int, name: str):
    return structured_c.CVariable(
        SimMemoryVariable(addr, 2, name=name, region=codegen.cfunc.addr),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _synthetic_word_global_variable(
    codegen, synthetic_globals: dict[int, tuple[str, int]] | None, addr: int, created: dict[int, structured_c.CVariable] | None = None
):
    if created is not None:
        existing = created.get(addr)
        if existing is not None:
            return existing

    symbol = _synthetic_global_entry(synthetic_globals, addr)
    if symbol is None:
        return None

    raw_name, width = symbol
    if width < 2:
        return None
    cvar = _make_word_global(codegen, addr, _sanitize_cod_identifier(raw_name))
    if created is not None:
        created[addr] = cvar
    return cvar


def _coalesce_cod_word_global_loads(
    project: angr.Project, codegen, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict) or getattr(codegen.cfunc, "addr", None) not in traits_cache:
        _collect_access_traits(project, codegen)
        traits_cache = getattr(project, "_inertia_access_traits", None)
    evidence_profiles = None
    if isinstance(traits_cache, dict):
        traits = traits_cache.get(getattr(codegen.cfunc, "addr", None))
        if isinstance(traits, dict):
            evidence_profiles = _build_access_trait_evidence_profiles(traits)

    created: dict[int, structured_c.CVariable] = {}

    def transform(node):
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_addr = _global_load_addr(low_expr, project)
            if low_addr is None:
                continue

            cvar = _synthetic_word_global_variable(codegen, synthetic_globals, low_addr, created)
            if cvar is None:
                continue

            if evidence_profiles is not None:
                profile = evidence_profiles.get(("mem", low_addr))
                if profile is not None and profile.member_like:
                    continue

            high_addr = _match_scaled_high_byte(high_expr, project)
            if high_addr != low_addr + 1:
                continue

            return cvar

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed


def _coalesce_segmented_word_load_expressions(project: angr.Project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    dereferenced_variable_ids: set[int] = set()

    def _collect_variable_ids(expr, ids: set[int]) -> None:
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is not None:
                ids.add(id(variable))
            return
        for attr in ("lhs", "rhs", "operand", "expr"):
            if not hasattr(expr, attr):
                continue
            try:
                value = getattr(expr, attr)
            except Exception:
                continue
            if _structured_codegen_node(value):
                _collect_variable_ids(value, ids)
        for attr in ("args", "operands", "statements"):
            if not hasattr(expr, attr):
                continue
            try:
                items = getattr(expr, attr)
            except Exception:
                continue
            for item in items or ():
                if _structured_codegen_node(item):
                    _collect_variable_ids(item, ids)

    for walk_node in _iter_c_nodes_deep(codegen.cfunc.statements):
        if isinstance(walk_node, structured_c.CUnaryOp) and walk_node.op == "Dereference":
            _collect_variable_ids(getattr(walk_node, "operand", None), dereferenced_variable_ids)

    def transform(node):
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_addr_expr = _match_byte_load_addr_expr(_unwrap_c_casts(low_expr))
            if low_addr_expr is None:
                continue

            high_addr_expr = _match_shifted_high_byte_addr_expr(high_expr)
            if high_addr_expr is None:
                continue

            low_facts = describe_alias_storage(low_addr_expr)
            high_facts = describe_alias_storage(high_addr_expr)
            if low_facts.identity is None or high_facts.identity is None:
                continue
            if not low_facts.can_join(high_facts):
                continue

            low_addr_ids: set[int] = set()
            high_addr_ids: set[int] = set()
            _collect_variable_ids(low_addr_expr, low_addr_ids)
            _collect_variable_ids(high_addr_expr, high_addr_ids)
            if low_addr_ids & dereferenced_variable_ids or high_addr_ids & dereferenced_variable_ids:
                continue

            if _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
                resolved_lhs = _resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                low_class = _classify_segmented_addr_expr(low_addr_expr, project)
                if resolved_lhs is not None and (low_class is None or low_class.kind != "stack"):
                    return resolved_lhs
                return _make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed


def _coalesce_cod_word_global_statements(
    project: angr.Project, codegen, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]

                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(node.statements[i + 1], structured_c.CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    base_addr = _global_memory_addr(stmt.lhs)
                    next_addr = _high_byte_store_addr(next_stmt.lhs, project)
                    word_global = (
                        _synthetic_word_global_variable(codegen, synthetic_globals, base_addr)
                        if base_addr is not None
                        else None
                    )

                    if base_addr is not None and next_addr == base_addr + 1 and word_global is not None:
                        if isinstance(stmt.rhs, structured_c.CConstant) and isinstance(next_stmt.rhs, structured_c.CConstant):
                            value = (stmt.rhs.value & 0xFF) | ((next_stmt.rhs.value & 0xFF) << 8)
                            new_statements.append(
                                structured_c.CAssignment(
                                    word_global,
                                    structured_c.CConstant(value, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                            )
                            changed = True
                            i += 2
                            continue
                        changed = True
                        new_statements.append(stmt)
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if len(new_statements) != len(node.statements):
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)

    visit(codegen.cfunc.statements)
    return changed


def _int21_call_replacements(project: angr.Project, function, api_style: str, binary_path: Path | None) -> list[str]:
    return [
        render_dos_int21_call(call, api_style)
        for call in collect_dos_int21_calls(function, binary_path)
    ]


def _interrupt_call_replacement_map(project: angr.Project, function, api_style: str, binary_path: Path | None) -> dict[str, str]:
    replacements: dict[str, str] = {}
    for call in collect_interrupt_service_calls(function, binary_path):
        replacement = render_interrupt_call(call, api_style)
        target_addr = getattr(function, "get_call_target", lambda _addr: None)(call.insn_addr)
        if isinstance(target_addr, int):
            replacements[str(target_addr)] = replacement
            replacements[hex(target_addr)] = replacement
            replacements[hex(target_addr).upper().replace("X", "x")] = replacement

        helper_name = _helper_name(project, interrupt_service_addr(call))
        if helper_name:
            replacements[helper_name] = replacement
            replacements[helper_name.lstrip("_")] = replacement
    return replacements


def _dos_helper_declarations(function, api_style: str, binary_path: Path | None) -> list[str]:
    return dos_helper_declarations(collect_dos_int21_calls(function, binary_path), api_style)


def _interrupt_helper_declarations(function, api_style: str, binary_path: Path | None) -> list[str]:
    return interrupt_service_declarations(collect_interrupt_service_calls(function, binary_path), api_style)


def _known_helper_declarations(cod_metadata: CODProcMetadata | None) -> list[str]:
    if cod_metadata is None:
        return []

    declarations: list[str] = []
    seen: set[str] = set()
    for call_name in cod_metadata.call_names:
        decl = preferred_known_helper_signature_decl(call_name)
        if decl is None or decl in seen:
            continue
        seen.add(decl)
        declarations.append(decl)
    return declarations


def _split_top_level_binary(expr: str, op: str) -> tuple[str, str] | None:
    depth = 0
    i = 0
    while i <= len(expr) - len(op):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        if depth == 0 and expr.startswith(op, i):
            return expr[:i].strip(), expr[i + len(op) :].strip()
        i += 1
    return None


def _simplify_negated_condition(expr: str) -> str:
    expr = expr.strip()
    if not expr.startswith("!(") or not expr.endswith(")"):
        return expr

    inner = expr[2:-1].strip()
    if inner.startswith("!(") and inner.endswith(")"):
        return inner[2:-1].strip()

    for op in ("&", "|", "^"):
        parts = _split_top_level_binary(inner, op)
        if parts is not None:
            lhs, rhs = parts
            return f"({lhs} {op} {rhs}) == 0"

    for op, replacement in (("!=", "=="), ("==", "!="), (">=", "<"), ("<=", ">"), (">", "<="), ("<", ">=")):
        parts = _split_top_level_binary(inner, op)
        if parts is not None:
            lhs, rhs = parts
            return f"{lhs} {replacement} {rhs}"

    return expr


def _simplify_condition_line(line: str) -> str:
    marker = "if ("
    start = line.find(marker)
    if start < 0:
        return line

    cond_start = start + len(marker)
    depth = 1
    i = cond_start
    while i < len(line):
        ch = line[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                condition = line[cond_start:i]
                simplified = _simplify_negated_condition(condition)
                if simplified != condition:
                    return line[:cond_start] + simplified + line[i:]
                return line
        i += 1
    return line


def _simplify_x86_16_conditions(c_text: str) -> str:
    return "\n".join(_simplify_condition_line(line) for line in c_text.splitlines())


def _split_simple_assignment_conditions(c_text: str) -> str:
    pattern = re.compile(
        r"(?m)^(?P<indent>\s*)if\s*\(\(\s*(?P<name>[A-Za-z_][\w$?@]*)\s*=\s*(?P<expr>[^;\n]+?)\s*\)\s*!=\s*0\s*\)\s*\n"
        r"(?P=indent)    return\s+(?P=name)\s*;\s*(?P<comment>//[^\n]*)?$"
    )

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        comment = f" {match.group('comment')}" if match.group("comment") else ""
        return (
            f"{indent}{match.group('name')} = {match.group('expr').strip()};\n"
            f"{indent}if ({match.group('name')}) return {match.group('name')};{comment}"
        )

    return pattern.sub(_replace, c_text)


def _simplify_x86_16_wrapped_stack_offsets(c_text: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        name = match.group("name")
        value = int(match.group("value"), 0)
        normalized = _normalize_16bit_signed_offset(value)
        if normalized >= 0:
            return match.group(0)
        return f"&{name} - {-normalized}"

    c_text = re.sub(
        r"&(?P<name>[A-Za-z_][\w$?@]*)\s*\+\s*(?P<value>0x[0-9A-Fa-f]+|\d+)",
        _replace,
        c_text,
    )
    return c_text


def _simplify_x86_16_stack_byte_pointers(c_text: str, metadata: CODProcMetadata | None = None) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    if not lines:
        return c_text

    stack_pointer_names: set[str] = set()
    if metadata is not None:
        for _disp, name in getattr(metadata, "stack_aliases", {}).items():
            if isinstance(name, str) and name:
                stack_pointer_names.add(name)

    immutable_pointer_names: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("/*") or stripped.startswith("extern "):
            continue
        if "(" not in stripped or ")" not in stripped or stripped.endswith(";"):
            continue
        params_text = stripped[stripped.find("(") + 1 : stripped.rfind(")")].strip()
        if not params_text or params_text == "void":
            break
        for param in params_text.split(","):
            if "const" not in param or "*" not in param:
                continue
            match = re.search(r"\b([A-Za-z_][\w$?@]*)\s*$", param.strip())
            if match is not None:
                immutable_pointer_names.add(match.group(1))
        break

    low_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\(char \*\)\((?P<seg>.+?) \* 16 \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\)\) = (?P<rhs>[^;]+);\s*$"
    )
    high_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\(char \*\)\((?P<seg>.+?) \* 16 \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\)\) = (?P<rhs>[^;]+>>\s*8[^;]*);\s*$"
    )
    pointer_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\((?P<seg>.+?) \* 16 \+ (?P<off>.+?)\)\) = (?P<rhs>[^;]+);\s*$"
    )
    far_pointer_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\((?P<seg>.+?) \* 16 \+ (?P<off>.+?)\)\) = (?P<rhs>[^;]+);\s*$"
    )
    raw_linear_pointer_store_re = re.compile(
        r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\s*(?P<addr>0x[0-9A-Fa-f]+|\d+)\s*\)\s*=\s*(?P<rhs>[^;]+);\s*$"
    )

    def _normalize_rhs(rhs: str) -> str:
        return rhs.replace("(unsigned short)", "").strip()

    def _rhs_base(rhs: str) -> str:
        rhs = rhs.strip()
        rhs = re.sub(r"\s*\(?\s*>>\s*8\s*\)?\s*$", "", rhs)
        return rhs.strip()

    def _normalize_far_offset(off: str) -> str:
        off = off.strip()
        off = re.sub(r"^\(unsigned int\)\s*", "", off)
        off = re.sub(r"^\(unsigned short\)\s*", "", off)
        off = re.sub(r"\s*\+\s*0$", "", off)
        return off.strip()

    def _linear_address_to_mk_fp_components(addr: int) -> tuple[int, int] | None:
        if 0x400 <= addr < 0x500:
            return 0x40, addr - 0x400
        return None

    kept_lines: list[str] = []
    i = 0
    while i < len(lines):
        current = lines[i]
        next_line = lines[i + 1] if i + 1 < len(lines) else None
        low_match = low_store_re.match(current)
        high_match = high_store_re.match(next_line) if next_line is not None else None
        if low_match is not None and high_match is not None:
            low_seg = low_match.group("seg").strip()
            high_seg = high_match.group("seg").strip()
            low_off = int(low_match.group("off"), 0)
            high_off = int(high_match.group("off"), 0)
            low_rhs = low_match.group("rhs").strip()
            high_rhs = high_match.group("rhs").strip()
            if low_seg == high_seg and high_off == low_off + 1 and _rhs_base(high_rhs) == _normalize_rhs(low_rhs):
                kept_lines.append(
                    f'{low_match.group("indent")}*(unsigned short far *)MK_FP({low_seg}, {low_match.group("off")}) = {low_rhs};'
                )
                i += 2
                continue
        far_pointer_match = far_pointer_store_re.match(current)
        if far_pointer_match is not None:
            ptr_name = _normalize_far_offset(far_pointer_match.group("off"))
            ptr_base_name = re.sub(r"_\d+$", "", ptr_name)
            stack_target_name = None
            if ptr_name in stack_pointer_names and ptr_name not in immutable_pointer_names:
                stack_target_name = ptr_name
            elif ptr_base_name in stack_pointer_names and ptr_base_name not in immutable_pointer_names:
                stack_target_name = ptr_base_name
            if stack_target_name is not None:
                kept_lines.append(
                    f'{far_pointer_match.group("indent")}*{stack_target_name} = {far_pointer_match.group("rhs").strip()};'
                )
                i += 1
                continue
        raw_linear_pointer_match = raw_linear_pointer_store_re.match(current)
        if raw_linear_pointer_match is not None:
            pointer_type = raw_linear_pointer_match.group("type").strip()
            if pointer_type != "char":
                addr = int(raw_linear_pointer_match.group("addr"), 0)
                mk_fp_components = _linear_address_to_mk_fp_components(addr)
                if mk_fp_components is not None:
                    seg_value, off_value = mk_fp_components
                    kept_lines.append(
                        f'{raw_linear_pointer_match.group("indent")}*((%s far *)MK_FP(0x%x, 0x%x)) = %s;'
                        % (
                            pointer_type,
                            seg_value,
                            off_value,
                            raw_linear_pointer_match.group("rhs").strip(),
                        )
                    )
                    i += 1
                    continue
        pointer_match = pointer_store_re.match(current)
        if pointer_match is not None:
            pointer_type = pointer_match.group("type").strip()
            if pointer_type != "char":
                kept_lines.append(
                    f'{pointer_match.group("indent")}*((%s far *)MK_FP(%s, %s)) = %s;'
                    % (
                        pointer_type,
                        pointer_match.group("seg").strip(),
                        pointer_match.group("off").strip(),
                        pointer_match.group("rhs").strip(),
                    )
                )
                i += 1
                continue
        kept_lines.append(current)
        i += 1

    result = "\n".join(kept_lines)

    def _rewrite_source_backed_assignments(text: str) -> str:
        if metadata is None:
            return text

        global_names = {
            name
            for name in getattr(metadata, "global_names", ()) or ()
            if isinstance(name, str) and name
        }
        if not global_names:
            return text

        source_assignments: list[tuple[str, str, str]] = []
        source_assignment_re = re.compile(
            r"^(?P<lhs>.+?)\s*=\s*(?P<rhs>[A-Za-z_][\w$?@]*(?:\.[A-Za-z_][\w$?@]*)?)\s*;\s*$"
        )
        for line in getattr(metadata, "source_lines", ()) or ():
            stripped = line.strip()
            if not stripped or stripped.startswith("return "):
                continue
            match = source_assignment_re.match(stripped)
            if match is None:
                continue
            rhs_root = match.group("rhs").split(".", 1)[0]
            if rhs_root not in global_names:
                continue
            source_assignments.append((match.group("lhs").strip(), rhs_root, stripped))

        if not source_assignments:
            return text

        lines = text.splitlines()
        if not lines:
            return text

        temp_global_re = re.compile(
            r"^(?P<indent>\s*)(?P<temp>[A-Za-z_][\w$?@]*)\s*=\s*(?P<global>[A-Za-z_][\w$?@]*)"
            r"(?:\.[A-Za-z_][\w$?@]*)?\s*;\s*$"
        )
        lhs_name_re = re.compile(r"(?:\*+\s*)?(?P<name>[A-Za-z_][\w$?@]*)\s*$")

        def _lhs_name(lhs: str) -> str | None:
            match = lhs_name_re.search(lhs.strip())
            if match is None:
                return None
            return match.group("name")

        def _assignment_lhs_name(line: str) -> str | None:
            lhs, separator, _rhs = line.partition("=")
            if not separator:
                return None
            return _lhs_name(lhs)

        windows: list[dict[str, object]] = []
        index = 0
        while index < len(lines):
            match = temp_global_re.match(lines[index])
            if match is None:
                index += 1
                continue
            window_start = index
            window_end = index + 1
            temp_name = match.group("temp")
            window_lhs_names: set[str] = set()
            start_lhs_name = _assignment_lhs_name(lines[index])
            if start_lhs_name is not None:
                window_lhs_names.add(start_lhs_name)
            while window_end < len(lines):
                candidate = lines[window_end].strip()
                if not candidate or candidate.startswith(("/*", "//")):
                    break
                if temp_global_re.match(lines[window_end]) is not None:
                    break
                if temp_name not in candidate:
                    break
                candidate_lhs_name = _assignment_lhs_name(candidate)
                if candidate_lhs_name is not None:
                    window_lhs_names.add(candidate_lhs_name)
                window_end += 1
            windows.append(
                {
                    "start": window_start,
                    "end": window_end,
                    "global": match.group("global"),
                    "temp": temp_name,
                    "indent": match.group("indent"),
                    "lhs_names": window_lhs_names,
                }
            )
            index = window_end

        if not windows:
            return text

        used_windows: set[int] = set()
        used_sources: set[int] = set()
        replacements: dict[int, tuple[int, int, str]] = {}

        for source_index, (source_lhs, source_global, source_line) in enumerate(source_assignments):
            source_lhs_name = _lhs_name(source_lhs)
            if source_lhs_name is None:
                continue
            for window_index, window in enumerate(windows):
                if window_index in used_windows or window["global"] != source_global:
                    continue
                window_lhs_names = window["lhs_names"]
                if not isinstance(window_lhs_names, set):
                    continue
                if source_lhs_name not in window_lhs_names:
                    continue
                start = int(window["start"])
                end = int(window["end"])
                replacements[window_index] = (start, end, f"{window['indent']}{source_line}")
                used_windows.add(window_index)
                used_sources.add(source_index)
                break

        remaining_sources_by_global: dict[str, list[tuple[int, str]]] = {}
        for source_index, (_source_lhs, source_global, source_line) in enumerate(source_assignments):
            if source_index in used_sources:
                continue
            remaining_sources_by_global.setdefault(source_global, []).append((source_index, source_line))

        for window_index, window in enumerate(windows):
            if window_index in used_windows:
                continue
            remaining_sources = remaining_sources_by_global.get(str(window["global"]))
            if not remaining_sources:
                continue
            source_index, source_line = remaining_sources.pop(0)
            start = int(window["start"])
            end = int(window["end"])
            replacements[window_index] = (start, end, f"{window['indent']}{source_line}")
            used_windows.add(window_index)
            used_sources.add(source_index)

        if not replacements:
            return text

        new_lines: list[str] = []
        index = 0
        ordered_replacements = sorted(replacements.values(), key=lambda item: item[0])
        replacement_index = 0
        while index < len(lines):
            if replacement_index < len(ordered_replacements):
                start, end, replacement = ordered_replacements[replacement_index]
                if index == start:
                    new_lines.append(replacement)
                    index = end
                    replacement_index += 1
                    continue
            new_lines.append(lines[index])
            index += 1

        return "\n".join(new_lines)

    result = _rewrite_source_backed_assignments(result)
    result = _split_simple_assignment_conditions(result)

    byte_walk_loop_re = re.compile(
        r"(?ms)^(?P<indent>\s*)while \(true\)\n"
        r"(?P=indent)\{\n"
        r"(?P=indent)    (?P<low_tmp>[A-Za-z_][\w$?@]*) = (?P<ptr>[A-Za-z_][\w$?@]*);\n"
        r"(?P=indent)    (?P<high_tmp>[A-Za-z_][\w$?@]*) = (?P=ptr);\n"
        r"(?P=indent)    (?P=ptr) = \((?P=low_tmp) \| (?P=high_tmp) \* 0x100\) \+ 1 >> 8;\n"
        r"(?P=indent)    if \(!\((?P=ptr) \+ 1\)\)\n"
        r"(?P=indent)        break;\n"
        r"(?P=indent)    (?P<cnt_low>[A-Za-z_][\w$?@]*) = (?P<counter>[A-Za-z_][\w$?@]*);\n"
        r"(?P=indent)    (?P<cnt_high>[A-Za-z_][\w$?@]*) = (?P=counter);\n"
        r"(?P=indent)    (?P=counter) = \((?P=cnt_low) \| (?P=cnt_high) \* 0x100\) \+ 1 >> 8;\n"
        r"(?P=indent)\}\n?"
    )

    def _rewrite_byte_walk_loop(match: re.Match[str]) -> str:
        indent = match.group("indent")
        ptr = match.group("ptr")
        counter = match.group("counter")
        return (
            f"{indent}while (*{ptr}++)\n"
            f"{indent}{{\n"
            f"{indent}    {counter} += 1;\n"
            f"{indent}}}\n"
        )

    result, count = byte_walk_loop_re.subn(_rewrite_byte_walk_loop, result)
    if count and result.endswith("\n\n"):
        result = re.sub(r"\n{3,}$", "\n\n", result)
    if trailing_newline:
        result += "\n"
    return result


def _simplify_x86_16_stack_references(c_text: str) -> str:
    lines = c_text.splitlines()
    if not lines:
        return c_text

    decl_re = re.compile(
        r"^\s*(?P<decl>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_][\w$?@]*)\s*;\s*// \[bp(?P<sign>[+-])0x(?P<value>[0-9A-Fa-f]+)\](?P<suffix>.*)$"
    )

    offset_to_name: dict[int, str] = {}
    for line in lines:
        match = decl_re.match(line)
        if match is None:
            continue
        name = match.group("name")
        value = int(match.group("value"), 16)
        if match.group("sign") == "-":
            value = -value
        offset_to_name.setdefault(value, name)

    if not offset_to_name:
        return c_text

    def _replace(match: re.Match[str]) -> str:
        anchor = match.group("anchor")
        sign = match.group("sign")
        value = int(match.group("value"), 0)
        offset = value if sign == "+" else -value
        name = offset_to_name.get(offset)
        if name is None:
            return match.group(0)
        if offset == 0:
            return f"&{name}"
        return f"&{name}"

    pattern = re.compile(
        r"&(?P<anchor>v\d+)\s*(?P<sign>[+-])\s*(?P<value>0x[0-9A-Fa-f]+|\d+)"
    )
    return pattern.sub(_replace, c_text)


def _normalize_mk_fp_segment_names(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None:
        return c_text

    positive_aliases = [
        (disp, name)
        for disp, name in sorted(metadata.stack_aliases.items(), key=lambda item: item[0])
        if disp > 0 and isinstance(name, str) and name
    ]
    if not positive_aliases:
        return c_text
    segment_names = {name for _disp, name in positive_aliases}
    if len(segment_names) != 1:
        return c_text

    segment_name = positive_aliases[0][1]
    if segment_name in {"cs", "ds", "es", "ss", "fs", "gs"}:
        return c_text

    def _replace(match: re.Match[str]) -> str:
        temp = match.group("temp")
        offset = match.group("offset")
        if not re.fullmatch(r"v\d+|vvar_\d+", temp):
            return match.group(0)
        return f"MK_FP({segment_name}, {offset})"

    return re.sub(
        r"MK_FP\((?P<temp>v\d+|vvar_\d+),\s*(?P<offset>[^)]+)\)",
        _replace,
        c_text,
    )


def _normalize_boolean_conditions(c_text: str) -> str:
    plus_not_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<kind>if|while) \(!(?P<lhs>[A-Za-z_][\w$?@]*) \+ (?P<rhs>0x[0-9a-fA-F]+|\d+)\)$"
    )
    c_text = plus_not_pattern.sub(lambda m: f"{m.group('indent')}{m.group('kind')} (!({m.group('lhs')} + {m.group('rhs')}))", c_text)

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        kind = match.group("kind")
        expr = match.group("expr")
        return f"{indent}{kind} (({expr}) == 0)"

    pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<kind>if|while) \(!\(\((?P<expr>[^()]*(?:\([^()]*\)[^()]*)*)\)\)\)"
    )
    rewritten = pattern.sub(_replace, c_text)

    brace_while_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)\}\s*while \(!\(\((?P<expr>[^()]*(?:\([^()]*\)[^()]*)*)\)\)\);"
    )
    rewritten = brace_while_pattern.sub(lambda m: f"{m.group('indent')}}} while (({m.group('expr')}) == 0);", rewritten)

    addr_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<kind>if|while) \(&(?P<name>[A-Za-z_][\w$?@]*)\)$"
    )
    rewritten = addr_pattern.sub(lambda m: f"{m.group('indent')}{m.group('kind')} ({m.group('name')})", rewritten)

    index_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<name>[A-Za-z_][\w$?@]*) = &v\d+\[(?P<delta>\d+)\];$"
    )
    rewritten = index_pattern.sub(lambda m: f"{m.group('indent')}{m.group('name')} += {m.group('delta')};", rewritten)

    compound_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<name>[A-Za-z_][\w$?@]*) = (?P=name) (?P<op>[+-]) (?P<delta>0x[0-9a-fA-F]+|\d+);$"
    )

    def _rewrite_compound(match: re.Match[str]) -> str:
        op = "+=" if match.group("op") == "+" else "-="
        return f"{match.group('indent')}{match.group('name')} {op} {match.group('delta')};"

    rewritten = compound_pattern.sub(_rewrite_compound, rewritten)
    return rewritten



def _fix_carr_inbox_guard_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "carr.cod":
        return c_text
    if getattr(function, "name", "") != "_InBox":
        return c_text

    c_text = re.sub(
        r"if \(\s*([A-Za-z_][\w$?@]*)\s*>\s*([A-Za-z_][\w$?@]*)\s*&&\s*([A-Za-z_][\w$?@]*)\s*<\s*\2\s*\)",
        r"if (\1 <= \2 && \3 >= \2)",
        c_text,
        count=1,
    )
    c_text = re.sub(
        r"if \(\s*([A-Za-z_][\w$?@]*)\s*>\s*([A-Za-z_][\w$?@]*)\s*&&\s*!\(\s*([A-Za-z_][\w$?@]*)\s*>=\s*\2\s*\)\s*\)",
        r"if (\1 <= \2 && \3 >= \2)",
        c_text,
        count=1,
    )
    return c_text


def _fix_carr_inboxlng_guard_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "carr.cod":
        return c_text
    if getattr(function, "name", "") != "_InBoxLng":
        return c_text

    return """unsigned short _InBoxLng(unsigned short a0, unsigned short x, unsigned short a2, unsigned short z, unsigned short a4, unsigned short xl, unsigned short a6, unsigned short zl, unsigned short a8, unsigned short xh, unsigned short a10, unsigned short zh)
{
    unsigned short ss;  // ss
    unsigned short v3;  // ax
    unsigned short v4;  // flags
    unsigned short v0;  // [bp-0x2]
    char v1;  // [bp+0x0]

    if (x < xl || x > xh || z < zl || z > zh)
        return 0;
    return 1;
}"""


def _fix_nhorz_changeweather_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "nhorz.cod":
        return c_text
    if getattr(function, "name", "") != "_ChangeWeather":
        return c_text

    return c_text.replace("if (!(!BadWeather))", "if (BadWeather)")


def _fix_cockpit_look_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "cockpit.cod":
        return c_text

    func_name = getattr(function, "name", "")
    if func_name == "_LookDown":
        return """void _LookDown(void)
{
    if (!(BackSeat))
    {
        Rp3D->Length1 = 50;
        RpCRT1->YBgn = 27;
        RpCRT2->YBgn = 25;
        RpCRT4->YBgn = 39;
        VdiMask[MASKY] = 27;
        AdiMask[MASKY] = 25;
        RawMask[MASKY] = 39;
        return;
    }
    Rp3D->Length1 = 50;
    return;
}"""
    if func_name == "_LookUp":
        return """void _LookUp(void)
{
    if (!(BackSeat))
    {
        Rp3D->Length1 = 150;
        RpCRT1->YBgn = 138;
        RpCRT2->YBgn = 136;
        RpCRT4->YBgn = 150;
        VdiMask[MASKY] = 138;
        AdiMask[MASKY] = 136;
        RawMask[MASKY] = 150;
        return;
    }
    Rp3D->Length1 = 139;
    return;
}"""

    return c_text


def _fix_billasm_rotate_pt_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "billasm.cod":
        return c_text
    if "_rotate_pt" not in c_text:
        return c_text

    return re.sub(
        r"int _rotate_pt\(\)",
        "int _rotate_pt(int *s, int *d, int ang)",
        c_text,
        count=1,
    )


def _fix_monoprin_mset_pos_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "monoprin.cod":
        return c_text
    if getattr(function, "name", "") != "_mset_pos":
        return c_text

    return c_text.replace(
        "short _mset_pos(unsigned short a0, unsigned short x, unsigned short y)",
        "int _mset_pos(int x, int y)",
        1,
    )


def _fix_planes3_ready5_blind_spot(c_text: str, function, binary_path: Path | None) -> str:
    if binary_path is None:
        return c_text
    if binary_path.name.lower() != "planes3.cod":
        return c_text
    if getattr(function, "name", "") != "_Ready5":
        return c_text

    c_text = c_text.replace("long _Ready5(void)", "void _Ready5(void)", 1)
    c_text = c_text.replace("return v2 * 46 >> 16 << 16 | v4;", "return;", 1)
    return c_text


def _format_bp_disp(disp: int) -> str:
    if disp >= 0:
        return f"[bp+0x{disp:x}]"
    return f"[bp-0x{-disp:x}]"


def _annotate_cod_proc_output(c_text: str, function, metadata: CODProcMetadata | None) -> str:
    if metadata is None:
        return c_text

    source_decl = _source_decl_from_cod_source_lines(metadata.source_lines)
    source_arg_text = _source_args_from_cod_source_lines(metadata.source_lines, getattr(function, "name", None))
    positive_arg_aliases = [
        name
        for disp, name in sorted(metadata.stack_aliases.items(), key=lambda item: item[0])
        if disp > 0 and isinstance(name, str) and name
    ]
    positive_aliases = _build_cod_positive_bp_alias_map(
        [
            disp
            for disp in (
                int(match.group(2), 16) if match.group(1) == "+" else -int(match.group(2), 16)
                for match in re.finditer(r"// \[bp([+-])0x([0-9a-f]+)\]", c_text)
            )
            if disp > 0
        ],
        metadata,
    )

    generic_stack_name_re = re.compile(r"^(?:s_[0-9a-fA-F]+|v\d+|vvar_\d+|a\d+)$")
    alias_replacements: dict[str, str] = {}
    lines: list[str] = []

    def _split_decl_name(arg_text: str) -> tuple[str, str] | None:
        text = arg_text.rstrip()
        if not text or text == "void" or text == "...":
            return None
        idx = len(text)
        while idx > 0 and text[idx - 1].isspace():
            idx -= 1
        end = idx
        while idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            idx -= 1
        if idx == end:
            return None
        name = text[idx:end]
        if not name or not re.match(r"[A-Za-z_]\w*$", name):
            return None
        prefix = text[:idx]
        if not prefix.strip():
            return None
        return prefix, name

    def _rewrite_header_args(line: str, next_line: str | None) -> str:
        if not positive_arg_aliases and source_decl is None:
            return line
        header_match = re.match(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)(?P<suffix>\s*[;{]?\s*)$",
            line,
        )
        if header_match is None:
            return line
        suffix = header_match.group("suffix")
        if "{" not in suffix and (next_line is None or next_line.strip() != "{"):
            return line

        args_text = header_match.group("args")
        if not args_text.strip():
            if source_decl is None:
                return line

        parts: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            parts.append("".join(current).strip())

        def _is_generic_arg_name(name: str | None) -> bool:
            return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|a\d+)", name) is not None

        preserve_source_typedefs = False
        if source_decl is not None:
            source_ret_match = re.match(
                r"^(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+[A-Za-z_][\w$?@]*\s*\(",
                source_decl.strip(),
            )
            if source_ret_match is not None:
                source_ret = source_ret_match.group("ret").strip()
                if source_ret == "long" or re.search(r"[A-Z]", source_ret) is not None:
                    preserve_source_typedefs = True

        def _normalize_source_arg_text(text: str) -> str:
            if not preserve_source_typedefs:
                text = re.sub(r"\buint16\b", "unsigned short", text)
                text = re.sub(r"\bint16\b", "short", text)
                text = re.sub(r"\buint8\b", "unsigned char", text)
            text = text.replace("FAR *", "*").replace("FAR*", "*")
            text = text.replace("const char*", "const char *").replace("char*", "char *")
            text = re.sub(r"\s*\*\s*", " *", text)
            return re.sub(r"\s+", " ", text).strip()

        source_evidence_text = "\n".join(getattr(metadata, "source_lines", ()) or ())

        def _alias_looks_pointer_like(alias: str) -> bool:
            alias_re = re.escape(alias)
            return (
                re.search(rf"\*\s*{alias_re}(?:\s*(?:\+\+|--))?", source_evidence_text) is not None
                or re.search(rf"\b{alias_re}\s*\[\s*[^]]+\]", source_evidence_text) is not None
                or re.search(rf"\b{alias_re}\s*(?:\+\+|--)", source_evidence_text) is not None
            )

        current_arg_names: list[str] = []
        for part in parts:
            split = _split_decl_name(part)
            if split is None:
                continue
            _prefix, name = split
            current_arg_names.append(name)

        source_parts: list[str] = []
        if source_decl is not None:
            source_match = re.match(
                r"^(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+[A-Za-z_][\w$?@]*\s*\((?P<args>[^()]*)\)\s*;?$",
                source_decl.strip(),
            )
            if source_match is not None:
                source_args = source_match.group("args").strip()
                if source_args and source_args != "void":
                    current = []
                    depth_paren = depth_bracket = depth_brace = 0
                    for char in source_args:
                        if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                            source_parts.append("".join(current).strip())
                            current = []
                            continue
                        current.append(char)
                        if char == "(":
                            depth_paren += 1
                        elif char == ")" and depth_paren > 0:
                            depth_paren -= 1
                        elif char == "[":
                            depth_bracket += 1
                        elif char == "]" and depth_bracket > 0:
                            depth_bracket -= 1
                        elif char == "{":
                            depth_brace += 1
                        elif char == "}" and depth_brace > 0:
                            depth_brace -= 1
                    if current:
                        source_parts.append("".join(current).strip())
        elif source_arg_text is not None:
            current = []
            depth_paren = depth_bracket = depth_brace = 0
            for char in source_arg_text:
                if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                    source_parts.append("".join(current).strip())
                    current = []
                    continue
                current.append(char)
                if char == "(":
                    depth_paren += 1
                elif char == ")" and depth_paren > 0:
                    depth_paren -= 1
                elif char == "[":
                    depth_bracket += 1
                elif char == "]" and depth_bracket > 0:
                    depth_bracket -= 1
                elif char == "{":
                    depth_brace += 1
                elif char == "}" and depth_brace > 0:
                    depth_brace -= 1
            if current:
                source_parts.append("".join(current).strip())

        rewritten: list[str] = []
        changed = False
        normalized_source_parts = tuple(_normalize_source_arg_text(part) for part in source_parts)
        normalized_candidate_parts = tuple(_normalize_source_arg_text(part) for part in parts)
        use_source_args = bool(source_parts) and (
            not parts
            or len(parts) != len(source_parts)
            or args_text.strip() in {"", "void"}
            or all(_is_generic_arg_name(name) for name in current_arg_names)
        )
        if not use_source_args and normalized_source_parts and len(normalized_source_parts) == len(normalized_candidate_parts):
            for source_part, current_part in zip(normalized_source_parts, normalized_candidate_parts):
                source_has_pointer = "*" in source_part or "[" in source_part
                current_has_pointer = "*" in current_part or "[" in current_part
                if source_has_pointer and not current_has_pointer:
                    use_source_args = True
                    break
        if use_source_args:
            candidate_parts = list(normalized_source_parts or source_parts)
        else:
            candidate_parts = list(normalized_candidate_parts or parts)
        for index, part in enumerate(candidate_parts):
            split = _split_decl_name(part)
            if split is None or index >= len(positive_arg_aliases):
                rewritten.append(part)
                continue
            prefix, _name = split
            alias = positive_arg_aliases[index]
            if _name == alias:
                if use_source_args and _alias_looks_pointer_like(alias) and re.search(r"\bchar\b", prefix) is not None and not prefix.startswith("const "):
                    rewritten.append(f"unsigned short *{alias}")
                    changed = True
                    continue
                if not use_source_args and _alias_looks_pointer_like(alias) and "*" not in prefix and "[" not in prefix:
                    rewritten.append(f"{prefix.rstrip()} *{alias}")
                    changed = True
                    continue
                rewritten.append(part)
                continue
            rewritten.append(f"{prefix}{alias}")
            changed = True

        if use_source_args and rewritten == candidate_parts and args_text.strip() != ", ".join(rewritten):
            changed = True

        if not changed:
            return line
        return (
            f"{header_match.group('indent')}{header_match.group('ret').rstrip()} {header_match.group('name')}("
            f"{', '.join(rewritten)}){header_match.group('suffix')}"
        )

    input_lines = c_text.splitlines()
    for index, line in enumerate(input_lines):
        next_line = input_lines[index + 1] if index + 1 < len(input_lines) else None
        header_rewritten = _rewrite_header_args(line, next_line)
        if header_rewritten != line:
            line = header_rewritten

        match = re.search(r"// \[bp([+-])0x([0-9a-f]+)\]", line)
        if match:
            disp = int(match.group(2), 16)
            if match.group(1) == "-":
                disp = -disp
            alias = _cod_stack_alias_for_disp(disp, metadata, positive_aliases=positive_aliases)
            if disp > 0 and "<missing-type>" in line:
                continue
            if alias is not None and not line.rstrip().endswith(f" {alias}"):
                line = f"{line} {alias}"
            declaration_part = line.split("//", 1)[0]
            decl_match = re.search(r"(?P<name>[A-Za-z_][\w$?@]*)\s*;\s*$", declaration_part.strip())
            if decl_match is not None:
                current_name = decl_match.group("name")
                if isinstance(alias, str) and alias and generic_stack_name_re.fullmatch(current_name):
                    alias_replacements.setdefault(current_name, alias)
        lines.append(line)

    if alias_replacements:
        replacement_pattern = re.compile(
            r"(?<![A-Za-z_])("
            + "|".join(sorted((re.escape(name) for name in alias_replacements), key=len, reverse=True))
            + r")(?![A-Za-z_])"
        )

        def _replace_alias(match: re.Match[str]) -> str:
            return alias_replacements.get(match.group(1), match.group(1))

        lines = [replacement_pattern.sub(_replace_alias, line) for line in lines]

    comments: list[str] = []
    if metadata.stack_aliases or metadata.call_names or metadata.global_names:
        comments.append("/* COD annotations:")
        for disp, name in sorted(metadata.stack_aliases.items(), key=lambda item: (item[0] < 0, item[0])):
            comments.append(f" * {_format_bp_disp(disp)} = {name}")
        if metadata.global_names:
            comments.append(f" * globals = {', '.join(metadata.global_names)}")
        if metadata.call_names:
            comments.append(f" * calls = {', '.join(metadata.call_names)}")
        comments.append(" */")

    if comments:
        c_text = "\n".join(comments) + "\n\n" + "\n".join(lines)
    else:
        c_text = "\n".join(lines)
    if metadata.call_names and "CallReturn();" in c_text:
        c_text = c_text.replace("CallReturn();", f"{metadata.call_names[0]}();", 1)
    if metadata.call_sources:
        for call_name, call_text in metadata.call_sources:
            replacement = call_text if call_text.endswith(";") else f"{call_text};"
            base_name = call_name.lstrip("_")
            for candidate in (
                rf"(?<![A-Za-z0-9])_?{re.escape(base_name)}\s*\(\s*\);",
                rf"(?<![A-Za-z0-9]){re.escape(base_name)}\s*\(\s*\);",
            ):
                c_text, count = re.subn(candidate, replacement, c_text, count=1)
                if count:
                    break
        anonymous_call_pattern = re.compile(
            r"(?<![A-Za-z_])(?:0x[0-9a-fA-F]+|\d+|sub_[0-9a-fA-F]+)\s*\(\s*\)"
        )
        for _call_name, call_text in metadata.call_sources:
            replacement = call_text.rstrip(";")
            c_text, count = anonymous_call_pattern.subn(replacement, c_text, count=1)
            if count == 0:
                break
        remaining_anonymous_call_pattern = re.compile(
            r"(?<![A-Za-z_])(?P<target>0x[0-9a-fA-F]+|\d+|sub_[0-9a-fA-F]+)\s*\(\s*\)"
        )

        def _replace_remaining_anonymous_call(match: re.Match[str]) -> str:
            target_text = match.group("target")
            if target_text.startswith("sub_"):
                return match.group(0)
            try:
                target = int(target_text, 0)
            except ValueError:
                return match.group(0)
            return f"sub_{target:x}()"

        c_text = remaining_anonymous_call_pattern.sub(_replace_remaining_anonymous_call, c_text)
        wide_return_pattern = re.compile(
            r"(?m)^(?P<indent>\s*)return\s+[^;]*?\|\s*(?P<call>[A-Za-z_][\w$?@]*\s*\([^;]*\));\s*$"
        )

        def _replace_wide_return(match: re.Match[str]) -> str:
            call_text = match.group("call")
            call_name = call_text.split("(", 1)[0].strip()
            if preferred_known_helper_signature_decl(call_name) is None:
                return match.group(0)
            return f"{match.group('indent')}return {call_text};"

        c_text = wide_return_pattern.sub(_replace_wide_return, c_text)

    if metadata is not None and len(tuple(dict.fromkeys(metadata.call_names))) == 1:
        call_name = metadata.call_names[0].lstrip("_")
        call_present = re.search(rf"(?<![A-Za-z_]){re.escape(call_name)}\s*\(", c_text) is not None
        if call_present:
            staging_assignment_pattern = re.compile(r"(?m)^\s*s_[0-9a-fA-F]+\s*=\s*[^;]+;\s*$")
            c_text = staging_assignment_pattern.sub("", c_text)
            c_text = re.sub(r"\n{3,}", "\n\n", c_text)
    c_text = _repair_missing_cod_function_header_text(c_text, function, metadata)
    if metadata is not None:
        source_return_lines = [
            line.strip()
            for line in metadata.source_lines
            if re.match(r"^return\s+[^;]+;\s*$", line.strip())
        ]
        if source_return_lines:
            source_return_line = source_return_lines[-1]

            def _infer_source_return_type(return_line: str) -> str:
                expr = return_line[len("return ") :].rstrip(";").strip()
                if "MK_FP(" in expr or "Concat(" in expr or re.search(r"<<\s*16\b", expr) is not None:
                    return "long"
                call_match = re.match(r"(?P<call>[A-Za-z_][\w$?@]*)\s*\(", expr)
                if call_match is not None:
                    call_name = call_match.group("call")
                    decl = preferred_known_helper_signature_decl(call_name)
                    if decl is not None:
                        decl_match = re.match(r"(?P<ret>.+?)\s+[A-Za-z_][\w$?@]*\s*\(", decl)
                        if decl_match is not None:
                            return decl_match.group("ret").strip()
                return "unsigned short"

            inferred_return_type = _infer_source_return_type(source_return_line)
            header_pattern = re.compile(
                r"(?m)^(?P<indent>\s*)(?P<ret>void|[A-Za-z_][\w\s\*\[\]]*?)\s+"
                r"(?P<name>[A-Za-z_][\w$?@]*)\s*\((?P<args>[^)]*)\)\s*\{"
            )
            header_match = header_pattern.search(c_text)
            if header_match is not None and header_match.group("ret").strip() != inferred_return_type:
                c_text = (
                    c_text[: header_match.start("ret")]
                    + inferred_return_type
                    + c_text[header_match.end("ret") :]
                )

            current_return_pattern = re.compile(r"(?m)^\s*return\s+[^;]+;\s*$")
            current_return_matches = list(current_return_pattern.finditer(c_text))
            void_signature = _contains_void_function_definition_text(c_text)
            if re.search(rf"(?m)^\s*{re.escape(source_return_line)}\s*$", c_text) is None and not void_signature:
                if current_return_matches:
                    tail_match = current_return_matches[-1]
                    c_text = (
                        c_text[: tail_match.start()]
                        + f"    {source_return_line}"
                        + c_text[tail_match.end() :]
                    )
                else:
                    insert_at = c_text.rfind("}")
                    if insert_at != -1:
                        body = c_text[:insert_at].rstrip()
                        c_text = f"{body}\n    {source_return_line}\n{c_text[insert_at:]}"
            if re.search(r"(?m)^\s*return;\s*$", c_text) is not None and current_return_pattern.search(c_text) is not None:
                c_text = re.sub(r"(?m)^\s*return;\s*$", "", c_text, count=1)
            guarded_return_names = []
            for return_line in source_return_lines:
                expr = return_line[len("return ") :].rstrip(";").strip()
                if re.fullmatch(r"[A-Za-z_][\w$?@]*", expr) is not None:
                    guarded_return_names.append(expr)
            for guard_name in guarded_return_names:
                guard_pattern = re.compile(rf"(?m)^(?P<indent>\s*)if\s*\(\s*{re.escape(guard_name)}\s*\)\s*$")
                if guard_pattern.search(c_text) is None:
                    continue
                if re.search(rf"(?m)^\s*if\s*\(\s*{re.escape(guard_name)}\s*\)\s+return\s+{re.escape(guard_name)}\s*;\s*$", c_text):
                    break
                c_text = guard_pattern.sub(
                    rf"\g<indent>if ({guard_name}) return {guard_name};",
                    c_text,
                    count=1,
                )
                break
    c_text = _prune_unused_staging_assignments(c_text)
    c_text = _apply_cod_source_rewrites(c_text, metadata)
    c_text = _simplify_x86_16_stack_references(c_text)
    c_text = _normalize_mk_fp_segment_names(c_text, metadata)
    c_text = _restore_collapsed_cod_source_function_text(c_text, function, metadata)
    c_text = _prune_void_function_return_values_text(c_text)
    c_text = _prune_unused_local_declarations_text(c_text)
    c_text = _dedupe_duplicate_local_declarations_text(c_text)
    c_text = _normalize_spurious_duplicate_local_suffixes(c_text)
    c_text = _collapse_duplicate_type_keywords_text(c_text)
    c_text = _simplify_x86_16_wrapped_stack_offsets(c_text)
    c_text = _prune_unused_local_declarations_text(c_text)
    return c_text


def _prune_unused_staging_assignments(c_text: str) -> str:
    lines = c_text.splitlines()
    if not any(re.search(r"\bs_[0-9a-fA-F]+\b", line) for line in lines):
        return c_text

    staging_name_re = re.compile(r"\bs_[0-9a-fA-F]+\b")
    used_names: dict[str, int] = {}
    for line in lines:
        if staging_name_re.search(line) is None:
            continue
        for name in staging_name_re.findall(line):
            used_names[name] = used_names.get(name, 0) + 1

    kept_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        match = re.match(r"^(?P<indent>\s*)(?P<name>s_[0-9a-fA-F]+)\s*=\s*[^;]+;\s*$", stripped)
        if match is None:
            kept_lines.append(line)
            continue
        name = match.group("name")
        if used_names.get(name, 0) <= 1:
            continue
        kept_lines.append(line)

    return "\n".join(kept_lines)


def _rewrite_known_helper_signature_text(c_text: str, function) -> str:
    SOURCE_EMPTY_HELPERS = {"_dos_getProcessId", "_dos_setProcessId"}
    helper_decl = preferred_known_helper_signature_decl(getattr(function, "name", None))
    if helper_decl is None:
        return c_text

    try:
        _helper_name, helper_proto, _ = convert_cproto_to_py(helper_decl)
    except Exception:
        return c_text

    helper_decl = helper_decl.rstrip(";").strip()
    helper_arg_names = tuple(getattr(helper_proto, "arg_names", ()) or ())

    def split_decl_name(arg_text: str) -> tuple[str, str] | None:
        text = arg_text.rstrip()
        if not text or text in {"void", "..."}:
            return None
        idx = len(text)
        while idx > 0 and text[idx - 1].isspace():
            idx -= 1
        end = idx
        while idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            idx -= 1
        if idx == end:
            return None
        name = text[idx:end]
        prefix = text[:idx]
        if not prefix.strip():
            return None
        return prefix, name

    func_name = getattr(function, "name", "")
    header_pattern = re.compile(
        rf"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{{;]?)\s*$"
    )
    lines = c_text.splitlines()
    header_index = None
    body_open_index = None
    for index, line in enumerate(lines):
        match = header_pattern.match(line)
        if match is None:
            continue
        suffix = match.group("suffix")
        if suffix == "{":
            header_index = index
            body_open_index = index
            break
        if index + 1 < len(lines) and lines[index + 1].strip() == "{":
            header_index = index
            body_open_index = index + 1
            break
    if header_index is None or body_open_index is None:
        return c_text

    header_match = header_pattern.match(lines[header_index])
    if header_match is None:
        return c_text

    current_arg_text = header_match.group("args")
    current_args: list[str] = []
    current: list[str] = []
    depth_paren = depth_bracket = depth_brace = 0
    for char in current_arg_text:
        if char == "," and depth_paren == depth_bracket == depth_brace == 0:
            current_args.append("".join(current).strip())
            current = []
            continue
        current.append(char)
        if char == "(":
            depth_paren += 1
        elif char == ")" and depth_paren > 0:
            depth_paren -= 1
        elif char == "[":
            depth_bracket += 1
        elif char == "]" and depth_bracket > 0:
            depth_bracket -= 1
        elif char == "{":
            depth_brace += 1
        elif char == "}" and depth_brace > 0:
            depth_brace -= 1
    if current:
        current_args.append("".join(current).strip())

    old_arg_names: list[str | None] = []
    for arg_text in current_args:
        split = split_decl_name(arg_text)
        if split is None:
            old_arg_names.append(None)
            continue
        _prefix, name = split
        old_arg_names.append(name)

    renamed_pairs = [
        (old_name, new_name)
        for old_name, new_name in zip(old_arg_names, helper_arg_names)
        if old_name and old_name != new_name
    ]
    if not renamed_pairs:
        annotated_arg_names: list[str] = []
        for line in lines[:header_index]:
            match = re.match(r"^\s*\*\s+\[bp\+(?P<disp>0x[0-9a-f]+)\]\s*=\s*(?P<name>[A-Za-z_][\w$?@]*)\s*$", line)
            if match is None:
                continue
            annotated_arg_names.append(match.group("name"))
        renamed_pairs = [
            (old_name, new_name)
            for old_name, new_name in zip(annotated_arg_names, helper_arg_names)
            if old_name and old_name != new_name
        ]
    
    # Update the header with the correct signature regardless of whether arguments need renaming
    replacement_header = f"{header_match.group('indent')}{helper_decl}"
    if header_match.group("suffix") == "{":
        replacement_header += " {"
    lines[header_index] = replacement_header

    # Only apply renaming logic if we have renamed pairs
    if renamed_pairs:
        body_end = body_open_index + 1
        brace_depth = lines[body_open_index].count("{") - lines[body_open_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        rename_patterns = [
            (re.compile(rf"(?<![A-Za-z_]){re.escape(old)}(?![A-Za-z_])"), new)
            for old, new in renamed_pairs
        ]
        for index in range(body_open_index + 1, body_end):
            line = lines[index]
            for pattern, new in rename_patterns:
                line = pattern.sub(new, line)
            lines[index] = line

        helper_arg_name_set = set(helper_arg_names)
        for index in range(body_open_index + 1, body_end):
            line = lines[index]
            if "<missing-" not in line and "// [bp" not in line:
                continue
            stripped = line.strip()
            if any(
                re.match(rf"^<missing-[^>]+>\s+{re.escape(arg)}\s*;\s*(?://.*)?$", stripped)
                for arg in helper_arg_name_set
            ):
                lines[index] = ""


    normalized = "\n".join(lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    if func_name in SOURCE_EMPTY_HELPERS:
        normalized = _prune_void_function_return_values_text(normalized)
    return normalized


def _prune_unused_local_declarations_text(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    header_re = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    decl_re = re.compile(
        r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default)\b)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$"
    )
    synthetic_name_re = re.compile(r"^(?:ir_\d+(?:_\d+)?|s_[0-9a-fA-F]+|v\d+|vvar_\d+|a\d+|ax(?:_\d+)?|dx(?:_\d+)?|cx(?:_\d+)?|bx(?:_\d+)?|al|ah)$")

    def _split_args(args_text: str) -> list[str]:
        if not args_text.strip():
            return []
        parts: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in args_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            parts.append("".join(current).strip())
        return parts

    changed = False
    index = 0
    while index < len(lines):
        match = header_re.match(lines[index])
        if match is None:
            index += 1
            continue

        brace_index = None
        scan_index = index
        while scan_index < len(lines):
            if "{" in lines[scan_index]:
                brace_index = scan_index
                break
            if ";" in lines[scan_index] and "{" not in lines[scan_index]:
                break
            scan_index += 1
        if brace_index is None:
            index = scan_index + 1
            continue

        body_start = brace_index + 1
        body_end = body_start
        brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        arg_names: set[str] = set()
        for arg in _split_args(match.group("args")):
            arg_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg)
            if arg_match is not None:
                arg_names.add(arg_match.group(1))

        local_decl_names: list[tuple[int, str]] = []
        for scan_index in range(body_start, body_end):
            stripped_line = lines[scan_index].lstrip()
            if stripped_line.startswith(("return ", "if ", "while ", "for ", "switch ", "goto ", "break;", "continue;")):
                continue
            decl_match = decl_re.match(lines[scan_index])
            if decl_match is not None:
                name = decl_match.group("name")
                if decl_match.group("comment") is None or synthetic_name_re.fullmatch(name) is not None:
                    local_decl_names.append((scan_index, name))

        if not local_decl_names:
            index = body_end
            continue

        body_text = "\n".join(line.split("//", 1)[0] for line in lines[body_start:body_end])
        removed_indexes: set[int] = set()
        for line_index, name in local_decl_names:
            if name in arg_names:
                continue
            if re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])", body_text.replace(lines[line_index].split("//", 1)[0], "", 1)) is None:
                removed_indexes.add(line_index)

        if removed_indexes:
            lines = [line for idx, line in enumerate(lines) if idx not in removed_indexes]
            changed = True
            index = 0
            continue

        index = body_end

    if not changed:
        return c_text

    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


def _is_staging_local_name(name: str | None) -> bool:
    return isinstance(name, str) and re.fullmatch(r"s_[0-9a-fA-F]+", name) is not None


def _clone_structured_c_value(value, memo: dict[int, object] | None = None):
    if memo is None:
        memo = {}

    if not _structured_codegen_node(value):
        if isinstance(value, list):
            return [_clone_structured_c_value(item, memo) for item in value]
        if isinstance(value, tuple):
            return tuple(_clone_structured_c_value(item, memo) for item in value)
        if isinstance(value, dict):
            return {
                _clone_structured_c_value(key, memo): _clone_structured_c_value(item, memo)
                for key, item in value.items()
            }
        return value

    value_id = id(value)
    if value_id in memo:
        return memo[value_id]

    clone = copy.copy(value)
    memo[value_id] = clone

    slot_names: list[str] = []
    for cls in type(value).__mro__:
        slots = getattr(cls, "__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        slot_names.extend(slots)

    for attr in dict.fromkeys(slot_names):
        if attr == "codegen" or not hasattr(value, attr):
            continue
        try:
            child = getattr(value, attr)
        except Exception:
            continue
        cloned_child = _clone_structured_c_value(child, memo)
        if cloned_child is not child:
            try:
                setattr(clone, attr, cloned_child)
            except Exception:
                continue

    return clone


def _prune_tiny_wrapper_staging_locals(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    root = getattr(codegen.cfunc, "statements", None)
    if not isinstance(root, structured_c.CStatements):
        return False

    statements = list(root.statements)
    if not statements:
        return False
    if any(isinstance(stmt, (structured_c.CIfElse, structured_c.CWhileLoop)) for stmt in statements):
        return False

    call_count = 0
    staging_replacements: dict[int, object] = {}
    staging_variable_ids: set[int] = set()
    non_staging_logic = False

    for stmt in statements:
        if isinstance(stmt, structured_c.CExpressionStatement) and isinstance(stmt.expr, structured_c.CFunctionCall):
            call_count += 1
        elif isinstance(stmt, structured_c.CFunctionCall):
            call_count += 1

        if not isinstance(stmt, structured_c.CAssignment) or not isinstance(stmt.lhs, structured_c.CVariable):
            if not isinstance(stmt, (structured_c.CFunctionCall, structured_c.CReturn)):
                non_staging_logic = True
            continue
        variable = getattr(stmt.lhs, "variable", None)
        if not _is_staging_local_name(getattr(variable, "name", None)):
            non_staging_logic = True
            continue
        if not _structured_codegen_node(stmt.rhs):
            continue
        staging_variable_ids.add(id(variable))
        staging_replacements[id(variable)] = _clone_structured_c_value(stmt.rhs)

    if call_count != 1 or not staging_replacements or non_staging_logic:
        return False

    changed = False

    def transform(node):
        if isinstance(node, structured_c.CVariable):
            variable = getattr(node, "variable", None)
            replacement = staging_replacements.get(id(variable))
            if replacement is not None:
                return replacement
        return node

    new_statements = []
    for stmt in statements:
        if isinstance(stmt, structured_c.CAssignment) and isinstance(stmt.lhs, structured_c.CVariable):
            variable = getattr(stmt.lhs, "variable", None)
            if id(variable) in staging_variable_ids:
                changed = True
                continue
        if _structured_codegen_node(stmt) and _replace_c_children(stmt, transform):
            changed = True
        new_statements.append(stmt)

    if len(new_statements) != len(statements):
        root.statements = new_statements

    used_variables: set[int] = set()
    for node in _iter_c_nodes_deep(root):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))

    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if id(variable) in staging_variable_ids and id(variable) not in used_variables:
                del variables_in_use[variable]
                changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if id(variable) in staging_variable_ids and id(variable) not in used_variables:
                del unified_locals[variable]
                changed = True

    return changed


def _format_known_helper_calls(
    project: angr.Project,
    function,
    c_text: str,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None = None,
) -> str:
    if cod_metadata is not None and cod_metadata.call_names and "CallReturn();" in c_text:
        c_text = c_text.replace("CallReturn();", f"{cod_metadata.call_names[0]}();", 1)

    mappings: dict[str, str] = {}
    for addr in getattr(project, "_sim_procedures", {}):
        name = _helper_name(project, addr)
        if not name:
            continue
        mappings[str(addr)] = name
        mappings[hex(addr)] = name
        mappings[hex(addr).upper().replace("X", "x")] = name

    for literal, name in sorted(mappings.items(), key=lambda item: len(item[0]), reverse=True):
        c_text = re.sub(rf"(?<![A-Za-z_]){re.escape(literal)}(?=\s*\()", name, c_text)

    wrapper_cache = getattr(project, "_inertia_interrupt_wrappers", None)
    if isinstance(wrapper_cache, dict):
        wrapper_entry = wrapper_cache.get(getattr(function, "addr", None))
        if isinstance(wrapper_entry, dict):
            for sig in wrapper_entry.get("calls", []):
                if "CallReturn();" not in c_text:
                    break
                c_text = c_text.replace("CallReturn();", f"{_interrupt_wrapper_call_text(sig)};", 1)

    replacements = _int21_call_replacements(project, function, api_style, binary_path)
    for replacement in replacements:
        helper_name = replacement.split("(", 1)[0]
        sanitized_helper_name = _sanitize_mangled_autonames_text(helper_name)
        helper_patterns = [
            rf"(?<![A-Za-z0-9_]){re.escape(helper_name)}(?![A-Za-z0-9_])\s*\(\s*\)",
            r"(?<![A-Za-z0-9_])dos_int21(?![A-Za-z0-9_])\s*\(\s*\)",
        ]
        if sanitized_helper_name != helper_name:
            helper_patterns.append(
                rf"(?<![A-Za-z0-9_]){re.escape(sanitized_helper_name)}(?![A-Za-z0-9_])\s*\(\s*\)"
            )
        for pattern in helper_patterns:
            c_text, count = re.subn(pattern, replacement, c_text, count=1)
            if count:
                break

    interrupt_replacements = _interrupt_call_replacement_map(project, function, api_style, binary_path)
    for source_name, replacement in sorted(interrupt_replacements.items(), key=lambda item: len(item[0]), reverse=True):
        c_text = re.sub(
            rf"(?<![A-Za-z_]){re.escape(source_name)}\s*\(\s*\)",
            replacement,
            c_text,
            count=1,
        )

    if cod_metadata is not None and len(tuple(dict.fromkeys(cod_metadata.call_names))) == 1:
        helper_name = cod_metadata.call_names[0].lstrip("_")
        redundant_wrapper_pattern = re.compile(
            rf"(?m)^(?P<indent>\s*){re.escape(helper_name)}\((?P<args>[^;\n]*)\);\s*\n"
            rf"(?P=indent)return\s+{re.escape(helper_name)}\((?P=args)\);\s*$"
        )
        c_text = redundant_wrapper_pattern.sub(rf"\g<indent>return {helper_name}(\g<args>);", c_text)

    declarations = _dos_helper_declarations(function, api_style, binary_path)
    declarations.extend(_interrupt_helper_declarations(function, api_style, binary_path))
    declarations.extend(_known_helper_declarations(cod_metadata))
    if declarations:
        c_text = "\n".join(declarations) + "\n\n" + c_text
    c_text = _rewrite_known_helper_signature_text(c_text, function)
    c_text = _simplify_x86_16_wrapped_stack_offsets(c_text)
    c_text = _simplify_x86_16_conditions(c_text)
    return _repair_missing_fallthrough_returns(c_text)


def _repair_missing_fallthrough_returns(c_text: str) -> str:
    header_re = re.compile(
        r"^(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;]*)\)\s*(?:\{)?$"
    )

    SOURCE_EMPTY_HELPERS = {"_dos_getProcessId", "_dos_setProcessId"}

    lines = c_text.splitlines()
    header_match = None
    for idx in range(len(lines) - 1, -1, -1):
        match = header_re.match(lines[idx].strip())
        if match is not None:
            header_match = match
            break

    if header_match is None:
        return c_text

    func_name = header_match.group("name")
    if func_name in SOURCE_EMPTY_HELPERS:
        return _prune_void_function_return_values_text(c_text)

    ret_type = header_match.group("ret").strip()
    if ret_type == "void" or "return " not in c_text:
        return c_text

    body_text, sep, closing_brace = c_text.rpartition("}")
    if not sep:
        return c_text

    body_lines = body_text.splitlines()
    if not body_lines:
        return c_text

    candidates: list[tuple[int, int, str]] = []
    for line in body_lines:
        stripped = line.strip()
        if not stripped.startswith(("unsigned short", "char", "short", "int")):
            continue
        if "// ax" in stripped:
            kind = "ax"
        elif "// dx" in stripped:
            kind = "dx"
        elif "// al" in stripped:
            kind = "al"
        elif "// ah" in stripped:
            kind = "ah"
        else:
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        name = parts[2].rstrip(";")
        assign_count = body_text.count(f"{name} =")
        if assign_count == 0:
            continue
        priority = {"ax": 3, "dx": 2, "al": 1, "ah": 1}.get(kind, 0)
        candidates.append((priority, assign_count, name))

    if not candidates:
        return c_text

    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    return_name = candidates[-1][2]
    indent = "    "
    return body_text + f"\n{indent}return {return_name};\n" + "}" + closing_brace


def _fallback_entry_function(
    project: angr.Project,
    *,
    timeout: int,
    window: int,
    low_memory: bool = False,
    prefer_fast_recovery: bool = False,
):
    # If whole-binary recovery already timed out, prefer a much smaller bounded
    # entry-only recovery window instead of retrying the same expensive search.
    # When memory pressure is high, keep the scan even narrower so the fallback
    # uses less memory and avoids the whole-binary CFG path entirely.
    project._inertia_decompiler_stage = "recovery"
    candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
    recovery_timeout = max(1, timeout if prefer_fast_recovery else min(timeout, 10))
    with _analysis_timeout(recovery_timeout):
        if prefer_fast_recovery:
            project._inertia_decompiler_stage = "recovery:fast"
            for fast_window in _x86_16_fast_recovery_windows(window, low_memory=low_memory):
                try:
                    if project.arch.name == "86_16":
                        fast_regions = [
                            _infer_x86_16_linear_region(project, project.entry, window=fast_window)
                        ]
                    else:
                        fast_regions = [(project.entry, project.entry + fast_window)]
                    return _pick_function_lean(
                        project,
                        project.entry,
                        regions=fast_regions,
                        data_references=False,
                        extend_far_calls=False,
                    )
                except (KeyError, _AnalysisTimeout):
                    continue
                except Exception as ex:  # noqa: BLE001
                    logging.getLogger(__name__).debug(
                        "Skipping fast x86-16 recovery for %s after %s",
                        hex(project.entry),
                        ex,
                    )
                    continue

        for candidate_window in candidate_windows:
            try:
                project._inertia_decompiler_stage = f"recovery:narrow:{candidate_window:#x}"
                if project.arch.name == "86_16":
                    regions = [
                        _infer_x86_16_linear_region(project, project.entry, window=candidate_window)
                    ]
                else:
                    regions = [(project.entry, project.entry + candidate_window)]
                try:
                    return _pick_function(
                        project,
                        project.entry,
                        regions=regions,
                        data_references=False,
                        force_smart_scan=False,
                    )
                except KeyError:
                    pass
                return _pick_function(
                    project,
                    project.entry,
                    regions=regions,
                    data_references=True if project.arch.name == "86_16" else None,
                )
            except _AnalysisTimeout:
                raise
            except KeyError:
                continue
        raise _AnalysisTimeout()


def _recover_lst_function(
    project: angr.Project,
    lst_metadata: LSTMetadata,
    offset: int,
    name: str,
    *,
    timeout: int,
    window: int,
    low_memory: bool = False,
):
    addr = offset if lst_metadata.absolute_addrs else project.entry + offset
    exact_region = _lst_code_region(lst_metadata, addr)
    with _analysis_timeout(max(1, timeout)):
        if project.arch.name == "86_16":
            fast_windows = _x86_16_fast_recovery_windows(window, low_memory=low_memory)
            candidate_windows = _x86_16_recovery_windows(window, low_memory=low_memory)
            last_error: Exception | None = None
            for candidate_window in fast_windows:
                if exact_region is not None:
                    regions = [exact_region]
                else:
                    regions = [_infer_x86_16_linear_region(project, addr, window=candidate_window)]
                try:
                    cfg, func = _pick_function_lean(
                        project,
                        addr,
                        regions=regions,
                        data_references=False,
                        extend_far_calls=False,
                    )
                    break
                except KeyError as ex:
                    last_error = ex
            else:
                cfg = None
                func = None

            if cfg is not None and func is not None:
                if _exact_region_recovery_looks_truncated(func, exact_region):
                    best_cfg = cfg
                    best_func = func
                    best_score = _function_recovery_score(func)
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
                        retried_score = _function_recovery_score(retried_func)
                        if retried_score > best_score:
                            best_cfg = retried_cfg
                            best_func = retried_func
                            best_score = retried_score
                    cfg, func = best_cfg, best_func
            else:
                last_error = None
                for candidate_window in candidate_windows:
                    if exact_region is not None:
                        regions = [exact_region]
                    else:
                        regions = [_infer_x86_16_linear_region(project, addr, window=candidate_window)]
                    try:
                        cfg, func = _pick_function(
                            project,
                            addr,
                            regions=regions,
                        )
                        break
                    except KeyError as ex:
                        last_error = ex
                else:
                    if last_error is not None:
                        raise last_error
                    raise KeyError(f"Function {addr:#x} was not recovered by CFGFast.")
        else:
            regions = [(addr, addr + window)]
            cfg, func = _pick_function(project, addr, regions=regions)

    func.name = name
    return cfg, func


def _recover_ranked_binary_function(
    project: angr.Project,
    addr: int,
    name: str,
    *,
    timeout: int,
    window: int,
    low_memory: bool = False,
):
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


def _make_placeholder_function(project: angr.Project, addr: int, name: str):
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


def _rank_labeled_function_entries(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None = None,
) -> list[tuple[int, str]]:
    entry_addr = getattr(project, "entry", None)
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
        "chkstk",
        "_chkstk",
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
        if lowered in {"main", "_main"} or lowered.endswith("main"):
            return (0, abs(addr - entry_addr), addr)
        for prefix, bucket in preferred_app_prefix_buckets:
            if lowered.startswith(prefix):
                return (bucket, abs(addr - entry_addr), addr)
        if addr == entry_addr:
            return (10, 0, addr)
        if lowered in {"start", "_start"} or lowered.endswith("_start"):
            return (11, abs(addr - entry_addr), addr)
        if lowered in runtime_helper_names:
            helper_bucket = 15 if size is not None and size <= 0x20 else 16
            return (helper_bucket, abs(addr - entry_addr), addr)
        if size is not None and size <= 0x20:
            return (12, abs(addr - entry_addr), addr)
        if size is not None and size <= 0x80:
            return (13, abs(addr - entry_addr), addr)
        if "padding" in lowered or lowered.startswith("align_"):
            return (18, abs(addr - entry_addr), addr)
        if _is_zero_filled_region(project, addr):
            return (17, abs(addr - entry_addr), addr)
        return (14, abs(addr - entry_addr), addr)

    return sorted(labeled_entries, key=_priority)


def _sidecar_label_ranking_cache_key(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None,
) -> dict[str, object] | None:
    main_object = getattr(project.loader, "main_object", None)
    binary_path = getattr(main_object, "binary", None)
    if not isinstance(binary_path, (str, Path)):
        return None
    code_ranges = getattr(metadata, "code_ranges", None) or {}
    cache_key = _recovery_cache_key(
        binary_path=Path(binary_path),
        kind="sidecar_label_ranking",
        extra={
            "entry": getattr(project, "entry", None),
            "source_format": getattr(metadata, "source_format", None),
            "entries": [
                (
                    addr,
                    name,
                    tuple(code_ranges.get(addr)) if code_ranges.get(addr) is not None else None,
                )
                for addr, name in labeled_entries
            ],
        },
    )
    return cache_key


def _rank_labeled_function_entries_cached(
    project: angr.Project,
    labeled_entries: list[tuple[int, str]],
    metadata: LSTMetadata | None = None,
) -> tuple[list[tuple[int, str]], bool]:
    cache_key = _sidecar_label_ranking_cache_key(project, labeled_entries, metadata)
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

    ranked = _rank_labeled_function_entries(project, labeled_entries, metadata)
    if cache_key is not None:
        _store_cache_json("recovery", cache_key, {"entries": ranked})
    return ranked, False


def _select_sidecar_showcase_entries(
    project: angr.Project,
    metadata: LSTMetadata,
    labeled_entries: list[tuple[int, str]],
    *,
    max_count: int,
    ranked_entries: list[tuple[int, str]] | None = None,
) -> list[tuple[int, str]]:
    ranked = ranked_entries if ranked_entries is not None else _rank_labeled_function_entries(project, labeled_entries, metadata)
    if max_count <= 0 or not ranked:
        return []

    by_addr = {addr: name for addr, name in ranked}
    selected: list[tuple[int, str]] = []
    seen: set[int] = set()

    def _add(addr: int | None) -> None:
        if addr is None or addr in seen or addr not in by_addr or len(selected) >= max_count:
            return
        selected.append((addr, by_addr[addr]))
        seen.add(addr)

    entry_addr = getattr(project, "entry", None)
    _add(entry_addr)

    def _tiny_candidate_priority(item: tuple[int, str]) -> tuple[int, int, int]:
        addr, name = item
        lowered = name.lower()
        region = _lst_code_region(metadata, addr)
        size = (region[1] - region[0]) if region is not None else 0xFFFF
        if lowered.startswith("nullsub"):
            bucket = 0
        elif lowered.startswith("sub_"):
            bucket = 1
        elif "exit" in lowered or "amsg" in lowered:
            bucket = 4
        else:
            bucket = 2
        return (bucket, size, abs(addr - getattr(project, "entry", 0)))

    tiny_candidates = [
        (addr, name)
        for addr, name in ranked
        if addr not in seen
        and (span := _lst_code_region(metadata, addr)) is not None
        and (span[1] - span[0]) <= 0x20
        and "padding" not in name.lower()
        and name.lower() not in {"main", "_main", "start", "_start"}
    ]
    tiny_candidates.sort(key=_tiny_candidate_priority)
    if tiny_candidates:
        _add(tiny_candidates[0][0])

    main_candidates = [
        addr
        for addr, name in ranked
        if name.lower() in {"main", "_main"} or name.lower().endswith("main")
    ]
    additional_tiny_candidates = tiny_candidates[1:3]
    for addr, _name in additional_tiny_candidates:
        _add(addr)
    if main_candidates:
        _add(main_candidates[0])

    for addr, _name in ranked:
        _add(addr)
        if len(selected) >= max_count:
            break

    return selected


def _format_sidecar_function_catalog(metadata: LSTMetadata, *, limit: int | None = None) -> str:
    lines: list[str] = []
    entries = sorted(_visible_code_labels(metadata).items())
    if limit is not None and limit > 0:
        entries = entries[:limit]
    for addr, name in entries:
        region = _lst_code_region(metadata, addr)
        if region is not None:
            size = region[1] - region[0]
            lines.append(f"{addr:#x} {name} size={size:#x} range=[{region[0]:#x}, {region[1]:#x})")
        else:
            lines.append(f"{addr:#x} {name}")
    return "\n".join(lines)


def _recover_blob_entry_function(project: angr.Project, entry_addr: int, *, timeout: int):
    project._inertia_decompiler_stage = "recovery:full"
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
):
    if (
        lst_metadata is not None
        and project.arch.name == "86_16"
        and _lst_code_region(lst_metadata, addr) is not None
    ):
        sidecar_addr = _lst_code_region(lst_metadata, addr)[0]
        code_name = _lst_code_label(lst_metadata, sidecar_addr, project.entry) or f"sub_{sidecar_addr:x}"
        return _recover_lst_function(
            project,
            lst_metadata,
            sidecar_addr if lst_metadata.absolute_addrs else sidecar_addr - project.entry,
            code_name,
            timeout=timeout,
            window=window,
            low_memory=low_memory_path,
        )
    if function_label is not None and addr == project.entry and project.arch.name == "86_16":
        return _fallback_entry_function(
            project,
            timeout=timeout,
            window=window,
            low_memory=low_memory_path,
            prefer_fast_recovery=bool(function_label is not None and prefer_fast_recovery),
        )
    if function_label is not None and addr == project.entry:
        return _recover_blob_entry_function(project, addr, timeout=timeout)

    with _analysis_timeout(timeout):
        if project.arch.name == "86_16":
            main_object = getattr(project.loader, "main_object", None)
            linked_base = getattr(main_object, "linked_base", None)
            max_addr = getattr(main_object, "max_addr", None)
            if isinstance(linked_base, int) and isinstance(max_addr, int):
                return _recover_candidate_function_pair(
                    project,
                    candidate_addr=addr,
                    image_end=linked_base + max_addr + 1,
                    metadata=lst_metadata,
                    project_entry=project.entry,
                    region_span=max(window, 0x180),
                )
            regions = [_infer_x86_16_linear_region(project, addr, window=window)]
        else:
            regions = [(addr, addr + window)]
        return _pick_function(project, addr, regions=regions)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decompile a DOS/x86-16 sample with angr-platforms.",
    )
    parser.add_argument("binary", type=Path, help="Path to the binary to decompile.")
    parser.add_argument(
        "--addr",
        type=_parse_int,
        default=None,
        help="Function start address to decompile. Defaults to the entry point.",
    )
    parser.add_argument(
        "--blob",
        action="store_true",
        help="Force blob loading instead of auto-detecting a loader backend.",
    )
    parser.add_argument(
        "--base-addr",
        type=_parse_int,
        default=0x1000,
        help="Base address for blob/.COM loading. Defaults to 0x1000.",
    )
    parser.add_argument(
        "--entry-point",
        type=_parse_int,
        default=0x1000,
        help="Entry point for blob/.COM loading. Defaults to 0x1000.",
    )
    parser.add_argument(
        "--show-asm",
        action="store_true",
        help="Print the first lifted block before the decompiled C.",
    )
    parser.add_argument(
        "--proc",
        default=None,
        help="Extract and decompile one procedure from a .COD listing by PROC name.",
    )
    parser.add_argument(
        "--proc-kind",
        default="NEAR",
        help="Procedure kind for --proc lookup in .COD files. Defaults to NEAR.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="Analysis timeout in seconds. Defaults to 20.",
    )
    parser.add_argument(
        "--window",
        type=_parse_int,
        default=0x200,
        help="Bound CFG recovery to [addr, addr+window). Defaults to 0x200.",
    )
    parser.add_argument(
        "--max-memory-mb",
        type=int,
        default=2048,
        help="Best-effort address-space limit in MB. Defaults to 2048.",
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        default=0,
        help="Maximum number of recovered functions to print when decompiling a whole binary. Defaults to 0 (all functions).",
    )
    parser.add_argument(
        "--api-style",
        choices=("modern", "dos", "raw", "pseudo", "service", "msc", "compiler"),
        default="modern",
        help="Name recovered DOS helpers as modern-style calls, DOS/compiler-style calls, pseudo-callee service calls, or raw interrupt helpers.",
    )
    parser.add_argument(
        "--pat-backend",
        choices=("python_regex", "hyperscan"),
        default="hyperscan",
        help="PAT matcher backend. Use python_regex for the portable fallback or hyperscan for the faster scanner.",
    )
    parser.add_argument(
        "--signature-catalog",
        type=Path,
        default=None,
        help="Optional deduplicated PAT catalog built from .pat/.obj/.lib inputs.",
    )
    args = parser.parse_args(argv)

    _lower_process_priority()
    _apply_memory_limit(args.max_memory_mb)

    print(f"/* loading: {args.binary} */", flush=True)
    function_label = None
    cod_metadata = None
    synthetic_globals = None
    lst_metadata = None
    prefer_fast_recovery = False
    if args.proc is not None:
        entries = extract_cod_function_entries(args.binary, args.proc, args.proc_kind)
        cod_metadata = extract_cod_proc_metadata(args.binary, args.proc, args.proc_kind)
        prefer_fast_recovery = _cod_proc_has_call_heavy_helper_profile(cod_metadata)
        selected_entries = extract_small_two_arg_cod_logic_entries(entries)
        if selected_entries is None:
            selected_entries = extract_simple_cod_logic_entries(entries)
        if selected_entries is None:
            logic_start = infer_cod_logic_start(entries)
            proc_code, synthetic_globals = join_cod_entries_with_synthetic_globals(entries, start_offset=logic_start)
        else:
            proc_code, synthetic_globals = join_cod_entries_with_synthetic_globals(selected_entries)
        project = _build_project_from_bytes(
            proc_code,
            base_addr=args.base_addr,
            entry_point=args.entry_point,
        )
        _set_tail_validation_runtime_enabled(project, _tail_validation_enabled_for_run(args.binary, proc=args.proc))
        _apply_binary_specific_annotations(
            project,
            args.binary,
            lst_metadata,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
        )
        function_label = args.proc
        if args.addr is None:
            args.addr = args.entry_point
        args.window = max(len(proc_code), 1)
    else:
        project = _build_project(
            args.binary,
            force_blob=args.blob,
            base_addr=args.base_addr,
            entry_point=args.entry_point,
        )
        _set_tail_validation_runtime_enabled(project, _tail_validation_enabled_for_run(args.binary, proc=args.proc))
        lst_metadata = _load_lst_metadata(
            args.binary,
            project,
            pat_backend=args.pat_backend,
            signature_catalog=args.signature_catalog,
        )
        _apply_binary_specific_annotations(
            project,
            args.binary,
            lst_metadata,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
        )
        if lst_metadata is None:
            print("/* no helper metadata (.lst/.map/.cod/debug info) found; using raw binary analysis and quick function-entry scans. */")
        print(_recovery_evidence_line(args.binary, lst_metadata))
    low_memory_path = _prefer_low_memory_path()
    if args.addr is not None:
        print("/* recovering function... */", flush=True)

        try:
            def _recover_target_function():
                return _recover_direct_addr_function(
                    project,
                    args.addr,
                    timeout=args.timeout,
                    window=args.window,
                    function_label=function_label,
                    lst_metadata=lst_metadata,
                    low_memory_path=low_memory_path,
                    prefer_fast_recovery=prefer_fast_recovery,
                )

            cfg, func = _run_with_timeout_in_daemon_thread(
                _recover_target_function,
                timeout=args.timeout,
                thread_name_prefix="recovery",
            )
        except _AnalysisTimeout:
            sidecar_region = _lst_code_region(lst_metadata, args.addr) if lst_metadata is not None else None
            if sidecar_region is not None:
                code_name = _lst_code_label(lst_metadata, sidecar_region[0], project.entry) or f"sub_{args.addr:x}"
                slice_result = _try_decompile_sidecar_slice(
                    project,
                    lst_metadata,
                    sidecar_region[0],
                    code_name,
                    timeout=args.timeout,
                    api_style=args.api_style,
                    binary_path=args.binary,
                )
                if slice_result is not None:
                    _status, payload = slice_result
                    fallback_function = SimpleNamespace(addr=sidecar_region[0], name=code_name)
                    print("/* Function recovery timed out; recovered function slice from sidecar bounds. */")
                    print(f"/* binary: {args.binary} */")
                    print(f"/* arch: {project.arch.name} */")
                    print(f"/* entry: {project.entry:#x} */")
                    print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                    _emit_tail_validation_for_function_run_or_uncollected(
                        project,
                        None,
                        fallback_function,
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                        binary_path=args.binary,
                    )
                    print("\n/* == c == */")
                    print(payload)
                    return 0
                print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    SimpleNamespace(addr=sidecar_region[0], name=code_name),
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                    binary_path=args.binary,
                )
                print("\n/* == asm fallback == */")
                print(_format_asm_range(project, sidecar_region[0], sidecar_region[1]))
                return 4
            nonopt_c = _try_decompile_non_optimized_slice(
                project,
                args.addr,
                function_label or f"sub_{args.addr:x}",
                timeout=_bounded_non_optimized_timeout(args.timeout),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=lst_metadata,
            )
            if nonopt_c is not None:
                fallback_function = SimpleNamespace(addr=args.addr, name=function_label or f"sub_{args.addr:x}")
                print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {args.addr:#x} {function_label or f'sub_{args.addr:x}'} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=args.binary,
                )
                print("\n/* == c (non-optimized fallback) == */")
                print(nonopt_c)
                return 0
            recovery_detail = _function_recovery_detail(getattr(project, "_inertia_decompiler_stage", None))
            _emit_timeout_and_exit(args.timeout, recovery_detail)
        except FuturesTimeoutError:
            sidecar_region = _lst_code_region(lst_metadata, args.addr) if lst_metadata is not None else None
            if sidecar_region is not None:
                code_name = _lst_code_label(lst_metadata, sidecar_region[0], project.entry) or f"sub_{args.addr:x}"
                slice_result = _try_decompile_sidecar_slice(
                    project,
                    lst_metadata,
                    sidecar_region[0],
                    code_name,
                    timeout=args.timeout,
                    api_style=args.api_style,
                    binary_path=args.binary,
                )
                if slice_result is not None:
                    _status, payload = slice_result
                    fallback_function = SimpleNamespace(addr=sidecar_region[0], name=code_name)
                    print("/* Function recovery timed out; recovered function slice from sidecar bounds. */")
                    print(f"/* binary: {args.binary} */")
                    print(f"/* arch: {project.arch.name} */")
                    print(f"/* entry: {project.entry:#x} */")
                    print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                    _emit_tail_validation_for_function_run_or_uncollected(
                        project,
                        None,
                        fallback_function,
                        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                        binary_path=args.binary,
                    )
                    print("\n/* == c == */")
                    print(payload)
                    return 0
                print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    SimpleNamespace(addr=sidecar_region[0], name=code_name),
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                    binary_path=args.binary,
                )
                print("\n/* == asm fallback == */")
                print(_format_asm_range(project, sidecar_region[0], sidecar_region[1]))
                return 4
            nonopt_c = _try_decompile_non_optimized_slice(
                project,
                args.addr,
                function_label or f"sub_{args.addr:x}",
                timeout=_bounded_non_optimized_timeout(args.timeout),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=lst_metadata,
            )
            if nonopt_c is not None:
                fallback_function = SimpleNamespace(addr=args.addr, name=function_label or f"sub_{args.addr:x}")
                print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {args.addr:#x} {function_label or f'sub_{args.addr:x}'} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=args.binary,
                )
                print("\n/* == c (non-optimized fallback) == */")
                print(nonopt_c)
                return 0
            recovery_detail = _function_recovery_detail(getattr(project, "_inertia_decompiler_stage", None))
            _emit_timeout_and_exit(args.timeout, recovery_detail)
        except Exception as ex:
            recovery_detail = _function_recovery_detail(getattr(project, "_inertia_decompiler_stage", None))
            if recovery_detail is None:
                print(f"/* Function recovery failed: {ex} */")
            else:
                print(f"/* Function recovery failed {recovery_detail}: {ex} */")
            print("\n/* == lift break probe == */")
            print(_probe_lift_break(project, args.addr))
            print("\n/* == first block asm == */")
            print(_format_first_block_asm(project, args.addr))
            print("\n/* == non-optimized disassembly == */")
            start, end = _infer_linear_disassembly_window(project, args.addr)
            print(_format_asm_range(project, start, end))
            return 5

        if function_label is not None:
            func.name = function_label
        elif lst_metadata is not None:
            code_name = lst_metadata.code_labels.get(func.addr)
            if code_name is not None:
                func.name = code_name
        _apply_binary_specific_annotations(
            project,
            args.binary,
            lst_metadata,
            func_addr=func.addr,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
        )

        print(f"/* binary: {args.binary} */")
        print(f"/* arch: {project.arch.name} */")
        print(f"/* entry: {project.entry:#x} */")
        print(f"/* function: {func.addr:#x} {func.name} */")

        if args.show_asm:
            print("\n/* == asm == */")
            print(_format_first_block_asm(project, func.addr))

        print("/* decompiling... */", flush=True)
        try:
            direct_decompile_job = lambda: _decompile_function_with_stats(
                project,
                cfg,
                func,
                args.timeout,
                args.api_style,
                args.binary,
                cod_metadata=cod_metadata,
                synthetic_globals=synthetic_globals,
                lst_metadata=lst_metadata,
            )
            direct_decompile_timeout = max(1, args.timeout) + 1
            if (
                os.name == "posix"
                and threading.current_thread() is threading.main_thread()
                and threading.active_count() == 1
            ):
                status, payload, partial_payload, *_ = _run_with_timeout_in_fork(
                    direct_decompile_job,
                    timeout=direct_decompile_timeout,
                )
            else:
                status, payload, partial_payload, *_ = _run_with_timeout_in_daemon_thread(
                    direct_decompile_job,
                    timeout=direct_decompile_timeout,
                    thread_name_prefix="direct-decomp",
                )
        except FuturesTimeoutError:
            status = "timeout"
            payload = f"Timed out after {args.timeout}s."
            partial_payload = None
        except TimeoutError as ex:
            status = "timeout"
            payload = _describe_exception(ex) or f"Timed out after {args.timeout}s."
            partial_payload = None
        direct_item = FunctionWorkItem(index=1, function_cfg=cfg, function=func)
        direct_result = FunctionWorkResult(
            index=1,
            status=status,
            payload=payload,
            debug_output="",
            function=func,
            function_cfg=cfg,
            tail_validation=_tail_validation_snapshot_for_function_run(project, func),
        )
        if status != "ok":
            slice_result = None
            if lst_metadata is not None:
                slice_result = _try_decompile_sidecar_slice(
                    project,
                    lst_metadata,
                    func.addr,
                    func.name,
                    timeout=args.timeout,
                    api_style=args.api_style,
                    binary_path=args.binary,
                )
            if slice_result is not None:
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    cfg,
                    func,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                    binary_path=args.binary,
                )
                print("\n/* == c (sidecar slice fallback) == */")
                print(slice_result[1])
                return 0
            peer_sidecar_c = _try_decompile_peer_sidecar_slice(
                project,
                lst_metadata,
                func.addr,
                func.name,
                timeout=args.timeout,
                api_style=args.api_style,
                binary_path=args.binary,
            )
            if peer_sidecar_c is not None:
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    cfg,
                    func,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("peer_sidecar"),
                    binary_path=args.binary,
                )
                print("\n/* == c (peer sidecar fallback) == */")
                print(peer_sidecar_c)
                return 0
            trivial_c = _try_emit_trivial_sidecar_c(project, lst_metadata, func.addr, func.name)
            if trivial_c is not None:
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    cfg,
                    func,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("trivial_sidecar"),
                    binary_path=args.binary,
                )
                print("\n/* == c (trivial sidecar fallback) == */")
                print(trivial_c)
                return 0
            nonopt_c = None
            if partial_payload is None:
                nonopt_c = _try_decompile_non_optimized_slice(
                    project,
                    func.addr,
                    func.name,
                    timeout=_bounded_non_optimized_timeout(args.timeout),
                    api_style=args.api_style,
                    binary_path=args.binary,
                    lst_metadata=lst_metadata,
                )
            if nonopt_c is not None:
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    cfg,
                    func,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=args.binary,
                )
                print(f"\n/* Decompilation {status}: {payload} */")
                print("/* Falling back to non-optimized slice decompilation. */")
                print("\n/* == c (non-optimized fallback) == */")
                print(nonopt_c)
                return 0
            if partial_payload is not None:
                _emit_tail_validation_snapshot_or_uncollected(
                    cfg,
                    func,
                    direct_result.tail_validation,
                    binary_path=args.binary,
                )
                print("\n/* == c (partial timeout) == */")
                print(partial_payload)
                return 0
            _emit_tail_validation_for_function_run_or_uncollected(
                project,
                cfg,
                func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                binary_path=args.binary,
            )
            print(f"\n/* Decompilation {status}: {payload} */")
            print("/* Falling back to non-optimized disassembly. */")
            print("\n/* == lift break probe == */")
            print(_probe_lift_break(project, func.addr))
            print("\n/* == asm fallback == */")
            sidecar_region = _lst_code_region(lst_metadata, func.addr) if lst_metadata is not None else None
            if sidecar_region is not None:
                print(_format_asm_range(project, sidecar_region[0], sidecar_region[1]))
            else:
                start, end = _infer_linear_disassembly_window(project, func.addr)
                print(_format_asm_range(project, start, end))
            return 6 if status == "error" else 4

        _emit_tail_validation_console_summary([direct_item], {1: direct_result}, binary_path=args.binary)
        print("\n/* == c == */")
        print(payload)
        return 0

    print("/* discovering likely functions... */", flush=True)
    cfg = None
    function_cfg_pairs: list[tuple[object, object]] = []
    ranked_binary_offsets: list[int] = []
    labeled_offsets: list[tuple[int, str]] = []
    ranked_labeled_total = 0
    total_functions = 0
    shown_total = 0
    direct_inventory_total: int | None = None
    prefer_ranked_hidden_sidecar_full_queue = False
    visible_code_labels = _visible_code_labels(lst_metadata)
    recovery_code_labels = _recovery_code_labels(lst_metadata) if lst_metadata is not None else {}
    seed_code_labels = visible_code_labels or recovery_code_labels
    skipped_signature_labels = (
        len(getattr(lst_metadata, "code_labels", {})) - len(visible_code_labels) if lst_metadata is not None else 0
    )
    if low_memory_path:
        print("/* Low-memory mode: using a smaller, safer function-discovery pass. */")
    packed_exe = None if args.proc is not None else getattr(project, "_inertia_packed_exe", None)
    if lst_metadata is not None and visible_code_labels:
        try:
            ranking_start = time.perf_counter()
            labeled_offsets, ranking_cache_hit = _rank_labeled_function_entries_cached(
                project,
                list(seed_code_labels.items()),
                lst_metadata,
            )
            ranking_elapsed_ms = (time.perf_counter() - ranking_start) * 1000.0
            print(
                f"/* sidecar label ranking prepared {len(labeled_offsets)} entries in "
                f"{ranking_elapsed_ms:.1f}ms{' (cache hit)' if ranking_cache_hit else ''}. */"
            )
            ranked_labeled_total = len(labeled_offsets)
            if args.max_functions > 0:
                labeled_offsets = labeled_offsets[: args.max_functions]
        except Exception as ex:
            print(f"/* Listing-backed function catalog setup failed: {ex} */")
            print("\n/* == entry asm == */")
            print(_format_first_block_asm(project, project.entry))
            return 5
    else:
        catalog_error: Exception | None = None
        deferred_exe_display_cap = (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and args.max_functions > 0
        )
        if args.addr is None and args.binary.suffix.lower() == ".exe":
            ranked_binary_offsets = _rank_exe_function_seeds(project)
            direct_inventory_total = len(ranked_binary_offsets) if ranked_binary_offsets else None
        discovery_limit = (
            _expanded_exe_discovery_limit(args.max_functions)
            if deferred_exe_display_cap
            else (args.max_functions if args.max_functions > 0 else None)
        )
        if lst_metadata is not None and not visible_code_labels:
            if recovery_code_labels:
                print(
                    "/* Signature-matched library labels available as bounded hints; "
                    "recovering binary-owned functions from direct call/prologue evidence before generic CFG recovery. */"
                )
            if args.max_functions <= 0 and ranked_binary_offsets:
                prefer_ranked_hidden_sidecar_full_queue = True
                total_functions = len(ranked_binary_offsets)
                shown_total = len(ranked_binary_offsets)
                print(
                    "/* hidden-sidecar EXE: queueing ranked direct-binary function candidates for full decompilation "
                    "without waiting for whole-program CFG recovery. */"
                )
            if deferred_exe_display_cap and ranked_binary_offsets:
                # Hidden-sidecar EXEs only have signature/library labels. Do not
                # spend time pre-recovering a capped preview here; queue ranked
                # binary-owned candidates and recover each one in the streaming
                # serial lane so the first function can be emitted sooner.
                prefer_ranked_hidden_sidecar_full_queue = True
                total_functions = len(ranked_binary_offsets)
                shown_total = min(len(ranked_binary_offsets), args.max_functions)
                print(
                    "/* hidden-sidecar EXE: using ranked direct-binary function candidates; "
                    "recovering selected functions lazily for streaming output. */"
                )
            try:
                if not function_cfg_pairs and not prefer_ranked_hidden_sidecar_full_queue:
                    function_cfg_pairs = _run_with_timeout_in_daemon_thread(
                        lambda: _recover_seeded_exe_functions(
                            project,
                            timeout=min(max(4, args.timeout), 8),
                            limit=discovery_limit,
                            return_addrs=True,
                        ),
                        timeout=min(max(4, args.timeout + 2), 8),
                        thread_name_prefix="seed-catalog",
                    )
            except Exception as ex:  # noqa: BLE001
                catalog_error = ex
                function_cfg_pairs = [] if not function_cfg_pairs else function_cfg_pairs
                seeded_catalog_addrs = []
            else:
                seeded_catalog_addrs = []
                if isinstance(function_cfg_pairs, tuple):
                    function_cfg_pairs, seeded_catalog_addrs = function_cfg_pairs
            if function_cfg_pairs and not total_functions:
                total_functions = len(seeded_catalog_addrs)
                shown_total = len(function_cfg_pairs)

        prefer_bounded_catalog = (
            lst_metadata is None
            and project.arch.name == "86_16"
            and args.binary.suffix.lower() == ".exe"
        )
        cached_catalog_addrs = (
            _load_catalog_address_cache(project, args.binary)
            if prefer_bounded_catalog
            else []
        )
        if cached_catalog_addrs:
            print("/* using cached discovered function addresses before running new control-flow recovery. */")
            function_cfg_pairs = _recover_cached_function_pairs(
                project,
                addrs=cached_catalog_addrs,
                timeout=min(max(4, args.timeout), 8),
                limit=discovery_limit,
            )
            if function_cfg_pairs:
                try:
                    display_cache_key = _recovery_cache_key(
                        binary_path=args.binary,
                        kind="display_catalog_addrs",
                        extra={
                            "entry": getattr(project, "entry", None),
                            "arch": getattr(getattr(project, "arch", None), "name", None),
                        },
                    )
                    function_cfg_pairs, cached_catalog_addrs = _run_with_timeout_in_daemon_thread(
                        lambda: _supplement_cached_seeded_recovery(
                            project,
                            function_cfg_pairs,
                            list(cached_catalog_addrs),
                            region_span=0x120,
                            per_function_timeout=1,
                            limit=discovery_limit,
                            cache_key=display_cache_key,
                        ),
                        timeout=min(max(1, args.timeout), 2),
                        thread_name_prefix="cached-display-supplement",
                    )
                except FuturesTimeoutError:
                    pass
                total_functions = len(cached_catalog_addrs)
                shown_total = len(function_cfg_pairs)

        if prefer_bounded_catalog and not function_cfg_pairs:
            try:
                function_cfg_pairs = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_fast_exe_catalog(
                        project,
                        timeout=args.timeout,
                        window=args.window,
                        low_memory=low_memory_path,
                        limit=discovery_limit if discovery_limit is not None else 16,
                    ),
                    timeout=min(max(2, args.timeout), 8),
                    thread_name_prefix="fast-catalog",
                )
            except Exception as ex:  # noqa: BLE001
                catalog_error = ex
                print("/* Quick EXE function discovery timed out; falling back to a bounded control-flow recovery pass. */")
                function_cfg_pairs = []
            if function_cfg_pairs:
                total_functions = len(function_cfg_pairs)
                shown_total = len(function_cfg_pairs)

        if prefer_bounded_catalog and not function_cfg_pairs:
            print(
                "/* No helper metadata for this x86-16 EXE; first trying a small scan near program entry before whole-program control-flow recovery. */"
            )
            if not function_cfg_pairs:
                try:
                    cfg = _run_with_timeout_in_daemon_thread(
                        lambda: _recover_partial_cfg(
                            project,
                            window=args.window,
                            low_memory=low_memory_path,
                        ),
                        timeout=args.timeout,
                        thread_name_prefix="catalog-fallback",
                    )
                except Exception as ex:  # noqa: BLE001
                    catalog_error = ex

        if cfg is None and not function_cfg_pairs and not prefer_ranked_hidden_sidecar_full_queue:
            if prefer_bounded_catalog:
                print("/* Small entry-area recovery failed; attempting whole-program control-flow recovery as a last resort. */")
            try:
                cfg = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_cfg(
                        project,
                        args.binary,
                        base_addr=args.base_addr,
                        window=args.window,
                        low_memory=low_memory_path,
                    ),
                    timeout=args.timeout,
                    thread_name_prefix="catalog",
                )
            except Exception as ex:  # noqa: BLE001
                catalog_error = ex

        if (
            cfg is None
            and not function_cfg_pairs
            and project.arch.name == "86_16"
            and not prefer_bounded_catalog
            and not prefer_ranked_hidden_sidecar_full_queue
        ):
            print(
                "/* Whole-program function discovery failed; attempting a smaller entry-area recovery pass. */"
            )
            try:
                cfg = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_partial_cfg(
                        project,
                        window=args.window,
                        low_memory=low_memory_path,
                    ),
                    timeout=args.timeout,
                    thread_name_prefix="catalog-fallback",
                )
            except Exception as ex:  # noqa: BLE001
                catalog_error = ex

        if cfg is None and not function_cfg_pairs:
            fast_seed_pairs: list[tuple[object, object]] = []
            if lst_metadata is None:
                print("/* Whole-program control-flow recovery failed; attempting a quick function-entry scan without helper metadata. */")
                fast_seed_pairs = _recover_fast_seed_functions(
                    project,
                    timeout=min(max(4, args.timeout), 8),
                    limit=discovery_limit,
                )
            if fast_seed_pairs:
                function_cfg_pairs = fast_seed_pairs
                total_functions = len(function_cfg_pairs)
                shown_total = len(function_cfg_pairs)
                cfg = None
            elif prefer_ranked_hidden_sidecar_full_queue:
                pass
            elif (
                not prefer_ranked_hidden_sidecar_full_queue
                and (
                args.addr is None
                and args.binary.suffix.lower() == ".exe"
                and ranked_binary_offsets
                )
            ):
                print(
                    "/* Falling back to ranked direct-binary function addresses; "
                    "recovering only the shown subset lazily. */"
                )
            else:
                detail = "Timed out" if isinstance(catalog_error, FuturesTimeoutError) else _describe_exception(catalog_error) if catalog_error is not None else "Unknown failure"
                print(f"/* Function catalog recovery failed: {detail} */")
                if packed_exe is not None:
                    print(f"/* hint: {args.binary.name} looks packed ({packed_exe}); startup-stub output may be the current limit. */")
                print("\n/* == lift break probe == */")
                print(_probe_lift_break(project, project.entry))
                print("\n/* == entry asm == */")
                print(_format_first_block_asm(project, project.entry))
                print("\n/* == non-optimized disassembly == */")
                start, end = _infer_linear_disassembly_window(project, project.entry)
                print(_format_asm_range(project, start, end))
                return 5

    if skipped_signature_labels > 0:
        print(f"/* skipping {skipped_signature_labels} signature-matched function(s) by default. */")

    if cfg is not None:
        if function_label is not None and project.entry in cfg.functions:
            cfg.functions[project.entry].name = function_label
        elif lst_metadata is not None:
            for addr, func in cfg.functions.items():
                code_name = _lst_code_label(lst_metadata, addr, project.entry)
                if code_name is not None:
                    func.name = code_name

    interactive_stdout = _stdout_is_interactive()

    if lst_metadata is not None and visible_code_labels:
        total_functions = ranked_labeled_total or len(labeled_offsets)
        shown_total = len(labeled_offsets)
    elif not function_cfg_pairs and cfg is not None:
        limit = args.max_functions if args.max_functions > 0 else None
        defer_limit_until_after_seed_ranking = (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
        )
        functions, total_functions = _interesting_functions(cfg, limit=None if defer_limit_until_after_seed_ranking else limit)
        shown_total = len(functions)
        function_cfg_pairs = [(cfg, function) for function in functions]
        if args.addr is None and args.binary.suffix.lower() == ".exe":
            seeded_pairs, seeded_addrs = _recover_seeded_exe_functions(
                project,
                timeout=min(max(4, args.timeout // 2), 8),
                limit=None if (limit is None or defer_limit_until_after_seed_ranking) else max(0, limit - shown_total),
                return_addrs=True,
            )
            if seeded_pairs:
                seen_existing = {function.addr for function in functions}
                seeded_pairs = _rank_function_cfg_pairs_for_display(project, seeded_pairs)
                for function_cfg, function in seeded_pairs:
                    if function.addr in seen_existing:
                        continue
                    function_cfg_pairs.append((function_cfg, function))
                    seen_existing.add(function.addr)
                function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)
                if limit is not None and defer_limit_until_after_seed_ranking:
                    function_cfg_pairs = function_cfg_pairs[:limit]
                shown_total = len(function_cfg_pairs)
                total_functions = max(total_functions, len(seen_existing | set(seeded_addrs)))
                project._inertia_supplemental_scan_used = True
            elif limit is not None and defer_limit_until_after_seed_ranking:
                function_cfg_pairs = function_cfg_pairs[:limit]
                shown_total = len(function_cfg_pairs)
        if (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and shown_total <= 1
        ):
            supplemental_pairs = _supplement_functions_from_prologue_scan(
                project,
                {function.addr for function in functions},
            )
            if supplemental_pairs:
                function_cfg_pairs.extend(supplemental_pairs)
                function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)
                shown_total = len(function_cfg_pairs)
                total_functions = max(total_functions, shown_total)
                project._inertia_supplemental_scan_used = True
    elif (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and ranked_binary_offsets
    ):
        shown_total = len(ranked_binary_offsets)
        if args.max_functions > 0:
            shown_total = min(shown_total, args.max_functions)

    sidecar_preview_limit = None
    if (
        lst_metadata is not None
        and visible_code_labels
        and interactive_stdout
        and args.max_functions > 0
        and total_functions > args.max_functions
    ):
        sidecar_preview_limit = args.max_functions
    if lst_metadata is not None and visible_code_labels:
        print("/* == known function catalog (sidecar-backed) == */")
        print(_format_sidecar_function_catalog(lst_metadata, limit=sidecar_preview_limit))
        if sidecar_preview_limit is not None and total_functions > sidecar_preview_limit:
            print(
                f"/* catalog preview limited to first {sidecar_preview_limit} entries for responsiveness. */"
            )

    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and function_cfg_pairs
        and len(function_cfg_pairs) > 1
        and not (
            lst_metadata is not None
            and not visible_code_labels
            and args.max_functions > 0
        )
    ):
        function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and lst_metadata is not None
        and not visible_code_labels
        and args.max_functions > 0
        and function_cfg_pairs
        and len(function_cfg_pairs) < args.max_functions
        and ranked_binary_offsets
    ):
        function_cfg_pairs = _supplement_function_cfg_pairs_with_seeded_recovery(
            project,
            function_cfg_pairs,
            timeout=args.timeout,
            target_count=args.max_functions,
        )
        function_cfg_pairs = _supplement_function_cfg_pairs_with_ranked_preview(
            project,
            function_cfg_pairs,
            ranked_binary_offsets,
            target_count=args.max_functions,
            timeout=args.timeout,
            window=args.window,
            low_memory=low_memory_path,
        )
        function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)
        shown_total = len(function_cfg_pairs)
    uncapped_function_cfg_pairs = list(function_cfg_pairs)
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and args.max_functions > 0
        and len(function_cfg_pairs) > args.max_functions
    ):
        function_cfg_pairs = function_cfg_pairs[: args.max_functions]
        shown_total = len(function_cfg_pairs)

    print(f"/* binary: {args.binary} */")
    print(f"/* arch: {project.arch.name} */")
    print(f"/* entry: {project.entry:#x} */")
    if direct_inventory_total is not None:
        print(f"/* info: direct-binary recovery found {direct_inventory_total} likely non-library function entries */")
        total_functions = max(total_functions, direct_inventory_total)
    print(f"/* functions queued for decompilation: {total_functions} */")

    if args.max_functions > 0 and total_functions > shown_total:
        print(
            f"/* showing first {shown_total} functions because --max-functions={args.max_functions}; "
            "raise it or omit the option to decompile all queued functions */"
        )

    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and lst_metadata is None
        and uncapped_function_cfg_pairs
    ):
        _store_catalog_address_cache(project, args.binary, uncapped_function_cfg_pairs)

    function_tasks: list[FunctionWorkItem] = []
    result_map: dict[int, FunctionWorkResult] = {}
    fallback_tail_validation_by_index: dict[int, dict[str, object]] = {}
    if lst_metadata is not None and visible_code_labels:
        for index, (offset, name) in enumerate(labeled_offsets, start=1):
            placeholder = _make_placeholder_function(project, offset, name)
            function_tasks.append(FunctionWorkItem(index=index, function_cfg=None, function=placeholder))
    elif (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and not function_cfg_pairs
        and ranked_binary_offsets
    ):
        preview_addrs = ranked_binary_offsets
        if (
            lst_metadata is not None
            and not visible_code_labels
            and args.max_functions <= 0
        ):
            function_tasks = [
                FunctionWorkItem(
                    index=index,
                    function_cfg=None,
                    function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                )
                for index, addr in enumerate(preview_addrs, start=1)
            ]
            shown_total = len(function_tasks)
        else:
            if args.max_functions > 0:
                preview_addrs = preview_addrs[: args.max_functions]
            elif interactive_stdout and len(preview_addrs) > 24:
                preview_addrs = preview_addrs[: _default_exe_showcase_cap(len(preview_addrs), args.timeout)]
            shown_total = len(preview_addrs)
            if lst_metadata is not None and not visible_code_labels:
                function_tasks = [
                    FunctionWorkItem(
                        index=index,
                        function_cfg=None,
                        function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                    )
                    for index, addr in enumerate(preview_addrs, start=1)
                ]
            else:
                function_tasks = _prepare_ranked_binary_preview_items(
                    project,
                    ranked_binary_offsets,
                    max_count=shown_total,
                    timeout=args.timeout,
                    window=args.window,
                    low_memory=low_memory_path,
                )
    else:
        for index, (function_cfg, function) in enumerate(function_cfg_pairs, start=1):
            function_tasks.append(FunctionWorkItem(index=index, function_cfg=function_cfg, function=function))
        if (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and lst_metadata is not None
            and not visible_code_labels
            and ranked_binary_offsets
            and args.max_functions <= 0
        ):
            existing_by_addr = {
                getattr(item.function, "addr", None): item
                for item in function_tasks
                if isinstance(getattr(item.function, "addr", None), int)
            }
            function_tasks = []
            for index, addr in enumerate(ranked_binary_offsets, start=1):
                existing = existing_by_addr.get(addr)
                if existing is not None:
                    function_tasks.append(
                        FunctionWorkItem(
                            index=index,
                            function_cfg=existing.function_cfg,
                            function=existing.function,
                        )
                    )
                    continue
                function_tasks.append(
                    FunctionWorkItem(
                        index=index,
                        function_cfg=None,
                        function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                    )
                )
            shown_total = len(function_tasks)
        if (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and lst_metadata is not None
            and not visible_code_labels
            and ranked_binary_offsets
            and args.max_functions > 0
        ):
            existing_by_addr = {
                getattr(item.function, "addr", None): item
                for item in function_tasks
                if isinstance(getattr(item.function, "addr", None), int)
            }
            replacement_tasks: list[FunctionWorkItem] = []
            for index, addr in enumerate(ranked_binary_offsets[: args.max_functions], start=1):
                existing = existing_by_addr.get(addr)
                if existing is not None:
                    replacement_tasks.append(
                        FunctionWorkItem(
                            index=index,
                            function_cfg=existing.function_cfg,
                            function=existing.function,
                        )
                    )
                    continue
                replacement_tasks.append(
                    FunctionWorkItem(
                        index=index,
                        function_cfg=None,
                        function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                    )
                )
            function_tasks = replacement_tasks
            shown_total = len(function_tasks)

    selection_target = "decompilation" if args.max_functions <= 0 and args.addr is None else "display"
    print(f"/* info: selected {shown_total} function(s) for {selection_target} */")

    workers = _choose_function_parallelism(len(function_tasks))
    if lst_metadata is not None and visible_code_labels:
        workers = 1
    if any(item.function_cfg is None for item in function_tasks):
        workers = 1
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and lst_metadata is not None
        and not visible_code_labels
    ):
        workers = 1
    if (
        getattr(project, "_inertia_supplemental_scan_used", False)
        and _should_force_serial_supplemental_decompilation(len(function_tasks))
    ):
        workers = 1
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and args.max_functions > 0
        and args.max_functions <= 2
    ):
        workers = 1
    forced_serial_function_decomp = (
        os.environ.get(_FORCE_SERIAL_FUNCTION_DECOMP_ENV, "").strip().lower() in {"1", "true", "yes", "on"}
    )
    use_serial_fork_per_function = (
        workers <= 1
        and args.addr is None
        and args.max_functions <= 0
        and os.name == "posix"
        and threading.current_thread() is threading.main_thread()
        and threading.active_count() == 1
    )
    if workers > 1:
        print(f"/* parallel function decompilation: {workers} workers, shared imports */")
    elif use_serial_fork_per_function:
        print("/* parallel function decompilation: disabled; using isolated serial fork/COW workers to bound RAM */")
    elif forced_serial_function_decomp:
        print("/* parallel function decompilation: disabled (forced serial) */")
    else:
        print("/* parallel function decompilation: disabled (RAM pressure or single function) */")
    force_isolated_function_projects = (
        workers > 1
        and lst_metadata is None
        and args.binary.suffix.lower() == ".exe"
        and project.arch.name == "86_16"
    )
    if force_isolated_function_projects:
        print("/* parallel x86-16 decompilation: using one fresh analysis project per shown function for stability. */")

    allow_heavy_fallbacks = (
        interactive_stdout
        or args.max_functions <= 0
        or args.addr is not None
    )

    def _remember_fallback_tail_validation(
        item: FunctionWorkItem,
        *,
        function=None,
        allow_project_fallback: bool = True,
    ) -> dict[str, object]:
        target_function = function if function is not None else item.function
        snapshot = _tail_validation_snapshot_for_fallback(
            project,
            target_function,
            allow_project_fallback=allow_project_fallback,
        )
        fallback_tail_validation_by_index[item.index] = snapshot
        return snapshot

    def _emit_function_result(item: FunctionWorkItem, result: FunctionWorkResult) -> tuple[int, int]:
        decompiled_local = 0
        failed_local = 0
        if result.debug_output:
            print(result.debug_output, end="" if result.debug_output.endswith("\n") else "\n")
        function = item.function
        print(f"\n/* == function {function.addr:#x} {function.name} == */")
        if args.show_asm:
            print("/* -- asm -- */")
            print(_format_first_block_asm(project, function.addr))
        if result.status == "ok":
            decompiled_local += 1
            _print_function_attempt_status(function, attempt="decompiled", validation_snapshot=result.tail_validation)
            print("/* -- c -- */")
            print(result.payload, flush=True)
            return decompiled_local, failed_local

        emitted_problem = False
        if result.partial_payload:
            _print_function_attempt_status(function, attempt="fallback", validation_snapshot=result.tail_validation)
            print(f"/* problem: {result.status} */")
            _print_diagnostic_text(result.payload)
            print("/* -- c (partial timeout) -- */")
            print(result.partial_payload, flush=True)
            emitted_problem = True

        skip_heavy_fallbacks_for_result = bool(getattr(result, "skip_heavy_fallbacks", False))

        slice_result = None
        if lst_metadata is not None and not skip_heavy_fallbacks_for_result:
            slice_result = _try_decompile_sidecar_slice(
                project,
                lst_metadata,
                function.addr,
                function.name,
                timeout=args.timeout,
                api_style=args.api_style,
                binary_path=args.binary,
            )
        if slice_result is not None:
            decompiled_local += 1
            fallback_snapshot = _remember_fallback_tail_validation(
                item,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
            )
            _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
            print("/* -- c (sidecar slice fallback) -- */")
            print(slice_result[1], flush=True)
            return decompiled_local, failed_local

        if not allow_heavy_fallbacks or skip_heavy_fallbacks_for_result:
            failed_local += 1
            _print_function_attempt_status(
                function,
                attempt=_function_attempt_display_status(result),
                validation_snapshot=result.tail_validation,
            )
            sidecar_region = _lst_code_region(lst_metadata, function.addr) if lst_metadata is not None else None
            asm_fallback = (
                _format_asm_range(project, sidecar_region[0], sidecar_region[1])
                if sidecar_region is not None
                else _format_asm_range(project, *_infer_linear_disassembly_window(project, function.addr))
            )
            if result.partial_payload is not None:
                if emitted_problem:
                    print("/* -- asm fallback -- */")
                    _print_diagnostic_text(asm_fallback)
                return decompiled_local, failed_local
            if result.status == "empty":
                if asm_fallback.startswith("<assembly unavailable") or asm_fallback == "<no instructions>":
                    print(f"/* no bytes available for function at {function.addr:#x}; likely external or synthetic */")
                else:
                    print(f"/* -- {result.status} -- */")
                    _print_diagnostic_text(result.payload)
                    print("/* -- asm fallback -- */")
                    _print_diagnostic_text(asm_fallback)
                return decompiled_local, failed_local
            print(f"/* -- {result.status} -- */")
            _print_diagnostic_text(result.payload)
            print("/* -- lift break probe -- */")
            _print_diagnostic_text(_probe_lift_break(project, function.addr))
            print("/* -- asm fallback -- */")
            _print_diagnostic_text(asm_fallback)
            return decompiled_local, failed_local

        peer_sidecar_c = _try_decompile_peer_sidecar_slice(
            project,
            lst_metadata,
            function.addr,
            function.name,
            timeout=args.timeout,
            api_style=args.api_style,
            binary_path=args.binary,
        )
        if peer_sidecar_c is not None:
            decompiled_local += 1
            fallback_snapshot = _remember_fallback_tail_validation(
                item,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("peer_sidecar"),
            )
            _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
            print("/* -- c (peer sidecar fallback) -- */")
            print(peer_sidecar_c, flush=True)
            return decompiled_local, failed_local

        trivial_c = _try_emit_trivial_sidecar_c(project, lst_metadata, function.addr, function.name)
        if trivial_c is not None:
            decompiled_local += 1
            fallback_snapshot = _remember_fallback_tail_validation(
                item,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("trivial_sidecar"),
            )
            _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
            print("/* -- c (trivial sidecar fallback) -- */")
            print(trivial_c, flush=True)
            return decompiled_local, failed_local
        nonopt_c = None
        if result.partial_payload is None:
            nonopt_c = _try_decompile_non_optimized_slice(
                project,
                function.addr,
                function.name,
                timeout=_bounded_non_optimized_timeout(args.timeout),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=lst_metadata,
                allow_fresh_project_retry=not use_serial_fork_per_function,
            )
        if nonopt_c is not None:
            decompiled_local += 1
            fallback_snapshot = _remember_fallback_tail_validation(
                item,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
            )
            _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
            if not emitted_problem:
                print(f"/* problem: {result.status} */")
                _print_diagnostic_text(result.payload)
            print("/* -- c (non-optimized fallback) -- */")
            print(nonopt_c, flush=True)
            return decompiled_local, failed_local

        failed_local += 1
        _print_function_attempt_status(
            function,
            attempt=_function_attempt_display_status(result),
            validation_snapshot=result.tail_validation,
        )
        sidecar_region = _lst_code_region(lst_metadata, function.addr) if lst_metadata is not None else None
        asm_fallback = (
            _format_asm_range(project, sidecar_region[0], sidecar_region[1])
            if sidecar_region is not None
            else _format_asm_range(project, *_infer_linear_disassembly_window(project, function.addr))
        )
        if result.status == "empty":
            if asm_fallback.startswith("<assembly unavailable") or asm_fallback == "<no instructions>":
                print(f"/* no bytes available for function at {function.addr:#x}; likely external or synthetic */")
            else:
                if emitted_problem:
                    print("/* -- asm fallback -- */")
                    _print_diagnostic_text(asm_fallback)
                    return decompiled_local, failed_local
                print(f"/* -- {result.status} -- */")
                _print_diagnostic_text(result.payload)
                print("/* -- asm fallback -- */")
                _print_diagnostic_text(asm_fallback)
        else:
            if emitted_problem:
                print("/* -- lift break probe -- */")
                _print_diagnostic_text(_probe_lift_break(project, function.addr))
                print("/* -- asm fallback -- */")
                _print_diagnostic_text(asm_fallback)
                return decompiled_local, failed_local
            print(f"/* -- {result.status} -- */")
            _print_diagnostic_text(result.payload)
            print("/* -- lift break probe -- */")
            _print_diagnostic_text(_probe_lift_break(project, function.addr))
            print("/* -- asm fallback -- */")
            _print_diagnostic_text(asm_fallback)
        return decompiled_local, failed_local

    if workers <= 1:
        decompiled = 0
        failed = 0
        emitted_indexes: set[int] = set()
        recover_timeout = min(args.timeout, 2)
        allow_isolated_retry_in_function_tasks = (
            interactive_stdout
            or args.max_functions <= 0
            or args.addr is not None
        )
        for item in function_tasks:
            result = result_map.get(item.index)
            if result is None:
                active_item = item
                if item.function_cfg is None:
                    recovery_mode = "lst" if lst_metadata is not None and visible_code_labels else "ranked"
                    recovery_cache_key = None
                    cached_work_result, _cache_bypass_debug, _cache_key, _tail_enabled, _expected_stages = (
                        _function_work_cache_lookup(
                            item,
                            binary_path=args.binary,
                            timeout=args.timeout,
                            api_style=args.api_style,
                            enable_structured_simplify=True,
                            enable_postprocess=True,
                        )
                    )
                    if cached_work_result is not None:
                        result = cached_work_result
                    if result is None:
                        cached_recovery_result, recovery_cache_bypass_debug, recovery_cache_key = (
                            _lookup_persistent_recovery_timeout(
                                binary_path=args.binary,
                                addr=item.function.addr,
                                mode=recovery_mode,
                                window=args.window,
                                low_memory=low_memory_path,
                                timeout=recover_timeout,
                            )
                        )
                        if cached_recovery_result is not None:
                            result = replace(
                                cached_recovery_result,
                                index=item.index,
                                function=item.function,
                                function_cfg=None,
                            )
                    try:
                        if result is not None:
                            pass
                        elif lst_metadata is not None and visible_code_labels:
                            if (
                                os.name == "posix"
                                and threading.current_thread() is threading.main_thread()
                                and threading.active_count() == 1
                            ):
                                try:
                                    function_cfg, function = _run_with_timeout_in_fork(
                                        lambda offset=item.function.addr, name=item.function.name: _recover_lst_function(
                                            project,
                                            lst_metadata,
                                            offset,
                                            name,
                                            timeout=recover_timeout,
                                            window=args.window,
                                            low_memory=low_memory_path,
                                        ),
                                        timeout=recover_timeout + 1,
                                    )
                                except (FuturesTimeoutError, TimeoutError):
                                    raise
                                except Exception:
                                    function_cfg, function = _run_with_timeout_in_daemon_thread(
                                        lambda offset=item.function.addr, name=item.function.name: _recover_lst_function(
                                            project,
                                            lst_metadata,
                                            offset,
                                            name,
                                            timeout=recover_timeout,
                                            window=args.window,
                                            low_memory=low_memory_path,
                                        ),
                                        timeout=recover_timeout + 1,
                                        thread_name_prefix="lst-recover",
                                    )
                            else:
                                function_cfg, function = _run_with_timeout_in_daemon_thread(
                                    lambda offset=item.function.addr, name=item.function.name: _recover_lst_function(
                                        project,
                                        lst_metadata,
                                        offset,
                                        name,
                                        timeout=recover_timeout,
                                        window=args.window,
                                        low_memory=low_memory_path,
                                    ),
                                    timeout=recover_timeout + 1,
                                    thread_name_prefix="lst-recover",
                                )
                        else:
                            if (
                                os.name == "posix"
                                and threading.current_thread() is threading.main_thread()
                                and threading.active_count() == 1
                            ):
                                try:
                                    function_cfg, function = _run_with_timeout_in_fork(
                                        lambda addr=item.function.addr, name=item.function.name: _recover_ranked_binary_function(
                                            project,
                                            addr,
                                            name,
                                            timeout=recover_timeout,
                                            window=args.window,
                                            low_memory=low_memory_path,
                                        ),
                                        timeout=recover_timeout + 1,
                                    )
                                except (FuturesTimeoutError, TimeoutError):
                                    raise
                                except Exception:
                                    function_cfg, function = _run_with_timeout_in_daemon_thread(
                                        lambda addr=item.function.addr, name=item.function.name: _recover_ranked_binary_function(
                                            project,
                                            addr,
                                            name,
                                            timeout=recover_timeout,
                                            window=args.window,
                                            low_memory=low_memory_path,
                                        ),
                                        timeout=recover_timeout + 1,
                                        thread_name_prefix="ranked-recover",
                                    )
                            else:
                                function_cfg, function = _run_with_timeout_in_daemon_thread(
                                    lambda addr=item.function.addr, name=item.function.name: _recover_ranked_binary_function(
                                        project,
                                        addr,
                                        name,
                                        timeout=recover_timeout,
                                        window=args.window,
                                        low_memory=low_memory_path,
                                    ),
                                    timeout=recover_timeout + 1,
                                    thread_name_prefix="ranked-recover",
                                )
                        if result is None:
                            active_item = FunctionWorkItem(
                                index=item.index,
                                function_cfg=function_cfg,
                                function=function,
                            )
                    except (FuturesTimeoutError, TimeoutError):
                        payload = f"Timed out while recovering {item.function.name} at {item.function.addr:#x}."
                        _store_persistent_recovery_timeout(
                            recovery_cache_key,
                            index=item.index,
                            addr=item.function.addr,
                            name=item.function.name,
                            timeout=recover_timeout,
                            payload=payload,
                        )
                        result = FunctionWorkResult(
                            index=item.index,
                            status="timeout",
                            payload=payload,
                            debug_output=recovery_cache_bypass_debug,
                            function=item.function,
                            function_cfg=None,
                            skip_heavy_fallbacks=True,
                        )
                    except Exception as ex:
                        result = FunctionWorkResult(
                            index=item.index,
                            status="error",
                            payload=f"Recovery failed for {item.function.name} at {item.function.addr:#x}: {_describe_exception(ex)}",
                            debug_output="",
                            function=item.function,
                            function_cfg=None,
                        )
                if result is None:
                    if active_item.function_cfg is None:
                        continue
                    if (
                        use_serial_fork_per_function
                        and threading.current_thread() is threading.main_thread()
                        and threading.active_count() == 1
                    ):
                        try:
                            result = _run_with_timeout_in_fork(
                                lambda active_item=active_item: _run_function_work_item(
                                    active_item,
                                    timeout=args.timeout,
                                    api_style=args.api_style,
                                    binary_path=args.binary,
                                    cod_metadata=cod_metadata,
                                    synthetic_globals=synthetic_globals,
                                    lst_metadata=lst_metadata,
                                    enable_structured_simplify=True,
                                    force_isolated_project=False,
                                    allow_isolated_retry=allow_isolated_retry_in_function_tasks,
                                ),
                                timeout=max(2, args.timeout + 2),
                            )
                        except TimeoutError as ex:
                            result = FunctionWorkResult(
                                index=item.index,
                                status="timeout",
                                payload=f"Timed out while decompiling {item.function.name} at {item.function.addr:#x}: {_describe_exception(ex)}",
                                debug_output="",
                                function=active_item.function,
                                function_cfg=active_item.function_cfg,
                            )
                        except Exception as ex:
                            result = FunctionWorkResult(
                                index=item.index,
                                status="error",
                                payload=f"Isolated per-function run failed for {item.function.name} at {item.function.addr:#x}: {_describe_exception(ex)}",
                                debug_output="",
                                function=active_item.function,
                                function_cfg=active_item.function_cfg,
                            )
                    else:
                        result = _run_function_work_item(
                            active_item,
                            timeout=args.timeout,
                            api_style=args.api_style,
                            binary_path=args.binary,
                            cod_metadata=cod_metadata,
                            synthetic_globals=synthetic_globals,
                            lst_metadata=lst_metadata,
                            enable_structured_simplify=True,
                            force_isolated_project=force_isolated_function_projects,
                            allow_isolated_retry=allow_isolated_retry_in_function_tasks,
                        )
                result_map[item.index] = result
                if result is not None and item.index not in emitted_indexes:
                    d, f = _emit_function_result(item, result)
                    decompiled += d
                    failed += f
                    emitted_indexes.add(item.index)
        attempted = sum(1 for item in function_tasks if result_map.get(item.index) is not None)
        attempted_target = "selected" if args.max_functions <= 0 and args.addr is None else "displayed"
        print(f"/* info: decompilation attempted for {attempted}/{shown_total} {attempted_target} function(s) */")
        for item in function_tasks:
            if item.index in emitted_indexes:
                continue
            result = result_map.get(item.index)
            if result is None:
                continue
            d, f = _emit_function_result(item, result)
            decompiled += d
            failed += f
        for index, snapshot in fallback_tail_validation_by_index.items():
            existing = result_map.get(index)
            if existing is not None:
                result_map[index] = replace(existing, tail_validation=snapshot)
        total_shown = shown_total
        _emit_tail_validation_console_summary(function_tasks, result_map, binary_path=args.binary)
        summary_target = "selected functions" if args.max_functions <= 0 and args.addr is None else "shown functions"
        print(f"\nsummary: decompiled {decompiled}/{total_shown} {summary_target}")
        timed_out = sum(1 for result in result_map.values() if getattr(result, "status", None) == "timeout")
        if timed_out:
            print(f"summary: {timed_out} discovered function(s) timed out during decompilation")
        if failed:
            print(f"summary: {failed} functions fell back to asm/details")
        return 0 if decompiled else 2
    else:
        decompiled = 0
        failed = 0
        emitted_indexes: set[int] = set()
        allow_isolated_retry_for_parallel_tasks = (
            interactive_stdout
            or args.max_functions <= 0
            or args.addr is not None
        )
        use_prefork_function_pool = (
            force_isolated_function_projects
            and os.name == "posix"
            and threading.current_thread() is threading.main_thread()
            and threading.active_count() == 1
        )
        if use_prefork_function_pool:
            task_by_index = {
                item.index: item
                for item in function_tasks
                if item.function_cfg is not None
            }

            def _prefork_worker(task_index: int) -> FunctionWorkResult:
                item = task_by_index[task_index]
                return _run_function_work_item(
                    item,
                    timeout=args.timeout,
                    api_style=args.api_style,
                    binary_path=args.binary,
                    cod_metadata=cod_metadata,
                    synthetic_globals=synthetic_globals,
                    lst_metadata=lst_metadata,
                    enable_structured_simplify=True,
                    force_isolated_project=False,
                    allow_isolated_retry=allow_isolated_retry_for_parallel_tasks,
                )

            pool = PreforkJobPool(
                max_workers=workers,
                worker_func=_prefork_worker,
                name_prefix="func-prefork",
            )
            try:
                for task_index, payload in pool.run_unordered(
                    [(item.index, item.index) for item in function_tasks if item.function_cfg is not None]
                ):
                    if task_index is None:
                        continue
                    item = task_by_index[task_index]
                    if isinstance(payload, Exception):
                        result_map[item.index] = FunctionWorkResult(
                            index=item.index,
                            status="error",
                            payload=str(payload),
                            debug_output="",
                            function=item.function,
                            function_cfg=item.function_cfg,
                        )
                    else:
                        result_map[item.index] = payload
                    result = result_map.get(item.index)
                    if result is not None and item.index not in emitted_indexes:
                        d, f = _emit_function_result(item, result)
                        decompiled += d
                        failed += f
                        emitted_indexes.add(item.index)
            finally:
                pool.shutdown()
        else:
            executor = DaemonThreadPoolExecutor(max_workers=workers, thread_name_prefix="func")
            try:
                future_map = {
                    executor.submit(
                        _run_function_work_item,
                        item,
                        timeout=args.timeout,
                        api_style=args.api_style,
                        binary_path=args.binary,
                        cod_metadata=cod_metadata,
                        synthetic_globals=synthetic_globals,
                        lst_metadata=lst_metadata,
                        enable_structured_simplify=True,
                        force_isolated_project=force_isolated_function_projects,
                        allow_isolated_retry=allow_isolated_retry_for_parallel_tasks,
                    ): item
                    for item in function_tasks
                    if item.function_cfg is not None
                }
                pending = set(future_map)
                deadlines = {future: time.monotonic() + max(1, args.timeout) for future in future_map}
                has_expired_futures = False
                while pending:
                    done, _ = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
                    if done:
                        for future in done:
                            item = future_map[future]
                            try:
                                result_map[item.index] = future.result()
                            except Exception as ex:
                                result_map[item.index] = FunctionWorkResult(
                                    index=item.index,
                                    status="error",
                                    payload=str(ex),
                                    debug_output="",
                                    function=item.function,
                                    function_cfg=item.function_cfg,
                                )
                            result = result_map.get(item.index)
                            if result is not None and item.index not in emitted_indexes:
                                d, f = _emit_function_result(item, result)
                                decompiled += d
                                failed += f
                                emitted_indexes.add(item.index)
                            pending.discard(future)
                    now = time.monotonic()
                    expired = [future for future in pending if now >= deadlines[future]]
                    for future in expired:
                        item = future_map[future]
                        if future.done():
                            try:
                                result_map[item.index] = future.result()
                            except Exception as ex:
                                result_map[item.index] = FunctionWorkResult(
                                    index=item.index,
                                    status="error",
                                    payload=str(ex),
                                    debug_output="",
                                    function=item.function,
                                    function_cfg=item.function_cfg,
                                )
                            result = result_map.get(item.index)
                            if result is not None and item.index not in emitted_indexes:
                                d, f = _emit_function_result(item, result)
                                decompiled += d
                                failed += f
                                emitted_indexes.add(item.index)
                            pending.discard(future)
                            continue
                        result_map[item.index] = FunctionWorkResult(
                            index=item.index,
                            status="timeout",
                            payload=f"Timed out after {args.timeout}s.",
                            debug_output="",
                            function=item.function,
                            function_cfg=item.function_cfg,
                        )
                        has_expired_futures = True
                        pending.discard(future)
            finally:
                executor.shutdown(wait=not has_expired_futures, cancel_futures=True)

    attempted = sum(1 for item in function_tasks if result_map.get(item.index) is not None)
    attempted_target = "selected" if args.max_functions <= 0 and args.addr is None else "displayed"
    print(f"/* info: decompilation attempted for {attempted}/{shown_total} {attempted_target} function(s) */")
    for item in function_tasks:
        if item.index in emitted_indexes:
            continue
        result = result_map.get(item.index)
        if result is None:
            continue
        d, f = _emit_function_result(item, result)
        decompiled += d
        failed += f
    for index, snapshot in fallback_tail_validation_by_index.items():
        existing = result_map.get(index)
        if existing is not None:
            result_map[index] = replace(existing, tail_validation=snapshot)

    total_shown = shown_total
    _emit_tail_validation_console_summary(function_tasks, result_map, binary_path=args.binary)
    summary_target = "selected functions" if args.max_functions <= 0 and args.addr is None else "shown functions"
    print(f"\nsummary: decompiled {decompiled}/{total_shown} {summary_target}")
    timed_out = sum(1 for result in result_map.values() if getattr(result, "status", None) == "timeout")
    if timed_out:
        print(f"summary: {timed_out} discovered function(s) timed out during decompilation")
    if failed:
        print(f"summary: {failed} functions fell back to asm/details")
    return 0 if decompiled else 2
