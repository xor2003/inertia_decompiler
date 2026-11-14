# cython: language_level=3, infer_types=True
"""Layer: Recovery/reporting.

Responsibility: scan corpora and report decompilation, readability, and validation outcomes.
Forbidden: making scan outcomes a semantic recovery source or acceptance shortcut.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations
import typing
import cython

import builtins
import io
import logging
import re
import resource
import signal
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import FrameType
from typing import Any, cast

import angr

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.cod_extract import join_cod_entries_with_synthetic_globals
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.analysis_helpers import INT21_SERVICE_SPECS, INTERRUPT_SERVICE_SPECS, seed_calling_conventions
from inertia.validation.recovery_confidence import (
    RecoveryConfidenceSummary,
    classify_x86_16_recovery_confidence,
    summarize_recovery_confidence,
)
from inertia.validation.tail_validation import (
    build_x86_16_tail_validation_aggregate,
    extract_x86_16_tail_validation_snapshot,
)

from .readability_goals import classify_readability_cluster
import dataclasses
import operator


@cython.ccall
def _silence_scan_loggers() -> None:
    name: object
    for name in (
        "angr.state_plugins.unicorn_engine",
        "angr.analyses.analysis",
        "angr.analyses.decompiler.clinic",
        "angr.analyses.decompiler.callsite_maker",
        "inertia.frontend.x86_16.lift_86_16",
        "inertia.frontend.x86_16.lift_86_16",
    ):
        logging.getLogger(name).setLevel(logging.CRITICAL)


_silence_scan_loggers()


@cython.ccall
def _dynamic_corpus_scan_getattr_8616(obj: object, name: object, default: object = None) -> Any:  # noqa: ANN401
    """Read an attribute across the dynamic angr/Capstone/codegen boundary."""
    return builtins.getattr(obj, name, default)


@cython.ccall
def _dynamic_corpus_scan_tuple_attr_8616(obj: object, name: object) -> tuple[object, ...]:
    """Read tuple-like data across the dynamic angr/Capstone/codegen boundary."""
    value: object
    value = _dynamic_corpus_scan_getattr_8616(obj, name, ())
    if value is None:
        return ()
    try:
        return tuple(cast(Any, value))
    except TypeError:
        return ()


@cython.ccall
def _counter_payload_8616(payload: object, key: object) -> Counter[object]:
    """Return a counter payload produced by the scan summary builders."""
    value: object
    value = payload.get(key)
    return value if isinstance(value, Counter) else Counter()


@cython.ccall
def _int_payload_8616(payload: object, key: object) -> cython.longlong:
    """Return an integer payload produced by the scan summary builders."""
    value: object
    value = payload.get(key, 0)
    return value if isinstance(value, int) else 0


@cython.ccall
def _dict_payload_8616(payload: object, key: object) -> object:
    """Return a dictionary payload produced by scan aggregation helpers."""
    value: object
    value = payload.get(key)
    return value if isinstance(value, dict) else {}

ENTRY_RE: re.Pattern[str] = re.compile(r"\*\*\*\s+([0-9A-Fa-f]+)\s+((?:[0-9A-Fa-f]{2}\s+)+)(.*)$")
PROC_RE: re.Pattern[str] = re.compile(r"^([^\s]+)\tPROC (NEAR|FAR)$")


@cython.dataclasses.dataclass
class StageResult:
    """Single scan pipeline stage verdict."""

    stage: object
    ok: cython.bint
    reason: object = None
    detail: object = None


@cython.dataclasses.dataclass
class FunctionScanResult:
    """Structured per-function corpus scan result."""

    cod_file: object
    proc_name: object
    proc_kind: object
    byte_len: cython.longlong
    has_near_call_reloc: cython.bint
    has_far_call_reloc: cython.bint
    ok: cython.bint = False
    stage_reached: str = "init"
    failure_class: object = None
    reason: object = None
    fallback_kind: object = None
    function_count: cython.longlong = 0
    decompiled_count: cython.longlong = 0
    interrupt_dos_helper_count: cython.longlong = 0
    interrupt_bios_helper_count: cython.longlong = 0
    interrupt_wrapper_call_count: cython.longlong = 0
    interrupt_unresolved_wrapper_count: cython.longlong = 0
    semantic_family: object = None
    semantic_family_reason: object = None
    readability_cluster: object = None
    readability_cluster_reason: object = None
    last_postprocess_pass: object = None
    rewrite_failed: cython.bint = False
    rewrite_failure_pass: object = None
    rewrite_failure_reason: object = None
    regeneration_failed: cython.bint = False
    regeneration_failure_pass: object = None
    regeneration_failure_reason: object = None
    structuring_failed: cython.bint = False
    structuring_failure_pass: object = None
    structuring_failure_reason: object = None
    last_structuring_pass: object = None
    confidence_status: object = None
    confidence_scan_safe_classification: object = None
    confidence_evidence_count: cython.longlong = 0
    confidence_assumption_count: cython.longlong = 0
    confidence_diagnostic_count: cython.longlong = 0
    confidence_evidence_kinds: tuple[str, ...] = ()
    confidence_assumption_kinds: tuple[str, ...] = ()
    confidence_diagnostics: tuple[str, ...] = ()
    tail_validation: object = None
    stages: object = field(default_factory=list)


class ScanTimeout(Exception):
    """Raised when a bounded corpus scan exceeds its per-function timeout."""


def _patch_scan_destructors() -> None:
    from angr.knowledge_plugins.rtdb import rtdb

    if _dynamic_corpus_scan_getattr_8616(rtdb.RuntimeDb.__del__, "_inertia_scan_safe", False):
        return

    original_del = rtdb.RuntimeDb.__del__

    def _safe_del(self: object) -> None:
        try:
            original_del(cast(Any, self))
        except Exception:
            return

    cast(Any, _safe_del)._inertia_scan_safe = True
    rtdb.RuntimeDb.__del__ = _safe_del


_patch_scan_destructors()


_SCAN_ACTIVE: cython.bint = False
_SCAN_TIMEOUT_FINALIZER_RETRY_SECONDS: cython.double = 0.01


@cython.ccall
def _alarm_handler(_signum: cython.longlong, frame: object) -> None:
    """Raise a scan timeout outside Python finalizers.

    Asynchronous exceptions raised inside ``__del__`` become unraisable and
    consume the timeout. A short retry preserves the deadline while allowing
    best-effort finalizers to finish.
    """
    global _SCAN_ACTIVE
    if not _SCAN_ACTIVE:
        return
    if frame is not None and frame.f_code.co_name == "__del__":
        signal.setitimer(signal.ITIMER_REAL, _SCAN_TIMEOUT_FINALIZER_RETRY_SECONDS)
        return
    _SCAN_ACTIVE = False
    _clear_alarm()
    raise ScanTimeout("timed out")


@cython.ccall
def _clear_alarm() -> None:
    signal.alarm(0)


def _finish_scan(result: FunctionScanResult) -> FunctionScanResult:
    global _SCAN_ACTIVE
    _SCAN_ACTIVE = False
    confidence = classify_x86_16_recovery_confidence(asdict(result))
    result.confidence_status = confidence.status
    result.confidence_scan_safe_classification = confidence.scan_safe_classification
    result.confidence_evidence_count = len(confidence.evidence)
    result.confidence_assumption_count = len(confidence.assumptions)
    result.confidence_diagnostic_count = len(confidence.diagnostics)
    result.confidence_evidence_kinds = tuple(item.kind for item in iter(confidence.evidence))
    result.confidence_assumption_kinds = tuple(item.kind for item in iter(confidence.assumptions))
    result.confidence_diagnostics = confidence.diagnostics
    _clear_alarm()
    return result


@cython.ccall
def _interrupt_api_helper_names() -> tuple[set[str], set[str]]:
    spec: object
    dos_names: set[str] = set()
    bios_names: set[str] = set()
    for spec in INT21_SERVICE_SPECS.values():
        dos_names.update({spec.pseudo_name, spec.dos_name, spec.modern_name})
    for spec in INTERRUPT_SERVICE_SPECS.values():
        bios_names.update({spec.pseudo_name, spec.dos_name, spec.modern_name})
    return dos_names, bios_names


_INTERRUPT_DOS_HELPER_NAMES, _INTERRUPT_BIOS_HELPER_NAMES = _interrupt_api_helper_names()

_ADDRESSING_HELPER_NAMES = {
    "address_width_bits",
    "advance_eip32",
    "advance_ip16",
    "decode_width_profile",
    "default_segment_for_modrm16",
    "default_segment_for_modrm32",
    "linear_address",
    "load_far_pointer",
    "load_far_pointer16",
    "load_resolved_operand",
    "load_word_pair16",
    "resolve_linear_operand",
    "store_resolved_operand",
    "width_profile",
}
_STACK_HELPER_NAMES = {
    "branch_rel16",
    "branch_rel32",
    "branch_rel8",
    "emit_far_call16",
    "emit_far_call32",
    "emit_far_jump16",
    "emit_far_jump32",
    "emit_near_call16",
    "emit_near_call32",
    "emit_near_jump16",
    "emit_near_jump32",
    "loop_rel8",
    "pop_all16",
    "pop_all32",
    "pop_far_return_frame16",
    "pop_far_return_frame32",
    "pop_flags16",
    "pop_flags32",
    "pop_interrupt_frame16",
    "pop_interrupt_frame32",
    "pop_segment16",
    "pop_segment32",
    "push16",
    "push16_register",
    "push32",
    "push32_register",
    "push_all16",
    "push_all32",
    "push_far_return_frame16",
    "push_far_return_frame32",
    "push_flags16",
    "push_flags32",
    "push_immediate16",
    "push_immediate32",
    "push_privilege_stack32",
    "push_segment16",
    "push_segment32",
    "return_far16",
    "return_far32",
    "return_interrupt16",
    "return_interrupt32",
    "return_near16",
    "return_near32",
}
_STRING_HELPER_NAMES = {
    "direction_step",
    "repeat_kind",
    "string_load",
    "string_store",
}
_ALU_HELPER_NAMES = {
    "binary_",
    "compare_",
    "rotate_",
    "shift_",
    "unary_",
    "update_eflags",
}


def _count_named_helper_calls(text: object, names: object) -> cython.longlong:
    if not text or not names:
        return 0
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(name) for name in builtins.iter(sorted(names, key=len, reverse=True))) + r")\s*\("
    )
    return len(pattern.findall(text))


@cython.ccall
def _count_interrupt_wrapper_calls(text: object) -> cython.longlong:
    if not text:
        return 0
    return len(re.findall(r"(?<![A-Za-z0-9_])(?:int86x?|intdosx?)\s*\(", text))


def _classify_semantic_family_from_text(
    text: object, result: FunctionScanResult | None = None
) -> tuple[str | None, str | None]:
    family: object
    markers: object
    if result is not None and (
        result.interrupt_dos_helper_count or result.interrupt_bios_helper_count or result.interrupt_wrapper_call_count
    ):
        return "interrupt_api", "interrupt helper or wrapper calls detected"

    if not text:
        return None, None

    text_lower = text.lower()
    family_markers = (
        (
            "interrupt_api",
            _INTERRUPT_DOS_HELPER_NAMES | _INTERRUPT_BIOS_HELPER_NAMES | {"int86", "int86x", "intdos", "intdosx"},
        ),
        ("string", _STRING_HELPER_NAMES),
        ("stack_control", _STACK_HELPER_NAMES),
        ("addressing", _ADDRESSING_HELPER_NAMES),
        ("alu", _ALU_HELPER_NAMES),
    )
    for family, markers in family_markers:
        if any(marker.lower() in text_lower for marker in iter(markers)):
            return family, f"{family} helper markers detected"
    return None, None


def _classify_semantic_family_from_failure(result: FunctionScanResult) -> object:
    def _impl() -> tuple[str | None, str | None]:
        family: object
        markers: object
        reason: object
        parts = " ".join(
            part.lower()
            for part in iter((result.failure_class,
                result.reason,
                ) + tuple((stage.reason or "" for stage in iter(result.stages))) + tuple((stage.detail or "" for stage in iter(result.stages))))
            if part
        )
        if not parts:
            return None, None
        families = (
            (
                "interrupt_api",
                "failure text points at interrupt/API lowering",
                ("interrupt", "int86", "intdos", "bios"),
            ),
            ("string", "failure text points at string family", ("string", "rep", "cmps", "stos", "lods", "scas")),
            (
                "stack_control",
                "failure text points at stack/control family",
                ("stack", "frame", "retf", "callf", "branch", "loop"),
            ),
            (
                "addressing",
                "failure text points at addressing family",
                ("address", "segment", "modrm", "pointer", "width"),
            ),
            ("alu", "failure text points at alu family", ("flag", "shift", "rotate", "alu")),
        )
        for family, reason, markers in families:
            if any(marker in parts for marker in iter(markers)):
                return family, reason
        return None, None

    return _impl()


@cython.ccall
def set_memory_limit(max_memory_mb: cython.longlong) -> None:
    """Set an address-space limit for corpus scanning when requested."""
    if max_memory_mb <= 0:
        return
    limit_bytes = max_memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


@cython.ccall
def extract_cod_functions(cod_path: Path) -> object:
    """Extract COD procedures as normalized byte blobs for corpus scanning."""
    entry_match: object
    proc_match: object
    line: object
    lines = cod_path.read_text(errors="ignore").splitlines()
    out: list[tuple[str, str, bytes]] = []
    collect = False
    proc_name = ""
    proc_kind = ""
    entries: list[dict[str, object]] = []

    for line in lines:
        proc_match = PROC_RE.match(line)
        if proc_match:
            collect = True
            proc_name, proc_kind = proc_match.groups()
            entries = []
            continue

        if collect and f"{proc_name}\tENDP" in line:
            code, _synthetic_globals = join_cod_entries_with_synthetic_globals(entries)
            out.append((proc_name, proc_kind, code))
            collect = False
            proc_name = ""
            proc_kind = ""
            entries = []
            continue

        if not collect:
            continue

        entry_match = ENTRY_RE.search(line)
        if entry_match:
            entries.append(
                {
                    "offset": int(entry_match.group(1), 16),
                    "bytes": bytes.fromhex("".join(entry_match.group(2).split())),
                    "text": entry_match.group(3).strip(),
                }
            )

    return out


@cython.ccall
def project_from_bytes(code: object) -> angr.Project:
    """Build a bounded blob project for one normalized COD procedure."""
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


@cython.ccall
def _stage_failure_class_8616(stage: object) -> object:
    """Map a pipeline stage name onto its stable failure class."""
    stage_failure_classes = {
        "load": "load_failure",
        "lift": "lift_failure",
        "cfg": "cfg_failure",
        "decompile": "decompiler_crash",
    }
    return stage_failure_classes.get(stage, "analysis_failure")


@cython.ccall
def _failure_class_from_message_8616(stage: object, message: object) -> tuple[str, str]:
    """Classify a failure by its exception message text."""
    lowered = message.lower()
    if "recursion" in lowered or "maximum recursion depth" in lowered:
        return "recursion_or_explosion", message
    if "unsupported" in lowered or "unknown opcode" in lowered or "not implemented" in lowered:
        return "unsupported_semantic", message
    if "render" in lowered or "codegen" in lowered:
        return "renderer_failure", message
    if "postprocess" in lowered or "simplify" in lowered:
        return "postprocess_failure", message
    return _stage_failure_class_8616(stage), message


@cython.ccall
def classify_failure(
    stage: object,
    exc: object,
    *,
    empty_codegen: cython.bint = False,
    rewrite_failed: cython.bint = False,
    regeneration_failed: cython.bint = False,
) -> object:
    """Classify a scan failure into stable reporting buckets."""
    if empty_codegen:
        if rewrite_failed:
            return "rewrite_failure", "Decompiler postprocess rewrite failed."
        if regeneration_failed:
            return "regeneration_failure", "Decompiler text regeneration failed."
        return "no_code_produced", "Decompiler did not produce code."
    if isinstance(exc, ScanTimeout):
        return "timeout", "timed out"
    if isinstance(exc, AssertionError):
        message = str(exc)
        return "analysis_assertion", message or "assertion failure"
    if rewrite_failed:
        return "rewrite_failure", "Decompiler postprocess rewrite failed."
    if regeneration_failed:
        return "regeneration_failure", "Decompiler text regeneration failed."
    if exc is None:
        return _stage_failure_class_8616(stage), "missing exception details"
    return _failure_class_from_message_8616(stage, str(exc))


@cython.ccall
def _mark_stage(
    result: FunctionScanResult, stage: object, ok: cython.bint, *, reason: object = None, detail: object = None
) -> None:
    result.stages.append(StageResult(stage=stage, ok=ok, reason=reason, detail=detail))
    result.stage_reached = stage


@cython.ccall
def _ugly_cluster_from_details_8616(details: object) -> object:
    """Match the aggregated failure details onto a stable cluster name."""
    if "empty codegen" in details or "no_code_produced" in details:
        return "empty_codegen"
    if "recursion" in details or "maximum recursion depth" in details:
        return "recursion_or_explosion"
    if "unsupported" in details or "unknown opcode" in details or "not implemented" in details:
        return "unsupported_semantics"
    if "oversized function" in details:
        return "oversized_function"
    if "complex cfg" in details or "pathological cfg" in details:
        return "control_flow_explosion"
    if "loop-heavy" in details:
        return "loop_heavy_helper"
    return None


@cython.ccall
def _ugly_cluster_from_fallback_8616(fallback_kind: object) -> object:
    """Map a fallback kind onto its recovery cluster name."""
    fallback_clusters = {
        "cfg_only": "cfg_only_recovery",
        "lift_only": "lift_only_recovery",
        "block_lift": "block_lift_recovery",
    }
    if fallback_kind is None:
        return None
    return fallback_clusters.get(fallback_kind)


def _classify_ugly_cluster(result: FunctionScanResult) -> object:
    cluster: object
    parts: list[str] = []
    if result.reason:
        parts.append(result.reason)
    if result.failure_class:
        parts.append(result.failure_class)
    parts.extend(stage.reason for stage in iter(result.stages) if stage.reason)
    parts.extend(stage.detail for stage in iter(result.stages) if stage.detail)
    details = " ".join(part.lower() for part in iter(parts))

    if result.failure_class == "timeout":
        return "timeout_hotspot"
    if result.failure_class == "skipped_relocation":
        return "call_relocation_rescue"
    cluster = _ugly_cluster_from_details_8616(details)
    if cluster is not None:
        return cluster
    cluster = _ugly_cluster_from_fallback_8616(result.fallback_kind)
    if cluster is not None:
        return cluster
    if not result.ok:
        return "analysis_failure"
    return None


def _classify_readability_cluster(result: FunctionScanResult, text: object) -> object:
    if not result.ok or result.fallback_kind not in (None, "none"):
        return None, None
    classification = classify_readability_cluster(text)
    if (
        isinstance(classification, tuple)
        and len(classification) == 2
        and all(item is None or isinstance(item, str) for item in iter(classification))
    ):
        return classification
    return None, None


@cython.ccall
def _scan_cfg(project: angr.Project, code_len: cython.longlong) -> object:
    return project.analyses.CFGFast(
        normalize=True,
        force_complete_scan=False,
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1000 + max(code_len, 1))],
    )


@cython.ccall
def _should_skip_scan_safe_decompile(code_len: cython.longlong, mode: object, max_decompile_bytes: cython.longlong) -> cython.bint:
    return mode == "scan-safe" and max_decompile_bytes > 0 and code_len > max_decompile_bytes


@cython.ccall
def _should_skip_scan_safe_cfg(code_len: cython.longlong, mode: object, max_cfg_bytes: cython.longlong) -> cython.bint:
    return mode == "scan-safe" and max_cfg_bytes > 0 and code_len > max_cfg_bytes


def _probe_scan_safe_lift(code: object, mode: object, max_cfg_bytes: cython.longlong, probe_bytes: cython.longlong = 16) -> object:
    def _impl() -> object:
        if mode != "scan-safe" or not code:
            return None

        local_probe_bytes = probe_bytes
        if max_cfg_bytes > 0:
            local_probe_bytes = min(local_probe_bytes, max_cfg_bytes)

        arch = Arch86_16()
        raw = code[: max(1, local_probe_bytes)]
        insns = list(arch.capstone.disasm(raw, 0x1000, 1))
        if insns:
            return bytes(insns[0].bytes)

        prefix_len = 0
        saw_lock = False
        while prefix_len < len(raw) and raw[prefix_len] in {0x26, 0x2E, 0x36, 0x3E, 0xF0, 0xF2, 0xF3}:
            if raw[prefix_len] == 0xF0:
                saw_lock = True
            prefix_len += 1
        if saw_lock and prefix_len < len(raw):
            stripped = list(arch.capstone.disasm(raw[prefix_len:], 0x1000 + prefix_len, 1))
            if stripped:
                return raw[: prefix_len + len(stripped[0].bytes)]

        raise RuntimeError("Unable to decode first instruction from scan-safe prefix")

    return _impl()


@cython.ccall
def _decode_scan_safe_prefix_insns(code: object, mode: object, max_bytes: cython.longlong) -> tuple[object, ...]:
    if mode != "scan-safe" or max_bytes <= 0 or not code:
        return ()

    arch = Arch86_16()
    arch.capstone.detail = True
    return tuple(arch.capstone.disasm(code[: min(len(code), max_bytes)], 0x1000))


@cython.ccall
def _should_skip_scan_safe_call_chain(
    capstone_block: object, mode: object, max_cfg_bytes: cython.longlong, min_call_count: cython.longlong = 3
) -> cython.bint:
    insn: object
    if mode != "scan-safe" or max_cfg_bytes <= 0:
        return False

    block = _dynamic_corpus_scan_getattr_8616(capstone_block, "insns", None)
    if not block:
        return False

    call_count = 0
    for insn in block:
        if _dynamic_corpus_scan_getattr_8616(insn, "mnemonic", "").lower() != "call":
            continue
        call_count += 1
        if call_count >= min_call_count:
            return True
    return False


@cython.ccall
def _should_skip_scan_safe_call_chain_from_insns(
    insns: Sequence[object], mode: object, max_cfg_bytes: cython.longlong, min_call_count: cython.longlong = 3
) -> cython.bint:
    insn: object
    if mode != "scan-safe" or max_cfg_bytes <= 0:
        return False

    call_count = 0
    for insn in insns:
        if _dynamic_corpus_scan_getattr_8616(insn, "mnemonic", "").lower() != "call":
            continue
        call_count += 1
        if call_count >= min_call_count:
            return True
    return False


@cython.ccall
def _tiny_guard_pre_call_ok_8616(
    insns: Sequence[object], call_idx: cython.longlong, conditional_jump_idx: cython.longlong
) -> cython.bint:
    """Check that pre-call instructions stay within the allowed guard set."""
    idx: object
    insn: object
    allowed_pre_call = {"cmp", "test", "push", "mov", "lea", "xor", "or", "and", "sub"}
    for idx, insn in enumerate(insns[:call_idx]):
        if idx == conditional_jump_idx:
            continue
        if _dynamic_corpus_scan_getattr_8616(insn, "mnemonic", "").lower() not in allowed_pre_call:
            return False
    return True


@cython.ccall
def _tiny_guard_post_call_ok_8616(insns: Sequence[object], call_idx: cython.longlong) -> cython.bint:
    """Check that post-call instructions are nops or sp-restoring adds."""
    insn: object
    for insn in insns[call_idx + 1 : -1]:
        mnemonic = _dynamic_corpus_scan_getattr_8616(insn, "mnemonic", "").lower()
        if mnemonic == "nop":
            continue
        if mnemonic != "add" or not _dynamic_corpus_scan_getattr_8616(insn, "op_str", "").replace(" ", "").startswith("sp,"):
            return False
    return True


def _should_skip_scan_safe_tiny_guard_call_helper(
    insns: Sequence[object], mode: object, max_cfg_bytes: cython.longlong, max_insns: cython.longlong = 8
) -> cython.bint:
    conditional_jump_idx: object
    if mode != "scan-safe" or max_cfg_bytes <= 0 or not insns:
        return False

    local_insns = tuple(insns)
    if len(local_insns) > max_insns:
        return False

    total_bytes = sum(len(_dynamic_corpus_scan_getattr_8616(insn, "bytes", b"")) or 1 for insn in iter(local_insns))
    if total_bytes > max_cfg_bytes:
        return False

    calls = [idx for idx, insn in builtins.iter(enumerate(local_insns)) if _dynamic_corpus_scan_getattr_8616(insn, "mnemonic", "").lower() == "call"]
    if len(calls) != 1:
        return False
    call_idx = calls[0]

    rets = [idx for idx, insn in builtins.iter(enumerate(insns)) if _dynamic_corpus_scan_getattr_8616(insn, "mnemonic", "").lower().startswith("ret")]
    if len(rets) != 1 or operator.ne(rets[0], len(insns) - 1):
        return False
    conditional_jump_idx = _tiny_guard_conditional_jump_index_8616(insns, call_idx)
    if conditional_jump_idx is None:
        return False

    if not _tiny_guard_pre_call_ok_8616(insns, call_idx, conditional_jump_idx):
        return False
    return _tiny_guard_post_call_ok_8616(insns, call_idx)


def _tiny_guard_conditional_jump_index_8616(insns: Sequence[object], call_idx: cython.longlong) -> int | None:
    def _impl() -> int | None:
        conditional_jump_idx: object
        target: object
        idx: object
        insn: object
        ret_addr = _dynamic_corpus_scan_getattr_8616(insns[-1], "address", None)
        if not isinstance(ret_addr, int):
            return None
        conditional_jump_idx = None
        for idx, insn in enumerate(insns):
            mnemonic = _dynamic_corpus_scan_getattr_8616(insn, "mnemonic", "").lower()
            if not mnemonic.startswith("j"):
                continue
            if mnemonic == "jmp" or mnemonic.startswith("loop"):
                return None
            if conditional_jump_idx is not None:
                return None
            operands = _dynamic_corpus_scan_getattr_8616(insn, "operands", ())
            if not operands:
                return None
            target = _dynamic_corpus_scan_getattr_8616(operands[0], "imm", None)
            if target is None and hasattr(operands[0], "value"):
                target = _dynamic_corpus_scan_getattr_8616(operands[0].value, "imm", None)
            if operator.ne(target, ret_addr) or idx >= call_idx:
                return None
            conditional_jump_idx = idx
        return conditional_jump_idx

    return _impl()


# Known hotspots that should use conservative recovery in scan-safe mode
# Format: (cod_filename, proc_name)
_SCAN_SAFE_KNOWN_HOTSPOTS = {
    ("OUTPUT.COD", "_hexdump"),
    ("START1.COD", "_processStoreInput"),
    ("UTIL.COD", "_sizeString"),
    ("START3.COD", "_sub_14BB4"),
}


@cython.ccall
def _should_skip_scan_safe_known_hotspot(cod_file: object, proc_name: object, mode: object) -> cython.bint:
    if mode != "scan-safe":
        return False
    return (cod_file, proc_name) in _SCAN_SAFE_KNOWN_HOTSPOTS


def _should_skip_scan_safe_back_edge(capstone_block: object, mode: object, max_loop_bytes: cython.longlong) -> cython.bint:
    def _impl() -> cython.bint:
        target: object
        insn: object
        if mode != "scan-safe" or max_loop_bytes <= 0:
            return False

        block = _dynamic_corpus_scan_getattr_8616(capstone_block, "insns", None)
        if not block:
            return False

        for insn in block:
            mnemonic = _dynamic_corpus_scan_getattr_8616(insn, "mnemonic", "")
            if not (mnemonic.startswith(("j", "loop"))):
                continue

            operands = _dynamic_corpus_scan_getattr_8616(insn, "operands", ())
            if not operands:
                continue
            target = _dynamic_corpus_scan_getattr_8616(operands[0], "imm", None)
            if target is None and hasattr(operands[0], "value"):
                target = _dynamic_corpus_scan_getattr_8616(operands[0].value, "imm", None)
            if target is None:
                continue
            insn_addr = _dynamic_corpus_scan_getattr_8616(insn, "address", None)
            if isinstance(insn_addr, int) and target < insn_addr and insn_addr < 0x1000 + (max_loop_bytes * 2):
                return True

        return False

    return _impl()


def _should_skip_scan_safe_decompile_for_cfg_shape(
    cfg: object, mode: object, max_cfg_blocks: cython.longlong, max_cfg_insns: cython.longlong
) -> cython.bint:
    func: object
    if mode != "scan-safe" or (max_cfg_blocks <= 0 and max_cfg_insns <= 0):
        return False
    cfg_any = cast(Any, cfg)
    func = cfg_any.functions.get(0x1000)
    if func is None:
        return False
    blocks = list(func.blocks)
    block_count = len(blocks)
    insn_count = sum(len(block.capstone.insns) for block in iter(blocks))
    return (max_cfg_blocks > 0 and block_count > max_cfg_blocks) or (max_cfg_insns > 0 and insn_count > max_cfg_insns)


@cython.ccall
def _fail_scan_stage(
    result: FunctionScanResult,
    *,
    stage: object,
    failure_class: object,
    reason: object,
    fallback_kind: object = None,
    classify_family: cython.bint = False,
) -> FunctionScanResult:
    result.failure_class = failure_class
    result.reason = reason
    if fallback_kind is not None:
        result.fallback_kind = fallback_kind
    if classify_family:
        result.semantic_family, result.semantic_family_reason = _classify_semantic_family_from_failure(result)
    _mark_stage(result, stage, False, reason=failure_class, detail=reason)
    return _finish_scan(result)


@cython.ccall
def _finish_scan_safe_skip(
    result: FunctionScanResult,
    *,
    fallback_kind: object,
    family: object,
    family_reason: object,
    stage: object,
    detail: object,
    mark_lift_decode: cython.bint = False,
) -> FunctionScanResult:
    result.function_count = 1
    result.ok = True
    result.fallback_kind = fallback_kind
    result.semantic_family, result.semantic_family_reason = family, family_reason
    if mark_lift_decode:
        _mark_stage(result, "lift", True, detail="bounded scan-safe instruction decode")
    _mark_stage(result, stage, True, detail=detail)
    _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")
    return _finish_scan(result)


@cython.ccall
def _scan_has_fallback_kind_8616(result: FunctionScanResult) -> cython.bint:
    return result.fallback_kind not in (None, "none")


def _sorted_top_8616(counter: Counter[Any], key_name: object) -> list[dict[str, object]]:
    return [
        {key_name: key, "count": count} for key, count in builtins.iter(sorted(tuple(counter.items()), key=lambda item: (-item[1], item[0])))
    ]


def _sorted_top_tuples_8616(counter: Counter[Any], field_names: object) -> object:
    count: object
    keys: object
    rows: list[dict[str, object]] = []
    for keys, count in sorted(tuple(counter.items()), key=lambda item: (-item[1], item[0])):
        row: dict[str, object] = dict(zip(field_names, keys, strict=False))
        row["count"] = count
        rows.append(row)
    return rows


def _classify_scan_files_8616(results: object) -> tuple[list[str], list[str], list[str]]:
    result: object
    per_file: object = defaultdict(lambda: {"scanned": 0, "ok": 0})
    for result in results:
        per_file[result.cod_file]["scanned"] += 1
        if result.ok:
            per_file[result.cod_file]["ok"] += 1
    files_zero_success = sorted(name for name, stats in builtins.iter(per_file.items()) if stats["ok"] == 0)
    files_scan_clean = sorted(name for name, stats in builtins.iter(per_file.items()) if operator.eq(stats["ok"], stats["scanned"]))
    files_partial_success = sorted(name for name, stats in builtins.iter(per_file.items()) if 0 < stats["ok"] < stats["scanned"])
    return files_zero_success, files_scan_clean, files_partial_success


@cython.ccall
def _aggregate_scan_tail_validation_8616(
    results: object,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    tail_validation_records = [
        {
            "cod_file": result.cod_file,
            "proc_name": result.proc_name,
            "proc_kind": result.proc_kind,
            "structuring": (result.tail_validation or {}).get("structuring"),
            "postprocess": (result.tail_validation or {}).get("postprocess"),
        }
        for result in iter(results)
    ]
    aggregate = build_x86_16_tail_validation_aggregate(tail_validation_records, scanned=len(results))
    return (
        _dict_payload_8616(aggregate, "summary"),
        _dict_payload_8616(aggregate, "surface"),
        {
            "cache_key": aggregate["cache_key"],
            "cache_hit": bool(aggregate["cache_hit"]),
        },
    )


@cython.ccall
def _scan_rate_8616(count: cython.longlong, total: cython.longlong) -> cython.double:
    if total <= 0:
        return 0.0
    return round(count / total, 6)


def _scan_summary_counters_8616(results: object) -> object:
    def _impl() -> dict[str, object]:
        confidence_summaries = [classify_x86_16_recovery_confidence(asdict(result)) for result in iter(results)]
        return {
            "confidence_summaries": confidence_summaries,
            "failure_counter": Counter(result.failure_class for result in iter(results) if result.failure_class is not None),
            "fallback_counter": Counter(
                result.fallback_kind for result in iter(results) if _scan_has_fallback_kind_8616(result)
            ),
            "stage_failure_counter": Counter(
                stage.stage for result in iter(results) for stage in iter(result.stages) if not stage.ok
            ),
            "timeout_stage_counter": Counter(
                stage.stage
                for result in iter(results)
                for stage in iter(result.stages)
                if not stage.ok and (stage.reason == "timeout" or result.failure_class == "timeout")
            ),
            "failure_file_counter": Counter(
                result.cod_file for result in iter(results) if not result.ok and result.failure_class is not None
            ),
            "failure_function_counter": Counter(
                (result.cod_file, result.proc_name, result.proc_kind, result.failure_class)
                for result in iter(results)
                if not result.ok and result.failure_class is not None
            ),
            "fallback_file_counter": Counter(
                result.cod_file for result in iter(results) if _scan_has_fallback_kind_8616(result)
            ),
            "fallback_function_counter": Counter(
                (result.cod_file, result.proc_name, result.proc_kind, result.fallback_kind)
                for result in iter(results)
                if _scan_has_fallback_kind_8616(result)
            ),
            "family_counter": Counter(
                result.semantic_family for result in iter(results) if result.semantic_family is not None
            ),
            "family_failure_counter": Counter(
                result.semantic_family for result in iter(results) if not result.ok and result.semantic_family is not None
            ),
            "family_fallback_counter": Counter(
                result.semantic_family
                for result in iter(results)
                if _scan_has_fallback_kind_8616(result) and result.semantic_family is not None
            ),
            "family_cluster_counter": Counter(
                (result.semantic_family, cluster)
                for result in iter(results)
                if (cluster := _classify_ugly_cluster(result)) is not None and result.semantic_family is not None
            ),
            "readability_cluster_counter": Counter(
                result.readability_cluster for result in iter(results) if result.readability_cluster is not None
            ),
            "ugly_cluster_counter": Counter(
                cluster for result in iter(results) if (cluster := _classify_ugly_cluster(result)) is not None
            ),
        }

    return _impl()


def _scan_summary_totals_8616(
    results: object, confidence_summaries: object
) -> object:
    def _impl() -> dict[str, object]:
        fallback_results = [result for result in iter(results) if _scan_has_fallback_kind_8616(result)]
        return {
            "files": _classify_scan_files_8616(results),
            "full_decompile_count": sum(1 for result in iter(results) if result.decompiled_count > 0),
            "cfg_only_count": sum(1 for result in iter(results) if result.fallback_kind == "cfg_only"),
            "lift_only_count": sum(1 for result in iter(results) if result.fallback_kind == "lift_only"),
            "block_lift_count": sum(1 for result in iter(results) if result.fallback_kind == "block_lift"),
            "rewrite_failure_count": sum(1 for result in iter(results) if result.rewrite_failed),
            "structuring_failure_count": sum(1 for result in iter(results) if result.structuring_failed),
            "regeneration_failure_count": sum(1 for result in iter(results) if result.regeneration_failed),
            "confidence_status_counter": Counter(summary.status for summary in iter(confidence_summaries)),
            "confidence_scan_safe_counter": Counter(
                summary.scan_safe_classification for summary in iter(confidence_summaries)
            ),
            "confidence_assumption_counter": Counter(
                item.kind for summary in iter(confidence_summaries) for item in iter(summary.assumptions)
            ),
            "confidence_evidence_counter": Counter(
                item.kind for summary in iter(confidence_summaries) for item in iter(summary.evidence)
            ),
            "confidence_diagnostic_counter": Counter(
                diagnostic for summary in iter(confidence_summaries) for diagnostic in iter(summary.diagnostics)
            ),
            "interrupt_dos_helper_count": sum(result.interrupt_dos_helper_count for result in iter(results)),
            "interrupt_bios_helper_count": sum(result.interrupt_bios_helper_count for result in iter(results)),
            "interrupt_wrapper_call_count": sum(result.interrupt_wrapper_call_count for result in iter(results)),
            "interrupt_unresolved_wrapper_count": sum(result.interrupt_unresolved_wrapper_count for result in iter(results)),
            "fallback_only_count": sum(1 for result in iter(fallback_results) if result.ok),
            "true_failure_count": sum(1 for result in iter(results) if not result.ok),
            "unclassified_failure_count": sum(
                1
                for result in iter(results)
                if not result.ok and result.failure_class in {"analysis_failure", "unknown_failure"}
            ),
        }

    return _impl()


def _scan_summary_output_8616(
    results: object, mode: object, counters: object, totals: object
) -> dict[str, object]:
    files_payload: object
    failure_counter = _counter_payload_8616(counters, "failure_counter")
    fallback_counter = _counter_payload_8616(counters, "fallback_counter")
    stage_failure_counter = _counter_payload_8616(counters, "stage_failure_counter")
    timeout_stage_counter = _counter_payload_8616(counters, "timeout_stage_counter")
    failure_file_counter = _counter_payload_8616(counters, "failure_file_counter")
    failure_function_counter = _counter_payload_8616(counters, "failure_function_counter")
    fallback_file_counter = _counter_payload_8616(counters, "fallback_file_counter")
    fallback_function_counter = _counter_payload_8616(counters, "fallback_function_counter")
    family_counter = _counter_payload_8616(counters, "family_counter")
    family_failure_counter = _counter_payload_8616(counters, "family_failure_counter")
    family_fallback_counter = _counter_payload_8616(counters, "family_fallback_counter")
    family_cluster_counter = _counter_payload_8616(counters, "family_cluster_counter")
    readability_cluster_counter = _counter_payload_8616(counters, "readability_cluster_counter")
    ugly_cluster_counter = _counter_payload_8616(counters, "ugly_cluster_counter")
    files_payload = totals.get("files", ((), (), ()))
    files_zero_success, files_scan_clean, files_partial_success = (
        files_payload if isinstance(files_payload, tuple) and len(files_payload) == 3 else ((), (), ())
    )
    full_decompile_count = _int_payload_8616(totals, "full_decompile_count")
    cfg_only_count = _int_payload_8616(totals, "cfg_only_count")
    lift_only_count = _int_payload_8616(totals, "lift_only_count")
    block_lift_count = _int_payload_8616(totals, "block_lift_count")
    fallback_only_count = _int_payload_8616(totals, "fallback_only_count")
    true_failure_count = _int_payload_8616(totals, "true_failure_count")

    top_failure_classes = _sorted_top_8616(failure_counter, "failure_class")
    top_fallback_kinds = _sorted_top_8616(fallback_counter, "fallback_kind")
    top_failure_stages = _sorted_top_8616(stage_failure_counter, "stage")
    top_failure_files = _sorted_top_8616(failure_file_counter, "cod_file")
    top_failure_functions = _sorted_top_tuples_8616(
        failure_function_counter,
        ("cod_file", "proc_name", "proc_kind", "failure_class"),
    )
    top_fallback_files = _sorted_top_8616(fallback_file_counter, "cod_file")
    top_fallback_functions = _sorted_top_tuples_8616(
        fallback_function_counter,
        ("cod_file", "proc_name", "proc_kind", "fallback_kind"),
    )
    top_ugly_clusters = _sorted_top_8616(ugly_cluster_counter, "cluster")
    top_family_ownership = _sorted_top_8616(family_counter, "family")
    top_family_failures = _sorted_top_8616(family_failure_counter, "family")
    top_family_fallbacks = _sorted_top_8616(family_fallback_counter, "family")
    family_ugly_clusters = _sorted_top_tuples_8616(family_cluster_counter, ("family", "cluster"))
    readability_clusters = _sorted_top_8616(readability_cluster_counter, "cluster")
    tail_validation_summary, tail_validation_surface, tail_validation_cache = _aggregate_scan_tail_validation_8616(
        results
    )

    return {
        "mode": mode,
        "scanned": len(results),
        "ok": sum(1 for result in iter(results) if result.ok),
        "failed": sum(1 for result in iter(results) if not result.ok),
        "failure_counts": dict(sorted(tuple(failure_counter.items()))),
        "fallback_counts": dict(sorted(tuple(fallback_counter.items()))),
        "top_failure_classes": top_failure_classes,
        "top_fallback_kinds": top_fallback_kinds,
        "top_failure_stages": top_failure_stages,
        "timeout_stage_counts": dict(sorted(tuple(timeout_stage_counter.items()))),
        "top_failure_files": top_failure_files,
        "top_failure_functions": top_failure_functions,
        "top_fallback_files": top_fallback_files,
        "top_fallback_functions": top_fallback_functions,
        "top_ugly_clusters": top_ugly_clusters,
        "readability_clusters": readability_clusters,
        "family_ownership": {
            "top_families": top_family_ownership,
            "top_failures": top_family_failures,
            "top_fallbacks": top_family_fallbacks,
            "top_ugly_clusters": family_ugly_clusters,
        },
        "files_zero_success": files_zero_success,
        "files_partial_success": files_partial_success,
        "files_scan_clean": files_scan_clean,
        "full_decompile_count": full_decompile_count,
        "cfg_only_count": cfg_only_count,
        "lift_only_count": lift_only_count,
        "block_lift_count": block_lift_count,
        "rewrite_failure_count": _int_payload_8616(totals, "rewrite_failure_count"),
        "structuring_failure_count": _int_payload_8616(totals, "structuring_failure_count"),
        "regeneration_failure_count": _int_payload_8616(totals, "regeneration_failure_count"),
        "fallback_only_count": fallback_only_count,
        "true_failure_count": true_failure_count,
        "visibility_debt": true_failure_count,
        "recovery_debt": fallback_only_count,
        "readability_debt": full_decompile_count,
        "unclassified_failure_count": _int_payload_8616(totals, "unclassified_failure_count"),
        "interrupt_api": {
            "dos_helpers": _int_payload_8616(totals, "interrupt_dos_helper_count"),
            "bios_helpers": _int_payload_8616(totals, "interrupt_bios_helper_count"),
            "wrapper_calls": _int_payload_8616(totals, "interrupt_wrapper_call_count"),
            "unresolved_wrappers": _int_payload_8616(totals, "interrupt_unresolved_wrapper_count"),
        },
        "confidence": summarize_recovery_confidence([asdict(result) for result in iter(results)]),
        "confidence_status_counts": dict(sorted(tuple(_counter_payload_8616(totals, "confidence_status_counter").items()))),
        "confidence_scan_safe_counts": dict(
            sorted(tuple(_counter_payload_8616(totals, "confidence_scan_safe_counter").items()))
        ),
        "confidence_assumption_counts": dict(
            sorted(tuple(_counter_payload_8616(totals, "confidence_assumption_counter").items()))
        ),
        "confidence_evidence_counts": dict(
            sorted(tuple(_counter_payload_8616(totals, "confidence_evidence_counter").items()))
        ),
        "confidence_diagnostic_counts": dict(
            sorted(tuple(_counter_payload_8616(totals, "confidence_diagnostic_counter").items()))
        ),
        "tail_validation": tail_validation_summary,
        "tail_validation_surface": tail_validation_surface,
        "tail_validation_cache": tail_validation_cache,
        "blind_spot_budget": {
            "full_decompile_rate": _scan_rate_8616(full_decompile_count, len(results)),
            "cfg_only_rate": _scan_rate_8616(cfg_only_count, len(results)),
            "lift_only_rate": _scan_rate_8616(lift_only_count, len(results)),
            "block_lift_rate": _scan_rate_8616(block_lift_count, len(results)),
            "true_failure_rate": _scan_rate_8616(true_failure_count, len(results)),
        },
        "debt": {
            "traversal": true_failure_count,
            "recovery": fallback_only_count,
            "readability": full_decompile_count,
        },
        "results": [asdict(result) for result in iter(results)],
    }


def _scan_safe_prefix_skip_result_8616(
    result: FunctionScanResult,
    *,
    code_len: cython.longlong,
    mode: object,
    max_cfg_bytes: cython.longlong,
    prefix_insns: Sequence[object],
    cod_file: Path,
) -> FunctionScanResult | None:
    def _impl() -> FunctionScanResult | None:
        is_3dplanes = "3DPLANES" in str(cod_file)
        is_oversized = _should_skip_scan_safe_cfg(code_len, mode, max_cfg_bytes)
        should_skip_call_chain = is_3dplanes and is_oversized
        if (
            prefix_insns
            and not should_skip_call_chain
            and _should_skip_scan_safe_call_chain_from_insns(prefix_insns, mode, max_cfg_bytes)
        ):
            call_count = sum(1 for insn in iter(prefix_insns) if _dynamic_corpus_scan_getattr_8616(insn, "mnemonic", "").lower() == "call")
            return _finish_scan_safe_skip(
                result,
                fallback_kind="cfg_only",
                family="stack_control",
                family_reason="call-heavy helper path",
                stage="cfg",
                detail=f"skipped cfg/decompile for call-heavy helper path ({call_count} calls in {code_len} bytes); lift ok",
                mark_lift_decode=True,
            )
        if prefix_insns and _should_skip_scan_safe_tiny_guard_call_helper(prefix_insns, mode, max_cfg_bytes):
            return _finish_scan_safe_skip(
                result,
                fallback_kind="cfg_only",
                family="stack_control",
                family_reason="tiny guard-call helper path",
                stage="cfg",
                detail=f"skipped cfg/decompile for tiny guard-call helper ({code_len} bytes); lift ok",
                mark_lift_decode=True,
            )
        if _should_skip_scan_safe_known_hotspot(result.cod_file, result.proc_name, mode):
            return _finish_scan_safe_skip(
                result,
                fallback_kind="cfg_only",
                family="stack_control",
                family_reason="known hotspot conservative recovery",
                stage="cfg",
                detail=f"skipped cfg/decompile for known hotspot ({code_len} bytes); lift ok",
                mark_lift_decode=True,
            )
        if not is_oversized:
            return None
        result.function_count = 1
        result.ok = True
        result.fallback_kind = "lift_only"
        result.semantic_family, result.semantic_family_reason = (
            "addressing",
            "oversized function skipped before decompile",
        )
        _mark_stage(result, "lift", True, detail="bounded scan-safe prefix lift")
        _mark_stage(
            result,
            "cfg",
            True,
            detail=(
                "bounded scan-safe prefix lift ok; "
                f"skipped cfg/decompile for oversized function ({code_len} bytes > {max_cfg_bytes}); lift ok"
            ),
        )
        _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")
        return _finish_scan(result)

    return _impl()


@cython.ccall
def _lift_block_scan_stage_8616(
    result: FunctionScanResult,
    project: angr.Project,
    code: object,
) -> FunctionScanResult | None:
    """Lift the whole blob to VEX; return a failure result or None."""
    try:
        project.factory.block(0x1000, len(code)).vex  # noqa: B018
        _mark_stage(result, "lift", True)
    except Exception as exc:
        failure_class, reason = classify_failure("lift", exc)
        return _fail_scan_stage(result, stage="lift", failure_class=failure_class, reason=reason)
    return None


@cython.ccall
def _scan_safe_probe_lift_8616(
    result: FunctionScanResult,
    code: object,
    mode: object,
    max_cfg_bytes: cython.longlong,
) -> FunctionScanResult | None:
    """Run the bounded scan-safe lift probe; return a failure result or None."""
    if mode != "scan-safe" or max_cfg_bytes <= 0:
        return None
    try:
        _probe_scan_safe_lift(code, mode, max_cfg_bytes)
    except Exception as exc:
        failure_class, reason = classify_failure("lift", exc)
        return _fail_scan_stage(result, stage="lift", failure_class=failure_class, reason=reason)
    return None


def _scan_safe_cfg_preflight_8616(
    result: FunctionScanResult,
    project: angr.Project,
    code: object,
    mode: object,
    max_cfg_bytes: cython.longlong,
    max_loop_bytes: cython.longlong,
) -> FunctionScanResult | None:
    """Return an early skip result for relocation/loop/call-heavy helpers."""
    loop_block: object
    if mode == "decompile-reloc-free" and (result.has_near_call_reloc or result.has_far_call_reloc):
        return _fail_scan_stage(
            result,
            stage="cfg",
            failure_class="skipped_relocation",
            reason="contains unresolved call relocation pattern",
            fallback_kind="block_lift",
            classify_family=True,
        )

    loop_block = None
    if mode == "scan-safe" and max_loop_bytes > 0:
        loop_block = project.factory.block(0x1000, len(code))
        if _should_skip_scan_safe_back_edge(loop_block.capstone, mode, max_loop_bytes):
            return _finish_scan_safe_skip(
                result,
                fallback_kind="cfg_only",
                family="stack_control",
                family_reason="loop-heavy helper path",
                stage="cfg",
                detail=(
                    f"skipped cfg/decompile for short loop-heavy function ({len(code)} bytes <= {max_loop_bytes}); "
                    "lift ok"
                ),
                mark_lift_decode=False,
            )

    if mode == "scan-safe" and loop_block is None:
        loop_block = project.factory.block(0x1000, len(code))

    if loop_block is not None and _should_skip_scan_safe_call_chain(loop_block.capstone, mode, max_cfg_bytes):
        call_count = sum(
            1
            for insn in builtins.iter(_dynamic_corpus_scan_getattr_8616(loop_block.capstone, "insns", ()))
            if _dynamic_corpus_scan_getattr_8616(insn, "mnemonic", "").lower() == "call"
        )
        return _finish_scan_safe_skip(
            result,
            fallback_kind="cfg_only",
            family="stack_control",
            family_reason="call-heavy helper path",
            stage="cfg",
            detail=f"skipped cfg/decompile for call-heavy helper path ({call_count} calls in {len(code)} bytes); lift ok",
            mark_lift_decode=False,
        )
    return None


@cython.ccall
def _cfg_shape_scan_skip_8616(
    result: FunctionScanResult,
    cfg: object,
    code: object,
    mode: object,
    max_cfg_blocks: cython.longlong,
    max_cfg_insns: cython.longlong,
    max_decompile_bytes: cython.longlong,
) -> FunctionScanResult | None:
    """Return a cfg_only result when CFG shape or size blocks decompile."""
    if _should_skip_scan_safe_decompile_for_cfg_shape(cfg, mode, max_cfg_blocks, max_cfg_insns):
        result.ok = True
        result.fallback_kind = "cfg_only"
        result.semantic_family, result.semantic_family_reason = (
            "stack_control",
            "complex CFG skipped before decompile",
        )
        _mark_stage(
            result,
            "decompile",
            True,
            detail=(
                f"skipped decompile for complex CFG (blocks>{max_cfg_blocks} or insns>{max_cfg_insns}); cfg ok"
            ),
        )
        return _finish_scan(result)

    if _should_skip_scan_safe_decompile(len(code), mode, max_decompile_bytes):
        result.ok = True
        result.fallback_kind = "cfg_only"
        result.semantic_family, result.semantic_family_reason = (
            "addressing",
            "oversized function skipped before decompile",
        )
        _mark_stage(
            result,
            "decompile",
            True,
            detail=f"skipped decompile for oversized function ({len(code)} bytes > {max_decompile_bytes}); cfg ok",
        )
        return _finish_scan(result)
    return None


@cython.ccall
def _record_codegen_diagnostics_8616(result: FunctionScanResult, codegen: object) -> None:
    """Copy structuring/rewrite/regeneration failure diagnostics off codegen."""
    if codegen is None:
        return
    result.last_postprocess_pass = _dynamic_corpus_scan_getattr_8616(codegen, "_inertia_last_postprocess_pass", None)
    result.last_structuring_pass = _dynamic_corpus_scan_getattr_8616(codegen, "_inertia_last_structuring_pass", None)
    result.rewrite_failed = bool(_dynamic_corpus_scan_getattr_8616(codegen, "_inertia_rewrite_failed", False))
    result.rewrite_failure_pass = _dynamic_corpus_scan_getattr_8616(codegen, "_inertia_rewrite_failure_pass", None)
    result.rewrite_failure_reason = _dynamic_corpus_scan_getattr_8616(codegen, "_inertia_rewrite_failure_error", None)
    result.structuring_failed = bool(_dynamic_corpus_scan_getattr_8616(codegen, "_inertia_structuring_failed", False))
    result.structuring_failure_pass = _dynamic_corpus_scan_getattr_8616(codegen, "_inertia_structuring_failure_pass", None)
    result.structuring_failure_reason = _dynamic_corpus_scan_getattr_8616(codegen, "_inertia_structuring_failure_error", None)
    result.regeneration_failed = bool(_dynamic_corpus_scan_getattr_8616(codegen, "_inertia_regeneration_failed", False))
    result.regeneration_failure_pass = _dynamic_corpus_scan_getattr_8616(codegen, "_inertia_regeneration_last_pass", None)
    result.regeneration_failure_reason = _dynamic_corpus_scan_getattr_8616(codegen, "_inertia_regeneration_error", None)


@cython.ccall
def _empty_codegen_scan_result_8616(result: FunctionScanResult, mode: object) -> FunctionScanResult:
    """Resolve the decompile stage when codegen produced no text."""
    failure_class, reason = classify_failure(
        "decompile",
        None,
        empty_codegen=True,
        rewrite_failed=result.rewrite_failed,
        regeneration_failed=result.regeneration_failed,
    )
    result.reason = reason
    if mode == "scan-safe":
        result.ok = True
        result.fallback_kind = "cfg_only"
        if result.regeneration_failed and result.regeneration_failure_reason:
            result.reason = result.regeneration_failure_reason
            reason = result.reason
        _mark_stage(result, "decompile", True, detail=reason)
        return _finish_scan(result)
    result.failure_class = failure_class
    result.fallback_kind = "block_lift"
    _mark_stage(result, "decompile", False, reason=failure_class, detail=reason)
    return _finish_scan(result)


@cython.ccall
def _decompile_scan_result_8616(
    result: FunctionScanResult,
    project: angr.Project,
    func: object,
    cfg: object,
    mode: object,
) -> FunctionScanResult:
    """Run the decompile stage and record its evidence on the result."""
    codegen: object
    dec = project.analyses.Decompiler(func, cfg=cast(Any, cfg))
    codegen = _dynamic_corpus_scan_getattr_8616(dec, "codegen", None)
    func_info = _dynamic_corpus_scan_getattr_8616(func, "info", None)
    result.tail_validation = extract_x86_16_tail_validation_snapshot(func_info)
    if not result.tail_validation and codegen is not None:
        result.tail_validation = dict(_dynamic_corpus_scan_getattr_8616(codegen, "_inertia_tail_validation_snapshot", {}) or {})
    _record_codegen_diagnostics_8616(result, codegen)
    if codegen is None or not _dynamic_corpus_scan_getattr_8616(codegen, "text", ""):
        return _empty_codegen_scan_result_8616(result, mode)
    text = codegen.text
    result.interrupt_dos_helper_count = _count_named_helper_calls(text, _INTERRUPT_DOS_HELPER_NAMES)
    result.interrupt_bios_helper_count = _count_named_helper_calls(text, _INTERRUPT_BIOS_HELPER_NAMES)
    result.interrupt_wrapper_call_count = _count_interrupt_wrapper_calls(text)
    result.interrupt_unresolved_wrapper_count = result.interrupt_wrapper_call_count
    result.semantic_family, result.semantic_family_reason = _classify_semantic_family_from_text(
        text, result
    )
    result.readability_cluster, result.readability_cluster_reason = _classify_readability_cluster(
        result, text
    )
    result.decompiled_count = 1
    result.ok = True
    _mark_stage(result, "decompile", True)
    return _finish_scan(result)


@cython.ccall
def _scan_function_stages_8616(
    result: FunctionScanResult,
    cod_file: Path,
    code: object,
    mode: object,
    max_cfg_bytes: cython.longlong,
    max_cfg_blocks: cython.longlong,
    max_cfg_insns: cython.longlong,
    max_decompile_bytes: cython.longlong,
    max_loop_bytes: cython.longlong,
) -> FunctionScanResult:
    """Run load/lift/cfg/decompile stages under the scan alarm window."""
    cfg_skip: object
    lift_failure: object
    prefix_skip: object
    probe_skip: object
    scan_safe_skip: object
    try:
        project = project_from_bytes(code)
        _mark_stage(result, "load", True)
    except Exception as exc:
        failure_class, reason = classify_failure("load", exc)
        return _fail_scan_stage(result, stage="load", failure_class=failure_class, reason=reason)

    _mark_stage(result, "normalize", True, detail="bounded blob pipeline")

    probe_skip = _scan_safe_probe_lift_8616(result, code, mode, max_cfg_bytes)
    if probe_skip is not None:
        return probe_skip

    # Decode prefix instructions BEFORE checking oversized to allow classification
    prefix_insns = _decode_scan_safe_prefix_insns(code, mode, max_cfg_bytes)

    prefix_skip = _scan_safe_prefix_skip_result_8616(
        result,
        code_len=len(code),
        mode=mode,
        max_cfg_bytes=max_cfg_bytes,
        prefix_insns=prefix_insns,
        cod_file=cod_file,
    )
    if prefix_skip is not None:
        return prefix_skip

    lift_failure = _lift_block_scan_stage_8616(result, project, code)
    if lift_failure is not None:
        return lift_failure

    result.function_count = 1
    if mode == "lift":
        result.ok = True
        return _finish_scan(result)

    scan_safe_skip = _scan_safe_cfg_preflight_8616(
        result, project, code, mode, max_cfg_bytes, max_loop_bytes
    )
    if scan_safe_skip is not None:
        return scan_safe_skip

    try:
        cfg = _scan_cfg(project, len(code))
        seed_calling_conventions(cfg)
        func = cast(Any, cfg).functions[0x1000]
        _mark_stage(result, "cfg", True)
    except Exception as exc:
        failure_class, reason = classify_failure("cfg", exc)
        return _fail_scan_stage(
            result,
            stage="cfg",
            failure_class=failure_class,
            reason=reason,
            fallback_kind="block_lift",
            classify_family=True,
        )

    _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")

    cfg_skip = _cfg_shape_scan_skip_8616(
        result, cfg, code, mode, max_cfg_blocks, max_cfg_insns, max_decompile_bytes
    )
    if cfg_skip is not None:
        return cfg_skip

    try:
        return _decompile_scan_result_8616(result, project, func, cfg, mode)
    except Exception as exc:
        failure_class, reason = classify_failure(
            "decompile",
            exc,
            rewrite_failed=result.rewrite_failed,
            regeneration_failed=result.regeneration_failed,
        )
        result.failure_class = failure_class
        result.reason = reason
        result.fallback_kind = "block_lift"
        result.semantic_family, result.semantic_family_reason = _classify_semantic_family_from_failure(result)
        _mark_stage(result, "decompile", False, reason=failure_class, detail=reason)
        return _finish_scan(result)


@cython.ccall
def scan_function(
    cod_file: Path,
    proc_name: object,
    proc_kind: object,
    code: object,
    timeout_sec: cython.longlong,
    mode: object,
    max_cfg_bytes: cython.longlong = 192,
    max_cfg_blocks: cython.longlong = 8,
    max_cfg_insns: cython.longlong = 200,
    max_decompile_bytes: cython.longlong = 384,
    max_loop_bytes: cython.longlong = 128,
) -> FunctionScanResult:
    """Scan a single COD procedure and return structured recovery/reporting status."""
    global _SCAN_ACTIVE
    result = FunctionScanResult(
        cod_file=cod_file.name,
        proc_name=proc_name,
        proc_kind=proc_kind,
        byte_len=len(code),
        has_near_call_reloc=b"\xe8\x00\x00" in code,
        has_far_call_reloc=b"\x9a\x00\x00\x00\x00" in code,
    )

    # Scan workers run the pipeline in-process and cannot rely on the CLI
    # entrypoint to have installed the frontend compatibility shims.
    from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap

    apply_x86_16_bootstrap()

    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    _SCAN_ACTIVE = True
    signal.alarm(timeout_sec)
    try:
        return _scan_function_stages_8616(
            result,
            cod_file,
            code,
            mode,
            max_cfg_bytes,
            max_cfg_blocks,
            max_cfg_insns,
            max_decompile_bytes,
            max_loop_bytes,
        )
    finally:
        _SCAN_ACTIVE = False
        _clear_alarm()
        signal.signal(signal.SIGALRM, old_handler)


@cython.ccall
def summarize_results(results: object, mode: object) -> object:
    """Summarize structured corpus scan results for reporting."""
    confidence_summaries: object
    counters = _scan_summary_counters_8616(results)
    confidence_summaries = counters.get("confidence_summaries", [])
    totals = _scan_summary_totals_8616(
        results,
        confidence_summaries if isinstance(confidence_summaries, list) else [],
    )
    return _scan_summary_output_8616(results, mode, counters, totals)


__all__ = [
    "FunctionScanResult",
    "ScanTimeout",
    "StageResult",
    "_classify_readability_cluster",
    "_clear_alarm",
    "_should_skip_scan_safe_back_edge",
    "_should_skip_scan_safe_call_chain",
    "_should_skip_scan_safe_cfg",
    "_should_skip_scan_safe_decompile",
    "_should_skip_scan_safe_decompile_for_cfg_shape",
    "classify_failure",
    "extract_cod_functions",
    "scan_function",
    "set_memory_limit",
    "summarize_results",
]
