# cython: language_level=3, infer_types=True
"""Layer: Recovery metadata.

Responsibility: identify and hook proven compiler helper patterns such as stack probes.
Forbidden: helper signature synthesis from COD/source names or rendered C.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

import dataclasses
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr import SimProcedure

from .callee_name_normalization import normalize_callee_name_8616
import operator
import builtins

__all__ = [
    "CompilerHelperEvidence8616",
    "CompilerHelperEvidenceKind8616",
    "X86_16MscStackProbeFarSimProcedure8616",
    "X86_16MscStackProbeSimProcedure8616",
    "hook_x86_16_compiler_helper_at_8616",
    "hook_x86_16_known_compiler_helpers_8616",
    "identify_x86_16_compiler_helper_at_8616",
    "is_x86_16_registered_stack_probe_target_8616",
    "is_x86_16_stack_probe_evidence_kind_8616",
    "is_x86_16_stack_probe_helper_at_8616",
    "is_x86_16_stack_probe_name_8616",
    "transfer_x86_16_compiler_helper_evidence_8616",
    "x86_16_compiler_helper_targets_8616",
]


class CompilerHelperEvidenceKind8616(Enum):
    """Binary evidence category for a recognized compiler helper."""

    STACK_PROBE = "stack_probe"
    STACK_PROBE_FAR = "stack_probe_far"
    SIGNED_LONG_DIVIDE = "signed_long_divide"


@dataclasses.dataclass(frozen=True, )
class CompilerHelperEvidence8616:
    """Evidence for a compiler helper recognized from binary bytes."""

    addr: cython.longlong
    name: object
    kind: CompilerHelperEvidenceKind8616
    pattern_name: object
    matched_bytes: cython.longlong


class X86_16MscStackProbeSimProcedure8616(SimProcedure):  # type: ignore[misc, unused-ignore] # dynamic angr SimProcedure base
    """Retain probe identity while delegating every effect to its native bytes.

    Pattern recognition is not an ABI or complete-effect proof. In particular,
    native execution owns the DS limit checks, flags, wrapped SS frame loads,
    and CS-relative return. The one-step NoHook edge avoids recursive hook
    dispatch without replacing these effects with an unconditional return.
    """

    NO_RET = False

    def run(self) -> None:  # pylint:disable=arguments-differ
        """Resume the unchanged entry through angr's native hook-bypass edge."""
        self.jump(self.addr, jumpkind="Ijk_NoHook")


class X86_16MscStackProbeFarSimProcedure8616(SimProcedure):  # type: ignore[misc, unused-ignore] # dynamic angr SimProcedure base
    """Retain far-probe identity without replacing its native guarded effects."""

    NO_RET = False

    def run(self) -> None:  # pylint:disable=arguments-differ
        """Execute native far-return, memory and failure paths after one bypass."""
        self.jump(self.addr, jumpkind="Ijk_NoHook")


_STACK_PROBE_NORMALIZED_NAMES_8616 = frozenset(
    {
        "anchkstk",
        "afchkstk",
        "chkstk",
        "analloca_probe",
    }
)


_MSC_ANCHKSTK_PATTERN_8616: tuple[int | None, ...] = (
    0x59,  # pop cx
    0x8B,
    0xDC,  # mov bx, sp
    0x2B,
    0xD8,  # sub bx, ax
    0x72,
    0x0A,  # jb past the returning path, not into its stack writes
    0x3B,
    0x1E,
    None,
    None,  # cmp bx, word ptr [limit]
    0x72,
    0x04,  # jb past the returning path
    0x8B,
    0xE3,  # mov sp, bx
    0xFF,
    0xE1,  # jmp cx
)

_MSC_AFCHKSTK_PATTERN_8616: tuple[int | None, ...] = (
    0x59,  # pop cx
    0x5A,  # pop dx
    0x8B,
    0xDC,  # mov bx, sp
    0x2B,
    0xD8,  # sub bx, ax
    0x72,
    0x0B,  # jb past the returning path, not into its stack writes
    0x3B,
    0x1E,
    None,
    None,  # cmp bx, word ptr [limit]
    0x72,
    0x05,  # jb past the returning path
    0x8B,
    0xE3,  # mov sp, bx
    0x52,  # push dx
    0x51,  # push cx
    0xCB,  # retf
)

_MSC_ANLDIV_PATTERN_8616: tuple[int | None, ...] = tuple(
    bytes.fromhex("55 8b ec 57 56 53 33 ff 8b 46 06 0b c0 7d 11 47 8b 56 04 f7 d8 f7 da 1d 00 00 89 46 06 89 56 04")
)


class _ArchWithStackProbeRegistry8616(Protocol):
    _inertia_stack_probe_helper_targets_8616: object


class _ProjectArchSurface8616(Protocol):
    """Third-party project field needed to transport compiler-helper evidence."""

    arch: object


@cython.ccall
def is_x86_16_stack_probe_name_8616(name: object) -> cython.bint:
    """Return whether a normalized symbol name is a known stack-probe spelling."""
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    return normalized.strip().lower().lstrip("_") in _STACK_PROBE_NORMALIZED_NAMES_8616


@cython.ccall
def _project_arch_name_8616(project: object) -> object:
    """Read the architecture name from a dynamic angr project boundary."""
    return getattr(getattr(project, "arch", None), "name", None)


@cython.ccall
def _load_project_bytes_8616(project: object, addr: cython.longlong, size: cython.longlong) -> object:
    """Read bytes from a dynamic angr loader memory boundary."""
    load: object
    loader: object
    memory: object
    loader = getattr(project, "loader", None)
    memories = (
        getattr(loader, "memory", None),
        getattr(getattr(loader, "main_object", None), "memory", None),
    )
    for memory in memories:
        load = getattr(memory, "load", None)
        if not callable(load):
            continue
        try:
            raw = load(addr, size)
        except Exception:
            continue
        if isinstance(raw, bytes):
            return raw
        if isinstance(raw, bytearray | memoryview):
            return bytes(raw)
    return None


@cython.ccall
def _main_object_addr_range_8616(project: object) -> object:
    """Return the main-object address range from a dynamic angr loader boundary."""
    main_object: object
    max_addr: object
    min_addr: object
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    min_addr = getattr(main_object, "min_addr", None)
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(min_addr, int) or not isinstance(max_addr, int) or max_addr < min_addr:
        return None
    return min_addr, max_addr


def _matches_masked_prefix_8616(data: object, pattern: object) -> cython.bint:
    if len(data) < len(pattern):
        return False
    return all(not (expected is not None and operator.ne(data[index], expected)) for index, expected in builtins.iter(enumerate(pattern)))


_STACK_PROBE_PATTERNS_8616: tuple[
    tuple[tuple[int | None, ...], CompilerHelperEvidence8616, CompilerHelperEvidenceKind8616], ...
] = (
    (
        _MSC_ANCHKSTK_PATTERN_8616,
        CompilerHelperEvidence8616(
            addr=0,
            name="aNchkstk",
            kind=CompilerHelperEvidenceKind8616.STACK_PROBE,
            pattern_name="msc_aNchkstk_popcx_sp_ax",
            matched_bytes=len(_MSC_ANCHKSTK_PATTERN_8616),
        ),
        CompilerHelperEvidenceKind8616.STACK_PROBE,
    ),
    (
        _MSC_AFCHKSTK_PATTERN_8616,
        CompilerHelperEvidence8616(
            addr=0,
            name="aFchkstk",
            kind=CompilerHelperEvidenceKind8616.STACK_PROBE_FAR,
            pattern_name="msc_aFchkstk_popcx_popdx_sp_ax_retf",
            matched_bytes=len(_MSC_AFCHKSTK_PATTERN_8616),
        ),
        CompilerHelperEvidenceKind8616.STACK_PROBE_FAR,
    ),
)

_STACK_PROBE_EVIDENCE_KINDS_8616: frozenset[CompilerHelperEvidenceKind8616] = frozenset(
    {
        CompilerHelperEvidenceKind8616.STACK_PROBE,
        CompilerHelperEvidenceKind8616.STACK_PROBE_FAR,
    }
)


@cython.ccall
def identify_x86_16_compiler_helper_at_8616(
    project: object, addr: int | None
) -> CompilerHelperEvidence8616 | None:
    """Identify a helper through binary bytes and a dynamic angr project boundary."""
    original_delta: object
    original_project: object
    signed_divide_code: object
    stack_probe_code: object
    _kind: object
    candidate_addr: object
    candidate_project: object
    pattern: object
    template: object
    if not isinstance(addr, int) or _project_arch_name_8616(project) != "86_16":
        return None

    candidates: list[tuple[object, cython.longlong]] = [(project, addr)]
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if original_project is not None:
        # Exact-slice calls may preserve a linked absolute external target or
        # expose a slice-local target. Both coordinates require byte proof.
        candidates.append((original_project, addr))
        if isinstance(original_delta, int):
            candidates.append((original_project, addr + original_delta))
    seen: set[tuple[cython.longlong, cython.longlong]] = set()
    for candidate_project, candidate_addr in candidates:
        key = id(candidate_project), candidate_addr
        if key in seen:
            continue
        seen.add(key)
        for pattern, template, _kind in _STACK_PROBE_PATTERNS_8616:
            stack_probe_code = _load_project_bytes_8616(
                candidate_project,
                candidate_addr,
                len(pattern),
            )
            if stack_probe_code is not None and _matches_masked_prefix_8616(stack_probe_code, pattern):
                return dataclasses.replace(template, addr=addr)
        signed_divide_code = _load_project_bytes_8616(
            candidate_project,
            candidate_addr,
            len(_MSC_ANLDIV_PATTERN_8616),
        )
        if signed_divide_code is not None and _matches_masked_prefix_8616(
            signed_divide_code,
            _MSC_ANLDIV_PATTERN_8616,
        ):
            return CompilerHelperEvidence8616(
                addr=addr,
                name="aNldiv",
                kind=CompilerHelperEvidenceKind8616.SIGNED_LONG_DIVIDE,
                pattern_name="msc_aNldiv_signed_dx_ax",
                matched_bytes=len(_MSC_ANLDIV_PATTERN_8616),
            )
    return None


@cython.ccall
def is_x86_16_stack_probe_evidence_kind_8616(kind: CompilerHelperEvidenceKind8616) -> cython.bint:
    """Return whether an evidence kind is any binary-proven stack-probe helper."""
    return kind in _STACK_PROBE_EVIDENCE_KINDS_8616


@cython.ccall
def is_x86_16_stack_probe_helper_at_8616(project: object, addr: int | None) -> cython.bint:
    """Return whether binary evidence identifies exactly a stack-probe helper."""
    evidence: object
    evidence = identify_x86_16_compiler_helper_at_8616(project, addr)
    return evidence is not None and is_x86_16_stack_probe_evidence_kind_8616(evidence.kind)


@cython.ccall
def hook_x86_16_compiler_helper_at_8616(project: object, addr: int | None) -> CompilerHelperEvidence8616 | None:
    """Hook a recognized compiler helper through the dynamic angr project API."""
    evidence: object
    hook: object
    is_hooked: object
    evidence = identify_x86_16_compiler_helper_at_8616(project, addr)
    if evidence is None:
        return None
    if is_x86_16_stack_probe_evidence_kind_8616(evidence.kind):
        procedure_class = (
            X86_16MscStackProbeFarSimProcedure8616
            if evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE_FAR
            else X86_16MscStackProbeSimProcedure8616
        )
        # Dynamic boundary: project is an angr.Project-like object supplied by callers.
        is_hooked = getattr(project, "is_hooked", None)
        # Dynamic boundary: hook installation is provided by the same angr.Project-like object.
        hook = getattr(project, "hook", None)
        if callable(is_hooked) and callable(hook) and not is_hooked(evidence.addr):
            hook(evidence.addr, procedure_class(display_name=evidence.name))
    return evidence


@cython.ccall
def hook_x86_16_known_compiler_helpers_8616(
    project: object, *, max_scan_bytes: cython.longlong = 0x20000
) -> tuple[CompilerHelperEvidence8616, ...]:
    """Scan the main object for known compiler helpers and hook proven matches."""
    addr_range: object
    evidence: object
    _kind: object
    _template: object
    pattern: object
    if _project_arch_name_8616(project) != "86_16":
        return ()
    addr_range = _main_object_addr_range_8616(project)
    if addr_range is None:
        return ()
    start, end = addr_range
    scan_size = min(end - start + 1, max_scan_bytes)
    data = _load_project_bytes_8616(project, start, scan_size)
    if not data:
        return ()

    found: list[CompilerHelperEvidence8616] = []
    for pattern, _template, _kind in _STACK_PROBE_PATTERNS_8616:
        pattern_len = len(pattern)
        for offset in range(max(0, len(data) - pattern_len + 1)):
            if not _matches_masked_prefix_8616(data[offset : offset + pattern_len], pattern):
                continue
            evidence = hook_x86_16_compiler_helper_at_8616(project, start + offset)
            if evidence is not None:
                found.append(evidence)
    if found:
        _register_compiler_helper_targets_on_arch_8616(project, tuple(found))
    return tuple(found)


@cython.ccall
def _register_compiler_helper_targets_on_arch_8616(
    project: object,
    evidence: object,
) -> None:
    """Register stack-probe helper addresses on the dynamic angr arch object."""
    arch: object
    item: object
    # Dynamic boundary: project is an angr.Project-like object with a runtime arch.
    arch = getattr(project, "arch", None)
    if arch is None:
        return
    targets: set[cython.longlong] = set()
    for item in evidence:
        if is_x86_16_stack_probe_evidence_kind_8616(item.kind):
            targets.add(item.addr)
            targets.add(item.addr & 0xFFFF)
    if targets:
        registry = cast(_ArchWithStackProbeRegistry8616, arch)
        registry._inertia_stack_probe_helper_targets_8616 = frozenset(sorted(targets))


@cython.ccall
def is_x86_16_registered_stack_probe_target_8616(arch: object, target: int | None) -> cython.bint:
    """Return whether an arch has recorded a target as a proven stack probe."""
    targets: object
    if not isinstance(target, int):
        return False
    # Dynamic boundary: arch is an angr Arch object carrying optional runtime metadata.
    targets = getattr(arch, "_inertia_stack_probe_helper_targets_8616", frozenset())
    return target in targets or (target & 0xFFFF) in targets


def x86_16_compiler_helper_targets_8616(project: object) -> object:
    """Return binary-proven helper targets from a dynamic angr project."""
    try:
        arch = cast(_ProjectArchSurface8616, project).arch
        targets = cast(_ArchWithStackProbeRegistry8616, arch)._inertia_stack_probe_helper_targets_8616
    except AttributeError:
        return frozenset()
    if not isinstance(targets, frozenset) or not all(isinstance(target, int) for target in iter(targets)):
        raise TypeError("compiler-helper target evidence must be a frozenset[int]")
    return targets


@cython.ccall
def transfer_x86_16_compiler_helper_evidence_8616(
    source_project: object,
    destination_project: object,
) -> cython.longlong:
    """Copy binary-proven compiler-helper targets across a project boundary."""
    try:
        source_arch = cast(_ProjectArchSurface8616, source_project).arch
        destination_arch = cast(_ProjectArchSurface8616, destination_project).arch
    except AttributeError:
        return 0
    try:
        source_targets = cast(_ArchWithStackProbeRegistry8616, source_arch)._inertia_stack_probe_helper_targets_8616
    except AttributeError:
        return 0
    try:
        destination_targets = cast(
            _ArchWithStackProbeRegistry8616,
            destination_arch,
        )._inertia_stack_probe_helper_targets_8616
    except AttributeError:
        destination_targets = frozenset()
    merged_targets = destination_targets | source_targets
    registry = cast(_ArchWithStackProbeRegistry8616, destination_arch)
    registry._inertia_stack_probe_helper_targets_8616 = frozenset(sorted(merged_targets))
    return len(source_targets)
