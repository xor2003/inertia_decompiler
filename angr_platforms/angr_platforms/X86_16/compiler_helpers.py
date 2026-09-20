"""Layer: Recovery metadata.

Responsibility: identify and hook proven compiler helper patterns such as stack probes.
Forbidden: helper signature synthesis from COD/source names or rendered C.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

import claripy
from angr import SimProcedure

from .callee_name_normalization import normalize_callee_name_8616

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


@dataclass(frozen=True, slots=True)
class CompilerHelperEvidence8616:
    """Evidence for a compiler helper recognized from binary bytes."""

    addr: int
    name: str
    kind: CompilerHelperEvidenceKind8616
    pattern_name: str
    matched_bytes: int


class X86_16MscStackProbeSimProcedure8616(SimProcedure):  # type: ignore[misc, unused-ignore] # dynamic angr SimProcedure base
    """Microsoft C 16-bit stack probe: pop return, allocate AX bytes, jump back."""

    NO_RET = False

    def run(self) -> None:  # pylint:disable=arguments-differ
        """Model the stack probe effect without inventing call signatures."""
        sp = cast(claripy.ast.BV, self.state.regs.sp)
        ax = cast(claripy.ast.BV, self.state.regs.ax)
        ss = cast(claripy.ast.BV, self.state.regs.ss)
        sp32 = claripy.ZeroExt(16, sp)
        ss32 = claripy.ZeroExt(16, ss)
        stack_addr = (ss32 << claripy.BVV(4, 32)) + sp32
        ret_addr = self.state.memory.load(stack_addr, 2, endness=self.state.arch.memory_endness)
        next_sp = sp + claripy.BVV(2, 16) - ax
        self.state.regs.cx = ret_addr
        self.state.regs.bx = next_sp
        self.state.regs.sp = next_sp
        self.jump(ret_addr, jumpkind="Ijk_Ret")


class X86_16MscStackProbeFarSimProcedure8616(SimProcedure):  # type: ignore[misc, unused-ignore] # dynamic angr SimProcedure base
    """Microsoft C 16-bit far stack probe: pop far return, allocate AX bytes, far-return.

    The binary helper pops the far return CS:IP pair, subtracts AX from SP,
    pushes the pair back, and executes RETF, so the net stack effect is the
    four-byte far return frame plus the AX-byte allocation.
    """

    NO_RET = False

    def run(self) -> None:  # pylint:disable=arguments-differ
        """Model the far stack probe effect without inventing call signatures."""
        sp = cast(claripy.ast.BV, self.state.regs.sp)
        ax = cast(claripy.ast.BV, self.state.regs.ax)
        ss = cast(claripy.ast.BV, self.state.regs.ss)
        sp32 = claripy.ZeroExt(16, sp)
        ss32 = claripy.ZeroExt(16, ss)
        stack_addr = (ss32 << claripy.BVV(4, 32)) + sp32
        ret_ip = self.state.memory.load(stack_addr, 2, endness=self.state.arch.memory_endness)
        ret_cs = self.state.memory.load(stack_addr + claripy.BVV(2, 32), 2, endness=self.state.arch.memory_endness)
        next_sp = sp + claripy.BVV(4, 16) - ax
        self.state.regs.cx = ret_ip
        self.state.regs.dx = ret_cs
        self.state.regs.bx = next_sp
        self.state.regs.sp = next_sp
        ret_linear = (claripy.ZeroExt(16, ret_cs) << claripy.BVV(4, 32)) + claripy.ZeroExt(16, ret_ip)
        self.jump(ret_linear, jumpkind="Ijk_Ret")


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
    None,  # jb stack_overflow
    0x3B,
    0x1E,
    None,
    None,  # cmp bx, word ptr [limit]
    0x72,
    None,  # jb stack_overflow
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
    None,  # jb stack_overflow
    0x3B,
    0x1E,
    None,
    None,  # cmp bx, word ptr [limit]
    0x72,
    None,  # jb stack_overflow
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
    _inertia_stack_probe_helper_targets_8616: frozenset[int]


class _ProjectArchSurface8616(Protocol):
    """Third-party project field needed to transport compiler-helper evidence."""

    arch: object


def is_x86_16_stack_probe_name_8616(name: str | None) -> bool:
    """Return whether a normalized symbol name is a known stack-probe spelling."""
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    return normalized.strip().lower().lstrip("_") in _STACK_PROBE_NORMALIZED_NAMES_8616


def _project_arch_name_8616(project: object) -> str | None:
    """Read the architecture name from a dynamic angr project boundary."""
    return getattr(getattr(project, "arch", None), "name", None)


def _load_project_bytes_8616(project: object, addr: int, size: int) -> bytes | None:
    """Read bytes from a dynamic angr loader memory boundary."""
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


def _main_object_addr_range_8616(project: object) -> tuple[int, int] | None:
    """Return the main-object address range from a dynamic angr loader boundary."""
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    min_addr = getattr(main_object, "min_addr", None)
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(min_addr, int) or not isinstance(max_addr, int) or max_addr < min_addr:
        return None
    return min_addr, max_addr


def _matches_masked_prefix_8616(data: bytes, pattern: tuple[int | None, ...]) -> bool:
    if len(data) < len(pattern):
        return False
    return all(not (expected is not None and data[index] != expected) for index, expected in enumerate(pattern))


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


def identify_x86_16_compiler_helper_at_8616(
    project: object, addr: int | None
) -> CompilerHelperEvidence8616 | None:
    """Identify a helper through binary bytes and a dynamic angr project boundary."""
    if not isinstance(addr, int) or _project_arch_name_8616(project) != "86_16":
        return None

    candidates: list[tuple[object, int]] = [(project, addr)]
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if original_project is not None:
        # Exact-slice calls may preserve a linked absolute external target or
        # expose a slice-local target. Both coordinates require byte proof.
        candidates.append((original_project, addr))
        if isinstance(original_delta, int):
            candidates.append((original_project, addr + original_delta))
    seen: set[tuple[int, int]] = set()
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


def is_x86_16_stack_probe_evidence_kind_8616(kind: CompilerHelperEvidenceKind8616) -> bool:
    """Return whether an evidence kind is any binary-proven stack-probe helper."""
    return kind in _STACK_PROBE_EVIDENCE_KINDS_8616


def is_x86_16_stack_probe_helper_at_8616(project: object, addr: int | None) -> bool:
    """Return whether binary evidence identifies exactly a stack-probe helper."""
    evidence = identify_x86_16_compiler_helper_at_8616(project, addr)
    return evidence is not None and is_x86_16_stack_probe_evidence_kind_8616(evidence.kind)


def hook_x86_16_compiler_helper_at_8616(project: object, addr: int | None) -> CompilerHelperEvidence8616 | None:
    """Hook a recognized compiler helper through the dynamic angr project API."""
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


def hook_x86_16_known_compiler_helpers_8616(
    project: object, *, max_scan_bytes: int = 0x20000
) -> tuple[CompilerHelperEvidence8616, ...]:
    """Scan the main object for known compiler helpers and hook proven matches."""
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


def _register_compiler_helper_targets_on_arch_8616(
    project: object,
    evidence: tuple[CompilerHelperEvidence8616, ...],
) -> None:
    """Register stack-probe helper addresses on the dynamic angr arch object."""
    # Dynamic boundary: project is an angr.Project-like object with a runtime arch.
    arch = getattr(project, "arch", None)
    if arch is None:
        return
    targets: set[int] = set()
    for item in evidence:
        if is_x86_16_stack_probe_evidence_kind_8616(item.kind):
            targets.add(item.addr)
            targets.add(item.addr & 0xFFFF)
    if targets:
        registry = cast(_ArchWithStackProbeRegistry8616, arch)
        registry._inertia_stack_probe_helper_targets_8616 = frozenset(sorted(targets))


def is_x86_16_registered_stack_probe_target_8616(arch: object, target: int | None) -> bool:
    """Return whether an arch has recorded a target as a proven stack probe."""
    if not isinstance(target, int):
        return False
    # Dynamic boundary: arch is an angr Arch object carrying optional runtime metadata.
    targets: frozenset[int] = getattr(arch, "_inertia_stack_probe_helper_targets_8616", frozenset())
    return target in targets or (target & 0xFFFF) in targets


def x86_16_compiler_helper_targets_8616(project: object) -> frozenset[int]:
    """Return binary-proven helper targets from a dynamic angr project."""
    try:
        arch = cast(_ProjectArchSurface8616, project).arch
        targets = cast(_ArchWithStackProbeRegistry8616, arch)._inertia_stack_probe_helper_targets_8616
    except AttributeError:
        return frozenset()
    if not isinstance(targets, frozenset) or not all(isinstance(target, int) for target in targets):
        raise TypeError("compiler-helper target evidence must be a frozenset[int]")
    return targets


def transfer_x86_16_compiler_helper_evidence_8616(
    source_project: object,
    destination_project: object,
) -> int:
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
