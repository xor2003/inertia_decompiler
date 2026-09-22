"""Layer: Recovery metadata.

Responsibility: provide helper metadata and interrupt surfaces consumed by recovery/reporting.
Forbidden: source/COD-backed semantic proof, validation acceptance, or emitted-C repair.
"""

from __future__ import annotations

import builtins
import contextlib
import logging
import os
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast

import claripy
from angr import SimProcedure
from angr.sim_type import SimTypeFunction
from capstone import CsInsn

from .frontend_function_instructions import collect_function_instruction_inventory_8616
from .frontend_instruction_reachability import collect_decoded_block_evidence_8616
from .function_evidence_inventory import (
    FunctionEvidenceKind8616,
    collect_function_binary_evidence_8616,
)
from .helper_abi import (
    known_helper_abi_8616,
    known_helper_signature_declarations_8616,
    preferred_known_helper_abi_8616,
)
from .interrupt_contract import (
    DOS_SERVICE_BASE_ADDR,
    INTERRUPT_CORE_VECTOR_BASE,
    INTERRUPT_CORE_VECTOR_COUNT,
    INTERRUPT_SERVICE_BASE_ADDR,
    SoftwareInterruptServiceTargetFact8616,
    record_software_interrupt_service_target_8616,
)
from .semantics.terminal_stack_cleanup import (
    TerminalReturnFrameKind8616,
    terminal_stack_cleanup_at_address_8616,
)
from .simos_86_16 import get_interrupt_handler_class

__all__ = (
    "DOS_SERVICE_BASE_ADDR",
    "INTERRUPT_CORE_VECTOR_BASE",
    "INTERRUPT_CORE_VECTOR_COUNT",
    "INTERRUPT_SERVICE_BASE_ADDR",
    "CallTargetKind8616",
    "CallTargetSeed",
    "DOSInt21Call",
    "DirectCallsiteSanitizationEvidence",
    "EntryScore",
    "FarCallTarget",
    "InterruptCall",
    "InterruptServiceResultKind8616",
    "InterruptServiceSpec",
    "canonicalize_x86_16_padding_call_target_8616",
    "collect_direct_far_call_targets",
    "collect_dos_int21_calls",
    "collect_interrupt_calls",
    "collect_interrupt_service_calls",
    "collect_neighbor_call_targets",
    "decode_com_c_string",
    "decode_com_dollar_string",
    "describe_x86_16_interrupt_api_surface",
    "describe_x86_16_interrupt_core_surface",
    "describe_x86_16_interrupt_lowering_boundary",
    "describe_x86_16_known_helper_signatures",
    "dos_helper_declarations",
    "dos_service_addr",
    "dos_service_name",
    "ensure_dos_service_hook",
    "ensure_interrupt_service_hook",
    "extend_cfg_for_far_calls",
    "extend_cfg_for_neighbor_calls",
    "infer_com_region",
    "interrupt_service_addr",
    "interrupt_service_declarations",
    "interrupt_service_name",
    "interrupt_service_result_kind_at_addr_8616",
    "interrupt_service_spec",
    "known_helper_signature_decl",
    "normalize_api_style",
    "patch_direct_call_sites",
    "patch_dos_int21_call_sites",
    "patch_far_call_sites",
    "patch_interrupt_service_call_sites",
    "preferred_known_helper_signature_decl",
    "rank_entry_addresses_8616",
    "render_dos_int21_call",
    "render_interrupt_call",
    "resolve_direct_call_target_from_block",
    "resolve_direct_call_target_from_instruction_8616",
    "resolve_direct_jump_target_from_block",
    "resolve_stored_near_call_target_from_function",
    "resolve_stored_near_jump_target_from_function",
    "sanitize_direct_call_sites_8616",
    "score_entry_address_8616",
    "seed_calling_conventions",
    "seed_wide_stack_prototype_from_binary_address_8616",
)


def _dynamic_analysis_getattr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read an attribute across the dynamic angr/project/Capstone boundary."""
    return builtins.getattr(obj, name, default)


def _dynamic_analysis_tuple_attr_8616(obj: object, name: str) -> tuple[object, ...]:
    """Read tuple-like metadata from the dynamic angr/project/Capstone boundary."""
    value = _dynamic_analysis_getattr_8616(obj, name, ())
    if value is None:
        return ()
    try:
        return tuple(cast(Any, value))
    except TypeError:
        return ()


def _dynamic_analysis_int_attr_8616(obj: object, name: str) -> int | None:
    """Read an integer attribute from the dynamic angr/project/Capstone boundary."""
    value = _dynamic_analysis_getattr_8616(obj, name, None)
    return value if isinstance(value, int) else None


def _analysis_project_block_8616(project: object, block_addr: int) -> Any:  # noqa: ANN401
    """Return typed frontend block evidence with VEX retained as fallback."""
    return collect_decoded_block_evidence_8616(project, block_addr, opt_level=0).block


def _analysis_function_addr_8616(function: object) -> int | None:
    """Read a function address from angr's dynamic Function boundary."""
    return _dynamic_analysis_int_attr_8616(function, "addr")


class _PrototypeFunctionBoundary8616(Protocol):
    """Typed angr function fields used to transfer inferred ABI evidence."""

    prototype: object | None
    calling_convention: object | None
    is_prototype_guessed: bool


def _function_has_proven_prototype_8616(function: object) -> bool:
    """Return whether a function already carries a non-guessed ABI contract."""
    typed_function = cast(_PrototypeFunctionBoundary8616, function)
    try:
        return typed_function.prototype is not None and not typed_function.is_prototype_guessed
    except AttributeError:
        return False


def _apply_far_return_calling_convention_8616(project: object, function: object) -> bool:
    """Assign the far-frame calling convention when the terminal return proves it.

    A function whose terminal return is ``retf``/``lret`` owns a four-byte
    return frame, so its stack arguments begin at ``BP+6`` rather than ``BP+4``.
    Seeding the matching ``SimCC8616MSClarge`` before variable recovery makes
    angr's ``arg_locs`` place arguments at the proven far base natively. The
    override only fires on proven far frames and never replaces an explicit
    non-MSC convention.
    """
    from .lowering.argument_frame_base import proven_far_return_frame_at_8616
    from .simos_86_16 import (
        SimCC8616MSClarge,
        SimCC8616MSCmedium,
        SimCC8616MSCsmall,
    )

    typed_function = cast(_PrototypeFunctionBoundary8616, function)
    function_addr = _analysis_function_addr_8616(function)
    if not isinstance(function_addr, int):
        return False
    try:
        arch = cast(Any, project).arch
    except AttributeError:
        return False
    if not proven_far_return_frame_at_8616(project, function_addr):
        return False
    current = typed_function.calling_convention
    if current is not None and not isinstance(
        current, (SimCC8616MSCsmall, SimCC8616MSCmedium, SimCC8616MSClarge)
    ):
        return False
    if isinstance(current, SimCC8616MSClarge):
        return False
    typed_function.calling_convention = SimCC8616MSClarge(arch)
    return True


def seed_wide_stack_prototype_from_binary_address_8616(
    project: object,
    source_function: object,
    target_function: object,
    address: int,
    *,
    target_project: object | None = None,
    target_address: int | None = None,
) -> bool:
    """Infer a wide stack ABI and copy its typed contract across project views."""
    from .calling_convention_compat import apply_x86_16_wide_stack_prototype_evidence_at_address
    from .lowering.callee_pointer_contracts import (
        transfer_callee_pointer_argument_evidence_8616,
    )
    from .lowering.callee_pointer_evidence import apply_callee_pointer_argument_evidence_at_address_8616

    canonical_address = (
        canonicalize_x86_16_padding_call_target_8616(project, address)
        or address
    )
    source_proven = _function_has_proven_prototype_8616(source_function)
    typed_source = cast(_PrototypeFunctionBoundary8616, source_function)
    bounded_refinement_allowed = (
        not source_proven
        or isinstance(typed_source.prototype, SimTypeFunction)
    )
    binary_wide_seeded = (
        apply_x86_16_wide_stack_prototype_evidence_at_address(
            project,
            source_function,
            canonical_address,
        )
        if bounded_refinement_allowed
        else False
    )
    abi_seeded = source_proven or binary_wide_seeded
    pointer_seeded = (
        apply_callee_pointer_argument_evidence_at_address_8616(
            project,
            source_function,
            canonical_address,
        )
        if bounded_refinement_allowed
        else False
    )
    if canonical_address != address:
        functions = _dynamic_analysis_getattr_8616(
            _dynamic_analysis_getattr_8616(project, "kb", None),
            "functions",
            None,
        )
        lookup = _dynamic_analysis_getattr_8616(functions, "function", None)
        canonical_function = (
            cast(Any, lookup)(addr=canonical_address, create=True)
            if callable(lookup)
            else None
        )
        if canonical_function is not None:
            if binary_wide_seeded and typed_source.prototype is not None:
                typed_canonical = cast(
                    _PrototypeFunctionBoundary8616,
                    canonical_function,
                )
                typed_canonical.prototype = typed_source.prototype
                typed_canonical.calling_convention = typed_source.calling_convention
                typed_canonical.is_prototype_guessed = typed_source.is_prototype_guessed
            pointer_seeded = apply_callee_pointer_argument_evidence_at_address_8616(
                project,
                canonical_function,
                canonical_address,
            ) or pointer_seeded
    if not abi_seeded and not pointer_seeded:
        return False
    if target_project is not None:
        if not isinstance(target_address, int):
            raise ValueError("cross-project ABI seed requires a target address")
        transfer_callee_pointer_argument_evidence_8616(
            project,
            target_project,
            source_addr=canonical_address,
            target_addr=target_address,
        )
    if typed_source.prototype is None or (
        typed_source.is_prototype_guessed and not pointer_seeded
    ):
        return False
    typed_target = cast(_PrototypeFunctionBoundary8616, target_function)
    typed_target.prototype = typed_source.prototype
    typed_target.calling_convention = typed_source.calling_convention
    typed_target.is_prototype_guessed = typed_source.is_prototype_guessed
    return True


def _analysis_function_block_addrs_8616(function: object) -> tuple[int, ...]:
    """Read sorted block addresses from angr's dynamic Function boundary."""
    return tuple(
        sorted(
            addr
            for addr in _dynamic_analysis_tuple_attr_8616(function, "block_addrs_set")
            if isinstance(addr, int)
        )
    )


def _analysis_function_call_sites_8616(function: object) -> tuple[int, ...]:
    """Read sorted callsite addresses from angr's dynamic Function boundary."""
    get_call_sites = _dynamic_analysis_getattr_8616(function, "get_call_sites", None)
    if not callable(get_call_sites):
        return ()
    with contextlib.suppress(Exception):
        return tuple(sorted(addr for addr in cast(Any, get_call_sites)() if isinstance(addr, int)))
    return ()


def _analysis_function_call_target_8616(function: object, callsite_addr: int) -> int | None:
    """Read a call target from angr's dynamic Function boundary."""
    get_call_target = _dynamic_analysis_getattr_8616(function, "get_call_target", None)
    if not callable(get_call_target):
        return None
    with contextlib.suppress(Exception):
        target_addr = cast(Any, get_call_target)(callsite_addr)
        return target_addr if isinstance(target_addr, int) else None
    return None


def _analysis_function_call_return_8616(function: object, callsite_addr: int) -> int | None:
    """Read and exactly linearize a CALL return from angr's Function boundary.

    angr may expose the architectural 16-bit IP for an indirect real-mode CALL
    even though function and instruction identities are linear addresses. Only
    an exact decoded CALL whose fall-through has the same low word authorizes
    replacing that IP projection with the decoded linear fall-through.
    """
    get_call_return = _dynamic_analysis_getattr_8616(function, "get_call_return", None)
    if not callable(get_call_return):
        return None
    with contextlib.suppress(Exception):
        return_addr = cast(Any, get_call_return)(callsite_addr)
        if not isinstance(return_addr, int):
            return None
        project = _x86_16_project_for_function_8616(function)
        if project is None:
            return return_addr
        block = _analysis_project_block_8616(project, callsite_addr)
        instructions = _dynamic_analysis_tuple_attr_8616(
            _dynamic_analysis_getattr_8616(block, "capstone", None),
            "insns",
        )
        matches = tuple(
            instruction
            for instruction in instructions
            if _dynamic_analysis_getattr_8616(instruction, "address", None)
            == callsite_addr
            and str(
                _dynamic_analysis_getattr_8616(instruction, "mnemonic", "") or ""
            ).lower()
            in {"call", "lcall"}
        )
        if len(matches) != 1:
            return return_addr
        size = _dynamic_analysis_getattr_8616(matches[0], "size", None)
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            return return_addr
        decoded_fallthrough = callsite_addr + size
        if (return_addr & 0xFFFF) == (decoded_fallthrough & 0xFFFF):
            return decoded_fallthrough
        return return_addr
    return None


KNOWN_HELPER_SIGNATURE_DECLS: dict[str, str] = known_helper_signature_declarations_8616()


@dataclass(frozen=True)
class FarCallTarget:
    """Recovered far-call target evidence from an x86-16 callsite."""

    callsite_addr: int
    target_addr: int
    return_addr: int | None


class CallTargetKind8616(StrEnum):
    """Typed origin and distance of one recovered control-transfer target."""

    CFG_RESOLVED_CALL = "existing"
    DIRECT_NEAR_CALL = "direct_near"
    DIRECT_FAR_CALL = "direct_far"
    STORED_NEAR_CALL = "stored_near"
    DIRECT_NEAR_TAIL_JUMP = "tail_jump"
    DIRECT_FAR_TAIL_JUMP = "far_tail_jump"
    STORED_NEAR_TAIL_JUMP = "stored_tail_jump"


@dataclass(frozen=True)
class CallTargetSeed:
    """Recovered neighboring call target used to seed bounded CFG recovery."""

    callsite_addr: int
    target_addr: int
    return_addr: int | None
    kind: CallTargetKind8616

    def __post_init__(self) -> None:
        """Normalize legacy string constructors at the typed frontend boundary."""
        if not isinstance(self.kind, CallTargetKind8616):
            object.__setattr__(self, "kind", CallTargetKind8616(cast(str, self.kind)))


@dataclass(frozen=True)
class DirectCallsiteSanitizationEvidence:
    """Evidence counters for direct-callsite pruning and materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    pruned_count: int = 0


@dataclass(frozen=True)
class InterruptCall:
    """Recovered interrupt instruction with register values and display expressions."""

    insn_addr: int
    vector: int = 0x21
    ah: int | None = None
    al: int | None = None
    ax: int | None = None
    bx: int | None = None
    cx: int | None = None
    dx: int | None = None
    si: int | None = None
    di: int | None = None
    bh: int | None = None
    bl: int | None = None
    ch: int | None = None
    cl: int | None = None
    dh: int | None = None
    dl: int | None = None
    ds: int | None = None
    es: int | None = None
    ss: int | None = None
    cs: int | None = None
    ah_expr: str | None = None
    al_expr: str | None = None
    ax_expr: str | None = None
    bx_expr: str | None = None
    cx_expr: str | None = None
    dx_expr: str | None = None
    si_expr: str | None = None
    di_expr: str | None = None
    bh_expr: str | None = None
    bl_expr: str | None = None
    ch_expr: str | None = None
    cl_expr: str | None = None
    dh_expr: str | None = None
    dl_expr: str | None = None
    ds_expr: str | None = None
    es_expr: str | None = None
    ss_expr: str | None = None
    cs_expr: str | None = None
    string_literal: str | None = None


type DOSInt21Call = InterruptCall


class InterruptServiceResultKind8616(StrEnum):
    """Typed generated-C result category for a resolved interrupt service."""

    VOID = "void"
    VALUE = "value"


@dataclass(frozen=True)
class InterruptServiceSpec:
    """Stable naming and rendering metadata for a DOS or BIOS interrupt service."""

    vector: int
    pseudo_name: str
    dos_name: str
    modern_name: str
    render_kind: str = "generic"
    default_output: str = "return"
    pseudo_decl: str | None = None
    dos_decl: str | None = None
    modern_decl: str | None = None
    result_kind: InterruptServiceResultKind8616 = InterruptServiceResultKind8616.VALUE
    no_return: bool = False


INT21_SERVICE_SPECS: dict[int, InterruptServiceSpec] = {
    0x09: InterruptServiceSpec(
        0x21,
        "dos_print_dollar_string",
        "_dos_print_dollar_string",
        "print_dos_string",
        "string_dollar",
        pseudo_decl="void dos_print_dollar_string(const char *s);",
        dos_decl="void _dos_print_dollar_string(const char far *s);",
        modern_decl="void print_dos_string(const char *s);",
        result_kind=InterruptServiceResultKind8616.VOID,
    ),
    0x0E: InterruptServiceSpec(
        0x21,
        "dos_set_current_drive",
        "_dos_setdrive",
        "set_current_drive",
        "drive",
        pseudo_decl="int dos_set_current_drive(int drive);",
        dos_decl="int _dos_setdrive(unsigned char drive);",
        modern_decl="int set_current_drive(int drive);",
    ),
    0x25: InterruptServiceSpec(
        0x21,
        "dos_setvect",
        "_dos_setvect",
        "setvect",
        "setvect",
        pseudo_decl="void dos_setvect(int vector, void (*handler)(void));",
        dos_decl="void _dos_setvect(unsigned int interruptno, void (far *isr)(void));",
        modern_decl="void setvect(int interruptno, void (*isr)(void));",
        result_kind=InterruptServiceResultKind8616.VOID,
    ),
    0x30: InterruptServiceSpec(
        0x21,
        "dos_get_version",
        "_dos_get_version",
        "get_dos_version",
        "zero_arg",
        pseudo_decl="int dos_get_version(void);",
        dos_decl="unsigned short _dos_get_version(void);",
        modern_decl="int get_dos_version(void);",
    ),
    0x35: InterruptServiceSpec(
        0x21,
        "dos_getvect",
        "_dos_getvect",
        "getvect",
        "getvect",
        pseudo_decl="void *dos_getvect(int vector);",
        dos_decl="void (far *_dos_getvect(unsigned int interruptno))(void);",
        modern_decl="void (*getvect(int interruptno))(void);",
    ),
    0x39: InterruptServiceSpec(
        0x21,
        "dos_mkdir",
        "_dos_mkdir",
        "mkdir",
        "path",
        pseudo_decl="int dos_mkdir(const char *path);",
        dos_decl="int _dos_mkdir(const char far *path);",
        modern_decl="int mkdir(const char *path);",
    ),
    0x3A: InterruptServiceSpec(
        0x21,
        "dos_rmdir",
        "_dos_rmdir",
        "rmdir",
        "path",
        pseudo_decl="int dos_rmdir(const char *path);",
        dos_decl="int _dos_rmdir(const char far *path);",
        modern_decl="int rmdir(const char *path);",
    ),
    0x3B: InterruptServiceSpec(
        0x21,
        "dos_chdir",
        "_dos_chdir",
        "chdir",
        "path",
        pseudo_decl="int dos_chdir(const char *path);",
        dos_decl="int _dos_chdir(const char far *path);",
        modern_decl="int chdir(const char *path);",
    ),
    0x3C: InterruptServiceSpec(
        0x21,
        "dos_creat",
        "_dos_creat",
        "creat",
        "path_attrs",
        pseudo_decl="int dos_creat(const char *path, int attrs);",
        dos_decl="int _dos_creat(const char far *path, unsigned short attrs);",
        modern_decl="int creat(const char *path, int attrs);",
    ),
    0x3D: InterruptServiceSpec(
        0x21,
        "dos_open",
        "_dos_open",
        "open",
        "path_mode",
        pseudo_decl="int dos_open(const char *path, int mode);",
        dos_decl="int _dos_open(const char far *path, unsigned char mode);",
        modern_decl="int open(const char *path, int oflag);",
    ),
    0x3E: InterruptServiceSpec(
        0x21,
        "dos_close",
        "_dos_close",
        "close",
        "handle",
        pseudo_decl="int dos_close(int handle);",
        dos_decl="int _dos_close(unsigned short handle);",
        modern_decl="int close(int fd);",
    ),
    0x3F: InterruptServiceSpec(
        0x21,
        "dos_read",
        "_dos_read",
        "read",
        "handle_buffer_count",
        pseudo_decl="int dos_read(int handle, void *buffer, unsigned int count);",
        dos_decl="int _dos_read(unsigned short handle, void far *buffer, unsigned short count);",
        modern_decl="int read(int fd, void *buf, unsigned int count);",
    ),
    0x40: InterruptServiceSpec(
        0x21,
        "dos_write",
        "_dos_write",
        "write",
        "handle_buffer_count",
        pseudo_decl="int dos_write(int handle, const void *buffer, unsigned int count);",
        dos_decl="int _dos_write(unsigned short handle, const void far *buffer, unsigned short count);",
        modern_decl="int write(int fd, const void *buf, unsigned int count);",
    ),
    0x41: InterruptServiceSpec(
        0x21,
        "dos_unlink",
        "_dos_unlink",
        "unlink",
        "path",
        pseudo_decl="int dos_unlink(const char *path);",
        dos_decl="int _dos_unlink(const char far *path);",
        modern_decl="int unlink(const char *path);",
    ),
    0x42: InterruptServiceSpec(
        0x21,
        "dos_seek",
        "_dos_seek",
        "lseek",
        "handle_seek",
        pseudo_decl="long dos_seek(int handle, long offset, int origin);",
        dos_decl="long _dos_seek(unsigned short handle, long offset, unsigned char origin);",
        modern_decl="long lseek(int fd, long offset, int whence);",
    ),
    0x47: InterruptServiceSpec(
        0x21,
        "dos_get_current_directory",
        "_dos_getcwd",
        "get_current_directory",
        "drive_buffer",
        pseudo_decl="int dos_get_current_directory(int drive, char *buffer);",
        dos_decl="int _dos_getcwd(unsigned char drive, char far *buffer);",
        modern_decl="int get_current_directory(int drive, char *buffer);",
    ),
    0x4A: InterruptServiceSpec(
        0x21,
        "dos_setblock",
        "_dos_setblock",
        "resize_dos_memory_block",
        "zero_arg",
        pseudo_decl="int dos_setblock(void);",
        dos_decl="int _dos_setblock(void);",
        modern_decl="int resize_dos_memory_block(void);",
    ),
    0x4C: InterruptServiceSpec(
        0x21,
        "dos_exit",
        "_dos_exit",
        "exit",
        "exit",
        pseudo_decl="void dos_exit(int status);",
        dos_decl="void _dos_exit(unsigned char status);",
        modern_decl="void exit(int status);",
        result_kind=InterruptServiceResultKind8616.VOID,
        no_return=True,
    ),
}


INTERRUPT_SERVICE_SPECS: dict[int, InterruptServiceSpec] = {
    0x10: InterruptServiceSpec(
        0x10,
        "bios_int10_video",
        "_bios_int10_video",
        "_bios_int10_video",
        "wrapper",
        pseudo_decl="int bios_int10_video(unsigned int service);",
        dos_decl="int _bios_int10_video(unsigned int service);",
        modern_decl="int _bios_int10_video(unsigned int service);",
    ),
    0x11: InterruptServiceSpec(
        0x11,
        "bios_equiplist",
        "_bios_equiplist",
        "_bios_equiplist",
        "direct",
        pseudo_decl="int bios_equiplist(void);",
        dos_decl="int _bios_equiplist(void);",
        modern_decl="int _bios_equiplist(void);",
    ),
    0x12: InterruptServiceSpec(
        0x12,
        "bios_memsize",
        "_bios_memsize",
        "_bios_memsize",
        "direct",
        pseudo_decl="int bios_memsize(void);",
        dos_decl="int _bios_memsize(void);",
        modern_decl="int _bios_memsize(void);",
    ),
    0x13: InterruptServiceSpec(
        0x13,
        "bios_int13_disk",
        "_bios_disk",
        "_bios_disk",
        "wrapper",
        pseudo_decl="int bios_int13_disk(void);",
        dos_decl="int _bios_disk(void);",
        modern_decl="int _bios_disk(void);",
    ),
    0x14: InterruptServiceSpec(
        0x14,
        "bios_int14_serial",
        "_bios_serialcom",
        "_bios_serialcom",
        "wrapper",
        pseudo_decl="int bios_int14_serial(void);",
        dos_decl="int _bios_serialcom(void);",
        modern_decl="int _bios_serialcom(void);",
    ),
    0x15: InterruptServiceSpec(
        0x15,
        "bios_int15_system",
        "_bios_int15_system",
        "_bios_int15_system",
        "wrapper",
        pseudo_decl="int bios_int15_system(void);",
        dos_decl="int _bios_int15_system(void);",
        modern_decl="int _bios_int15_system(void);",
    ),
    0x16: InterruptServiceSpec(
        0x16,
        "bios_keybrd",
        "_bios_keybrd",
        "_bios_keybrd",
        "direct",
        pseudo_decl="unsigned bios_keybrd(unsigned keycmd);",
        dos_decl="unsigned _bios_keybrd(unsigned keycmd);",
        modern_decl="unsigned _bios_keybrd(unsigned keycmd);",
    ),
    0x17: InterruptServiceSpec(
        0x17,
        "bios_int17_printer",
        "_bios_printer",
        "_bios_printer",
        "wrapper",
        pseudo_decl="int bios_int17_printer(void);",
        dos_decl="int _bios_printer(void);",
        modern_decl="int _bios_printer(void);",
    ),
    0x1A: InterruptServiceSpec(
        0x1A,
        "bios_timeofday",
        "_bios_timeofday",
        "_bios_timeofday",
        "direct",
        pseudo_decl="int bios_timeofday(void);",
        dos_decl="int _bios_timeofday(void);",
        modern_decl="int _bios_timeofday(void);",
    ),
}


def _interrupt_service_key(call: InterruptCall) -> int:
    return call.vector & 0xFF


def interrupt_service_addr(call: InterruptCall) -> int:
    """Return the synthetic hook address for a recovered interrupt service."""
    if call.vector == 0x21:
        service = call.ah & 0xFF if call.ah is not None else 0
        return int(DOS_SERVICE_BASE_ADDR) + service
    return int(INTERRUPT_SERVICE_BASE_ADDR) + _interrupt_service_key(call)


def interrupt_service_name(call: InterruptCall, api_style: str = "pseudo") -> str:
    """Return the service helper name for the selected API style."""

    def _impl() -> str:
        spec = _interrupt_service_spec_for_call(call)
        if spec is not None:
            if api_style == "pseudo":
                return spec.pseudo_name
            if api_style in {"dos", "msc", "compiler"}:
                return spec.dos_name
            return spec.modern_name

        if call.vector == 0x21:
            spec = INT21_SERVICE_SPECS.get(call.ah or -1)
            if spec is not None:
                if api_style == "pseudo":
                    return spec.pseudo_name
                if api_style in {"dos", "msc", "compiler"}:
                    return spec.dos_name
                return spec.modern_name
            return "dos_int21"

        if call.vector == 0x10:
            return "bios_int10_video" if api_style == "pseudo" else "_bios_int10_video"
        if call.vector == 0x11:
            return "bios_equiplist" if api_style == "pseudo" else "_bios_equiplist"
        if call.vector == 0x12:
            return "bios_memsize" if api_style == "pseudo" else "_bios_memsize"
        if call.vector == 0x13:
            return "bios_int13_disk" if api_style == "pseudo" else "_bios_disk"
        if call.vector == 0x14:
            return "bios_int14_serial" if api_style == "pseudo" else "_bios_serialcom"
        if call.vector == 0x15:
            return "bios_int15_system" if api_style == "pseudo" else "_bios_int15_system"
        if call.vector == 0x16:
            return "bios_keybrd" if api_style == "pseudo" else "_bios_keybrd"
        if call.vector == 0x17:
            return "bios_int17_printer" if api_style == "pseudo" else "_bios_printer"
        if call.vector == 0x1A:
            return "bios_timeofday" if api_style == "pseudo" else "_bios_timeofday"
        return get_interrupt_handler_class(call.vector).INT_NAME

    return _impl()


def dos_service_name(call: InterruptCall) -> str:
    """Return the pseudo DOS service helper name for a DOS interrupt call."""
    return interrupt_service_name(call, "pseudo")


def _interrupt_service_name_for_helper(call: InterruptCall, api_style: str) -> str:
    if api_style in {"dos", "msc", "compiler"}:
        return interrupt_service_name(call, "dos")
    return interrupt_service_name(call, "pseudo")


def interrupt_service_spec(call: InterruptCall) -> InterruptServiceSpec | None:
    """Return metadata for non-DOS interrupt services."""
    if call.vector == 0x21:
        return None
    return INTERRUPT_SERVICE_SPECS.get(call.vector)


def interrupt_service_result_kind_at_addr_8616(
    target_addr: int,
) -> InterruptServiceResultKind8616 | None:
    """Return typed result semantics for one exact synthetic interrupt target."""
    dos_selector = target_addr - int(DOS_SERVICE_BASE_ADDR)
    if 0 <= dos_selector <= 0xFF:
        spec = INT21_SERVICE_SPECS.get(dos_selector)
        return None if spec is None else spec.result_kind
    vector = target_addr - int(INTERRUPT_SERVICE_BASE_ADDR)
    if 0 <= vector <= 0xFF:
        spec = INTERRUPT_SERVICE_SPECS.get(vector)
        return None if spec is None else spec.result_kind
    return None


def _interrupt_service_spec_for_call(call: InterruptCall) -> InterruptServiceSpec | None:
    if call.vector == 0x21:
        return INT21_SERVICE_SPECS.get(call.ah or -1)
    return INTERRUPT_SERVICE_SPECS.get(call.vector)


def dos_service_addr(call: InterruptCall) -> int:
    """Return the synthetic hook address for a DOS service call."""
    return interrupt_service_addr(call)


def ensure_interrupt_service_hook(project: object, call: InterruptCall) -> tuple[int, str]:
    """Install the pseudo interrupt service hook for a recovered interrupt call."""
    addr = interrupt_service_addr(call)
    name = _interrupt_service_name_for_helper(call, "pseudo")

    project_any = cast(Any, project)
    if not project_any.is_hooked(addr):
        spec = _interrupt_service_spec_for_call(call)
        no_ret = spec is not None and spec.no_return

        def _run(self: SimProcedure) -> object:  # pylint:disable=unused-argument
            if no_ret:
                code = _dynamic_analysis_getattr_8616(self.state.regs, "al", claripy.BVV(0, 8))
                self.exit(claripy.ZeroExt(8, code))
            return claripy.BVS(f"{name}_ax", 16, explicit_name=True)

        proc_cls = type(
            f"{name.title().replace('_', '')}Procedure",
            (SimProcedure,),
            {
                "display_name": name,
                "NO_RET": no_ret,
                "run": _run,
            },
        )
        project_any.hook(addr, proc_cls(), replace=True)

    return addr, name


def ensure_dos_service_hook(project: object, call: InterruptCall) -> tuple[int, str]:
    """Install the pseudo DOS service hook for a recovered DOS call."""
    return ensure_interrupt_service_hook(project, call)


def _remove_proven_no_return_fallthrough_8616(
    function: object,
    *,
    insn_addr: int,
    return_addr: int | None,
) -> bool:
    """Remove the exact CFG fallthrough edge for a proven no-return service."""
    if return_addr is None:
        return False
    graph = _dynamic_analysis_getattr_8616(function, "transition_graph", None)
    if graph is None:
        return False
    nodes = tuple(_dynamic_analysis_getattr_8616(graph, "nodes", ()))
    source = next(
        (
            node
            for node in nodes
            if isinstance(_dynamic_analysis_getattr_8616(node, "addr", None), int)
            and isinstance(_dynamic_analysis_getattr_8616(node, "size", None), int)
            and node.addr <= insn_addr < node.addr + node.size
        ),
        None,
    )
    target = next(
        (
            node
            for node in nodes
            if _dynamic_analysis_getattr_8616(node, "addr", None) == return_addr
        ),
        None,
    )
    if source is None or target is None or not graph.has_edge(source, target):
        return False
    graph.remove_edge(source, target)
    return True


def patch_interrupt_service_call_sites(
    function: object,
    binary_path: Path | str | None = None,
    *,
    vectors: set[int] | None = None,
) -> bool:
    """Rewrite Function._call_sites for recoverable DOS and BIOS interrupt services.

    The decompiler needs these synthetic hooks so direct interrupt callsites can
    be rendered with the service-specific helper names recovered from the
    interrupt vector and register state.
    """
    project = _dynamic_analysis_getattr_8616(function, "project", None)
    if project is None:
        return False

    changed = False
    function_any = cast(Any, function)
    function_addr = _dynamic_analysis_getattr_8616(function, "addr", None)
    for call in collect_interrupt_service_calls(function, binary_path, vectors=vectors):
        target_addr, name = ensure_interrupt_service_hook(project, call)
        if isinstance(function_addr, int):
            record_software_interrupt_service_target_8616(
                project,
                SoftwareInterruptServiceTargetFact8616(
                    function_addr=function_addr,
                    callsite_addr=call.insn_addr,
                    vector=call.vector,
                    target_addr=target_addr,
                    helper_name=name,
                ),
            )
        return_addr = _analysis_function_call_return_8616(function, call.insn_addr)
        spec = _interrupt_service_spec_for_call(call)
        if spec is not None and spec.no_return:
            changed |= _remove_proven_no_return_fallthrough_8616(
                function,
                insn_addr=call.insn_addr,
                return_addr=return_addr,
            )
            return_addr = None
        new = (target_addr, return_addr)
        old = function_any._call_sites.get(call.insn_addr)
        if old != new:
            function_any._call_sites[call.insn_addr] = new
            changed = True
        callee = cast(Any, project).kb.functions.function(addr=target_addr, create=True)
        if callee is not None:
            callee.name = name
            callee._init_prototype_and_calling_convention()

    return changed


def normalize_api_style(api_style: str) -> str:
    """Normalize user-facing API style aliases to renderer modes."""
    if api_style in {"pseudo", "service"}:
        return "pseudo"
    if api_style in {"dos", "msc", "compiler"}:
        return "dos"
    return api_style


def describe_x86_16_interrupt_api_surface() -> dict[str, object]:
    """Describe the public interrupt helper API surface."""
    return {
        "dos": {
            "service_count": len(INT21_SERVICE_SPECS),
            "service_names": tuple(spec.modern_name for spec in INT21_SERVICE_SPECS.values()),
            "helper_names": tuple(spec.dos_name for spec in INT21_SERVICE_SPECS.values()),
        },
        "bios": {
            "service_count": len(INTERRUPT_SERVICE_SPECS),
            "service_names": tuple(spec.modern_name for spec in INTERRUPT_SERVICE_SPECS.values()),
            "helper_names": tuple(spec.dos_name for spec in INTERRUPT_SERVICE_SPECS.values()),
            "vectors": tuple(sorted(INTERRUPT_SERVICE_SPECS)),
        },
        "wrappers": {
            "kinds": ("int86", "int86x", "intdos", "intdosx"),
            "input_fields": ("inregs", "outregs", "sregs"),
            "result_paths": (
                "outregs.h.ah",
                "outregs.h.al",
                "outregs.x.ax",
                "outregs.x.bx",
                "outregs.x.cx",
                "outregs.x.dx",
                "sregs.es",
            ),
        },
    }


def describe_x86_16_interrupt_core_surface() -> dict[str, object]:
    """Describe the low-level interrupt hook surface."""
    return {
        "vector_base": INTERRUPT_CORE_VECTOR_BASE,
        "vector_count": INTERRUPT_CORE_VECTOR_COUNT,
        "hook_count": INTERRUPT_CORE_VECTOR_COUNT,
        "runtime_alias_base": 0x0000,
        "named_vectors": (*sorted(INTERRUPT_SERVICE_SPECS), 32, 33, 37, 38, 39, 47),
        "control_transfer_policy": "int -> synthetic target -> SimOS hook",
        "low_level_helpers": (
            "interrupt_service_addr",
            "ensure_interrupt_service_hook",
            "ensure_dos_service_hook",
            "collect_interrupt_service_calls",
            "patch_interrupt_service_call_sites",
        ),
    }


def describe_x86_16_interrupt_lowering_boundary() -> dict[str, object]:
    """Describe the interrupt analysis/lowering ownership boundary."""
    return {
        "boundary_rule": "interrupt instruction semantics stay low-level; DOS/BIOS/MS-C lowering stays in analysis and rewrite helpers",
        "core_surface": describe_x86_16_interrupt_core_surface(),
        "api_surface": describe_x86_16_interrupt_api_surface(),
        "validated_by": (
            "tests/test_x86_16_milestone_report.py",
            "tests/test_x86_16_package_exports.py",
            "tests/test_x86_16_helper_modeling.py",
        ),
    }


def known_helper_signature_decl(name: str) -> str | None:
    """Return a known helper declaration by exact helper name."""
    abi = known_helper_abi_8616(name)
    return None if abi is None else abi.declaration


def preferred_known_helper_signature_decl(name: str) -> str | None:
    """Return the preferred declaration for a helper name or underscore variant."""
    abi = preferred_known_helper_abi_8616(name)
    return None if abi is None else abi.declaration


def describe_x86_16_known_helper_signatures() -> dict[str, object]:
    """Describe the known helper signature catalog."""
    return {
        "signature_count": len(KNOWN_HELPER_SIGNATURE_DECLS),
        "helper_names": tuple(sorted(KNOWN_HELPER_SIGNATURE_DECLS)),
        "declarations": tuple(sorted(KNOWN_HELPER_SIGNATURE_DECLS.values())),
    }


def infer_com_region(path: Path, *, base_addr: int, window: int, arch: object) -> tuple[int, int]:
    """Infer a bounded `.COM` code region by scanning until a likely terminator.

    This keeps tiny DOS stubs from decompiling their trailing strings as code.
    """

    def _impl() -> tuple[int, int]:
        data = path.read_bytes()
        end_limit = min(len(data), window)
        current = 0
        ah = None

        while current < end_limit:
            chunk = data[current : current + 16]
            insn = next(cast(Any, arch).capstone.disasm(chunk, base_addr + current, 1), None)
            if insn is None:
                break

            text = f"{insn.mnemonic} {insn.op_str}".strip().lower()
            if text.startswith("mov ah, "):
                ah = int(text.split(", ", 1)[1], 0)
            elif text.startswith("mov ax, "):
                ax = int(text.split(", ", 1)[1], 0)
                ah = (ax >> 8) & 0xFF

            current += insn.size

            if insn.mnemonic == "int":
                if insn.op_str.lower() == "0x20":
                    break
                if insn.op_str.lower() == "0x21" and ah == 0x4C:
                    break
                if insn.op_str.lower() == "0x27":
                    break
            if insn.mnemonic in {"ret", "retf", "iret", "jmp"}:
                break

        return base_addr, base_addr + max(current, 1)

    return _impl()


def _decode_com_ascii_string(binary_path: Path | None, dx: int | None, *, terminator: int) -> str | None:
    def _impl() -> str | None:
        if binary_path is None or binary_path.suffix.lower() != ".com" or dx is None or dx < 0x100:
            return None
        try:
            data = binary_path.read_bytes()
        except OSError:
            return None

        start = dx - 0x100
        if start < 0 or start >= len(data):
            return None
        end = data.find(bytes([terminator]), start)
        if end == -1:
            return None
        raw = data[start:end]
        if not raw:
            return ""
        if any(byte < 0x20 or byte > 0x7E for byte in raw):
            return None
        text = raw.decode("ascii", errors="ignore")
        return text.replace("\\", "\\\\").replace('"', '\\"')

    return _impl()


def _coerce_path(binary_path: Path | str | None) -> Path | None:
    if binary_path is None or isinstance(binary_path, Path):
        return binary_path
    return Path(binary_path)


def decode_com_dollar_string(binary_path: Path | str | None, dx: int | None) -> str | None:
    """Decode a DOS dollar-terminated string from a COM binary image."""
    binary_path = _coerce_path(binary_path)
    return _decode_com_ascii_string(binary_path, dx, terminator=ord("$"))


def decode_com_c_string(binary_path: Path | str | None, dx: int | None) -> str | None:
    """Decode a NUL-terminated string from a COM binary image."""
    binary_path = _coerce_path(binary_path)
    return _decode_com_ascii_string(binary_path, dx, terminator=0)


def _format_imm(value: int) -> str:
    if 0 <= value <= 9:
        return str(value)
    return f"0x{value:x}"


def _format_mem_operand(ins: object, operand: object) -> str:
    """Render one typed Capstone memory operand as a segmented C load."""
    mem = _dynamic_analysis_getattr_8616(operand, "mem", None)
    if mem is None:
        return "<mem>"

    pieces: list[str] = []
    base = _dynamic_analysis_getattr_8616(mem, "base", 0)
    index = _dynamic_analysis_getattr_8616(mem, "index", 0)
    scale = _dynamic_analysis_getattr_8616(mem, "scale", 1)
    disp = _dynamic_analysis_getattr_8616(mem, "disp", 0)
    base_name = cast(Any, ins).reg_name(base).lower() if base else ""
    if base:
        pieces.append(base_name)
    if index:
        index_name = cast(Any, ins).reg_name(index).lower()
        pieces.append(f"+{index_name} * {scale}" if pieces and scale != 1 else f"+{index_name}" if pieces else index_name)
    if disp:
        disp_text = hex(abs(disp)) if abs(disp) > 9 else str(abs(disp))
        if pieces:
            pieces.append(("+" if disp >= 0 else "-") + disp_text)
        else:
            pieces.append(("-" if disp < 0 else "") + disp_text)
    if not pieces:
        pieces.append("0")
    segment = _dynamic_analysis_getattr_8616(mem, "segment", 0)
    segment_name = (
        cast(Any, ins).reg_name(segment).lower()
        if segment
        else "ss" if base_name in {"bp", "sp", "ebp", "esp"} else "ds"
    )
    width = _dynamic_analysis_getattr_8616(operand, "size", 0)
    macro = {1: "SEG_U8", 2: "SEG_U16", 4: "SEG_U32"}.get(width)
    if macro is None:
        return "<mem>"
    return f"{macro}(inertia_{segment_name}, {''.join(pieces)})"


def _operand_expr(ins: object, operand: object) -> tuple[int | None, str | None]:
    operand_any = cast(Any, operand)
    if operand_any.type == 1:
        reg_name = cast(Any, ins).reg_name(operand_any.reg).lower()
        return None, reg_name
    if operand_any.type == 2:
        imm = operand_any.imm & 0xFFFF
        return imm, _format_imm(imm)
    if operand_any.type == 3:
        return None, _format_mem_operand(ins, operand)
    return None, None


@dataclass(frozen=True, slots=True)
class _InterruptSymbolicStackWord8616:
    """One exactly decoded PUSH value retained for interrupt-input recovery."""

    value: int | None
    expr: str | None
    source_register: str | None
    fallthrough_addr: int | None


@dataclass(frozen=True, slots=True)
class _InterruptDirectCallStackEffect8616:
    """Typed caller-stack effect proven from one direct callee's terminals."""

    preserves_stack: bool
    return_frame_kind: TerminalReturnFrameKind8616 | None


def collect_interrupt_calls(
    function: object,
    binary_path: Path | str | None = None,
    *,
    vectors: set[int] | None = None,
) -> list[InterruptCall]:
    """Collect recoverable interrupt calls from a dynamic angr Function boundary."""

    def _impl() -> list[InterruptCall]:
        nonlocal binary_path
        binary_path = _coerce_path(binary_path)
        project = _dynamic_analysis_getattr_8616(function, "project", None)
        if project is None:
            return []

        calls: list[InterruptCall] = []
        debug_interrupt_stack = bool(os.environ.get("INERTIA_DEBUG_INTERRUPT_STACK"))
        regs: dict[str, tuple[int | None, str | None]] = {
            "ah": (None, None),
            "al": (None, None),
            "ax": (None, None),
            "bh": (None, None),
            "bl": (None, None),
            "bx": (None, None),
            "ch": (None, None),
            "cl": (None, None),
            "cx": (None, None),
            "dh": (None, None),
            "dl": (None, None),
            "dx": (None, None),
            "si": (None, None),
            "di": (None, None),
            "ds": (None, None),
            "es": (None, None),
            "ss": (None, None),
            "cs": (None, None),
        }

        def set_reg(reg_name: str, value: int | None, expr: str | None) -> None:
            regs[reg_name] = (value, expr)

            if reg_name in {"ax", "bx", "cx", "dx"}:
                if value is not None:
                    high = (value >> 8) & 0xFF
                    low = value & 0xFF
                    regs[f"{reg_name[0]}h"] = (high, _format_imm(high))
                    regs[f"{reg_name[0]}l"] = (low, _format_imm(low))
                else:
                    regs[f"{reg_name[0]}h"] = (None, None)
                    regs[f"{reg_name[0]}l"] = (None, None)
            elif reg_name in {"ah", "al"}:
                high_byte, _ = regs["ah"]
                low_byte, _ = regs["al"]
                if high_byte is not None and low_byte is not None:
                    regs["ax"] = (((high_byte & 0xFF) << 8) | (low_byte & 0xFF), None)
                else:
                    regs["ax"] = (None, None)
            elif reg_name in {"bh", "bl"}:
                high_byte, _ = regs["bh"]
                low_byte, _ = regs["bl"]
                if high_byte is not None and low_byte is not None:
                    regs["bx"] = (((high_byte & 0xFF) << 8) | (low_byte & 0xFF), None)
                else:
                    regs["bx"] = (None, None)
            elif reg_name in {"ch", "cl"}:
                high_byte, _ = regs["ch"]
                low_byte, _ = regs["cl"]
                if high_byte is not None and low_byte is not None:
                    regs["cx"] = (((high_byte & 0xFF) << 8) | (low_byte & 0xFF), None)
                else:
                    regs["cx"] = (None, None)
            elif reg_name in {"dh", "dl"}:
                high_byte, _ = regs["dh"]
                low_byte, _ = regs["dl"]
                if high_byte is not None and low_byte is not None:
                    regs["dx"] = (((high_byte & 0xFF) << 8) | (low_byte & 0xFF), None)
                else:
                    regs["dx"] = (None, None)

        def pushed_value(ins: object, operand: object) -> _InterruptSymbolicStackWord8616 | None:
            """Capture one exact register/immediate PUSH source before later calls."""
            ins_addr = _dynamic_analysis_int_attr_8616(ins, "address")
            ins_size = _dynamic_analysis_int_attr_8616(ins, "size")
            fallthrough_addr = (
                ins_addr + ins_size
                if ins_addr is not None and ins_size is not None and ins_size > 0
                else None
            )
            operand_type = _dynamic_analysis_getattr_8616(operand, "type", None)
            if operand_type == 1:
                reg_name = cast(Any, ins).reg_name(cast(Any, operand).reg).lower()
                if reg_name not in regs:
                    return None
                value, expr = regs[reg_name]
                if value is None and expr is None:
                    expr = {
                        "ax": "inertia_eax & 0xffff",
                        "bx": "inertia_ebx & 0xffff",
                        "cx": "inertia_ecx & 0xffff",
                        "dx": "inertia_edx & 0xffff",
                        "si": "inertia_esi & 0xffff",
                        "di": "inertia_edi & 0xffff",
                        "ds": "inertia_ds",
                        "es": "inertia_es",
                        "ss": "inertia_ss",
                        "cs": "inertia_cs",
                    }.get(reg_name)
                return _InterruptSymbolicStackWord8616(value, expr, reg_name, fallthrough_addr)
            if operand_type == 2:
                value, expr = _operand_expr(ins, operand)
                return _InterruptSymbolicStackWord8616(value, expr, None, fallthrough_addr)
            return None

        def direct_call_stack_effect(
            ins: CsInsn,
            operands: object,
        ) -> _InterruptDirectCallStackEffect8616:
            """Prove one direct callee's cleanup and consistent return-frame shape."""
            unknown = _InterruptDirectCallStackEffect8616(False, None)
            if not isinstance(operands, (list, tuple)) or len(operands) != 1:
                return unknown
            target = operands[0]
            if _dynamic_analysis_getattr_8616(target, "type", None) != 2:
                return unknown
            target_addr = _dynamic_analysis_getattr_8616(target, "imm", None)
            if not isinstance(target_addr, int):
                return unknown
            if ins.mnemonic == "call":
                ins_addr = _dynamic_analysis_getattr_8616(ins, "address", None)
                if isinstance(ins_addr, int):
                    target_addr = (ins_addr & ~0xFFFF) | (target_addr & 0xFFFF)
            candidates = [(project, target_addr)]
            original_project = _dynamic_analysis_getattr_8616(project, "_inertia_original_project", None)
            original_delta = _dynamic_analysis_getattr_8616(project, "_inertia_original_linear_delta", None)
            if original_project is not None and isinstance(original_delta, int):
                candidates.append((original_project, target_addr + original_delta))
            proofs = tuple(
                (
                    candidate_addr,
                    terminal_stack_cleanup_at_address_8616(candidate_project, candidate_addr),
                )
                for candidate_project, candidate_addr in candidates
            )
            if debug_interrupt_stack:
                print(
                    f"[interrupt-stack] target={target_addr:#x} delta={original_delta!r} proofs={proofs!r}",
                    file=sys.stderr,
                )
            qualifying = tuple(
                evidence
                for _candidate_addr, evidence in proofs
                if evidence.complete and evidence.consistent_cleanup == 0
            )
            if not qualifying:
                return unknown
            frame_kinds = frozenset(evidence.consistent_return_frame_kind for evidence in qualifying)
            if len(frame_kinds) != 1:
                return unknown
            return _InterruptDirectCallStackEffect8616(True, next(iter(frame_kinds)))

        block_sizes: dict[int, int] = {}
        graph = _dynamic_analysis_getattr_8616(function, "transition_graph", None)
        if graph is not None:
            for node in tuple(_dynamic_analysis_getattr_8616(graph, "nodes", ())):
                node_addr = _dynamic_analysis_getattr_8616(node, "addr", None)
                node_size = _dynamic_analysis_getattr_8616(node, "size", None)
                if isinstance(node_addr, int) and isinstance(node_size, int) and node_size > 0:
                    block_sizes[node_addr] = node_size
        block_addrs = {
            *(
                addr
                for addr in _dynamic_analysis_getattr_8616(function, "block_addrs_set", ())
                if isinstance(addr, int)
            ),
            *block_sizes,
        }
        symbolic_stack: list[_InterruptSymbolicStackWord8616] = []
        expected_next_block: int | None = None
        for block_addr in sorted(block_addrs):
            if debug_interrupt_stack:
                print(
                    f"[interrupt-stack] block={block_addr:#x} expected={expected_next_block!r} depth={len(symbolic_stack)}",
                    file=sys.stderr,
                )
            if expected_next_block != block_addr:
                symbolic_stack.clear()
            expected_next_block = None
            block_size = block_sizes.get(block_addr)
            if block_size is None:
                block = project.factory.block(block_addr, opt_level=0)
            else:
                block = project.factory.block(block_addr, size=block_size, opt_level=0)
            block_bytes = bytes(_dynamic_analysis_getattr_8616(block, "bytes", b""))
            capstone_engine = cast(Any, project).arch.capstone
            for ins in capstone_engine.disasm(block_bytes, block_addr):
                ins_size = _dynamic_analysis_getattr_8616(ins, "size", None)
                expected_next_block = (
                    ins.address + ins_size
                    if isinstance(ins.address, int) and isinstance(ins_size, int)
                    else None
                )
                operands = _dynamic_analysis_getattr_8616(ins, "operands", ())
                if ins.mnemonic == "push" and len(operands) == 1:
                    captured = pushed_value(ins, operands[0])
                    if captured is None:
                        symbolic_stack.clear()
                    else:
                        symbolic_stack.append(captured)
                    if debug_interrupt_stack:
                        print(
                            f"[interrupt-stack] push={ins.op_str!r} captured={captured!r} depth={len(symbolic_stack)}",
                            file=sys.stderr,
                        )
                elif ins.mnemonic == "pop" and len(operands) == 1:
                    destination = operands[0]
                    if destination.type != 1 or not symbolic_stack:
                        symbolic_stack.clear()
                        continue
                    reg_name = ins.reg_name(destination.reg).lower()
                    if reg_name not in regs:
                        symbolic_stack.clear()
                        continue
                    restored = symbolic_stack.pop()
                    set_reg(reg_name, restored.value, restored.expr)
                    if debug_interrupt_stack:
                        print(
                            f"[interrupt-stack] pop={reg_name} "
                            f"value={(restored.value, restored.expr)!r} depth={len(symbolic_stack)}",
                            file=sys.stderr,
                        )
                elif ins.mnemonic in {"call", "lcall"}:
                    effect = direct_call_stack_effect(ins, operands)
                    call_addr = _dynamic_analysis_int_attr_8616(ins, "address")
                    consumes_explicit_return_segment = (
                        effect.preserves_stack
                        and effect.return_frame_kind is TerminalReturnFrameKind8616.FAR
                        and ins.mnemonic == "call"
                        and bool(symbolic_stack)
                        and symbolic_stack[-1].source_register == "cs"
                        and symbolic_stack[-1].fallthrough_addr == call_addr
                    )
                    if consumes_explicit_return_segment:
                        symbolic_stack.pop()
                    if debug_interrupt_stack:
                        print(
                            f"[interrupt-stack] call={ins.op_str!r} preserves={effect.preserves_stack} "
                            f"frame={effect.return_frame_kind!r} "
                            f"consumed_cs={consumes_explicit_return_segment} depth={len(symbolic_stack)}",
                            file=sys.stderr,
                        )
                    if not effect.preserves_stack or (
                        effect.return_frame_kind is TerminalReturnFrameKind8616.FAR
                        and ins.mnemonic == "call"
                        and not consumes_explicit_return_segment
                    ):
                        symbolic_stack.clear()
                elif ins.mnemonic == "mov" and len(operands) == 2:
                    dst, src = operands
                    if dst.type == 1:
                        reg_name = ins.reg_name(dst.reg).lower()
                        if reg_name in {"sp", "esp"}:
                            symbolic_stack.clear()
                        if reg_name in regs:
                            value, expr = _operand_expr(ins, src)
                            set_reg(reg_name, value, expr)
                elif ins.mnemonic == "xor" and len(operands) == 2 and operands[0].type == 1 and operands[1].type == 1:
                    dst_name = ins.reg_name(operands[0].reg).lower()
                    src_name = ins.reg_name(operands[1].reg).lower()
                    if dst_name == src_name and dst_name in regs:
                        set_reg(dst_name, 0, "0")
                    if dst_name in {"sp", "esp"}:
                        symbolic_stack.clear()
                elif operands and _dynamic_analysis_getattr_8616(operands[0], "type", None) == 1:
                    destination_name = ins.reg_name(operands[0].reg).lower()
                    if destination_name in {"sp", "esp"}:
                        symbolic_stack.clear()
                elif ins.mnemonic in {"int", "int3"}:
                    if ins.mnemonic == "int3":
                        vector = 3
                    else:
                        vector_text = ins.op_str.lower().strip()
                        try:
                            vector = int(vector_text, 0) & 0xFF
                        except ValueError:
                            continue
                    if vectors is not None and vector not in vectors:
                        continue

                    ah, ah_expr = regs["ah"]
                    al, al_expr = regs["al"]
                    ax, ax_expr = regs["ax"]
                    bh, bh_expr = regs["bh"]
                    bl, bl_expr = regs["bl"]
                    bx, bx_expr = regs["bx"]
                    ch, ch_expr = regs["ch"]
                    cl, cl_expr = regs["cl"]
                    cx, cx_expr = regs["cx"]
                    dh, dh_expr = regs["dh"]
                    dl, dl_expr = regs["dl"]
                    dx, dx_expr = regs["dx"]
                    si, si_expr = regs["si"]
                    di, di_expr = regs["di"]
                    ds, ds_expr = regs["ds"]
                    es, es_expr = regs["es"]
                    ss, ss_expr = regs["ss"]
                    cs, cs_expr = regs["cs"]
                    if debug_interrupt_stack and (symbolic_stack or dx_expr is not None):
                        print(
                            f"[interrupt-stack] int={ins.address:#x} ah={ah!r} dx={(dx, dx_expr)!r} depth={len(symbolic_stack)}",
                            file=sys.stderr,
                        )
                    path_literal = None
                    if vector == 0x21 and ah in {0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x41}:
                        path_literal = decode_com_c_string(binary_path, dx)
                    elif vector == 0x21 and ah == 0x09:
                        path_literal = decode_com_dollar_string(binary_path, dx)
                    calls.append(
                        InterruptCall(
                            insn_addr=ins.address,
                            vector=vector,
                            ah=ah,
                            al=al,
                            ax=ax,
                            bh=bh,
                            bl=bl,
                            bx=bx,
                            ch=ch,
                            cl=cl,
                            cx=cx,
                            dh=dh,
                            dl=dl,
                            dx=dx,
                            si=si,
                            di=di,
                            ds=ds,
                            es=es,
                            ss=ss,
                            cs=cs,
                            ah_expr=ah_expr,
                            al_expr=al_expr,
                            ax_expr=ax_expr,
                            bh_expr=bh_expr,
                            bl_expr=bl_expr,
                            bx_expr=bx_expr,
                            ch_expr=ch_expr,
                            cl_expr=cl_expr,
                            cx_expr=cx_expr,
                            dh_expr=dh_expr,
                            dl_expr=dl_expr,
                            dx_expr=dx_expr,
                            si_expr=si_expr,
                            di_expr=di_expr,
                            ds_expr=ds_expr,
                            es_expr=es_expr,
                            ss_expr=ss_expr,
                            cs_expr=cs_expr,
                            string_literal=path_literal,
                        )
                    )
                    if vector == 0x21:
                        set_reg("dx", None, None)
                if ins.mnemonic.startswith("j") or ins.mnemonic.startswith("loop") or ins.mnemonic.startswith("ret"):
                    expected_next_block = None

        return calls

    return _impl()


def collect_dos_int21_calls(function: object, binary_path: Path | str | None = None) -> list[DOSInt21Call]:
    """Collect recovered DOS int 21h service calls from an angr Function."""
    return [call for call in collect_interrupt_calls(function, binary_path, vectors={0x21}) if call.vector == 0x21]


def collect_interrupt_service_calls(
    function: object,
    binary_path: Path | str | None = None,
    *,
    vectors: set[int] | None = None,
) -> list[InterruptCall]:
    """Collect recovered DOS/BIOS interrupt service calls from an angr Function."""
    return collect_interrupt_calls(function, binary_path, vectors=vectors)


def _dos_path_arg(call: DOSInt21Call, *, far_ptr: bool) -> str | None:
    if call.string_literal is not None:
        return f'"{call.string_literal}"'
    if call.dx is not None:
        cast = "const char far *" if far_ptr else "const char *"
        return f"({cast})0x{call.dx:x}"
    if call.dx_expr is not None:
        cast = "const char far *" if far_ptr else "const char *"
        return f"({cast})({call.dx_expr})"
    return None


def _dos_arg(value: int | None, expr: str | None) -> str | None:
    if value is not None:
        return _format_imm(value)
    return expr


def _dos_buffer_arg(call: DOSInt21Call, *, far_ptr: bool, const: bool) -> str | None:
    cast = (
        "const void far *" if far_ptr and const else "void far *" if far_ptr else "const void *" if const else "void *"
    )
    if call.dx is not None:
        return f"({cast})0x{call.dx:x}"
    if call.dx_expr is not None:
        return f"({cast}){call.dx_expr}"
    return None


def _dos_si_buffer_arg(call: DOSInt21Call, *, far_ptr: bool, const: bool) -> str | None:
    cast = (
        "const char far *" if far_ptr and const else "char far *" if far_ptr else "const char *" if const else "char *"
    )
    if call.si is not None:
        return f"({cast})0x{call.si:x}"
    if call.si_expr is not None:
        return f"({cast}){call.si_expr}"
    return None


def _dos_drive_arg(call: DOSInt21Call) -> str | None:
    if call.dl is not None:
        return _format_imm(call.dl)
    return call.dl_expr


def _dos_seek_offset_arg(call: DOSInt21Call) -> str:
    if call.cx is not None and call.dx is not None:
        return f"0x{(((call.cx & 0xFFFF) << 16) | (call.dx & 0xFFFF)):x}"
    high = _dos_arg(call.cx, call.cx_expr)
    low = _dos_arg(call.dx, call.dx_expr)
    if high is not None and low is not None:
        return f"MK_LONG({low}, {high})"
    if low is not None:
        return low
    return "0"


def _dos_vector_arg(call: DOSInt21Call) -> str | None:
    if call.al is not None:
        return _format_imm(call.al)
    return call.al_expr


def _dos_far_pointer_arg(call: DOSInt21Call) -> str | None:
    segment = _dos_arg(call.ds, call.ds_expr)
    offset = _dos_arg(call.dx, call.dx_expr)
    if segment is not None and offset is not None:
        return f"MK_FP({segment}, {offset})"
    if offset is not None:
        return offset
    return None


def _interrupt_service_decl(spec: InterruptServiceSpec, api_style: str) -> str:
    api_style = normalize_api_style(api_style)
    if api_style == "pseudo" and spec.pseudo_decl is not None:
        return spec.pseudo_decl
    if api_style == "dos" and spec.dos_decl is not None:
        return spec.dos_decl
    if api_style == "raw":
        return ""
    if spec.modern_decl is not None:
        return spec.modern_decl
    if api_style == "pseudo":
        return f"int {spec.pseudo_name}(void);"
    if api_style == "dos":
        return f"int {spec.dos_name}(void);"
    return f"int {spec.modern_name.lstrip('_')}(void);"


def _render_string_dollar_call_8616(call: DOSInt21Call, api_style: str, name: str) -> str:
    helper_name = "_dos_print_dollar_string" if api_style == "dos" else name if api_style == "pseudo" else "print_dos_string"
    if call.string_literal is not None:
        return f'{helper_name}("{call.string_literal}")'
    argument = _dos_path_arg(call, far_ptr=api_style == "dos")
    return f"{helper_name}({argument})" if argument is not None else f"{helper_name}()"


def _render_setvect_call_8616(call: DOSInt21Call, api_style: str, name: str) -> str:
    vector = _dos_vector_arg(call) or "0"
    handler = _dos_far_pointer_arg(call) or "NULL"
    if api_style == "dos":
        return f"_dos_setvect({vector}, {handler})"
    if api_style == "pseudo":
        return f"{name}({vector}, {handler})"
    return f"setvect({vector}, {handler})"


def _render_getvect_call_8616(call: DOSInt21Call, api_style: str, name: str) -> str:
    vector = _dos_vector_arg(call) or "0"
    if api_style == "dos":
        return f"_dos_getvect({vector})"
    if api_style == "pseudo":
        return f"{name}({vector})"
    return f"getvect({vector})"


def _render_dos_int21_by_kind_8616(call: DOSInt21Call, api_style: str, name: str, render_kind: str) -> str:
    def _impl() -> str:
        if render_kind == "string_dollar":
            return _render_string_dollar_call_8616(call, api_style, name)
        if render_kind == "drive":
            return f"{name}({_dos_drive_arg(call) or '0'})"
        if render_kind == "path":
            return f"{name}({_dos_path_arg(call, far_ptr=api_style == 'dos') or 'NULL'})"
        if render_kind == "path_mode":
            path = _dos_path_arg(call, far_ptr=api_style == "dos") or "NULL"
            mode = _dos_arg(call.al, call.al_expr) or "0"
            return f"{name}({path}, {mode})"
        if render_kind == "path_attrs":
            path = _dos_path_arg(call, far_ptr=api_style == "dos") or "NULL"
            attrs = _dos_arg(call.cx, call.cx_expr) or "0"
            return f"{name}({path}, {attrs})"
        if render_kind == "handle":
            return f"{name}({_dos_arg(call.bx, call.bx_expr) or '0'})"
        if render_kind == "handle_buffer_count":
            handle = _dos_arg(call.bx, call.bx_expr) or "0"
            buffer = _dos_buffer_arg(call, far_ptr=api_style == "dos", const=call.ah == 0x40) or "NULL"
            count = _dos_arg(call.cx, call.cx_expr) or "0"
            return f"{name}({handle}, {buffer}, {count})"
        if render_kind == "handle_seek":
            handle = _dos_arg(call.bx, call.bx_expr) or "0"
            offset = _dos_seek_offset_arg(call)
            origin = _dos_arg(call.al, call.al_expr) or "0"
            return f"{name}({handle}, {offset}, {origin})"
        if render_kind == "drive_buffer":
            drive = _dos_drive_arg(call) or "0"
            buffer = _dos_si_buffer_arg(call, far_ptr=api_style == "dos", const=False) or "NULL"
            return f"{name}({drive}, {buffer})"
        if render_kind == "setvect":
            return _render_setvect_call_8616(call, api_style, name)
        if render_kind == "getvect":
            return _render_getvect_call_8616(call, api_style, name)
        if render_kind == "exit":
            exit_code = call.ax & 0xFF if call.ax is not None else 0
            return f"{name}({exit_code})"
        if render_kind in {"zero_arg", "wrapper", "setblock", "get_version"}:
            return f"{name}()"
        return f"{name}()"

    return _impl()


def render_dos_int21_call(call: DOSInt21Call, api_style: str) -> str:
    """Render a recovered DOS int 21h call as a helper call expression."""
    api_style = normalize_api_style(api_style)

    if api_style == "raw":
        return "dos_int21()"

    spec = INT21_SERVICE_SPECS.get(call.ah or -1)
    if spec is None:
        return "dos_int21()"

    name = interrupt_service_name(call, api_style)
    return _render_dos_int21_by_kind_8616(call, api_style, name, spec.render_kind)


def _render_simple_interrupt_call(call: InterruptCall, api_style: str) -> str:
    def _impl() -> str:
        nonlocal api_style
        api_style = normalize_api_style(api_style)
        spec = interrupt_service_spec(call)
        if spec is None:
            return render_dos_int21_call(call, api_style)
        if api_style == "raw":
            return f"int{call.vector:02x}()"

        if call.vector == 0x10 and spec.render_kind == "wrapper":
            if call.ah is not None:
                selector = _format_imm(call.ah)
                return f"{interrupt_service_name(call, api_style)}({selector})"
            extended = any(value is not None for value in (call.ds, call.es, call.ss, call.cs))
            if extended:
                return "int86x(0x10, &inregs, &outregs, &sregs)"
            return "int86(0x10, &inregs, &outregs)"

        name = interrupt_service_name(call, api_style)
        if call.vector == 0x16:
            dos_selector = _dos_arg(call.ah, call.ah_expr)
            if dos_selector is not None:
                return f"{name}({dos_selector})"
            return f"{name}()"
        if call.vector == 0x10 and api_style in {"dos", "msc", "compiler"}:
            return f"{name}(0x10)"
        if call.vector == 0x13 and api_style == "pseudo":
            return f"{name}()"
        return f"{name}()"

    return _impl()


def render_interrupt_call(call: InterruptCall, api_style: str) -> str:
    """Render a recovered DOS or BIOS interrupt call as a helper call expression."""
    spec = interrupt_service_spec(call)
    if spec is None:
        return render_dos_int21_call(call, api_style)
    return _render_simple_interrupt_call(call, api_style)


def dos_helper_declarations(calls: list[DOSInt21Call], api_style: str) -> list[str]:
    """Return declarations required by rendered DOS helper calls."""
    api_style = normalize_api_style(api_style)
    if api_style == "raw":
        return []

    declarations: list[str] = []
    seen: set[str] = set()
    for call in calls:
        spec = _interrupt_service_spec_for_call(call)
        if spec is None:
            decl = "int dos_int21(void);"
        else:
            if spec.render_kind == "wrapper" and call.vector not in {0x21, 0x10}:
                continue
            if call.vector == 0x10 and call.ah is None:
                continue
            decl = _interrupt_service_decl(spec, api_style)
        if decl not in seen:
            seen.add(decl)
            declarations.append(decl)
    return declarations


def interrupt_service_declarations(calls: list[InterruptCall], api_style: str) -> list[str]:
    """Return declarations required by rendered interrupt service helper calls."""

    def _impl() -> list[str]:
        nonlocal api_style
        api_style = normalize_api_style(api_style)
        if api_style == "raw":
            return []

        declarations: list[str] = []
        seen: set[str] = set()
        for call in calls:
            spec = _interrupt_service_spec_for_call(call)
            if spec is None:
                decls = dos_helper_declarations([call], api_style)
                for decl in decls:
                    if decl not in seen:
                        seen.add(decl)
                        declarations.append(decl)
                continue

            if spec.render_kind == "wrapper" and call.vector not in {0x21, 0x10}:
                continue
            if call.vector == 0x10 and call.ah is None:
                continue

            decl = _interrupt_service_decl(spec, api_style)
            if decl not in seen:
                seen.add(decl)
                declarations.append(decl)
        return declarations

    return _impl()


def _absolute_mem_disp(operand: object) -> int | None:
    mem = _dynamic_analysis_getattr_8616(operand, "mem", None)
    if mem is None:
        return None
    if _dynamic_analysis_getattr_8616(mem, "base", 0) != 0 or _dynamic_analysis_getattr_8616(mem, "index", 0) != 0:
        return None
    return int(_dynamic_analysis_getattr_8616(mem, "disp", 0)) & 0xFFFF


def _initial_cs_linear_base(project: object) -> int | None:
    main_object = _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(project, "loader", None), "main_object", None)
    initial_regs = _dynamic_analysis_getattr_8616(main_object, "initial_register_values", None)
    if not isinstance(initial_regs, Mapping):
        return None
    cs = initial_regs.get("cs")
    if not isinstance(cs, int):
        return None
    return (cs & 0xFFFF) << 4


def _x86_16_project_for_function_8616(function: object) -> object | None:
    project = _dynamic_analysis_getattr_8616(function, "project", None)
    if _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(project, "arch", None), "name", None) == "86_16":
        return cast(object, project)
    return None


def _canonical_code_linear_addr(project: object, addr: int | None) -> int | None:
    if not isinstance(addr, int):
        return None
    original_project = _dynamic_analysis_getattr_8616(project, "_inertia_original_project", None)
    original_delta = _dynamic_analysis_getattr_8616(project, "_inertia_original_linear_delta", None)
    if original_project is not None and isinstance(original_delta, int):
        original_main = _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(original_project, "loader", None), "main_object", None)
        original_base = _dynamic_analysis_getattr_8616(original_main, "linked_base", None)
        if isinstance(original_base, int) and addr < original_base:
            return addr + original_delta
        return addr

    main_object = _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(project, "loader", None), "main_object", None)
    linked_base = _dynamic_analysis_getattr_8616(main_object, "linked_base", None)
    max_addr = _dynamic_analysis_getattr_8616(main_object, "max_addr", None)
    if isinstance(linked_base, int) and isinstance(max_addr, int) and addr < linked_base:
        rebased = linked_base + addr
        image_end = linked_base + max_addr + 1
        if linked_base <= rebased < image_end:
            return rebased
    return addr


def _project_memory_load_8616(project: object, addr: int, size: int) -> bytes | None:
    memory = _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(project, "loader", None), "memory", None)
    load = _dynamic_analysis_getattr_8616(memory, "load", None)
    if not callable(load):
        return None
    with contextlib.suppress(Exception):
        loaded = cast(Any, load)(addr, size)
        return bytes(cast(Any, loaded))
    return None


def _looks_like_x86_16_frame_prologue_8616(code: bytes, offset: int) -> bool:
    return 0 <= offset <= len(code) - 3 and code[offset : offset + 3] in {b"\x55\x8b\xec", b"\x55\x89\xe5"}


def canonicalize_x86_16_padding_call_target_8616(
    project: object,
    addr: int | None,
) -> int | None:
    """Advance a public padding entry to its proven x86-16 frame prologue."""
    if not isinstance(addr, int):
        return None
    if _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(project, "arch", None), "name", None) != "86_16":
        return addr

    padding_bytes = {0x00, 0x90, 0xCC}
    scan_limit = 0x80
    for candidate_project, candidate_addr in (
        (project, addr),
        (_dynamic_analysis_getattr_8616(project, "_inertia_original_project", None), addr),
    ):
        if candidate_project is None:
            continue
        code = _project_memory_load_8616(candidate_project, candidate_addr, scan_limit + 4)
        if not code:
            continue
        if _looks_like_x86_16_frame_prologue_8616(code, 0):
            return addr
        cursor = 0
        while cursor < min(scan_limit, len(code)) and code[cursor] in padding_bytes:
            cursor += 1
        if cursor > 0 and _looks_like_x86_16_frame_prologue_8616(code, cursor):
            return addr + cursor
    return addr


def _neighbor_image_bounds(project: object) -> tuple[int | None, int | None]:
    candidate_projects = [_dynamic_analysis_getattr_8616(project, "_inertia_original_project", None), project]
    for candidate_project in candidate_projects:
        main_object = _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(candidate_project, "loader", None), "main_object", None)
        linked_base = _dynamic_analysis_getattr_8616(main_object, "linked_base", None)
        max_addr = _dynamic_analysis_getattr_8616(main_object, "max_addr", None)
        if isinstance(linked_base, int) and isinstance(max_addr, int):
            return linked_base, linked_base + max_addr + 1
    return None, None


def _direct_call_insn_from_block(project: object, block_addr: int) -> object | None:
    block = _analysis_project_block_8616(project, block_addr)
    insns = _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(block, "capstone", None), "insns", ()) or ()
    if not insns:
        return None

    for insn in insns:
        if _dynamic_analysis_getattr_8616(insn, "address", None) != block_addr:
            continue
        mnemonic = str(_dynamic_analysis_getattr_8616(insn, "mnemonic", "") or "").lower()
        if mnemonic in {"call", "lcall"}:
            return cast(object, insn)

    last = insns[-1]
    mnemonic = str(_dynamic_analysis_getattr_8616(last, "mnemonic", "") or "").lower()
    if mnemonic in {"call", "lcall"}:
        return cast(object, last)
    return None


def _resolve_direct_call_target_from_insn(project: object, insn: object) -> int | None:
    operands: tuple[Any, ...] = tuple(
        _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(insn, "insn", None), "operands", ()) or ()
    )
    mnemonic = str(_dynamic_analysis_getattr_8616(insn, "mnemonic", "") or "").lower()

    if mnemonic == "lcall" and len(operands) == 2 and all(_dynamic_analysis_getattr_8616(op, "type", None) == 2 for op in operands):
        seg = operands[0].imm & 0xFFFF
        off = operands[1].imm & 0xFFFF
        return canonicalize_x86_16_padding_call_target_8616(
            project,
            (seg << 4) + off,
        )

    if mnemonic == "call" and len(operands) == 1 and _dynamic_analysis_getattr_8616(operands[0], "type", None) == 2:
        return canonicalize_x86_16_padding_call_target_8616(
            project,
            _canonical_code_linear_addr(project, operands[0].imm),
        )

    return None


def resolve_direct_call_target_from_instruction_8616(
    project: object,
    instruction: object,
) -> int | None:
    """Recover a direct target from one exact decoded CALL instruction."""
    return _resolve_direct_call_target_from_insn(project, instruction)


def resolve_direct_call_target_from_block(project: object, block_addr: int) -> int | None:
    """Recover a direct call target from a block-end call or a callsite inside a block.

    This is intentionally narrow and only handles the direct near/far forms
    that show up in our DOS samples. Indirect calls still return ``None``.
    """
    insn = _direct_call_insn_from_block(project, block_addr)
    if insn is None:
        return None
    return resolve_direct_call_target_from_instruction_8616(project, insn)


def _callsite_addr_decodes_to_direct_call_8616(project: object, callsite_addr: int) -> bool | None:
    try:
        block = _analysis_project_block_8616(project, callsite_addr)
    except Exception:
        return None

    insns = _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(block, "capstone", None), "insns", ()) or ()
    for insn in insns:
        if _dynamic_analysis_getattr_8616(insn, "address", None) != callsite_addr:
            continue
        mnemonic = str(_dynamic_analysis_getattr_8616(insn, "mnemonic", "") or "").lower()
        return mnemonic in {"call", "lcall"}
    return None


def sanitize_direct_call_sites_8616(function: object) -> DirectCallsiteSanitizationEvidence:
    """Prune impossible direct-call entries from a recovered x86-16 function."""

    def _impl() -> DirectCallsiteSanitizationEvidence:
        project = _x86_16_project_for_function_8616(function)
        if project is None:
            return DirectCallsiteSanitizationEvidence()

        call_sites = _dynamic_analysis_getattr_8616(function, "_call_sites", None)
        if not isinstance(call_sites, dict):
            return DirectCallsiteSanitizationEvidence()

        raw_fact_count = len(call_sites)
        normalized_fact_count = 0
        classified_fact_count = 0
        failure_count = 0
        pruned_count = 0
        for callsite_addr in tuple(call_sites):
            if not isinstance(callsite_addr, int):
                failure_count += 1
                continue
            normalized_fact_count += 1
            is_call = _callsite_addr_decodes_to_direct_call_8616(project, callsite_addr)
            if is_call is None:
                failure_count += 1
                continue
            classified_fact_count += 1
            if not is_call:
                del call_sites[callsite_addr]
                pruned_count += 1

        return DirectCallsiteSanitizationEvidence(
            raw_fact_count=raw_fact_count,
            normalized_fact_count=normalized_fact_count,
            classified_fact_count=classified_fact_count,
            materialized_count=pruned_count,
            failure_count=failure_count,
            pruned_count=pruned_count,
        )

    return _impl()


def resolve_direct_jump_target_from_block(project: object, block_addr: int) -> int | None:
    """Recover a direct jump target from the last instruction in a block.

    This is used for tail-jump thunks that should seed neighbor recovery even
    when no explicit call edge exists.
    """

    def _impl() -> int | None:
        block = _analysis_project_block_8616(project, block_addr)
        insns = _dynamic_analysis_getattr_8616(block.capstone, "insns", ())
        if not insns:
            return None

        last = insns[-1]
        capstone_insn = _dynamic_analysis_getattr_8616(last, "insn", None)
        operands: tuple[Any, ...] = tuple(
            _dynamic_analysis_getattr_8616(capstone_insn, "operands", ()) if capstone_insn is not None else ()
        )

        if last.mnemonic == "ljmp" and len(operands) == 2 and all(op.type == 2 for op in operands):
            seg = operands[0].imm & 0xFFFF
            off = operands[1].imm & 0xFFFF
            return _canonical_code_linear_addr(project, (seg << 4) + off)

        if last.mnemonic == "jmp" and len(operands) == 1 and operands[0].type == 2:
            return _canonical_code_linear_addr(project, operands[0].imm & 0xFFFF)

        op_str = str(_dynamic_analysis_getattr_8616(last, "op_str", "") or "").strip().lower()
        if last.mnemonic == "jmp" and op_str and "[" not in op_str:
            for token in op_str.replace(":", " ").split():
                try:
                    return _canonical_code_linear_addr(project, int(token, 0) & 0xFFFF)
                except ValueError:
                    continue

        return None

    return _impl()


def _direct_call_target_kind_8616(project: object, callsite_addr: int) -> CallTargetKind8616 | None:
    """Classify an exact decoded direct call without interpreting rendered assembly."""
    insn = _direct_call_insn_from_block(project, callsite_addr)
    if insn is None or _resolve_direct_call_target_from_insn(project, insn) is None:
        return None
    mnemonic = str(_dynamic_analysis_getattr_8616(insn, "mnemonic", "") or "").lower()
    if mnemonic == "lcall":
        return CallTargetKind8616.DIRECT_FAR_CALL
    if mnemonic == "call":
        return CallTargetKind8616.DIRECT_NEAR_CALL
    return None


def _direct_tail_jump_kind_8616(project: object, block_addr: int) -> CallTargetKind8616 | None:
    """Classify an exact decoded direct tail jump by architectural form."""
    block = _analysis_project_block_8616(project, block_addr)
    insns = _dynamic_analysis_tuple_attr_8616(block.capstone, "insns")
    if not insns:
        return None
    mnemonic = str(_dynamic_analysis_getattr_8616(insns[-1], "mnemonic", "") or "").lower()
    if mnemonic == "ljmp":
        return CallTargetKind8616.DIRECT_FAR_TAIL_JUMP
    if mnemonic == "jmp":
        return CallTargetKind8616.DIRECT_NEAR_TAIL_JUMP
    return None


def _tail_jump_target_is_function_entry_8616(project: object, target_addr: int) -> bool:
    """Require exact function-entry evidence before treating a jump as a tail call."""
    metadata = _dynamic_analysis_getattr_8616(project, "_inertia_lst_metadata", None)
    function_entries = _dynamic_analysis_getattr_8616(metadata, "function_entry_addrs", ())
    if function_entries:
        candidates = {target_addr}
        original_delta = _dynamic_analysis_getattr_8616(project, "_inertia_original_linear_delta", None)
        if isinstance(original_delta, int):
            candidates.update((target_addr + original_delta, target_addr - original_delta))
        return any(candidate in function_entries for candidate in candidates)

    functions = _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(project, "kb", None), "functions", None)
    lookup = _dynamic_analysis_getattr_8616(functions, "function", None)
    if not callable(lookup):
        return False
    with contextlib.suppress(Exception):
        return lookup(addr=target_addr, create=False) is not None
    return False


def patch_direct_call_sites(function: object) -> bool:
    """Recover direct near/far callsites from block ends when CFG left `_call_sites` empty.

    Rebased exact-region recovery for small 16-bit functions sometimes keeps the
    block boundaries but loses the function callsite inventory. Downstream
    callsite summaries and argument recovery consume `Function.get_call_sites()`,
    so patch the direct block-end calls back into `_call_sites` before later
    passes give up on call reasoning.
    """

    def _impl() -> bool:
        project = _x86_16_project_for_function_8616(function)
        if project is None:
            return False

        call_sites = _dynamic_analysis_getattr_8616(function, "_call_sites", None)
        if not isinstance(call_sites, dict):
            return False
        sanitization = sanitize_direct_call_sites_8616(function)
        changed = sanitization.pruned_count > 0
        instruction_inventory = collect_function_instruction_inventory_8616(
            project,
            function_entry=_analysis_function_addr_8616(function),
        )
        instruction_groups: tuple[tuple[object, ...], ...]
        if instruction_inventory.complete:
            instruction_groups = (instruction_inventory.instructions,)
        else:
            fallback_groups: list[tuple[object, ...]] = []
            for block_addr in _analysis_function_block_addrs_8616(function):
                try:
                    block = _analysis_project_block_8616(project, block_addr)
                except Exception:
                    continue
                instructions = _dynamic_analysis_tuple_attr_8616(
                    _dynamic_analysis_getattr_8616(block, "capstone", None),
                    "insns",
                )
                if instructions:
                    fallback_groups.append(instructions)
            instruction_groups = tuple(fallback_groups)
        for insns in instruction_groups:
            for insn in insns:
                mnemonic = str(_dynamic_analysis_getattr_8616(insn, "mnemonic", "") or "").lower()
                if mnemonic not in {"call", "lcall"}:
                    continue
                callsite_addr = _dynamic_analysis_getattr_8616(insn, "address", None)
                if not isinstance(callsite_addr, int):
                    continue
                target_addr = _resolve_direct_call_target_from_insn(project, insn)
                if target_addr is None:
                    target_addr = resolve_stored_near_call_target_from_function(function, callsite_addr)
                if target_addr is None:
                    continue
                size = _dynamic_analysis_getattr_8616(insn, "size", None)
                if not isinstance(size, int) or size <= 0:
                    size = _dynamic_analysis_getattr_8616(_dynamic_analysis_getattr_8616(insn, "insn", None), "size", None)
                return_addr = None
                if isinstance(size, int) and size > 0:
                    return_addr = callsite_addr + size
                current = call_sites.get(callsite_addr)
                recovered = (target_addr, return_addr)
                if current != recovered:
                    call_sites[callsite_addr] = recovered
                    changed = True
        return changed

    return _impl()


def resolve_stored_near_call_target_from_function(function: object, callsite_addr: int) -> int | None:
    """Recover a near call target from a startup-built absolute pointer slot.

    This is intentionally narrow. It only handles patterns like:

        mov word ptr ss:[0x60], 0x01a2
        ...
        call word ptr [0x60]

    which appear in MSC startup code for real-mode DOS.
    """

    def _impl() -> int | None:
        project = _x86_16_project_for_function_8616(function)
        if project is None:
            return None

        block = _analysis_project_block_8616(project, callsite_addr)
        insns = _dynamic_analysis_getattr_8616(block.capstone, "insns", ())
        if not insns:
            return None
        last = insns[-1]
        capstone_insn = _dynamic_analysis_getattr_8616(last, "insn", None)
        operands: tuple[Any, ...] = tuple(
            _dynamic_analysis_getattr_8616(capstone_insn, "operands", ()) if capstone_insn is not None else ()
        )
        if last.mnemonic != "call" or len(operands) != 1 or operands[0].type != 3:
            return None

        slot_disp = _absolute_mem_disp(operands[0])
        if slot_disp is None:
            return None

        cs_base = _initial_cs_linear_base(project)
        if cs_base is None:
            return None

        prior_insns: list[object] = []
        for addr in _analysis_function_block_addrs_8616(function):
            if addr >= callsite_addr:
                continue
            prior_block = _analysis_project_block_8616(project, addr)
            prior_insns.extend(_dynamic_analysis_getattr_8616(prior_block.capstone, "insns", ()))

        for ins in reversed(prior_insns):
            ins_any = cast(Any, ins)
            if ins_any.address >= callsite_addr:
                continue
            opers: tuple[Any, ...] = tuple(_dynamic_analysis_getattr_8616(ins_any.insn, "operands", ()) or ())
            if ins_any.mnemonic != "mov" or len(opers) != 2:
                continue
            dst, src = opers
            if dst.type != 3 or src.type != 2:
                continue
            dst_disp = _absolute_mem_disp(dst)
            if dst_disp != slot_disp:
                continue
            return _canonical_code_linear_addr(project, cs_base + (src.imm & 0xFFFF))

        return None

    return _impl()


def resolve_stored_near_jump_target_from_function(function: object, jump_addr: int) -> int | None:
    """Recover a near jump target from a startup-built absolute pointer slot.

    This mirrors ``resolve_stored_near_call_target_from_function`` for tail-jump
    thunks that end in ``jmp word ptr [slot]``.
    """

    def _impl() -> int | None:
        project = _x86_16_project_for_function_8616(function)
        if project is None:
            return None

        block = _analysis_project_block_8616(project, jump_addr)
        insns = _dynamic_analysis_getattr_8616(block.capstone, "insns", ())
        if not insns:
            return None
        last = insns[-1]
        capstone_insn = _dynamic_analysis_getattr_8616(last, "insn", None)
        operands: tuple[Any, ...] = tuple(
            _dynamic_analysis_getattr_8616(capstone_insn, "operands", ()) if capstone_insn is not None else ()
        )
        if last.mnemonic != "jmp" or len(operands) != 1 or operands[0].type != 3:
            return None

        slot_disp = _absolute_mem_disp(operands[0])
        if slot_disp is None:
            return None

        cs_base = _initial_cs_linear_base(project)
        if cs_base is None:
            return None

        prior_insns: list[object] = []
        for addr in _analysis_function_block_addrs_8616(function):
            if addr >= jump_addr:
                continue
            prior_block = _analysis_project_block_8616(project, addr)
            prior_insns.extend(_dynamic_analysis_getattr_8616(prior_block.capstone, "insns", ()))

        for ins in reversed(prior_insns):
            ins_any = cast(Any, ins)
            if ins_any.address >= jump_addr:
                continue
            opers: tuple[Any, ...] = tuple(_dynamic_analysis_getattr_8616(ins_any.insn, "operands", ()) or ())
            if ins_any.mnemonic != "mov" or len(opers) != 2:
                continue
            dst, src = opers
            if dst.type != 3 or src.type != 2:
                continue
            dst_disp = _absolute_mem_disp(dst)
            if dst_disp != slot_disp:
                continue
            return _canonical_code_linear_addr(project, cs_base + (src.imm & 0xFFFF))

        return None

    return _impl()


def collect_direct_far_call_targets(function: object) -> list[FarCallTarget]:
    """Recover only immediate far-call targets directly from lifted blocks.

    angr's stock call-target recovery does not currently understand the x86-16
    `CS:IP` far-call pattern very well, so medium-model DOS startup code often
    ends up with `UnresolvableCallTarget` call edges even when the block itself
    is fully understood. This helper keeps the workaround small, explicit, and
    reusable for CLI tooling and tests.
    """
    project = _x86_16_project_for_function_8616(function)
    if project is None:
        return []
    recovered: list[FarCallTarget] = []

    for callsite_addr in _analysis_function_call_sites_8616(function):
        if _direct_call_target_kind_8616(project, callsite_addr) is not CallTargetKind8616.DIRECT_FAR_CALL:
            continue
        target_addr = resolve_direct_call_target_from_block(project, callsite_addr)
        # Real-mode far calls commonly land below 64 KiB once segment:offset is
        # linearized (for example 0x0114:0x0240 -> 0x1380). Only discard calls
        # we still failed to resolve, not low linear addresses.
        if target_addr is None:
            continue

        recovered.append(
            FarCallTarget(
                callsite_addr=callsite_addr,
                target_addr=target_addr,
                return_addr=_analysis_function_call_return_8616(function, callsite_addr),
            )
        )

    return recovered


def collect_neighbor_call_targets(function: object) -> list[CallTargetSeed]:
    """Recover direct x86-16 call neighbors from a function's traced call sites.

    We prefer targets already recorded by CFG when they stay inside the loaded
    image, then fall back to block-level decoding for direct near/far calls and
    the narrow startup pointer-slot recovery used by MSC-style startup code.
    Proven tail transfers refine generic CFG entries for the same site/target;
    decoded calls retain precedence and repeated evidence does not add edges.
    """

    def _impl() -> list[CallTargetSeed]:
        """Merge machine transfer evidence without losing its decoded origin."""
        project = _x86_16_project_for_function_8616(function)
        if project is None:
            return []

        patch_direct_call_sites(function)

        linked_base, image_end = _neighbor_image_bounds(project)

        recovered: dict[tuple[int, int], CallTargetSeed] = {}
        for callsite_addr in _analysis_function_call_sites_8616(function):
            target_addr = None
            kind = CallTargetKind8616.CFG_RESOLVED_CALL
            target_addr = _analysis_function_call_target_8616(function, callsite_addr)
            if target_addr is not None and linked_base is not None and image_end is not None and not (
                linked_base <= target_addr < image_end
            ):
                target_addr = None

            direct_target = resolve_direct_call_target_from_block(project, callsite_addr)
            direct_kind = _direct_call_target_kind_8616(project, callsite_addr)
            if direct_target is not None:
                target_addr = direct_target
                if direct_kind is not None:
                    kind = direct_kind
            if direct_target is None and target_addr is None:
                stored_target = resolve_stored_near_call_target_from_function(function, callsite_addr)
                if stored_target is not None:
                    target_addr = stored_target
                    kind = CallTargetKind8616.STORED_NEAR_CALL
            if target_addr is None:
                continue
            if linked_base is not None and image_end is not None and not (linked_base <= target_addr < image_end):
                continue
            key = (callsite_addr, target_addr)
            if key in recovered:
                continue
            recovered[key] = CallTargetSeed(
                callsite_addr=callsite_addr,
                target_addr=target_addr,
                return_addr=_analysis_function_call_return_8616(function, callsite_addr),
                kind=kind,
            )

        block_addrs = sorted(_dynamic_analysis_getattr_8616(function, "block_addrs_set", ()))
        block_addr_set = set(block_addrs)
        for block_addr in block_addrs:
            jump_target = resolve_direct_jump_target_from_block(project, block_addr)
            tail_kind: CallTargetKind8616 | None = _direct_tail_jump_kind_8616(project, block_addr)
            if jump_target is None:
                jump_target = resolve_stored_near_jump_target_from_function(function, block_addr)
                if jump_target is not None:
                    tail_kind = CallTargetKind8616.STORED_NEAR_TAIL_JUMP
            if jump_target is None or tail_kind is None:
                continue
            function_addr = _analysis_function_addr_8616(function)
            if jump_target in block_addr_set or jump_target == function_addr:
                continue
            if not _tail_jump_target_is_function_entry_8616(project, jump_target):
                continue
            if linked_base is not None and image_end is not None and not (linked_base <= jump_target < image_end):
                continue
            key = (block_addr, jump_target)
            existing = recovered.get(key)
            if existing is not None and existing.kind is not CallTargetKind8616.CFG_RESOLVED_CALL:
                continue
            recovered[key] = CallTargetSeed(
                callsite_addr=block_addr,
                target_addr=jump_target,
                return_addr=None,
                kind=tail_kind,
            )

        return list(recovered.values())

    def _build_cached_evidence(
        _project: object | None,
        _function: object,
    ) -> list[CallTargetSeed]:
        """Adapt the closed collector to the shared evidence inventory."""
        return _impl()

    project = _x86_16_project_for_function_8616(function)
    if project is None:
        return []
    function_addr = _analysis_function_addr_8616(function)
    function_size = _dynamic_analysis_int_attr_8616(function, "size")
    if function_addr is None or function_size is None or function_size <= 0:
        return _impl()
    try:
        function_content = bytes(cast(Any, project).loader.memory.load(function_addr, function_size))
    except (AttributeError, KeyError, TypeError, ValueError):
        return _impl()
    return list(
        collect_function_binary_evidence_8616(
            project,
            function,
            kind=FunctionEvidenceKind8616.NEIGHBOR_CALL_TARGETS,
            builder=_build_cached_evidence,
            content_identity=function_content,
        )
    )


def patch_far_call_sites(function: object, far_targets: list[FarCallTarget]) -> bool:
    """Rewrite Function._call_sites for immediate far calls recovered from blocks.

    CFGFast currently leaves some x86-16 far callsites pointing at a bogus short
    target (for example `0x14`) even when the block disassembly clearly shows an
    immediate `seg:off` far call. The decompiler reads `Function.get_call_target()`
    from `_call_sites`, so patching those entries gives downstream analyses a
    much better callee address without needing to modify site-packages angr.
    """
    changed = False
    function_any = cast(Any, function)

    for target in far_targets:
        old = function_any._call_sites.get(target.callsite_addr)
        new = (target.target_addr, target.return_addr)
        if old != new:
            function_any._call_sites[target.callsite_addr] = new
            changed = True

    return changed


def patch_dos_int21_call_sites(function: object, binary_path: Path | str | None = None) -> bool:
    """Rewrite Function._call_sites for recoverable int 21h services.

    This gives the decompiler service-specific pseudo-callees instead of a
    single undifferentiated `dos_int21` hook at every site.
    """
    return patch_interrupt_service_call_sites(function, binary_path, vectors={0x21})


def seed_calling_conventions(cfg: object) -> None:
    """Initialize and refine x86-16 calling conventions for CFG functions."""
    from .calling_convention_seed_cache import (
        CallingConventionSeedRevision8616,
        calling_convention_seed_revision_8616,
    )
    from .lowering.terminal_call_return_types import apply_terminal_call_return_type_evidence_8616
    from .lowering.terminal_register_return_types import apply_terminal_register_return_type_evidence_8616

    apply_x86_16_stack_byte_prototype_evidence: Callable[[object, object], bool] | None
    apply_x86_16_wide_stack_prototype_evidence: Callable[[object, object], bool] | None
    try:
        from .calling_convention_compat import apply_x86_16_stack_byte_prototype_evidence as _stack_byte_evidence
        from .calling_convention_compat import apply_x86_16_wide_stack_prototype_evidence as _wide_stack_evidence

        apply_x86_16_stack_byte_prototype_evidence = _stack_byte_evidence
        apply_x86_16_wide_stack_prototype_evidence = _wide_stack_evidence
    except Exception:  # pragma: no cover - compatibility fallback during partial imports
        apply_x86_16_stack_byte_prototype_evidence = None
        apply_x86_16_wide_stack_prototype_evidence = None

    def _function_identity_8616(function: object) -> int:
        function_addr = _analysis_function_addr_8616(function)
        if isinstance(function_addr, int):
            return function_addr
        return id(function)

    def _seeded_calling_conventions_function_ids(cfg_obj: object) -> set[int]:
        cached = _dynamic_analysis_getattr_8616(cfg_obj, "_inertia_seeded_calling_conventions", None)
        if isinstance(cached, set):
            return cast(set[int], cached)
        return set()

    def _function_seed_revision_8616(
        function: object,
        inspected_targets: tuple[int, ...] | None = None,
    ) -> CallingConventionSeedRevision8616:
        """Refresh the exact dependencies recorded by terminal-call typing."""
        if inspected_targets is None:
            previous = seeded_revisions.get(_function_identity_8616(function))
            inspected_targets = tuple(item.target_addr for item in previous.callees) if previous is not None else ()
        return calling_convention_seed_revision_8616(project, function, inspected_targets)

    def _seeded_calling_convention_revisions_8616(
        cfg_obj: object,
    ) -> dict[int, CallingConventionSeedRevision8616]:
        """Read revision-aware cache state across the dynamic CFG boundary."""
        cached = _dynamic_analysis_getattr_8616(
            cfg_obj,
            "_inertia_seeded_calling_convention_revisions_8616",
            None,
        )
        return {
            key: value for key, value in cached.items()
            if isinstance(key, int) and isinstance(value, CallingConventionSeedRevision8616)
        } if isinstance(cached, Mapping) else {}

    def _is_stack_probe_helper_name(name: str | None) -> bool:
        if not isinstance(name, str):
            return False
        normalized = name.strip().lower().lstrip("_")
        return normalized in {"anchkstk", "analloca_probe"}

    cfg_functions = _dynamic_analysis_getattr_8616(cfg, "functions", {})
    if not isinstance(cfg_functions, Mapping):
        cfg_functions = {}
    project = _dynamic_analysis_getattr_8616(cfg, "project", None) or _dynamic_analysis_getattr_8616(cfg, "_project", None)
    total_functions = len(cfg_functions)
    seeded_ids = _seeded_calling_conventions_function_ids(cfg)
    seeded_revisions = _seeded_calling_convention_revisions_8616(cfg)
    candidates = tuple(
        function for function in cfg_functions.values()
        if (
            _function_identity_8616(function) not in seeded_ids
            or seeded_revisions.get(_function_identity_8616(function))
            != _function_seed_revision_8616(function)
        )
    )
    candidate_count = len(candidates)
    if candidate_count == 0:
        return

    track = True
    success_count = 0
    error_count = 0
    stack_probe_count = 0
    stack_byte_count = 0
    wide_stack_count = 0
    terminal_call_return_count = 0
    terminal_call_return_raw = 0
    terminal_call_return_normalized = 0
    terminal_call_return_classified = 0
    terminal_call_return_materialized = 0
    terminal_call_return_failures = 0
    terminal_register_return_raw = 0
    terminal_register_return_normalized = 0
    terminal_register_return_classified = 0
    terminal_register_return_materialized = 0
    terminal_register_return_failures = 0
    if track:
        start = time.perf_counter()
    for function in candidates:
        function_id = _function_identity_8616(function)
        try:
            if not _function_has_proven_prototype_8616(function):
                function._init_prototype_and_calling_convention()
            if project is not None and apply_x86_16_stack_byte_prototype_evidence is not None:  # noqa: SIM102
                if apply_x86_16_stack_byte_prototype_evidence(project, function):
                    stack_byte_count += 1
            if project is not None and apply_x86_16_wide_stack_prototype_evidence is not None:  # noqa: SIM102
                if apply_x86_16_wide_stack_prototype_evidence(project, function):
                    wide_stack_count += 1
            if project is not None:
                terminal_register_result = apply_terminal_register_return_type_evidence_8616(project, function)
                terminal_register_return_raw += terminal_register_result.stats.raw_fact_count
                terminal_register_return_normalized += terminal_register_result.stats.normalized_fact_count
                terminal_register_return_classified += terminal_register_result.stats.classified_fact_count
                terminal_register_return_materialized += terminal_register_result.stats.materialized_count
                terminal_register_return_failures += terminal_register_result.stats.failure_count
            # Apply the far-frame convention last so evidence passes that seed a
            # near CC do not clobber the proven ``BP+6`` argument base.
            if project is not None:
                _apply_far_return_calling_convention_8616(project, function)
            success_count += 1
            if _is_stack_probe_helper_name(_dynamic_analysis_getattr_8616(function, "name", None)):
                stack_probe_count += 1
        except Exception as ex:
            logging.getLogger(__name__).debug("prototype init skipped: %s", ex)
            error_count += 1
            continue

        if _is_stack_probe_helper_name(_dynamic_analysis_getattr_8616(function, "name", None)):
            with contextlib.suppress(Exception):
                function.returning = True
        seeded_ids.add(function_id)
        seeded_revisions[function_id] = _function_seed_revision_8616(function)
        try:
            cast(Any, cfg)._inertia_seeded_calling_conventions = seeded_ids
            cast(Any, cfg)._inertia_seeded_calling_convention_revisions_8616 = seeded_revisions
        except Exception:
            logging.getLogger(__name__).debug("failed to cache calling convention seed state on CFG")
            cast(Any, cfg)._inertia_seeded_calling_conventions = seeded_ids
            cast(Any, cfg)._inertia_seeded_calling_convention_revisions_8616 = seeded_revisions

    if project is not None:
        for function in candidates:
            function_id = _function_identity_8616(function)
            result = apply_terminal_call_return_type_evidence_8616(project, function)
            terminal_call_return_raw += result.evidence.raw_fact_count
            terminal_call_return_normalized += result.evidence.normalized_fact_count
            terminal_call_return_classified += result.evidence.classified_fact_count
            terminal_call_return_materialized += result.evidence.materialized_count
            terminal_call_return_failures += result.evidence.failure_count
            if result.changed:
                terminal_call_return_count += 1
            _apply_far_return_calling_convention_8616(project, function)
            seeded_ids.add(function_id)
            seeded_revisions[function_id] = _function_seed_revision_8616(function, result.evidence.inspected_target_addrs)
        try:
            cast(Any, cfg)._inertia_seeded_calling_conventions = seeded_ids
            cast(Any, cfg)._inertia_seeded_calling_convention_revisions_8616 = seeded_revisions
        except Exception:
            logging.getLogger(__name__).debug("failed to cache calling convention seed state on CFG")
            cast(Any, cfg)._inertia_seeded_calling_conventions = seeded_ids
            cast(Any, cfg)._inertia_seeded_calling_convention_revisions_8616 = seeded_revisions

    if track:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        print(
            f"[metric] seed_calling_conventions cfg_functions={total_functions} "
            f"candidates={candidate_count} initialized={success_count} errors={error_count} "
            f"stack_probes={stack_probe_count} stack_byte={stack_byte_count} "
            f"wide_stack={wide_stack_count} terminal_call_return={terminal_call_return_count} "
            f"terminal_call_return_raw={terminal_call_return_raw} "
            f"terminal_call_return_normalized={terminal_call_return_normalized} "
            f"terminal_call_return_classified={terminal_call_return_classified} "
            f"terminal_call_return_materialized={terminal_call_return_materialized} "
            f"terminal_call_return_failures={terminal_call_return_failures} "
            f"terminal_register_return_raw={terminal_register_return_raw} "
            f"terminal_register_return_normalized={terminal_register_return_normalized} "
            f"terminal_register_return_classified={terminal_register_return_classified} "
            f"terminal_register_return_materialized={terminal_register_return_materialized} "
            f"terminal_register_return_failures={terminal_register_return_failures} "
            f"elapsed_ms={elapsed_ms}",
            file=sys.stderr,
            flush=True,
        )


def extend_cfg_for_far_calls(
    project: object,
    function: object,
    *,
    entry_window: int,
    callee_window: int = 0x80,
) -> object | None:
    """Re-run CFG with direct far callees seeded as extra function starts.

    This keeps bounded DOS startup recovery focused on the functions actually
    reached by immediate far calls, instead of forcing a broad CFG window that
    quickly runs into unrelated unsupported instructions.
    """
    far_targets = collect_direct_far_call_targets(function)
    if not far_targets:
        return None

    patch_far_call_sites(function, far_targets)

    function_addr = _analysis_function_addr_8616(function)
    if function_addr is None:
        return None
    function_starts = [function_addr, *(target.target_addr for target in far_targets)]
    regions = [(function_addr, function_addr + entry_window)]
    regions.extend((target.target_addr, target.target_addr + callee_window) for target in far_targets)

    cfg = cast(Any, project).analyses.CFGFast(
        start_at_entry=False,
        function_starts=sorted(set(function_starts)),
        regions=regions,
        normalize=True,
        force_complete_scan=False,
    )
    seed_calling_conventions(cfg)
    all_targets = list(far_targets)
    if function_addr in cfg.functions:
        recovered_function = cfg.functions[function_addr]
        recovered_targets = collect_direct_far_call_targets(recovered_function)
        merged: dict[tuple[int, int], FarCallTarget] = {
            (target.callsite_addr, target.target_addr): target for target in far_targets
        }
        for target in recovered_targets:
            merged[(target.callsite_addr, target.target_addr)] = target
        all_targets = list(merged.values())
        patch_far_call_sites(recovered_function, all_targets)
    for target in all_targets:
        callee = cfg.kb.functions.function(addr=target.target_addr, create=True)
        if callee is not None:
            callee._init_prototype_and_calling_convention()
    seed_calling_conventions(cfg)
    return cast(object, cfg)


# ── Function discovery ranking ──


@dataclass(frozen=True)
class EntryScore:
    """Deterministic entry-point confidence score for function discovery ranking."""

    addr: int
    score: int
    source: str = ""


def score_entry_address_8616(
    addr: int,
    *,
    is_explicit_entry: bool = False,
    is_direct_call_target: bool = False,
    is_mz_relocation_target: bool = False,
    has_prologue_match: bool = False,
    is_interrupt_service: bool = False,
    is_known_wrapper: bool = False,
    source_hint: str = "",
) -> EntryScore:
    """Compute a deterministic entry score for function discovery ranking.

    Weighted signal combination with address ascending as tie-break.
    Higher score = stronger evidence this is a real function entry point.

    Signals:
        explicit_entry:         +100  (MZ/NE entry point, linker entry)
        direct_call_target:     +80   (called by another function)
        mz_relocation_target:   +60   (MZ relocation entry)
        prologue_match:         +40   (push bp / mov bp,sp pattern)
        interrupt_service:      +20   (interrupt vector target)
        known_wrapper:          -30   (runtime/compiler wrapper, e.g. __acrtused)

    Tie-break: address ascending (lower addr = earlier = higher priority).
    """
    score = 0
    if is_explicit_entry:
        score += 100
    if is_direct_call_target:
        score += 80
    if is_mz_relocation_target:
        score += 60
    if has_prologue_match:
        score += 40
    if is_interrupt_service:
        score += 20
    if is_known_wrapper:
        score -= 30

    return EntryScore(addr=addr, score=score, source=source_hint)


def rank_entry_addresses_8616(
    entries: list[tuple[int, dict[str, object]]],
) -> list[EntryScore]:
    """Sort entry addresses by discovery confidence score, descending.

    Each entry is (addr, signals_dict).  Signals dict may contain:
        explicit_entry, direct_call_target, mz_relocation_target,
        prologue_match, interrupt_service, known_wrapper, source.

    Tie-break: address ascending.
    """
    scored = [
        score_entry_address_8616(
            addr,
            is_explicit_entry=bool(signals.get("explicit_entry")),
            is_direct_call_target=bool(signals.get("direct_call_target")),
            is_mz_relocation_target=bool(signals.get("mz_relocation_target")),
            has_prologue_match=bool(signals.get("prologue_match")),
            is_interrupt_service=bool(signals.get("interrupt_service")),
            is_known_wrapper=bool(signals.get("known_wrapper")),
            source_hint=str(signals.get("source", "")),
        )
        for addr, signals in entries
    ]
    # Higher score first; tie-break by address ascending
    scored.sort(key=lambda e: (-e.score, e.addr))
    return scored


def extend_cfg_for_neighbor_calls(
    project: object,
    function: object,
    *,
    entry_window: int,
    callee_window: int = 0x80,
    max_targets: int = 8,
) -> object | None:
    """Re-run bounded CFG with nearby traced callees seeded as extra starts.

    This keeps 16-bit function recovery local: once we recover one function we
    immediately reuse its traced call neighbors instead of widening into a
    broader scan of unrelated code bytes.
    """

    def _impl() -> object | None:
        neighbor_targets = collect_neighbor_call_targets(function)
        if not neighbor_targets:
            return None

        far_targets = collect_direct_far_call_targets(function)
        if far_targets:
            patch_far_call_sites(function, far_targets)

        unique_targets: list[CallTargetSeed] = []
        function_addr = _analysis_function_addr_8616(function)
        if function_addr is None:
            return None
        seen_targets: set[int] = {function_addr}
        for target in sorted(
            neighbor_targets,
            key=lambda item: (abs(item.target_addr - function_addr), item.callsite_addr, item.target_addr),
        ):
            if target.target_addr in seen_targets:
                continue
            seen_targets.add(target.target_addr)
            unique_targets.append(target)
            if len(unique_targets) >= max_targets:
                break
        if not unique_targets:
            return None

        function_starts = [function_addr, *(target.target_addr for target in unique_targets)]
        regions = [(function_addr, function_addr + entry_window)]
        regions.extend((target.target_addr, target.target_addr + callee_window) for target in unique_targets)

        cfg = cast(Any, project).analyses.CFGFast(
            start_at_entry=False,
            function_starts=sorted(set(function_starts)),
            regions=regions,
            normalize=True,
            force_complete_scan=False,
        )
        seed_calling_conventions(cfg)

        if function_addr in cfg.functions:
            recovered_function = cfg.functions[function_addr]
            recovered_far_targets = collect_direct_far_call_targets(recovered_function)
            if recovered_far_targets:
                patch_far_call_sites(recovered_function, recovered_far_targets)
        for target in unique_targets:
            callee = cfg.kb.functions.function(addr=target.target_addr, create=True)
            if callee is not None:
                callee._init_prototype_and_calling_convention()
        seed_calling_conventions(cfg)
        return cast(object, cfg)

    return _impl()
