"""Declared-context native fixture for scoped returning-SP proofs.

Builds one minimal conditional world per call: a declared caller entry
(``mov ax,K; call callee; ret``, or ``nop`` padding when no AX seed is
declared) chained across one decoded near-call edge into a callee whose
continuation performs ``pop cx; mov bx,sp; sub bx,ax; mov sp,bx; jmp cx``.
Every value is derived from native loader/lift/census evidence — this is a
declared-environment fixture, not proof for any real binary.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import replace
from functools import partial
from typing import cast

import angr

import inertia.ir.entry_domain_call_preservation as edcp
import inertia.ir.vex_import as vex_import
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredEntryMemory8616,
    DeclaredEntryReturn8616,
    DeclaredEntryReturnKind8616,
    DeclaredFunctionEntryAdmission8616,
    DeclaredFunctionEntrySpec8616,
    admit_declared_function_entry_8616,
)
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    build_boundary_direct_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from inertia.frontend.x86_16.frontend_near_return_continuation import (
    prove_near_call_frame_premise_8616,
)
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.ir.ir_boundary_cfg import (
    consume_scoped_ir_boundary_projection_8616,
    prove_ir_boundary_coverage_8616,
)
from inertia.ir.real16_declared_interrupt8616 import declared_environment_digest_8616
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    Real16CallChainLink8616,
    prove_fresh_real16_chained_invocation_domain_8616,
    prove_real16_declared_function_entry_domain_8616,
    real16_native_census_import_8616,
)
from inertia.lowering.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from tests.ir import test_x86_16_declared_interrupt_boundary as native
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

CALLER = 0x1020
CALLEE = 0x1060
CALLSITE = CALLER + 3
CALL2_SITE_1 = CALLER + 7
CALL2_SITE_2 = CALLER + 12
CALL2_RET_1 = CALLER + 10
CALL2_RET_2 = CALLER + 15
RETURN_ADDR = CALLSITE + 3
CONT_BLOCK = 0x1073
FRAME_LIN = 0x1280

CALLEE_LOOP = bytes.fromhex(
    "85 C0"                    # 0x1060 test ax,ax
    "74 0F"                    # 0x1062 jz 0x1073
    "909090909090909090909090"  # 0x1064..0x106F nops
    "E9 F1 FF"                 # 0x1070 jmp 0x1064 (selector self loop)
    "59 8B DC 2B D8 8B E3 FF E1"  # 0x1073 pop cx;mov bx,sp;sub bx,ax;mov sp,bx;jmp cx
)
CALLEE_CLOBBER = bytes.fromhex(
    "85 C0"                    # 0x1060 test ax,ax
    "74 0F"                    # 0x1062 jz 0x1073
    "E3 05"                    # 0x1064 jcxz 0x106B (cx unseeded, both edges live)
    "B8 07 00"                 # 0x1066 mov ax,7 (path-local clobber)
    "EB 08"                    # 0x1069 jmp 0x1073
    "9090909090"               # 0x106B..0x106F nops
    "E9 F1 FF"                 # 0x1070 jmp 0x1064 (selector self loop)
    "59 8B DC 2B D8 8B E3 FF E1"  # 0x1073 pop cx;mov bx,sp;sub bx,ax;mov sp,bx;jmp cx
)
CALLEE_LOOP_CX = CALLEE_LOOP.replace(b"\x2b\xd8", b"\x2b\xd9")  # sub bx,cx variant
CALLEE_CLEAN_RET = bytes.fromhex("59 C3")  # 0x1060 pop cx; ret (no pending markers)


def caller_code_8616(ax_seed: int | None, *, two_calls: bool = False) -> bytes:
    """Encode the caller body: one call, or two calls on disjoint branches.

    Two-call layout keeps each callsite reachable without crossing the
    other call — a declared-entry census refuses unproven call boundaries,
    so the second call sits on the ``jz`` edge while the first keeps the
    fall-through edge and jumps over it::

        mov ax,K ; test bx,bx ; jz +5 -> site2
        call CALLEE            (site1, returns into the jmp)
        jmp +3 -> ret
        call CALLEE            (site2, returns into ret)
        ret
    """
    head = (
        b"\x90\x90\x90"
        if ax_seed is None
        else b"\xb8" + ax_seed.to_bytes(2, "little")
    )
    first = b"\xe8" + ((CALLEE - RETURN_ADDR) & 0xFFFF).to_bytes(2, "little")
    if not two_calls:
        return head + first + b"\xc3"
    call1 = b"\xe8" + ((CALLEE - CALL2_RET_1) & 0xFFFF).to_bytes(2, "little")
    call2 = b"\xe8" + ((CALLEE - CALL2_RET_2) & 0xFFFF).to_bytes(2, "little")
    return head + b"\x85\xdb\x74\x05" + call1 + b"\xeb\x03" + call2 + b"\xc3"


def build_scoped_stack_parts_8616(
    ax_seed: int | None, callee_code: bytes, *, needs_scope: bool = True,
    two_calls: bool = False,
) -> dict[str, object]:
    """Build one declared-entry world and the chained callee domain.

    With ``needs_scope`` the retained chain is derived end to end and the
    joint control-obligation view is consumed into scoped coverage. The
    returned dict exposes every intermediate evidence object so negative
    controls can tamper with real carriers instead of fabricating passes.
    """
    apply_x86_16_bootstrap()
    caller_code = caller_code_8616(ax_seed, two_calls=two_calls)
    first_callsite = CALL2_SITE_1 if two_calls else CALLSITE
    image = bytearray(0x80)
    image[:2] = bytes.fromhex("0f0b")
    image[0x20:0x20 + len(caller_code)] = caller_code
    image[0x60:0x60 + len(callee_code)] = callee_code
    header = bytearray(32)
    header[:2] = b"MZ"
    for offset, value in ((2, 160), (4, 1), (8, 2), (10, 0x10), (12, 0x40),
                          (14, 0x10), (16, 0x100), (24, 0x1c)):
        header[offset:offset + 2] = value.to_bytes(2, "little")
    source = bytes(header + image)
    environment = replace(native._environment(), psp_segment=0xF0, allocation=bytes(0x500))
    boot = program_from_mz_bytes(source, environment, code_ranges=(
        LinearRange(CALLER, len(caller_code)), LinearRange(CALLEE, len(callee_code)),
    ))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000,
        "entry_point": 0x1000,
    }, auto_load_libs=False)

    def recompute(current: object) -> object:
        return program_from_mz_bytes(
            current.source, current.environment, code_ranges=current.image.code_ranges)

    digest = declared_environment_digest_8616(environment)
    spec = DeclaredFunctionEntrySpec8616(
        version=1, source_sha256=hashlib.sha256(source).hexdigest(),
        relocated_sha256=hashlib.sha256(module).hexdigest(), load_segment=0x100,
        entry_segment=0x100, entry_offset=0x20, range_start=CALLER,
        range_end=CALLER + len(caller_code),
        native_sha256=hashlib.sha256(caller_code).hexdigest(),
        environment_sha256=digest, use_environment_memory=False,
        registers=(("ss", 0x120), ("sp", 0x80)),
        memory=(DeclaredEntryMemory8616(FRAME_LIN, (0x70).to_bytes(2, "little")),),
        return_boundary=DeclaredEntryReturn8616(
            DeclaredEntryReturnKind8616.NEAR, 0x100, 0x70),
    )
    admission = admit_declared_function_entry_8616(
        spec, source=source, loaded_module=module, environment_sha256=digest)
    assert isinstance(admission, DeclaredFunctionEntryAdmission8616)

    caller_boundary = exact_function_range_boundary_8616(project, CALLER, CALLER + len(caller_code))
    caller_artifact = real16_native_census_import_8616(project, caller_boundary)
    index = build_boundary_direct_callsite_index_8616(
        caller_boundary,
        direct_target_resolver=partial(
            resolve_direct_call_target_from_instruction_8616, project))
    edcp.install_real16_invocation_source_8616(
        project,
        edcp.Real16InvocationSource8616(
            boot=boot, boot_recompute=recompute,
            callsite_index=index, function_entries=(admission,)),
    )
    try:
        rows_all = tuple(
            row for row in index.for_target(CALLEE)
            if row.caller_start == CALLER and not row.is_far)
        assert len(rows_all) == (2 if two_calls else 1)
        resolved = edcp._callee_artifact_and_boundary_8616(
            project, CALLEE,
            callsite=rows_all[0] if two_calls else None)
        assert resolved is not None
        callee_artifact, callee_boundary = resolved
        if not needs_scope:
            return {
                "project": project,
                "callee_artifact": callee_artifact,
                "callee_boundary": callee_boundary,
                "raw_coverage": prove_ir_boundary_coverage_8616(
                    project, callee_boundary, callee_artifact),
            }
        link_root = DeclaredFunctionEntryLink8616(admission, caller_artifact, caller_boundary)
        caller_domain = prove_real16_declared_function_entry_domain_8616(
            project, link_root, first_callsite, boot=boot, boot_recompute=recompute)
        assert caller_domain.failure is None and caller_domain.complete
        rows = rows_all
        first_row = next(
            row for row in rows if row.callsite_addr == first_callsite)
        chain = Real16CallChainLink8616(
            parent=caller_domain, callsite_index=index, callsite=first_row,
            callsite_artifact=caller_artifact, callsite_boundary=caller_boundary,
            call_state=caller_domain.callsite_call_state,
            callee_artifact=callee_artifact, callee_boundary=callee_boundary)
        callee_domain = prove_fresh_real16_chained_invocation_domain_8616(
            project, None, CALLEE, boot=boot, boot_recompute=recompute, chain=chain)
        assert callee_domain is not None and callee_domain.failure is None
        bundle = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, callee_boundary, callee_artifact)
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, callee_boundary, invocation_scope=callee_domain)
        assert view.failure is None
        consumed = consume_scoped_ir_boundary_projection_8616(
            project, callee_boundary, callee_artifact, view, callee_domain)
        assert consumed.coverage.complete_for(callee_domain)
        raw_coverage = prove_ir_boundary_coverage_8616(
            project, callee_boundary, callee_artifact)
        return {
            "project": project,
            "boot": boot,
            "recompute": recompute,
            "admission": admission,
            "caller_artifact": caller_artifact,
            "caller_boundary": caller_boundary,
            "index": index,
            "caller_domain": caller_domain,
            "link_root": link_root,
            "callsite_row": first_row,
            "callsite_rows": rows,
            "chain": chain,
            "callee_domain": callee_domain,
            "callee_artifact": callee_artifact,
            "callee_boundary": callee_boundary,
            "callee_end": CALLEE + len(callee_code),
            "view": view,
            "coverage": consumed.coverage,
            "raw_coverage": raw_coverage,
        }
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def build_scoped_stack_fixture_8616(
    ax_seed: int | None, callee_code: bytes, *, needs_scope: bool = True,
) -> tuple[object, object, object, object]:
    """Return ``(callee_scope, scoped_coverage, raw_coverage, artifact)``."""
    parts = build_scoped_stack_parts_8616(
        ax_seed, callee_code, needs_scope=needs_scope)
    if not needs_scope:
        return None, None, parts["raw_coverage"], parts["callee_artifact"]
    return (
        parts["callee_domain"],
        parts["coverage"],
        parts["raw_coverage"],
        parts["callee_artifact"],
    )


def scoped_callee_domain_for_callsite_8616(
    parts: dict[str, object], callsite_addr: int,
) -> tuple[object, object, object]:
    """Derive one callsite's parent domain, callee domain and coverage.

    Each physical callsite needs its own caller-entry-to-callsite premise:
    the parent census authenticates the register state reaching THAT exact
    edge, the chain binds that exact decoded row, and the callee body's
    scoped coverage is consumed under this edge's own domain — never
    another call's retained scope.
    """
    parent = prove_real16_declared_function_entry_domain_8616(
        parts["project"], parts["link_root"], callsite_addr,
        boot=parts["boot"], boot_recompute=parts["recompute"])
    assert parent.failure is None and parent.complete
    rows = [
        row for row in cast(tuple, parts["callsite_rows"])
        if row.callsite_addr == callsite_addr
    ]
    assert len(rows) == 1
    premise = prove_near_call_frame_premise_8616(rows[0], parts["index"], CALLEE)
    assert premise is not None
    callee_boundary = exact_function_range_boundary_8616(
        parts["project"], CALLEE, cast(int, parts["callee_end"]), premise=premise)
    assert callee_boundary is not None
    callee_artifact = real16_native_census_import_8616(
        parts["project"], callee_boundary)
    assert callee_artifact is not None
    chain = Real16CallChainLink8616(
        parent=parent, callsite_index=parts["index"], callsite=rows[0],
        callsite_artifact=parts["caller_artifact"],
        callsite_boundary=parts["caller_boundary"],
        call_state=parent.callsite_call_state,
        callee_artifact=callee_artifact,
        callee_boundary=callee_boundary)
    domain = prove_fresh_real16_chained_invocation_domain_8616(
        parts["project"], None, CALLEE, boot=parts["boot"],
        boot_recompute=parts["recompute"], chain=chain)
    assert domain is not None and domain.failure is None
    bundle = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
        parts["project"], callee_boundary, callee_artifact)
    view = vex_import.prove_scoped_control_obligations_view_8616(
        parts["project"], bundle, callee_boundary,
        invocation_scope=domain)
    assert view.failure is None
    consumed = consume_scoped_ir_boundary_projection_8616(
        parts["project"], callee_boundary, callee_artifact,
        view, domain)
    assert consumed.coverage.complete_for(domain)
    return parent, domain, consumed.coverage
