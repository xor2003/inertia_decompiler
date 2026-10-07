"""Typed refusal-site evidence on the invocation-domain proof result.

When the instruction-level census classifies a row and refuses it, the
public ``Real16InvocationDomain8616`` must name the exact site —
censused function head, IR block, and instruction address — so callers
can see *which* row failed instead of re-running a full traversal.
Structural, binding, and budget refusals that never classify a row keep
``refusal_site=None``, and a nested parent replay that fails at a real
row propagates that row's site rather than the consuming callsite.
Authentic-byte fixtures only; every number below is the fixture's own
decoded layout.
"""

from __future__ import annotations

import dataclasses
from functools import partial
from pathlib import Path

import angr
import inertia.ir.entry_domain_call_preservation as edcp
from inertia.ir.real16_invocation_domain import (
    Real16CallChainLink8616,
    Real16InvocationFailure8616,
    Real16InvocationRefusalSite8616,
    prove_real16_chained_invocation_domain_8616,
    prove_real16_invocation_domain_8616,
)
from inertia.ir.vex_import import (
    build_x86_16_ir_function_artifact,
)

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    build_boundary_direct_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    mapped_entry_function_boundary_8616,
)
from inertia.frontend.x86_16.mz_static_boot import (
    mz_static_boot_8616,
    recompute_mz_static_boot_8616,
)
from inertia.lowering.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from inertia.cli.project_loading import _build_project
from tools.dosunit.runtime.real16_declared_invocation8616 import (
    declared_int21_version_service_8616,
)
from tools.dosunit.runtime.real16_program_boot import (
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.runtime.real16_program_memory import InitialMemoryRegion
from tools.dosunit.runtime.real16_program_vectors import VectorPolicy, vector_bytes
from tools.dosunit.runtime.real16_program_version import VersionPolicy
from tools.dosunit.runtime.real16_replay_model import SegOffset

LOAD_SEGMENT = 0x1000
BASE = LOAD_SEGMENT << 4
PSP = LOAD_SEGMENT - 0x10
DOS_ENTRY = SegOffset(0xF000, 0xF100)

INT21_ADDR = BASE + 2  # mov ah,0x30 (2 bytes) then int 21h (2 bytes)
CALL_AFTER_INT = BASE + 4
CALL_BAD = BASE + 3  # mov ax,1 (3 bytes) then an unproven near call
CALL_AFTER_BAD = BASE + 6
PENDING = BASE + 0x300
LEAF = BASE + 0x400
PENDING_CODE = bytes.fromhex("59 ff e1")  # pop cx; jmp cx


def _build_image(islands: tuple[tuple[int, bytes], ...]) -> bytes:
    """Lay out code islands inside one loaded module image."""
    image = b""
    cursor = BASE
    for address, code in islands:
        assert address >= cursor
        image += bytes(address - cursor) + code
        cursor = address + len(code)
    return image


def _build_mz(image: bytes, *, entry_ip: int) -> bytes:
    """Emit a deterministic MZ wrapper around the module image."""
    header_size = 2 * 16
    exe_size = header_size + len(image)
    nblocks = (exe_size + 511) // 512
    lastsize = exe_size % 512
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = nblocks.to_bytes(2, "little")
    header[0x08:0x0A] = (2).to_bytes(2, "little")
    header[0x0A:0x0C] = (0x10).to_bytes(2, "little")
    header[0x0C:0x0E] = (0x20).to_bytes(2, "little")
    header[0x0E:0x10] = (0x10).to_bytes(2, "little")
    header[0x10:0x12] = (0x100).to_bytes(2, "little")
    header[0x14:0x16] = entry_ip.to_bytes(2, "little")
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    return bytes(header) + image


def _near_call(callsite: int, target: int) -> bytes:
    """Encode one real near CALL rel16 targeting ``target``."""
    return (
        b"\xe8" + ((target - (callsite + 3)) & 0xFFFF).to_bytes(2, "little")
    )


def _interrupt_mz() -> bytes:
    """Entry does ``mov ah,30h; int 21h; call PENDING; ret``."""
    entry_code = (
        b"\xb4\x30\xcd\x21" + _near_call(CALL_AFTER_INT, PENDING) + b"\xc3"
    )
    image = _build_image(((BASE, entry_code), (PENDING, PENDING_CODE)))
    return _build_mz(image, entry_ip=0)


def _badcall_mz() -> bytes:
    """Entry does ``mov ax,1; call LEAF; call PENDING; ret``."""
    entry_code = (
        b"\xb8\x01\x00"
        + _near_call(CALL_BAD, LEAF)
        + _near_call(CALL_AFTER_BAD, PENDING)
        + b"\xc3"
    )
    image = _build_image(
        ((BASE, entry_code), (PENDING, PENDING_CODE), (LEAF, b"\xc3"))
    )
    return _build_mz(image, entry_ip=0)


def _ivt() -> bytes:
    """Live IVT page whose 0x21 slot points at the declared DOS entry."""
    table = bytearray(0x400)
    table[0x84:0x88] = vector_bytes(DOS_ENTRY)
    return bytes(table)


def _env(mz: bytes) -> ProgramEnvironment:
    """A declared environment sized to the fixture's header grant."""
    image_len = len(mz) - 0x20
    module_paragraphs = (image_len + 15) // 16
    stack_top = (PSP + 0x10 + 0x10) * 16 + 0x100
    arena_paragraphs = max(
        0x10 + module_paragraphs + 0x10,
        (stack_top - PSP * 16 + 15) // 16,
    )
    alloc = arena_paragraphs * 16
    return ProgramEnvironment(
        psp_segment=PSP,
        allocation=bytes(alloc),
        registers=tuple(
            (name, 0)
            for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
                "esp", "eflags",
            )
        ),
        fs=0,
        gs=0,
        version_policy=VersionPolicy(major=5, minor=0, oem=0, serial=0),
        vector_policy=VectorPolicy(DOS_ENTRY),
        extra_memory=(InitialMemoryRegion(SegOffset(0, 0), _ivt()),),
    )


def _boot_recompute(boot: object) -> object:
    """Recompute authority mirroring the declared boot's construction."""
    image = boot.image  # type: ignore[attr-defined]
    ranges = () if image.code_scope == "whole_image" else image.code_ranges
    return program_from_mz_bytes(
        boot.source, boot.environment, code_ranges=ranges  # type: ignore[attr-defined]
    )


def _make_project(mz: bytes, tmp_path: Path) -> angr.Project:
    """Load the retained MZ bytes through the production DOS MZ loader."""
    fixture = tmp_path / "fixture.exe"
    fixture.write_bytes(mz)
    project = _build_project(
        fixture, force_blob=False, base_addr=BASE, entry_point=BASE
    )
    assert isinstance(project, angr.Project)
    return project


def _coverage(project: angr.Project, head: int) -> object:
    """Import, publish, and prove coverage for one closed head surface."""
    boundary = mapped_entry_function_boundary_8616(project, head)
    assert boundary is not None and boundary.addr == head
    raw = build_x86_16_ir_function_artifact(project, boundary)
    assert not raw.refusals
    publication = edcp.publish_function_ir_artifact_8616(project, raw)
    assert publication.artifact is not None
    coverage = edcp.prove_ir_boundary_coverage_8616(
        project, boundary, publication.artifact
    )
    assert coverage.complete
    return coverage


def test_interrupt_refusal_reports_exact_row(tmp_path: Path) -> None:
    """The bare static INT21 refusal names the exact instruction site."""
    mz = _interrupt_mz()
    project = _make_project(mz, tmp_path)
    coverage = _coverage(project, BASE)
    boot = mz_static_boot_8616(mz, LOAD_SEGMENT)
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        CALL_AFTER_INT,
        boot=boot,
        boot_recompute=recompute_mz_static_boot_8616,
    )
    assert not leg.complete
    # Static boot proves AH but no AL seed exists: declared-service
    # refusal exactly at the int 21h row — not a guessed callsite.
    assert leg.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    site = leg.refusal_site
    assert type(site) is Real16InvocationRefusalSite8616
    assert site.function_addr == BASE
    assert site.instruction_addr == INT21_ADDR
    assert site.block_addr == BASE
    assert leg.failure_count == 1


def test_unproven_call_reports_exact_row(tmp_path: Path) -> None:
    """An interior near call with no bound proof names its own row."""
    mz = _badcall_mz()
    project = _make_project(mz, tmp_path)
    coverage = _coverage(project, BASE)
    boot = mz_static_boot_8616(mz, LOAD_SEGMENT)
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        CALL_AFTER_BAD,
        boot=boot,
        boot_recompute=recompute_mz_static_boot_8616,
    )
    assert not leg.complete
    assert leg.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    site = leg.refusal_site
    assert type(site) is Real16InvocationRefusalSite8616
    assert site.function_addr == BASE
    assert site.instruction_addr == CALL_BAD


def test_declared_success_keeps_site_none(tmp_path: Path) -> None:
    """A domain that completes under declared evidence has no site."""
    mz = _interrupt_mz()
    project = _make_project(mz, tmp_path)
    coverage = _coverage(project, BASE)
    env = _env(mz)
    boot = program_from_mz_bytes(mz, env)
    relation = declared_int21_version_service_8616(
        env, caller_addr=BASE, callsite_addr=INT21_ADDR
    )
    assert type(relation).__name__ == "DeclaredInterruptService8616"
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        CALL_AFTER_INT,
        boot=boot,
        boot_recompute=_boot_recompute,
        declared_services=(relation,),
    )
    assert leg.complete
    assert leg.failure is None
    assert leg.refusal_site is None
    assert leg.failure_count == 0


def test_pre_census_refusal_keeps_site_none(tmp_path: Path) -> None:
    """A structural refusal before any row keeps ``refusal_site=None``."""
    mz = _interrupt_mz()
    project = _make_project(mz, tmp_path)
    coverage = _coverage(project, BASE)
    boot = mz_static_boot_8616(mz, LOAD_SEGMENT)
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        BASE + 0x321,  # inside the surface but not a call row
        boot=boot,
        boot_recompute=recompute_mz_static_boot_8616,
    )
    assert not leg.complete
    assert leg.failure is Real16InvocationFailure8616.CALLSITE_UNREACHABLE
    assert leg.refusal_site is None
    assert leg.failure_count == 0


def test_nested_parent_failure_keeps_row_site(tmp_path: Path) -> None:
    """A chained replay surfaces the *parent's* real failing row.

    The declared parent premise completes first. A link retained over a
    forged copy of that record — a ``dataclasses.replace`` relation with
    a corrupted answer lane — makes the edge replay refuse the parent
    census at the exact ``int 21h`` instruction, and the outer
    ``chain_link_unproven`` refusal must carry the parent's row site —
    never the callee's callsite.
    """
    mz = _interrupt_mz()
    project = _make_project(mz, tmp_path)
    coverage = _coverage(project, BASE)
    env = _env(mz)
    boot = program_from_mz_bytes(mz, env)
    relation = declared_int21_version_service_8616(
        env, caller_addr=BASE, callsite_addr=INT21_ADDR
    )
    assert type(relation).__name__ == "DeclaredInterruptService8616"
    parent = prove_real16_invocation_domain_8616(
        project,
        coverage,
        CALL_AFTER_INT,
        boot=boot,
        boot_recompute=_boot_recompute,
        declared_services=(relation,),
    )
    assert parent.complete
    # Build the retained link by hand over the exact census objects:
    # the closed decoded index for the caller boundary, the exact row
    # the parent's census transported across, the parent's captured
    # call-row state, and the resolved callee pair. The retained parent
    # is a forged-field copy: its replayed census must refuse at the
    # declared interrupt row it originally consumed.
    boundary = mapped_entry_function_boundary_8616(project, BASE)
    index = build_boundary_direct_callsite_index_8616(
        boundary,
        direct_target_resolver=partial(
            resolve_direct_call_target_from_instruction_8616, project
        ),
    )
    rows = index.for_target(PENDING)
    row = next(
        entry
        for entry in rows
        if entry.caller_start == BASE and entry.callsite_addr == CALL_AFTER_INT
    )
    callee = edcp._callee_artifact_and_boundary_8616(project, PENDING)
    assert callee is not None
    callee_artifact, callee_boundary = callee
    forged_parent = dataclasses.replace(
        parent,
        declared_services=(
            dataclasses.replace(relation, answer_ax=0xBEEF),
        ),
    )
    link = Real16CallChainLink8616(
        parent=forged_parent,
        callsite_index=index,
        callsite=row,
        callsite_artifact=parent.coverage.artifact,
        callsite_boundary=parent.coverage.boundary,
        call_state=parent.callsite_call_state,
        callee_artifact=callee_artifact,
        callee_boundary=callee_boundary,
    )
    chained = prove_real16_chained_invocation_domain_8616(
        project,
        None,
        PENDING,
        boot=boot,
        boot_recompute=_boot_recompute,
        chain=link,
        declared_services=(relation,),
    )
    assert not chained.complete
    assert chained.failure is Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    site = chained.refusal_site
    assert type(site) is Real16InvocationRefusalSite8616
    assert site.function_addr == BASE
    assert site.instruction_addr == INT21_ADDR


def test_to_dict_serializes_site(tmp_path: Path) -> None:
    """The typed site survives receipt serialization as plain ints."""
    mz = _interrupt_mz()
    project = _make_project(mz, tmp_path)
    coverage = _coverage(project, BASE)
    boot = mz_static_boot_8616(mz, LOAD_SEGMENT)
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        CALL_AFTER_INT,
        boot=boot,
        boot_recompute=recompute_mz_static_boot_8616,
    )
    receipt = leg.to_dict()
    assert receipt["refusal_site"] == {
        "function_addr": BASE,
        "block_addr": BASE,
        "instruction_addr": INT21_ADDR,
    }
