"""Invocation-local edge feasibility on authentic-byte fixtures.

A proven-infeasible conditional edge — established by the converged
known-bits must-state of the exact invocation prefix — may drop the dead
tail's CALL/effect obligations from the instruction-level census. The
fixture encodes the observed bound prefix shape: ``mov ah,30h; int 21h;
add sp,imm16; sti; jcc target; <dead: call>; <live: callsite call>``.
Positive runs complete only because the dead branch's unprovable call is
never obligated; every corruption keeps the edge (and its refusal) or
produces a different reachable branch. ``infeasible_edges`` is typed
per-edge evidence on the proof record — never a universal dead-code
claim. Every address below is computed from the fixture's own layout.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import angr
import archinfo
import pyvex
import inertia.ir.entry_domain_call_preservation as edcp
from inertia.ir.real16_invocation_domain import (
    Real16InvocationFailure8616,
    Real16InvocationRefusalSite8616,
    prove_real16_invocation_domain_8616,
)
from inertia.ir.vex_import import (
    build_x86_16_ir_function_artifact,
)

from inertia.frontend.x86_16.frontend_function_boundary import (
    mapped_entry_function_boundary_8616,
)
from inertia.frontend.x86_16.mz_static_boot import (
    mz_static_boot_8616,
    recompute_mz_static_boot_8616,
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

INT21_ADDR = BASE + 0x02
PENDING = BASE + 0x300
DEADCALLEE = BASE + 0x380


def _build_image(islands: tuple[tuple[int, bytes], ...]) -> bytes:
    """Lay out code islands inside one loaded module image."""
    image = b""
    cursor = BASE
    for address, code in islands:
        assert address >= cursor
        image += bytes(address - cursor) + code
        cursor = address + len(code)
    return image


def _build_mz(
    image: bytes,
    *,
    entry_ip: int,
    stack_sp: int = 0x100,
    maxalloc: int = 0x20,
) -> bytes:
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
    header[0x0C:0x0E] = maxalloc.to_bytes(2, "little")
    header[0x0E:0x10] = (0x10).to_bytes(2, "little")
    header[0x10:0x12] = stack_sp.to_bytes(2, "little")
    header[0x14:0x16] = entry_ip.to_bytes(2, "little")
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    return bytes(header) + image


def _near_call(callsite: int, target: int) -> bytes:
    """Encode one real near CALL rel16 targeting ``target``."""
    return (
        b"\xe8" + ((target - (callsite + 3)) & 0xFFFF).to_bytes(2, "little")
    )


def _bound_mz(
    *,
    add_encoding: bytes = b"\x81\xc4\xae\x0b",
    jcc_op: int = 0x73,
    clobber: bytes = b"",
    indirect_live: bool = False,
    stack_sp: int = 0x100,
    maxalloc: int = 0x20,
) -> tuple[bytes, dict[str, int]]:
    """Entry: declared INT21, bound ``add sp``, guard, dead+live branches.

    The returned layout names every derived address so mutations that
    shift instruction boundaries stay honest — no hard-coded targets.
    """
    jcc = BASE + 4 + len(add_encoding) + 1 + len(clobber)
    dead = jcc + 2
    taken = dead + 3  # dead tail: near call (3) falling through to merge
    if indirect_live:
        taken_tail = (
            b"\xff\x16\x00\x02"  # call word ptr [0x0200]
            + _near_call(taken + 4, PENDING)
            + b"\xc3"
        )
        callsite = taken + 4
    else:
        taken_tail = _near_call(taken, PENDING) + b"\xc3"
        callsite = taken
    entry_code = (
        b"\xb4\x30\xcd\x21"
        + add_encoding
        + b"\xfb"
        + clobber
        + bytes((jcc_op, taken - (jcc + 2)))
        + _near_call(dead, DEADCALLEE)
        + taken_tail
    )
    image = _build_image(
        (
            (BASE, entry_code),
            (PENDING, bytes.fromhex("59 ff e1")),
            (DEADCALLEE, b"\xc3"),
        )
    )
    layout = {
        "jcc_block": BASE + 4,
        "jcc": jcc,
        "dead": dead,
        "taken": taken,
        "callsite": callsite,
    }
    return _build_mz(
        image, entry_ip=0, stack_sp=stack_sp, maxalloc=maxalloc
    ), layout


def _ivt() -> bytes:
    """Live IVT page whose 0x21 slot points at the declared DOS entry."""
    table = bytearray(0x400)
    table[0x84:0x88] = vector_bytes(DOS_ENTRY)
    return bytes(table)


def _env(mz: bytes, *, stack_sp: int = 0x100) -> ProgramEnvironment:
    """A declared environment sized to the fixture's header grant."""
    image_len = len(mz) - 0x20
    module_paragraphs = (image_len + 15) // 16
    stack_top = (PSP + 0x10 + 0x10) * 16 + stack_sp
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


def _declared(mz: bytes, *, stack_sp: int = 0x100) -> tuple[object, object]:
    """Declared boot plus the exact INT21/AH30 relation for this entry."""
    env = _env(mz, stack_sp=stack_sp)
    boot = program_from_mz_bytes(mz, env)
    relation = declared_int21_version_service_8616(
        env, caller_addr=BASE, callsite_addr=INT21_ADDR
    )
    assert type(relation).__name__ == "DeclaredInterruptService8616"
    return boot, relation


def _prove(
    mz: bytes,
    tmp_path: Path,
    callsite: int,
    *,
    declared: bool = True,
    stack_sp: int = 0x100,
    coverage: object | None = None,
) -> object:
    """Prove the entry domain at the live-branch callsite."""
    project = _make_project(mz, tmp_path)
    if coverage is None:
        coverage = _coverage(project, BASE)
    if declared:
        boot, relation = _declared(mz, stack_sp=stack_sp)
        return prove_real16_invocation_domain_8616(
            project,
            coverage,
            callsite,
            boot=boot,
            boot_recompute=_boot_recompute,
            declared_services=(relation,),
        )
    boot = mz_static_boot_8616(mz, LOAD_SEGMENT)
    return prove_real16_invocation_domain_8616(
        project,
        coverage,
        callsite,
        boot=boot,
        boot_recompute=recompute_mz_static_boot_8616,
    )


def test_bound_prefix_prunes_dead_call_edge(tmp_path: Path) -> None:
    """The authentic bound prefix skips only the proven-dead call branch."""
    mz, layout = _bound_mz()
    leg = _prove(mz, tmp_path, layout["callsite"])
    assert leg.complete
    assert leg.failure is None
    assert leg.refusal_site is None
    # Exactly one proven-dead edge: the guard block's error-branch edge.
    assert leg.infeasible_edges == ((layout["jcc_block"], layout["dead"]),)
    assert layout["dead"] not in leg.path_block_addrs
    assert leg.failure_count == 0


def test_add_immediate_carry_keeps_edge(tmp_path: Path) -> None:
    """A mutated ADD immediate producing carry keeps the dead branch live."""
    mz, layout = _bound_mz(add_encoding=b"\x81\xc4\x00\xff")
    leg = _prove(mz, tmp_path, layout["callsite"])
    assert not leg.complete
    assert leg.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    site = leg.refusal_site
    assert type(site) is Real16InvocationRefusalSite8616
    assert site.instruction_addr == layout["dead"]


def test_header_sp_carry_keeps_edge(tmp_path: Path) -> None:
    """A header SP that carries on the bound ADD keeps the dead call live."""
    mz, layout = _bound_mz(stack_sp=0xF500, maxalloc=0xFFFF)
    leg = _prove(mz, tmp_path, layout["callsite"], stack_sp=0xF500)
    assert not leg.complete
    assert leg.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    assert type(leg.refusal_site) is Real16InvocationRefusalSite8616
    assert leg.refusal_site.instruction_addr == layout["dead"]


def test_add_width_mutation_keeps_edge(tmp_path: Path) -> None:
    """A sign-extended byte-width ADD producing carry keeps the edge live."""
    mz, layout = _bound_mz(add_encoding=b"\x83\xc4\xff")
    leg = _prove(mz, tmp_path, layout["callsite"])
    assert not leg.complete
    assert leg.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    assert type(leg.refusal_site) is Real16InvocationRefusalSite8616
    assert leg.refusal_site.instruction_addr == layout["dead"]


def test_inverted_branch_still_reaches_dead_call(tmp_path: Path) -> None:
    """An inverted guard reaches the error branch: different live edge."""
    mz, layout = _bound_mz(jcc_op=0x72)
    leg = _prove(mz, tmp_path, layout["callsite"])
    assert not leg.complete
    assert leg.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    site = leg.refusal_site
    assert type(site) is Real16InvocationRefusalSite8616
    assert site.instruction_addr == layout["dead"]
    # The *other* edge is the proven-dead one here — pruning published
    # exactly the inverted verdict, never an escape for the live call.
    assert leg.infeasible_edges == ((layout["jcc_block"], layout["taken"]),)


def test_unproved_flag_clobber_keeps_edge(tmp_path: Path) -> None:
    """POPF between the bound ADD and the guard leaves flags unproven."""
    mz, layout = _bound_mz(clobber=b"\x9d")
    leg = _prove(mz, tmp_path, layout["callsite"])
    assert not leg.complete
    assert leg.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    site = leg.refusal_site
    assert type(site) is Real16InvocationRefusalSite8616
    assert site.instruction_addr == layout["dead"]
    assert leg.infeasible_edges == ()


def test_missing_boot_refuses(tmp_path: Path) -> None:
    """No boot authority: no feasibility claim and no domain."""
    mz, layout = _bound_mz()
    project = _make_project(mz, tmp_path)
    coverage = _coverage(project, BASE)
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        layout["callsite"],
        boot=None,
        boot_recompute=None,
    )
    assert not leg.complete
    assert leg.failure is not None
    assert leg.infeasible_edges == ()


def test_foreign_boot_refuses(tmp_path: Path) -> None:
    """A boot minted for different bytes cannot authenticate this image."""
    mz, layout = _bound_mz()
    other, _ = _bound_mz(add_encoding=b"\x81\xc4\x00\xff")
    project = _make_project(mz, tmp_path)
    coverage = _coverage(project, BASE)
    env = _env(other)
    foreign = program_from_mz_bytes(other, env)
    relation = declared_int21_version_service_8616(
        env, caller_addr=BASE, callsite_addr=INT21_ADDR
    )
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        layout["callsite"],
        boot=foreign,
        boot_recompute=_boot_recompute,
        declared_services=(relation,),
    )
    assert not leg.complete
    assert leg.failure is not None


def test_missing_service_authority_refuses(tmp_path: Path) -> None:
    """Without the declared AH30 relation the crossing refuses first."""
    mz, layout = _bound_mz()
    project = _make_project(mz, tmp_path)
    coverage = _coverage(project, BASE)
    env = _env(mz)
    boot = program_from_mz_bytes(mz, env)
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        layout["callsite"],
        boot=boot,
        boot_recompute=_boot_recompute,
        declared_services=(),
    )
    assert not leg.complete
    # The census crosses the actual INT21 row and refuses there — a
    # typed call-boundary refusal at the exact instruction, not a
    # guessed service-level failure kind.
    assert leg.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    assert type(leg.refusal_site) is Real16InvocationRefusalSite8616
    assert leg.refusal_site.instruction_addr == INT21_ADDR
    assert leg.infeasible_edges == ()


def test_forged_ir_condition_refuses(tmp_path: Path) -> None:
    """A forged CJMP condition cannot mint a skip: the edge stays live."""
    mz, layout = _bound_mz()
    project = _make_project(mz, tmp_path)
    coverage = _coverage(project, BASE)
    artifact = coverage.artifact  # type: ignore[attr-defined]
    forged_blocks = []
    for block in artifact.blocks:
        instrs = []
        for instr in block.instrs:
            if instr.op == "CJMP" and instr.addr == layout["jcc"]:
                cond = instr.args[0]
                # Point the truth test at a temporary the block never
                # produced — the lattice cannot prove it, so no edge may
                # be pruned and the dead call's obligation remains.
                forged_arg = dataclasses.replace(
                    cond.args[0], source_tmp=2**30
                )
                instr = dataclasses.replace(
                    instr,
                    args=(dataclasses.replace(cond, args=(forged_arg,)), instr.args[1]),
                )
            instrs.append(instr)
        forged_blocks.append(dataclasses.replace(block, instrs=tuple(instrs)))
    forged = dataclasses.replace(artifact, blocks=tuple(forged_blocks))
    forged_coverage = dataclasses.replace(coverage, artifact=forged)
    leg = _prove(
        mz, tmp_path, layout["callsite"], coverage=forged_coverage
    )
    assert not leg.complete
    assert leg.failure is not None
    assert leg.infeasible_edges == ()


def test_reachable_indirect_call_still_refuses(tmp_path: Path) -> None:
    """A reachable memory-indirect call on the live edge stays refused."""
    mz, layout = _bound_mz(indirect_live=True)
    leg = _prove(mz, tmp_path, layout["callsite"])
    assert not leg.complete
    assert leg.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    site = leg.refusal_site
    assert type(site) is Real16InvocationRefusalSite8616
    assert site.instruction_addr == layout["taken"]
    # The dead branch still prunes: only the proven-dead edge is excluded.
    assert leg.infeasible_edges == ((layout["jcc_block"], layout["dead"]),)


def test_to_dict_serializes_infeasible_edges(tmp_path: Path) -> None:
    """The typed per-edge verdict survives receipt serialization."""
    mz, layout = _bound_mz()
    leg = _prove(mz, tmp_path, layout["callsite"])
    receipt = leg.to_dict()
    assert receipt["infeasible_edges"] == [[layout["jcc_block"], layout["dead"]]]
    assert layout["dead"] not in receipt["path_block_addrs"]


_TYPE_ENV_I1 = pyvex.IRTypeEnv(archinfo.ArchX86(), types=["Ity_I1"] * 8)


def _converted(expr: object, tmps: dict[int, object]) -> object:
    """Run a real VEX expression through the production converter."""
    from inertia.ir.vex_import import _expr_to_value

    return _expr_to_value(
        expr, tmps, {}, type_environment=_TYPE_ENV_I1
    )


def test_active_not1_on_capture_applies_typed_evidence() -> None:
    """``Not1(RdTmp7)`` carries authoritative ``active_unary`` evidence —
    the NOT is applied to the captured operand, never silently dropped.

    tmp7 is proven ``1``, so the real inverted result is ``0``: the
    evaluator proves ``eq(result, 0)`` at the evidence's own 1-bit width
    and disproves ``eq(result, 1)``. A provenance-skip (the old bug)
    would have proven ``1`` instead.
    """
    import inertia.ir.real16_edge_feasibility8616 as edge
    from inertia.ir.core import IRCondition, IRValue, MemSpace

    value = _converted(
        pyvex.expr.Unop("Iop_Not1", [pyvex.expr.RdTmp(7)]),
        {7: IRValue(MemSpace.TMP, size=1, source_tmp=7)},
    )
    assert value.active_unary is not None
    assert value.active_unary.op == "Iop_Not1"
    assert value.active_unary.result_bits == 1
    # A capture pin must not leak onto the operation result.
    assert value.source_tmp is None
    zero = IRValue(MemSpace.CONST, const=0, size=1)
    one = IRValue(MemSpace.CONST, const=1, size=1)
    assert (
        edge._kb_eval_condition_8616(
            IRCondition("eq", (value, zero), width_bits=1),
            {},
            {7: (1, 1)},
        )
        is True
    )
    assert (
        edge._kb_eval_condition_8616(
            IRCondition("eq", (value, one), width_bits=1),
            {},
            {7: (1, 1)},
        )
        is False
    )


def test_captured_not_result_read_back_never_double_inverts() -> None:
    """A pinned view names the already-computed tmp result: its ``expr``
    tag is producer provenance, never an active re-application."""
    import inertia.ir.real16_edge_feasibility8616 as edge
    from inertia.ir.core import IRCondition, IRValue, MemSpace

    # tmp7's producer row was a Not1 write; the read-back view carries
    # that tag as provenance only — no active_unary evidence.
    value = _converted(
        pyvex.expr.RdTmp(7),
        {7: IRValue(MemSpace.TMP, size=1, source_tmp=7, expr=("Iop_Not1",))},
    )
    assert value.active_unary is None
    condition = IRCondition("nonzero", (value,), width_bits=8)
    # tmps[7] = known-1: the stored result reads back as proven nonzero;
    # double inversion would wrongly claim unknown/false.
    verdict = edge._kb_eval_condition_8616(condition, {}, {7: (1, 1)})
    assert verdict is True
