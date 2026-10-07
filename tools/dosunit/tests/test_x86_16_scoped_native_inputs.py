"""Staged red/green regression for scoped terminal-jump admission.

Layer: tests.
Responsibility: prove that a conditional callsite record — one whose
Semantics binding consumed an invocation-local premise — may be consumed
by the entry-domain jump proof only under an authenticated consuming
entry, that the conditional dependency is retained on the admission and
revalidated at application, and that context-free or foreign-entry
consumption stays refused end to end.

The fixture loads through the production DOS MZ loader (``dos_mz``
backend at linear 0x10000) with ``ProgramBoot`` as the retained source
authority. The caller surface is in-flight: its entry premise can only
exist through the genuine registered MZ-entry edge (the STUB call row),
so this is the registered-boundary native positive; deeper in-flight
bootstraps remain refused by contract.

``SCOPE_VARIANT=before`` runs the identical suite against the
parent-patched baseline to produce the red evidence.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path

import angr
import pytest
import inertia.ir.entry_domain_call_preservation as edcp
import inertia.ir.entry_jump_domain as ejd
import inertia.ir.scoped_function_ir_view as view_owner
import inertia.ir.vex_import as vi
from inertia.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from inertia.ir.ir_boundary_cfg import (
    prove_ir_boundary_coverage_8616,
)

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    build_boundary_direct_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
    mapped_entry_function_boundary_8616,
)
from inertia.lowering.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from inertia.cli.project_loading import _build_project
from tools.dosunit.runtime.real16_program_boot import (
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.runtime.real16_replay_model import LinearRange

LOAD_SEGMENT = 0x1000
PSP_SEGMENT = LOAD_SEGMENT - 0x10
BASE = LOAD_SEGMENT << 4

# Fixture C: scoped-admission positive. LEAF=BASE (mov ax,0x1234; ret) —
# its call row sits below the caller's decoded fetch window, so only the
# transported premise can bind the target and only the conditional record
# it leaves behind can carry the caller's census and surrogate view past
# that row. CALLER at BASE+0x20: `e8 dd ff` (call BASE), sixteen NOPs,
# then `e9` at BASE+0x33 targeting the `c3` island at BASE+0x140 — beyond
# the joint root/head fetch-window band [0x10020, 0x1013f] but inside the
# transported CS=0x1000 band. STUB is the MZ entry at BASE+0x160 and its
# `e8 bd fe` row is the sole registered edge into CALLER.
LEAF = BASE
LEAF_CODE = bytes.fromhex("b8 34 12 c3")
CALLER = BASE + 0x20
CALL_SITE = CALLER
JUMP_HEAD = CALLER + 0x13
JUMP_NEXT = JUMP_HEAD + 3
ISLAND = BASE + 0x140
CALLER_CODE = (
    bytes.fromhex("e8 dd ff")
    + b"\x90" * 0x10
    + b"\xe9" + (ISLAND - JUMP_NEXT).to_bytes(2, "little")
)
CALLER_END = ISLAND + 1
STUB = BASE + 0x160
STUB_CODE = (
    b"\xe8"
    + ((CALLER - (STUB + 3)) & 0xFFFF).to_bytes(2, "little")
    + b"\xc3"
)

CALL_RANGES = (
    LinearRange(LEAF, len(LEAF_CODE)),
    LinearRange(CALLER, len(CALLER_CODE)),
    LinearRange(ISLAND, 1),
    LinearRange(STUB, len(STUB_CODE)),
)


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
    stack_ss: int = 0x10,
    stack_sp: int = 0x100,
    minalloc: int = 0x10,
    maxalloc: int = 0x20,
    hdr_paras: int = 2,
) -> bytes:
    """Emit a deterministic MZ wrapper around the module image."""
    header_size = hdr_paras * 16
    exe_size = header_size + len(image)
    nblocks = (exe_size + 511) // 512
    lastsize = exe_size % 512
    reloc_pos = 0x1C
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = nblocks.to_bytes(2, "little")
    header[0x06:0x08] = (0).to_bytes(2, "little")
    header[0x08:0x0A] = hdr_paras.to_bytes(2, "little")
    header[0x0A:0x0C] = minalloc.to_bytes(2, "little")
    header[0x0C:0x0E] = maxalloc.to_bytes(2, "little")
    header[0x0E:0x10] = stack_ss.to_bytes(2, "little")
    header[0x10:0x12] = stack_sp.to_bytes(2, "little")
    header[0x12:0x14] = (0).to_bytes(2, "little")
    header[0x14:0x16] = entry_ip.to_bytes(2, "little")
    header[0x16:0x18] = (0).to_bytes(2, "little")
    header[0x18:0x1A] = reloc_pos.to_bytes(2, "little")
    return bytes(header) + image


def _build_environment(allocation_size: int = 0x400) -> ProgramEnvironment:
    """Return the declared loader environment for the fixture."""
    return ProgramEnvironment(
        psp_segment=PSP_SEGMENT,
        allocation=bytes(allocation_size),
        registers=tuple(
            (name, 0)
            for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                "eflags",
            )
        ),
        fs=0,
        gs=0,
    )


def _make_boot(
    image: bytes, entry_ip: int, code_ranges: tuple[LinearRange, ...],
) -> tuple[object, bytes]:
    """Build the authentic ProgramBoot for one MZ fixture."""
    mz = _build_mz(image, entry_ip=entry_ip)
    boot = program_from_mz_bytes(
        mz, _build_environment(), code_ranges=code_ranges
    )
    return boot, mz


def _boot_recompute(boot: object) -> object:
    """Recompute an equal boot object from the retained source bytes."""
    return program_from_mz_bytes(
        boot.source, boot.environment, code_ranges=boot.image.code_ranges
    )


def _make_project(mz: bytes, tmp_path: Path) -> angr.Project:
    """Load the retained MZ bytes through the production DOS MZ loader."""
    fixture = tmp_path / "fixture.exe"
    fixture.write_bytes(mz)
    project = _build_project(
        fixture, force_blob=False, base_addr=BASE, entry_point=STUB
    )
    assert isinstance(project, angr.Project)
    return project


def _assert_loader_bytes(
    project: angr.Project, boot: object,
    code_ranges: tuple[LinearRange, ...],
) -> None:
    """Independently verify loaded bytes equal the boot's relocated image."""
    (chunk_addr, chunk), *rest = boot.image.chunks
    assert not rest
    assert chunk_addr == BASE
    for region in code_ranges:
        start = region.address
        loaded = bytes(project.loader.memory.load(start, region.size))
        expected = chunk[start - chunk_addr:start - chunk_addr + region.size]
        assert loaded == expected, (
            f"loader bytes diverge at {start:#x}: "
            f"{loaded.hex()} != {expected.hex()}"
        )


def _boundary(project: angr.Project, head: int, end: int) -> object:
    """Resolve one exact decoded boundary or fail the fixture loudly."""
    boundary = exact_function_range_boundary_8616(project, head, end)
    assert boundary is not None
    return boundary


def _resolver(project: angr.Project) -> object:
    """Return the shared decoded direct-target resolver for one project."""
    return partial(resolve_direct_call_target_from_instruction_8616, project)


@pytest.fixture()
def world(tmp_path: Path) -> object:
    """Build the scoped-admission MZ fixture (project, boot, parent, caller)."""
    image = _build_image(
        (
            (LEAF, LEAF_CODE),
            (CALLER, CALLER_CODE),
            (ISLAND, b"\xc3"),
            (STUB, STUB_CODE),
        )
    )
    boot, mz = _make_boot(image, STUB - BASE, CALL_RANGES)
    project = _make_project(mz, tmp_path)
    _assert_loader_bytes(project, boot, CALL_RANGES)
    stub_boundary = _boundary(project, STUB, STUB + len(STUB_CODE))
    stub_artifact = vi.build_x86_16_ir_function_artifact(
        project, stub_boundary
    )
    publish_function_ir_artifact_8616(project, stub_artifact)
    stub_coverage = prove_ir_boundary_coverage_8616(
        project, stub_boundary, stub_artifact
    )
    assert stub_coverage.complete
    stub_index = build_boundary_direct_callsite_index_8616(
        stub_boundary, direct_target_resolver=_resolver(project)
    )
    # The caller surface uses the mapped-entry owner — the same boundary
    # authority the on-demand callee re-import resolves — so the retained
    # decoded index census stays coherent across the nested import.
    caller_boundary = mapped_entry_function_boundary_8616(project, CALLER)
    assert caller_boundary is not None
    caller_artifact = vi.build_x86_16_ir_function_artifact(
        project, caller_boundary
    )
    try:
        yield (
            boot, project, stub_boundary, stub_artifact, stub_index,
            caller_boundary, caller_artifact,
        )
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def _install(project: angr.Project, boot: object, index: object) -> None:
    """Install the typed invocation source for chained premises."""
    edcp.install_real16_invocation_source_8616(
        project,
        edcp.Real16InvocationSource8616(
            boot=boot,
            boot_recompute=_boot_recompute,
            callsite_index=index,
        ),
    )


def _premise(
    project: angr.Project,
    artifact: object,
    boundary: object,
    callsite_addr: int,
    records: tuple = (),
) -> object | None:
    """Resolve the chained premise for one exact caller row."""
    return edcp.entry_domain_invocation_premise_8616(
        project, artifact, boundary, callsite_addr, records
    )


def _records(project: angr.Project, artifact: object, boundary: object) -> tuple:
    """Collect the caller's per-callsite preservation records."""
    return edcp.collect_entry_domain_call_preservations_8616(
        project, artifact, boundary,
        direct_target_resolver=_resolver(project),
    )










def _pending_evidence(project: angr.Project, artifact: object) -> dict:
    """Produce the importer's exact pending-jump evidence for the fixture.

    The evidence is re-derived through the staged importer's own
    ``_block_to_ir`` boundary on the identical jump head the artifact
    carries — never fabricated — so the retained decoded edge is the
    same object the import path would consult.
    """
    evidence: dict = {}
    for block in artifact.blocks:
        size = max(
            (instr.addr - block.addr + 3) for instr in block.instrs
        )
        native = project.factory.block(
            block.addr, size=size, opt_level=0, collect_data_refs=True
        )
        _ir_block, _transport, terminal = vi._block_to_ir(native)
        if terminal is not None:
            evidence[block.addr] = terminal
    return evidence









def _view(world: tuple) -> tuple:
    """Derive the consuming entry independently before constructing the view."""
    boot, project, _sb, _sa, index, boundary, artifact = world
    _install(project, boot, index)
    records = _records(project, artifact, boundary)
    offered = _premise(project, artifact, boundary, JUMP_HEAD, records)
    assert offered is not None and offered.complete
    proof = ejd.prove_entry_jump_domains_8616(
        artifact, _pending_evidence(project, artifact), project=project,
        call_preservations=records,
        invocation_resolver=partial(
            edcp.entry_domain_invocation_premise_8616, project, artifact,
            boundary, entry_call_preservations=records,
        ),
    )
    assert len(proof.admitted) == 1
    view = view_owner.prove_scoped_function_ir_view_8616(
        artifact, boundary, proof, invocation_scope=offered,
    )
    return view, offered, artifact
