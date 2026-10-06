"""Source-bound static-MZ invocation intake controls.

These tests exercise the header-only intake route: ``_build_project`` (or the
intake owner directly) installs a ``Real16InvocationSource8616`` whose boot
is a ``MzStaticBoot8616`` projected from the retained MZ bytes and the
loader's declared load paragraph — no environment is invented. The
domain owner seeds only CS/SS/SP; every other register stays unknown and
effects depending on unknown state must refuse.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path

import angr
import pytest
from angr_platforms.X86_16.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from angr_platforms.X86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
    mapped_entry_function_boundary_8616,
)
from angr_platforms.X86_16.frontend_invocation_inventory import (
    InvocationInventoryBudget8616,
    InvocationInventoryStatus8616,
)
from angr_platforms.X86_16.ir import entry_domain_call_preservation as edcp
from angr_platforms.X86_16.ir import vex_import as vi
from angr_platforms.X86_16.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    prove_ir_boundary_coverage_8616,
)
from angr_platforms.X86_16.ir.real16_invocation_domain import (
    Real16InvocationAssumption8616,
    Real16InvocationFailure8616,
    prove_real16_invocation_domain_8616,
)
from angr_platforms.X86_16.mz_static_boot import (
    MzStaticBoot8616,
    MzStaticBootPoint8616,
    mz_static_boot_8616,
    recompute_mz_static_boot_8616,
)

from inertia_decompiler.mz_static_intake import (
    MzStaticIntakeStatus8616,
    install_mz_static_invocation_source_8616,
)
from inertia_decompiler.project_loading import _build_project
from tools.dosunit.real16_scoped_invocation import (
    DeclaredInvocationStatus8616,
    install_declared_invocation_source_8616,
)

LOAD_SEGMENT = 0x1000
BASE = LOAD_SEGMENT << 4

# Same scoped-admission layout as the declared fixture: LEAF at BASE,
# CALLER at BASE+0x20 with an interior `e9` into an island, and STUB — the
# MZ entry — whose `e8` row is the sole registered edge into CALLER.
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
STUB = BASE + 0x160
STUB_CODE = (
    b"\xe8"
    + ((CALLER - (STUB + 3)) & 0xFFFF).to_bytes(2, "little")
    + b"\xc3"
)

# Unknown-state refusal fixture: ENTRY2 writes through BX — never seeded by
# a static-header input — before its near CALL, so the boot census must
# refuse rather than guess the store's target.
LEAF2 = BASE
ENTRY2 = BASE + 0x160
ENTRY2_CALL = ENTRY2 + 2
ENTRY2_CODE = (
    b"\x89\x07"  # mov word [bx], ax — store through unseeded BX
    + b"\xe8" + ((LEAF2 - (ENTRY2_CALL + 3)) & 0xFFFF).to_bytes(2, "little")
    + b"\xc3"
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
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    return bytes(header) + image


def _fixture_mz() -> bytes:
    """The scoped-admission fixture MZ with STUB as its entry."""
    image = _build_image(
        (
            (LEAF, LEAF_CODE),
            (CALLER, CALLER_CODE),
            (ISLAND, b"\xc3"),
            (STUB, STUB_CODE),
        )
    )
    return _build_mz(image, entry_ip=STUB - BASE)


def _store_fixture_mz() -> bytes:
    """The unknown-store fixture MZ with ENTRY2 as its entry."""
    image = _build_image(
        (
            (LEAF2, LEAF_CODE),
            (ENTRY2, ENTRY2_CODE),
        )
    )
    return _build_mz(image, entry_ip=ENTRY2 - BASE)


def _make_project(mz: bytes, tmp_path: Path, entry: int) -> angr.Project:
    """Load the retained MZ bytes through the production DOS MZ loader."""
    fixture = tmp_path / "fixture.exe"
    fixture.write_bytes(mz)
    project = _build_project(
        fixture, force_blob=False, base_addr=BASE, entry_point=entry
    )
    assert isinstance(project, angr.Project)
    return project


def _source(project: angr.Project) -> object | None:
    """Return the source through the real consumer seam — demand consults
    the deferred intake request retained at build time."""
    return edcp._real16_invocation_source_8616(project)


def _raw_source(project: angr.Project) -> object | None:
    """Read the source slot directly, without triggering a demand attempt."""
    return getattr(project, "_inertia_real16_invocation_source_8616", None)


def _boundary(project: angr.Project, head: int, end: int) -> object:
    """Resolve one exact decoded boundary or fail the fixture loudly."""
    boundary = exact_function_range_boundary_8616(project, head, end)
    assert boundary is not None
    return boundary


def _resolver(project: angr.Project) -> object:
    """Return the shared decoded direct-target resolver for one project."""
    return partial(resolve_direct_call_target_from_instruction_8616, project)


def _records(project: angr.Project, artifact: object, boundary: object) -> tuple:
    """Collect the caller's per-callsite preservation records."""
    return edcp.collect_entry_domain_call_preservations_8616(
        project, artifact, boundary,
        direct_target_resolver=_resolver(project),
    )


def _premise(
    project: angr.Project,
    artifact: object,
    boundary: object,
    callsite_addr: int,
    records: tuple = (),
) -> object | None:
    """Resolve the invocation premise for one exact caller row."""
    return edcp.entry_domain_invocation_premise_8616(
        project, artifact, boundary, callsite_addr, records
    )


def _caller_surface(project: angr.Project) -> tuple[object, object]:
    """Return the CALLER mapped-entry boundary and imported artifact."""
    caller_boundary = mapped_entry_function_boundary_8616(project, CALLER)
    assert caller_boundary is not None
    caller_artifact = vi.build_x86_16_ir_function_artifact(
        project, caller_boundary
    )
    return caller_boundary, caller_artifact


@pytest.fixture()
def world(tmp_path: Path) -> angr.Project:
    """Load the scoped-admission MZ; the staged intake installs the source.

    The STUB entry artifact is published exactly as the declared-boot
    fixture does — the chained premise's parent proof consumes the
    registry-owned entry surface.
    """
    project = _make_project(_fixture_mz(), tmp_path, STUB)
    stub_boundary = _boundary(project, STUB, STUB + len(STUB_CODE))
    stub_artifact = vi.build_x86_16_ir_function_artifact(
        project, stub_boundary
    )
    publish_function_ir_artifact_8616(project, stub_artifact)
    try:
        yield project
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_intake_installs_source_on_demand(world: angr.Project) -> None:
    """The P1 route: the consumer seam installs the static source on demand."""
    source = _source(world)
    assert source is not None
    assert type(source.boot) is MzStaticBoot8616
    assert callable(source.boot_recompute)
    assert source.callsite_index is not None
    assert source.pending_targets == ()
    receipt = getattr(
        world, "_inertia_mz_static_invocation_install_8616", None
    )
    assert receipt is not None and receipt.installed
    assert receipt.entry_linear == STUB


def test_build_defers_inventory_scan(tmp_path: Path) -> None:
    """An MZ build retains only the deferred request; no scan runs eagerly."""
    project = _make_project(_fixture_mz(), tmp_path, STUB)
    try:
        request = getattr(
            project, "_inertia_mz_static_invocation_request_8616", None
        )
        assert request is not None and isinstance(request.source, bytes)
        assert _raw_source(project) is None
        assert (
            getattr(project, "_inertia_mz_static_invocation_install_8616", None)
            is None
        )
        source = _source(project)
        assert source is not None
        assert _raw_source(project) is source
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_static_source_admits_scoped_premise(world: angr.Project) -> None:
    """Header facts suffice: the chained premise derives with header-only
    assumptions — STATIC_HEADER_STATE is declared, DECLARED_ENVIRONMENT is
    not."""
    caller_boundary, caller_artifact = _caller_surface(world)
    records = _records(world, caller_artifact, caller_boundary)
    offered = _premise(world, caller_artifact, caller_boundary, JUMP_HEAD, records)
    assert offered is not None
    assert offered.complete
    assert offered.failure is None
    assert (
        Real16InvocationAssumption8616.STATIC_HEADER_STATE
        in offered.assumptions
    )
    assert (
        Real16InvocationAssumption8616.DECLARED_ENVIRONMENT
        not in offered.assumptions
    )


def test_unknown_gp_store_refuses(tmp_path: Path) -> None:
    """A store through an unseeded GP register must not be guessed."""
    mz = _store_fixture_mz()
    project = _make_project(mz, tmp_path, ENTRY2)
    try:
        source = _source(project)
        assert source is not None
        entry_boundary = _boundary(project, ENTRY2, ENTRY2 + len(ENTRY2_CODE))
        entry_artifact = vi.build_x86_16_ir_function_artifact(
            project, entry_boundary
        )
        publish_function_ir_artifact_8616(project, entry_artifact)
        coverage = prove_ir_boundary_coverage_8616(
            project, entry_boundary, entry_artifact
        )
        premise = prove_real16_invocation_domain_8616(
            project,
            coverage,
            ENTRY2_CALL,
            boot=source.boot,
            boot_recompute=source.boot_recompute,
        )
        assert premise.failure is (
            Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN
        )
        assert not premise.complete
        assert _premise(
            project, entry_artifact, entry_boundary, ENTRY2_CALL
        ) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_mistyped_source_refuses(tmp_path: Path) -> None:
    """A non-bytes source cannot authenticate at the intake."""
    project = _make_project(_fixture_mz(), tmp_path, STUB)
    try:
        receipt = install_mz_static_invocation_source_8616(project, "")
        assert receipt.status is MzStaticIntakeStatus8616.SOURCE_REFUSED
        assert _raw_source(project) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_forged_source_refuses(tmp_path: Path) -> None:
    """Non-MZ bytes cannot project header facts."""
    project = _make_project(_fixture_mz(), tmp_path, STUB)
    try:
        receipt = install_mz_static_invocation_source_8616(
            project, b"\x00" * 0x400
        )
        assert receipt.status is MzStaticIntakeStatus8616.PROJECTION_REFUSED
        assert _raw_source(project) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_changed_source_refuses(tmp_path: Path) -> None:
    """MZ bytes that differ from the mapped image must not authenticate."""
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, STUB)
    mutated = bytearray(mz)
    mutated[0x20 + (STUB - BASE)] ^= 0xFF  # flip STUB's first byte in the file
    try:
        receipt = install_mz_static_invocation_source_8616(
            project, bytes(mutated)
        )
        assert receipt.status is MzStaticIntakeStatus8616.IMAGE_MISMATCH_REFUSED
        assert receipt.refusal_addr == BASE
        assert _raw_source(project) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_mutated_mapped_bytes_refuse(tmp_path: Path) -> None:
    """Tampered mapped bytes revoke the image authentication on demand too."""
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, STUB)
    try:
        project.loader.memory.store(
            CALLER, bytes([project.loader.memory.load(CALLER, 1)[0] ^ 0xFF])
        )
        receipt = install_mz_static_invocation_source_8616(project, mz)
        assert receipt.status is MzStaticIntakeStatus8616.IMAGE_MISMATCH_REFUSED
        assert _raw_source(project) is None
        # A consumer demand under the mutated image re-authenticates and
        # refuses again — the deferred request never masks stale evidence.
        assert _source(project) is None
        receipt = getattr(
            project, "_inertia_mz_static_invocation_install_8616", None
        )
        assert (
            receipt is not None
            and receipt.status is MzStaticIntakeStatus8616.IMAGE_MISMATCH_REFUSED
        )
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_restored_mapped_bytes_reauthenticate_on_demand(tmp_path: Path) -> None:
    """A refusal is memoized per evidence fingerprint — never across changes."""
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, STUB)
    original = project.loader.memory.load(CALLER, 1)
    try:
        project.loader.memory.store(CALLER, bytes([original[0] ^ 0xFF]))
        assert _source(project) is None
        # Identical evidence, memoized refusal — no rescan, same verdict.
        assert _source(project) is None
        # Restoring the image re-authenticates: negative evidence is not
        # cached across a real source/image change.
        project.loader.memory.store(CALLER, original)
        source = _source(project)
        assert source is not None
        assert type(source.boot) is MzStaticBoot8616
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_forged_boot_fields_refuse(tmp_path: Path) -> None:
    """A static input whose typed fields were forged is not reproduced."""
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, STUB)
    try:
        boot = mz_static_boot_8616(mz, LOAD_SEGMENT)
        assert boot.complete
        forged_entry = MzStaticBootPoint8616(
            boot.entry.segment, boot.entry.offset + 1
        )
        forged = MzStaticBoot8616(
            source=boot.source,
            entry=forged_entry,
            stack=boot.stack,
            image=boot.image,
            boot_sha256=boot.boot_sha256,
        )
        assert not forged.complete
        stub_boundary = _boundary(project, STUB, STUB + len(STUB_CODE))
        stub_artifact = vi.build_x86_16_ir_function_artifact(
            project, stub_boundary
        )
        publish_function_ir_artifact_8616(project, stub_artifact)
        coverage = prove_ir_boundary_coverage_8616(
            project, stub_boundary, stub_artifact
        )
        assert coverage.complete
        premise = prove_real16_invocation_domain_8616(
            project,
            coverage,
            STUB,
            boot=forged,
            boot_recompute=lambda b: b,
        )
        assert premise.failure is Real16InvocationFailure8616.BOOT_NOT_REPRODUCED
        assert not premise.complete
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_wrong_load_paragraph_refuses(tmp_path: Path) -> None:
    """A static input projected at a foreign paragraph authenticates nothing."""
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, STUB)
    try:
        foreign = mz_static_boot_8616(mz, LOAD_SEGMENT + 1)
        stub_boundary = _boundary(project, STUB, STUB + len(STUB_CODE))
        stub_artifact = vi.build_x86_16_ir_function_artifact(
            project, stub_boundary
        )
        publish_function_ir_artifact_8616(project, stub_artifact)
        coverage = prove_ir_boundary_coverage_8616(
            project, stub_boundary, stub_artifact
        )
        assert coverage.complete
        premise = prove_real16_invocation_domain_8616(
            project,
            coverage,
            STUB,
            boot=foreign,
            boot_recompute=recompute_mz_static_boot_8616,
        )
        assert premise.failure is (
            Real16InvocationFailure8616.ENTRY_NOT_FUNCTION_HEAD
        )
        assert not premise.complete
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_static_boot_cannot_masquerade_as_declared(tmp_path: Path) -> None:
    """The declared installer must refuse a header-only input by type."""
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, STUB)
    try:
        boot = mz_static_boot_8616(mz, LOAD_SEGMENT)
        receipt = install_declared_invocation_source_8616(project, boot)
        assert receipt.status is DeclaredInvocationStatus8616.BOOT_TYPE_REFUSED
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_intake_clears_and_reinstalls(tmp_path: Path) -> None:
    """Each intake attempt clears the slot before deciding — no stale reuse."""
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, STUB)
    try:
        first = _source(project)
        assert first is not None
        receipt = install_mz_static_invocation_source_8616(
            project, b"not an mz at all"
        )
        assert not receipt.installed
        assert _raw_source(project) is None
        receipt = install_mz_static_invocation_source_8616(project, mz)
        assert receipt.installed
        assert _source(project) is not None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def _pending_callee_mz() -> tuple[bytes, int, int]:
    """The parent fixture: a header-rooted CALL to a ``pop cx; jmp cx`` callee.

    The callee's mapped boundary cannot close without the transported
    caller premise, so its head is a discovered obligation, not a closure
    failure — the caller's decoded CALL row is evidence before the
    callee's behavior closes.
    """
    callee = BASE + 0x20
    root = BASE + 0x60
    body = bytes.fromhex("59 ff e1")  # pop cx; jmp cx
    caller = (
        b"\xe8" + ((callee - root - 3) & 0xFFFF).to_bytes(2, "little") + b"\xc3"
    )
    image = _build_image(((callee, body), (root, caller)))
    return _build_mz(image, entry_ip=root - BASE), callee, root


def test_pending_callee_intake_installs_partial_evidence(tmp_path: Path) -> None:
    """Decoded caller CALL evidence precedes the callee's closure.

    The inventory reports ``PARTIAL_CALLER_EVIDENCE`` — never READY — and
    the intake installs a source whose index holds the caller's row while
    the callee head remains a typed pending obligation.
    """
    mz, callee, root = _pending_callee_mz()
    project = _make_project(mz, tmp_path, root)
    try:
        source = _source(project)
        assert source is not None
        assert source.pending_targets == (callee,)
        rows = source.callsite_index.for_target(callee)
        assert len(rows) == 1
        assert rows[0].callsite_addr == root
        assert rows[0].caller_start == root
        assert rows[0].target_addr == callee
        receipt = getattr(
            project, "_inertia_mz_static_invocation_install_8616", None
        )
        assert receipt is not None and receipt.installed
        assert receipt.pending_targets == (callee,)
        inventory = receipt.inventory
        assert inventory is not None
        assert inventory.status is (
            InvocationInventoryStatus8616.PARTIAL_CALLER_EVIDENCE
        )
        assert not inventory.ready
        assert inventory.pending_targets == (callee,)
        assert inventory.stats.closed
        assert inventory.stats.pending_count == 1
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_pending_callee_explicit_root_still_refuses(tmp_path: Path) -> None:
    """Caller-supplied roots are trusted: an unclosable one refuses."""
    mz, callee, root = _pending_callee_mz()
    project = _make_project(mz, tmp_path, root)
    try:
        receipt = install_mz_static_invocation_source_8616(
            project, mz, extra_entries=(callee,)
        )
        assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
        inventory = receipt.inventory
        assert inventory is not None
        assert inventory.status is (
            InvocationInventoryStatus8616.BOUNDARY_MISSING
        )
        assert inventory.refusal_addr == callee
        assert inventory.callsite_index is None
        assert _raw_source(project) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_exhausted_boundary_budget_still_refuses(tmp_path: Path) -> None:
    """A boundary budget below the reachable corpus refuses, deferred or not."""
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, STUB)
    try:
        receipt = install_mz_static_invocation_source_8616(
            project,
            mz,
            budget=InvocationInventoryBudget8616(
                max_boundaries=1, max_instructions=1024, max_root_inputs=8
            ),
        )
        assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
        assert receipt.inventory is not None
        assert receipt.inventory.status is (
            InvocationInventoryStatus8616.BUDGET_BOUNDARIES
        )
        assert _raw_source(project) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_pending_callee_edge_is_per_edge_only(tmp_path: Path) -> None:
    """The partial index supplies the caller edge — never universal proof.

    A premise demand for an edge that is not the authenticated decoded row
    still refuses: the pending-callee contract grants per-edge caller
    evidence, not a universal premise over the unclosed target.
    """
    mz, callee, root = _pending_callee_mz()
    project = _make_project(mz, tmp_path, root)
    try:
        source = _source(project)
        assert source is not None
        assert source.pending_targets == (callee,)
        # No decoded row exists into the entry head: a premise demand
        # anchored on it finds no evidence and refuses.
        assert source.callsite_index.for_target(root) == ()
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_non_mz_project_refuses_intake(tmp_path: Path) -> None:
    """A blob project exposes no loader paragraph; the intake refuses."""
    import io

    from angr_platforms.X86_16.arch_86_16 import Arch86_16

    project = angr.Project(
        io.BytesIO(LEAF_CODE),
        auto_load_libs=False,
        main_opts={"backend": "blob", "arch": Arch86_16()},
    )
    try:
        receipt = install_mz_static_invocation_source_8616(
            project, _fixture_mz()
        )
        assert receipt.status is (
            MzStaticIntakeStatus8616.LOADER_SURFACE_REFUSED
        )
        assert _source(project) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
