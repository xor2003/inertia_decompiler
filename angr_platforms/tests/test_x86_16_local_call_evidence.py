"""Local conditional near-CALL frame evidence controls.

The bounded entry-rooted caller inventory refuses at an unchanged boundary
budget while the requested caller sits inside the closed prefix. The intake
then retains a separate typed LOCAL authority — a closed decoded callsite
index over exactly the re-closed caller surfaces, bound to the
authenticated MZ source and mapped-image digests — and only the
conditional frame-premise consumer may consult it. These controls prove
the refused corpus keeps its typed ledger, the global
``Real16InvocationSource8616`` stays uninstalled, premise-derived callees
keep their pending markers and never publish, and no boot-to-caller
reachability or complete invocation chain is claimed. Every negative —
unvisited head, foreign or forged row, changed native bytes, changed
source, far call, and ``66 E8`` wrong-width call — must keep refusing.
"""

from __future__ import annotations

from dataclasses import replace
from functools import partial
from pathlib import Path

import angr
import archinfo
import capstone
import pytest
from angr_platforms.X86_16.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    build_boundary_direct_callsite_index_8616,
)
from angr_platforms.X86_16.frontend_function_boundary import (
    mapped_entry_function_boundary_8616,
)
from angr_platforms.X86_16.frontend_invocation_inventory import (
    InvocationInventoryBudget8616,
    InvocationInventoryStatus8616,
)
from angr_platforms.X86_16.frontend_local_call_evidence import (
    LocalCallFrameEvidence8616,
    install_local_call_frame_evidence_8616,
    local_call_frame_evidence_8616,
)
from angr_platforms.X86_16.frontend_near_return_continuation import (
    NearCallFramePremise8616,
)
from angr_platforms.X86_16.ir import entry_domain_call_preservation as edcp
from angr_platforms.X86_16.ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    registered_function_ir_artifact_8616,
)

from inertia_decompiler.mz_static_intake import (
    MzStaticIntakeStatus8616,
    install_mz_static_invocation_source_8616,
)
from inertia_decompiler.project_loading import _build_project

LOAD_SEGMENT = 0x1000
BASE = LOAD_SEGMENT << 4
_PENDING_KIND = "near_return_continuation_pending"

# The premise-needing callee: ``pop cx; jmp cx`` cannot close without the
# caller's transported entry-frame premise.
PENDING = BASE + 0x40
PENDING_CODE = bytes.fromhex("59 ff e1")
WIDE_CALLEE = BASE + 0x60
WIDE_CODE = bytes.fromhex("5a ff e2")
FAR_CALLEE = BASE + 0x80
FAR_CODE = b"\xc3"
ISOLATED = BASE + 0xA0
ISOLATED_CODE = b"\xc3"
LATE = BASE + 0xC0
LATE_CODE = b"\xc3"

ENTRY = BASE + 0x100
CALL1 = ENTRY
WIDE_CALL = CALL1 + 3
FAR_CALL = WIDE_CALL + 6
CALL4 = FAR_CALL + 5
ENTRY_CODE = (
    b"\xe8" + ((PENDING - (CALL1 + 3)) & 0xFFFF).to_bytes(2, "little")
    + b"\x66\xe8"
    + ((WIDE_CALLEE - (WIDE_CALL + 6)) & 0xFFFFFFFF).to_bytes(4, "little")
    + b"\x9a"
    + (FAR_CALLEE - BASE).to_bytes(2, "little")
    + LOAD_SEGMENT.to_bytes(2, "little")
    + b"\xe8" + ((LATE - (CALL4 + 3)) & 0xFFFF).to_bytes(2, "little")
    + b"\xc3"
)

LOW_BUDGET = InvocationInventoryBudget8616(
    max_boundaries=2, max_instructions=4096, max_root_inputs=16
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


def _fixture_mz() -> bytes:
    """The refused-inventory fixture MZ with ENTRY as its header entry."""
    image = _build_image(
        (
            (PENDING, PENDING_CODE),
            (WIDE_CALLEE, WIDE_CODE),
            (FAR_CALLEE, FAR_CODE),
            (ISOLATED, ISOLATED_CODE),
            (LATE, LATE_CODE),
            (ENTRY, ENTRY_CODE),
        )
    )
    return _build_mz(image, entry_ip=ENTRY - BASE)


def _big_fixture_mz() -> tuple[bytes, int, int]:
    """An entry plus 66 leaves and one pending callee — over 64 boundaries.

    The header entry near-calls the pending ``pop cx; jmp cx`` head first,
    then 66 distinct one-instruction leaves; the unchanged default
    ``max_boundaries=64`` exhausts on the full corpus while the requested
    caller (the entry head itself) sits inside the closed prefix.
    """
    pending = BASE + 0x300
    leaf_base = BASE + 0x400
    calls = _near_call(BASE, pending)
    offset = len(calls)
    leaves = tuple(leaf_base + 0x10 * index for index in range(66))
    for leaf in leaves:
        calls += _near_call(BASE + offset, leaf)
        offset += 3
    entry_code = calls + b"\xc3"
    islands = [(BASE, entry_code), (pending, PENDING_CODE)]
    islands.extend((leaf, b"\xc3") for leaf in leaves)
    image = _build_image(tuple(islands))
    return _build_mz(image, entry_ip=0), pending, BASE


def _near_call(callsite: int, target: int) -> bytes:
    """Encode one real near CALL rel16 targeting ``target``."""
    return (
        b"\xe8" + ((target - (callsite + 3)) & 0xFFFF).to_bytes(2, "little")
    )


def _make_project(mz: bytes, tmp_path: Path, entry: int) -> angr.Project:
    """Load the retained MZ bytes through the production DOS MZ loader."""
    fixture = tmp_path / "fixture.exe"
    fixture.write_bytes(mz)
    project = _build_project(
        fixture, force_blob=False, base_addr=BASE, entry_point=entry
    )
    assert isinstance(project, angr.Project)
    return project


def _resolver(project: angr.Project) -> object:
    """Return the shared decoded direct-target resolver for one project."""
    return partial(resolve_direct_call_target_from_instruction_8616, project)


def _raw_source(project: angr.Project) -> object | None:
    """Read the global source slot directly, without a demand attempt."""
    return getattr(project, "_inertia_real16_invocation_source_8616", None)


def _raw_evidence(project: angr.Project) -> object | None:
    """Read the local evidence slot directly, without revalidation."""
    return getattr(project, "_inertia_local_call_frame_evidence_8616", None)


def _refused_world(
    tmp_path: Path,
) -> tuple[angr.Project, LocalCallFrameEvidence8616]:
    """Install under the low boundary budget and neutralize the deferred demand.

    The retained request is cleared so the terminal refused state stands —
    a demand with default budgets would close this tiny corpus and install
    the global source, exactly as production does for small programs. The
    real exhausted-budget demand path is covered by the big fixture.
    """
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, ENTRY)
    receipt = install_mz_static_invocation_source_8616(
        project, mz, budget=LOW_BUDGET
    )
    assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    inventory = receipt.inventory
    assert inventory is not None
    assert inventory.status is InvocationInventoryStatus8616.BUDGET_BOUNDARIES
    assert inventory.boundary_heads == (ENTRY,)
    assert inventory.pending_targets == (PENDING,)
    assert _raw_source(project) is None
    project._inertia_mz_static_invocation_request_8616 = None
    evidence = local_call_frame_evidence_8616(project)
    assert type(evidence) is LocalCallFrameEvidence8616
    assert receipt.local_evidence is evidence
    return project, evidence


def _entry_edge_row(project: angr.Project) -> DecodedDirectCallsite8616:
    """Decode an independent boundary-scoped row for the PENDING edge."""
    boundary = mapped_entry_function_boundary_8616(project, ENTRY)
    assert boundary is not None
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=_resolver(project)
    )
    row = next(
        row
        for row in index.for_target(PENDING)
        if row.callsite_addr == CALL1
    )
    assert type(row) is DecodedDirectCallsite8616
    return row


@pytest.fixture()
def world(tmp_path: Path) -> angr.Project:
    """Yield the refused-inventory project, clearing both evidence slots."""
    project, _ = _refused_world(tmp_path)
    try:
        yield project
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


def test_refused_inventory_retains_local_evidence(world: angr.Project) -> None:
    """The closed prefix is retained as typed local evidence, not a source."""
    evidence = local_call_frame_evidence_8616(world)
    assert type(evidence) is LocalCallFrameEvidence8616
    assert evidence.boundary_heads == (ENTRY,)
    assert evidence.pending_targets == (PENDING,)
    assert evidence.inventory_status is (
        InvocationInventoryStatus8616.BUDGET_BOUNDARIES
    )
    assert evidence.entry_linear == ENTRY
    assert evidence.callsite_index.stats.closed
    stats = evidence.stats
    assert (stats.raw_fact_count, stats.normalized_fact_count) == (1, 1)
    assert (stats.classified_fact_count, stats.materialized_count) == (1, 1)
    assert stats.failure_count == 0 and stats.closed
    # The decoded near-CALL row into the pending callee is retained.
    rows = evidence.callsite_index.for_target(PENDING)
    assert len(rows) == 1
    assert rows[0].callsite_addr == CALL1
    assert rows[0].caller_start == ENTRY
    assert rows[0].target_addr == PENDING


def test_local_evidence_proves_conditional_frame_premise(
    world: angr.Project,
) -> None:
    """A closed-prefix caller proves the pending callee's exact frame."""
    evidence = local_call_frame_evidence_8616(world)
    assert type(evidence) is LocalCallFrameEvidence8616
    premise = edcp._near_return_frame_premise_8616(world, PENDING)
    assert type(premise) is NearCallFramePremise8616
    assert premise.callee_addr == PENDING
    assert premise.callsite_addr == CALL1
    assert premise.caller_start == ENTRY
    assert premise.return_addr == CALL1 + 3
    # Identical retained row/index ownership: the premise re-binds the
    # exact objects the evidence index retains.
    index_rows = evidence.callsite_index.for_target(PENDING)
    assert premise.callsite is index_rows[0]
    assert premise.callsite_index is evidence.callsite_index
    # The premise is conditional only: it discharges the callee's
    # unresolved indirect terminal so the boundary can close.
    assert mapped_entry_function_boundary_8616(world, PENDING) is None
    boundary = mapped_entry_function_boundary_8616(
        world, PENDING, premise=premise
    )
    assert boundary is not None and boundary.addr == PENDING


def test_imported_callee_keeps_pending_markers(world: angr.Project) -> None:
    """The premise-derived callee stays conditional and unpublished."""
    resolved = edcp._callee_artifact_and_boundary_8616(world, PENDING)
    assert resolved is not None
    artifact, boundary = resolved
    continuations = boundary.near_return_continuations
    assert continuations is not None
    assert type(continuations.premise) is NearCallFramePremise8616
    block = next(b for b in artifact.blocks if b.addr == PENDING)
    assert any(r.kind == _PENDING_KIND for r in block.refusals)
    resolution = registered_function_ir_artifact_8616(world, PENDING)
    assert resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN


def test_local_evidence_grants_no_invocation_chain(
    world: angr.Project,
) -> None:
    """Local evidence is conditional frame authority, not a closed chain."""
    resolved = edcp._callee_artifact_and_boundary_8616(world, PENDING)
    assert resolved is not None
    artifact, boundary = resolved
    scope = edcp.entry_domain_invocation_premise_8616(
        world, artifact, boundary, CALL1
    )
    assert scope is None


def test_transport_edge_binds_retained_row(world: angr.Project) -> None:
    """An independently decoded row selects the identical retained row."""
    edge = _entry_edge_row(world)
    premise = edcp._near_return_frame_premise_8616(world, PENDING, edge)
    assert premise is not None
    assert premise.callsite is not edge
    assert premise.callsite_addr == CALL1
    assert premise.return_addr == CALL1 + 3


def test_unvisited_head_refuses(world: angr.Project) -> None:
    """A target no closed-prefix row names keeps its absence."""
    assert edcp._near_return_frame_premise_8616(world, ISOLATED) is None


def test_foreign_callsite_row_refuses(world: angr.Project) -> None:
    """A fabricated row cannot borrow the retained edge's coordinates."""
    forged = DecodedDirectCallsite8616(
        caller_start=ENTRY,
        instructions=(),
        instruction_index=0,
        callsite_addr=CALL1,
        target_addr=PENDING,
    )
    assert (
        edcp._near_return_frame_premise_8616(world, PENDING, forged) is None
    )


def test_far_row_refuses(world: angr.Project) -> None:
    """A far call never mints a near-CALL frame premise."""
    # The decoded ``lcall`` row exists in the retained index but its
    # instruction proves no word-width return push.
    assert edcp._near_return_frame_premise_8616(world, FAR_CALLEE) is None
    edge = _entry_edge_row(world)
    far = replace(edge, is_far=True)
    assert edcp._near_return_frame_premise_8616(world, PENDING, far) is None


def test_wide_row_refuses(world: angr.Project) -> None:
    """A ``66 E8`` dword-push call never mints a word-frame premise."""
    assert edcp._near_return_frame_premise_8616(world, WIDE_CALLEE) is None
    edge = _entry_edge_row(world)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instruction, = tuple(
        decoder.disasm(
            b"\x66\xe8"
            + ((PENDING - (CALL1 + 6)) & 0xFFFFFFFF).to_bytes(4, "little"),
            CALL1,
        )
    )
    wide = replace(edge, instructions=(instruction,), instruction_index=0)
    assert edcp._near_return_frame_premise_8616(world, PENDING, wide) is None


def test_foreign_project_revokes_local_evidence(world: angr.Project, tmp_path: Path) -> None:
    """Equal image bytes do not transport the original project authority."""
    other = _make_project(_fixture_mz(), tmp_path, ENTRY)
    other._inertia_local_call_frame_evidence_8616 = _raw_evidence(world)
    assert local_call_frame_evidence_8616(other) is None
    assert _raw_evidence(other) is None


@pytest.mark.parametrize("changed_field", ("entry", "load_segment", "architecture"))
def test_changed_project_context_revokes_local_evidence(
    world: angr.Project, changed_field: str,
) -> None:
    """Preserved bytes cannot authenticate a changed loader or decoding mode."""
    if changed_field == "entry":
        world.entry += 1
    elif changed_field == "load_segment":
        world.loader.main_object.mz_load_segment += 1
    else:
        world.arch = archinfo.ArchX86()
    assert local_call_frame_evidence_8616(world) is None
    assert _raw_evidence(world) is None


def test_changed_mapped_bytes_revoke_evidence(world: angr.Project) -> None:
    """Mutated native bytes revoke the retained census and its slot."""
    original = world.loader.memory.load(CALL1, 1)
    world.loader.memory.store(CALL1, bytes([original[0] ^ 0xFF]))
    try:
        assert local_call_frame_evidence_8616(world) is None
        assert _raw_evidence(world) is None
        assert edcp._near_return_frame_premise_8616(world, PENDING) is None
    finally:
        world.loader.memory.store(CALL1, original)


def test_changed_source_clears_evidence(tmp_path: Path) -> None:
    """A failed re-authentication clears the local evidence slot."""
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, ENTRY)
    try:
        receipt = install_mz_static_invocation_source_8616(
            project, mz, budget=LOW_BUDGET
        )
        assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
        assert receipt.local_evidence is not None
        mutated = bytearray(mz)
        mutated[0x20 + (ENTRY - BASE)] ^= 0xFF
        receipt = install_mz_static_invocation_source_8616(
            project, bytes(mutated), budget=LOW_BUDGET
        )
        assert receipt.status is (
            MzStaticIntakeStatus8616.IMAGE_MISMATCH_REFUSED
        )
        assert receipt.local_evidence is None
        assert local_call_frame_evidence_8616(project) is None
        assert _raw_evidence(project) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


def test_forged_evidence_install_refuses(world: angr.Project) -> None:
    """Evidence whose census set disagrees with its heads cannot install."""
    evidence = local_call_frame_evidence_8616(world)
    assert type(evidence) is LocalCallFrameEvidence8616
    forged_heads = replace(evidence, boundary_heads=(PENDING,))
    with pytest.raises(ValueError):
        install_local_call_frame_evidence_8616(world, forged_heads)
    forged_census = replace(
        evidence,
        callsite_index=replace(
            evidence.callsite_index,
            caller_censuses=(),
        ),
    )
    with pytest.raises(ValueError):
        install_local_call_frame_evidence_8616(world, forged_census)


def test_cleared_evidence_refuses_premise(world: angr.Project) -> None:
    """Clearing the local slot removes conditional frame authority."""
    install_local_call_frame_evidence_8616(world, None)
    assert local_call_frame_evidence_8616(world) is None
    assert edcp._near_return_frame_premise_8616(world, PENDING) is None


def test_successful_inventory_keeps_local_slot_empty(tmp_path: Path) -> None:
    """A corpus that installs the global source retains no local evidence."""
    mz = _fixture_mz()
    project = _make_project(mz, tmp_path, ENTRY)
    try:
        receipt = install_mz_static_invocation_source_8616(project, mz)
        assert receipt.status is MzStaticIntakeStatus8616.INSTALLED
        assert receipt.local_evidence is None
        assert _raw_source(project) is not None
        assert _raw_evidence(project) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


def test_deferred_demand_retains_local_evidence(tmp_path: Path) -> None:
    """The unchanged default budget exhausts; the demand retains local rows.

    The entry head sits inside the closed prefix, so its decoded near-CALL
    into the still-pending callee proves the conditional frame premise
    while the corpus-wide inventory stays ``BUDGET_BOUNDARIES`` and no
    global source is ever installed.
    """
    mz, pending, entry = _big_fixture_mz()
    project = _make_project(mz, tmp_path, entry)
    try:
        source = edcp._real16_invocation_source_8616(project)
        assert source is None
        receipt = getattr(
            project, "_inertia_mz_static_invocation_install_8616", None
        )
        assert receipt is not None
        assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
        inventory = receipt.inventory
        assert inventory is not None
        assert inventory.status is (
            InvocationInventoryStatus8616.BUDGET_BOUNDARIES
        )
        assert entry in inventory.boundary_heads
        evidence = local_call_frame_evidence_8616(project)
        assert type(evidence) is LocalCallFrameEvidence8616
        assert entry in evidence.boundary_heads
        assert pending in evidence.pending_targets
        premise = edcp._near_return_frame_premise_8616(project, pending)
        assert type(premise) is NearCallFramePremise8616
        assert premise.callee_addr == pending
        assert premise.caller_start == entry
        assert premise.callsite_addr == entry
        assert premise.return_addr == entry + 3
        boundary = mapped_entry_function_boundary_8616(
            project, pending, premise=premise
        )
        assert boundary is not None and boundary.addr == pending
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)
