"""Dependency-local scoped invocation source over a refused inventory.

When the bounded entry-rooted caller inventory refuses under an unchanged
budget, no project-wide ``Real16InvocationSource8616`` may install — but
the retained deferred-intake record can still mint a typed, dependency-local
source over exactly the independently re-closed caller census. These
controls prove the minted record authenticates the identical MZ bytes,
loader paragraph, and header entry; that caller-domain premise consumers
can derive a real boot-to-caller invocation chain through it; and that
every refusal channel — missing, foreign, stale, or mistyped authority —
stays refused while the global inventory verdict remains
``BUDGET_BOUNDARIES`` and never ``READY``.
"""

from __future__ import annotations

from pathlib import Path

import angr
import pytest
import inertia.ir.entry_domain_call_preservation as edcp
from inertia.ir.real16_invocation_domain import (
    Real16InvocationFailure8616,
    Real16InvocationKind8616,
    prove_real16_invocation_domain_8616,
    same_real16_entry_scope_8616,
)
from inertia.ir.vex_import import (
    build_x86_16_ir_function_artifact,
)

from inertia.frontend.x86_16.frontend_function_boundary import (
    mapped_entry_function_boundary_8616,
)
from inertia.frontend.x86_16.frontend_invocation_inventory import (
    InvocationInventoryStatus8616,
)
from inertia.frontend.x86_16.frontend_local_call_evidence import (
    LocalCallFrameEvidence8616,
    install_local_call_frame_evidence_8616,
    local_call_frame_evidence_8616,
)
from inertia.frontend.x86_16.mz_static_boot import recompute_mz_static_boot_8616
from inertia.cli.mz_static_intake import (
    MzStaticIntakeRequest8616,
    MzStaticIntakeStatus8616,
    install_mz_static_invocation_source_8616,
)
from inertia.cli.project_loading import _build_project

LOAD_SEGMENT = 0x1000
BASE = LOAD_SEGMENT << 4


def _repo_root() -> Path:
    """Locate the repository root by walking up to the saved binary."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "SORTD.EXE").is_file():
            return parent
    raise FileNotFoundError("SORTD.EXE not found above the test file")


SORTD_EXE = _repo_root() / "SORTD.EXE"

PENDING = BASE + 0x300
PENDING_CODE = bytes.fromhex("59 ff e1")
LEAF_BASE = BASE + 0x400


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


def _big_fixture_mz() -> tuple[bytes, int, int]:
    """An entry plus 66 leaves and one pending callee — over 64 boundaries.

    The header entry near-calls the pending ``pop cx; jmp cx`` head first,
    then 66 distinct one-instruction leaves; the unchanged default
    ``max_boundaries=64`` exhausts on the full corpus while the requested
    caller (the entry head itself) sits inside the closed prefix.
    """
    calls = _near_call(BASE, PENDING)
    offset = len(calls)
    leaves = tuple(LEAF_BASE + 0x10 * index for index in range(66))
    for leaf in leaves:
        calls += _near_call(BASE + offset, leaf)
        offset += 3
    entry_code = calls + b"\xc3"
    islands = [(BASE, entry_code), (PENDING, PENDING_CODE)]
    islands.extend((leaf, b"\xc3") for leaf in leaves)
    image = _build_image(tuple(islands))
    return _build_mz(image, entry_ip=0), PENDING, BASE


def _make_project(mz: bytes, tmp_path: Path, entry: int) -> angr.Project:
    """Load the retained MZ bytes through the production DOS MZ loader."""
    fixture = tmp_path / "fixture.exe"
    fixture.write_bytes(mz)
    project = _build_project(
        fixture, force_blob=False, base_addr=BASE, entry_point=entry
    )
    assert isinstance(project, angr.Project)
    return project


def _request(project: angr.Project) -> MzStaticIntakeRequest8616:
    """Return the retained deferred-intake record, asserting its type."""
    request = getattr(project, "_inertia_mz_static_invocation_request_8616", None)
    assert type(request) is MzStaticIntakeRequest8616
    return request


def _raw_source(project: angr.Project) -> object | None:
    """Read the global source slot directly, without a demand attempt."""
    return getattr(project, "_inertia_real16_invocation_source_8616", None)


def _refused_world(
    tmp_path: Path,
) -> tuple[angr.Project, LocalCallFrameEvidence8616, MzStaticIntakeRequest8616, int]:
    """Install under the unchanged budget; keep the deferred request.

    Unlike the local-evidence review world, the retained request stays on
    the project: it is the dependency-local scoped-authority owner these
    controls exercise.
    """
    mz, pending, entry = _big_fixture_mz()
    project = _make_project(mz, tmp_path, entry)
    request = _request(project)
    receipt = request.install(project)
    assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    inventory = receipt.inventory
    assert inventory is not None
    assert inventory.status is InvocationInventoryStatus8616.BUDGET_BOUNDARIES
    assert not inventory.caller_evidence_ready
    assert inventory.pending_targets == (pending,)
    assert _raw_source(project) is None
    evidence = local_call_frame_evidence_8616(project)
    assert type(evidence) is LocalCallFrameEvidence8616
    assert receipt.local_evidence is evidence
    return project, evidence, request, entry


@pytest.fixture()
def world(
    tmp_path: Path,
) -> tuple[angr.Project, LocalCallFrameEvidence8616, MzStaticIntakeRequest8616, int]:
    """Yield the refused-inventory project with the retained request."""
    project, evidence, request, entry = _refused_world(tmp_path)
    try:
        yield project, evidence, request, entry
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


def _register_head(project: angr.Project, head_addr: int) -> bool:
    """Import and publish one closed caller surface when it is refusal-free."""
    boundary = mapped_entry_function_boundary_8616(project, head_addr)
    if boundary is None or boundary.addr != head_addr:
        return False
    raw = build_x86_16_ir_function_artifact(project, boundary)
    if raw.refusals:
        return False
    publication = edcp.publish_function_ir_artifact_8616(project, raw)
    return publication.artifact is not None


def test_scoped_source_mints_over_refused_inventory(
    world: tuple,
) -> None:
    """The retained request mints typed authority over the closed census."""
    project, evidence, request, entry = world
    scoped = request.scoped_invocation_source_8616(project)
    assert type(scoped) is edcp.Real16InvocationSource8616
    # The boot is real MZ-header authority recomputed from the identical
    # retained bytes — never declared environment or evidence provenance.
    assert scoped.boot.entry.linear() == entry
    assert scoped.boot.image.file_sha256 == evidence.source_sha256
    assert recompute_mz_static_boot_8616(scoped.boot) == scoped.boot
    # The index is the identical closed census the evidence retains;
    # pending targets ride on the record as unresolved obligations.
    assert scoped.callsite_index is evidence.callsite_index
    assert scoped.pending_targets == evidence.pending_targets
    # Memoized identity: the same evidence object returns the identical
    # record so derived premises share one boot identity.
    assert request.scoped_invocation_source_8616(project) is scoped
    # The mint installs nothing: the global slot stays empty and the
    # refused verdict is untouched.
    assert _raw_source(project) is None
    receipt = getattr(
        project, "_inertia_mz_static_invocation_install_8616", None
    )
    assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    assert receipt.inventory.status is (
        InvocationInventoryStatus8616.BUDGET_BOUNDARIES
    )


def test_scoped_source_derives_boot_chained_premise(
    world: tuple,
) -> None:
    """A closed-census edge proves a real boot-to-caller chain premise."""
    project, evidence, request, entry = world
    scoped = request.scoped_invocation_source_8616(project)
    assert scoped is not None
    assert _register_head(project, entry)
    pending = evidence.pending_targets[0]
    resolved = edcp._callee_artifact_and_boundary_8616(project, pending)
    assert resolved is not None
    artifact, boundary = resolved
    premise = edcp.entry_domain_invocation_premise_8616(
        project, artifact, boundary, pending
    )
    assert premise is not None
    assert premise.complete
    assert premise.callsite_addr == pending
    assert premise.kind is Real16InvocationKind8616.CALL_CHAINED
    # The chain binds the retained decoded row and a boot-rooted parent:
    # entry head → pending callee, with transported call-row state.
    assert premise.chain is not None
    assert premise.chain.callsite.callsite_addr == entry
    assert premise.chain.callsite.caller_start == entry
    # Each premise demand re-runs the refused install and re-collects
    # evidence, so the premise binds the CURRENT evidence epoch's index.
    current = request.scoped_invocation_source_8616(project)
    assert current is not None
    assert premise.chain.callsite_index is current.callsite_index
    assert premise.chain.parent.kind is (
        Real16InvocationKind8616.BOOT_ENTRY_PATH
    )
    # Transported boot-to-caller entry state: the parent's captured
    # call-row state and the link's transported state carry real facts.
    assert premise.chain.parent.callsite_call_state
    assert premise.chain.call_state
    assert same_real16_entry_scope_8616(premise, premise)
    # Consumption bound nothing project-wide.
    assert _raw_source(project) is None


def test_missing_request_refuses_scoped_authority(world: tuple) -> None:
    """No retained deferred record means no scoped authority at all."""
    project, evidence, _, _ = world
    project._inertia_mz_static_invocation_request_8616 = None
    assert edcp._scoped_invocation_source_8616(project) is None
    pending = evidence.pending_targets[0]
    resolved = edcp._callee_artifact_and_boundary_8616(project, pending)
    assert resolved is not None
    artifact, boundary = resolved
    assert (
        edcp.entry_domain_invocation_premise_8616(
            project, artifact, boundary, pending
        )
        is None
    )


def test_foreign_request_source_revokes(world: tuple, tmp_path: Path) -> None:
    """A request carrying different MZ bytes cannot borrow the evidence."""
    project, _, _, entry = world
    foreign_mz = _build_mz(b"\x90" * 64, entry_ip=entry - BASE)
    project._inertia_mz_static_invocation_request_8616 = (
        MzStaticIntakeRequest8616(source=foreign_mz)
    )
    request = _request(project)
    assert request.scoped_invocation_source_8616(project) is None
    assert local_call_frame_evidence_8616(project) is None
    assert _raw_source(project) is None


def test_stale_mapped_bytes_revoke_scoped(world: tuple) -> None:
    """Mutated native bytes revoke evidence and scoped authority alike."""
    project, _, request, entry = world
    scoped = request.scoped_invocation_source_8616(project)
    assert scoped is not None
    original = project.loader.memory.load(entry, 1)
    project.loader.memory.store(entry, bytes([original[0] ^ 0xFF]))
    try:
        assert request.scoped_invocation_source_8616(project) is None
        assert local_call_frame_evidence_8616(project) is None
    finally:
        project.loader.memory.store(entry, original)
    # The revoked slot stays empty until a fresh refused install
    # re-collects evidence; the re-minted record is a new provenance epoch.
    receipt = request.install(project)
    assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    reminted = request.scoped_invocation_source_8616(project)
    assert reminted is not None
    assert reminted is not scoped
    assert reminted.callsite_index is not scoped.callsite_index


@pytest.mark.parametrize(
    "replacement", ("removed", "same_bytes", "detached_changed_bytes")
)
def test_detached_request_cannot_reuse_scoped_authority(
    world: tuple, replacement: str
) -> None:
    """A previously minted receiver must not borrow replacement provenance.

    Parent-reported revocation controls: request removal, replacement by
    a same-bytes record, and mutation of a detached receiver's own
    source must all refuse the public scoped callable — even on a memo
    hit — because scoped authority stays bound to the identical retained
    receiver, never to bytes alone.
    """
    project, _, request, _ = world
    assert request.scoped_invocation_source_8616(project) is not None
    project._inertia_mz_static_invocation_request_8616 = (
        None
        if replacement == "removed"
        else MzStaticIntakeRequest8616(source=request.source)
    )
    if replacement == "detached_changed_bytes":
        request.source = b"revoked"
    assert request.scoped_invocation_source_8616(project) is None


def test_retained_request_source_mutation_revokes(world: tuple) -> None:
    """Mutating the retained receiver's own bytes revokes authority."""
    project, _, request, _ = world
    assert request.scoped_invocation_source_8616(project) is not None
    original = request.source
    request.source = b"revoked"
    try:
        assert request.scoped_invocation_source_8616(project) is None
        assert local_call_frame_evidence_8616(project) is None
    finally:
        request.source = original


def test_retained_premise_refuses_after_byte_revocation(world: tuple) -> None:
    """A derived premise refuses once its underlying bytes are revoked.

    The retained premise replays its whole chain per consumption and
    re-binds current native bytes, so mutating the callee surface it
    censused turns ``complete`` off — a stale retained scope is never
    served — and restoring the bytes restores the replay verdict.
    """
    project, evidence, _, entry = world
    assert _register_head(project, entry)
    pending = evidence.pending_targets[0]
    resolved = edcp._callee_artifact_and_boundary_8616(project, pending)
    assert resolved is not None
    artifact, boundary = resolved
    premise = edcp.entry_domain_invocation_premise_8616(
        project, artifact, boundary, pending
    )
    assert premise is not None and premise.complete
    original = project.loader.memory.load(pending, 1)
    project.loader.memory.store(pending, bytes([original[0] ^ 0xFF]))
    try:
        assert not premise.complete
    finally:
        project.loader.memory.store(pending, original)
    assert premise.complete


def test_request_without_seam_refuses(world: tuple) -> None:
    """An install-only record offers no scoped authority — never error."""
    project, _, request, _ = world

    class _InstallOnly:
        def install(self, project: object) -> object:
            return request.install(project)

    project._inertia_mz_static_invocation_request_8616 = _InstallOnly()
    assert edcp._scoped_invocation_source_8616(project) is None


def test_mistyped_seam_raises(world: tuple) -> None:
    """A non-callable scoped seam is a caller contract error, not a refusal."""
    project, _, request, _ = world

    class _Mistyped:
        def install(self, project: object) -> object:
            return request.install(project)

        scoped_invocation_source_8616 = "not a method"

    project._inertia_mz_static_invocation_request_8616 = _Mistyped()
    with pytest.raises(TypeError):
        edcp._scoped_invocation_source_8616(project)


def test_installed_world_never_scopes(tmp_path: Path) -> None:
    """A corpus that installs the global source mints no local authority."""
    small_mz = _build_mz(
        _build_image(
            (
                (BASE, _near_call(BASE, PENDING) + b"\xc3"),
                (PENDING, PENDING_CODE),
            )
        ),
        entry_ip=0,
    )
    project = _make_project(small_mz, tmp_path, BASE)
    try:
        receipt = install_mz_static_invocation_source_8616(project, small_mz)
        assert receipt.status is MzStaticIntakeStatus8616.INSTALLED
        request = _request(project)
        assert request.scoped_invocation_source_8616(project) is None
        assert _raw_source(project) is not None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


def test_global_refusal_stays_visible(world: tuple) -> None:
    """Scoped consumption never relabels the refused inventory or its debts."""
    project, evidence, request, _ = world
    scoped = request.scoped_invocation_source_8616(project)
    assert scoped is not None
    receipt = getattr(
        project, "_inertia_mz_static_invocation_install_8616", None
    )
    inventory = receipt.inventory
    assert inventory is not None
    assert inventory.status is InvocationInventoryStatus8616.BUDGET_BOUNDARIES
    assert not inventory.caller_evidence_ready
    assert scoped.pending_targets == inventory.pending_targets
    assert evidence.stats.closed
    assert _raw_source(project) is None


def _sortd_world() -> tuple:
    """Build the real SORTD project; install must stay budget-refused."""
    project = _build_project(
        SORTD_EXE, force_blob=False, base_addr=0x10000, entry_point=0x1000
    )
    request = getattr(project, "_inertia_mz_static_invocation_request_8616", None)
    assert type(request) is MzStaticIntakeRequest8616
    receipt = request.install(project)
    assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    inventory = receipt.inventory
    assert inventory is not None
    assert inventory.status is InvocationInventoryStatus8616.BUDGET_BOUNDARIES
    local = local_call_frame_evidence_8616(project)
    assert type(local) is LocalCallFrameEvidence8616
    return project, local, request


def _index_rows(index: object) -> list:
    """Enumerate every decoded near-call row in the retained index."""
    rows = [
        row
        for group in index._entries_by_normalized_target.values()
        for row in group
        if not row.is_far
    ]
    return sorted(rows, key=lambda row: (row.caller_start, row.callsite_addr))


def test_sortd_native_scoped_source_authenticates() -> None:
    """Native bytes: scoped mint binds the real MZ boot and closed census."""
    project, local, request = _sortd_world()
    scoped = request.scoped_invocation_source_8616(project)
    assert type(scoped) is edcp.Real16InvocationSource8616
    assert scoped.boot.entry.linear() == local.entry_linear == 0x10F9A
    assert scoped.boot.image.file_sha256 == local.source_sha256
    assert recompute_mz_static_boot_8616(scoped.boot) == scoped.boot
    assert scoped.callsite_index is local.callsite_index
    assert scoped.pending_targets == local.pending_targets
    assert _raw_source(project) is None


def test_sortd_exact_initbars_chain_documents_earliest_contract() -> None:
    """Native bytes: the exact assigned chain reports its earliest refusal.

    The requested route is ``boot 0x10f9a → caller 0x10010 → CALL 0x10566
    → 0x11222``. The decoded index retains the two transporting rows —
    ``entry@0x1104a → 0x10010`` and ``0x10010@0x10042 → 0x10560`` — and
    the scoped record mints over the identical bytes. But the entry
    surface's census cannot close: its first interior call boundary is
    ``int 21h`` at ``0x10f9c``, where the integrated declared-service
    census proves ``AH=0x30`` but the static header boot seeds no ``AL``
    — the declared-service route refuses ``declared_service_unproven``
    and every chained leg behind it stays premise-less. The assertion is
    the typed refusal, not a nearby easier callee.
    """
    project, local, request = _sortd_world()
    scoped = request.scoped_invocation_source_8616(project)
    assert scoped is not None
    entry = local.entry_linear
    index = scoped.callsite_index
    # The exact assigned edges exist as decoded rows.
    caller_rows = index.for_target(0x10010)
    assert [
        (row.caller_start, row.callsite_addr) for row in caller_rows
    ] == [(entry, 0x1104A)]
    initbars_rows = index.for_target(0x10560)
    assert [
        (row.caller_start, row.callsite_addr) for row in initbars_rows
    ] == [(0x10010, 0x10042)]
    assert any(
        row.caller_start == 0x10560 and row.callsite_addr == 0x10566
        for row in index.for_target(0x11222)
    )
    assert 0x11222 in scoped.pending_targets
    # The entry head imports and registers cleanly.
    assert _register_head(project, entry)
    boundary = mapped_entry_function_boundary_8616(project, entry)
    publication = edcp.registered_function_ir_artifact_8616(project, entry)
    artifact = publication.artifact
    assert artifact is not None
    coverage = edcp.prove_ir_boundary_coverage_8616(
        project, boundary, artifact
    )
    assert coverage.complete
    # The earliest leg — the boot-rooted domain over the entry surface
    # at the edge into 0x10010 — refuses its typed contract.
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        0x1104A,
        boot=scoped.boot,
        boot_recompute=scoped.boot_recompute,
    )
    assert not leg.complete
    assert leg.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    # The surface's first interior call is ``int 21h`` at 0x10f9c — the
    # boundary with no record producer; the decoded index has no row
    # for it, confirming the census refused before any near callsite.
    first_call = next(
        instruction
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL"
    )
    assert first_call.addr == 0x10F9C
    assert project.loader.memory.load(0x10F9C, 2) == b"\xcd\x21"
    # The unchanged premise consumer keeps the same refusal.
    resolution = edcp._PremiseResolution8616()
    parent = edcp._registered_invocation_premise_8616(
        project, entry, 0x1104A, scoped, resolution
    )
    assert parent is None
    assert _raw_source(project) is None


def test_sortd_native_foreign_and_stale_revoke() -> None:
    """Native controls: foreign request bytes and mutated image revoke."""
    project, local, request = _sortd_world()
    entry = local.entry_linear
    # A retained request carrying different bytes revokes the evidence
    # and offers no scoped authority.
    project._inertia_mz_static_invocation_request_8616 = (
        MzStaticIntakeRequest8616(source=b"MZforeign" + b"\x00" * 64)
    )
    assert _request(project).scoped_invocation_source_8616(project) is None
    assert local_call_frame_evidence_8616(project) is None
    assert _raw_source(project) is None
    # Restoring the authentic request and re-installing re-collects the
    # refused census; mutated native bytes then revoke it again.
    project._inertia_mz_static_invocation_request_8616 = request
    receipt = request.install(project)
    assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    assert local_call_frame_evidence_8616(project) is not None
    original = project.loader.memory.load(entry, 1)
    project.loader.memory.store(entry, bytes([original[0] ^ 0xFF]))
    try:
        assert request.scoped_invocation_source_8616(project) is None
        assert local_call_frame_evidence_8616(project) is None
    finally:
        project.loader.memory.store(entry, original)
    assert _raw_source(project) is None
