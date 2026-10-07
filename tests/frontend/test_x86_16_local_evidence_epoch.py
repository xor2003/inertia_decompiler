"""Local frame-evidence epoch retention across refused-intake demands.

Every refused-inventory demand re-runs the full bounded inventory and
re-collects the closed-caller census: retained project proof evidence can
change what is collected, so freshness is never skipped. When the fresh
record is value-identical in every compared field under the identical
project and decoding architecture, the retained
``LocalCallFrameEvidence8616`` object stays installed — the
scoped-authority memo's object-identity epoch then survives repeated
demands and derived entry scopes keep their boot/index/row identity so
``same_real16_entry_scope_8616`` and the nested-caller seam authenticate.

These controls exercise the production owners directly — no staged
install, no monkeypatching: epoch retention, wrong-context and
changed-census predicate rejection, changed recollection through the
real install path under an unchanged image, and byte revocation
followed by restoration minting a new epoch. Conditional/pending scope
stays explicit: the refused verdict, the unresolved discovered
obligations and the never-installed global source are asserted on every
demand.
"""

from __future__ import annotations

from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import cast

import angr
import pytest
import inertia.ir.entry_domain_call_preservation as edcp
from inertia.ir.real16_invocation_domain import (
    Real16InvocationDomain8616,
    Real16InvocationKind8616,
    same_real16_entry_scope_8616,
)
from inertia.ir.vex_import import (
    IRFunctionArtifact,
    build_x86_16_ir_function_artifact,
)

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedFarCallTarget8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    mapped_entry_function_boundary_8616,
)
from inertia.frontend.x86_16.frontend_invocation_inventory import (
    InvocationInventoryBudget8616,
    InvocationInventoryStatus8616,
)
from inertia.frontend.x86_16.frontend_local_call_evidence import (
    LocalCallFrameEvidence8616,
    install_local_call_frame_evidence_8616,
    local_call_frame_evidence_8616,
    local_call_frame_evidence_epoch_matches_8616,
)
from inertia.lowering.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from inertia.cli.mz_static_intake import (
    MzStaticIntakeRequest8616,
    MzStaticIntakeStatus8616,
    install_mz_static_invocation_source_8616,
)
from inertia.cli.project_loading import _build_project

LOAD_SEGMENT = 0x1000
BASE = LOAD_SEGMENT << 4

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
    """An entry plus 66 leaves and one pending callee — over 64 boundaries."""
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
    """Install under the unchanged budget; keep the deferred request."""
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


def _pending_premise(
    project: angr.Project, pending: int
) -> tuple[
    IRFunctionArtifact,
    ExactFunctionRangeBoundary8616,
    Real16InvocationDomain8616 | None,
]:
    """Derive the complete chained premise for the pending callee head."""
    resolved = edcp._callee_artifact_and_boundary_8616(project, pending)
    assert resolved is not None
    artifact, boundary = resolved
    premise = edcp.entry_domain_invocation_premise_8616(
        project, artifact, boundary, pending
    )
    return artifact, boundary, premise


def test_retained_epoch_preserves_required_entry_scope(
    world: tuple[angr.Project, LocalCallFrameEvidence8616, MzStaticIntakeRequest8616, int],
) -> None:
    """An identical recollection keeps the retained epoch object installed.

    The refused inventory still re-runs in full on every demand, but a
    value-identical recollection keeps the retained evidence object — so
    the scoped memo keeps serving one minted source, boot/index/row
    identity survives across demands, and a fresh premise derived over
    the identical resolved surface objects satisfies the otherwise
    identical required entry scope.
    """
    project, evidence, request, entry = world
    assert _register_head(project, entry)
    pending = evidence.pending_targets[0]
    artifact, boundary, premise1 = _pending_premise(project, pending)
    assert premise1 is not None and premise1.complete
    assert premise1.kind is Real16InvocationKind8616.CALL_CHAINED
    # Same resolved surface objects: the only variable is the epoch the
    # second demand mints or retains.
    premise2 = edcp.entry_domain_invocation_premise_8616(
        project, artifact, boundary, pending
    )
    assert premise2 is not None and premise2.complete
    # The epoch was retained, not replaced.
    assert local_call_frame_evidence_8616(project) is evidence
    assert premise2.boot is premise1.boot
    chain1, chain2 = premise1.chain, premise2.chain
    assert chain1 is not None and chain2 is not None
    assert chain2.callsite_index is chain1.callsite_index
    assert chain2.callsite is chain1.callsite
    # The required entry scope now authenticates across demands.
    assert same_real16_entry_scope_8616(premise2, premise1)
    # The memoized scoped mint also survives the demand.
    scoped = request.scoped_invocation_source_8616(project)
    assert scoped is request.scoped_invocation_source_8616(project)
    assert scoped is not None
    assert scoped.callsite_index is evidence.callsite_index
    # Nothing installs project-wide; the refusal stays visible and the
    # receipt binds the retained epoch object.
    assert _raw_source(project) is None
    receipt = request.install(project)
    assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    assert receipt.local_evidence is evidence


def test_retained_epoch_admits_scoped_nested_premise(
    world: tuple[angr.Project, LocalCallFrameEvidence8616, MzStaticIntakeRequest8616, int],
) -> None:
    """The nested-caller seam derives the matching premise under one epoch.

    ``_scoped_nested_premise_8616`` is the production seam a scoped caller
    census uses to derive a per-callsite premise sharing the consuming
    entry. Under epoch retention the freshly re-derived premise
    authenticates against the required scope derived under the previous
    demand instead of keeping its default refusal.
    """
    project, evidence, _, entry = world
    assert _register_head(project, entry)
    pending = evidence.pending_targets[0]
    artifact, boundary, scope = _pending_premise(project, pending)
    assert scope is not None and scope.complete
    coverage = edcp.prove_ir_boundary_coverage_8616(
        project, boundary, artifact
    )
    nested = edcp._scoped_nested_premise_8616(
        project, coverage, boundary, pending, scope
    )
    assert nested is not None
    assert nested.complete
    assert nested.callsite_addr == pending
    assert same_real16_entry_scope_8616(nested, scope)


def test_epoch_predicate_context_controls(
    world: tuple[angr.Project, LocalCallFrameEvidence8616, MzStaticIntakeRequest8616, int],
) -> None:
    """The epoch predicate refuses mistyped and foreign-context records.

    ``project`` and ``architecture`` are excluded from dataclass
    equality, so the predicate must reject a record that is value-equal
    in every compared field but minted under a different project object
    or decoding architecture — context identity is part of the epoch.
    """
    _, evidence, _, _ = world
    assert not local_call_frame_evidence_epoch_matches_8616(
        cast(LocalCallFrameEvidence8616, None),
        cast(LocalCallFrameEvidence8616, None),
    )
    assert not local_call_frame_evidence_epoch_matches_8616(
        cast(LocalCallFrameEvidence8616, "evidence"),
        cast(LocalCallFrameEvidence8616, "evidence"),
    )
    foreign_project = replace(evidence, project=object())
    foreign_architecture = replace(evidence, architecture=object())
    # Dataclass equality ignores the context fields; the predicate does not.
    assert foreign_project == evidence
    assert foreign_architecture == evidence
    assert not local_call_frame_evidence_epoch_matches_8616(
        foreign_project, evidence
    )
    assert not local_call_frame_evidence_epoch_matches_8616(
        foreign_architecture, evidence
    )
    assert local_call_frame_evidence_epoch_matches_8616(evidence, evidence)


def test_epoch_predicate_census_controls(
    world: tuple[angr.Project, LocalCallFrameEvidence8616, MzStaticIntakeRequest8616, int],
) -> None:
    """Any divergent compared field is conservatively a different epoch."""
    _, evidence, _, _ = world
    changed_pending = replace(evidence, pending_targets=())
    changed_stats = replace(
        evidence,
        stats=replace(
            evidence.stats,
            failure_count=evidence.stats.failure_count + 1,
        ),
    )
    changed_digest = replace(evidence, image_sha256="0" * 64)
    changed_heads = replace(evidence, boundary_heads=evidence.boundary_heads[1:])
    for divergent in (changed_pending, changed_stats, changed_digest, changed_heads):
        assert divergent != evidence
        assert not local_call_frame_evidence_epoch_matches_8616(
            divergent, evidence
        )


def test_changed_recollection_mints_new_epoch(
    world: tuple[angr.Project, LocalCallFrameEvidence8616, MzStaticIntakeRequest8616, int],
) -> None:
    """A recollection with changed proof prerequisites never interns.

    The module bytes never change here: the install demand runs under a
    different target resolver — the pending edge resolves to a closable
    leaf — then under a reduced boundary budget, so the fresh record's
    pending obligations and closed census diverge from the retained
    epoch. Each divergent recollection installs a new epoch object; the
    retained object is never revived. A later identical demand
    recollects a record value-identical to the original census, yet
    still mints a fresh object because the epoch chain was broken.
    """
    project, evidence, request, _ = world
    assert local_call_frame_evidence_epoch_matches_8616(evidence, evidence)

    real_resolver = partial(
        resolve_direct_call_target_from_instruction_8616, project
    )

    def shifted_resolver(
        instruction: object,
    ) -> int | DecodedFarCallTarget8616 | None:
        """Redirect only the pending edge to a closable leaf target."""
        target = real_resolver(instruction)
        return LEAF_BASE if target == PENDING else target

    receipt_shifted = install_mz_static_invocation_source_8616(
        project, request.source, direct_target_resolver=shifted_resolver
    )
    assert receipt_shifted.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    shifted = receipt_shifted.local_evidence
    assert type(shifted) is LocalCallFrameEvidence8616
    assert shifted is not evidence
    assert shifted.pending_targets != evidence.pending_targets
    assert not local_call_frame_evidence_epoch_matches_8616(
        evidence, shifted
    )
    assert local_call_frame_evidence_8616(project) is shifted

    reduced = InvocationInventoryBudget8616(
        max_boundaries=4,
        max_instructions=evidence.stats.materialized_count + 4096,
    )
    receipt_reduced = install_mz_static_invocation_source_8616(
        project, request.source, budget=reduced
    )
    assert receipt_reduced.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    narrowed = receipt_reduced.local_evidence
    assert type(narrowed) is LocalCallFrameEvidence8616
    assert narrowed is not shifted
    assert narrowed.boundary_heads != evidence.boundary_heads
    assert not local_call_frame_evidence_epoch_matches_8616(
        shifted, narrowed
    )

    # The epoch chain broke: even though the next default-resolution
    # recollection is value-identical to the original census, the
    # installed record diverged, so a new epoch object installs — the
    # stale retained object is never revived.
    receipt_restored = request.install(project)
    assert receipt_restored.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    restored = receipt_restored.local_evidence
    assert type(restored) is LocalCallFrameEvidence8616
    assert restored is not narrowed
    assert restored is not evidence
    assert local_call_frame_evidence_8616(project) is restored
    assert local_call_frame_evidence_epoch_matches_8616(restored, evidence)


def test_mutation_revokes_and_restore_mints_new_epoch(
    world: tuple[angr.Project, LocalCallFrameEvidence8616, MzStaticIntakeRequest8616, int],
) -> None:
    """Byte mutation revokes; restoring bytes mints a NEW epoch object.

    Interning never serves stale authority: mutating mapped bytes revokes
    the evidence and the scoped mint; restoring them and re-installing
    produces a new epoch — the revoked slot was cleared, so there is no
    retained epoch to intern against.
    """
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
    receipt = request.install(project)
    assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    reminted = request.scoped_invocation_source_8616(project)
    assert reminted is not None
    assert reminted is not scoped
    assert reminted.callsite_index is not scoped.callsite_index
    # Two identical demands after that still share the new epoch.
    receipt2 = request.install(project)
    assert receipt2.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    assert request.scoped_invocation_source_8616(project) is reminted
    assert local_call_frame_evidence_8616(project) is receipt2.local_evidence
