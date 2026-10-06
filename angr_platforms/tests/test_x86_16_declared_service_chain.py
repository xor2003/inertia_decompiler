"""Declared interrupt-service propagation through retained source authority.

When the bounded entry-rooted caller inventory refuses under an unchanged
budget, the deferred-intake record can mint dependency-local scoped
authority over the closed caller census. These controls prove that
caller-declared environment evidence — a ``ProgramBoot`` over the
identical retained MZ bytes plus ``DeclaredInterruptService8616``
relations minted by the canonical dosunit adapter — binds into that
scoped source, propagates into recursive premise census derivations, and
lets an interior ``int 21h`` boundary cross only under the declared
contract. Every refusal channel — absent, foreign, stale, forged, or
mistyped declared evidence — stays refused, and the global inventory
verdict remains ``BUDGET_BOUNDARIES``.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import angr
import pytest
from angr_platforms.X86_16.frontend_function_boundary import (
    mapped_entry_function_boundary_8616,
)
from angr_platforms.X86_16.frontend_invocation_inventory import (
    InvocationInventoryStatus8616,
)
from angr_platforms.X86_16.frontend_local_call_evidence import (
    LocalCallFrameEvidence8616,
    install_local_call_frame_evidence_8616,
    local_call_frame_evidence_8616,
)
from angr_platforms.X86_16.ir import entry_domain_call_preservation as edcp
from angr_platforms.X86_16.ir.real16_invocation_domain import (
    Real16InvocationFailure8616,
    Real16InvocationKind8616,
    prove_real16_invocation_domain_8616,
)
from angr_platforms.X86_16.ir.vex_import import (
    build_x86_16_ir_function_artifact,
)
from angr_platforms.X86_16.mz_static_boot import recompute_mz_static_boot_8616

from inertia_decompiler.mz_static_intake import (
    MzStaticIntakeRequest8616,
    MzStaticIntakeStatus8616,
)
from inertia_decompiler.project_loading import _build_project
from tools.dosunit.real16_declared_invocation8616 import (
    declared_int21_version_service_8616,
)
from tools.dosunit.real16_program_boot import (
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.real16_program_memory import InitialMemoryRegion
from tools.dosunit.real16_program_vectors import VectorPolicy, vector_bytes
from tools.dosunit.real16_program_version import VersionPolicy
from tools.dosunit.real16_replay_model import SegOffset

LOAD_SEGMENT = 0x1000
BASE = LOAD_SEGMENT << 4
PSP = LOAD_SEGMENT - 0x10
DOS_ENTRY = SegOffset(0xF000, 0xF100)

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


INT21_ADDR = BASE + 2  # mov ah,0x30 (2 bytes) then int 21h (2 bytes)
FIRST_CALL = BASE + 4


def _big_fixture_mz() -> tuple[bytes, int, int]:
    """Entry does ``mov ah,30h; int 21h`` then near-calls over budget.

    The interior ``int 21h`` sits before the first near call so a
    boot-rooted census to any edge must cross it; the 66 extra leaf calls
    exhaust the unchanged ``max_boundaries=64`` inventory while the
    entry caller surface itself stays closed.
    """
    calls = _near_call(FIRST_CALL, PENDING)
    offset = 4 + len(calls)
    leaves = tuple(LEAF_BASE + 0x10 * index for index in range(66))
    for leaf in leaves:
        calls += _near_call(BASE + offset, leaf)
        offset += 3
    entry_code = b"\xb4\x30\xcd\x21" + calls + b"\xc3"
    islands = [(BASE, entry_code), (PENDING, PENDING_CODE)]
    islands.extend((leaf, b"\xc3") for leaf in leaves)
    image = _build_image(tuple(islands))
    return _build_mz(image, entry_ip=0), PENDING, BASE


def _small_fixture_mz() -> tuple[bytes, int]:
    """A closable corpus: entry does int 21h then one near call."""
    entry_code = b"\xb4\x30\xcd\x21" + _near_call(FIRST_CALL, PENDING) + b"\xc3"
    image = _build_image(((BASE, entry_code), (PENDING, PENDING_CODE)))
    return _build_mz(image, entry_ip=0), BASE


def _ivt() -> bytes:
    """Live IVT page whose 0x21 slot points at the declared DOS entry."""
    table = bytearray(0x400)
    table[0x84:0x88] = vector_bytes(DOS_ENTRY)
    return bytes(table)


def _env(mz: bytes, *, major: int = 5, eax: int = 0) -> ProgramEnvironment:
    """A declared environment sized to the fixture's header grant.

    The arena must hold the PSP, the paragraph-rounded module, the
    declared minalloc, *and* the header stack top: SS is fixed at 0x10
    paragraphs above the load segment and SP at 0x100 in ``_build_mz``,
    so the smallest legal arena reaches the stack top even for a tiny
    image.
    """
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
            (name, eax if name == "eax" else 0)
            for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
                "esp", "eflags",
            )
        ),
        fs=0,
        gs=0,
        version_policy=VersionPolicy(major=major, minor=0, oem=0, serial=0),
        vector_policy=VectorPolicy(DOS_ENTRY),
        extra_memory=(InitialMemoryRegion(SegOffset(0, 0), _ivt()),),
    )


def _declared_boot(mz: bytes, env: ProgramEnvironment) -> object:
    """Derive the canonical declared boot over the fixture bytes."""
    return program_from_mz_bytes(mz, env)


def _boot_recompute(boot: object) -> object:
    """Recompute authority mirroring the declared boot's construction."""
    image = boot.image  # type: ignore[attr-defined]
    ranges = () if image.code_scope == "whole_image" else image.code_ranges
    return program_from_mz_bytes(
        boot.source, boot.environment, code_ranges=ranges  # type: ignore[attr-defined]
    )


def _declared_fields(mz: bytes, *, major: int = 5) -> dict[str, object]:
    """Mint the declared boot plus the INT21 relation for the fixture."""
    env = _env(mz, major=major)
    boot = _declared_boot(mz, env)
    relation = declared_int21_version_service_8616(
        env, caller_addr=BASE, callsite_addr=INT21_ADDR
    )
    assert type(relation).__name__ == "DeclaredInterruptService8616"
    return {
        "declared_boot": boot,
        "declared_boot_recompute": _boot_recompute,
        "declared_services": (relation,),
    }


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


def _world(
    tmp_path: Path,
    *,
    declared: dict[str, object] | None,
) -> tuple[angr.Project, LocalCallFrameEvidence8616, MzStaticIntakeRequest8616, int]:
    """Install under the unchanged budget; keep the deferred request."""
    mz, pending, entry = _big_fixture_mz()
    project = _make_project(mz, tmp_path, entry)
    request = _request(project)
    if declared is not None:
        request.declared_boot = declared["declared_boot"]
        request.declared_boot_recompute = declared["declared_boot_recompute"]
        request.declared_services = declared["declared_services"]
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
    return project, evidence, request, entry


@pytest.fixture()
def declared_world(tmp_path: Path) -> tuple:
    """Yield the refused-inventory project with declared evidence bound."""
    mz, _, entry = _big_fixture_mz()
    declared = _declared_fields(mz)
    project, evidence, request, _ = _world(tmp_path, declared=declared)
    try:
        yield project, evidence, request, entry
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


@pytest.fixture()
def bare_world(tmp_path: Path) -> tuple:
    """Yield the refused-inventory project without any declared evidence."""
    project, evidence, request, entry = _world(tmp_path, declared=None)
    try:
        yield project, evidence, request, entry
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


def _register_head(project: angr.Project, head_addr: int) -> bool:
    """Import and publish one closed caller surface when refusal-free."""
    boundary = mapped_entry_function_boundary_8616(project, head_addr)
    if boundary is None or boundary.addr != head_addr:
        return False
    raw = build_x86_16_ir_function_artifact(project, boundary)
    if raw.refusals:
        return False
    publication = edcp.publish_function_ir_artifact_8616(project, raw)
    return publication.artifact is not None


def _leaf_premise(
    project: angr.Project, head: int
) -> object | None:
    """Demand the caller-domain premise for one callee head."""
    resolved = edcp._callee_artifact_and_boundary_8616(project, head)
    if resolved is None:
        return None
    artifact, boundary = resolved
    return edcp.entry_domain_invocation_premise_8616(
        project, artifact, boundary, head
    )


def test_declared_scoped_source_binds_environment(declared_world: tuple) -> None:
    """The scoped mint binds the declared boot and its relation tuple."""
    project, evidence, request, entry = declared_world
    scoped = request.scoped_invocation_source_8616(project)
    assert type(scoped) is edcp.Real16InvocationSource8616
    # The bound boot is the declared ProgramBoot over the identical
    # retained bytes, not the static header boot.
    assert scoped.boot is request.declared_boot
    assert scoped.boot.entry.linear() == entry
    assert len(scoped.declared_services) == 1
    relation = scoped.declared_services[0]
    assert relation.callsite_addr == INT21_ADDR
    assert relation.caller_addr == entry
    assert scoped.callsite_index is evidence.callsite_index
    assert scoped.pending_targets == evidence.pending_targets
    # Memoized identity: derived premises share one boot object.
    assert request.scoped_invocation_source_8616(project) is scoped
    assert _raw_source(project) is None


def test_declared_premise_crosses_interrupt(declared_world: tuple) -> None:
    """A declared relation lets the boot census cross int 21h to the edge."""
    project, evidence, request, entry = declared_world
    assert request.scoped_invocation_source_8616(project) is not None
    assert _register_head(project, entry)
    premise = _leaf_premise(project, evidence.pending_targets[0])
    assert premise is not None
    assert premise.complete
    assert premise.kind is Real16InvocationKind8616.CALL_CHAINED
    assert premise.chain.callsite.callsite_addr == FIRST_CALL
    # The declared consumption rides on the retained parent premise —
    # it is the parent census that crossed the interior ``int 21h``.
    assert premise.chain.parent.service_consumptions
    consumption = premise.chain.parent.service_consumptions[0]
    assert consumption.callsite_addr == INT21_ADDR
    assert consumption.vector == 0x21
    # The global slot stays empty; the refused verdict is untouched.
    assert _raw_source(project) is None


def test_bare_request_still_refuses_interrupt(bare_world: tuple) -> None:
    """Without declaration the identical bytes keep the typed refusal."""
    project, evidence, request, entry = bare_world
    scoped = request.scoped_invocation_source_8616(project)
    assert scoped is not None
    assert scoped.declared_services == ()
    assert type(scoped.boot).__name__ == "MzStaticBoot8616"
    assert _register_head(project, entry)
    premise = _leaf_premise(project, evidence.pending_targets[0])
    assert premise is None
    # Direct proof under the static boot confirms the exact refusal.
    boundary = mapped_entry_function_boundary_8616(project, entry)
    publication = edcp.registered_function_ir_artifact_8616(project, entry)
    coverage = edcp.prove_ir_boundary_coverage_8616(
        project, boundary, publication.artifact
    )
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        FIRST_CALL,
        boot=scoped.boot,
        boot_recompute=scoped.boot_recompute,
    )
    # Static boot proves AH but no AL seed exists — the declared-service
    # route refuses on the unproven selector, not on a missing relation.
    assert leg.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_foreign_environment_relation_revokes(declared_world: tuple, tmp_path: Path) -> None:
    """A relation minted under a different environment cannot bind."""
    project, _, request, _ = declared_world
    mz, _, _ = _big_fixture_mz()
    foreign = _declared_fields(mz, major=6)
    request.declared_services = foreign["declared_services"]
    assert request.scoped_invocation_source_8616(project) is None
    # Restoring the authentic relation re-binds.
    request.declared_services = _declared_fields(mz)["declared_services"]
    assert request.scoped_invocation_source_8616(project) is not None


def test_declared_boot_over_foreign_bytes_revokes(declared_world: tuple) -> None:
    """A declared boot retaining different bytes cannot bind."""
    project, _, request, _ = declared_world
    foreign_mz = _build_mz(b"\x90" * 64, entry_ip=0)
    request.declared_boot = _declared_boot(foreign_mz, _env(foreign_mz))
    assert request.scoped_invocation_source_8616(project) is None


def test_orphaned_services_refuse(tmp_path: Path) -> None:
    """Services without a declared boot refuse at both mint paths."""
    mz, _, entry = _big_fixture_mz()
    declared = _declared_fields(mz)
    project = _make_project(mz, tmp_path, entry)
    request = _request(project)
    request.declared_services = declared["declared_services"]
    try:
        receipt = request.install(project)
        assert receipt.status is MzStaticIntakeStatus8616.DECLARED_REFUSED
        assert request.scoped_invocation_source_8616(project) is None
        assert _raw_source(project) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


def test_recompute_mismatch_refuses(tmp_path: Path) -> None:
    """A recompute authority that does not reproduce the boot refuses."""
    mz, _, entry = _big_fixture_mz()
    declared = _declared_fields(mz)
    project = _make_project(mz, tmp_path, entry)
    request = _request(project)
    request.declared_boot = declared["declared_boot"]
    request.declared_boot_recompute = lambda boot: _declared_boot(
        mz, _env(mz, major=6)
    )
    request.declared_services = declared["declared_services"]
    try:
        assert request.install(project).status is (
            MzStaticIntakeStatus8616.DECLARED_REFUSED
        )
        assert request.scoped_invocation_source_8616(project) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


def test_forged_relation_fields_refuse(declared_world: tuple) -> None:
    """A dataclasses.replace answer forgery keeps the census refusal."""
    project, _, request, entry = declared_world
    forged = dataclasses.replace(
        request.declared_services[0], answer_ax=0xBEEF
    )
    request.declared_services = (forged,)
    assert request.scoped_invocation_source_8616(project) is not None
    assert _register_head(project, entry)
    boundary = mapped_entry_function_boundary_8616(project, entry)
    publication = edcp.registered_function_ir_artifact_8616(project, entry)
    coverage = edcp.prove_ir_boundary_coverage_8616(
        project, boundary, publication.artifact
    )
    scoped = request.scoped_invocation_source_8616(project)
    leg = prove_real16_invocation_domain_8616(
        project,
        coverage,
        FIRST_CALL,
        boot=scoped.boot,
        boot_recompute=scoped.boot_recompute,
        declared_services=scoped.declared_services,
    )
    assert leg.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_declared_installed_path_binds(tmp_path: Path) -> None:
    """A closable corpus installs the declared source end-to-end."""
    mz, entry = _small_fixture_mz()
    declared = _declared_fields(mz)
    project = _make_project(mz, tmp_path, entry)
    request = _request(project)
    request.declared_boot = declared["declared_boot"]
    request.declared_boot_recompute = declared["declared_boot_recompute"]
    request.declared_services = declared["declared_services"]
    try:
        receipt = request.install(project)
        assert receipt.status is MzStaticIntakeStatus8616.INSTALLED
        source = _raw_source(project)
        assert source is not None
        assert source.boot is request.declared_boot
        assert len(source.declared_services) == 1
        # Scoped mint is never needed on an installed world.
        assert request.scoped_invocation_source_8616(project) is None
        assert _register_head(project, entry)
        premise = _leaf_premise(project, PENDING)
        assert premise is not None
        assert premise.complete
        assert premise.chain is not None
        assert premise.chain.parent.service_consumptions
        assert (
            premise.chain.parent.service_consumptions[0].callsite_addr
            == INT21_ADDR
        )
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


def test_bare_installed_path_unchanged(tmp_path: Path) -> None:
    """The same closable corpus without declaration installs statically."""
    mz, entry = _small_fixture_mz()
    project = _make_project(mz, tmp_path, entry)
    request = _request(project)
    try:
        receipt = request.install(project)
        assert receipt.status is MzStaticIntakeStatus8616.INSTALLED
        source = _raw_source(project)
        assert source is not None
        assert type(source.boot).__name__ == "MzStaticBoot8616"
        assert recompute_mz_static_boot_8616(source.boot) == source.boot
        assert source.declared_services == ()
        assert _register_head(project, entry)
        assert _leaf_premise(project, PENDING) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        install_local_call_frame_evidence_8616(project, None)


def test_declared_premise_revokes_with_bytes(declared_world: tuple) -> None:
    """Mutating native bytes revokes both authority and a derived premise."""
    project, evidence, request, entry = declared_world
    assert _register_head(project, entry)
    premise = _leaf_premise(project, evidence.pending_targets[0])
    assert premise is not None and premise.complete
    original = project.loader.memory.load(INT21_ADDR, 1)
    project.loader.memory.store(INT21_ADDR, bytes([original[0] ^ 0xFF]))
    try:
        assert request.scoped_invocation_source_8616(project) is None
        assert not premise.complete
    finally:
        project.loader.memory.store(INT21_ADDR, original)
    assert premise.complete


@pytest.mark.parametrize(
    "field,value",
    (
        ("declared_boot", object()),
        ("declared_boot_recompute", "not-callable"),
        ("declared_services", (object(),)),
    ),
)
def test_static_memo_revalidates_declaration(
    bare_world: tuple, field: str, value: object
) -> None:
    """A static memo hit must not serve once declaration fields break.

    Parent-reported controls: the minted static record is memoized, then
    a caller-mutable declared field is replaced by a malformed value;
    the next demand must re-admit the declaration before serving, so the
    stale memo refuses rather than outliving the change.
    """
    project, _, request, _ = bare_world
    scoped = request.scoped_invocation_source_8616(project)
    assert scoped is not None
    assert scoped.declared_services == ()
    setattr(request, field, value)
    assert request.scoped_invocation_source_8616(project) is None
    assert request.scoped_invocation_source_8616(project) is None


@pytest.mark.parametrize(
    "field,value",
    (
        ("declared_boot", object()),
        ("declared_boot_recompute", "not-callable"),
        ("declared_services", (object(),)),
    ),
)
def test_declared_memo_revalidates_declaration(
    declared_world: tuple, field: str, value: object
) -> None:
    """A declared memo hit must not serve a revoked or malformed field.

    The minted declared source is memoized under the identical evidence
    epoch; replacing any caller-mutable declared field with a malformed
    value revokes the memo — the demand re-runs declaration admission
    rather than serving the earlier declaration.
    """
    project, _, request, _ = declared_world
    scoped = request.scoped_invocation_source_8616(project)
    assert scoped is not None and scoped.declared_services
    setattr(request, field, value)
    assert request.scoped_invocation_source_8616(project) is None


def test_declared_memo_remints_valid_replacement(declared_world: tuple) -> None:
    """A valid replacement declaration mints a fresh provenance epoch.

    Replacing the declared environment with a different authentic
    declaration does not serve the stale memo: the demand mints a new
    scoped source bound to the replacement's own digest and relations —
    the minted old declaration never borrows the new policy's authority
    and the new mint never borrows the old's.
    """
    project, _, request, _ = declared_world
    scoped = request.scoped_invocation_source_8616(project)
    assert scoped is not None
    old_services = scoped.declared_services
    mz, _, _ = _big_fixture_mz()
    replacement = _declared_fields(mz, major=6)
    request.declared_boot = replacement["declared_boot"]
    request.declared_boot_recompute = replacement["declared_boot_recompute"]
    request.declared_services = replacement["declared_services"]
    reminted = request.scoped_invocation_source_8616(project)
    assert reminted is not None
    assert reminted is not scoped
    assert reminted.boot is request.declared_boot
    assert reminted.declared_services == request.declared_services
    assert reminted.declared_services != old_services
    # The stale record stays minted-but-revoked: the memo never returns it.
    assert request.scoped_invocation_source_8616(project) is reminted


def test_old_scope_obeyed_revocation_on_use(declared_world: tuple) -> None:
    """A previously returned scope cannot derive premises after revocation.

    The minted declared source derives a real chained premise; revoking
    the request's declared fields then makes every later premise demand
    re-admit the declaration through the seam — the seam refuses, the
    derived-premise path returns ``None``, and the previously returned
    source object is never consulted as authority.
    """
    project, evidence, request, entry = declared_world
    assert request.scoped_invocation_source_8616(project) is not None
    assert _register_head(project, entry)
    premise = _leaf_premise(project, evidence.pending_targets[0])
    assert premise is not None and premise.complete
    request.declared_services = (object(),)
    assert request.scoped_invocation_source_8616(project) is None
    assert _leaf_premise(project, evidence.pending_targets[0]) is None
    # Restoring authentic evidence re-mints under a new epoch: the
    # revocation cleared the retained census, so a fresh refused install
    # re-collects it before the declared mint can re-derive.
    mz, _, _ = _big_fixture_mz()
    request.declared_services = _declared_fields(mz)["declared_services"]
    receipt = request.install(project)
    assert receipt.status is MzStaticIntakeStatus8616.INVENTORY_REFUSED
    reminted = request.scoped_invocation_source_8616(project)
    assert reminted is not None
    assert reminted.declared_services == request.declared_services
    assert _leaf_premise(project, evidence.pending_targets[0]) is not None


def test_declared_memo_rebinds_recompute_authority(declared_world: tuple) -> None:
    """An equal boot cannot conceal replacement of its recompute authority."""
    project, _, request, _ = declared_world
    first = request.scoped_invocation_source_8616(project)
    assert first is not None
    original = request.declared_boot_recompute
    assert callable(original)

    def replacement(boot: object) -> object:
        return original(boot)

    request.declared_boot_recompute = replacement
    second = request.scoped_invocation_source_8616(project)
    assert second is not None and second is not first
    assert second.boot_recompute is replacement


def test_removed_declaration_remints_static(declared_world: tuple) -> None:
    """Removing the declaration remints the unchanged static contract.

    Clearing all declared fields is a revocation back to the bare world,
    not a refusal: the re-minted source binds the static header boot and
    the identical interior ``int 21h`` boundary refuses again — the
    declared authority never leaks into the static epoch.
    """
    project, evidence, request, entry = declared_world
    declared_scoped = request.scoped_invocation_source_8616(project)
    assert declared_scoped.declared_services
    request.declared_boot = None
    request.declared_boot_recompute = None
    request.declared_services = ()
    scoped = request.scoped_invocation_source_8616(project)
    assert scoped is not None
    assert scoped is not declared_scoped
    assert type(scoped.boot).__name__ == "MzStaticBoot8616"
    assert scoped.declared_services == ()
    assert _register_head(project, entry)
    assert _leaf_premise(project, evidence.pending_targets[0]) is None
