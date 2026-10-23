"""Genuine-MZ raw-boot -> direct near-CALL callee transport regression.

Fixture provenance: `_mz`, `_recompute` and `_world` mirror the private
helpers in `tests/ir/test_x86_16_boot_entry_link.py`. They yield a real MZ
whose boot root 0x10000 holds a pending JMP to 0x10010, where `e8 10 00` is
a direct near CALL to 0x10023 followed by `c3`; the callee at 0x10023 is a
single `c3`.

Obligation: a complete raw-boot parent premise (`coverage is None` by the
`RAW_BOOT_ENTRY_PATH` contract) transports across the exact decoded
near-CALL edge into the callee entry domain. The retained census surface
is named by `_retained_parent_census_surface_8616` from the parent's
retained `RawBootEntrySurface8616` — never manufactured coverage. Refusal
controls pin every leg that must still fail.
"""
from __future__ import annotations

import io

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    build_boundary_direct_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from inertia.ir import entry_domain_call_preservation as owner
from inertia.ir import real16_invocation_domain as domain
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    registered_function_ir_artifact_8616,
)
from inertia.ir.real16_boot_entry_link import (
    RawBootEntrySurface8616,
    raw_boot_entry_surface_pending_8616,
)
from inertia.ir.real16_invocation_domain import (
    prove_real16_raw_boot_invocation_domain_8616,
    real16_native_census_import_8616,
)
from inertia.lowering.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler

BOOT_HEAD = 0x10000
BOOT_END = 0x10014
PENDING_JMP_DISP = BOOT_HEAD + 1
CALLSITE = 0x10010
CALL_REGION_HEAD = 0x10010
CALL_REGION_END = 0x10014
CALLEE = 0x10023
CALLEE_END = 0x10024


def _mz(image: bytes) -> bytes:
    """Build a source-bound MZ with an initialized stack disjoint from code."""
    header = bytearray(32)
    header[:2] = b"MZ"
    values = {2: (32 + len(image)) % 512, 4: (32 + len(image) + 511) // 512,
              8: 2, 10: 0x10, 12: 0x20, 14: 0x10, 16: 0x100, 24: 0x1c}
    for offset, value in values.items():
        header[offset:offset + 2] = value.to_bytes(2, "little")
    return bytes(header) + image


def _recompute(boot: object) -> object:
    """Reconstruct source authority without borrowing its derived entry."""
    return program_from_mz_bytes(boot.source, boot.environment, code_ranges=boot.image.code_ranges)


def _world(prefix: bytes = bytes.fromhex("eb0e")) -> tuple:
    """Retain genuine bytes, frontend census and raw native IR."""
    from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment
    image = prefix + bytes.fromhex("90") * (16 - len(prefix)) + bytes.fromhex("e81000c3") + bytes(0x23-0x14) + bytes.fromhex("c3")
    environment = ProgramEnvironment(psp_segment=0xff0, allocation=bytes(0x300),
        registers=tuple((name, 0) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags")), fs=0, gs=0)
    boot = program_from_mz_bytes(_mz(image), environment, code_ranges=(LinearRange(0x10000, len(prefix)), LinearRange(0x10010, 4), LinearRange(0x10023, 1)))
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(io.BytesIO(boot.image.chunks[0][1]), main_opts={"backend":"blob", "arch":arch, "base_addr":0x10000, "entry_point":0x10000}, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project,0x10000,0x10014)
    assert boundary is not None
    raw = real16_native_census_import_8616(project,boundary)
    assert raw is not None
    return project, boundary, raw, boot


def _ret_only_world() -> tuple:
    """A refusal-free boot head: the entry surface is a bare RET."""
    from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment
    image = bytes.fromhex("c3")
    environment = ProgramEnvironment(psp_segment=0xff0, allocation=bytes(0x300),
        registers=tuple((name, 0) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags")), fs=0, gs=0)
    boot = program_from_mz_bytes(_mz(image), environment, code_ranges=(LinearRange(BOOT_HEAD, 1),))
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(io.BytesIO(boot.image.chunks[0][1]), main_opts={"backend":"blob", "arch":arch, "base_addr":0x10000, "entry_point":0x10000}, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, BOOT_HEAD, BOOT_HEAD + 1)
    assert boundary is not None
    return project, boundary, boot


def _resolver(project: object):
    """Bind the public direct-call decoder to one loaded image."""
    return lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction)


def _install(project: object, boot: object, index: object) -> object:
    """Install the typed retained source on the project and return it."""
    source = owner.Real16InvocationSource8616(boot, _recompute, index)
    owner.install_real16_invocation_source_8616(project, source)
    return source


def _bind_boot_boundary(monkeypatch: pytest.MonkeyPatch, project: object, boundary: object) -> None:
    """Bind only the exact boot-boundary lookup seam for this project."""
    monkeypatch.setattr(
        owner,
        "_exact_boundary_for_8616",
        lambda current, head: boundary if current is project and head == BOOT_HEAD else None,
    )


def _surface(project: object, head: int, end: int) -> tuple:
    """Return (boundary, raw artifact) for one exact decoded range."""
    boundary = exact_function_range_boundary_8616(project, head, end)
    assert boundary is not None
    raw = real16_native_census_import_8616(project, boundary)
    assert raw is not None
    return boundary, raw


def _prove_boot(project: object, boundary: object, raw: object, boot: object):
    """Run the raw-boot premise proof over the retained authentic surface."""
    return prove_real16_raw_boot_invocation_domain_8616(
        project, RawBootEntrySurface8616(raw, boundary), CALLSITE,
        boot=boot, boot_recompute=_recompute,
    )


def test_raw_boot_direct_call_transports_to_exact_callee_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A complete raw-boot parent transports over the exact CALL edge."""
    project, boundary, raw, boot = _world()
    callee_boundary, callee_raw = _surface(project, CALLEE, CALLEE_END)
    assert callee_raw.function_addr == CALLEE

    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=_resolver(project)
    )
    rows = index.for_target(CALLEE)
    assert len(rows) == 1
    assert rows[0].caller_start == BOOT_HEAD and rows[0].callsite_addr == CALLSITE

    # The boot surface carries a genuine pending-selector refusal pool.
    assert raw_boot_entry_surface_pending_8616(RawBootEntrySurface8616(raw, boundary))

    source = _install(project, boot, index)
    _bind_boot_boundary(monkeypatch, project, boundary)

    parent = owner._registered_invocation_premise_8616(
        project, BOOT_HEAD, CALLSITE, source, owner._PremiseResolution8616()
    )
    assert parent is not None
    assert parent.complete
    assert parent.coverage is None
    assert parent.kind is domain.Real16InvocationKind8616.RAW_BOOT_ENTRY_PATH
    assert parent.callsite_call_state

    premise = owner.entry_domain_invocation_premise_8616(
        project, callee_raw, callee_boundary, CALLEE
    )
    assert premise is not None
    assert premise.complete
    assert premise.callsite_addr == CALLEE
    assert premise.kind is domain.Real16InvocationKind8616.CALL_CHAINED
    # The in-flight callee has no registry coverage; the retained chain binds
    # the identical surfaces instead.
    assert premise.coverage is None
    chain = premise.chain
    assert type(chain) is domain.Real16CallChainLink8616
    assert chain.parent.complete
    assert chain.parent.kind is domain.Real16InvocationKind8616.RAW_BOOT_ENTRY_PATH
    assert type(chain.parent.chain) is RawBootEntrySurface8616
    assert chain.callsite_boundary is boundary
    assert chain.callsite_artifact.function_addr == BOOT_HEAD
    assert chain.callee_artifact is callee_raw
    assert chain.callee_boundary is callee_boundary
    assert chain.complete
    # The retained surface accessor names the raw-boot parent's identical
    # census pair — the boundary object is the seam-bound one.
    parent_surface = domain._retained_parent_census_surface_8616(chain.parent)
    assert parent_surface is not None
    assert parent_surface[0].function_addr == BOOT_HEAD
    assert parent_surface[1] is boundary
    # A coverage-free chained premise retains the callee surface its link
    # reached — the identical artifact/boundary the chain binds.
    chained_surface = domain._retained_parent_census_surface_8616(premise)
    assert chained_surface is not None
    assert chained_surface[0] is callee_raw
    assert chained_surface[1] is callee_boundary


def test_transport_attempt_never_publishes_raw_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The transport demand must keep raw surfaces out of the IR registry."""
    project, boundary, _raw, boot = _world()
    callee_boundary, callee_raw = _surface(project, CALLEE, CALLEE_END)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=_resolver(project)
    )
    _install(project, boot, index)
    _bind_boot_boundary(monkeypatch, project, boundary)
    premise = owner.entry_domain_invocation_premise_8616(
        project, callee_raw, callee_boundary, CALLEE
    )
    assert premise is not None and premise.complete
    for head in (BOOT_HEAD, CALL_REGION_HEAD, CALLEE):
        registered = registered_function_ir_artifact_8616(project, head)
        assert registered.verdict is not FunctionIRArtifactVerdict8616.PROVEN


def test_registered_boot_head_keeps_coverage_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal-free or registered boot head must not take the raw path."""
    project, boundary, boot = _ret_only_world()
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=_resolver(project)
    )
    source = _install(project, boot, index)
    _bind_boot_boundary(monkeypatch, project, boundary)
    artifact = real16_native_census_import_8616(project, boundary)
    assert artifact is not None

    # No pending-selector obligation exists: the raw bootstrap is ineligible
    # and the typed proof refuses it outright with an empty refusal pool.
    surface = RawBootEntrySurface8616(artifact, boundary)
    assert not raw_boot_entry_surface_pending_8616(surface)
    refused = prove_real16_raw_boot_invocation_domain_8616(
        project, surface, BOOT_HEAD, boot=boot, boot_recompute=_recompute
    )
    assert refused.failure is domain.Real16InvocationFailure8616.COVERAGE_UNBOUND
    assert not refused.complete

    # The ordinary route imports, publishes and covers the head instead.
    premise = owner._registered_invocation_premise_8616(
        project, BOOT_HEAD, BOOT_HEAD, source, owner._PremiseResolution8616()
    )
    assert premise is not None and premise.complete
    assert premise.coverage is not None
    assert premise.kind is domain.Real16InvocationKind8616.BOOT_ENTRY_PATH
    assert (
        registered_function_ir_artifact_8616(project, BOOT_HEAD).verdict
        is FunctionIRArtifactVerdict8616.PROVEN
    )

    # Against the now-registered head the raw bootstrap cannot shadow the
    # ordinary coverage route on a second resolution either.
    again = owner._registered_invocation_premise_8616(
        project, BOOT_HEAD, BOOT_HEAD, source, owner._PremiseResolution8616()
    )
    assert again is not None and again.complete
    assert again.coverage is not None
    assert again.kind is domain.Real16InvocationKind8616.BOOT_ENTRY_PATH


def test_transport_refuses_for_head_without_decoded_edge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A callee surface no decoded CALL row targets cannot earn a premise."""
    project, boundary, _raw, boot = _world()
    other_boundary, other_raw = _surface(project, CALL_REGION_HEAD, CALL_REGION_END)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=_resolver(project)
    )
    _install(project, boot, index)
    _bind_boot_boundary(monkeypatch, project, boundary)
    premise = owner.entry_domain_invocation_premise_8616(
        project, other_raw, other_boundary, CALL_REGION_HEAD
    )
    assert premise is None


def test_transport_refuses_under_different_caller_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An index rooted at a different caller boundary cannot transport."""
    project, boundary, _raw, boot = _world()
    callee_boundary, callee_raw = _surface(project, CALLEE, CALLEE_END)
    alt_boundary = exact_function_range_boundary_8616(
        project, CALL_REGION_HEAD, CALL_REGION_END
    )
    assert alt_boundary is not None
    alt_index = build_boundary_direct_callsite_index_8616(
        alt_boundary, direct_target_resolver=_resolver(project)
    )
    rows = alt_index.for_target(CALLEE)
    assert len(rows) == 1
    assert rows[0].caller_start == CALL_REGION_HEAD
    _install(project, boot, alt_index)
    _bind_boot_boundary(monkeypatch, project, boundary)
    premise = owner.entry_domain_invocation_premise_8616(
        project, callee_raw, callee_boundary, CALLEE
    )
    assert premise is None


def test_transport_refuses_after_callsite_byte_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bytes mutated under the captured CS cannot keep any premise alive."""
    project, boundary, raw, boot = _world()
    callee_boundary, callee_raw = _surface(project, CALLEE, CALLEE_END)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=_resolver(project)
    )
    _install(project, boot, index)
    _bind_boot_boundary(monkeypatch, project, boundary)
    project.loader.memory.store(CALLSITE, bytes.fromhex("90"))
    assert not _prove_boot(project, boundary, raw, boot).complete
    premise = owner.entry_domain_invocation_premise_8616(
        project, callee_raw, callee_boundary, CALLEE
    )
    assert premise is None


def test_transport_refuses_after_pending_successor_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mutated pending JMP displacement must refuse even when it still
    reaches the same CALL.

    ``eb 0d`` lands on the last NOP before the CALL region: the mutated path
    still reaches 0x10010, so reachability alone cannot distinguish it. The
    census byte binding must compare live loader bytes to the boot source
    and the decoded machine bytes — the retained source is unchanged while
    the loaded image mutated, so the premise must refuse.
    """
    project, boundary, raw, boot = _world()
    callee_boundary, callee_raw = _surface(project, CALLEE, CALLEE_END)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=_resolver(project)
    )
    _install(project, boot, index)
    _bind_boot_boundary(monkeypatch, project, boundary)
    project.loader.memory.store(PENDING_JMP_DISP, bytes.fromhex("0d"))
    assert not _prove_boot(project, boundary, raw, boot).complete
    premise = owner.entry_domain_invocation_premise_8616(
        project, callee_raw, callee_boundary, CALLEE
    )
    assert premise is None


def test_transport_refuses_when_pending_successor_skips_callsite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pending JMP redirected past the CALL makes the callsite unreachable."""
    project, boundary, raw, boot = _world()
    callee_boundary, callee_raw = _surface(project, CALLEE, CALLEE_END)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=_resolver(project)
    )
    _install(project, boot, index)
    _bind_boot_boundary(monkeypatch, project, boundary)
    # eb 11: jump from 0x10000 to the RET at 0x10013, skipping the CALL.
    project.loader.memory.store(PENDING_JMP_DISP, bytes.fromhex("11"))
    assert not _prove_boot(project, boundary, raw, boot).complete
    premise = owner.entry_domain_invocation_premise_8616(
        project, callee_raw, callee_boundary, CALLEE
    )
    assert premise is None


def test_transport_refuses_for_foreign_project_and_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A foreign project cannot spend this source, index, or boundary seam."""
    project, boundary, _raw, boot = _world()
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=_resolver(project)
    )
    _install(project, boot, index)
    _bind_boot_boundary(monkeypatch, project, boundary)

    foreign, foreign_boundary, _, foreign_boot = _world()
    foreign_callee_boundary, foreign_callee_raw = _surface(
        foreign, CALLEE, CALLEE_END
    )
    assert (
        owner.entry_domain_invocation_premise_8616(
            foreign, foreign_callee_raw, foreign_callee_boundary, CALLEE
        )
        is None
    )

    foreign_index = build_boundary_direct_callsite_index_8616(
        foreign_boundary, direct_target_resolver=_resolver(foreign)
    )
    _install(foreign, foreign_boot, foreign_index)
    assert (
        owner.entry_domain_invocation_premise_8616(
            foreign, foreign_callee_raw, foreign_callee_boundary, CALLEE
        )
        is None
    )
