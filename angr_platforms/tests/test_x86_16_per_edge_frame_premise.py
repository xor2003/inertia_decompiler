"""Per-edge near-return frame-premise transport controls (staged slice M7-P2).

Real minimal MZ fixture: caller A (the MZ entry) and caller B each hold an
independently decoded near-CALL row targeting the same unregistered pending
callee. The project source-authenticated index therefore carries two rows
for one head — the shape that made the old head-unique premise selection
refuse ``CALLEE_UNRESOLVED``. Every control below drives the actual callee
resolution path: the independently authenticated decoded row for the edge
being resolved is transported into the premise-bound import, and only the
source-authenticated row agreeing on callsite, caller head, and target is
admitted. Raw ``E8`` byte scans are never used as evidence.
"""

from __future__ import annotations

from dataclasses import replace
from functools import partial
from pathlib import Path

import angr
import capstone
import pytest
from angr_platforms.X86_16 import frontend_function_boundary as boundary_mod
from angr_platforms.X86_16.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from angr_platforms.X86_16.frontend_caller_entry_identity import (
    caller_target_identity_8616,
)
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
    build_boundary_direct_callsite_index_8616,
    build_decoded_direct_callsite_index_8616,
)
from angr_platforms.X86_16.frontend_near_return_continuation import (
    NearCallFramePremise8616,
)
from angr_platforms.X86_16.ir import entry_domain_call_preservation as edcp
from angr_platforms.X86_16.ir import near_return_continuation_view as nrcv
from angr_platforms.X86_16.ir import vex_import
from angr_platforms.X86_16.ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    prove_ir_boundary_coverage_8616,
    prove_scoped_ir_boundary_coverage_8616,
)

from inertia_decompiler.project_loading import _build_project
from tools.dosunit.real16_program_boot import (
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.real16_replay_model import LinearRange

_PENDING_KIND = "near_return_continuation_pending"

# Multi-caller MZ layout: caller A is the MZ entry, caller B a second
# head; both decode a near CALL into the shared unregistered callee.
_MZ_SEGMENT = 0x1000
_MZ_BASE = _MZ_SEGMENT << 4
_MZ_CALLER_A = _MZ_BASE + 0x20
_MZ_CALLEE = _MZ_BASE + 0x60
_MZ_JMP_HEAD = _MZ_CALLEE + 7
_MZ_CALLER_B = _MZ_BASE + 0xA0

# pop cx; mov bx,sp; sub bx,ax; mov sp,bx; jmp cx — the blocker shape.
_MZ_CALLEE_CODE = bytes.fromhex("59 8B DC 2B D8 8B E3 FF E1")


def _near_call_bytes(callsite_addr: int, target_addr: int) -> bytes:
    """Encode one real near CALL rel16 targeting ``target_addr``."""
    return (
        b"\xe8"
        + ((target_addr - (callsite_addr + 3)) & 0xFFFF).to_bytes(2, "little")
    )


_MZ_CALLER_A_CODE = _near_call_bytes(_MZ_CALLER_A, _MZ_CALLEE) + b"\xc3"
_MZ_CALLER_B_CODE = _near_call_bytes(_MZ_CALLER_B, _MZ_CALLEE) + b"\xc3"
_MZ_CALLER_A_CALLSITE = _MZ_CALLER_A
_MZ_CALLER_B_CALLSITE = _MZ_CALLER_B
_MZ_RANGES = (
    LinearRange(_MZ_CALLER_A, len(_MZ_CALLER_A_CODE)),
    LinearRange(_MZ_CALLEE, len(_MZ_CALLEE_CODE)),
    LinearRange(_MZ_CALLER_B, len(_MZ_CALLER_B_CODE)),
)


def _mz_image() -> bytes:
    """Lay out both callers and the callee inside one module image."""
    image = b""
    cursor = _MZ_BASE
    for address, code in (
        (_MZ_CALLER_A, _MZ_CALLER_A_CODE),
        (_MZ_CALLEE, _MZ_CALLEE_CODE),
        (_MZ_CALLER_B, _MZ_CALLER_B_CODE),
    ):
        assert address >= cursor
        image += bytes(address - cursor) + code
        cursor = address + len(code)
    return image


def _mz_exe(image: bytes, entry_ip: int) -> bytes:
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
    header[0x0A:0x0C] = (0x00).to_bytes(2, "little")
    header[0x0C:0x0E] = (0x40).to_bytes(2, "little")
    header[0x0E:0x10] = (0x10).to_bytes(2, "little")
    header[0x10:0x12] = (0x100).to_bytes(2, "little")
    header[0x14:0x16] = entry_ip.to_bytes(2, "little")
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    return bytes(header) + image


def _mz_boot_recompute(boot: object) -> object:
    """Recompute an equal boot object from the retained source bytes."""
    return program_from_mz_bytes(
        boot.source, boot.environment, code_ranges=boot.image.code_ranges
    )


def _mz_resolver(project: angr.Project) -> object:
    """Return the shared decoded direct-target resolver for one project."""
    return partial(resolve_direct_call_target_from_instruction_8616, project)


def _mz_world(tmp_path: Path) -> tuple[object, angr.Project]:
    """Build the authentic ProgramBoot and project for the MZ fixture."""
    image = _mz_image()
    mz = _mz_exe(image, _MZ_CALLER_A - _MZ_BASE)
    env = ProgramEnvironment(
        psp_segment=_MZ_SEGMENT - 0x10,
        allocation=bytes(0x400),
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
    boot = program_from_mz_bytes(mz, env, code_ranges=_MZ_RANGES)
    fixture = tmp_path / "near_return_multi_caller.exe"
    fixture.write_bytes(mz)
    project = _build_project(
        fixture, force_blob=False, base_addr=_MZ_BASE,
        entry_point=_MZ_CALLER_A,
    )
    return boot, project


def _boundary_instructions(boundary: object) -> tuple[object, ...]:
    """Return the boundary's decoded instructions in address order."""
    return tuple(
        instruction
        for block in sorted(boundary.blocks, key=lambda item: item.addr)
        for instruction in block.capstone.insns
    )


class _MultiCallerWorld:
    """Retained surfaces for the two-caller fixture."""

    def __init__(self, boot: object, project: angr.Project) -> None:
        self.project = project
        self.boot = boot
        # Caller A: mapped boundary, real IR artifact, published as PROVEN
        # so its own domain premise resolves through the registered-head
        # route exactly like the single-caller fixture.
        self.boundary_a = boundary_mod.mapped_entry_function_boundary_8616(
            project, _MZ_CALLER_A
        )
        assert self.boundary_a is not None
        self.artifact_a = vex_import.build_x86_16_ir_function_artifact(
            project, self.boundary_a
        )
        verdict = publish_function_ir_artifact_8616(
            project, self.artifact_a
        )
        assert verdict.verdict is FunctionIRArtifactVerdict8616.PROVEN
        self.boundary_b = boundary_mod.mapped_entry_function_boundary_8616(
            project, _MZ_CALLER_B
        )
        assert self.boundary_b is not None
        # The caller-scoped boundary indexes supply the edge rows the
        # callsite-driven resolution path actually transports; their row
        # objects differ from the source index rows while the decoded
        # coordinates agree — the production shape.
        self.index_a = build_boundary_direct_callsite_index_8616(
            self.boundary_a, direct_target_resolver=_mz_resolver(project)
        )
        self.index_b = build_boundary_direct_callsite_index_8616(
            self.boundary_b, direct_target_resolver=_mz_resolver(project)
        )
        # The project source-authenticated index: one decoded corpus over
        # both caller ranges, so the shared callee head carries two rows.
        self.source_index = build_decoded_direct_callsite_index_8616(
            {
                (
                    self.boundary_a.addr,
                    self.boundary_a.addr + self.boundary_a.size,
                ): _boundary_instructions(self.boundary_a),
                (
                    self.boundary_b.addr,
                    self.boundary_b.addr + self.boundary_b.size,
                ): _boundary_instructions(self.boundary_b),
            },
            direct_target_resolver=_mz_resolver(project),
            instruction_address_resolver=lambda instruction: instruction.address,
        )
        rows = self.source_index.for_target(_MZ_CALLEE)
        self.row_a = next(
            row for row in rows if row.caller_start == _MZ_CALLER_A
        )
        self.row_b = next(
            row for row in rows if row.caller_start == _MZ_CALLER_B
        )
        assert len(rows) == 2
        self.edge_a = next(
            row
            for row in self.index_a.for_target(_MZ_CALLEE)
            if row.callsite_addr == _MZ_CALLER_A_CALLSITE
        )
        self.edge_b = next(
            row
            for row in self.index_b.for_target(_MZ_CALLEE)
            if row.callsite_addr == _MZ_CALLER_B_CALLSITE
        )
        # The transported edge is a distinct row object sharing the
        # source row's decoded coordinates — never the identical object.
        assert self.edge_a is not self.row_a
        assert self.edge_b is not self.row_b

    def install_source(
        self, index: DecodedDirectCallsiteIndex8616 | None = None,
    ) -> None:
        """Install the invocation source carrying the multi-caller index."""
        edcp.install_real16_invocation_source_8616(
            self.project,
            edcp.Real16InvocationSource8616(
                boot=self.boot,
                boot_recompute=_mz_boot_recompute,
                callsite_index=(
                    self.source_index if index is None else index
                ),
            ),
        )

    @staticmethod
    def clear_source(project: angr.Project) -> None:
        """Remove the invocation source after each control."""
        edcp.install_real16_invocation_source_8616(project, None)


@pytest.fixture
def world(tmp_path: Path) -> object:
    """Build the two-caller MZ world with the source installed."""
    boot, project = _mz_world(tmp_path)
    holder = _MultiCallerWorld(boot, project)
    holder.install_source()
    try:
        yield holder
    finally:
        holder.clear_source(project)


def _pending_pair(
    world: _MultiCallerWorld, edge: DecodedDirectCallsite8616 | None,
) -> tuple[object, object] | None:
    """Resolve the shared callee through the transported edge."""
    if edge is None:
        # Context-free request: signature-stable against the baseline so
        # the preserved ambiguous-head refusal is exercised on both.
        return edcp._callee_artifact_and_boundary_8616(
            world.project, _MZ_CALLEE
        )
    return edcp._callee_artifact_and_boundary_8616(
        world.project, _MZ_CALLEE, callsite=edge
    )


def _premise_of(boundary: object) -> NearCallFramePremise8616:
    """Return the boundary's retained source-bound frame premise."""
    continuations = boundary.near_return_continuations
    assert continuations is not None
    premise = continuations.premise
    assert type(premise) is NearCallFramePremise8616
    return premise


def _assert_unregistered(artifact: object, project: angr.Project) -> None:
    """The conditional callee is never published into the registry."""
    resolution = registered_function_ir_artifact_8616(
        project, artifact.function_addr
    )
    assert resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN


def test_selected_edge_binds_premise_to_its_own_row(
    world: _MultiCallerWorld,
) -> None:
    """The transported edge selects the matching source row, not first."""
    resolved = _pending_pair(world, world.edge_a)
    assert resolved is not None
    artifact, boundary = resolved
    premise = _premise_of(boundary)
    # The premise binds the source-authenticated row — never the passed
    # boundary-index object — and names edge A's exact coordinates.
    assert premise.callsite is world.row_a
    assert premise.callsite is not world.edge_a
    assert premise.callsite_index is world.source_index
    assert premise.callsite_addr == _MZ_CALLER_A_CALLSITE
    assert premise.caller_start == _MZ_CALLER_A
    assert premise.callee_addr == _MZ_CALLEE
    assert premise.return_addr == _MZ_CALLER_A_CALLSITE + 3
    _assert_unregistered(artifact, world.project)


def test_second_edge_binds_second_row_not_first(
    world: _MultiCallerWorld,
) -> None:
    """Edge B transports row B even though row A sorts first by address."""
    assert world.row_a.callsite_addr < world.row_b.callsite_addr
    resolved = _pending_pair(world, world.edge_b)
    assert resolved is not None
    artifact, boundary = resolved
    premise = _premise_of(boundary)
    assert premise.callsite is world.row_b
    assert premise.callsite_addr == _MZ_CALLER_B_CALLSITE
    assert premise.caller_start == _MZ_CALLER_B
    assert premise.return_addr == _MZ_CALLER_B_CALLSITE + 3
    _assert_unregistered(artifact, world.project)


def test_collect_route_reports_pending_not_unresolved(
    world: _MultiCallerWorld,
) -> None:
    """The actual callsite-driven route resolves the shared callee.

    Signature-stable against the baseline: before the transport, this
    exact route refused ``CALLEE_UNRESOLVED`` because the head-unique
    selection could not pick a row. With the edge transported, the
    conditional callee resolves and the record carries the typed
    conditional refusal instead.
    """
    records = edcp.collect_entry_domain_call_preservations_8616(
        world.project,
        world.artifact_a,
        world.boundary_a,
        direct_target_resolver=_mz_resolver(world.project),
    )
    assert len(records) == 1
    record = records[0]
    assert record.callsite_addr == _MZ_CALLER_A_CALLSITE
    assert type(record.entry) is DecodedDirectCallsite8616
    assert record.failure is (
        edcp.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    )


def test_scoped_consumption_binds_selected_edge(
    world: _MultiCallerWorld,
) -> None:
    """The chain-bound entry consumes exactly the transported edge."""
    resolved = _pending_pair(world, world.edge_a)
    assert resolved is not None
    artifact, boundary = resolved
    scope = edcp.entry_domain_invocation_premise_8616(
        world.project, artifact, boundary, _MZ_JMP_HEAD
    )
    assert scope is not None and scope.complete
    # The derived consuming entry names the identical source row.
    assert scope.chain.callsite is world.row_a
    assert scope.chain.callsite_index is world.source_index
    view = nrcv.prove_scoped_near_return_continuation_view_8616(
        artifact, boundary, invocation_scope=scope
    )
    assert view.failure is None
    assert view.source_artifact is artifact
    projection = view.cfg_projection_for(scope)
    assert projection is not None
    block = next(b for b in projection.blocks if b.addr == _MZ_CALLEE)
    assert block.instrs[-1].op == "RET"
    raw_block = next(b for b in artifact.blocks if b.addr == _MZ_CALLEE)
    assert raw_block.instrs[-1].op == "JMP"
    assert any(r.kind == _PENDING_KIND for r in raw_block.refusals)
    coverage = prove_scoped_ir_boundary_coverage_8616(
        world.project, boundary, artifact, view
    )
    assert coverage.complete_for(scope)
    assert not coverage.complete
    resolution = edcp._CalleeResolution8616(
        resolver=_mz_resolver(world.project)
    )
    closure, refusal = edcp._callee_closure_8616(
        world.project, _MZ_CALLEE, resolution, invocation_scope=scope
    )
    assert refusal is None and closure is not None
    assert closure.complete_for(scope)
    assert not closure.complete


def test_wrong_edge_scope_is_unbound_for_other_row(
    world: _MultiCallerWorld,
) -> None:
    """A premise bound to row B cannot be consumed under the row-A entry.

    The only derivable consuming entry in this fixture chains through
    caller A (caller B has no proven parent), so the scope names row A.
    The pending artifact bound to row B keeps its typed refusal — the
    return coordinate of one edge never authorizes another.
    """
    resolved = _pending_pair(world, world.edge_b)
    assert resolved is not None
    artifact_b, boundary_b = resolved
    premise_b = _premise_of(boundary_b)
    assert premise_b.callsite is world.row_b
    assert premise_b.return_addr == _MZ_CALLER_B_CALLSITE + 3
    scope = edcp.entry_domain_invocation_premise_8616(
        world.project, artifact_b, boundary_b, _MZ_JMP_HEAD
    )
    assert scope is not None and scope.complete
    assert scope.chain.callsite is world.row_a
    view = nrcv.prove_scoped_near_return_continuation_view_8616(
        artifact_b, boundary_b, invocation_scope=scope
    )
    assert view.failure is (
        nrcv.ScopedNearReturnContinuationViewFailure8616.SCOPE_UNBOUND
    )
    assert view.cfg_projection_for(scope) is None
    coverage = prove_scoped_ir_boundary_coverage_8616(
        world.project, boundary_b, artifact_b, view
    )
    assert not coverage.complete_for(scope)
    resolution = edcp._CalleeResolution8616(
        resolver=_mz_resolver(world.project)
    )
    closure, refusal = edcp._callee_closure_8616(
        world.project, _MZ_CALLEE, resolution, invocation_scope=scope
    )
    assert closure is None
    assert refusal is (
        edcp.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    )


def test_scoped_closures_stay_keyed_by_identity(
    world: _MultiCallerWorld,
) -> None:
    """Conditional closures live in the scope-keyed pool, never universal."""
    resolved = _pending_pair(world, world.edge_a)
    assert resolved is not None
    artifact, boundary = resolved
    scope = edcp.entry_domain_invocation_premise_8616(
        world.project, artifact, boundary, _MZ_JMP_HEAD
    )
    assert scope is not None and scope.complete
    resolution = edcp._CalleeResolution8616(
        resolver=_mz_resolver(world.project)
    )
    closure, refusal = edcp._callee_closure_8616(
        world.project, _MZ_CALLEE, resolution, invocation_scope=scope
    )
    assert refusal is None and closure is not None
    # The conditional closure is retained only under the identical scope
    # identity — never under the callee head in the universal pool, and a
    # scope derived over a foreign artifact object cannot reuse it.
    assert _MZ_CALLEE not in resolution.retained_closures
    assert resolution.scoped_closures[(_MZ_CALLEE, id(scope))] is closure
    from angr_platforms.X86_16.ir.real16_invocation_domain import (
        real16_native_census_import_8616,
    )

    foreign_artifact = real16_native_census_import_8616(
        world.project, boundary
    )
    assert foreign_artifact is not None and foreign_artifact is not artifact
    foreign_scope = edcp.entry_domain_invocation_premise_8616(
        world.project, foreign_artifact, boundary, _MZ_JMP_HEAD
    )
    assert foreign_scope is not None and foreign_scope.complete
    assert id(foreign_scope) != id(scope)
    assert (_MZ_CALLEE, id(foreign_scope)) not in resolution.scoped_closures


def test_foreign_edge_refuses(world: _MultiCallerWorld) -> None:
    """An edge whose coordinates the index does not carry is refused."""
    instruction = world.row_a.instructions[world.row_a.instruction_index]
    foreign = DecodedDirectCallsite8616(
        caller_start=_MZ_CALLER_A,
        instructions=world.row_a.instructions,
        instruction_index=world.row_a.instruction_index,
        callsite_addr=_MZ_BASE + 0x400,
        target_addr=_MZ_CALLEE,
    )
    assert instruction is not None
    assert _pending_pair(world, foreign) is None


def test_target_mismatched_edge_refuses(world: _MultiCallerWorld) -> None:
    """An edge decoded against another head cannot transport here."""
    mismatched = DecodedDirectCallsite8616(
        caller_start=_MZ_CALLER_A,
        instructions=world.row_a.instructions,
        instruction_index=world.row_a.instruction_index,
        callsite_addr=_MZ_CALLER_A_CALLSITE,
        target_addr=_MZ_CALLER_B,
    )
    assert _pending_pair(world, mismatched) is None


def test_far_edge_refuses(world: _MultiCallerWorld) -> None:
    """A far-call row never transports a near-call frame premise."""
    far = DecodedDirectCallsite8616(
        caller_start=_MZ_CALLER_A,
        instructions=world.row_a.instructions,
        instruction_index=world.row_a.instruction_index,
        callsite_addr=_MZ_CALLER_A_CALLSITE,
        target_addr=_MZ_CALLEE,
        is_far=True,
    )
    assert _pending_pair(world, far) is None


def test_context_free_request_stays_ambiguous(
    world: _MultiCallerWorld,
) -> None:
    """Without a transported edge the shared head keeps its refusal."""
    assert _pending_pair(world, None) is None


def test_wide_row_at_edge_coordinates_refuses(
    world: _MultiCallerWorld,
) -> None:
    """A ``66 E8`` source row at the edge's coordinates never proves."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    code = b"\x66\xe8" + (
        (_MZ_CALLEE - (_MZ_CALLER_A_CALLSITE + 6)) & 0xFFFFFFFF
    ).to_bytes(4, "little")
    instruction, = tuple(decoder.disasm(code, _MZ_CALLER_A_CALLSITE))
    assert instruction.size == 6
    wide_row = DecodedDirectCallsite8616(
        caller_start=_MZ_CALLER_A,
        instructions=(instruction,),
        instruction_index=0,
        callsite_addr=_MZ_CALLER_A_CALLSITE,
        target_addr=_MZ_CALLEE,
    )
    stats = DecodedDirectCallsiteIndexStats8616(
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
    )
    index = DecodedDirectCallsiteIndex8616(
        {caller_target_identity_8616(_MZ_CALLEE, ()): (wide_row, world.row_b)},
        stats,
    )
    world.install_source(index)
    try:
        # The edge row coordinates match the wide source row; the premise
        # owner refuses the non-word push, so nothing resolves.
        assert _pending_pair(world, world.edge_a) is None
    finally:
        world.install_source()


def test_rebuilt_index_without_edge_row_refuses(
    world: _MultiCallerWorld,
) -> None:
    """A rebuilt index that dropped the edge's row revokes the edge."""
    index = build_decoded_direct_callsite_index_8616(
        {
            (
                world.boundary_b.addr,
                world.boundary_b.addr + world.boundary_b.size,
            ): _boundary_instructions(world.boundary_b),
        },
        direct_target_resolver=_mz_resolver(world.project),
        instruction_address_resolver=lambda instruction: instruction.address,
    )
    world.install_source(index)
    try:
        assert _pending_pair(world, world.edge_a) is None
    finally:
        world.install_source()


def test_pending_callee_never_enters_universal_route(
    world: _MultiCallerWorld,
) -> None:
    """The resolved conditional body stays refused on the universal path."""
    resolved = _pending_pair(world, world.edge_a)
    assert resolved is not None
    artifact, boundary = resolved
    block = next(b for b in artifact.blocks if b.addr == _MZ_CALLEE)
    assert block.instrs[-1].op == "JMP"
    assert any(r.kind == _PENDING_KIND for r in block.refusals)
    verdict = publish_function_ir_artifact_8616(world.project, artifact)
    assert verdict.verdict is not FunctionIRArtifactVerdict8616.PROVEN
    coverage = prove_ir_boundary_coverage_8616(
        world.project, boundary, artifact
    )
    assert not coverage.complete
    resolution = edcp._CalleeResolution8616(
        resolver=_mz_resolver(world.project)
    )
    closure, refusal = edcp._callee_closure_8616(
        world.project, _MZ_CALLEE, resolution, callsite=world.edge_a
    )
    assert closure is None
    assert refusal is (
        edcp.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    )


def test_transport_row_with_equivalent_raw_decoding_proves(
    world: _MultiCallerWorld,
) -> None:
    """A distinct raw decoder object with equal evidence still binds.

    The transport relation is instruction evidence — decoded address,
    extent, and bytes — not row or instruction object identity: a row
    whose instruction is a freshly decoded raw ``CsInsn`` agreeing with
    the retained source row and the mapped native bytes authenticates
    the edge exactly like the boundary-index row.
    """
    retained = world.row_a.instructions[world.row_a.instruction_index]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instruction, = tuple(
        decoder.disasm(bytes(retained.insn.bytes), _MZ_CALLER_A_CALLSITE)
    )
    transported = replace(
        world.edge_a, instructions=(instruction,), instruction_index=0
    )
    premise = edcp._near_return_frame_premise_8616(
        world.project, _MZ_CALLEE, transported
    )
    assert premise is not None
    assert premise.callsite is world.row_a
    assert premise.callsite_index is world.source_index


def test_transport_row_with_undecoded_instruction_refuses(
    world: _MultiCallerWorld,
) -> None:
    """A transported row without decoded byte evidence cannot bind."""

    class _UndecodedInstruction8616:
        """Address/size carrier with no decoded byte payload."""

        def __init__(self, address: int, size: int) -> None:
            self.address = address
            self.size = size

    transported = replace(
        world.edge_a,
        instructions=(
            _UndecodedInstruction8616(_MZ_CALLER_A_CALLSITE, 3),
        ),
        instruction_index=0,
    )
    assert (
        edcp._near_return_frame_premise_8616(
            world.project, _MZ_CALLEE, transported
        )
        is None
    )


def test_transport_row_with_changed_extent_refuses(
    world: _MultiCallerWorld,
) -> None:
    """A transported instruction of different extent cannot borrow."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instruction, = tuple(decoder.disasm(b"\x6a\x00", _MZ_CALLER_A_CALLSITE))
    assert instruction.size == 2
    transported = replace(
        world.edge_a, instructions=(instruction,), instruction_index=0
    )
    assert (
        edcp._near_return_frame_premise_8616(
            world.project, _MZ_CALLEE, transported
        )
        is None
    )


def test_transport_row_with_out_of_range_index_refuses(
    world: _MultiCallerWorld,
) -> None:
    """An instruction index outside the transported tuple refuses."""
    transported = replace(world.edge_a, instruction_index=7)
    assert (
        edcp._near_return_frame_premise_8616(
            world.project, _MZ_CALLEE, transported
        )
        is None
    )


def test_mutated_native_bytes_revoke_source_row(
    world: _MultiCallerWorld,
) -> None:
    """Stale retained evidence refuses once mapped bytes diverge."""
    world.project.loader.memory.store(
        _MZ_CALLER_A_CALLSITE, b"\x90\x90\x90"
    )
    assert (
        edcp._near_return_frame_premise_8616(
            world.project, _MZ_CALLEE, world.edge_a
        )
        is None
    )


@pytest.mark.parametrize("kind", ["wide", "jump"])
def test_transport_instruction_cannot_borrow_word_call_coordinates(world: _MultiCallerWorld, kind: str) -> None:
    """A wide CALL or JMP at matching coordinates cannot borrow a word frame."""
    edge = world.edge_a
    size = 6 if kind == "wide" else 3
    width = 4 if kind == "wide" else 2
    code = b"\x66\xe8" if kind == "wide" else b"\xe9"
    code += ((edge.target_addr - edge.callsite_addr - size) & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instruction, = tuple(decoder.disasm(code, edge.callsite_addr))
    transported = replace(edge, instructions=(instruction,), instruction_index=0)
    assert edcp._near_return_frame_premise_8616(
        world.project, edge.target_addr, transported,
    ) is None
