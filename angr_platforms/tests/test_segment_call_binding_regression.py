"""Binary-derived segment-CALL bindings and retained-evidence corruption controls.

Layer: Tests.
Responsibility: preserve symbolic/full-width target binding, exact decoder
coordinates, callee segment effects, and honest refusal of stale evidence.
"""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import caller_return_use_program_scope_8616
from angr_platforms.X86_16.control_coordinates import ControlAddressDomain
from angr_platforms.X86_16.frontend_caller_return_use_program import (
    current_caller_return_use_program_evidence_8616,
)
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from angr_platforms.X86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.ir import (
    IRBlock,
    IRInstr,
    IRValue,
    MemSpace,
    build_x86_16_segment_state_artifact,
)
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    IRBoundaryCoverageResult8616,
    prove_ir_boundary_coverage_8616,
)
from angr_platforms.X86_16.ir.segment_call_preservation import (
    SegmentCallPreservationFailure8616,
    SegmentCallPreservationResult8616,
    prove_segment_call_preservation_8616,
)
from angr_platforms.X86_16.ir.segment_effect_closure import prove_segment_effect_closure_8616
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.semantics.direct_near_call_target_binding import (
    DirectNearCallCoordinates8616,
    DirectNearCallTargetBindingFailure8616,
    prove_direct_near_call_target_binding_at_coordinates_8616,
    prove_direct_near_call_target_binding_from_decoded_8616,
)

from tools.dosunit.recursive_proofs.real16_loader_arch import real16_loader_arch

_CALLER = 0x1000
_CALLEE_RET = 0x1006
# caller: e8 03 00 (call +3 -> 0x1006) c3; padding; callee: c3
_CODE_LEAF_RET = bytes.fromhex("e8 03 00 c3 90 90 c3")
# callee at 0x1006: mov ax,0x1234; mov es,ax; ret  (changes ES only)
_CODE_LEAF_WRITE_ES = bytes.fromhex("e8 03 00 c3 90 90 b8 34 12 8e c0 c3")
_CALLEE_WRITE_END = _CALLER + len(_CODE_LEAF_WRITE_ES)
# high-address caller/callee inside a window that excludes selector zero:
# head 0x10020 e8 01 00 -> next 0x10023, target 0x10024 (ret)
_HIGH_HEAD = 0x10020
_HIGH_TARGET = 0x10024
_HIGH_IMAGE_SIZE = 0x11000


def _project(code: bytes | bytearray, *, base: int = _CALLER,
             image_size: int = 0x2000, entry: int | None = None,
             wide_loader: bool = False) -> angr.Project:
    """Build a real blob project with Arch86_16 and DOS simos.

    ``wide_loader`` selects the 32-bit-capable loader arch so CLE image bounds
    can hold linear addresses above ``0xFFFF``.
    """
    image = bytearray(image_size)
    image[: len(code)] = code
    return angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob",
            "arch": real16_loader_arch() if wide_loader else Arch86_16(),
            "base_addr": base,
            "entry_point": base if entry is None else entry,
        },
        auto_load_libs=False,
        simos="DOS",
    )


def _coverage(
    project: angr.Project,
    start: int,
    end: int,
) -> IRBoundaryCoverageResult8616:
    """Import, publish, and cover one exact function boundary."""
    boundary = exact_function_range_boundary_8616(project, start, end)
    assert boundary is not None
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, artifact)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    assert coverage.complete
    return coverage


def _program_index(
    project: angr.Project,
    caller_start: int,
    caller_end: int,
) -> DecodedDirectCallsiteIndex8616:
    """Decode the real caller corpus through the existing request owner."""
    ranges = ((caller_start, caller_end),)
    with caller_return_use_program_scope_8616(project, ranges):
        program = current_caller_return_use_program_evidence_8616(project, ranges)
    assert program is not None
    assert program.callsites.stats.closed
    return program.callsites


def _prove(
    project: angr.Project,
    caller_range: tuple[int, int],
    callee_range: tuple[int, int],
    site: int,
) -> SegmentCallPreservationResult8616:
    """Run the real caller/callee/index pipeline into one proof."""
    caller = _coverage(project, *caller_range)
    callee = _coverage(project, *callee_range)
    closure = prove_segment_effect_closure_8616(
        callee, build_x86_16_segment_state_artifact(callee.artifact),
    )
    assert closure.complete and not closure.callsite_addrs
    index = _program_index(project, *caller_range)
    return prove_segment_call_preservation_8616(caller, closure, index, site)


def _decoded_entry(
    index: DecodedDirectCallsiteIndex8616,
    target: int,
    site: int,
) -> DecodedDirectCallsite8616:
    """Extract the single decoded entry the consumer binds against."""
    entries = tuple(
        entry for entry in index.for_target(target) if entry.callsite_addr == site
    )
    assert len(entries) == 1
    return entries[0]


def _call_parts(
    caller: IRBoundaryCoverageResult8616,
    site: int,
) -> tuple[IRBlock, IRInstr]:
    """Locate the exact CALL instruction and its block in caller coverage."""
    block = next(
        block for block in caller.artifact.blocks
        if any(i.op == "CALL" and i.addr == site for i in block.instrs)
    )
    call = next(i for i in block.instrs if i.op == "CALL" and i.addr == site)
    return block, call


def test_symbolic_near_call_preserves_unchanged_segments() -> None:
    """A leaf callee keeps proven segment identities across the call."""
    project = _project(_CODE_LEAF_RET)
    proof = _prove(project, (0x1000, 0x1004), (_CALLEE_RET, 0x1007), 0x1000)
    assert proof.complete
    assert "ds" in proof.preserved_registers
    entry = _decoded_entry(proof.index, _CALLEE_RET, 0x1000)
    block, call = _call_parts(proof.caller, 0x1000)
    binding = prove_direct_near_call_target_binding_from_decoded_8616(
        project, block=block, instruction=call, decoded=entry,
    )
    assert binding.complete and binding.target_addr == _CALLEE_RET


def test_changed_callee_segment_drops_only_written_register() -> None:
    """An ES-writing leaf drops ES while unrelated segment identities stay."""
    proof = _prove(
        _project(_CODE_LEAF_WRITE_ES),
        (0x1000, 0x1004),
        (_CALLEE_RET, _CALLEE_WRITE_END),
        0x1000,
    )
    assert proof.complete
    assert "ds" in proof.preserved_registers
    assert "es" not in proof.preserved_registers


def test_full_width_symbolic_target_binds_above_64k() -> None:
    """A high linear callee binds through the symbolic target proof."""
    image = bytearray(_HIGH_IMAGE_SIZE)
    image[_HIGH_HEAD:_HIGH_HEAD + 4] = bytes.fromhex("e80100c3")
    image[_HIGH_TARGET] = 0xC3
    project = _project(
        image, base=0, image_size=_HIGH_IMAGE_SIZE, entry=_HIGH_HEAD, wide_loader=True,
    )
    proof = _prove(
        project, (_HIGH_HEAD, _HIGH_HEAD + 4), (_HIGH_TARGET, _HIGH_TARGET + 1), _HIGH_HEAD,
    )
    assert proof.complete


def _prove_const_target(target: int) -> SegmentCallPreservationResult8616:
    """Replace only a decoded CALL's operand to test exact CONST binding.

    Native bytes, instruction census, CFG and decoded index remain authentic.
    The intentionally substituted operand probes the consumer's CONST contract.
    """
    image = bytearray(_HIGH_IMAGE_SIZE)
    image[_HIGH_HEAD:_HIGH_HEAD + 4] = bytes.fromhex("e80100c3")
    image[_HIGH_TARGET] = 0xC3
    project = _project(
        image, base=0, image_size=_HIGH_IMAGE_SIZE, entry=_HIGH_HEAD, wide_loader=True,
    )
    boundary = exact_function_range_boundary_8616(project, _HIGH_HEAD, _HIGH_HEAD + 4)
    assert boundary is not None
    original_artifact = build_x86_16_ir_function_artifact(project, boundary)
    block = next(block for block in original_artifact.blocks
                 if any(instruction.op == "CALL" for instruction in block.instrs))
    call = next(instruction for instruction in block.instrs if instruction.op == "CALL")
    callee = _coverage(project, _HIGH_TARGET, _HIGH_TARGET + 1)
    changed_call = replace(call, args=(IRValue(MemSpace.CONST, const=target, size=4),))
    changed_block = replace(
        block, instrs=tuple(changed_call if instruction is call else instruction
                           for instruction in block.instrs),
    )
    artifact = replace(
        original_artifact,
        blocks=tuple(changed_block if original is block else original
                     for original in original_artifact.blocks),
    )
    publish_function_ir_artifact_8616(project, artifact)
    caller = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    assert caller.complete
    closure = prove_segment_effect_closure_8616(
        callee, build_x86_16_segment_state_artifact(callee.artifact),
    )
    assert closure.complete
    index = _program_index(project, _HIGH_HEAD, _HIGH_HEAD + 4)
    return prove_segment_call_preservation_8616(caller, closure, index, _HIGH_HEAD)


def test_const_low16_alias_refuses() -> None:
    """Truncating a high linear CONST target must refuse exact binding."""
    proof = _prove_const_target(_HIGH_TARGET & 0xFFFF)
    assert not proof.complete
    assert proof.failure is SegmentCallPreservationFailure8616.TARGET_MISMATCH


def test_const_exact_full_width_binds() -> None:
    """An exact CONST target above 64 KiB retains the full linear address."""
    proof = _prove_const_target(_HIGH_TARGET)
    assert proof.complete


def test_selector_wrap_call_refuses() -> None:
    """A callsite whose valid selector window excludes the target refuses."""
    head = 0x10020
    image = bytearray(_HIGH_IMAGE_SIZE)
    image[head:head + 4] = bytes.fromhex("e80001c3")
    image[0x10123] = 0xC3
    project = _project(
        image, base=0, image_size=_HIGH_IMAGE_SIZE, entry=head, wide_loader=True,
    )
    proof = _prove(project, (head, head + 4), (0x10123, 0x10124), head)
    assert not proof.complete
    assert proof.failure is SegmentCallPreservationFailure8616.TARGET_MISMATCH


@pytest.mark.parametrize("mutation,failure", [
    ("operand_prefix", DirectNearCallTargetBindingFailure8616.DECODED_ENCODING_MISMATCH),
    ("wrong_opcode", DirectNearCallTargetBindingFailure8616.DECODED_ENCODING_MISMATCH),
    ("wrong_address", DirectNearCallTargetBindingFailure8616.CALLSITE_MISMATCH),
    ("missing_surface", DirectNearCallTargetBindingFailure8616.DECODED_INSTRUCTION_MISSING),
    ("stale_target", DirectNearCallTargetBindingFailure8616.DECODED_TARGET_MISMATCH),
    ("far_entry", DirectNearCallTargetBindingFailure8616.FRAME_KIND_NOT_NEAR),
])
def test_decoded_evidence_mutations_refuse(
    mutation: str, failure: DirectNearCallTargetBindingFailure8616,
) -> None:
    """Tampered decoded-index facts cannot reach the shared binding."""
    project = _project(_CODE_LEAF_RET)
    index = _program_index(project, 0x1000, 0x1004)
    entry = _decoded_entry(index, _CALLEE_RET, 0x1000)
    if mutation == "operand_prefix":
        insn = SimpleNamespace(
            address=0x1000, size=6, bytes=b"\x66\xe8\x03\x00\x00\x00",
        )
        entry = replace(entry, instructions=(insn,), instruction_index=0)
    elif mutation == "wrong_opcode":
        insn = SimpleNamespace(address=0x1000, size=3, bytes=b"\xe9\x03\x00")
        entry = replace(entry, instructions=(insn,), instruction_index=0)
    elif mutation == "wrong_address":
        insn = SimpleNamespace(address=0x1004, size=3, bytes=b"\xe8\x03\x00")
        entry = replace(entry, instructions=(insn,), instruction_index=0)
    elif mutation == "missing_surface":
        entry = replace(entry, instructions=(SimpleNamespace(address=0x1000),), instruction_index=0)
    elif mutation == "stale_target":
        entry = replace(entry, target_addr=_CALLEE_RET + 2)
    else:
        entry = replace(entry, is_far=True)
    caller = _coverage(project, 0x1000, 0x1004)
    block, call = _call_parts(caller, 0x1000)
    binding = prove_direct_near_call_target_binding_from_decoded_8616(
        project, block=block, instruction=call, decoded=entry,
    )
    assert not binding.complete and binding.failure is failure


@pytest.mark.parametrize("mutation", ["origin_missing", "origin_tmp", "domain", "native_bytes"])
def test_provenance_and_native_mutations_refuse(mutation: str) -> None:
    """Origin, control-domain, and mapped-byte tampering all refuse."""
    project = _project(_CODE_LEAF_RET)
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1004)
    assert boundary is not None
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    callee = _coverage(project, 0x1006, 0x1007)
    closure = prove_segment_effect_closure_8616(
        callee, build_x86_16_segment_state_artifact(callee.artifact),
    )
    index = _program_index(project, 0x1000, 0x1004)
    if mutation in ("origin_missing", "origin_tmp"):
        block = next(block for block in artifact.blocks
                     if any(instruction.op == "CALL" for instruction in block.instrs))
        call = next(instruction for instruction in block.instrs if instruction.op == "CALL")
        assert call.origin is not None and call.origin.block_next_tmp is not None
        altered = (
            None if mutation == "origin_missing"
            else replace(call.origin, block_next_tmp=call.origin.block_next_tmp + 1)
        )
        new_call = replace(call, origin=altered)
        new_block = replace(block, instrs=tuple(
            new_call if item is call else item for item in block.instrs
        ))
        artifact = replace(artifact, blocks=tuple(
            new_block if item is block else item for item in artifact.blocks
        ))
    publish_function_ir_artifact_8616(project, artifact)
    caller = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    assert caller.complete
    if mutation == "domain":
        assert isinstance(project.arch, Arch86_16)
        project.arch.control_address_domain = ControlAddressDomain.ARCHITECTURAL_OFFSET
    elif mutation == "native_bytes":
        project.loader.memory.store(0x1001, b"\xff")
    proof = prove_segment_call_preservation_8616(caller, closure, index, 0x1000)
    assert not proof.complete
    assert proof.failure is SegmentCallPreservationFailure8616.TARGET_MISMATCH


def test_shared_owner_accepts_typed_coordinates() -> None:
    """The coordinate entry point binds the same proof the summary wrapper does."""
    project = _project(_CODE_LEAF_RET)
    caller = _coverage(project, 0x1000, 0x1004)
    block, call = _call_parts(caller, 0x1000)
    coordinates = DirectNearCallCoordinates8616(0x1000, 0x1003, _CALLEE_RET)
    binding = prove_direct_near_call_target_binding_at_coordinates_8616(
        project, block=block, instruction=call, coordinates=coordinates,
    )
    assert binding.complete and binding.target_addr == _CALLEE_RET
    wrong = DirectNearCallCoordinates8616(0x1000, 0x1003, _CALLEE_RET + 1)
    refused = prove_direct_near_call_target_binding_at_coordinates_8616(
        project, block=block, instruction=call, coordinates=wrong,
    )
    assert not refused.complete
    assert refused.failure is DirectNearCallTargetBindingFailure8616.DISPLACEMENT_MISMATCH


def test_retained_result_revalidates_same_proof() -> None:
    """Mutated retained fields or stale evidence never certify completion."""
    project = _project(_CODE_LEAF_RET)
    caller = _coverage(project, 0x1000, 0x1004)
    callee = _coverage(project, 0x1006, 0x1007)
    closure = prove_segment_effect_closure_8616(
        callee, build_x86_16_segment_state_artifact(callee.artifact),
    )
    index = _program_index(project, 0x1000, 0x1004)
    proof = prove_segment_call_preservation_8616(caller, closure, index, 0x1000)
    assert proof.complete
    assert not replace(proof, callsite_addr=0x1001).complete
    assert not replace(proof, materialized_count=0).complete
    stale_index = replace(
        index, stats=DecodedDirectCallsiteIndexStats8616(1, 1, 1, 1, 1),
    )
    assert not replace(proof, index=stale_index).complete
    project.loader.memory.store(0x1001, b"\xff")
    assert not proof.complete
