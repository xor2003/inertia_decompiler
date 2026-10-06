"""Bind invocation transport to encoded CALL bytes, not lookup aliases.

Layer: tests.
Responsibility: retain prefix effects under normalized call lookup and reject
forged direct links and self-consistent counterfeit instruction indexes.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from functools import partial
from pathlib import Path

import angr
import pytest
from angr_platforms.X86_16.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    build_decoded_direct_callsite_index_8616,
)
from angr_platforms.X86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from angr_platforms.X86_16.ir import IRFunctionArtifact
from angr_platforms.X86_16.ir import entry_domain_call_preservation as edcp
from angr_platforms.X86_16.ir import real16_invocation_domain as domain
from angr_platforms.X86_16.ir import vex_import as vi
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from test_x86_16_scoped_native_inputs import (
    BASE,
    LOAD_SEGMENT,
    _assert_loader_bytes,
    _boot_recompute,
    _boundary,
    _build_environment,
    _build_image,
    _build_mz,
)

from inertia_decompiler.project_loading import _build_project
from tools.dosunit.real16_program_boot import ProgramBoot, program_from_mz_bytes
from tools.dosunit.real16_replay_model import LinearRange

LEAF = BASE
LEAF_CODE = bytes.fromhex("b8 34 12 c3")
PAD1, CALLEE1, STUB1 = BASE + 0x10, BASE + 0x20, BASE + 0x40
CALL1, EDGE1 = CALLEE1, STUB1

def _near_call(target: int, at: int) -> bytes:
    return b"\xe8" + ((target - at - 3) & 0xffff).to_bytes(2, "little")

CALLEE1_CODE = _near_call(LEAF, CALL1) + b"\xc3"
STUB1_CODE = _near_call(PAD1, EDGE1) + b"\xc3"
E1_RANGES = (LinearRange(LEAF, len(LEAF_CODE)),
             LinearRange(PAD1, 16 + len(CALLEE1_CODE)),
             LinearRange(STUB1, len(STUB1_CODE)))

def _make_project(mz: bytes, entry: int, tmp_path: Path) -> angr.Project:
    path = tmp_path / "fixture.exe"
    path.write_bytes(mz)
    return _build_project(path, force_blob=False, base_addr=BASE, entry_point=entry)

def _decoded_instructions(boundary: ExactFunctionRangeBoundary8616) -> tuple[object, ...]:
    return tuple(instruction for block in sorted(boundary.blocks, key=lambda item: item.addr)
                 for instruction in block.capstone.insns)

def _resolver(project: object) -> Callable[[object], int | None]:
    return partial(resolve_direct_call_target_from_instruction_8616, project)

def _install(project: object, boot: ProgramBoot, index: DecodedDirectCallsiteIndex8616) -> None:
    edcp.install_real16_invocation_source_8616(project, edcp.Real16InvocationSource8616(
        boot=boot, boot_recompute=_boot_recompute, callsite_index=index,
    ))

def _premise(project: object, artifact: IRFunctionArtifact, boundary: ExactFunctionRangeBoundary8616, callsite: int) -> domain.Real16InvocationDomain8616 | None:
    return edcp.entry_domain_invocation_premise_8616(project, artifact, boundary, callsite)

@pytest.mark.parametrize(("prefix", "expected"), [(bytes.fromhex("b9 55 00") + b"\x90" * 13, 0x55), (b"\x90" * 16, 0)])
def test_normalized_target_preserves_native_prefix(
    tmp_path: Path, prefix: bytes, expected: int,
) -> None:
    """The indexed lookup identity cannot erase an executed MOV CX prefix."""
    from angr_platforms.X86_16.frontend_direct_callsite_index import DecodedCallerCensus8616

    image = _build_image(((LEAF, LEAF_CODE), (PAD1, prefix),
                          (CALLEE1, CALLEE1_CODE), (STUB1, STUB1_CODE)))
    mz = _build_mz(image, entry_ip=STUB1 - BASE)
    boot = program_from_mz_bytes(mz, _build_environment(0x300), code_ranges=E1_RANGES)
    project = _make_project(mz, STUB1, tmp_path)
    _assert_loader_bytes(project, boot, E1_RANGES)
    enclosing = _boundary(project, PAD1, CALLEE1 + len(CALLEE1_CODE))
    callee = _boundary(project, CALLEE1, CALLEE1 + len(CALLEE1_CODE))
    artifact = vi.build_x86_16_ir_function_artifact(project, callee)
    caller = _boundary(project, STUB1, STUB1 + len(STUB1_CODE))
    caller_artifact = vi.build_x86_16_ir_function_artifact(project, caller)
    publish_function_ir_artifact_8616(project, caller_artifact)
    resolve = _resolver(project)
    index = build_decoded_direct_callsite_index_8616(
        tuple(DecodedCallerCensus8616(boundary.addr, boundary.decode_start,
                                     boundary.decode_end, _decoded_instructions(boundary))
              for boundary in (enclosing, caller)),
        direct_target_resolver=lambda instruction: (
            CALLEE1 if instruction.address == EDGE1 else resolve(instruction)),
        instruction_address_resolver=lambda instruction: instruction.address,
    )
    _install(project, boot, index)
    premise = _premise(project, artifact, callee, CALL1)
    assert premise is not None and premise.complete
    from unicorn import UC_ARCH_X86, UC_MODE_16, Uc
    from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_CX, UC_X86_REG_IP, UC_X86_REG_SP, UC_X86_REG_SS

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x20000)
    machine.mem_write(BASE, image)
    for register, value in ((UC_X86_REG_CS, LOAD_SEGMENT), (UC_X86_REG_SS, LOAD_SEGMENT + 0x10),
                            (UC_X86_REG_SP, 0x100), (UC_X86_REG_CX, 0)):
        machine.reg_write(register, value)
    machine.emu_start(STUB1, CALL1, count=64)
    assert machine.reg_read(UC_X86_REG_IP) == CALL1 - BASE
    assert dict(premise.callsite_call_state)["cx"] == machine.reg_read(UC_X86_REG_CX) == expected
    assert premise.kind is domain.Real16InvocationKind8616.ENCLOSED_ENTRY
    # A caller cannot bypass the enclosing prefix by constructing the public
    # direct-link contract with the same canonicalized index row.
    enclosing_link = premise.chain
    direct_link = domain.Real16CallChainLink8616(
        parent=enclosing_link.parent, callsite_index=index, callsite=enclosing_link.callsite,
        callsite_artifact=enclosing_link.callsite_artifact,
        callsite_boundary=enclosing_link.callsite_boundary, call_state=enclosing_link.call_state,
        callee_artifact=artifact, callee_boundary=callee,
    )
    assert not direct_link.complete
    refused = domain.prove_real16_chained_invocation_domain_8616(
        project, None, CALL1, boot=boot, boot_recompute=_boot_recompute, chain=direct_link,
    )
    assert refused.failure is domain.Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    assert not refused.complete
    # Even a counterfeit index that agrees with its fabricated E8 bytes must
    # bind the CALL bytes from the parent's authenticated native census.
    from types import SimpleNamespace

    row = enclosing_link.callsite
    instructions = list(row.instructions)
    instructions[row.instruction_index] = SimpleNamespace(
        address=EDGE1, size=3, bytes=_near_call(CALLEE1, EDGE1),
    )
    forged_row = replace(row, instructions=tuple(instructions))
    forged_index = replace(index, _entries_by_normalized_target={
        target: tuple(forged_row if item is row else item for item in rows)
        for target, rows in index._entries_by_normalized_target.items()
    })
    forged_direct = replace(direct_link, callsite=forged_row, callsite_index=forged_index)
    assert not forged_direct.complete
    refused = domain.prove_real16_chained_invocation_domain_8616(
        project, None, CALL1, boot=boot, boot_recompute=_boot_recompute, chain=forged_direct,
    )
    assert refused.failure is domain.Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    assert not refused.complete

