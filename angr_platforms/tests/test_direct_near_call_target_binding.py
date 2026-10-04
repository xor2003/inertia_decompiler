"""Binary-derived CALL binding and retained-evidence corruption controls."""
from __future__ import annotations

import io
from dataclasses import replace
from enum import StrEnum
from typing import NamedTuple

import angr
import pytest
import test_x86_16_near_return_expression as near_return
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.callsite_summary_program import build_callsite_summary_inventory_with_program_evidence_8616
from angr_platforms.X86_16.control_coordinates import ControlAddressDomain
from angr_platforms.X86_16.frontend_function_boundary import exact_function_range_boundary_8616
from angr_platforms.X86_16.ir.core import IRBlock, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.semantics.call_stack_effects import _bound_call_target_8616
from angr_platforms.X86_16.semantics.direct_near_call_target_binding import (
    DirectNearCallTargetBinding8616,
    prove_direct_near_call_target_binding_8616,
)
from angr_platforms.X86_16.semantics.direct_near_call_target_binding import (
    DirectNearCallTargetBindingFailure8616 as Failure,
)

from tools.dosunit.recursive_proofs.real16_loader_arch import real16_loader_arch


class Fixture(NamedTuple):
    """One exact binary CALL and its unmodified production-imported IR."""

    project: angr.Project
    block: IRBlock
    call: IRInstr
    summary: CallsiteSummary8616


def _fixture(project: angr.Project, start: int, end: int, callsite: int) -> Fixture:
    """Derive control provenance through the actual production importer."""
    boundary = exact_function_range_boundary_8616(project, start, end)
    assert boundary is not None
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    block = next(block for block in artifact.blocks if any(i.addr == callsite and i.op == "CALL" for i in block.instrs))
    call = next(i for i in block.instrs if i.addr == callsite and i.op == "CALL")
    summary = build_callsite_summary_inventory_with_program_evidence_8616(project, boundary, (callsite,))[callsite]
    return Fixture(project, block, call, summary)


@pytest.fixture(scope="module")
def fixture() -> Fixture:
    """Reuse immutable low-address binary-derived evidence per worker."""
    return _fixture(near_return._project(), 0x10F1, 0x110D, 0x10F7)


def _prove(fixture: Fixture, call: IRInstr | None = None,
           summary: CallsiteSummary8616 | None = None) -> DirectNearCallTargetBinding8616:
    """Replace a mutated instruction inside its own block before checking."""
    instruction = fixture.call if call is None else call
    block = replace(fixture.block, instrs=tuple(
        instruction if item is fixture.call else item for item in fixture.block.instrs
    ))
    return prove_direct_near_call_target_binding_8616(
        fixture.project, block=block, instruction=instruction,
        summary=fixture.summary if summary is None else summary,
    )


def test_production_importer_binds_symbolic_call(fixture: Fixture) -> None:
    """The imported terminal supplies provenance; no test stamps it afterward."""
    proof = _prove(fixture)
    assert proof.complete
    assert proof.shape is not None and proof.shape.segment_register == "cs"
    assert proof.target_addr == 0x15BC
    assert fixture.call.origin is not None and fixture.call.origin.is_block_next


@pytest.mark.parametrize("field,value", [
    ("offset", 0x1000),
    ("offset", False),
    ("expr", ("Iop_Neg16",)),
    ("version", 1),
    ("index", IRValue(MemSpace.REG, name="ax", size=2)),
    ("index_shift", 1),
    ("memory_access_size", 2),
    ("memory_access_insn", 0x10F7),
])
def test_decorated_cs_leaf_refuses(fixture: Fixture, field: str, value: object) -> None:
    """Arithmetic or access metadata cannot be erased by register-name reduction."""
    changed = 0
    instructions = []
    for instruction in fixture.block.instrs:
        arguments = []
        for argument in instruction.args:
            if isinstance(argument, IRValue) and argument.space is MemSpace.REG and argument.name == "cs":
                argument = replace(argument, **{field: value})
                changed += 1
            arguments.append(argument)
        instructions.append(replace(instruction, args=tuple(arguments)))
    assert changed > 0
    block = replace(fixture.block, instrs=tuple(instructions))
    call = next(instruction for instruction in block.instrs if instruction.op == "CALL")
    proof = prove_direct_near_call_target_binding_8616(
        fixture.project, block=block, instruction=call, summary=fixture.summary,
    )
    assert not proof.complete
    assert proof.failure is Failure.SHAPE_MISMATCH


class OriginMutation(StrEnum):
    """Independent terminal provenance corruptions."""

    MISSING = "missing"
    NOT_TERMINAL = "not_terminal"
    POSITION = "position"
    BLOCK = "block"
    TEMPORARY = "temporary"


@pytest.mark.parametrize("mutation,failure", [
    (OriginMutation.MISSING, Failure.ORIGIN_MISSING),
    (OriginMutation.NOT_TERMINAL, Failure.ORIGIN_NOT_BLOCK_NEXT),
    (OriginMutation.POSITION, Failure.TERMINAL_POSITION_MISMATCH),
    (OriginMutation.BLOCK, Failure.ORIGIN_BLOCK_MISMATCH),
    (OriginMutation.TEMPORARY, Failure.NEXT_TMP_MISMATCH),
])
def test_corrupted_terminal_provenance_refuses(fixture: Fixture, mutation: OriginMutation, failure: Failure) -> None:
    origin = fixture.call.origin
    assert origin is not None and origin.block_next_tmp is not None
    match mutation:
        case OriginMutation.MISSING:
            altered = None
        case OriginMutation.NOT_TERMINAL:
            altered = replace(origin, is_block_next=False)
        case OriginMutation.POSITION:
            altered = replace(origin, statement_index=origin.statement_index + 1)
        case OriginMutation.BLOCK:
            altered = replace(origin, block_addr=origin.block_addr + 1)
        case OriginMutation.TEMPORARY:
            altered = replace(origin, block_next_tmp=origin.block_next_tmp + 1)
    proof = _prove(fixture, replace(fixture.call, origin=altered))
    assert not proof.complete and proof.failure is failure


@pytest.mark.parametrize("mutation", ["segment", "target", "width", "boolean_count"])
def test_retained_binding_rechecks_corrupt_evidence(fixture: Fixture, mutation: str) -> None:
    proof = _prove(fixture)
    assert proof.complete and proof.shape is not None and proof.target_addr is not None
    if mutation == "segment":
        altered = replace(proof, shape=replace(proof.shape, segment_register="es"))
    elif mutation == "target":
        altered = replace(proof, target_addr=proof.target_addr + 1)
    elif mutation == "width":
        altered = replace(proof, shape=replace(proof.shape, control_bits=16))
    else:
        altered = replace(proof, stats=replace(proof.stats, raw_fact_count=True))
    assert not altered.complete


def test_wrong_control_address_domain_refuses(fixture: Fixture) -> None:
    project = near_return._project()
    assert isinstance(project.arch, Arch86_16)
    project.arch.control_address_domain = ControlAddressDomain.ARCHITECTURAL_OFFSET
    proof = _prove(fixture._replace(project=project))
    assert not proof.complete and proof.failure is Failure.CONTROL_DOMAIN_UNPROVED


@pytest.mark.parametrize("mutation,failure", [
    ("temporary", Failure.NEXT_TMP_MISMATCH),
    ("width", Failure.TARGET_OPERAND_MALFORMED),
    ("expression", Failure.TARGET_OPERAND_MALFORMED),
    ("register", Failure.TARGET_OPERAND_MALFORMED),
    ("constant", Failure.TARGET_OPERAND_CONSTANT),
    ("opcode", Failure.CALL_IDENTITY_MALFORMED),
])
def test_changed_call_operand_refuses(fixture: Fixture, mutation: str, failure: Failure) -> None:
    target = fixture.call.args[0]
    assert isinstance(target, IRValue) and target.source_tmp is not None
    if mutation == "temporary":
        operand = replace(target, source_tmp=target.source_tmp + 1)
    elif mutation == "width":
        operand = replace(target, size=2)
    elif mutation == "expression":
        operand = replace(target, expr=("Iop_Sub32",))
    elif mutation == "register":
        operand = replace(target, space=MemSpace.REG, name="ax", source_tmp=None)
    else:
        operand = replace(target, space=MemSpace.CONST, const=0x15BC, source_tmp=None)
    call = replace(fixture.call, op="JMP") if mutation == "opcode" else replace(fixture.call, args=(operand,))
    proof = _prove(fixture, call)
    assert not proof.complete and proof.failure is failure


@pytest.mark.parametrize("mutation,failure", [
    ("callsite", Failure.CALLSITE_MISMATCH),
    ("return", Failure.RETURN_ADDRESS_MISMATCH),
    ("target", Failure.DISPLACEMENT_MISMATCH),
])
def test_changed_summary_coordinate_refuses(fixture: Fixture, mutation: str, failure: Failure) -> None:
    assert fixture.summary.return_addr is not None and fixture.summary.target_addr is not None
    if mutation == "callsite":
        summary = replace(fixture.summary, callsite_addr=0x10F8)
    elif mutation == "return":
        summary = replace(fixture.summary, return_addr=fixture.summary.return_addr + 1)
    else:
        summary = replace(fixture.summary, target_addr=fixture.summary.target_addr + 1)
    proof = _prove(fixture, summary=summary)
    assert not proof.complete and proof.failure is failure


def test_changed_native_displacement_refuses(fixture: Fixture) -> None:
    project = near_return._project()
    project.loader.memory.store(0x10F8, b"\xc3")
    proof = _prove(fixture._replace(project=project))
    assert not proof.complete and proof.failure is Failure.TARGET_BYTES_MISMATCH


def test_valid_selector_wrap_refuses_linear_callee_summary() -> None:
    """Exact high-address E8 has a different target for a valid CS window."""
    head = 0x10020
    image = bytearray(0x11000)
    image[head:head + 4] = bytes.fromhex("e80001c3")
    image[0x10123] = 0xC3
    project = angr.Project(io.BytesIO(image), auto_load_libs=False, simos="DOS",
                           main_opts={"backend": "blob", "arch": real16_loader_arch(),
                                      "base_addr": 0, "entry_point": head})
    proof = _prove(_fixture(project, head, head + 4, head))
    assert not proof.complete and proof.failure is Failure.SELECTOR_WINDOW_UNPROVED


def test_truncated_constant_target_cannot_bind_high_summary(fixture: Fixture) -> None:
    """A low16 coincidence never proves full-width callee identity."""
    target = fixture.call.args[0]
    assert fixture.summary.target_addr is not None
    assert isinstance(target, IRValue)
    call = replace(fixture.call, args=(replace(target, space=MemSpace.CONST,
                   const=fixture.summary.target_addr, source_tmp=None, expr=None),))
    summary = replace(fixture.summary, target_addr=fixture.summary.target_addr + 0x10000)
    bound, proof = _bound_call_target_8616(fixture.project, fixture.block, summary, call)
    assert not bound and proof is not None and not proof.complete
