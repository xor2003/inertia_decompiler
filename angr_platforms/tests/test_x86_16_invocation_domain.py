"""Genuine-MZ invocation-domain tests for production real16 admission.

Builds a real DOS MZ + ProgramBoot (the production source authority) and
binds it to one exact near-call CS domain. Every raw root-to-callsite STORE
— including the callsite CALL's own stack push — must evaluate exactly
under the initialized header state and stay disjoint from every fetched
instruction byte; otherwise the premise refuses with a typed failure.
"""

import io
from collections.abc import Callable
from dataclasses import fields, replace
from types import SimpleNamespace
from typing import cast

import angr
from angr_platforms.X86_16.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from angr_platforms.X86_16.frontend_function_boundary import exact_function_range_boundary_8616
from angr_platforms.X86_16.ir.core import (
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCallOutputProvenance8616,
    IRCallStackEffect8616,
    IRCondition,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
)
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    IRBoundaryCoverageResult8616,
    prove_ir_boundary_coverage_8616,
)
from angr_platforms.X86_16.ir.real16_invocation_domain import (
    Real16InvocationDomain8616,
    Real16InvocationFailure8616,
    prove_real16_invocation_domain_8616,
    real16_invocation_discharges_8616,
)
from angr_platforms.X86_16.ir.segment_call_preservation import prove_segment_call_preservation_8616
from angr_platforms.X86_16.ir.segment_effect_closure import prove_segment_effect_closure_8616
from angr_platforms.X86_16.ir.segment_state import build_x86_16_segment_state_artifact
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact

from tools.dosunit.real16_program_boot import (
    ProgramBoot,
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.real16_replay_model import LinearRange

LOAD_SEGMENT = 0x100
PSP_SEGMENT = LOAD_SEGMENT - 0x10
CALLER_CODE = bytes.fromhex("e81000 89c3 36 8b0f c3")
CALLEE_CODE = bytes.fromhex("c3")
STUB_CODE = bytes.fromhex("161f e8cbff c3")


def _build_image() -> bytes:
    image = CALLER_CODE + bytes(0x13 - len(CALLER_CODE)) + CALLEE_CODE
    return image + bytes(0x30 - len(image)) + STUB_CODE


def _build_mz(image: bytes, *, entry_cs: int, entry_ip: int,
              stack_ss: int, stack_sp: int) -> bytes:
    header_size = 2 * 16
    exe_size = header_size + len(image)
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = (exe_size % 512).to_bytes(2, "little")
    header[0x04:0x06] = ((exe_size + 511) // 512).to_bytes(2, "little")
    header[0x06:0x08] = (1).to_bytes(2, "little")
    header[0x08:0x0A] = (2).to_bytes(2, "little")
    header[0x0A:0x0C] = (0x10).to_bytes(2, "little")
    header[0x0C:0x0E] = (0x20).to_bytes(2, "little")
    header[0x0E:0x10] = stack_ss.to_bytes(2, "little")
    header[0x10:0x12] = stack_sp.to_bytes(2, "little")
    header[0x14:0x16] = entry_ip.to_bytes(2, "little")
    header[0x16:0x18] = entry_cs.to_bytes(2, "little")
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    # The single reloc entry must target image padding (module offset
    # 0x20); offset 0 would relocate the caller's CALL opcode bytes and
    # silently corrupt the fixture's direct target.
    header[0x1C:0x1E] = (0x20).to_bytes(2, "little")
    header[0x1E:0x20] = (0).to_bytes(2, "little")
    return bytes(header) + image


def _environment() -> ProgramEnvironment:
    return ProgramEnvironment(
        psp_segment=PSP_SEGMENT,
        allocation=bytes(0x300),
        registers=tuple(
            (name, 0)
            for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
                         "esp", "eflags")
        ),
        fs=0,
        gs=0,
    )


def _boot(*, entry_cs: int = 0, entry_ip: int = 0x30,
          stack_ss: int = 0x10, stack_sp: int = 0x100) -> ProgramBoot:
    mz = _build_mz(_build_image(), entry_cs=entry_cs, entry_ip=entry_ip,
                   stack_ss=stack_ss, stack_sp=stack_sp)
    ranges = (
        LinearRange(0x1000, len(CALLER_CODE)),
        LinearRange(0x1013, len(CALLEE_CODE)),
        LinearRange(0x1030, len(STUB_CODE)),
    )
    return program_from_mz_bytes(mz, _environment(), code_ranges=ranges)


def _recompute(boot: object) -> object:
    """Replay the deterministic boot authority for one boot-shaped value."""
    typed = cast(ProgramBoot, boot)
    return program_from_mz_bytes(
        typed.source, typed.environment, code_ranges=typed.image.code_ranges
    )


def _world(boot: ProgramBoot) -> tuple:
    """Build the registered caller/callee/stub world for one boot image."""
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={"backend": "blob", "arch": Arch86_16(),
                   "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    boundaries = (
        exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(CALLER_CODE)),
        exact_function_range_boundary_8616(project, 0x1013, 0x1013 + len(CALLEE_CODE)),
        exact_function_range_boundary_8616(project, 0x1030, 0x1036),
    )
    for boundary in boundaries:
        assert boundary is not None
    raw = tuple(
        build_x86_16_ir_function_artifact(project, boundary)
        for boundary in boundaries
        if boundary is not None
    )
    for artifact in raw:
        publish_function_ir_artifact_8616(project, artifact)
    coverage = tuple(
        prove_ir_boundary_coverage_8616(project, boundary, artifact)
        for boundary, artifact in zip(boundaries, raw, strict=True)
        if boundary is not None
    )
    assert all(item.complete for item in coverage)
    caller_boundary = boundaries[0]
    assert caller_boundary is not None
    index = build_boundary_direct_callsite_index_8616(
        caller_boundary,
        direct_target_resolver=lambda instruction:
            resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    closure = prove_segment_effect_closure_8616(
        coverage[1], build_x86_16_segment_state_artifact(raw[1])
    )
    preservation = prove_segment_call_preservation_8616(
        coverage[0], closure, index, 0x1000
    )
    assert preservation.complete
    return project, coverage[2], raw[2], preservation


def test_initialized_mz_binds_exact_selector_and_disjoint_stores() -> None:
    """Authentic MZ with disjoint header stack proves the singleton domain."""
    boot = _boot()
    project, stub_coverage, stub_raw, preservation = _world(boot)
    premise = prove_real16_invocation_domain_8616(
        project, stub_coverage, 0x1032, boot=boot, boot_recompute=_recompute,
        call_preservations=(preservation,),
    )
    assert premise.complete
    assert premise.domain_interval == (0x1000, 0x10FFF)
    assert (premise.stack_segment, premise.stack_offset) == (0x110, 0x100)
    assert premise.load_segment == LOAD_SEGMENT
    assert premise.fetched_range_count == 3
    assert premise.checked_store_count == 4
    call_block = next(b for b in stub_raw.blocks if b.addr == 0x1030)
    assert real16_invocation_discharges_8616(
        premise, project=project, block=call_block,
        callsite_addr=0x1032, target_addr=0x1035,
    )
    assert not real16_invocation_discharges_8616(
        premise, project=project, block=call_block,
        callsite_addr=0x1030, target_addr=0x1035,
    )


def test_self_modifying_stack_into_fetched_call_bytes_refuses() -> None:
    """SS:100/SP:34 pushes through the future CALL bytes: explicit refuse."""
    boot = _boot(stack_ss=0x00, stack_sp=0x34)
    project, stub_coverage, _, preservation = _world(boot)
    premise = prove_real16_invocation_domain_8616(
        project, stub_coverage, 0x1032, boot=boot, boot_recompute=_recompute,
        call_preservations=(preservation,),
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    # Real five-stage census: rows before the violating store were
    # classified and materialized; the refused row is classified but not
    # materialized.
    assert premise.failure_count == 1
    assert premise.materialized_count < premise.classified_fact_count
    assert premise.raw_fact_count > premise.materialized_count


def test_callsite_frame_store_into_fetched_call_tail_refuses() -> None:
    """SP:36 lands push + CALL return-frame stores on 0x1034/0x1035."""
    boot = _boot(stack_ss=0x00, stack_sp=0x36)
    project, stub_coverage, _, preservation = _world(boot)
    premise = prove_real16_invocation_domain_8616(
        project, stub_coverage, 0x1032, boot=boot, boot_recompute=_recompute,
        call_preservations=(preservation,),
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.CODE_WRITE_VIOLATION


def _stub_with_injected_row(boot: ProgramBoot, injected: IRInstr) -> tuple:
    """Build a fresh stub world with one opaque row prepended to its head."""
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={"backend": "blob", "arch": Arch86_16(),
                   "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(project, 0x1030, 0x1036)
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    raw = replace(raw, blocks=tuple(
        replace(block, instrs=(injected, *block.instrs))
        if block.addr == 0x1030 else block
        for block in raw.blocks
    ))
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    return project, coverage


def _assert_closed_refusal(
    premise: Real16InvocationDomain8616,
    failure: Real16InvocationFailure8616,
) -> None:
    """Closed-ledger contract: classified == materialized + failure."""
    assert not premise.complete
    assert premise.failure is failure
    assert premise.failure_count >= 1
    assert premise.classified_fact_count == (
        premise.materialized_count + premise.failure_count
    )


def _assert_native_refusal_closed(premise: Real16InvocationDomain8616) -> None:
    """A native-binding refusal classifies each in-scope row once."""
    _assert_closed_refusal(
        premise, Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    )
    # Binding precedes materialization: an unbound block materializes
    # nothing, so every classified row accounts for exactly one failure.
    assert premise.materialized_count == 0
    assert premise.failure_count == premise.classified_fact_count
    assert premise.refusal_site is not None


def test_opaque_destination_effects_refuse() -> None:
    """Unknown raw effects must refuse, whatever their destination.

    Two layers now answer: an *injected* foreign row is unbound (it is not
    what the importer re-derives) and refuses ``native_effect_unproven``
    before simulation, while an *authentic* importer-emitted row the scalar
    classifier cannot close still refuses ``path_effect_unproven``.
    """
    boot = _boot()
    injected = (
        IRInstr("DIRTY", IRValue(MemSpace.TMP, name="opaque", source_tmp=9000,
                                 size=4), (), size=4, addr=0x1030),
        IRInstr("DIRTY", IRValue(MemSpace.REG, name="bx", size=2),
                (), size=2, addr=0x1030),
        IRInstr("Iop_Mul16", IRValue(MemSpace.TMP, source_tmp=9001, size=2),
                (IRValue(MemSpace.CONST, const=3, size=2),
                 IRValue(MemSpace.CONST, const=4, size=2)),
                size=2, addr=0x1030),
    )
    for row in injected:
        project, coverage = _stub_with_injected_row(boot, row)
        premise = prove_real16_invocation_domain_8616(
            project, coverage, 0x1032, boot=boot, boot_recompute=_recompute,
        )
        _assert_native_refusal_closed(premise)


def test_authentic_unsupported_effect_refuses_path_effect_unproven() -> None:
    """A genuine ``mul`` row the classifier cannot close refuses cleanly.

    The authentic ``mul bx`` lift emits ``Iop_Mul16`` TMP writes the
    authoritative scalar classifier marks ``unknown/unsupported_op``;
    binding passes (the artifact is byte-exact) so the refusal comes from
    the classifier itself — the opaque-effect control at its real layer.
    """
    mul_code = bytes.fromhex("16 1f f6e3 e8c9ff c3")
    image = _build_image()[:0x30] + mul_code
    boot = program_from_mz_bytes(
        _build_mz(image, entry_cs=0, entry_ip=0x30,
                  stack_ss=0x10, stack_sp=0x100),
        _environment(), code_ranges=(LinearRange(0x1030, len(mul_code)),),
    )
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={"backend": "blob", "arch": Arch86_16(),
                   "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(project, 0x1030, 0x1038)
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    premise = prove_real16_invocation_domain_8616(
        project, coverage, 0x1034, boot=boot, boot_recompute=_recompute,
    )
    _assert_closed_refusal(
        premise, Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    )
    assert premise.materialized_count < premise.classified_fact_count


def _stub_with_mutated_artifact(
    boot: ProgramBoot, mutate: Callable[[IRBlock], IRBlock]
) -> tuple:
    """Build a stub world with ``mutate`` applied to each artifact block.

    ``mutate`` receives the authentic imported ``IRBlock`` — so a test can
    copy its rows or origin tags — and returns the replacement block.
    """
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={"backend": "blob", "arch": Arch86_16(),
                   "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(project, 0x1030, 0x1036)
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    raw = replace(raw, blocks=tuple(mutate(block) for block in raw.blocks))
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    return project, coverage


def _prove_stub(
    boot: ProgramBoot,
    project: angr.Project,
    coverage: IRBoundaryCoverageResult8616,
) -> Real16InvocationDomain8616:
    """Prove the stub premise for one (possibly mutated) coverage."""
    return prove_real16_invocation_domain_8616(
        project, coverage, 0x1032, boot=boot, boot_recompute=_recompute,
    )


def test_inserted_scalar_row_refuses_native_effect_unproven() -> None:
    """A fabricated scalar MOV sharing a native address cannot repair SMC.

    This is the parent counterexample verbatim: the authentic SS:0x100/
    SP:0x34 stub pushes through the following CALL bytes and must refuse
    ``code_write_violation``; a fabricated ``MOV sp, 0x100`` prepended at
    the push's own address must not earn ``proven``.
    """
    boot = _boot(stack_ss=0x00, stack_sp=0x34)
    project, coverage = _stub_with_injected_row(
        boot,
        IRInstr("MOV", IRValue(MemSpace.REG, name="sp", size=2),
                (IRValue(MemSpace.CONST, const=0x100, size=2),),
                size=2, addr=0x1030),
    )
    premise = _prove_stub(boot, project, coverage)
    _assert_native_refusal_closed(premise)


def test_tampered_source_operand_refuses_native_effect_unproven() -> None:
    """An altered CALL operand rejects the block even at the callsite row."""
    boot = _boot()

    def mutate(block: IRBlock) -> IRBlock:
        if block.addr != 0x1030:
            return block
        call = block.instrs[-1]
        assert call.op == "CALL" and call.addr == 0x1032
        forged = replace(
            call,
            args=(*call.args, IRValue(MemSpace.CONST, const=7, size=2)),
        )
        return replace(block, instrs=(*block.instrs[:-1], forged))

    project, coverage = _stub_with_mutated_artifact(boot, mutate)
    premise = _prove_stub(boot, project, coverage)
    _assert_native_refusal_closed(premise)


def test_copied_origin_tag_does_not_repair_fabricated_row() -> None:
    """An injected row carrying an authentic origin still refuses."""
    boot = _boot()

    def mutate(block: IRBlock) -> IRBlock:
        if block.addr != 0x1030:
            return block
        forged = IRInstr(
            "MOV", IRValue(MemSpace.REG, name="sp", size=2),
            (IRValue(MemSpace.CONST, const=0x100, size=2),),
            size=2, addr=0x1030, origin=block.instrs[0].origin,
        )
        return replace(block, instrs=(forged, *block.instrs))

    project, coverage = _stub_with_mutated_artifact(boot, mutate)
    premise = _prove_stub(boot, project, coverage)
    _assert_native_refusal_closed(premise)


def test_mutated_capture_id_refuses_native_effect_unproven() -> None:
    """A ``source_tmp`` shift invisible to ``==`` must still refuse.

    ``IRValue.source_tmp`` is ``compare=False`` yet the simulator consumes
    it for capture evaluation; the parent counterexample changed capture0
    to 10000 while ``native_block == block`` stayed True. Exact binding
    covers every declared field, so the mutated block refuses.
    """
    boot = _boot()

    def mutate(block: IRBlock) -> IRBlock:
        if block.addr != 0x1030:
            return block
        for index, row in enumerate(block.instrs):
            dst = row.dst
            if (
                isinstance(dst, IRValue)
                and dst.space is MemSpace.TMP
                and dst.source_tmp is not None
            ):
                altered = replace(
                    row, dst=replace(dst, source_tmp=dst.source_tmp + 10000)
                )
                candidate = replace(
                    block,
                    instrs=(
                        *block.instrs[:index],
                        altered,
                        *block.instrs[index + 1:],
                    ),
                )
                # The defect under test: ordinary equality stays blind.
                assert candidate == block
                return candidate
        raise AssertionError("no TMP capture row in head block")

    project, coverage = _stub_with_mutated_artifact(boot, mutate)
    premise = _prove_stub(boot, project, coverage)
    _assert_native_refusal_closed(premise)


def test_dropped_native_row_refuses_native_effect_unproven() -> None:
    """Deleting the terminal CALL row must refuse, not shrink effects."""
    boot = _boot()

    def mutate(block: IRBlock) -> IRBlock:
        if block.addr != 0x1030:
            return block
        assert block.instrs[-1].op == "CALL"
        return replace(block, instrs=block.instrs[:-1])

    project, coverage = _stub_with_mutated_artifact(boot, mutate)
    premise = _prove_stub(boot, project, coverage)
    _assert_native_refusal_closed(premise)


def test_forged_boot_fields_and_unbound_invocation_refuse() -> None:
    """Tampered declared identity and absent boot evidence refuse."""
    boot = _boot()
    project, stub_coverage, _, preservation = _world(boot)
    forged_fields = {f.name: getattr(boot, f.name) for f in fields(boot)}
    forged_fields["boot_sha256"] = "0" * 64
    premise = prove_real16_invocation_domain_8616(
        project, stub_coverage, 0x1032, boot=SimpleNamespace(**forged_fields),
        boot_recompute=_recompute, call_preservations=(preservation,),
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.BOOT_NOT_REPRODUCED
    unbound = prove_real16_invocation_domain_8616(
        project, stub_coverage, 0x1032, boot=None, boot_recompute=None,
    )
    assert not unbound.complete
    assert unbound.failure is Real16InvocationFailure8616.BOOT_UNBOUND


def test_loop_carried_stack_write_revokes_materialization() -> None:
    """A backedge can invalidate SP and the earlier STORE's proof ledger."""
    code = bytes.fromhex("16 75fd e8caff c3")
    image = _build_image()[:0x30] + code
    boot = program_from_mz_bytes(
        _build_mz(image, entry_cs=0, entry_ip=0x30, stack_ss=0, stack_sp=0x3A),
        _environment(), code_ranges=(LinearRange(0x1030, len(code)),),
    )
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={"backend": "blob", "arch": Arch86_16(),
                   "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(project, 0x1030, 0x1037)
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    assert coverage.complete
    premise = prove_real16_invocation_domain_8616(
        project, coverage, 0x1033, boot=boot, boot_recompute=_recompute,
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN
    assert premise.failure_count == 1
    assert premise.classified_fact_count == (
        premise.materialized_count + premise.failure_count
    )


def test_loop_capture_mutation_refuses_native_effect_unproven() -> None:
    """A ``source_tmp`` shift inside a fixpoint-revisited block refuses.

    The loop head is simulated repeatedly under the path fixpoint; its
    mutated capture id must refuse on binding and leave no stale
    materialization — the durable repeated-visit control.
    """
    code = bytes.fromhex("16 75fd e8caff c3")
    image = _build_image()[:0x30] + code
    boot = program_from_mz_bytes(
        _build_mz(image, entry_cs=0, entry_ip=0x30, stack_ss=0, stack_sp=0x3A),
        _environment(), code_ranges=(LinearRange(0x1030, len(code)),),
    )
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={"backend": "blob", "arch": Arch86_16(),
                   "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(project, 0x1030, 0x1037)
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)

    def mutate(block: IRBlock) -> IRBlock:
        if block.addr != 0x1030:
            return block
        for index, row in enumerate(block.instrs):
            dst = row.dst
            if (
                isinstance(dst, IRValue)
                and dst.space is MemSpace.TMP
                and dst.source_tmp is not None
            ):
                altered = replace(
                    row, dst=replace(dst, source_tmp=dst.source_tmp + 10000)
                )
                mutated = replace(
                    block,
                    instrs=(
                        *block.instrs[:index],
                        altered,
                        *block.instrs[index + 1:],
                    ),
                )
                assert mutated == block
                return mutated
        raise AssertionError("no TMP capture row in loop head")

    raw = replace(raw, blocks=tuple(mutate(block) for block in raw.blocks))
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    assert coverage.complete
    premise = prove_real16_invocation_domain_8616(
        project, coverage, 0x1033, boot=boot, boot_recompute=_recompute,
    )
    _assert_native_refusal_closed(premise)


def test_native_binding_field_sets_cover_declared_fields() -> None:
    """Each owned comparator field set must equal the node's declared fields.

    The binding comparators fail closed when a node's declared field set
    drifts from the owned expectation; this guard keeps every expectation
    honest so a newly added IR field can never be silently skipped.
    """
    from angr_platforms.X86_16.ir import real16_invocation_domain as dom
    from angr_platforms.X86_16.ir.instruction_origin import (
        IRInstructionOrigin8616,
    )

    pairs = (
        (dom._IR_BLOCK_FIELDS_8616, IRBlock),
        (dom._IR_INSTR_FIELDS_8616, IRInstr),
        (dom._IR_VALUE_FIELDS_8616, IRValue),
        (dom._IR_BINARY_VALUE_FIELDS_8616, IRBinaryValue),
        (dom._IR_ADDRESS_FIELDS_8616, IRAddress),
        (dom._IR_CONDITION_FIELDS_8616, IRCondition),
        (dom._IR_CALL_EFFECT_FIELDS_8616, IRCallStackEffect8616),
        (dom._IR_CALL_OUTPUT_FIELDS_8616, IRCallOutputProvenance8616),
        (dom._IR_ORIGIN_FIELDS_8616, IRInstructionOrigin8616),
        (dom._IR_REFUSAL_FIELDS_8616, IRRefusal),
    )
    for expected, node_type in pairs:
        assert expected == {member.name for member in fields(node_type)}
