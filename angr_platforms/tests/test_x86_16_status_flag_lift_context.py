from __future__ import annotations

import io
from types import SimpleNamespace
from typing import Any

import angr
import pytest
from angr.analyses.decompiler.clinic import Clinic
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.compat import apply_x86_16_compatibility
from angr_platforms.X86_16.ir import status_flag_lift_context
from angr_platforms.X86_16.ir.status_flag_lift_context import (
    StatusFlagLiftArtifact8616,
    StatusFlagLiftArtifactSource8616,
    StatusFlagLiftCandidate8616,
    StatusFlagLiftSession8616,
    active_status_flag_lift_artifact_8616,
    active_status_flag_lift_context_8616,
    published_status_flag_lift_artifact_8616,
    resolve_status_flag_lift_artifact_8616,
)
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.semantics.status_flag_contracts import (
    INCDEC_STATUS_FLAG_WRITES_8616,
    SHIFT_COUNT_MANY_STATUS_FLAG_WRITES_8616,
    SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616,
    STATUS_FLAGS_8616,
    StatusFlag8616,
)
from angr_platforms.X86_16.validation.status_flag_preservation import (
    packed_status_flag_preservation_evidence_8616,
)
from pyvex.expr import Binop
from pyvex.stmt import Put, WrTmp


def _project_function(
    code: bytes,
    *,
    function_starts: tuple[int, ...],
) -> tuple[angr.Project, Any]:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        simos="DOS",
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=list(function_starts),
        regions=[(0x1000, 0x1000 + len(code))],
        normalize=True,
        force_complete_scan=False,
    )
    return project, cfg.functions[0x1000]


def _flags_puts(project: angr.Project, block_address: int) -> tuple[Put, ...]:
    block = project.factory.block(block_address, opt_level=0)
    flags_offset = project.arch.get_register_offset("flags")
    assert block.vex is not None
    return tuple(
        statement
        for statement in block.vex.statements
        if isinstance(statement, Put) and statement.offset == flags_offset
    )


def test_cfg_context_suppresses_writes_across_call_and_block_boundary() -> None:
    code = bytes.fromhex("050100 e80a00 83c402 39d8 7500 c3 9090 29db c3")
    project, function = _project_function(
        code,
        function_starts=(0x1000, 0x1010),
    )

    with active_status_flag_lift_context_8616(project, function) as session:
        assert {candidate.instruction_address for candidate in session.candidates} == {
            0x1000,
            0x1006,
        }
        assert _flags_puts(project, 0x1000) == ()
        _flags_puts(project, 0x1006)
        assert session.materialized_addresses == frozenset({0x1000, 0x1006})

    assert session.stats.complete
    assert function.info["status_flag_lift_stats_8616"] == session.stats.to_dict()


@pytest.mark.parametrize("producer", ("050100", "a90100", "f646fc01"))
def test_cfg_context_keeps_flags_consumed_by_successor_condition(producer: str) -> None:
    code = bytes.fromhex(producer + "7500 c3")
    project, function = _project_function(code, function_starts=(0x1000,))

    with active_status_flag_lift_context_8616(project, function) as session:
        assert session.candidates == ()
        assert _flags_puts(project, 0x1000)

    assert session.stats.complete
    assert session.materialized_addresses == frozenset()


def test_cfg_context_reuses_nested_same_function_session(monkeypatch: pytest.MonkeyPatch) -> None:
    project, function = _project_function(
        bytes.fromhex("050100 7500 c3"),
        function_starts=(0x1000,),
    )
    from angr_platforms.X86_16.ir import status_flag_cfg_projection

    original = status_flag_cfg_projection.build_status_flag_function_projection_8616
    calls = 0

    def _counted_projection(project_arg: object, function_arg: object) -> object:
        nonlocal calls
        calls += 1
        return original(project_arg, function_arg)

    monkeypatch.setattr(
        status_flag_cfg_projection,
        "build_status_flag_function_projection_8616",
        _counted_projection,
    )
    with (
        active_status_flag_lift_context_8616(project, function) as outer,
        active_status_flag_lift_context_8616(project, function) as inner,
    ):
        assert inner is outer

    assert calls == 1
    assert outer.stats.complete


def test_cfg_context_rejects_nested_different_function() -> None:
    project, function = _project_function(
        bytes.fromhex("c3 909090 c3"),
        function_starts=(0x1000, 0x1004),
    )
    other = project.kb.functions[0x1004]

    with (
        active_status_flag_lift_context_8616(project, function),
        pytest.raises(PipelineHardError, match="changed function identity") as error,
        active_status_flag_lift_context_8616(project, other),
    ):
        pass

    assert error.value.function_addr == other.addr
    assert error.value.details == {"active_function_addr": 0x1000}


def test_cfg_context_suppresses_cmp_flags_overwritten_before_use() -> None:
    project, function = _project_function(
        bytes.fromhex("39d8 39ca 7500 c3"),
        function_starts=(0x1000,),
    )

    with active_status_flag_lift_context_8616(project, function) as session:
        assert {candidate.instruction_address for candidate in session.candidates} == {0x1000}
        assert _flags_puts(project, 0x1000) == ()
        assert session.materialized_addresses == frozenset({0x1000})

    assert session.stats.complete


@pytest.mark.parametrize("producer", ("050100", "a90100", "f646fc01"))
def test_cfg_context_emits_only_the_status_bit_live_at_successor_condition(producer: str) -> None:
    code = bytes.fromhex(producer + "7500 39d8 c3")
    overwrite_address = 0x1000 + len(bytes.fromhex(producer)) + 2
    project, function = _project_function(code, function_starts=(0x1000,))

    with active_status_flag_lift_context_8616(project, function) as session:
        assert len(session.candidates) == 1
        candidate = session.candidates[0]
        assert candidate.instruction_address == function.addr
        assert candidate.written == STATUS_FLAGS_8616
        assert candidate.dead_writes == STATUS_FLAGS_8616 & ~StatusFlag8616.ZERO
        block = project.factory.block(0x1000, opt_level=0)
        assert block.vex is not None
        operations = {
            statement.data.op
            for statement in block.vex.statements
            if isinstance(statement, WrTmp) and isinstance(statement.data, Binop)
        }
        assert "Iop_Xor8" not in operations
        assert "Iop_Xor16" not in operations
        assert _flags_puts(project, 0x1000)
        assert session.materialized_addresses == frozenset({0x1000})
        artifact = active_status_flag_lift_artifact_8616(function.addr)
        assert isinstance(artifact, StatusFlagLiftArtifact8616)
        assert artifact.partial_write_addresses == frozenset({0x1000})
        assert artifact.packed_preservation_addresses == frozenset({0x1000, overwrite_address})
        active_resolution = resolve_status_flag_lift_artifact_8616(project, function.addr)
        assert active_resolution is not None
        assert active_resolution.artifact == artifact
        assert active_resolution.source is StatusFlagLiftArtifactSource8616.ACTIVE

    assert session.stats.complete
    published = published_status_flag_lift_artifact_8616(function)
    assert isinstance(published, StatusFlagLiftArtifact8616)
    assert published.packed_preservation_addresses == frozenset({0x1000, overwrite_address})
    published_resolution = resolve_status_flag_lift_artifact_8616(project, function.addr)
    assert published_resolution is not None
    assert published_resolution.artifact == published
    assert published_resolution.source is StatusFlagLiftArtifactSource8616.PUBLISHED
    evidence = packed_status_flag_preservation_evidence_8616(
        project,
        SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr)),
    )
    assert evidence is not None
    assert evidence.covers_instruction(0x1000)


@pytest.mark.parametrize("opcode", ("d1e0", "d1e8", "d1f8"))
def test_cfg_context_emits_only_live_shift_status_bit(opcode: str) -> None:
    project, function = _project_function(
        bytes.fromhex(f"{opcode} 7500 39d8 c3"),
        function_starts=(0x1000,),
    )

    with active_status_flag_lift_context_8616(project, function) as session:
        assert len(session.candidates) == 1
        candidate = session.candidates[0]
        assert candidate.written == SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616
        assert candidate.dead_writes == candidate.written & ~StatusFlag8616.ZERO
        block = project.factory.block(0x1000, opt_level=0)
        assert block.vex is not None
        operations = {
            statement.data.op
            for statement in block.vex.statements
            if isinstance(statement, WrTmp) and isinstance(statement.data, Binop)
        }
        assert "Iop_Xor8" not in operations
        assert "Iop_Xor16" not in operations
        assert _flags_puts(project, 0x1000)

    assert session.stats.complete


def test_cfg_context_retains_live_incdec_flags_for_typed_jcc() -> None:
    project, function = _project_function(
        bytes.fromhex("48 7d00 39d8 c3"),
        function_starts=(0x1000,),
    )

    with active_status_flag_lift_context_8616(project, function) as session:
        assert len(session.candidates) == 1
        candidate = session.candidates[0]
        assert candidate.instruction_address == function.addr
        assert candidate.written == INCDEC_STATUS_FLAG_WRITES_8616
        assert candidate.dead_writes == INCDEC_STATUS_FLAG_WRITES_8616 & ~(
            StatusFlag8616.SIGN | StatusFlag8616.OVERFLOW
        )
        # A typed branch does not prove its architectural SF/OF outputs dead.
        assert _flags_puts(project, 0x1000)
        assert session.materialized_addresses == frozenset({0x1000})

    assert session.stats.complete


@pytest.mark.parametrize("opcode", ("11ca", "19ca"))
def test_cfg_context_omits_dead_carry_arithmetic_output_flags(opcode: str) -> None:
    project, function = _project_function(
        bytes.fromhex(f"01d8 {opcode} 39db c3"),
        function_starts=(0x1000,),
    )

    with active_status_flag_lift_context_8616(project, function) as session:
        candidate_by_address = {
            candidate.instruction_address: candidate for candidate in session.candidates
        }
        carry_arithmetic = candidate_by_address[0x1002]
        assert carry_arithmetic.written == STATUS_FLAGS_8616
        assert carry_arithmetic.dead_writes == STATUS_FLAGS_8616
        _flags_puts(project, 0x1000)
        assert carry_arithmetic.instruction_address in session.materialized_addresses

    assert session.stats.complete


def test_cfg_context_rejects_classified_but_unmaterialized_decisions() -> None:
    code = bytes.fromhex("050100 e80a00 83c402 39d8 7500 c3 9090 29db c3")
    project, function = _project_function(
        code,
        function_starts=(0x1000, 0x1010),
    )

    with (
        pytest.raises(PipelineHardError, match="not consumed") as error,
        active_status_flag_lift_context_8616(project, function) as session,
    ):
        assert session.candidates

    assert error.value.layer == "ir:status_flag_lift_context"
    expected_decision_count = 2
    assert error.value.details["classified_fact_count"] == expected_decision_count
    assert error.value.details["materialized_count"] == 0


def test_session_consumes_original_address_candidate_from_rebased_slice() -> None:
    candidate = StatusFlagLiftCandidate8616(
        instruction_address=0x1419B,
        written=SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616,
        dead_writes=SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616,
    )
    session = StatusFlagLiftSession8616(
        function_address=0x14199,
        candidates=(candidate,),
        original_linear_delta=0x13199,
    )

    dead = session.dead_write_mask(0x1002, SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616)

    assert dead == SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616
    assert session.materialized_addresses == frozenset({0x1419B})
    session.finalize()
    assert session.stats.complete


def test_narrow_relift_does_not_shrink_published_preservation_coverage() -> None:
    """A fallback subset cannot erase full-function packed-FLAGS evidence."""
    function = SimpleNamespace(info={})
    full = StatusFlagLiftSession8616(
        function_address=0x1000,
        candidates=(),
        packed_preservation_addresses=frozenset({0x1000, 0x1004, 0x1008}),
    )
    full.finalize()
    status_flag_lift_context._publish_stats_8616(function, full)
    narrow = StatusFlagLiftSession8616(
        function_address=0x1000,
        candidates=(),
        packed_preservation_addresses=frozenset({0x1000}),
    )
    narrow.finalize()
    status_flag_lift_context._publish_stats_8616(function, narrow)

    published = published_status_flag_lift_artifact_8616(function)
    assert published is not None
    assert published.packed_preservation_addresses == full.packed_preservation_addresses


def test_clinic_fast_relift_does_not_bypass_custom_x86_16_lifter() -> None:
    apply_x86_16_compatibility()
    clinic = SimpleNamespace(project=SimpleNamespace(arch=SimpleNamespace(name="86_16")))

    assert Clinic._convert_vex_fast(clinic, object()) is None


def test_cfg_context_consumes_defined_multibit_shift_writes() -> None:
    project, function = _project_function(
        bytes.fromhex("c1ee04 c1ef04 7500 c3"),
        function_starts=(0x1000,),
    )

    with active_status_flag_lift_context_8616(project, function) as session:
        candidate = next(candidate for candidate in session.candidates if candidate.instruction_address == function.addr)
        assert candidate.written == SHIFT_COUNT_MANY_STATUS_FLAG_WRITES_8616
        _flags_puts(project, 0x1000)
        assert function.addr in session.materialized_addresses

    assert session.stats.complete
