from __future__ import annotations

from types import SimpleNamespace

from inertia.ir import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
    build_x86_16_function_ssa,
    build_x86_16_segment_state_artifact,
    build_x86_16_typed_string_effect_artifact,
)
from inertia.semantics.string_instruction_artifact import StringInstructionArtifact, StringInstructionRecord
from inertia.lowering.type_array_matching import apply_x86_16_array_expression_matching


def test_segment_state_tracks_explicit_ds_and_es_writes() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr(
                        "MOV", IRValue(MemSpace.REG, name="ds", size=2), (IRValue(MemSpace.REG, name="ax", size=2),)
                    ),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="es", size=2),
                        (IRValue(MemSpace.CONST, const=0xB800, size=2),),
                    ),
                ),
            ),
        ),
    )

    segment_state = build_x86_16_segment_state_artifact(artifact, function_ssa=build_x86_16_function_ssa(artifact))

    assert segment_state.state_at_block_exit(0x1000, "ds").origin is SegmentOrigin.UNKNOWN
    assert segment_state.state_at_block_exit(0x1000, "es").origin is SegmentOrigin.PROVEN
    assert segment_state.state_for_register("ds") is None
    assert segment_state.state_for_register("es") is None
    assert segment_state.summary["explicit_write_count"] == 2
    assert segment_state.summary["classified_fact_count"] == 1
    assert segment_state.summary["materialized_count"] == 1
    assert segment_state.summary["failure_count"] == 1


def test_segment_state_tracks_register_mediated_constant_across_blocks() -> None:
    """A constant loaded through a GP register remains proven after a DS copy."""
    artifact = IRFunctionArtifact(
        function_addr=0x1200,
        blocks=(
            IRBlock(
                addr=0x1200,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="bx", size=2),
                        (IRValue(MemSpace.CONST, const=0x245A, size=2),),
                        addr=0x1200,
                    ),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (IRValue(MemSpace.REG, name="bx", size=2),),
                        addr=0x1203,
                    ),
                ),
                successor_addrs=(0x1210,),
            ),
            IRBlock(
                addr=0x1210,
                instrs=(IRInstr("LOAD", None, (), addr=0x1210),),
            ),
        ),
    )

    segment_state = build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=build_x86_16_function_ssa(artifact),
    )

    state = segment_state.state_before_instruction(0x1210, "ds")
    assert state is not None
    assert state.origin is SegmentOrigin.PROVEN
    assert state.constant_value() == 0x245A


def test_segment_state_unknown_predecessor_poisons_must_join() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(addr=0x1000, successor_addrs=(0x1010, 0x1020)),
            IRBlock(addr=0x1010, successor_addrs=(0x1030,)),
            IRBlock(
                addr=0x1020,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (IRValue(MemSpace.REG, name="ax", size=2),),
                    ),
                ),
                successor_addrs=(0x1030,),
            ),
            IRBlock(addr=0x1030),
        ),
    )

    segment_state = build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=build_x86_16_function_ssa(artifact),
    )

    assert segment_state.state_at_block_exit(0x1010, "ds").origin is SegmentOrigin.PROVEN
    assert segment_state.state_at_block_exit(0x1020, "ds").origin is SegmentOrigin.UNKNOWN
    assert segment_state.state_at_block_entry(0x1030, "ds").origin is SegmentOrigin.UNKNOWN


def test_segment_state_segment_copy_uses_source_identity_at_exact_instruction() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x1400,
        blocks=(
            IRBlock(
                addr=0x1400,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="es", size=2),
                        (IRValue(MemSpace.REG, name="ds", size=2),),
                        addr=0x1400,
                    ),
                ),
            ),
        ),
    )

    segment_state = build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=build_x86_16_function_ssa(artifact),
    )

    before = segment_state.state_before_instruction(0x1400, "es")
    after = segment_state.state_after_instruction(0x1400, "es")
    assert before is not None and before.source == "es"
    assert after is not None and after.source == "ds"
    assert after.value_kind == "segment_copy"
    assert after.origin is SegmentOrigin.PROVEN
    assert segment_state.state_for_register("es") is None


def test_segment_state_without_ssa_derives_cfg_and_reaches_proven_fixpoint() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x1600,
        blocks=(
            IRBlock(addr=0x1600, successor_addrs=(0x1640,)),
            IRBlock(addr=0x1610, successor_addrs=(0x1620,)),
            IRBlock(addr=0x1620, successor_addrs=(0x1610,)),
            IRBlock(addr=0x1640, successor_addrs=(0x1610,)),
        ),
    )

    segment_state = build_x86_16_segment_state_artifact(artifact)

    assert segment_state.state_at_block_entry(0x1600, "ds").origin is SegmentOrigin.PROVEN
    assert segment_state.state_at_block_entry(0x1610, "ds").origin is SegmentOrigin.PROVEN
    assert segment_state.state_at_block_entry(0x1610, "ds").source == "ds"
    assert segment_state.state_at_block_entry(0x1620, "ds").origin is SegmentOrigin.PROVEN
    assert segment_state.state_for_register("ds").origin is SegmentOrigin.PROVEN


def test_segment_state_restores_segment_from_proven_register_value_flow() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x1700,
        blocks=(
            IRBlock(
                addr=0x1700,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ax", size=2),
                        (IRValue(MemSpace.REG, name="ds", size=2),),
                        addr=0x1700,
                    ),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (IRValue(MemSpace.CONST, const=0xB800, size=2),),
                        addr=0x1702,
                    ),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (IRValue(MemSpace.REG, name="ax", size=2),),
                        addr=0x1704,
                    ),
                ),
            ),
        ),
    )

    segment_state = build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=build_x86_16_function_ssa(artifact),
    )

    changed = segment_state.state_after_instruction(0x1702, "ds")
    restored = segment_state.state_after_instruction(0x1704, "ds")
    assert changed is not None and changed.source == "0xb800"
    assert restored is not None and restored.source == "ds"
    assert restored.origin is SegmentOrigin.PROVEN
    assert segment_state.summary["classified_fact_count"] == 2
    assert segment_state.summary["failure_count"] == 0


def test_segment_state_marks_function_entry_segments_as_architectural_live_ins() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x1800,
        blocks=(IRBlock(addr=0x1800),),
    )

    segment_state = build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=build_x86_16_function_ssa(artifact),
    )

    ds_entry = segment_state.entry_states[0x1800]["ds"]
    assert ds_entry.value_kind == "architectural_live_in"
    assert ds_entry.source == "ds"
    assert ds_entry.origin is SegmentOrigin.PROVEN
    assert segment_state.summary["architectural_live_in_count"] == 6


def test_typed_string_effects_become_stable_from_segment_state_and_feed_array_matching() -> None:
    segment_ir = IRFunctionArtifact(
        function_addr=0x2000,
        blocks=(
            IRBlock(
                addr=0x2000,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="es", size=2),
                        (IRValue(MemSpace.REG, name="ds", size=2),),
                        addr=0x2000,
                    ),
                    IRInstr("MOVS", None, (), addr=0x2002),
                ),
            ),
        ),
    )
    segment_state = build_x86_16_segment_state_artifact(segment_ir, function_ssa=build_x86_16_function_ssa(segment_ir))
    string_artifact = build_x86_16_typed_string_effect_artifact(
        StringInstructionArtifact(
            records=(
                StringInstructionRecord(
                    index=0,
                    family="movs",
                    mnemonic="movsw",
                    repeat_kind="rep",
                    width=2,
                    source_segment="ds",
                    destination_segment="es",
                    direction_mode="forward",
                    zero_seeded_accumulator=None,
                    zf_sensitive=False,
                    instruction_addr=0x2002,
                ),
            )
        ),
        segment_state_artifact=segment_state,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x2000),
        project=None,
        _inertia_string_effect_artifact=string_artifact,
    )

    result = apply_x86_16_array_expression_matching(codegen)

    assert result is False
    assert set(codegen._inertia_array_matching_string_candidates) == {
        ("ds", ("si",), 2),
        ("es", ("di",), 2),
    }
    assert codegen._inertia_array_matching_stats["string_arrays"] == 2


def test_typed_string_effects_refuse_destination_after_unknown_segment_write() -> None:
    segment_ir = IRFunctionArtifact(
        function_addr=0x2100,
        blocks=(
            IRBlock(
                addr=0x2100,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="es", size=2),
                        (IRValue(MemSpace.REG, name="ax", size=2),),
                        addr=0x2100,
                    ),
                    IRInstr("MOVS", None, (), addr=0x2102),
                ),
            ),
        ),
    )
    segment_state = build_x86_16_segment_state_artifact(
        segment_ir,
        function_ssa=build_x86_16_function_ssa(segment_ir),
    )
    string_artifact = build_x86_16_typed_string_effect_artifact(
        StringInstructionArtifact(
            records=(
                StringInstructionRecord(
                    index=0,
                    family="movs",
                    mnemonic="movsw",
                    repeat_kind="rep",
                    width=2,
                    source_segment="ds",
                    destination_segment="es",
                    direction_mode="forward",
                    zero_seeded_accumulator=None,
                    zf_sensitive=False,
                    instruction_addr=0x2102,
                ),
            )
        ),
        segment_state_artifact=segment_state,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x2100),
        project=None,
        _inertia_string_effect_artifact=string_artifact,
    )

    result = apply_x86_16_array_expression_matching(codegen)

    assert result is False
    assert set(codegen._inertia_array_matching_string_candidates) == {("ds", ("si",), 2)}
    assert codegen._inertia_array_matching_stats["string_arrays"] == 1


def test_typed_string_effects_without_segment_state_do_not_seed_string_arrays() -> None:
    string_artifact = build_x86_16_typed_string_effect_artifact(
        StringInstructionArtifact(
            records=(
                StringInstructionRecord(
                    index=0,
                    family="movs",
                    mnemonic="movsw",
                    repeat_kind="rep",
                    width=2,
                    source_segment="ds",
                    destination_segment="es",
                    direction_mode="forward",
                    zero_seeded_accumulator=None,
                    zf_sensitive=False,
                ),
            )
        )
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x2000),
        project=None,
        _inertia_string_effect_artifact=string_artifact,
    )

    result = apply_x86_16_array_expression_matching(codegen)

    assert result is False
    assert codegen._inertia_array_matching_string_candidates == {}
    assert codegen._inertia_array_matching_stats["string_arrays"] == 0
