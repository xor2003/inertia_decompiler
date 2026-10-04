from __future__ import annotations

from types import SimpleNamespace

import pytest
import pyvex
from angr_platforms.X86_16.semantics.status_flag_contracts import (
    STATUS_FLAGS_8616,
    DecodedStatusFlagInstruction8616,
    StatusFlag8616,
    StatusFlagLivenessStats8616,
    StatusFlagLivenessVerdict8616,
)
from angr_platforms.X86_16.semantics.status_flag_liveness import (
    decide_status_flag_liveness_8616,
    decoded_status_flag_instruction_8616,
    status_flag_effect_8616,
    status_flags_dead_before_use_8616,
)
from pyvex.stmt import Put


def _instruction(mnemonic: str, immediate_count: int | None = None) -> DecodedStatusFlagInstruction8616:
    return DecodedStatusFlagInstruction8616(mnemonic, immediate_count)


def test_partial_writers_cumulatively_kill_all_previous_status_flags() -> None:
    future = (_instruction("inc"), _instruction("shl", 1))

    assert status_flags_dead_before_use_8616(STATUS_FLAGS_8616, future)


def test_sortd_109e8_sub_flags_die_through_sar_mov_inc_sequence() -> None:
    future = (_instruction("sar", 1), _instruction("mov"), _instruction("inc"))

    decision = decide_status_flag_liveness_8616(STATUS_FLAGS_8616, future)

    assert decision.verdict is StatusFlagLivenessVerdict8616.SUPPRESS_DEAD
    assert decision.suppresses_write
    assert decision.stats.closed
    assert decision.stats.complete
    assert (
        decision.stats.raw_fact_count,
        decision.stats.normalized_fact_count,
        decision.stats.classified_fact_count,
        decision.stats.materialized_count,
        decision.stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_inc_preserves_carry_consumed_by_adc() -> None:
    future = (_instruction("inc"), _instruction("adc"))

    assert not status_flags_dead_before_use_8616(STATUS_FLAGS_8616, future)


def test_explicit_carry_overwrite_breaks_dependency_before_adc() -> None:
    future = (_instruction("inc"), _instruction("clc"), _instruction("adc"))

    assert status_flags_dead_before_use_8616(STATUS_FLAGS_8616, future)


def test_condition_consumer_keeps_only_the_bits_it_reads() -> None:
    future = (_instruction("mov"), _instruction("setne"))

    assert not status_flags_dead_before_use_8616(StatusFlag8616.ZERO, future)
    assert status_flags_dead_before_use_8616(StatusFlag8616.CARRY, (*future, _instruction("cmp")))


def test_unknown_instruction_refuses_dead_flag_proof() -> None:
    decision = decide_status_flag_liveness_8616(
        STATUS_FLAGS_8616,
        (_instruction("unknown_opcode"), _instruction("cmp")),
    )

    assert decision.verdict is StatusFlagLivenessVerdict8616.KEEP_UNKNOWN
    assert not decision.suppresses_write
    assert decision.stats.closed
    assert not decision.stats.complete
    assert decision.stats.failure_count == 1


def test_classified_flag_decision_cannot_escape_without_materialization() -> None:
    with pytest.raises(ValueError, match="not materialized"):
        StatusFlagLivenessStats8616(1, 1, 1, 0, 1)


def test_capstone_boundary_adapter_keeps_immediate_shift_count() -> None:
    decoded = decoded_status_flag_instruction_8616(
        SimpleNamespace(
            cs=SimpleNamespace(
                mnemonic="sar",
                operands=(SimpleNamespace(type=1), SimpleNamespace(type=2, imm=1)),
            )
        )
    )

    assert decoded == DecodedStatusFlagInstruction8616("sar", 1)


@pytest.mark.parametrize(
    ("mnemonic", "expected"),
    (
        ("rep stosw", DecodedStatusFlagInstruction8616("stosw", None)),
        ("repne scasb", DecodedStatusFlagInstruction8616("scasb", None)),
    ),
)
def test_capstone_boundary_adapter_normalizes_semantic_instruction_prefixes(
    mnemonic: str,
    expected: DecodedStatusFlagInstruction8616,
) -> None:
    """Capstone prefixes must not turn known string operations into unknowns."""
    decoded = decoded_status_flag_instruction_8616(
        SimpleNamespace(cs=SimpleNamespace(mnemonic=mnemonic, operands=()))
    )

    assert decoded == expected
    assert decoded is not None
    effect = status_flag_effect_8616(decoded)
    assert effect is not None
    if expected.mnemonic == "stosw":
        assert effect.overwrites == StatusFlag8616.NONE
    else:
        assert effect.overwrites == STATUS_FLAGS_8616


def test_simple_lifter_suppresses_add_flags_before_later_cmp() -> None:
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction._future_instructions = (
        SimpleNamespace(cs=SimpleNamespace(mnemonic="mov")),
        SimpleNamespace(cs=SimpleNamespace(mnemonic="cmp")),
    )

    assert not instruction._should_update_binop_flags_8616("add", logical_condition_recorded=False)


def test_simple_lifter_without_lookahead_keeps_flags() -> None:
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    instruction = Instruction_ANY.__new__(Instruction_ANY)

    assert instruction._should_update_binop_flags_8616("add", logical_condition_recorded=False)


def test_simple_lifter_keeps_sub_carry_for_inc_then_adc() -> None:
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction._future_instructions = (
        SimpleNamespace(cs=SimpleNamespace(mnemonic="inc")),
        SimpleNamespace(cs=SimpleNamespace(mnemonic="adc")),
    )

    assert instruction._should_update_binop_flags_8616("sub", logical_condition_recorded=False)


def test_full_lifter_omits_dead_sortd_status_flag_chain() -> None:
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401

    # SUB; SAR; MOV; INC; SHL; SHL; CMP; JG. Intermediate status-bit
    # definitions die, but the final CMP FLAGS remain live at the cutpoint.
    code = bytes.fromhex("2bc2 d1f8 89c3 40 d1e1 d1e3 39d8 7f00")
    arch = Arch86_16()
    irsb = pyvex.lift(code, 0x1000, arch, max_inst=20, opt_level=0)
    flags_offset = arch.get_register_offset("flags")

    current_address = None
    flag_writes = []
    for statement in irsb.statements:
        if isinstance(statement, pyvex.stmt.IMark):
            current_address = statement.addr
        if isinstance(statement, Put) and statement.offset == flags_offset:
            flag_writes.append(current_address)
    assert flag_writes == [0x100b]


def test_wide_stack_compare_retains_flags_and_typed_condition() -> None:
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401

    # cmp word ptr [bp+4], 0; jne next. The byte-safe word load is the typed
    # condition source; architectural FLAGS must also survive the branch.
    arch = Arch86_16()
    irsb = pyvex.lift(bytes.fromhex("837e0400 7500"), 0x1000, arch, max_inst=2, opt_level=0)
    flags_offset = arch.get_register_offset("flags")

    assert any(isinstance(statement, Put) and statement.offset == flags_offset for statement in irsb.statements)
    assert "CmpNE16" in str(irsb)


def test_full_lifter_keeps_observable_standalone_shift_flags() -> None:
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401

    arch = Arch86_16()
    irsb = pyvex.lift(bytes.fromhex("d1e0"), 0x1000, arch, max_inst=1, opt_level=0)
    flags_offset = arch.get_register_offset("flags")

    assert any(isinstance(statement, Put) and statement.offset == flags_offset for statement in irsb.statements)


def test_lifter_max_inst_excludes_decoded_suffix_from_flag_liveness() -> None:
    """A decoded instruction outside the requested lift cannot kill live flags."""
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401

    # SHL AX, 1; XOR AX, AX. The XOR is present in the decode buffer but lies
    # outside max_inst=1, so it cannot prove the SHL flag definition dead.
    arch = Arch86_16()
    irsb = pyvex.lift(bytes.fromhex("d1e0 31c0"), 0x1000, arch, max_inst=1, opt_level=0)
    flags_offset = arch.get_register_offset("flags")

    assert any(isinstance(statement, Put) and statement.offset == flags_offset for statement in irsb.statements)
