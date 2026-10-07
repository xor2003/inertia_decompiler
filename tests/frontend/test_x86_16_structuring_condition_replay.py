from __future__ import annotations

from types import SimpleNamespace

from inertia.ir.condition_ir import ConditionIR

from inertia.structuring.condition_replay import (
    condition_replay_facts_8616,
    record_condition_replay_fact_8616,
    select_condition_replay_fact_8616,
)


def _condition(src_insn: int = 0x1014) -> ConditionIR:
    return ConditionIR(
        op="sle",
        lhs="left",
        rhs="right",
        src_insn=src_insn,
        block_addr=0x1009,
    )


def test_structuring_condition_replay_records_exact_cfg_targets() -> None:
    codegen = SimpleNamespace()
    condition = _condition()

    record_condition_replay_fact_8616(codegen, condition, 0x102F, 0x1026)
    facts = condition_replay_facts_8616(codegen)

    assert len(facts) == 1
    assert select_condition_replay_fact_8616(condition, facts) == facts[0]
    assert facts[0].true_target == 0x102F
    assert facts[0].false_target == 0x1026


def test_structuring_condition_replay_refuses_different_root() -> None:
    codegen = SimpleNamespace()
    record_condition_replay_fact_8616(codegen, _condition(), 0x102F, 0x1026)

    assert select_condition_replay_fact_8616(
        _condition(src_insn=0x1019), condition_replay_facts_8616(codegen)
    ) is None
