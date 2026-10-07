from __future__ import annotations

from types import SimpleNamespace

import inertia.structuring.decompiler_structuring_stage as stage

from inertia.structuring.direct_stack_move_branches import (
    DirectStackMoveBranchArm8616,
    DirectStackMoveBranchFact8616,
)
from inertia.structuring.direct_stack_move_loop_evidence import (
    DirectStackMoveLoopEntryEdge8616,
)
from inertia.structuring.direct_stack_move_ownership import (
    DirectStackMoveControlClaim8616,
    DirectStackMoveControlOwner8616,
    direct_stack_move_loop_entry_supersedes_branch_claim_8616,
)


def test_branch_ownership_replays_after_broader_loop_owners(monkeypatch) -> None:
    calls: list[str] = []

    def _record(owner: str):
        def _materialize(*_args: object) -> bool:
            calls.append(owner)
            return True

        return _materialize

    monkeypatch.setattr(
        stage,
        "materialize_direct_stack_move_loop_entry_ownership_8616",
        _record("loop-entry"),
    )
    monkeypatch.setattr(
        stage,
        "materialize_direct_stack_move_loop_tail_ownership_8616",
        _record("loop-tail"),
    )
    monkeypatch.setattr(
        stage,
        "materialize_direct_stack_move_branch_ownership_8616",
        _record("branch"),
    )
    project = SimpleNamespace()
    codegen = SimpleNamespace()

    stage._bind_direct_stack_move_branch_ownership_8616(project, codegen, object())

    assert codegen._inertia_direct_stack_move_branch_ownership_replay_8616()
    assert calls == ["branch", "loop-entry", "loop-tail"]


def _branch_claim() -> DirectStackMoveControlClaim8616:
    return DirectStackMoveControlClaim8616(
        move_ins_addr=0x10D54,
        owner=DirectStackMoveControlOwner8616.CONDITIONAL_BRANCH,
        branch_fact=DirectStackMoveBranchFact8616(
            move_ins_addr=0x10D54,
            condition_ins_addr=0x10CF1,
            condition_producer_insn=0x10CEE,
            arm=DirectStackMoveBranchArm8616.TAKEN,
            arm_start=0x10CF6,
            merge_addr=0x10E57,
        ),
    )


def test_nested_loop_entry_supersedes_enclosing_branch_claim() -> None:
    edge = DirectStackMoveLoopEntryEdge8616(
        move_addr=0x10D54,
        entry_addr=0x10D51,
        jump_addr=0x10DE2,
    )

    assert direct_stack_move_loop_entry_supersedes_branch_claim_8616(
        _branch_claim(),
        edge,
    )


def test_enclosing_loop_does_not_supersede_nested_branch_claim() -> None:
    edge = DirectStackMoveLoopEntryEdge8616(
        move_addr=0x10D54,
        entry_addr=0x10C00,
        jump_addr=0x10F00,
    )

    assert not direct_stack_move_loop_entry_supersedes_branch_claim_8616(
        _branch_claim(),
        edge,
    )
