"""Tests for CFG-owned multi-arm condition provenance."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant, CIfElse, CLabel, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.structuring import multi_arm_condition_ownership as owner
from angr_platforms.X86_16.structuring.multi_arm_condition_ownership import (
    MultiArmConditionOwnershipStatus8616,
    materialize_multi_arm_condition_owners_8616,
    select_multi_arm_condition_owners_8616,
)


@pytest.mark.parametrize("last_taken", [False, True])
def test_exact_ladder_owns_mixed_polarity_arms_and_final_else(last_taken):
    root, second = _dispatch_conditions()
    if not last_taken:
        second = replace(second, taken_target=0x1030, fallthrough_target=0x1200)
    result = owner.select_exact_multi_arm_condition_owners_8616(
        (0x1100, 0x1200), (root, second), else_target=0x1030,
        successors={0x1010: (0x1100, 0x1020), 0x1020: (0x1200, 0x1030)},
    )
    assert result.selected
    assert result.facts == (root, second)
    assert result.taken_polarities == (True, last_taken)


@pytest.mark.parametrize("fault", ["disconnected", "missing-else", "wrong-body", "extra-edge", "duplicate-fact"])
def test_exact_ladder_refuses_incomplete_or_conflicting_edges(fault):
    root, second = _dispatch_conditions()
    targets = (0x1100, 0x1200)
    otherwise = 0x1030
    successors = {0x1010: (0x1100, 0x1020), 0x1020: (0x1200, 0x1030)}
    if fault == "disconnected":
        root = replace(root, fallthrough_target=0x1090)
    elif fault == "missing-else":
        otherwise = None
    elif fault == "wrong-body":
        targets = (0x1101, 0x1200)
    elif fault == "extra-edge":
        successors[0x1020] = (0x1200, 0x1030, 0x1400)
    else:
        second = root
    result = owner.select_exact_multi_arm_condition_owners_8616(
        targets, (root, second), else_target=otherwise, successors=successors,
    )
    assert not result.selected


@pytest.mark.parametrize("fault", [None, "missing-ssa", "refusal", "conflicting-edge", "effect"])
@pytest.mark.parametrize("inverted", [False, True])
def test_exact_ladder_consumes_only_proven_empty_connectors(fault, inverted):
    root, second = _dispatch_conditions()
    root = replace(root, taken_target=0x1080)
    if inverted:
        root = replace(root, taken_target=root.fallthrough_target, fallthrough_target=root.taken_target)
    edges = {0x1010: (0x1080, 0x1020), 0x1080: (0x1100,), 0x1020: (0x1200, 0x1030)}
    connector = SSABlock(0x1080, (), ())
    artifact = SSAFunctionArtifact(
        0x1010, (connector,), predecessor_map={0x1100: (0x1080,)},
    )
    if fault == "missing-ssa":
        artifact = None
    elif fault == "refusal":
        artifact = replace(artifact, blocks=(replace(connector, refusals=("unknown",)),))
    elif fault == "conflicting-edge":
        artifact = replace(artifact, predecessor_map={0x1200: (0x1080,)})
    elif fault == "effect":
        call = IRInstr(op="CALL", dst=None, args=(), size=0, addr=connector.addr)
        artifact = replace(artifact, blocks=(replace(connector, instrs=(call,)),))
    result = owner.select_exact_multi_arm_condition_owners_8616(
        (0x1100, 0x1200), (root, second), else_target=0x1030,
        successors=edges, artifact=artifact,
    )
    assert result.selected is (fault is None)
    if result.selected:
        assert result.facts == (root, second)
        assert result.facts[0].taken_target == root.taken_target
        assert result.taken_polarities == (not inverted, True)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.map_addr_to_label = {}

    def next_idx(self, _name: str) -> int:
        self._next_index += 1
        return self._next_index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


@pytest.mark.parametrize("fault", [None, "unregistered", "ambiguous", "wrong-tag"])
def test_label_entry_requires_unique_address_map_identity(fault):
    codegen = _Codegen()
    address = 0x1230
    label = CLabel("arbitrary_name", codegen=codegen, tags={"ins_addr": address})
    codegen.map_addr_to_label[(address, None)] = label
    if fault == "unregistered":
        codegen.map_addr_to_label.clear()
    elif fault == "ambiguous":
        codegen.map_addr_to_label[(address + 1, None)] = label
    elif fault == "wrong-tag":
        label.tags["ins_addr"] = address + 1
    body = CStatements([label], codegen=codegen)
    assert owner.first_statement_block_8616(body) == (address if fault is None else None)


@pytest.mark.parametrize("fault", [None, "unbound", "wrong-owner"])
def test_nested_condition_entry_requires_materialized_owner(fault):
    codegen = _Codegen()
    block, instruction = 0x1230, 0x1234
    condition = CConstant(1, SimTypeShort(False), codegen=codegen, tags={
        "ins_addr": instruction, "vex_block_addr": block,
        "inertia_structuring_condition_cfg_materialized_8616": True,
    })
    nested = CIfElse([(condition, CStatements([], codegen=codegen))],
                     codegen=codegen, tags={"ins_addr": instruction})
    if fault == "unbound":
        condition.tags.pop("inertia_structuring_condition_cfg_materialized_8616")
    elif fault == "wrong-owner":
        nested.tags["ins_addr"] = instruction + 1
    assert owner.first_statement_block_8616(nested) == (block if fault is None else None)


def _dispatch_conditions() -> tuple[ConditionIR, ConditionIR]:
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    return (
        ConditionIR(
            op="zero",
            lhs=argument,
            source=("test", "je"),
            src_insn=0x1012,
            block_addr=0x1010,
            producer_insn=0x1010,
            taken_target=0x1100,
            fallthrough_target=0x1020,
        ),
        ConditionIR(
            op="eq",
            lhs=argument,
            rhs=IRValue(MemSpace.CONST, const=1, size=2),
            source=("cmp", "je"),
            src_insn=0x1021,
            block_addr=0x1020,
            producer_insn=0x1020,
            taken_target=0x1200,
            fallthrough_target=0x1030,
            producer_semantics=("dec_reg16", "ax", 1),
        ),
    )


def test_multi_arm_ownership_selects_exact_taken_edges_in_fallthrough_order() -> None:
    root, second = _dispatch_conditions()

    result = select_multi_arm_condition_owners_8616(
        (0x1100, 0x1200),
        (root, second),
        root=root,
        successors={
            0x1010: (0x1100, 0x1020),
            0x1020: (0x1200, 0x1030),
        },
    )

    assert result.status is MultiArmConditionOwnershipStatus8616.SELECTED
    assert result.facts == (root, second)


def test_multi_arm_ownership_refuses_a_disconnected_decision_ladder() -> None:
    root, second = _dispatch_conditions()
    disconnected_root = replace(root, fallthrough_target=0x1090)

    result = select_multi_arm_condition_owners_8616(
        (0x1100, 0x1200),
        (disconnected_root, second),
        root=disconnected_root,
        successors={
            0x1010: (0x1100, 0x1090),
            0x1020: (0x1200, 0x1030),
        },
    )

    assert (
        result.status
        is MultiArmConditionOwnershipStatus8616.DISCONNECTED_FALLTHROUGH
    )
    assert result.facts == ()


def test_multi_arm_materialization_replaces_copied_tags_with_fact_owners() -> None:
    root, second = _dispatch_conditions()
    ownership = select_multi_arm_condition_owners_8616(
        (0x1100, 0x1200),
        (root, second),
        root=root,
        successors={
            0x1010: (0x1100, 0x1020),
            0x1020: (0x1200, 0x1030),
        },
    )
    codegen = _Codegen()
    first_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    second_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    copied_tags = {"ins_addr": root.src_insn, "vex_block_addr": root.block_addr}
    first_condition.tags = dict(copied_tags)
    second_condition.tags = dict(copied_tags)
    first_body = CStatements([], codegen=codegen, tags={"ins_addr": 0x1100})
    second_body = CStatements([], codegen=codegen, tags={"ins_addr": 0x1200})

    result = materialize_multi_arm_condition_owners_8616(
        ((first_condition, first_body), (second_condition, second_body)),
        ownership,
        lambda fact: CConstant(
            fact.src_insn,
            SimTypeShort(False),
            codegen=codegen,
        ),
    )

    expected_count = len(ownership.facts)
    assert result.raw_fact_count == expected_count
    assert result.normalized_fact_count == expected_count
    assert result.classified_fact_count == expected_count
    assert result.materialized_count == expected_count
    assert result.failure_count == 0
    assert result.condition_and_nodes[0][1] is first_body
    assert result.condition_and_nodes[1][1] is second_body
    replacements = tuple(condition for condition, _body in result.condition_and_nodes)
    assert replacements[0].tags["ins_addr"] == root.src_insn
    assert replacements[1].tags["ins_addr"] == second.src_insn
    assert replacements[1].tags["vex_block_addr"] == second.block_addr
    assert replacements[1].tags[
        "inertia_structuring_multi_arm_owner_materialized_8616"
    ] is True
