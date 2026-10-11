"""Tests for CFG-owned multi-arm condition provenance."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpression,
    CIfElse,
    CLabel,
    CReturn,
    CStatements,
)
from angr.sim_type import SimTypeShort

import inertia.structuring.multi_arm_condition_ownership as owner
import inertia.structuring.scalar_return_arm_ownership as scalar_owner
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRInstr, IRValue, MemSpace
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.structuring.multi_arm_condition_ownership import (
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


_SHARED_EPILOGUE_BLOCK = 0x9000


def _shared_epilogue_return_body(
    value: int, codegen: _Codegen, ins_addr: int
) -> CStatements:
    """Build one sole scalar return body tagged with the shared epilogue."""
    statement = CReturn(
        CConstant(value, SimTypeShort(True), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": ins_addr, "vex_block_addr": _SHARED_EPILOGUE_BLOCK},
    )
    return CStatements(
        [statement],
        codegen=codegen,
        tags={"ins_addr": ins_addr, "vex_block_addr": _SHARED_EPILOGUE_BLOCK},
    )


def _return_ladder_conditions() -> tuple[ConditionIR, ...]:
    """Three proven ladder facts: two continue by fallthrough, one by taken."""
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    return (
        ConditionIR(
            op="sge",
            lhs=argument,
            source=("cmp", "jge"),
            src_insn=0x1012,
            block_addr=0x1010,
            producer_insn=0x1010,
            taken_target=0x2010,
            fallthrough_target=0x1020,
        ),
        ConditionIR(
            op="sle",
            lhs=argument,
            source=("cmp", "jle"),
            src_insn=0x1022,
            block_addr=0x1020,
            producer_insn=0x1020,
            taken_target=0x1030,
            fallthrough_target=0x2020,
        ),
        ConditionIR(
            op="ne",
            lhs=argument,
            source=("cmp", "jne"),
            src_insn=0x1032,
            block_addr=0x1030,
            producer_insn=0x1030,
            taken_target=0x2030,
            fallthrough_target=0x2040,
        ),
    )


def _return_ladder_successors() -> dict[int, tuple[int, ...]]:
    return {
        0x1010: (0x2010, 0x1020),
        0x1020: (0x1030, 0x2020),
        0x1030: (0x2030, 0x2040),
    }


def _return_ladder_recover(
    codegen: _Codegen,
    leaf_values: dict[int, int | None] | None = None,
):
    """Recover each native leaf return expression from classified effects."""
    values = {0x2010: -1, 0x2020: 1, 0x2030: 0, 0x2040: 2}
    if leaf_values:
        values.update(leaf_values)

    def recover(addr: int) -> CExpression | None:
        value = values.get(addr)
        if value is None:
            return None
        return CConstant(value, SimTypeShort(True), codegen=codegen)

    return recover


def _return_ladder_bodies(
    codegen: _Codegen,
    arm_values: tuple[int, int, int] = (-1, 1, 0),
    else_value: int = 2,
) -> tuple[tuple[CStatements, ...], CStatements]:
    bodies = tuple(
        _shared_epilogue_return_body(value, codegen, 0x3000 + index)
        for index, value in enumerate(arm_values)
    )
    return bodies, _shared_epilogue_return_body(else_value, codegen, 0x3100)


def test_shared_epilogue_return_ladder_proves_arm_ownership() -> None:
    codegen = _Codegen()
    facts = _return_ladder_conditions()
    successors = _return_ladder_successors()
    bodies, else_body = _return_ladder_bodies(codegen)

    exact = owner.select_exact_multi_arm_condition_owners_8616(
        tuple(owner.first_statement_block_8616(body) for body in bodies),
        facts,
        else_target=owner.first_statement_block_8616(else_body),
        successors=successors,
    )
    assert not exact.selected

    result = scalar_owner.select_scalar_return_arm_owners_8616(
        bodies,
        else_body,
        facts,
        successors=successors,
        recover_return=_return_ladder_recover(codegen),
    )

    assert result.status is MultiArmConditionOwnershipStatus8616.SELECTED
    assert result.facts == facts
    assert result.taken_polarities == (True, False, True)

    inverted: list[CExpression] = []
    materialized = materialize_multi_arm_condition_owners_8616(
        tuple(
            (CConstant(1, SimTypeShort(False), codegen=codegen), body)
            for body in bodies
        ),
        result,
        lambda fact: CConstant(fact.src_insn, SimTypeShort(False), codegen=codegen),
        invert=lambda expression: inverted.append(expression) or expression,
    )

    assert materialized.materialized_count == len(facts)
    assert materialized.failure_count == 0
    assert len(inverted) == 1
    assert tuple(body for _cond, body in materialized.condition_and_nodes) == bodies


@pytest.mark.parametrize(
    ("fault", "expected"),
    [
        ("wrong-body-value", MultiArmConditionOwnershipStatus8616.RETURN_VALUE_MISMATCH),
        ("swapped-arm", MultiArmConditionOwnershipStatus8616.RETURN_VALUE_MISMATCH),
        ("missing-native-effect", MultiArmConditionOwnershipStatus8616.RETURN_LEAF_UNPROVED),
        ("extra-edge", MultiArmConditionOwnershipStatus8616.CFG_EDGE_MISMATCH),
        ("side-effect-body", MultiArmConditionOwnershipStatus8616.RETURN_BODY_UNPROVED),
        ("non-return-else", MultiArmConditionOwnershipStatus8616.RETURN_BODY_UNPROVED),
        ("ambiguous-leaf", MultiArmConditionOwnershipStatus8616.AMBIGUOUS_RETURN),
        ("disconnected", MultiArmConditionOwnershipStatus8616.DISCONNECTED_FALLTHROUGH),
    ],
)
def test_shared_epilogue_return_ladder_refuses_unproven_ownership(
    fault, expected
) -> None:
    codegen = _Codegen()
    facts = list(_return_ladder_conditions())
    successors = _return_ladder_successors()
    leaf_values: dict[int, int | None] = {}
    arm_values: tuple[int, int, int] = (-1, 1, 0)
    else_value = 2
    if fault == "wrong-body-value":
        leaf_values[0x2010] = 7
    elif fault == "swapped-arm":
        arm_values = (1, -1, 0)
    elif fault == "missing-native-effect":
        leaf_values[0x2010] = None
    elif fault == "extra-edge":
        successors[0x1010] = (0x2010, 0x1020, 0x2FF0)
    elif fault == "ambiguous-leaf":
        arm_values = (-1, 1, 0)
        else_value = 0
        leaf_values[0x2040] = 0
    elif fault == "disconnected":
        facts[0] = replace(facts[0], fallthrough_target=0x1090)
        successors[0x1010] = (0x2010, 0x1090)
    bodies, else_body = _return_ladder_bodies(codegen, arm_values, else_value)
    if fault == "side-effect-body":
        first = bodies[0].statements[0]
        bodies = (
            CStatements(
                [first, first],
                codegen=codegen,
                tags=dict(bodies[0].tags),
            ),
            *bodies[1:],
        )
    elif fault == "non-return-else":
        else_body = CStatements(
            [], codegen=codegen, tags=dict(else_body.tags)
        )

    result = scalar_owner.select_scalar_return_arm_owners_8616(
        bodies,
        else_body,
        tuple(facts),
        successors=successors,
        recover_return=_return_ladder_recover(codegen, leaf_values),
    )

    assert result.status is expected
    assert result.facts == ()
    assert not result.selected
