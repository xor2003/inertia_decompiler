"""Regressions for typed carry/borrow bit placement across structured scopes."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.carry_borrow_bit_contracts import (
    CarryBorrowBitLoweringFact8616,
    CarryBorrowBitLoweringFailure8616,
    CarryBorrowBitLoweringResolution8616,
    CarryBorrowBitLoweringVerdict8616,
)
from inertia.lowering.carry_borrow_bit_placement import (
    materialize_carry_borrow_bit_value_8616,
)
from tests.lowering.x86_16_carry_borrow_bit_fixtures import build_test_cfg_ownership_8616

from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.widening.carry_borrow_values import WideCarryBorrowValue8616

_BLOCK_ADDR = 0x10520
_LOW_ADDR = 0x1052F
_HIGH_ADDR = 0x10532


class _FakeCodegen(SimpleNamespace):
    def __init__(self) -> None:
        super().__init__()
        self._next = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        self._next += 1
        return self._next

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _ownership(*statement_addrs: int):
    """Build the real typed pre-join ownership contract for one synthetic block."""
    return build_test_cfg_ownership_8616({_BLOCK_ADDR: tuple(statement_addrs)})


def _constant(codegen: _FakeCodegen, value: int) -> structured_c.CConstant:
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def _vvar(
    codegen: _FakeCodegen,
    register_name: str,
    name: str,
    vvar_id: int,
) -> structured_c.CVariable:
    offset = codegen.project.arch.registers[register_name][0]
    return structured_c.CVariable(
        SimRegisterVariable(offset, 2, name=name),
        variable_type=SimTypeShort(False),
        vvar_id=vvar_id,
        codegen=codegen,
    )


def _fact() -> CarryBorrowBitLoweringFact8616:
    return CarryBorrowBitLoweringFact8616(
        function_addr=0x10498,
        kind=CarryBorrowKind8616.SUB_WITH_BORROW,
        low_block_addr=_BLOCK_ADDR,
        low_ins_addr=_LOW_ADDR,
        high_block_addr=_BLOCK_ADDR,
        high_ins_addr=_HIGH_ADDR,
    )


def _source() -> WideCarryBorrowValue8616:
    return cast(WideCarryBorrowValue8616, object())


def _addition_fact() -> CarryBorrowBitLoweringFact8616:
    """Create one exact ADD_WITH_CARRY fact for split-region tests."""
    return CarryBorrowBitLoweringFact8616(
        function_addr=0x10498,
        kind=CarryBorrowKind8616.ADD_WITH_CARRY,
        low_block_addr=_BLOCK_ADDR,
        low_ins_addr=_LOW_ADDR,
        high_block_addr=_BLOCK_ADDR,
        high_ins_addr=_HIGH_ADDR,
    )


def _inlined_addition_fixture() -> tuple[
    structured_c.CStatements,
    structured_c.CAssignment,
    structured_c.CAssignment,
]:
    """Build one low result plus a high-region inlined carry projection."""
    codegen = _FakeCodegen()
    lhs = _vvar(codegen, "ax", "lhs", 10)
    rhs = _vvar(codegen, "bx", "rhs", 11)
    low_result = _vvar(codegen, "ax", "low_result", 12)
    low_tags = {"ins_addr": _LOW_ADDR, "vex_block_addr": _BLOCK_ADDR}
    low_arithmetic = structured_c.CBinaryOp("Add", lhs, rhs, codegen=codegen, tags=low_tags)
    low_assignment = structured_c.CAssignment(
        low_result,
        low_arithmetic,
        codegen=codegen,
        tags=low_tags,
    )
    inlined_addition = structured_c.CBinaryOp("Add", lhs, rhs, codegen=codegen, tags=low_tags)
    low_projection = structured_c.CBinaryOp(
        "Shr",
        inlined_addition,
        _constant(codegen, 16),
        codegen=codegen,
        tags=low_tags,
    )
    high_tags = {"ins_addr": _HIGH_ADDR, "vex_block_addr": _HIGH_ADDR}
    high_sum = structured_c.CBinaryOp(
        "Add",
        _vvar(codegen, "dx", "high_lhs", 20),
        low_projection,
        codegen=codegen,
        tags=high_tags,
    )
    high_projection = structured_c.CBinaryOp(
        "Shr",
        high_sum,
        _constant(codegen, 16),
        codegen=codegen,
        tags=high_tags,
    )
    high_assignment = structured_c.CAssignment(
        _vvar(codegen, "dx", "high_result", 21),
        high_projection,
        codegen=codegen,
        tags=high_tags,
    )
    root = structured_c.CStatements([low_assignment, high_assignment], codegen=codegen)
    return root, low_assignment, high_assignment


def _fixture(
    *,
    duplicate_low_definition: bool = False,
    duplicate_low_addr: int = _LOW_ADDR,
    conflicting_duplicate: bool = False,
    sequential_duplicate: bool = False,
    retain_other_read: bool = False,
    tag_nested_nodes: bool = True,
    include_borrow_predicate: bool = True,
) -> tuple[
    structured_c.CStatements,
    structured_c.CStatements,
    structured_c.CAssignment,
    structured_c.CAssignment,
]:
    codegen = _FakeCodegen()
    lhs = _vvar(codegen, "ax", "lhs", 10)
    rhs = _vvar(codegen, "bx", "rhs", 11)
    flags_definition = _vvar(codegen, "flags", "flags_def", 5)
    flags_use = _vvar(codegen, "flags", "flags_use", 5)
    arithmetic = structured_c.CBinaryOp(
        "Sub",
        lhs,
        rhs,
        codegen=codegen,
        tags={"ins_addr": _LOW_ADDR} if tag_nested_nodes else None,
    )
    predicate = structured_c.CBinaryOp(
        "CmpLT",
        lhs,
        rhs,
        codegen=codegen,
        tags={"ins_addr": _LOW_ADDR} if tag_nested_nodes else None,
    )
    low_rhs: object = (
        structured_c.CBinaryOp("Or", arithmetic, predicate, codegen=codegen)
        if include_borrow_predicate
        else arithmetic
    )
    low_assignment = structured_c.CAssignment(
        flags_definition,
        low_rhs,
        codegen=codegen,
        tags={"ins_addr": _LOW_ADDR},
    )
    low_container = structured_c.CStatements([low_assignment], codegen=codegen)
    containers: list[object]
    if duplicate_low_definition:
        duplicate_rhs = rhs
        if conflicting_duplicate:
            duplicate_rhs = _vvar(codegen, "cx", "conflicting_rhs", 12)
        duplicate_arithmetic = structured_c.CBinaryOp(
            "Sub", lhs, duplicate_rhs, codegen=codegen, tags={"ins_addr": duplicate_low_addr}
        )
        duplicate_predicate = structured_c.CBinaryOp(
            "CmpLT", lhs, duplicate_rhs, codegen=codegen, tags={"ins_addr": duplicate_low_addr}
        )
        duplicate_flags_rhs: object = (
            structured_c.CBinaryOp(
                "Or",
                _constant(codegen, 0x100),
                structured_c.CBinaryOp(
                    "Or", duplicate_arithmetic, duplicate_predicate, codegen=codegen
                ),
                codegen=codegen,
            )
            if include_borrow_predicate
            else duplicate_arithmetic
        )
        duplicate = structured_c.CAssignment(
            _vvar(codegen, "flags", "flags_duplicate", 5),
            duplicate_flags_rhs,
            codegen=codegen,
            tags={"ins_addr": duplicate_low_addr},
        )
        duplicate_container = structured_c.CStatements([duplicate], codegen=codegen)
        if sequential_duplicate:
            containers = [low_container, duplicate_container]
        else:
            branch_condition = structured_c.CBinaryOp(
                "CmpNE",
                _vvar(codegen, "si", "branch", 30),
                _constant(codegen, 0),
                codegen=codegen,
            )
            containers = [
                structured_c.CIfElse(
                    [(branch_condition, low_container)],
                    else_node=duplicate_container,
                    cstyle_ifs=True,
                    codegen=codegen,
                )
            ]
    else:
        containers = [low_container]
    shifted_flags = structured_c.CBinaryOp(
        "Shr", flags_use, _constant(codegen, 0), codegen=codegen
    )
    carry = structured_c.CBinaryOp(
        "And",
        structured_c.CBinaryOp(
            "And", _constant(codegen, 1), shifted_flags, codegen=codegen
        ),
        _constant(codegen, 1),
        codegen=codegen,
        tags={"ins_addr": _HIGH_ADDR},
    )
    high_assignment = structured_c.CAssignment(
        _vvar(codegen, "dx", "high", 20), carry, codegen=codegen
    )
    high_container = structured_c.CStatements([high_assignment], codegen=codegen)
    containers.append(high_container)
    if retain_other_read:
        retained = structured_c.CAssignment(
            _vvar(codegen, "cx", "retained", 21),
            _vvar(codegen, "flags", "flags_retained", 5),
            codegen=codegen,
        )
        containers.append(structured_c.CStatements([retained], codegen=codegen))
    return structured_c.CStatements(containers, codegen=codegen), low_container, low_assignment, high_assignment


def test_materialization_resolves_exact_ssa_definition_across_sibling_containers() -> None:
    root, low_container, _low_assignment, high_assignment = _fixture()

    resolution = materialize_carry_borrow_bit_value_8616(
        root, _source(), _fact(), _ownership(_LOW_ADDR, _HIGH_ADDR)
    )

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED
    assert resolution.changed is True
    assert low_container.statements == []
    assert isinstance(high_assignment.rhs, structured_c.CBinaryOp)
    assert high_assignment.rhs.op == "CmpLT"
    replay = materialize_carry_borrow_bit_value_8616(
        root, _source(), _fact(), _ownership(_LOW_ADDR, _HIGH_ADDR),
    )
    assert replay.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED
    assert replay.already_materialized and not replay.changed


def test_materialization_refuses_when_nested_arithmetic_lacks_instruction_ownership() -> None:
    """An assignment tag cannot stand in for exact arithmetic-node ownership."""
    root, low_container, _low_assignment, high_assignment = _fixture(tag_nested_nodes=False)
    original_rhs = high_assignment.rhs

    resolution = materialize_carry_borrow_bit_value_8616(
        root, _source(), _fact(), _ownership(_LOW_ADDR, _HIGH_ADDR)
    )

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.UNKNOWN_REFUSE
    assert resolution.failure is CarryBorrowBitLoweringFailure8616.CARRY_PREDICATE_MISSING
    assert low_container.statements
    assert high_assignment.rhs is original_rhs


def test_materialization_derives_borrow_from_exact_low_subtraction() -> None:
    """Typed SUB_WITH_BORROW does not require angr to render CF as CmpLT."""
    root, low_container, _low_assignment, high_assignment = _fixture(
        duplicate_low_definition=True,
        include_borrow_predicate=False,
    )

    resolution = materialize_carry_borrow_bit_value_8616(
        root, _source(), _fact(), _ownership(_LOW_ADDR, _HIGH_ADDR)
    )

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED
    assert low_container.statements == []
    assert isinstance(high_assignment.rhs, structured_c.CBinaryOp)
    assert high_assignment.rhs.op == "CmpLT"
    assert isinstance(high_assignment.rhs.lhs, structured_c.CTypeCast)
    assert isinstance(high_assignment.rhs.rhs, structured_c.CTypeCast)


def test_materialization_ignores_unowned_entry_flags_carrier() -> None:
    """An unowned entry FLAGS copy cannot override exact low/high IR provenance."""
    root, low_container, low_assignment, high_assignment = _fixture()
    codegen = cast(_FakeCodegen, root.codegen)
    low_assignment.lhs = _vvar(codegen, "ax", "low_result", 6)
    entry_flags = structured_c.CAssignment(
        _vvar(codegen, "flags", "flags_def", 5),
        _vvar(codegen, "flags", "entry_flags", 7),
        codegen=codegen,
    )
    low_container.statements.insert(0, entry_flags)

    resolution = materialize_carry_borrow_bit_value_8616(
        root, _source(), _fact(), _ownership(_LOW_ADDR, _HIGH_ADDR)
    )

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED
    assert low_container.statements == [entry_flags, low_assignment]
    assert isinstance(high_assignment.rhs, structured_c.CBinaryOp)
    assert high_assignment.rhs.op == "CmpLT"


def test_materialization_joins_exclusive_definitions_with_one_common_predicate() -> None:
    root, low_container, _low_assignment, high_assignment = _fixture(duplicate_low_definition=True)

    resolution = materialize_carry_borrow_bit_value_8616(
        root, _source(), _fact(), _ownership(_LOW_ADDR, _HIGH_ADDR)
    )

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED
    assert low_container.statements == []
    assert isinstance(high_assignment.rhs, structured_c.CBinaryOp)
    assert high_assignment.rhs.op == "CmpLT"


def test_materialization_refuses_exclusive_definitions_with_different_predicates() -> None:
    root, low_container, low_assignment, high_assignment = _fixture(
        duplicate_low_definition=True,
        conflicting_duplicate=True,
    )
    original_rhs = high_assignment.rhs

    resolution = materialize_carry_borrow_bit_value_8616(
        root, _source(), _fact(), _ownership(_LOW_ADDR, _HIGH_ADDR)
    )

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.UNKNOWN_REFUSE
    assert resolution.failure is CarryBorrowBitLoweringFailure8616.CARRY_PREDICATE_AMBIGUOUS
    assert low_container.statements == [low_assignment]
    assert high_assignment.rhs is original_rhs


def test_materialization_refuses_sequential_competing_definitions() -> None:
    root, low_container, low_assignment, high_assignment = _fixture(
        duplicate_low_definition=True,
        sequential_duplicate=True,
    )
    original_rhs = high_assignment.rhs

    resolution = materialize_carry_borrow_bit_value_8616(
        root, _source(), _fact(), _ownership(_LOW_ADDR, _HIGH_ADDR)
    )

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.UNKNOWN_REFUSE
    assert resolution.failure is CarryBorrowBitLoweringFailure8616.CARRIER_ASSIGNMENT_AMBIGUOUS
    assert low_container.statements == [low_assignment]
    assert high_assignment.rhs is original_rhs


def test_materialization_refuses_reaching_definition_from_another_instruction_site() -> None:
    """A shared FLAGS identity cannot hide a second machine definition."""
    competing_addr = _LOW_ADDR + 1
    root, low_container, low_assignment, high_assignment = _fixture(
        duplicate_low_definition=True,
        duplicate_low_addr=competing_addr,
        sequential_duplicate=True,
    )
    original_rhs = high_assignment.rhs

    resolution = materialize_carry_borrow_bit_value_8616(
        root,
        _source(),
        _fact(),
        _ownership(_LOW_ADDR, competing_addr, _HIGH_ADDR),
    )

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.UNKNOWN_REFUSE
    assert resolution.failure is CarryBorrowBitLoweringFailure8616.CARRIER_ASSIGNMENT_AMBIGUOUS
    assert low_container.statements == [low_assignment]
    assert high_assignment.rhs is original_rhs


def test_materialization_keeps_cross_container_carrier_with_another_live_read() -> None:
    root, low_container, low_assignment, _high_assignment = _fixture(retain_other_read=True)

    resolution = materialize_carry_borrow_bit_value_8616(
        root, _source(), _fact(), _ownership(_LOW_ADDR, _HIGH_ADDR)
    )

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED
    assert low_container.statements == [low_assignment]


def test_materialization_accepts_inlined_carry_in_owned_split_region() -> None:
    """Exact instruction tags may project through a uniquely owned split region."""
    root, low_assignment, high_assignment = _inlined_addition_fixture()
    ownership = build_test_cfg_ownership_8616(
        {_BLOCK_ADDR: (), _HIGH_ADDR: ()},
        ((_BLOCK_ADDR, _HIGH_ADDR),),
    )

    resolution = materialize_carry_borrow_bit_value_8616(root, _source(), _addition_fact(), ownership)

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED
    assert resolution.changed is True
    assert root.statements[0] is low_assignment
    assert isinstance(high_assignment.rhs, structured_c.CBinaryOp)
    assert high_assignment.rhs.op == "CmpLT"
    assert high_assignment.rhs.tags["inertia_x86_16_carry_borrow_bit_lowering"] == _addition_fact()


def test_materialization_refuses_inlined_carry_without_owned_split_region() -> None:
    """Instruction-shaped tags alone cannot authorize a missing CFG region."""
    root, _low_assignment, high_assignment = _inlined_addition_fixture()
    original_rhs = high_assignment.rhs
    ownership = build_test_cfg_ownership_8616({_BLOCK_ADDR: ()})

    resolution = materialize_carry_borrow_bit_value_8616(root, _source(), _addition_fact(), ownership)

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.UNKNOWN_REFUSE
    assert resolution.failure is CarryBorrowBitLoweringFailure8616.CARRY_USE_MISSING
    assert high_assignment.rhs is original_rhs


def test_refusal_diagnostic_projects_exact_typed_instruction_identity() -> None:
    """Failure reporting keeps the owning fact visible without text-based decisions."""
    resolution = CarryBorrowBitLoweringResolution8616(
        source=_source(),
        verdict=CarryBorrowBitLoweringVerdict8616.UNKNOWN_REFUSE,
        fact=_fact(),
        failure=CarryBorrowBitLoweringFailure8616.CARRY_PREDICATE_MISSING,
        placement_classified=True,
    )

    assert resolution.failure_diagnostic == (
        "carry_predicate_missing:function=0x10498:kind=sub_with_borrow:"
        "low=0x10520:0x1052f:high=0x10520:0x10532"
    )
