import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from archinfo import ArchX86

from inertia.validation.validation_dataflow import (
    DefUseEntryStackRange8616,
    validate_structured_def_use_8616,
)
from inertia.validation.validation_predicates import invert_predicate_token_8616

_ENTRY_FREQUENCY_RANGE = (DefUseEntryStackRange8616(4, 2),)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.project = _Project()
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _Project:
    def __init__(self) -> None:
        self.arch = ArchX86()


def _stack_word(offset: int, codegen: _Codegen, name: str) -> CVariable:
    return CVariable(
        SimStackVariable(offset, 2, base="bp", name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _constant(value: int, codegen: _Codegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _comparison(op: str, offset: int, codegen: _Codegen) -> CBinaryOp:
    return CBinaryOp(
        op,
        _stack_word(offset, codegen, "frequency"),
        _constant(0, codegen),
        codegen=codegen,
    )


@pytest.mark.parametrize(
    ("op", "inverted_op"),
    [
        ("CmpEQ", "CmpNE"),
        ("CmpNE", "CmpEQ"),
        ("CmpLT", "CmpGE"),
        ("CmpLE", "CmpGT"),
        ("CmpGT", "CmpLE"),
        ("CmpGE", "CmpLT"),
    ],
)
def test_predicate_token_inversion_uses_condition_ir_identity(
    op: str,
    inverted_op: str,
) -> None:
    lhs = ("storage", "stack-local", 4, 2, None, "")
    rhs = ("constant", "int", 0)
    token = ("binary", op, lhs, rhs)

    inverted = invert_predicate_token_8616(token)

    assert inverted == ("binary", inverted_op, lhs, rhs)
    assert invert_predicate_token_8616(inverted) == token


def test_predicate_token_inversion_cancels_canonical_logical_not() -> None:
    token = ("storage", "stack-local", 4, 2, None, "")

    inverted = invert_predicate_token_8616(token)

    assert inverted == ("logical-not", token)
    assert invert_predicate_token_8616(inverted) == token


def test_def_use_accepts_guarded_definition_in_complementary_else() -> None:
    codegen = _Codegen()
    root = CStatements(
        [
            CIfElse(
                [
                    (
                        _comparison("CmpNE", 4, codegen),
                        CStatements(
                            [
                                CAssignment(
                                    _stack_word(-2, codegen, "control"),
                                    _constant(7, codegen),
                                    codegen=codegen,
                                )
                            ],
                            codegen=codegen,
                        ),
                    )
                ],
                codegen=codegen,
            ),
            CIfElse(
                [
                    (
                        _comparison("CmpEQ", 4, codegen),
                        CStatements([], codegen=codegen),
                    )
                ],
                else_node=CStatements(
                    [_stack_word(-2, codegen, "control")],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(
        root,
        entry_defined_stack_ranges=_ENTRY_FREQUENCY_RANGE,
    )

    assert report.passed
    assert report.raw_fact_count == report.normalized_fact_count
    assert report.normalized_fact_count == report.classified_fact_count
    assert report.classified_fact_count == report.materialized_count
    assert report.failure_count == 0


def test_def_use_refuses_complementary_else_after_predicate_write() -> None:
    codegen = _Codegen()
    root = CStatements(
        [
            CIfElse(
                [
                    (
                        _comparison("CmpNE", 4, codegen),
                        CStatements(
                            [
                                CAssignment(
                                    _stack_word(-2, codegen, "control"),
                                    _constant(7, codegen),
                                    codegen=codegen,
                                )
                            ],
                            codegen=codegen,
                        ),
                    )
                ],
                codegen=codegen,
            ),
            CAssignment(
                _stack_word(4, codegen, "frequency"),
                _constant(1, codegen),
                codegen=codegen,
            ),
            CIfElse(
                [
                    (
                        _comparison("CmpEQ", 4, codegen),
                        CStatements([], codegen=codegen),
                    )
                ],
                else_node=CStatements(
                    [_stack_word(-2, codegen, "control")],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(
        root,
        entry_defined_stack_ranges=_ENTRY_FREQUENCY_RANGE,
    )

    assert not report.passed
    assert report.failure_count == 1
    assert report.classified_fact_count == report.materialized_count + report.failure_count
