from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CReturn,
    CStatements,
    CSwitchCase,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeChar, SimTypeFixedSizeArray, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.ir.core import SegmentOrigin
from inertia.ir.segment_state import SegmentRegisterState, SegmentStateArtifact
from inertia.lowering.semantic_cast import CSemanticCast8616
from archinfo import ArchX86

from inertia.validation.status_flag_preservation import (
    PackedStatusFlagPreservationEvidence8616,
)
from inertia.validation.tail_validation import (
    X86_16TailValidationSummary,
    _def_use_entry_segment_register_offsets_8616,
    build_x86_16_tail_validation_cached_result,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    refresh_x86_16_final_semantic_validation_8616,
    x86_16_tail_validation_snapshot_passed,
)
from inertia.validation.validation_dataflow import (
    DefUseCallOutputDefinition8616,
    DefUseEntryStackRange8616,
    validate_structured_def_use_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.cstyle_null_cmp = False
        self.project = _Project()

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


def _codegen() -> _Codegen:
    return _Codegen()


def _local(offset: int, codegen: _Codegen, name: str = "local") -> CVariable:
    return _local_view(offset, 2, codegen, name)


def _local_view(offset: int, width: int, codegen: _Codegen, name: str = "local") -> CVariable:
    return CVariable(
        SimStackVariable(offset, width, base="bp", name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _const(value: int, codegen: _Codegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


_ENTRY_STACK_ARGUMENTS = (
    DefUseEntryStackRange8616(4, 2),
    DefUseEntryStackRange8616(6, 2),
)


def _register_carrier(
    reg_offset: int,
    codegen: _Codegen,
    name: str,
    *,
    ident: int | str | None = "ssa_1",
    region: int | None = 0x1000,
) -> CVariable:
    return CVariable(
        SimRegisterVariable(
            reg_offset,
            2,
            ident=ident,
            name=name,
            region=region,
        ),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _empty_summary(*, def_use_issues: tuple[str, ...] = ()) -> X86_16TailValidationSummary:
    return X86_16TailValidationSummary((), (), (), (), (), (), (), (), def_use_issues)


def test_def_use_refuses_stack_local_read_before_assignment():
    codegen = _codegen()
    root = CStatements([_local(-2, codegen, "i")], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.failure_count == 1
    assert report.issue_tokens() == ("uninitialized-read:stack-local:SS:BP-0x2:size2:root.stmt0",)
    assert report.semantic_issue_tokens() == ("uninitialized-read:stack-local:SS:BP-0x2:size2",)


def test_def_use_accepts_stack_local_read_after_assignment():
    codegen = _codegen()
    local = _local(-2, codegen, "i")
    root = CStatements(
        [
            CAssignment(local, _const(1, codegen), codegen=codegen),
            local,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_def_use_accepts_byte_reads_covered_by_prior_word_assignment():
    codegen = _codegen()
    word = _local_view(-6, 2, codegen, "word")
    high_byte = _local_view(-5, 1, codegen, "high_byte")
    root = CStatements(
        [
            CAssignment(word, _const(1, codegen), codegen=codegen),
            high_byte,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.materialized_count == 1


def test_def_use_uses_narrow_typed_view_over_stale_backing_extent():
    codegen = _codegen()
    backing = SimStackVariable(-2, 4, base="bp", name="iRow")
    word_type = SimTypeShort(False).with_arch(codegen.project.arch)
    word_view = CVariable(backing, variable_type=word_type, codegen=codegen)
    root = CStatements(
        [
            CAssignment(word_view, _const(1, codegen), codegen=codegen),
            word_view,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.materialized_count == 1


def test_def_use_refuses_word_read_after_only_one_byte_assignment():
    codegen = _codegen()
    word = _local_view(-6, 2, codegen, "word")
    low_byte = _local_view(-6, 1, codegen, "low_byte")
    root = CStatements(
        [
            CAssignment(low_byte, _const(1, codegen), codegen=codegen),
            word,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.failure_count == 1
    assert report.materialized_count == 0


def test_def_use_refuses_adjacent_byte_not_covered_by_word_assignment():
    codegen = _codegen()
    word = _local_view(-6, 2, codegen, "word")
    adjacent_byte = _local_view(-4, 1, codegen, "adjacent")
    root = CStatements(
        [
            CAssignment(word, _const(1, codegen), codegen=codegen),
            adjacent_byte,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.failure_count == 1
    assert report.materialized_count == 0


def test_def_use_does_not_classify_direct_address_taking_as_value_read():
    codegen = _codegen()
    local = _local_view(-2, 1, codegen, "addressed")
    root = CStatements([CUnaryOp("Reference", local, codegen=codegen)], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.raw_fact_count == 0


def test_def_use_still_classifies_dereference_operand_as_value_read():
    codegen = _codegen()
    local = _local(-2, codegen, "pointer")
    root = CStatements([CUnaryOp("Dereference", local, codegen=codegen)], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.failure_count == 1
    assert report.raw_fact_count == 1


def test_def_use_accepts_lowering_proven_call_output_before_field_read() -> None:
    codegen = _codegen()
    output_object = CVariable(
        SimStackVariable(-8, 4, base="bp", name="output"),
        variable_type=SimTypeFixedSizeArray(SimTypeShort(False), 2),
        codegen=codegen,
    )
    output_field = _local_view(-6, 2, codegen, "output_field")
    output_reference = CUnaryOp("Reference", output_object, codegen=codegen)
    call = CFunctionCall(
        _const(0x1234, codegen),
        None,
        [output_reference],
        codegen=codegen,
    )
    root = CStatements(
        [
            CExpressionStatement(call, codegen=codegen),
            output_field,
        ],
        codegen=codegen,
    )

    without_fact = validate_structured_def_use_8616(root)
    with_fact = validate_structured_def_use_8616(
        root,
        call_output_definitions={
            id(call): (DefUseCallOutputDefinition8616(base_offset=-8, width=4),),
        },
    )

    assert without_fact.failure_count == 1
    assert with_fact.passed
    assert with_fact.materialized_count == 1


def test_def_use_indexed_array_lvalue_does_not_read_destination_storage():
    codegen = _codegen()
    element_type = SimTypeShort(False)
    array = CVariable(
        SimStackVariable(-8, 8, base="bp", name="items"),
        variable_type=SimTypeFixedSizeArray(element_type, 4),
        codegen=codegen,
    )
    lhs = CIndexedVariable(array, _const(1, codegen), variable_type=element_type, codegen=codegen)
    root = CStatements([CAssignment(lhs, _const(7, codegen), codegen=codegen)], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.raw_fact_count == 0


def test_def_use_semantic_cast_lvalue_defines_low_byte_only() -> None:
    codegen = _codegen()
    local = _local(-2, codegen, "word")
    low_byte = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeChar(False),
        local,
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(low_byte, _const(7, codegen), codegen=codegen),
            local,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.raw_fact_count == 1
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP-0x2:size2:root.stmt1",
    )


def test_def_use_semantic_cast_lvalue_byte_pair_defines_word() -> None:
    codegen = _codegen()
    local = _local(-2, codegen, "word")
    byte_type = SimTypeChar(False)
    low_byte = CSemanticCast8616(
        SimTypeShort(False),
        byte_type,
        local,
        codegen=codegen,
    )
    high_byte = CSemanticCast8616(
        SimTypeShort(False),
        byte_type,
        CBinaryOp("Shr", local, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(low_byte, _const(7, codegen), codegen=codegen),
            CAssignment(high_byte, _const(0, codegen), codegen=codegen),
            local,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.materialized_count == 1


def test_def_use_indexed_array_read_requires_exact_element_definition() -> None:
    codegen = _codegen()
    element_type = SimTypeShort(False)
    array = CVariable(
        SimStackVariable(-8, 8, base="bp", name="items"),
        variable_type=SimTypeFixedSizeArray(element_type, 4),
        codegen=codegen,
    )
    first = CIndexedVariable(
        array,
        _const(0, codegen),
        variable_type=element_type,
        codegen=codegen,
    )
    second = CIndexedVariable(
        array,
        _const(1, codegen),
        variable_type=element_type,
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(first, _const(7, codegen), codegen=codegen),
            first,
            second,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.raw_fact_count == 2
    assert report.materialized_count == 1
    assert report.issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP-0x6:size2:root.stmt2",
    )


def test_def_use_dynamic_array_read_requires_complete_object_definition() -> None:
    codegen = _codegen()
    element_type = SimTypeShort(False)
    array = CVariable(
        SimStackVariable(-8, 8, base="bp", name="items"),
        variable_type=SimTypeFixedSizeArray(element_type, 4),
        codegen=codegen,
    )
    index = _local(-10, codegen, "index")
    dynamic_read = CIndexedVariable(
        array,
        index,
        variable_type=element_type,
        codegen=codegen,
    )
    output_call = CFunctionCall("fill_items", None, [], codegen=codegen)
    root = CStatements(
        [
            CAssignment(index, _const(1, codegen), codegen=codegen),
            CExpressionStatement(output_call, codegen=codegen),
            dynamic_read,
        ],
        codegen=codegen,
    )

    without_object_fact = validate_structured_def_use_8616(root)
    with_object_fact = validate_structured_def_use_8616(
        root,
        call_output_definitions={
            id(output_call): (
                DefUseCallOutputDefinition8616(base_offset=-8, width=8),
            ),
        },
    )

    assert without_object_fact.issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP-0x8:size8:root.stmt2",
    )
    assert with_object_fact.passed
    assert with_object_fact.materialized_count == 2


def test_def_use_dynamic_array_store_does_not_define_complete_object() -> None:
    codegen = _codegen()
    element_type = SimTypeShort(False)
    array = CVariable(
        SimStackVariable(-8, 8, base="bp", name="items"),
        variable_type=SimTypeFixedSizeArray(element_type, 4),
        codegen=codegen,
    )
    index = _local(-10, codegen, "index")
    dynamic_element = CIndexedVariable(
        array,
        index,
        variable_type=element_type,
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(index, _const(1, codegen), codegen=codegen),
            CAssignment(dynamic_element, _const(7, codegen), codegen=codegen),
            dynamic_element,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP-0x8:size8:root.stmt2",
    )


def test_def_use_dynamic_array_read_accepts_all_exact_elements_defined() -> None:
    codegen = _codegen()
    element_type = SimTypeShort(False)
    array = CVariable(
        SimStackVariable(-8, 8, base="bp", name="items"),
        variable_type=SimTypeFixedSizeArray(element_type, 4),
        codegen=codegen,
    )
    index = _local(-10, codegen, "index")
    statements: list[object] = [
        CAssignment(index, _const(1, codegen), codegen=codegen),
    ]
    statements.extend(
        CAssignment(
            CIndexedVariable(
                array,
                _const(item_index, codegen),
                variable_type=element_type,
                codegen=codegen,
            ),
            _const(item_index + 1, codegen),
            codegen=codegen,
        )
        for item_index in range(4)
    )
    statements.append(
        CIndexedVariable(
            array,
            index,
            variable_type=element_type,
            codegen=codegen,
        )
    )
    root = CStatements(statements, codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.raw_fact_count == 2
    assert report.materialized_count == 2


def test_def_use_out_of_bounds_indexed_stack_read_is_refused() -> None:
    codegen = _codegen()
    element_type = SimTypeShort(False)
    array = CVariable(
        SimStackVariable(-8, 8, base="bp", name="items"),
        variable_type=SimTypeFixedSizeArray(element_type, 4),
        codegen=codegen,
    )
    out_of_bounds = CIndexedVariable(
        array,
        _const(4, codegen),
        variable_type=element_type,
        codegen=codegen,
    )
    root = CStatements([out_of_bounds], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP-0x8:size8:root.stmt0",
    )
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0


def test_def_use_array_expression_is_an_address_not_a_whole_object_read():
    codegen = _codegen()
    array = CVariable(
        SimStackVariable(-8, 8, base="bp", name="items"),
        variable_type=SimTypeFixedSizeArray(SimTypeShort(False), 4),
        codegen=codegen,
    )
    root = CStatements([array], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.raw_fact_count == 0


def test_def_use_indexed_pointer_lvalue_reads_stack_pointer_base():
    codegen = _codegen()
    element_type = SimTypeShort(False)
    pointer = CVariable(
        SimStackVariable(-2, 2, base="bp", name="items"),
        variable_type=SimTypePointer(element_type),
        codegen=codegen,
    )
    lhs = CIndexedVariable(pointer, _const(1, codegen), variable_type=element_type, codegen=codegen)
    root = CStatements([CAssignment(lhs, _const(7, codegen), codegen=codegen)], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP-0x2:size2:root.stmt0.lhs.base",
    )


def test_def_use_branch_intersection_tracks_byte_coverage_not_view_shape():
    codegen = _codegen()
    word = _local_view(-6, 2, codegen, "word")
    low_byte = _local_view(-6, 1, codegen, "low_byte")
    high_byte = _local_view(-5, 1, codegen, "high_byte")
    conditional = CIfElse(
        [
            (
                _const(1, codegen),
                CStatements([CAssignment(word, _const(2, codegen), codegen=codegen)], codegen=codegen),
            )
        ],
        else_node=CStatements(
            [
                CAssignment(low_byte, _const(3, codegen), codegen=codegen),
                CAssignment(high_byte, _const(4, codegen), codegen=codegen),
            ],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([conditional, word], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.materialized_count == 1


def test_def_use_requires_assignment_on_every_branch():
    codegen = _codegen()
    local = _local(-2, codegen, "i")
    conditional = CIfElse(
        [
            (
                _const(1, codegen),
                CStatements([CAssignment(local, _const(2, codegen), codegen=codegen)], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    root = CStatements([conditional, local], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.failure_count == 1
    assert report.materialized_count == 0


def test_def_use_accepts_assignment_on_both_branches():
    codegen = _codegen()
    local = _local(-2, codegen, "i")
    conditional = CIfElse(
        [
            (
                _const(1, codegen),
                CStatements([CAssignment(local, _const(2, codegen), codegen=codegen)], codegen=codegen),
            )
        ],
        else_node=CStatements(
            [CAssignment(local, _const(3, codegen), codegen=codegen)],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([conditional, local], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.materialized_count == 1


def test_def_use_ignores_terminated_branch_when_joining_definitions():
    codegen = _codegen()
    carrier = _register_carrier(0, codegen, "joined_ax")
    conditional = CIfElse(
        [
            (
                _const(1, codegen),
                CStatements([CAssignment(carrier, _const(2, codegen), codegen=codegen)], codegen=codegen),
            )
        ],
        else_node=CStatements([CReturn(None, codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([conditional, carrier], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.materialized_count == 1


def test_def_use_accepts_definition_under_repeated_exact_predicate():
    codegen = _codegen()
    first_frequency = _local(4, codegen, "frequency")
    updated_frequency = _local(4, codegen, "frequency")
    second_frequency = _local(4, codegen, "frequency")
    duration = _local(6, codegen, "duration")
    control_definition = _local(-2, codegen, "control")
    control_read = _local(-2, codegen, "control")
    divide_call = CFunctionCall(
        _const(0x1234, codegen),
        None,
        [first_frequency],
        codegen=codegen,
    )
    sleep_call = CFunctionCall(
        _const(0x5678, codegen),
        None,
        [duration],
        codegen=codegen,
    )
    root = CStatements(
        [
            CIfElse(
                [
                    (
                        first_frequency,
                        CStatements(
                            [
                                CAssignment(
                                    control_definition,
                                    _const(7, codegen),
                                    codegen=codegen,
                                ),
                                CAssignment(
                                    updated_frequency,
                                    divide_call,
                                    codegen=codegen,
                                ),
                            ],
                            codegen=codegen,
                        ),
                    )
                ],
                codegen=codegen,
            ),
            CExpressionStatement(sleep_call, codegen=codegen),
            CIfElse(
                [
                    (
                        second_frequency,
                        CStatements([control_read], codegen=codegen),
                    )
                ],
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(
        root,
        entry_defined_stack_ranges=_ENTRY_STACK_ARGUMENTS,
    )

    assert report.passed
    assert report.raw_fact_count == 5
    assert report.materialized_count == 5


def test_def_use_refuses_guarded_definition_after_predicate_write():
    codegen = _codegen()
    predicate = _local(4, codegen, "frequency")
    control = _local(-2, codegen, "control")
    root = CStatements(
        [
            CIfElse(
                [
                    (
                        predicate,
                        CStatements(
                            [
                                CAssignment(
                                    control,
                                    _const(7, codegen),
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
                _local(4, codegen, "frequency"),
                _const(1, codegen),
                codegen=codegen,
            ),
            CIfElse(
                [
                    (
                        _local(4, codegen, "frequency"),
                        CStatements([_local(-2, codegen, "control")], codegen=codegen),
                    )
                ],
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(
        root,
        entry_defined_stack_ranges=_ENTRY_STACK_ARGUMENTS,
    )

    assert report.failure_count == 1
    assert report.materialized_count == 2


def test_def_use_refuses_guarded_definition_for_different_storage_predicate():
    codegen = _codegen()
    root = CStatements(
        [
            CIfElse(
                [
                    (
                        _local(4, codegen, "frequency"),
                        CStatements(
                            [
                                CAssignment(
                                    _local(-2, codegen, "control"),
                                    _const(7, codegen),
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
                        _local(6, codegen, "duration"),
                        CStatements([_local(-2, codegen, "control")], codegen=codegen),
                    )
                ],
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(
        root,
        entry_defined_stack_ranges=_ENTRY_STACK_ARGUMENTS,
    )

    assert report.failure_count == 1
    assert report.materialized_count == 2


def test_def_use_refuses_guarded_definition_after_predicate_address_escape():
    codegen = _codegen()
    escaped_frequency = CUnaryOp(
        "Reference",
        _local(4, codegen, "frequency"),
        codegen=codegen,
    )
    mutating_call = CFunctionCall(
        _const(0x5678, codegen),
        None,
        [escaped_frequency],
        codegen=codegen,
    )
    root = CStatements(
        [
            CIfElse(
                [
                    (
                        _local(4, codegen, "frequency"),
                        CStatements(
                            [
                                CAssignment(
                                    _local(-2, codegen, "control"),
                                    _const(7, codegen),
                                    codegen=codegen,
                                )
                            ],
                            codegen=codegen,
                        ),
                    )
                ],
                codegen=codegen,
            ),
            CExpressionStatement(mutating_call, codegen=codegen),
            CIfElse(
                [
                    (
                        _local(4, codegen, "frequency"),
                        CStatements([_local(-2, codegen, "control")], codegen=codegen),
                    )
                ],
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(
        root,
        entry_defined_stack_ranges=_ENTRY_STACK_ARGUMENTS,
    )

    assert report.failure_count == 1
    assert report.materialized_count == 2


def test_def_use_does_not_treat_while_body_assignment_as_definite_after_loop():
    codegen = _codegen()
    local = _local(-2, codegen, "i")
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([CAssignment(local, _const(2, codegen), codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop, local], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.failure_count == 1


def test_def_use_carries_definitions_from_all_unconditional_loop_breaks() -> None:
    codegen = _codegen()
    definition = _local(-2, codegen, "i")
    read = _local(-2, codegen, "i")
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements(
            [
                CAssignment(definition, _const(2, codegen), codegen=codegen),
                CIfElse(
                    [
                        (
                            _local(4, codegen, "arg_4"),
                            CStatements([CBreak(codegen=codegen)], codegen=codegen),
                        )
                    ],
                    codegen=codegen,
                ),
                CBreak(codegen=codegen),
            ],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([loop, read], codegen=codegen)

    report = validate_structured_def_use_8616(
        root,
        entry_defined_stack_ranges=_ENTRY_STACK_ARGUMENTS,
    )

    assert report.passed
    assert report.materialized_count == 2


def test_def_use_refuses_unconditional_loop_definition_after_possible_break() -> None:
    codegen = _codegen()
    definition = _local(-2, codegen, "i")
    read = _local(-2, codegen, "i")
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements(
            [
                CIfElse(
                    [
                        (
                            _local(4, codegen, "arg_4"),
                            CStatements([CBreak(codegen=codegen)], codegen=codegen),
                        )
                    ],
                    codegen=codegen,
                ),
                CAssignment(definition, _const(2, codegen), codegen=codegen),
                CBreak(codegen=codegen),
            ],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([loop, read], codegen=codegen)

    report = validate_structured_def_use_8616(
        root,
        entry_defined_stack_ranges=_ENTRY_STACK_ARGUMENTS,
    )

    assert report.failure_count == 1
    assert report.materialized_count == 1


def test_def_use_refuses_conditional_loop_definition_even_with_break() -> None:
    codegen = _codegen()
    definition = _local(-2, codegen, "i")
    read = _local(-2, codegen, "i")
    loop = CWhileLoop(
        _local(4, codegen, "arg_4"),
        CStatements(
            [
                CAssignment(definition, _const(2, codegen), codegen=codegen),
                CBreak(codegen=codegen),
            ],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([loop, read], codegen=codegen)

    report = validate_structured_def_use_8616(
        root,
        entry_defined_stack_ranges=_ENTRY_STACK_ARGUMENTS,
    )

    assert report.failure_count == 1
    assert report.materialized_count == 1


def test_def_use_refuses_positive_bp_read_without_explicit_argument_range() -> None:
    codegen = _codegen()
    root = CStatements([_local(4, codegen, "arg_4")], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.failure_count == 1
    assert report.raw_fact_count == 1


def test_def_use_refuses_structured_register_carrier_read_before_assignment() -> None:
    codegen = _codegen()
    carrier = _register_carrier(6, codegen, "bx")
    root = CStatements([carrier], codegen=codegen)

    report = validate_structured_def_use_8616(root)

    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "uninitialized-read:register-carrier:reg+0x6:size2:region0x1000:ssa-str-ssa_1:root.stmt0",
    )


def test_def_use_accepts_structured_register_carrier_after_assignment() -> None:
    codegen = _codegen()
    definition = _register_carrier(6, codegen, "bx")
    read = _register_carrier(6, codegen, "bx")
    root = CStatements(
        [
            CAssignment(definition, _const(7, codegen), codegen=codegen),
            read,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.passed
    assert report.materialized_count == 1


def test_def_use_accepts_only_exact_typed_packed_flag_preservation_site() -> None:
    codegen = _codegen()
    flags = _register_carrier(36, codegen, "flags", ident="flags_in")
    result = _register_carrier(100, codegen, "flags_result", ident="flags_result")
    assignment = CAssignment(result, flags, codegen=codegen)
    assignment.tags["ins_addr"] = 0x1010
    root = CStatements([assignment], codegen=codegen)
    evidence = PackedStatusFlagPreservationEvidence8616(36, frozenset({0x1010}))

    accepted = validate_structured_def_use_8616(
        root,
        packed_status_flag_preservation=evidence,
    )
    refused = validate_structured_def_use_8616(
        root,
        packed_status_flag_preservation=PackedStatusFlagPreservationEvidence8616(
            36,
            frozenset({0x1020}),
        ),
    )

    assert accepted.passed
    assert accepted.materialized_count == 1
    assert refused.failure_count == 1


def test_def_use_accepts_tagged_packed_flag_condition_at_exact_site() -> None:
    codegen = _codegen()
    flags = _register_carrier(36, codegen, "flags", ident="flags_in")
    condition = CUnaryOp("LogicalNot", flags, codegen=codegen)
    condition.tags["ins_addr"] = 0x1010
    root = CStatements(
        [CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)],
        codegen=codegen,
    )

    accepted = validate_structured_def_use_8616(
        root,
        packed_status_flag_preservation=PackedStatusFlagPreservationEvidence8616(
            36, frozenset({0x1010})
        ),
    )
    refused = validate_structured_def_use_8616(
        root,
        packed_status_flag_preservation=PackedStatusFlagPreservationEvidence8616(
            36, frozenset({0x1020})
        ),
    )

    assert accepted.passed
    assert accepted.materialized_count == 1
    assert refused.failure_count == 1


def test_def_use_accepts_explicit_register_argument_at_entry() -> None:
    codegen = _codegen()
    argument = _register_carrier(6, codegen, "bx")
    read = _register_carrier(6, codegen, "bx")
    root = CStatements([read], codegen=codegen)

    report = validate_structured_def_use_8616(
        root,
        entry_defined_registers=(argument,),
    )

    assert report.passed
    assert report.materialized_count == 1


def test_def_use_refuses_unstructured_register_identity_after_apparent_assignment() -> None:
    codegen = _codegen()
    definition = _register_carrier(6, codegen, "bx", ident=None, region=None)
    read = _register_carrier(6, codegen, "bx", ident=None, region=None)
    root = CStatements(
        [
            CAssignment(definition, _const(7, codegen), codegen=codegen),
            read,
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "uninitialized-read:register-carrier:reg+0x6:size2:ssa-unproven:root.stmt1",
    )


def test_def_use_refuses_segment_carrier_read_before_assignment() -> None:
    codegen = _codegen()
    segment = _register_carrier(20, codegen, "ss", ident="ssa_ss")
    root = CStatements([segment], codegen=codegen)

    report = validate_structured_def_use_8616(
        root,
        segment_register_offsets=frozenset({20}),
    )

    assert report.issue_tokens() == (
        "uninitialized-read:segment-carrier:reg+0x14:size2:region0x1000:ssa-str-ssa_ss:root.stmt0",
    )


def test_def_use_accepts_typed_architectural_segment_live_in() -> None:
    codegen = _codegen()
    segment = _register_carrier(20, codegen, "ss", ident=None, region=None)
    root = CStatements([segment], codegen=codegen)

    report = validate_structured_def_use_8616(
        root,
        segment_register_offsets=frozenset({20}),
        entry_defined_segment_register_offsets=frozenset({20}),
    )

    assert report.passed
    assert report.materialized_count == 1


def test_tail_validation_derives_entry_segments_only_from_proven_typed_ir_state() -> None:
    project = SimpleNamespace(arch=ArchX86())
    function_addr = 0x4010
    ds_state = SegmentRegisterState(
        register="ds",
        value_kind="architectural_live_in",
        source="ds",
        origin=SegmentOrigin.PROVEN,
    )
    unknown_es_state = SegmentRegisterState(
        register="es",
        value_kind="unknown",
        source=None,
        origin=SegmentOrigin.UNKNOWN,
    )
    artifact = SegmentStateArtifact(
        entry_states={function_addr: {"ds": ds_state, "es": unknown_es_state}},
        exit_states={},
        summary={},
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=function_addr),
        _inertia_segment_state_artifact=artifact,
    )

    offsets = _def_use_entry_segment_register_offsets_8616(project, codegen)

    assert offsets == frozenset({project.arch.registers["ds"][0]})


def test_def_use_ignores_stale_direct_call_target_carrier() -> None:
    codegen = _codegen()
    segment = _register_carrier(20, codegen, "ss", ident="ssa_ss")
    direct_call = CFunctionCall(
        segment,
        SimpleNamespace(addr=0x4010),
        [],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(
        direct_call,
        segment_register_offsets=frozenset({20}),
    )

    assert report.passed
    assert report.raw_fact_count == 0


def test_def_use_refuses_live_indirect_call_target_carrier() -> None:
    codegen = _codegen()
    segment = _register_carrier(20, codegen, "ss", ident="ssa_ss")
    indirect_call = CFunctionCall(segment, None, [], codegen=codegen)

    report = validate_structured_def_use_8616(
        indirect_call,
        segment_register_offsets=frozenset({20}),
    )

    assert report.issue_tokens() == (
        "uninitialized-read:segment-carrier:reg+0x14:size2:region0x1000:ssa-str-ssa_ss:root",
    )


def test_def_use_refuses_segment_carrier_argument_to_direct_call() -> None:
    codegen = _codegen()
    segment = _register_carrier(20, codegen, "ss", ident="ssa_ss")
    direct_call = CFunctionCall(
        _const(0x4010, codegen),
        SimpleNamespace(addr=0x4010),
        [segment],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(
        direct_call,
        segment_register_offsets=frozenset({20}),
    )

    assert report.issue_tokens() == (
        "uninitialized-read:segment-carrier:reg+0x14:size2:region0x1000:ssa-str-ssa_ss:root",
    )


def test_def_use_accepts_pair_list_switch_cases_exposed_by_angr():
    codegen = _codegen()
    switch = CSwitchCase(
        _const(1, codegen),
        [(_const(1, codegen), CStatements([], codegen=codegen))],
        None,
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(switch)

    assert report.passed


def test_tail_validation_refuses_def_use_failure_even_when_baseline_already_lost_definition():
    issue = "uninitialized-read:stack-local:SS:BP-0x2:size2:root.stmt0"

    direct_diff = compare_x86_16_tail_validation_summaries(
        _empty_summary(def_use_issues=(issue,)), _empty_summary(def_use_issues=(issue,))
    )
    final_result = build_x86_16_tail_validation_cached_result(
        owner={},
        stage="postprocess",
        mode="live_out",
        before_fingerprint="same-lost-definition",
        after_fingerprint="same-lost-definition",
        before_summary=_empty_summary(def_use_issues=(issue,)),
        after_summary=_empty_summary(def_use_issues=(issue,)),
    )

    assert direct_diff["changed"] is False
    assert direct_diff["status"] == "stable"
    assert final_result["changed"] is True
    assert final_result["status"] == "failed"
    assert final_result["semantic_failures"] == {"def_use": (issue,)}


def test_tail_validation_comparison_refuses_new_def_use_failure():
    issue = "uninitialized-read:register-carrier:reg+0x24:size2:root.stmt0"

    diff = compare_x86_16_tail_validation_summaries(
        _empty_summary(),
        _empty_summary(def_use_issues=(issue,)),
    )

    assert diff["changed"] is True
    assert diff["status"] == "failed"
    assert diff["semantic_failures"] == {"def_use": (issue,)}


def test_tail_validation_summary_cache_keys_def_use_state_separately():
    codegen = _codegen()
    local = _local(-2, codegen, "i")
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([local], codegen=codegen)
    )

    before = collect_x86_16_tail_validation_summary(
        codegen.project,
        codegen,
        boundary_fingerprint="same-observable-boundary",
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(local, _const(1, codegen), codegen=codegen),
            local,
        ],
        codegen=codegen,
    )
    after = collect_x86_16_tail_validation_summary(
        codegen.project,
        codegen,
        boundary_fingerprint="same-observable-boundary",
    )

    assert before.def_use_issues
    assert after.def_use_issues == ()
    assert codegen._inertia_tail_validation_last_summary_cache_hit is False


def test_tail_validation_summary_includes_uninitialized_register_carrier() -> None:
    codegen = _codegen()
    carrier = _register_carrier(6, codegen, "bx")
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements([carrier], codegen=codegen),
    )

    summary = collect_x86_16_tail_validation_summary(
        codegen.project,
        codegen,
        boundary_fingerprint="register-carrier-negative-control",
    )

    assert summary.def_use_issues == (
        "uninitialized-read:register-carrier:reg+0x6:size2:region0x1000:ssa-str-ssa_1",
    )


def test_final_semantic_refresh_promotes_absolute_def_use_failure() -> None:
    codegen = _codegen()
    local = _local(-2, codegen, "control")
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements([local], codegen=codegen),
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(codegen.project, codegen)

    assert report.passed is False
    assert report.def_use.failure_count == 1
    assert x86_16_tail_validation_snapshot_passed(
        codegen._inertia_tail_validation_snapshot
    ) is False
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["status"] == "failed"
    assert postprocess["semantic_failures"] == {
        "def_use": (
            "uninitialized-read:stack-local:SS:BP-0x2:size2:root.stmt0",
        )
    }
    assert postprocess["final_semantic_guard"]["def_use"] == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


def test_final_semantic_probe_does_not_persist_transient_failure() -> None:
    codegen = _codegen()
    local = _local(-2, codegen, "control")
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements([local], codegen=codegen),
    )
    stable_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }
    expected_snapshot = {stage: dict(entry) for stage, entry in stable_snapshot.items()}
    codegen._inertia_tail_validation_snapshot = stable_snapshot

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
        persist_failures=False,
    )

    assert report.passed is False
    assert codegen._inertia_tail_validation_snapshot == expected_snapshot


def test_final_semantic_refresh_refuses_dynamic_read_of_partial_stack_array() -> None:
    codegen = _codegen()
    element_type = SimTypeShort(False)
    array = CVariable(
        SimStackVariable(-8, 8, base="bp", name="items"),
        variable_type=SimTypeFixedSizeArray(element_type, 4),
        codegen=codegen,
    )
    index = _local(-10, codegen, "index")
    dynamic_read = CIndexedVariable(
        array,
        index,
        variable_type=element_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements(
            [
                CAssignment(index, _const(1, codegen), codegen=codegen),
                dynamic_read,
            ],
            codegen=codegen,
        ),
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
    )

    issue = "uninitialized-read:stack-local:SS:BP-0x8:size8:root.stmt1"
    assert report.passed is False
    assert report.def_use.issue_tokens() == (issue,)
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["status"] == "failed"
    assert postprocess["semantic_failures"] == {"def_use": (issue,)}
    assert postprocess["final_semantic_guard"]["def_use"] == {
        "raw_fact_count": 2,
        "normalized_fact_count": 2,
        "classified_fact_count": 2,
        "materialized_count": 1,
        "failure_count": 1,
    }
