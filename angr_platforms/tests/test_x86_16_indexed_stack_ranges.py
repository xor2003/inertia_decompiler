from dataclasses import dataclass, replace
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CIndexedVariable,
    CStatements,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeFixedSizeArray, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.semantics.call_contracts import (
    CallContractEvidenceKind8616,
    IntegerValueRange8616,
    RuntimeCallReturnContract8616,
    runtime_call_return_contract_8616,
)
from angr_platforms.X86_16.structuring.indexed_stack_ranges import (
    IndexedStackReadProofKind8616,
    collect_indexed_stack_read_proofs_8616,
)
from angr_platforms.X86_16.validation_dataflow import (
    validate_structured_def_use_8616,
)
from angr_platforms.X86_16.widening.segmented_load_identity import (
    SegmentedLoadIdentity8616,
    segmented_load_tags_8616,
)
from archinfo import ArchX86


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.project = SimpleNamespace(arch=ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _const(value: int, codegen: _Codegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _stack(
    offset: int,
    codegen: _Codegen,
    name: str,
    *,
    region: int | None = 0x4010,
) -> CVariable:
    return CVariable(
        SimStackVariable(offset, 2, base="bp", name=name, region=region),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _global(addr: int, codegen: _Codegen, name: str) -> CVariable:
    return CVariable(
        SimMemoryVariable(addr, 2, name=name, region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _array(codegen: _Codegen) -> CVariable:
    return CVariable(
        SimStackVariable(-8, 2, base="bp", name="items", region=0x4010),
        variable_type=SimTypeFixedSizeArray(SimTypeShort(False), 4),
        codegen=codegen,
    )


def _loop(
    codegen: _Codegen,
    induction: CVariable,
    bound: CVariable,
    body: CStatements,
) -> CForLoop:
    return CForLoop(
        CAssignment(induction, _const(0, codegen), codegen=codegen),
        CBinaryOp("CmpGT", bound, induction, codegen=codegen),
        CAssignment(
            induction,
            CBinaryOp("Add", induction, _const(1, codegen), codegen=codegen),
            codegen=codegen,
        ),
        body,
        codegen=codegen,
    )


def _while_loop(
    codegen: _Codegen,
    induction: CVariable,
    bound: object,
    body: CStatements,
    *,
    boolified_guard: bool = False,
    guard_after_body: bool = False,
    guard_induction: CVariable | None = None,
    duplicate_guard: bool = False,
    direct_condition: bool = False,
    conditional_increment: bool = False,
) -> tuple[CAssignment, CWhileLoop]:
    continuation: object = CBinaryOp(
        "CmpGT",
        bound,
        guard_induction or induction,
        codegen=codegen,
    )
    if boolified_guard:
        continuation = CITE(
            continuation,
            _const(0, codegen),
            _const(1, codegen),
            codegen=codegen,
        )
    guard = CIfElse(
        [
            (
                CUnaryOp(
                    "Not",
                    continuation,
                    codegen=codegen,
                ),
                CStatements([CBreak(codegen=codegen)], codegen=codegen),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    increment = CAssignment(
        induction,
        CBinaryOp("Add", induction, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    increment_statement: object = increment
    if conditional_increment:
        increment_statement = CIfElse(
            [
                (
                    CBinaryOp("CmpEQ", induction, _const(0, codegen), codegen=codegen),
                    CStatements([increment], codegen=codegen),
                )
            ],
            else_node=None,
            cstyle_ifs=True,
            codegen=codegen,
        )
    if direct_condition:
        statements = [*body.statements, increment_statement]
        loop_condition = continuation
    else:
        statements = (
            [*body.statements, guard, increment_statement]
            if guard_after_body
            else [guard, *body.statements, increment_statement]
        )
        loop_condition = _const(1, codegen)
    if duplicate_guard and not guard_after_body:
        statements.insert(
            1,
            CIfBreak(guard.condition_and_nodes[0][0], codegen=codegen),
        )
    return (
        CAssignment(induction, _const(0, codegen), codegen=codegen),
        CWhileLoop(
            loop_condition,
            CStatements(statements, codegen=codegen),
            codegen=codegen,
        ),
    )


def _signed_remainder_fact() -> DirectStackMoveFact8616:
    return DirectStackMoveFact8616(
        dst_offset=-14,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER,
        ins_addr=0x4020,
        source_offset=-12,
        source_immediate=1,
        source_call_name="rand",
        source_call_ins_addr=0x4010,
        source_call_return_contract=runtime_call_return_contract_8616("rand"),
    )


def _signed_remainder_fact_with_write(
    write_offset: int,
) -> DirectStackMoveFact8616:
    """Return a binary-proven remainder fact with one exact DS write."""
    return replace(
        _signed_remainder_fact(),
        source_call_name="sub_1234",
        source_call_return_contract=RuntimeCallReturnContract8616(
            semantic_id=None,
            value_range=IntegerValueRange8616(minimum=0, maximum=0x7FFF),
            preserves_caller_storage=False,
            evidence_kind=CallContractEvidenceKind8616.DECODED_BINARY,
            exact_memory_writes=(
                IRAddress(
                    space=MemSpace.DS,
                    offset=write_offset,
                    size=2,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
            ),
        ),
    )


@dataclass(frozen=True, slots=True)
class _TwoLoopOptions:
    conditional_decrement: bool = False
    control_before_prefix_write: bool = False
    nested_straight_line: bool = False
    unknown_call_contract: bool = False
    read_high_after_decrement: bool = False
    while_shape: bool = False
    while_boolified_guard: bool = False
    while_guard_after_body: bool = False
    while_tagged_segment_bound: bool = False
    mixed_stack_regions: bool = False
    predecessor_uses_segment_load: bool = False
    duplicate_call_carrier: bool = False
    insert_intrinsic_carrier: bool = False
    duplicate_prefix_guard: bool = False
    direct_while_shape: bool = False
    conditional_while_increment: bool = False


def _fixture_loop_bound(codegen, count, options: _TwoLoopOptions):
    if not options.while_tagged_segment_bound:
        return count
    return CFunctionCall(
        "opaque_segment_load",
        None,
        [],
        codegen=codegen,
        tags=segmented_load_tags_8616(
            SegmentedLoadIdentity8616(
                space=MemSpace.DS,
                offset=0x2000,
                width=2,
                region=0x4010,
            )
        ),
    )


def _fixture_prefix_statements(codegen, array, first_index, options: _TwoLoopOptions):
    prefix_assignment = CAssignment(
        CIndexedVariable(
            array,
            first_index,
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        CBinaryOp("Add", first_index, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    prefix_statements: list[object] = [prefix_assignment]
    if options.control_before_prefix_write:
        prefix_statements.insert(
            0,
            CIfElse(
                [
                    (
                        CBinaryOp(
                            "CmpEQ",
                            first_index,
                            _const(0, codegen),
                            codegen=codegen,
                        ),
                        CStatements([], codegen=codegen),
                    )
                ],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            ),
        )
    if options.nested_straight_line:
        prefix_statements = [
            CStatements(prefix_statements, codegen=codegen),
            CStatements([], codegen=codegen),
        ]
    return prefix_statements


def _guard_induction_clone(codegen, offset, name, options: _TwoLoopOptions):
    if not options.mixed_stack_regions:
        return None
    return _stack(offset, codegen, name, region=None)


def _shaped_loop_nodes(
    codegen,
    induction,
    guard_induction,
    loop_bound,
    count,
    body,
    options: _TwoLoopOptions,
    *,
    guard_after_body: bool = False,
    duplicate_guard: bool = False,
) -> tuple[object, ...]:
    if options.while_shape or options.direct_while_shape:
        return _while_loop(
            codegen,
            induction,
            loop_bound,
            body,
            boolified_guard=options.while_boolified_guard,
            guard_after_body=guard_after_body,
            guard_induction=guard_induction,
            duplicate_guard=duplicate_guard,
            direct_condition=options.direct_while_shape,
            conditional_increment=options.conditional_while_increment,
        )
    return (
        _loop(
            codegen,
            induction,
            count,
            body,
        ),
    )


def _random_call(codegen, options: _TwoLoopOptions):
    return CFunctionCall(
        "rand" if not options.unknown_call_contract else "unknown",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )


def _decrement_statement(codegen, high, second_index, options: _TwoLoopOptions):
    decrement = CAssignment(
        high,
        CBinaryOp("Sub", high, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    if not options.conditional_decrement:
        return decrement
    return CIfElse(
        [
            (
                CBinaryOp(
                    "CmpEQ",
                    second_index,
                    _const(0, codegen),
                    codegen=codegen,
                ),
                CStatements([decrement], codegen=codegen),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )


def _carrier_statements(codegen, options: _TwoLoopOptions) -> list[object]:
    carrier_statements: list[object] = []
    if options.duplicate_call_carrier:
        carrier_statements.append(
            CExpressionStatement(
                CFunctionCall(
                    "rand",
                    None,
                    [],
                    codegen=codegen,
                    tags={"ins_addr": 0x4010},
                ),
                codegen=codegen,
            )
        )
    if options.insert_intrinsic_carrier:
        carrier_statements.append(
            CExpressionStatement(
                CFunctionCall(
                    "_INSERT",
                    None,
                    [
                        _const(0, codegen),
                        _const(0, codegen),
                        _const(1, codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        )
    return carrier_statements


def _ordered_reads(
    carrier_statements,
    random_assignment,
    random_read,
    decrement_statement,
    high_read,
    options: _TwoLoopOptions,
):
    reads = [*carrier_statements, random_assignment, random_read]
    if options.read_high_after_decrement:
        reads.extend([decrement_statement, high_read])
    else:
        reads.extend([high_read, decrement_statement])
    return reads


def _second_body(codegen, reads, options: _TwoLoopOptions):
    if options.nested_straight_line:
        return [
            CStatements(reads[:2], codegen=codegen),
            CStatements(reads[2:], codegen=codegen),
        ]
    return reads


def _high_init(codegen, high, loop_bound, count, options: _TwoLoopOptions):
    return CAssignment(
        high,
        CBinaryOp(
            "Sub",
            loop_bound if options.predecessor_uses_segment_load else count,
            _const(1, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _two_loop_fixture(
    *,
    conditional_decrement: bool = False,
    control_before_prefix_write: bool = False,
    nested_straight_line: bool = False,
    unknown_call_contract: bool = False,
    read_high_after_decrement: bool = False,
    while_shape: bool = False,
    while_boolified_guard: bool = False,
    while_guard_after_body: bool = False,
    while_tagged_segment_bound: bool = False,
    mixed_stack_regions: bool = False,
    predecessor_uses_segment_load: bool = False,
    duplicate_call_carrier: bool = False,
    insert_intrinsic_carrier: bool = False,
    duplicate_prefix_guard: bool = False,
    direct_while_shape: bool = False,
    conditional_while_increment: bool = False,
) -> tuple[CStatements, CIndexedVariable, CIndexedVariable]:
    options = _TwoLoopOptions(
        conditional_decrement=conditional_decrement,
        control_before_prefix_write=control_before_prefix_write,
        nested_straight_line=nested_straight_line,
        unknown_call_contract=unknown_call_contract,
        read_high_after_decrement=read_high_after_decrement,
        while_shape=while_shape,
        while_boolified_guard=while_boolified_guard,
        while_guard_after_body=while_guard_after_body,
        while_tagged_segment_bound=while_tagged_segment_bound,
        mixed_stack_regions=mixed_stack_regions,
        predecessor_uses_segment_load=predecessor_uses_segment_load,
        duplicate_call_carrier=duplicate_call_carrier,
        insert_intrinsic_carrier=insert_intrinsic_carrier,
        duplicate_prefix_guard=duplicate_prefix_guard,
        direct_while_shape=direct_while_shape,
        conditional_while_increment=conditional_while_increment,
    )
    codegen = _Codegen()
    array = _array(codegen)
    count = _global(0x2000, codegen, "count")
    loop_bound = _fixture_loop_bound(codegen, count, options)
    first_index = _stack(-10, codegen, "first_index")
    prefix_body = CStatements(_fixture_prefix_statements(codegen, array, first_index, options), codegen=codegen)
    prefix_nodes = _shaped_loop_nodes(
        codegen,
        first_index,
        _guard_induction_clone(codegen, -10, "first_index_clone", options),
        loop_bound,
        count,
        prefix_body,
        options,
        guard_after_body=options.while_guard_after_body,
        duplicate_guard=options.duplicate_prefix_guard,
    )
    high = _stack(-12, codegen, "high")
    random_index = _stack(-14, codegen, "random_index")
    second_index = _stack(-16, codegen, "second_index")
    random_assignment = CAssignment(
        random_index,
        CBinaryOp(
            "Mod",
            _random_call(codegen, options),
            CBinaryOp("Add", high, _const(1, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    random_read = CIndexedVariable(
        array,
        random_index,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_read = CIndexedVariable(
        array,
        high,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    decrement_statement = _decrement_statement(codegen, high, second_index, options)
    reads = _ordered_reads(
        _carrier_statements(codegen, options),
        random_assignment,
        random_read,
        decrement_statement,
        high_read,
        options,
    )
    second_loop_body = CStatements(_second_body(codegen, reads, options), codegen=codegen)
    second_nodes = _shaped_loop_nodes(
        codegen,
        second_index,
        _guard_induction_clone(codegen, -16, "second_index_clone", options),
        loop_bound,
        count,
        second_loop_body,
        options,
    )
    root = CStatements(
        [
            *prefix_nodes,
            _high_init(codegen, high, loop_bound, count, options),
            *second_nodes,
        ],
        codegen=codegen,
    )
    return root, random_read, high_read


def test_structuring_proves_prefix_reads_for_remainder_and_countdown_indices() -> None:
    root, random_read, high_read = _two_loop_fixture()

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.raw_fact_count == 2
    assert report.normalized_fact_count == 2
    assert report.classified_fact_count == 2
    assert report.materialized_count == 2
    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }
    assert {
        proof.kind for proof in report.proofs
    } == {IndexedStackReadProofKind8616.INITIALIZED_PREFIX_BOUNDED_INDEX}


def test_structuring_proves_transparently_nested_straight_line_bodies() -> None:
    root, random_read, high_read = _two_loop_fixture(nested_straight_line=True)

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }


def test_structuring_proves_canonical_while_break_guard_prefix_reads() -> None:
    root, random_read, high_read = _two_loop_fixture(while_shape=True)

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }


def test_structuring_proves_direct_conditional_while_prefix_reads() -> None:
    root, random_read, high_read = _two_loop_fixture(direct_while_shape=True)

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }


def test_structuring_refuses_conditional_direct_while_increment() -> None:
    root, _random_read, _high_read = _two_loop_fixture(
        direct_while_shape=True,
        conditional_while_increment=True,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.raw_fact_count == 2
    assert report.materialized_count == 0
    assert report.failure_count == 2


def test_structuring_proves_duplicate_equivalent_while_break_guards() -> None:
    root, random_read, high_read = _two_loop_fixture(
        while_shape=True,
        duplicate_prefix_guard=True,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }


def test_structuring_joins_cloned_stack_variables_across_codegen_regions() -> None:
    root, random_read, high_read = _two_loop_fixture(
        while_shape=True,
        mixed_stack_regions=True,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.materialized_count == 2
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }


def test_structuring_joins_machine_bp_facts_to_entry_sp_ast_offsets() -> None:
    root, random_read, high_read = _two_loop_fixture()
    codegen = root.codegen
    array = random_read.variable
    assert isinstance(array, CVariable)
    array_variable = array.variable
    assert isinstance(array_variable, SimStackVariable)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=array_variable,
        cvar=array,
        bp_offset=-6,
        entry_sp_offset=-8,
        size=8,
    )
    for cvar, bp_offset in ((random_read.index, -12), (high_read.index, -10)):
        assert isinstance(cvar, CVariable)
        variable = cvar.variable
        assert isinstance(variable, SimStackVariable)
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=cvar,
            bp_offset=bp_offset,
            entry_sp_offset=variable.offset,
            size=variable.size,
        )
    fact = replace(
        _signed_remainder_fact(),
        dst_offset=-12,
        source_offset=-10,
    )

    without_registry = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(fact,),
    )
    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(fact,),
        codegen=codegen,
    )

    assert {proof.read_node_id for proof in without_registry.proofs} == {
        id(high_read),
    }
    assert report.materialized_count == 2
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }
    assert {proof.index_storage_offset for proof in report.proofs} == {-14, -12}
    assert {proof.array_offset for proof in without_registry.proofs} == {-8}
    assert {proof.array_offset for proof in report.proofs} == {-6}


def test_structuring_proves_boolified_while_break_guard_prefix_reads() -> None:
    root, random_read, high_read = _two_loop_fixture(
        while_shape=True,
        while_boolified_guard=True,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }


def test_structuring_uses_typed_segmented_load_identity_for_while_bound() -> None:
    root, random_read, high_read = _two_loop_fixture(
        while_shape=True,
        while_tagged_segment_bound=True,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }


def test_structuring_does_not_invalidate_prefix_for_typed_segmented_load() -> None:
    root, random_read, high_read = _two_loop_fixture(
        while_shape=True,
        while_tagged_segment_bound=True,
        predecessor_uses_segment_load=True,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }


def test_structuring_preserves_bound_across_disjoint_exact_call_write() -> None:
    root, random_read, high_read = _two_loop_fixture(
        duplicate_call_carrier=True,
        insert_intrinsic_carrier=True,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(
            _signed_remainder_fact_with_write(0x2100),
        ),
    )

    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }


def test_structuring_invalidates_bound_across_overlapping_exact_call_write() -> None:
    root, random_read, high_read = _two_loop_fixture()

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(
            _signed_remainder_fact_with_write(0x2000),
        ),
    )

    assert id(random_read) not in report.by_read_node_id()
    assert id(high_read) not in report.by_read_node_id()
    assert report.failure_count == 2


def test_structuring_refuses_while_prefix_write_before_break_guard() -> None:
    root, _random_read, _high_read = _two_loop_fixture(
        while_shape=True,
        while_guard_after_body=True,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.materialized_count == 0
    assert report.failure_count == 2


def test_structuring_refuses_prefix_write_after_control_split() -> None:
    root, _random_read, _high_read = _two_loop_fixture(
        control_before_prefix_write=True,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.materialized_count == 0
    assert report.failure_count == 2


def test_structuring_refuses_conditionally_executed_countdown_decrement() -> None:
    root, random_read, high_read = _two_loop_fixture(conditional_decrement=True)

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert id(random_read) not in report.by_read_node_id()
    assert id(high_read) not in report.by_read_node_id()
    assert report.failure_count == 2


def test_structuring_refuses_remainder_without_nonnegative_call_contract() -> None:
    root, random_read, high_read = _two_loop_fixture(unknown_call_contract=True)
    fact = _signed_remainder_fact()
    fact = DirectStackMoveFact8616(
        dst_offset=fact.dst_offset,
        width=fact.width,
        source_kind=fact.source_kind,
        ins_addr=fact.ins_addr,
        source_offset=fact.source_offset,
        source_immediate=fact.source_immediate,
        source_call_name="unknown",
        source_call_ins_addr=fact.source_call_ins_addr,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(fact,),
    )

    assert id(random_read) not in report.by_read_node_id()
    assert id(high_read) not in report.by_read_node_id()
    assert report.failure_count == 2


def test_structuring_refuses_countdown_read_after_decrement() -> None:
    root, random_read, high_read = _two_loop_fixture(read_high_after_decrement=True)

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert id(random_read) in report.by_read_node_id()
    assert id(high_read) not in report.by_read_node_id()
    assert report.failure_count == 1


def test_tail_validation_consumes_only_exact_structuring_read_proofs() -> None:
    root, _random_read, _high_read = _two_loop_fixture()
    proof_report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    without_proofs = validate_structured_def_use_8616(root)
    with_proofs = validate_structured_def_use_8616(
        root,
        indexed_stack_read_proofs=proof_report.by_read_node_id(),
    )

    assert without_proofs.failure_count == 2
    assert with_proofs.passed
    assert with_proofs.materialized_count == without_proofs.materialized_count + 2
