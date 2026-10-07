from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.call_argument_stack_sources import containing_stack_cvariable_8616
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_alias_8616,
    record_stack_variable_coordinate_projection_8616,
)
from archinfo import ArchX86

from inertia.validation.validation_calls import validate_call_argument_classes_8616


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self._inertia_callsite_summaries: dict[int, CallsiteSummary8616] = {}
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _summary() -> CallsiteSummary8616:
    address_source = (
        "expr",
        ("bp", 6),
        (("add_source", ("expr", ("bp", -2), (("shl", 1),))),),
    )
    return CallsiteSummary8616(
        callsite_addr=0x1010,
        target_addr=0x2000,
        return_addr=0x1013,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        push_arg_sources=(("imm", 104), ("seg_indirect", "ds", 2, address_source)),
        logical_arg_classes=(),
    )


def _byte_source_summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1030,
        target_addr=0x2000,
        return_addr=0x1033,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=False,
        push_arg_sources=(("bp", 5, 1),),
        logical_arg_classes=(),
    )


def _call_with_first_argument(codegen: _Codegen, first_argument: object) -> CFunctionCall:
    call = CFunctionCall(
        "consume",
        None,
        [first_argument, CConstant(104, SimTypeShort(False), codegen=codegen)],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries[id(call)] = _summary()
    return call


def test_call_argument_source_validation_accepts_exact_stack_dependencies() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False)
    pointer_type = SimTypePointer(short_type).with_arch(codegen.project.arch)
    argument = CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_5"),
        variable_type=pointer_type,
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=short_type,
        codegen=codegen,
    )
    indexed = CIndexedVariable(argument, index, variable_type=short_type, codegen=codegen)
    call = _call_with_first_argument(codegen, indexed)

    report = validate_call_argument_classes_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_call_argument_source_validation_uses_machine_bp_projection() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False)
    producer_variable = SimStackVariable(-4, 2, base="bp", name="local_2")
    producer_cvar = CVariable(
        producer_variable,
        variable_type=short_type,
        codegen=codegen,
    )
    variable = SimStackVariable(-4, 2, base="bp", name="local_2")
    argument = CVariable(
        variable,
        variable_type=short_type,
        codegen=codegen,
    )
    call = CFunctionCall(
        "consume",
        None,
        [argument],
        tags={"ins_addr": 0x1040},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries[id(call)] = CallsiteSummary8616(
        callsite_addr=0x1040,
        target_addr=0x2000,
        return_addr=0x1043,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        push_arg_sources=(("bp", -2, 2),),
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=producer_variable,
        cvar=producer_cvar,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )
    record_stack_variable_coordinate_alias_8616(
        codegen,
        bp_offset=-2,
        size=2,
        variable=variable,
    )

    report = validate_call_argument_classes_8616(
        codegen,
        CStatements([call], codegen=codegen),
    )

    assert report.passed
    assert report.materialized_count == 1


def test_call_argument_source_validation_uses_typed_function_coordinate_delta() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False)
    formal = CVariable(
        SimStackVariable(2, 2, base="bp", name="arg_4"),
        variable_type=short_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=(formal,),
        functy=SimTypeFunction((short_type,), short_type),
    )
    local_argument = CVariable(
        SimStackVariable(-0x2E, 2, base="bp", name="local_2c"),
        variable_type=short_type,
        codegen=codegen,
    )
    call = CFunctionCall(
        "consume",
        None,
        [local_argument],
        tags={"ins_addr": 0x1040},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries[id(call)] = CallsiteSummary8616(
        callsite_addr=0x1040,
        target_addr=0x2000,
        return_addr=0x1043,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        push_arg_sources=(("bp", -0x2C, 2),),
    )

    report = validate_call_argument_classes_8616(
        codegen,
        CStatements([call], codegen=codegen),
    )

    assert report.passed
    assert report.materialized_count == 1


def test_call_argument_source_validation_refuses_recycled_constant_pointer() -> None:
    codegen = _Codegen()
    wrong_argument = CConstant(104, SimTypeShort(False), codegen=codegen)
    call = _call_with_first_argument(codegen, wrong_argument)

    report = validate_call_argument_classes_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed is False
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "call-argument-source:stack-dependency-mismatch:callsite=0x1010:"
        "target=0x2000:arg=0:expected-bp=-0x2,+0x6:actual-bp=none",
    )


def test_call_argument_source_validation_refuses_recycled_call_node_id() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False)
    pointer_type = SimTypePointer(short_type).with_arch(codegen.project.arch)
    wrong_call = CFunctionCall(
        "consume",
        None,
        [CConstant(104, short_type, codegen=codegen), CConstant(104, short_type, codegen=codegen)],
        tags={"ins_addr": 0x1020},
        codegen=codegen,
    )
    argument = CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_5"),
        variable_type=pointer_type,
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=short_type,
        codegen=codegen,
    )
    right_call = CFunctionCall(
        "consume",
        None,
        [CIndexedVariable(argument, index, variable_type=short_type, codegen=codegen), CConstant(104, short_type, codegen=codegen)],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries[id(wrong_call)] = _summary()

    report = validate_call_argument_classes_8616(
        codegen,
        CStatements([wrong_call, right_call], codegen=codegen),
    )

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_containing_stack_source_sees_object_created_during_same_call_pass() -> None:
    codegen = _Codegen()
    codegen.cfunc = SimpleNamespace(arg_list=(), statements=None, variables_in_use={})
    argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    selected = containing_stack_cvariable_8616(codegen, {4: argument}, offset=5, size_hint=2)

    assert selected is argument


def test_containing_stack_source_sees_declared_function_argument() -> None:
    codegen = _Codegen()
    argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(arg_list=(argument,), statements=None, variables_in_use={})

    selected = containing_stack_cvariable_8616(codegen, {}, offset=5, size_hint=2)

    assert selected is argument


def test_containing_stack_source_prefers_exact_word_over_wider_overlap() -> None:
    codegen = _Codegen()
    argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    overlapping = CVariable(
        SimStackVariable(2, 4, base="bp", name="local_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=(argument,),
        statements=None,
        variables_in_use={overlapping.variable: overlapping},
    )

    selected = containing_stack_cvariable_8616(codegen, {}, offset=4, size_hint=2)

    assert selected is argument


def test_containing_stack_source_prefers_exact_width_at_same_offset() -> None:
    codegen = _Codegen()
    exact = CVariable(
        SimStackVariable(-2, 2, base="bp", name="err"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    widened = CVariable(
        SimStackVariable(-2, 4, base="bp", name="err"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=(),
        statements=None,
        variables_in_use={widened.variable: widened, exact.variable: exact},
    )

    selected = containing_stack_cvariable_8616(codegen, {}, offset=-2, size_hint=2)

    assert selected is exact


def test_call_argument_source_validation_accepts_high_byte_projection() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False)
    argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4"),
        variable_type=short_type,
        codegen=codegen,
    )
    high_byte = CBinaryOp(
        "Shr",
        argument,
        CConstant(8, short_type, codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall(
        "consume",
        None,
        [high_byte],
        tags={"ins_addr": 0x1030},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries[id(call)] = _byte_source_summary()

    report = validate_call_argument_classes_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.materialized_count == 1


def test_call_argument_source_validation_refuses_wrong_high_byte_projection() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False)
    overlapping = CVariable(
        SimStackVariable(2, 4, base="bp", name="local_2"),
        variable_type=short_type,
        codegen=codegen,
    )
    wrong_high_byte = CBinaryOp(
        "Shr",
        overlapping,
        CConstant(8, short_type, codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall(
        "consume",
        None,
        [wrong_high_byte],
        tags={"ins_addr": 0x1030},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries[id(call)] = _byte_source_summary()

    report = validate_call_argument_classes_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed is False
    assert report.issue_tokens() == (
        "call-argument-source:stack-dependency-mismatch:callsite=0x1030:"
        "target=0x2000:arg=0:expected-bp=+0x5:actual-bp=+0x3",
    )
