from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.postprocess.decompiler_postprocess_jcc import _stack_slot_expr_8616
from inertia.postprocess.decompiler_postprocess_stage import (
    _ensure_pointer_stack_arg_expr_8616,
)
from inertia.lowering.pointer_memory_idioms import (
    splice_proven_pointer_swap_statements_8616,
)
from inertia.lowering.real_mode_linear import (
    RealModeLinearStackAccess8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)
from inertia.lowering.stack_value_projection import (
    StackValueOwnerHint8616,
    StackValueProjectionStatus8616,
    project_stack_value_range_8616,
    stack_value_projection_stats_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
    stack_cvar_for_machine_bp_value_range_8616,
)


def test_byte_fill_reuses_typed_value_inside_word_abi_slot() -> None:
    """Keep a byte formal distinct from the following word formal."""
    arch = Arch86_16()
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=arch),
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000)
    value_storage = SimStackVariable(4, 2, base="bp", name="value", ident="arg_1")
    count_storage = SimStackVariable(6, 2, base="bp", name="count", ident="arg_2")
    value = CVariable(
        value_storage,
        variable_type=SimTypeChar(False).with_arch(arch),
        codegen=codegen,
    )
    count = CVariable(
        count_storage,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=value_storage,
        cvar=value,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=count_storage,
        cvar=count,
        bp_offset=8,
        entry_sp_offset=6,
        size=2,
    )

    assert stack_cvar_for_machine_bp_value_range_8616(codegen, 6, 1) is value
    assert stack_cvar_for_machine_bp_value_range_8616(codegen, 7, 1) is None
    assert stack_cvar_for_machine_bp_value_range_8616(codegen, 8, 1) is None
    assert _stack_slot_expr_8616(codegen, 6, 1) is value
    assert _stack_slot_expr_8616(codegen, 8, 2) is count


def test_runtime_byte_load_projects_unsigned_value_inside_word_abi_slot() -> None:
    """Preserve SEG_U8 zero extension while reusing a signed C formal."""
    arch = Arch86_16()
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=arch),
    )
    storage = SimStackVariable(2, 2, base="bp", name="value", ident="arg_0")
    value = CVariable(
        storage,
        variable_type=SimTypeChar(True).with_arch(arch),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[value],
        variables_in_use={storage: value},
        unified_local_vars={},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=storage,
        cvar=value,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )

    projected = project_stack_value_range_8616(codegen, 4, 1)

    assert projected.status is StackValueProjectionStatus8616.EXACT_VALUE
    assert projected.owner is not None
    assert projected.owner.cvar is value
    assert projected.expression is not None
    assert projected.expression.expr is value
    assert projected.expression.dst_type.signed is False
    writable = stack_cvar_for_stable_ss_linear_access_8616(
        codegen,
        RealModeLinearStackAccess8616(displacement=4, width=1),
        require_lvalue=True,
    )
    assert writable is value
    assert stack_value_projection_stats_8616(codegen).materialized_count == 2


def test_runtime_high_byte_load_projects_word_argument_not_padding() -> None:
    """Map BP+5 to the high byte of a word formal and refuse char padding."""
    arch = Arch86_16()
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=arch),
    )
    word_storage = SimStackVariable(2, 2, base="bp", name="word", ident="arg_0")
    word = CVariable(
        word_storage,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(arg_list=[word])
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=word_storage,
        cvar=word,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    overlapping_storage = SimStackVariable(
        5,
        2,
        base="bp",
        name="local_5",
        ident="is_5",
    )
    overlapping = CVariable(
        overlapping_storage,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=overlapping_storage,
        cvar=overlapping,
        bp_offset=5,
        entry_sp_offset=5,
        size=2,
    )
    codegen.cfunc.arg_list = [word, overlapping]

    high = project_stack_value_range_8616(
        codegen,
        5,
        1,
        owner_hint=StackValueOwnerHint8616(4, 2),
    )
    low = _stack_slot_expr_8616(codegen, 4, 1)

    assert high.status is StackValueProjectionStatus8616.CONTAINED_VALUE
    assert high.owner is not None
    assert high.owner.cvar is word
    assert high.expression is not None
    assert high.expression.expr.op == "Shr"
    assert high.expression.expr.lhs is word
    assert high.expression.expr.rhs.value == 8
    assert low.expr is word
    assert low.dst_type.size == 8
    word.variable_type = SimTypePointer(SimTypeChar(False)).with_arch(arch)
    pointer_high = project_stack_value_range_8616(
        codegen,
        5,
        1,
        owner_hint=StackValueOwnerHint8616(4, 2),
    )
    assert pointer_high.expression is not None
    assert isinstance(pointer_high.expression.expr.lhs, CFunctionCall)
    assert pointer_high.expression.expr.lhs.callee_target == "PTR_U16"

    char_codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=arch),
    )
    char_storage = SimStackVariable(2, 2, base="bp", name="byte", ident="arg_0")
    char = CVariable(
        char_storage,
        variable_type=SimTypeChar(False).with_arch(arch),
        codegen=char_codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        char_codegen,
        variable=char_storage,
        cvar=char,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )

    padding = project_stack_value_range_8616(char_codegen, 5, 1)

    assert padding.status is StackValueProjectionStatus8616.OUTSIDE_VALUE
    assert padding.expression is None
    char.variable_type = SimTypeShort(False).with_arch(arch)
    promoted_high = project_stack_value_range_8616(
        char_codegen,
        5,
        1,
        owner_hint=StackValueOwnerHint8616(4, 2),
    )
    assert promoted_high.status is StackValueProjectionStatus8616.CONTAINED_VALUE
    assert promoted_high.expression is not None
    assert promoted_high.expression.expr.op == "Shr"
    assert promoted_high.expression.expr.lhs is char
    assert stack_value_projection_stats_8616(char_codegen).failure_count == 1


def test_exact_function_pointer_stack_load_preserves_callable_type() -> None:
    """Do not turn an exact function-pointer argument into a guest data offset."""
    arch = Arch86_16()
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=arch),
    )
    storage = SimStackVariable(2, 2, base="bp", name="fn", ident="arg_0")
    function_type = SimTypeFunction(
        [SimTypeShort(False)],
        SimTypeShort(False),
    ).with_arch(arch)
    pointer = CVariable(
        storage,
        variable_type=SimTypePointer(function_type).with_arch(arch),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(arg_list=[pointer])
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=storage,
        cvar=pointer,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )

    projected = project_stack_value_range_8616(codegen, 4, 2)

    assert projected.status is StackValueProjectionStatus8616.EXACT_VALUE
    assert projected.expression is pointer


def test_pointer_memory_arguments_reuse_exact_machine_bp_projections() -> None:
    """Keep distinct BP arguments when their entry-SP offsets collide numerically."""
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    pointer_type = SimTypePointer(word_type).with_arch(arch)
    prototype = SimTypeFunction(
        [pointer_type, pointer_type],
        word_type,
        arg_names=("bar1", "bar2"),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        prototype=prototype,
        is_prototype_guessed=False,
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create: (
                    function if addr == function.addr and not create else None
                )
            )
        ),
    )
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=project,
    )
    left_storage = SimStackVariable(2, 2, base="bp", name="bar1")
    right_storage = SimStackVariable(4, 2, base="bp", name="bar2")
    left = CVariable(left_storage, variable_type=pointer_type, codegen=codegen)
    right = CVariable(right_storage, variable_type=pointer_type, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=function.addr,
        arg_list=[left, right],
        functy=prototype,
        prototype=prototype,
        statements=CStatements([], codegen=codegen),
        unified_local_vars={},
        variables_in_use={left_storage: left, right_storage: right},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=left_storage,
        cvar=left,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
        display_name="bar1",
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=right_storage,
        cvar=right,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
        display_name="bar2",
    )

    selected_left = _ensure_pointer_stack_arg_expr_8616(
        project,
        codegen,
        4,
        pointee_size=2,
        fallback_name="left",
    )
    selected_right = _ensure_pointer_stack_arg_expr_8616(
        project,
        codegen,
        6,
        pointee_size=2,
        fallback_name="right",
    )

    assert selected_left is left
    assert selected_right is right
    assert selected_left.variable is not selected_right.variable
    assert codegen.cfunc.arg_list == [left, right]


def test_pointer_swap_refuses_collapsed_argument_storage_identity() -> None:
    """Refuse a swap whose two pointer expressions own the same stack slot."""
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    pointer_type = SimTypePointer(word_type).with_arch(arch)
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
    )
    shared_storage = SimStackVariable(4, 2, base="bp", name="shared")
    left = CVariable(shared_storage, variable_type=pointer_type, codegen=codegen)
    right = CVariable(shared_storage, variable_type=pointer_type, codegen=codegen)
    temporary = CVariable(
        SimStackVariable(-2, 2, base="bp", name="temporary"),
        variable_type=word_type,
        codegen=codegen,
    )
    zero = CConstant(0, word_type, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements(
            [
                CAssignment(
                    temporary,
                    CIndexedVariable(left, zero, variable_type=word_type, codegen=codegen),
                    codegen=codegen,
                ),
                CAssignment(
                    CIndexedVariable(left, zero, variable_type=word_type, codegen=codegen),
                    CIndexedVariable(right, zero, variable_type=word_type, codegen=codegen),
                    codegen=codegen,
                ),
                CAssignment(
                    CIndexedVariable(right, zero, variable_type=word_type, codegen=codegen),
                    temporary,
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        )
    )

    assert not splice_proven_pointer_swap_statements_8616(
        codegen,
        left,
        right,
        temporary,
        frozenset({0x1010, 0x1012, 0x1014, 0x1016}),
        frozenset({0x1014, 0x1016}),
    )
    stats = codegen._inertia_pointer_swap_splice_stats_8616
    assert stats.failure_count == 1
    assert stats.materialized_count == 0
    assert stats.idempotent_count == 0
