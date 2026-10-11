from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from archinfo import ArchX86

import inertia.structuring.branch_return_expressions as branch_return_expressions
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.annotations import ANNOTATION_KEY
from inertia.lowering.stack_prototype_materialization import (
    materialize_annotated_stack_prototype_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from inertia.structuring.branch_return_expressions import (
    branch_target_preserves_return_registers_8616,
    recover_branch_target_return_expression_8616,
    sole_return_expression_8616,
)


@dataclass
class _Operand:
    type: int
    reg: int = 0
    imm: int = 0
    size: int = 2
    mem: object | None = None


class _Insn:
    def __init__(self, mnemonic: str, operands: tuple[_Operand, ...]) -> None:
        self.mnemonic = mnemonic
        self.operands = operands

    def reg_name(self, reg_id: int) -> str:
        return {1: "ax", 2: "dx", 3: "bp"}.get(reg_id, "")


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _Factory:
    def __init__(self, insns: tuple[_Insn, ...]) -> None:
        self._block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))

    def block(self, _addr: int, *, opt_level: int = 0) -> object:
        del opt_level
        return self._block


def _project(*insns: _Insn) -> object:
    return SimpleNamespace(factory=_Factory(insns))


def _mapped_project(blocks: dict[int, tuple[_Insn, ...]]) -> object:
    """Build a project whose block factory resolves exact CFG addresses."""
    return SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda addr, *, opt_level=0: SimpleNamespace(
                capstone=SimpleNamespace(insns=blocks[addr])
            )
        )
    )


def test_sole_return_expression_accepts_one_wrapped_return() -> None:
    codegen = _Codegen()
    expression = CConstant(7, SimTypeShort(False), codegen=codegen)
    body = CStatements([CReturn(expression, codegen=codegen)], codegen=codegen)

    assert sole_return_expression_8616(body) is expression


@pytest.mark.parametrize("inverse", [False, True])
@pytest.mark.parametrize("case", ["valid", "missing", "same", "wrong", "prefix"])
def test_binary_return_arm_polarity_requires_both_complete_values(inverse, case):
    codegen = _Codegen()
    values = [CConstant(value, SimTypeShort(False), codegen=codegen) for value in (0, 1, 2)]
    true_value, false_value = (values[1], values[0]) if inverse else (values[0], values[1])
    true_body = CStatements([CReturn(true_value, codegen=codegen)], codegen=codegen)
    false_body = CStatements([CReturn(false_value, codegen=codegen)], codegen=codegen)
    recovered = {0x1010: values[0], 0x1020: values[1]}
    if case == "missing":
        recovered.pop(0x1020)
    elif case == "same":
        recovered[0x1020] = values[0]
    elif case == "wrong":
        recovered[0x1020] = values[2]
    elif case == "prefix":
        true_body.statements.insert(0, values[2])
    condition = ConditionIR("eq", 1, 0, taken_target=0x1010, fallthrough_target=0x1020)
    result = branch_return_expressions.binary_return_arm_polarity_8616(
        condition, true_body, false_body, recovered.get,
    )
    assert result is (not inverse if case == "valid" else None)


def _current_copy_branch():
    from inertia.alias.stack_memory_ssa import build_x86_16_stack_memory_ssa_alias_artifact
    from inertia.ir.ssa_function import build_x86_16_function_ssa
    from tests.widening.test_x86_16_segmented_load_origins import _lift_function

    codegen = _Codegen()
    source = build_x86_16_function_ssa(_lift_function(bytes.fromhex("55 8b ec 8b 56 04 8b 5e 06 5d c3")))
    alias = build_x86_16_stack_memory_ssa_alias_artifact(source)
    assert alias.complete
    codegen._inertia_vex_ir_function_ssa = source
    codegen._inertia_stack_memory_ssa_alias_artifact = alias
    leaves = [CVariable(SimStackVariable(offset, 2, base="bp"),
                        variable_type=SimTypeShort(False), codegen=codegen) for offset in (2, 4)]
    carriers = [CVariable(SimRegisterVariable(register, 2), vvar_id=varid,
                          variable_type=SimTypeShort(False), codegen=codegen)
                for register, varid in ((8, 9), (12, 10))]
    copies = [CAssignment(carrier, leaf, codegen=codegen) for carrier, leaf in zip(carriers, leaves, strict=True)]
    arms = [CStatements([CReturn(carrier, codegen=codegen)], codegen=codegen) for carrier in carriers]
    branch = CIfElse([(CConstant(1, SimTypeChar(False), codegen=codegen), arms[0])], arms[1], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=source.function_addr, statements=CStatements([*copies, branch], codegen=codegen))
    for leaf, bp_offset in zip(leaves, (4, 6), strict=True):
        record_stack_variable_coordinate_projection_8616(codegen, variable=leaf.variable, cvar=leaf,
                                                        bp_offset=bp_offset, entry_sp_offset=bp_offset-2, size=2)
    condition = ConditionIR("eq", 1, 0, taken_target=0x1010, fallthrough_target=0x1020)
    return codegen, copies, branch, carriers, leaves, arms, condition


def test_binary_return_polarity_resolves_current_dominating_stack_copies():
    _, _, _, _, leaves, arms, condition = _current_copy_branch()
    assert branch_return_expressions.binary_return_arm_polarity_8616(
        condition, *arms, {0x1010: leaves[0], 0x1020: leaves[1]}.get) is True


@pytest.mark.parametrize("corruption", ["duplicate", "different_variable", "after_branch", "type", "store", "missing_alias", "bypass", "call", "unified_store"])
def test_current_return_copy_corruption_refuses(corruption):
    codegen, copies, branch, carriers, leaves, arms, condition = _current_copy_branch()
    statements = codegen.cfunc.statements.statements
    if corruption == "duplicate":
        statements.insert(0, CAssignment(carriers[0], leaves[0], codegen=codegen))
    elif corruption == "different_variable":
        copies[0].lhs = CVariable(SimRegisterVariable(8, 2), vvar_id=9,
                                 variable_type=SimTypeShort(False), codegen=codegen)
    elif corruption == "after_branch":
        statements[:] = [branch, *copies]
    elif corruption == "type":
        copies[0].rhs.variable_type = SimTypeChar(False)
    elif corruption == "store":
        statements.insert(2, CAssignment(leaves[0], CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen))
    elif corruption == "bypass":
        statements.insert(0, CReturn(CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen))
    elif corruption == "call":
        from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
        statements.insert(2, CAssignment(carriers[1], CFunctionCall("effect", None, [], codegen=codegen), codegen=codegen))
    elif corruption == "unified_store":
        destination = CVariable(SimRegisterVariable(0, 2), unified_variable=leaves[0].variable,
                                vvar_id=30, variable_type=SimTypeShort(False), codegen=codegen)
        statements.insert(2, CAssignment(destination, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen))
    else:
        del codegen._inertia_stack_memory_ssa_alias_artifact
    assert branch_return_expressions.binary_return_arm_polarity_8616(
        condition, *arms, {0x1010: leaves[0], 0x1020: leaves[1]}.get) is None


@pytest.mark.parametrize("corruption", ["leaf_unified", "volatile"])
def test_current_return_copy_leaf_identity_and_qualifier_refuse(corruption):
    codegen, copies, _, _, leaves, arms, condition = _current_copy_branch()
    if corruption == "leaf_unified":
        copies[0].rhs = CVariable(leaves[0].variable, unified_variable=SimStackVariable(2, 2, base="bp"),
                                 variable_type=SimTypeShort(False), codegen=codegen)
    else:
        copies[0].rhs.variable_type = SimTypeShort(False, qualifier="volatile")
    assert branch_return_expressions.binary_return_arm_polarity_8616(
        condition, *arms, {0x1010: leaves[0], 0x1020: leaves[1]}.get) is None


@pytest.mark.parametrize("identity", ["variable", "unified"])
def test_current_copy_refuses_later_ssa_write_to_same_rendered_owner(identity):
    codegen, _, _, carriers, leaves, arms, condition = _current_copy_branch()
    if identity == "unified":
        owner_variable = SimRegisterVariable(8, 2)
        carriers[0].unified_variable = owner_variable
        destination = CVariable(SimRegisterVariable(8, 2), unified_variable=owner_variable,
                                vvar_id=25, variable_type=SimTypeShort(False), codegen=codegen)
    else:
        destination = CVariable(carriers[0].variable, vvar_id=25,
                                variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.statements.statements.insert(2, CAssignment(
        destination, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen))
    assert branch_return_expressions.binary_return_arm_polarity_8616(
        condition, *arms, {0x1010: leaves[0], 0x1020: leaves[1]}.get) is None


def test_branch_target_return_expression_recovers_signed_ax_immediate() -> None:
    codegen = _Codegen()
    project = _project(
        _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=0xFFFF))),
        _Insn("ret", ()),
    )

    expression = recover_branch_target_return_expression_8616(project, codegen, 0x1000)

    assert isinstance(expression, CConstant)
    assert expression.value == -1
    assert expression.type.signed is True


def test_branch_target_return_expression_refuses_value_before_conditional_branch() -> None:
    codegen = _Codegen()
    project = _project(
        _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=7))),
        _Insn("jge", (_Operand(2, imm=0x1100),)),
    )

    assert recover_branch_target_return_expression_8616(project, codegen, 0x1000) is None


def test_branch_target_preservation_follows_jump_only_path_to_epilogue() -> None:
    project = _mapped_project(
        {
            0x1000: (_Insn("jmp", (_Operand(2, imm=0x1010),)),),
            0x1010: (_Insn("leave", ()), _Insn("ret", ())),
        }
    )

    assert branch_target_preserves_return_registers_8616(project, 0x1000)


def test_branch_target_preservation_refuses_ax_write_before_epilogue() -> None:
    project = _mapped_project(
        {
            0x1000: (
                _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=7))),
                _Insn("jmp", (_Operand(2, imm=0x1010),)),
            ),
            0x1010: (_Insn("ret", ()),),
        }
    )

    assert not branch_target_preserves_return_registers_8616(project, 0x1000)


def test_branch_target_return_expression_uses_projected_machine_bp_argument() -> None:
    """Resolve BP+4 return evidence to an entry-SP+2 C argument."""
    arch = Arch86_16()
    codegen = _Codegen()
    codegen.project = SimpleNamespace(arch=arch)
    word_type = SimTypeShort(False).with_arch(arch)
    argument = CVariable(
        SimStackVariable(2, 2, base="bp", name="a", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[argument],
        variables_in_use={argument.variable: argument},
        unified_local_vars={},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=argument.variable,
        cvar=argument,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    memory = SimpleNamespace(base=3, index=0, disp=4)
    project = _project(_Insn("mov", (_Operand(1, reg=1), _Operand(3, mem=memory))), _Insn("ret", ()))

    expression = recover_branch_target_return_expression_8616(project, codegen, 0x1000)

    assert isinstance(expression, CVariable)
    assert expression.variable is argument.variable


def test_narrow_arguments_keep_word_storage_for_branch_returns() -> None:
    """Keep logical byte types distinct from physical 16-bit argument slots."""
    arch = Arch86_16()
    byte_type = SimTypeChar(False).with_arch(arch)
    word_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction(
        [byte_type, byte_type, word_type],
        word_type,
        arg_names=("a", "b", "which"),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        prototype=prototype,
        prototype_source=PrototypeSource.GUESSED,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    2: {"name": "a"},
                    4: {"name": "b"},
                    6: {"name": "which"},
                }
            }
        },
    )
    codegen = _Codegen()
    codegen.project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: function if addr == 0x1000 else None
            )
        ),
    )
    arguments = tuple(
        CVariable(
            SimStackVariable(offset, size, base="bp", name=name, region=0x1000),
            variable_type=type_,
            codegen=codegen,
        )
        for offset, size, name, type_ in (
            (2, 1, "a", byte_type),
            (4, 1, "b", byte_type),
            (6, 2, "which", word_type),
        )
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=list(arguments),
        variables_in_use={arg.variable: arg for arg in arguments},
        unified_local_vars={},
        functy=prototype,
        prototype=prototype,
        statements=CStatements([], codegen=codegen),
    )
    for argument, bp_offset in zip(arguments, (4, 6, 8), strict=True):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=argument.variable,
            cvar=argument,
            bp_offset=bp_offset,
            entry_sp_offset=argument.variable.offset,
            size=argument.variable.size,
        )

    assert materialize_annotated_stack_prototype_8616(codegen.project, codegen)
    assert [arg.variable.offset for arg in codegen.cfunc.arg_list] == [2, 4, 6]
    assert [arg.variable.size for arg in codegen.cfunc.arg_list] == [2, 2, 2]

    for expected, bp_offset in zip(arguments[:2], (4, 6), strict=True):
        memory = SimpleNamespace(base=3, index=0, disp=bp_offset)
        project = _project(_Insn("mov", (_Operand(1, reg=1), _Operand(3, mem=memory))), _Insn("ret", ()))
        expression = recover_branch_target_return_expression_8616(
            project,
            codegen,
            0x1000,
        )
        assert isinstance(expression, CVariable)
        assert expression.variable is expected.variable


def test_branch_target_return_expression_combines_adjacent_dx_ax_stack_slices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lowered_values: list[object] = []

    def _lower(value: object, _project: object, _codegen: object) -> CConstant:
        lowered_values.append(value)
        return CConstant(77, SimTypeShort(False), codegen=_codegen)

    monkeypatch.setattr(branch_return_expressions, "lower_ir_value_to_c_expr_8616", _lower)
    codegen = _Codegen()
    ax_mem = SimpleNamespace(base=3, index=0, disp=4)
    dx_mem = SimpleNamespace(base=3, index=0, disp=6)
    project = _project(
        _Insn("mov", (_Operand(1, reg=1), _Operand(3, mem=ax_mem))),
        _Insn("mov", (_Operand(1, reg=2), _Operand(3, mem=dx_mem))),
        _Insn("ret", ()),
    )

    expression = recover_branch_target_return_expression_8616(project, codegen, 0x1000)

    assert isinstance(expression, CConstant)
    assert expression.value == 77
    assert len(lowered_values) == 1
    assert lowered_values[0].offset == 4
    assert lowered_values[0].size == 4
