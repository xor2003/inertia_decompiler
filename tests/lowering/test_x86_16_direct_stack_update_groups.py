"""Regressions for binary-proven direct stack-update multiplicity."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CForLoop,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.real_mode_linear as real_mode_linear
from inertia.lowering.real_mode_linear import (
    DirectStackUpdateFact8616,
    _has_existing_stack_update_assignment_8616,
    materialize_direct_stack_incdec_instructions_8616,
)
from inertia.pipeline.structured_ast_query_index import (
    StructuredAstQueryIndex8616,
)
from capstone.x86_const import X86_INS_INC, X86_OP_MEM, X86_REG_BP, X86_REG_INVALID


class _DummyCodegen:
    def __init__(self, project: SimpleNamespace) -> None:
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _stack_increment_fixture(
    *,
    count: int,
    tagged_addr: int | None = None,
) -> tuple[SimpleNamespace, CStatements, DirectStackUpdateFact8616, CVariable, CConstant]:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    stack_var = SimStackVariable(-6, 2, base="bp", name="j", region=0x1000)
    cvar = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    one = CConstant(1, SimTypeShort(False), codegen=codegen)
    statements = []
    for index in range(count):
        tags = {"ins_addr": tagged_addr} if index == 0 and tagged_addr is not None else {}
        statements.append(
            CAssignment(
                cvar,
                CBinaryOp("Add", cvar, one, codegen=codegen),
                codegen=codegen,
                tags=tags,
            )
        )
    fact = DirectStackUpdateFact8616(offset=-6, width=2, delta=1, ins_addr=0x1030)
    return project, CStatements(statements, codegen=codegen), fact, cvar, one


def test_existing_stack_update_group_accepts_exact_binary_multiplicity() -> None:
    project, root, fact, cvar, one = _stack_increment_fixture(count=2)

    assert _has_existing_stack_update_assignment_8616(
        root,
        project,
        fact,
        cvar,
        one,
        expected_semantic_count=2,
    )


def test_existing_stack_update_group_refuses_incomplete_multiplicity() -> None:
    project, root, fact, cvar, one = _stack_increment_fixture(count=1)

    assert not _has_existing_stack_update_assignment_8616(
        root,
        project,
        fact,
        cvar,
        one,
        expected_semantic_count=2,
    )


def test_existing_stack_update_group_accepts_exact_instruction_tag() -> None:
    project, root, fact, cvar, one = _stack_increment_fixture(count=1, tagged_addr=0x1030)

    assert _has_existing_stack_update_assignment_8616(
        root,
        project,
        fact,
        cvar,
        one,
        expected_semantic_count=2,
    )


def test_existing_stack_update_indexes_rendered_owners_once(monkeypatch) -> None:
    project, root, fact, cvar, one = _stack_increment_fixture(count=20)
    original_iter = real_mode_linear._iter_structured_c_nodes_8616
    traversal_count = 0

    def _counted_iter(node):
        nonlocal traversal_count
        traversal_count += 1
        yield from original_iter(node)

    monkeypatch.setattr(real_mode_linear, "_iter_structured_c_nodes_8616", _counted_iter)

    assert _has_existing_stack_update_assignment_8616(
        root,
        project,
        fact,
        cvar,
        one,
        expected_semantic_count=20,
    )
    assert traversal_count == 1


def test_existing_stack_update_reuses_request_index(monkeypatch) -> None:
    """A shared immutable request index must eliminate repeated root walks."""
    project, root, fact, cvar, one = _stack_increment_fixture(count=20)
    query_index = StructuredAstQueryIndex8616.build(root)

    def _unexpected_walk(_node):
        raise AssertionError("existing-update query ignored its request index")

    monkeypatch.setattr(
        real_mode_linear,
        "_iter_structured_c_nodes_8616",
        _unexpected_walk,
    )

    assert _has_existing_stack_update_assignment_8616(
        root,
        project,
        fact,
        cvar,
        one,
        expected_semantic_count=20,
        query_index=query_index,
    )


def _materialize_existing_iterator_with_conflict(
    conflict_tag: int | None,
) -> tuple[CStatements, CForLoop, CAssignment, SimpleNamespace]:
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _DummyCodegen(project)
    root = CStatements([], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={},
        unified_local_vars={},
    )
    target_var = SimStackVariable(-6, 2, base="bp", name="local_6", region=0x4010)
    target = CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    conflict_var = SimStackVariable(-8, 2, base="bp", name="local_8", region=0x4010)
    conflict = CVariable(conflict_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[target_var] = target
    codegen.cfunc.variables_in_use[conflict_var] = conflict
    one = CConstant(1, SimTypeShort(False), codegen=codegen)
    iterator = CAssignment(
        target,
        CBinaryOp("Add", target, one, codegen=codegen),
        codegen=codegen,
    )
    conflicting_assignment = CAssignment(
        conflict,
        CBinaryOp("Add", conflict, one, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": conflict_tag} if conflict_tag is not None else {},
    )
    loop = CForLoop(
        CAssignment(
            target,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        CBinaryOp(
            "CmpLE",
            target,
            CConstant(5, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        iterator,
        CStatements([conflicting_assignment], codegen=codegen),
        codegen=codegen,
    )
    root.statements.append(loop)
    operand = SimpleNamespace(
        type=X86_OP_MEM,
        size=2,
        mem=SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-6),
    )
    insn = SimpleNamespace(address=0x1030, id=X86_INS_INC, operands=(operand,))
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(insn,))),),
    )

    materialize_direct_stack_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )
    return root, loop, conflicting_assignment, codegen


def test_existing_iterator_consumes_exact_tagged_conflicting_alias() -> None:
    _root, loop, conflicting_assignment, codegen = _materialize_existing_iterator_with_conflict(0x1030)

    assert conflicting_assignment not in loop.body.statements
    assert codegen._inertia_direct_stack_update_lowering_8616[
        "conflicting_tagged_assignment_removed_count"
    ] == 1


def test_existing_iterator_keeps_untagged_conflicting_alias() -> None:
    _root, loop, conflicting_assignment, codegen = _materialize_existing_iterator_with_conflict(None)

    assert conflicting_assignment in loop.body.statements
    assert codegen._inertia_direct_stack_update_lowering_8616[
        "conflicting_tagged_assignment_removed_count"
    ] == 0
