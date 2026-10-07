from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteReturnUseKind8616, CallsiteSummary8616
from inertia.pipeline.errors import PipelineHardError

from inertia.structuring.shared_tail_call_ownership import (
    SharedTailCallOwnershipStats8616,
    SharedTailCallOwnershipStatus8616,
    materialize_shared_tail_call_ownership_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _Graph:
    def __init__(self, edges: tuple[tuple[int, int], ...]) -> None:
        successors: dict[int, list[int]] = {}
        for source, target in edges:
            successors.setdefault(source, []).append(target)
            successors.setdefault(target, [])
        self._successors = successors
        self.nodes = tuple(successors)

    def successors(self, node: object) -> tuple[int, ...]:
        assert isinstance(node, int)
        return tuple(self._successors[node])


def _summary(*, return_used: bool | None = None) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1034,
        target_addr=0x2000,
        return_addr=0x1039,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register=None,
        return_used=return_used,
    )


def _project(*, shared_tail: bool) -> SimpleNamespace:
    edges = [
        (0x1000, 0x1010),
        (0x1000, 0x1020),
        (0x1010, 0x1030),
    ]
    if shared_tail:
        edges.append((0x1020, 0x1030))
    edges.append((0x1030, 0x1039))
    graph = _Graph(tuple(edges))
    function = SimpleNamespace(
        block_addrs_set=set(graph.nodes),
        transition_graph=graph,
    )
    functions = SimpleNamespace(function=lambda **_kwargs: function)
    return SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(functions=functions))


def _codegen(
    *,
    retained_after_branch: bool,
    transparent_wrapper: bool = False,
    bind_structured_tags: bool = True,
) -> tuple[_Codegen, CStatements, CExpressionStatement]:
    codegen = _Codegen()
    returned_call = CFunctionCall(
        "sink",
        None,
        [CConstant(1, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    if bind_structured_tags:
        returned_call.tags = {"ins_addr": 0x1034}
    retained_call = CFunctionCall("sink", None, [], codegen=codegen)
    if bind_structured_tags:
        retained_call.tags = {"ins_addr": 0x1034}
    returned_body = CStatements(
        [CReturn(returned_call, codegen=codegen)],
        codegen=codegen,
    )
    branch = CIfElse(
        [
            (
                CConstant(1, SimTypeShort(False), codegen=codegen),
                returned_body,
            )
        ],
        else_node=CStatements([], codegen=codegen),
        cstyle_ifs=True,
        codegen=codegen,
    )
    retained_statement = CExpressionStatement(retained_call, codegen=codegen)
    statements: list[object] = (
        [branch, retained_statement]
        if retained_after_branch
        else [retained_statement, branch]
    )
    if transparent_wrapper:
        statements = [CStatements(statements, codegen=codegen)]
    root = CStatements(statements, codegen=codegen)
    summary = _summary()
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_callsite_summaries = {
        id(returned_call): summary,
        id(retained_call): summary,
    }
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}
    return codegen, returned_body, retained_statement


def _nested_standalone_codegen(
    *,
    matching_arguments: bool = True,
    retained_after_branch: bool = True,
) -> tuple[_Codegen, CStatements, CExpressionStatement]:
    codegen = _Codegen()
    retained_call = CFunctionCall(
        "sink",
        None,
        [CConstant(1, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    clone_call = CFunctionCall(
        "sink",
        None,
        [CConstant(1 if matching_arguments else 2, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    retained_call.tags = {"ins_addr": 0x1034}
    clone_call.tags = {"ins_addr": 0x1034}
    retained_statement = CExpressionStatement(retained_call, codegen=codegen)
    clone_body = CStatements(
        [CExpressionStatement(clone_call, codegen=codegen)],
        codegen=codegen,
    )
    nested_branch = CIfElse(
        [
            (
                CConstant(1, SimTypeShort(False), codegen=codegen),
                CStatements([], codegen=codegen),
            )
        ],
        else_node=clone_body,
        cstyle_ifs=True,
        codegen=codegen,
    )
    retained_projection = CStatements(
        [CStatements([retained_statement], codegen=codegen)],
        codegen=codegen,
    )
    outer_body = CStatements(
        [nested_branch, retained_projection]
        if retained_after_branch
        else [retained_projection, nested_branch],
        codegen=codegen,
    )
    root = CStatements(
        [
            CIfElse(
                [
                    (
                        CConstant(1, SimTypeShort(False), codegen=codegen),
                        CStatements([], codegen=codegen),
                    )
                ],
                else_node=outer_body,
                cstyle_ifs=True,
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    summary = _summary(return_used=False)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_callsite_summaries = {
        id(retained_call): summary,
        id(clone_call): summary,
    }
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}
    return codegen, clone_body, retained_statement


def test_shared_tail_ownership_removes_returned_clone_after_closed_cfg_proof() -> None:
    codegen, returned_body, retained_statement = _codegen(retained_after_branch=True)

    result = materialize_shared_tail_call_ownership_8616(
        _project(shared_tail=True),
        codegen,
    )

    assert result.status is SharedTailCallOwnershipStatus8616.MATERIALIZED
    assert result.stats == SharedTailCallOwnershipStats8616(1, 1, 1, 1, 0)
    assert returned_body.statements == []
    assert retained_statement in codegen.cfunc.statements.statements
    assert tuple(codegen._inertia_callsite_summaries.values()) == (_summary(),)


def test_shared_tail_ownership_removes_trailing_condition_return_carrier() -> None:
    codegen = _Codegen()
    call = CFunctionCall("clock", None, [], codegen=codegen)
    call.tags = {"ins_addr": 0x1034}
    carrier_call = CFunctionCall("sub_2000", None, [], codegen=codegen)
    carrier_call.tags = {"ins_addr": 0x1034}
    guard = CIfBreak(
        CBinaryOp("CmpGT", call, CConstant(10, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CStatements([guard], codegen=codegen),
        codegen=codegen,
    )
    carrier = CAssignment(
        CVariable(
            SimRegisterVariable(0, 2, name="ax"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        carrier_call,
        codegen=codegen,
    )
    root = CStatements([loop, carrier], codegen=codegen)
    summary = CallsiteSummary8616(
        callsite_addr=0x1034,
        target_addr=0x2000,
        return_addr=0x1039,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.CONDITION,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_callsite_summaries = {id(call): summary, id(carrier_call): summary}
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

    result = materialize_shared_tail_call_ownership_8616(_project(shared_tail=True), codegen)

    assert result.status is SharedTailCallOwnershipStatus8616.MATERIALIZED
    assert result.stats == SharedTailCallOwnershipStats8616(1, 1, 1, 1, 0)
    assert root.statements == [loop]
    assert codegen._inertia_callsite_summaries == {id(call): summary}


def test_shared_tail_ownership_uses_owned_identity_before_tag_refresh() -> None:
    codegen, returned_body, retained_statement = _codegen(
        retained_after_branch=True,
        bind_structured_tags=False,
    )

    result = materialize_shared_tail_call_ownership_8616(
        _project(shared_tail=True),
        codegen,
    )

    assert result.status is SharedTailCallOwnershipStatus8616.MATERIALIZED
    assert result.stats == SharedTailCallOwnershipStats8616(1, 1, 1, 1, 0)
    assert returned_body.statements == []
    assert retained_statement in codegen.cfunc.statements.statements


def test_shared_tail_ownership_rejects_tag_summary_identity_drift() -> None:
    codegen, _returned_body, retained_statement = _codegen(retained_after_branch=True)
    retained_statement.expr.tags = {"ins_addr": 0x1040}

    with pytest.raises(PipelineHardError, match="tag contradicts"):
        materialize_shared_tail_call_ownership_8616(
            _project(shared_tail=True),
            codegen,
        )


def test_shared_tail_ownership_refuses_single_predecessor_call_block() -> None:
    codegen, returned_body, _retained_statement = _codegen(retained_after_branch=True)

    result = materialize_shared_tail_call_ownership_8616(
        _project(shared_tail=False),
        codegen,
    )

    assert result.status is SharedTailCallOwnershipStatus8616.UNKNOWN_REFUSE
    assert result.stats == SharedTailCallOwnershipStats8616(1, 1, 0, 0, 1)
    assert len(returned_body.statements) == 1


def test_shared_tail_ownership_crosses_transparent_statement_wrapper() -> None:
    codegen, returned_body, _retained_statement = _codegen(
        retained_after_branch=True,
        transparent_wrapper=True,
    )

    result = materialize_shared_tail_call_ownership_8616(
        _project(shared_tail=True),
        codegen,
    )

    assert result.status is SharedTailCallOwnershipStatus8616.MATERIALIZED
    assert returned_body.statements == []


def test_shared_tail_ownership_refuses_retained_call_before_branch() -> None:
    codegen, returned_body, _retained_statement = _codegen(retained_after_branch=False)

    result = materialize_shared_tail_call_ownership_8616(
        _project(shared_tail=True),
        codegen,
    )

    assert result.status is SharedTailCallOwnershipStatus8616.UNKNOWN_REFUSE
    assert result.stats == SharedTailCallOwnershipStats8616(1, 1, 0, 0, 1)
    assert len(returned_body.statements) == 1


def test_shared_tail_ownership_removes_nested_clone_before_common_tail() -> None:
    codegen, clone_body, retained_statement = _nested_standalone_codegen()

    result = materialize_shared_tail_call_ownership_8616(
        _project(shared_tail=True),
        codegen,
    )

    assert result.status is SharedTailCallOwnershipStatus8616.MATERIALIZED
    assert result.stats == SharedTailCallOwnershipStats8616(1, 1, 1, 1, 0)
    assert clone_body.statements == []
    assert id(retained_statement.expr) in codegen._inertia_callsite_summaries


def test_shared_tail_ownership_removes_bare_call_clone_before_common_tail() -> None:
    """Bare angr call statements retain the same typed occurrence ownership."""
    codegen = _Codegen()
    nested_call = CFunctionCall("sink", None, [], tags={"ins_addr": 0x1034}, codegen=codegen)
    retained_call = CFunctionCall("sink", None, [], tags={"ins_addr": 0x1034}, codegen=codegen)
    nested_body = CStatements([nested_call], codegen=codegen)
    branch = CIfElse(
        [(CConstant(1, SimTypeShort(False), codegen=codegen), nested_body)],
        else_node=CStatements([], codegen=codegen),
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch, retained_call], codegen=codegen)
    summary = _summary(return_used=False)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_callsite_summaries = {
        id(nested_call): summary,
        id(retained_call): summary,
    }
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

    result = materialize_shared_tail_call_ownership_8616(
        _project(shared_tail=True),
        codegen,
    )

    assert result.status is SharedTailCallOwnershipStatus8616.MATERIALIZED
    assert result.stats == SharedTailCallOwnershipStats8616(1, 1, 1, 1, 0)
    assert nested_body.statements == []
    assert root.statements == [branch, retained_call]
    assert codegen._inertia_callsite_summaries == {id(retained_call): summary}


def test_shared_tail_ownership_refuses_retained_call_before_nested_call() -> None:
    codegen, clone_body, _retained_statement = _nested_standalone_codegen(
        retained_after_branch=False,
    )

    result = materialize_shared_tail_call_ownership_8616(
        _project(shared_tail=True),
        codegen,
    )

    assert result.status is SharedTailCallOwnershipStatus8616.UNKNOWN_REFUSE
    assert result.stats == SharedTailCallOwnershipStats8616(1, 1, 0, 0, 1)
    assert len(clone_body.statements) == 1


def test_shared_tail_ownership_refuses_divergent_nested_call_arguments() -> None:
    codegen, clone_body, _retained_statement = _nested_standalone_codegen(
        matching_arguments=False,
    )

    result = materialize_shared_tail_call_ownership_8616(
        _project(shared_tail=True),
        codegen,
    )

    assert result.status is SharedTailCallOwnershipStatus8616.UNKNOWN_REFUSE
    assert result.stats == SharedTailCallOwnershipStats8616(1, 1, 0, 0, 1)
    assert len(clone_body.statements) == 1
