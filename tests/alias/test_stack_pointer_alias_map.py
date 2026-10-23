"""Contract tests for the shared stack-pointer alias result and cache.

The result is reusable only while the statements root is unchanged, and only
carries weight when its verdict is COMPLETE. Legacy bare tuples, stale roots,
and exhausted results are never consumed as proven aliases.
"""

from __future__ import annotations

from types import SimpleNamespace

import archinfo
import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CExpressionStatement,
    CFunctionCall,
    CGoto,
    CIfElse,
    CLabel,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable

from inertia.alias.stack_pointer_alias_map import (
    StackPointerAliasResult8616,
    StackPointerAliasStatus8616,
    compute_stack_pointer_aliases_8616,
    read_stack_pointer_alias_map_8616,
    write_stack_pointer_alias_map_8616,
)

pytestmark = pytest.mark.decompiler


class _Codegen:
    cstyle_null_cmp = True
    cstyle_ifs = True
    project = SimpleNamespace(arch=archinfo.ArchX86())

    def next_idx(self, _name):
        return 0

    def next_node_idx(self):
        return 0

    def next_ident(self, name):
        return name


def _bp_cvar(codegen, offset, name):
    var = SimStackVariable(offset, 2, base="bp", name=name)
    return var, CVariable(var, codegen=codegen)


def _result(root, status=StackPointerAliasStatus8616.COMPLETE):
    """Build a typed result for contract tests."""
    return StackPointerAliasResult8616(
        root=root,
        status=status,
        aliases={1: (object(), 0)},
        definition_index={1: 0},
        refused=frozenset(),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        decision_count=1,
    )


def test_read_returns_complete_matching_entry():
    """A typed COMPLETE result for the live root is returned."""
    codegen, root = SimpleNamespace(), object()
    codegen.cfunc = SimpleNamespace(statements=root)
    entry = _result(root)
    write_stack_pointer_alias_map_8616(codegen, entry)

    read_back = read_stack_pointer_alias_map_8616(codegen)

    assert read_back is entry
    assert read_back.complete


def test_read_refuses_legacy_tuple():
    """A legacy bare ``(root, dict)`` tuple carries no verdict: never reused."""
    codegen, root = SimpleNamespace(), object()
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_stack_pointer_aliases_for_cvars = (root, {1: (object(), 0)})

    assert read_stack_pointer_alias_map_8616(codegen) is None


def test_read_refuses_stale_root():
    """A replaced statements root invalidates the cached result by identity."""
    codegen, root = SimpleNamespace(), object()
    codegen.cfunc = SimpleNamespace(statements=root)
    write_stack_pointer_alias_map_8616(codegen, _result(root))
    codegen.cfunc.statements = object()

    assert read_stack_pointer_alias_map_8616(codegen) is None


def test_exhausted_result_is_returned_but_not_complete():
    """The contract exposes exhaustion explicitly; completeness decides use."""
    codegen, root = SimpleNamespace(), object()
    codegen.cfunc = SimpleNamespace(statements=root)
    entry = _result(root, status=StackPointerAliasStatus8616.NODE_BUDGET_EXHAUSTED)
    write_stack_pointer_alias_map_8616(codegen, entry)

    read_back = read_stack_pointer_alias_map_8616(codegen)

    assert read_back is entry
    assert not read_back.complete


def test_ordered_unique_definitions_prove_chain():
    """An ordered single-definition chain materializes terminal aliases."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    a_var, a = _bp_cvar(codegen, -2, "s_2")
    b_var, b = _bp_cvar(codegen, -4, "s_4")
    root = CStatements(
        [
            CAssignment(a, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
            CAssignment(b, a, codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases[id(a_var)] == (local_cvar, 0)
    assert result.aliases[id(b_var)] == (local_cvar, 0)
    assert result.materialized_count == 2
    assert result.failure_count == 0
    assert result.classified_fact_count == 2
    assert result.decision_count == 2


def test_use_before_definition_refuses_carrier():
    """A carrier read before its only definition is not proven."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    a_var, a = _bp_cvar(codegen, -2, "s_2")
    b_var, b = _bp_cvar(codegen, -4, "s_4")
    root = CStatements(
        [
            CAssignment(b, a, codegen=codegen),
            CAssignment(a, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    # `a` is also read (inside `b = a`) before its definition, so global
    # publication of `a` is unsafe and it refuses too.
    assert result.aliases == {}
    assert id(a_var) in result.refused
    assert id(b_var) in result.refused
    assert result.classified_fact_count == 0
    assert result.materialized_count == 0
    assert result.failure_count == 2
    assert result.decision_count == 2


def test_overwritten_carrier_refuses():
    """A variable with multiple definitions is not a proven carrier."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    _other_var, other_cvar = _bp_cvar(codegen, -22, "local_22")
    x_var, x = _bp_cvar(codegen, -2, "s_2")
    root = CStatements(
        [
            CAssignment(x, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
            CAssignment(x, CUnaryOp("Reference", other_cvar, codegen=codegen), codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert id(x_var) in result.refused
    assert result.aliases == {}
    assert result.failure_count == 1


def test_plain_pointer_copy_refuses():
    """``p = q`` copies a pointer VALUE and must never become ``p = &q``."""
    codegen = _Codegen()
    _q_var, q_cvar = _bp_cvar(codegen, -4, "local_4")
    p_var, p = _bp_cvar(codegen, -2, "s_2")
    root = CStatements(
        [CAssignment(p, q_cvar, codegen=codegen)],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases == {}
    assert id(p_var) in result.refused


def test_conditional_single_definition_refuses():
    """A sole definition inside an if-branch cannot prove a global alias."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    _cond_var, cond_cvar = _bp_cvar(codegen, -6, "cond_6")
    p_var, p = _bp_cvar(codegen, -2, "s_2")
    root = CStatements(
        [
            CIfElse(
                [
                    (
                        cond_cvar,
                        CStatements(
                            [
                                CAssignment(
                                    p,
                                    CUnaryOp("Reference", local_cvar, codegen=codegen),
                                    codegen=codegen,
                                )
                            ],
                            codegen=codegen,
                        ),
                    )
                ],
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases == {}
    assert id(p_var) in result.refused


def test_nested_statements_keep_program_order():
    """Nested statement blocks preserve unconditional ordered definitions."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    a_var, a = _bp_cvar(codegen, -2, "s_2")
    b_var, b = _bp_cvar(codegen, -4, "s_4")
    root = CStatements(
        [
            CStatements(
                [CAssignment(a, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen)],
                codegen=codegen,
            ),
            CAssignment(b, a, codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases[id(a_var)] == (local_cvar, 0)
    assert result.aliases[id(b_var)] == (local_cvar, 0)


def test_read_before_later_definition_refuses_publication():
    """Any read ordered before the unique definition refuses globally."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    _y_var, y = _bp_cvar(codegen, -24, "local_24")
    x_var, x = _bp_cvar(codegen, -2, "s_2")
    root = CStatements(
        [
            CExpressionStatement(
                CBinaryOp("Add", x, y, codegen=codegen), codegen=codegen
            ),
            CAssignment(x, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases == {}
    assert id(x_var) in result.refused


def test_escaped_address_refuses_carrier():
    """``&carrier`` passed to a call can mutate the carrier; refuse it."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    x_var, x = _bp_cvar(codegen, -2, "s_2")
    call = CFunctionCall(
        "callee",
        None,
        [CUnaryOp("Reference", x, codegen=codegen)],
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(x, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases == {}
    assert id(x_var) in result.refused


def test_increment_mutation_refuses_carrier():
    """A non-assignment write (``x++``) invalidates the carrier proof."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    x_var, x = _bp_cvar(codegen, -2, "s_2")
    root = CStatements(
        [
            CAssignment(x, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
            CExpressionStatement(
                CUnaryOp("PreIncrement", x, codegen=codegen), codegen=codegen
            ),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases == {}
    assert id(x_var) in result.refused


def test_mixed_outcomes_close_counters():
    """Proven and refused carriers both materialize as typed decisions."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    _q_var, q_cvar = _bp_cvar(codegen, -22, "local_22")
    a_var, a = _bp_cvar(codegen, -2, "s_2")
    p_var, p = _bp_cvar(codegen, -4, "s_4")
    root = CStatements(
        [
            CAssignment(a, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
            CAssignment(p, q_cvar, codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases == {id(a_var): (local_cvar, 0)}
    assert result.refused == frozenset({id(p_var)})
    assert result.classified_fact_count == 1
    assert result.materialized_count == 1
    assert result.failure_count == 1
    assert result.decision_count == 2


def test_transitive_escape_refuses_pointed_at_carrier():
    """``temp = &p; f(temp)`` hands &p to the call, so p must refuse."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    p_var, p = _bp_cvar(codegen, -2, "s_2")
    _t_var, t = _bp_cvar(codegen, -4, "s_4")
    call = CFunctionCall("callee", None, [t], codegen=codegen)
    root = CStatements(
        [
            CAssignment(p, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
            CAssignment(t, CUnaryOp("Reference", p, codegen=codegen), codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert id(p_var) in result.refused


def test_narrowing_cast_refuses_carrier():
    """``(byte)&local`` truncates the pointer; it cannot prove an alias."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    x_var, x = _bp_cvar(codegen, -2, "s_2")
    narrowed = CTypeCast(
        SimTypeLong(),
        SimTypeChar(),
        CUnaryOp("Reference", local_cvar, codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([CAssignment(x, narrowed, codegen=codegen)], codegen=codegen)

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases == {}
    assert id(x_var) in result.refused
    assert result.classified_fact_count == 0


def test_goto_before_definition_refuses():
    """A jumpable control node before a definition breaks domination."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    x_var, x = _bp_cvar(codegen, -2, "s_2")
    root = CStatements(
        [
            CLabel("L1", codegen=codegen),
            CGoto(None, None, codegen=codegen),
            CAssignment(x, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases == {}
    assert id(x_var) in result.refused


def test_computed_budget_exhaustion_refuses():
    """A real deep-expression scan exhausts the shared node budget."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    _p_var, p = _bp_cvar(codegen, -2, "s_2")
    _q_var, q = _bp_cvar(codegen, -4, "s_4")
    p.variable_type = SimTypeShort(False).with_arch(codegen.project.arch)
    expr = p
    for _ in range(100):
        expr = CUnaryOp("Not", expr, codegen=codegen)
    root = CStatements(
        [
            CAssignment(p, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
            CAssignment(q, expr, codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root, max_nodes=4)

    assert not result.complete
    assert result.status is StackPointerAliasStatus8616.NODE_BUDGET_EXHAUSTED
    assert result.visited_nodes > 0


def test_escape_invalidates_dependent_proof():
    """``t=&p; f(t); q=p`` escapes p, and q's copy of p must refuse too."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    p_var, p = _bp_cvar(codegen, -2, "s_2")
    t_var, t = _bp_cvar(codegen, -4, "s_4")
    q_var, q = _bp_cvar(codegen, -6, "s_6")
    call = CFunctionCall("callee", None, [t], codegen=codegen)
    root = CStatements(
        [
            CAssignment(p, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
            CAssignment(t, CUnaryOp("Reference", p, codegen=codegen), codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
            CAssignment(q, p, codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    # f(t) hands &p to the call: p's slot may be written, so p and the
    # dependent copy q=p refuse. t itself stays proven: its value &p is
    # unaffected by writes through the escaped pointer.
    assert id(p_var) in result.refused
    assert id(q_var) in result.refused
    assert id(t_var) in result.aliases


def test_overlapping_slot_write_refuses_carrier():
    """A distinct bp view overlapping the carrier's slot invalidates it."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    _y_var, y = _bp_cvar(codegen, -24, "local_24")
    p_var, p = _bp_cvar(codegen, -2, "s_2")
    # byte view at bp-3 size2 covers [-3,-1): overlaps p's [-2,0) slot.
    _w_var, w = _bp_cvar(codegen, -3, "w_3")
    root = CStatements(
        [
            CAssignment(p, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
            CAssignment(w, y, codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert id(p_var) in result.refused


def test_disjoint_slot_write_preserves_carrier():
    """A write to a provably non-overlapping bp slot does not invalidate."""
    codegen = _Codegen()
    _local_var, local_cvar = _bp_cvar(codegen, -20, "local_20")
    _y_var, y = _bp_cvar(codegen, -24, "local_24")
    p_var, p = _bp_cvar(codegen, -2, "s_2")
    # distinct slot at bp-6 size2 covers [-6,-4): disjoint from p's [-2,0).
    _w_var, w = _bp_cvar(codegen, -6, "w_6")
    root = CStatements(
        [
            CAssignment(p, CUnaryOp("Reference", local_cvar, codegen=codegen), codegen=codegen),
            CAssignment(w, y, codegen=codegen),
        ],
        codegen=codegen,
    )

    result = compute_stack_pointer_aliases_8616(codegen, root)

    assert result.complete
    assert result.aliases[id(p_var)] == (local_cvar, 0)


def test_complete_result_rejects_contradictory_census():
    """A COMPLETE result whose counts disagree with its payload is rejected."""
    codegen = _Codegen()
    root = CStatements([], codegen=codegen)
    with pytest.raises(ValueError):
        StackPointerAliasResult8616(
            root=root,
            status=StackPointerAliasStatus8616.COMPLETE,
            aliases={1: (object(), 0)},
            definition_index={1: 0},
            refused=frozenset(),
            # classified/materialized 0 contradicts one published alias
        )
    with pytest.raises(ValueError):
        StackPointerAliasResult8616(
            root=root,
            status=StackPointerAliasStatus8616.COMPLETE,
            aliases={1: (object(), 0)},
            definition_index={1: 0},
            refused=frozenset({2}),
            raw_fact_count=2,
            normalized_fact_count=2,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=1,
            # decision_count must equal classified + failure
            decision_count=0,
        )
