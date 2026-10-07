from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.pipeline.structured_assignment_index import (
    StructuredAssignmentIdentityIndex8616,
    StructuredAssignmentIdentityKey8616,
    StructuredAssignmentIdentityKind8616,
    StructuredAssignmentLookupVerdict8616,
)
from inertia.pipeline.structured_ast_query_index import (
    StructuredAstQueryIndex8616,
)

import inertia.cli.cli_stack_byte_offsets as stack_rewrite


@dataclass(frozen=True)
class _AliasState:
    base: object
    offset: int = 0


def _codegen():
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    return SimpleNamespace(
        cfunc=cfunc,
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 0,
        cstyle_null_cmp=False,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 0,
    )


def _assignment(codegen, name: str, value: int):
    variable = SimRegisterVariable(value * 2, 2, name=name)
    lhs = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    rhs = structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)
    return structured_c.CAssignment(lhs, rhs, codegen=codegen)


def _name_key(name: str) -> StructuredAssignmentIdentityKey8616:
    return StructuredAssignmentIdentityKey8616(
        StructuredAssignmentIdentityKind8616.CVARIABLE_NAME,
        name,
    )


def _keys_for_lhs(lhs: object):
    if not isinstance(lhs, structured_c.CVariable):
        return ()
    return (_name_key(lhs.variable.name),)


def test_structured_assignment_index_returns_closed_typed_verdicts():
    codegen = _codegen()
    first = _assignment(codegen, "first", 1)
    duplicate_a = _assignment(codegen, "duplicate", 2)
    duplicate_b = _assignment(codegen, "duplicate", 3)
    root = structured_c.CStatements([first, duplicate_a, duplicate_b], addr=0x10010, codegen=codegen)

    index = StructuredAssignmentIdentityIndex8616.build(
        StructuredAstQueryIndex8616.build(root),
        _keys_for_lhs,
    )

    unique = index.lookup((_name_key("first"), _name_key("first")))
    missing = index.lookup((_name_key("missing"),))
    ambiguous = index.lookup((_name_key("duplicate"),))

    assert unique.verdict is StructuredAssignmentLookupVerdict8616.UNIQUE
    assert unique.rhs is first.rhs
    assert missing.verdict is StructuredAssignmentLookupVerdict8616.MISSING
    assert ambiguous.verdict is StructuredAssignmentLookupVerdict8616.AMBIGUOUS
    assert ambiguous.rhs is None
    stats = index.stats()
    assert (stats.build_count, stats.query_count) == (1, 3)
    assert (stats.unique_count, stats.missing_count, stats.ambiguous_count) == (1, 1, 1)


def test_structured_assignment_index_rejects_cross_root_reuse_and_bad_keys():
    codegen = _codegen()
    root = structured_c.CStatements([_assignment(codegen, "first", 1)], addr=0x10010, codegen=codegen)
    index = StructuredAssignmentIdentityIndex8616.build(
        StructuredAstQueryIndex8616.build(root),
        _keys_for_lhs,
    )

    with pytest.raises(ValueError, match="different AST root"):
        index.require_root(object())
    with pytest.raises(ValueError, match="requires integer offset and width"):
        StructuredAssignmentIdentityKey8616(
            StructuredAssignmentIdentityKind8616.REGISTER,
            "ax",
        )


def test_cli_stack_alias_lookup_builds_one_projection_for_many_assignments():
    codegen = _codegen()
    stack_variable = SimStackVariable(-2, 2, base="bp", name="s_2", region=0x10010)
    stack_cvar = structured_c.CVariable(
        stack_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignments = []
    previous = stack_cvar
    for index in range(64):
        variable = SimRegisterVariable(index * 2, 2, name=f"vvar_{index}")
        current = structured_c.CVariable(
            variable,
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        assignments.append(structured_c.CAssignment(current, previous, codegen=codegen))
        previous = current
    codegen.cfunc.statements = structured_c.CStatements(assignments, addr=0x10010, codegen=codegen)

    def forbidden_legacy_scan(_node: object):
        raise AssertionError("CLI assignment lookup performed a legacy AST scan")

    changed = stack_rewrite._rewrite_ss_stack_byte_offsets(
        codegen.project,
        codegen,
        unwrap_c_casts=lambda node: node,
        iter_c_nodes_deep=forbidden_legacy_scan,
        replace_c_children=lambda _root, _transform: False,
        c_constant_value=lambda _node: None,
        flatten_c_add_terms=lambda node: (node,),
        classify_segmented_dereference=lambda _node, _project: None,
        strip_segment_scale_from_addr_expr=lambda node, _project: node,
        resolve_stack_cvar_at_offset=lambda _codegen, _offset: None,
        promote_direct_stack_cvariable=lambda *_args: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args: None,
        stack_slot_identity_for_variable=lambda variable: SimpleNamespace(
            base=variable.base,
            offset=variable.offset,
        )
        if isinstance(variable, SimStackVariable)
        else None,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is False
    assert codegen._inertia_ss_stack_assignment_index_builds_8616 == 1
    stats = codegen._inertia_ss_stack_assignment_index_stats_8616
    assert stats.build_count == 1
    assert stats.query_count >= 60
