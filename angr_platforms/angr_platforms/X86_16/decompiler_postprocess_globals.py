"""Late global-load/store cleanup; global identity belongs earlier.

Layer: Rewrite/Postprocess cleanup.
Responsibility: consume already-proven adjacent global byte access facts for conservative rendered-C cleanup only.

This module coalesces adjacent byte-shaped global accesses into word-shaped C
globals and updates rendered variable types. That is acceptable only as a
temporary consumer of already-proven adjacent-byte evidence.

Current migration debt:
- word global load/store coalescing still recognizes byte-pair shapes in the C
  AST;
- type repair mutates rendered variables after codegen;
- unused memory declaration pruning depends on late rendered-use inspection.

The permanent home is segmented memory analysis, alias/widening, object/global
recovery, and lowering. Those layers should prove Address(space, offset, width)
and materialize the correct object before structuring/rewrite.

Do not add new global object inference, byte-pair reconstruction, or type
recovery here. If adjacency or width is not proven by structured facts, preserve
the original byte accesses and let validation/reporting show the missing proof.
"""

from __future__ import annotations

import builtins
import typing
from dataclasses import dataclass
from typing import Any

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable

from .decompiler_postprocess_loads import _global_load_addr_8616, _match_global_scaled_high_byte_8616
from .decompiler_postprocess_utils import (
    _global_memory_addr_8616,
    _is_shifted_high_byte_8616,
    _iter_c_nodes_deep_8616,
    _make_word_global_8616,
    _replace_c_children_8616,
)

__all__ = [
    "WordGlobalStoreCandidate",
    "_apply_word_global_types_8616",
    "_coalesce_word_global_constant_stores_8616",
    "_coalesce_word_global_loads_8616",
    "_prune_unused_unnamed_memory_declarations_8616",
    "describe_word_global_constant_store_candidates_8616",
]


def _dynamic_globals_getattr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read an attribute across the dynamic third-party angr/codegen global-cleanup boundary."""
    return builtins.getattr(obj, name, default)


@dataclass(frozen=True)
class WordGlobalStoreCandidate:
    """Adjacent byte stores that can be rendered as one validation-gated word store."""

    base_addr: int
    next_addr: int
    kind: str


def _word_global_constant_store_candidate_8616(
    project: object,
    stmt: object,
    next_stmt: object,
) -> WordGlobalStoreCandidate | None:
    if not isinstance(stmt, CAssignment) or not isinstance(next_stmt, CAssignment):
        return None

    base_addr = _global_memory_addr_8616(stmt.lhs)
    if base_addr is None:
        return None

    next_addr = _global_memory_addr_8616(next_stmt.lhs)
    if not isinstance(next_addr, int) or next_addr != base_addr + 1:
        return None

    if isinstance(stmt.rhs, CConstant) and isinstance(next_stmt.rhs, CConstant):
        return WordGlobalStoreCandidate(base_addr, next_addr, "constant")
    if _is_shifted_high_byte_8616(next_stmt.rhs, stmt.rhs):
        return WordGlobalStoreCandidate(base_addr, next_addr, "shifted_high_byte")
    return None


def describe_word_global_constant_store_candidates_8616(
    project: object,
    codegen: object,
) -> tuple[WordGlobalStoreCandidate, ...]:
    """Describe adjacent byte-store shapes without mutating generated code."""
    cfunc = _dynamic_globals_getattr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return ()

    candidates: list[WordGlobalStoreCandidate] = []

    def visit(node: object) -> None:
        if isinstance(node, CStatements):
            for idx in range(len(node.statements) - 1):
                candidate = _word_global_constant_store_candidate_8616(
                    project, node.statements[idx], node.statements[idx + 1]
                )
                if candidate is not None:
                    candidates.append(candidate)
            for stmt in node.statements:
                visit(stmt)
        elif hasattr(node, "condition_and_nodes"):
            for _, body in _dynamic_globals_getattr_8616(node, "condition_and_nodes", ()):
                visit(body)
            else_node = _dynamic_globals_getattr_8616(node, "else_node", None)
            if else_node is not None:
                visit(else_node)

    visit(_dynamic_globals_getattr_8616(cfunc, "statements", None))
    return tuple(candidates)


def _make_word_global_cached_8616(codegen: object, created: dict, addr: int) -> CVariable:
    """Return the cached word global CVariable for ``addr``, creating it once."""
    existing = created.get(addr)
    if existing is not None:
        return existing
    cvar = _make_word_global_8616(codegen, addr)
    created[addr] = cvar
    return cvar


def _coalesce_word_global_node_8616(node: object, codegen: object, created: dict, changed_addrs: set[int]) -> object:
    """Fold one Or/Add byte-pair global load into a word global."""
    if not isinstance(node, CBinaryOp) or node.op not in {"Or", "Add"}:
        return node
    for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_addr = _global_load_addr_8616(low_expr)
        if low_addr is None:
            continue
        high_addr = _match_global_scaled_high_byte_8616(high_expr)
        if high_addr != low_addr + 1:
            continue
        changed_addrs.add(low_addr)
        return _make_word_global_cached_8616(codegen, created, low_addr)
    return node


def _coalesce_word_global_loads_8616(project: object, codegen: object) -> set[int]:
    cfunc = _dynamic_globals_getattr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return set()

    created: dict[int, CVariable] = {}
    changed_addrs: set[int] = set()

    root = _dynamic_globals_getattr_8616(cfunc, "statements", None)
    new_root = _coalesce_word_global_node_8616(root, codegen, created, changed_addrs)
    if new_root is not root:
        # Preserve CStatements wrapper — transform() may return a plain list
        if isinstance(root, CStatements) and not isinstance(new_root, CStatements):
            new_root = CStatements(statements=new_root if isinstance(new_root, list) else [new_root], codegen=codegen)
        typing.cast(typing.Any, cfunc).statements = new_root
        root = new_root
    _replace_c_children_8616(
        root,
        lambda node: _coalesce_word_global_node_8616(node, codegen, created, changed_addrs),
    )
    return changed_addrs


def _coalesce_word_global_constant_stores_8616(project: object, codegen: object) -> set[int]:
    cfunc = _dynamic_globals_getattr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return set()

    changed_addrs: set[int] = set()

    _visit_word_global_stores_8616(
        _dynamic_globals_getattr_8616(cfunc, "statements", None),
        project,
        codegen,
        changed_addrs,
    )
    return changed_addrs


def _visit_word_global_stores_8616(node: object, project: object, codegen: object, changed_addrs: set[int]) -> None:
    """Visit one node, merging adjacent byte-constant global stores."""
    if isinstance(node, CStatements):
        new_statements = []
        i = 0
        while i < len(node.statements):
            stmt = node.statements[i]
            consumed = _word_global_store_pair_step_8616(
                node, i, stmt, project, codegen, new_statements, changed_addrs
            )
            if consumed:
                i += consumed
                continue
            _visit_word_global_stores_8616(stmt, project, codegen, changed_addrs)
            new_statements.append(stmt)
            i += 1
        if len(new_statements) != len(node.statements):
            node.statements = new_statements
    elif hasattr(node, "condition_and_nodes"):
        for _, body in _dynamic_globals_getattr_8616(node, "condition_and_nodes", ()):
            _visit_word_global_stores_8616(body, project, codegen, changed_addrs)
        else_node = _dynamic_globals_getattr_8616(node, "else_node", None)
        if else_node is not None:
            _visit_word_global_stores_8616(else_node, project, codegen, changed_addrs)


def _word_global_store_pair_step_8616(
    node: object,
    i: int,
    stmt: object,
    project: object,
    codegen: object,
    new_statements: list,
    changed_addrs: set[int],
) -> int:
    """Merge a byte-pair store into one word store; return statements consumed."""
    if not (
        i + 1 < len(node.statements)
        and isinstance(stmt, CAssignment)
        and isinstance(node.statements[i + 1], CAssignment)
    ):
        return 0
    next_stmt = node.statements[i + 1]
    candidate = _word_global_constant_store_candidate_8616(project, stmt, next_stmt)
    if candidate is None:
        return 0
    base_addr = candidate.base_addr
    if candidate.kind == "constant":
        value = (stmt.rhs.value & 0xFF) | ((next_stmt.rhs.value & 0xFF) << 8)
        new_statements.append(
            CAssignment(
                _make_word_global_8616(codegen, base_addr),
                CConstant(value, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        )
        changed_addrs.add(base_addr)
        return 2
    if candidate.kind == "shifted_high_byte":
        new_statements.append(
            CAssignment(
                _make_word_global_8616(codegen, base_addr),
                stmt.rhs,
                codegen=codegen,
            )
        )
        changed_addrs.add(base_addr)
        return 2
    return 0


def _apply_word_global_type_variables_in_use_8616(cfunc: object, addrs: set[int], target_type: object) -> bool:
    """Retype matching variables_in_use entries to ``target_type``."""
    changed = False
    for variable, cvar in _dynamic_globals_getattr_8616(cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimMemoryVariable):
            continue
        if _dynamic_globals_getattr_8616(variable, "addr", None) not in addrs:
            continue
        if _dynamic_globals_getattr_8616(variable, "size", None) != 2:
            variable.size = 2
            changed = True
        if _dynamic_globals_getattr_8616(cvar, "variable_type", None) != target_type:
            cvar.variable_type = target_type
            changed = True
        unified = _dynamic_globals_getattr_8616(cvar, "unified_variable", None)
        if unified is not None and _dynamic_globals_getattr_8616(unified, "size", None) != 2:
            try:
                unified.size = 2
                changed = True
            except Exception:
                pass
    return changed


def _apply_word_global_type_cexterns_8616(codegen: object, addrs: set[int], target_type: object) -> bool:
    """Retype matching cextern declarations to ``target_type``."""
    changed = False
    for cextern in _dynamic_globals_getattr_8616(codegen, "cexterns", ()) or ():
        variable = _dynamic_globals_getattr_8616(cextern, "variable", None)
        if not isinstance(variable, SimMemoryVariable):
            continue
        if _dynamic_globals_getattr_8616(variable, "addr", None) not in addrs:
            continue
        if _dynamic_globals_getattr_8616(variable, "size", None) != 2:
            variable.size = 2
            changed = True
        if _dynamic_globals_getattr_8616(cextern, "variable_type", None) != target_type:
            cextern.variable_type = target_type
            changed = True
    return changed


def _apply_word_global_type_unified_locals_8616(cfunc: object, addrs: set[int], target_type: object) -> bool:
    """Retype matching unified_local_vars entries to ``target_type``."""
    changed = False
    unified_locals = _dynamic_globals_getattr_8616(cfunc, "unified_local_vars", None)
    if not isinstance(unified_locals, dict):
        return False
    for variable, cvar_and_vartypes in list(unified_locals.items()):
        if not isinstance(variable, SimMemoryVariable):
            continue
        if _dynamic_globals_getattr_8616(variable, "addr", None) not in addrs:
            continue
        if _dynamic_globals_getattr_8616(variable, "size", None) != 2:
            variable.size = 2
            changed = True
        new_entries = {(cvariable, target_type) for cvariable, _vartype in cvar_and_vartypes}
        if new_entries != cvar_and_vartypes:
            unified_locals[variable] = new_entries
            changed = True
    return changed


def __apply_word_global_types_8616___impl(codegen: object, addrs: set[int]) -> bool:
    """Retype every matching global variable surface to word width."""
    cfunc = _dynamic_globals_getattr_8616(codegen, "cfunc", None)
    if not addrs or cfunc is None:
        return False

    target_type = SimTypeShort(False)
    changed = _apply_word_global_type_variables_in_use_8616(cfunc, addrs, target_type)
    changed = _apply_word_global_type_cexterns_8616(codegen, addrs, target_type) or changed
    return _apply_word_global_type_unified_locals_8616(cfunc, addrs, target_type) or changed


def _apply_word_global_types_8616(codegen: object, addrs: set[int]) -> bool:
    return __apply_word_global_types_8616___impl(codegen, addrs)


def _collect_used_variable_ids_8616(cfunc: object) -> set[int]:
    """Collect ids of variables referenced by the C statement tree."""
    used_variables: set[int] = set()
    for node in _iter_c_nodes_deep_8616(_dynamic_globals_getattr_8616(cfunc, "statements", None)):
        if not isinstance(node, CVariable):
            continue
        variable = _dynamic_globals_getattr_8616(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = _dynamic_globals_getattr_8616(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))
    return used_variables


def _drop_unused_named_variables_8616(variables_in_use: dict, used_variables: set[int]) -> bool:
    """Delete unnamed ``g_`` variables absent from ``used_variables``."""
    changed = False
    for variable in list(variables_in_use):
        if not isinstance(variable, SimMemoryVariable):
            continue
        name = _dynamic_globals_getattr_8616(variable, "name", None)
        if not isinstance(name, str) or not name.startswith("g_"):
            continue
        if id(variable) in used_variables:
            continue
        cvar = variables_in_use[variable]
        unified = _dynamic_globals_getattr_8616(cvar, "unified_variable", None)
        if unified is not None and id(unified) in used_variables:
            continue
        del variables_in_use[variable]
        changed = True
    return changed


def __prune_unused_unnamed_memory_declarations_8616___impl(codegen: object) -> bool:
    """Remove g_-prefixed memory declarations not referenced by the tree."""
    cfunc = _dynamic_globals_getattr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return False

    used_variables = _collect_used_variable_ids_8616(cfunc)
    variables_in_use = _dynamic_globals_getattr_8616(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return False
    return _drop_unused_named_variables_8616(variables_in_use, used_variables)


def _prune_unused_unnamed_memory_declarations_8616(codegen: object) -> bool:
    return __prune_unused_unnamed_memory_declarations_8616___impl(codegen)
