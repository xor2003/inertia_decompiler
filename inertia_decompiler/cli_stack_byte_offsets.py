"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from types import SimpleNamespace
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.segment_register_state import (
    runtime_segment_name_for_variable_8616,
)
from angr_platforms.X86_16.pipeline.structured_assignment_index import (
    StructuredAssignmentIdentityIndex8616,
    StructuredAssignmentIdentityKey8616,
    StructuredAssignmentIdentityKind8616,
    StructuredAssignmentLookupVerdict8616,
)
from angr_platforms.X86_16.pipeline.structured_ast_query_index import (
    StructuredAstQueryIndex8616,
)

_LINEAR_TEMP_NAME_RE_8616 = re.compile(r"(?:v\d+|vvar_\d+|ir_\d+|tmp_\d+)")


def _dynamic_codegen_attr(obj: object, name: str, default: Any = None) -> Any:  # noqa: ANN401
    """Read a dynamic angr structured-codegen attribute at the CLI boundary."""
    # Dynamic codegen boundary: angr C-AST nodes expose version-dependent fields.
    return getattr(obj, name, default)


def _dynamic_codegen_setattr(obj: object, name: str, value: object) -> None:
    """Write a dynamic angr structured-codegen attribute at the CLI boundary."""
    # Dynamic codegen boundary: angr C-AST nodes expose version-dependent fields.
    setattr(obj, name, value)


def _strip_typed_suffix_8616(name: object) -> str | None:
    if not isinstance(name, str):
        return None
    if name.endswith("}"):
        brace_pos = name.find("{")
        if brace_pos > 0:
            return name[:brace_pos]
    return name


def _is_linear_temp_name_8616(name: object) -> bool:
    base = _strip_typed_suffix_8616(name)
    return isinstance(base, str) and _LINEAR_TEMP_NAME_RE_8616.fullmatch(base) is not None


class _SsStackByteOffsetRewrite8616:
    """State carrier for the SS stack byte-offset rewrite pass.

    Layer: rewrite/cleanup orchestration.
    Responsibility: resolve SS-local pointer-carrier chains into stack derefs.
    """

    __slots__ = ('_UNRESOLVED_SINGLE_ASSIGN', 'assignment_identity_index', 'binary_name', 'binary_path', 'c_constant_value', 'changed', 'classify_segmented_dereference', 'codegen', 'cvar_single_assignment_cache', 'dirty_expr_single_assignment_cache', 'flatten_c_add_terms', 'func_name', 'iter_c_nodes_deep', 'materialize_stack_cvar_at_offset', 'new_root', 'project', 'promote_direct_stack_cvariable', 'replace_c_children', 'resolve_stack_cvar_at_offset', 'root', 'stack_pointer_alias_state', 'stack_pointer_aliases', 'stack_slot_identity_for_variable', 'stack_type_for_size', 'strip_segment_scale_from_addr_expr', 'structured_query_index', 'synthetic_sp_anchor', 'unwrap_c_casts')

    def __init__(
        self,
        project: Any,  # noqa: ANN401
        codegen: Any,  # noqa: ANN401
        unwrap_c_casts: Callable[[object], object],
        iter_c_nodes_deep: Callable[[object], Iterable[object]],
        replace_c_children: Callable[[object, Callable[[object], object]], bool],
        c_constant_value: Callable[[object], int | None],
        flatten_c_add_terms: Callable[[object], Iterable[object]],
        classify_segmented_dereference: Callable[[object, object], Any],
        strip_segment_scale_from_addr_expr: Callable[[object, object], Any],
        resolve_stack_cvar_at_offset: Callable[[object, int], Any],
        promote_direct_stack_cvariable: Callable[[object, object, int, object], Any],
        stack_type_for_size: Callable[[int], object],
        materialize_stack_cvar_at_offset: Callable[[object, int, int], Any],
        stack_slot_identity_for_variable: Callable[[object], Any],
        stack_pointer_alias_state: Callable[[object, int], Any],
    ) -> None:
        self.project: Any = project
        self.codegen: Any = codegen
        self.unwrap_c_casts: Any = unwrap_c_casts
        self.iter_c_nodes_deep: Any = iter_c_nodes_deep
        self.replace_c_children: Any = replace_c_children
        self.c_constant_value: Any = c_constant_value
        self.flatten_c_add_terms: Any = flatten_c_add_terms
        self.classify_segmented_dereference: Any = classify_segmented_dereference
        self.strip_segment_scale_from_addr_expr: Any = strip_segment_scale_from_addr_expr
        self.resolve_stack_cvar_at_offset: Any = resolve_stack_cvar_at_offset
        self.promote_direct_stack_cvariable: Any = promote_direct_stack_cvariable
        self.stack_type_for_size: Any = stack_type_for_size
        self.materialize_stack_cvar_at_offset: Any = materialize_stack_cvar_at_offset
        self.stack_slot_identity_for_variable: Any = stack_slot_identity_for_variable
        self.stack_pointer_alias_state: Any = stack_pointer_alias_state
        self._UNRESOLVED_SINGLE_ASSIGN: object = object()
        self.assignment_identity_index: StructuredAssignmentIdentityIndex8616 | None = None
        self.binary_name: Any = None
        self.binary_path: Any = None
        self.changed: bool = False
        self.cvar_single_assignment_cache: dict[int, object | None] = {}
        self.dirty_expr_single_assignment_cache: dict[str, object | None] = {}
        self.func_name: Any = None
        self.new_root: Any = None
        self.root: Any = None
        self.stack_pointer_aliases: dict[object, Any] = {}
        self.structured_query_index: StructuredAstQueryIndex8616 | None = None
        self.synthetic_sp_anchor: Any | None = None

    def run_8616(self) -> object:
        """Run each phase; the first done phase supplies the result."""
        done, result = self.run_8616_part0()
        if done:
            return result
        done, result = self.run_8616_part1()
        if done:
            return result
        return None

    def run_8616_part0(self) -> tuple[bool, object]:
        """Collect alias state and refuse early when no codegen function exists."""
        if _dynamic_codegen_attr(self.codegen, "cfunc", None) is None:
            return True, False

        # Ownership boundary:
        # This pass is the generic AST-level place to resolve SS-local pointer-carrier
        # chains (for example vvar_/ir_/tmp_ aliases that ultimately point at BP stack
        # slots). If final emitted C still contains raw stack carrier math, fix it here
        # or earlier in stack lowering, not in the final text cleanup layer.

        self.binary_path = _dynamic_codegen_attr(_dynamic_codegen_attr(self.codegen.cfunc, "project", None), "loader", None)
        self.binary_name = _dynamic_codegen_attr(_dynamic_codegen_attr(self.binary_path, "main_object", None), "binary_basename", "")
        if isinstance(self.binary_name, str) and self.binary_name.lower().endswith(".cod"):
            self.func_name = _dynamic_codegen_attr(_dynamic_codegen_attr(self.codegen.cfunc, "function", None), "name", "")
            if self.func_name == "fold_values":
                return True, False

        self.changed = False
        self.stack_pointer_aliases = {}
        self.synthetic_sp_anchor = None
        self._UNRESOLVED_SINGLE_ASSIGN = object()
        self.dirty_expr_single_assignment_cache = {}
        self.cvar_single_assignment_cache = {}
        self.structured_query_index = None
        self.assignment_identity_index = None
        return False, None

    def _safe_dirty_attr_8616(self, obj: object, attr: str) -> object | None:
        try:
            return cast(object, _dynamic_codegen_attr(obj, attr, None))
        except (AttributeError, TypeError, ValueError):
            return None

    def _synthetic_sp_anchor_cvar(self) -> object:
        if self.synthetic_sp_anchor is not None:
            return self.synthetic_sp_anchor
        region = _dynamic_codegen_attr(self.codegen.cfunc, "addr", None)
        variable = SimStackVariable(0, 2, base="sp", name="sp_0", region=region)
        self.synthetic_sp_anchor = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=self.codegen)
        variables_in_use = _dynamic_codegen_attr(self.codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use.setdefault(variable, self.synthetic_sp_anchor)
        unified_local_vars = _dynamic_codegen_attr(self.codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_local_vars, dict):
            unified_local_vars.setdefault(
                variable, {(self.synthetic_sp_anchor, _dynamic_codegen_attr(self.synthetic_sp_anchor, "variable_type", None))}
            )
        return self.synthetic_sp_anchor

    def _is_sp_virtual_register(self, variable: object) -> bool:
        sp_offset = _dynamic_codegen_attr(_dynamic_codegen_attr(self.project, "arch", None), "registers", {}).get("sp", (None, None))[0]
        return isinstance(sp_offset, int) and _dynamic_codegen_attr(variable, "reg", None) == sp_offset

    def _is_ss_virtual_register(self, variable: object) -> bool:
        ss_offset = _dynamic_codegen_attr(_dynamic_codegen_attr(self.project, "arch", None), "registers", {}).get("ss", (None, None))[0]
        return isinstance(ss_offset, int) and _dynamic_codegen_attr(variable, "reg", None) == ss_offset

    def _dirty_reg_offset_8616(self, node: object) -> int | None:
        dirty = _dynamic_codegen_attr(node, "dirty", None)
        if dirty is None:
            return None
        for attr in ("reg_offset", "reg"):
            reg = self._safe_dirty_attr_8616(dirty, attr)
            if isinstance(reg, int):
                return int(reg)
        return None

    def _dirty_is_ss_virtual_register_8616(self, node: object) -> bool:
        return self._is_ss_virtual_register(SimpleNamespace(reg=self._dirty_reg_offset_8616(node)))

    def _is_linear_temp(self, cvar: object) -> bool:
        if not isinstance(cvar, structured_c.CVariable):
            return False
        variable = _dynamic_codegen_attr(cvar, "variable", None)
        if isinstance(variable, SimStackVariable):
            return False
        name = _dynamic_codegen_attr(cvar, "name", None)
        if name is None:
            return True
        return _is_linear_temp_name_8616(name)

    def _alias_keys_for_cvar(self, cvar: object) -> tuple[object, ...]:
        keys: list[object] = []
        variable = _dynamic_codegen_attr(cvar, "variable", None)
        linear_temp = self._is_linear_temp(cvar)
        if variable is not None:
            keys.append(("var", id(variable)))
            reg = _dynamic_codegen_attr(variable, "reg", None)
            size = _dynamic_codegen_attr(variable, "size", None)
            if not linear_temp and isinstance(reg, int) and isinstance(size, int):
                keys.append(("reg", reg, size))
        name = _dynamic_codegen_attr(cvar, "name", None) or _dynamic_codegen_attr(variable, "name", None)
        if isinstance(name, str) and name:
            normalized_name = _strip_typed_suffix_8616(name)
            if isinstance(normalized_name, str) and normalized_name:
                keys.append(("name", normalized_name))
        return tuple(keys)

    def _alias_lookup_keys_for_cvar(self, cvar: object) -> tuple[object, ...]:
        variable = _dynamic_codegen_attr(cvar, "variable", None)
        keys: list[object] = []
        linear_temp = self._is_linear_temp(cvar)
        if variable is not None:
            keys.append(("var", id(variable)))
            reg = _dynamic_codegen_attr(variable, "reg", None)
            size = _dynamic_codegen_attr(variable, "size", None)
            if not linear_temp and isinstance(reg, int) and isinstance(size, int):
                keys.append(("reg", reg, size))
        for candidate in (
            _dynamic_codegen_attr(cvar, "name", None),
            _dynamic_codegen_attr(variable, "name", None),
        ):
            if isinstance(candidate, str) and candidate:
                normalized_name = _strip_typed_suffix_8616(candidate)
                if isinstance(normalized_name, str) and normalized_name:
                    keys.append(("name", normalized_name))
        return tuple(dict.fromkeys(keys))

    def _assignment_keys_for_cvar(self, 
        cvar: structured_c.CVariable,
        *,
        include_virtual_name: bool,
    ) -> tuple[StructuredAssignmentIdentityKey8616, ...]:
        keys: list[StructuredAssignmentIdentityKey8616] = []
        variable = _dynamic_codegen_attr(cvar, "variable", None)
        if variable is not None:
            keys.append(
                StructuredAssignmentIdentityKey8616(
                    StructuredAssignmentIdentityKind8616.VARIABLE_OBJECT,
                    id(variable),
                )
            )
            reg = _dynamic_codegen_attr(variable, "reg", None)
            size = _dynamic_codegen_attr(variable, "size", None)
            if not self._is_linear_temp(cvar) and isinstance(reg, int) and isinstance(size, int):
                keys.append(
                    StructuredAssignmentIdentityKey8616(
                        StructuredAssignmentIdentityKind8616.REGISTER,
                        reg,
                        size,
                    )
                )
        name = _dynamic_codegen_attr(cvar, "name", None) or _dynamic_codegen_attr(variable, "name", None)
        normalized_name = _strip_typed_suffix_8616(name)
        if isinstance(normalized_name, str) and normalized_name:
            keys.append(
                StructuredAssignmentIdentityKey8616(
                    StructuredAssignmentIdentityKind8616.CVARIABLE_NAME,
                    normalized_name,
                )
            )
            if include_virtual_name:
                keys.append(
                    StructuredAssignmentIdentityKey8616(
                        StructuredAssignmentIdentityKind8616.VIRTUAL_NAME,
                        normalized_name,
                    )
                )
        return tuple(dict.fromkeys(keys))

    def _assignment_identity_keys_for_lhs(self, 
        lhs: object,
    ) -> tuple[StructuredAssignmentIdentityKey8616, ...]:
        keys = list(self._assignment_keys_for_cvar(lhs, include_virtual_name=True)) if isinstance(
            lhs, structured_c.CVariable
        ) else []
        lhs_varid = self._safe_dirty_attr_8616(_dynamic_codegen_attr(lhs, "dirty", None), "varid")
        if isinstance(lhs_varid, int):
            keys.append(
                StructuredAssignmentIdentityKey8616(
                    StructuredAssignmentIdentityKind8616.VIRTUAL_NAME,
                    f"vvar_{lhs_varid}",
                )
            )
        return tuple(dict.fromkeys(keys))

    def _assignment_index(self) -> StructuredAssignmentIdentityIndex8616 | None:
        if self.assignment_identity_index is not None:
            return self.assignment_identity_index
        root = _dynamic_codegen_attr(_dynamic_codegen_attr(self.codegen, "cfunc", None), "statements", None)
        if root is None:
            return None
        self.structured_query_index = StructuredAstQueryIndex8616.build(root)
        self.assignment_identity_index = StructuredAssignmentIdentityIndex8616.build(
            self.structured_query_index,
            self._assignment_identity_keys_for_lhs,
        )
        _dynamic_codegen_setattr(
            self.codegen,
            "_inertia_ss_stack_assignment_index_builds_8616",
            int(_dynamic_codegen_attr(self.codegen, "_inertia_ss_stack_assignment_index_builds_8616", 0) or 0) + 1,
        )
        return self.assignment_identity_index

    def _single_assignment_expr_for_virtual_name(self, name: str) -> object | None:
        normalized_name = _strip_typed_suffix_8616(name)
        if not normalized_name:
            return None
        cached = self.dirty_expr_single_assignment_cache.get(normalized_name)
        if cached is not None:
            return None if cached is self._UNRESOLVED_SINGLE_ASSIGN else cached
        target_varid = None
        if normalized_name.startswith("vvar_"):
            suffix = normalized_name.removeprefix("vvar_")
            if suffix.isdigit():
                target_varid = int(suffix)
        if not isinstance(target_varid, int):
            self.dirty_expr_single_assignment_cache[normalized_name] = self._UNRESOLVED_SINGLE_ASSIGN
            return None

        index = self._assignment_index()
        if index is None:
            self.dirty_expr_single_assignment_cache[normalized_name] = self._UNRESOLVED_SINGLE_ASSIGN
            return None
        result = index.lookup(
            (
                StructuredAssignmentIdentityKey8616(
                    StructuredAssignmentIdentityKind8616.VIRTUAL_NAME,
                    normalized_name,
                ),
            )
        )
        resolved = result.rhs if result.verdict is StructuredAssignmentLookupVerdict8616.UNIQUE else None
        self.dirty_expr_single_assignment_cache[normalized_name] = (
            resolved if resolved is not None else self._UNRESOLVED_SINGLE_ASSIGN
        )
        if resolved is not None:
            self.codegen._inertia_ss_stack_virtual_assignment_index_hits = (
                int(_dynamic_codegen_attr(self.codegen, "_inertia_ss_stack_virtual_assignment_index_hits", 0) or 0) + 1
            )
        return resolved

    def _single_assignment_expr_for_cvar(self, node_cvar: object) -> object | None:
        cache_key = id(node_cvar)
        if cache_key in self.cvar_single_assignment_cache:
            return self.cvar_single_assignment_cache[cache_key]

        if not isinstance(node_cvar, structured_c.CVariable):
            self.cvar_single_assignment_cache[cache_key] = None
            return None
        index = self._assignment_index()
        if index is None:
            self.cvar_single_assignment_cache[cache_key] = None
            return None
        result = index.lookup(self._assignment_keys_for_cvar(node_cvar, include_virtual_name=False))
        resolved = result.rhs if result.verdict is StructuredAssignmentLookupVerdict8616.UNIQUE else None
        self.cvar_single_assignment_cache[cache_key] = resolved
        return resolved

    def _top_level_statements(self) -> list[object]:
        root = _dynamic_codegen_attr(_dynamic_codegen_attr(self.codegen, "cfunc", None), "statements", None)
        statements = _dynamic_codegen_attr(root, "statements", None)
        if isinstance(statements, (list, tuple)):
            return list(statements)
        return []

    def _statement_index_containing(self, node: object) -> int | None:
        if node is None:
            return None
        for idx, stmt in enumerate(self._top_level_statements()):
            for nested in self.iter_c_nodes_deep(stmt):
                if nested is node:
                    return idx
        return None

    def _nearest_preceding_assignment_expr_for_cvar(self, node_cvar: object) -> object | None:
        if not isinstance(node_cvar, structured_c.CVariable):
            return None
        node_var = _dynamic_codegen_attr(node_cvar, "variable", None)
        node_reg = _dynamic_codegen_attr(node_var, "reg", None)
        node_size = _dynamic_codegen_attr(node_var, "size", None)
        if not (isinstance(node_reg, int) and isinstance(node_size, int)):
            return None
        stmt_idx = self._statement_index_containing(node_cvar)
        if stmt_idx is None:
            return None

        nearest_rhs = None
        for idx, stmt in enumerate(self._top_level_statements()):
            if idx >= stmt_idx or not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = _dynamic_codegen_attr(stmt, "lhs", None)
            if not isinstance(lhs, structured_c.CVariable):
                continue
            lhs_var = _dynamic_codegen_attr(lhs, "variable", None)
            lhs_reg = _dynamic_codegen_attr(lhs_var, "reg", None)
            lhs_size = _dynamic_codegen_attr(lhs_var, "size", None)
            if lhs_reg == node_reg and lhs_size == node_size:
                nearest_rhs = _dynamic_codegen_attr(stmt, "rhs", None)
        return nearest_rhs

    def _resolve_dirty_virtual_expr(self, 
        node: object,
        *,
        seen_varids: set[int] | None = None,
    ) -> object | None:
        dirty = _dynamic_codegen_attr(node, "dirty", None)
        if dirty is None:
            return None
        varid = self._safe_dirty_attr_8616(dirty, "varid")
        if not isinstance(varid, int):
            reg = self._safe_dirty_attr_8616(dirty, "reg")
            bits = self._safe_dirty_attr_8616(dirty, "bits")
            if self._is_sp_virtual_register(SimpleNamespace(reg=reg, size=(bits // 8) if isinstance(bits, int) else None)):
                return self._synthetic_sp_anchor_cvar()
            return None
        if seen_varids is None:
            seen_varids = set()
        if varid in seen_varids:
            return None
        seen_varids.add(varid)
        resolved = self._single_assignment_expr_for_virtual_name(f"vvar_{varid}")
        if resolved is not None:
            return resolved
        reg = self._safe_dirty_attr_8616(dirty, "reg")
        bits = self._safe_dirty_attr_8616(dirty, "bits")
        if self._is_sp_virtual_register(SimpleNamespace(reg=reg, size=(bits // 8) if isinstance(bits, int) else None)):
            return self._synthetic_sp_anchor_cvar()
        return None

    def _dirty_alias_key(self, node: object) -> tuple[str, int] | None:
        varid = self._safe_dirty_attr_8616(_dynamic_codegen_attr(node, "dirty", None), "varid")
        if isinstance(varid, int):
            return ("vvar", varid)
        return None

    def _resolve_stack_pointer_alias(self, 
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        node = self.unwrap_c_casts(node)
        if node is None:
            return None
        if seen_expr_ids is None:
            seen_expr_ids = set()
        node_id = id(node)
        if node_id in seen_expr_ids:
            return None
        seen_expr_ids.add(node_id)

        dirty_key = self._dirty_alias_key(node)
        if dirty_key is not None:
            alias = self.stack_pointer_aliases.get(dirty_key)
            if alias is not None:
                return _dynamic_codegen_attr(alias, "base"), int(_dynamic_codegen_attr(alias, "offset", 0))
        resolved_dirty = self._resolve_dirty_virtual_expr(node, seen_varids=seen_varids)
        if resolved_dirty is not None:
            return self._resolve_stack_pointer_alias(
                resolved_dirty,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        if isinstance(node, structured_c.CVariable):
            return self._resolve_cvar_stack_pointer_alias(
                node,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            return self._resolve_reference_stack_pointer_alias(node)
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            return self._resolve_addsub_stack_pointer_alias(
                node,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        return None

    def _resolve_cvar_stack_pointer_alias(
        self,
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        variable = _dynamic_codegen_attr(node, "variable", None)
        if isinstance(variable, SimStackVariable):
            identity = self.stack_slot_identity_for_variable(variable)
            if identity is not None and _dynamic_codegen_attr(identity, "base", None) == "bp":
                return node, 0
        if self._is_sp_virtual_register(variable):
            return self._synthetic_sp_anchor_cvar(), 0
        for key in self._alias_lookup_keys_for_cvar(node):
            alias = self.stack_pointer_aliases.get(key)
            if alias is not None:
                return _dynamic_codegen_attr(alias, "base"), int(_dynamic_codegen_attr(alias, "offset", 0))
        single_assignment_rhs = self._single_assignment_expr_for_cvar(node)
        if single_assignment_rhs is not None:
            return self._resolve_stack_pointer_alias(
                single_assignment_rhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        nearest_assignment_rhs = self._nearest_preceding_assignment_expr_for_cvar(node)
        if nearest_assignment_rhs is not None:
            return self._resolve_stack_pointer_alias(
                nearest_assignment_rhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        return None

    def _resolve_reference_stack_pointer_alias(self, node: structured_c.CUnaryOp) -> tuple[object, int] | None:
        operand = self.unwrap_c_casts(node.operand)
        if isinstance(operand, structured_c.CVariable):
            variable = _dynamic_codegen_attr(operand, "variable", None)
            if isinstance(variable, SimStackVariable):
                identity = self.stack_slot_identity_for_variable(variable)
                if identity is not None and _dynamic_codegen_attr(identity, "base", None) == "bp":
                    return operand, 0
            for key in self._alias_lookup_keys_for_cvar(operand):
                alias = self.stack_pointer_aliases.get(key)
                if alias is not None:
                    return _dynamic_codegen_attr(alias, "base"), int(_dynamic_codegen_attr(alias, "offset", 0))
        return None

    def _resolve_addsub_stack_pointer_alias(
        self,
        node: structured_c.CBinaryOp,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        lhs = self._resolve_stack_pointer_alias(
            node.lhs,
            seen_expr_ids=seen_expr_ids,
            seen_varids=seen_varids,
        )
        rhs = self._resolve_stack_pointer_alias(
            node.rhs,
            seen_expr_ids=seen_expr_ids,
            seen_varids=seen_varids,
        )
        lhs_const = self.c_constant_value(self.unwrap_c_casts(node.lhs))
        rhs_const = self.c_constant_value(self.unwrap_c_casts(node.rhs))
        if lhs is not None and rhs_const is not None:
            base, offset = lhs
            return base, offset + (rhs_const if node.op == "Add" else -rhs_const)
        if rhs is not None and lhs_const is not None:
            base, offset = rhs
            return base, offset + lhs_const
        return None

    def _expr_is_ss_segment_value_8616(self, 
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> bool:
        node = self.unwrap_c_casts(node)
        if node is None:
            return False
        if seen_expr_ids is None:
            seen_expr_ids = set()
        node_id = id(node)
        if node_id in seen_expr_ids:
            return False
        seen_expr_ids.add(node_id)

        if isinstance(node, structured_c.CVariable):
            return self._cvar_is_ss_segment_value_8616(
                node,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )

        resolved_dirty = self._resolve_dirty_virtual_expr(node, seen_varids=seen_varids)
        if resolved_dirty is not None:
            return self._expr_is_ss_segment_value_8616(
                resolved_dirty,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        if self._dirty_is_ss_virtual_register_8616(node):
            self.codegen._inertia_ss_stack_byte_ss_dirty_register_evidence_8616 = (
                int(_dynamic_codegen_attr(self.codegen, "_inertia_ss_stack_byte_ss_dirty_register_evidence_8616", 0) or 0) + 1
            )
            return True
        return False

    def _cvar_is_ss_segment_value_8616(
        self,
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> bool:
        variable = _dynamic_codegen_attr(node, "variable", None)
        if runtime_segment_name_for_variable_8616(variable) == "ss":
            return True
        if self._is_ss_virtual_register(variable):
            self.codegen._inertia_ss_stack_byte_ss_virtual_register_evidence_8616 = (
                int(_dynamic_codegen_attr(self.codegen, "_inertia_ss_stack_byte_ss_virtual_register_evidence_8616", 0) or 0) + 1
            )
            return True
        if self._dirty_is_ss_virtual_register_8616(node):
            self.codegen._inertia_ss_stack_byte_ss_dirty_register_evidence_8616 = (
                int(_dynamic_codegen_attr(self.codegen, "_inertia_ss_stack_byte_ss_dirty_register_evidence_8616", 0) or 0) + 1
            )
            return True
        name = _dynamic_codegen_attr(node, "name", None) or _dynamic_codegen_attr(variable, "name", None)
        if isinstance(name, str) and name.lower() == "ss":
            return True
        single_assignment_rhs = self._single_assignment_expr_for_cvar(node)
        if single_assignment_rhs is not None:
            return self._expr_is_ss_segment_value_8616(
                single_assignment_rhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        return False

    def _expr_is_ss_segment_scale_term_8616(self, node: object, *, seen_varids: set[int] | None = None) -> bool:
        node = self.unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp):
            return False
        op = _dynamic_codegen_attr(node, "op", None)
        lhs = _dynamic_codegen_attr(node, "lhs", None)
        rhs = _dynamic_codegen_attr(node, "rhs", None)
        lhs_const = self.c_constant_value(self.unwrap_c_casts(lhs))
        rhs_const = self.c_constant_value(self.unwrap_c_casts(rhs))
        if op == "Shl" and rhs_const == 4:
            return self._expr_is_ss_segment_value_8616(lhs, seen_varids=seen_varids)
        if op != "Mul":
            return False
        if rhs_const == 16 and self._expr_is_ss_segment_value_8616(lhs, seen_varids=seen_varids):
            return True
        return lhs_const == 16 and self._expr_is_ss_segment_value_8616(rhs, seen_varids=seen_varids)

    def _strip_proven_ss_segment_scale_from_addr_expr_8616(self, 
        addr_expr: object,
        *,
        seen_varids: set[int] | None = None,
    ) -> object | None:
        terms = self.flatten_c_add_terms(addr_expr)
        if not terms:
            return None
        kept_terms = []
        stripped = 0
        for term in terms:
            inner = self.unwrap_c_casts(term)
            if self._expr_is_ss_segment_scale_term_8616(inner, seen_varids=seen_varids):
                stripped += 1
                continue
            kept_terms.append(term)
        if stripped != 1 or not kept_terms:
            if stripped > 1:
                self.codegen._inertia_ss_stack_byte_segment_strip_refused_8616 = (
                    int(_dynamic_codegen_attr(self.codegen, "_inertia_ss_stack_byte_segment_strip_refused_8616", 0) or 0) + 1
                )
            return None
        result: object = kept_terms[0]
        for term in kept_terms[1:]:
            result = structured_c.CBinaryOp("Add", result, term, codegen=_dynamic_codegen_attr(term, "codegen", None))
        self.codegen._inertia_ss_stack_byte_segment_strip_materialized_8616 = (
            int(_dynamic_codegen_attr(self.codegen, "_inertia_ss_stack_byte_segment_strip_materialized_8616", 0) or 0) + 1
        )
        return result

    def _expr_contains_ss_segment_scale_8616(self, 
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> bool:
        node = self.unwrap_c_casts(node)
        if node is None:
            return False
        if seen_expr_ids is None:
            seen_expr_ids = set()
        node_id = id(node)
        if node_id in seen_expr_ids:
            return False
        seen_expr_ids.add(node_id)

        if isinstance(node, structured_c.CBinaryOp):
            return self._binop_contains_ss_segment_scale_8616(
                node,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )

        resolved_dirty = self._resolve_dirty_virtual_expr(node, seen_varids=seen_varids)
        if resolved_dirty is not None:
            return self._expr_contains_ss_segment_scale_8616(
                resolved_dirty,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        if isinstance(node, structured_c.CVariable):
            single_assignment_rhs = self._single_assignment_expr_for_cvar(node)
            if single_assignment_rhs is not None:
                return self._expr_contains_ss_segment_scale_8616(
                    single_assignment_rhs,
                    seen_expr_ids=seen_expr_ids,
                    seen_varids=seen_varids,
                )
        return False

    def _binop_contains_ss_segment_scale_8616(
        self,
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> bool:
        op = _dynamic_codegen_attr(node, "op", None)
        lhs = _dynamic_codegen_attr(node, "lhs", None)
        rhs = _dynamic_codegen_attr(node, "rhs", None)
        lhs_const = self.c_constant_value(self.unwrap_c_casts(lhs))
        rhs_const = self.c_constant_value(self.unwrap_c_casts(rhs))
        if (
            op == "Shl"
            and rhs_const == 4
            and self._expr_is_ss_segment_value_8616(
                lhs,
                seen_varids=seen_varids,
            )
        ):
            return True
        if op == "Mul":
            if rhs_const == 16 and self._expr_is_ss_segment_value_8616(lhs, seen_varids=seen_varids):
                return True
            if lhs_const == 16 and self._expr_is_ss_segment_value_8616(rhs, seen_varids=seen_varids):
                return True
        return self._expr_contains_ss_segment_scale_8616(
            lhs,
            seen_expr_ids=seen_expr_ids,
            seen_varids=seen_varids,
        ) or self._expr_contains_ss_segment_scale_8616(
            rhs,
            seen_expr_ids=seen_expr_ids,
            seen_varids=seen_varids,
        )

    def _resolve_ss_linear_stack_pointer_alias(self,
        node: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        node = self.unwrap_c_casts(node)
        if node is None:
            return None
        if seen_expr_ids is None:
            seen_expr_ids = set()
        node_id = id(node)
        if node_id in seen_expr_ids:
            return None
        seen_expr_ids.add(node_id)

        direct = self._resolve_stack_pointer_alias(node, seen_varids=seen_varids)
        if direct is not None:
            return direct

        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            addsub = self._resolve_ss_linear_addsub_alias(
                node,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
            if addsub is not None:
                return addsub

        resolved_expr = self._resolved_alias_carrier_expr(node, seen_varids=seen_varids)
        if resolved_expr is None:
            return None

        stripped = self._resolve_stripped_segment_carrier_alias(
            resolved_expr,
            seen_varids=seen_varids,
        )
        if stripped is not None:
            return stripped
        return self._resolve_ss_linear_stack_pointer_alias(
            resolved_expr,
            seen_expr_ids=seen_expr_ids,
            seen_varids=seen_varids,
        )

    def _resolve_ss_linear_addsub_alias(
        self,
        node: structured_c.CBinaryOp,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        lhs_const = self.c_constant_value(self.unwrap_c_casts(node.lhs))
        rhs_const = self.c_constant_value(self.unwrap_c_casts(node.rhs))
        if rhs_const is not None:
            lhs = self._resolve_ss_linear_stack_pointer_alias(
                node.lhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
            if lhs is not None:
                base, offset = lhs
                return base, offset + (rhs_const if node.op == "Add" else -rhs_const)
        if lhs_const is not None and node.op == "Add":
            rhs = self._resolve_ss_linear_stack_pointer_alias(
                node.rhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
            if rhs is not None:
                base, offset = rhs
                return base, offset + lhs_const
        return None

    def _resolved_alias_carrier_expr(
        self,
        node: object,
        *,
        seen_varids: set[int] | None = None,
    ) -> object | None:
        resolved_dirty = self._resolve_dirty_virtual_expr(node, seen_varids=seen_varids)
        if resolved_dirty is not None:
            return resolved_dirty
        if isinstance(node, structured_c.CVariable):
            resolved_expr = self._single_assignment_expr_for_cvar(node)
            if resolved_expr is not None:
                return resolved_expr
            return self._nearest_preceding_assignment_expr_for_cvar(node)
        return None

    def _resolve_stripped_segment_carrier_alias(
        self,
        resolved_expr: object,
        *,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        if not self._expr_contains_ss_segment_scale_8616(resolved_expr, seen_varids=seen_varids):
            return None
        addr_expr = self.strip_segment_scale_from_addr_expr(resolved_expr, self.project)
        if addr_expr is None or self._expr_contains_ss_segment_scale_8616(addr_expr, seen_varids=seen_varids):
            addr_expr = self._strip_proven_ss_segment_scale_from_addr_expr_8616(
                resolved_expr,
                seen_varids=seen_varids,
            )
        if addr_expr is None:
            return None
        resolved = self._resolve_stack_pointer_alias(addr_expr, seen_varids=seen_varids)
        if resolved is not None:
            self.codegen._inertia_ss_stack_byte_linear_carrier_resolved_8616 = (
                int(_dynamic_codegen_attr(self.codegen, "_inertia_ss_stack_byte_linear_carrier_resolved_8616", 0) or 0) + 1
            )
            return resolved
        return None

    def _is_uncast_ss_linear_carrier_byte_offset_8616(self, node: object) -> bool:
        if isinstance(node, structured_c.CTypeCast):
            return False
        node = self.unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Add", "Sub"}:
            return False
        lhs_const = self.c_constant_value(self.unwrap_c_casts(node.lhs))
        rhs_const = self.c_constant_value(self.unwrap_c_casts(node.rhs))
        if rhs_const not in (1, -1) and lhs_const not in (1, -1):
            return False
        base_expr = node.rhs if lhs_const in (1, -1) and node.op == "Add" else node.lhs
        resolved_dirty = self._resolve_dirty_virtual_expr(base_expr)
        if resolved_dirty is not None:
            base_expr = resolved_dirty
        elif isinstance(self.unwrap_c_casts(base_expr), structured_c.CVariable):
            base_expr = (
                self._single_assignment_expr_for_cvar(self.unwrap_c_casts(base_expr))
                or self._nearest_preceding_assignment_expr_for_cvar(self.unwrap_c_casts(base_expr))
                or base_expr
            )
        return self._expr_contains_ss_segment_scale_8616(base_expr)

    def _collect_stack_pointer_aliases(self) -> None:
        aliases: dict[object, object] = {}
        index = self._assignment_index()
        if index is None or self.structured_query_index is None:
            return
        assignments = self.structured_query_index.assignments
        for _ in range(3):
            changed_local = False
            for walk_node in assignments:
                if self._record_assignment_stack_pointer_alias(aliases, walk_node):
                    changed_local = True
            if not changed_local:
                break
        self.stack_pointer_aliases.update(aliases)

    def _record_assignment_stack_pointer_alias(
        self,
        aliases: dict[object, object],
        walk_node: structured_c.CAssignment,
    ) -> bool:
        lhs = _dynamic_codegen_attr(walk_node, "lhs", None)
        if isinstance(lhs, structured_c.CVariable):
            if not self._is_linear_temp(lhs):
                return False
            keys = self._alias_keys_for_cvar(lhs)
        else:
            dirty_key = self._dirty_alias_key(lhs)
            if dirty_key is None:
                return False
            keys = (dirty_key,)
        if not keys:
            return False
        rhs = self.unwrap_c_casts(walk_node.rhs)
        resolved = self._resolve_stack_pointer_alias(rhs)
        if resolved is None:
            return False
        resolved_state = self.stack_pointer_alias_state(*resolved)
        needs_update = False
        for key in keys:
            if aliases.get(key) != resolved_state:
                aliases[key] = resolved_state
                needs_update = True
        return needs_update

    def _effective_deref_bits(self, node: object) -> int | None:
        type_ = _dynamic_codegen_attr(node, "type", None)
        bits = _dynamic_codegen_attr(type_, "size", None)
        if isinstance(bits, int) and bits in {8, 16}:
            return bits
        operand = _dynamic_codegen_attr(node, "operand", None)
        cast_type = _dynamic_codegen_attr(operand, "type", None)
        if isinstance(cast_type, SimTypePointer):
            pointee = _dynamic_codegen_attr(cast_type, "pts_to", None)
            pointee_bits = _dynamic_codegen_attr(pointee, "size", None)
            if isinstance(pointee_bits, int) and pointee_bits in {8, 16}:
                return pointee_bits
        return None

    def make_stack_deref(self, cvar: Any, offset: int, bits: int) -> object:  # noqa: ANN401
        """Build a typed dereference for a proven stack-relative address."""
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(self.project.arch)
        base_ref = structured_c.CUnaryOp("Reference", cvar, codegen=self.codegen)
        addr_expr: structured_c.CExpression
        addr_expr = base_ref
        if offset > 0:
            addr_expr = structured_c.CBinaryOp(
                "Add",
                base_ref,
                structured_c.CConstant(offset, SimTypeShort(False), codegen=self.codegen),
                codegen=self.codegen,
            )
        elif offset < 0:
            addr_expr = structured_c.CBinaryOp(
                "Add",
                base_ref,
                structured_c.CConstant(offset, SimTypeShort(True), codegen=self.codegen),
                codegen=self.codegen,
            )
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(
                _dynamic_codegen_attr(addr_expr, "type", None) or ptr_type,
                ptr_type,
                addr_expr,
                codegen=self.codegen,
            ),
            codegen=self.codegen,
        )

    def make_addr_deref(self, addr_expr: Any, bits: int) -> object:  # noqa: ANN401
        """Build a typed dereference for a proven 16-bit address expression."""
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(self.project.arch)
        source_type = _dynamic_codegen_attr(addr_expr, "type", None) or SimTypeShort(False)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(source_type, ptr_type, addr_expr, codegen=self.codegen),
            codegen=self.codegen,
        )

    def _contains_large_unsigned_constant(self, node: object) -> bool:
        for term in self.flatten_c_add_terms(node):
            value = self.c_constant_value(self.unwrap_c_casts(term))
            if isinstance(value, int) and value > 0x7FFF:
                return True
        return False

    def _stack_cvar_identity(self, cvar: object) -> tuple[str, int, int | None, object] | None:
        variable = _dynamic_codegen_attr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        base = _dynamic_codegen_attr(variable, "base", None)
        offset = _dynamic_codegen_attr(variable, "offset", None)
        size = _dynamic_codegen_attr(variable, "size", None)
        region = _dynamic_codegen_attr(variable, "region", None)
        if not isinstance(base, str) or not isinstance(offset, int):
            return None
        return base, offset, size if isinstance(size, int) else None, region

    def _stack_deref_identity(self, node: object) -> tuple[tuple[str, int, int | None, object], int, int] | None:
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return None
        bits = self._effective_deref_bits(node)
        if bits not in {8, 16}:
            bits = 16
        resolved = self._resolve_stack_pointer_alias(_dynamic_codegen_attr(node, "operand", None))
        if resolved is None:
            return None
        base_cvar, extra_offset = resolved
        base_identity = self._stack_cvar_identity(base_cvar)
        if base_identity is None:
            return None
        return base_identity, int(extra_offset), int(bits)

    def _expr_contains_rewrite_alias_carrier(self, expr: object, *, seen_ids: set[int] | None = None) -> bool:
        expr = self.unwrap_c_casts(expr)
        if seen_ids is None:
            seen_ids = set()
        if expr is not None:
            expr_id = id(expr)
            if expr_id in seen_ids:
                return False
            seen_ids.add(expr_id)
        if self._dirty_alias_key(expr) is not None:
            return True
        if isinstance(expr, structured_c.CVariable):
            return self._is_linear_temp(expr)
        if isinstance(expr, structured_c.CUnaryOp):
            return self._expr_contains_rewrite_alias_carrier(_dynamic_codegen_attr(expr, "operand", None), seen_ids=seen_ids)
        if isinstance(expr, structured_c.CBinaryOp):
            return self._expr_contains_rewrite_alias_carrier(
                _dynamic_codegen_attr(expr, "lhs", None), seen_ids=seen_ids
            ) or self._expr_contains_rewrite_alias_carrier(_dynamic_codegen_attr(expr, "rhs", None), seen_ids=seen_ids)
        if isinstance(expr, structured_c.CTypeCast):
            return self._expr_contains_rewrite_alias_carrier(_dynamic_codegen_attr(expr, "expr", None), seen_ids=seen_ids)
        return False

    def _return_if_changed(self, original: object, replacement: object) -> object:
        if replacement is original:
            return original
        original_cvar = self._stack_cvar_identity(original)
        replacement_cvar = self._stack_cvar_identity(replacement)
        if original_cvar is not None and original_cvar == replacement_cvar:
            return original
        original_deref = self._stack_deref_identity(original)
        replacement_deref = self._stack_deref_identity(replacement)
        if original_deref is not None and original_deref == replacement_deref:
            return self._identical_deref_replacement(original, replacement)
        return replacement

    def _identical_deref_replacement(self, original: object, replacement: object) -> object:
        if isinstance(original, structured_c.CUnaryOp) and original.op == "Dereference":  # noqa: SIM102
            if self._expr_contains_rewrite_alias_carrier(_dynamic_codegen_attr(original, "operand", None)):
                return replacement
        return original

    def _resolved_stack_deref_for_offset(
        self,
        node: object,
        target_offset: int,
        access_size: int | None,
    ) -> object | None:
        resolved_cvar = self.resolve_stack_cvar_at_offset(self.codegen, target_offset)
        if resolved_cvar is not None:
            resolved_variable = _dynamic_codegen_attr(resolved_cvar, "variable", None)
            resolved_offset = _dynamic_codegen_attr(resolved_variable, "offset", None)
            resolved_size = _dynamic_codegen_attr(resolved_variable, "size", None)
            if (
                isinstance(resolved_variable, SimStackVariable)
                and isinstance(access_size, int)
                and access_size >= 4
            ):
                if resolved_size is not None and resolved_size < access_size:
                    self.promote_direct_stack_cvariable(
                        self.codegen,
                        resolved_cvar,
                        access_size,
                        self.stack_type_for_size(access_size),
                    )
                return self._return_if_changed(node, resolved_cvar)
            if (
                isinstance(resolved_variable, SimStackVariable)
                and isinstance(access_size, int)
                and resolved_offset == target_offset
                and resolved_size == access_size
            ):
                return self._return_if_changed(node, resolved_cvar)
        if isinstance(access_size, int) and access_size >= 4:
            return self._return_if_changed(
                node, self.materialize_stack_cvar_at_offset(self.codegen, target_offset, access_size)
            )
        return None

    def _transform_plain_alias_lane(self, node: object, resolved_plain_alias: tuple[object, int]) -> object:
        base_cvar, extra_offset = resolved_plain_alias
        bits = self._effective_deref_bits(node)
        if extra_offset != 0 and self._is_uncast_ss_linear_carrier_byte_offset_8616(_dynamic_codegen_attr(node, "operand", None)):
            bits = 8
        elif bits not in {8, 16}:
            bits = 8 if extra_offset != 0 else 16
        base_variable = _dynamic_codegen_attr(base_cvar, "variable", None)
        access_size = bits // self.project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
        if isinstance(base_variable, SimStackVariable) and isinstance(access_size, int):
            target_offset = _dynamic_codegen_attr(base_variable, "offset", 0) + extra_offset
            resolved = self._resolved_stack_deref_for_offset(node, target_offset, access_size)
            if resolved is not None:
                return resolved
        return self._return_if_changed(node, self.make_stack_deref(base_cvar, extra_offset, bits))

    def _transform_resolved_stack_alias_deref(self, node: object, resolved_stack_alias: tuple[object, int]) -> object:
        base_cvar, extra_offset = resolved_stack_alias
        type_ = _dynamic_codegen_attr(node, "type", None)
        bits = _dynamic_codegen_attr(type_, "size", None)
        if bits not in {8, 16}:
            bits = 16
        base_variable = _dynamic_codegen_attr(base_cvar, "variable", None)
        access_size = bits // self.project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
        if isinstance(base_variable, SimStackVariable) and isinstance(access_size, int):
            target_offset = _dynamic_codegen_attr(base_variable, "offset", 0) + extra_offset
            resolved = self._resolved_stack_deref_for_offset(node, target_offset, access_size)
            if resolved is not None:
                return resolved
        return self._return_if_changed(node, self.make_stack_deref(base_cvar, extra_offset, bits))

    def _transform_unclassified_deref(self, node: object, classified: Any) -> object:  # noqa: ANN401
        if classified is None or classified.seg_name != "ss":
            return node
        addr_expr = self.strip_segment_scale_from_addr_expr(_dynamic_codegen_attr(classified, "addr_expr", None), self.project)
        if addr_expr is None or self._expr_contains_ss_segment_scale_8616(addr_expr):
            addr_expr = self._strip_proven_ss_segment_scale_from_addr_expr_8616(
                _dynamic_codegen_attr(classified, "addr_expr", None),
            )
        if addr_expr is None:
            return node
        resolved_stack_alias = self._resolve_stack_pointer_alias(addr_expr)
        if resolved_stack_alias is not None:
            return self._transform_resolved_stack_alias_deref(node, resolved_stack_alias)
        if classified.extra_offset <= 0:
            return node
        if self._contains_large_unsigned_constant(addr_expr):
            return node
        bits = self._effective_deref_bits(node)
        if bits not in {8, 16}:
            return node
        return self._return_if_changed(node, self.make_addr_deref(addr_expr, bits))

    def _transform_classified_stack_deref(self, node: object, classified: Any) -> object:  # noqa: ANN401
        cvar = classified.cvar
        extra_offset = classified.extra_offset
        base_variable = _dynamic_codegen_attr(cvar, "variable", None)
        if isinstance(base_variable, SimStackVariable):
            bits = self._effective_deref_bits(node)
            if bits not in {8, 16}:
                bits = 16
            access_size = bits // self.project.arch.byte_width if isinstance(bits, int) and bits > 0 else None
            target_offset = _dynamic_codegen_attr(base_variable, "offset", 0) + extra_offset
            resolved = self._resolved_stack_deref_for_offset(node, target_offset, access_size)
            if resolved is not None:
                return resolved
        elif _dynamic_codegen_attr(classified, "seg_name", None) == "ss":
            addr_expr = self.strip_segment_scale_from_addr_expr(_dynamic_codegen_attr(classified, "addr_expr", None), self.project)
            if addr_expr is None or self._expr_contains_ss_segment_scale_8616(addr_expr):
                addr_expr = self._strip_proven_ss_segment_scale_from_addr_expr_8616(
                    _dynamic_codegen_attr(classified, "addr_expr", None),
                )
            if addr_expr is not None:
                resolved_stack_alias = self._resolve_stack_pointer_alias(addr_expr)
                if resolved_stack_alias is not None:
                    return self._transform_resolved_stack_alias_deref(node, resolved_stack_alias)
        bits = self._effective_deref_bits(node)
        if bits not in {8, 16}:
            if _dynamic_codegen_attr(classified, "seg_name", None) == "ss":
                bits = 16
            else:
                return node
        return self._return_if_changed(node, self.make_stack_deref(cvar, extra_offset, bits))

    def transform(self, node: object) -> object:
        """Rewrite a dereference node into a proven stack dereference when possible."""
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        resolved_plain_alias = self._resolve_stack_pointer_alias(_dynamic_codegen_attr(node, "operand", None))
        if resolved_plain_alias is None:
            resolved_plain_alias = self._resolve_ss_linear_stack_pointer_alias(_dynamic_codegen_attr(node, "operand", None))
        if resolved_plain_alias is not None:
            return self._transform_plain_alias_lane(node, resolved_plain_alias)
        classified = self.classify_segmented_dereference(node, self.project)
        if classified is None or classified.kind != "stack" or classified.cvar is None:
            return self._transform_unclassified_deref(node, classified)
        return self._transform_classified_stack_deref(node, classified)

    def run_8616_part1(self) -> tuple[bool, object]:
        """Apply the transform over the function body and report change state."""
        self.root = self.codegen.cfunc.statements
        self.new_root = self.transform(self.root)
        if self.new_root is not self.root:
            self.codegen.cfunc.statements = self.new_root
            self.root = self.new_root
            self.changed = True
        if self.replace_c_children(self.root, self.transform):
            self.changed = True

        if self.assignment_identity_index is not None:
            _dynamic_codegen_setattr(
                self.codegen,
                "_inertia_ss_stack_assignment_index_stats_8616",
                self.assignment_identity_index.stats(),
            )

        return True, self.changed
        return False, None

def _rewrite_ss_stack_byte_offsets(
    project: Any,  # noqa: ANN401
    codegen: Any,  # noqa: ANN401
    *,
    unwrap_c_casts: Callable[[object], object],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    replace_c_children: Callable[[object, Callable[[object], object]], bool],
    c_constant_value: Callable[[object], int | None],
    flatten_c_add_terms: Callable[[object], Iterable[object]],
    classify_segmented_dereference: Callable[[object, object], Any],
    strip_segment_scale_from_addr_expr: Callable[[object, object], Any],
    resolve_stack_cvar_at_offset: Callable[[object, int], Any],
    promote_direct_stack_cvariable: Callable[[object, object, int, object], Any],
    stack_type_for_size: Callable[[int], object],
    materialize_stack_cvar_at_offset: Callable[[object, int, int], Any],
    stack_slot_identity_for_variable: Callable[[object], Any],
    stack_pointer_alias_state: Callable[[object, int], Any],
) -> bool:
    return cast(bool, _SsStackByteOffsetRewrite8616(project, codegen, unwrap_c_casts, iter_c_nodes_deep, replace_c_children, c_constant_value, flatten_c_add_terms, classify_segmented_dereference, strip_segment_scale_from_addr_expr, resolve_stack_cvar_at_offset, promote_direct_stack_cvariable, stack_type_for_size, materialize_stack_cvar_at_offset, stack_slot_identity_for_variable, stack_pointer_alias_state).run_8616())
