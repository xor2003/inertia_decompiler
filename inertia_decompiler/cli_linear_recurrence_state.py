from __future__ import annotations

import re
from dataclasses import dataclass, field

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable


@dataclass
class LinearRecurrenceState:
    project: object
    codegen: object
    unwrap_c_casts: object
    structured_codegen_node: object
    iter_c_nodes_deep: object
    same_c_expression: object
    c_constant_value: object
    canonicalize_stack_cvar_expr: object
    seed_adjacent_byte_pair_aliases: object
    describe_alias_storage: object
    analyze_widening_expr: object
    match_high_byte_projection_base: object
    match_duplicate_word_base_expr: object
    match_duplicate_word_increment_shift_expr: object
    same_stack_slot_identity_var: object
    changed: bool = False
    linear_defs: dict[object, tuple[object, int]] = field(default_factory=dict)
    protected_linear_defs: set[int] = field(default_factory=set)
    shift_defs: dict[int, tuple[object, int]] = field(default_factory=dict)
    expr_aliases: dict[object, object] = field(default_factory=dict)
    dereferenced_variable_ids: set[int] = field(default_factory=set)
    protected_linear_alias_ids: set[int] = field(default_factory=set)
    variable_use_counts: dict[int, int] = field(default_factory=dict)

    def prepare(self) -> None:
        self.expr_aliases.update(self.seed_adjacent_byte_pair_aliases(self.project, self.codegen))
        for walk_node in self.iter_c_nodes_deep(self.codegen.cfunc.statements):
            if isinstance(walk_node, structured_c.CUnaryOp) and walk_node.op == "Dereference":
                self.collect_variable_ids(getattr(walk_node, "operand", None), self.dereferenced_variable_ids)
            if isinstance(walk_node, structured_c.CVariable):
                variable = getattr(walk_node, "variable", None)
                if variable is not None:
                    key = id(variable)
                    self.variable_use_counts[key] = self.variable_use_counts.get(key, 0) + 1
        for alias_var_id, alias_expr in self.expr_aliases.items():
            alias_expr = self.unwrap_c_casts(alias_expr)
            if not isinstance(alias_expr, structured_c.CUnaryOp) or alias_expr.op != "Dereference":
                continue
            self.protected_linear_alias_ids.add(alias_var_id)
            self.collect_variable_ids(getattr(alias_expr, "operand", None), self.protected_linear_alias_ids)
        for alias_var_id, alias_expr in list(self.expr_aliases.items()):
            resolved_alias = self.resolve_known_copy_alias_expr(alias_expr)
            if self.expr_contains_dereference(resolved_alias):
                self.protected_linear_alias_ids.add(alias_var_id)
                self.collect_variable_ids(resolved_alias, self.protected_linear_alias_ids)

    def collect_variable_ids(self, expr, ids: set[int]) -> None:
        expr = self.unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is not None:
                ids.add(id(variable))
            return
        for attr in ("lhs", "rhs", "operand", "expr"):
            if not hasattr(expr, attr):
                continue
            try:
                value = getattr(expr, attr)
            except Exception:
                continue
            if self.structured_codegen_node(value):
                self.collect_variable_ids(value, ids)
        for attr in ("args", "operands", "statements"):
            if not hasattr(expr, attr):
                continue
            try:
                items = getattr(expr, attr)
            except Exception:
                continue
            for item in items or ():
                if self.structured_codegen_node(item):
                    self.collect_variable_ids(item, ids)

    def is_linear_register_temp(self, cvar) -> bool:
        if not isinstance(cvar, structured_c.CVariable):
            return False
        name = getattr(cvar, "name", None)
        if not isinstance(name, str):
            return False
        if re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", name) is not None:
            return True
        variable = getattr(cvar, "variable", None)
        return isinstance(variable, SimRegisterVariable) and re.fullmatch(r"[A-Za-z]{1,3}_\d+", name) is not None

    def is_copy_alias_candidate(self, expr) -> bool:
        return isinstance(self.unwrap_c_casts(expr), structured_c.CVariable)

    def extract_linear_delta(self, expr):
        expr = self.unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
            return None, int(expr.value)
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Or":
            duplicate_word_base = self.match_duplicate_word_base_expr(expr, self.resolve_known_copy_alias_expr)
            if duplicate_word_base is not None:
                return duplicate_word_base, 0
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
            return expr, 0
        left_base, left_delta = self.extract_linear_delta(expr.lhs)
        right_base, right_delta = self.extract_linear_delta(expr.rhs)
        if left_base is not None and right_base is not None:
            if self.same_c_expression(left_base, right_base) and expr.op == "Add":
                return left_base, left_delta + right_delta
            return expr, 0
        if left_base is not None:
            return (left_base, left_delta + right_delta) if expr.op == "Add" else (left_base, left_delta - right_delta)
        if right_base is not None:
            return (right_base, left_delta + right_delta) if expr.op == "Add" else (expr, 0)
        return (None, left_delta + right_delta) if expr.op == "Add" else (None, left_delta - right_delta)

    def build_linear_expr(self, base_expr, delta):
        if delta == 0:
            return base_expr
        op = "Add" if delta > 0 else "Sub"
        magnitude = delta if delta > 0 else -delta
        return structured_c.CBinaryOp(
            op,
            base_expr,
            structured_c.CConstant(magnitude, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
        )

    def build_shift_expr(self, base_expr, count):
        if count == 0:
            return base_expr
        return structured_c.CBinaryOp(
            "Shr",
            base_expr,
            structured_c.CConstant(count, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
        )

    def inline_known_linear_defs(self, expr, seen_vars: set[int] | None = None, seen_exprs: set[int] | None = None, depth: int = 0):
        expr = self.unwrap_c_casts(expr)
        if depth > 64:
            return expr
        seen_vars = set() if seen_vars is None else seen_vars
        seen_exprs = set() if seen_exprs is None else seen_exprs
        expr_key = id(expr)
        if expr_key in seen_exprs:
            return expr
        seen_exprs.add(expr_key)
        if isinstance(expr, structured_c.CVariable):
            linear = None
            variable = getattr(expr, "variable", None)
            if variable is not None:
                var_id = id(variable)
                if var_id in self.dereferenced_variable_ids or var_id in self.protected_linear_alias_ids or var_id in seen_vars:
                    return expr
                seen_vars.add(var_id)
                alias = self.expr_aliases.get(var_id)
                if alias is not None:
                    aliased = self.inline_known_linear_defs(alias, seen_vars, seen_exprs, depth + 1)
                    if aliased is not expr:
                        return aliased
                linear = self.linear_defs.get(var_id)
            if linear is not None:
                base_expr, delta = linear
                if id(variable) in self.protected_linear_defs:
                    return expr
                if self.match_duplicate_word_base_expr(self.resolve_known_copy_alias_expr(base_expr), self.resolve_known_copy_alias_expr) is not None:
                    return expr
                return self.build_linear_expr(base_expr, delta)
            return expr
        if isinstance(expr, structured_c.CBinaryOp):
            lhs = self.inline_known_linear_defs(expr.lhs, seen_vars, seen_exprs, depth + 1)
            rhs = self.inline_known_linear_defs(expr.rhs, seen_vars, seen_exprs, depth + 1)
            if lhs is not expr.lhs or rhs is not expr.rhs:
                expr = structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=self.codegen)
            linear_expr = self.match_linear_word_delta_expr(expr)
            if linear_expr is not None and not self.same_c_expression(linear_expr, expr):
                return linear_expr
            return expr
        if isinstance(expr, structured_c.CUnaryOp):
            if expr.op == "Dereference":
                return expr
            operand = self.inline_known_linear_defs(expr.operand, seen_vars, seen_exprs, depth + 1)
            if operand is not expr.operand:
                return structured_c.CUnaryOp(expr.op, operand, codegen=self.codegen)
        return expr

    def extract_shift_delta(self, expr):
        expr = self.unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
            return None, int(expr.value)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
            return expr, 0
        shift = self.c_constant_value(self.unwrap_c_casts(expr.rhs))
        if not isinstance(shift, int):
            return expr, 0
        base = self.unwrap_c_casts(expr.lhs)
        if isinstance(base, structured_c.CVariable):
            variable = getattr(base, "variable", None)
            if variable is not None:
                alias = self.shift_defs.get(id(variable))
                if alias is not None:
                    alias_base, alias_shift = alias
                    return alias_base, alias_shift + shift
        return base, shift

    def alias_storage_key(self, expr):
        return self.describe_alias_storage(expr).identity

    def resolve_known_copy_alias_expr(self, expr, active_expr_ids: set[int] | None = None, seen_var_ids: set[int] | None = None, seen_storage: set[object] | None = None, depth: int = 0):
        expr = self.unwrap_c_casts(expr)
        if depth > 64:
            return self.canonicalize_stack_cvar_expr(expr, self.codegen)
        active_expr_ids = set() if active_expr_ids is None else active_expr_ids
        expr_id = id(expr)
        if expr_id in active_expr_ids:
            return self.canonicalize_stack_cvar_expr(expr, self.codegen)
        active_expr_ids.add(expr_id)
        seen_var_ids = set() if seen_var_ids is None else seen_var_ids
        seen_storage = set() if seen_storage is None else seen_storage
        while isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is None:
                break
            key = id(variable)
            storage_key = self.alias_storage_key(expr)
            if key in seen_var_ids:
                break
            seen_var_ids.add(key)
            if storage_key is not None:
                if storage_key in seen_storage:
                    break
                seen_storage.add(storage_key)
            alias = self.expr_aliases.get(key)
            if alias is None and storage_key is not None:
                alias = self.expr_aliases.get(storage_key)
            if alias is None:
                linear = self.linear_defs.get(key)
                if linear is not None:
                    base_expr, delta = linear
                    alias = self.build_linear_expr(base_expr, delta)
            if alias is None:
                break
            expr = self.unwrap_c_casts(alias)
        if isinstance(expr, structured_c.CTypeCast):
            inner = self.resolve_known_copy_alias_expr(expr.expr, active_expr_ids, seen_var_ids.copy(), seen_storage.copy(), depth + 1)
            active_expr_ids.discard(expr_id)
            if inner is not expr.expr:
                return structured_c.CTypeCast(None, expr.type, inner, codegen=getattr(expr, "codegen", None))
            return self.canonicalize_stack_cvar_expr(expr, self.codegen)
        if isinstance(expr, structured_c.CUnaryOp):
            operand = self.resolve_known_copy_alias_expr(expr.operand, active_expr_ids, seen_var_ids.copy(), seen_storage.copy(), depth + 1)
            active_expr_ids.discard(expr_id)
            if operand is not expr.operand:
                return structured_c.CUnaryOp(expr.op, operand, codegen=getattr(expr, "codegen", None))
            return self.canonicalize_stack_cvar_expr(expr, self.codegen)
        if isinstance(expr, structured_c.CBinaryOp):
            lhs = self.resolve_known_copy_alias_expr(expr.lhs, active_expr_ids, seen_var_ids.copy(), seen_storage.copy(), depth + 1)
            rhs = self.resolve_known_copy_alias_expr(expr.rhs, active_expr_ids, seen_var_ids.copy(), seen_storage.copy(), depth + 1)
            active_expr_ids.discard(expr_id)
            if lhs is not expr.lhs or rhs is not expr.rhs:
                return structured_c.CBinaryOp(expr.op, lhs, rhs, codegen=getattr(expr, "codegen", None))
            return self.canonicalize_stack_cvar_expr(expr, self.codegen)
        active_expr_ids.discard(expr_id)
        return self.canonicalize_stack_cvar_expr(expr, self.codegen)

    def expr_contains_dereference(self, expr, active_expr_ids: set[int] | None = None) -> bool:
        expr = self.unwrap_c_casts(expr)
        active_expr_ids = set() if active_expr_ids is None else active_expr_ids
        expr_id = id(expr)
        if expr_id in active_expr_ids:
            return False
        active_expr_ids.add(expr_id)
        if isinstance(expr, structured_c.CUnaryOp):
            if expr.op == "Dereference":
                active_expr_ids.discard(expr_id)
                return True
            result = self.expr_contains_dereference(expr.operand, active_expr_ids)
            active_expr_ids.discard(expr_id)
            return result
        if isinstance(expr, structured_c.CBinaryOp):
            result = self.expr_contains_dereference(expr.lhs, active_expr_ids) or self.expr_contains_dereference(expr.rhs, active_expr_ids)
            active_expr_ids.discard(expr_id)
            return result
        if isinstance(expr, structured_c.CTypeCast):
            result = self.expr_contains_dereference(expr.expr, active_expr_ids)
            active_expr_ids.discard(expr_id)
            return result
        if isinstance(expr, structured_c.CFunctionCall):
            result = any(self.expr_contains_dereference(arg, active_expr_ids) for arg in getattr(expr, "args", ()) or ())
            active_expr_ids.discard(expr_id)
            return result
        active_expr_ids.discard(expr_id)
        return False

    def match_linear_word_delta_expr(self, expr):
        analysis = self.analyze_widening_expr(expr, self.resolve_known_copy_alias_expr, self.match_high_byte_projection_base)
        if analysis is None or analysis.kind != "linear":
            return None
        resolved_base = self.resolve_known_copy_alias_expr(analysis.base_expr)
        if self.match_duplicate_word_base_expr(resolved_base, self.resolve_known_copy_alias_expr) is not None:
            return None
        if analysis.delta == 0:
            return analysis.base_expr
        return self.build_linear_expr(analysis.base_expr, analysis.delta)
