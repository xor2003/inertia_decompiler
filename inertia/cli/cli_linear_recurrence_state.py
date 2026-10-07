"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

type CExpr = object
type LinearDelta = tuple[CExpr | None, int]


class _CFunctionLike(Protocol):
    """Structured C function surface needed by linear recurrence state."""

    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by linear recurrence state."""

    cfunc: _CFunctionLike | None
    _inertia_stack_lowering_debug: dict[str, object]
    _inertia_stack_variable_bindings: object
    _inertia_has_rebound_materialized_recurrence: bool


class _AliasStorageLike(Protocol):
    """Alias-storage summary used to avoid recursive copy aliases."""

    identity: object


class _WideningAnalysisLike(Protocol):
    """Widening analysis fields consumed by linear recurrence rebuilding."""

    kind: str
    base_expr: CExpr
    delta: int


@dataclass
class LinearRecurrenceState:
    """Carry state and callback contracts for CLI linear-recurrence cleanup."""

    project: object
    codegen: _CodegenLike
    unwrap_c_casts: Callable[[CExpr], CExpr]
    structured_codegen_node: Callable[[CExpr], bool]
    iter_c_nodes_deep: Callable[[CExpr], Iterable[CExpr]]
    same_c_expression: Callable[[CExpr, CExpr], bool]
    c_constant_value: Callable[[CExpr], object | None]
    canonicalize_stack_cvar_expr: Callable[[CExpr, _CodegenLike], CExpr]
    seed_adjacent_byte_pair_aliases: Callable[[object, _CodegenLike], dict[object, CExpr]]
    describe_alias_storage: Callable[[CExpr], _AliasStorageLike | None]
    analyze_widening_expr: Callable[
        [CExpr, Callable[..., CExpr], Callable[..., CExpr | None]], _WideningAnalysisLike | None
    ]
    match_high_byte_projection_base: Callable[..., CExpr | None]
    match_duplicate_word_base_expr: Callable[..., CExpr | None]
    match_duplicate_word_increment_shift_expr: Callable[..., CExpr | None]
    same_stack_slot_identity_var: Callable[..., bool]
    changed: bool = False
    linear_defs: dict[object, tuple[object, int]] = field(default_factory=dict)
    protected_linear_defs: set[int] = field(default_factory=set)
    shift_defs: dict[int, tuple[object, int]] = field(default_factory=dict)
    expr_aliases: dict[object, object] = field(default_factory=dict)
    dereferenced_variable_ids: set[int] = field(default_factory=set)
    protected_linear_alias_ids: set[int] = field(default_factory=set)
    variable_use_counts: dict[int, int] = field(default_factory=dict)
    recurrence_candidates: int = 0
    recurrence_bound_to_materialized_local: int = 0
    recurrence_failed_to_bind: int = 0
    recurrence_reasons: dict[str, int] = field(default_factory=dict)

    def prepare(self) -> None:
        """Seed recurrence bookkeeping from codegen C-AST statements."""

        def _impl() -> None:
            # Dynamic codegen boundary: CLI codegen metadata may be attached lazily.
            debug_stats = getattr(self.codegen, "_inertia_stack_lowering_debug", None)
            if not isinstance(debug_stats, dict):
                debug_stats = {}
                self.codegen._inertia_stack_lowering_debug = debug_stats
            debug_stats.setdefault("recurrence_candidates", 0)
            debug_stats.setdefault("recurrence_bound_to_materialized_local", 0)
            debug_stats.setdefault("recurrence_failed_to_bind", 0)
            debug_stats.setdefault("recurrence_reasons", {})
            self.expr_aliases.update(self.seed_adjacent_byte_pair_aliases(self.project, self.codegen))
            cfunc = self.codegen.cfunc
            if cfunc is None:
                return
            for walk_node in self.iter_c_nodes_deep(cfunc.statements):
                if isinstance(walk_node, structured_c.CUnaryOp) and walk_node.op == "Dereference":
                    # Dynamic codegen boundary: CUnaryOp operand is supplied by angr structured codegen.
                    self.collect_variable_ids(getattr(walk_node, "operand", None), self.dereferenced_variable_ids)
                if isinstance(walk_node, structured_c.CVariable):
                    # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
                    variable = getattr(walk_node, "variable", None)
                    if variable is not None:
                        key = id(variable)
                        self.variable_use_counts[key] = self.variable_use_counts.get(key, 0) + 1
            self._seed_deref_alias_protection()
            self._seed_resolved_alias_protection()

        return _impl()

    def _seed_deref_alias_protection(self) -> None:
        """Protect aliases whose proven target is a dereference."""
        for alias_var_id, alias_expr in self.expr_aliases.items():
            if not isinstance(alias_var_id, int):
                continue
            alias_expr = self.unwrap_c_casts(alias_expr)
            if not isinstance(alias_expr, structured_c.CUnaryOp) or alias_expr.op != "Dereference":
                continue
            self.protected_linear_alias_ids.add(alias_var_id)
            # Dynamic codegen boundary: CUnaryOp operand is supplied by angr structured codegen.
            self.collect_variable_ids(getattr(alias_expr, "operand", None), self.protected_linear_alias_ids)

    def _seed_resolved_alias_protection(self) -> None:
        """Protect aliases whose resolved form contains a dereference."""
        for alias_var_id, alias_expr in list(self.expr_aliases.items()):
            if not isinstance(alias_var_id, int):
                continue
            resolved_alias = self.resolve_known_copy_alias_expr(alias_expr)
            if self.expr_contains_dereference(resolved_alias):
                self.protected_linear_alias_ids.add(alias_var_id)
                self.collect_variable_ids(resolved_alias, self.protected_linear_alias_ids)

    def collect_variable_ids(self, expr: CExpr, ids: set[int]) -> None:
        """Collect underlying variable identities referenced by a C expression."""
        expr = self.unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
            variable = getattr(expr, "variable", None)
            if variable is not None:
                ids.add(id(variable))
            return
        self._collect_scalar_child_ids(expr, ids)
        self._collect_sequence_child_ids(expr, ids)

    def _collect_scalar_child_ids(self, expr: object, ids: set[int]) -> None:
        """Recurse into scalar child fields of one C expression."""
        for attr in ("lhs", "rhs", "operand", "expr"):
            if not hasattr(expr, attr):
                continue
            try:
                # Dynamic codegen boundary: child field names vary across angr C AST nodes.
                value = getattr(expr, attr)
            except Exception:
                continue
            if self.structured_codegen_node(value):
                self.collect_variable_ids(value, ids)

    def _collect_sequence_child_ids(self, expr: object, ids: set[int]) -> None:
        """Recurse into sequence child fields of one C expression."""
        for attr in ("args", "operands", "statements"):
            if not hasattr(expr, attr):
                continue
            try:
                # Dynamic codegen boundary: child sequence fields vary across angr C AST nodes.
                items = getattr(expr, attr)
            except Exception:
                continue
            for item in items or ():
                if self.structured_codegen_node(item):
                    self.collect_variable_ids(item, ids)

    def is_linear_register_temp(self, cvar: CExpr) -> bool:
        """Return whether a C variable is a synthetic linear-register temp."""
        if not isinstance(cvar, structured_c.CVariable):
            return False
        # Dynamic codegen boundary: generated CVariable names may be absent.
        name = getattr(cvar, "name", None)
        if not isinstance(name, str):
            return False
        if re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", name) is not None:
            return True
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        variable = getattr(cvar, "variable", None)
        return isinstance(variable, SimRegisterVariable) and re.fullmatch(r"[A-Za-z]{1,3}_\d+", name) is not None

    def is_copy_alias_candidate(self, expr: CExpr) -> bool:
        """Return whether an expression can seed a copy-alias candidate."""
        return isinstance(self.unwrap_c_casts(expr), structured_c.CVariable)

    def expr_contains_stack_base_carrier(self, expr: CExpr, active_expr_ids: set[int] | None = None) -> bool:
        """Return whether an expression recursively references the stack-base carrier."""
        expr = self.unwrap_c_casts(expr)
        active_expr_ids = set() if active_expr_ids is None else active_expr_ids
        expr_id = id(expr)
        if expr_id in active_expr_ids:
            return False
        active_expr_ids.add(expr_id)
        # Dynamic codegen boundary: CFakeVariable names come from angr structured C.
        if isinstance(expr, structured_c.CFakeVariable) and getattr(expr, "name", None) == "stack_base":
            active_expr_ids.discard(expr_id)
            return True
        if self._scalar_child_has_stack_base(expr, active_expr_ids, expr_id):
            return True
        if self._sequence_child_has_stack_base(expr, active_expr_ids, expr_id):
            return True
        active_expr_ids.discard(expr_id)
        return False

    def _scalar_child_has_stack_base(self, expr: object, active_expr_ids: set[int], expr_id: int) -> bool:
        """Probe scalar child fields for a stack-base carrier reference."""
        for attr in ("lhs", "rhs", "operand", "expr", "variable", "index"):
            if not hasattr(expr, attr):
                continue
            try:
                # Dynamic codegen boundary: child field names vary across angr C AST nodes.
                value = getattr(expr, attr)
            except Exception:
                continue
            if value is not None and self.expr_contains_stack_base_carrier(value, active_expr_ids):
                active_expr_ids.discard(expr_id)
                return True
        return False

    def _sequence_child_has_stack_base(self, expr: object, active_expr_ids: set[int], expr_id: int) -> bool:
        """Probe sequence child fields for a stack-base carrier reference."""
        for attr in ("args", "operands"):
            if not hasattr(expr, attr):
                continue
            try:
                # Dynamic codegen boundary: child sequence fields vary across angr C AST nodes.
                items = getattr(expr, attr)
            except Exception:
                continue
            for item in items or ():
                if self.expr_contains_stack_base_carrier(item, active_expr_ids):
                    active_expr_ids.discard(expr_id)
                    return True
        return False

    def extract_linear_delta(self, expr: CExpr) -> LinearDelta:
        """Split a linear expression into a base expression and integer delta."""

        def _impl() -> LinearDelta:
            nonlocal expr
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
                return (
                    (left_base, left_delta + right_delta) if expr.op == "Add" else (left_base, left_delta - right_delta)
                )
            if right_base is not None:
                return (right_base, left_delta + right_delta) if expr.op == "Add" else (expr, 0)
            return (None, left_delta + right_delta) if expr.op == "Add" else (None, left_delta - right_delta)

        return _impl()

    def build_binary_op_or_none(self, op: str, lhs: CExpr, rhs: CExpr, *, codegen: _CodegenLike | None = None) -> CExpr | None:
        """Build a binary C expression, refusing known unarched-type rebuild failures."""
        try:
            return cast(CExpr, structured_c.CBinaryOp(op, lhs, rhs, codegen=codegen or self.codegen))
        except ValueError as ex:
            if "Can't tell my size without an arch" in str(ex):
                self._record_recurrence_reason("binary_rebuild_unarched_type")
                return None
            raise

    def build_linear_expr(self, base_expr: CExpr, delta: int) -> CExpr:
        """Build `base_expr +/- delta`, preserving the original expression on rebuild failure."""
        if delta == 0:
            return base_expr
        op = "Add" if delta > 0 else "Sub"
        magnitude = delta if delta > 0 else -delta
        rebuilt = self.build_binary_op_or_none(
            op,
            base_expr,
            structured_c.CConstant(magnitude, SimTypeShort(False), codegen=self.codegen),
        )
        return rebuilt if rebuilt is not None else base_expr

    def build_shift_expr(self, base_expr: CExpr, count: int) -> CExpr:
        """Build `base_expr >> count`, preserving the original expression on rebuild failure."""
        if count == 0:
            return base_expr
        rebuilt = self.build_binary_op_or_none(
            "Shr",
            base_expr,
            structured_c.CConstant(count, SimTypeShort(False), codegen=self.codegen),
        )
        return rebuilt if rebuilt is not None else base_expr

    def inline_known_linear_defs(
        self, expr: CExpr, seen_vars: set[int] | None = None, seen_exprs: set[int] | None = None, depth: int = 0
    ) -> CExpr:
        """Inline already-proven linear definitions into a C expression."""

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
            return self._inline_variable_linear_defs(expr, seen_vars, seen_exprs, depth)
        if isinstance(expr, structured_c.CBinaryOp):
            return self._inline_binop_linear_defs(expr, seen_vars, seen_exprs, depth)
        if isinstance(expr, structured_c.CUnaryOp):
            if expr.op == "Dereference":
                return expr
            operand = self.inline_known_linear_defs(expr.operand, seen_vars, seen_exprs, depth + 1)
            if operand is not expr.operand:
                return structured_c.CUnaryOp(expr.op, cast(structured_c.CExpression, operand), codegen=self.codegen)
        return expr

    def _inline_variable_linear_defs(
        self, expr: structured_c.CVariable, seen_vars: set[int], seen_exprs: set[int], depth: int
    ) -> CExpr:
        """Inline a proven linear definition behind one C variable."""
        if self.is_materialized_stack_local(expr):
            return expr
        linear = None
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        variable = getattr(expr, "variable", None)
        if variable is not None:
            var_id = id(variable)
            if (
                var_id in self.dereferenced_variable_ids
                or var_id in self.protected_linear_alias_ids
                or var_id in seen_vars
            ):
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
            if self.expr_contains_stack_base_carrier(base_expr):
                return expr
            if (
                self.match_duplicate_word_base_expr(
                    self.resolve_known_copy_alias_expr(base_expr), self.resolve_known_copy_alias_expr
                )
                is not None
            ):
                return expr
            return self.build_linear_expr(base_expr, delta)
        return expr

    def _inline_binop_linear_defs(
        self, expr: structured_c.CBinaryOp, seen_vars: set[int], seen_exprs: set[int], depth: int
    ) -> CExpr:
        """Inline linear defs under a binary op and re-fold word deltas."""
        lhs = self.inline_known_linear_defs(expr.lhs, seen_vars, seen_exprs, depth + 1)
        rhs = self.inline_known_linear_defs(expr.rhs, seen_vars, seen_exprs, depth + 1)
        if lhs is not expr.lhs or rhs is not expr.rhs:
            rebuilt = self.build_binary_op_or_none(expr.op, lhs, rhs)
            if rebuilt is None:
                return expr
            expr = rebuilt
        linear_expr = self.match_linear_word_delta_expr(expr)
        if linear_expr is not None and not self.same_c_expression(linear_expr, expr):
            return linear_expr
        return expr

    def extract_shift_delta(self, expr: CExpr) -> LinearDelta:
        """Split a shift expression into a base expression and shift count."""
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
            # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
            variable = getattr(base, "variable", None)
            if variable is not None:
                alias = self.shift_defs.get(id(variable))
                if alias is not None:
                    alias_base, alias_shift = alias
                    return alias_base, alias_shift + shift
        return base, shift

    def alias_storage_key(self, expr: CExpr) -> object:
        """Return alias-storage identity for an expression when one is available."""
        storage = self.describe_alias_storage(expr)
        return None if storage is None else storage.identity

    def resolve_known_copy_alias_expr(
        self,
        expr: CExpr,
        active_expr_ids: set[int] | None = None,
        seen_var_ids: set[int] | None = None,
        seen_storage: set[object] | None = None,
        depth: int = 0,
    ) -> CExpr:
        """Resolve copy-alias chains while preserving materialized stack locals."""

        expr = self.unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable) and self.is_materialized_stack_local(expr):
            return self.canonicalize_stack_cvar_expr(expr, self.codegen)
        if depth > 64:
            return self.canonicalize_stack_cvar_expr(expr, self.codegen)
        active_expr_ids = set() if active_expr_ids is None else active_expr_ids
        expr_id = id(expr)
        if expr_id in active_expr_ids:
            return self.canonicalize_stack_cvar_expr(expr, self.codegen)
        active_expr_ids.add(expr_id)
        seen_var_ids = set() if seen_var_ids is None else seen_var_ids
        seen_storage = set() if seen_storage is None else seen_storage
        expr = self._chase_copy_alias_chain(expr, seen_var_ids, seen_storage)
        if isinstance(expr, structured_c.CTypeCast):
            return self._resolve_alias_typecast(expr, active_expr_ids, seen_var_ids, seen_storage, depth, expr_id)
        if isinstance(expr, structured_c.CUnaryOp):
            return self._resolve_alias_unary(expr, active_expr_ids, seen_var_ids, seen_storage, depth, expr_id)
        if isinstance(expr, structured_c.CBinaryOp):
            return self._resolve_alias_binop(expr, active_expr_ids, seen_var_ids, seen_storage, depth, expr_id)
        active_expr_ids.discard(expr_id)
        return self.canonicalize_stack_cvar_expr(expr, self.codegen)

    def _chase_copy_alias_chain(self, expr: CExpr, seen_var_ids: set[int], seen_storage: set[object]) -> CExpr:
        """Walk variable -> alias edges until the chain ends or repeats."""
        while isinstance(expr, structured_c.CVariable):
            # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
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
            alias = self._copy_alias_for_variable(key, storage_key)
            if alias is None:
                break
            expr = self.unwrap_c_casts(alias)
        return expr

    def _copy_alias_for_variable(self, key: int, storage_key: object | None) -> CExpr | None:
        """Resolve the next alias target for a variable key, or None to stop."""
        alias = self.expr_aliases.get(key)
        if alias is None and storage_key is not None:
            alias = self.expr_aliases.get(storage_key)
        if alias is not None and self.expr_contains_stack_base_carrier(alias):
            alias = None
        if alias is None:
            linear = self.linear_defs.get(key)
            if linear is not None:
                base_expr, delta = linear
                if not self.expr_contains_stack_base_carrier(base_expr):
                    alias = self.build_linear_expr(base_expr, delta)
        return alias

    def _resolve_alias_typecast(
        self,
        expr: structured_c.CTypeCast,
        active_expr_ids: set[int],
        seen_var_ids: set[int],
        seen_storage: set[object],
        depth: int,
        expr_id: int,
    ) -> CExpr:
        """Resolve through a CTypeCast node and rebuild when the operand moved."""
        inner = self.resolve_known_copy_alias_expr(
            expr.expr, active_expr_ids, seen_var_ids.copy(), seen_storage.copy(), depth + 1
        )
        active_expr_ids.discard(expr_id)
        if inner is not expr.expr:
            # Dynamic codegen boundary: rebuilt nodes reuse optional angr codegen metadata.
            codegen_metadata = getattr(expr, "codegen", None)
            return structured_c.CTypeCast(
                None,
                expr.type,
                cast(structured_c.CExpression, inner),
                codegen=codegen_metadata,
            )
        return self.canonicalize_stack_cvar_expr(expr, self.codegen)

    def _resolve_alias_unary(
        self,
        expr: structured_c.CUnaryOp,
        active_expr_ids: set[int],
        seen_var_ids: set[int],
        seen_storage: set[object],
        depth: int,
        expr_id: int,
    ) -> CExpr:
        """Resolve through a CUnaryOp node and rebuild when the operand moved."""
        operand = self.resolve_known_copy_alias_expr(
            expr.operand, active_expr_ids, seen_var_ids.copy(), seen_storage.copy(), depth + 1
        )
        active_expr_ids.discard(expr_id)
        if operand is not expr.operand:
            # Dynamic codegen boundary: rebuilt nodes reuse optional angr codegen metadata.
            codegen_metadata = getattr(expr, "codegen", None)
            return structured_c.CUnaryOp(
                expr.op,
                cast(structured_c.CExpression, operand),
                codegen=codegen_metadata,
            )
        return self.canonicalize_stack_cvar_expr(expr, self.codegen)

    def _resolve_alias_binop(
        self,
        expr: structured_c.CBinaryOp,
        active_expr_ids: set[int],
        seen_var_ids: set[int],
        seen_storage: set[object],
        depth: int,
        expr_id: int,
    ) -> CExpr:
        """Resolve through a CBinaryOp node and rebuild when either operand moved."""
        lhs = self.resolve_known_copy_alias_expr(
            expr.lhs, active_expr_ids, seen_var_ids.copy(), seen_storage.copy(), depth + 1
        )
        rhs = self.resolve_known_copy_alias_expr(
            expr.rhs, active_expr_ids, seen_var_ids.copy(), seen_storage.copy(), depth + 1
        )
        active_expr_ids.discard(expr_id)
        if lhs is not expr.lhs or rhs is not expr.rhs:
            # Dynamic codegen boundary: rebuilt nodes reuse optional angr codegen metadata.
            rebuilt = self.build_binary_op_or_none(expr.op, lhs, rhs, codegen=getattr(expr, "codegen", None))
            if rebuilt is not None:
                return rebuilt
        return self.canonicalize_stack_cvar_expr(expr, self.codegen)

    def expr_contains_dereference(self, expr: CExpr, active_expr_ids: set[int] | None = None) -> bool:
        """Return whether an expression recursively contains a dereference."""

        def _impl() -> bool:
            nonlocal expr, active_expr_ids
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
                result = self.expr_contains_dereference(expr.lhs, active_expr_ids) or self.expr_contains_dereference(
                    expr.rhs, active_expr_ids
                )
                active_expr_ids.discard(expr_id)
                return result
            if isinstance(expr, structured_c.CTypeCast):
                result = self.expr_contains_dereference(expr.expr, active_expr_ids)
                active_expr_ids.discard(expr_id)
                return result
            if isinstance(expr, structured_c.CFunctionCall):
                result = any(
                    # Dynamic codegen boundary: function-call args are an optional angr C AST sequence.
                    self.expr_contains_dereference(arg, active_expr_ids) for arg in getattr(expr, "args", ()) or ()
                )
                active_expr_ids.discard(expr_id)
                return result
            active_expr_ids.discard(expr_id)
            return False

        return _impl()

    def match_linear_word_delta_expr(self, expr: CExpr) -> CExpr | None:
        """Return a rebuilt linear word expression when widening analysis proves one."""
        analysis = self.analyze_widening_expr(
            expr, self.resolve_known_copy_alias_expr, self.match_high_byte_projection_base
        )
        if analysis is None or analysis.kind != "linear":
            return None
        resolved_base = self.resolve_known_copy_alias_expr(analysis.base_expr)
        if self.match_duplicate_word_base_expr(resolved_base, self.resolve_known_copy_alias_expr) is not None:
            return None
        if analysis.delta == 0:
            return analysis.base_expr
        return self.build_linear_expr(analysis.base_expr, analysis.delta)

    def _record_recurrence_reason(self, reason: str) -> None:
        self.recurrence_failed_to_bind += 1
        self.recurrence_reasons[reason] = self.recurrence_reasons.get(reason, 0) + 1
        # Dynamic codegen boundary: CLI codegen metadata may be attached lazily.
        debug_stats = getattr(self.codegen, "_inertia_stack_lowering_debug", None)
        if isinstance(debug_stats, dict):
            debug_stats["recurrence_failed_to_bind"] = int(debug_stats.get("recurrence_failed_to_bind", 0) or 0) + 1
            reasons = debug_stats.setdefault("recurrence_reasons", {})
            if isinstance(reasons, dict):
                reasons[reason] = int(reasons.get(reason, 0) or 0) + 1

    def _record_recurrence_candidate(self) -> None:
        self.recurrence_candidates += 1
        # Dynamic codegen boundary: CLI codegen metadata may be attached lazily.
        debug_stats = getattr(self.codegen, "_inertia_stack_lowering_debug", None)
        if isinstance(debug_stats, dict):
            debug_stats["recurrence_candidates"] = int(debug_stats.get("recurrence_candidates", 0) or 0) + 1

    def _record_recurrence_success(self) -> None:
        self.recurrence_bound_to_materialized_local += 1
        # Dynamic codegen boundary: CLI codegen metadata may be attached lazily.
        debug_stats = getattr(self.codegen, "_inertia_stack_lowering_debug", None)
        if isinstance(debug_stats, dict):
            debug_stats["recurrence_bound_to_materialized_local"] = (
                int(debug_stats.get("recurrence_bound_to_materialized_local", 0) or 0) + 1
            )
        self.codegen._inertia_has_rebound_materialized_recurrence = True

    def is_materialized_stack_local(self, cvar: CExpr) -> bool:
        """Return whether a variable already represents a materialized stack local."""

        def _impl() -> bool:
            if not isinstance(cvar, structured_c.CVariable):
                return False
            # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                return False
            # Dynamic codegen boundary: generated CVariable names may be absent.
            name = getattr(cvar, "name", None) or getattr(variable, "name", None)
            if not isinstance(name, str):
                return False
            # `local_*` / `arg_*` are already materialized stack locals/args even if
            # they still carry generic names. Reject only synthetic carriers/temps.
            if not re.fullmatch(r"(?:s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name):
                return True
            # Dynamic codegen boundary: stack-variable binding metadata is attached by prior CLI passes.
            bindings = getattr(self.codegen, "_inertia_stack_variable_bindings", None)
            offset = variable.offset
            size = variable.size
            if not isinstance(bindings, tuple | list) or not isinstance(offset, int) or not isinstance(size, int):
                return False
            for binding in bindings:
                # Dynamic codegen boundary: legacy stack binding records used both offset names.
                binding_offset = getattr(binding, "bp_offset", None)
                if binding_offset is None:
                    # Dynamic codegen boundary: legacy stack binding records used both offset names.
                    binding_offset = getattr(binding, "offset", None)
                # Dynamic codegen boundary: stack binding records may be external dataclasses.
                binding_size = getattr(binding, "size", None)
                if (
                    isinstance(binding_offset, int)
                    and isinstance(binding_size, int)
                    and binding_size >= 2
                    and binding_offset == offset
                    and size >= 2
                ):
                    return True
            return False

        return _impl()
