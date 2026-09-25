"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.postprocess.optimization.local_liveness import (
    local_liveness_key_8616,
    stack_storage_liveness_key_8616,
)
from angr_platforms.X86_16.postprocess.optimization.local_read_keys import collect_local_read_keys_8616

_PURE_GENERATED_HELPER_CALLEES = frozenset(
    {
        "MEM_U8",
        "MEM_U16",
        "MEM_U32",
        "SEG_U8",
        "SEG_U16",
        "SEG_U32",
        "MK_FP",
        "SEG_PTR",
    }
)


class _CFunctionLike(Protocol):
    """Structured C function surface needed by dead-local pruning."""

    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by dead-local pruning."""

    cfunc: _CFunctionLike | None
    _inertia_dead_local_prune_protected_direct_stack_move_count_8616: int
    _inertia_dead_local_prune_walk_refused_complex_8616: int


class _AliasStorageLike(Protocol):
    """Alias-storage summary used to compare local assignment reads."""

    identity: tuple[object, ...] | None


def _call_name(node: structured_c.CFunctionCall) -> str | None:
    target = node.callee_target
    if isinstance(target, str):
        return target
    # Dynamic codegen boundary: callee targets may be function-like payloads.
    target_name = getattr(target, "name", None)
    if isinstance(target_name, str):
        return target_name
    # Dynamic codegen boundary: older structured codegen call nodes expose callee directly.
    callee = getattr(node, "callee", None)
    if isinstance(callee, str):
        return callee
    callee_func = node.callee_func
    if isinstance(callee_func, str):
        return callee_func
    # Dynamic codegen boundary: callee_func may be a function-like object.
    name = getattr(callee_func, "name", None)
    return name if isinstance(name, str) else None


def _expr_has_side_effects(node: object, *, iter_c_nodes_deep: Callable[[object], Iterable[object]]) -> bool:
    for subnode in iter_c_nodes_deep(node):
        if not isinstance(subnode, structured_c.CFunctionCall):
            continue
        if _call_name(subnode) in _PURE_GENERATED_HELPER_CALLEES:
            continue
        return True
    return False


def _stack_variable_offset_8616(variable: object) -> int | None:
    """Return the BP-relative offset for one stack variable."""
    if not isinstance(variable, SimStackVariable):
        return None
    return variable.offset if isinstance(variable.offset, int) else None


def _is_local_variable_8616(variable: object) -> bool:
    """Return whether one codegen variable is a register/stack local."""
    return isinstance(variable, (SimRegisterVariable, SimStackVariable))


def _statement_may_diverge_control_flow_8616(stmt: object) -> bool:
    """Return whether a statement can interrupt fall-through order."""
    control_flow_types = (
        structured_c.CBreak,
        structured_c.CContinue,
        structured_c.CDoWhileLoop,
        structured_c.CForLoop,
        structured_c.CGoto,
        structured_c.CIfBreak,
        structured_c.CIfElse,
        structured_c.CReturn,
        structured_c.CWhileLoop,
    )
    return isinstance(stmt, control_flow_types)


@dataclass(slots=True)
class _DeadLocalPruneRun:
    """State for one dead-local-assignment prune pass over a cfunc."""

    codegen: _CodegenLike
    root: object
    structured_codegen_node: Callable[[object], bool]
    iter_c_nodes_deep: Callable[[object], Iterable[object]]
    unwrap_c_casts: Callable[[object], object]
    describe_alias_storage: Callable[[object], _AliasStorageLike]
    reads: set[tuple[object, ...]]
    protected_stack_offsets: frozenset[int]
    direct_stack_move_protected_keys: set[tuple[object, ...]]
    changed: bool = False
    seen_prune_nodes: set[int] = field(default_factory=set)
    prune_visit_count: int = 0
    max_prune_visits: int = 20000

    def collect_storage_read_keys(
        self,
        node: object,
        keys: set[tuple[object, ...]],
        seen: set[int] | None = None,
        *,
        allow_variable_read: bool = True,
    ) -> None:
        """Delegate read traversal to the structured-C cleanup owner."""
        collect_local_read_keys_8616(
            node, keys, seen, allow_variable_read=allow_variable_read,
            structured_codegen_node=self.structured_codegen_node,
            describe_alias_storage=self.describe_alias_storage,
        )


    def call_callee_key(self, call_expr: structured_c.CFunctionCall) -> tuple[str, object] | None:
        """Return a stable identity key for one call target."""
        callee_target = call_expr.callee_target
        if callee_target is not None:
            return ("target", callee_target)

        callee_func = call_expr.callee_func
        if callee_func is not None:
            # Dynamic codegen boundary: function-like call targets may expose addr.
            callee_addr = getattr(callee_func, "addr", None)
            if callee_addr is not None:
                return ("func_addr", callee_addr)
            # Dynamic codegen boundary: function-like call targets may expose name.
            callee_name = getattr(callee_func, "name", None)
            if callee_name is not None:
                return ("func_name", callee_name)
            return ("func_id", id(callee_func))

        # Dynamic codegen boundary: older structured codegen call nodes expose callee directly.
        callee = getattr(call_expr, "callee", None)
        if isinstance(callee, str):
            return ("callee", callee)
        return None

    def normalized_call_arg_key(self, expr: object) -> tuple[object, ...]:
        """Return a structural identity key for one call argument."""
        expr = self.unwrap_c_casts(expr)
        storage_key = self.describe_alias_storage(expr).identity
        if storage_key is not None:
            return ("storage", storage_key)
        if isinstance(expr, structured_c.CConstant):
            return ("const", expr.value)
        if isinstance(expr, structured_c.CVariable):
            variable = expr.variable
            if isinstance(variable, SimRegisterVariable):
                return ("reg", variable.reg, variable.size)
            if isinstance(variable, SimStackVariable):
                return (
                    "stack",
                    variable.base,
                    variable.offset,
                    variable.size,
                )
            if isinstance(variable, SimMemoryVariable):
                return ("mem", variable.addr, variable.size)
            return ("var", id(variable))
        if isinstance(expr, structured_c.CUnaryOp):
            return ("unary", expr.op, self.normalized_call_arg_key(expr.operand))
        if isinstance(expr, structured_c.CBinaryOp):
            return ("binary", expr.op, self.normalized_call_arg_key(expr.lhs), self.normalized_call_arg_key(expr.rhs))
        if isinstance(expr, structured_c.CFunctionCall):
            return (
                "call",
                self.call_callee_key(expr),
                tuple(self.normalized_call_arg_key(arg) for arg in expr.args or ()),
            )
        return ("expr", type(expr).__name__)

    def same_call_signature(self, lhs: object, rhs: object) -> bool:
        """Return whether two call expressions name the same callee/args."""
        lhs_call = self.unwrap_c_casts(lhs)
        rhs_call = self.unwrap_c_casts(rhs)
        if not isinstance(lhs_call, structured_c.CFunctionCall) or not isinstance(rhs_call, structured_c.CFunctionCall):
            return False
        lhs_key = self.call_callee_key(lhs_call)
        rhs_key = self.call_callee_key(rhs_call)
        if lhs_key is None or rhs_key is None or lhs_key != rhs_key:
            return False
        lhs_args = tuple(self.normalized_call_arg_key(arg) for arg in lhs_call.args or ())
        rhs_args = tuple(self.normalized_call_arg_key(arg) for arg in rhs_call.args or ())
        return lhs_args == rhs_args

    def collect_stmt_reads(self, stmt: object) -> set[tuple[object, ...]]:
        """Return all read keys observed inside one statement."""
        stmt_reads: set[tuple[object, ...]] = set()
        self.collect_storage_read_keys(stmt, stmt_reads)
        return stmt_reads

    def _local_assignment_lhs_keys(
        self, stmt: structured_c.CAssignment
    ) -> set[tuple[object, ...]]:
        """Return every identity key owned by one local assignment lhs."""
        lhs_variable = stmt.lhs.variable
        lhs_unified = stmt.lhs.unified_variable
        lhs_exact_keys: set[tuple[object, ...]] = set()
        if lhs_variable is not None:
            lhs_exact_keys.add(("var", id(lhs_variable)))
        if lhs_unified is not None:
            lhs_exact_keys.add(("unified", id(lhs_unified)))
        lhs_keys = set(lhs_exact_keys)
        storage_key = self.describe_alias_storage(stmt.lhs).identity
        if storage_key is not None:
            lhs_keys.add(("storage", storage_key))
        liveness_key = local_liveness_key_8616(stmt.lhs)
        if liveness_key is not None:
            lhs_keys.add(("liveness", liveness_key))
        if _stack_variable_offset_8616(lhs_variable) in self.protected_stack_offsets:
            physical_key = stack_storage_liveness_key_8616(stmt.lhs)
            if physical_key is not None:
                lhs_keys.add(("physical", physical_key))
        return lhs_keys

    def _bump_protected_direct_stack_move_count(self) -> None:
        """Record one protected direct-stack-move lhs diagnostic."""
        # Dynamic codegen compatibility boundary: diagnostics are attached to the codegen object.
        self.codegen._inertia_dead_local_prune_protected_direct_stack_move_count_8616 = (
            int(
                # Dynamic codegen compatibility boundary: diagnostics are attached to the codegen object.
                getattr(
                    self.codegen,
                    "_inertia_dead_local_prune_protected_direct_stack_move_count_8616",
                    0,
                )
                or 0
            )
            + 1
        )

    def _prune_local_assignment(
        self,
        stmt: structured_c.CAssignment,
        new_statements: list[object | None],
        pending_assignment_indices: dict[tuple[object, ...], int],
    ) -> bool:
        """Handle one local-variable assignment; True when fully consumed."""
        lhs_keys = self._local_assignment_lhs_keys(stmt)
        rhs_reads: set[tuple[object, ...]] = set()
        if self.structured_codegen_node(stmt.rhs):
            self.collect_storage_read_keys(stmt.rhs, rhs_reads)
        protected_direct_stack_move_lhs = bool(
            lhs_keys and not lhs_keys.isdisjoint(self.direct_stack_move_protected_keys)
        )
        if protected_direct_stack_move_lhs:
            self._bump_protected_direct_stack_move_count()
            for key in lhs_keys:
                pending_assignment_indices.pop(key, None)
            self.prune(stmt)
            new_statements.append(stmt)
            return True
        return self._drop_or_keep_dead_assignment(
            stmt, lhs_keys, rhs_reads, new_statements, pending_assignment_indices
        )

    def _drop_or_keep_dead_assignment(
        self,
        stmt: structured_c.CAssignment,
        lhs_keys: set[tuple[object, ...]],
        rhs_reads: set[tuple[object, ...]],
        new_statements: list[object | None],
        pending_assignment_indices: dict[tuple[object, ...], int],
    ) -> bool:
        """Drop a never-read assignment or record it as pending; True = consumed."""
        self_referential_rhs = bool(lhs_keys) and not lhs_keys.isdisjoint(rhs_reads)
        if lhs_keys.isdisjoint(self.reads) and not self_referential_rhs:
            return True
        self._mark_pending_assignment(lhs_keys, new_statements, pending_assignment_indices)
        return False

    def _mark_pending_assignment(
        self,
        lhs_keys: set[tuple[object, ...]],
        new_statements: list[object | None],
        pending_assignment_indices: dict[tuple[object, ...], int],
    ) -> None:
        """Record one still-live assignment and drop its shadowed writers."""
        for key in lhs_keys:
            if key in pending_assignment_indices:
                new_statements[pending_assignment_indices[key]] = None
                self.changed = True
            pending_assignment_indices[key] = len(new_statements)

    def _prune_dirty_assignment(
        self,
        stmt: structured_c.CAssignment,
        new_statements: list[object | None],
        pending_assignment_indices: dict[tuple[object, ...], int],
    ) -> bool:
        """Handle one dirty-expression assignment; True when consumed/dropped."""
        # Dynamic codegen boundary: dirty expressions are external codegen nodes.
        dirty = getattr(stmt.lhs, "dirty", None)
        # Dynamic codegen boundary: dirty metadata fields vary by angr expression.
        dirty_varid = getattr(dirty, "varid", None) if dirty is not None else None
        # Dynamic codegen boundary: dirty metadata fields vary by angr expression.
        dirty_name = getattr(dirty, "name", None) if dirty is not None else None
        lhs_keys: set[tuple[object, ...]] = set()
        if isinstance(dirty_varid, int):
            lhs_keys.add(("dirty_varid", dirty_varid))
        if isinstance(dirty_name, str) and dirty_name:
            lhs_keys.add(("dirty_name", dirty_name))
        if lhs_keys and lhs_keys.isdisjoint(self.reads):
            self.changed = True
            return True
        self._mark_pending_assignment(lhs_keys, new_statements, pending_assignment_indices)
        return False

    def _is_prunable_local_assignment(self, stmt: object) -> bool:
        """Return whether one statement is a side-effect-free local assignment."""
        return (
            isinstance(stmt, structured_c.CAssignment)
            and isinstance(stmt.lhs, structured_c.CVariable)
            and _is_local_variable_8616(stmt.lhs.variable)
            and not _expr_has_side_effects(stmt.rhs, iter_c_nodes_deep=self.iter_c_nodes_deep)
        )

    def _is_prunable_dirty_assignment(self, stmt: object) -> bool:
        """Return whether one statement is a side-effect-free dirty assignment."""
        return (
            isinstance(stmt, structured_c.CAssignment)
            and stmt.lhs.__class__.__name__ == "CDirtyExpression"
            and not _expr_has_side_effects(stmt.rhs, iter_c_nodes_deep=self.iter_c_nodes_deep)
        )

    def _call_shadowed_by_return(
        self, statements: list[object], index: int, stmt: object
    ) -> bool:
        """Return whether a bare call repeats the following return's call."""
        # Dynamic codegen boundary: expression statements expose expr in angr structured C.
        call_expr = stmt if isinstance(stmt, structured_c.CFunctionCall) else getattr(stmt, "expr", None)
        if not isinstance(call_expr, structured_c.CFunctionCall):
            return False
        next_stmt = statements[index + 1] if index + 1 < len(statements) else None
        return (
            isinstance(next_stmt, structured_c.CReturn)
            and isinstance(next_stmt.retval, structured_c.CFunctionCall)
            and self.same_call_signature(call_expr, next_stmt.retval)
        )

    def _prune_statements(self, node: structured_c.CStatements) -> None:
        """Rewrite one statement list, dropping proven-dead assignments."""
        new_statements: list[object | None] = []
        pending_assignment_indices: dict[tuple[object, ...], int] = {}
        statements = list(node.statements)
        for index, stmt in enumerate(statements):
            if self._call_shadowed_by_return(statements, index, stmt):
                self.changed = True
                continue
            stmt_reads = self.collect_stmt_reads(stmt)
            if stmt_reads:
                for key in list(pending_assignment_indices):
                    if key in stmt_reads:
                        pending_assignment_indices.pop(key, None)
            if _statement_may_diverge_control_flow_8616(stmt):
                pending_assignment_indices.clear()
            if self._is_prunable_local_assignment(stmt) and self._prune_local_assignment(
                stmt, new_statements, pending_assignment_indices
            ):
                continue
            if self._is_prunable_dirty_assignment(stmt) and self._prune_dirty_assignment(
                stmt, new_statements, pending_assignment_indices
            ):
                continue
            self.prune(stmt)
            new_statements.append(stmt)
        if new_statements != list(node.statements):
            node.statements = [stmt for stmt in new_statements if stmt is not None]
            self.changed = True

    def _prune_scalar_children(self, node: object) -> None:
        """Recurse into single-child node attributes."""
        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "body",
            "iffalse",
            "iftrue",
            "else_node",
            "retval",
        ):
            if not hasattr(node, attr):
                continue
            try:
                # Dynamic codegen boundary: child field names vary across angr C AST nodes.
                value = getattr(node, attr)
            except Exception:
                continue
            if self.structured_codegen_node(value):
                self.prune(value)

    def _prune_sequence_children(self, node: object) -> None:
        """Recurse into sequence-valued node attributes."""
        for attr in ("args", "operands", "statements"):
            if not hasattr(node, attr):
                continue
            try:
                # Dynamic codegen boundary: child sequence fields vary across angr C AST nodes.
                items = getattr(node, attr)
            except Exception:
                continue
            if not items:
                continue
            for item in items:
                if self.structured_codegen_node(item):
                    self.prune(item)

    def _prune_condition_pairs(self, node: object) -> None:
        """Recurse into CIfElse-like condition/body pairs."""
        if hasattr(node, "condition_and_nodes"):
            try:
                # Dynamic codegen boundary: CIfElse-like nodes may expose condition/body pairs.
                pairs = node.condition_and_nodes
            except Exception:
                pairs = None
            if pairs:
                for cond, body in pairs:
                    if self.structured_codegen_node(cond):
                        self.prune(cond)
                    if self.structured_codegen_node(body):
                        self.prune(body)

    def prune(self, node: object) -> None:
        """Prune one node and its structured children."""
        if not self.structured_codegen_node(node):
            return
        marker = id(node)
        if marker in self.seen_prune_nodes:
            return
        self.seen_prune_nodes.add(marker)
        self.prune_visit_count += 1
        if self.prune_visit_count > self.max_prune_visits:
            # Dynamic codegen compatibility boundary: diagnostics are attached to the codegen object.
            self.codegen._inertia_dead_local_prune_walk_refused_complex_8616 = (
                # Dynamic codegen compatibility boundary: diagnostics are attached to the codegen object.
                int(getattr(self.codegen, "_inertia_dead_local_prune_walk_refused_complex_8616", 0) or 0) + 1
            )
            return

        if isinstance(node, structured_c.CStatements):
            self._prune_statements(node)
            return

        self._prune_scalar_children(node)
        self._prune_sequence_children(node)
        self._prune_condition_pairs(node)


def _direct_stack_move_protected_offsets(codegen: _CodegenLike) -> frozenset[int]:
    """Collect stack offsets protected by direct-stack-move evidence."""
    protected: set[int] = set()
    # Dynamic codegen compatibility boundary: this counter is attached by the CLI orchestration pass.
    for record in tuple(getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ()):
        if isinstance(record, Mapping):
            values = record
        else:
            try:
                values = dict(record)
            except (TypeError, ValueError):
                continue
        offset = values.get("dst_offset")
        if isinstance(offset, int):
            protected.add(offset)
    return frozenset(protected)


def _direct_stack_move_protected_keys(
    root: object,
    reads: set[tuple[object, ...]],
    protected_stack_offsets: frozenset[int],
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> set[tuple[object, ...]]:
    """Return read-backed keys for variables at protected stack offsets."""
    protected_keys: set[tuple[object, ...]] = set()
    if not protected_stack_offsets:
        return protected_keys
    for node in iter_c_nodes_deep(root):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = node.variable
        if _stack_variable_offset_8616(variable) not in protected_stack_offsets:
            continue
        node_keys: set[tuple[object, ...]] = {("var", id(variable))}
        unified = node.unified_variable
        if unified is not None:
            node_keys.add(("unified", id(unified)))
        storage_key = describe_alias_storage(node).identity
        if storage_key is not None:
            node_keys.add(("storage", storage_key))
        liveness_key = local_liveness_key_8616(node)
        if liveness_key is not None:
            node_keys.add(("liveness", liveness_key))
        if not node_keys.isdisjoint(reads):
            protected_keys.update(node_keys)
            physical_key = stack_storage_liveness_key_8616(node)
            if physical_key is not None:
                protected_keys.add(("physical", physical_key))
    return protected_keys


def _prune_dead_local_assignments(
    codegen: _CodegenLike,
    *,
    structured_codegen_node: Callable[[object], bool],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    unwrap_c_casts: Callable[[object], object],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> bool:
    """Prune local assignments using read keys from the cleanup owner."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return False
    root = cfunc.statements
    if not structured_codegen_node(root):
        return False

    reads: set[tuple[object, ...]] = set()
    collect_local_read_keys_8616(
        root, reads, None,
        structured_codegen_node=structured_codegen_node,
        describe_alias_storage=describe_alias_storage,
    )

    protected_stack_offsets = _direct_stack_move_protected_offsets(codegen)
    protected_keys = _direct_stack_move_protected_keys(
        root,
        reads,
        protected_stack_offsets,
        iter_c_nodes_deep=iter_c_nodes_deep,
        describe_alias_storage=describe_alias_storage,
    )

    run = _DeadLocalPruneRun(
        codegen=codegen,
        root=root,
        structured_codegen_node=structured_codegen_node,
        iter_c_nodes_deep=iter_c_nodes_deep,
        unwrap_c_casts=unwrap_c_casts,
        describe_alias_storage=describe_alias_storage,
        reads=reads,
        protected_stack_offsets=protected_stack_offsets,
        direct_stack_move_protected_keys=protected_keys,
    )
    run.prune(root)
    return run.changed
