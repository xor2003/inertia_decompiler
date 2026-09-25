"""Layer: Rewrite/Postprocess cleanup.

Responsibility: prune adjacent temporary or dead register copy carriers after their value has moved.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Set
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CConstant, CFunctionCall, CStatements, CVariable
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from ...decompiler_postprocess_utils import _iter_c_nodes_deep_8616

__all__ = ["prune_adjacent_temporary_copy_assignments_8616"]

type TrivialCopyKey8616 = tuple[object, ...]


class TrivialCopyCodegen8616(Protocol):
    """Dynamic codegen contract for trivial-copy cleanup counters and CFunction root."""

    cfunc: object
    trivial_copy_candidates_8616: int
    trivial_copy_pruned_8616: int
    trivial_copy_dead_temp_to_local_pruned_8616: int
    trivial_copy_refused_live_temp_8616: int


_TRIVIAL_COPY_COUNTERS_8616 = (
    "trivial_copy_candidates_8616",
    "trivial_copy_pruned_8616",
    "trivial_copy_dead_temp_to_local_pruned_8616",
    "trivial_copy_refused_live_temp_8616",
)


def _ensure_trivial_copy_counters_8616(typed_codegen: TrivialCopyCodegen8616) -> None:
    """Initialize dynamic codegen boundary diagnostic counters."""
    for name in _TRIVIAL_COPY_COUNTERS_8616:
        try:
            value = getattr(typed_codegen, name)
        except AttributeError:
            setattr(typed_codegen, name, 0)
        else:
            if not isinstance(value, int):
                setattr(typed_codegen, name, 0)


def _is_temporary_name_8616(name: str | None) -> bool:
    """Return whether a dynamic angr/codegen variable name is a generated temporary."""
    return isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_"))


def _is_generic_local_name_8616(name: str | None) -> bool:
    """Return whether a dynamic angr/codegen variable name is a generic local."""
    return isinstance(name, str) and name.startswith(("local_", "arg_"))


@dataclass
class _TrivialCopyWalk8616:
    """State and helpers for one trivial-copy prune walk over a C AST."""

    typed_codegen: TrivialCopyCodegen8616
    debug: bool
    log: logging.Logger
    changed: bool = False
    seen_statement_lists: set[int] = field(default_factory=set)

    def _debug_expr(self, expr: object) -> tuple[str, str | None, str | None]:
        """Render one dynamic boundary: third-party angr AST node for diagnostics."""
        c_repr = getattr(expr, "c_repr", None)
        if not callable(c_repr):
            return type(expr).__name__, None, None
        try:
            rendered = c_repr()
        except Exception:
            return type(expr).__name__, None, None
        dirty = getattr(expr, "dirty", None)
        return (
            type(expr).__name__,
            rendered if isinstance(rendered, str) else None,
            repr(dirty) if dirty is not None else None,
        )

    def _variable_name(self, expr: object) -> str | None:
        """Return variable names from a dynamic boundary: angr codegen C AST nodes."""
        if expr.__class__.__name__ == "CDirtyExpression":
            c_repr = getattr(expr, "c_repr", None)
            if callable(c_repr):
                rendered = c_repr()
                return rendered if isinstance(rendered, str) and rendered else None
            idx = getattr(expr, "idx", None)
            return idx if isinstance(idx, str) and idx else None
        if not isinstance(expr, CVariable):
            return None
        name = expr.name
        if isinstance(name, str) and name:
            return name
        variable = expr.variable
        name = getattr(variable, "name", None)
        return name if isinstance(name, str) and name else None

    def _temporary_key(self, expr: object) -> TrivialCopyKey8616 | None:
        """Return temporary identity keys from a dynamic boundary: angr codegen C AST nodes."""
        if expr.__class__.__name__ == "CDirtyExpression":
            name = self._variable_name(expr)
            return ("dirty", name) if _is_temporary_name_8616(name) else None
        if isinstance(expr, CVariable):
            name = self._variable_name(expr)
            if _is_temporary_name_8616(name):
                return ("temp_name", name)
            variable = expr.variable
            if isinstance(variable, SimRegisterVariable):
                return ("register", variable.reg, variable.size, getattr(expr, "offset", None))
            if variable is not None:
                return ("var", id(variable), getattr(expr, "offset", None))
            return ("name", name) if _is_temporary_name_8616(name) else None
        return None

    def _is_generated_temporary_lvalue(self, expr: object) -> bool:
        """Return whether a dynamic angr/codegen lvalue is a generated temporary."""
        if expr.__class__.__name__ == "CDirtyExpression":
            return _is_temporary_name_8616(self._variable_name(expr))
        return isinstance(expr, CVariable) and (
            _is_temporary_name_8616(self._variable_name(expr))
            or isinstance(expr.variable, SimRegisterVariable)
        )

    def _is_local_non_temp_lvalue(self, expr: object) -> bool:
        """Return stack-local status from a dynamic boundary: angr codegen C AST variables."""
        name = self._variable_name(expr)
        if not isinstance(expr, CVariable) or _is_temporary_name_8616(name) or not _is_generic_local_name_8616(name):
            return False
        variable = getattr(expr, "variable", None)
        if isinstance(variable, SimStackVariable):
            offset = variable.offset
            base = variable.base
            return base == "bp" and isinstance(offset, int) and offset >= 0
        return False

    def _same_variable(self, left: object, right: object) -> bool:
        """Compare variables from a dynamic boundary: angr codegen C AST nodes."""
        left_key = self._temporary_key(left)
        right_key = self._temporary_key(right)
        if left_key is not None or right_key is not None:
            return left_key == right_key
        if not isinstance(left, CVariable) or not isinstance(right, CVariable):
            return False
        return getattr(left, "variable", None) is getattr(right, "variable", None) and getattr(
            left, "offset", None
        ) == getattr(right, "offset", None)

    @staticmethod
    def _rhs_is_movable(expr: object) -> bool:
        """Classify movable RHS expressions from a dynamic boundary: angr codegen C AST."""
        if isinstance(expr, CFunctionCall):
            return True
        for attr in ("lhs", "rhs", "operand", "expr"):
            child = getattr(expr, attr, None)
            if isinstance(child, CFunctionCall):
                return False
        return True

    def _temporary_keys_in_node(self, node: object) -> set[TrivialCopyKey8616]:
        """Collect temporary keys from a dynamic boundary: angr codegen C AST subtree."""
        keys: set[TrivialCopyKey8616] = set()
        key = self._temporary_key(node)
        if key is not None:
            keys.add(key)
        for child in _iter_c_nodes_deep_8616(node):
            child_key = self._temporary_key(child)
            if child_key is not None:
                keys.add(child_key)
        return keys

    def _suffix_temporary_keys(self, statements: list[object]) -> list[set[TrivialCopyKey8616]]:
        """Build suffix key sets from a dynamic boundary: angr codegen statement lists."""
        suffix: list[set[TrivialCopyKey8616]] = [set() for _ in range(len(statements) + 1)]
        running: set[TrivialCopyKey8616] = set()
        for index in range(len(statements) - 1, -1, -1):
            running = running | self._temporary_keys_in_node(statements[index])
            suffix[index] = running
        return suffix

    def _references_temporary_key(self, node: object, key: TrivialCopyKey8616) -> bool:
        """Return whether a subtree references one temporary key."""
        return key in self._temporary_keys_in_node(node)

    def _pure_generated_setup_between_copy(self, stmt: CAssignment, lhs_key: TrivialCopyKey8616) -> bool:
        """Classify setup statements from a dynamic boundary: angr codegen assignments."""
        stmt_lhs = getattr(stmt, "lhs", None)
        stmt_rhs = getattr(stmt, "rhs", None)
        stmt_lhs_key = self._temporary_key(stmt_lhs)
        return (
            stmt_lhs_key is not None
            and self._is_generated_temporary_lvalue(stmt_lhs)
            and stmt_lhs_key != lhs_key
            and not self._references_temporary_key(stmt_rhs, lhs_key)
            and not isinstance(stmt_rhs, CFunctionCall)
            and self._rhs_is_movable(stmt_rhs)
        )

    def _find_consumer_index(
        self,
        statements: list[object],
        start_idx: int,
        lhs_key: TrivialCopyKey8616,
        rhs: object,
    ) -> int | None:
        """Find immediate consumers in a dynamic boundary: angr codegen statement list."""
        if not isinstance(rhs, CConstant):
            return start_idx + 1
        idx = start_idx + 1
        while idx < len(statements):
            candidate = statements[idx]
            if not isinstance(candidate, CAssignment):
                return None
            candidate_lhs = candidate.lhs
            candidate_rhs = candidate.rhs
            if (
                not _is_temporary_name_8616(self._variable_name(candidate_lhs))
                and self._temporary_key(candidate_rhs) == lhs_key
            ):
                return idx
            if not self._pure_generated_setup_between_copy(candidate, lhs_key):
                return None
            idx += 1
        return None

    def _dead_temp_to_local_assignment(
        self,
        stmt: CAssignment,
        idx: int,
        suffix_keys: list[set[TrivialCopyKey8616]],
        live_out_keys: Set[TrivialCopyKey8616],
    ) -> bool:
        """Classify dead temp-to-local assignments from a dynamic boundary: angr codegen C AST."""
        lhs = getattr(stmt, "lhs", None)
        rhs = getattr(stmt, "rhs", None)
        lhs_key = self._temporary_key(lhs)
        return (
            lhs_key is not None
            and self._is_local_non_temp_lvalue(lhs)
            and lhs_key not in suffix_keys[idx + 1]
            and lhs_key not in live_out_keys
            and self._temporary_key(rhs) is not None
            and self._rhs_is_movable(rhs)
        )

    def _dead_temp_to_local(
        self,
        stmt: object,
        idx: int,
        suffix_keys: list[set[TrivialCopyKey8616]],
        live_out_keys: Set[TrivialCopyKey8616],
    ) -> bool:
        """Delete one proven dead temp-to-local assignment."""
        if not isinstance(stmt, CAssignment) or not self._dead_temp_to_local_assignment(
            stmt, idx, suffix_keys, live_out_keys
        ):
            return False
        if self.debug:
            self.log.warning(
                "[trivial-copy] dead-temp-to-local candidate lhs=%r rhs=%r "
                "lhs_expr=%r rhs_expr=%r",
                self._variable_name(stmt.lhs),
                self._variable_name(stmt.rhs),
                self._debug_expr(stmt.lhs),
                self._debug_expr(stmt.rhs),
            )
        self.typed_codegen.trivial_copy_dead_temp_to_local_pruned_8616 += 1
        self.changed = True
        return True

    def _debug_copy_candidate_8616(
        self,
        stmt: CAssignment,
        next_stmt: object,
        lhs_key: TrivialCopyKey8616,
    ) -> None:
        """Emit the detailed copy-candidate debug record."""
        lhs = stmt.lhs
        rhs = stmt.rhs
        next_lhs = getattr(next_stmt, "lhs", None)
        next_rhs = getattr(next_stmt, "rhs", None)
        self.log.warning(
            "[trivial-copy] candidate producer_lhs=%r producer_rhs=%r "
            "consumer_lhs=%r consumer_rhs=%r producer_key=%r consumer_key=%r "
            "producer_variable=%#x consumer_variable=%#x "
            "producer_lhs_expr=%r producer_rhs_expr=%r consumer_lhs_expr=%r "
            "consumer_rhs_expr=%r",
            self._variable_name(lhs),
            getattr(rhs, "value", None),
            self._variable_name(next_lhs),
            self._variable_name(next_rhs),
            lhs_key,
            self._temporary_key(next_rhs),
            id(getattr(lhs, "variable", None)),
            id(getattr(next_rhs, "variable", None)),
            self._debug_expr(lhs),
            self._debug_expr(rhs),
            self._debug_expr(next_lhs),
            self._debug_expr(next_rhs),
        )

    def _materialize_copy_fold_8616(
        self,
        statements: list[object],
        idx: int,
        consumer_idx: int,
        next_stmt: CAssignment,
        rhs: object,
        lhs_key: TrivialCopyKey8616,
        suffix_keys: list[set[TrivialCopyKey8616]],
        live_out_keys: Set[TrivialCopyKey8616],
        pruned: list[object],
    ) -> int:
        """Splice a producer value into its consumer and return the next index."""
        for skipped_idx, skipped in enumerate(
            statements[idx + 1 : consumer_idx], start=idx + 1
        ):
            self._walk_structural_children(
                skipped, live_out_keys | suffix_keys[skipped_idx + 1]
            )
            pruned.append(skipped)
        next_stmt.rhs = rhs
        pruned.append(next_stmt)
        self.typed_codegen.trivial_copy_pruned_8616 += 1
        if self.debug:
            self.log.warning("[trivial-copy] materialized producer_key=%r", lhs_key)
        self.changed = True
        return consumer_idx + 1

    def _copy_pair_arm(
        self,
        statements: list[object],
        idx: int,
        suffix_keys: list[set[TrivialCopyKey8616]],
        live_out_keys: Set[TrivialCopyKey8616],
        statement_live_out: Set[TrivialCopyKey8616],
        pruned: list[object],
    ) -> int | None:
        """Fold a producer/consumer copy pair; return the next index or None."""
        stmt = statements[idx]
        if idx + 1 >= len(statements) or not isinstance(stmt, CAssignment):
            return None
        lhs = stmt.lhs
        rhs = stmt.rhs
        lhs_key = self._temporary_key(lhs)
        if (
            lhs_key is None
            or not self._is_generated_temporary_lvalue(lhs)
            or not self._rhs_is_movable(rhs)
        ):
            return None
        consumer_idx = self._find_consumer_index(statements, idx, lhs_key, rhs)
        if consumer_idx is None or consumer_idx >= len(statements):
            return None
        next_stmt = statements[consumer_idx]
        next_lhs = getattr(next_stmt, "lhs", None) if isinstance(next_stmt, CAssignment) else None
        next_rhs = getattr(next_stmt, "rhs", None) if isinstance(next_stmt, CAssignment) else None
        if not (
            isinstance(next_stmt, CAssignment)
            and not _is_temporary_name_8616(self._variable_name(next_lhs))
            and self._same_variable(lhs, next_rhs)
        ):
            return None
        self.typed_codegen.trivial_copy_candidates_8616 += 1
        if self.debug:
            self._debug_copy_candidate_8616(stmt, next_stmt, lhs_key)
        if lhs_key in live_out_keys or lhs_key in suffix_keys[consumer_idx + 1]:
            self.typed_codegen.trivial_copy_refused_live_temp_8616 += 1
            if self.debug:
                self.log.warning("[trivial-copy] refused-live producer_key=%r", lhs_key)
            self._walk_structural_children(stmt, statement_live_out)
            pruned.append(stmt)
            return idx + 1
        return self._materialize_copy_fold_8616(
            statements, idx, consumer_idx, next_stmt, rhs, lhs_key, suffix_keys, live_out_keys, pruned
        )

    def _walk_statement_list(
        self,
        statements: list[object],
        live_out_keys: Set[TrivialCopyKey8616] = frozenset(),
    ) -> None:
        """Rewrite one statement list from a dynamic boundary: angr codegen C AST."""
        list_id = id(statements)
        if list_id in self.seen_statement_lists:
            return
        self.seen_statement_lists.add(list_id)
        suffix_keys = self._suffix_temporary_keys(statements)

        pruned: list[object] = []
        idx = 0
        while idx < len(statements):
            stmt = statements[idx]
            statement_live_out = live_out_keys | suffix_keys[idx + 1]
            if self._dead_temp_to_local(stmt, idx, suffix_keys, live_out_keys):
                idx += 1
                continue
            next_idx = self._copy_pair_arm(
                statements, idx, suffix_keys, live_out_keys, statement_live_out, pruned
            )
            if next_idx is not None:
                idx = next_idx
                continue
            self._walk_structural_children(stmt, statement_live_out)
            pruned.append(stmt)
            idx += 1
        if len(pruned) != len(statements):
            statements[:] = pruned

    def _walk_switch_cases_8616(self, node: object, live_out_keys: Set[TrivialCopyKey8616]) -> None:
        """Walk switch-case bodies from a dynamic angr/codegen boundary node."""
        cases = cast(Iterable[tuple[object, object]], getattr(node, "cases", ()) or ())
        for _case_value, case_body in tuple(cases):
            self._walk_structural_children(case_body, live_out_keys)

    def _walk_structural_children(
        self,
        node: object,
        live_out_keys: Set[TrivialCopyKey8616] = frozenset(),
    ) -> None:
        """Walk structural children from a dynamic boundary: angr codegen C AST nodes."""
        if node is None:
            return
        node_type = type(node).__name__
        if isinstance(node, CStatements):
            self._walk_statement_list(cast(list[object], node.statements), live_out_keys)
            return
        if node_type == "CSwitchCase":
            self._walk_switch_cases_8616(node, live_out_keys)
            self._walk_structural_children(getattr(node, "default", None), live_out_keys)
            return
        if node_type == "CIncompleteSwitchCase":
            self._walk_switch_cases_8616(node, live_out_keys)
            return
        if node_type == "CIfElse":
            condition_nodes = cast(Iterable[tuple[object, object]], getattr(node, "condition_and_nodes", ()) or ())
            for _condition, child in tuple(condition_nodes):
                self._walk_structural_children(child, live_out_keys)
            self._walk_structural_children(getattr(node, "else_node", None), live_out_keys)
            return
        if node_type in {"CWhileLoop", "CDoWhileLoop", "CForLoop"}:
            loop_live_out = set(live_out_keys)
            loop_live_out.update(self._temporary_keys_in_node(getattr(node, "condition", None)))
            loop_live_out.update(self._temporary_keys_in_node(getattr(node, "iteration", None)))
            self._walk_structural_children(getattr(node, "body", None), loop_live_out)


def prune_adjacent_temporary_copy_assignments_8616(codegen: object) -> bool:
    """Fold dead copy carriers across a dynamic boundary: angr codegen C AST."""
    typed_codegen = cast(TrivialCopyCodegen8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return False
    _ensure_trivial_copy_counters_8616(typed_codegen)
    walk = _TrivialCopyWalk8616(
        typed_codegen=typed_codegen,
        debug=os.environ.get("INERTIA_DEBUG_TRIVIAL_COPY") == "1",
        log=logging.getLogger(__name__),
    )
    walk._walk_structural_children(getattr(cfunc, "statements", None))
    return walk.changed
