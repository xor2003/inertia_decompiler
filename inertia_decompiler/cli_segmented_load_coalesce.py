"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c


class _CFunctionLike(Protocol):
    """Structured C function surface needed by segmented load coalescing."""

    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by segmented load coalescing."""

    cfunc: _CFunctionLike | None


class _AliasStorageLike(Protocol):
    """Alias-storage summary needed for adjacent byte-load proof."""

    identity: tuple[object, ...] | None

    def can_join(self, other: object) -> bool:
        """Return whether two byte-load storage facts prove one joined word."""
        ...


class _SegmentedAddrClassLike(Protocol):
    """Segmented-address classification surface used by this CLI helper."""

    kind: str


@dataclass(slots=True)
class _SegmentedWordLoadCoalescer:
    """Visitor folding adjacent byte loads into one segmented word load."""

    project: object
    codegen: _CodegenLike
    unwrap_c_casts: Callable[[object], object]
    structured_codegen_node: Callable[[object], bool]
    match_byte_load_addr_expr: Callable[[object], object | None]
    match_shifted_high_byte_addr_expr: Callable[[object], object | None]
    addr_exprs_are_byte_pair: Callable[[object, object, object], bool]
    classify_segmented_addr_expr: Callable[[object, object], _SegmentedAddrClassLike | None]
    resolve_stack_cvar_from_addr_expr: Callable[[object, _CodegenLike, object], object | None]
    make_word_dereference_from_addr_expr: Callable[[_CodegenLike, object, object], object]
    describe_alias_storage: Callable[[object], _AliasStorageLike]
    dereferenced_variable_ids: set[int] = field(default_factory=set)

    def _collect_variable_ids(self, expr: object, ids: set[int]) -> None:
        """Collect backend variable identities referenced by one expression."""
        expr = self.unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            # Dynamic codegen boundary: angr structured C variable nodes expose optional payloads.
            variable = getattr(expr, "variable", None)
            if variable is not None:
                ids.add(id(variable))
            return
        for attr in ("lhs", "rhs", "operand", "expr"):
            # Dynamic codegen boundary: angr C AST node shapes vary by expression class.
            if not hasattr(expr, attr):
                continue
            try:
                # Dynamic codegen boundary: child access is guarded by the C AST node shape.
                value = getattr(expr, attr)
            except Exception:
                continue
            if self.structured_codegen_node(value):
                self._collect_variable_ids(value, ids)
        self._collect_sequence_variable_ids(expr, ids)

    def _collect_sequence_variable_ids(self, expr: object, ids: set[int]) -> None:
        """Collect variable identities from sequence-valued node attributes."""
        for attr in ("args", "operands", "statements"):
            # Dynamic codegen boundary: statement containers are node-specific in angr C ASTs.
            if not hasattr(expr, attr):
                continue
            try:
                # Dynamic codegen boundary: sequence payloads are guarded by the C AST node shape.
                items = getattr(expr, attr)
            except Exception:
                continue
            for item in items or ():
                if self.structured_codegen_node(item):
                    self._collect_variable_ids(item, ids)

    def _try_join_byte_pair(
        self, low_expr: object, high_expr: object
    ) -> object | None:
        """Return the joined word expression for one proven byte pair."""
        low_addr_expr = self.match_byte_load_addr_expr(self.unwrap_c_casts(low_expr))
        if low_addr_expr is None:
            return None

        high_addr_expr = self.match_shifted_high_byte_addr_expr(high_expr)
        if high_addr_expr is None:
            return None

        low_facts = self.describe_alias_storage(low_addr_expr)
        high_facts = self.describe_alias_storage(high_addr_expr)
        if low_facts.identity is None or high_facts.identity is None:
            return None
        if not low_facts.can_join(high_facts):
            return None

        low_addr_ids: set[int] = set()
        high_addr_ids: set[int] = set()
        self._collect_variable_ids(low_addr_expr, low_addr_ids)
        self._collect_variable_ids(high_addr_expr, high_addr_ids)
        if low_addr_ids & self.dereferenced_variable_ids or high_addr_ids & self.dereferenced_variable_ids:
            return None

        if self.addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, self.project):
            resolved_lhs = self.resolve_stack_cvar_from_addr_expr(self.project, self.codegen, low_addr_expr)
            low_class = self.classify_segmented_addr_expr(low_addr_expr, self.project)
            if resolved_lhs is not None and (low_class is None or low_class.kind != "stack"):
                return resolved_lhs
            return self.make_word_dereference_from_addr_expr(self.codegen, self.project, low_addr_expr)
        return None

    def transform(self, node: object) -> object:
        """Rewrite one Or/Add byte-pair node into a word load when proven."""
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            joined = self._try_join_byte_pair(low_expr, high_expr)
            if joined is not None:
                return joined

        return node


def _coalesce_segmented_word_load_expressions(
    project: object,
    codegen: _CodegenLike,
    *,
    unwrap_c_casts: Callable[[object], object],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    replace_c_children: Callable[[object, Callable[[object], object]], bool],
    structured_codegen_node: Callable[[object], bool],
    match_byte_load_addr_expr: Callable[[object], object | None],
    match_shifted_high_byte_addr_expr: Callable[[object], object | None],
    addr_exprs_are_byte_pair: Callable[[object, object, object], bool],
    classify_segmented_addr_expr: Callable[[object, object], _SegmentedAddrClassLike | None],
    resolve_stack_cvar_from_addr_expr: Callable[[object, _CodegenLike, object], object | None],
    make_word_dereference_from_addr_expr: Callable[[_CodegenLike, object, object], object],
    describe_alias_storage: Callable[[object], _AliasStorageLike],
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    coalescer = _SegmentedWordLoadCoalescer(
        project,
        codegen,
        unwrap_c_casts,
        structured_codegen_node,
        match_byte_load_addr_expr,
        match_shifted_high_byte_addr_expr,
        addr_exprs_are_byte_pair,
        classify_segmented_addr_expr,
        resolve_stack_cvar_from_addr_expr,
        make_word_dereference_from_addr_expr,
        describe_alias_storage,
    )

    for walk_node in iter_c_nodes_deep(cfunc.statements):
        if isinstance(walk_node, structured_c.CUnaryOp) and walk_node.op == "Dereference":
            # Dynamic codegen boundary: CUnaryOp operand is supplied by angr structured codegen.
            coalescer._collect_variable_ids(
                getattr(walk_node, "operand", None), coalescer.dereferenced_variable_ids
            )

    changed = False
    root = cfunc.statements
    new_root = coalescer.transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        changed = True

    if replace_c_children(root, coalescer.transform):
        changed = True
    return changed
