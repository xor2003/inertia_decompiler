"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable
from archinfo.arch import Arch


class _ProjectLike(Protocol):
    """Project surface needed by segmented pointer elision."""

    arch: Arch


class _CFunctionLike(Protocol):
    """Structured C function surface needed by segmented pointer elision."""

    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by segmented pointer elision."""

    cfunc: _CFunctionLike | None


class _SegmentedDereferenceLike(Protocol):
    """Classified segmented dereference fields consumed by this CLI helper."""

    addr_expr: object | None
    cvar: object | None
    extra_offset: int
    seg_name: str


@dataclass(slots=True)
class _SegmentedDerefElider:
    """Visitor eliding redundant segment-scale dereferences in one cfunc."""

    project: _ProjectLike
    codegen: _CodegenLike
    classify_segmented_dereference: Callable[[object, _ProjectLike], _SegmentedDereferenceLike | None]
    flatten_c_add_terms: Callable[[object], Sequence[object]]
    unwrap_c_casts: Callable[[object], object]
    c_constant_value: Callable[[object], int | None]
    segment_reg_name: Callable[[object, _ProjectLike], str | None]
    match_segment_register_based_dereference: Callable[
        [object, _ProjectLike], tuple[_SegmentedDereferenceLike, object] | None
    ]
    strip_segment_scale_from_addr_expr: Callable[[object, _ProjectLike], object | None]
    same_c_storage: Callable[[object, object], bool]
    iter_c_nodes_deep: Callable[[object], Iterable[object]]
    eligible_bases: dict[int, tuple[structured_c.CVariable, set[int]]] = field(default_factory=dict)

    def _term_is_segment_scale(self, inner: object) -> bool:
        """Return whether one add term is a `segment * 16` scale factor."""
        if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "Mul":
            return False
        for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
            if self.c_constant_value(self.unwrap_c_casts(maybe_scale)) != 16:
                continue
            if self.segment_reg_name(self.unwrap_c_casts(maybe_seg), self.project) is not None:
                return True
        return False

    def _base_terms_of(self, addr_expr: object) -> list[object]:
        """Return the single register base term of one address expression."""
        base_terms: list[object] = []
        for term in self.flatten_c_add_terms(addr_expr):
            inner = self.unwrap_c_casts(term)
            if self._term_is_segment_scale(inner):
                continue

            if self.c_constant_value(inner) is not None:
                continue

            if isinstance(inner, structured_c.CVariable) and isinstance(
                # Dynamic codegen boundary: angr CVariable nodes expose optional SimVariable payloads.
                getattr(inner, "variable", None), SimRegisterVariable
            ):
                base_terms.append(inner)
                continue

            return []

        return base_terms

    def collect_candidate_bases(self, statements: object) -> None:
        """Record register bases whose every use carries a constant offset."""
        for node in self.iter_c_nodes_deep(statements):
            classified = self.classify_segmented_dereference(node, self.project)
            if classified is None or classified.addr_expr is None or classified.seg_name not in {"ds", "es"}:
                continue

            base_terms = self._base_terms_of(classified.addr_expr)
            if len(base_terms) != 1:
                continue
            # Dynamic codegen boundary: CVariable payloads come from angr structured codegen.
            base_var = getattr(base_terms[0], "variable", None)
            if not isinstance(base_var, SimRegisterVariable):
                continue
            entry = self.eligible_bases.get(id(base_var))
            if entry is None:
                self.eligible_bases[id(base_var)] = (base_terms[0], {classified.extra_offset})
            else:
                entry[1].add(classified.extra_offset)

    def _addr_expr_is_safe_projection(self, addr_expr: object) -> bool:
        """Return whether one address expression contains only safe terms."""
        node = self.unwrap_c_casts(addr_expr)
        if self.c_constant_value(node) is not None:
            return True
        if isinstance(node, structured_c.CVariable) and isinstance(
            # Dynamic codegen boundary: angr CVariable nodes expose optional SimVariable payloads.
            getattr(node, "variable", None), SimRegisterVariable
        ):
            return True
        if isinstance(node, structured_c.CUnaryOp) and node.op in {"Neg", "BitNot"}:
            return self._addr_expr_is_safe_projection(node.operand)
        allowed_ops = {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr", "Div"}
        if isinstance(node, structured_c.CBinaryOp) and node.op in allowed_ops:
            return self._addr_expr_is_safe_projection(node.lhs) and self._addr_expr_is_safe_projection(node.rhs)
        return False

    def make_deref(self, base_expr: object, bits: int) -> structured_c.CUnaryOp:
        """Build one typed dereference of the elided base expression."""
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(self.project.arch)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(
                None, ptr_type, cast(structured_c.CExpression, base_expr), codegen=self.codegen
            ),
            codegen=self.codegen,
        )

    def _matched_base_expr(self, node: structured_c.CUnaryOp) -> object | None:
        """Resolve the elidable base expression for one dereference node."""
        match = self.match_segment_register_based_dereference(node, self.project)
        if match is None:
            classified = self.classify_segmented_dereference(node, self.project)
            if classified is None or classified.seg_name not in {"ds", "es"} or classified.addr_expr is None:
                return None
            base_expr = self.strip_segment_scale_from_addr_expr(classified.addr_expr, self.project)
            if base_expr is None or not self._addr_expr_is_safe_projection(base_expr):
                return None
            if classified.cvar is None or not isinstance(base_expr, structured_c.CVariable):
                return None
            if not self.same_c_storage(base_expr, classified.cvar):
                return None
            return base_expr
        _classified, base_expr = match
        # Dynamic codegen boundary: match results may be CVariable-like codegen nodes.
        base_var = getattr(getattr(base_expr, "variable", None), "reg", None)
        if base_var is None:
            return None
        # Dynamic codegen boundary: CVariable payload identity is supplied by angr codegen.
        eligible = self.eligible_bases.get(id(getattr(base_expr, "variable", None)))
        if eligible is None or eligible[1] != {0}:
            return None
        return base_expr

    def transform(self, node: object) -> object:
        """Rewrite one dereference node when its segment scale is redundant."""
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        base_expr = self._matched_base_expr(node)
        if base_expr is None:
            return node
        # Dynamic codegen boundary: CUnaryOp type metadata is optional in angr structured C.
        type_ = getattr(node, "type", None)
        # Dynamic codegen boundary: angr SimType instances expose size only on concrete types.
        bits = getattr(type_, "size", None)
        if bits != 8:
            return node
        return self.make_deref(base_expr, bits)


def _elide_redundant_segment_pointer_dereferences(
    project: _ProjectLike,
    codegen: _CodegenLike,
    *,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    classify_segmented_dereference: Callable[[object, _ProjectLike], _SegmentedDereferenceLike | None],
    flatten_c_add_terms: Callable[[object], Sequence[object]],
    unwrap_c_casts: Callable[[object], object],
    c_constant_value: Callable[[object], int | None],
    segment_reg_name: Callable[[object, _ProjectLike], str | None],
    match_segment_register_based_dereference: Callable[
        [object, _ProjectLike], tuple[_SegmentedDereferenceLike, object] | None
    ],
    strip_segment_scale_from_addr_expr: Callable[[object, _ProjectLike], object | None],
    same_c_storage: Callable[[object, object], bool],
    replace_c_children: Callable[[object, Callable[[object], object]], bool],
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    elider = _SegmentedDerefElider(
        project,
        codegen,
        classify_segmented_dereference,
        flatten_c_add_terms,
        unwrap_c_casts,
        c_constant_value,
        segment_reg_name,
        match_segment_register_based_dereference,
        strip_segment_scale_from_addr_expr,
        same_c_storage,
        iter_c_nodes_deep,
    )
    elider.collect_candidate_bases(cfunc.statements)
    changed = False
    root = cfunc.statements
    new_root = elider.transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, elider.transform):
        changed = True
    return changed
