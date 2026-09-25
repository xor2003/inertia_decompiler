"""Classify and lower typed segmented-address C AST carriers.

Layer: Types/Lowering.
Responsibility: typed segmented-address classification and SS/DS/ES lowering helpers.
Consumes alias, widening, and typed facts to classify SS/DS/ES address forms
before materialization.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, MutableMapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from .physical_registers import physical_register_name_8616, physical_register_view_8616
from .segment_register_state import runtime_segment_name_for_variable_8616

type _CacheMap8616 = MutableMapping[str, MutableMapping[int, object]]
type _ProjectRewriteCache8616 = Callable[[object], _CacheMap8616]
type _UnaryObjectCallback8616 = Callable[[object], object]
type _ConstantValueCallback8616 = Callable[[object], int | None]
type _NormalizeOffsetCallback8616 = Callable[[object], int]
type _StackMatchCallback8616 = Callable[[object], tuple[object, object] | None]
type _StackIdentityCallback8616 = Callable[[SimStackVariable], object | None]


class _ArchRegisterNames8616(Protocol):
    """Minimal project.arch contract needed for segmented lowering."""

    register_names: Mapping[int, str]


class _ProjectArch8616(Protocol):
    """Minimal project contract needed for segmented lowering."""

    arch: _ArchRegisterNames8616


@runtime_checkable
class _JoinableStackIdentity8616(Protocol):
    """Owned stack-slot identity contract that can merge compatible slots."""

    def can_join(self, other: object) -> bool:
        """Return whether this identity can join with another identity."""
        ...

    def join(self, other: object) -> object | None:
        """Return the joined identity when compatible."""
        ...


def _dynamic_c_attr_8616(obj: object | None, name: str, default: object | None = None) -> object | None:
    """Dynamic third-party angr/codegen boundary: read optional C AST attributes."""
    if obj is None:
        return default
    try:
        # Dynamic third-party angr/codegen boundary: C AST nodes expose optional attributes by shape.
        return getattr(obj, name, default)
    except Exception:
        return default


@dataclass(frozen=True)
class _SegmentedAccess:
    kind: str
    seg_name: str | None
    assoc_kind: str = "unknown"
    assoc_state: _SegmentAssociationState | None = None
    linear: int | None = None
    cvar: structured_c.CVariable | None = None
    stack_var: SimStackVariable | None = None
    extra_offset: int = 0
    addr_expr: object | None = None

    def allows_object_rewrite(self) -> bool:
        """Return whether this classified access may be rewritten as an object access."""
        if self.assoc_state is not None:
            return not self.assoc_state.is_over_associated()
        return self.assoc_kind != "over"


@dataclass(frozen=True)
class _SegmentAssociationState:
    seg_name: str | None
    base_terms: int = 0
    other_terms: int = 0
    const_offset: int = 0
    stack_slots: tuple[object, ...] = ()

    @property
    def assoc_kind(self) -> str:
        """Return the segment association classification for this address expression."""
        if self.seg_name is None:
            return "unknown"
        if len(self.stack_slots) > 1:
            return "over"
        if self.base_terms == 0:
            return "const" if self.other_terms == 0 else "over"
        if self.other_terms > 0:
            return "over"
        return "single"

    def is_over_associated(self) -> bool:
        """Return whether the expression mixes segment identity with unrelated terms."""
        return self.assoc_kind == "over"


def _merge_stack_slot_identity_8616(stack_slots: list[object], identity: object | None) -> None:
    if identity is None:
        return
    if not stack_slots:
        stack_slots.append(identity)
        return
    if stack_slots[0] == identity:
        return
    existing = stack_slots[0]
    if isinstance(existing, _JoinableStackIdentity8616) and existing.can_join(identity):
        joined_identity = existing.join(identity)
        if joined_identity is not None:
            stack_slots[0] = joined_identity
        return
    stack_slots.append(identity)


def _segment_reg_name(
    node: object,
    project: _ProjectArch8616,
    *,
    project_rewrite_cache: _ProjectRewriteCache8616,
) -> str | None:
    cache = project_rewrite_cache(project).setdefault("segment_reg_name", {})
    key = id(node)
    if key in cache:
        cached = cache[key]
        return cached if isinstance(cached, str) else None

    result = None
    if isinstance(node, structured_c.CVariable):
        result = runtime_segment_name_for_variable_8616(node.variable)
    if result is None:
        reg_offset = _register_offset_for_node_8616(node)
        result = project.arch.register_names.get(reg_offset) if isinstance(reg_offset, int) else None
    cache[key] = result
    return result


def _register_offset_for_node_8616(node: object) -> int | None:
    """Return an exact physical-register offset from one structured-C node."""
    register_view = physical_register_view_8616(node)
    if register_view is not None:
        reg_offset = register_view.reg_offset
        return reg_offset if isinstance(reg_offset, int) else None
    if isinstance(node, structured_c.CVariable):
        variable = _dynamic_c_attr_8616(node, "variable")
        if isinstance(variable, SimRegisterVariable):
            reg = _dynamic_c_attr_8616(variable, "reg")
            return int(reg) if isinstance(reg, int) else None
    if type(node).__name__ == "CDirtyExpression":
        dirty = _dynamic_c_attr_8616(node, "dirty")
        for attr in ("reg_offset", "reg"):
            reg = _dynamic_c_attr_8616(dirty, attr)
            if isinstance(reg, int):
                return int(reg)
    return None


def _register_size_for_node_8616(node: object) -> int | None:
    """Return an exact physical-register width in bytes from one structured-C node."""
    register_view = physical_register_view_8616(node)
    if register_view is not None:
        width = register_view.width
        return width if isinstance(width, int) else None
    if isinstance(node, structured_c.CVariable):
        variable = _dynamic_c_attr_8616(node, "variable")
        size = _dynamic_c_attr_8616(variable, "size")
        return int(size) if isinstance(size, int) else None
    if type(node).__name__ == "CDirtyExpression":
        dirty = _dynamic_c_attr_8616(node, "dirty")
        size = _dynamic_c_attr_8616(dirty, "size")
        if isinstance(size, int):
            return int(size)
        bits = _dynamic_c_attr_8616(dirty, "bits")
        if isinstance(bits, int) and bits > 0:
            return max(1, int(bits) // 8)
    return None


def _iter_statement_nodes_8616(root: object) -> Iterator[structured_c.CConstruct]:
    """Yield all C constructs under one root via the dynamic codegen boundary."""
    stack = [root]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if not isinstance(current, structured_c.CConstruct):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        stack.extend(_c_child_nodes_8616(current))


def _c_child_nodes_8616(current: object) -> list[object]:
    """Return the known child nodes of one C construct."""
    children: list[object] = []
    nested_statements = _dynamic_c_attr_8616(current, "statements")
    if isinstance(nested_statements, (list, tuple)):
        children.extend(reversed(tuple(nested_statements)))
    body = _dynamic_c_attr_8616(current, "body")
    if body is not None:
        children.append(body)
    else_node = _dynamic_c_attr_8616(current, "else_node")
    if else_node is not None:
        children.append(else_node)
    condition_and_nodes = _dynamic_c_attr_8616(current, "condition_and_nodes")
    if isinstance(condition_and_nodes, (list, tuple)):
        for pair in reversed(tuple(condition_and_nodes)):
            if isinstance(pair, tuple):
                children.extend(reversed(pair))
    return children


def _same_assignment_lhs_8616(
    lhs: object,
    *,
    term_var: object,
    term_name: object,
    term_reg: object,
    term_size: object,
) -> bool:
    """Return whether a candidate lhs names the same variable identity."""
    if not isinstance(lhs, structured_c.CVariable):
        return False
    lhs_var = _dynamic_c_attr_8616(lhs, "variable")
    if lhs_var is term_var:
        return True
    lhs_name = _dynamic_c_attr_8616(lhs, "name") or _dynamic_c_attr_8616(lhs_var, "name")
    if isinstance(term_name, str) and term_name and lhs_name == term_name:
        return True
    lhs_reg = _dynamic_c_attr_8616(lhs_var, "reg")
    lhs_size = _dynamic_c_attr_8616(lhs_var, "size")
    return (
        isinstance(term_reg, int)
        and isinstance(term_size, int)
        and isinstance(lhs_reg, int)
        and isinstance(lhs_size, int)
        and lhs_reg == term_reg
        and lhs_size == term_size
    )


def _single_assignment_rhs_for_cvar_8616(term: object) -> object | None:
    """Return the unique single-assignment rhs for a CVariable, or None."""
    if not isinstance(term, structured_c.CVariable):
        return None
    term_var = _dynamic_c_attr_8616(term, "variable")
    term_name = _dynamic_c_attr_8616(term, "name") or _dynamic_c_attr_8616(term_var, "name")
    term_reg = _dynamic_c_attr_8616(term_var, "reg")
    term_size = _dynamic_c_attr_8616(term_var, "size")
    codegen = _dynamic_c_attr_8616(term, "codegen")
    cfunc = _dynamic_c_attr_8616(codegen, "cfunc")
    root = _dynamic_c_attr_8616(cfunc, "statements")
    if root is None:
        return None

    matches: list[object] = []
    for stmt in _iter_statement_nodes_8616(root):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        if not _same_assignment_lhs_8616(
            _dynamic_c_attr_8616(stmt, "lhs"),
            term_var=term_var, term_name=term_name, term_reg=term_reg, term_size=term_size,
        ):
            continue
        matches.append(_dynamic_c_attr_8616(stmt, "rhs"))
        if len(matches) > 1:
            return None
    return matches[0] if len(matches) == 1 else None


@dataclass
class _SegmentedAddrClassifier8616:
    """Mutable classify state for one segmented-address expression."""

    project: _ProjectArch8616
    project_rewrite_cache: _ProjectRewriteCache8616
    unwrap_c_casts: _UnaryObjectCallback8616
    c_constant_value: _ConstantValueCallback8616
    match_stack_cvar_and_offset: _StackMatchCallback8616
    normalize_16bit_signed_offset: _NormalizeOffsetCallback8616
    stack_slot_identity_for_variable: _StackIdentityCallback8616
    seg_name: str | None = None
    cvar: object | None = None
    stack_var: SimStackVariable | None = None
    const_offset: int = 0
    other_terms: list[object] = field(default_factory=list)
    base_terms: int = 0
    stack_slots: list[object] = field(default_factory=list)
    resolved_term_cache: dict[int, object] = field(default_factory=dict)

    def _synthetic_sp_anchor(self, term: object) -> tuple[structured_c.CVariable, int] | None:
        """Return a synthetic sp/bp stack-slot anchor for one term."""
        reg_name = physical_register_name_8616(term)
        if reg_name not in {"bp", "sp"}:
            return None
        codegen = _dynamic_c_attr_8616(term, "codegen")
        cfunc = _dynamic_c_attr_8616(codegen, "cfunc")
        region = _dynamic_c_attr_8616(cfunc, "addr")
        synthetic = SimStackVariable(
            0,
            _register_size_for_node_8616(term) or 2,
            base=reg_name,
            name=f"{reg_name}_0",
            region=region if isinstance(region, int) else None,
        )
        return structured_c.CVariable(
            synthetic, variable_type=_dynamic_c_attr_8616(term, "variable_type"), codegen=codegen
        ), 0

    def _synthetic_sp_match(self, term: object) -> tuple[structured_c.CVariable, int] | None:
        """Return a synthetic sp/bp match for one term or binary add/sub."""
        synthetic = self._synthetic_sp_anchor(term)
        if synthetic is not None:
            return synthetic
        if not isinstance(term, structured_c.CBinaryOp) or term.op not in {"Add", "Sub"}:
            return None
        lhs = self._synthetic_sp_anchor(self.unwrap_c_casts(term.lhs))
        rhs = self._synthetic_sp_anchor(self.unwrap_c_casts(term.rhs))
        lhs_const = self.c_constant_value(self.unwrap_c_casts(term.lhs))
        rhs_const = self.c_constant_value(self.unwrap_c_casts(term.rhs))
        if lhs is not None and rhs_const is not None:
            base, offset = lhs
            return base, offset + (rhs_const if term.op == "Add" else -rhs_const)
        if rhs is not None and lhs_const is not None and term.op == "Add":
            base, offset = rhs
            return base, offset + lhs_const
        return None

    def _segment_scale_name(self, term: object) -> str | None:
        """Return the segment name for a *16 or <<4 scaled term."""
        if not isinstance(term, structured_c.CBinaryOp):
            return None
        if term.op == "Mul":
            for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                if self.c_constant_value(self.unwrap_c_casts(maybe_scale)) != 16:
                    continue
                local_seg = _segment_reg_name(
                    self.unwrap_c_casts(maybe_seg),
                    self.project,
                    project_rewrite_cache=self.project_rewrite_cache,
                )
                if local_seg is not None:
                    return local_seg
            return None
        if term.op == "Shl":
            for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                if self.c_constant_value(self.unwrap_c_casts(maybe_scale)) != 4:
                    continue
                local_seg = _segment_reg_name(
                    self.unwrap_c_casts(maybe_seg),
                    self.project,
                    project_rewrite_cache=self.project_rewrite_cache,
                )
                if local_seg is not None:
                    return local_seg
        return None

    def _constant_term_value(self, term: object) -> int | None:
        """Fold one term into a constant value when possible."""
        term = self.unwrap_c_casts(term)
        constant = self.c_constant_value(term)
        if constant is not None:
            return constant
        if not isinstance(term, structured_c.CBinaryOp) or term.op not in {"Add", "Sub"}:
            return None
        lhs = self._constant_term_value(term.lhs)
        rhs = self._constant_term_value(term.rhs)
        if lhs is None or rhs is None:
            return None
        return lhs + rhs if term.op == "Add" else lhs - rhs

    def _resolve_term_aliases(self, term: object) -> object:
        """Resolve single-assignment aliases for one term."""
        current = self.unwrap_c_casts(term)
        seen_ids: set[int] = set()
        while isinstance(current, structured_c.CVariable):
            key = id(current)
            if key in self.resolved_term_cache:
                return self.resolved_term_cache[key]
            if key in seen_ids:
                break
            seen_ids.add(key)
            rhs = _single_assignment_rhs_for_cvar_8616(current)
            if rhs is None:
                break
            rhs_unwrapped = self.unwrap_c_casts(rhs)
            if rhs_unwrapped is current:
                break
            self.resolved_term_cache[key] = rhs_unwrapped
            current = rhs_unwrapped
        return current

    def _consume_stack_match(
        self,
        matched_cvar: object,
        stack_offset: object,
        term: object,
    ) -> tuple[bool, object | None, SimStackVariable | None, int, int]:
        """Consume one matched stack view, updating the base state."""
        stack_offset = self.normalize_16bit_signed_offset(stack_offset)
        if not isinstance(matched_cvar, structured_c.CVariable):
            return False, self.cvar, self.stack_var, 0, 0
        matched_var = _dynamic_c_attr_8616(matched_cvar, "variable")
        current_var = _dynamic_c_attr_8616(self.cvar, "variable") if self.cvar is not None else None
        if self.cvar is None:
            self.cvar = matched_cvar
            if isinstance(matched_var, SimStackVariable):
                self.stack_var = matched_var
                _merge_stack_slot_identity_8616(
                    self.stack_slots, self.stack_slot_identity_for_variable(matched_var),
                )
            return True, self.cvar, self.stack_var, stack_offset, 1
        if current_var is matched_var:
            if isinstance(matched_var, SimStackVariable):
                _merge_stack_slot_identity_8616(
                    self.stack_slots, self.stack_slot_identity_for_variable(matched_var),
                )
            return True, self.cvar, self.stack_var, stack_offset, 1
        self.other_terms.append(term)
        return False, self.cvar, self.stack_var, 0, 0

    def consume_term(self, term: object) -> None:
        """Fold one add-term into the classification state."""
        inner = self._resolve_term_aliases(term)
        local_seg = self._segment_scale_name(inner)
        if local_seg is not None:
            self.seg_name = local_seg
            return
        constant = self._constant_term_value(inner)
        if constant is not None:
            self.const_offset += constant
            return
        matched_stack = self.match_stack_cvar_and_offset(inner) or self._synthetic_sp_match(inner)
        if matched_stack is not None:
            consumed, _cvar, _stack_var, offset_delta, base_delta = self._consume_stack_match(
                matched_stack[0], matched_stack[1], term
            )
            self.const_offset += offset_delta
            self.base_terms += base_delta
            if consumed:
                return
        self.other_terms.append(term)

    def build_result(self, node: object) -> _SegmentedAccess | None:
        """Build the classified access from the consumed state."""
        if self.seg_name is None:
            return None

        assoc_state = _SegmentAssociationState(
            seg_name=self.seg_name,
            base_terms=self.base_terms,
            other_terms=len(self.other_terms),
            const_offset=self.const_offset,
            stack_slots=tuple(self.stack_slots),
        )
        assoc_kind = assoc_state.assoc_kind

        if self.seg_name == "ss" and self.cvar is not None and not self.other_terms:
            normalized_offset = self.normalize_16bit_signed_offset(self.const_offset)
            return _SegmentedAccess(
                "stack",
                self.seg_name,
                assoc_kind=assoc_kind,
                assoc_state=assoc_state,
                cvar=self.cvar,
                stack_var=self.stack_var,
                extra_offset=normalized_offset,
                addr_expr=node,
            )

        if self.cvar is None and not self.other_terms:
            if self.seg_name == "es":
                kind = "extra"
                linear = self.const_offset
            else:
                kind = "segment_const"
                linear = self.const_offset
            return _SegmentedAccess(
                kind,
                self.seg_name,
                assoc_kind=assoc_kind,
                assoc_state=assoc_state,
                linear=linear,
                extra_offset=self.const_offset,
                addr_expr=node,
            )

        return _SegmentedAccess(
            "unknown",
            self.seg_name,
            assoc_kind=assoc_kind,
            assoc_state=assoc_state,
            linear=self.const_offset if self.cvar is None else None,
            cvar=self.cvar,
            stack_var=self.stack_var,
            extra_offset=self.const_offset,
            addr_expr=node,
        )


def _classify_segmented_addr_expr(
    node: object,
    project: _ProjectArch8616,
    *,
    project_rewrite_cache: _ProjectRewriteCache8616,
    flatten_c_add_terms: Callable[[object], Iterable[object]],
    unwrap_c_casts: _UnaryObjectCallback8616,
    c_constant_value: _ConstantValueCallback8616,
    match_stack_cvar_and_offset: _StackMatchCallback8616,
    normalize_16bit_signed_offset: _NormalizeOffsetCallback8616,
    stack_slot_identity_for_variable: _StackIdentityCallback8616,
) -> _SegmentedAccess | None:
    cache = project_rewrite_cache(project).setdefault("segmented_addr_expr", {})
    key = id(node)
    if key in cache:
        cached = cache[key]
        return cached if isinstance(cached, _SegmentedAccess) else None

    classifier = _SegmentedAddrClassifier8616(
        project=project,
        project_rewrite_cache=project_rewrite_cache,
        unwrap_c_casts=unwrap_c_casts,
        c_constant_value=c_constant_value,
        match_stack_cvar_and_offset=match_stack_cvar_and_offset,
        normalize_16bit_signed_offset=normalize_16bit_signed_offset,
        stack_slot_identity_for_variable=stack_slot_identity_for_variable,
    )
    for term in flatten_c_add_terms(node):
        classifier.consume_term(term)
    result = classifier.build_result(node)
    cache[key] = result
    return result


def _classify_segmented_dereference(
    node: object,
    project: _ProjectArch8616,
    *,
    project_rewrite_cache: _ProjectRewriteCache8616,
    classify_segmented_addr_expr: Callable[[object, _ProjectArch8616], _SegmentedAccess | None],
) -> _SegmentedAccess | None:
    cache = project_rewrite_cache(project).setdefault("segmented_dereference_class", {})
    key = id(node)
    if key in cache:
        cached = cache[key]
        return cached if isinstance(cached, _SegmentedAccess) else None

    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        cache[key] = None
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        operand = operand.expr
    result = classify_segmented_addr_expr(operand, project)
    cache[key] = result
    return result


def _match_real_mode_linear_expr(
    node: object,
    project: _ProjectArch8616,
    *,
    project_rewrite_cache: _ProjectRewriteCache8616,
    classify_segmented_addr_expr: Callable[[object, _ProjectArch8616], _SegmentedAccess | None],
) -> tuple[str | None, int | None]:
    cache = project_rewrite_cache(project).setdefault("real_mode_linear_expr", {})
    key = id(node)
    if key in cache:
        cached = cache[key]
        return cached if isinstance(cached, tuple) and len(cached) == 2 else (None, None)

    classified = classify_segmented_addr_expr(node, project)
    if classified is None or classified.kind not in {"extra", "segment_const"}:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result


def _match_segmented_dereference(
    node: object,
    project: _ProjectArch8616,
    *,
    project_rewrite_cache: _ProjectRewriteCache8616,
    classify_segmented_dereference: Callable[[object, _ProjectArch8616], _SegmentedAccess | None],
) -> tuple[str | None, int | None]:
    cache = project_rewrite_cache(project).setdefault("segmented_dereference", {})
    key = id(node)
    if key in cache:
        cached = cache[key]
        return cached if isinstance(cached, tuple) and len(cached) == 2 else (None, None)

    classified = classify_segmented_dereference(node, project)
    if classified is None or classified.linear is None:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result
