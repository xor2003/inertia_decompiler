from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable


@dataclass(frozen=True)
class _SegmentedAccess:
    kind: str
    seg_name: str | None
    assoc_kind: str = "unknown"
    assoc_state: object | None = None
    linear: int | None = None
    cvar: structured_c.CVariable | None = None
    stack_var: SimStackVariable | None = None
    extra_offset: int = 0
    addr_expr: object | None = None

    def allows_object_rewrite(self) -> bool:
        if self.assoc_state is not None and hasattr(self.assoc_state, "is_over_associated"):
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
        return self.assoc_kind == "over"


def _segment_reg_name(node, project, *, project_rewrite_cache):
    cache = project_rewrite_cache(project).setdefault("segment_reg_name", {})
    key = id(node)
    if key in cache:
        return cache[key]

    if not isinstance(node, structured_c.CVariable):
        cache[key] = None
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        cache[key] = None
        return None
    result = project.arch.register_names.get(variable.reg)
    cache[key] = result
    return result


def _classify_segmented_addr_expr(
    node,
    project,
    *,
    project_rewrite_cache,
    flatten_c_add_terms,
    unwrap_c_casts,
    c_constant_value,
    match_stack_cvar_and_offset,
    normalize_16bit_signed_offset,
    stack_slot_identity_for_variable,
):
    cache = project_rewrite_cache(project).setdefault("segmented_addr_expr", {})
    key = id(node)
    if key in cache:
        return cache[key]

    seg_name = None
    cvar = None
    stack_var = None
    const_offset = 0
    other_terms = []
    base_terms = 0
    stack_slots: list[object] = []

    def _synthetic_sp_anchor(term):
        if not isinstance(term, structured_c.CVariable):
            return None
        variable = getattr(term, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            return None
        sp_offset = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))[0]
        if not isinstance(sp_offset, int) or getattr(variable, "reg", None) != sp_offset:
            return None
        codegen = getattr(term, "codegen", None)
        region = getattr(getattr(codegen, "cfunc", None), "addr", None)
        synthetic = SimStackVariable(0, getattr(variable, "size", None) or 2, base="sp", name="sp_0", region=region)
        return structured_c.CVariable(synthetic, variable_type=getattr(term, "variable_type", None), codegen=codegen), 0

    def _synthetic_sp_match(term):
        synthetic = _synthetic_sp_anchor(term)
        if synthetic is not None:
            return synthetic
        if not isinstance(term, structured_c.CBinaryOp) or term.op not in {"Add", "Sub"}:
            return None
        lhs = _synthetic_sp_anchor(unwrap_c_casts(term.lhs))
        rhs = _synthetic_sp_anchor(unwrap_c_casts(term.rhs))
        lhs_const = c_constant_value(unwrap_c_casts(term.lhs))
        rhs_const = c_constant_value(unwrap_c_casts(term.rhs))
        if lhs is not None and rhs_const is not None:
            base, offset = lhs
            return base, offset + (rhs_const if term.op == "Add" else -rhs_const)
        if rhs is not None and lhs_const is not None and term.op == "Add":
            base, offset = rhs
            return base, offset + lhs_const
        return None

    def _segment_scale_name(term) -> str | None:
        if not isinstance(term, structured_c.CBinaryOp):
            return None
        if term.op == "Mul":
            for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                if c_constant_value(unwrap_c_casts(maybe_scale)) != 16:
                    continue
                local_seg = _segment_reg_name(
                    unwrap_c_casts(maybe_seg),
                    project,
                    project_rewrite_cache=project_rewrite_cache,
                )
                if local_seg is not None:
                    return local_seg
            return None
        if term.op == "Shl":
            for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                if c_constant_value(unwrap_c_casts(maybe_scale)) != 4:
                    continue
                local_seg = _segment_reg_name(
                    unwrap_c_casts(maybe_seg),
                    project,
                    project_rewrite_cache=project_rewrite_cache,
                )
                if local_seg is not None:
                    return local_seg
        return None

    for term in flatten_c_add_terms(node):
        inner = unwrap_c_casts(term)
        local_seg = _segment_scale_name(inner)
        if local_seg is not None:
            seg_name = local_seg
            continue

        constant = c_constant_value(inner)
        if constant is not None:
            const_offset += constant
            continue

        matched_stack = match_stack_cvar_and_offset(inner)
        if matched_stack is None:
            matched_stack = _synthetic_sp_match(inner)
        if matched_stack is not None:
            matched_cvar, stack_offset = matched_stack
            stack_offset = normalize_16bit_signed_offset(stack_offset)
            matched_var = getattr(matched_cvar, "variable", None)
            current_var = getattr(cvar, "variable", None) if cvar is not None else None
            if cvar is None:
                cvar = matched_cvar
                if isinstance(matched_var, SimStackVariable):
                    stack_var = matched_var
                    identity = stack_slot_identity_for_variable(matched_var)
                    if identity is not None:
                        if not stack_slots:
                            stack_slots.append(identity)
                        elif stack_slots[0] == identity:
                            pass
                        elif hasattr(stack_slots[0], "can_join") and stack_slots[0].can_join(identity):
                            joined_identity = stack_slots[0].join(identity)
                            if joined_identity is not None:
                                stack_slots[0] = joined_identity
                        else:
                            stack_slots.append(identity)
                const_offset += stack_offset
                base_terms += 1
            elif current_var is matched_var:
                if isinstance(matched_var, SimStackVariable):
                    identity = stack_slot_identity_for_variable(matched_var)
                    if identity is not None:
                        if not stack_slots:
                            stack_slots.append(identity)
                        elif stack_slots[0] == identity:
                            pass
                        elif hasattr(stack_slots[0], "can_join") and stack_slots[0].can_join(identity):
                            joined_identity = stack_slots[0].join(identity)
                            if joined_identity is not None:
                                stack_slots[0] = joined_identity
                        else:
                            stack_slots.append(identity)
                const_offset += stack_offset
                base_terms += 1
            else:
                other_terms.append(term)
            continue

        other_terms.append(term)

    if seg_name is None:
        cache[key] = None
        return None

    assoc_state = _SegmentAssociationState(
        seg_name=seg_name,
        base_terms=base_terms,
        other_terms=len(other_terms),
        const_offset=const_offset,
        stack_slots=tuple(stack_slots),
    )
    assoc_kind = assoc_state.assoc_kind

    if seg_name == "ss" and cvar is not None and not other_terms:
        normalized_offset = normalize_16bit_signed_offset(const_offset)
        result = _SegmentedAccess(
            "stack",
            seg_name,
            assoc_kind=assoc_kind,
            assoc_state=assoc_state,
            cvar=cvar,
            stack_var=stack_var,
            extra_offset=normalized_offset,
            addr_expr=node,
        )
        cache[key] = result
        return result

    if cvar is None and not other_terms:
        if seg_name == "es":
            kind = "extra"
            linear = const_offset
        else:
            kind = "segment_const"
            linear = const_offset
        result = _SegmentedAccess(
            kind,
            seg_name,
            assoc_kind=assoc_kind,
            assoc_state=assoc_state,
            linear=linear,
            extra_offset=const_offset,
            addr_expr=node,
        )
        cache[key] = result
        return result

    result = _SegmentedAccess(
        "unknown",
        seg_name,
        assoc_kind=assoc_kind,
        assoc_state=assoc_state,
        linear=const_offset if cvar is None else None,
        cvar=cvar,
        stack_var=stack_var,
        extra_offset=const_offset,
        addr_expr=node,
    )
    cache[key] = result
    return result


def _classify_segmented_dereference(node, project, *, project_rewrite_cache, classify_segmented_addr_expr):
    cache = project_rewrite_cache(project).setdefault("segmented_dereference_class", {})
    key = id(node)
    if key in cache:
        return cache[key]

    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        cache[key] = None
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        operand = operand.expr
    result = classify_segmented_addr_expr(operand, project)
    cache[key] = result
    return result


def _match_real_mode_linear_expr(node, project, *, project_rewrite_cache, classify_segmented_addr_expr):
    cache = project_rewrite_cache(project).setdefault("real_mode_linear_expr", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = classify_segmented_addr_expr(node, project)
    if classified is None or classified.kind not in {"extra", "segment_const"}:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result


def _match_segmented_dereference(node, project, *, project_rewrite_cache, classify_segmented_dereference):
    cache = project_rewrite_cache(project).setdefault("segmented_dereference", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = classify_segmented_dereference(node, project)
    if classified is None or classified.linear is None:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result
