"""Implement stack-slot and C-variable lowering from typed alias evidence.

Layer: Types/Lowering.
Responsibility: materialize stack-slot C variables from alias-proven stack evidence.
Consumes alias, widening, and typed facts to resolve stable stack carriers into
named stack variables.
Do not recover semantics from COD, source, assembly, or rendered C text.
Dynamic boundary: dynamic attribute access in this legacy module is limited to
angr structured-C and codegen compatibility surfaces; avoidable owned-contract
getattr/setattr is cleanup debt and must be removed when touching nearby code.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import typing
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable

from ..alias.alias_model_impl import AliasStorageFacts, _StackSlotIdentity
from ..structured_tags import copy_structured_tags_8616
from .call_return_stack_bindings import bind_call_return_stack_assignment_8616
from .segmented_lowering import _SegmentedAccess
from .semantic_cast import CSemanticCast8616
from .stack_c_ast_matching import _match_bp_stack_dereference_8616
from .stack_variable_binding import (
    StackBaseBpBiasEvidence8616,
    StackVariableBinding,
    stack_binding_from_tags_8616,
)
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    stack_cvar_for_machine_bp_range_8616,
)

log: logging.Logger = logging.getLogger(__name__)


_LINEAR_TEMP_NAME_RE_8616 = re.compile(r"(?:v\d+|vvar_\d+|ir_\d+|tmp_\d+)")


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


def _is_generic_stack_name_text_8616(name: object) -> bool:
    base = _strip_typed_suffix_8616(name)
    if base is None:
        return False
    return re.fullmatch(r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", base) is not None


def _canonical_stack_offset_8616(offset: object) -> object:
    if not isinstance(offset, int):
        return offset
    if 0x8000 <= offset <= 0xFFFF:
        return offset - 0x10000
    return offset


def _typed_alias_fact_bp_offsets_8616(facts: object) -> set[int]:
    """Return BP-relative stack offsets from typed alias facts."""
    if not isinstance(facts, list):
        return set()
    offsets: set[int] = set()
    for fact in facts:
        if not isinstance(fact, AliasStorageFacts):
            continue
        identity = fact.identity
        if not (isinstance(identity, tuple) and len(identity) >= 2 and identity[0] == "stack"):
            continue
        slot = identity[1]
        if not isinstance(slot, _StackSlotIdentity):
            continue
        if slot.base != "bp":
            continue
        offset = _canonical_stack_offset_8616(slot.offset)
        if isinstance(offset, int):
            offsets.add(offset)
    return offsets


def _safe_sim_type_size_bits(type_obj: object) -> int | None:
    if type_obj is None:
        return None

    raw_size = getattr(type_obj, "_size", None)
    if isinstance(raw_size, int) and raw_size >= 0:
        return raw_size * 8

    arch = getattr(type_obj, "_arch", None)
    if arch is None:
        return None

    try:
        size = cast(Any, type_obj).size
    except Exception:
        return None
    return size if isinstance(size, int) else None


def _structured_c_codegen_owner_8616(node: object) -> object | None:
    """Return the dynamic structured-C codegen owner carried by an angr C AST node."""
    # dynamic-boundary: angr structured-C expression nodes expose ``codegen``
    # dynamically; owned Inertia contracts must continue to use dot access.
    return getattr(node, "codegen", None)


def _dynamic_int_counter_8616(owner: object, name: str) -> int:
    """Read a runtime compatibility counter from an angr-owned object."""
    # dynamic-boundary: compatibility counters are attached to angr codegen
    # objects by optional passes and are absent before the pass runs.
    return int(getattr(cast(Any, owner), name, 0) or 0)


def _bind_expr_types_to_project_arch_8616(
    node: object,
    codegen: object,
    seen: set[int] | None = None,
) -> None:
    """Bind live structured-expression types before current angr combines them."""
    arch = getattr(getattr(codegen, "project", None), "arch", None)
    if arch is None or node is None:
        return
    if seen is None:
        seen = set()
    node_id = id(node)
    if node_id in seen:
        return
    seen.add(node_id)

    if isinstance(node, structured_c.CVariable):
        variable_type = node.variable_type
        if (
            variable_type is not None
            and getattr(variable_type, "_arch", None) is None
            and hasattr(variable_type, "with_arch")
        ):
            node.variable_type = variable_type.with_arch(arch)
    elif isinstance(node, structured_c.CExpression):
        with contextlib.suppress(Exception):
            expression_type = node.type
            if (
                expression_type is not None
                and getattr(expression_type, "_arch", None) is None
                and hasattr(expression_type, "with_arch")
            ):
                node.set_type(expression_type.with_arch(arch))

    _bind_expr_child_types_8616(node, codegen, seen)

def _bind_expr_child_types_8616(node: object, codegen: object, seen: set[int]) -> None:
    """Recurse into a structured-C node's child expressions and sequences."""
    for attr in (
        "lhs",
        "rhs",
        "operand",
        "expr",
        "variable",
        "index",
        "condition",
        "cond",
        "retval",
    ):
        with contextlib.suppress(Exception):
            child = getattr(node, attr, None)
        if child is not None:
            _bind_expr_types_to_project_arch_8616(child, codegen, seen)

    for attr in ("args", "operands", "statements"):
        with contextlib.suppress(Exception):
            seq = getattr(node, attr, None)
        if not isinstance(seq, (list, tuple)):
            continue
        for item in seq:
            _bind_expr_types_to_project_arch_8616(item, codegen, seen)


def _debug_stack_condition_rebind_8616(
    codegen: object,
    before: object,
    after: object,
    *,
    note: str,
) -> None:
    def _impl() -> None:
        before_dynamic = cast(Any, before)
        after_dynamic = cast(Any, after)
        if not os.environ.get("INERTIA_DEBUG_STACK_CONDITION_CANON"):
            return
        cfunc = getattr(codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
        delta = getattr(getattr(codegen, "project", None), "_inertia_original_linear_delta", None)
        original = func_addr + delta if isinstance(func_addr, int) and isinstance(delta, int) else func_addr
        target_text = os.environ.get("INERTIA_DEBUG_STACK_CONDITION_CANON_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and original != target_addr:
            return
        try:
            before_text = before_dynamic.c_repr(indent=0)
        except Exception:
            before_text = str(before)
        try:
            after_text = after_dynamic.c_repr(indent=0)
        except Exception:
            after_text = str(after)
        log.warning(
            "[stack-condition-canon] function=%#x note=%s before=%r after=%r",
            original or -1,
            note,
            before_text,
            after_text,
        )

    return _impl()


def _is_generic_stack_name_8616(name: object) -> bool:
    return _is_generic_stack_name_text_8616(name)


def _sole_bound_stack_cvar_8616(
    codegen: object,
    resolve_stack_cvar_at_offset: Callable[[object, int], object],
) -> object | None:
    bindings = getattr(codegen, "_inertia_stack_variable_bindings", None)
    if not isinstance(bindings, tuple) or len(bindings) != 1:
        return None
    binding = bindings[0]
    if not isinstance(binding, StackVariableBinding):
        return None
    offset = _canonical_stack_offset_8616(binding.bp_offset)
    if not isinstance(offset, int):
        return None
    resolved = resolve_stack_cvar_at_offset(codegen, offset)
    if isinstance(resolved, structured_c.CVariable) and isinstance(
        getattr(resolved, "variable", None), SimStackVariable
    ):
        return cast(object | None, resolved)
    return None


def _sole_named_stack_cvar_8616(codegen: object) -> object | None:
    def _impl() -> object | None:
        cfunc = getattr(codegen, "cfunc", None)
        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if not isinstance(variables_in_use, dict):
            return None
        arg_variable_ids = {
            id(getattr(arg, "variable", None))
            for arg in getattr(cfunc, "arg_list", ()) or ()
            if getattr(arg, "variable", None) is not None
        }
        candidates = []
        for variable, cvar in variables_in_use.items():
            if not isinstance(variable, SimStackVariable):
                continue
            if id(variable) in arg_variable_ids:
                continue
            name = getattr(cvar, "name", None) or variable.name
            if _is_generic_stack_name_8616(name):
                continue
            candidates.append(cvar)
        return candidates[0] if len(candidates) == 1 else None

    return _impl()


def _prefer_bound_stack_cvar_8616(
    codegen: object,
    resolved: object,
    resolve_stack_cvar_at_offset: Callable[[object, int], object],
) -> object:
    """Prefer a named binding only when it identifies the same stack slot."""
    if not isinstance(resolved, structured_c.CVariable):
        return resolved
    variable = resolved.variable
    if not isinstance(variable, SimStackVariable):
        return resolved
    bound = _bound_cvar_for_stack_var_8616(codegen, variable)
    if bound is not None:
        return bound
    name = resolved.name or variable.name
    if not _is_generic_stack_name_8616(name):
        return resolved
    fallback = _sole_bound_stack_cvar_8616(codegen, resolve_stack_cvar_at_offset)
    if fallback is None:
        fallback = _sole_named_stack_cvar_8616(codegen)
    if fallback is None or fallback is resolved:
        return resolved
    fallback_var = getattr(fallback, "variable", None)
    if not isinstance(fallback_var, SimStackVariable):
        return resolved
    if (
        fallback_var.base != variable.base
        or _canonical_stack_offset_8616(fallback_var.offset) != _canonical_stack_offset_8616(variable.offset)
        or fallback_var.size != variable.size
    ):
        return resolved
    fallback_name = getattr(fallback, "name", None) or fallback_var.name
    if _is_generic_stack_name_8616(fallback_name):
        return resolved
    return fallback

def _bound_cvar_for_stack_var_8616(codegen: object, variable: Any) -> object | None:
    """Return the bound cvar identifying the same stack slot as `variable`, if any."""
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        bound = variables_in_use.get(variable)
        if isinstance(bound, structured_c.CVariable):
            return cast(object, bound)
        var_base = variable.base
        var_offset = variable.offset
        var_size = variable.size
        if isinstance(var_offset, int):
            for candidate_var, candidate_cvar in variables_in_use.items():
                if not isinstance(candidate_var, SimStackVariable) or not isinstance(
                    candidate_cvar, structured_c.CVariable
                ):
                    continue
                if (
                    getattr(candidate_var, "base", None) == var_base
                    and getattr(candidate_var, "offset", None) == var_offset
                    and getattr(candidate_var, "size", None) == var_size
                ):
                    return cast(object, candidate_cvar)
    return None



def _record_stack_canonicalization_bridge_8616(
    codegen: object,
    *,
    expr: object,
    resolved_offset: int,
    kind: str,
) -> None:
    if codegen is None or not isinstance(resolved_offset, int):
        return
    codegen_dynamic = cast(Any, codegen)
    bridges = getattr(codegen_dynamic, "_inertia_stack_canonicalization_bridges", None)
    if not isinstance(bridges, dict):
        bridges = {}
        codegen_dynamic._inertia_stack_canonicalization_bridges = bridges
    unwrapped_expr = _local_unwrap_casts_8616(expr)
    indexed = _indexed_bridge_operand_8616(unwrapped_expr, kind)
    if indexed is None:
        return
    indexed_dynamic = cast(Any, indexed)
    base_ref = _local_unwrap_casts_8616(indexed_dynamic.variable)
    if not (isinstance(base_ref, structured_c.CUnaryOp) and base_ref.op == "Reference"):
        return
    base_var_expr = _local_unwrap_casts_8616(base_ref.operand)
    base_var = getattr(base_var_expr, "variable", None)
    index_expr = _local_unwrap_casts_8616(indexed_dynamic.index)
    index_value = getattr(index_expr, "value", None)
    if not isinstance(base_var, SimStackVariable) or not isinstance(index_value, int):
        return
    bridges[(kind, id(base_var), index_value)] = resolved_offset

def _local_unwrap_casts_8616(node: object) -> object:
    """Strip CTypeCast wrappers without touching semantic casts."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node

def _indexed_bridge_operand_8616(unwrapped_expr: object, kind: str) -> object | None:
    """Return the indexed operand carrying the bridge for a supported kind."""
    if kind == "indexed_deref":
        if not (
            isinstance(unwrapped_expr, structured_c.CUnaryOp)
            and unwrapped_expr.op == "Dereference"
            and isinstance(_local_unwrap_casts_8616(unwrapped_expr.operand), structured_c.CIndexedVariable)
        ):
            return None
        return _local_unwrap_casts_8616(unwrapped_expr.operand)
    if kind == "indexed_value":
        if not isinstance(unwrapped_expr, structured_c.CIndexedVariable):
            return None
        return cast(object, unwrapped_expr)
    return None



def _preferred_stack_name_8616(variable: object, cvar: object) -> str | None:
    variable_name = getattr(variable, "name", None)
    cvar_name = getattr(cvar, "name", None)
    unified_name = getattr(getattr(cvar, "unified_variable", None), "name", None)
    return next(
        (
            name
            for name in (variable_name, cvar_name, unified_name)
            if isinstance(name, str) and name and not _is_generic_stack_name_8616(name)
        ),
        None,
    )


def _build_stack_resolution_context_8616(
    codegen: object,
    stack_slot_identity_for_variable: Callable[[object], object],
) -> tuple[list[tuple[object, object]], set[int], set[object]]:
    codegen_dynamic = cast(Any, codegen)
    arg_list = tuple(getattr(codegen_dynamic.cfunc, "arg_list", ()) or ())
    arg_candidates: list[tuple[object, object]] = []
    arg_variable_ids = {
        id(getattr(arg, "variable", None)) for arg in arg_list if getattr(arg, "variable", None) is not None
    }
    arg_slot_identities = {
        stack_slot_identity_for_variable(getattr(arg, "variable", None))
        for arg in arg_list
        if isinstance(getattr(arg, "variable", None), SimStackVariable)
    }
    arg_slot_identities.discard(None)
    for arg in arg_list:
        variable = getattr(arg, "variable", None)
        if isinstance(variable, SimStackVariable):
            arg_candidates.append((variable, arg))
    return arg_candidates, arg_variable_ids, arg_slot_identities


def _stack_candidate_score_8616(
    variable: object,
    cvar: object,
    *,
    exact: bool,
    preferred_size: int | None,
    stack_slot_identity_for_variable: Callable[[object], object],
    arg_variable_ids: set[int],
    arg_slot_identities: set[object],
) -> tuple[int, int, int, int, int, int]:
    def _impl() -> tuple[int, int, int, int, int, int]:
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            return (-1, -1, -1, -1, -1, -1)
        preferred_name = _preferred_stack_name_8616(variable, cvar)
        is_arg_variable = 1 if id(variable) in arg_variable_ids else 0
        is_arg_slot = 1 if identity in arg_slot_identities else 0
        has_preferred_name = 1 if preferred_name is not None else 0
        size = getattr(variable, "size", None)
        type_size = _safe_sim_type_size_bits(getattr(cvar, "variable_type", None))
        if isinstance(preferred_size, int) and preferred_size > 0 and isinstance(size, int):
            preferred_bits = preferred_size * 8
            if size == preferred_size:
                size_rank = 3
            elif size > preferred_size:
                size_rank = 2
            else:
                size_rank = 1
            if type_size == preferred_bits:
                type_rank = 3
            elif isinstance(type_size, int) and type_size > preferred_bits:
                type_rank = 2
            else:
                type_rank = 1
            preferred_rank = min(size_rank, type_rank)
            name_rank = has_preferred_name
        else:
            size_rank = -size if isinstance(size, int) else 0
            preferred_rank = has_preferred_name
            name_rank = size_rank
        exact_rank = 1 if exact else 0
        canonical_offset = _canonical_stack_offset_8616(getattr(variable, "offset", 0))
        offset_rank = -canonical_offset if exact and isinstance(canonical_offset, int) else canonical_offset
        if not isinstance(offset_rank, int):
            offset_rank = 0
        return (exact_rank, is_arg_variable, is_arg_slot, preferred_rank, name_rank, offset_rank)

    return _impl()


def _resolve_stack_cvar_at_offset(
    codegen: object,
    offset: int,
    *,
    stack_slot_identity_for_variable: Callable[[object], object],
    preferred_size: int | None = None,
) -> object | None:
    codegen_dynamic = cast(Any, codegen)
    if getattr(codegen_dynamic, "cfunc", None) is None:
        return None
    canonical_offset = _canonical_stack_offset_8616(offset)
    if not isinstance(canonical_offset, int):
        return None

    arg_candidates, arg_variable_ids, arg_slot_identities = _build_stack_resolution_context_8616(
        codegen, stack_slot_identity_for_variable
    )
    candidates = list(arg_candidates)
    candidates.extend(list(getattr(codegen_dynamic.cfunc, "variables_in_use", {}).items()))

    best_exact, best_covering = _best_stack_cvar_candidates_8616(
        candidates,
        canonical_offset,
        preferred_size=preferred_size,
        stack_slot_identity_for_variable=stack_slot_identity_for_variable,
        arg_variable_ids=arg_variable_ids,
        arg_slot_identities=arg_slot_identities,
    )
    if best_exact is not None:
        return cast(object, best_exact[1])
    return cast(object | None, best_covering[1] if best_covering is not None else None)

def _best_stack_cvar_candidates_8616(
    candidates: list[tuple[Any, Any]],
    offset: int,
    *,
    preferred_size: int | None,
    stack_slot_identity_for_variable: Callable[[object], object],
    arg_variable_ids: set[int],
    arg_slot_identities: set[object],
) -> tuple[tuple[Any, Any] | None, tuple[Any, Any] | None]:
    """Score candidates and return (best_exact, best_covering) (variable, cvar) pairs."""
    best_exact = None
    best_exact_score = None
    best_covering = None
    best_covering_score = None
    for variable, cvar in candidates:
        if not isinstance(variable, SimStackVariable):
            continue
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            continue
        base_offset = _canonical_stack_offset_8616(variable.offset)
        size = variable.size
        if not isinstance(base_offset, int) or not isinstance(size, int):
            continue
        if base_offset == offset:
            score = _stack_candidate_score_8616(
                variable,
                cvar,
                exact=True,
                preferred_size=preferred_size,
                stack_slot_identity_for_variable=stack_slot_identity_for_variable,
                arg_variable_ids=arg_variable_ids,
                arg_slot_identities=arg_slot_identities,
            )
            if best_exact_score is None or score > best_exact_score:
                best_exact = (variable, cvar)
                best_exact_score = score
            continue
        if base_offset <= offset < base_offset + size:
            score = _stack_candidate_score_8616(
                variable,
                cvar,
                exact=False,
                preferred_size=preferred_size,
                stack_slot_identity_for_variable=stack_slot_identity_for_variable,
                arg_variable_ids=arg_variable_ids,
                arg_slot_identities=arg_slot_identities,
            )
            if best_covering_score is None or score > best_covering_score:
                best_covering = (variable, cvar)
                best_covering_score = score
    return best_exact, best_covering



def _materialize_stack_cvar_at_offset(
    codegen: object,
    offset: int,
    size: int = 2,
    *,
    resolve_stack_cvar_at_offset: Callable[..., object],
    promote_direct_stack_cvariable: Callable[..., object],
    stack_type_for_size: Callable[[int], object],
) -> object | None:
    codegen_dynamic = cast(Any, codegen)
    if getattr(codegen_dynamic, "cfunc", None) is None:
        return None
    canonical_offset = _canonical_stack_offset_8616(offset)
    if not isinstance(canonical_offset, int):
        return None
    offset = canonical_offset

    resolved = resolve_stack_cvar_at_offset(codegen, offset, preferred_size=size)
    resolved_variable = getattr(resolved, "variable", None)
    if (
        isinstance(resolved_variable, SimStackVariable)
        and _canonical_stack_offset_8616(getattr(resolved_variable, "offset", None)) == offset
    ):
        target_type = stack_type_for_size(size)
        promote_direct_stack_cvariable(codegen, resolved, size, target_type)
        return resolved

    target_type = stack_type_for_size(size)
    variable = SimStackVariable(
        offset,
        size,
        base="bp",
        name=_stack_object_name(offset, codegen=codegen),
        region=getattr(codegen_dynamic.cfunc, "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)

    variables_in_use = getattr(codegen_dynamic.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar

    unified_locals = getattr(codegen_dynamic.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        unified_locals[variable] = {(cvar, target_type)}

    stack_local_candidates = getattr(codegen_dynamic, "_inertia_stack_local_declaration_candidates", None)
    if isinstance(stack_local_candidates, dict):
        stack_local_candidates[id(variable)] = (variable, cvar)

    sort_local_vars = getattr(codegen_dynamic.cfunc, "sort_local_vars", None)
    if callable(sort_local_vars):
        with contextlib.suppress(Exception):
            sort_local_vars()

    return cast(object | None, cvar)


class _StackCvarCanonicalize8616:
    """Canonicalize structured-C stack expressions into 16-bit stack cvars.

    Layer: lowering (X86_16).
    Responsibility: rewrite SS-relative stack evidence into materialized
    stack variables while preserving segmented-memory and alias semantics.
    """

    __slots__ = ('_UNRESOLVED_SINGLE_ASSIGNMENT', 'access_size', 'active_dirty_varids', 'active_expr_ids', 'alias_base_expr', 'alias_base_var', 'alias_offset', 'alias_state', 'analysis_context', 'arch', 'base_displacement', 'base_expr', 'base_ref', 'base_size', 'base_var', 'base_var_expr', 'byte_width', 'candidate_offset', 'canonical_offset', 'codegen', 'codegen_dynamic', 'context', 'cvar_single_assignment_cache', 'debug_stats', 'deref_operand', 'dirty', 'dirty_expr_cls', 'dirty_expr_single_assignment_cache', 'dirtyized', 'displacement', 'exact_binding', 'expr', 'expr_dynamic', 'expr_id', 'index_expr', 'index_value', 'indexed_resolved_offset', 'inferred_stack_base_alias', 'inner', 'lhs', 'machine_bp_offset', 'materialize_stack_cvar_at_offset', 'materialized', 'materialized_var', 'max_depth', 'offset', 'operand', 'preferred_size', 'project', 'projected', 'rebased', 'referenced', 'refusal_reasons', 'requested_size', 'resolution_candidates', 'resolve_stack_cvar_at_offset', 'resolved', 'resolved_offset', 'resolved_var', 'resolved_variable', 'rhs', 'synthetic_bp_anchor', 'synthetic_sp_anchor', 'target_offset', 'type_bits', 'type_size_bits', 'unwrap_c_casts', 'variable', 'variable_type', 'varid')

    def __init__(
        self,
        expr: object,
        codegen: object,
        *,
        unwrap_c_casts: Callable[[object], object],
        resolve_stack_cvar_at_offset: Callable[..., object],
        materialize_stack_cvar_at_offset: Callable[..., object] | None,
        active_expr_ids: set[int] | None,
        analysis_context: dict[str, object] | None,
    ) -> None:
        self.expr: Any = expr
        self.codegen: Any = codegen
        self.unwrap_c_casts: Any = unwrap_c_casts
        self.resolve_stack_cvar_at_offset: Any = resolve_stack_cvar_at_offset
        self.materialize_stack_cvar_at_offset: Any = materialize_stack_cvar_at_offset
        self.active_expr_ids: Any = active_expr_ids
        self.analysis_context: Any = analysis_context
        self._UNRESOLVED_SINGLE_ASSIGNMENT: Any = None
        self.access_size: Any = None
        self.active_dirty_varids: Any = None
        self.alias_base_expr: Any = None
        self.alias_base_var: Any = None
        self.alias_offset: Any = None
        self.alias_state: Any = None
        self.arch: Any = None
        self.base_displacement: Any = None
        self.base_expr: Any = None
        self.base_ref: Any = None
        self.base_size: Any = None
        self.base_var: Any = None
        self.base_var_expr: Any = None
        self.byte_width: Any = None
        self.candidate_offset: Any = None
        self.canonical_offset: Any = None
        self.codegen_dynamic: Any = None
        self.context: Any = None
        self.cvar_single_assignment_cache: Any = None
        self.debug_stats: Any = None
        self.deref_operand: Any = None
        self.dirty: Any = None
        self.dirty_expr_cls: Any = None
        self.dirty_expr_single_assignment_cache: Any = None
        self.dirtyized: Any = None
        self.displacement: Any = None
        self.exact_binding: Any = None
        self.expr_dynamic: Any = None
        self.expr_id: Any = None
        self.index_expr: Any = None
        self.index_value: Any = None
        self.indexed_resolved_offset: Any = None
        self.inferred_stack_base_alias: Any = None
        self.inner: Any = None
        self.lhs: Any = None
        self.machine_bp_offset: Any = None
        self.materialized: Any = None
        self.materialized_var: Any = None
        self.max_depth: Any = None
        self.offset: Any = None
        self.operand: Any = None
        self.preferred_size: Any = None
        self.project: Any = None
        self.projected: Any = None
        self.rebased: Any = None
        self.referenced: Any = None
        self.refusal_reasons: Any = None
        self.requested_size: Any = None
        self.resolution_candidates: Any = None
        self.resolved: Any = None
        self.resolved_offset: Any = None
        self.resolved_var: Any = None
        self.resolved_variable: Any = None
        self.rhs: Any = None
        self.synthetic_bp_anchor: Any = None
        self.synthetic_sp_anchor: Any = None
        self.target_offset: Any = None
        self.type_bits: Any = None
        self.type_size_bits: Any = None
        self.variable: Any = None
        self.variable_type: Any = None
        self.varid: Any = None

    def run_8616(self) -> object:
        """Run each canonicalization phase; the first done phase supplies the result."""
        done, result = self.run_8616_part0()
        if done:
            return result
        done, result = self.run_8616_part1()
        if done:
            return result
        done, result = self.run_8616_part2()
        if done:
            return result
        done, result = self.run_8616_part3()
        if done:
            return result
        return None

    def run_8616_part0(self) -> tuple[bool, object]:
        while isinstance(self.expr, structured_c.CTypeCast) and not isinstance(
            self.expr, CSemanticCast8616
        ):
            self.expr = self.expr.expr
        if self.active_expr_ids is None:
            self.active_expr_ids = set()
        if self.analysis_context is None:
            self.analysis_context = {}
        self.context = self.analysis_context
        self.codegen_dynamic = cast(Any, self.codegen)
        # dynamic-boundary: stack-lowering telemetry is attached to angr
        # codegen objects at runtime; owned Inertia state still uses dot access.
        self.debug_stats = getattr(self.codegen_dynamic, "_inertia_stack_lowering_debug", None)
        if not isinstance(self.debug_stats, dict):
            self.debug_stats = {}
            self.codegen_dynamic._inertia_stack_lowering_debug = self.debug_stats
        self.debug_stats.setdefault("candidate_ast_match_count", 0)
        self.debug_stats.setdefault("candidate_text_match_count", 0)
        self.debug_stats.setdefault("lowering_replacements", 0)
        self.debug_stats.setdefault("lowering_refusals", 0)
        self.debug_stats.setdefault("stable_ss_lowering_refusal_reasons", {})
        self.expr_id = id(self.expr)
        if self._part0_dirty_cycle_refusal_8616():
            return True, self.expr
        self.max_depth = getattr(self.codegen_dynamic, "_inertia_stack_lowering_canonicalize_max_depth_8616", 64)
        if not isinstance(self.max_depth, int) or self.max_depth <= 0:
            self.max_depth = 64
        if self._part0_depth_refusal_8616():
            return True, self.expr
        self.active_expr_ids.add(self.expr_id)

        self.synthetic_sp_anchor = None
        self.synthetic_bp_anchor = None
        self.inferred_stack_base_alias = ...
        return False, None
    def _part0_dirty_cycle_refusal_8616(self) -> bool:
        if self.expr_id in self.active_expr_ids:
            self.dirty_expr_cls = getattr(structured_c, "CDirtyExpression", None)
            self.dirty = getattr(self.expr, "dirty", None)
            self.active_dirty_varids = self.analysis_context.get("active_dirty_varids")
            try:
                self.varid = getattr(self.dirty, "varid", None)
            except (AttributeError, TypeError, ValueError):
                self.varid = None
            if (
                self.dirty_expr_cls is not None
                and isinstance(self.expr, self.dirty_expr_cls)
                and isinstance(self.varid, int)
                and isinstance(self.active_dirty_varids, set)
                and self.varid in self.active_dirty_varids
            ):
                self.codegen_dynamic._inertia_stack_lowering_dirty_cycle_refused_8616 = (
                    _dynamic_int_counter_8616(self.codegen_dynamic, "_inertia_stack_lowering_dirty_cycle_refused_8616") + 1
                )
            return True
        return False

    def _part0_depth_refusal_8616(self) -> bool:
        if len(self.active_expr_ids) >= self.max_depth:
            self.codegen_dynamic._inertia_stack_lowering_canonicalize_depth_refused_8616 = (
                _dynamic_int_counter_8616(
                    self.codegen_dynamic, "_inertia_stack_lowering_canonicalize_depth_refused_8616"
                )
                + 1
            )
            self.debug_stats["lowering_refusals"] += 1
            self.refusal_reasons = self.debug_stats.setdefault("stable_ss_lowering_refusal_reasons", {})
            if isinstance(self.refusal_reasons, dict):
                self.refusal_reasons["canonicalize_depth_limit"] = (
                    int(self.refusal_reasons.get("canonicalize_depth_limit", 0) or 0) + 1
                )
            return True
        return False


    def _iter_statement_nodes(self, root: object) -> Iterator[object]:
        stack = [root]
        seen_nodes: set[int] = set()
        while stack:
            node = stack.pop()
            if node is None:
                continue
            node_id = id(node)
            if node_id in seen_nodes:
                continue
            seen_nodes.add(node_id)
            yield node
            self._push_node_children_8616(node, stack)

    def _push_node_children_8616(self, node: object, stack: list[object]) -> None:
        """Queue a structured-C node's child statements and expressions for traversal."""
        for attr in (
            "statements",
            "condition_and_nodes",
            "else_node",
            "lhs",
            "rhs",
            "operand",
            "expr",
            "init",
            "condition",
            "iteration",
            "body",
            "args",
            "operands",
        ):
            if not hasattr(node, attr):
                continue
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if value is None:
                continue
            if isinstance(value, list | tuple):
                for item in reversed(tuple(value)):
                    if isinstance(item, tuple):
                        for nested in reversed(item):
                            stack.append(nested)  # noqa: PERF402
                    else:
                        stack.append(item)
            else:
                stack.append(value)


    def _synthetic_sp_anchor_cvar(self) -> object:
        if self.synthetic_sp_anchor is not None:
            return self.synthetic_sp_anchor
        cfunc = getattr(self.codegen, "cfunc", None)
        region = getattr(cfunc, "addr", None) if cfunc is not None else None
        variable = SimStackVariable(0, 2, base="sp", name="sp_0", region=region)
        self.synthetic_sp_anchor = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=self.codegen)
        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use.setdefault(variable, self.synthetic_sp_anchor)
        unified_local_vars = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified_local_vars, dict):
            unified_local_vars.setdefault(
                variable, {(self.synthetic_sp_anchor, getattr(self.synthetic_sp_anchor, "variable_type", None))}
            )
        return self.synthetic_sp_anchor

    def _synthetic_bp_anchor_cvar(self) -> object:
        if self.synthetic_bp_anchor is not None:
            return self.synthetic_bp_anchor
        cfunc = getattr(self.codegen, "cfunc", None)
        region = getattr(cfunc, "addr", None) if cfunc is not None else None
        variable = SimStackVariable(0, 2, base="bp", name="bp_0", region=region)
        self.synthetic_bp_anchor = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=self.codegen)
        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use.setdefault(variable, self.synthetic_bp_anchor)
        unified_local_vars = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified_local_vars, dict):
            unified_local_vars.setdefault(
                variable, {(self.synthetic_bp_anchor, getattr(self.synthetic_bp_anchor, "variable_type", None))}
            )
        return self.synthetic_bp_anchor

    def _infer_stack_base_alias_from_bp_slots(self) -> tuple[object, int] | None:
        if self.inferred_stack_base_alias is not ...:
            return cast(tuple[object, int] | None, self.inferred_stack_base_alias)

        root = getattr(getattr(self.codegen, "cfunc", None), "statements", None)
        if root is None:
            self.inferred_stack_base_alias = None
            return None

        known_bp_offsets = self._known_bp_offsets_8616()
        if not known_bp_offsets:
            self.inferred_stack_base_alias = None
            return None

        stack_base_displacements = self._stack_base_displacements_8616(root)
        if len(stack_base_displacements) < 2:
            self.inferred_stack_base_alias = None
            return None

        best_bias = self._best_stack_base_bias_8616(stack_base_displacements, known_bp_offsets)
        if best_bias is None:
            self.inferred_stack_base_alias = None
            return None

        self.inferred_stack_base_alias = (self._synthetic_bp_anchor_cvar(), best_bias)
        return cast(tuple[object, int] | None, self.inferred_stack_base_alias)

    def _known_bp_offsets_8616(self) -> set[int]:
        """Collect negative bp-relative stack offsets from cfunc variables_in_use."""
        known_bp_offsets: set[int] = set()
        variables_in_use = getattr(getattr(self.codegen, "cfunc", None), "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable in variables_in_use:
                if not isinstance(variable, SimStackVariable):
                    continue
                if variable.base != "bp":
                    continue
                offset = variable.offset
                if isinstance(offset, int) and offset < 0:
                    known_bp_offsets.add(offset)
        return known_bp_offsets

    def _stack_base_displacements_8616(self, root: object) -> set[int]:
        """Collect absolute displacements of stack_base-derived accesses in the function."""
        stack_base_displacements: set[int] = set()
        for node in self._iter_statement_nodes(root):
            if isinstance(node, structured_c.CIndexedVariable):
                base_disp = self._stack_base_displacement_expr_8616(node.variable)
                index_value = getattr(self.unwrap_c_casts(node.index), "value", None)
                if isinstance(base_disp, int) and isinstance(index_value, int):
                    stack_base_displacements.add(base_disp + index_value)
                continue
            if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
                disp = self._stack_base_displacement_expr_8616(node.operand)
                if isinstance(disp, int):
                    stack_base_displacements.add(disp)
        return stack_base_displacements

    def _best_stack_base_bias_8616(
        self, stack_base_displacements: set[int], known_bp_offsets: set[int]
    ) -> int | None:
        """Return the most-evidenced bp bias mapping stack_base displacements onto bp slots."""
        bias_scores: dict[int, int] = {}
        for disp in stack_base_displacements:
            for offset in known_bp_offsets:
                bias = offset - disp
                bias_scores[bias] = bias_scores.get(bias, 0) + 1

        best_bias = None
        best_score = 0
        tied = False
        for bias, _ in sorted(bias_scores.items()):
            matched_offsets = {
                disp + bias for disp in stack_base_displacements if (disp + bias) in known_bp_offsets
            }
            score = len(matched_offsets)
            if score > best_score:
                best_bias = bias
                best_score = score
                tied = False
            elif score == best_score and score > 0:
                tied = True

        if tied or not isinstance(best_bias, int) or best_score < 2:
            return None
        return best_bias


    def _is_stack_base_fake_variable(self, node: object) -> bool:
        return isinstance(node, structured_c.CFakeVariable) and getattr(node, "name", None) == "stack_base"

    def _stack_base_displacement_expr_8616(self, node: object) -> int | None:
        node = self.unwrap_c_casts(node)
        if self._is_stack_base_fake_variable(node):
            return 0
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs = self._stack_base_displacement_expr_8616(node.lhs)
            rhs = self._stack_base_displacement_expr_8616(node.rhs)
            lhs_value = getattr(self.unwrap_c_casts(node.lhs), "value", None)
            rhs_value = getattr(self.unwrap_c_casts(node.rhs), "value", None)
            if lhs is not None and isinstance(rhs_value, int):
                return lhs + (rhs_value if node.op == "Add" else -rhs_value)
            if rhs is not None and isinstance(lhs_value, int) and node.op == "Add":
                return rhs + lhs_value
        return None

    def _is_ss_segment_scale_expr(self, node: object) -> bool:
        node = self.unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp):
            return False
        scale = 16 if node.op == "Mul" else 4 if node.op == "Shl" else None
        if scale is None:
            return False
        for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            if getattr(self.unwrap_c_casts(maybe_scale), "value", None) != scale:
                continue
            if self._expr_is_ss_segment_8616(maybe_seg):
                return True
        return False

    def _expr_is_ss_segment_8616(self, expr: object, *, depth: int = 0) -> bool:
        """Return whether an expression carries the SS segment, following temp assignments."""
        if depth > 4:
            return False
        seg_expr = self.unwrap_c_casts(expr)
        if isinstance(seg_expr, structured_c.CVariable):
            seg_var = seg_expr.variable
            seg_name = seg_expr.name or getattr(seg_var, "name", None)
            if seg_name == "ss":
                return True
            # Accept temporary segment carriers when single-assignment
            # evidence resolves them back to SS.
            if self._is_linear_temp_cvar(seg_expr):
                rhs = self._single_assignment_expr_for_cvar(seg_expr)
                if rhs is not None and self._expr_is_ss_segment_8616(rhs, depth=depth + 1):
                    return True
        return False


    def _ss_linear_stack_base_displacement_expr_8616(self, node: object) -> int | None:
        node = self.unwrap_c_casts(node)
        direct = self._stack_base_displacement_expr_8616(node)
        if direct is not None:
            return direct
        if not (isinstance(node, structured_c.CBinaryOp) and node.op == "Add"):
            return None
        lhs_disp = self._stack_base_displacement_expr_8616(node.lhs)
        rhs_disp = self._stack_base_displacement_expr_8616(node.rhs)
        if lhs_disp is not None and self._is_ss_segment_scale_expr(node.rhs):
            return lhs_disp
        if rhs_disp is not None and self._is_ss_segment_scale_expr(node.lhs):
            return rhs_disp
        return None

    def _is_sp_virtual_register(self, variable: object) -> bool:
        sp_offset = getattr(getattr(getattr(self.codegen, "project", None), "arch", None), "registers", {}).get(
            "sp", (None, None)
        )[0]
        return isinstance(sp_offset, int) and getattr(variable, "reg", None) == sp_offset

    def _is_linear_temp_cvar(self, node: object) -> bool:
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = node.variable
        if isinstance(variable, SimStackVariable):
            return False
        name = node.name or getattr(variable, "name", None)
        if name is None:
            return True
        return _is_linear_temp_name_8616(name)

    def run_8616_part1(self) -> tuple[bool, object]:
        self._UNRESOLVED_SINGLE_ASSIGNMENT = self.analysis_context.setdefault("unresolved_single_assignment_sentinel", object())
        self.dirty_expr_single_assignment_cache = self.analysis_context.setdefault("dirty_expr_single_assignment_cache", {})
        if not isinstance(self.dirty_expr_single_assignment_cache, dict):
            self.dirty_expr_single_assignment_cache = {}
            self.analysis_context["dirty_expr_single_assignment_cache"] = self.dirty_expr_single_assignment_cache
        self.cvar_single_assignment_cache = self.analysis_context.setdefault("cvar_single_assignment_cache", {})
        if not isinstance(self.cvar_single_assignment_cache, dict):
            self.cvar_single_assignment_cache = {}
            self.analysis_context["cvar_single_assignment_cache"] = self.cvar_single_assignment_cache
        return False, None

    def _safe_dirty_attr_8616(self, obj: object, attr: str) -> object:
        try:
            return getattr(obj, attr, None)
        except (AttributeError, TypeError, ValueError):
            return None

    def _alias_keys_for_cvar(self, node: object, *, lookup: bool) -> tuple[object, ...]:
        if not isinstance(node, structured_c.CVariable):
            return ()
        variable = node.variable
        keys: list[object] = []
        linear_temp = self._is_linear_temp_cvar(node)
        if variable is not None:
            keys.append(("var", id(variable)))
            reg = getattr(variable, "reg", None)
            size = getattr(variable, "size", None)
            if lookup and not linear_temp and isinstance(reg, int) and isinstance(size, int):
                keys.append(("reg", reg, size))
        for candidate in (
            node.name,
            getattr(variable, "name", None),
        ):
            if isinstance(candidate, str) and candidate:
                normalized = _strip_typed_suffix_8616(candidate)
                if isinstance(normalized, str) and normalized:
                    keys.append(("name", normalized))
        return tuple(dict.fromkeys(keys))

    def _single_assignment_expr_for_cvar(self, node_cvar: object) -> object | None:
        cache_key = id(node_cvar)
        if cache_key in self.cvar_single_assignment_cache:
            return cast(object | None, self.cvar_single_assignment_cache[cache_key])

        root = getattr(getattr(self.codegen, "cfunc", None), "statements", None)
        if root is None or not isinstance(node_cvar, structured_c.CVariable):
            self.cvar_single_assignment_cache[cache_key] = None
            return None

        node_var = getattr(node_cvar, "variable", None)
        node_name = getattr(node_cvar, "name", None) or getattr(node_var, "name", None)
        node_reg = getattr(node_var, "reg", None)
        node_size = getattr(node_var, "size", None)
        node_linear_temp = self._is_linear_temp_cvar(node_cvar)

        matches = []
        for stmt in self._iter_statement_nodes(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            if not self._same_lhs_8616(
                stmt.lhs,
                node_var=node_var,
                node_name=node_name,
                node_reg=node_reg,
                node_size=node_size,
                node_linear_temp=node_linear_temp,
            ):
                continue
            matches.append(stmt.rhs)
            if len(matches) > 1:
                self.cvar_single_assignment_cache[cache_key] = None
                return None
        resolved = matches[0] if len(matches) == 1 else None
        self.cvar_single_assignment_cache[cache_key] = resolved
        return cast(object | None, resolved)

    def _same_lhs_8616(
        self, lhs: object, *, node_var: object, node_name: object, node_reg: object, node_size: object,
        node_linear_temp: bool,
    ) -> bool:
        """Return whether an assignment lhs refers to the same cvar identity as the probe node."""
        if not isinstance(lhs, structured_c.CVariable):
            return False
        lhs_var = lhs.variable
        if lhs_var is node_var:
            return True
        lhs_name = lhs.name or getattr(lhs_var, "name", None)
        lhs_name = _strip_typed_suffix_8616(lhs_name)
        normalized_node_name = _strip_typed_suffix_8616(node_name)
        if isinstance(normalized_node_name, str) and normalized_node_name and lhs_name == normalized_node_name:
            return True
        lhs_reg = getattr(lhs_var, "reg", None)
        lhs_size = getattr(lhs_var, "size", None)
        lhs_linear_temp = self._is_linear_temp_cvar(lhs)
        if node_linear_temp or lhs_linear_temp:
            return False
        return (
            isinstance(node_reg, int)
            and isinstance(node_size, int)
            and isinstance(lhs_reg, int)
            and isinstance(lhs_size, int)
            and lhs_reg == node_reg
            and lhs_size == node_size
        )


    def _single_assignment_expr_for_virtual_name(self, name: str) -> object | None:
        normalized_name = _strip_typed_suffix_8616(name)
        if normalized_name is None:
            return None
        cached = self.dirty_expr_single_assignment_cache.get(normalized_name)
        if cached is not None:
            return None if cached is self._UNRESOLVED_SINGLE_ASSIGNMENT else cached

        root = getattr(getattr(self.codegen, "cfunc", None), "statements", None)
        if root is None:
            self.dirty_expr_single_assignment_cache[normalized_name] = self._UNRESOLVED_SINGLE_ASSIGNMENT
            return None

        target_varid = None
        if normalized_name.startswith("vvar_"):
            suffix = normalized_name.removeprefix("vvar_")
            if suffix.isdigit():
                target_varid = int(suffix)
        if not isinstance(target_varid, int):
            self.dirty_expr_single_assignment_cache[normalized_name] = self._UNRESOLVED_SINGLE_ASSIGNMENT
            return None

        dirty_expr_single_assignment_index = self.context.get("dirty_expr_single_assignment_index")
        dirty_expr_single_assignment_index = self.context.get("dirty_expr_single_assignment_index")
        if not isinstance(dirty_expr_single_assignment_index, dict):
            dirty_expr_single_assignment_index = self._virtual_assignment_index_8616(root)

        resolved = dirty_expr_single_assignment_index.get(normalized_name)
        if resolved is self._UNRESOLVED_SINGLE_ASSIGNMENT:
            self.dirty_expr_single_assignment_cache[normalized_name] = self._UNRESOLVED_SINGLE_ASSIGNMENT
            return None
        self.dirty_expr_single_assignment_cache[normalized_name] = (
            resolved if resolved is not None else self._UNRESOLVED_SINGLE_ASSIGNMENT
        )
        if resolved is not None:
            self.codegen_dynamic._inertia_stack_lowering_virtual_assignment_index_hits = (
                _dynamic_int_counter_8616(self.codegen_dynamic, "_inertia_stack_lowering_virtual_assignment_index_hits")
                + 1
            )
        return cast(object | None, resolved)
    def _virtual_assignment_index_8616(self, root: object) -> dict[str, object | None]:
        """Build the name->rhs single-assignment index for virtual register names."""
        index: dict[str, object | None] = {}
        scanned = 0
        for stmt in self._iter_statement_nodes(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            scanned += 1
            lhs = stmt.lhs
            lhs_keys: set[str] = set()
            if isinstance(lhs, structured_c.CVariable):
                lhs_name = lhs.name or getattr(lhs.variable, "name", None)
                lhs_normalized = _strip_typed_suffix_8616(lhs_name)
                if isinstance(lhs_normalized, str) and lhs_normalized:
                    lhs_keys.add(lhs_normalized)
            lhs_varid = self._safe_dirty_attr_8616(getattr(lhs, "dirty", None), "varid")
            if isinstance(lhs_varid, int):
                lhs_keys.add(f"vvar_{lhs_varid}")
            if not lhs_keys:
                continue
            rhs = stmt.rhs
            for lhs_key in lhs_keys:
                if lhs_key in index:
                    index[lhs_key] = self._UNRESOLVED_SINGLE_ASSIGNMENT
                else:
                    index[lhs_key] = rhs
        dirty_expr_single_assignment_index = index
        self.context["dirty_expr_single_assignment_index"] = dirty_expr_single_assignment_index
        self.codegen_dynamic._inertia_stack_lowering_virtual_assignment_index_scanned = (
            _dynamic_int_counter_8616(
                self.codegen_dynamic, "_inertia_stack_lowering_virtual_assignment_index_scanned"
            )
            + scanned
        )
        self.codegen_dynamic._inertia_stack_lowering_virtual_assignment_index_keys = (
            _dynamic_int_counter_8616(
                self.codegen_dynamic, "_inertia_stack_lowering_virtual_assignment_index_keys"
            )
            + len(index)
        )
        return index


    def _top_level_statements(self) -> list[object]:
        root = getattr(getattr(self.codegen, "cfunc", None), "statements", None)
        statements = getattr(root, "statements", None)
        if isinstance(statements, list | tuple):
            return list(statements)
        return []

    def _statement_index_containing(self, node: object) -> int | None:
        if node is None:
            return None
        for idx, stmt in enumerate(self._top_level_statements()):
            for nested in self._iter_statement_nodes(stmt):
                if nested is node:
                    return idx
        return None

    def _nearest_preceding_assignment_expr_for_cvar(self, node_cvar: object) -> object | None:
        if not isinstance(node_cvar, structured_c.CVariable):
            return None
        node_var = node_cvar.variable
        node_reg = getattr(node_var, "reg", None)
        node_size = getattr(node_var, "size", None)
        if not (isinstance(node_reg, int) and isinstance(node_size, int)):
            return None
        stmt_idx = self._statement_index_containing(node_cvar)
        if stmt_idx is None:
            return None

        nearest_rhs = None
        for idx, stmt in enumerate(self._top_level_statements()):
            if idx >= stmt_idx or not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = getattr(stmt, "lhs", None)
            if not isinstance(lhs, structured_c.CVariable):
                continue
            lhs_var = lhs.variable
            lhs_reg = getattr(lhs_var, "reg", None)
            lhs_size = getattr(lhs_var, "size", None)
            if lhs_reg == node_reg and lhs_size == node_size:
                nearest_rhs = getattr(stmt, "rhs", None)
        return nearest_rhs

    def _resolve_dirty_virtual_expr(self, 
        node: object,
        *,
        seen_varids: set[int] | None = None,
    ) -> object | None:
        dirty = getattr(node, "dirty", None)
        if dirty is None:
            return None
        varid = self._safe_dirty_attr_8616(dirty, "varid")
        if not isinstance(varid, int):
            reg = self._safe_dirty_attr_8616(dirty, "reg")
            bits = self._safe_dirty_attr_8616(dirty, "bits")
            if self._is_sp_virtual_register(
                SimpleNamespace(reg=reg, size=(bits // 8) if isinstance(bits, int) else None)
            ):
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

    def _canonicalize_dirty_expression(self, node: object) -> object:
        dirty_expr_cls = getattr(structured_c, "CDirtyExpression", None)
        if dirty_expr_cls is None or not isinstance(node, dirty_expr_cls):
            return node
        dirty = getattr(node, "dirty", None)
        varid = self._safe_dirty_attr_8616(dirty, "varid")
        active_dirty_varids = self.context.get("active_dirty_varids")
        if not isinstance(active_dirty_varids, set):
            active_dirty_varids = set()
            self.context["active_dirty_varids"] = active_dirty_varids
        if isinstance(varid, int) and varid in active_dirty_varids:
            self.codegen_dynamic._inertia_stack_lowering_dirty_cycle_refused_8616 = (
                _dynamic_int_counter_8616(self.codegen_dynamic, "_inertia_stack_lowering_dirty_cycle_refused_8616") + 1
            )
            return node
        resolved = self._resolve_dirty_virtual_expr(node)
        if resolved is None:
            return node
        if isinstance(varid, int):
            active_dirty_varids.add(varid)
        try:
            return _canonicalize_stack_cvar_expr(
                resolved,
                self.codegen,
                unwrap_c_casts=self.unwrap_c_casts,
                resolve_stack_cvar_at_offset=self.resolve_stack_cvar_at_offset,
                materialize_stack_cvar_at_offset=self.materialize_stack_cvar_at_offset,
                active_expr_ids=self.active_expr_ids,
                analysis_context=self.analysis_context,
            )
        finally:
            if isinstance(varid, int):
                active_dirty_varids.discard(varid)

    def run_8616_part2(self) -> tuple[bool, object]:
        self.dirtyized = self._canonicalize_dirty_expression(self.expr)
        if self.dirtyized is not self.expr:
            self.active_expr_ids.discard(self.expr_id)
            return True, self.dirtyized
        return False, None

    def _is_pointer_capable_stack_variable(self, var: object, cvar: object | None = None) -> bool:
        if not isinstance(var, SimStackVariable):
            return False
        if var.base != "bp":
            return False
        size = var.size
        if isinstance(size, int) and size >= 2:
            return True
        var_type = getattr(cvar, "variable_type", None)
        return isinstance(var_type, SimTypePointer)

    def _is_synthetic_stack_anchor_cvar_8616(self, node: object) -> bool:
        if not isinstance(node, structured_c.CVariable):
            return False
        var = node.variable
        if not isinstance(var, SimStackVariable):
            return False
        base = var.base
        offset = var.offset
        name = node.name or var.name
        return base in {"sp", "bp"} and offset == 0 and name in {"sp_0", "bp_0"}

    def _stack_pointer_aliases(self) -> dict[object, tuple[object, int]]:
        # dynamic-boundary: alias caches live on angr codegen/cfunc objects
        # during this lowering pass; owned Inertia contracts use dot access.
        cached = getattr(self.codegen_dynamic, "_inertia_stack_pointer_aliases_for_cvars", None)
        cache_key = getattr(self.codegen_dynamic.cfunc, "statements", None)
        if isinstance(cached, tuple) and len(cached) == 2 and cached[0] is cache_key and isinstance(cached[1], dict):
            return cast(dict[object, tuple[object, int]], cached[1])

        aliases: dict[object, tuple[object, int]] = {}
        root = getattr(getattr(self.codegen, "cfunc", None), "statements", None)
        if root is not None:
            self._fixpoint_stack_pointer_aliases_8616(aliases, root)

        typing.cast(typing.Any, self.codegen)._inertia_stack_pointer_aliases_for_cvars = (cache_key, aliases)
        return aliases

    def _fixpoint_stack_pointer_aliases_8616(
        self, aliases: dict[object, tuple[object, int]], root: object
    ) -> None:
        """Propagate stack-pointer aliases through assignments until a fixpoint."""
        for _ in range(3):
            changed_local = False
            for node in self._iter_statement_nodes(root):
                if self._apply_assignment_alias_8616(aliases, node):
                    changed_local = True
            if not changed_local:
                break

    def _apply_assignment_alias_8616(
        self, aliases: dict[object, tuple[object, int]], node: object
    ) -> bool:
        """Apply one assignment statement to the alias map; return whether it changed."""
        if not isinstance(node, structured_c.CAssignment):
            return False
        lhs = self.unwrap_c_casts(node.lhs)
        if not isinstance(lhs, structured_c.CVariable):
            return False
        lhs_var = lhs.variable
        if lhs_var is None:
            return False
        keys = self._alias_keys_for_cvar(lhs, lookup=False)
        if not keys:
            return False
        resolved = self._resolve_stack_pointer_alias_8616(node.rhs, aliases)
        if resolved is None:
            return False
        if isinstance(lhs_var, SimStackVariable) and lhs_var.base != "bp":
            return False
        if not self._stack_carrier_lhs_allowed_8616(lhs_var, lhs, node):
            return False
        needs_update = False
        for key in keys:
            if aliases.get(key) != resolved:
                aliases[key] = resolved
                needs_update = True
        return needs_update

    def _stack_carrier_lhs_allowed_8616(self, lhs_var: Any, lhs: Any, node: Any) -> bool:
        """Return whether a non-pointer-capable stack lhs may still carry a pointer."""
        if not isinstance(lhs_var, SimStackVariable) or self._is_pointer_capable_stack_variable(
            lhs_var, lhs
        ):
            return True
        # Accept tiny stack temporaries that are proved to carry a stack pointer.
        # These appear in helper prologue/epilogue carrier patterns.
        rhs_expr = self.unwrap_c_casts(node.rhs)
        return (
            isinstance(rhs_expr, structured_c.CUnaryOp)
            and rhs_expr.op == "Reference"
        ) or isinstance(rhs_expr, structured_c.CBinaryOp)

    def _resolve_stack_pointer_alias_8616(
        self,
        node: Any,
        aliases: dict[object, tuple[object, int]],
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        """Resolve a node to a (base, offset) stack-pointer alias pair, if provable."""
        node = self.unwrap_c_casts(node)
        if node is None:
            return None
        if seen_expr_ids is None:
            seen_expr_ids = set()
        node_id = id(node)
        if node_id in seen_expr_ids:
            return None
        seen_expr_ids.add(node_id)

        if isinstance(node, structured_c.CVariable):
            return self._cvar_stack_pointer_alias_8616(
                node, aliases, seen_expr_ids=seen_expr_ids, seen_varids=seen_varids
            )
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            return self._reference_stack_pointer_alias_8616(node, aliases)
        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            return self._binop_stack_pointer_alias_8616(
                node, aliases, seen_expr_ids=seen_expr_ids, seen_varids=seen_varids
            )
        return None

    def _cvar_stack_pointer_alias_8616(
        self,
        node: Any,
        aliases: dict[object, tuple[object, int]],
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        """Resolve a CVariable through aliases, sp-register evidence, or assignments."""
        variable = node.variable
        for key in self._alias_keys_for_cvar(node, lookup=True):
            alias = aliases.get(key)
            if alias is not None:
                return alias
        if self._is_sp_virtual_register(variable):
            return self._synthetic_sp_anchor_cvar(), 0
        single_assignment_rhs = self._single_assignment_expr_for_cvar(node)
        if single_assignment_rhs is not None:
            return self._resolve_stack_pointer_alias_8616(
                single_assignment_rhs,
                aliases,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        nearest_assignment_rhs = self._nearest_preceding_assignment_expr_for_cvar(node)
        if nearest_assignment_rhs is not None:
            return self._resolve_stack_pointer_alias_8616(
                nearest_assignment_rhs,
                aliases,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        return None

    def _reference_stack_pointer_alias_8616(
        self, node: Any, aliases: dict[object, tuple[object, int]]
    ) -> tuple[object, int] | None:
        """Resolve a `&var` reference through bp evidence or alias keys."""
        operand = self.unwrap_c_casts(node.operand)
        if isinstance(operand, structured_c.CVariable):
            variable = operand.variable
            if isinstance(variable, SimStackVariable) and variable.base == "bp":
                return operand, 0
            for key in self._alias_keys_for_cvar(operand, lookup=True):
                alias = aliases.get(key)
                if alias is not None:
                    return alias
        return None

    def _binop_stack_pointer_alias_8616(
        self,
        node: Any,
        aliases: dict[object, tuple[object, int]],
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        """Resolve an Add/Sub expression through per-side aliases and constants."""
        lhs = self._resolve_stack_pointer_alias_8616(
            node.lhs,
            aliases,
            seen_expr_ids=seen_expr_ids,
            seen_varids=seen_varids,
        )
        rhs = self._resolve_stack_pointer_alias_8616(
            node.rhs,
            aliases,
            seen_expr_ids=seen_expr_ids,
            seen_varids=seen_varids,
        )
        lhs_value = getattr(self.unwrap_c_casts(node.lhs), "value", None)
        rhs_value = getattr(self.unwrap_c_casts(node.rhs), "value", None)
        if lhs is not None and isinstance(rhs_value, int):
            base, offset = lhs
            return base, offset + (rhs_value if node.op == "Add" else -rhs_value)
        if rhs is not None and isinstance(lhs_value, int) and node.op == "Add":
            base, offset = rhs
            return base, offset + lhs_value
        return None


    def _resolve_stack_pointer_alias_expr(self, 
        base_expr: object,
        *,
        seen_expr_ids: set[int] | None = None,
        seen_varids: set[int] | None = None,
    ) -> tuple[object, int] | None:
        base_ref = self.unwrap_c_casts(base_expr)
        if base_ref is None:
            return None
        if seen_expr_ids is None:
            seen_expr_ids = set()
        base_ref_id = id(base_ref)
        if base_ref_id in seen_expr_ids:
            return None
        seen_expr_ids.add(base_ref_id)

        resolved_dirty = self._resolve_dirty_virtual_expr(base_ref, seen_varids=seen_varids)
        if resolved_dirty is not None:
            return self._resolve_stack_pointer_alias_expr(
                resolved_dirty,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )

        if isinstance(base_ref, structured_c.CUnaryOp) and base_ref.op == "Reference":
            return self._reference_alias_expr_8616(base_ref)

        if self._is_stack_base_fake_variable(base_ref):
            return self._stack_base_alias_expr_8616()

        if isinstance(base_ref, structured_c.CVariable):
            return self._cvar_alias_expr_8616(
                base_ref, seen_expr_ids=seen_expr_ids, seen_varids=seen_varids
            )

        if isinstance(base_ref, structured_c.CBinaryOp) and base_ref.op in {"Add", "Sub"}:
            return self._binop_alias_expr_8616(
                base_ref, seen_expr_ids=seen_expr_ids, seen_varids=seen_varids
            )
        return None

    def _lookup_alias_keys_8616(self, node: Any) -> tuple[object, int] | None:
        """Return the cached stack-pointer alias for a node's alias keys, if any."""
        for key in self._alias_keys_for_cvar(node, lookup=True):
            alias_state = self._stack_pointer_aliases().get(key)
            if alias_state is not None:
                return alias_state
        return None

    def _reference_alias_expr_8616(self, base_ref: Any) -> tuple[object, int] | None:
        """Resolve a `&var` reference through alias keys or direct bp stack evidence."""
        operand = self.unwrap_c_casts(base_ref.operand)
        if isinstance(operand, structured_c.CVariable):
            base_var = operand.variable
            alias_state = self._lookup_alias_keys_8616(operand)
            if alias_state is not None:
                return alias_state
            if isinstance(base_var, SimStackVariable) and getattr(base_var, "base", None) == "bp":
                return operand, 0
        return None

    def _stack_base_alias_expr_8616(self) -> tuple[object, int] | None:
        """Resolve angr's entry-SP `stack_base` placeholder to a stack alias."""
        sp_anchor = self._synthetic_sp_anchor_cvar()
        alias_state = self._lookup_alias_keys_8616(sp_anchor)
        if alias_state is not None:
            return alias_state
        inferred_alias = self._infer_stack_base_alias_from_bp_slots()
        if inferred_alias is not None:
            return inferred_alias
        # `stack_base` is angr's entry-SP placeholder. In a BP-framed
        # 16-bit function, `push bp; mov bp, sp` makes BP two bytes below
        # that value, so stack_base-relative offsets need a +2 BP bias.
        return self._synthetic_bp_anchor_cvar(), 2

    def _cvar_alias_expr_8616(
        self, base_ref: Any, *, seen_expr_ids: set[int] | None = None, seen_varids: set[int] | None = None
    ) -> tuple[object, int] | None:
        """Resolve a CVariable through alias keys, bp/sp evidence, or assignment chains."""
        base_var = base_ref.variable
        alias_state = self._lookup_alias_keys_8616(base_ref)
        if alias_state is not None:
            return alias_state
        if isinstance(base_var, SimStackVariable) and getattr(base_var, "base", None) == "bp":
            return base_ref, 0
        if self._is_sp_virtual_register(base_var):
            return self._synthetic_sp_anchor_cvar(), 0
        single_assignment_rhs = self._single_assignment_expr_for_cvar(base_ref)
        if single_assignment_rhs is not None:
            return self._resolve_stack_pointer_alias_expr(
                single_assignment_rhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        nearest_assignment_rhs = self._nearest_preceding_assignment_expr_for_cvar(base_ref)
        if nearest_assignment_rhs is not None:
            return self._resolve_stack_pointer_alias_expr(
                nearest_assignment_rhs,
                seen_expr_ids=seen_expr_ids,
                seen_varids=seen_varids,
            )
        return None

    def _binop_alias_expr_8616(
        self, base_ref: Any, *, seen_expr_ids: set[int] | None = None, seen_varids: set[int] | None = None
    ) -> tuple[object, int] | None:
        """Resolve an Add/Sub expression through per-side aliases, SS scaling, and constants."""
        lhs = self._resolve_stack_pointer_alias_expr(
            base_ref.lhs,
            seen_expr_ids=seen_expr_ids,
            seen_varids=seen_varids,
        )
        rhs = self._resolve_stack_pointer_alias_expr(
            base_ref.rhs,
            seen_expr_ids=seen_expr_ids,
            seen_varids=seen_varids,
        )
        lhs_value = getattr(self.unwrap_c_casts(base_ref.lhs), "value", None)
        rhs_value = getattr(self.unwrap_c_casts(base_ref.rhs), "value", None)
        if base_ref.op == "Add":
            if self._is_ss_segment_scale_expr(base_ref.lhs):
                return rhs
            if self._is_ss_segment_scale_expr(base_ref.rhs):
                return lhs
        if lhs is not None and isinstance(rhs_value, int):
            alias_base_expr, alias_offset = lhs
            return alias_base_expr, alias_offset + (rhs_value if base_ref.op == "Add" else -rhs_value)
        if rhs is not None and isinstance(lhs_value, int) and base_ref.op == "Add":
            alias_base_expr, alias_offset = rhs
            return alias_base_expr, alias_offset + lhs_value
        return None


    def _resolve_base_stack_pointer_alias(self, base_expr: object) -> tuple[object, int] | None:
        return self._resolve_stack_pointer_alias_expr(base_expr)

    def _fact_backed_stack_size_for_offset(self, offset: int) -> int | None:
        bindings = getattr(self.codegen, "_inertia_stack_variable_bindings", None)
        if not isinstance(bindings, tuple):
            return None
        for binding in bindings:
            if not isinstance(binding, StackVariableBinding):
                continue
            binding_offset = _canonical_stack_offset_8616(binding.bp_offset)
            if binding_offset != offset:
                continue
            if binding.size > 0:
                return cast(int | None, binding.size)
        return None

    def _alias_fact_bp_offsets_8616(self) -> set[int]:
        facts = getattr(self.codegen, "_inertia_semantic_alias_facts", None)
        return _typed_alias_fact_bp_offsets_8616(facts)

    def _cached_stack_base_bp_bias_8616(self) -> int | None:
        active_bias = getattr(self.codegen, "_inertia_active_stack_base_bp_bias_8616", None)
        if isinstance(active_bias, int):
            return active_bias
        cached = getattr(self.codegen, "_inertia_stack_base_bp_bias_evidence_8616", None)
        cache_key = getattr(getattr(self.codegen, "cfunc", None), "statements", None)
        if isinstance(cached, StackBaseBpBiasEvidence8616) and cached.statement_root is cache_key:
                inferred_bias = cached.inferred_bias
                return inferred_bias if isinstance(inferred_bias, int) else None
        return None

    def _alias_rebased_stack_offset_8616(self, offset: int) -> int | None:
        alias_offsets = self._alias_fact_bp_offsets_8616()
        if not alias_offsets or offset in alias_offsets:
            return None
        bias = self._cached_stack_base_bp_bias_8616()
        if not isinstance(bias, int) or bias == 0:
            return None
        rebased = _canonical_stack_offset_8616(offset + bias)
        if isinstance(rebased, int) and rebased in alias_offsets:
            return rebased
        return None

    def _resolve_rebased_stack_cvar_8616(self, offset: int, size: int | None) -> object | None:
        rebased_offset = self._alias_rebased_stack_offset_8616(offset)
        if not isinstance(rebased_offset, int):
            return None
        preferred_size = self._fact_backed_stack_size_for_offset(rebased_offset)
        if preferred_size is None:
            preferred_size = size
        resolved = self.resolve_stack_cvar_at_offset(
            self.codegen,
            rebased_offset,
            preferred_size=preferred_size if isinstance(preferred_size, int) else None,
        )
        resolved_var = getattr(resolved, "variable", None)
        if (
            isinstance(resolved, structured_c.CVariable)
            and isinstance(resolved_var, SimStackVariable)
            and _canonical_stack_offset_8616(getattr(resolved_var, "offset", None)) == rebased_offset
        ):
            self.debug_stats["candidate_ast_match_count"] += 1
            self.debug_stats["lowering_replacements"] += 1
            self.codegen_dynamic._inertia_stack_cvar_rebased_from_stack_base_bias_count_8616 = (
                _dynamic_int_counter_8616(
                    self.codegen_dynamic, "_inertia_stack_cvar_rebased_from_stack_base_bias_count_8616"
                )
                + 1
            )
            return cast(object | None, resolved)
        if not callable(self.materialize_stack_cvar_at_offset):
            return None
        materialized_size = preferred_size if isinstance(preferred_size, int) and preferred_size > 0 else 2
        materialized = self.materialize_stack_cvar_at_offset(self.codegen, rebased_offset, materialized_size)
        materialized_var = getattr(materialized, "variable", None)
        if (
            isinstance(materialized, structured_c.CVariable)
            and isinstance(materialized_var, SimStackVariable)
            and _canonical_stack_offset_8616(getattr(materialized_var, "offset", None)) == rebased_offset
        ):
            self.debug_stats["candidate_ast_match_count"] += 1
            self.debug_stats["lowering_replacements"] += 1
            self.codegen_dynamic._inertia_stack_cvar_rebased_from_stack_base_bias_count_8616 = (
                _dynamic_int_counter_8616(
                    self.codegen_dynamic, "_inertia_stack_cvar_rebased_from_stack_base_bias_count_8616"
                )
                + 1
            )
            return cast(object | None, materialized)
        return None

    def run_8616_part3(self) -> tuple[bool, object]:
        done, result = self._part3_cvar_lane_8616()
        if done:
            return True, result
        done, result = self._part3_indexed_lane_8616()
        if done:
            return True, result
        done, result = self._part3_deref_lane_8616()
        if done:
            return True, result
        done, result = self._part3_stackaddr_lane_8616()
        if done:
            return True, result
        done, result = self._part3_tail_lane_8616()
        if done:
            return True, result
        self.active_expr_ids.discard(self.expr_id)
        return True, self.expr
        return False, None
    def _part3_cvar_lane_8616(self) -> tuple[bool, object]:
        if isinstance(self.expr, structured_c.CVariable):
            self.variable = self.expr.variable
            done, result = self._part3_cvar_stackvar_8616()
            if done:
                return True, result
            self.active_expr_ids.discard(self.expr_id)
            return True, self.expr
        return False, None
    def _part3_cvar_stackvar_8616(self) -> tuple[bool, object]:
        if isinstance(self.variable, SimStackVariable):
            if self._is_synthetic_stack_anchor_cvar_8616(self.expr):
                self.active_expr_ids.discard(self.expr_id)
                return True, self.expr
            self.offset = self.variable.offset
            done, result = self._part3_cvar_stackvar_body_8616()
            if done:
                return True, result
            if self._is_pointer_capable_stack_variable(self.variable, self.expr):
                self.active_expr_ids.discard(self.expr_id)
                return True, self.expr
        return False, None
    def _part3_cvar_stackvar_body_8616(self) -> tuple[bool, object]:
        if isinstance(self.offset, int):
            self.canonical_offset = _canonical_stack_offset_8616(self.offset)
            self.exact_binding = stack_binding_from_tags_8616(self.expr.tags)
            if self.exact_binding is not None:
                self.projected = stack_cvar_for_machine_bp_range_8616(
                    self.codegen,
                    self.exact_binding.bp_offset,
                    self.exact_binding.size,
                )
                if isinstance(self.projected, structured_c.CVariable):
                    self.active_expr_ids.discard(self.expr_id)
                    return True, self.projected
            self.machine_bp_offset = machine_bp_offset_for_stack_variable_8616(
                self.codegen,
                self.variable,
            )
            done, result = self._part3_cvar_rebind_8616()
            if done:
                return True, result
            self.resolved_variable = getattr(self.resolved, "variable", None)
            if isinstance(self.resolved_variable, SimStackVariable):
                self.variable_type = getattr(self.resolved, "variable_type", None) or self.expr.variable_type
                self.active_expr_ids.discard(self.expr_id)
                return True, structured_c.CVariable(self.resolved_variable, variable_type=self.variable_type, codegen=self.codegen)
        return False, None
    def _part3_cvar_rebind_8616(self) -> tuple[bool, object]:
        if isinstance(self.machine_bp_offset, int) and isinstance(self.variable.size, int):
            self.projected = stack_cvar_for_machine_bp_range_8616(
                self.codegen,
                self.machine_bp_offset,
                self.variable.size,
            )
            if isinstance(self.projected, structured_c.CVariable):
                self.active_expr_ids.discard(self.expr_id)
                return True, self.projected
        if isinstance(self.canonical_offset, int) and self.exact_binding is None:
            self.rebased = self._resolve_rebased_stack_cvar_8616(self.canonical_offset, self.variable.size)
            if isinstance(self.rebased, structured_c.CVariable):
                self.active_expr_ids.discard(self.expr_id)
                return True, self.rebased
        self.preferred_size = (
            self._fact_backed_stack_size_for_offset(self.canonical_offset)
            if isinstance(self.canonical_offset, int)
            else None
        )
        if self.preferred_size is None:
            self.preferred_size = self.variable.size
        self.resolved = self.resolve_stack_cvar_at_offset(
            self.codegen,
            self.offset,
            preferred_size=self.preferred_size if isinstance(self.preferred_size, int) else None,
        )
        if isinstance(self.resolved, structured_c.CVariable):
            self.active_expr_ids.discard(self.expr_id)
            return True, self.resolved
        return False, None




    def _part3_indexed_lane_8616(self) -> tuple[bool, object]:
        if isinstance(self.expr, structured_c.CIndexedVariable):
            self.base_expr = _canonicalize_stack_cvar_expr(
                self.expr.variable,
                self.codegen,
                unwrap_c_casts=self.unwrap_c_casts,
                resolve_stack_cvar_at_offset=self.resolve_stack_cvar_at_offset,
                materialize_stack_cvar_at_offset=self.materialize_stack_cvar_at_offset,
                active_expr_ids=self.active_expr_ids,
                analysis_context=self.analysis_context,
            )
            self.index_expr = _canonicalize_stack_cvar_expr(
                self.expr.index,
                self.codegen,
                unwrap_c_casts=self.unwrap_c_casts,
                resolve_stack_cvar_at_offset=self.resolve_stack_cvar_at_offset,
                materialize_stack_cvar_at_offset=self.materialize_stack_cvar_at_offset,
                active_expr_ids=self.active_expr_ids,
                analysis_context=self.analysis_context,
            )
            self.arch = getattr(getattr(self.codegen, "project", None), "arch", None)
            self.byte_width = getattr(self.arch, "byte_width", None)
            self.type_size_bits = _safe_sim_type_size_bits(self.expr.type)
            self.requested_size = (
                max(self.type_size_bits // self.byte_width, 1)
                if isinstance(self.type_size_bits, int)
                and self.type_size_bits > 0
                and isinstance(self.byte_width, int)
                and self.byte_width > 0
                else None
            )
            self.index_value = getattr(self.index_expr, "value", None)
            self.resolution_candidates = []
            self.base_displacement = self._stack_base_displacement_expr_8616(self.base_expr)
            if isinstance(self.base_displacement, int) and isinstance(self.index_value, int):
                self.resolution_candidates.append((self.base_displacement + self.index_value, None))
            self.alias_state = self._resolve_base_stack_pointer_alias(self.base_expr)
            if self.alias_state is not None and isinstance(self.index_value, int):
                self.alias_base_expr, self.alias_offset = self.alias_state
                self.alias_base_var = getattr(self.alias_base_expr, "variable", None)
                self.target_offset = getattr(self.alias_base_var, "offset", None)
                if isinstance(self.target_offset, int):
                    self.resolution_candidates.append((self.target_offset + self.alias_offset + self.index_value, self.alias_base_var))
            done, result = self._part3_indexed_materialize_8616()
            if done:
                return True, result
            self.expr_dynamic = cast(Any, self.expr)
            if self.base_expr is not self.expr_dynamic.variable or self.index_expr is not self.expr_dynamic.index:
                self.active_expr_ids.discard(self.expr_id)
                return True, structured_c.CIndexedVariable(
                    cast(Any, self.base_expr),
                    cast(Any, self.index_expr),
                    codegen=_structured_c_codegen_owner_8616(self.expr),
                    tags=copy_structured_tags_8616(self.expr.tags) or {},
                )
            self.active_expr_ids.discard(self.expr_id)
            return True, self.expr
        return False, None
    def _part3_indexed_materialize_8616(self) -> tuple[bool, object]:
        for resolved_offset_l, alias_base_var_l in self.resolution_candidates:
            self.resolved_offset, self.alias_base_var = resolved_offset_l, alias_base_var_l
            self.resolved = self.resolve_stack_cvar_at_offset(self.codegen, self.resolved_offset, preferred_size=self.requested_size)
            self.resolved = _prefer_bound_stack_cvar_8616(self.codegen, self.resolved, self.resolve_stack_cvar_at_offset)
            self.resolved_var = getattr(self.resolved, "variable", None)
            if (
                isinstance(self.resolved, structured_c.CVariable)
                and isinstance(self.resolved_var, SimStackVariable)
                and getattr(self.resolved_var, "offset", None) == self.resolved_offset
            ):
                _record_stack_canonicalization_bridge_8616(
                    self.codegen,
                    expr=self.expr,
                    resolved_offset=self.resolved_offset,
                    kind="indexed_value",
                )
                self.debug_stats["candidate_ast_match_count"] += 1
                self.debug_stats["lowering_replacements"] += 1
                self.active_expr_ids.discard(self.expr_id)
                return True, self.resolved
            if self.alias_base_var is None:
                continue
            self.base_size = getattr(self.alias_base_var, "size", None)
            if (
                callable(self.materialize_stack_cvar_at_offset)
                and isinstance(self.requested_size, int)
                and isinstance(self.base_size, int)
                and self.requested_size > self.base_size
            ):
                self.materialized = self.materialize_stack_cvar_at_offset(self.codegen, self.resolved_offset, self.requested_size)
                self.materialized_var = getattr(self.materialized, "variable", None)
                if (
                    isinstance(self.materialized, structured_c.CVariable)
                    and isinstance(self.materialized_var, SimStackVariable)
                    and getattr(self.materialized_var, "offset", None) == self.resolved_offset
                ):
                    self.materialized = _prefer_bound_stack_cvar_8616(
                        self.codegen, self.materialized, self.resolve_stack_cvar_at_offset
                    )
                    _record_stack_canonicalization_bridge_8616(
                        self.codegen,
                        expr=self.expr,
                        resolved_offset=self.resolved_offset,
                        kind="indexed_value",
                    )
                    self.debug_stats["candidate_ast_match_count"] += 1
                    self.debug_stats["lowering_replacements"] += 1
                    self.active_expr_ids.discard(self.expr_id)
                    return True, self.materialized
            if callable(self.materialize_stack_cvar_at_offset):
                self.materialized = self.materialize_stack_cvar_at_offset(
                    self.codegen,
                    self.resolved_offset,
                    self.requested_size if isinstance(self.requested_size, int) and self.requested_size > 0 else 1,
                )
                self.materialized_var = getattr(self.materialized, "variable", None)
                if (
                    isinstance(self.materialized, structured_c.CVariable)
                    and isinstance(self.materialized_var, SimStackVariable)
                    and getattr(self.materialized_var, "offset", None) == self.resolved_offset
                ):
                    self.materialized = _prefer_bound_stack_cvar_8616(
                        self.codegen, self.materialized, self.resolve_stack_cvar_at_offset
                    )
                    _record_stack_canonicalization_bridge_8616(
                        self.codegen,
                        expr=self.expr,
                        resolved_offset=self.resolved_offset,
                        kind="indexed_value",
                    )
                    self.debug_stats["candidate_ast_match_count"] += 1
                    self.debug_stats["lowering_replacements"] += 1
                    self.active_expr_ids.discard(self.expr_id)
                    return True, self.materialized
        return False, None


    def _part3_deref_lane_8616(self) -> tuple[bool, object]:
        if isinstance(self.expr, structured_c.CUnaryOp):
            self.operand = _canonicalize_stack_cvar_expr(
                self.expr.operand,
                self.codegen,
                unwrap_c_casts=self.unwrap_c_casts,
                resolve_stack_cvar_at_offset=self.resolve_stack_cvar_at_offset,
                materialize_stack_cvar_at_offset=self.materialize_stack_cvar_at_offset,
                active_expr_ids=self.active_expr_ids,
                analysis_context=self.analysis_context,
            )
            self.deref_operand = self.unwrap_c_casts(self.operand)
            done, result = self._part3_deref_resolve_8616()
            if done:
                return True, result
            self.active_expr_ids.discard(self.expr_id)
            return True, self.expr
        return False, None
    def _part3_deref_resolve_8616(self) -> tuple[bool, object]:
        done, result = self._part3_deref_addr_8616()
        if done:
            return True, result
        done, result = self._part3_deref_chain_8616()
        if done:
            return True, result
        done, result = self._part3_deref_operand_8616()
        if done:
            return True, result
        return False, None

    def _part3_deref_chain_8616(self) -> tuple[bool, object]:
        if (
            self.expr.op == "Dereference"
            and isinstance(self.deref_operand, structured_c.CUnaryOp)
            and self.deref_operand.op == "Reference"
        ):
            self.referenced = self.unwrap_c_casts(self.deref_operand.operand)
            if isinstance(self.referenced, (structured_c.CVariable, structured_c.CIndexedVariable)):
                _debug_stack_condition_rebind_8616(self.codegen, self.expr, self.referenced, note="deref-reference-collapse")
                self.active_expr_ids.discard(self.expr_id)
                return True, self.referenced
        return False, None

    def _part3_deref_operand_8616(self) -> tuple[bool, object]:
        if self.operand is not self.expr.operand:
            self.active_expr_ids.discard(self.expr_id)
            return True, structured_c.CUnaryOp(
                self.expr.op,
                cast(Any, self.operand),
                codegen=_structured_c_codegen_owner_8616(self.expr),
                tags=copy_structured_tags_8616(self.expr.tags) or {},
            )
        return False, None


    def _part3_deref_addr_8616(self) -> tuple[bool, object]:
        if self.expr.op == "Dereference":
            # dynamic-boundary: project is owned by the surrounding angr
            # codegen object, not an Inertia dataclass contract.
            self.project = getattr(self.codegen, "project", None)
            self.displacement = self._ss_linear_stack_base_displacement_expr_8616(self.deref_operand)
            if self.displacement is None:
                self.displacement = _match_bp_stack_dereference_8616(
                    structured_c.CUnaryOp(
                        self.expr.op, cast(Any, self.deref_operand), codegen=_structured_c_codegen_owner_8616(self.expr)
                    ),
                    cast(Any, self.project),
                    self.codegen,
                )
            if self.displacement is None:
                self.alias_state = self._resolve_stack_pointer_alias_expr(self.deref_operand)
                if self.alias_state is not None:
                    self.alias_base_var = getattr(self.alias_state[0], "variable", None)
                    self.candidate_offset = getattr(self.alias_base_var, "offset", None)
                    if isinstance(self.candidate_offset, int):
                        self.displacement = self.candidate_offset + self.alias_state[1]
            done, result = self._part3_deref_offset_8616()
            if done:
                return True, result
            done, result = self._part3_deref_apply_8616()
            if done:
                return True, result
        return False, None
    def _part3_deref_apply_8616(self) -> tuple[bool, object]:
        if isinstance(self.deref_operand, structured_c.CIndexedVariable):
            self.base_ref = self.unwrap_c_casts(self.deref_operand.variable)
            self.index_expr = self.unwrap_c_casts(self.deref_operand.index)
            self.base_var_expr = (
                self.unwrap_c_casts(getattr(self.base_ref, "operand", None))
                if isinstance(self.base_ref, structured_c.CUnaryOp) and self.base_ref.op == "Reference"
                else None
            )
            self.base_var = getattr(self.base_var_expr, "variable", None)
            self.index_value = getattr(self.index_expr, "value", None)
            if (
                isinstance(self.base_var_expr, structured_c.CVariable)
                and isinstance(self.base_var, SimStackVariable)
                and isinstance(self.index_value, int)
            ):
                self.alias_state = self._stack_pointer_aliases().get(id(self.base_var))
                if self.alias_state is not None:
                    self.alias_base_expr, self.alias_offset = self.alias_state
                    self.alias_base_var = getattr(self.alias_base_expr, "variable", None)
                    self.candidate_offset = getattr(self.alias_base_var, "offset", None)
                    self.indexed_resolved_offset = (
                        self.candidate_offset + self.alias_offset if isinstance(self.candidate_offset, int) else None
                    )
                else:
                    self.indexed_resolved_offset = self.base_var.offset
                if isinstance(self.indexed_resolved_offset, int):
                    self.indexed_resolved_offset += self.index_value
                    self.resolved = self.resolve_stack_cvar_at_offset(self.codegen, self.indexed_resolved_offset, preferred_size=2)
                    self.resolved = _prefer_bound_stack_cvar_8616(self.codegen, self.resolved, self.resolve_stack_cvar_at_offset)
                    self.resolved_var = getattr(self.resolved, "variable", None)
                    if (
                        isinstance(self.resolved, structured_c.CVariable)
                        and isinstance(self.resolved_var, SimStackVariable)
                        and getattr(self.resolved_var, "offset", None) == self.indexed_resolved_offset
                    ):
                        _record_stack_canonicalization_bridge_8616(
                            self.codegen,
                            expr=self.expr,
                            resolved_offset=self.indexed_resolved_offset,
                            kind="indexed_deref",
                        )
                        self.debug_stats["candidate_ast_match_count"] += 1
                        self.debug_stats["lowering_replacements"] += 1
                        _debug_stack_condition_rebind_8616(
                            self.codegen, self.expr, self.resolved, note="indexed-deref-resolved"
                        )
                        self.active_expr_ids.discard(self.expr_id)
                        return True, self.resolved
                    if callable(self.materialize_stack_cvar_at_offset):
                        self.materialized = self.materialize_stack_cvar_at_offset(self.codegen, self.indexed_resolved_offset, 2)
                        self.materialized_var = getattr(self.materialized, "variable", None)
                        if (
                            isinstance(self.materialized, structured_c.CVariable)
                            and isinstance(self.materialized_var, SimStackVariable)
                            and getattr(self.materialized_var, "offset", None) == self.indexed_resolved_offset
                        ):
                            self.materialized = _prefer_bound_stack_cvar_8616(
                                self.codegen, self.materialized, self.resolve_stack_cvar_at_offset
                            )
                            _record_stack_canonicalization_bridge_8616(
                                self.codegen,
                                expr=self.expr,
                                resolved_offset=self.indexed_resolved_offset,
                                kind="indexed_deref",
                            )
                            self.debug_stats["candidate_ast_match_count"] += 1
                            self.debug_stats["lowering_replacements"] += 1
                            _debug_stack_condition_rebind_8616(
                                self.codegen, self.expr, self.materialized, note="indexed-deref-materialized"
                            )
                            self.active_expr_ids.discard(self.expr_id)
                            return True, self.materialized
        return False, None

    def _part3_deref_offset_8616(self) -> tuple[bool, object]:
        if isinstance(self.displacement, int):
            self.type_bits = _safe_sim_type_size_bits(self.expr.type)
            self.arch = getattr(getattr(self.codegen, "project", None), "arch", None)
            self.byte_width = getattr(self.arch, "byte_width", None)
            self.access_size = (
                max(self.type_bits // self.byte_width, 1)
                if isinstance(self.type_bits, int)
                and self.type_bits > 0
                and isinstance(self.byte_width, int)
                and self.byte_width > 0
                else 2
            )
            self.resolved = self.resolve_stack_cvar_at_offset(self.codegen, self.displacement, preferred_size=self.access_size)
            self.resolved = _prefer_bound_stack_cvar_8616(self.codegen, self.resolved, self.resolve_stack_cvar_at_offset)
            self.resolved_var = getattr(self.resolved, "variable", None)
            if (
                isinstance(self.resolved, structured_c.CVariable)
                and isinstance(self.resolved_var, SimStackVariable)
                and getattr(self.resolved_var, "offset", None) == self.displacement
            ):
                self.debug_stats["candidate_ast_match_count"] += 1
                self.debug_stats["lowering_replacements"] += 1
                _debug_stack_condition_rebind_8616(self.codegen, self.expr, self.resolved, note="bp-deref-resolved")
                self.active_expr_ids.discard(self.expr_id)
                return True, self.resolved
            if callable(self.materialize_stack_cvar_at_offset):
                self.materialized = self.materialize_stack_cvar_at_offset(self.codegen, self.displacement, self.access_size)
                self.materialized_var = getattr(self.materialized, "variable", None)
                if (
                    isinstance(self.materialized, structured_c.CVariable)
                    and isinstance(self.materialized_var, SimStackVariable)
                    and getattr(self.materialized_var, "offset", None) == self.displacement
                ):
                    self.materialized = _prefer_bound_stack_cvar_8616(
                        self.codegen, self.materialized, self.resolve_stack_cvar_at_offset
                    )
                    self.debug_stats["candidate_ast_match_count"] += 1
                    self.debug_stats["lowering_replacements"] += 1
                    _debug_stack_condition_rebind_8616(
                        self.codegen, self.expr, self.materialized, note="bp-deref-materialized"
                    )
                    self.active_expr_ids.discard(self.expr_id)
                    return True, self.materialized
        return False, None




    def _part3_stackaddr_lane_8616(self) -> tuple[bool, object]:
        if isinstance(self.expr, structured_c.CBinaryOp):
            if self._stack_base_displacement_expr_8616(self.expr) is not None:
                self.active_expr_ids.discard(self.expr_id)
                return True, self.expr
            self.lhs = _canonicalize_stack_cvar_expr(
                self.expr.lhs,
                self.codegen,
                unwrap_c_casts=self.unwrap_c_casts,
                resolve_stack_cvar_at_offset=self.resolve_stack_cvar_at_offset,
                materialize_stack_cvar_at_offset=self.materialize_stack_cvar_at_offset,
                active_expr_ids=self.active_expr_ids,
                analysis_context=self.analysis_context,
            )
            self.rhs = _canonicalize_stack_cvar_expr(
                self.expr.rhs,
                self.codegen,
                unwrap_c_casts=self.unwrap_c_casts,
                resolve_stack_cvar_at_offset=self.resolve_stack_cvar_at_offset,
                materialize_stack_cvar_at_offset=self.materialize_stack_cvar_at_offset,
                active_expr_ids=self.active_expr_ids,
                analysis_context=self.analysis_context,
            )
            if self.lhs is not self.expr.lhs or self.rhs is not self.expr.rhs:
                self.active_expr_ids.discard(self.expr_id)
                _bind_expr_types_to_project_arch_8616(self.lhs, self.codegen)
                _bind_expr_types_to_project_arch_8616(self.rhs, self.codegen)
                return True, structured_c.CBinaryOp(
                    self.expr.op,
                    self.lhs,
                    self.rhs,
                    codegen=self.expr.codegen,
                    tags=copy_structured_tags_8616(self.expr.tags) or {},
                )
            self.active_expr_ids.discard(self.expr_id)
            return True, self.expr
        return False, None

    def _part3_tail_lane_8616(self) -> tuple[bool, object]:
        if isinstance(self.expr, structured_c.CTypeCast):
            self.inner = _canonicalize_stack_cvar_expr(
                self.expr.expr,
                self.codegen,
                unwrap_c_casts=self.unwrap_c_casts,
                resolve_stack_cvar_at_offset=self.resolve_stack_cvar_at_offset,
                materialize_stack_cvar_at_offset=self.materialize_stack_cvar_at_offset,
                active_expr_ids=self.active_expr_ids,
                analysis_context=self.analysis_context,
            )
            if self.inner is not self.expr.expr:
                self.active_expr_ids.discard(self.expr_id)
                return True, CSemanticCast8616(
                    self.expr.src_type,
                    self.expr.dst_type,
                    cast(Any, self.inner),
                    codegen=_structured_c_codegen_owner_8616(self.expr),
                    tags=copy_structured_tags_8616(self.expr.tags) or {},
                )
            self.active_expr_ids.discard(self.expr_id)
            return True, self.expr
        return False, None


def _canonicalize_stack_cvar_expr(
    expr: object,
    codegen: object,
    *,
    unwrap_c_casts: Callable[[object], object],
    resolve_stack_cvar_at_offset: Callable[..., object],
    materialize_stack_cvar_at_offset: Callable[..., object] | None = None,
    active_expr_ids: set[int] | None = None,
    analysis_context: dict[str, object] | None = None,
) -> object:
    return _StackCvarCanonicalize8616(
        expr,
        codegen,
        unwrap_c_casts=unwrap_c_casts,
        resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
        materialize_stack_cvar_at_offset=materialize_stack_cvar_at_offset,
        active_expr_ids=active_expr_ids,
        analysis_context=analysis_context,
    ).run_8616()


def _canonicalize_stack_cvars(
    codegen: object,
    *,
    replace_c_children: Callable[..., bool],
    canonicalize_stack_cvar_expr: Callable[..., object],
) -> bool:
    codegen_dynamic = cast(Any, codegen)
    if getattr(codegen_dynamic, "cfunc", None) is None:
        return False

    changed = False
    analysis_context: dict[str, object] = {}

    def transform(node: object) -> object:
        nonlocal changed
        call_return_binding = bind_call_return_stack_assignment_8616(node, codegen)
        if call_return_binding.changed:
            changed = True
            return call_return_binding.node
        canonical = canonicalize_stack_cvar_expr(node, codegen, analysis_context=analysis_context)
        if canonical is not node:
            changed = True
            return canonical
        return node

    root = codegen_dynamic.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen_dynamic.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform, should_process_child=_safe_child_update_eligible_8616):
        changed = True
    debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
    if isinstance(debug_stats, dict) and changed:
        log.debug(
            "stage=stack_canonicalize function=%#x candidate_ast_match_count=%d lowering_replacements=%d",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            int(debug_stats.get("candidate_ast_match_count", 0) or 0),
            int(debug_stats.get("lowering_replacements", 0) or 0),
        )
    return changed

def _safe_child_update_eligible_8616(current: object, attr: str) -> bool:
    """Return whether a child attribute is safe for the canonicalize rewrite to update."""
    if not isinstance(current, structured_c.CAssignment):
        return True
    if attr != "lhs":
        return True
    lhs = current.lhs
    if isinstance(lhs, (structured_c.CConstant, structured_c.CBinaryOp, structured_c.CIndexedVariable)):
        return False
    if isinstance(lhs, structured_c.CVariable):
        return True
    if isinstance(lhs, structured_c.CTypeCast):
        return True
    return bool(isinstance(lhs, structured_c.CUnaryOp) and lhs.op in {"Dereference", "Reference"})



def _resolve_stack_cvar_from_addr_expr(
    project: object,
    codegen: object,
    addr_expr: object,
    *,
    classify_segmented_addr_expr: Callable[[object, object], _SegmentedAccess | None],
    resolve_stack_cvar_at_offset: Callable[..., object],
    promote_direct_stack_cvariable: Callable[..., object],
    materialize_stack_cvar_at_offset: Callable[..., object],
    stack_type_for_size: Callable[[int], object],
) -> object | None:
    classified = classify_segmented_addr_expr(addr_expr, project)
    if classified is None or classified.kind != "stack" or classified.cvar is None:
        return None

    variable = getattr(classified.cvar, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return None

    target_offset = _canonical_stack_offset_8616(variable.offset)
    if not isinstance(target_offset, int):
        return None

    resolved_offset = target_offset + classified.extra_offset
    resolved = resolve_stack_cvar_at_offset(codegen, resolved_offset, preferred_size=2)
    resolved_variable = getattr(resolved, "variable", None)
    if (
        isinstance(resolved_variable, SimStackVariable)
        and _canonical_stack_offset_8616(getattr(resolved_variable, "offset", None)) == resolved_offset
    ):
        promote_direct_stack_cvariable(codegen, resolved, 2, stack_type_for_size(2))
        return resolved
    return materialize_stack_cvar_at_offset(codegen, resolved_offset, 2)


def _stack_object_name(offset: int, *, codegen: object | None = None) -> str:
    canonical_offset = _canonical_stack_offset_8616(offset)
    if not isinstance(canonical_offset, int):
        return "arg_0"
    offset = canonical_offset

    arg_offsets: set[int] = set()
    cfunc = getattr(codegen, "cfunc", None) if codegen is not None else None
    if cfunc is not None:
        for arg in getattr(cfunc, "arg_list", ()) or ():
            arg_var = getattr(arg, "variable", None)
            if isinstance(arg_var, SimStackVariable):
                arg_offset = _canonical_stack_offset_8616(arg_var.offset)
                if isinstance(arg_offset, int):
                    arg_offsets.add(arg_offset)

    if offset in arg_offsets:
        return f"arg_{offset:x}"

    if offset >= 0:
        return f"local_{offset:x}"
    return f"local_{-offset:x}"
