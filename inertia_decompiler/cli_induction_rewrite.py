"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

type BaseKey = tuple[object, ...]
type BuildAccessTraitEvidenceProfiles = Callable[[dict[str, dict[BaseKey, object]]], dict[BaseKey, object]]
type InferInductionVariable = Callable[[object], object | None]


class _CFunctionLike(Protocol):
    """Structured C function surface needed by induction condition rewriting."""

    addr: int
    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by induction condition rewriting."""

    cfunc: _CFunctionLike | None


class _ProjectLike(Protocol):
    """Project cache surface used by induction condition rewriting."""

    _inertia_access_traits: object


def _loop_index_key(loop_var: object) -> BaseKey | None:
    # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
    variable = getattr(loop_var, "variable", None)
    if isinstance(variable, SimRegisterVariable):
        return ("reg", variable.reg)
    if isinstance(variable, SimStackVariable):
        base = variable.base
        offset = variable.offset
        region = variable.region
        if base is None or offset is None:
            return None
        return ("stack", base, offset, region)
    if isinstance(variable, SimMemoryVariable):
        addr = variable.addr
        if addr is None:
            return None
        return ("mem", addr)
    return None


def _const_int(node: object) -> int | None:
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return int(node.value)
    return None


def _expr_index_key(expr: object) -> BaseKey | None:
    def _impl() -> BaseKey | None:
        if isinstance(expr, structured_c.CVariable):
            return _loop_index_key(expr)
        if isinstance(expr, structured_c.CTypeCast):
            return _expr_index_key(expr.expr)
        if isinstance(expr, structured_c.CUnaryOp) and expr.op in {"Dereference", "Reference"}:
            return _expr_index_key(expr.operand)
        if not isinstance(expr, structured_c.CIndexedVariable):
            return None
        # Dynamic codegen boundary: indexed variable base payload is supplied by angr structured C.
        base_expr = getattr(expr, "variable", None)
        if isinstance(base_expr, structured_c.CUnaryOp) and base_expr.op == "Reference":
            base_expr = base_expr.operand
        # Dynamic codegen boundary: indexed variable index payload is supplied by angr structured C.
        index_value = _const_int(getattr(expr, "index", None))
        if not isinstance(base_expr, structured_c.CVariable) or not isinstance(index_value, int):
            return None
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        variable = getattr(base_expr, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        base = variable.base
        offset = variable.offset
        region = variable.region
        if base is None or not isinstance(offset, int):
            return None
        return ("stack", base, offset + index_value, region)

    return _impl()


def _condition_index_key(node: object) -> BaseKey | None:
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    lhs_key = _expr_index_key(node.lhs)
    if lhs_key is not None:
        return lhs_key
    return _expr_index_key(node.rhs)


def _unwrap_boolified_condition(node: object) -> structured_c.CBinaryOp | None:
    """Extract a comparison from supported boolean wrappers without changing it."""
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Not":
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CUnaryOp) and operand.op == "Not":
        cond = operand.operand
        if isinstance(cond, structured_c.CBinaryOp):
            return cond
        return None
    if type(operand).__name__ != "CITE":
        return None
    # Dynamic codegen boundary: CITE condition arms are supplied by angr structured C.
    if _const_int(getattr(operand, "iftrue", None)) != 0:
        return None
    # Dynamic codegen boundary: CITE condition arms are supplied by angr structured C.
    if _const_int(getattr(operand, "iffalse", None)) != 1:
        return None
    # Dynamic codegen boundary: CITE condition payload is supplied by angr structured C.
    ite_cond = getattr(operand, "cond", None)
    if not isinstance(ite_cond, structured_c.CBinaryOp):
        return None
    return ite_cond


def _induction_candidate_index_key(candidate: object) -> object | None:
    # Dynamic codegen boundary: induction candidates are supplied by access-trait inference.
    return getattr(candidate, "index_key", None)


def _stable_induction_index_keys_8616(
    traits: dict,
    build_access_trait_evidence_profiles: BuildAccessTraitEvidenceProfiles,
    infer_induction_variable: InferInductionVariable,
) -> set[object]:
    """Collect index keys for access-trait profiles that prove an induction variable."""
    stable_index_keys: set[object] = set()
    for profile in build_access_trait_evidence_profiles(traits).values():
        index_key = _induction_candidate_index_key(infer_induction_variable(profile))
        if index_key is not None:
            stable_index_keys.add(index_key)
    return stable_index_keys


def rewrite_for_loop_conditions_from_access_traits(
    project: _ProjectLike,
    codegen: _CodegenLike,
    *,
    build_access_trait_evidence_profiles: BuildAccessTraitEvidenceProfiles,
    infer_induction_variable: InferInductionVariable,
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
) -> bool:
    """Simplify boolified for-loop conditions only when access-trait induction evidence proves the index."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return False
    cache = project._inertia_access_traits
    if not isinstance(cache, dict):
        return False
    traits = cache.get(cfunc.addr)
    if not isinstance(traits, dict):
        return False

    stable_index_keys = _stable_induction_index_keys_8616(
        traits, build_access_trait_evidence_profiles, infer_induction_variable
    )
    if not stable_index_keys:
        return False

    changed = False
    for node in iter_c_nodes_deep(cfunc.statements):
        if not isinstance(node, structured_c.CForLoop):
            continue
        simplified = _unwrap_boolified_condition(node.condition)
        if simplified is None:
            continue
        index_key = _condition_index_key(simplified)
        if index_key not in stable_index_keys:
            continue
        node.condition = simplified
        changed = True
    return changed

