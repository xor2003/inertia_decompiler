"""Layer: Helper boundary.

Responsibility: summarize typed IR, string-effect, and induction evidence into array-access candidates.
Forbidden: guessing arrays from names, source text, rendered C shape, or postprocess-only patterns.
Dynamic boundary: this module traverses third-party angr codegen/C-AST objects while preserving owned typed evidence contracts.
"""

from __future__ import annotations

import logging
import typing
from dataclasses import dataclass
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CForLoop,
    CIndexedVariable,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from inertia_decompiler.cli_access_profiles import (
    AccessTraitEvidenceProfile,
    AccessTraitInductionVar,
    InductionSummary,
    build_access_trait_evidence_profiles,
    infer_induction_variable,
)

from .c_ast_utils import _replace_c_children_8616, _safe_assign_cfunc_statements_8616, _same_c_expression_8616
from .ir.core import IRAddress
from .type_storage_object_bridge import load_storage_object_bridge

logger: logging.Logger = logging.getLogger(__name__)
MAX_TYPED_ARRAY_CANDIDATES: int = 64


def _limit_sorted_mapping_8616[MappingKey, MappingValue](
    mapping: dict[MappingKey, MappingValue], limit: int
) -> dict[MappingKey, MappingValue]:
    """Limit an already ordered mapping without changing its key/value types."""
    if limit <= 0 or len(mapping) <= limit:
        return mapping
    return dict(list(mapping.items())[:limit])


def _typed_ir_array_candidates(codegen: object) -> dict[tuple[str, tuple[str, ...], int], dict[str, object]]:
    """Collect typed IR address candidates that look like indexed array accesses."""

    def _impl() -> dict[tuple[str, tuple[str, ...], int], dict[str, object]]:
        """Read optional typed IR from the dynamic third-party angr codegen boundary."""
        # Dynamic codegen boundary: typed IR metadata is optional on third-party angr codegen objects.
        artifact = getattr(codegen, "_inertia_vex_ir_artifact", None)
        function_ssa = getattr(codegen, "_inertia_vex_ir_function_ssa", None)
        if artifact is None or not hasattr(artifact, "blocks"):
            return {}

        phi_registers = {
            phi.target.name
            for phi in tuple(function_ssa.phi_nodes if function_ssa is not None else ())
            if phi.target.name is not None
        }
        candidates: dict[tuple[str, tuple[str, ...], int], dict[str, object]] = {}
        for block in tuple(artifact.blocks or ()):
            for instr in tuple(block.instrs or ()):
                for atom in tuple(instr.args or ()):
                    if not isinstance(atom, IRAddress):
                        continue
                    if len(atom.base or ()) < 2:
                        continue
                    if not phi_registers.intersection(set(atom.base)):
                        continue
                    key = (atom.space.value, tuple(atom.base), int(atom.size or 0))
                    candidates[key] = {
                        "space": atom.space.value,
                        "base": tuple(atom.base),
                        "element_size": int(atom.size or 0),
                        "has_phi_index": True,
                    }
        return dict(sorted(candidates.items()))

    return _impl()


def _typed_string_array_candidates(codegen: object) -> dict[tuple[str, tuple[str, ...], int], dict[str, object]]:
    """Collect stable string-effect addresses that look like array bases."""

    def _impl() -> dict[tuple[str, tuple[str, ...], int], dict[str, object]]:
        # Dynamic codegen boundary: string-effect metadata is optional on third-party angr codegen objects.
        artifact = getattr(codegen, "_inertia_string_effect_artifact", None)
        if artifact is None or not hasattr(artifact, "records"):
            return {}

        candidates: dict[tuple[str, tuple[str, ...], int], dict[str, object]] = {}
        for record in tuple(artifact.records or ()):
            for role, address in (("source", record.source), ("destination", record.destination)):
                if not isinstance(address, IRAddress):
                    continue
                if not address.base:
                    continue
                if address.status.value != "stable":
                    continue
                key = (address.space.value, tuple(address.base), int(address.size or 0))
                candidates[key] = {
                    "space": address.space.value,
                    "base": tuple(address.base),
                    "element_size": int(address.size or 0),
                    "has_string_effect": True,
                    "segment_origin": address.segment_origin.value,
                    "string_family": record.family,
                    "repeat_kind": record.repeat_kind,
                    "role": role,
                }
        return dict(sorted(candidates.items()))

    return _impl()


def _cached_access_trait_profiles_8616(
    project: object, func_addr: int
) -> dict[tuple[object, ...], AccessTraitEvidenceProfile] | None:
    """Build cached access-trait profiles across the dynamic compatibility project boundary."""
    # Dynamic compatibility boundary: project-side access-trait caches are optional CLI/fallback metadata.
    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict) or func_addr not in traits_cache:
        return None
    traits = traits_cache.get(func_addr)
    if not isinstance(traits, dict):
        return None

    # Dynamic compatibility boundary: legacy callers may not pre-create the derived profile cache.
    profile_cache = getattr(project, "_inertia_access_trait_profiles_cache", None)
    if not isinstance(profile_cache, dict):
        profile_cache = {}
        typing.cast(typing.Any, project)._inertia_access_trait_profiles_cache = profile_cache

    cache_key = (func_addr, id(traits))
    profiles = profile_cache.get(cache_key)
    if profiles is None:
        typed_traits = cast(dict[str, dict[tuple[object, ...], object]], traits)
        profiles = build_access_trait_evidence_profiles(typed_traits)
        profile_cache[cache_key] = profiles
    if not isinstance(profiles, dict):
        return None
    return cast(dict[tuple[object, ...], AccessTraitEvidenceProfile], profiles)


@dataclass(frozen=True)
class InductionVariable:
    """Represents a loop-carried induction variable with stride."""

    var_name: str
    stride: int  # Bytes per iteration
    base_value: int  # Initial value
    loop_bound: int | None  # Upper bound if known
    element_width: int  # Bit width of element (8, 16, 32)

    def __repr__(self) -> str:
        return f"IndVar({self.var_name}, stride={self.stride}, width={self.element_width})"


def _access_trait_induction_var_8616(candidate: AccessTraitInductionVar, variable: object) -> InductionVariable:
    """Convert CLI access-trait induction evidence into the owned array-matching contract."""
    var_name = variable.name or f"reg_{variable.reg}" if isinstance(variable, SimRegisterVariable) else "reg_unknown"
    return InductionVariable(
        var_name=var_name,
        stride=int(candidate.stride),
        base_value=int(candidate.offset),
        loop_bound=None,
        element_width=int(candidate.width),
    )


@dataclass
class ArrayAccessPattern:
    """Detected array access pattern."""

    base_expr: str  # Base pointer
    index_var: str  # Index variable
    stride: int  # Bytes per element
    offset: int  # Constant offset
    element_type: str  # "int", "char", "ptr", etc.
    element_width: int  # Bit width

    def __repr__(self) -> str:
        return f"Array({self.base_expr}[{self.index_var} * {self.stride} + {self.offset}]:{self.element_type})"


@dataclass
class ArrayRecoveryInfo:
    """Information about recovered array structure."""

    array_name: str
    base_ptr: str
    element_type: str
    element_width: int
    element_stride: int
    access_patterns: set[str]  # Collected access patterns
    confidence: float  # 0.0-1.0 based on pattern consistency

    def __repr__(self) -> str:
        return f"ArrayInfo({self.array_name}: {self.element_type}[{len(self.access_patterns)} accesses])"


class InductionVariableCollector:
    """Collect loop induction variables with stride patterns.

    Identifies variables that are:
    - Incremented/decremented by constant stride each iteration
    - Used as array indices or pointer offsets
    - Loop-carried across function calls
    """

    def __init__(self) -> None:
        self.induction_vars: dict[str, InductionVariable] = {}
        self.stride_patterns: dict[str, int] = {}

    def collect(self, expressions: list[str]) -> dict[str, InductionVariable]:
        """Collect induction variables from expression list.

        Args:
            expressions: List of expression strings

        Returns:
            Dictionary mapping variable name to InductionVariable
        """
        # Placeholder: would analyze loop bodies and variable updates
        # For now, demonstrate structure

        for expr in expressions:
            if "+=" in expr or "-=" in expr:
                self._analyze_update_expr(expr)

        return self.induction_vars

    def _analyze_update_expr(self, expr: str) -> None:
        """Analyze variable update expression for stride patterns."""
        # Example: "si += 2" or "di -= 4"
        if "+=" in expr:
            parts = expr.split("+=")
            if len(parts) == 2:
                var = parts[0].strip()
                stride_str = parts[1].strip()
                try:
                    stride = int(stride_str)
                    self.stride_patterns[var] = stride
                    self.induction_vars[var] = InductionVariable(
                        var_name=var, stride=stride, base_value=0, loop_bound=None, element_width=16
                    )
                except ValueError:
                    pass


class ArrayExpressionMatcher:
    """Detect and match array access patterns.

    Recognizes:
    - Simple indexed access: base[index]
    - Strided access: base + index * stride
    - Offset access: base + index * stride + offset
    - Nested arrays: base[i][j]
    """

    def __init__(self) -> None:
        self.detected_patterns: list[ArrayAccessPattern] = []
        self.array_infos: dict[str, ArrayRecoveryInfo] = {}

    def match_patterns(
        self, expressions: list[str], induction_vars: dict[str, InductionVariable]
    ) -> list[ArrayAccessPattern]:
        """Match array access patterns in expressions.

        Args:
            expressions: List of expression strings
            induction_vars: Known induction variables with strides

        Returns:
            List of detected ArrayAccessPattern
        """
        patterns = []

        for expr in expressions:
            if self._looks_like_array_access(expr):
                pattern = self._extract_array_pattern(expr, induction_vars)
                if pattern:
                    patterns.append(pattern)
                    self.detected_patterns.append(pattern)

        return patterns

    def _looks_like_array_access(self, expr: str) -> bool:
        """Heuristic check if expression might be array access."""
        # Check for patterns like "[", "*", "+", "-"
        return any(marker in expr for marker in ["[", "mem[", "*"])

    def _extract_array_pattern(
        self, expr: str, induction_vars: dict[str, InductionVariable]
    ) -> ArrayAccessPattern | None:
        """Extract array pattern from expression if possible."""
        # Placeholder: would parse expression into base, index, stride, offset
        # For now, return generic pattern

        for var_name, ind_var in induction_vars.items():
            if var_name in expr:
                # Found expression with induction variable
                return ArrayAccessPattern(
                    base_expr="array_base",
                    index_var=var_name,
                    stride=ind_var.stride,
                    offset=0,
                    element_type="int",
                    element_width=ind_var.element_width,
                )

        return None

    def synthesize_arrays(self, patterns: list[ArrayAccessPattern]) -> dict[str, ArrayRecoveryInfo]:
        """Synthesize array recovery info from matched patterns.

        Groups patterns by base expression to recover array structure.

        Args:
            patterns: List of detected array access patterns

        Returns:
            Dictionary mapping base_expr to ArrayRecoveryInfo
        """
        arrays: dict[str, ArrayRecoveryInfo] = {}

        for pattern in patterns:
            if pattern.base_expr not in arrays:
                arrays[pattern.base_expr] = ArrayRecoveryInfo(
                    array_name=f"array_{pattern.base_expr}",
                    base_ptr=pattern.base_expr,
                    element_type=pattern.element_type,
                    element_width=pattern.element_width,
                    element_stride=pattern.stride,
                    access_patterns=set(),
                    confidence=0.5,
                )

            arrays[pattern.base_expr].access_patterns.add(str(pattern))

            # Increase confidence with more consistent patterns
            num_patterns = len(arrays[pattern.base_expr].access_patterns)
            arrays[pattern.base_expr].confidence = min(1.0, 0.5 + (num_patterns * 0.1))

        self.array_infos = arrays
        return arrays


def _invert_cmp_op_8616(op: str) -> str | None:
    return {
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
    }.get(op)


def _literal_true_8616(node: object) -> bool:
    return isinstance(node, CConstant) and isinstance(node.value, int) and node.value != 0


def _extract_break_guard_8616(stmt: object) -> object | None:
    def _impl() -> object | None:
        if type(stmt).__name__ not in {"CIfElse", "CIfBreak"}:
            return None
        # Dynamic angr boundary: CIfElse/CIfBreak expose variant-specific children outside a common typed base.
        cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
        if not isinstance(cond_nodes, (tuple, list)) or len(cond_nodes) != 1:
            return None
        cond_body = cond_nodes[0]
        if not isinstance(cond_body, (tuple, list)) or len(cond_body) != 2:
            return None
        cond, body = cond_body
        if not isinstance(body, CStatements) or len(body.statements or ()) != 1:
            return None
        if not isinstance(body.statements[0], CBreak):
            return None
        # Dynamic angr boundary: else_node exists only on the CIfElse-shaped guard variant.
        else_node = getattr(stmt, "else_node", None)
        if else_node is not None and not (isinstance(else_node, CStatements) and not else_node.statements):
            return None
        return cast(object, cond)

    return _impl()


def _extract_monotonic_update_8616(stmt: object) -> tuple[CVariable, int] | None:
    def _impl() -> tuple[CVariable, int] | None:
        if not isinstance(stmt, CAssignment) or not isinstance(stmt.lhs, CVariable):
            return None
        rhs = stmt.rhs
        if not isinstance(rhs, CBinaryOp) or rhs.op not in {"Add", "Sub"}:
            return None
        if (
            _same_c_expression_8616(rhs.lhs, stmt.lhs)
            and isinstance(rhs.rhs, CConstant)
            and isinstance(rhs.rhs.value, int)
        ):
            delta = rhs.rhs.value if rhs.op == "Add" else -rhs.rhs.value
            return stmt.lhs, delta
        if (
            rhs.op == "Add"
            and _same_c_expression_8616(rhs.rhs, stmt.lhs)
            and isinstance(rhs.lhs, CConstant)
            and isinstance(rhs.lhs.value, int)
        ):
            return stmt.lhs, rhs.lhs.value
        return None

    return _impl()


def _cond_uses_var_8616(node: object, target: object) -> bool:
    if isinstance(node, CVariable):
        return bool(_same_c_expression_8616(node, target))
    target_key = _expr_index_key_8616(target)
    if target_key is not None and _expr_index_key_8616(node) == target_key:
        return True
    for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval"):
        # Dynamic angr boundary: recursive C-AST traversal crosses expression variants with different child names.
        child = getattr(node, attr, None)
        if child is not None and _cond_uses_var_8616(child, target):
            return True
    return False


def _loop_index_key_8616(loop_var: object) -> tuple[object, ...] | None:
    # Dynamic angr boundary: CVariable wraps several SimVariable subclasses behind a common .variable slot.
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


def _expr_index_key_8616(expr: object) -> tuple[object, ...] | None:
    def _impl() -> tuple[object, ...] | None:
        if isinstance(expr, CVariable):
            return _loop_index_key_8616(expr)
        if isinstance(expr, CTypeCast):
            return _expr_index_key_8616(expr.expr)
        if isinstance(expr, CUnaryOp) and expr.op in {"Dereference", "Reference"}:
            return _expr_index_key_8616(expr.operand)
        if isinstance(expr, CIndexedVariable):
            base_expr = expr.variable
            if isinstance(base_expr, CUnaryOp) and base_expr.op == "Reference":
                base_expr = base_expr.operand
            index_expr = expr.index
            if (
                not isinstance(base_expr, CVariable)
                or not isinstance(index_expr, CConstant)
                or not isinstance(index_expr.value, int)
            ):
                return None
            variable = base_expr.variable
            if not isinstance(variable, SimStackVariable):
                return None
            base = variable.base
            offset = variable.offset
            region = variable.region
            if base is None or not isinstance(offset, int):
                return None
            return ("stack", base, offset + int(index_expr.value), region)
        return None

    return _impl()


def _unwrap_double_negation_8616(node: object) -> object | None:
    if (
        isinstance(node, CUnaryOp)
        and node.op == "Not"
        and isinstance(node.operand, CUnaryOp)
        and node.operand.op == "Not"
    ):
        return cast(object, node.operand.operand)
    return None


def _condition_index_key_8616(node: object) -> tuple[object, ...] | None:
    if isinstance(node, CBinaryOp):
        lhs_key = _expr_index_key_8616(node.lhs)
        if lhs_key is not None:
            return lhs_key
        rhs_key = _expr_index_key_8616(node.rhs)
        if rhs_key is not None:
            return rhs_key
    return None


def _typed_induction_summaries_8616(codegen: object) -> tuple[InductionSummary, ...]:
    """Return typed induction summaries attached by the structuring stage."""
    # Dynamic codegen boundary: structuring attaches optional induction summaries to angr codegen objects.
    summaries = getattr(codegen, "_inertia_induction_summaries", ()) or ()
    return tuple(summary for summary in summaries if isinstance(summary, InductionSummary))


def _has_induction_evidence_for_key_8616(codegen: object, index_key: tuple[object, ...]) -> bool:
    def _impl() -> bool:
        """Check induction evidence through the dynamic third-party angr codegen/project boundary."""
        summaries = _typed_induction_summaries_8616(codegen)
        if any(summary.index_key == index_key for summary in summaries):
            return True
        # Dynamic codegen boundary: project/cfunc are third-party angr codegen attachments.
        project = getattr(codegen, "project", None)
        cfunc = getattr(codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None)
        if project is None or not isinstance(func_addr, int):
            return False
        profiles = _cached_access_trait_profiles_8616(project, func_addr)
        if profiles is None:
            return False
        direct_profile = profiles.get(index_key)
        if direct_profile is not None and infer_induction_variable(direct_profile) is not None:
            return True
        for profile in profiles.values():
            candidate = infer_induction_variable(profile)
            if candidate is not None and candidate.index_key == index_key:
                return True
        return False

    return _impl()


def _best_typed_induction_summary_8616(
    summaries: object,
    index_key: object,
) -> object | None:
    """Return the highest-scoring typed summary for one index key."""
    best_summary = None
    best_summary_score: tuple[int, int, int] | None = None
    for summary in summaries:
        if summary.index_key != index_key:
            continue
        summary_score: tuple[int, int, int] = (
            int(summary.count),
            abs(int(summary.stride)),
            int(summary.width),
        )
        if best_summary_score is None or summary_score > best_summary_score:
            best_summary = summary
            best_summary_score = summary_score
    return best_summary


def _best_profile_induction_match_8616(
    profiles: object,
    index_key: object,
    variable: object,
) -> InductionVariable | None:
    """Return the best access-trait induction match for one index key."""
    direct_profile = profiles.get(index_key)
    if direct_profile is not None:
        direct_match = infer_induction_variable(direct_profile)
        if direct_match is not None and direct_match.index_key == index_key:
            return _access_trait_induction_var_8616(direct_match, variable)

    best_match: InductionVariable | None = None
    best_score: tuple[int, int, int, int] | None = None
    for profile_key, profile in profiles.items():
        candidate = infer_induction_variable(profile)
        if candidate is None or candidate.index_key != index_key:
            continue
        candidate_score: tuple[int, int, int, int] = (
            int(candidate.count),
            abs(int(candidate.stride)),
            int(candidate.width),
            1 if profile_key == index_key else 0,
        )
        if best_score is None or candidate_score > best_score:
            best_match = _access_trait_induction_var_8616(candidate, variable)
            best_score = candidate_score
    return best_match


def _profile_induction_match_8616(codegen: object, loop_var: object) -> InductionVariable | None:
    """Match induction evidence through the dynamic third-party angr codegen/project boundary."""
    # Dynamic angr boundary: CVariable-compatible loop nodes expose the wrapped SimVariable dynamically.
    variable = getattr(loop_var, "variable", None)
    index_key = _loop_index_key_8616(loop_var)
    if variable is None or index_key is None:
        return None

    best_summary = _best_typed_induction_summary_8616(_typed_induction_summaries_8616(codegen), index_key)
    if best_summary is not None:
        var_name = variable.name if isinstance(variable, SimRegisterVariable) else "reg_unknown"
        return InductionVariable(
            var_name=var_name or f"reg_{variable.reg}",
            stride=int(best_summary.stride),
            base_value=int(best_summary.offset),
            loop_bound=int(best_summary.bound_candidate) if best_summary.bound_candidate is not None else None,
            element_width=int(best_summary.width),
        )

    # Dynamic codegen boundary: access-trait evidence is attached to third-party angr project/codegen objects.
    project = getattr(codegen, "project", None)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return None

    profiles = _cached_access_trait_profiles_8616(project, func_addr)
    if profiles is None:
        return None
    return _best_profile_induction_match_8616(profiles, index_key, variable)


@dataclass
class _InductionLoopRewrite8616:
    """Mutable run state for induction-loop condition rewriting."""

    codegen: object
    changed: bool = False

    @staticmethod
    def _last_monotonic_update(statements: list[object]) -> object | None:
        """Return the last monotonic update statement, or None."""
        for stmt in reversed(statements[1:]):
            update = _extract_monotonic_update_8616(stmt)
            if update is not None:
                return update
        return None

    def _rewrite_while_loop(self, node: CWhileLoop) -> object:
        """Convert while(1)+guard+update into a bounded loop condition."""
        if not _literal_true_8616(node.condition):
            return node
        body = node.body
        if not isinstance(body, CStatements):
            return node
        statements = list(body.statements or ())
        if len(statements) < 2:
            return node
        guard = _extract_break_guard_8616(statements[0])
        if not isinstance(guard, CBinaryOp):
            return node
        inverted = _invert_cmp_op_8616(guard.op)
        if inverted is None:
            return node

        update = self._last_monotonic_update(statements)
        if update is None:
            return node
        loop_var, _delta = update
        if not _cond_uses_var_8616(guard, loop_var):
            return node
        induction_info = _profile_induction_match_8616(self.codegen, loop_var)
        if induction_info is None:
            return node
        if abs(int(_delta)) != int(induction_info.stride):
            return node

        node.condition = CBinaryOp(
            inverted,
            guard.lhs,
            guard.rhs,
            codegen=self.codegen,
            tags=guard.tags,
        )
        body.statements = statements[1:]
        self.changed = True
        return node

    def transform(self, node: object) -> object:
        """Rewrite one node when induction evidence supports it."""
        if isinstance(node, CForLoop):
            simplified = _unwrap_double_negation_8616(node.condition)
            if simplified is not None:
                index_key = _condition_index_key_8616(simplified)
                if index_key is not None and _has_induction_evidence_for_key_8616(self.codegen, index_key):
                    node.condition = simplified
                    self.changed = True
            return node
        if not isinstance(node, CWhileLoop):
            return node
        return self._rewrite_while_loop(node)


def _rewrite_induction_loops_8616(codegen: object) -> bool:
    """Rewrite induction loop shape at the dynamic third-party angr codegen boundary."""
    # Dynamic codegen boundary: this pass is called with third-party angr codegen instances.
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    rewrite = _InductionLoopRewrite8616(codegen=codegen)

    root = cfunc.statements
    new_root = rewrite.transform(root)
    if new_root is not root:
        root = _safe_assign_cfunc_statements_8616(codegen, new_root, root)
        if hasattr(cfunc, "body"):
            cfunc.body = cfunc.statements
    if _replace_c_children_8616(cfunc.statements, rewrite.transform):
        rewrite.changed = True
    return rewrite.changed


def apply_x86_16_array_expression_matching(codegen: object) -> bool:
    """Attach array matching evidence to an angr codegen object without rewriting semantics."""

    def _impl() -> bool:
        """Attach optional array metadata across the dynamic third-party angr codegen boundary."""
        # Dynamic codegen boundary: angr codegen supplies cfunc/project at runtime.
        if getattr(codegen, "cfunc", None) is None:
            return False

        try:
            # Dynamic codegen boundary: project and function address live on third-party angr objects.
            project = getattr(codegen, "project", None)
            function_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
            bridge = None
            if project is not None:
                bridge = load_storage_object_bridge(project, function_addr, codegen=codegen)
            lowerable_arrays = (
                {}
                if bridge is None
                else {
                    base_key: fact
                    for base_key, fact in bridge.array_facts.items()
                    if bridge.allows_object_lowering(base_key)
                }
            )
            refused_arrays = (
                {}
                if bridge is None
                else {
                    base_key: bridge.lowering_refusal_reason(base_key)
                    for base_key in bridge.array_facts
                    if not bridge.allows_object_lowering(base_key)
                }
            )
            typed_ir_candidates = _typed_ir_array_candidates(codegen)
            typed_string_candidates = _typed_string_array_candidates(codegen)
            typed_ir_candidates = _limit_sorted_mapping_8616(typed_ir_candidates, MAX_TYPED_ARRAY_CANDIDATES)
            typed_string_candidates = _limit_sorted_mapping_8616(typed_string_candidates, MAX_TYPED_ARRAY_CANDIDATES)
            # Dynamic codegen boundary: attach optional array-matching metadata to third-party angr codegen.
            typing.cast(typing.Any, codegen)._inertia_array_matching_applied = True
            typing.cast(typing.Any, codegen)._inertia_array_matching_bridge = bridge
            typing.cast(typing.Any, codegen)._inertia_array_matching_lowerable_arrays = lowerable_arrays
            typing.cast(typing.Any, codegen)._inertia_array_matching_refused_arrays = refused_arrays
            typing.cast(typing.Any, codegen)._inertia_array_matching_typed_ir_candidates = typed_ir_candidates
            typing.cast(typing.Any, codegen)._inertia_array_matching_string_candidates = typed_string_candidates
            typing.cast(typing.Any, codegen)._inertia_array_matching_stats = {
                "induction_vars": len(typed_ir_candidates),
                "array_patterns": 0 if bridge is None else len(bridge.array_facts),
                "recovered_arrays": len(lowerable_arrays) + len(typed_ir_candidates) + len(typed_string_candidates),
                "refused_arrays": len(refused_arrays),
                "string_arrays": len(typed_string_candidates),
            }

            changed = _rewrite_induction_loops_8616(codegen)
            logger.debug("Array expression matching pass completed")
            return changed
        except Exception as ex:
            logger.warning("Array expression matching pass failed: %s", ex)
            # Dynamic codegen boundary: preserve the failure reason on the third-party codegen object for diagnostics.
            typing.cast(typing.Any, codegen)._inertia_array_matching_error = str(ex)
            return False

    return _impl()
