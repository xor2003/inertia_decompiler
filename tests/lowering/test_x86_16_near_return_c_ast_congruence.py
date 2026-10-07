"""Identity-bound operand congruence tests for the near scaled-return proof.

Layer: Tests.
Responsibility: prove the staged congruence checker binds the retained IR
coefficients to exact canonical stack variables, and refuses every control
shape that would weaken numeric congruence into text or offset-only identity.
"""

from __future__ import annotations

import copy
import io
from dataclasses import replace
from functools import lru_cache
from types import SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
)
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.near_return_c_ast_congruence import (
    NearReturnOperandCongruenceFailure8616,
    NearReturnOperandCongruenceStats8616,
    NearReturnOperandCongruenceVerdict8616,
    NearReturnOperandRole8616,
    bind_near_return_offset_c_ast_8616,
)
from inertia.lowering.near_scaled_return_candidate import (
    NearScaledReturnCandidateFailure8616,
    NearScaledReturnCandidateResult8616,
    NearScaledReturnCandidateVerdict8616,
    collect_near_scaled_return_candidate_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_alias_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)

from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from inertia.semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)

_CODE = bytes.fromhex(
    "55 8b ec b8 00 00 e8 c2 04 57 56 8b 46 06 d1 e0 "
    "03 46 04 e9 00 00 5e 5f 8b e5 5d c3"
)
_FUNC_ADDR = 0x10F1
_FUNC_END = 0x110D
_ENTRY_SP_BIAS = 6
_BASE = IRAddress(
    space=MemSpace.SS, base=("bp",), offset=4, size=2,
    status=AddressStatus.STABLE, segment_origin=SegmentOrigin.PROVEN,
)
_INDEX = replace(_BASE, offset=6)


class _StubCodegen:
    """Minimal angr structured-codegen boundary with its allocator API."""

    def __init__(self, project: object, function_addr: int) -> None:
        self._idx = 0
        self.project = project
        self.cfunc = SimpleNamespace(addr=function_addr, statements=None)
        self.cstyle_null_cmp = False

    def next_ident(self, name: str) -> str:
        """Return a stable class display identity."""
        return name

    def next_node_idx(self) -> int:
        """Return one unique C AST node identity."""
        self._idx += 1
        return self._idx


def _project() -> angr.Project:
    """Build the blob image carrying the proven scaled-return bytes."""
    image = bytearray(0x5BE)
    image[0xF1 : 0xF1 + len(_CODE)] = _CODE
    image[0x5BC] = 0xC3
    image[0x5BD] = 0xC3
    return angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": _FUNC_ADDR,
        },
        auto_load_libs=False,
        simos="DOS",
    )


def _boundary(project: angr.Project) -> ExactFunctionRangeBoundary8616:
    """Return the exact byte-verified boundary for the fixture function."""
    boundary = exact_function_range_boundary_8616(project, _FUNC_ADDR, _FUNC_END)
    assert boundary is not None
    return boundary


@lru_cache(maxsize=1)
def _proven_candidate() -> tuple[angr.Project, NearScaledReturnCandidateResult8616]:
    """Register the Semantics SSA once and retain the proven candidate."""
    project = _project()
    boundary = _boundary(project)
    resolution = semantic_function_ssa_artifact_at_address_8616(
        project, _FUNC_ADDR, function=boundary,
    )
    assert resolution.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    candidate = collect_near_scaled_return_candidate_8616(
        project, _FUNC_ADDR, _BASE, _INDEX, function=boundary,
    )
    assert candidate.complete
    return project, candidate


def _record_word_arg(
    codegen: object, bp_offset: int, name: str
) -> structured_c.CVariable:
    """Project one exact machine-BP word to a canonical C variable."""
    variable = SimStackVariable(
        bp_offset - _ENTRY_SP_BIAS, 2, base="bp", name=name,
        ident=f"is_{bp_offset:x}",
    )
    cvar = structured_c.CVariable(
        variable, variable_type=SimTypeShort(False), codegen=codegen
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=bp_offset,
        entry_sp_offset=bp_offset - _ENTRY_SP_BIAS,
        size=2,
    )
    return cvar


def _case() -> tuple[
    _StubCodegen,
    NearScaledReturnCandidateResult8616,
    dict[str, structured_c.CVariable],
]:
    """Pair the proven candidate with a stub codegen and canonical args."""
    project, candidate = _proven_candidate()
    codegen = _StubCodegen(project, _FUNC_ADDR)
    cvars = {
        "base": _record_word_arg(codegen, _BASE.offset, "arg_base"),
        "index": _record_word_arg(codegen, _INDEX.offset, "arg_index"),
    }
    return codegen, candidate, cvars


def _const(codegen: object, value: int) -> structured_c.CConstant:
    """Build one 16-bit integer literal node."""
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def _add(
    codegen: object,
    lhs: structured_c.CExpression,
    rhs: structured_c.CExpression,
) -> structured_c.CBinaryOp:
    """Build ``lhs + rhs``."""
    return structured_c.CBinaryOp("Add", lhs, rhs, codegen=codegen)


def _sub(
    codegen: object,
    lhs: structured_c.CExpression,
    rhs: structured_c.CExpression,
) -> structured_c.CBinaryOp:
    """Build ``lhs - rhs``."""
    return structured_c.CBinaryOp("Sub", lhs, rhs, codegen=codegen)


def _mul(
    codegen: object,
    expr: structured_c.CExpression,
    factor: int,
) -> structured_c.CBinaryOp:
    """Build ``expr * factor``."""
    return structured_c.CBinaryOp(
        "Mul", expr, _const(codegen, factor), codegen=codegen
    )


def _shl(
    codegen: object, expr: structured_c.CExpression, amount: int
) -> structured_c.CBinaryOp:
    """Build ``expr << amount``."""
    return structured_c.CBinaryOp(
        "Shl", expr, _const(codegen, amount), codegen=codegen
    )


def _cast(
    codegen: object, expr: structured_c.CExpression, dst_type: SimType
) -> structured_c.CTypeCast:
    """Build a C cast of ``expr`` to ``dst_type``."""
    return structured_c.CTypeCast(None, dst_type, expr, codegen=codegen)


def _scaled_offset(codegen: object, cvars: dict[str, structured_c.CVariable]) -> structured_c.CBinaryOp:
    """Build the proven ``(index << 1) + base`` operand order."""
    return _add(codegen, _shl(codegen, cvars["index"], 1), cvars["base"])


def test_shl_add_offset_binds_canonical_operands() -> None:
    """``(index << 1) + base`` binds both proven word roles by identity."""
    codegen, candidate, cvars = _case()
    expression = _scaled_offset(codegen, cvars)

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)

    assert result.complete
    assert result.verdict is NearReturnOperandCongruenceVerdict8616.CONGRUENT
    assert result.failure is None
    assert result.callee_addr == _FUNC_ADDR
    assert result.candidate is candidate
    assert result.expression is expression
    assert result.stats == NearReturnOperandCongruenceStats8616(1, 1, 1, 1, 0)
    by_role = {operand.role: operand for operand in result.bound_operands}
    base = by_role[NearReturnOperandRole8616.OFFSET_BASE]
    index = by_role[NearReturnOperandRole8616.OFFSET_INDEX]
    assert base.cvar is cvars["base"]
    assert index.cvar is cvars["index"]
    assert base.storage == _BASE and index.storage == _INDEX
    assert base.coefficient == 1 and index.coefficient == 2


def test_reversed_add_order_stays_congruent() -> None:
    """``base + (index << 1)`` keeps the same modular affine form."""
    codegen, candidate, cvars = _case()
    expression = _add(codegen, cvars["base"], _shl(codegen, cvars["index"], 1))

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)

    assert result.complete


def test_constant_multiply_binds_like_shift() -> None:
    """``base + index * 2`` equals the proven scaled sum modulo 2^16."""
    codegen, candidate, cvars = _case()
    expression = _add(codegen, cvars["base"], _mul(codegen, cvars["index"], 2))

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)

    assert result.complete


def test_full_word_unsigned_cast_is_transparent() -> None:
    """An unsigned word or wider integer view preserves the bit pattern."""
    codegen, candidate, cvars = _case()
    inner = _scaled_offset(codegen, cvars)

    word = bind_near_return_offset_c_ast_8616(
        codegen, candidate, _cast(codegen, inner, SimTypeShort(False))
    )
    wide = bind_near_return_offset_c_ast_8616(
        codegen, candidate, _cast(codegen, inner, SimTypeLong(False))
    )

    assert word.complete
    assert wide.complete


def test_cloned_cvar_retaining_canonical_variable_binds() -> None:
    """A copied CVariable binds when it keeps the exact stack variable."""
    codegen, candidate, cvars = _case()
    cloned_index = copy.copy(cvars["index"])
    assert cloned_index.variable is cvars["index"].variable
    expression = _add(codegen, cvars["base"], _shl(codegen, cloned_index, 1))

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)

    assert result.complete


def test_swapped_variable_roles_refuse() -> None:
    """``index + (base << 1)`` carries the wrong proven coefficient map."""
    codegen, candidate, cvars = _case()
    expression = _add(codegen, cvars["index"], _shl(codegen, cvars["base"], 1))

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)

    assert result.failure is NearReturnOperandCongruenceFailure8616.AFFINE_MISMATCH
    assert result.stats == NearReturnOperandCongruenceStats8616(1, 1, 1, 0, 1)
    assert not result.complete


def test_wrong_scale_constant_and_subtraction_refuse() -> None:
    """Shift by 2, an extra +1, and base-minus-index all change the form."""
    codegen, candidate, cvars = _case()
    shifted_two = _add(codegen, cvars["base"], _shl(codegen, cvars["index"], 2))
    offset_one = _add(codegen, _scaled_offset(codegen, cvars), _const(codegen, 1))
    subtracted = _sub(codegen, cvars["base"], cvars["index"])

    for expression in (shifted_two, offset_one, subtracted):
        result = bind_near_return_offset_c_ast_8616(
            codegen, candidate, expression
        )
        assert (
            result.failure
            is NearReturnOperandCongruenceFailure8616.AFFINE_MISMATCH
        )
        assert result.stats.materialized_count == 0
        assert not result.complete


def test_unregistered_variable_at_same_offset_refuses() -> None:
    """A distinct SimStackVariable object is never the canonical operand."""
    codegen, candidate, cvars = _case()
    impostor = structured_c.CVariable(
        SimStackVariable(
            _BASE.offset - _ENTRY_SP_BIAS, 2, base="bp",
            name="arg_base", ident="is_4",
        ),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expression = _add(codegen, impostor, _shl(codegen, cvars["index"], 1))

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)

    assert result.failure is NearReturnOperandCongruenceFailure8616.OPERAND_UNBOUND
    assert result.stats == NearReturnOperandCongruenceStats8616(1, 1, 0, 0, 1)
    assert not result.complete


def test_missing_projection_refuses() -> None:
    """A never-registered stack variable cannot bind a proven role."""
    project, candidate = _proven_candidate()
    codegen = _StubCodegen(project, _FUNC_ADDR)
    base = _record_word_arg(codegen, _BASE.offset, "arg_base")
    index = structured_c.CVariable(
        SimStackVariable(
            _INDEX.offset - _ENTRY_SP_BIAS, 2, base="bp", name="arg_index"
        ),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expression = _add(codegen, base, _shl(codegen, index, 1))

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)

    assert result.failure is NearReturnOperandCongruenceFailure8616.OPERAND_UNBOUND
    assert not result.complete


def test_operand_from_foreign_storage_refuses() -> None:
    """A canonical word at another BP slot is not a proven input."""
    codegen, candidate, cvars = _case()
    other = _record_word_arg(codegen, 8, "arg_other")
    expression = _add(codegen, other, _shl(codegen, cvars["index"], 1))

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)

    assert (
        result.failure
        is NearReturnOperandCongruenceFailure8616.OPERAND_STORAGE_MISMATCH
    )
    assert not result.complete


def test_refused_candidate_never_binds() -> None:
    """A refused candidate keeps its typed failure instead of binding."""
    codegen, candidate, cvars = _case()
    refused = replace(
        candidate,
        verdict=NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE,
        failure=NearScaledReturnCandidateFailure8616.INPUT_STORAGE_UNPROVEN,
    )
    expression = _scaled_offset(codegen, cvars)

    result = bind_near_return_offset_c_ast_8616(codegen, refused, expression)

    assert result.failure is NearReturnOperandCongruenceFailure8616.CANDIDATE_INCOMPLETE
    assert (
        result.upstream_failure
        is NearScaledReturnCandidateFailure8616.INPUT_STORAGE_UNPROVEN
    )
    assert result.stats == NearReturnOperandCongruenceStats8616(1, 0, 0, 0, 1)
    assert not result.complete


def test_wrong_function_and_missing_surface_refuse() -> None:
    """A candidate proven for another callee cannot bind this codegen."""
    project, candidate = _proven_candidate()
    foreign = _StubCodegen(project, 0x2000)
    foreign_cvars = {
        "base": _record_word_arg(foreign, _BASE.offset, "arg_base"),
        "index": _record_word_arg(foreign, _INDEX.offset, "arg_index"),
    }
    mismatched = bind_near_return_offset_c_ast_8616(
        foreign, candidate, _scaled_offset(foreign, foreign_cvars)
    )
    assert mismatched.failure is NearReturnOperandCongruenceFailure8616.FUNCTION_MISMATCH

    codegen, _, cvars = _case()
    headless = SimpleNamespace(project=project, cstyle_null_cmp=False)
    surfaced = bind_near_return_offset_c_ast_8616(
        headless, candidate, _scaled_offset(codegen, cvars)
    )
    assert (
        surfaced.failure
        is NearReturnOperandCongruenceFailure8616.CODEGEN_SURFACE_UNPROVEN
    )


def test_narrowing_and_signed_casts_refuse() -> None:
    """Truncating or signed views cannot carry the proven 16-bit word."""
    codegen, candidate, cvars = _case()
    inner = _scaled_offset(codegen, cvars)

    for dst_type in (SimTypeChar(False), SimTypeShort(True)):
        narrowed = bind_near_return_offset_c_ast_8616(
            codegen, candidate, _cast(codegen, inner, dst_type)
        )
        assert (
            narrowed.failure
            is NearReturnOperandCongruenceFailure8616.EXPRESSION_UNSUPPORTED
        )
        assert not narrowed.complete


def test_call_deref_and_unknown_nodes_refuse() -> None:
    """Calls, indexing, dereferences, and foreign nodes never evaluate."""
    codegen, candidate, cvars = _case()
    call = structured_c.CFunctionCall("helper", None, [], codegen=codegen)
    indexed = structured_c.CIndexedVariable(
        cvars["base"], _const(codegen, 0),
        variable_type=SimTypeShort(False), codegen=codegen,
    )
    dereference = structured_c.CUnaryOp(
        "Dereference", cvars["base"], codegen=codegen
    )
    unknown = object()

    for node in (call, indexed, dereference, unknown):
        result = bind_near_return_offset_c_ast_8616(codegen, candidate, node)
        assert (
            result.failure
            is NearReturnOperandCongruenceFailure8616.EXPRESSION_UNSUPPORTED
        )
        assert not result.complete


def test_congruence_check_is_mutation_free() -> None:
    """The check leaves the codegen surface, registry, and candidate intact."""
    codegen, candidate, cvars = _case()
    projections = stack_variable_coordinate_registry_8616(codegen).projections
    codegen_keys = set(vars(codegen))

    result = bind_near_return_offset_c_ast_8616(
        codegen, candidate, _scaled_offset(codegen, cvars)
    )

    assert result.complete
    assert codegen.cfunc.statements is None
    assert set(vars(codegen)) == codegen_keys
    assert (
        stack_variable_coordinate_registry_8616(codegen).projections
        == projections
    )
    assert candidate.complete


@pytest.mark.parametrize("canonical_unified", [False, True])
def test_competing_unified_variable_cannot_bind_original_leaf(canonical_unified: bool) -> None:
    """The rendered unified view must not silently borrow another leaf's proof."""
    codegen, candidate, cvars = _case()
    competing = copy.copy(cvars["base"])
    competing.unified_variable = (
        cvars["index"].variable if canonical_unified else SimStackVariable(
            22, 2, base="bp", name="foreign_word", ident="foreign_word"
        )
    )
    expression = _add(codegen, competing, _shl(codegen, cvars["index"], 1))

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)

    assert not result.complete
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_explicitly_registered_unified_alias_binds() -> None:
    """A producer-registered alias of the same storage remains admissible."""
    codegen, candidate, cvars = _case()
    alias = SimStackVariable(22, 2, base="bp", name="base_alias", ident="base_alias")
    projection = record_stack_variable_coordinate_alias_8616(
        codegen, bp_offset=_BASE.offset, size=2, variable=alias
    )
    assert projection is not None
    view = copy.copy(cvars["base"])
    view.unified_variable = alias

    result = bind_near_return_offset_c_ast_8616(
        codegen, candidate, _add(codegen, view, _shl(codegen, cvars["index"], 1))
    )

    assert result.complete


@pytest.mark.parametrize("corruption", ["callee", "storage", "coefficient", "cvar", "projection"])
def test_complete_rechecks_each_retained_operand_binding(corruption: str) -> None:
    """Detached result fields must not preserve an apparent complete verdict."""
    codegen, candidate, cvars = _case()
    result = bind_near_return_offset_c_ast_8616(codegen, candidate, _scaled_offset(codegen, cvars))
    assert result.complete
    base, index = result.bound_operands
    if corruption == "callee":
        damaged = replace(result, callee_addr=result.callee_addr + 1)
    else:
        changes = {
            "storage": {"storage": index.storage},
            "coefficient": {"coefficient": index.coefficient},
            "cvar": {"cvar": index.cvar},
            "projection": {"projection": index.projection},
        }
        damaged = replace(result, bound_operands=(replace(base, **changes[corruption]), index))

    assert not damaged.complete


def test_complete_rechecks_mutated_expression() -> None:
    """A retained mutable AST cannot keep proof after its arithmetic changes."""
    codegen, candidate, cvars = _case()
    expression = _scaled_offset(codegen, cvars)
    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)
    assert result.complete
    expression.op = "Sub"
    assert not result.complete


def test_shift_count_is_not_reduced_as_an_operand_word() -> None:
    """A mathematical coefficient match cannot legalize a huge C shift count."""
    codegen, candidate, cvars = _case()
    count = _add(codegen, _const(codegen, 65536), _const(codegen, 1))
    expression = _add(codegen, cvars["base"], structured_c.CBinaryOp(
        "Shl", cvars["index"], count, codegen=codegen
    ))

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, expression)

    assert result.failure is NearReturnOperandCongruenceFailure8616.EXPRESSION_UNSUPPORTED
    assert not result.complete


def test_missing_function_address_is_typed_non_result() -> None:
    """An incomplete third-party codegen surface supplies no function proof."""
    codegen, candidate, cvars = _case()
    codegen.cfunc = SimpleNamespace(statements=None)

    result = bind_near_return_offset_c_ast_8616(codegen, candidate, _scaled_offset(codegen, cvars))

    assert result.failure is NearReturnOperandCongruenceFailure8616.CODEGEN_SURFACE_UNPROVEN
    assert not result.complete
