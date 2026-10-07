"""Staged controls for the nonpublishing near-return expression builder.

Layer: Tests.
Responsibility: prove the owned ``near_return_expression`` builder emits the
structured ``(T)NEAR_BYTE_ADD(src, dst, base, (uint16_t)((uint32_t)(uint16_t)
index * 2UL))`` candidate over the binary-backed congruence proof, retains
exact canonical C-variable identity, refuses every stale congruence,
malformed result type, volatile or side-effectful selector, undefined
arithmetic, and unproven selector domain, and mutates nothing. Structured
node assertions are primary; a compiled
portable-flat behavioral check exercises the real helper's guest-view
pointer, wrap16, and null handling only — it claims no native or segment
proof and no validation acceptance.
"""

from __future__ import annotations

import io
import shutil
import subprocess
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import (
    SimTypeChar,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
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
from inertia.lowering.c_runtime_header import (
    render_c_runtime_header_8616,
)
from inertia.lowering.near_pointer_type import (
    near_pointer_type_8616,
)
from inertia.lowering.near_return_c_ast_congruence import (
    NearReturnOperandCongruenceResult8616,
    bind_near_return_offset_c_ast_8616,
)
from inertia.lowering.near_return_expression import (
    NearReturnPointerExpressionFailure8616,
    NearReturnPointerExpressionStats8616,
    NearReturnPointerExpressionVerdict8616,
    build_near_return_pointer_expression_8616,
)
from inertia.lowering.near_scaled_return_candidate import (
    NearScaledReturnCandidateFailure8616,
    NearScaledReturnCandidateResult8616,
    NearScaledReturnCandidateVerdict8616,
    collect_near_scaled_return_candidate_8616,
)
from inertia.lowering.stack_variable_coordinates import (
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
_SRC_SEG = 0x1234
_DST_SEG = 0x4321


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
    image[0xF1:0xF1 + len(_CODE)] = _CODE
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


def _scaled_offset(
    codegen: object, cvars: dict[str, structured_c.CVariable]
) -> structured_c.CBinaryOp:
    """Build the proven ``(index << 1) + base`` operand order."""
    shift = structured_c.CBinaryOp(
        "Shl",
        cvars["index"],
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    return structured_c.CBinaryOp(
        "Add", shift, cvars["base"], codegen=codegen
    )


def _congruence() -> tuple[
    _StubCodegen,
    NearReturnOperandCongruenceResult8616,
    dict[str, structured_c.CVariable],
]:
    """Pair the proven candidate with complete binary-backed congruence."""
    project, candidate = _proven_candidate()
    codegen = _StubCodegen(project, _FUNC_ADDR)
    cvars = {
        "base": _record_word_arg(codegen, _BASE.offset, "arg_base"),
        "index": _record_word_arg(codegen, _INDEX.offset, "arg_index"),
    }
    congruence = bind_near_return_offset_c_ast_8616(
        codegen, candidate, _scaled_offset(codegen, cvars)
    )
    assert congruence.complete
    return codegen, congruence, cvars


def _selector(codegen: object, segment: int) -> structured_c.CConstant:
    """Build one explicit 16-bit segment selector constant."""
    return structured_c.CConstant(
        segment, SimTypeShort(False), codegen=codegen
    )


def _near_result_type(project: angr.Project) -> object:
    """Return the owned fixed16 near result pointer type."""
    return near_pointer_type_8616(SimTypeChar(True), project.arch)


def _build(
    codegen: object,
    congruence: NearReturnOperandCongruenceResult8616,
    *,
    src: object | None = None,
    dst: object | None = None,
    result_type: object | None = None,
) -> object:
    """Build the candidate with default constant selectors and result type."""
    return build_near_return_pointer_expression_8616(
        codegen,
        congruence,
        src if src is not None else _selector(codegen, _SRC_SEG),
        dst if dst is not None else _selector(codegen, _DST_SEG),
        result_type if result_type is not None else _near_result_type(codegen.project),
    )


def test_builds_bound_near_byte_add_candidate() -> None:
    """The proven congruence emits the exact structured candidate shape."""
    codegen, congruence, cvars = _congruence()
    src, dst = _selector(codegen, _SRC_SEG), _selector(codegen, _DST_SEG)
    result_type = _near_result_type(codegen.project)

    result = build_near_return_pointer_expression_8616(
        codegen, congruence, src, dst, result_type
    )

    assert result.complete
    assert result.verdict is NearReturnPointerExpressionVerdict8616.BOUND
    assert result.failure is None
    assert result.callee_addr == _FUNC_ADDR
    assert result.congruence is congruence
    assert result.bound_operands == congruence.bound_operands
    assert result.stats == NearReturnPointerExpressionStats8616(1, 1, 1, 1, 0)
    assert result.byte_scale == 2
    assert result.source_selector is src and result.result_selector is dst
    assert result.result_pointer_type is result_type

    cast_node = result.expression
    assert isinstance(cast_node, structured_c.CTypeCast)
    assert cast_node.dst_type == result_type
    call = cast_node.expr
    assert isinstance(call, structured_c.CFunctionCall)
    assert call.callee_func is None
    assert call.callee_target == "NEAR_BYTE_ADD"
    assert len(call.args) == 4
    # The exact canonical cvar objects are retained, never cloned.
    assert call.args[0] is src and call.args[1] is dst
    assert call.args[2] is cvars["base"]
    byte_term = call.args[3]
    assert isinstance(byte_term, structured_c.CTypeCast)
    assert isinstance(byte_term.dst_type, SimTypeShort)
    product = byte_term.expr
    assert isinstance(product, structured_c.CBinaryOp) and product.op == "Mul"
    widened = product.lhs
    assert isinstance(widened, structured_c.CTypeCast)
    assert isinstance(widened.dst_type, SimTypeLong)
    narrowed = widened.expr
    assert isinstance(narrowed, structured_c.CTypeCast)
    assert isinstance(narrowed.dst_type, SimTypeShort)
    assert narrowed.expr is cvars["index"]
    scale = product.rhs
    assert isinstance(scale, structured_c.CConstant) and scale.value == 2


def test_construction_is_mutation_free_and_nonpublishing() -> None:
    """The builder touches no codegen body, registry, cvar, or project state."""
    codegen, congruence, _cvars = _congruence()
    projections = stack_variable_coordinate_registry_8616(codegen).projections
    codegen_keys = set(vars(codegen))
    project_keys = set(vars(codegen.project))

    result = _build(codegen, congruence)

    assert result.complete
    assert codegen.cfunc.statements is None
    assert set(vars(codegen)) == codegen_keys
    assert (
        stack_variable_coordinate_registry_8616(codegen).projections
        == projections
    )
    assert set(vars(codegen.project)) == project_keys
    assert congruence.complete


def test_word_variable_and_casted_selector_forms_bind() -> None:
    """An unsigned-word variable and a masked composite selector are pure."""
    codegen, congruence, _cvars = _congruence()
    seg_var = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="seg", ident="seg"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    composite = structured_c.CTypeCast(
        None,
        SimTypeShort(False),
        structured_c.CBinaryOp(
            "Add",
            _selector(codegen, 0x100),
            _selector(codegen, 0x34),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    for src, dst in ((seg_var, _selector(codegen, _DST_SEG)),
                     (composite, composite)):
        result = _build(codegen, congruence, src=src, dst=dst)
        assert result.complete, result.failure


def test_refused_congruence_never_builds() -> None:
    """An upstream-refused candidate keeps its typed failure."""
    codegen, congruence, _cvars = _congruence()
    candidate = congruence.candidate
    refused = bind_near_return_offset_c_ast_8616(
        codegen,
        replace(
            candidate,
            verdict=NearScaledReturnCandidateVerdict8616.UNKNOWN_REFUSE,
            failure=NearScaledReturnCandidateFailure8616.INPUT_STORAGE_UNPROVEN,
        ),
        _scaled_offset(codegen, {"base": _record_word_arg(codegen, _BASE.offset, "b2"),
                                 "index": _record_word_arg(codegen, _INDEX.offset, "i2")}),
    )

    result = _build(codegen, refused)

    assert (
        result.failure
        is NearReturnPointerExpressionFailure8616.CONGRUENCE_INCOMPLETE
    )
    assert result.stats == NearReturnPointerExpressionStats8616(1, 0, 0, 0, 1)
    assert not result.complete


def test_stale_congruence_identity_refuses() -> None:
    """Mutating the checked operand AST invalidates the retained congruence."""
    codegen, congruence, _cvars = _congruence()
    congruence.expression.op = "Sub"
    assert not congruence.complete

    result = _build(codegen, congruence)

    assert (
        result.failure
        is NearReturnPointerExpressionFailure8616.CONGRUENCE_INCOMPLETE
    )
    assert not result.complete


@pytest.mark.parametrize(
    "corruption", ["callee", "storage", "coefficient", "cvar", "projection"]
)
def test_corrupted_bound_operand_refuses(corruption: str) -> None:
    """Detached congruence fields cannot keep an apparent bound identity."""
    codegen, congruence, _cvars = _congruence()
    base, index = congruence.bound_operands
    if corruption == "callee":
        damaged = replace(congruence, callee_addr=congruence.callee_addr + 1)
    else:
        changes = {
            "storage": {"storage": index.storage},
            "coefficient": {"coefficient": index.coefficient},
            "cvar": {"cvar": index.cvar},
            "projection": {"projection": index.projection},
        }
        damaged = replace(
            congruence,
            bound_operands=(replace(base, **changes[corruption]), index),
        )
    assert not damaged.complete

    result = _build(codegen, damaged)

    assert (
        result.failure
        is NearReturnPointerExpressionFailure8616.CONGRUENCE_INCOMPLETE
    )
    assert not result.complete


def test_foreign_codegen_surface_refuses() -> None:
    """A different function or a foreign registry never reuses the proof."""
    project, _candidate = _proven_candidate()
    _codegen, congruence, _cvars = _congruence()

    wrong_addr = _StubCodegen(project, 0x2000)
    mismatched = _build(wrong_addr, congruence)
    assert (
        mismatched.failure
        is NearReturnPointerExpressionFailure8616.FUNCTION_MISMATCH
    )

    no_registry = _StubCodegen(project, _FUNC_ADDR)
    surface = _build(no_registry, congruence)
    assert (
        surface.failure
        is NearReturnPointerExpressionFailure8616.CODEGEN_SURFACE_UNPROVEN
    )


@pytest.mark.parametrize(
    "bad_type_factory",
    [
        lambda arch: SimTypeShort(False).with_arch(arch),
        lambda arch: SimTypePointer(SimTypeChar(True)).with_arch(arch),
        lambda arch: SimTypePointer(SimTypeChar(True)),
        lambda arch: SimTypeLong(False).with_arch(arch),
    ],
)
def test_malformed_result_type_refuses(bad_type_factory: object) -> None:
    """Only a fixed16 near pointer type can carry the candidate result."""
    codegen, congruence, _cvars = _congruence()
    bad_type = bad_type_factory(codegen.project.arch)

    result = _build(codegen, congruence, result_type=bad_type)

    assert (
        result.failure
        is NearReturnPointerExpressionFailure8616.RESULT_TYPE_MALFORMED
    )
    assert result.stats.materialized_count == 0
    assert not result.complete


@pytest.mark.parametrize("selector_kind", ["call", "indexed", "deref", "object"])
def test_side_effectful_selector_refuses(selector_kind: str) -> None:
    """Calls, indexing, dereferences, and non-AST nodes are not selectors."""
    codegen, congruence, cvars = _congruence()
    bad = {
        "call": structured_c.CFunctionCall("helper", None, [], codegen=codegen),
        "indexed": structured_c.CIndexedVariable(
            cvars["base"],
            _selector(codegen, 0),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        "deref": structured_c.CUnaryOp(
            "Dereference", cvars["base"], codegen=codegen
        ),
        "object": object(),
    }[selector_kind]

    result = _build(codegen, congruence, src=bad)

    assert (
        result.failure
        is NearReturnPointerExpressionFailure8616.SELECTOR_NOT_SIDE_EFFECT_FREE
    )
    assert result.stats.materialized_count == 0
    assert not result.complete


def test_out_of_domain_selector_refuses() -> None:
    """Constants past 16 bits, signed leaves, and bare Adds prove no domain."""
    codegen, congruence, _cvars = _congruence()
    wide = _selector(codegen, 0x1_0000)
    signed_var = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="sseg", ident="sseg"),
        variable_type=SimTypeShort(True),
        codegen=codegen,
    )
    bare_add = structured_c.CBinaryOp(
        "Add", _selector(codegen, 0x8000), _selector(codegen, 0x8001),
        codegen=codegen,
    )

    for bad in (wide, signed_var, bare_add):
        result = _build(codegen, congruence, dst=bad)
        assert (
            result.failure
            is NearReturnPointerExpressionFailure8616.SELECTOR_DOMAIN_UNPROVEN
        ), (bad, result.failure)
        assert not result.complete


def test_volatile_selector_reads_refuse() -> None:
    """Volatile-qualified leaves cannot back a re-evaluated macro argument."""
    codegen, congruence, _cvars = _congruence()
    volatile_var = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="vseg", ident="vseg"),
        variable_type=SimTypeShort(False, qualifier=["volatile"]),
        codegen=codegen,
    )
    volatile_cast = structured_c.CTypeCast(
        None,
        SimTypeShort(False, qualifier=["volatile"]),
        _selector(codegen, 1),
        codegen=codegen,
    )

    for bad in (volatile_var, volatile_cast):
        result = _build(codegen, congruence, src=bad)
        assert (
            result.failure
            is NearReturnPointerExpressionFailure8616.SELECTOR_NOT_SIDE_EFFECT_FREE
        ), (bad, result.failure)
        assert not result.complete


@pytest.mark.parametrize("count", [-1, 16, 31, 0xFFFF])
def test_unbounded_shift_count_selector_refuses(count: int) -> None:
    """Shift counts outside the proven literal [0, 16) bound are refused."""
    codegen, congruence, _cvars = _congruence()
    count_node = structured_c.CConstant(count, SimTypeShort(False), codegen=codegen)

    for op in ("Shl", "Shr"):
        shift = structured_c.CBinaryOp(
            op, _selector(codegen, 0x40), count_node, codegen=codegen
        )
        result = _build(codegen, congruence, src=shift)
        assert (
            result.failure
            is NearReturnPointerExpressionFailure8616.SELECTOR_NOT_SIDE_EFFECT_FREE
        ), (op, count, result.failure)
        assert not result.complete


def test_nonliteral_shift_count_selector_refuses() -> None:
    """A variable or computed shift count carries no proven bound."""
    codegen, congruence, cvars = _congruence()
    masked = structured_c.CBinaryOp(
        "And", cvars["index"], _selector(codegen, 0xF), codegen=codegen
    )
    for count_node in (cvars["index"], masked):
        shift = structured_c.CBinaryOp(
            "Shr", _selector(codegen, 0x40), count_node, codegen=codegen
        )
        result = _build(codegen, congruence, dst=shift)
        assert (
            result.failure
            is NearReturnPointerExpressionFailure8616.SELECTOR_NOT_SIDE_EFFECT_FREE
        ), (count_node, result.failure)


def test_bounded_shift_selector_forms_bind() -> None:
    """A Shr word selector and a casted bounded Shl selector are proven."""
    codegen, congruence, _cvars = _congruence()
    shift_right = structured_c.CBinaryOp(
        "Shr", _selector(codegen, 0x8000), _selector(codegen, 4), codegen=codegen
    )
    shift_left = structured_c.CTypeCast(
        None,
        SimTypeShort(False),
        structured_c.CBinaryOp(
            "Shl", _selector(codegen, 0x123), _selector(codegen, 2), codegen=codegen
        ),
        codegen=codegen,
    )

    for selector in (shift_right, shift_left):
        result = _build(codegen, congruence, dst=selector)
        assert result.complete, (selector, result.failure)


def test_shift_result_without_u16_view_refuses() -> None:
    """A bare Shl result is defined but carries no proven u16 bound."""
    codegen, congruence, _cvars = _congruence()
    shift = structured_c.CBinaryOp(
        "Shl", _selector(codegen, 0x123), _selector(codegen, 2), codegen=codegen
    )

    result = _build(codegen, congruence, dst=shift)

    assert (
        result.failure
        is NearReturnPointerExpressionFailure8616.SELECTOR_DOMAIN_UNPROVEN
    )
    assert not result.complete


@pytest.mark.parametrize("op", ["Add", "Sub", "Mul"])
def test_mixed_signed_arithmetic_selector_refuses(op: str) -> None:
    """Arithmetic with one signed/unproven operand is UB on DOS int16."""
    codegen, congruence, _cvars = _congruence()
    signed_leaf = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="mseg", ident="mseg"),
        variable_type=SimTypeShort(True),
        codegen=codegen,
    )
    arithmetic = structured_c.CTypeCast(
        None,
        SimTypeShort(False),
        structured_c.CBinaryOp(
            op, _selector(codegen, 0x100), signed_leaf, codegen=codegen
        ),
        codegen=codegen,
    )

    result = _build(codegen, congruence, src=arithmetic)

    assert (
        result.failure
        is NearReturnPointerExpressionFailure8616.SELECTOR_NOT_SIDE_EFFECT_FREE
    )
    assert not result.complete


@pytest.mark.parametrize(
    "field",
    [
        "raw_fact_count",
        "normalized_fact_count",
        "classified_fact_count",
        "materialized_count",
        "failure_count",
    ],
)
def test_boolean_stats_field_revokes_completeness(field: str) -> None:
    """A bool masquerading as an int count cannot keep the bound receipt."""
    codegen, congruence, _cvars = _congruence()
    result = _build(codegen, congruence)
    assert result.complete

    damaged = replace(
        result, stats=replace(result.stats, **{field: True})
    )

    assert not damaged.complete


@pytest.mark.parametrize("bad_scale", [True, 2.0, "2"])
def test_noninteger_byte_scale_revokes_completeness(bad_scale: object) -> None:
    """The retained byte scale must be a real int inside [0, 65536)."""
    codegen, congruence, _cvars = _congruence()
    result = _build(codegen, congruence)
    assert result.complete

    assert not replace(result, byte_scale=bad_scale).complete


@pytest.mark.parametrize(
    "corruption",
    ["callee_target", "widened_type", "scale_value", "byte_term_type"],
)
def test_mutated_inner_nodes_revoke_completeness(corruption: str) -> None:
    """Inner node mutations beneath the outer cast revoke the verdict."""
    codegen, congruence, _cvars = _congruence()
    result = _build(codegen, congruence)
    assert result.complete
    call = result.expression.expr
    product = call.args[3].expr
    if corruption == "callee_target":
        call.callee_target = "NEAR_BYTE_ADD_TAMPERED"
    elif corruption == "widened_type":
        product.lhs.dst_type = SimTypeShort(True)
    elif corruption == "scale_value":
        product.rhs.value = float(product.rhs.value)
    else:
        call.args[3].dst_type = SimTypeLong(False)

    assert not result.complete


def test_missing_bound_operand_role_revokes_completeness() -> None:
    """A retained operand tuple without both roles cannot keep the verdict."""
    codegen, congruence, _cvars = _congruence()
    result = _build(codegen, congruence)
    assert result.complete

    for damaged in (
        replace(result, bound_operands=()),
        replace(result, bound_operands=congruence.bound_operands[1:]),
    ):
        assert not damaged.complete


def test_complete_rechecks_retained_candidate_fields() -> None:
    """A detached or swapped result field cannot keep the bound verdict."""
    codegen, congruence, _cvars = _congruence()
    result = _build(codegen, congruence)
    assert result.complete

    damaged_scale = replace(result, byte_scale=3)
    damaged_expr = replace(
        result, expression=_selector(codegen, _SRC_SEG)
    )
    damaged_selector = replace(
        result, source_selector=_selector(codegen, _SRC_SEG)
    )
    for damaged in (damaged_scale, damaged_expr, damaged_selector):
        assert not damaged.complete


def test_rendered_shape_matches_runtime_helper_form() -> None:
    """The emitted tree renders as the NEAR_BYTE_ADD call with the widened
    unsigned byte term — a printed-text cross-check, not the primary oracle."""
    codegen, congruence, _cvars = _congruence()
    codegen.stmt_comments = {}
    codegen.expr_comments = {}
    codegen.const_formats = {}
    codegen.display_vvar_ids = False
    codegen.show_casts = True

    result = _build(codegen, congruence)

    rendered = result.expression.c_repr()
    assert "NEAR_BYTE_ADD(" in rendered
    assert "unsigned long" in rendered


def test_compiled_portable_near_byte_add_semantics(tmp_path: Path) -> None:
    """Compile the real portable-flat helper and run the emitted C shape.

    This exercises guest-view pointer arithmetic, 16-bit wrap, and the null
    result under the actual NEAR_BYTE_ADD definition. It proves no native or
    segment binding and claims no validation acceptance.
    """
    compiler = shutil.which("gcc")
    assert compiler is not None, "gcc is required for the enrolled portable behavioral check"
    header = render_c_runtime_header_8616("portable-flat")
    source = tmp_path / "near_return_expr.c"
    source.write_text(header + r"""
uint8_t inertia_memory[0x30000];
uint16_t inertia_cs, inertia_ds, inertia_es, inertia_ss;
int main(void) {
    static const uint16_t cases[][4] = {
        /* src_seg dst_seg base_off index */
        {0x123, 0x432, 0x0017, 0x0003},
        {0x123, 0x432, 0xfffe, 0x0001},
        {0x123, 0x432, 0xffff, 0x0001},
        {0x123, 0x432, 0x1234, 0xfffe},
        {0x123, 0x432, 0x0000, 0x0000},
        {0x123, 0x432, 0x0000, 0x0007}
    };
    unsigned int i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint16_t src_seg = cases[i][0], dst_seg = cases[i][1];
        uint16_t base_off = cases[i][2], index = cases[i][3];
        uint16_t expected = (uint16_t)(base_off + 2 * index);
        void *base = base_off ? SEG_PTR(src_seg, base_off) : 0;
        void *result = NEAR_BYTE_ADD(
            src_seg, dst_seg, base,
            (uint16_t)((uint32_t)(uint16_t)index * 2UL));
        void *expected_pointer = expected ? SEG_PTR(dst_seg, expected) : 0;
        if (result != expected_pointer) return 1;
        if (NEAR_OFFSET(dst_seg, result) != expected) return 2;
    }
    return 0;
}
""")
    executable = tmp_path / "near_return_expr"
    compiled = subprocess.run(
        [compiler, "-std=c99", "-pedantic-errors", "-Wall", "-Wextra",
         "-Werror", "-O2", str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run(
        [str(executable)], capture_output=True, text=True, check=False,
        timeout=10,
    )
    assert executed.returncode == 0, executed.stderr
