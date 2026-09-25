"""Preserve a proven loop-carried AX value through structured C returns.

Layer: Structuring.
Responsibility: bind one exact full-AX assignment to an existing typed C
temporary from Semantics-proven terminal AX and one mandatory loop.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CDoWhileLoop,
    CExpression,
    CExpressionStatement,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeInt, SimTypeShort
from angr.sim_variable import SimTemporaryVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..lowering.physical_registers import PhysicalRegisterView8616, physical_register_view_8616
from ..semantics.terminal_return_storage import TerminalReturnStorage8616, terminal_return_storage_8616
from ..structured_tags import copy_structured_tags_8616
from .loop_carried_terminal_return_contracts import (
    LoopCarriedTerminalReturnEvidence8616,
    LoopCarriedTerminalReturnRefusal8616,
    LoopCarriedTerminalReturnResult8616,
    LoopCarriedTerminalReturnStatus8616,
    _CFunctionSurface8616,
    _CodegenSurface8616,
    _FunctionSurface8616,
    _ProjectSurface8616,
)

__all__ = [
    "LoopCarriedTerminalReturnEvidence8616",
    "LoopCarriedTerminalReturnRefusal8616",
    "LoopCarriedTerminalReturnResult8616",
    "LoopCarriedTerminalReturnStatus8616",
    "materialize_loop_carried_terminal_return_8616",
]

_MATERIALIZED_TAG = "inertia_loop_carried_terminal_return_8616"


def _result_8616(
    codegen: _CodegenSurface8616,
    status: LoopCarriedTerminalReturnStatus8616,
    refusal: LoopCarriedTerminalReturnRefusal8616,
    evidence: LoopCarriedTerminalReturnEvidence8616,
) -> LoopCarriedTerminalReturnResult8616:
    """Store and return one typed Structuring result."""
    result = LoopCarriedTerminalReturnResult8616(
        status is LoopCarriedTerminalReturnStatus8616.MATERIALIZED,
        status,
        refusal,
        evidence,
    )
    codegen._inertia_loop_carried_terminal_return_result_8616 = result
    return result


def _refused_8616(
    codegen: _CodegenSurface8616,
    refusal: LoopCarriedTerminalReturnRefusal8616,
    *,
    raw: int = 1,
    normalized: int = 0,
    failures: int = 0,
) -> LoopCarriedTerminalReturnResult8616:
    """Build one conservative refusal before semantic classification."""
    return _result_8616(
        codegen,
        LoopCarriedTerminalReturnStatus8616.REFUSED,
        refusal,
        LoopCarriedTerminalReturnEvidence8616(raw, normalized, 0, 0, failures),
    )


def _linear_statements_8616(root: object) -> tuple[object, ...]:
    """Flatten transparent CStatements wrappers without crossing control flow."""
    if not isinstance(root, CStatements):
        return (root,)
    statements: list[object] = []
    for statement in tuple(root.statements or ()):
        statements.extend(_linear_statements_8616(statement))
    return tuple(statements)


def _overlaps_ax_8616(
    view: PhysicalRegisterView8616,
    ax_offset: int,
    ax_width: int,
) -> bool:
    """Return whether one physical register view overlaps the AX word."""
    return bool(view.reg_offset < ax_offset + ax_width and ax_offset < view.reg_offset + view.width)


def _is_full_ax_8616(
    node: object,
    ax_offset: int,
    ax_width: int,
) -> bool:
    """Return whether one C expression denotes exactly the full AX storage."""
    view = physical_register_view_8616(node)
    return view is not None and view.reg_offset == ax_offset and view.width == ax_width


def _ax_views_8616(node: object, ax_offset: int, ax_width: int) -> tuple[PhysicalRegisterView8616, ...]:
    """Collect physical C-expression views overlapping AX in one subtree."""
    views: list[PhysicalRegisterView8616] = []
    for candidate in _iter_c_nodes_deep_8616(node):
        view = physical_register_view_8616(candidate)
        if view is not None and _overlaps_ax_8616(view, ax_offset, ax_width):
            views.append(view)
    return tuple(views)


def _typed_word_8616(expression: object, arch: Arch) -> SimTypeInt | SimTypeShort | None:
    """Return one existing typed 16-bit scalar without inferring signedness."""
    if not isinstance(expression, CExpression) or not isinstance(expression.type, (SimTypeInt, SimTypeShort)):
        return None
    return expression.type.with_arch(arch)


def _already_materialized_8616(returns: tuple[CReturn, ...]) -> bool:
    """Return whether the current AST already carries this pass's durable tag."""
    if len(returns) != 1 or not isinstance(returns[0].retval, CVariable):
        return False
    tags = copy_structured_tags_8616(returns[0].tags) or {}
    return (
        tags.get(_MATERIALIZED_TAG) is True
        and isinstance(returns[0].retval.variable, SimTemporaryVariable)
    )


def _next_temporary_id_8616(root: object, seed: int) -> int:
    """Choose one deterministic temporary identity absent from the current AST."""
    used = {
        node.variable.tmp_id
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CVariable) and isinstance(node.variable, SimTemporaryVariable)
    }
    candidate = max(0, seed)
    while candidate in used:
        candidate += 1
    return candidate


def _c_return_nodes_8616(root: object) -> tuple[CReturn, ...]:
    """Collect every structured return node."""
    return tuple(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CReturn))


def _terminal_ax_function_8616(
    project: object,
    project_surface: _ProjectSurface8616,
    codegen_surface: _CodegenSurface8616,
    function_addr: int,
) -> _FunctionSurface8616 | LoopCarriedTerminalReturnResult8616:
    """Resolve the owning function and prove AX terminal storage."""
    function = project_surface.kb.functions.function(addr=function_addr, create=False)
    if function is None:
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.MISSING_FUNCTION,
            failures=1,
        )
    if terminal_return_storage_8616(project, function) is not TerminalReturnStorage8616.AX:
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.TERMINAL_STORAGE_NOT_AX,
        )
    return function


def _loop_carried_prelude_8616(
    project_surface: _ProjectSurface8616,
    codegen_surface: _CodegenSurface8616,
) -> tuple[_CFunctionSurface8616, CStatements] | LoopCarriedTerminalReturnResult8616:
    """Prove the applicable codegen shape or return NOT_APPLICABLE."""
    cfunc = codegen_surface.cfunc
    prototype = cfunc.functy
    root = cfunc.statements
    if (
        project_surface.arch.name != "86_16"
        or not isinstance(prototype, SimTypeFunction)
        or isinstance(prototype.returnty, SimTypeBottom)
        or not isinstance(root, CStatements)
    ):
        return _result_8616(
            codegen_surface,
            LoopCarriedTerminalReturnStatus8616.NOT_APPLICABLE,
            LoopCarriedTerminalReturnRefusal8616.NOT_APPLICABLE,
            LoopCarriedTerminalReturnEvidence8616(),
        )
    return cfunc, root


def _ax_geometry_8616(
    project_surface: _ProjectSurface8616,
    codegen_surface: _CodegenSurface8616,
) -> tuple[int, int] | LoopCarriedTerminalReturnResult8616:
    """Return the proven AX register geometry or refuse."""
    ax_register = project_surface.arch.registers.get("ax")
    if not isinstance(ax_register, tuple) or len(ax_register) < 2:
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.INCOMPLETE_STRUCTURED_SHAPE,
            normalized=1,
            failures=1,
        )
    ax_offset, ax_width = ax_register[:2]
    if not isinstance(ax_offset, int) or not isinstance(ax_width, int):
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.INCOMPLETE_STRUCTURED_SHAPE,
            normalized=1,
            failures=1,
        )
    return ax_offset, ax_width


def _loop_carried_shape_8616(
    codegen_surface: _CodegenSurface8616,
    root: CStatements,
    returns: tuple[CReturn, ...],
) -> tuple[tuple[object, ...], CReturn] | LoopCarriedTerminalReturnResult8616:
    """Prove the single mandatory loop + bare terminal return shape."""
    top_level = _linear_statements_8616(root)
    loops = tuple(node for node in top_level if isinstance(node, CDoWhileLoop))
    if len(loops) != 1 or len(returns) != 1 or returns[0].retval is not None:
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.INCOMPLETE_STRUCTURED_SHAPE,
            normalized=1,
        )
    loop = loops[0]
    return_node = returns[0]
    loop_index = top_level.index(loop)
    if top_level[loop_index + 1 :] != (return_node,):
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.INCOMPLETE_STRUCTURED_SHAPE,
            normalized=1,
        )
    body = _linear_statements_8616(loop.body)
    if not body or not all(isinstance(node, (CAssignment, CExpressionStatement)) for node in body):
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.INCOMPLETE_STRUCTURED_SHAPE,
            normalized=1,
        )
    return body, return_node


def _proven_ax_assignment_8616(
    codegen_surface: _CodegenSurface8616,
    body: tuple[object, ...],
    ax_offset: int,
    ax_width: int,
) -> tuple[CAssignment, int] | LoopCarriedTerminalReturnResult8616:
    """Return the sole self-contained full-AX assignment or refuse."""
    assignments = tuple(
        node
        for node in body
        if isinstance(node, CAssignment) and _is_full_ax_8616(node.lhs, ax_offset, ax_width)
    )
    if len(assignments) != 1:
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.AMBIGUOUS_AX_DEFINITION,
            normalized=1,
        )
    assignment = assignments[0]
    if _ax_views_8616(assignment.rhs, ax_offset, ax_width):
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.UNSAFE_AX_FLOW,
            normalized=1,
        )
    return assignment, body.index(assignment)


def _suffix_ax_safety_8616(
    codegen_surface: _CodegenSurface8616,
    suffix: tuple[object, ...],
    ax_offset: int,
    ax_width: int,
) -> LoopCarriedTerminalReturnResult8616 | None:
    """Refuse when the suffix writes or partially reads physical AX."""
    for statement in suffix:
        for nested in _iter_c_nodes_deep_8616(statement):
            if isinstance(nested, CAssignment):
                view = physical_register_view_8616(nested.lhs)
                if view is not None and _overlaps_ax_8616(view, ax_offset, ax_width):
                    return _refused_8616(
                        codegen_surface,
                        LoopCarriedTerminalReturnRefusal8616.UNSAFE_AX_FLOW,
                        normalized=1,
                    )
        if any(
            view.reg_offset != ax_offset or view.width != ax_width
            for view in _ax_views_8616(statement, ax_offset, ax_width)
        ):
            return _refused_8616(
                codegen_surface,
                LoopCarriedTerminalReturnRefusal8616.UNSAFE_AX_FLOW,
                normalized=1,
            )
    return None


def materialize_loop_carried_terminal_return_8616(
    project: object,
    codegen: object,
) -> LoopCarriedTerminalReturnResult8616:
    """Preserve one mandatory loop's exact full-AX carrier as a C temporary."""
    project_surface = cast(_ProjectSurface8616, project)
    codegen_surface = cast(_CodegenSurface8616, codegen)
    prelude = _loop_carried_prelude_8616(project_surface, codegen_surface)
    if isinstance(prelude, LoopCarriedTerminalReturnResult8616):
        return prelude
    cfunc, root = prelude

    returns = _c_return_nodes_8616(root)
    if _already_materialized_8616(returns):
        return _result_8616(
            codegen_surface,
            LoopCarriedTerminalReturnStatus8616.ALREADY_MATERIALIZED,
            LoopCarriedTerminalReturnRefusal8616.NONE,
            LoopCarriedTerminalReturnEvidence8616(1, 1, 1, 1, 0),
        )

    function = _terminal_ax_function_8616(
        project, project_surface, codegen_surface, cfunc.addr
    )
    if isinstance(function, LoopCarriedTerminalReturnResult8616):
        return function

    geometry = _ax_geometry_8616(project_surface, codegen_surface)
    if isinstance(geometry, LoopCarriedTerminalReturnResult8616):
        return geometry
    ax_offset, ax_width = geometry

    shape = _loop_carried_shape_8616(codegen_surface, root, returns)
    if isinstance(shape, LoopCarriedTerminalReturnResult8616):
        return shape
    body, return_node = shape

    proven = _proven_ax_assignment_8616(codegen_surface, body, ax_offset, ax_width)
    if isinstance(proven, LoopCarriedTerminalReturnResult8616):
        return proven
    assignment, assignment_index = proven

    suffix = body[assignment_index + 1 :]
    unsafe = _suffix_ax_safety_8616(codegen_surface, suffix, ax_offset, ax_width)
    if unsafe is not None:
        return unsafe

    word_type = _typed_word_8616(assignment.rhs, project_surface.arch)
    if word_type is None:
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.MISSING_TYPED_WORD,
            normalized=1,
        )
    return _materialize_loop_carrier_8616(
        codegen,
        codegen_surface,
        root,
        return_node,
        assignment,
        suffix,
        ax_offset,
        ax_width,
        word_type,
    )


def _materialize_loop_carrier_8616(
    codegen: object,
    codegen_surface: _CodegenSurface8616,
    root: CStatements,
    return_node: CReturn,
    assignment: CAssignment,
    suffix: tuple[object, ...],
    ax_offset: int,
    ax_width: int,
    word_type: SimTypeInt | SimTypeShort,
) -> LoopCarriedTerminalReturnResult8616:
    """Install the temporary carrier and rewrite all proven AX reads."""
    assignment_tags = copy_structured_tags_8616(assignment.tags) or {}
    instruction_addr = assignment_tags.get("ins_addr")
    if not isinstance(instruction_addr, int) or isinstance(instruction_addr, bool):
        return _refused_8616(
            codegen_surface,
            LoopCarriedTerminalReturnRefusal8616.MISSING_INSTRUCTION_IDENTITY,
            normalized=1,
        )

    temporary = SimTemporaryVariable(
        _next_temporary_id_8616(root, instruction_addr),
        ax_width,
    )
    carrier_tags = {**assignment_tags, _MATERIALIZED_TAG: True}

    def _carrier_8616() -> CVariable:
        """Build one typed occurrence of the same local carrier."""
        return CVariable(
            temporary,
            variable_type=word_type,
            codegen=codegen,
            tags=carrier_tags,
        )

    assignment.lhs = _carrier_8616()
    assignment.tags = carrier_tags
    expected_reads = sum(
        len(_ax_views_8616(statement, ax_offset, ax_width))
        for statement in suffix
    )
    for statement in suffix:
        _replace_c_children_8616(
            statement,
            lambda node: _carrier_8616() if _is_full_ax_8616(node, ax_offset, ax_width) else node,
        )
    remaining_reads = sum(
        len(_ax_views_8616(statement, ax_offset, ax_width))
        for statement in suffix
    )
    if remaining_reads != 0:
        raise RuntimeError(
            "classified loop-carried AX reads were not fully materialized "
            f"(expected={expected_reads}, remaining={remaining_reads})"
        )
    return_node.retval = _carrier_8616()
    return_node.tags = {
        **(copy_structured_tags_8616(return_node.tags) or {}),
        _MATERIALIZED_TAG: True,
    }
    evidence = LoopCarriedTerminalReturnEvidence8616(1, 1, 1, 1, 0)
    if evidence.classified_fact_count > 0 and evidence.materialized_count == 0:
        raise RuntimeError("loop-carried terminal-return evidence was classified but not materialized")
    return _result_8616(
        codegen_surface,
        LoopCarriedTerminalReturnStatus8616.MATERIALIZED,
        LoopCarriedTerminalReturnRefusal8616.NONE,
        evidence,
    )
