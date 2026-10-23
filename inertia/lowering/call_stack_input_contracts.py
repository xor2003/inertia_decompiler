"""Typed architectural word-SP call-context layout and proof census.

Layer: Types/Lowering.
Responsibility: declare the source-bound call-input protocol shared by its
materializer and independent validation. Tags are candidates, never authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimType, SimTypeArray, SimTypeBottom, SimTypeFunction, SimTypePointer
from angr.sim_variable import SimTemporaryVariable
from archinfo import Arch

from inertia.alias.call_stack_positions import CallStackPosition8616
from inertia.ir.core import IRFunctionArtifact

from .c_ast_utils import _iter_c_nodes_deep_8616
from .call_stack_value_uses import CallStackValueUse8616
from .entry_stack_pointer_capture import (
    ScopedCallPositionAuthority8616,
    StackPointerCaptureFunction8616,
)
from .gp_register_state import runtime_gp_expression_view_8616

CALL_STACK_INPUT_BINDING_TAG_8616: str = "inertia_call_stack_input_binding_8616"


class _CodegenCallSource8616(Protocol):
    """Active owned extensions on the native codegen boundary."""

    project: object
    cfunc: StackPointerCaptureFunction8616 | None
    _inertia_vex_ir_artifact: IRFunctionArtifact | None


class _NativeCallTarget8616(Protocol):
    """Native callee identity with its owning project scope."""

    addr: int
    project: object


class _NativeProjectArchitecture8616(Protocol):
    """The native expression owner supplies the target's pointer architecture."""

    arch: Arch


def current_call_stack_source_8616(codegen: object) -> IRFunctionArtifact | None:
    """Admit the current function and the project owning its CALL evidence."""
    boundary = cast(_CodegenCallSource8616, codegen)
    try:
        function, source, project = boundary.cfunc, boundary._inertia_vex_ir_artifact, boundary.project
    except AttributeError:
        return None
    if function is None or not isinstance(source, IRFunctionArtifact) or function.addr != source.function_addr:
        return None
    for block in source.blocks:
        for instruction in block.instrs:
            effect = instruction.call_stack_effect
            coordinates = effect.stack_coordinates if effect is not None else None
            if coordinates is not None and coordinates.source is not None and coordinates.source.project is not project:
                return None
    return source


def direct_call_target_8616(codegen: object, call: c.CFunctionCall) -> int | None:
    """Read a native target bound to this project, never a rendered function name."""
    if call.callee_func is None:
        return None
    try:
        callee = cast(_NativeCallTarget8616, call.callee_func)
        target, project = callee.addr, callee.project
    except AttributeError:
        return None
    return target if type(target) is int and project is cast(_CodegenCallSource8616, codegen).project else None


type CallStackInputAuthority8616 = (
    CallStackPosition8616 | ScopedCallPositionAuthority8616
)


def call_stack_authority_position_8616(
    authority: object,
) -> CallStackPosition8616 | None:
    """Project scalar coordinates from either authority variant.

    The universal variant IS the scalar proof; the scoped variant carries
    it as a read-only projection of retained live evidence. Neither scalar
    is authority by itself.
    """
    if type(authority) is CallStackPosition8616:
        return authority
    if type(authority) is ScopedCallPositionAuthority8616:
        return authority.position
    return None


@dataclass(frozen=True, slots=True)
class CallStackInputBinding8616:
    """Source authority and local identities for one ordered call context.

    Arguments are evaluated into their C value types before the SP input is
    installed. Arrays and function designators undergo the standard pointer
    conversion; scalar and pointer values retain their declared type. Then the
    call executes once. Required results are saved; discarded results do not
    acquire a synthetic use. Then the proven
    caller-after word is installed while preserving the current upper ESP.
    ``authority`` is the owned variant: a universal ``CallStackPosition8616``
    or a scoped ``ScopedCallPositionAuthority8616`` — never a bare scalar.
    """

    authority: CallStackInputAuthority8616
    entry_tmp_id: int
    argument_tmp_ids: tuple[int, ...]
    result_tmp_id: int | None

    @property
    def position(self) -> CallStackPosition8616 | None:
        """Project scalar coordinates for layout; never proof by itself."""
        return call_stack_authority_position_8616(self.authority)












def call_stack_argument_is_stable_8616(expression: object) -> bool:
    """Admit transparent argument expressions evaluated once before frame setup.

    Opaque operations, nested calls and assignment expressions refuse. This
    does not infer purity from a callee name or rendered expression.
    """
    allowed = (c.CConstant, c.CVariable, c.CBinaryOp, c.CUnaryOp, c.CTypeCast, c.CIndexedVariable)
    for node in _iter_c_nodes_deep_8616(expression):
        if not isinstance(node, allowed):
            return False
        if isinstance(node, c.CUnaryOp) and node.op not in {"Neg", "Not", "Reference", "Dereference"}:
            return False
    return isinstance(expression, c.CExpression)


def call_stack_argument_value_type_8616(expression: object) -> SimType | None:
    """Project C argument value conversion without copying arrays or functions.

    Their designators become pointers, as they do at the original call. Pointer
    width comes from the expression's native project, including when an array
    type has no attached architecture. No callee-name or rendered-text inference
    participates in this conversion.
    """
    if not isinstance(expression, c.CExpression) or not isinstance(expression.type, SimType):
        return None
    type_ = expression.type
    if isinstance(type_, SimTypeArray):
        pointee = type_.elem_type
    elif isinstance(type_, SimTypeFunction):
        pointee = type_
    else:
        return type_
    try:
        project = cast(_CodegenCallSource8616, expression.codegen).project
        arch = cast(_NativeProjectArchitecture8616, project).arch
    except AttributeError:
        return None
    if not isinstance(arch, Arch):
        return None
    return SimTypePointer(pointee).with_arch(arch)


def call_stack_value_size_8616(type_: object) -> int | None:
    """Return assignable C value storage bytes; native void has no value slot.

    Arrays and functions require argument conversion before allocating storage;
    neither can be a return-value temporary.
    """
    if isinstance(type_, SimTypeBottom):
        return 0
    if not isinstance(type_, SimType) or isinstance(type_, (SimTypeArray, SimTypeFunction)):
        return None
    try:
        bits = type_.size
    except ValueError:
        return None
    return bits // 8 if type(bits) is int and bits > 0 and bits % 8 == 0 else None


def call_stack_temporary_8616(node: object, identity: int) -> bool:
    """Identify exact local temporary storage without unified register aliases."""
    return (isinstance(node, c.CVariable) and isinstance(node.variable, SimTemporaryVariable)
            and node.variable.tmp_id == identity and node.unified_variable is None)


def call_stack_has_runtime_sp_8616(root: object) -> bool:
    """Detect explicit runtime ESP observations through the register owner."""
    return any(isinstance(node, c.CVariable) and (view := runtime_gp_expression_view_8616(node)) is not None
               and view.parent_name == "esp" for node in _iter_c_nodes_deep_8616(root))


@dataclass(frozen=True, slots=True)
class CallStackContextLayout8616:
    """Parsed ordered context; source position and SP equations remain unproved."""

    marker: CallStackInputBinding8616
    call: c.CFunctionCall
    original_arguments: tuple[c.CExpression, ...]
    pre_write: c.CAssignment
    post_write: c.CAssignment


def _layout_call(wrapper: c.CMultiStatementExpression, marker: CallStackInputBinding8616,
                 invoked: object) -> c.CFunctionCall | None:
    """Preserve the call result's exact declared type and local storage."""
    if marker.result_tmp_id is None:
        if not isinstance(invoked, c.CFunctionCall) or call_stack_value_size_8616(invoked.type) is None:
            return None
        if not isinstance(wrapper.expr, c.CTypeCast) or call_stack_value_size_8616(wrapper.expr.dst_type) != 0:
            return None
        if not isinstance(wrapper.expr.expr, c.CConstant) or wrapper.expr.expr.value != 0:
            return None
        return invoked
    if not isinstance(invoked, c.CAssignment) or not isinstance(invoked.rhs, c.CFunctionCall):
        return None
    call = invoked.rhs
    if call_stack_value_size_8616(call.type) in {None, 0}:
        return None
    if not call_stack_temporary_8616(invoked.lhs, marker.result_tmp_id) or not call_stack_temporary_8616(wrapper.expr, marker.result_tmp_id):
        return None
    if invoked.lhs.type != call.type or wrapper.expr.type != call.type:
        return None
    return call


def _layout_arguments(marker: CallStackInputBinding8616, statements: list[object],
                      call: c.CFunctionCall) -> tuple[c.CExpression, ...] | None:
    """Require each transparent argument to be evaluated once before SP setup."""
    args = call.args or []
    if len(args) != len(marker.argument_tmp_ids):
        return None
    originals: list[c.CExpression] = []
    for index, identity in enumerate(marker.argument_tmp_ids):
        assignment = statements[index]
        if not isinstance(assignment, c.CAssignment) or not call_stack_temporary_8616(assignment.lhs, identity):
            return None
        converted = call_stack_argument_value_type_8616(assignment.rhs)
        if converted is None or not call_stack_temporary_8616(args[index], identity):
            return None
        if assignment.lhs.type != converted or args[index].type != converted:
            return None
        if not call_stack_argument_is_stable_8616(assignment.rhs):
            return None
        if call_stack_has_runtime_sp_8616(assignment.rhs):
            return None
        originals.append(assignment.rhs)
    return tuple(originals)


def call_stack_context_layout_8616(
    wrapper: object, *, value_use: CallStackValueUse8616 | None = None,
) -> CallStackContextLayout8616 | None:
    """Inspect layout; a supplied actual use prevents dropping a needed result.

    Omitting use information gives syntax inspection only, never validation
    authority. Source identity and register equations still require reproof.
    """
    if not isinstance(wrapper, c.CMultiStatementExpression):
        return None
    marker = wrapper.tags.get(CALL_STACK_INPUT_BINDING_TAG_8616)
    if not isinstance(marker, CallStackInputBinding8616) or not isinstance(wrapper.stmts, c.CStatements):
        return None
    identities = (marker.entry_tmp_id, *marker.argument_tmp_ids)
    if marker.result_tmp_id is not None:
        identities = (*identities, marker.result_tmp_id)
    count = len(marker.argument_tmp_ids)
    statements = list(wrapper.stmts.statements)
    if len(set(identities)) != len(identities) or len(statements) != count + 3:
        return None
    pre, post = statements[count], statements[-1]
    if not isinstance(pre, c.CAssignment) or not isinstance(post, c.CAssignment):
        return None
    call = _layout_call(wrapper, marker, statements[count + 1])
    if call is None:
        return None
    if value_use is CallStackValueUse8616.UNKNOWN:
        return None
    if value_use is CallStackValueUse8616.VALUE and marker.result_tmp_id is None:
        return None
    arguments = _layout_arguments(marker, statements, call)
    return None if arguments is None else CallStackContextLayout8616(marker, call, arguments, pre, post)
