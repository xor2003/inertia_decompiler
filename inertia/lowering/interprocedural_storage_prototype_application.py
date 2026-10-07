"""Apply an accepted storage contract to one function prototype transaction.

Layer: Types/Lowering.
Responsibility: preflight one accepted function storage contract, then update
the structured callee, angr function metadata, argument variables and the
authoritative replay snapshot together. A stale snapshot must not undo an
accepted pointer/value contract during annotation or codegen replay.
Consumes alias, widening, and typed facts through the atomic interprocedural
storage publication and the pure storage-to-``SimType`` projection.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimType, SimTypeFunction
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from .authoritative_function_prototypes import publish_authoritative_function_prototype_8616
from .interprocedural_storage_contracts import FunctionStorageContract8616
from .interprocedural_storage_prototype_types import (
    FunctionStoragePrototypeApplicationResult8616,
    FunctionStoragePrototypeApplicationVerdict8616,
    preflight_storage_prototype_types_8616,
    storage_prototype_with_types_8616,
)
from .interprocedural_storage_transaction import function_storage_resolution_8616

__all__ = [
    "FunctionStoragePrototypeApplicationResult8616",
    "FunctionStoragePrototypeApplicationVerdict8616",
    "apply_accepted_function_storage_prototype_8616",
]


class _CFunctionSurface8616(Protocol):
    """Owned structured-callee fields consumed and updated together."""

    addr: int
    arg_list: list[structured_c.CVariable]
    functy: object


class _CodegenSurface8616(Protocol):
    """Owned codegen projection and declaration-refresh state."""

    cfunc: _CFunctionSurface8616
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_storage_prototype_application_8616: FunctionStoragePrototypeApplicationResult8616


class _FunctionSurface8616(Protocol):
    """Third-party angr function prototype fields synchronized by this pass."""

    prototype: object
    is_prototype_guessed: bool


class _FunctionManager8616(Protocol):
    """Third-party exact-function lookup boundary."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an existing function without creating one."""
        ...


class _KnowledgeBase8616(Protocol):
    """Third-party knowledge-base function surface."""

    functions: _FunctionManager8616


class _ProjectSurface8616(Protocol):
    """Project architecture and knowledge-base boundary."""

    arch: Arch
    kb: _KnowledgeBase8616


def _record_result_8616(
    codegen: object,
    result: FunctionStoragePrototypeApplicationResult8616,
) -> FunctionStoragePrototypeApplicationResult8616:
    """Retain the typed application result at the dynamic codegen boundary."""
    with contextlib.suppress(AttributeError):
        cast(
            _CodegenSurface8616,
            codegen,
        )._inertia_storage_prototype_application_8616 = result
    return result


@dataclass(slots=True)
class _PrototypeApplyContext8616:
    """Proven surfaces needed for the atomic callee prototype update."""

    function_addr: int
    project_surface: _ProjectSurface8616
    function_surface: _FunctionSurface8616
    cfunc: _CFunctionSurface8616
    cfunc_prototype: SimTypeFunction
    function_prototype: SimTypeFunction
    cvars: tuple[structured_c.CVariable, ...]
    contract: FunctionStorageContract8616


def _proven_apply_context_8616(
    project: object,
    codegen: object,
) -> _PrototypeApplyContext8616 | FunctionStoragePrototypeApplicationResult8616:
    """Collect every proven surface for the atomic prototype update."""
    try:
        cfunc = cast(_CodegenSurface8616, codegen).cfunc
        function_addr = cfunc.addr
    except AttributeError:
        return _record_result_8616(
            codegen,
            FunctionStoragePrototypeApplicationResult8616(
                None,
                FunctionStoragePrototypeApplicationVerdict8616.FUNCTION_UNAVAILABLE,
            ),
        )
    if not isinstance(function_addr, int):
        return _record_result_8616(
            codegen,
            FunctionStoragePrototypeApplicationResult8616(
                None,
                FunctionStoragePrototypeApplicationVerdict8616.FUNCTION_UNAVAILABLE,
            ),
        )
    resolution = function_storage_resolution_8616(project, function_addr)
    if resolution is None:
        return _record_result_8616(
            codegen,
            FunctionStoragePrototypeApplicationResult8616(
                function_addr,
                FunctionStoragePrototypeApplicationVerdict8616.CONTRACT_UNAVAILABLE,
            ),
        )
    if resolution.contract is None:
        return _record_result_8616(
            codegen,
            FunctionStoragePrototypeApplicationResult8616(
                function_addr,
                FunctionStoragePrototypeApplicationVerdict8616.CONTRACT_REFUSED,
            ),
        )
    project_surface = cast(_ProjectSurface8616, project)
    function = project_surface.kb.functions.function(addr=function_addr, create=False)
    if function is None:
        return _record_result_8616(
            codegen,
            FunctionStoragePrototypeApplicationResult8616(
                function_addr,
                FunctionStoragePrototypeApplicationVerdict8616.FUNCTION_UNAVAILABLE,
            ),
        )
    function_surface = cast(_FunctionSurface8616, function)
    cfunc_prototype = cfunc.functy
    function_prototype = function_surface.prototype
    if not isinstance(cfunc_prototype, SimTypeFunction):
        return _record_result_8616(
            codegen,
            FunctionStoragePrototypeApplicationResult8616(
                function_addr,
                FunctionStoragePrototypeApplicationVerdict8616.PROTOTYPE_UNAVAILABLE,
            ),
        )
    if not isinstance(function_prototype, SimTypeFunction):
        function_prototype = cfunc_prototype
    cvars = tuple(cfunc.arg_list or ())
    if not all(isinstance(item, structured_c.CVariable) for item in cvars):
        return _record_result_8616(
            codegen,
            FunctionStoragePrototypeApplicationResult8616(
                function_addr,
                FunctionStoragePrototypeApplicationVerdict8616.ARGUMENT_SHAPE_REFUSED,
            ),
        )
    return _PrototypeApplyContext8616(
        function_addr=function_addr,
        project_surface=project_surface,
        function_surface=function_surface,
        cfunc=cfunc,
        cfunc_prototype=cfunc_prototype,
        function_prototype=function_prototype,
        cvars=cvars,
        contract=resolution.contract,
    )


def _mutate_prototype_surfaces_8616(
    project: object,
    ctx: _PrototypeApplyContext8616,
    argument_types: tuple[SimType, ...],
    cfunc_return: SimType,
    function_return: SimType,
) -> tuple[SimTypeFunction, bool]:
    """Update cvar types, stack sizes, prototypes, and the replay snapshot."""
    new_cfunc_prototype = storage_prototype_with_types_8616(
        ctx.cfunc_prototype,
        argument_types,
        cfunc_return,
        ctx.project_surface.arch,
    )
    new_function_prototype = storage_prototype_with_types_8616(
        ctx.function_prototype,
        argument_types,
        function_return,
        ctx.project_surface.arch,
    )
    changed = False
    for slot, cvar, argument_type in zip(
        ctx.contract.inputs,
        ctx.cvars,
        argument_types,
        strict=True,
    ):
        if cvar.variable_type != argument_type:
            cvar.variable_type = argument_type
            changed = True
        variable = cast(SimStackVariable, cvar.variable)
        if variable.size != slot.width:
            variable.size = slot.width
            changed = True
    if ctx.cfunc.functy != new_cfunc_prototype:
        ctx.cfunc.functy = new_cfunc_prototype
        changed = True
    if ctx.function_surface.prototype != new_function_prototype:
        ctx.function_surface.prototype = new_function_prototype
        changed = True
    if ctx.function_surface.is_prototype_guessed:
        ctx.function_surface.is_prototype_guessed = False
        changed = True
    publish_authoritative_function_prototype_8616(
        project,
        ctx.function_addr,
        new_cfunc_prototype,
        source=PrototypeSource.CCA_DECOMPILER,
    )
    return new_cfunc_prototype, changed


def apply_accepted_function_storage_prototype_8616(
    project: object,
    codegen: object,
) -> FunctionStoragePrototypeApplicationResult8616:
    """Apply one complete accepted contract to every current callee projection."""
    context = _proven_apply_context_8616(project, codegen)
    if isinstance(context, FunctionStoragePrototypeApplicationResult8616):
        return context
    function_addr = context.function_addr
    preflight = preflight_storage_prototype_types_8616(
        context.contract,
        context.cfunc_prototype,
        context.function_prototype,
        context.cvars,
        context.project_surface.arch,
        codegen,
    )
    if not preflight.accepted or preflight.argument_types is None:
        return _record_result_8616(
            codegen,
            FunctionStoragePrototypeApplicationResult8616(
                function_addr,
                FunctionStoragePrototypeApplicationVerdict8616.TYPE_REFUSED,
                type_failures=preflight.failures,
            ),
        )
    argument_types = preflight.argument_types
    cfunc_return = preflight.proven_return or cast(SimType, context.cfunc_prototype.returnty)
    function_return = preflight.proven_return or cast(
        SimType, context.function_prototype.returnty
    )
    if not isinstance(cfunc_return, SimType) or not isinstance(function_return, SimType):
        return _record_result_8616(
            codegen,
            FunctionStoragePrototypeApplicationResult8616(
                function_addr,
                FunctionStoragePrototypeApplicationVerdict8616.PROTOTYPE_UNAVAILABLE,
            ),
        )
    new_cfunc_prototype, changed = _mutate_prototype_surfaces_8616(
        project,
        context,
        argument_types,
        cfunc_return,
        function_return,
    )
    if changed:
        cast(_CodegenSurface8616, codegen)._inertia_codegen_decl_refresh_required_8616 = True
    return _record_result_8616(
        codegen,
        FunctionStoragePrototypeApplicationResult8616(
            function_addr,
            (
                FunctionStoragePrototypeApplicationVerdict8616.APPLIED
                if changed
                else FunctionStoragePrototypeApplicationVerdict8616.UNCHANGED
            ),
            prototype=new_cfunc_prototype,
            changed=changed,
        ),
    )
