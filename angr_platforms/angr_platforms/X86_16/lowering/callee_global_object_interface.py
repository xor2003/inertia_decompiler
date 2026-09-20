"""Join binary caller pointer sources with project-proven global object types.

Layer: Types/Lowering.
Responsibility: promote callee pointer parameters and exact temporary copies
only when every normalized direct caller points into one Widening-proven global
object family. This module consumes structured callsite and layout facts; it
never inspects sidecars.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Sequence
from dataclasses import replace
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CIndexedVariable,
    CVariable,
)
from angr.sim_type import SimStruct, SimType, SimTypeFunction, TypeRef
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..pipeline.errors import PipelineHardError
from ..widening.global_object_layout import GlobalObjectLayoutEvidence8616
from .callee_argument_interface import materialize_callee_pointer_codegen_interface_8616
from .callee_global_object_collection import (
    collect_callee_global_object_interface_evidence_8616,
)
from .callee_global_object_evidence import (
    CalleeGlobalObjectInterfaceEvidence8616,
)
from .callee_global_object_type_surface import (
    cfunc_roots_8616,
    is_named_struct_type_8616,
    materialize_local_struct_declarations_8616,
    same_stack_variable_8616,
)
from .callee_pointer_evidence import CalleePointerArgumentEvidence8616
from .near_pointer_type import near_pointer_type_8616

type GlobalStructFactory8616 = Callable[[str], SimStruct]
_LOGGER = logging.getLogger(__name__)


class _TypeStore8616(Protocol):
    """angr named-type store used at the third-party codegen boundary."""

    def __setitem__(self, name: str, value: TypeRef) -> None:
        """Register one named type reference."""


class _VariableManager8616(Protocol):
    """angr variable-manager type mutation surface."""

    types: _TypeStore8616

    def set_variable_type(
        self,
        variable: object,
        type_: SimType,
        *,
        name: str | None = None,
        override_bot: bool = True,
        all_unified: bool = False,
    ) -> None:
        """Assign one proven type to an exact variable identity."""


class _CFunction8616(Protocol):
    """angr CFunction fields used to materialize the interface."""

    addr: int
    arg_list: Sequence[object]
    body: object
    functy: SimTypeFunction
    statements: object
    variable_manager: _VariableManager8616


class _Function8616(Protocol):
    """angr function prototype field retained across regeneration."""

    prototype: object | None


class _FunctionManager8616(Protocol):
    """angr function-manager lookup surface."""

    def function(self, *, addr: int, create: bool = False) -> _Function8616 | None:
        """Return one function without creating a guessed contract."""


class _KnowledgeBase8616(Protocol):
    """angr knowledge-base function surface."""

    functions: _FunctionManager8616


class _Project8616(Protocol):
    """angr project fields needed by interface materialization."""

    arch: Arch
    kb: _KnowledgeBase8616


class _PointerEvidenceCarrier8616(Protocol):
    """Owned project extension carrying binary pointer evidence by address."""

    _inertia_callee_pointer_argument_evidence_8616: dict[
        int,
        CalleePointerArgumentEvidence8616,
    ]


class _Codegen8616(Protocol):
    """Owned codegen state plus the dynamic angr CFunction boundary."""

    cfunc: _CFunction8616 | None
    project: _Project8616
    show_local_types: bool
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_callee_global_object_interface_evidence_8616: CalleeGlobalObjectInterfaceEvidence8616


def _materialize_aggregate_interface_8616(
    codegen: _Codegen8616,
    evidence: CalleeGlobalObjectInterfaceEvidence8616,
    struct_type: SimStruct,
) -> tuple[int, bool]:
    """Apply one closed aggregate-interface fact to args, uses, and copies."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return 0, False
    registered_type = TypeRef(struct_type.name, struct_type)
    cfunc.variable_manager.types[struct_type.name] = registered_type
    codegen.show_local_types = True
    pointer_type = near_pointer_type_8616(registered_type, codegen.project.arch)
    function_type = cfunc.functy
    function_argument_types = list(function_type.args or ())
    if any(
        index >= len(cfunc.arg_list) or index >= len(function_argument_types)
        for index in evidence.pointer_argument_indices
    ):
        return 0, False
    argument_nodes: list[CVariable] = []
    for index in evidence.pointer_argument_indices:
        argument = cfunc.arg_list[index]
        if not isinstance(argument, CVariable) or not isinstance(
            argument.variable,
            SimStackVariable,
        ):
            return 0, False
        argument_nodes.append(argument)
    argument_variables = [
        cast(SimStackVariable, argument.variable) for argument in argument_nodes
    ]
    changed = False
    for index, argument in zip(
        evidence.pointer_argument_indices,
        argument_nodes,
        strict=True,
    ):
        if argument.variable_type != pointer_type:
            argument.variable_type = pointer_type
            changed = True
        cfunc.variable_manager.set_variable_type(
            argument.variable,
            pointer_type,
            override_bot=True,
            all_unified=True,
        )
        if function_argument_types[index] != pointer_type:
            function_argument_types[index] = pointer_type
            changed = True
    cfunc.functy = SimTypeFunction(
        function_argument_types,
        function_type.returnty,
        arg_names=tuple(function_type.arg_names or ()),
        variadic=function_type.variadic,
    ).with_arch(codegen.project.arch)

    roots = cfunc_roots_8616(cfunc)
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            if isinstance(node, CVariable) and any(
                same_stack_variable_8616(node.variable, argument)
                for argument in argument_variables
            ) and node.variable_type != pointer_type:
                node.variable_type = pointer_type
                changed = True
            if (
                isinstance(node, CIndexedVariable)
                and isinstance(node.variable, CVariable)
                and any(
                    same_stack_variable_8616(node.variable.variable, argument)
                    for argument in argument_variables
                )
                and not is_named_struct_type_8616(node.type, struct_type)
            ):
                node._type = registered_type
                changed = True

    aggregate_locals: list[SimStackVariable] = []
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            if (
                isinstance(node, CAssignment)
                and isinstance(node.lhs, CVariable)
                and isinstance(node.lhs.variable, SimStackVariable)
                and node.lhs.variable.offset < 0
                and isinstance(node.rhs, CIndexedVariable)
                and is_named_struct_type_8616(node.rhs.type, struct_type)
            ):
                aggregate_locals.append(node.lhs.variable)
    for local in aggregate_locals:
        cfunc.variable_manager.set_variable_type(
            local,
            registered_type,
            name=struct_type.name,
            override_bot=True,
            all_unified=True,
        )
    changed = (
        materialize_local_struct_declarations_8616(
            cfunc,
            aggregate_locals,
            registered_type,
            struct_type,
        )
        or changed
    )
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            if isinstance(node, CVariable) and any(
                same_stack_variable_8616(node.variable, local)
                for local in aggregate_locals
            ) and not is_named_struct_type_8616(node.variable_type, struct_type):
                node.variable_type = registered_type
                changed = True

    try:
        function = codegen.project.kb.functions.function(
            addr=evidence.target_addr,
            create=False,
        )
    except (AttributeError, KeyError, TypeError):
        function = None
    if function is not None and isinstance(function.prototype, SimTypeFunction):
        argument_types = list(function.prototype.args or ())
        for index in evidence.pointer_argument_indices:
            if index < len(argument_types):
                argument_types[index] = pointer_type
        function.prototype = SimTypeFunction(
            argument_types,
            function.prototype.returnty,
            arg_names=tuple(function.prototype.arg_names or ()),
            variadic=function.prototype.variadic,
        ).with_arch(codegen.project.arch)
    return len(argument_variables), changed


def materialize_callee_global_object_interface_8616(
    project: object,
    codegen_raw: object,
    layout_evidence: GlobalObjectLayoutEvidence8616,
    struct_factory: GlobalStructFactory8616,
) -> bool:
    """Collect and materialize one all-callers aggregate pointer contract."""
    codegen = cast(_Codegen8616, codegen_raw)
    try:
        cfunc = codegen.cfunc
    except AttributeError:
        return False
    if cfunc is None or not isinstance(cfunc.addr, int):
        return False
    evidence = collect_callee_global_object_interface_evidence_8616(
        project,
        cfunc.addr,
        layout_evidence,
    )
    try:
        pointer_evidence = cast(
            _PointerEvidenceCarrier8616,
            project,
        )._inertia_callee_pointer_argument_evidence_8616.get(cfunc.addr)
    except AttributeError:
        pointer_evidence = None
    if os.environ.get("INERTIA_DEBUG_CALLEE_GLOBAL_OBJECT_INTERFACE") == "1":
        _LOGGER.warning(
            "callee global object interface target=%#x pointers=%s sources=%s "
            "pointer_evidence=%r family=%s census=%s surface=%s",
            cfunc.addr,
            evidence.pointer_argument_indices,
            tuple(
                (
                    fact.callsite_addr,
                    fact.argument_index,
                    fact.base_offset,
                    fact.family_base_offset,
                )
                for fact in evidence.source_facts
            ),
            pointer_evidence,
            evidence.family_base_offset,
            (
                evidence.raw_fact_count,
                evidence.normalized_fact_count,
                evidence.classified_fact_count,
                evidence.materialized_count,
                evidence.failure_count,
            ),
            (
                len(cfunc.arg_list),
                len(cfunc.functy.args or ()),
                tuple(type(argument).__name__ for argument in cfunc.arg_list),
            ),
        )
    if evidence.family_base_offset is None:
        codegen._inertia_callee_global_object_interface_evidence_8616 = evidence
        return False
    interface_changed = False
    if isinstance(pointer_evidence, CalleePointerArgumentEvidence8616):
        interface_result = materialize_callee_pointer_codegen_interface_8616(
            project,
            codegen,
            pointer_evidence,
        )
        interface_changed = interface_result.changed
    struct_type = struct_factory(f"g_{evidence.family_base_offset:04X}")
    materialized_count, changed = _materialize_aggregate_interface_8616(
        codegen,
        evidence,
        struct_type,
    )
    evidence = replace(evidence, materialized_count=materialized_count)
    codegen._inertia_callee_global_object_interface_evidence_8616 = evidence
    if evidence.classified_fact_count > 0 and materialized_count == 0:
        raise PipelineHardError(
            "callee aggregate interface classified facts without materialization "
            f"target={evidence.target_addr:#x} raw={evidence.raw_fact_count} "
            f"normalized={evidence.normalized_fact_count} "
            f"classified={evidence.classified_fact_count} failures={evidence.failure_count}"
        )
    if changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
    return interface_changed or changed


__all__ = [
    "materialize_callee_global_object_interface_8616",
]
