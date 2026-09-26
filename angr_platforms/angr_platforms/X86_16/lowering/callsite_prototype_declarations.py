"""Materialize typed direct-call identities and declarations.

Layer: Types/lowering.
Responsibility: lower typed callsite summaries into canonical direct-call
identities and recompilable declaration metadata after structuring creates calls.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: source/COD/assembly/rendered-C recovery, callee prototype mutation,
call-argument repair, or call-body mutation.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CConstant, CFunctionCall, CUnaryOp
from angr.knowledge_plugins.functions import Function
from angr.sim_type import (
    SimStruct,
    SimType,
    SimTypeArray,
    SimTypeBottom,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypePointer,
)
from archinfo import Arch

from ..analysis_helpers import preferred_known_helper_signature_decl
from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..call_target_identity import normalize_x86_16_call_target_addr_8616
from ..callsite_summary import (
    CallsiteMachineFrameKind8616,
    CallsiteSummary8616,
    caller_return_use_evidence_by_addr_8616,
    callsite_machine_frame_kind_8616,
    callsite_summary_inventory_8616,
    structured_callsite_addr_8616,
)
from ..codegen_metadata import get_codegen_sequence_attr, set_codegen_sequence_attr
from ..pipeline.errors import PipelineHardError
from .c_runtime_header import (
    KNOWN_EXTERNAL_RETURN_TYPES_8616,
    is_lowered_runtime_macro_8616,
    runtime_helper_declaration_8616,
)
from .callee_argument_width_evidence import collect_callee_argument_width_evidence_8616
from .callee_global_object_type_surface import resolved_type_8616
from .callee_pointer_evidence import callee_pointer_argument_is_proven_8616
from .callsite_pointer_tables import (
    callsite_pointer_table_argument_type_8616,
    materialize_callsite_pointer_table_types_8616,
)
from .dos_interrupt_abi import dos_interrupt_prototype_declaration_8616
from .interprocedural_storage_contracts import (
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from .interprocedural_storage_simtypes import (
    StorageSimTypeVerdict8616,
    storage_contract_return_type_8616,
)
from .interprocedural_storage_transaction import (
    accepted_callsite_storage_binding_8616,
    function_storage_resolution_8616,
)
from .return_type_evidence import (
    caller_return_use_evidence_proves_unused_8616,
    collect_unobserved_callee_void_evidence_8616,
)

__all__ = [
    "CallTargetIdentityStats8616",
    "CallsiteCResultContract8616",
    "CallsiteCResultKind8616",
    "canonicalize_callsite_target_identities_8616",
    "materialize_callsite_prototype_declarations_8616",
]

_C_IDENTIFIER_RE_8616 = re.compile(r"[A-Za-z_]\w*")
_DECLARATION_NAME_RE_8616 = re.compile(
    r"^\s*[A-Za-z_][\w\s*]*?\s+(?P<name>[A-Za-z_]\w*)\s*\("
)
_LOGGER = logging.getLogger(__name__)


class _CodegenSurface8616(Protocol):
    """Owned view of dynamic codegen fields consumed by this lowering pass."""

    cfunc: object
    _inertia_callsite_summaries: object
    _inertia_callsite_c_result_contracts_8616: dict[int, CallsiteCResultContract8616]
    _inertia_call_target_identity_stats_8616: CallTargetIdentityStats8616


class _CFunctionSurface8616(Protocol):
    """Minimal structured function boundary used to find the current root."""

    statements: object
    body: object


class _NamedFunctionSurface8616(Protocol):
    """Minimal callee identity exposed by angr function objects."""

    name: object


class _AddressedFunctionSurface8616(Protocol):
    """Minimal callee identity used for target-backed summary rebinding."""

    addr: object
    name: object


class _FunctionManagerSurface8616(Protocol):
    """Minimal project function lookup used at the angr boundary."""

    def function(self, *, addr: int, create: bool) -> Function | None:
        """Return the function at an exact target address."""


class _KnowledgeBaseSurface8616(Protocol):
    """Minimal knowledge-base surface used for exact target lookup."""

    functions: _FunctionManagerSurface8616


class _ProjectSurface8616(Protocol):
    """Minimal project surface used for exact target lookup."""

    arch: Arch
    kb: _KnowledgeBaseSurface8616
    _inertia_original_linear_delta: object


class _PrototypeFunctionSurface8616(Protocol):
    """Typed callee prototype boundary used by declaration lowering."""

    prototype: object | None


class _TargetProjectSurface8616(Protocol):
    """Minimal owned project policy used to select the generated-C ABI."""

    _inertia_c_target: str


class _TypedExpressionSurface8616(Protocol):
    """Minimal structured expression type boundary exposed by angr."""

    type: object


@dataclass(frozen=True, slots=True)
class _CallsiteDeclarationInterface8616:
    """Typed callsite fields that determine one generated C declaration."""

    target_addr: int | None
    argument_widths: tuple[int, ...]
    stack_probe_helper: bool


@dataclass(slots=True)
class CallTargetIdentityStats8616:
    """Closed evidence loop for canonical direct-call identity materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


class _CallsiteReturnClass8616(Enum):
    """ABI-visible return classes proven by caller-side use."""

    UNKNOWN = "unknown"
    AX = "unsigned short"
    DX_AX = "unsigned long"


class CallsiteCResultKind8616(Enum):
    """Typed C result categories published by declaration Lowering."""

    VOID = "void"
    VALUE = "value"


@dataclass(frozen=True, slots=True)
class CallsiteCResultContract8616:
    """Final C result contract for one exactly resolved structured call."""

    kind: CallsiteCResultKind8616
    c_type: str


def _structured_root_8616(cfunc: object) -> object | None:
    """Return the current structured root from the angr C function boundary."""
    if cfunc is None:
        return None
    surface = cast(_CFunctionSurface8616, cfunc)
    try:
        statements = surface.statements
    except AttributeError:
        statements = None
    if statements is not None:
        return statements
    try:
        return surface.body
    except AttributeError:
        return None


def _call_name_8616(node: CFunctionCall) -> str | None:
    """Return a valid direct-call name from typed structured-call identity."""
    target = node.callee_target
    if isinstance(target, str) and _C_IDENTIFIER_RE_8616.fullmatch(target) is not None:
        return target
    callee = node.callee_func
    if callee is None:
        return None
    try:
        name = cast(_NamedFunctionSurface8616, callee).name
    except AttributeError:
        return None
    return name if isinstance(name, str) and _C_IDENTIFIER_RE_8616.fullmatch(name) is not None else None


def _typed_summary_map_8616(value: object) -> dict[int, CallsiteSummary8616]:
    """Narrow dynamic codegen metadata to the owned typed summary contract."""
    if not isinstance(value, Mapping):
        return {}
    return {
        node_id: summary
        for node_id, summary in value.items()
        if isinstance(node_id, int) and isinstance(summary, CallsiteSummary8616)
    }


def _summary_for_call_8616(
    project: object,
    node: CFunctionCall,
    summaries: Mapping[int, CallsiteSummary8616],
) -> CallsiteSummary8616 | None:
    """Resolve exact identity or repeated summaries with one proven interface."""
    exact = summaries.get(id(node))
    if exact is not None:
        return exact
    callsite_addr = _call_tag_addr_8616(node)
    matches: tuple[CallsiteSummary8616, ...] = (
        ()
        if not isinstance(callsite_addr, int)
        else tuple(summary for summary in summaries.values() if summary.callsite_addr == callsite_addr)
    )
    compatible = _compatible_summary_8616(matches)
    if compatible is not None:
        return compatible
    compatible = _callee_summary_8616(node, summaries)
    if compatible is not None:
        return compatible
    return _name_summary_8616(project, node, summaries)


def _name_summary_8616(
    project: object,
    node: CFunctionCall,
    summaries: Mapping[int, CallsiteSummary8616],
) -> CallsiteSummary8616 | None:
    """Resolve a summary whose target's symbol name equals the call name."""
    call_name = _call_name_8616(node)
    if call_name is None:
        return None
    try:
        functions = cast(_ProjectSurface8616, project).kb.functions
    except AttributeError:
        return None
    target_matches: list[CallsiteSummary8616] = []
    for summary in summaries.values():
        if not isinstance(summary.target_addr, int):
            continue
        try:
            function = functions.function(addr=summary.target_addr, create=False)
        except (KeyError, TypeError):
            continue
        if function is None:
            continue
        try:
            target_name = cast(_AddressedFunctionSurface8616, function).name
        except AttributeError:
            continue
        if target_name == call_name:
            target_matches.append(summary)
    return _compatible_summary_8616(target_matches)


def _callsite_addr_8616(node: CFunctionCall) -> int | None:
    """Return one exact instruction address from a structured call."""
    callsite_addr = structured_callsite_addr_8616(node)
    return callsite_addr if isinstance(callsite_addr, int) else None


def _callsite_matches_summary_8616(
    project: object,
    node: CFunctionCall,
    summary: CallsiteSummary8616,
) -> bool:
    """Match exact active or rebased instruction identity to one summary."""
    callsite_addr = _callsite_addr_8616(node)
    if callsite_addr == summary.callsite_addr:
        return True
    try:
        original_delta = cast(_ProjectSurface8616, project)._inertia_original_linear_delta
    except AttributeError:
        return False
    return (
        isinstance(callsite_addr, int)
        and isinstance(original_delta, int)
        and callsite_addr + original_delta == summary.callsite_addr
    )


def _callee_addr_8616(node: CFunctionCall) -> int | None:
    """Return the explicit function-object address from a structured call."""
    callee = node.callee_func
    if callee is None:
        return None
    try:
        addr = cast(_AddressedFunctionSurface8616, callee).addr
    except AttributeError:
        return None
    return addr if isinstance(addr, int) else None


def _constant_register_indirect_target_addr_8616(
    project: object,
    node: CFunctionCall,
    summary: CallsiteSummary8616,
) -> int | None:
    """Return a proven near address from one constant register-call branch."""
    target = node.callee_target
    target_source = summary.target_source
    target_value = target.value if isinstance(target, CConstant) else None
    register_name = _indirect_register_call_reg_name_8616(
        summary, node, target, target_source, target_value
    )
    if register_name is None:
        return None
    try:
        register_shape = cast(_ProjectSurface8616, project).arch.registers[register_name]
    except (AttributeError, KeyError, TypeError):
        return None
    if len(register_shape) < 2 or register_shape[1] != 2:
        return None
    normalized_target = normalize_x86_16_call_target_addr_8616(project, target_value)
    return normalized_target if isinstance(normalized_target, int) else None


def _indirect_register_call_reg_name_8616(
    summary: CallsiteSummary8616,
    node: CFunctionCall,
    target: object,
    target_source: object,
    target_value: object,
) -> str | None:
    """Return the proven near-register name, or None when unproven."""
    if (
        summary.target_addr is not None
        or not isinstance(target_source, tuple)
        or len(target_source) != 2
        or target_source[0] != "reg"
        or not isinstance(target_source[1], str)
    ):
        return None
    if (
        not isinstance(target, CConstant)
        or not isinstance(target.type, SimTypePointer)
        or not isinstance(target_value, int)
        or not 0 <= target_value <= 0xFFFF
    ):
        return None
    if not isinstance(summary.arg_count, int) or summary.arg_count != len(
        tuple(cast(Sequence[object], node.args or ()))
    ):
        return None
    return target_source[1]


def _storage_contract_return_decision_8616(
    project: object, target_addr: int
) -> tuple[bool, str | None]:
    """Resolve the storage-contract return lane: (decided, c_type)."""
    storage_resolution = function_storage_resolution_8616(
        project,
        target_addr,
    )
    if storage_resolution is None:
        return False, None
    if storage_resolution.contract is None:
        return True, None
    storage_return = storage_contract_return_type_8616(
        storage_resolution.contract,
        cast(_ProjectSurface8616, project).arch,
    )
    if storage_return.verdict is StorageSimTypeVerdict8616.REFUSED:
        return True, None
    if storage_return.accepted:
        return True, storage_return.c_type if isinstance(storage_return.c_type, str) else None
    return False, None


def _prototype_is_void_return_8616(project: object, target_addr: int) -> bool:
    """True when the target function's prototype declares a void return."""
    try:
        function = cast(_ProjectSurface8616, project).kb.functions.function(
            addr=target_addr,
            create=False,
        )
        prototype = (
            cast(_PrototypeFunctionSurface8616, function).prototype
            if function is not None
            else None
        )
    except (AttributeError, KeyError, TypeError):
        prototype = None
    if isinstance(prototype, SimTypeFunction) and isinstance(prototype.returnty, SimTypeBottom):  # noqa: SIM102
        if prototype.returnty.label == "void":
            return True
    return False


def _call_tag_addr_8616(node: CFunctionCall) -> int | None:
    """Return the exact callsite instruction address recorded in node tags."""
    tags = node.tags
    callsite_addr = None
    if isinstance(tags, Mapping):
        for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
            value = tags.get(key)
            if isinstance(value, int):
                callsite_addr = value
                break
    return callsite_addr


def _callee_summary_8616(
    node: CFunctionCall, summaries: Mapping[int, CallsiteSummary8616]
) -> CallsiteSummary8616 | None:
    """Resolve a summary by the callee's exact target address."""
    callee = node.callee_func
    if callee is None:
        return None
    try:
        callee_addr = cast(_AddressedFunctionSurface8616, callee).addr
    except AttributeError:
        callee_addr = None
    if not isinstance(callee_addr, int):
        return None
    matches = tuple(summary for summary in summaries.values() if summary.target_addr == callee_addr)
    return _compatible_summary_8616(matches)


def canonicalize_callsite_target_identities_8616(
    project: object,
    codegen: object,
) -> bool:
    """Rebind each exact callsite to its authoritative target function and name."""
    carrier = cast(_CodegenSurface8616, codegen)
    stats = CallTargetIdentityStats8616()
    carrier._inertia_call_target_identity_stats_8616 = stats
    try:
        cfunc = carrier.cfunc
        summaries = _typed_summary_map_8616(carrier._inertia_callsite_summaries)
    except AttributeError:
        return False
    root = _structured_root_8616(cfunc)
    if root is None or not summaries:
        return False
    try:
        functions = cast(_ProjectSurface8616, project).kb.functions
    except AttributeError:
        return False

    changed = False
    decisions: list[tuple[int | None, int | None, str]] = []
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        summary = _summary_for_call_8616(project, node, summaries)
        if summary is None:
            continue
        changed = _canonicalize_call_identity_8616(
            project, functions, node, summary, stats, decisions
        ) or changed

    if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
        _LOGGER.warning(
            "[call-target-identity] raw=%d normalized=%d classified=%d "
            "materialized=%d failed=%d decisions=%r",
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            tuple(decisions),
        )
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified canonical call targets were not materialized"
        )
    return changed


def _canonicalize_call_identity_8616(
    project: object,
    functions: object,
    node: CFunctionCall,
    summary: CallsiteSummary8616,
    stats: CallTargetIdentityStats8616,
    decisions: list[tuple[int | None, int | None, str]],
) -> bool:
    """Rebind one call to its authoritative target identity; True when changed."""
    constant_target_addr = _constant_register_indirect_target_addr_8616(
        project,
        node,
        summary,
    )
    authoritative_target_addr = (
        summary.target_addr
        if isinstance(summary.target_addr, int)
        else constant_target_addr
    )
    if not isinstance(authoritative_target_addr, int):
        return False
    stats.raw_fact_count += 1
    if not _callsite_matches_summary_8616(project, node, summary):
        stats.failure_count += 1
        decisions.append(
            (_callee_addr_8616(node), authoritative_target_addr, "callsite-mismatch")
        )
        return False
    current_addr = _callee_addr_8616(node)
    if constant_target_addr is None and current_addr != authoritative_target_addr:
        exact_far_target = (
            callsite_machine_frame_kind_8616(summary)
            is CallsiteMachineFrameKind8616.FAR
        )
        canonical_addr = (
            authoritative_target_addr
            if exact_far_target
            else normalize_x86_16_call_target_addr_8616(project, current_addr)
        )
        if canonical_addr != authoritative_target_addr:
            stats.failure_count += 1
            decisions.append((current_addr, authoritative_target_addr, "target-mismatch"))
            return False
    stats.normalized_fact_count += 1
    canonical_function, canonical_name, decision = _canonical_target_identity_8616(
        functions, node, current_addr, authoritative_target_addr
    )
    if (
        not isinstance(canonical_name, str)
        or _C_IDENTIFIER_RE_8616.fullmatch(canonical_name) is None
    ):
        stats.failure_count += 1
        decisions.append((current_addr, authoritative_target_addr, "name-missing"))
        return False
    if node.callee_func is canonical_function and node.callee_target == canonical_name:
        decisions.append((current_addr, authoritative_target_addr, "already-canonical"))
        return False
    stats.classified_fact_count += 1
    node.callee_func = canonical_function
    node.callee_target = canonical_name
    stats.materialized_count += 1
    decisions.append((current_addr, authoritative_target_addr, decision))
    return True


def _canonical_target_identity_8616(
    functions: Any,  # noqa: ANN401
    node: CFunctionCall,
    current_addr: int | None,
    authoritative_target_addr: int,
) -> tuple[object, object, str]:
    """Resolve the canonical function object and name for a proven target."""
    try:
        canonical_function = functions.function(
            addr=authoritative_target_addr,
            create=False,
        )
    except (KeyError, TypeError):
        canonical_function = None
    if canonical_function is None:
        if current_addr == authoritative_target_addr:
            canonical_function = node.callee_func
        return canonical_function, f"sub_{authoritative_target_addr:x}", "materialized-generic"
    try:
        canonical_name = cast(
            _AddressedFunctionSurface8616,
            canonical_function,
        ).name
    except AttributeError:
        canonical_name = None
    return canonical_function, canonical_name, "materialized-function"


def _summary_arg_widths_8616(summary: CallsiteSummary8616) -> tuple[int, ...] | None:
    """Return exact logical argument widths or refuse an incomplete summary."""
    if not isinstance(summary.arg_count, int) or summary.arg_count < 0:
        return None
    logical = summary.logical_arg_widths
    if logical:
        normalized_logical = tuple(width for width in logical if isinstance(width, int) and width > 0)
        if len(normalized_logical) != len(logical):
            return None
        return normalized_logical
    widths = summary.arg_widths
    normalized_widths = tuple(width for width in widths if isinstance(width, int) and width > 0)
    if len(normalized_widths) != summary.arg_count or len(normalized_widths) != len(widths):
        return None
    return normalized_widths


def _scalar_decl_for_width_8616(
    width: int,
    name: str,
    signedness: StorageTrialSignedness8616 = StorageTrialSignedness8616.UNSIGNED,
) -> str:
    """Render a target-width scalar argument declaration."""
    prefix = "" if signedness is StorageTrialSignedness8616.SIGNED else "unsigned "
    if width >= 4:
        return f"{prefix}long {name}"
    if width == 1:
        return f"{prefix}char {name}"
    return f"{prefix}short {name}"


def _argument_type_8616(argument: object, *, codegen: object | None = None) -> object:
    """Return the explicit or structured-reference argument type."""
    if codegen is not None:
        pointer_table_type = callsite_pointer_table_argument_type_8616(codegen, argument)
        if pointer_table_type is not None:
            return pointer_table_type
    try:
        argument_type = cast(_TypedExpressionSurface8616, argument).type
    except AttributeError:
        argument_type = None
    if isinstance(argument, CUnaryOp) and argument.op == "Reference":
        try:
            referent_type = cast(_TypedExpressionSurface8616, argument.operand).type
        except AttributeError:
            referent_type = None
        if isinstance(referent_type, SimType) and isinstance(resolved_type_8616(referent_type), SimStruct):
            return SimTypePointer(referent_type)
        if isinstance(argument_type, SimTypePointer):
            return argument_type
        return SimTypePointer(referent_type if isinstance(referent_type, SimType) else SimTypeBottom())
    return argument_type


def _argument_decl_8616(
    codegen: object,
    argument: object,
    width: int,
    index: int,
    *,
    pointer_proven: bool,
    signedness: StorageTrialSignedness8616 = StorageTrialSignedness8616.UNSIGNED,
) -> str:
    """Render pointer class from typed AST evidence, otherwise summary width."""
    argument_type = _argument_type_8616(argument, codegen=codegen)
    if isinstance(argument_type, SimTypePointer):
        pointee = resolved_type_8616(argument_type.pts_to)
        if isinstance(pointee, SimStruct) and isinstance(pointee.name, str):
            return f"struct {pointee.name} *a{index}"
        return cast(str, cast(SimType, argument_type).c_repr(name=f"a{index}"))
    if isinstance(argument_type, (SimTypeArray, SimTypeFixedSizeArray)):
        return cast(str, SimTypePointer(argument_type.elem_type).c_repr(name=f"a{index}"))
    if pointer_proven:
        return f"void *a{index}"
    return _scalar_decl_for_width_8616(width, f"a{index}", signedness)


def _argument_forward_declarations_8616(codegen: object, argument: object) -> tuple[str, ...]:
    """Return file-scope tag declarations required by one typed argument."""
    argument_type = _argument_type_8616(argument, codegen=codegen)
    if not isinstance(argument_type, SimTypePointer):
        return ()
    pointee = resolved_type_8616(argument_type.pts_to)
    if not isinstance(pointee, SimStruct) or not isinstance(pointee.name, str):
        return ()
    if _C_IDENTIFIER_RE_8616.fullmatch(pointee.name) is None:
        return ()
    return (f"struct {pointee.name};",)


def _used_return_class_8616(
    summary: CallsiteSummary8616,
) -> _CallsiteReturnClass8616 | None:
    """Return a proven used-result class; unused results provide no evidence."""
    if summary.return_used is not True:
        return None
    if summary.return_shape == "dx_ax":
        return _CallsiteReturnClass8616.DX_AX
    if summary.return_register == "ax" or summary.return_shape == "ax":
        return _CallsiteReturnClass8616.AX
    return _CallsiteReturnClass8616.UNKNOWN


def _joined_return_type_8616(
    project: object,
    summary: CallsiteSummary8616,
    summaries: Sequence[CallsiteSummary8616],
) -> str | None:
    """Join caller-use evidence for one exact target or refuse ABI conflict."""
    if isinstance(summary.target_addr, int):
        decided, storage_type = _storage_contract_return_decision_8616(project, summary.target_addr)
        if decided:
            return storage_type
        if _prototype_is_void_return_8616(project, summary.target_addr):
            return "void"
    evidence = (
        caller_return_use_evidence_by_addr_8616(project).get(summary.target_addr)
        if isinstance(summary.target_addr, int)
        else None
    )
    if os.environ.get("INERTIA_DEBUG_RETURN_TYPE_EVIDENCE") == "1":
        _LOGGER.warning(
            "callsite return declaration evidence: target=%s verdict=%s raw=%d classified=%d "
            "materialized=%d failures=%d",
            hex(summary.target_addr) if isinstance(summary.target_addr, int) else None,
            evidence.verdict.value if evidence is not None else "missing",
            evidence.raw_fact_count if evidence is not None else 0,
            evidence.classified_fact_count if evidence is not None else 0,
            evidence.materialized_count if evidence is not None else 0,
            evidence.failure_count if evidence is not None else 0,
        )
    if evidence is not None and isinstance(summary.target_addr, int) and caller_return_use_evidence_proves_unused_8616(evidence):
        void_evidence = collect_unobserved_callee_void_evidence_8616(project, summary.target_addr)
        return "void" if void_evidence.proves_void else "int"

    if isinstance(summary.target_addr, int):
        related = tuple(candidate for candidate in summaries if candidate.target_addr == summary.target_addr)
    else:
        related = (summary,)
    used_classes = {
        return_class
        for candidate in related
        if (return_class := _used_return_class_8616(candidate)) is not None
    }
    if _CallsiteReturnClass8616.UNKNOWN in used_classes or len(used_classes) > 1:
        return None
    if not used_classes:
        return "int"
    return next(iter(used_classes)).value


def _declaration_interface_8616(
    summary: CallsiteSummary8616,
) -> _CallsiteDeclarationInterface8616 | None:
    """Return the declaration contract or refuse incomplete argument evidence."""
    widths = _summary_arg_widths_8616(summary)
    if widths is None:
        return None
    return _CallsiteDeclarationInterface8616(
        target_addr=summary.target_addr,
        argument_widths=widths,
        stack_probe_helper=summary.stack_probe_helper,
    )


def _compatible_summary_8616(
    summaries: Sequence[CallsiteSummary8616],
) -> CallsiteSummary8616 | None:
    """Return one representative only when every summary proves one interface."""
    if not summaries:
        return None
    first = summaries[0]
    expected = _declaration_interface_8616(first)
    if expected is None:
        return None
    for summary in summaries[1:]:
        if _declaration_interface_8616(summary) != expected:
            return None
    return first



def _process_callsite_declaration_8616(
    project: object,
    codegen: object,
    node: CFunctionCall,
    summary: CallsiteSummary8616 | None,
    all_summaries: tuple[CallsiteSummary8616, ...],
    result_contracts: dict[int, CallsiteCResultContract8616],
    desired_by_name: dict[str, str],
    fallback_declarations_by_name: dict[str, set[str]],
    required_forward_decls: set[str],
    ambiguous_names: set[str],
) -> int:
    """Process one resolved call; returns 1 when a summary was consumed."""
    if summary is None or summary.stack_probe_helper:
        if summary is None:
            _debug_callsite_unmatched_8616(node)
        return 0
    _debug_callsite_declaration_evidence_8616(node, summary)
    call_name = _call_name_8616(node)
    if call_name is not None and is_lowered_runtime_macro_8616(call_name):
        return 1
    return_type = _call_return_contract_8616(
        project, summary, call_name, all_summaries, result_contracts
    )
    declaration, runtime_declaration = _select_call_declaration_8616(
        project, codegen, node, summary, call_name, return_type
    )
    if declaration is None:
        _debug_callsite_declaration_refused_8616(node, summary)
        return 1
    _record_call_declaration_8616(
        codegen,
        node,
        summary,
        declaration,
        runtime_declaration,
        return_type,
        desired_by_name,
        fallback_declarations_by_name,
        required_forward_decls,
        ambiguous_names,
    )
    return 1


def _debug_callsite_unmatched_8616(node: CFunctionCall) -> None:
    """Emit the unmatched-callsite diagnostic when enabled."""
    if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
        _LOGGER.warning(
            "callsite declaration unmatched: name=%s callsite=%s callee=%s",
            _call_name_8616(node),
            _callsite_addr_8616(node),
            _callee_addr_8616(node),
        )


def _debug_callsite_declaration_evidence_8616(node: CFunctionCall, summary: CallsiteSummary8616) -> None:
    """Emit the per-callsite evidence diagnostic when enabled."""
    if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
        _LOGGER.warning(
            "callsite declaration evidence: name=%s callsite=%#x target=%s "
            "arg_count=%s arg_widths=%s logical_widths=%s return_register=%s "
            "return_used=%s return_shape=%s",
            _call_name_8616(node),
            summary.callsite_addr,
            None if summary.target_addr is None else hex(summary.target_addr),
            summary.arg_count,
            summary.arg_widths,
            summary.logical_arg_widths,
            summary.return_register,
            summary.return_used,
            summary.return_shape,
        )


def _debug_callsite_declaration_refused_8616(node: CFunctionCall, summary: CallsiteSummary8616) -> None:
    """Emit the refused-declaration diagnostic when enabled."""
    if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
        _LOGGER.warning(
            "callsite declaration refused: callsite=%#x name=%s args=%d widths=%s",
            summary.callsite_addr,
            _call_name_8616(node),
            len(tuple(cast(Sequence[object], node.args or ()))),
            _summary_arg_widths_8616(summary),
        )


def _call_return_contract_8616(
    project: object,
    summary: CallsiteSummary8616,
    call_name: str | None,
    all_summaries: tuple[CallsiteSummary8616, ...],
    result_contracts: dict[int, CallsiteCResultContract8616],
) -> str | None:
    """Join the call's return type and record the result contract."""
    inferred_return_type = _joined_return_type_8616(project, summary, all_summaries)
    return_type = (
        KNOWN_EXTERNAL_RETURN_TYPES_8616.get(call_name, inferred_return_type)
        if call_name is not None
        else inferred_return_type
    )
    if return_type is not None:
        result_contracts[summary.callsite_addr] = CallsiteCResultContract8616(
            kind=(
                CallsiteCResultKind8616.VOID
                if return_type == "void"
                else CallsiteCResultKind8616.VALUE
            ),
            c_type=return_type,
        )
    return return_type


def _debug_callsite_no_declarations_8616(
    call_count: int,
    summaries: Mapping[int, CallsiteSummary8616],
    matched_count: int,
    existing: tuple[str, ...],
    ambiguous_names: set[str],
) -> None:
    """Emit the no-declarations diagnostic when enabled."""
    if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
        _LOGGER.warning(
            "callsite declaration lowering produced no declarations: "
            "calls=%d summaries=%d matched=%d existing=%d ambiguous=%s",
            call_count,
            len(summaries),
            matched_count,
            len(existing),
            tuple(sorted(ambiguous_names)),
        )


def _select_call_declaration_8616(
    project: object,
    codegen: object,
    node: CFunctionCall,
    summary: CallsiteSummary8616,
    call_name: str | None,
    return_type: str | None,
) -> tuple[str | None, object]:
    """Choose the declaration for one call; also returns the runtime decl."""
    runtime_declaration = (
        runtime_helper_declaration_8616(call_name, _project_c_target_8616(project))
        if call_name is not None
        else None
    )
    known_helper_declaration = (
        preferred_known_helper_signature_decl(call_name)
        if call_name is not None
        else None
    )
    abi_declaration = dos_interrupt_prototype_declaration_8616(call_name)
    inferred_declaration = (
        _prototype_decl_8616(project, codegen, node, summary, return_type)
        if return_type is not None
        else None
    )
    declaration = (
        inferred_declaration
        if inferred_declaration is not None and _has_typed_aggregate_pointer_argument_8616(node)
        else abi_declaration or runtime_declaration or known_helper_declaration
    )
    if (
        isinstance(known_helper_declaration, str)
        and declaration == known_helper_declaration
        and isinstance(call_name, str)
        and call_name
        and _declaration_name_8616(known_helper_declaration) != call_name
    ):
        declaration = _declaration_with_call_name_8616(known_helper_declaration, call_name)
    if declaration is None and return_type is not None:
        declaration = inferred_declaration if summary.logical_arg_widths else None
        if declaration is None:
            declaration = (
                _program_arity_fallback_decl_8616(
                    project,
                    summary,
                    call_name,
                    return_type,
                )
                if call_name is not None
                else None
            )
        if declaration is None:
            declaration = _prototype_decl_8616(project, codegen, node, summary, return_type)
    return declaration, runtime_declaration


def _record_call_declaration_8616(
    codegen: object,
    node: CFunctionCall,
    summary: CallsiteSummary8616,
    declaration: str,
    runtime_declaration: object,
    return_type: str | None,
    desired_by_name: dict[str, str],
    fallback_declarations_by_name: dict[str, set[str]],
    required_forward_decls: set[str],
    ambiguous_names: set[str],
) -> None:
    """Record one call's declaration, forward decls, and conflicts."""
    for argument in tuple(cast(Sequence[object], node.args or ())):
        required_forward_decls.update(_argument_forward_declarations_8616(codegen, argument))
    name = _declaration_name_8616(declaration)
    if name is None or name in ambiguous_names:
        return
    if runtime_declaration is None and return_type is not None:
        fallback_declarations_by_name.setdefault(name, set()).add(f"{return_type} {name}();")
    previous = desired_by_name.get(name)
    if previous is not None and previous != declaration:
        if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
            _LOGGER.warning(
                "callsite declaration conflict: name=%s previous=%s current=%s callsite=%#x",
                name,
                previous,
                declaration,
                summary.callsite_addr,
            )
        desired_by_name.pop(name, None)
        ambiguous_names.add(name)
        return
    desired_by_name[name] = declaration


def _debug_callsite_lowering_unavailable_8616(
    root: object,
    summaries: Mapping[int, CallsiteSummary8616],
    inventory: Mapping[int, CallsiteSummary8616],
) -> None:
    """Emit the lowering-unavailable diagnostic when enabled."""
    if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
        _LOGGER.warning(
            "callsite declaration lowering unavailable: root=%s summaries=%d inventory=%d",
            root is not None,
            len(summaries),
            len(inventory),
        )


def _resolved_call_summary_pairs_8616(
    project: object,
    root: object,
    summaries: Mapping[int, CallsiteSummary8616],
    inventory: Mapping[int, CallsiteSummary8616],
) -> list[tuple[CFunctionCall, CallsiteSummary8616 | None]]:
    """Resolve every structured call to its summary when provable."""
    call_nodes = tuple(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CFunctionCall))
    resolved_calls: list[tuple[CFunctionCall, CallsiteSummary8616 | None]] = []
    for node in call_nodes:
        summary = _summary_for_call_8616(project, node, summaries)
        if summary is None:
            summary = _summary_for_call_8616(project, node, inventory)
        resolved_calls.append((node, summary))
    return resolved_calls


def _call_name_sets_8616(
    resolved_calls: list[tuple[CFunctionCall, CallsiteSummary8616 | None]],
) -> tuple[frozenset[str], frozenset[str]]:
    """Return (active call names, obsolete numeric sub_ names)."""
    active_call_names = frozenset(
        name for node, _summary in resolved_calls if (name := _call_name_8616(node)) is not None
    )
    obsolete_numeric_names = frozenset(
        numeric_name
        for node, summary in resolved_calls
        if summary is not None and isinstance(summary.target_addr, int)
        and (numeric_name := f"sub_{summary.target_addr:x}") not in active_call_names
        and _call_name_8616(node) != numeric_name
    )
    return active_call_names, obsolete_numeric_names


def _resolve_ambiguous_declarations_8616(
    desired_by_name: dict[str, str],
    fallback_declarations_by_name: dict[str, set[str]],
    ambiguous_names: set[str],
) -> None:
    """Re-admit ambiguous names only when one fallback spelling survives."""
    for name in ambiguous_names:
        fallback_declarations = fallback_declarations_by_name.get(name, set())
        if len(fallback_declarations) == 1:
            desired_by_name[name] = next(iter(fallback_declarations))


def _merge_prototype_declarations_8616(
    existing: tuple[str, ...],
    desired_by_name: dict[str, str],
    obsolete_numeric_names: frozenset[str],
    required_forward_decls: set[str],
) -> tuple[str, ...]:
    """Merge desired declarations into the existing surface deterministically."""
    merged: list[str] = []
    materialized_names: set[str] = set()
    for declaration in existing:
        name = _declaration_name_8616(declaration)
        if name in obsolete_numeric_names:
            continue
        desired = desired_by_name.get(name or "")
        if desired is None:
            merged.append(declaration)
            continue
        if name is not None and name not in materialized_names:
            merged.append(desired)
            materialized_names.add(name)
    for name, declaration in desired_by_name.items():
        if name not in materialized_names:
            merged.append(declaration)
            materialized_names.add(name)
    ordered_forward_decls = tuple(sorted(required_forward_decls))
    return (
        *ordered_forward_decls,
        *(declaration for declaration in merged if declaration not in required_forward_decls),
    )


def _prototype_decl_8616(
    project: object,
    codegen: object,
    node: CFunctionCall,
    summary: CallsiteSummary8616,
    return_type: str,
) -> str | None:
    """Build one declaration when name, arity, widths, and arguments agree."""
    name = _call_name_8616(node)
    widths = _summary_arg_widths_8616(summary)
    storage_contract = None
    if isinstance(summary.target_addr, int):
        storage_resolution = function_storage_resolution_8616(project, summary.target_addr)
        if storage_resolution is not None and storage_resolution.contract is None:
            return None
        storage_contract = None if storage_resolution is None else storage_resolution.contract
        if storage_contract is not None:
            binding = accepted_callsite_storage_binding_8616(
                project,
                summary.target_addr,
                summary.callsite_addr,
            )
            if binding is None:
                return None
            widths = tuple(slot.width for slot in storage_contract.inputs)
        else:
            width_contract = collect_callee_argument_width_evidence_8616(
                project, summary.target_addr
            )
            if width_contract.raw_fact_count > 0:
                widths = (
                    width_contract.argument_widths if width_contract.closes_census else None
                )
    arguments = tuple(cast(Sequence[object], node.args or ()))
    if name is None or widths is None or len(arguments) != len(widths):
        return None
    args = "void" if not arguments else ", ".join(
        _argument_decl_8616(
            codegen,
            argument,
            width,
            index,
            pointer_proven=(
                storage_contract.inputs[index].value_class
                is StorageTrialValueClass8616.POINTER
                if storage_contract is not None
                else callee_pointer_argument_is_proven_8616(project, name, index)
            ),
            signedness=(
                storage_contract.inputs[index].signedness
                if storage_contract is not None
                else StorageTrialSignedness8616.UNSIGNED
            ),
        )
        for index, (argument, width) in enumerate(zip(arguments, widths, strict=True))
    )
    return f"{return_type} {name}({args});"


def _has_typed_aggregate_pointer_argument_8616(node: CFunctionCall) -> bool:
    """Prefer inferred declarations when a call carries a proven struct pointer."""
    for argument in tuple(cast(Sequence[object], node.args or ())):
        try:
            argument_type = cast(_TypedExpressionSurface8616, argument).type
        except AttributeError:
            continue
        if not isinstance(argument_type, SimTypePointer):
            continue
        if isinstance(argument_type.pts_to, SimStruct):
            return True
    return False


def _program_arity_fallback_decl_8616(
    project: object,
    summary: CallsiteSummary8616,
    name: str,
    return_type: str,
) -> str | None:
    """Return an unprototyped declaration for a discovered but open arity census."""
    if not isinstance(summary.target_addr, int):
        return None
    width_evidence = collect_callee_argument_width_evidence_8616(
        project,
        summary.target_addr,
    )
    evidence = width_evidence.required_count_evidence
    if evidence.raw_fact_count <= 0 or evidence.closes_census:
        return None
    return f"{return_type} {name}();"


def _declaration_name_8616(declaration: str) -> str | None:
    """Return the outer function name from a generated C declaration."""
    match = _DECLARATION_NAME_RE_8616.match(declaration)
    return match.group("name") if match is not None else None


def _declaration_with_call_name_8616(declaration: str, call_name: str) -> str:
    """Spell a known helper declaration with the emitted call identifier."""
    match = _DECLARATION_NAME_RE_8616.match(declaration)
    if match is None:
        return declaration
    return (
        declaration[: match.start("name")]
        + call_name
        + declaration[match.end("name") :]
    )


def _project_c_target_8616(project: object) -> str | None:
    """Return the configured generated-C target from the project policy."""
    try:
        target = cast(_TargetProjectSurface8616, project)._inertia_c_target
    except AttributeError:
        return None
    return target if isinstance(target, str) else None


def materialize_callsite_prototype_declarations_8616(project: object, codegen: object) -> bool:
    """Store evidence-backed declaration metadata for current direct calls.

    This pass deliberately does not assign ``callee.prototype``. It runs after
    call-producing structuring passes, where semantic prototype mutation can
    invalidate an already materialized return call.
    """
    surface = cast(_CodegenSurface8616, codegen)
    try:
        root = _structured_root_8616(surface.cfunc)
        summaries = _typed_summary_map_8616(surface._inertia_callsite_summaries)
    except AttributeError:
        return False
    inventory = callsite_summary_inventory_8616(codegen)
    all_summaries = tuple({summary.callsite_addr: summary for summary in (*summaries.values(), *inventory.values())}.values())
    if root is None or not all_summaries:
        _debug_callsite_lowering_unavailable_8616(root, summaries, inventory)
        return False
    resolved_calls = _resolved_call_summary_pairs_8616(project, root, summaries, inventory)
    _active_call_names, obsolete_numeric_names = _call_name_sets_8616(resolved_calls)
    materialize_callsite_pointer_table_types_8616(
        project,
        codegen,
        ((node, summary) for node, summary in resolved_calls if summary is not None and not summary.stack_probe_helper),
    )
    existing = get_codegen_sequence_attr(codegen, surface.cfunc, "_inertia_callsite_prototype_decls")
    desired_by_name: dict[str, str] = {}
    fallback_declarations_by_name: dict[str, set[str]] = {}
    required_forward_decls: set[str] = set()
    ambiguous_names: set[str] = set()
    result_contracts: dict[int, CallsiteCResultContract8616] = {}
    call_count = 0
    matched_count = 0
    for node, summary in resolved_calls:
        call_count += 1
        matched_count += _process_callsite_declaration_8616(
            project,
            codegen,
            node,
            summary,
            all_summaries,
            result_contracts,
            desired_by_name,
            fallback_declarations_by_name,
            required_forward_decls,
            ambiguous_names,
        )
    _resolve_ambiguous_declarations_8616(
        desired_by_name, fallback_declarations_by_name, ambiguous_names
    )
    surface._inertia_callsite_c_result_contracts_8616 = result_contracts
    if not desired_by_name:
        _debug_callsite_no_declarations_8616(
            call_count, summaries, matched_count, existing, ambiguous_names
        )
        return False
    merged_tuple = _merge_prototype_declarations_8616(
        existing, desired_by_name, obsolete_numeric_names, required_forward_decls
    )
    if merged_tuple == existing:
        return False
    if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
        _LOGGER.warning(
            "callsite declaration lowering materialized: calls=%d summaries=%d matched=%d declarations=%s",
            call_count,
            len(summaries),
            matched_count,
            tuple(desired_by_name.values()),
        )
    set_codegen_sequence_attr(
        codegen,
        surface.cfunc,
        "_inertia_callsite_prototype_decls",
        merged_tuple,
    )
    return True
