"""Materialize a void C contract from closed unobservable-return evidence.

Layer: Types/lowering.
Responsibility: combine a complete caller census with complete empty AIL
terminal returns, exact empty return-register storage, or a synthetic zero
return, then synchronize the generated function and C prototypes.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Function names are not evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CIndexedVariable,
    CReturn,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction
from archinfo import Arch

from ..annotations import ANNOTATION_KEY
from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallerReturnUseVerdict8616
from ..pipeline.errors import PipelineHardError
from ..semantics.terminal_return_storage import (
    TerminalReturnStorage8616,
    terminal_return_storage_8616,
)
from .return_type_evidence import proven_function_result_observation_8616
from .runtime_segment_access import is_runtime_segment_load_helper_8616
from .unobserved_returns import return_value_needs_neutralization_8616


def _return_expr_is_side_effect_free_8616(expr: object) -> bool:
    """Return whether an expression contains only side-effect-free value nodes."""
    nodes = tuple(_iter_c_nodes_deep_8616(expr))
    pure_node_types = (
        CBinaryOp,
        CConstant,
        CDirtyExpression,
        CIndexedVariable,
        CTypeCast,
        CUnaryOp,
        CVariable,
        CVariableField,
    )
    return bool(nodes) and all(
        isinstance(node, pure_node_types)
        or (isinstance(node, CFunctionCall) and is_runtime_segment_load_helper_8616(node))
        for node in nodes
    )

__all__ = [
    "TerminalReturnStorageInput8616",
    "TerminalReturnValueEvidence8616",
    "materialize_unused_caller_void_codegen_type_8616",
    "materialize_unused_caller_void_return_type_8616",
    "proven_void_return_address_8616",
    "record_terminal_return_value_evidence_8616",
    "terminal_return_value_evidence_8616",
]


@dataclass(frozen=True, slots=True)
class TerminalReturnStorageInput8616:
    """Carry one terminal-storage classification already collected by Semantics."""

    storage: TerminalReturnStorage8616 | None


@dataclass(frozen=True, slots=True)
class TerminalReturnValueEvidence8616:
    """Closed accounting for AIL terminal returns after ReturnMaker."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    value_return_count: int
    empty_return_count: int
    failure_count: int

    @property
    def proves_no_terminal_value(self) -> bool:
        """Return whether every discovered terminal return is empty."""
        return (
            self.raw_fact_count > 0
            and self.normalized_fact_count == self.raw_fact_count
            and self.classified_fact_count == self.raw_fact_count
            and self.value_return_count == 0
            and self.empty_return_count == self.classified_fact_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class UnusedVoidReturnTypeStats8616:
    """Closed evidence counts for one void-contract materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class UnusedVoidReturnTypeResult8616:
    """Result of one void-contract materialization."""

    changed: bool
    stats: UnusedVoidReturnTypeStats8616


class _EvidenceOwner8616(Protocol):
    """Owned typed evidence registry carried by an angr project boundary."""

    _inertia_terminal_return_value_evidence_8616: dict[int, TerminalReturnValueEvidence8616]


class _VoidContractOwner8616(Protocol):
    """Typed project state carrying closed void-return contracts."""

    _inertia_proven_void_return_addresses_8616: frozenset[int]


class _ProjectSurface8616(Protocol):
    """Third-party project fields consumed by void return lowering."""

    arch: Arch
    kb: object



class _FunctionSurface8616(Protocol):
    """Third-party function fields consumed by void return lowering."""

    addr: int
    info: object
    prototype: object | None
    prototype_source: PrototypeSource


class _FunctionManagerSurface8616(Protocol):
    """Third-party function lookup boundary."""

    def function(self, *, addr: int, create: bool) -> _FunctionSurface8616 | None:
        """Return an existing function without creating one."""


class _KnowledgeBaseSurface8616(Protocol):
    """Third-party knowledge-base fields used by void return lowering."""

    functions: _FunctionManagerSurface8616


class _CFunctionSurface8616(Protocol):
    """Third-party generated C function fields updated by void lowering."""

    addr: int
    functy: object
    statements: object


class _CodegenSurface8616(Protocol):
    """Third-party codegen fields updated by void return lowering."""

    cfunc: _CFunctionSurface8616
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_force_codegen_regeneration_8616: bool


def record_terminal_return_value_evidence_8616(
    owner: object,
    function_addr: int,
    evidence: TerminalReturnValueEvidence8616,
) -> None:
    """Record immutable terminal-return evidence for final type lowering."""
    carrier = cast(_EvidenceOwner8616, owner)
    try:
        evidence_by_addr = dict(carrier._inertia_terminal_return_value_evidence_8616)
    except AttributeError:
        evidence_by_addr = {}
    evidence_by_addr[function_addr] = evidence
    carrier._inertia_terminal_return_value_evidence_8616 = evidence_by_addr


def terminal_return_value_evidence_8616(
    owner: object,
    function_addr: int,
) -> TerminalReturnValueEvidence8616 | None:
    """Return recorded terminal-return evidence for one exact function address."""
    carrier = cast(_EvidenceOwner8616, owner)
    try:
        evidence = carrier._inertia_terminal_return_value_evidence_8616.get(function_addr)
    except AttributeError:
        return None
    return evidence if isinstance(evidence, TerminalReturnValueEvidence8616) else None


def proven_void_return_address_8616(owner: object, function_addr: int) -> bool:
    """Return whether Types/lowering proved an empty result contract for an address."""
    carrier = cast(_VoidContractOwner8616, owner)
    try:
        return function_addr in carrier._inertia_proven_void_return_addresses_8616
    except AttributeError:
        return False


def _has_explicit_prototype_8616(function: _FunctionSurface8616) -> bool:
    """Return whether source/debug annotations own the function prototype."""
    if not isinstance(function.info, Mapping):
        return False
    annotations = function.info.get(ANNOTATION_KEY)
    return isinstance(annotations, Mapping) and isinstance(annotations.get("prototype"), SimTypeFunction)


def _demotion_boundary_8616(
    project_surface: _ProjectSurface8616,
    function_surface: _FunctionSurface8616,
    prototype: object,
    prototype_was_guessed: bool,
) -> bool:
    """Return whether ABI/prototype evidence permits return demotion."""
    return (
        project_surface.arch.name == "86_16"
        and not _has_explicit_prototype_8616(function_surface)
        and prototype_was_guessed
        and isinstance(prototype, SimTypeFunction)
    )


def materialize_unused_caller_void_return_type_8616(
    project: object,
    function: object,
    *,
    caller_observation: CallerReturnUseVerdict8616,
    prototype_was_guessed: bool,
    terminal_value_proven: bool,
) -> UnusedVoidReturnTypeResult8616:
    """Demote a generated scalar return when closed facts prove no result contract."""
    project_surface = cast(_ProjectSurface8616, project)
    function_surface = cast(_FunctionSurface8616, function)
    prototype = function_surface.prototype
    if not _demotion_boundary_8616(
        project_surface, function_surface, prototype, prototype_was_guessed
    ) or (
        caller_observation is not CallerReturnUseVerdict8616.UNUSED
        or terminal_value_proven
    ):
        return UnusedVoidReturnTypeResult8616(False, UnusedVoidReturnTypeStats8616())
    assert isinstance(prototype, SimTypeFunction)
    materialized = UnusedVoidReturnTypeStats8616(2, 2, 2, 1, 0)
    if isinstance(prototype.returnty, SimTypeBottom):
        return UnusedVoidReturnTypeResult8616(False, materialized)
    rebuilt = SimTypeFunction(
        list(prototype.args),
        SimTypeBottom(label="void").with_arch(project_surface.arch),
        arg_names=prototype.arg_names,
        variadic=prototype.variadic,
    ).with_arch(project_surface.arch)
    function_surface.prototype = rebuilt
    try:
        void_addresses = set(cast(_VoidContractOwner8616, project)._inertia_proven_void_return_addresses_8616)
    except AttributeError:
        void_addresses = set()
    void_addresses.add(function_surface.addr)
    cast(_VoidContractOwner8616, project)._inertia_proven_void_return_addresses_8616 = frozenset(void_addresses)
    # The return contract is closed independently. Keep argument inference open
    # until stack/interface lowering has finalized the function parameters.
    return UnusedVoidReturnTypeResult8616(True, materialized)


def materialize_unused_caller_void_codegen_type_8616(
    project: object,
    codegen: object,
    *,
    terminal_storage_input: TerminalReturnStorageInput8616 | None = None,
) -> UnusedVoidReturnTypeResult8616:
    """Replay a proven empty result contract on the final generated C surface.

    ``terminal_storage_input`` lets another Types/lowering consumer reuse the
    same Semantics classification instead of decoding the function twice.
    """
    project_surface = cast(_ProjectSurface8616, project)
    codegen_surface = cast(_CodegenSurface8616, codegen)
    try:
        cfunc = codegen_surface.cfunc
        evidence = terminal_return_value_evidence_8616(project, cfunc.addr)
        knowledge_base = cast(_KnowledgeBaseSurface8616, project_surface.kb)
        function = knowledge_base.functions.function(addr=cfunc.addr, create=False)
    except AttributeError:
        return UnusedVoidReturnTypeResult8616(
            False,
            UnusedVoidReturnTypeStats8616(failure_count=1),
        )
    terminal_value_empty = evidence is not None and evidence.proves_no_terminal_value
    terminal_storage = (
        None
        if function is None or terminal_value_empty
        else (
            terminal_storage_input.storage
            if terminal_storage_input is not None
            else terminal_return_storage_8616(project, function)
        )
    )
    caller_observation = proven_function_result_observation_8616(project, cfunc.addr)
    if (
        function is None
        or _has_explicit_prototype_8616(function)
        or (
            caller_observation is not CallerReturnUseVerdict8616.UNUSED
            and terminal_storage is not TerminalReturnStorage8616.NONE
        )
        or not isinstance(cfunc.functy, SimTypeFunction)
    ):
        return UnusedVoidReturnTypeResult8616(False, UnusedVoidReturnTypeStats8616())
    return_nodes = tuple(node for node in _iter_c_nodes_deep_8616(cfunc.statements) if isinstance(node, CReturn))
    prototype = cfunc.functy
    nonempty_returns = tuple(node for node in return_nodes if node.retval is not None)
    function_prototype_is_void = (
        isinstance(function.prototype, SimTypeFunction) and isinstance(function.prototype.returnty, SimTypeBottom)
    ) or proven_void_return_address_8616(project, cfunc.addr)
    pure_returns = bool(nonempty_returns) and all(
        _return_expr_is_side_effect_free_8616(node.retval) for node in nonempty_returns
    )
    synthetic_zero_returns = bool(nonempty_returns) and all(
        isinstance(node.retval, CConstant) and node.retval.value == 0
        for node in nonempty_returns
    )
    unresolved_returns = bool(nonempty_returns) and all(
        return_value_needs_neutralization_8616(node.retval, prototype.returnty)
        for node in nonempty_returns
    )
    terminal_register_empty = terminal_storage in {
        TerminalReturnStorage8616.NONE,
        TerminalReturnStorage8616.CALL_OUTPUT,
    }
    if (
        not terminal_value_empty
        and not terminal_register_empty
        and not unresolved_returns
        and not synthetic_zero_returns
        and not (function_prototype_is_void and pure_returns)
    ):
        return UnusedVoidReturnTypeResult8616(False, UnusedVoidReturnTypeStats8616())
    unsafe_returns = tuple(
        node
        for node in return_nodes
        if node.retval is not None
        and not (isinstance(node.retval, CConstant) and node.retval.value == 0)
        and not return_value_needs_neutralization_8616(node.retval, prototype.returnty)
        and not (
            (function_prototype_is_void or terminal_value_empty or terminal_register_empty)
            and _return_expr_is_side_effect_free_8616(node.retval)
        )
    )
    if unsafe_returns:
        raise PipelineHardError("proven empty result produced non-synthetic C return values")
    already_void = isinstance(prototype.returnty, SimTypeBottom)
    rebuilt = SimTypeFunction(
        list(prototype.args),
        SimTypeBottom(label="void").with_arch(project_surface.arch),
        arg_names=prototype.arg_names,
        variadic=prototype.variadic,
    ).with_arch(project_surface.arch)
    cfunc.functy = rebuilt
    function.prototype = rebuilt
    function.prototype_source = PrototypeSource.CCA_DECOMPILER
    changed_returns = 0
    for node in return_nodes:
        if node.retval is not None:
            node.retval = None
            changed_returns += 1
    changed = not already_void or changed_returns > 0
    if changed:
        codegen_surface._inertia_codegen_decl_refresh_required_8616 = True
        codegen_surface._inertia_force_codegen_regeneration_8616 = True
    fact_count = 2 + len(return_nodes) + int(terminal_storage is not None)
    return UnusedVoidReturnTypeResult8616(
        changed,
        UnusedVoidReturnTypeStats8616(fact_count, fact_count, fact_count, 1 + len(return_nodes), 0),
    )
