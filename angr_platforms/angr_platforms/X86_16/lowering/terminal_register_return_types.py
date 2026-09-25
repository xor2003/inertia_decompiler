"""Materialize a terminal AX word as a generated C return type.

Layer: Types/lowering.
Responsibility: refine a guessed byte C return type after storage recovery when
Semantics proves both AX byte lanes reach the binary return.
Forbidden: instruction parsing, source/COD/name evidence, or body rewriting.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CReturn
from angr.sim_type import SimType, SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeLong, SimTypeShort
from archinfo import Arch

from ..annotations import ANNOTATION_KEY
from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallerReturnUseVerdict8616
from ..semantics.terminal_return_storage import TerminalReturnStorage8616, terminal_return_storage_8616
from .caller_observed_byte_return_types import (
    CallerObservedByteReturnTypeResult8616,
    apply_caller_observed_byte_return_type_8616,
    materialize_caller_observed_byte_return_type_8616,
)
from .return_type_evidence import proven_function_result_observation_8616
from .unused_void_return_types import (
    TerminalReturnStorageInput8616,
    UnusedVoidReturnTypeResult8616,
    materialize_unused_caller_void_codegen_type_8616,
)

__all__ = [
    "TerminalRegisterReturnTypeResult8616",
    "apply_terminal_register_return_type_evidence_8616",
    "materialize_terminal_register_return_type_8616",
]

_LOGGER = logging.getLogger(__name__)


class _TypedReturnCodegenSurface8616(Protocol):
    """Structured codegen fields needed for preserved return-type evidence."""

    statements: object
    functy: object


def _typed_terminal_return_type_8616(cfunc: object) -> SimType | None:
    """Return one explicit scalar C return type when terminal lowering preserved it."""
    surface = cast(_TypedReturnCodegenSurface8616, cfunc)
    try:
        statements = surface.statements
    except AttributeError:
        statements = None
    if statements is None:
        return None
    candidates = tuple(
        node.retval.type
        for node in _iter_c_nodes_deep_8616(statements)
        if isinstance(node, CReturn)
        and node.retval is not None
        and isinstance(node.retval.type, (SimTypeChar, SimTypeInt, SimTypeLong, SimTypeShort))
    )
    if not candidates or any(candidate != candidates[0] for candidate in candidates[1:]):
        return None
    candidate = candidates[0]
    if isinstance(candidate, SimTypeChar):
        return candidate
    if isinstance(candidate, (SimTypeInt, SimTypeLong)) and candidate.size > 16:
        prototype = surface.functy
        if isinstance(prototype, SimTypeFunction) and any(
            isinstance(argument, (SimTypeInt, SimTypeLong)) and argument.size > 16
            for argument in prototype.args
        ):
            return candidate
    return None


class _ProjectSurface8616(Protocol):
    """Third-party project fields used by return type lowering."""

    arch: Arch
    kb: object


class _CodegenSurface8616(Protocol):
    """Third-party codegen fields used by return type lowering."""

    cfunc: object
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_force_codegen_regeneration_8616: bool
    _inertia_terminal_register_return_type_result_8616: TerminalRegisterReturnTypeResult8616


class _CFunctionSurface8616(Protocol):
    """angr CFunction fields updated by this lowering pass."""

    addr: int
    functy: object


class _FunctionSurface8616(Protocol):
    """Third-party function metadata and blocks consumed as evidence."""

    addr: int
    block_addrs_set: set[int]
    calling_convention: object | None
    info: object
    is_prototype_guessed: bool
    prototype: object | None


class _FunctionManagerSurface8616(Protocol):
    """Third-party function lookup boundary."""

    def function(self, *, addr: int, create: bool) -> _FunctionSurface8616 | None:
        """Return an existing function without creating one."""


class _KnowledgeBaseSurface8616(Protocol):
    """Third-party knowledge-base fields used by return type lowering."""

    functions: _FunctionManagerSurface8616


@dataclass(frozen=True, slots=True)
class TerminalRegisterReturnTypeStats8616:
    """Evidence accounting for one terminal register return type decision."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class TerminalRegisterReturnTypeResult8616:
    """Result of refining one generated function return type."""

    changed: bool
    stats: TerminalRegisterReturnTypeStats8616


def _has_explicit_prototype_8616(function: _FunctionSurface8616) -> bool:
    """Return whether source/debug annotations own the prototype."""
    if not isinstance(function.info, Mapping):
        return False
    annotations = function.info.get(ANNOTATION_KEY)
    return isinstance(annotations, Mapping) and isinstance(annotations.get("prototype"), SimTypeFunction)


def _refinable_generated_word_return_8616(type_: object) -> bool:
    """Return whether terminal AX width may refine one generated scalar header."""
    # Arch86_16 is VEX-wide, so generated SimTypes may not carry an arch and
    # SimTypeInt.size is not the target C ABI width. These classes are the
    # complete set of generated scalar headers that fit the 16-bit AX result.
    return isinstance(type_, (SimTypeChar, SimTypeInt, SimTypeShort))


def _terminal_result_from_byte_8616(
    byte_result: CallerObservedByteReturnTypeResult8616,
) -> TerminalRegisterReturnTypeResult8616:
    """Project byte evidence counters into the terminal-register result."""
    evidence = byte_result.evidence
    stats = evidence.stats if evidence is not None else None
    return TerminalRegisterReturnTypeResult8616(
        byte_result.changed,
        TerminalRegisterReturnTypeStats8616(
            raw_fact_count=stats.raw_fact_count if stats is not None else 0,
            normalized_fact_count=stats.normalized_fact_count if stats is not None else 0,
            classified_fact_count=stats.classified_fact_count if stats is not None else 0,
            materialized_count=stats.materialized_count if stats is not None else 0,
            failure_count=(
                stats.failure_count
                if stats is not None
                else int(byte_result.failure is not None)
            ),
        ),
    )


def apply_terminal_register_return_type_evidence_8616(
    project: object,
    function: object,
) -> TerminalRegisterReturnTypeResult8616:
    """Seed a word result from terminal AX and observed-caller evidence."""
    project_surface = cast(_ProjectSurface8616, project)
    function_surface = cast(_FunctionSurface8616, function)
    prototype = function_surface.prototype
    if os.environ.get("INERTIA_DEBUG_TERMINAL_RETURN_TYPES") == "1":
        _LOGGER.warning(
            "terminal AX seed candidate: prototype=%s return=%s explicit=%s guessed=%s",
            type(prototype).__name__,
            type(prototype.returnty).__name__ if isinstance(prototype, SimTypeFunction) else None,
            _has_explicit_prototype_8616(function_surface),
            function_surface.is_prototype_guessed,
        )
    explicit_prototype = _has_explicit_prototype_8616(function_surface)
    if (
        project_surface.arch.name != "86_16"
        or explicit_prototype
    ):
        return TerminalRegisterReturnTypeResult8616(False, TerminalRegisterReturnTypeStats8616())

    storage = terminal_return_storage_8616(project, function)
    byte_result = apply_caller_observed_byte_return_type_8616(
        project,
        function,
        storage,
        explicit_prototype=explicit_prototype,
    )
    if byte_result.applicable:
        return _terminal_result_from_byte_8616(byte_result)
    if prototype is not None and (
        not isinstance(prototype, SimTypeFunction)
        or not isinstance(prototype.returnty, SimTypeBottom)
    ):
        return TerminalRegisterReturnTypeResult8616(False, TerminalRegisterReturnTypeStats8616())
    caller_use = proven_function_result_observation_8616(
        project,
        function_surface.addr,
    )
    normalized_count = int(storage is not None)
    if (
        storage is not TerminalReturnStorage8616.AX
        or caller_use is CallerReturnUseVerdict8616.UNUSED
    ):
        return TerminalRegisterReturnTypeResult8616(
            False,
            TerminalRegisterReturnTypeStats8616(1, normalized_count, 0, 0, 0),
        )

    function_surface.prototype = SimTypeFunction(
        list(prototype.args) if isinstance(prototype, SimTypeFunction) else [],
        SimTypeShort(signed=False).with_arch(project_surface.arch),
        arg_names=prototype.arg_names if isinstance(prototype, SimTypeFunction) else None,
        variadic=prototype.variadic if isinstance(prototype, SimTypeFunction) else False,
    ).with_arch(project_surface.arch)
    function_surface.is_prototype_guessed = prototype is None
    return TerminalRegisterReturnTypeResult8616(
        True,
        TerminalRegisterReturnTypeStats8616(1, 1, 1, 1, 0),
    )


def _record_result_8616(
    codegen_surface: _CodegenSurface8616,
    result: TerminalRegisterReturnTypeResult8616,
) -> TerminalRegisterReturnTypeResult8616:
    """Retain the typed materialization result at the codegen boundary."""
    codegen_surface._inertia_terminal_register_return_type_result_8616 = result
    return result


def _debug_return_type_candidate_8616(
    cfunc: _CFunctionSurface8616,
    function: _FunctionSurface8616 | None,
    prototype: object,
) -> None:
    """Emit the opt-in terminal AX return-type candidate dump."""
    _LOGGER.warning(
        "terminal AX return type candidate: addr=%#x function=%s prototype=%s return=%s "
        "function_return=%s explicit=%s",
        cfunc.addr,
        function is not None,
        type(prototype).__name__,
        type(prototype.returnty).__name__ if isinstance(prototype, SimTypeFunction) else None,
        type(function.prototype.returnty).__name__
        if function is not None and isinstance(function.prototype, SimTypeFunction)
        else None,
        function is not None and _has_explicit_prototype_8616(function),
    )


def materialize_terminal_register_return_type_8616(
    project: object,
    codegen: object,
) -> TerminalRegisterReturnTypeResult8616:
    """Replace a guessed byte header with an unsigned word from AX evidence."""
    project_surface = cast(_ProjectSurface8616, project)
    codegen_surface = cast(_CodegenSurface8616, codegen)
    try:
        cfunc = cast(_CFunctionSurface8616, codegen_surface.cfunc)
        knowledge_base = cast(_KnowledgeBaseSurface8616, project_surface.kb)
        function = knowledge_base.functions.function(addr=cfunc.addr, create=False)
    except AttributeError:
        if os.environ.get("INERTIA_DEBUG_TERMINAL_RETURN_TYPES") == "1":
            _LOGGER.warning("terminal AX return type unavailable: missing codegen or function-manager surface")
        return _record_result_8616(
            codegen_surface,
            TerminalRegisterReturnTypeResult8616(False, TerminalRegisterReturnTypeStats8616(failure_count=1)),
        )
    prototype = cfunc.functy
    if os.environ.get("INERTIA_DEBUG_TERMINAL_RETURN_TYPES") == "1":
        _debug_return_type_candidate_8616(cfunc, function, prototype)
    if (
        function is None
        or _has_explicit_prototype_8616(function)
        or not isinstance(prototype, SimTypeFunction)
    ):
        return _record_result_8616(
            codegen_surface,
            TerminalRegisterReturnTypeResult8616(False, TerminalRegisterReturnTypeStats8616()),
        )
    storage = terminal_return_storage_8616(project, function)
    void_result = materialize_unused_caller_void_codegen_type_8616(
        project,
        codegen,
        terminal_storage_input=TerminalReturnStorageInput8616(storage),
    )
    delegated = _delegated_void_result_8616(void_result)
    if delegated is not None:
        return _record_result_8616(codegen_surface, delegated)
    if not _refinement_permitted_8616(project, cfunc, prototype):
        return _record_result_8616(
            codegen_surface,
            TerminalRegisterReturnTypeResult8616(False, TerminalRegisterReturnTypeStats8616()),
        )
    if os.environ.get("INERTIA_DEBUG_TERMINAL_RETURN_TYPES") == "1":
        _LOGGER.warning("terminal return storage: addr=%#x storage=%s", cfunc.addr, storage)
    byte_result = materialize_caller_observed_byte_return_type_8616(
        project,
        codegen,
        function,
        storage,
        explicit_prototype=False,
    )
    if byte_result.applicable:
        return _record_result_8616(
            codegen_surface,
            _terminal_result_from_byte_8616(byte_result),
        )
    if storage is not TerminalReturnStorage8616.AX:
        return _record_result_8616(
            codegen_surface,
            TerminalRegisterReturnTypeResult8616(
                False, TerminalRegisterReturnTypeStats8616(1, int(storage is not None), 0, 0, 0)
            ),
        )
    return _record_result_8616(
        codegen_surface,
        _apply_ax_terminal_type_8616(project_surface, codegen_surface, cfunc, prototype),
    )


def _refinement_permitted_8616(
    project: object,
    cfunc: _CFunctionSurface8616,
    prototype: SimTypeFunction,
) -> bool:
    """Return whether the generated scalar return may be refined."""
    return _refinable_generated_word_return_8616(
        prototype.returnty
    ) and proven_function_result_observation_8616(
        project, cfunc.addr
    ) is not CallerReturnUseVerdict8616.UNUSED


def _delegated_void_result_8616(
    void_result: UnusedVoidReturnTypeResult8616,
) -> TerminalRegisterReturnTypeResult8616 | None:
    """Forward caller-observed void demotion when it classified facts."""
    stats = void_result.stats
    if not stats.classified_fact_count:
        return None
    return TerminalRegisterReturnTypeResult8616(
        void_result.changed,
        TerminalRegisterReturnTypeStats8616(
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ),
    )


def _apply_ax_terminal_type_8616(
    project_surface: _ProjectSurface8616,
    codegen_surface: _CodegenSurface8616,
    cfunc: _CFunctionSurface8616,
    prototype: SimTypeFunction,
) -> TerminalRegisterReturnTypeResult8616:
    """Rewrite a guessed scalar header to the proven AX word type."""
    terminal_type = _typed_terminal_return_type_8616(cfunc) or SimTypeShort(signed=False).with_arch(project_surface.arch)
    if prototype.returnty == terminal_type:
        return TerminalRegisterReturnTypeResult8616(
            False,
            TerminalRegisterReturnTypeStats8616(1, 1, 1, 1, 0),
        )
    if not isinstance(prototype, SimTypeFunction):
        return TerminalRegisterReturnTypeResult8616(False, TerminalRegisterReturnTypeStats8616())
    cfunc.functy = SimTypeFunction(
        list(prototype.args),
        terminal_type.with_arch(project_surface.arch),
        arg_names=prototype.arg_names,
        variadic=prototype.variadic,
    ).with_arch(project_surface.arch)
    codegen_surface._inertia_codegen_decl_refresh_required_8616 = True
    codegen_surface._inertia_force_codegen_regeneration_8616 = True
    return TerminalRegisterReturnTypeResult8616(
        True, TerminalRegisterReturnTypeStats8616(1, 1, 1, 1, 0)
    )
