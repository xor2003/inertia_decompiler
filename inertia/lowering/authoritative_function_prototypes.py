"""Retain explicit function prototypes across angr inference replays.

Layer: Types/lowering.
Responsibility: snapshot a strong typed function interface before third-party
Clinic or later lowering rebuilds the mutable angr ``Function.prototype``.
Consumers may use the snapshot only when its argument census still matches.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not infer types from names, assembly, rendered C, COD, or source text here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction

from inertia.lowering.annotations import ANNOTATION_KEY


@dataclass(frozen=True, slots=True)
class AuthoritativeFunctionPrototype8616:
    """One explicit prototype and its original evidence precedence."""

    prototype: SimTypeFunction
    source: PrototypeSource


class _FunctionBoundary8616(Protocol):
    """Third-party angr fields used by the authoritative prototype owner."""

    addr: int
    prototype: object
    prototype_source: PrototypeSource
    info: Mapping[str, object]


class _ProjectBoundary8616(Protocol):
    """Third-party project extension carrying typed prototype snapshots."""

    _inertia_authoritative_function_prototypes_8616: dict[
        int,
        AuthoritativeFunctionPrototype8616,
    ]


class _CodegenFunctionBoundary8616(Protocol):
    """Third-party C-function fields used to publish a materialized interface."""

    addr: int
    functy: object


class _CodegenBoundary8616(Protocol):
    """Third-party codegen field carrying the materialized C function."""

    cfunc: _CodegenFunctionBoundary8616 | None


def _registry_8616(
    project: object,
) -> dict[int, AuthoritativeFunctionPrototype8616]:
    """Return the project-local typed snapshot registry."""
    boundary = cast(_ProjectBoundary8616, project)
    try:
        registry = boundary._inertia_authoritative_function_prototypes_8616
    except AttributeError:
        registry = {}
        boundary._inertia_authoritative_function_prototypes_8616 = registry
    return registry


def capture_authoritative_function_prototype_8616(
    project: object,
    function: object,
) -> AuthoritativeFunctionPrototype8616 | None:
    """Capture one explicit prototype, never an unowned CCA inference."""
    boundary = cast(_FunctionBoundary8616, function)
    prototype = boundary.prototype
    try:
        source = boundary.prototype_source
    except AttributeError:
        source = PrototypeSource.NONE
    registry = _registry_8616(project)
    existing = registry.get(boundary.addr)
    try:
        info = boundary.info
    except AttributeError:
        info = {}
    annotations = info.get(ANNOTATION_KEY)
    annotated_prototype = (
        annotations.get("prototype") if isinstance(annotations, Mapping) else None
    )
    has_typed_annotation = isinstance(annotated_prototype, SimTypeFunction)
    if has_typed_annotation:
        prototype = annotated_prototype
        source = PrototypeSource.USER
    elif isinstance(existing, AuthoritativeFunctionPrototype8616) and (
        not isinstance(prototype, SimTypeFunction) or source <= existing.source
    ):
        return existing
    if (
        not isinstance(prototype, SimTypeFunction)
        or source < PrototypeSource.SIMPROC
    ):
        return None
    if (
        isinstance(existing, AuthoritativeFunctionPrototype8616)
        and not has_typed_annotation
        and source <= existing.source
    ):
        return existing
    captured = AuthoritativeFunctionPrototype8616(
        cast(SimTypeFunction, prototype.copy()),
        source,
    )
    registry[boundary.addr] = captured
    return captured


def authoritative_function_prototype_8616(
    project: object,
    function: object | None,
    *,
    argument_count: int,
    minimum_source: PrototypeSource = PrototypeSource.CCA_DECOMPILER,
) -> SimTypeFunction | None:
    """Return a sufficiently strong snapshot when its argument census closes."""
    if function is None:
        return None
    boundary = cast(_FunctionBoundary8616, function)
    try:
        function_addr = boundary.addr
    except AttributeError:
        return None
    captured = _registry_8616(project).get(function_addr)
    if not isinstance(captured, AuthoritativeFunctionPrototype8616):
        captured = capture_authoritative_function_prototype_8616(project, function)
    if captured is None or captured.source < minimum_source:
        return None
    prototype = captured.prototype
    return prototype if len(tuple(prototype.args or ())) == argument_count else None


def publish_authoritative_function_prototype_8616(
    project: object,
    function_addr: int,
    prototype: SimTypeFunction,
    *,
    source: PrototypeSource,
) -> AuthoritativeFunctionPrototype8616:
    """Replace a snapshot after an owned typed contract is materialized."""
    registry = _registry_8616(project)
    existing = registry.get(function_addr)
    if isinstance(existing, AuthoritativeFunctionPrototype8616) and existing.source > source:
        return existing
    captured = AuthoritativeFunctionPrototype8616(
        cast(SimTypeFunction, prototype.copy()),
        source,
    )
    registry[function_addr] = captured
    return captured


def publish_codegen_function_prototype_8616(
    project: object,
    codegen: object,
    *,
    source: PrototypeSource = PrototypeSource.CCA_DECOMPILER,
) -> AuthoritativeFunctionPrototype8616 | None:
    """Publish the current typed codegen interface after owned materialization."""
    try:
        cfunc = cast(_CodegenBoundary8616, codegen).cfunc
        function_addr = cfunc.addr if cfunc is not None else None
        prototype = cfunc.functy if cfunc is not None else None
    except AttributeError:
        return None
    if not isinstance(function_addr, int) or not isinstance(prototype, SimTypeFunction):
        return None
    return publish_authoritative_function_prototype_8616(
        project,
        function_addr,
        prototype,
        source=source,
    )


__all__ = [
    "AuthoritativeFunctionPrototype8616",
    "authoritative_function_prototype_8616",
    "capture_authoritative_function_prototype_8616",
    "publish_authoritative_function_prototype_8616",
    "publish_codegen_function_prototype_8616",
]
