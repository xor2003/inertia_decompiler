"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.

Export subresponsibility: canonicalize top-level declarations, join
ABI-compatible external prototypes, and use generated definitions as internal
contracts without changing any function-body AST.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from angr_platforms.X86_16.lowering.gp_word_runtime import coherent_gp_runtime_header_8616
from pycparser import c_ast, c_generator, c_parser

from inertia_decompiler.generated_external_function_contracts import (
    canonical_external_function_decl,
)

_PARSE_PREFIX: str = (
    "typedef _Bool bool;\n"
    "typedef signed char int8_t;\n"
    "typedef unsigned char uint8_t;\n"
    "typedef signed short int16_t;\n"
    "typedef unsigned short uint16_t;\n"
    "typedef signed long int32_t;\n"
    "typedef unsigned long uint32_t;\n"
    "typedef long clock_t;\n"
    "typedef long time_t;\n"
)
_PARSE_PREFIX_NODE_COUNT: int = 9
_RUNTIME_HEADER_SOURCE: str = "inertia_owned_gp_runtime.h"


class DeclarationContractKind(StrEnum):
    """Typed top-level declaration families used by export assembly."""

    TYPE = "type"
    GLOBAL = "global"
    EXTERNAL_FUNCTION = "external-function"


@dataclass(frozen=True, slots=True)
class DeclarationContractConflict:
    """One named declaration for which generated payloads disagree."""

    kind: DeclarationContractKind
    name: str
    variants: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GeneratedTranslationUnit:
    """Canonical syntax plus declarations that require an owning-layer fix."""

    source: str
    function_count: int
    conflicts: tuple[DeclarationContractConflict, ...]


@dataclass(slots=True)
class _NamedDeclarationSet:
    """Mutable first-seen declaration state used only during assembly."""

    kind: DeclarationContractKind
    name: str
    nodes: list[c_ast.Node]
    variants: list[str]


def _preprocess_payload(payload: str, *, compiler: str) -> str:
    """Parse macros while retaining provenance of the exact owned ABI header.

    Its declarations are checked with all other contracts, but must be exported
    through the portable header rather than frozen to the host compiler's ABI.
    This recognizes only the authoritative generated header, not arbitrary C.
    """
    header = coherent_gp_runtime_header_8616()
    marked_header = (
        f'#line 1 "{_RUNTIME_HEADER_SOURCE}"\n'
        + header
        + '#line 1 "inertia_generated_payload.c"\n'
    )
    payload = payload.replace(header, marked_header)
    completed = subprocess.run(
        [compiler, "-E", "-x", "c", "-"],
        input=f"{_PARSE_PREFIX}{payload}",
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(f"generated C preprocessing failed: {completed.stderr.strip()}")
    return completed.stdout


def _parse_payload(payload: str, *, compiler: str) -> tuple[c_ast.Node, ...]:
    """Parse one independently validated C payload into top-level syntax nodes."""
    preprocessed = _preprocess_payload(payload, compiler=compiler)
    try:
        parsed = c_parser.CParser().parse(preprocessed)
    except c_parser.ParseError as ex:
        raise ValueError(f"generated C parser rejected validated payload: {ex}") from ex
    return tuple(parsed.ext[_PARSE_PREFIX_NODE_COUNT:])


def _declaration_identity(
    node: c_ast.Node,
    generator: c_generator.CGenerator,
) -> tuple[str, str] | None:
    """Return a stable syntax identity for one non-definition declaration."""
    rendered = generator.visit(node)
    if isinstance(node, c_ast.Typedef):
        return node.name, rendered
    if isinstance(node, c_ast.Decl):
        if node.name is not None:
            return node.name, rendered
        if isinstance(node.type, (c_ast.Struct, c_ast.Union, c_ast.Enum)) and node.type.name is not None:
            return node.type.name, rendered
        return rendered, rendered
    return None


def _declaration_kind(node: c_ast.Node) -> DeclarationContractKind:
    """Classify a parsed top-level declaration without semantic inference."""
    if isinstance(node, c_ast.Typedef) or (
        isinstance(node, c_ast.Decl)
        and isinstance(node.type, (c_ast.Struct, c_ast.Union, c_ast.Enum))
    ):
        return DeclarationContractKind.TYPE
    if isinstance(node, c_ast.Decl) and isinstance(node.type, c_ast.FuncDecl):
        return DeclarationContractKind.EXTERNAL_FUNCTION
    return DeclarationContractKind.GLOBAL


def _is_redundant_aggregate_forward_decl(node: c_ast.Node) -> bool:
    """Return whether a node is only ``struct/union/enum Name;``."""
    return (
        isinstance(node, c_ast.Decl)
        and node.name is None
        and isinstance(node.type, (c_ast.Struct, c_ast.Union, c_ast.Enum))
        and (
            node.type.values is None
            if isinstance(node.type, c_ast.Enum)
            else node.type.decls is None
        )
    )


def _collect_declaration_sets(
    parsed_payloads: tuple[tuple[c_ast.Node, ...], ...],
    definition_names: set[str],
    generator: c_generator.CGenerator,
) -> tuple[list[_NamedDeclarationSet], set[tuple[DeclarationContractKind, str]]]:
    """Group top-level declarations by contract kind and name, preserving order."""
    declaration_order: list[_NamedDeclarationSet] = []
    declarations_by_key: dict[tuple[DeclarationContractKind, str], _NamedDeclarationSet] = {}
    runtime_keys: set[tuple[DeclarationContractKind, str]] = set()
    for payload_nodes in parsed_payloads:
        for node in payload_nodes:
            if isinstance(node, c_ast.FuncDef):
                continue
            if isinstance(node, c_ast.Decl) and isinstance(node.type, c_ast.FuncDecl):  # noqa: SIM102
                if node.name in definition_names:
                    continue
            identity = _declaration_identity(node, generator)
            if identity is None:
                raise ValueError(f"unsupported generated top-level node: {type(node).__name__}")
            name, rendered = identity
            kind = _declaration_kind(node)
            key = kind, name
            if node.coord is not None and node.coord.file == _RUNTIME_HEADER_SOURCE:
                runtime_keys.add(key)
            declaration_set = declarations_by_key.get(key)
            if declaration_set is None:
                declaration_set = _NamedDeclarationSet(kind=kind, name=name, nodes=[], variants=[])
                declarations_by_key[key] = declaration_set
                declaration_order.append(declaration_set)
            if rendered not in declaration_set.variants:
                declaration_set.nodes.append(node)
                declaration_set.variants.append(rendered)
    return declaration_order, runtime_keys


def _canonicalize_declaration_sets(
    declaration_order: list[_NamedDeclarationSet],
    generator: c_generator.CGenerator,
) -> None:
    """Collapse redundant aggregates and join compatible external declarations."""
    for declaration_set in declaration_order:
        if declaration_set.kind is DeclarationContractKind.TYPE:
            type_definitions = tuple(
                node
                for node in declaration_set.nodes
                if not _is_redundant_aggregate_forward_decl(node)
            )
            if len(type_definitions) == 1 and all(
                node is type_definitions[0] or _is_redundant_aggregate_forward_decl(node)
                for node in declaration_set.nodes
            ):
                declaration_set.nodes = [type_definitions[0]]
                declaration_set.variants = [generator.visit(type_definitions[0])]
            continue
        if declaration_set.kind is not DeclarationContractKind.EXTERNAL_FUNCTION:
            continue
        canonical = canonical_external_function_decl(declaration_set.nodes)
        if canonical is None:
            continue
        declaration_set.nodes = [canonical]
        declaration_set.variants = [generator.visit(canonical)]


def assemble_generated_translation_unit(
    payloads: Sequence[str],
    *,
    compiler: str = "gcc",
) -> GeneratedTranslationUnit:
    """Build one declaration table and preserve every parsed function-body AST."""
    parsed_payloads = tuple(_parse_payload(payload, compiler=compiler) for payload in payloads)
    definitions = tuple(
        node
        for payload_nodes in parsed_payloads
        for node in payload_nodes
        if isinstance(node, c_ast.FuncDef)
    )
    definition_names = {definition.decl.name for definition in definitions}
    if len(definition_names) != len(definitions):
        raise ValueError("generated C contains duplicate function definitions")

    generator = c_generator.CGenerator()
    declaration_order, runtime_keys = _collect_declaration_sets(parsed_payloads, definition_names, generator)
    _canonicalize_declaration_sets(declaration_order, generator)

    conflicts = tuple(
        DeclarationContractConflict(item.kind, item.name, tuple(item.variants))
        for item in declaration_order
        if len(item.variants) > 1
    )
    declaration_nodes = [
        node
        for kind in (
            DeclarationContractKind.TYPE,
            DeclarationContractKind.GLOBAL,
            DeclarationContractKind.EXTERNAL_FUNCTION,
        )
        for item in declaration_order
        if item.kind is kind and (item.kind, item.name) not in runtime_keys
        for node in item.nodes
    ]
    internal_prototypes = [definition.decl for definition in definitions]
    merged = c_ast.FileAST([*declaration_nodes, *internal_prototypes, *definitions])
    return GeneratedTranslationUnit(
        source=(coherent_gp_runtime_header_8616() if runtime_keys else "")
        + generator.visit(merged).rstrip() + "\n",
        function_count=len(definitions),
        conflicts=conflicts,
    )


__all__ = [
    "DeclarationContractConflict",
    "DeclarationContractKind",
    "GeneratedTranslationUnit",
    "assemble_generated_translation_unit",
]
