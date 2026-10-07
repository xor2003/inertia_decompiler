"""Layer: CLI/fallback/reporting.

Responsibility: join ABI-compatible external function declarations while
preserving their strongest evidence-backed return and parameter contracts.
Forbidden: inspecting generated function bodies or recovering semantics that
belong in X86_16 Types/Lowering.
"""

from __future__ import annotations

import copy
from collections.abc import Sequence

from pycparser import c_ast

_TypeContract = tuple[object, ...]


def _identifier_tokens(node: c_ast.Node) -> tuple[str, ...] | None:
    """Return identifier-type tokens beneath one declarator node."""
    current = node
    while isinstance(current, (c_ast.Decl, c_ast.Typename, c_ast.TypeDecl)):
        current = current.type
    if not isinstance(current, c_ast.IdentifierType):
        return None
    return tuple(current.names)


def _type_contract(node: c_ast.Node, *, parameter: bool = False) -> _TypeContract | None:
    """Return a structural type contract with parameter arrays decayed to pointers."""
    if isinstance(node, (c_ast.Decl, c_ast.Typename)):
        return _type_contract(node.type, parameter=parameter)
    if isinstance(node, c_ast.TypeDecl):
        nested = _type_contract(node.type, parameter=parameter)
        return None if nested is None else ("type", tuple(node.quals or ()), nested)
    if isinstance(node, c_ast.IdentifierType):
        return "identifier", tuple(node.names)
    if isinstance(node, c_ast.PtrDecl):
        nested = _type_contract(node.type)
        return None if nested is None else ("pointer", tuple(node.quals or ()), nested)
    if isinstance(node, c_ast.ArrayDecl):
        nested = _type_contract(node.type)
        if nested is None:
            return None
        if parameter:
            return "pointer", (), nested
        return "array", nested
    return _named_type_contract(node)


def _named_type_contract(node: c_ast.Node) -> _TypeContract | None:
    """Return the contract tag for named struct/union/enum types."""
    if isinstance(node, c_ast.Struct):
        return "struct", node.name
    if isinstance(node, c_ast.Union):
        return "union", node.name
    if isinstance(node, c_ast.Enum):
        return "enum", node.name
    return None


def _parameter_contracts(function_type: c_ast.FuncDecl) -> tuple[_TypeContract, ...] | None:
    """Return normalized prototype parameters, or None for K&R declarations."""
    if function_type.args is None:
        return None
    parameters = tuple(function_type.args.params or ())
    if len(parameters) == 1 and _identifier_tokens(parameters[0]) == ("void",):
        return ()
    contracts: list[_TypeContract] = []
    for parameter in parameters:
        if isinstance(parameter, c_ast.EllipsisParam):
            contracts.append(("ellipsis",))
            continue
        contract = _type_contract(parameter, parameter=True)
        if contract is None:
            return None
        contracts.append(contract)
    return tuple(contracts)


def _integer_return_contract(node: c_ast.Node) -> tuple[int, bool] | None:
    """Return target x86-16 integer width and unsignedness for one return type."""
    tokens = _identifier_tokens(node)
    if tokens is None:
        return None
    token_set = frozenset(tokens)
    if token_set in {
        frozenset({"int8_t"}),
        frozenset({"char"}),
        frozenset({"signed", "char"}),
    }:
        return 8, False
    if token_set in {frozenset({"uint8_t"}), frozenset({"unsigned", "char"})}:
        return 8, True
    if token_set in {
        frozenset({"int16_t"}),
        frozenset({"short"}),
        frozenset({"signed", "short"}),
        frozenset({"int"}),
        frozenset({"signed", "int"}),
    }:
        return 16, False
    if token_set in {
        frozenset({"uint16_t"}),
        frozenset({"unsigned", "short"}),
        frozenset({"unsigned", "int"}),
    }:
        return 16, True
    if token_set in {
        frozenset({"int32_t"}),
        frozenset({"long"}),
        frozenset({"signed", "long"}),
    }:
        return 32, False
    if token_set in {frozenset({"uint32_t"}), frozenset({"unsigned", "long"})}:
        return 32, True
    return None


def _return_declaration(declarations: Sequence[c_ast.Decl]) -> c_ast.Decl | None:
    """Select the strongest compatible return contract without claiming void."""
    exact_returns = tuple(_type_contract(declaration.type.type) for declaration in declarations)
    if len(set(exact_returns)) == 1:
        return declarations[0]

    return_capable = tuple(
        declaration
        for declaration in declarations
        if _identifier_tokens(declaration.type.type) != ("void",)
    )
    if not return_capable:
        return declarations[0]
    integer_returns = tuple(
        (declaration, _integer_return_contract(declaration.type.type))
        for declaration in return_capable
    )
    if any(contract is None for _declaration, contract in integer_returns):
        return None
    widest_bits = max(contract[0] for _declaration, contract in integer_returns if contract is not None)
    widest = tuple(
        (declaration, contract)
        for declaration, contract in integer_returns
        if contract is not None and contract[0] == widest_bits
    )
    if len({contract[1] for _declaration, contract in widest}) != 1:
        return None
    return widest[0][0]


def canonical_external_function_decl(nodes: Sequence[c_ast.Node]) -> c_ast.Decl | None:
    """Join compatible external declarations without consulting generated bodies."""
    declarations = tuple(
        node
        for node in nodes
        if isinstance(node, c_ast.Decl) and isinstance(node.type, c_ast.FuncDecl)
    )
    if len(declarations) != len(nodes):
        return None
    typed = tuple(
        (declaration, _parameter_contracts(declaration.type))
        for declaration in declarations
        if declaration.type.args is not None
    )
    if typed:
        parameter_contracts = {contracts for _declaration, contracts in typed}
        if None in parameter_contracts or len(parameter_contracts) != 1:
            return None

    return_declaration = _return_declaration(declarations)
    if return_declaration is None:
        return None
    if not typed:
        return return_declaration
    for declaration, _contracts in typed:
        if _type_contract(declaration.type.type) == _type_contract(return_declaration.type.type):
            return declaration
    canonical = copy.deepcopy(typed[0][0])
    canonical.type.type = copy.deepcopy(return_declaration.type.type)
    return canonical


__all__ = ["canonical_external_function_decl"]
