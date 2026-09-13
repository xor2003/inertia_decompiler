"""Check returned-call provenance in parsed fixture output.

Layer: Tooling/gates.
Responsibility: accept direct returns or unchanged local copies of a required
call result. Refuse control-flow joins, indirect writes and intervening calls
without claiming whole-program equivalence. Never rewrite generated C.
"""

from __future__ import annotations

from collections.abc import Sequence

from pycparser import c_ast

_MUTATING_UNARY_OPERATORS = frozenset({"p++", "p--", "++", "--", "&"})


def _required_call(node: c_ast.Node | None, name: str) -> bool:
    """Recognize a call to the exact source-contract function identifier."""
    return isinstance(node, c_ast.FuncCall) and isinstance(node.name, c_ast.ID) and node.name.name == name


def _pure_expression(node: c_ast.Node | None) -> bool:
    """Refuse expression writes, calls and address escapes in intervening code."""
    pending = [node] if node is not None else []
    while pending:
        current = pending.pop()
        if isinstance(current, (c_ast.Assignment, c_ast.FuncCall)):
            return False
        if isinstance(current, c_ast.UnaryOp) and current.op in _MUTATING_UNARY_OPERATORS:
            return False
        pending.extend(child for _name, child in current.children())
    return True


def _definition_rhs(node: c_ast.Node, name: str) -> tuple[bool, c_ast.Node | None]:
    """Find one direct definition, keeping compound overwrites unproven."""
    if isinstance(node, c_ast.Assignment) and isinstance(node.lvalue, c_ast.ID) and node.lvalue.name == name:
        return True, node.rvalue if node.op == "=" else None
    if isinstance(node, c_ast.Decl) and node.name == name:
        return True, node.init
    return False, None


def _transparent_statement(node: c_ast.Node) -> bool:
    """Allow only unrelated scalar writes, pure declarations and empty statements."""
    if isinstance(node, c_ast.Assignment):
        return isinstance(node.lvalue, c_ast.ID) and _pure_expression(node.rvalue)
    if isinstance(node, c_ast.Decl):
        return _pure_expression(node.init)
    return isinstance(node, c_ast.EmptyStatement)


def _has_call_origin(node: c_ast.Node | None, prefix: Sequence[c_ast.Node], name: str) -> bool:
    """Follow a local's last dominating straight-line definition back to the call."""
    if _required_call(node, name):
        return True
    if not isinstance(node, c_ast.ID):
        return False
    if not any(isinstance(statement, c_ast.Decl) and statement.name == node.name for statement in prefix):
        return False
    for index in range(len(prefix) - 1, -1, -1):
        statement = prefix[index]
        defines, rhs = _definition_rhs(statement, node.name)
        if defines:
            return _has_call_origin(rhs, prefix[:index], name)
        if not _transparent_statement(statement):
            return False
    return False


def has_returned_call_8616(function: c_ast.FuncDef, name: str) -> bool:
    """Check bounded return provenance without requiring literal return-call syntax."""
    pending: list[c_ast.Node] = [function.body]
    while pending:
        node = pending.pop()
        if isinstance(node, c_ast.Compound):
            statements = tuple(node.block_items or ())
            for index, statement in enumerate(statements):
                if isinstance(statement, c_ast.Return):
                    if _has_call_origin(statement.expr, statements[:index], name):
                        return True
                    break
                pending.append(statement)
        elif isinstance(node, c_ast.Return):
            if _required_call(node.expr, name):
                return True
        else:
            pending.extend(child for _field, child in node.children())
    return False
