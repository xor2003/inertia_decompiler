# cython: language_level=3, infer_types=True
"""Select register reload consumers within one instruction-owning statement.

Layer: Types/Lowering.
Responsibility: identify an existing register read in local expressions only.
A control statement's instruction tag cannot authorize reusing an SSA identity
from its body, another branch, or a later iteration. This does not infer storage
or remove effects; absent or ambiguous consumers refuse reconstruction.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_variable import SimRegisterVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

from .register_variable_identity import register_cvar_name_8616
import operator


@cython.ccall
def _local_expressions(statement: object) -> object:
    """Exclude child control regions and direct assignment definitions."""
    if isinstance(statement, c.CAssignment):
        return tuple((statement.rhs,)) if isinstance(statement.lhs, c.CVariable) else tuple((statement.lhs, statement.rhs))
    if isinstance(statement, (c.CForLoop, c.CWhileLoop, c.CDoWhileLoop, c.CIfBreak)):
        return (statement.condition,)
    if isinstance(statement, c.CIfElse):
        pairs = statement.condition_and_nodes
        return tuple((pairs[0][0],)) if len(pairs) == 1 else tuple(())
    if isinstance(statement, c.CSwitchCase):
        return (statement.switch,)
    if isinstance(statement, c.CExpressionStatement):
        return (statement.expr,)
    if isinstance(statement, c.CReturn):
        return (statement.retval,)
    return tuple((statement,)) if isinstance(statement, c.CExpression) else tuple(())


@cython.ccall
def instruction_local_register_read_8616(
    statement: object, register_name: object, register_width: cython.longlong,
) -> c.CVariable | None:
    """Return a unique existing identity, never a same-register body substitute."""
    selected: object
    expression: object
    node: object
    selected = None
    for expression in _local_expressions(statement):
        for node in _iter_c_nodes_deep_8616(expression):
            if not isinstance(node, c.CVariable) or not isinstance(node.variable, SimRegisterVariable):
                continue
            if operator.ne(node.variable.size, register_width) or operator.ne(register_cvar_name_8616(node), register_name):
                continue
            if selected is not None and (
                node.variable is not selected.variable or operator.ne(node.vvar_id, selected.vvar_id)
            ):
                return None
            selected = node
    return selected
