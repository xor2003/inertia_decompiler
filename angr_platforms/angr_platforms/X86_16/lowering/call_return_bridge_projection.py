"""Recognize the existing call-carrier and word-local copy projection.

Layer: Types/Lowering.
Responsibility: expose both assignments of an unchanged adjacent bridge to
callsite replay consumers. This neither discovers calls nor repairs arguments
or placement. Consumers must still match their authoritative callsite fact.
"""

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimTemporaryVariable


def word_call_bridge_projection_8616(node: object) -> tuple[c.CAssignment, c.CAssignment] | None:
    """Return an exact unsigned word call definition and its immediate copy."""
    if not isinstance(node, c.CStatements) or len(node.statements) != 2:
        return None
    producer, store = node.statements
    if not isinstance(producer, c.CAssignment) or not isinstance(store, c.CAssignment):
        return None
    if not isinstance(producer.rhs, c.CFunctionCall):
        return None
    source, destination, copied = producer.lhs, store.lhs, store.rhs
    if not all(isinstance(value, c.CVariable) for value in (source, destination, copied)):
        return None
    if not isinstance(source.variable, (SimTemporaryVariable, SimRegisterVariable)):
        return None
    if not isinstance(destination.variable, SimStackVariable) or copied.variable != source.variable:
        return None
    exact_words = all(
        value.variable.size == 2 and isinstance(value.variable_type, SimTypeShort)
        and value.variable_type.signed is False for value in (source, destination, copied)
    )
    return (producer, store) if exact_words else None
