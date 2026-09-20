"""Consume an existing word-local binding for a proven terminal GP reload.

Layer: Types/Lowering.
Responsibility: reconcile Alias storage and Semantics return-flow evidence
with an already initialized C local, without inventing a PUSH/POP snapshot.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not rewrite expressions or infer values from source names.
"""

from __future__ import annotations

from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeNum

from ..alias.segment_stack_restore import SegmentStackRestoreFact8616, SegmentStackRestoreVerdict8616
from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir import IRFunctionArtifact
from ..semantics.register_definition_return import RegisterReturnPath8616, unchanged_register_return_path_8616
from .codegen_return_origin import return_value_origin_8616
from .gp_stack_local_reload import _exact_local, _stores_for_local
from .gp_stack_restore_identity import _entry_sp_byte_offset_8616, _unconditional_sequence_8616, _unique_byte_save_8616
from .segment_access_policy import instruction_addrs_from_node_8616

_WORD_BYTES = 2
_WORD_BITS = 16


class _ReturnProjectionOwner8616(Enum):
    """Machine-proven owner of one structured return projection."""

    SAVED_VALUE = "saved_value"
    OTHER_DEFINITION = "other_definition"
    UNKNOWN = "unknown"


class _FunctionSurface8616(Protocol):
    """Third-party structured function prototype boundary."""

    functy: object
    statements: object


class _CodegenSurface8616(Protocol):
    """Owned IR evidence and third-party function fields used for binding."""

    _inertia_vex_ir_artifact: object
    cfunc: _FunctionSurface8616


def _proven_return_path(codegen: object, fact: SegmentStackRestoreFact8616) -> RegisterReturnPath8616 | None:
    """Join the owned machine-value proof with the current word return type."""
    surface = cast(_CodegenSurface8616, codegen)
    try:
        artifact = surface._inertia_vex_ir_artifact
        prototype = surface.cfunc.functy
    except AttributeError:
        return None
    if not isinstance(artifact, IRFunctionArtifact) or fact.restore_register != "ax":
        return None
    if not isinstance(prototype, SimTypeFunction) or not isinstance(prototype.returnty, (SimTypeInt, SimTypeNum)):
        return None
    if prototype.returnty.size != _WORD_BITS:
        return None
    return unchanged_register_return_path_8616(artifact, fact.restore_instruction_addr, "ax")


def _projection_owner(
    artifact: IRFunctionArtifact, statement: structured_c.CReturn, expected: RegisterReturnPath8616,
) -> _ReturnProjectionOwner8616:
    """Join per-use origin to machine flow without guessing another path's owner."""
    origin = return_value_origin_8616(statement)
    if origin is None:
        # Preserve the existing same-block proof, where every matching return
        # must use the saved local. Cross-block projections require provenance.
        return (_ReturnProjectionOwner8616.SAVED_VALUE if len(expected.block_addrs) == 1
                else _ReturnProjectionOwner8616.UNKNOWN)
    if origin.width_bits != _WORD_BITS:
        return _ReturnProjectionOwner8616.UNKNOWN
    actual = unchanged_register_return_path_8616(artifact, origin.instruction_addr, expected.register)
    if actual is None or actual.return_addr != expected.return_addr or actual.block_addrs[0] != origin.block_addr:
        return _ReturnProjectionOwner8616.UNKNOWN
    if actual.definition_addr == expected.definition_addr:
        return _ReturnProjectionOwner8616.SAVED_VALUE
    return _ReturnProjectionOwner8616.OTHER_DEFINITION


def _initialized_binding(
    codegen: object, containers: tuple[structured_c.CStatements, ...],
    prefix: list[object], operand: object, fact: SegmentStackRestoreFact8616,
) -> bool:
    """Require the exact uniquely written local in one unconditional sequence."""
    if not isinstance(operand, structured_c.CVariable) or operand.variable.size != _WORD_BYTES:
        return False
    offset = _entry_sp_byte_offset_8616(codegen, operand)
    if offset is None or fact.stack_offsets != (offset, offset + 1):
        return False
    save = _unique_byte_save_8616(containers, operand)
    if save is None or fact.saved_instruction_addr not in instruction_addrs_from_node_8616(save):
        return False
    if not any(candidate is save for candidate in prefix):
        return False
    unconditional = all(isinstance(candidate, structured_c.CAssignment) for candidate in prefix)
    no_calls = not any(isinstance(node, structured_c.CFunctionCall)
                       for statement in prefix for node in _iter_c_nodes_deep_8616(statement))
    return unconditional and no_calls


def _return_prefixes(
    root: object, target: structured_c.CReturn, prefix: tuple[object, ...] = (),
) -> list[tuple[object, ...]]:
    """Collect unconditional ancestors of a return, entering only lists and ifs."""
    if root is target:
        return [prefix]
    prefixes: list[tuple[object, ...]] = []
    if isinstance(root, structured_c.CStatements):
        for statement in _unconditional_sequence_8616(root):
            prefixes.extend(_return_prefixes(statement, target, prefix))
            prefix = (*prefix, statement)
    elif isinstance(root, structured_c.CIfElse):
        for _condition, branch in root.condition_and_nodes:
            prefixes.extend(_return_prefixes(branch, target, prefix))
        prefixes.extend(_return_prefixes(root.else_node, target, prefix))
    return prefixes


def _initialized_byte_binding(
    codegen: object, containers: tuple[structured_c.CStatements, ...],
    returned: structured_c.CReturn, fact: SegmentStackRestoreFact8616,
) -> bool:
    """Require complete nonescaping local stores before this conditional return.

    Unique storage writers and no address escape let unrelated calls occur
    after initialization. They do not authorize a call to mutate this C local.
    Gotos, opaque effects, loops containing the return and shared AST return
    objects refuse rather than guessing their dominance.
    """
    local = returned.retval
    if not _exact_local(codegen, local, fact):
        return False
    assert isinstance(local, structured_c.CVariable)
    root = cast(_CodegenSurface8616, codegen).cfunc.statements
    if any(isinstance(node, (structured_c.CGoto, structured_c.CDirtyExpression, structured_c.CMultiStatementExpression))
           for node in _iter_c_nodes_deep_8616(root)):
        return False
    stores = _stores_for_local(codegen, containers, local, fact)
    if not stores:
        return False
    prefixes = _return_prefixes(root, returned)
    if len(prefixes) != 1:
        return False
    prefix = prefixes[0]
    if any(isinstance(statement, structured_c.CReturn) for statement in prefix):
        return False
    indices = [index for index, statement in enumerate(prefix)
               if any(statement is store for store in stores)]
    return len(indices) == len(stores) and indices[-1] - indices[0] + 1 == len(stores)


def has_materialized_gp_local_return_8616(
    codegen: object, containers: tuple[structured_c.CStatements, ...],
    fact: SegmentStackRestoreFact8616,
) -> bool:
    """Require every projection of this saved value to use its initialized local.

    Other proven definitions at a shared return remain independent validation
    obligations. Unknown origins refuse; tags alone never prove value flow.
    Local initialization requires an unconditional dominating store sequence.
    """
    if fact.verdict is not SegmentStackRestoreVerdict8616.PROVEN:
        return False
    path = _proven_return_path(codegen, fact)
    if path is None:
        return False
    artifact = cast(_CodegenSurface8616, codegen)._inertia_vex_ir_artifact
    assert isinstance(artifact, IRFunctionArtifact)
    matched = False
    for container in containers:
        for return_index, statement in enumerate(container.statements):
            if not isinstance(statement, structured_c.CReturn):
                continue
            if path.return_addr not in instruction_addrs_from_node_8616(statement):
                continue
            owner = _projection_owner(artifact, statement, path)
            if owner is _ReturnProjectionOwner8616.OTHER_DEFINITION:
                continue
            if owner is _ReturnProjectionOwner8616.UNKNOWN:
                return False
            immediate_binding = _initialized_binding(
                codegen, containers, container.statements[:return_index], statement.retval, fact,
            )
            if not immediate_binding and not _initialized_byte_binding(codegen, containers, statement, fact):
                return False
            matched = True
    return matched
