"""Consume an existing word-local binding for a proven terminal GP reload.

Layer: Types/Lowering.
Responsibility: reconcile Alias storage and Semantics return-flow evidence
with an already initialized C local, without inventing a PUSH/POP snapshot.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not rewrite expressions or infer values from source names.
"""

from __future__ import annotations

from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeNum

from ..alias.segment_stack_restore import SegmentStackRestoreFact8616
from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir import IRFunctionArtifact
from ..semantics.register_definition_return import unchanged_register_return_site_8616
from .gp_stack_restore_identity import _entry_sp_byte_offset_8616, _unique_byte_save_8616
from .segment_access_policy import instruction_addrs_from_node_8616

_WORD_BYTES = 2
_WORD_BITS = 16


class _FunctionSurface8616(Protocol):
    """Third-party structured function prototype boundary."""

    functy: object


class _CodegenSurface8616(Protocol):
    """Owned IR evidence and third-party function fields used for binding."""

    _inertia_vex_ir_artifact: object
    cfunc: _FunctionSurface8616


def _proven_return_site(codegen: object, fact: SegmentStackRestoreFact8616) -> int | None:
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
    return unchanged_register_return_site_8616(artifact, fact.restore_instruction_addr, "ax")


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


def has_materialized_gp_local_return_8616(
    codegen: object, containers: tuple[structured_c.CStatements, ...],
    fact: SegmentStackRestoreFact8616,
) -> bool:
    """Require every projection of the proven return to use its initialized local.

    Only an unconditional statement sequence is accepted. Other projections
    remain obligations of the normal materializer and semantic validation.
    """
    return_site = _proven_return_site(codegen, fact)
    if return_site is None:
        return False
    matched = False
    for container in containers:
        for return_index, statement in enumerate(container.statements):
            if not isinstance(statement, structured_c.CReturn):
                continue
            if return_site not in instruction_addrs_from_node_8616(statement):
                continue
            if not _initialized_binding(codegen, containers, container.statements[:return_index], statement.retval, fact):
                return False
            matched = True
    return matched
