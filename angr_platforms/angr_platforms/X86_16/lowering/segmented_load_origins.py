"""Project exact IR byte-load origins using retained C address operands.

Layer: Types/Lowering.
Responsibility: consume proven segmented IR addresses and exact VEX statement
origins to materialize surviving integer dereferences without rereading registers.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..ir.core import (
    SEGMENTED_LOAD_ADDRESS_TAG_8616,
    AddressStatus,
    IRAddress,
    IRBlock,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from ..ir.function_ir_registry import FunctionIRArtifactVerdict8616, registered_function_ir_artifact_8616
from ..ir.instruction_origin import IRInstructionOrigin8616
from ..structured_tags import copy_structured_tags_8616

type LoadKey8616 = tuple[int, int]


class _Function8616(Protocol):
    """Structured function identity and body at the third-party boundary."""

    addr: int
    statements: object


class _Codegen8616(Protocol):
    """Codegen fields required for an exact registered-IR query."""

    project: object
    cfunc: _Function8616 | None


@dataclass(frozen=True, slots=True)
class _LoadProjection8616:
    """One byte load with proven address and segment-scale statement owners."""

    key: LoadKey8616
    address: IRAddress
    root: IRInstructionOrigin8616
    scale: IRInstructionOrigin8616
    scale_side: int


def _definitions_8616(block: IRBlock) -> dict[int, IRInstr]:
    """Index unambiguous source temporaries; duplicate definitions refuse the block."""
    definitions: dict[int, IRInstr] = {}
    for instruction in block.instrs:
        destination = instruction.dst
        if destination is None or destination.space is not MemSpace.TMP or destination.source_tmp is None:
            continue
        if destination.source_tmp in definitions:
            return {}
        definitions[destination.source_tmp] = instruction
    return definitions


def _segment_scale_8616(instruction: IRInstr, space: MemSpace) -> bool:
    """Require the typed zero-extended segment selector shifted by four bits."""
    if instruction.op != "Iop_Shl32" or len(instruction.args) != 2:
        return False
    selector, shift = instruction.args
    if not isinstance(selector, IRValue) or not isinstance(shift, IRValue):
        return False
    exact_selector = (
        selector.space is MemSpace.REG and selector.name == space.value
        and selector.size == 4 and selector.offset == 0 and selector.expr == ("Iop_16Uto32",)
    )
    return exact_selector and shift.space is MemSpace.CONST and shift.const == 4


def _projection_8616(load: IRInstr, definitions: dict[int, IRInstr]) -> _LoadProjection8616 | None:
    """Select only a proven 16-bit segmented byte load with exact source owners."""
    if load.op != "LOAD" or len(load.args) != 1 or load.origin is None:
        return None
    address = load.args[0]
    if not isinstance(address, IRAddress) or address.size != 1:
        return None
    stable_data = (
        address.space in {MemSpace.DS, MemSpace.ES}
        and address.status is AddressStatus.STABLE and address.segment_origin is SegmentOrigin.PROVEN
    )
    if not stable_data or load.dst is None or load.dst.source_tmp is None or load.addr is None:
        return None
    root = definitions.get(load.origin.address_tmp) if load.origin.address_tmp is not None else None
    if root is None or root.origin is None or root.op != "Iop_Add32" or len(root.args) != 2:
        return None
    for side in (0, 1):
        scaled, offset = root.args[side], root.args[1 - side]
        if not isinstance(scaled, IRValue) or scaled.source_tmp is None or not isinstance(offset, IRValue):
            continue
        scale = definitions.get(scaled.source_tmp)
        if scale is None or scale.origin is None or not _segment_scale_8616(scale, address.space):
            continue
        offset_is_word = offset.size == 4 and offset.expr == ("Iop_16Uto32",)
        same_source = (
            scale.origin.block_addr == root.origin.block_addr == load.origin.block_addr
            and scale.addr == root.addr == load.addr
            and scale.origin.statement_index < root.origin.statement_index < load.origin.statement_index
        )
        if offset_is_word and same_source:
            return _LoadProjection8616((load.dst.source_tmp, load.addr), address, root.origin, scale.origin, side)
    return None


def _node_origin_8616(node: structured_c.CBinaryOp) -> tuple[int, int, int] | None:
    """Read exact address-expression tags, never descendant or nearby tags."""
    tags = copy_structured_tags_8616(node.tags)
    if tags is None:
        return None
    block, statement, instruction = tags.get("vex_block_addr"), tags.get("vex_stmt_idx"), tags.get("ins_addr")
    if isinstance(block, int) and isinstance(statement, int) and isinstance(instruction, int):
        return block, statement, instruction
    return None


def _replace_load_8616(node: object, proof: _LoadProjection8616, codegen: object) -> object:
    """Preserve the actual selector/offset expressions instead of current registers."""
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return node
    if not isinstance(node.type, SimTypeChar):
        return node
    root = node.operand
    if not isinstance(root, structured_c.CBinaryOp) or root.op != "Add":
        return node
    scale, offset = (root.lhs, root.rhs) if proof.scale_side == 0 else (root.rhs, root.lhs)
    if not isinstance(scale, structured_c.CBinaryOp) or scale.op != "Shl":
        return node
    if not isinstance(scale.rhs, structured_c.CConstant) or scale.rhs.value != 4:
        return node
    expected_scale = (proof.scale.block_addr, proof.scale.statement_index, proof.key[1])
    if _node_origin_8616(scale) != expected_scale:
        return node
    return structured_c.CFunctionCall(
        "SEG_U8", None, [scale.lhs, offset], codegen=codegen,
        tags={
            "inertia_x86_16_runtime_segment_helper": "SEG_U8",
            "inertia_source_instruction_addrs": (proof.key[1],),
            SEGMENTED_LOAD_ADDRESS_TAG_8616: proof.address,
        },
    )


def _projection_index_8616(
    blocks: tuple[IRBlock, ...], accepted_loads: frozenset[LoadKey8616],
) -> dict[tuple[int, int, int], list[_LoadProjection8616]]:
    """Index source owners without resolving duplicate proofs by iteration order."""
    projections: dict[tuple[int, int, int], list[_LoadProjection8616]] = {}
    for block in blocks:
        definitions = _definitions_8616(block)
        for instruction in block.instrs:
            proof = _projection_8616(instruction, definitions)
            if proof is not None and proof.key in accepted_loads:
                origin = (proof.root.block_addr, proof.root.statement_index, proof.key[1])
                projections.setdefault(origin, []).append(proof)
    return projections


def _nonread_nodes_8616(statements: object) -> set[int]:
    """Protect lvalues and address-taking, including nodes shared with a read."""
    protected: set[int] = set()
    for node in _iter_c_nodes_deep_8616(statements):
        if isinstance(node, structured_c.CAssignment):
            protected.update(id(child) for child in _iter_c_nodes_deep_8616(node.lhs))
        elif isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            protected.update(id(child) for child in _iter_c_nodes_deep_8616(node.operand))
    return protected


def materialize_segmented_load_origins_8616(
    codegen: object, accepted_loads: frozenset[LoadKey8616],
) -> frozenset[LoadKey8616]:
    """Return exact load keys materialized from proven IR and retained AST operands."""
    boundary = cast(_Codegen8616, codegen)
    if boundary.cfunc is None or not accepted_loads:
        return frozenset()
    resolution = registered_function_ir_artifact_8616(boundary.project, boundary.cfunc.addr)
    if resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN or resolution.artifact is None:
        return frozenset()
    projections = _projection_index_8616(resolution.artifact.blocks, accepted_loads)
    if not projections:
        return frozenset()
    protected = _nonread_nodes_8616(boundary.cfunc.statements)
    materialized: set[LoadKey8616] = set()

    def transform(node: object) -> object:
        """Replace one read only if its exact address owner has a unique proof."""
        if id(node) in protected:
            return node
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        if not isinstance(node.operand, structured_c.CBinaryOp):
            return node
        origin = _node_origin_8616(node.operand)
        candidates = projections.get(origin, []) if origin is not None else []
        if len(candidates) != 1:
            return node
        replacement = _replace_load_8616(node, candidates[0], codegen)
        if replacement is not node:
            materialized.add(candidates[0].key)
        return replacement

    _replace_c_children_8616(boundary.cfunc.statements, transform)
    return frozenset(materialized)
