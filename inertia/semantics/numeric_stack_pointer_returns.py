"""Bind an Alias numeric frame value to its owning machine return.

Layer: Semantics.
Responsibility: prove that one exact word assignment supplies a particular RET
without intervening register effects. Consumes Alias coordinates; does not
infer native SSA inputs, C variables, or ownership across shared epilogues.
Owns instruction effects, flags, branch meaning, and expression interpretation
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.alias.numeric_stack_pointer_values import (
    NumericStackPointerAssignment8616,
    prove_numeric_stack_pointer_assignment_8616,
)
from inertia.ir.core import IRFunctionArtifact, IRValue, MemSpace

from .register_definition_return import RegisterReturnPath8616, unchanged_register_return_path_8616
from .register_value_preservation import register_value_family_8616


@dataclass(frozen=True, slots=True)
class NumericStackPointerReturn8616:
    """One scalar definition and the same-block return it necessarily reaches."""

    assignment: NumericStackPointerAssignment8616
    path: RegisterReturnPath8616


class NumericStackPointerReturnRefusal8616(StrEnum):
    """Non-results of exact source return ownership, never guessed values."""

    UNKNOWN_VALUE_OR_PATH = "unknown_value_or_path"
    DUPLICATE_RETURN_SCOPE = "duplicate_return_scope"


@dataclass(frozen=True, slots=True)
class NumericStackPointerReturnObservation8616:
    """Account for one machine return whether its scalar is proved or unknown."""

    block_addr: int
    return_addr: int | None
    proof: NumericStackPointerReturn8616 | None
    refusal: NumericStackPointerReturnRefusal8616 | None


@dataclass(frozen=True, slots=True)
class NumericStackPointerReturnStats8616:
    """Closed source-proof publication ledger, before any C materialization."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    refusal_count: int


@dataclass(frozen=True, slots=True)
class NumericStackPointerReturnInventory8616:
    """Source-bound Alias/value and Semantics/path outputs for Types consumers.

    Materialization in this ledger means publication of typed proof records.
    C consumers own a separate materialization ledger; a refusal here must
    leave the existing C return untouched.
    """

    source_ir: IRFunctionArtifact
    observations: tuple[NumericStackPointerReturnObservation8616, ...]
    stats: NumericStackPointerReturnStats8616

    def to_dict(self) -> dict[str, object]:
        """Serialize deterministic outcomes without duplicating upstream IR."""
        return {
            "function_addr": self.source_ir.function_addr,
            "observations": [asdict(item) for item in self.observations],
            "stats": asdict(self.stats),
        }


class _CodegenBoundary8616(Protocol):
    """Typed owned artifacts on the dynamic native codegen boundary."""

    _inertia_vex_ir_artifact: object
    _inertia_numeric_stack_pointer_returns_8616: NumericStackPointerReturnInventory8616


def numeric_stack_pointer_return_inventory_8616(
    codegen: object,
) -> NumericStackPointerReturnInventory8616 | None:
    """Read only a typed publication bound to the currently installed IR."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        inventory = boundary._inertia_numeric_stack_pointer_returns_8616
        source = boundary._inertia_vex_ir_artifact
    except AttributeError:
        return None
    return inventory if isinstance(inventory, NumericStackPointerReturnInventory8616) and inventory.source_ir is source else None


def numeric_stack_pointer_return_inventory_is_current_8616(
    inventory: NumericStackPointerReturnInventory8616,
) -> bool:
    """Recheck source/callee effects at consumption without caching authority."""
    current = build_numeric_stack_pointer_return_inventory_8616(inventory.source_ir)
    return current.observations == inventory.observations and current.stats == inventory.stats


def build_numeric_stack_pointer_return_inventory_8616(
    artifact: IRFunctionArtifact,
) -> NumericStackPointerReturnInventory8616:
    """Publish one typed outcome for every source RET before Alias completion."""
    observations: list[NumericStackPointerReturnObservation8616] = []
    seen: set[tuple[int, int | None]] = set()
    failures = 0
    for block in artifact.blocks:
        for instruction in block.instrs:
            if instruction.op != "RET":
                continue
            key = (block.addr, instruction.addr)
            proof: NumericStackPointerReturn8616 | None
            refusal: NumericStackPointerReturnRefusal8616 | None
            if key in seen:
                proof = None
                refusal = NumericStackPointerReturnRefusal8616.DUPLICATE_RETURN_SCOPE
                failures += 1
            else:
                seen.add(key)
                proof = (prove_numeric_stack_pointer_return_8616(artifact, block.addr, instruction.addr)
                         if instruction.addr is not None else None)
                refusal = None if proof is not None else NumericStackPointerReturnRefusal8616.UNKNOWN_VALUE_OR_PATH
            observations.append(NumericStackPointerReturnObservation8616(*key, proof, refusal))
    proved = sum(item.proof is not None for item in observations)
    return NumericStackPointerReturnInventory8616(
        artifact, tuple(observations),
        NumericStackPointerReturnStats8616(
            len(observations), len(seen), proved, proved, failures,
            sum(item.refusal is not None for item in observations),
        ),
    )


def apply_numeric_stack_pointer_return_inventory_8616(
    codegen: object,
) -> NumericStackPointerReturnInventory8616 | None:
    """Build fresh source proof outputs at the authenticated prefix boundary."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        source = boundary._inertia_vex_ir_artifact
    except AttributeError:
        return None
    if not isinstance(source, IRFunctionArtifact):
        return None
    inventory = build_numeric_stack_pointer_return_inventory_8616(source)
    boundary._inertia_numeric_stack_pointer_returns_8616 = inventory
    return inventory


def prove_numeric_stack_pointer_return_8616(
    artifact: IRFunctionArtifact, return_block_addr: int, return_addr: int,
    register: str = "ax",
) -> NumericStackPointerReturn8616 | None:
    """Prove the final word definition on every path reaching this block's RET.

    Restrict ownership to a definition in the return block itself. A preserved
    path from another predecessor is insufficient to establish ownership of a
    shared epilogue. Calls, partial writes, later clobbers and unknown effects
    remain obligations of the existing register-preservation proof.
    """
    owners = [block for block in artifact.blocks if block.addr == return_block_addr]
    if len(owners) != 1 or not owners[0].instrs:
        return None
    block = owners[0]
    terminal = block.instrs[-1]
    if terminal.op != "RET" or terminal.addr != return_addr:
        return None
    family = register_value_family_8616(register)
    definitions = [
        (index, instruction) for index, instruction in enumerate(block.instrs)
        if isinstance(instruction.dst, IRValue) and instruction.dst.space is MemSpace.REG
        and instruction.dst.name in family
    ]
    if not definitions:
        return None
    index, definition = definitions[-1]
    assignment = prove_numeric_stack_pointer_assignment_8616(artifact, block.addr, index)
    if assignment is None or assignment.register != register or definition.addr is None:
        return None
    path = unchanged_register_return_path_8616(artifact, definition.addr, register)
    if path is None or path.return_addr != return_addr or path.block_addrs != (block.addr,):
        return None
    return NumericStackPointerReturn8616(assignment, path)
