"""Index exact scalar SSA definitions for IR-owned evidence producers.

Layer: IR.
Responsibility: provide deterministic identities and locations for scalar SSA
definitions without interpreting their semantics or crossing block-local SSA
boundaries.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import IRFunctionArtifact, IRInstr, IRValue, MemSpace
from .ssa_function import SSAFunctionArtifact

type ScalarDefinitionKey8616 = tuple[str, str | None, int, int, int | None]
type ScalarDefinitionIndex8616 = dict[
    ScalarDefinitionKey8616,
    tuple["ScalarDefinition8616", ...],
]


@dataclass(frozen=True, slots=True)
class ScalarDefinition8616:
    """One exact scalar SSA definition and its block-local location.

    A CALL target is an input use, never a defining operation. Explicit output
    instructions retain their own records; this index does not infer effects.
    """

    block_addr: int
    instr_index: int
    instruction: IRInstr

    @property
    def complete(self) -> bool:
        """Require a defining operation, not merely a nonempty CALL target."""
        return bool(
            self.block_addr >= 0
            and self.instr_index >= 0
            and self.instruction.dst is not None
            and self.instruction.op != "CALL"
        )


def scalar_definition_key_8616(value: IRValue) -> ScalarDefinitionKey8616:
    """Return the exact scalar identity used by IR definition tracing."""
    if value.source_tmp is not None:
        # A VEX temporary is the authoritative identity. Consumer projections
        # may retain the source carrier width across an explicit truncation;
        # operation-specific tracers must validate the defining width.
        return (
            MemSpace.TMP.value,
            f"vex_tmp:{value.source_tmp}",
            0,
            0,
            None,
        )
    return (
        value.space.value,
        value.name,
        value.offset,
        value.size,
        value.version,
    )


def build_scalar_definition_index_8616(
    artifact: IRFunctionArtifact | SSAFunctionArtifact,
) -> ScalarDefinitionIndex8616:
    """Index true raw/SSA definitions, excluding input-only CALL targets.

    Target reads never create a competing producer or change immutable captured
    values. All actual definitions remain visible, including their conflicts.
    This exclusion proves neither register nor memory preservation across CALL.
    """
    grouped: dict[ScalarDefinitionKey8616, list[ScalarDefinition8616]] = {}
    for block in artifact.blocks:
        for instr_index, instruction in enumerate(block.instrs):
            if instruction.dst is None or instruction.op == "CALL":
                continue
            key = scalar_definition_key_8616(instruction.dst)
            grouped.setdefault(key, []).append(
                ScalarDefinition8616(block.addr, instr_index, instruction)
            )
    return {key: tuple(items) for key, items in grouped.items()}


def reaching_scalar_definitions_8616(
    definitions: ScalarDefinitionIndex8616,
    value: IRValue,
    *,
    block_addr: int,
    before_index: int,
) -> tuple[ScalarDefinition8616, ...]:
    """Return same-block definitions of one value preceding an exact use."""
    return tuple(
        item
        for item in definitions.get(scalar_definition_key_8616(value), ())
        if item.block_addr == block_addr and item.instr_index < before_index
    )


__all__ = [
    "ScalarDefinition8616",
    "ScalarDefinitionIndex8616",
    "ScalarDefinitionKey8616",
    "build_scalar_definition_index_8616",
    "reaching_scalar_definitions_8616",
    "scalar_definition_key_8616",
]
