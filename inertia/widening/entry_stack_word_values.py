"""Prove one entry-block word value from exact initial SS byte captures.

Layer: Widening.
Responsibility: bind canonical Alias byte witnesses to ordered, locally built
SSA definitions and transport exact bit provenance to one selected definition.
This is value-only evidence, not a memory read, frame, pointer, callee or CFG proof.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from inertia.alias.entry_stack_byte_contracts import (
    EntryStackByteProof8616,
    EntryStackByteRead8616,
)
from inertia.alias.entry_stack_bytes import prove_entry_stack_bytes_8616
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.scalar_instruction_effects import (
    ScalarInstructionClobber8616,
    scalar_instruction_effect_8616,
)
from inertia.ir.scalar_value_projection import (
    ScalarBinaryKind8616,
    scalar_binary_operation_8616,
    scalar_produced_decoration_8616,
    scalar_read_projection_8616,
)
from inertia.ir.ssa import build_x86_16_block_local_ssa
from inertia.semantics.register_value_preservation import (
    register_value_family_8616,
    register_value_projection_8616,
)

from .entry_stack_word_bits import (
    BitVector8616,
    EntryStackWordBit8616,
    binary_entry_bits_8616,
    constant_bits_8616,
    project_entry_bits_8616,
)
from .entry_stack_word_value_contracts import (
    EntryStackWord8616,
    EntryStackWordProof8616,
    EntryStackWordRefusal8616,
    EntryStackWordVerdict8616,
)
from .entry_stack_word_value_contracts import (
    EntryStackWordRefusalKind8616 as Refusal,
)


@dataclass(frozen=True, slots=True)
class _Outcome8616:
    """Proven bit transport or one retained typed reason for missing evidence."""

    bits: BitVector8616 | None
    refusal: Refusal | None = None


@dataclass(frozen=True, slots=True)
class _Definition8616:
    """One ordered SSA definition; no TMP identifier alone proves a value."""

    index: int
    version: int | None
    width: int
    produced: tuple[str, ...]
    outcome: _Outcome8616


def _plain_scalar_read_8616(value: IRValue) -> bool:
    """Refuse storage/indexed views and unproved register snapshot projections.

    TMP identifiers establish lineage only for TMP reads. A REG value tagged
    with a TMP also needs a proven register-capture projection, which this
    bounded consumer does not yet implement; guessing that relation is unsafe.
    """
    if value.space not in {MemSpace.TMP, MemSpace.REG, MemSpace.CONST}:
        return False
    if value.offset or value.index is not None or value.index_shift:
        return False
    if value.call_output is not None:
        return False
    if value.source_tmp is not None and value.space is not MemSpace.TMP:
        return False
    return value.const is not None if value.space is MemSpace.CONST else value.const is None


def _plain_scalar_destination_8616(value: IRValue) -> bool:
    """A definition is exact storage, not a displaced/decorated operand view."""
    return (
        value.space in {MemSpace.TMP, MemSpace.REG}
        and _plain_scalar_read_8616(value) and not value.expr
    )


@dataclass(slots=True)
class _State8616:
    """Track exact immutable TMP definitions and current full register values."""

    captures: dict[int, EntryStackByteRead8616]
    temporaries: dict[int, _Definition8616] = field(default_factory=dict)
    registers: dict[str, _Definition8616] = field(default_factory=dict)

    def read(self, value: IRValue, index: int) -> _Outcome8616:
        """Resolve an existing producer, check its view, then transport bits."""
        if not _plain_scalar_read_8616(value):
            return _Outcome8616(None, Refusal.UNSUPPORTED_OPERAND)
        if value.size not in {1, 2, 4, 8}:
            return _Outcome8616(None, Refusal.BAD_PROJECTION)
        definition = self._definition(value)
        if definition is None:
            return _Outcome8616(None, Refusal.NO_PRODUCER_SITE)
        if definition.index >= index:
            return _Outcome8616(None, Refusal.FORWARD_TMP_DEFINITION)
        if definition.version != value.version:
            return _Outcome8616(None, Refusal.STALE_TMP_VERSION)
        if definition.outcome.bits is None:
            return definition.outcome
        projection = scalar_read_projection_8616(
            read_expr=value.expr, read_bits=value.size * 8,
            produced=definition.produced, produced_bits=definition.width,
        )
        if projection is None:
            return _Outcome8616(None, Refusal.BAD_PROJECTION)
        result = project_entry_bits_8616(definition.outcome.bits, projection)
        return _Outcome8616(result, None if result is not None else Refusal.BAD_PROJECTION)

    def _definition(self, value: IRValue) -> _Definition8616 | None:
        """Resolve only a retained TMP/register producer or an explicit literal."""
        if value.source_tmp is not None:
            return self.temporaries.get(value.source_tmp)
        if value.space is MemSpace.REG and value.name is not None:
            return self.registers.get(value.name.lower())
        if value.space is MemSpace.CONST and value.const is not None:
            return _Definition8616(
                -1, value.version, value.size * 8, (),
                _Outcome8616(constant_bits_8616(value.const, value.size * 8)),
            )
        return None

    def evaluate(self, instruction: IRInstr, index: int) -> _Outcome8616:
        """Interpret a scalar producer without inferring any memory effects."""
        if instruction.op == "LOAD":
            capture = self.captures.get(index)
            destination = instruction.dst
            if capture is None or destination is None:
                return _Outcome8616(None, Refusal.UNPROVEN_LOAD_SEED)
            valid = (
                capture.width == 1 and len(capture.byte_offsets) == 1
                and destination.size == 1 and instruction.size == 1
                and destination.space is MemSpace.TMP
                and destination.source_tmp == capture.producer_tmp
            )
            if not valid:
                return _Outcome8616(None, Refusal.UNPROVEN_LOAD_SEED)
            return _Outcome8616(tuple(EntryStackWordBit8616(capture, bit) for bit in range(8)))
        arguments = instruction.args
        if not all(isinstance(argument, IRValue) for argument in arguments):
            return _Outcome8616(None, Refusal.UNSUPPORTED_OPERAND)
        if instruction.op == "MOV" and len(arguments) == 1:
            source = arguments[0]
            if isinstance(source, IRValue):
                return self.read(source, index)
        return self._binary(instruction, index)

    def _binary(self, instruction: IRInstr, index: int) -> _Outcome8616:
        """Apply only shared typed pure-operation descriptors at exact widths."""
        operation = scalar_binary_operation_8616(instruction.op)
        if operation is None or len(instruction.args) != 2:
            return _Outcome8616(None, Refusal.UNSUPPORTED_PRODUCER_OP)
        a, b = instruction.args
        if not isinstance(a, IRValue) or not isinstance(b, IRValue):
            return _Outcome8616(None, Refusal.UNSUPPORTED_OPERAND)
        left, right = self.read(a, index), self.read(b, index)
        if left.bits is None:
            return left
        if right.bits is None:
            return right
        shifts = {ScalarBinaryKind8616.SHL, ScalarBinaryKind8616.SHR}
        if len(left.bits) != operation.bits:
            return _Outcome8616(None, Refusal.BAD_PROJECTION)
        if operation.kind not in shifts and len(right.bits) != operation.bits:
            return _Outcome8616(None, Refusal.BAD_PROJECTION)
        result = binary_entry_bits_8616(operation.kind, left.bits, right.bits)
        return _Outcome8616(result, None if result is not None else Refusal.UNSUPPORTED_PRODUCER_OP)

    def observe(self, instruction: IRInstr, index: int) -> _Outcome8616:
        """Read old definitions before publishing; unknown effects kill registers.

        Immutable captured TMP values remain values after unrelated effects.
        Current architectural register contents need separate preservation
        evidence across CALLs and any unmodelled instruction effect.
        """
        effect = scalar_instruction_effect_8616(instruction)
        if effect.clobber is ScalarInstructionClobber8616.UNKNOWN:
            self.registers.clear()
        elif effect.clobber is ScalarInstructionClobber8616.INSTRUCTION_POINTER:
            for member in register_value_family_8616("ip"):
                self.registers.pop(member, None)
        if instruction.op == "CALL":
            return _Outcome8616(None, Refusal.NON_SCALAR_TARGET)
        destination = instruction.dst
        if destination is None or destination.space not in {MemSpace.TMP, MemSpace.REG}:
            return _Outcome8616(None, Refusal.NON_SCALAR_TARGET)
        if not _plain_scalar_destination_8616(destination):
            outcome = _Outcome8616(None, Refusal.UNSUPPORTED_OPERAND)
        elif instruction.size != destination.size:
            outcome = _Outcome8616(None, Refusal.BAD_PROJECTION)
        else:
            outcome = self.evaluate(instruction, index)
        width = destination.size * 8
        if outcome.bits is not None and len(outcome.bits) != width:
            outcome = _Outcome8616(None, Refusal.BAD_PROJECTION)
        definition = _Definition8616(
            index, destination.version, width,
            scalar_produced_decoration_8616(instruction), outcome,
        )
        return self._publish(destination, definition)

    def _publish(self, destination: IRValue, definition: _Definition8616) -> _Outcome8616:
        """Replace one exact producer, invalidating every register-family sibling."""
        if destination.space is MemSpace.TMP:
            if destination.source_tmp is not None:
                if destination.source_tmp in self.temporaries:
                    definition = replace(
                        definition, outcome=_Outcome8616(None, Refusal.AMBIGUOUS_PRODUCER),
                    )
                self.temporaries[destination.source_tmp] = definition
                return definition.outcome
            return _Outcome8616(None, Refusal.NO_PRODUCER_SITE)
        if destination.name is None:
            self.registers.clear()
            return _Outcome8616(None, Refusal.NON_SCALAR_TARGET)
        name = destination.name.lower()
        for member in register_value_family_8616(name):
            self.registers.pop(member, None)
        view = register_value_projection_8616(name, name)
        if view is None or view[1] != definition.width:
            return _Outcome8616(None, Refusal.UNSUPPORTED_TARGET_WIDTH)
        self.registers[name] = definition
        return definition.outcome


def _refused_8616(
    artifact: IRFunctionArtifact, byte_proof: EntryStackByteProof8616,
    reason: Refusal, index: int, *, candidate: bool = False,
) -> EntryStackWordProof8616:
    """Retain a closed typed non-result rather than inventing a word value."""
    count = int(candidate)
    return EntryStackWordProof8616(
        artifact=artifact, byte_proof=byte_proof,
        refusals=(EntryStackWordRefusal8616(reason, reason.value, index),),
        raw_fact_count=count, normalized_fact_count=count,
        classified_fact_count=count, failure_count=1,
    )


def _word_origins_8616(
    bits: BitVector8616,
) -> tuple[tuple[EntryStackWordBit8616, ...] | None, Refusal | None]:
    """Require every output bit to retain the exact ordered two-byte identity."""
    origins: list[EntryStackWordBit8616] = []
    for bit in bits:
        if not isinstance(bit, EntryStackWordBit8616):
            return None, Refusal.MISSING_BYTE_LANES
        origins.append(bit)
    if len(origins) != 16:
        return None, Refusal.UNSUPPORTED_TARGET_WIDTH
    low, high = origins[0].capture, origins[8].capture
    for index, bit in enumerate(origins):
        capture = low if index < 8 else high
        if bit.capture != capture or bit.bit_index != index % 8:
            return None, Refusal.WRONG_BIT_LANES
    if high.byte_offsets[0] != low.byte_offsets[0] + 1:
        return None, Refusal.NON_ADJACENT_BYTES
    return tuple(origins), None


def _entry_block_8616(
    artifact: IRFunctionArtifact, byte_proof: EntryStackByteProof8616, target_index: int,
) -> IRBlock | Refusal:
    """Validate the exact Alias owner and bounded selected execution site."""
    if byte_proof.artifact is not artifact:
        return Refusal.CROSS_ARTIFACT_PROOF
    if byte_proof != prove_entry_stack_bytes_8616(artifact):
        return Refusal.STALE_BYTE_PROOF
    entries = [block for block in artifact.blocks if block.addr == artifact.function_addr]
    if len(entries) != 1:
        return Refusal.MISSING_ENTRY_BLOCK
    block = entries[0]
    if not 0 <= target_index < len(block.instrs):
        return Refusal.BAD_TARGET_INDEX
    if not byte_proof.facts:
        return Refusal.BYTE_PREFIX_NOT_PROVEN
    return block


def prove_entry_stack_word_value_8616(
    artifact: IRFunctionArtifact, byte_proof: EntryStackByteProof8616, target_index: int,
) -> EntryStackWordProof8616:
    """Prove one selected value using canonical Alias and locally owned SSA.

    The byte proof is replay-checked against its exact immutable raw owner.
    Earlier valid captures remain usable when later unrelated LOADs refuse.
    No caller-provided SSA, serialized witness or address alone is lineage.
    """
    block = _entry_block_8616(artifact, byte_proof, target_index)
    if isinstance(block, Refusal):
        return _refused_8616(artifact, byte_proof, block, target_index)
    ssa = build_x86_16_block_local_ssa(block)
    target = ssa.instrs[target_index]
    destination = target.dst
    if destination is None or target.op == "CALL":
        return _refused_8616(artifact, byte_proof, Refusal.NON_SCALAR_TARGET, target_index)
    if not _plain_scalar_destination_8616(destination):
        return _refused_8616(artifact, byte_proof, Refusal.NON_SCALAR_TARGET, target_index)
    if destination.size != 2 or destination.space not in {MemSpace.TMP, MemSpace.REG}:
        return _refused_8616(artifact, byte_proof, Refusal.UNSUPPORTED_TARGET_WIDTH, target_index)
    if destination.space is MemSpace.TMP and destination.source_tmp is None:
        return _refused_8616(artifact, byte_proof, Refusal.NON_SCALAR_TARGET, target_index)
    state = _State8616({fact.instr_index: fact for fact in byte_proof.facts})
    outcome = _Outcome8616(None, Refusal.NO_PRODUCER_SITE)
    for index, instruction in enumerate(ssa.instrs[:target_index + 1]):
        outcome = state.observe(instruction, index)
    if outcome.bits is None:
        return _refused_8616(
            artifact, byte_proof, outcome.refusal or Refusal.MISSING_BYTE_LANES,
            target_index, candidate=True,
        )
    origins, failure = _word_origins_8616(outcome.bits)
    if origins is None:
        return _refused_8616(
            artifact, byte_proof, failure or Refusal.WRONG_BIT_LANES,
            target_index, candidate=True,
        )
    fact = EntryStackWord8616(
        block.addr, target_index, target.addr, destination.space, destination.source_tmp,
        destination.name, destination.version, origins, origins[0].capture, origins[8].capture,
    )
    return EntryStackWordProof8616(
        artifact=artifact, byte_proof=byte_proof, verdict=EntryStackWordVerdict8616.PROVEN,
        fact=fact, raw_fact_count=1, normalized_fact_count=1,
        classified_fact_count=1, materialized_count=1,
    )
