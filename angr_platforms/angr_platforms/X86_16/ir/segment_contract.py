"""Build exact per-function segment requirements and effects from typed IR.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
This module narrows those facts into function-local segment requirements and
effects without inferring a program memory model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from .core import (
    IRAddress,
    IRAtom,
    IRBinaryValue,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .segment_state import SegmentRegisterState, SegmentStateArtifact, SegmentValueKind8616

__all__ = [
    "SegmentAccessFact", "SegmentAccessKind",
    "SegmentFactVerdict", "SegmentFunctionContract",
    "SegmentInstructionStateFact", "SegmentWriteFact", "SegmentWriteKind",
    "apply_x86_16_segment_function_contract",
    "build_x86_16_segment_function_contract",
]

_SEGMENT_REGISTERS = ("cs", "ds", "es", "ss", "fs", "gs")
_SPACE_SEGMENTS = {MemSpace.DS: "ds", MemSpace.ES: "es", MemSpace.SS: "ss"}


class _SegmentContractCodegenBoundary(Protocol):
    """Dynamic codegen fields consumed and produced at the IR boundary."""

    _inertia_vex_ir_artifact: object
    _inertia_segment_state_artifact: object
    _inertia_segment_function_contract: SegmentFunctionContract


class SegmentFactVerdict(StrEnum):
    """Proof status for one segment contract fact."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class SegmentAccessKind(StrEnum):
    """Direction of one typed memory access."""

    READ = "read"
    WRITE = "write"


class SegmentWriteKind(StrEnum):
    """Classification of one explicit segment-register assignment."""

    ASSIGN = "assign"
    RESTORE = "restore"


@dataclass(frozen=True, slots=True)
class SegmentInstructionStateFact:
    """Exact physical segment identity before one typed IR instruction."""

    block_addr: int
    instruction_addr: int
    register: str
    physical_source: str | None
    verdict: SegmentFactVerdict

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "block_addr": self.block_addr, "instruction_addr": self.instruction_addr,
            "register": self.register, "physical_source": self.physical_source,
            "verdict": self.verdict.value,
        }


@dataclass(frozen=True, slots=True)
class SegmentAccessFact:
    """Exact segment identity at one typed memory access."""

    block_addr: int
    instruction_addr: int | None
    kind: SegmentAccessKind
    address: IRAddress
    segment_register: str | None
    physical_source: str | None
    verdict: SegmentFactVerdict

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "block_addr": self.block_addr,
            "instruction_addr": self.instruction_addr,
            "kind": self.kind.value,
            "address": self.address.to_dict(),
            "segment_register": self.segment_register,
            "physical_source": self.physical_source,
            "verdict": self.verdict.value,
        }


@dataclass(frozen=True, slots=True)
class SegmentWriteFact:
    """Before/after must-state for one explicit segment-register write."""

    block_addr: int
    instruction_addr: int | None
    register: str
    kind: SegmentWriteKind
    before: SegmentRegisterState | None
    after: SegmentRegisterState | None
    verdict: SegmentFactVerdict

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "block_addr": self.block_addr,
            "instruction_addr": self.instruction_addr,
            "register": self.register,
            "kind": self.kind.value,
            "before": None if self.before is None else self.before.to_dict(),
            "after": None if self.after is None else self.after.to_dict(),
            "verdict": self.verdict.value,
        }


@dataclass(frozen=True, slots=True)
class SegmentFunctionContract:
    """Function-local segment requirements, accesses, writes, and exit effects."""

    function_addr: int
    entry_requirements: tuple[str, ...] = ()
    accesses: tuple[SegmentAccessFact, ...] = ()
    writes: tuple[SegmentWriteFact, ...] = ()
    instruction_states: tuple[SegmentInstructionStateFact, ...] = ()
    clobbered_registers: tuple[str, ...] = ()
    restored_registers: tuple[str, ...] = ()
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addr": self.function_addr,
            "entry_requirements": list(self.entry_requirements),
            "accesses": [fact.to_dict() for fact in self.accesses],
            "writes": [fact.to_dict() for fact in self.writes],
            "instruction_states": [fact.to_dict() for fact in self.instruction_states],
            "clobbered_registers": list(self.clobbered_registers),
            "restored_registers": list(self.restored_registers),
            "summary": dict(self.summary),
        }


def _proven_source(state: SegmentRegisterState | None) -> str | None:
    """Return a physical source only from a proven must-state."""
    if state is None or state.origin is not SegmentOrigin.PROVEN:
        return None
    source = state.source
    return source if isinstance(source, str) else None


def _state_before(
    segment_state: SegmentStateArtifact,
    instruction_addr: int | None,
    register: str,
) -> SegmentRegisterState | None:
    """Look up exact state and refuse instructions without an address."""
    if instruction_addr is None:
        return None
    return segment_state.state_before_instruction(instruction_addr, register)


def _segment_reads(atom: IRAtom) -> tuple[str, ...]:
    """Return segment registers read by one typed IR atom."""
    if isinstance(atom, IRValue):
        if atom.space is MemSpace.REG and atom.name in _SEGMENT_REGISTERS:
            return (atom.name,)
        return ()
    if isinstance(atom, IRBinaryValue):
        return (*_segment_reads(atom.lhs), *_segment_reads(atom.rhs))
    if isinstance(atom, IRCondition):
        return tuple(register for argument in atom.args for register in _segment_reads(argument))
    return ()


def _access_fact(
    block_addr: int,
    instruction: IRInstr,
    address: IRAddress,
    kind: SegmentAccessKind,
    segment_state: SegmentStateArtifact,
) -> SegmentAccessFact:
    """Classify one memory operand using exact pre-instruction state."""
    register = _SPACE_SEGMENTS.get(address.space)
    state = None if register is None else _state_before(segment_state, instruction.addr, register)
    source = _proven_source(state)
    verdict = SegmentFactVerdict.PROVEN if source is not None else SegmentFactVerdict.UNKNOWN_REFUSE
    return SegmentAccessFact(
        block_addr=block_addr,
        instruction_addr=instruction.addr,
        kind=kind,
        address=address,
        segment_register=register,
        physical_source=source,
        verdict=verdict,
    )


def _write_fact(
    block_addr: int,
    instruction: IRInstr,
    register: str,
    segment_state: SegmentStateArtifact,
) -> SegmentWriteFact:
    """Classify one segment write and recognize a proven local restoration."""
    before = _state_before(segment_state, instruction.addr, register)
    after = None if instruction.addr is None else segment_state.state_after_instruction(instruction.addr, register)
    before_source = _proven_source(before)
    after_source = _proven_source(after)
    kind = (
        SegmentWriteKind.RESTORE
        if after_source == register
        and (
            (after is not None and after.value_kind is SegmentValueKind8616.STACK_RESTORE)
            or (before_source is not None and before_source != register)
        )
        else SegmentWriteKind.ASSIGN
    )
    verdict = SegmentFactVerdict.PROVEN if after_source is not None else SegmentFactVerdict.UNKNOWN_REFUSE
    return SegmentWriteFact(block_addr, instruction.addr, register, kind, before, after, verdict)


def _exit_clobbers(
    artifact: IRFunctionArtifact,
    segment_state: SegmentStateArtifact,
) -> tuple[str, ...]:
    """Return registers whose physical identity is not preserved at every exit."""
    block_addrs = {block.addr for block in artifact.blocks}
    exit_addrs = tuple(
        block.addr for block in artifact.blocks if not any(successor in block_addrs for successor in block.successor_addrs)
    )
    entry = segment_state.entry_states.get(artifact.function_addr, {})
    return tuple(
        register
        for register in _SEGMENT_REGISTERS
        if (entry_source := _proven_source(entry.get(register))) is not None
        and any(
            _proven_source(segment_state.exit_states.get(exit_addr, {}).get(register)) != entry_source
            for exit_addr in exit_addrs
        )
    )


@dataclass(slots=True)
class _SegmentFactScan8616:
    """Mutable collector for per-block segment fact extraction."""

    accesses: list[SegmentAccessFact] = field(default_factory=list)
    writes: list[SegmentWriteFact] = field(default_factory=list)
    instruction_states: list[SegmentInstructionStateFact] = field(default_factory=list)
    entry_requirements: set[str] = field(default_factory=set)

    def scan(self, block: IRBlock, segment_state: SegmentStateArtifact) -> None:
        """Collect all segment facts owned by one IR block."""
        for instruction in block.instrs:
            if instruction.addr is not None:
                for register in _SEGMENT_REGISTERS:
                    source = _proven_source(_state_before(segment_state, instruction.addr, register))
                    verdict = SegmentFactVerdict.PROVEN if source is not None else SegmentFactVerdict.UNKNOWN_REFUSE
                    self.instruction_states.append(
                        SegmentInstructionStateFact(block.addr, instruction.addr, register, source, verdict)
                    )
            self._scan_accesses(block.addr, instruction, segment_state)
            self._scan_write(block.addr, instruction, segment_state)

    def _scan_accesses(
        self,
        block_addr: int,
        instruction: IRInstr,
        segment_state: SegmentStateArtifact,
    ) -> None:
        """Collect typed access facts and segment entry requirements."""
        for argument_index, argument in enumerate(instruction.args):
            if isinstance(argument, IRAddress):
                kind = (
                    SegmentAccessKind.WRITE
                    if instruction.op == "STORE" and argument_index == 0
                    else SegmentAccessKind.READ
                )
                access = _access_fact(block_addr, instruction, argument, kind, segment_state)
                self.accesses.append(access)
                if access.physical_source in _SEGMENT_REGISTERS:
                    self.entry_requirements.add(access.physical_source)
            for register in _segment_reads(argument):
                source = _proven_source(_state_before(segment_state, instruction.addr, register))
                if source in _SEGMENT_REGISTERS:
                    self.entry_requirements.add(source)

    def _scan_write(
        self,
        block_addr: int,
        instruction: IRInstr,
        segment_state: SegmentStateArtifact,
    ) -> None:
        """Collect one typed segment-register write fact."""
        dst = instruction.dst
        if isinstance(dst, IRValue) and dst.space is MemSpace.REG and dst.name in _SEGMENT_REGISTERS:
            self.writes.append(_write_fact(block_addr, instruction, dst.name, segment_state))


def build_x86_16_segment_function_contract(
    artifact: IRFunctionArtifact,
    segment_state: SegmentStateArtifact,
) -> SegmentFunctionContract:
    """Build an exact function-local segment contract from typed IR facts."""
    scan = _SegmentFactScan8616()
    for block in artifact.blocks:
        scan.scan(block, segment_state)
    accesses = scan.accesses
    writes = scan.writes
    instruction_states = scan.instruction_states
    entry_requirements = scan.entry_requirements

    clobbered = _exit_clobbers(artifact, segment_state)
    restored = tuple(
        sorted(
            {
                fact.register
                for fact in writes
                if fact.kind is SegmentWriteKind.RESTORE and fact.register not in clobbered
            }
        )
    )
    facts = (*accesses, *writes, *instruction_states)
    classified_count = (
        sum(fact.verdict is SegmentFactVerdict.PROVEN for fact in accesses)
        + sum(fact.verdict is SegmentFactVerdict.PROVEN for fact in writes)
        + sum(fact.verdict is SegmentFactVerdict.PROVEN for fact in instruction_states)
    )
    return SegmentFunctionContract(
        function_addr=artifact.function_addr,
        entry_requirements=tuple(sorted(entry_requirements)),
        accesses=tuple(accesses),
        writes=tuple(writes),
        instruction_states=tuple(instruction_states),
        clobbered_registers=clobbered,
        restored_registers=restored,
        summary={
            "raw_fact_count": len(facts),
            "normalized_fact_count": len(facts),
            "classified_fact_count": classified_count,
            "materialized_count": classified_count,
            "failure_count": len(facts) - classified_count,
            "access_count": len(accesses),
            "write_count": len(writes),
            "instruction_state_count": len(instruction_states),
        },
    )


def apply_x86_16_segment_function_contract(project: object, codegen: object) -> bool:
    """Attach a function-local segment contract after typed IR state analysis."""
    boundary = cast(_SegmentContractCodegenBoundary, codegen)
    try:
        artifact = boundary._inertia_vex_ir_artifact
        segment_state = boundary._inertia_segment_state_artifact
    except AttributeError:
        return False
    if not isinstance(artifact, IRFunctionArtifact) or not isinstance(segment_state, SegmentStateArtifact):
        return False
    boundary._inertia_segment_function_contract = build_x86_16_segment_function_contract(artifact, segment_state)
    return False
