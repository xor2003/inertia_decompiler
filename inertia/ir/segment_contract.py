# cython: language_level=3, infer_types=True
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
import typing
import cython

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from inertia.frontend.x86_16.frontend_boundary_transport import (
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    mapped_entry_function_boundary_8616,
)

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
from .function_ssa_registry import function_boundary_at_address_8616
from .ir_boundary_cfg import IRBoundaryCoverageResult8616, prove_ir_boundary_coverage_8616
from .segment_effect_closure import SegmentEffectClosureResult8616, prove_segment_effect_closure_8616
from .segment_state import SegmentRegisterState, SegmentStateArtifact, SegmentValueKind8616
import dataclasses
import operator
import builtins

__all__ = [
    "SegmentAccessFact", "SegmentAccessKind",
    "SegmentFactVerdict", "SegmentFunctionContract",
    "SegmentInstructionStateFact", "SegmentWriteFact", "SegmentWriteKind",
    "apply_x86_16_segment_function_contract",
    "build_x86_16_segment_function_contract",
]

_SEGMENT_REGISTERS = ("cs", "ds", "es", "ss", "fs", "gs")
_SPACE_SEGMENTS = {MemSpace.CS: "cs", MemSpace.DS: "ds", MemSpace.ES: "es", MemSpace.SS: "ss"}


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


@dataclasses.dataclass(frozen=True, )
class SegmentInstructionStateFact:
    """Exact physical segment identity before one typed IR instruction."""

    block_addr: cython.longlong
    instruction_addr: cython.longlong
    register: object
    physical_source: object
    verdict: SegmentFactVerdict

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "block_addr": self.block_addr, "instruction_addr": self.instruction_addr,
            "register": self.register, "physical_source": self.physical_source,
            "verdict": self.verdict.value,
        }


@dataclasses.dataclass(frozen=True, )
class SegmentAccessFact:
    """Exact segment identity at one typed memory access."""

    block_addr: cython.longlong
    instruction_addr: int | None
    kind: SegmentAccessKind
    address: IRAddress
    segment_register: object
    physical_source: object
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


@dataclasses.dataclass(frozen=True, )
class SegmentWriteFact:
    """Before/after must-state for one explicit segment-register write."""

    block_addr: cython.longlong
    instruction_addr: int | None
    register: object
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


@dataclasses.dataclass(frozen=True, )
class SegmentFunctionContract:
    """Function-local segment requirements, accesses, writes, and exit effects."""

    function_addr: cython.longlong
    entry_requirements: tuple[str, ...] = ()
    accesses: tuple[SegmentAccessFact, ...] = ()
    writes: tuple[SegmentWriteFact, ...] = ()
    instruction_states: tuple[SegmentInstructionStateFact, ...] = ()
    clobbered_registers: tuple[str, ...] = ()
    restored_registers: tuple[str, ...] = ()
    summary: object = field(default_factory=dict)
    effect_closure: SegmentEffectClosureResult8616 | None = None

    @property
    def effects_complete(self) -> cython.bint:
        """Authorize effects only from retained closure and its exact clobber projection."""
        proof: object
        proof = self.effect_closure
        return bool(
            proof is not None
            and proof.complete
            and operator.eq(proof.coverage.artifact.function_addr, self.function_addr)
            and operator.eq(self.clobbered_registers, _exit_clobbers(proof.coverage.artifact, proof.state))
        )

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addr": self.function_addr,
            "entry_requirements": list(self.entry_requirements),
            "accesses": [fact.to_dict() for fact in iter(self.accesses)],
            "writes": [fact.to_dict() for fact in iter(self.writes)],
            "instruction_states": [fact.to_dict() for fact in iter(self.instruction_states)],
            "clobbered_registers": list(self.clobbered_registers),
            "restored_registers": list(self.restored_registers),
            "summary": dict(self.summary),
            "effects_complete": self.effects_complete,
            "effect_callsite_addrs": [] if self.effect_closure is None else list(self.effect_closure.callsite_addrs),
        }


@cython.ccall
def _proven_source(state: object) -> object:
    """Return a physical source only from a proven must-state."""
    if state is None or state.origin is not SegmentOrigin.PROVEN:
        return None
    source = state.source
    return source if isinstance(source, str) else None


@cython.ccall
def _state_before(
    segment_state: SegmentStateArtifact,
    instruction_addr: object,
    register: object,
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
        return tuple(register for argument in iter(atom.args) for register in builtins.iter(_segment_reads(argument)))
    return ()


@cython.ccall
def _access_fact(
    block_addr: cython.longlong,
    instruction: IRInstr,
    address: IRAddress,
    kind: SegmentAccessKind,
    segment_state: SegmentStateArtifact,
) -> SegmentAccessFact:
    """Classify one memory operand using exact pre-instruction state."""
    register: object
    source: object
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


@cython.ccall
def _write_fact(
    block_addr: cython.longlong,
    instruction: IRInstr,
    register: object,
    segment_state: SegmentStateArtifact,
) -> SegmentWriteFact:
    """Classify one segment write and recognize a proven local restoration."""
    after: object
    after_source: object
    before_source: object
    before = _state_before(segment_state, instruction.addr, register)
    after = None if instruction.addr is None else segment_state.state_after_instruction(instruction.addr, register)
    before_source = _proven_source(before)
    after_source = _proven_source(after)
    kind = (
        SegmentWriteKind.RESTORE
        if operator.eq(after_source, register)
        and (
            (after is not None and after.value_kind is SegmentValueKind8616.STACK_RESTORE)
            or (before_source is not None and operator.ne(before_source, register))
        )
        else SegmentWriteKind.ASSIGN
    )
    verdict = SegmentFactVerdict.PROVEN if after_source is not None else SegmentFactVerdict.UNKNOWN_REFUSE
    return SegmentWriteFact(block_addr, instruction.addr, register, kind, before, after, verdict)


def _exit_clobbers(
    artifact: IRFunctionArtifact,
    segment_state: SegmentStateArtifact,
) -> tuple[str, ...]:
    """Check terminal blocks and every edge leaving the function artifact.

    A block may both continue internally and escape externally. Its outgoing
    state must participate even if another internal path restores a register.
    """
    entry: object
    block_addrs = {block.addr for block in iter(artifact.blocks)}
    exit_addrs = tuple(
        block.addr
        for block in iter(artifact.blocks)
        if not block.successor_addrs
        or any(successor not in block_addrs for successor in iter(block.successor_addrs))
    )
    entry = segment_state.entry_states.get(artifact.function_addr, {})
    return tuple(
        register
        for register in iter(_SEGMENT_REGISTERS)
        if (entry_source := _proven_source(entry.get(register))) is not None
        and any(
            operator.ne(_proven_source(segment_state.exit_states.get(exit_addr, {}).get(register)), entry_source)
            for exit_addr in iter(exit_addrs)
        )
    )


@cython.dataclasses.dataclass()
class _SegmentFactScan8616:
    """Mutable collector for per-block segment fact extraction."""

    accesses: object = field(default_factory=list)
    writes: object = field(default_factory=list)
    instruction_states: object = field(default_factory=list)
    entry_requirements: object = field(default_factory=set)

    @cython.ccall
    def scan(self, block: IRBlock, segment_state: SegmentStateArtifact) -> None:
        """Collect all segment facts owned by one IR block."""
        source: object
        instruction: object
        register: object
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

    @cython.ccall
    def _scan_accesses(
        self,
        block_addr: cython.longlong,
        instruction: IRInstr,
        segment_state: SegmentStateArtifact,
    ) -> None:
        """Collect typed access facts and segment entry requirements."""
        argument: object
        argument_index: object
        register: object
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

    @cython.ccall
    def _scan_write(
        self,
        block_addr: cython.longlong,
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
    *,
    coverage: IRBoundaryCoverageResult8616 | None = None,
) -> SegmentFunctionContract:
    """Build an exact function-local segment contract from typed IR facts."""
    block: object
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
                for fact in iter(writes)
                if fact.kind is SegmentWriteKind.RESTORE and fact.register not in clobbered
            }
        )
    )
    facts = (*accesses, *writes, *instruction_states)
    classified_count = (
        sum(fact.verdict is SegmentFactVerdict.PROVEN for fact in iter(accesses))
        + sum(fact.verdict is SegmentFactVerdict.PROVEN for fact in iter(writes))
        + sum(fact.verdict is SegmentFactVerdict.PROVEN for fact in iter(instruction_states))
    )
    return SegmentFunctionContract(
        function_addr=artifact.function_addr,
        entry_requirements=tuple(sorted(entry_requirements)),
        accesses=tuple(accesses),
        writes=tuple(writes),
        instruction_states=tuple(instruction_states),
        clobbered_registers=clobbered,
        restored_registers=restored,
        effect_closure=None if coverage is None else prove_segment_effect_closure_8616(coverage, segment_state),
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


@cython.ccall
def apply_x86_16_segment_function_contract(project: object, codegen: object) -> cython.bint:
    """Attach a function-local segment contract after typed IR state analysis."""
    exact: object
    function: object
    witness: object
    boundary = cast(_SegmentContractCodegenBoundary, codegen)
    try:
        artifact = boundary._inertia_vex_ir_artifact
        segment_state = boundary._inertia_segment_state_artifact
    except AttributeError:
        return False
    if not isinstance(artifact, IRFunctionArtifact) or not isinstance(segment_state, SegmentStateArtifact):
        return False
    function = function_boundary_at_address_8616(project, artifact.function_addr)
    exact = function if isinstance(function, ExactFunctionRangeBoundary8616) else None
    if exact is None and function is not None:
        witness = capture_function_boundary_8616(project, function)
        if witness is not None:
            exact = restore_function_boundary_8616(project, witness)
    if function is None:
        exact = mapped_entry_function_boundary_8616(project, artifact.function_addr)
    coverage = None if exact is None else prove_ir_boundary_coverage_8616(project, exact, artifact)
    boundary._inertia_segment_function_contract = build_x86_16_segment_function_contract(
        artifact, segment_state, coverage=coverage,
    )
    return False
