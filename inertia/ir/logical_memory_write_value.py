"""Prove values written by exact logical word memory accesses.

Layer: IR.
Responsibility: prove immediate and old-word-plus-one values for exact logical word WRITE slices and proof sites.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from . import logical_memory_contracts as logical
from . import scalar_definitions as scalar_defs
from .core import IRAddress, IRValue, MemSpace
from .indexed_address_contracts import IndexedAddressDefinitionSite8616
from .logical_constant_word_receipt import (
    LogicalConstantWordReceipt8616,
    prove_logical_constant_word_write_8616,
)
from .logical_memory_value_trace import LogicalMemoryValueTrace8616, trace_logical_word_load_8616
from .scalar_value_projection import scalar_active_unary_projection_8616
from .ssa import SSABlock
from .ssa_function import SSAFunctionArtifact

__all__ = [
    "LogicalWordWriteLaneProof8616", "LogicalWordWriteValueArtifact8616",
    "LogicalWordWriteValueFact8616", "LogicalWordWriteValueFailureKind8616", "LogicalWordWriteValueKind8616",
    "LogicalWordWriteValueRefusal8616", "trace_logical_word_write_values_8616",
]


class LogicalWordWriteValueKind8616(StrEnum):
    """Bounded logical word values proven by this prerequisite."""
    CONSTANT_ZERO = "constant_zero"
    CONSTANT_WORD = "constant_word"
    REPLAYED_CONSTANT_WORD = "replayed_constant_word"
    OLD_LOGICAL_WORD_PLUS_ONE = "old_logical_word_plus_one"


class LogicalWordWriteValueFailureKind8616(StrEnum):
    """Stable reason one logical word WRITE value cannot be proven."""
    LOGICAL_MEMORY_MISSING = "logical_memory_missing"
    LOGICAL_MEMORY_OPEN = "logical_memory_open"
    LOGICAL_ACCESS_CONFLICT = "logical_access_conflict"
    MISSING_LANE = "missing_lane"
    LANE_CONFLICT = "lane_conflict"
    MIXED_INSTRUCTION = "mixed_instruction"
    STORE_VALUE_MISSING = "store_value_missing"
    DEFINITION_MISSING = "definition_missing"
    DEFINITION_CONFLICT = "definition_conflict"
    UNKNOWN_EXPRESSION = "unknown_expression"
    SOURCE_ACCESS_CONFLICT = "source_access_conflict"


_Failure = LogicalWordWriteValueFailureKind8616
_Kind = LogicalWordWriteValueKind8616
type _ProofSites8616 = tuple[IndexedAddressDefinitionSite8616, ...]


@dataclass(frozen=True, slots=True)
class LogicalWordWriteLaneProof8616:
    """One exact STORE slice, stored byte value, and scalar proof path."""
    execution_slice: logical.IRMemoryExecutionSlice8616
    stored_value: IRValue
    proof_sites: _ProofSites8616
    source_constant_root: int | None = None
    extracted_word: bool = False
    shifted_high: bool = False


@dataclass(frozen=True, slots=True)
class LogicalWordWriteValueFact8616:
    """One proven word WRITE retaining all destination and source evidence."""
    access: logical.IRLogicalMemoryAccess8616
    kind: LogicalWordWriteValueKind8616
    constant: int
    lanes: tuple[LogicalWordWriteLaneProof8616, LogicalWordWriteLaneProof8616]
    source_expression_site: IndexedAddressDefinitionSite8616 | None = None
    source_trace: LogicalMemoryValueTrace8616 | None = None
    constant_receipt: LogicalConstantWordReceipt8616 | None = None

    @property
    def is_constant(self) -> bool:
        """Classify constant value kinds; callers must separately prove completeness."""
        return self.kind in {_Kind.CONSTANT_ZERO, _Kind.CONSTANT_WORD, _Kind.REPLAYED_CONSTANT_WORD}

    @property
    def proves_constant_zero(self) -> bool:
        """Consume either immediate or replayed evidence for the zero value."""
        return self.is_constant and self.constant == 0 and self.complete

    @property
    def complete(self) -> bool:
        """Return whether access, lanes, and optional old-word proof agree."""
        base = self.access.complete and self.access.kind is logical.IRMemoryAccessKind8616.WRITE
        base = base and self.access.address.size == 2
        base = base and tuple(lane.execution_slice for lane in self.lanes) == self.access.execution_slices
        base = base and all(lane.stored_value.size == 1 and all(site.complete for site in lane.proof_sites)
                            for lane in self.lanes)
        zero = self.constant == 0 and self.source_expression_site is None and self.source_trace is None
        low, high = self.lanes
        receipt = self.constant_receipt
        if self.kind is _Kind.REPLAYED_CONSTANT_WORD:
            sources = None if receipt is None else receipt.stored_values
            return bool(
                base and type(self.constant) is int and receipt is not None
                and receipt.matches_access(self.access) and sources is not None
                and self.constant == receipt.constant
                and low.stored_value is sources[0] and high.stored_value is sources[1]
                and self.source_expression_site is None and self.source_trace is None
            )
        if receipt is not None or type(self.constant) is not int:
            return False
        constant_word = (
            0 < self.constant <= 0xFFFF
            and self.source_expression_site is None
            and self.source_trace is None
            and low.source_constant_root == self.constant
            and high.source_constant_root == self.constant
            and low.extracted_word
            and not low.shifted_high
            and high.extracted_word
            and high.shifted_high
        )
        site, trace = self.source_expression_site, self.source_trace
        old_plus_one = bool(self.constant == 1 and site is not None and site.complete and trace is not None
                            and trace.complete and trace.source == self.access.address)
        return base and ((self.kind is _Kind.CONSTANT_ZERO and zero)
                         or (self.kind is _Kind.CONSTANT_WORD and constant_word)
                         or (self.kind is _Kind.OLD_LOGICAL_WORD_PLUS_ONE and old_plus_one))


@dataclass(frozen=True, slots=True)
class LogicalWordWriteValueRefusal8616:
    """One candidate, every available proof site, and a typed refusal."""
    access: logical.IRLogicalMemoryAccess8616 | None
    failure: LogicalWordWriteValueFailureKind8616
    proof_sites: _ProofSites8616 = ()
    constant_receipt: LogicalConstantWordReceipt8616 | None = None


@dataclass(frozen=True, slots=True)
class LogicalWordWriteValueArtifact8616:
    """Function-wide logical word WRITE facts with closed five counters."""
    function_addr: int
    facts: tuple[LogicalWordWriteValueFact8616, ...]
    refusals: tuple[LogicalWordWriteValueRefusal8616, ...]
    stats: logical.IRLogicalMemoryStats8616

    @property
    def closed(self) -> bool:
        """Return whether every candidate has one coherent outcome."""
        return bool(self.stats.closed and len(self.facts) == self.stats.materialized_count
                    and len(self.refusals) == self.stats.failure_count and all(fact.complete for fact in self.facts))


@dataclass(frozen=True, slots=True)
class _LaneTrace8616:
    """Internal lane root used to prove convergence."""
    proof: LogicalWordWriteLaneProof8616
    constant: int | None
    root: scalar_defs.ScalarDefinition8616 | None
    saw_extract: bool
    saw_shift: bool


class _TraceFailure8616(Exception):
    """Internal structured refusal carrying partial proof sites."""

    def __init__(self, failure: LogicalWordWriteValueFailureKind8616, sites: _ProofSites8616 = ()) -> None:
        """Initialize one internal refusal without losing evidence."""
        super().__init__(failure.value)
        self.failure = failure
        self.sites = sites


def _require_8616(condition: bool, failure: LogicalWordWriteValueFailureKind8616,
                  sites: _ProofSites8616 = ()) -> None:
    """Raise one typed internal refusal when an invariant is absent."""
    if not condition:
        raise _TraceFailure8616(failure, sites)


def _definition_site_8616(definition: scalar_defs.ScalarDefinition8616) -> IndexedAddressDefinitionSite8616:
    """Return one exact scalar definition site or refuse missing identity."""
    instruction = definition.instruction
    _require_8616(instruction.addr is not None, _Failure.UNKNOWN_EXPRESSION)
    assert instruction.addr is not None
    return IndexedAddressDefinitionSite8616(
        definition.block_addr, definition.instr_index, instruction.addr, instruction.op
    )


def _stored_projection_operand_8616(value: IRValue, sites: _ProofSites8616) -> IRValue:
    """Follow one authenticated pending word extraction without losing capture identity."""
    unary = value.active_unary
    if unary is None:
        return value
    projection = scalar_active_unary_projection_8616(value)
    _require_8616(
        projection is not None and (projection.source_bits, projection.target_bits) == (16, 8),
        _Failure.UNKNOWN_EXPRESSION,
        sites,
    )
    _require_8616(unary.operand.active_unary is None, _Failure.UNKNOWN_EXPRESSION, sites)
    return unary.operand


def _trace_lane_8616(
    block: SSABlock,
    execution_slice: logical.IRMemoryExecutionSlice8616,
    definitions: scalar_defs.ScalarDefinitionIndex8616,
) -> _LaneTrace8616:
    """Trace one STORE byte to its 16-bit constant root or word ADD definition."""
    index = execution_slice.instr_index
    _require_8616(0 <= index < len(block.instrs), _Failure.STORE_VALUE_MISSING)
    store = block.instrs[index]
    _require_8616(store.op == "STORE" and store.size == 1 and len(store.args) == 2, _Failure.STORE_VALUE_MISSING)
    address, stored = store.args
    address_matches = (isinstance(address, IRAddress) and address.size == execution_slice.address.size == 1
                       and logical.logical_memory_execution_address_matches_8616(address, execution_slice.address, 0, 32))
    _require_8616(address_matches, _Failure.LOGICAL_ACCESS_CONFLICT)
    _require_8616(isinstance(stored, IRValue) and stored.size == 1, _Failure.STORE_VALUE_MISSING)
    assert isinstance(stored, IRValue)
    current, before = stored, index
    sites: list[IndexedAddressDefinitionSite8616] = []
    seen: set[tuple[str, str | None, int, int, int | None]] = set()
    saw_extract, saw_shift = current.expr == ("Iop_16to8",), False
    while True:
        saw_extract |= current.active_unary is not None
        current = _stored_projection_operand_8616(current, tuple(sites))
        if current.space is MemSpace.CONST:
            break
        key = scalar_defs.scalar_definition_key_8616(current)
        _require_8616(key not in seen, _Failure.DEFINITION_CONFLICT, tuple(sites))
        seen.add(key)
        found = scalar_defs.reaching_scalar_definitions_8616(
            definitions, current, block_addr=block.addr, before_index=before
        )
        failure = _Failure.DEFINITION_MISSING if not found else _Failure.DEFINITION_CONFLICT
        _require_8616(len(found) == 1, failure, tuple(sites))
        definition = found[0]
        sites.append(_definition_site_8616(definition))
        operation = definition.instruction
        if operation.op == "Iop_Add16":
            proof = LogicalWordWriteLaneProof8616(execution_slice, stored, tuple(sites))
            return _LaneTrace8616(proof, None, definition, saw_extract, saw_shift)
        if operation.op == "MOV" and len(operation.args) == 1 and isinstance(operation.args[0], IRValue):
            current, before = operation.args[0], definition.instr_index
            saw_extract |= current.expr == ("Iop_16to8",)
            continue
        if operation.op == "Iop_Shr16" and len(operation.args) == 2 and not saw_shift:
            source, amount = operation.args
            if (
                execution_slice.source_byte_offset == 1
                and isinstance(source, IRValue)
                and isinstance(amount, IRValue)
                and amount.space is MemSpace.CONST
                and amount.const == 8
            ):
                current, before, saw_shift = source, definition.instr_index, True
                continue
        raise _TraceFailure8616(_Failure.UNKNOWN_EXPRESSION, tuple(sites))
    _require_8616(current.const is not None, _Failure.UNKNOWN_EXPRESSION, tuple(sites))
    proof = LogicalWordWriteLaneProof8616(
        execution_slice,
        stored,
        tuple(sites),
        source_constant_root=current.const,
        extracted_word=saw_extract,
        shifted_high=saw_shift,
    )
    return _LaneTrace8616(proof, current.const, None, saw_extract, saw_shift)


def _trace_increment_8616(
    access: logical.IRLogicalMemoryAccess8616,
    lanes: tuple[_LaneTrace8616, _LaneTrace8616],
    definitions: scalar_defs.ScalarDefinitionIndex8616,
    logical_memory: logical.IRLogicalMemoryArtifact8616,
) -> LogicalWordWriteValueFact8616:
    """Prove that two STORE lanes are the same old logical word plus one."""
    low, high = lanes
    _require_8616(
        low.root is not None
        and high.root is not None
        and (low.root.block_addr, low.root.instr_index) == (high.root.block_addr, high.root.instr_index)
        and low.saw_extract
        and not low.saw_shift
        and high.saw_extract
        and high.saw_shift,
        _Failure.LANE_CONFLICT,
    )
    assert low.root is not None
    add = low.root
    constants = tuple(
        arg for arg in add.instruction.args if isinstance(arg, IRValue) and arg.space is MemSpace.CONST
    )
    sources = tuple(
        arg for arg in add.instruction.args if isinstance(arg, IRValue) and arg.space is not MemSpace.CONST
    )
    _require_8616(
        add.instruction.size == 2 and len(constants) == 1 and constants[0].const == 1 and len(sources) == 1,
        _Failure.UNKNOWN_EXPRESSION,
    )
    source_defs = scalar_defs.reaching_scalar_definitions_8616(
        definitions, sources[0], block_addr=add.block_addr, before_index=add.instr_index
    )
    failure = _Failure.DEFINITION_MISSING if not source_defs else _Failure.DEFINITION_CONFLICT
    _require_8616(len(source_defs) == 1, failure)
    source_definition = source_defs[0]
    source_site = _definition_site_8616(source_definition)
    _require_8616(
        source_definition.instruction.op == "Iop_Or16",
        _Failure.UNKNOWN_EXPRESSION,
    )
    trace = trace_logical_word_load_8616(
        source_definition.instruction,
        definitions,
        logical_memory,
        function_addr=access.key.function_addr,
        block_addr=add.block_addr,
        before_index=source_definition.instr_index,
    )
    source_sites = (source_site, *trace.definition_path)
    _require_8616(
        trace.complete and trace.source == access.address,
        _Failure.SOURCE_ACCESS_CONFLICT,
        source_sites,
    )
    _require_8616(
        all(
            site.block_addr == access.key.block_addr and site.instr_addr == access.key.insn_addr
            for site in trace.definition_path
        ),
        _Failure.MIXED_INSTRUCTION,
        source_sites,
    )
    proofs = (low.proof, high.proof)
    return LogicalWordWriteValueFact8616(
        access, _Kind.OLD_LOGICAL_WORD_PLUS_ONE, 1, proofs, source_site, trace
    )


def _trace_access_8616(
    access: logical.IRLogicalMemoryAccess8616,
    blocks: dict[int, SSABlock],
    definitions: scalar_defs.ScalarDefinitionIndex8616,
    logical_memory: logical.IRLogicalMemoryArtifact8616,
) -> LogicalWordWriteValueFact8616 | LogicalWordWriteValueRefusal8616:
    """Close one logical word WRITE as a fact or refusal."""
    lanes: list[_LaneTrace8616] = []
    try:
        slices = access.execution_slices
        offsets = tuple(item.source_byte_offset for item in slices)
        _require_8616(
            len(slices) >= 2 and set(offsets) == {0, 1}, _Failure.MISSING_LANE
        )
        _require_8616(
            len(slices) == 2 and offsets == (0, 1), _Failure.LANE_CONFLICT
        )
        _require_8616(
            all(item.block_addr == access.key.block_addr and item.insn_addr == access.key.insn_addr for item in slices),
            _Failure.MIXED_INSTRUCTION,
        )
        _require_8616(
            all(
                logical.logical_memory_execution_address_matches_8616(
                    item.address, access.address, item.source_byte_offset, access.address_bits
                )
                for item in slices
            ),
            _Failure.LOGICAL_ACCESS_CONFLICT,
        )
        block = blocks.get(access.key.block_addr)
        _require_8616(block is not None, _Failure.LOGICAL_ACCESS_CONFLICT)
        assert block is not None
        lanes.extend(_trace_lane_8616(block, item, definitions) for item in slices)
        _require_8616(
            all(
                site.block_addr == access.key.block_addr and site.instr_addr == access.key.insn_addr
                for lane in lanes
                for site in lane.proof.proof_sites
            ),
            _Failure.MIXED_INSTRUCTION,
        )
        _require_8616(logical_memory.closed, _Failure.LOGICAL_MEMORY_OPEN)
        pair = (lanes[0], lanes[1])
        if tuple(lane.constant for lane in pair) == (0, 0):
            return LogicalWordWriteValueFact8616(access, _Kind.CONSTANT_ZERO, 0, (pair[0].proof, pair[1].proof))
        low, high = pair
        immediate_word = (
            low.root is None
            and high.root is None
            and isinstance(low.constant, int)
            and 0 < low.constant <= 0xFFFF
            and high.constant == low.constant
            and low.saw_extract
            and not low.saw_shift
            and high.saw_extract
            and high.saw_shift
        )
        if immediate_word and isinstance(low.constant, int):
            return LogicalWordWriteValueFact8616(
                access, _Kind.CONSTANT_WORD, low.constant, (low.proof, high.proof)
            )
        return _trace_increment_8616(access, pair, definitions, logical_memory)
    except _TraceFailure8616 as failure:
        sites = tuple(site for lane in lanes for site in lane.proof.proof_sites)
        return LogicalWordWriteValueRefusal8616(access, failure.failure, (*sites, *failure.sites))


def _close_word_write_8616(
    artifact: SSAFunctionArtifact, access: logical.IRLogicalMemoryAccess8616,
    blocks: dict[int, SSABlock], definitions: scalar_defs.ScalarDefinitionIndex8616,
    memory: logical.IRLogicalMemoryArtifact8616,
) -> LogicalWordWriteValueFact8616 | LogicalWordWriteValueRefusal8616:
    """Keep atomic update proofs strict; replay exact values at the refused boundary."""
    outcome = _trace_access_8616(access, blocks, definitions, memory)
    if not isinstance(outcome, LogicalWordWriteValueRefusal8616) or outcome.failure is not _Failure.MIXED_INSTRUCTION:
        return outcome
    receipt = prove_logical_constant_word_write_8616(artifact, access)
    sources = receipt.stored_values
    if not receipt.complete or sources is None:
        return replace(outcome, constant_receipt=receipt)
    assert receipt.constant is not None
    lanes = (LogicalWordWriteLaneProof8616(access.execution_slices[0], sources[0], ()),
             LogicalWordWriteLaneProof8616(access.execution_slices[1], sources[1], ()))
    return LogicalWordWriteValueFact8616(
        access, _Kind.REPLAYED_CONSTANT_WORD, receipt.constant, lanes, constant_receipt=receipt,
    )


def trace_logical_word_write_values_8616(artifact: SSAFunctionArtifact) -> LogicalWordWriteValueArtifact8616:
    """Trace every logical word WRITE in one function with closed accounting."""
    logical_memory = artifact.logical_memory
    if logical_memory is None or logical_memory.function_addr != artifact.function_addr:
        refusal = LogicalWordWriteValueRefusal8616(None, _Failure.LOGICAL_MEMORY_MISSING)
        return LogicalWordWriteValueArtifact8616(
            artifact.function_addr, (), (refusal,), logical.IRLogicalMemoryStats8616(1, 1, 1, 0, 1)
        )
    candidates = tuple(access for access in logical_memory.accesses
                       if access.kind is logical.IRMemoryAccessKind8616.WRITE and access.address.size == 2)
    grouped: dict[int, list[SSABlock]] = {}
    for block in artifact.blocks:
        grouped.setdefault(block.addr, []).append(block)
    blocks = {address: items[0] for address, items in grouped.items() if len(items) == 1}
    definitions = scalar_defs.build_scalar_definition_index_8616(artifact)
    outcomes = tuple(_close_word_write_8616(artifact, access, blocks, definitions, logical_memory)
                     for access in candidates)
    facts = tuple(item for item in outcomes if isinstance(item, LogicalWordWriteValueFact8616))
    refusals = tuple(item for item in outcomes if isinstance(item, LogicalWordWriteValueRefusal8616))
    count = len(candidates)
    stats = logical.IRLogicalMemoryStats8616(count, count, count, len(facts), len(refusals))
    return LogicalWordWriteValueArtifact8616(artifact.function_addr, facts, refusals, stats)
