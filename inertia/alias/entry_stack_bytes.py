"""Prove exact entry-frame SS byte reads inside one entry-block prefix.

Layer: Alias.
Responsibility: for the unique entry block at ``artifact.function_addr``, decide
whether each LOAD provably reads immutable bytes at exact entry-SP-relative SS
offsets, and emit typed immutable facts plus typed refusals with closed counts.
Owns nothing outside this prefix proof: no whole-function, return-word, callee,
caller-frame, MemorySSA, or admission claims are produced here.

Contract: entry SP is coordinate 0; entry BP is unknown. All frame-coordinate
and producer-identity truth is owned by ``EntryStackPointerSnapshots8616``
(in ``entry_stack_pointer_snapshots.py``, a bounded extension of the shared
``StackPointerSnapshots8616``); this consumer validates and consumes that owner
and never recomputes coordinates. A LOAD is refused after any earlier STORE,
CALL, control transfer, or unrecognized op in this prefix; an ``ss`` register
write forfeits entry-SS identity for all later loads. The proof asserts the
initial invocation only: an incoming edge to the entry block is refused
because one entry coordinate cannot hold on revisits. Byte arithmetic is
modulo 2**16; wrapping multi-byte geometry refuses.

Owns storage identity for proven entry-SP-relative SS byte reads.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.vex_operation_membership import is_registered_vex_operation_8616
from inertia.semantics.register_value_preservation import (
    register_value_family_8616,
)

from .entry_stack_byte_contracts import (
    EntryStackByteProof8616,
    EntryStackByteRead8616,
    EntryStackByteRefusal8616,
    EntryStackByteRefusalKind8616,
    EntryStackByteScope8616,
    EntryStackByteVerdict8616,
)
from .entry_stack_pointer_snapshots import EntryStackPointerSnapshots8616

_WORD_BYTES = 2
_MOD16 = 1 << 16
_SUPPORTED_LOAD_WIDTHS = frozenset({1, 2})
_SCALAR_MOV_SPACES = frozenset({MemSpace.REG, MemSpace.TMP})
_SCALAR_ARG_SPACES = frozenset({MemSpace.REG, MemSpace.TMP, MemSpace.CONST})
_MEMORY_MOV_SPACES = frozenset({MemSpace.SS, MemSpace.DS, MemSpace.ES})
# Ops that transfer control; any later LOAD executes on a different path or
# not at all in entry-prefix terms, so entry-byte origin is refused.
_CONTROL_FLOW_OPS = frozenset({"RET", "CJMP", "JMP", "BRANCH", "CBRANCH", "JUMP", "CJUMP"})
_SS_FAMILY = register_value_family_8616("ss")
# Writes to the program-counter family or cs are control effects in prefix terms.
_CONTROL_REGISTER_FAMILY = register_value_family_8616("ip") | frozenset({"cs"})


@dataclass(slots=True)
class _EntryPrefixState8616:
    """Scan state: the single snapshot owner plus consumer-side effect state.

    ``engine`` is the only owner of frame coordinates and producer evidence.
    ``ss_identity`` and ``closed_by`` are consumer-side prefix effects (segment
    identity and side-effect closure), deliberately not frame coordinates.
    """

    engine: EntryStackPointerSnapshots8616 = field(
        default_factory=EntryStackPointerSnapshots8616
    )
    ss_identity: bool = True
    closed_by: EntryStackByteRefusalKind8616 | None = None


def _scalar_operand_8616(atom: object) -> bool:
    """Return whether an instruction operand is a scalar REG/TMP/CONST value."""
    return isinstance(atom, IRValue) and atom.space in _SCALAR_ARG_SPACES


def _coherent_word_transfer_8616(instr: IRInstr, destination: IRValue) -> bool:
    """Return whether a MOV has one scalar source and agreeing widths."""
    if len(instr.args) != 1:
        return False
    source = instr.args[0]
    return (
        isinstance(source, IRValue)
        and _scalar_operand_8616(source)
        and destination.size == instr.size
        and source.size == instr.size
    )


def _side_effect_kind_8616(instr: IRInstr) -> EntryStackByteRefusalKind8616 | None:
    """Classify non-LOAD ops: pure value ops stay open; anything else closes.

    Pure-IR contract: ``MOV`` is pure only for a supported scalar destination
    (REG/TMP), exactly one scalar source, and agreeing source/destination/
    instruction widths; memory-space destinations are writes that close the
    prefix and any other shape is unknown. ``Iop_*`` ops are pure only when
    actually registered in the VEX operation enum AND carrying the documented
    importer shape — a scalar REG/TMP destination whose width matches the
    instruction and only scalar operands; registered membership alone is not
    destination or operand-shape evidence, and a destination-less ``Iop_*``
    contradicts the importer's WrTmp-only contract. STORE and CALL touch
    memory or a callee; control ops end the prefix path; anything
    unrecognized refuses explicitly.
    """
    if instr.op == "STORE":
        return EntryStackByteRefusalKind8616.PRIOR_MEMORY_WRITE
    if instr.op == "CALL":
        return EntryStackByteRefusalKind8616.PRIOR_CALL
    if instr.op in _CONTROL_FLOW_OPS:
        return EntryStackByteRefusalKind8616.PRIOR_CONTROL_FLOW
    if instr.op == "MOV":
        destination = instr.dst
        if isinstance(destination, IRValue) and destination.space in _MEMORY_MOV_SPACES:
            return EntryStackByteRefusalKind8616.PRIOR_MEMORY_WRITE
        if (
            not isinstance(destination, IRValue)
            or destination.space not in _SCALAR_MOV_SPACES
            or not _coherent_word_transfer_8616(instr, destination)
        ):
            return EntryStackByteRefusalKind8616.PRIOR_UNKNOWN_OPERATION
        return None
    if instr.op.startswith("Iop_"):
        destination = instr.dst
        if isinstance(destination, IRValue) and destination.space in _MEMORY_MOV_SPACES:
            return EntryStackByteRefusalKind8616.PRIOR_MEMORY_WRITE
        if (
            not is_registered_vex_operation_8616(instr.op)
            or not isinstance(destination, IRValue)
            or destination.space not in _SCALAR_MOV_SPACES
            or destination.size != instr.size
            or not all(
                _scalar_operand_8616(arg) for arg in instr.args
            )
        ):
            return EntryStackByteRefusalKind8616.PRIOR_UNKNOWN_OPERATION
        return None
    return EntryStackByteRefusalKind8616.PRIOR_UNKNOWN_OPERATION


def _load_shape_refusal_8616(
    state: _EntryPrefixState8616, instr: IRInstr, block_addr: int, instr_index: int,
) -> EntryStackByteRefusal8616 | None:
    """Refuse a LOAD closed by a prior side effect or of malformed shape."""
    if state.closed_by is not None:
        return EntryStackByteRefusal8616(
            state.closed_by, "entry-byte proof closed by an earlier prefix side effect",
            block_addr, instr_index)
    dst = instr.dst
    if not isinstance(dst, IRValue) or dst.space is not MemSpace.TMP or dst.source_tmp is None:
        return EntryStackByteRefusal8616(
            EntryStackByteRefusalKind8616.BAD_DESTINATION,
            "LOAD destination is not a typed temporary with an observed producer",
            block_addr, instr_index)
    if len(instr.args) != 1 or not isinstance(instr.args[0], IRAddress):
        return EntryStackByteRefusal8616(
            EntryStackByteRefusalKind8616.BAD_ADDRESS_ARGUMENT,
            "LOAD does not carry exactly one typed address argument",
            block_addr, instr_index)
    return None


def _load_address_refusal_8616(
    state: _EntryPrefixState8616, instr: IRInstr, dst: IRValue, address: IRAddress,
    block_addr: int, instr_index: int,
) -> EntryStackByteRefusal8616 | None:
    """Refuse a LOAD whose typed address or width evidence is not entry-SS-exact."""

    def refuse(kind: EntryStackByteRefusalKind8616, detail: str) -> EntryStackByteRefusal8616:
        return EntryStackByteRefusal8616(kind, detail, block_addr, instr_index)

    if address.space is not MemSpace.SS:
        return refuse(EntryStackByteRefusalKind8616.NON_SS_ADDRESS, "LOAD address is not SS space")
    if not state.ss_identity:
        return refuse(
            EntryStackByteRefusalKind8616.SS_IDENTITY_LOST,
            "an earlier ss write forfeited entry-SS identity in this prefix")
    if address.status is not AddressStatus.STABLE:
        return refuse(EntryStackByteRefusalKind8616.UNSTABLE_ADDRESS, "LOAD address is not stable")
    if address.segment_origin is not SegmentOrigin.PROVEN:
        return refuse(
            EntryStackByteRefusalKind8616.UNPROVEN_SEGMENT, "SS segment choice is not proven")
    if instr.size not in _SUPPORTED_LOAD_WIDTHS:
        return refuse(
            EntryStackByteRefusalKind8616.UNSUPPORTED_WIDTH,
            "only 1- or 2-byte loads are supported")
    if address.size != instr.size or dst.size != instr.size:
        return refuse(
            EntryStackByteRefusalKind8616.WIDTH_DISAGREEMENT,
            "address, instruction, and destination widths disagree")
    return None


def _classify_load_8616(
    state: _EntryPrefixState8616, instr: IRInstr, block_addr: int, instr_index: int,
) -> EntryStackByteRead8616 | EntryStackByteRefusal8616:
    """Materialize one LOAD fact or return its first typed refusal."""
    refusal = _load_shape_refusal_8616(state, instr, block_addr, instr_index)
    if refusal is not None:
        return refusal
    dst = instr.dst
    assert isinstance(dst, IRValue) and dst.source_tmp is not None
    address = instr.args[0]
    assert isinstance(address, IRAddress)
    refusal = _load_address_refusal_8616(state, instr, dst, address, block_addr, instr_index)
    if refusal is not None:
        return refusal
    base = state.engine.strict_address_base(address)
    if base is None:
        return EntryStackByteRefusal8616(
            EntryStackByteRefusalKind8616.MISSING_FRAME_BASE,
            "SS address has no word-exact captured sp/bp base", block_addr, instr_index)
    base_value = address.base_values[0] if address.base_values else None
    base_producer = (
        None
        if base_value is None or base_value.source_tmp is None
        else state.engine.producers.get(base_value.source_tmp)
    )
    start = (base.entry_sp_offset + address.offset) % _MOD16
    if start + instr.size > _MOD16:
        return EntryStackByteRefusal8616(
            EntryStackByteRefusalKind8616.WRAP_GEOMETRY,
            "byte range wraps the 16-bit entry frame", block_addr, instr_index)
    return EntryStackByteRead8616(
        block_addr=block_addr,
        instr_index=instr_index,
        instruction_addr=instr.addr,
        producer_tmp=dst.source_tmp,
        base_producer_tmp=None if base_producer is None else base_producer.tmp,
        base_producer_index=None if base_producer is None else base_producer.instr_index,
        base_register=base.register,
        base_entry_sp_offset=base.entry_sp_offset,
        address_offset=address.offset,
        byte_offsets=tuple(range(start, start + instr.size)),
        width=instr.size,
    )


def _is_normalized_load_8616(instr: IRInstr) -> bool:
    """Return whether a LOAD has the typed TMP dst and single-address shape."""
    return (
        isinstance(instr.dst, IRValue)
        and instr.dst.space is MemSpace.TMP
        and instr.dst.source_tmp is not None
        and len(instr.args) == 1
        and isinstance(instr.args[0], IRAddress)
    )


def _refused_proof(
    artifact: IRFunctionArtifact,
    refusals: list[EntryStackByteRefusal8616],
    *,
    raw: int = 0,
    normalized: int = 0,
    closed_by: EntryStackByteRefusalKind8616 | None = None,
) -> EntryStackByteProof8616:
    """Assemble a REFUSED result with closed counts and no materialized facts."""
    return EntryStackByteProof8616(
        artifact=artifact,
        verdict=EntryStackByteVerdict8616.REFUSED,
        refusals=tuple(refusals),
        prefix_closed_by=closed_by,
        raw_fact_count=raw,
        normalized_fact_count=normalized,
        classified_fact_count=raw,
        failure_count=len(refusals),
    )


def _observe_8616(state: _EntryPrefixState8616, instr: IRInstr, index: int) -> None:
    """Advance the snapshot owner and consumer-side effects across one instr."""
    state.engine.observe_entry_instruction(instr, index)
    dst = instr.dst
    if not isinstance(dst, IRValue) or dst.space is not MemSpace.REG or dst.name is None:
        return
    if dst.name in _SS_FAMILY:
        state.ss_identity = False
    if dst.name in _CONTROL_REGISTER_FAMILY and state.closed_by is None:
        state.closed_by = EntryStackByteRefusalKind8616.PRIOR_CONTROL_FLOW


def _structural_proof_refusal_8616(
    artifact: IRFunctionArtifact, block: IRBlock, raw: int, normalized: int,
) -> EntryStackByteProof8616 | None:
    """Return a refused proof when entry scope or raw-IR trust fails.

    An incoming edge to the entry block forfeits the initial-invocation scope:
    one entry-SP coordinate cannot be asserted on loop revisits. Raw IR
    refusals on the artifact or entry block make the whole stream untrusted and
    are recorded structurally even with zero LOAD candidates, plus one refusal
    per candidate to keep classified accounting closed.
    """
    if any(
        artifact.function_addr in other.successor_addrs for other in artifact.blocks
    ):
        return _refused_proof(
            artifact,
            [
                EntryStackByteRefusal8616(
                    EntryStackByteRefusalKind8616.ENTRY_REENTRY,
                    "entry block has an incoming edge; the initial-entry "
                    "coordinate cannot be asserted on revisits",
                    block.addr,
                )
            ],
            raw=raw,
            normalized=normalized,
            closed_by=EntryStackByteRefusalKind8616.ENTRY_REENTRY,
        )
    if not artifact.refusals and not block.refusals:
        return None
    raw_ir_refusals = [
        EntryStackByteRefusal8616(
            EntryStackByteRefusalKind8616.RAW_IR_REFUSAL,
            "entry block or artifact carries raw IR refusals; the "
            "instruction stream is not trusted",
            block.addr,
        )
    ]
    raw_ir_refusals += [
        EntryStackByteRefusal8616(
            EntryStackByteRefusalKind8616.RAW_IR_REFUSAL,
            "entry prefix carries raw IR refusals; instruction stream is not trusted",
            block.addr,
            index,
        )
        for index, instr in enumerate(block.instrs)
        if instr.op == "LOAD"
    ]
    return _refused_proof(
        artifact, raw_ir_refusals, raw=raw, normalized=normalized,
        closed_by=EntryStackByteRefusalKind8616.RAW_IR_REFUSAL,
    )


def prove_entry_stack_bytes_8616(artifact: IRFunctionArtifact) -> EntryStackByteProof8616:
    """Prove exact entry-SS byte reads in the unique entry block's prefix."""
    entries = [block for block in artifact.blocks if block.addr == artifact.function_addr]
    if len(entries) != 1:
        kind = (
            EntryStackByteRefusalKind8616.MISSING_ENTRY_BLOCK
            if not entries
            else EntryStackByteRefusalKind8616.DUPLICATE_ENTRY_BLOCK
        )
        refusal = EntryStackByteRefusal8616(
            kind, f"expected exactly one entry block at {artifact.function_addr:#x}"
        )
        return _refused_proof(artifact, [refusal])
    block = entries[0]
    raw = sum(1 for instr in block.instrs if instr.op == "LOAD")
    normalized = sum(
        1 for instr in block.instrs if instr.op == "LOAD" and _is_normalized_load_8616(instr)
    )
    structural = _structural_proof_refusal_8616(artifact, block, raw, normalized)
    if structural is not None:
        return structural
    state = _EntryPrefixState8616()
    facts: list[EntryStackByteRead8616] = []
    refusals: list[EntryStackByteRefusal8616] = []
    for index, instr in enumerate(block.instrs):
        if instr.op == "LOAD":
            outcome = _classify_load_8616(state, instr, block.addr, index)
            if isinstance(outcome, EntryStackByteRead8616):
                facts.append(outcome)
            else:
                refusals.append(outcome)
        elif state.closed_by is None:
            state.closed_by = _side_effect_kind_8616(instr)
        _observe_8616(state, instr, index)
    materialized = len(facts)
    if raw == 0:
        refusals.append(
            EntryStackByteRefusal8616(
                EntryStackByteRefusalKind8616.NO_LOAD_CANDIDATES,
                "entry block prefix contains no LOAD candidates",
                block.addr,
            )
        )
    if materialized == 0:
        verdict = EntryStackByteVerdict8616.REFUSED
    elif materialized == raw:
        verdict = EntryStackByteVerdict8616.PROVEN
    else:
        verdict = EntryStackByteVerdict8616.PARTIAL
    return EntryStackByteProof8616(
        artifact=artifact,
        verdict=verdict,
        facts=tuple(facts),
        refusals=tuple(refusals),
        prefix_closed_by=state.closed_by,
        raw_fact_count=raw,
        normalized_fact_count=normalized,
        classified_fact_count=raw,
        materialized_count=materialized,
        failure_count=len(refusals),
    )


__all__ = [
    "EntryStackByteProof8616",
    "EntryStackByteRead8616",
    "EntryStackByteRefusal8616",
    "EntryStackByteRefusalKind8616",
    "EntryStackByteScope8616",
    "EntryStackByteVerdict8616",
    "prove_entry_stack_bytes_8616",
]
