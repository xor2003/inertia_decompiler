"""Bind an SSA block's CALL operand producer closure to its owned projection.

Layer: Types/Lowering.
This boundary consumes the IR-owned SSA projection; it does not own SSA
construction. Originally staged under
``.cache/comparator-implementation/call-target-consolidation/`` with a proposed
home in ``ir/`` alongside ``ssa.py``; the current module verifies projection
integrity for the Lowering CALL-target binder.
Responsibility: prove that every instruction transitively producing a CALL's
operands — plus the CALL itself — inside one ``SSABlock`` equals the owned
``build_x86_16_block_local_ssa`` projection of the exact typed ``IRBlock``
that claims to be its source, including operand versions, ``source_tmp``/
``memory_access_insn`` provenance, ``origin`` identity, and the recorded
``bindings``/``refusals`` ledgers.

The check is source-agnostic: the supplied ``IRBlock`` may be a registered
raw artifact block (input/output gates on raw-stage SSA) or the retained
Semantics-enriched ``outputs.function`` block (semantic-stage SSA carrying
``CALL_OUTPUT`` prefixes and ``call_stack_effect`` annotations). No constant
is fabricated, no operand is rewritten, no provenance field is erased to
force a comparison, and no VEX/IR rebuild runs here — the block-local SSA
owner's bounded identity cache is reused.

Permitted projection delta, verified against ``ssa_memory.py``: memory SSA
rewrites only ``IRAddress.version`` on argument atoms in accepted ``SS``
ranges. Every other field must match the projection exactly.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import replace
from enum import StrEnum

from angr_platforms.X86_16.ir import (
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCondition,
    IRInstr,
    IRValue,
    MemSpace,
)
from angr_platforms.X86_16.ir.core import IRActiveUnary8616, IRAtom
from angr_platforms.X86_16.ir.ssa import (
    SSABlock,
    _version_key,
    build_x86_16_block_local_ssa,
)

__all__ = [
    "CallProducerIntegrityFailure8616",
    "call_operand_producer_integrity_8616",
    "ssa_value_modulo_version_8616",
]


class CallProducerIntegrityFailure8616(StrEnum):
    """Stable reasons an SSA block's producer closure is not its projection.

    ``PROJECTION_MISMATCH``: block shape or recorded ledgers disagree with the
    owned projection. ``PRODUCER_AMBIGUOUS``: the projection ledger names two
    producers for one identity. ``PRODUCER_UNBOUND``: a ``TMP`` use resolves
    to no in-block definition. ``PRODUCER_MISMATCH``: a closure instruction
    differs from the projection at its exact position.
    """

    PROJECTION_MISMATCH = "projection_mismatch"
    PRODUCER_AMBIGUOUS = "producer_ambiguous"
    PRODUCER_UNBOUND = "producer_unbound"
    PRODUCER_MISMATCH = "producer_mismatch"


def ssa_value_modulo_version_8616(ssa_value: IRValue, source_value: IRValue) -> bool:
    """Return whether one SSA value is the source value modulo its SSA version.

    ``IRValue`` equality compares every ``compare=True`` field, including the
    nested ``index`` and ``call_output`` provenance; the SSA version is the
    single permitted delta. The compare-exempt provenance fields
    ``source_tmp`` and ``memory_access_insn`` are checked explicitly so a
    foreign temporary identity cannot hide inside an otherwise equal value.
    """
    return _value_matches_projection_8616(
        replace(ssa_value, version=source_value.version), source_value,
    )


def _active_unary_matches_projection_8616(
    actual: IRActiveUnary8616 | None,
    expected: IRActiveUnary8616 | None,
) -> bool:
    """Bind the pending operation and its operand's otherwise equality-exempt provenance."""
    if actual is None or expected is None:
        return actual is expected
    return (
        actual.op == expected.op
        and actual.result_bits == expected.result_bits
        and _value_matches_projection_8616(actual.operand, expected.operand)
    )


def _value_matches_projection_8616(
    ssa_value: IRValue | IRBinaryValue,
    projection_value: IRValue | IRBinaryValue,
) -> bool:
    """Return whether one value tree is exactly the projected counterpart.

    Unlike the CALL-site operand check this comparison is version-exact: both
    sides must be the same owned projection of the same source block. The
    compare-exempt provenance fields ``source_tmp`` and
    ``memory_access_insn`` are checked explicitly at every nesting level so a
    foreign temporary identity cannot hide inside an ``index`` subtree.
    """
    if isinstance(projection_value, IRBinaryValue):
        return bool(
            isinstance(ssa_value, IRBinaryValue)
            and ssa_value.op == projection_value.op
            and ssa_value.size == projection_value.size
            and _value_matches_projection_8616(ssa_value.lhs, projection_value.lhs)
            and _value_matches_projection_8616(ssa_value.rhs, projection_value.rhs)
        )
    if not isinstance(projection_value, IRValue) or not isinstance(ssa_value, IRValue):
        return False
    index_bound = (ssa_value.index is None and projection_value.index is None) or (
        ssa_value.index is not None
        and projection_value.index is not None
        and _value_matches_projection_8616(ssa_value.index, projection_value.index)
    )
    return bool(
        index_bound
        and _active_unary_matches_projection_8616(ssa_value.active_unary, projection_value.active_unary)
        and ssa_value == projection_value
        and ssa_value.source_tmp == projection_value.source_tmp
        and ssa_value.memory_access_insn == projection_value.memory_access_insn
    )


def _atom_matches_projection_8616(ssa_atom: IRAtom, projection_atom: IRAtom) -> bool:
    """Return whether one argument atom matches its owned projection.

    The single permitted delta is the ``version`` field of ``IRAddress``
    atoms: memory SSA rewrites accepted ``SS``-range access addresses in
    place and records every such rewrite in the artifact's typed
    ``memory_accesses`` evidence. Every other field — including the
    condition ``width_bits`` and every compare-exempt value field nested in
    ``IRAddress.base_values`` — must be identical to the projection.
    """
    if isinstance(projection_atom, IRAddress):
        return bool(
            isinstance(ssa_atom, IRAddress)
            and len(ssa_atom.base_values) == len(projection_atom.base_values)
            and replace(ssa_atom, version=projection_atom.version) == projection_atom
            and all(
                _value_matches_projection_8616(ssa_base, projection_base)
                for ssa_base, projection_base in zip(
                    ssa_atom.base_values, projection_atom.base_values, strict=True
                )
            )
        )
    if isinstance(projection_atom, IRCondition):
        return bool(
            isinstance(ssa_atom, IRCondition)
            and ssa_atom.op == projection_atom.op
            and ssa_atom.expr == projection_atom.expr
            and ssa_atom.width_bits == projection_atom.width_bits
            and len(ssa_atom.args) == len(projection_atom.args)
            and all(
                _atom_matches_projection_8616(ssa_arg, projection_arg)
                for ssa_arg, projection_arg in zip(
                    ssa_atom.args, projection_atom.args, strict=True
                )
            )
        )
    if isinstance(projection_atom, (IRValue, IRBinaryValue)):
        return isinstance(ssa_atom, (IRValue, IRBinaryValue)) and (
            _value_matches_projection_8616(ssa_atom, projection_atom)
        )
    return bool(ssa_atom == projection_atom)


def _instr_matches_projection_8616(ssa_instr: IRInstr, projection_instr: IRInstr) -> bool:
    """Return whether one SSA instruction is exactly the projected instruction.

    Identity, effect, and provenance metadata must be identical; ``dst`` and
    ``args`` must match the projection with only the documented memory-SSA
    address-version enrichment permitted inside argument atoms.
    """
    dst_bound = (ssa_instr.dst is None and projection_instr.dst is None) or (
        ssa_instr.dst is not None
        and projection_instr.dst is not None
        and _value_matches_projection_8616(ssa_instr.dst, projection_instr.dst)
    )
    return bool(
        dst_bound
        and ssa_instr.op == projection_instr.op
        and ssa_instr.addr == projection_instr.addr
        and ssa_instr.size == projection_instr.size
        and ssa_instr.call_stack_effect == projection_instr.call_stack_effect
        and ssa_instr.origin == projection_instr.origin
        and len(ssa_instr.args) == len(projection_instr.args)
        and all(
            _atom_matches_projection_8616(ssa_arg, projection_arg)
            for ssa_arg, projection_arg in zip(
                ssa_instr.args, projection_instr.args, strict=True
            )
        )
    )


def _atom_use_values_8616(atom: IRAtom) -> list[IRValue]:
    """Collect every use-position scalar value inside one argument atom.

    Nested indexes, address bases and pending unary operands contribute their
    reaching definitions. A pending unary computation is not itself a captured
    temporary use: its operation is checked by exact projection comparison,
    while its operand supplies the dependency that must be bound.
    """
    values: list[IRValue] = []
    pending: list[IRAtom] = [atom]
    while pending:
        node = pending.pop()
        if isinstance(node, IRValue):
            if node.active_unary is not None:
                pending.append(node.active_unary.operand)
                continue
            values.append(node)
            if node.index is not None:
                pending.append(node.index)
        elif isinstance(node, IRBinaryValue):
            pending.extend((node.lhs, node.rhs))
        elif isinstance(node, IRAddress):
            pending.extend(node.base_values)
        elif isinstance(node, IRCondition):
            pending.extend(node.args)
    return values


_ProducerLedger8616 = tuple[
    dict[int, int],
    dict[tuple[tuple[str, str | None, int], int | None], int],
]


def _producer_ledger_8616(
    projection: SSABlock,
) -> _ProducerLedger8616 | CallProducerIntegrityFailure8616:
    """Index the projection's producers or refuse an ambiguous ledger.

    Temporary uses resolve through their retained VEX ``source_tmp``
    identity, mirroring the Semantics owner's ``_tmp_producers_8616`` ledger;
    every other versioned use resolves through the block's recorded SSA
    ``bindings``. A duplicated producer identity on either axis means the
    projection cannot name a unique definition and is refused.
    """
    tmp_producers: dict[int, int] = {}
    for index, instruction in enumerate(projection.instrs):
        destination = instruction.dst
        if destination is None or destination.source_tmp is None:
            continue
        if destination.source_tmp in tmp_producers:
            return CallProducerIntegrityFailure8616.PRODUCER_AMBIGUOUS
        tmp_producers[destination.source_tmp] = index
    versioned_defs: dict[tuple[tuple[str, str | None, int], int | None], int] = {}
    for binding in projection.bindings:
        key = (_version_key(binding.target), binding.version)
        if key in versioned_defs:
            return CallProducerIntegrityFailure8616.PRODUCER_AMBIGUOUS
        versioned_defs[key] = binding.instr_index
    return tmp_producers, versioned_defs


def _producer_index_8616(
    value: IRValue,
    tmp_producers: dict[int, int],
    versioned_defs: dict[tuple[tuple[str, str | None, int], int | None], int],
) -> int | CallProducerIntegrityFailure8616 | None:
    """Resolve one use value to its in-block producer index, leaf, or refusal.

    ``None`` marks a legitimate leaf: a ``CONST``/``UNKNOWN`` literal or a
    live-in read of storage defined outside the block. A ``TMP``-space use
    that resolves on neither axis has no producer anywhere — the operand's
    dependency cannot be bound, so the obligation refuses.
    """
    if value.source_tmp is not None:
        producer = tmp_producers.get(value.source_tmp)
        return (
            producer
            if producer is not None
            else CallProducerIntegrityFailure8616.PRODUCER_UNBOUND
        )
    if value.space in {MemSpace.CONST, MemSpace.UNKNOWN}:
        return None
    producer = versioned_defs.get((_version_key(value), value.version))
    if producer is None and value.space is MemSpace.TMP:
        return CallProducerIntegrityFailure8616.PRODUCER_UNBOUND
    return producer


def _operand_closure_8616(
    projection: SSABlock,
    call_index: int,
) -> frozenset[int] | CallProducerIntegrityFailure8616:
    """Collect the transitive producer indices feeding the CALL operands.

    The walk runs on the owned projection of the supplied source block —
    never on the artifact's own claims — and returns the instruction indices
    the artifact must reproduce exactly. Producer instructions are followed
    through their argument uses; unresolved ``TMP`` uses refuse rather than
    silently truncating the closure.
    """
    ledger = _producer_ledger_8616(projection)
    if isinstance(ledger, CallProducerIntegrityFailure8616):
        return ledger
    tmp_producers, versioned_defs = ledger
    closure: set[int] = set()
    seen: set[tuple[object, ...]] = set()
    pending = [
        value
        for atom in projection.instrs[call_index].args
        for value in _atom_use_values_8616(atom)
    ]
    while pending:
        value = pending.pop()
        marker = (
            value.space,
            value.name,
            value.offset,
            value.const,
            value.size,
            value.version,
            value.source_tmp,
        )
        if marker in seen:
            continue
        seen.add(marker)
        producer = _producer_index_8616(value, tmp_producers, versioned_defs)
        if isinstance(producer, CallProducerIntegrityFailure8616):
            return producer
        if producer is None or producer in closure:
            continue
        closure.add(producer)
        pending.extend(
            use
            for atom in projection.instrs[producer].args
            for use in _atom_use_values_8616(atom)
        )
    return frozenset(closure)


def _bindings_match_projection_8616(ssa_block: SSABlock, projection: SSABlock) -> bool:
    """Compare binding identities including equality-exempt value provenance."""
    return len(ssa_block.bindings) == len(projection.bindings) and all(
        actual.version == expected.version
        and actual.instr_index == expected.instr_index
        and _value_matches_projection_8616(actual.target, expected.target)
        for actual, expected in zip(ssa_block.bindings, projection.bindings, strict=True)
    )


def call_operand_producer_integrity_8616(
    ssa_block: SSABlock,
    source_block: IRBlock,
    call_index: int,
) -> CallProducerIntegrityFailure8616 | None:
    """Bind the SSA block's CALL operand closure to the source projection.

    ``build_x86_16_block_local_ssa`` is the owned typed projection of the
    supplied source block (identity-cached, no re-lift); the artifact block
    must equal it at every instruction position that transitively produces a
    CALL operand input, and its recorded ``bindings``/``refusals`` ledgers —
    which memory SSA copies verbatim — must equal it everywhere. The CALL
    position itself is rechecked with version-exact operand equality so
    corrupted operand versions cannot slip through a modulo-version
    provenance gate.
    """
    if (
        type(call_index) is not int
        or not 0 <= call_index < len(source_block.instrs)
        or source_block.instrs[call_index].op != "CALL"
    ):
        return CallProducerIntegrityFailure8616.PROJECTION_MISMATCH
    projection = build_x86_16_block_local_ssa(source_block)
    if (
        ssa_block.addr != projection.addr
        or len(ssa_block.instrs) != len(projection.instrs)
        or ssa_block.refusals != projection.refusals
        or not _bindings_match_projection_8616(ssa_block, projection)
    ):
        return CallProducerIntegrityFailure8616.PROJECTION_MISMATCH
    closure = _operand_closure_8616(projection, call_index)
    if isinstance(closure, CallProducerIntegrityFailure8616):
        return closure
    for index in sorted(closure | {call_index}):
        if not _instr_matches_projection_8616(
            ssa_block.instrs[index], projection.instrs[index]
        ):
            return CallProducerIntegrityFailure8616.PRODUCER_MISMATCH
    return None
