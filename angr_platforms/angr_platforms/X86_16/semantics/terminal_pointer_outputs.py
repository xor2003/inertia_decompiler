"""Classify exact pointer-relative storage reaching function returns.

Layer: Semantics.
Responsibility: prove whether each stable versioned DS/ES pointer STORE is
definitely written on every entry-reachable return path while retaining all
store sites. Consumes typed function SSA and structured instruction decoding.
This module does not create Alias identities, choose C types, mutate prototypes,
or render C. Direct DS/ES storage and SS storage remain outside this producer.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import Any, cast

from angr.errors import SimEngineError, SimTranslationError

from ..frontend_instruction_reachability import decoded_block_instructions_8616
from ..ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from ..ir.ssa_function import SSAFunctionArtifact
from .terminal_pointer_output_contracts import (
    PointerOutputKey8616,
    TerminalPointerOutputDisposition8616,
    TerminalPointerOutputEvidence8616,
    TerminalPointerOutputFact8616,
    TerminalPointerOutputFailure8616,
    TerminalPointerOutputStats8616,
    TerminalPointerStoreSite8616,
)


def _stable_proven_address_8616(address: IRAddress) -> bool:
    """Return whether one address is a stable proven DS/ES store target."""
    return (
        address.space in {MemSpace.DS, MemSpace.ES}
        and address.status is AddressStatus.STABLE
        and address.segment_origin is SegmentOrigin.PROVEN
        and address.size > 0
    )


def _pointer_address_8616(
    address: IRAddress,
) -> tuple[PointerOutputKey8616, IRValue] | None:
    """Return one exact stable DS/ES address with one versioned register base."""
    if not _stable_proven_address_8616(address) or len(address.base) != 1 or len(address.base_values) != 1:
        return None
    base_value = address.base_values[0]
    if (
        base_value.space is not MemSpace.REG
        or base_value.name is None
        or base_value.version is None
        or address.base != (base_value.name,)
    ):
        return None
    key: PointerOutputKey8616 = (
        address.space,
        base_value.name,
        base_value.version,
        address.offset,
        address.size,
    )
    return key, base_value


def _pointer_store_8616(
    block_addr: int,
    instr_index: int,
    instruction: IRInstr,
) -> tuple[PointerOutputKey8616, IRAddress, IRValue, TerminalPointerStoreSite8616] | None:
    """Return one width-coherent stable versioned DS/ES pointer STORE."""
    if instruction.op != "STORE" or len(instruction.args) < 2:
        return None
    address, value = instruction.args[:2]
    if not isinstance(address, IRAddress) or not isinstance(value, IRValue):
        return None
    pointer = _pointer_address_8616(address)
    if (
        pointer is None
        or address.size != instruction.size
        or address.size != value.size
        or instruction.addr is None
    ):
        return None
    key, base_value = pointer
    site = TerminalPointerStoreSite8616(block_addr, instr_index, instruction.addr)
    return key, address, base_value, site


def _ranges_overlap_8616(left: PointerOutputKey8616, right: PointerOutputKey8616) -> bool:
    """Return whether two relative ranges overlap for one exact pointer base."""
    return left[3] < right[3] + right[4] and right[3] < left[3] + left[4]


def _terminal_is_return_8616(project: object, block_addr: int) -> bool:
    """Prove a terminal block ends in a structured machine return."""
    try:
        instructions = decoded_block_instructions_8616(cast(Any, project), block_addr, opt_level=0)
    except (KeyError, SimEngineError, SimTranslationError, ValueError):
        return False
    if not instructions:
        return False
    # Dynamic angr/Capstone boundary: decoded objects may retain an angr wrapper.
    decoded = cast(Any, instructions[-1])
    try:
        mnemonic = str(decoded.insn.mnemonic or "").lower()
    except AttributeError:
        try:
            mnemonic = str(decoded.mnemonic or "").lower()
        except AttributeError:
            return False
    return mnemonic in {"iret", "ret", "retf", "retw"}


def _refused_8616(
    artifact: SSAFunctionArtifact,
    failure: TerminalPointerOutputFailure8616,
    raw_count: int,
    normalized_count: int = 0,
) -> TerminalPointerOutputEvidence8616:
    """Build one atomic refusal without publishing partial pointer facts."""
    return TerminalPointerOutputEvidence8616(
        function_addr=artifact.function_addr,
        facts=(),
        failure=failure,
        stats=TerminalPointerOutputStats8616(
            raw_fact_count=max(1, raw_count),
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
    )


def _reachable_blocks_8616(
    artifact: SSAFunctionArtifact,
) -> tuple[
    set[int] | None,
    dict[int, frozenset[int]] | None,
    TerminalPointerOutputFailure8616 | None,
]:
    """Return the closed entry-reachable SSA block set."""
    blocks = {block.addr: block for block in artifact.blocks}
    if artifact.function_addr not in blocks:
        return None, None, TerminalPointerOutputFailure8616.ENTRY_BLOCK_MISSING
    if set(artifact.predecessor_map) != set(blocks):
        return None, None, TerminalPointerOutputFailure8616.CFG_INCOMPLETE
    successors: dict[int, set[int]] = {address: set() for address in blocks}
    for successor, predecessors in artifact.predecessor_map.items():
        if any(predecessor not in blocks for predecessor in predecessors):
            return None, None, TerminalPointerOutputFailure8616.CFG_INCOMPLETE
        for predecessor in predecessors:
            successors[predecessor].add(successor)
    reachable: set[int] = set()
    pending = [artifact.function_addr]
    while pending:
        block_addr = pending.pop()
        if block_addr in reachable:
            continue
        reachable.add(block_addr)
        pending.extend(successors[block_addr])
    frozen = {address: frozenset(values) for address, values in successors.items()}
    return reachable, frozen, None


def _must_write_keys_8616(
    artifact: SSAFunctionArtifact,
    reachable: set[int],
    successors: dict[int, frozenset[int]],
    candidate_keys: frozenset[PointerOutputKey8616],
) -> tuple[
    frozenset[PointerOutputKey8616],
    tuple[int, ...],
    dict[PointerOutputKey8616, tuple[int, ...]],
] | None:
    """Solve definite pointer stores to every terminal over the exact SSA CFG."""
    blocks = {block.addr: block for block in artifact.blocks if block.addr in reachable}
    predecessors = {
        address: {
            predecessor
            for predecessor in artifact.predecessor_map[address]
            if predecessor in reachable
        }
        for address in reachable
    }
    terminals = tuple(sorted(address for address in reachable if not successors[address]))
    if not terminals:
        return None
    can_reach_terminal = set(terminals)
    pending = list(terminals)
    while pending:
        address = pending.pop()
        for predecessor in predecessors[address]:
            if predecessor not in can_reach_terminal:
                can_reach_terminal.add(predecessor)
                pending.append(predecessor)
    if can_reach_terminal != reachable:
        return None
    local = {
        block.addr: frozenset(
            pointer[0]
            for index, instruction in enumerate(block.instrs)
            if (pointer := _pointer_store_8616(block.addr, index, instruction)) is not None
        )
        for block in blocks.values()
    }
    incoming = dict.fromkeys(reachable, candidate_keys)
    outgoing = dict.fromkeys(reachable, candidate_keys)
    incoming[artifact.function_addr] = frozenset()
    changed = True
    while changed:
        changed = False
        for address in sorted(reachable):
            if address == artifact.function_addr:
                new_in: frozenset[PointerOutputKey8616] = frozenset()
            else:
                pred_sets = tuple(outgoing[pred] for pred in sorted(predecessors[address]))
                new_in = frozenset.intersection(*pred_sets) if pred_sets else frozenset()
            new_out = new_in | local[address]
            if new_in != incoming[address] or new_out != outgoing[address]:
                incoming[address], outgoing[address], changed = new_in, new_out, True
    terminal_sets = tuple(outgoing[address] for address in terminals)
    definite_terminals = {
        key: tuple(address for address in terminals if key in outgoing[address])
        for key in candidate_keys
    }
    return frozenset.intersection(*terminal_sets), terminals, definite_terminals


def _store_may_alias_candidates_8616(
    instruction: IRInstr,
    candidate_keys: tuple[PointerOutputKey8616, ...],
) -> bool:
    """Return whether an unsupported indirect STORE may alias a pointer fact."""
    address = instruction.args[0] if instruction.args else None
    if not isinstance(address, IRAddress):
        return True
    if address.space is MemSpace.SS or not address.base:
        return False
    if address.space not in {MemSpace.DS, MemSpace.ES}:
        return address.space is MemSpace.UNKNOWN
    same_space = tuple(key for key in candidate_keys if key[0] is address.space)
    if not same_space:
        return False
    value = instruction.args[1] if len(instruction.args) >= 2 else None
    if (
        not isinstance(value, IRValue)
        or address.size != instruction.size
        or address.size != value.size
    ):
        return True
    pointer = _pointer_address_8616(address)
    if pointer is None:
        return True
    store_key = pointer[0]
    for candidate in same_space:
        if store_key[1:3] != candidate[1:3] or _ranges_overlap_8616(store_key, candidate):
            return True
    return False


def _grouped_pointer_sites_8616(
    artifact: SSAFunctionArtifact,
    reachable: set[int],
) -> tuple[
    dict[PointerOutputKey8616, tuple[IRAddress, IRValue, list[TerminalPointerStoreSite8616]]],
    list[tuple[int, int, IRInstr]],
    set[tuple[int, int]],
]:
    """Group proven pointer-store sites and census every reachable STORE."""
    grouped: dict[
        PointerOutputKey8616,
        tuple[IRAddress, IRValue, list[TerminalPointerStoreSite8616]],
    ] = {}
    all_stores: list[tuple[int, int, IRInstr]] = []
    pointer_sites: set[tuple[int, int]] = set()
    for block in artifact.blocks:
        if block.addr not in reachable:
            continue
        for instr_index, instruction in enumerate(block.instrs):
            if instruction.op != "STORE":
                continue
            all_stores.append((block.addr, instr_index, instruction))
            pointer = _pointer_store_8616(block.addr, instr_index, instruction)
            if pointer is None:
                continue
            pointer_sites.add((block.addr, instr_index))
            key, address, base_value, site = pointer
            grouped.setdefault(key, (address, base_value, []))[2].append(site)
    return grouped, all_stores, pointer_sites


def _pointer_output_facts_8616(
    grouped: dict[PointerOutputKey8616, tuple[IRAddress, IRValue, list[TerminalPointerStoreSite8616]]],
    keys: tuple[PointerOutputKey8616, ...],
    must_write: frozenset[PointerOutputKey8616],
    terminals: tuple[int, ...],
    definite_terminals: dict[PointerOutputKey8616, tuple[int, ...]],
) -> tuple[TerminalPointerOutputFact8616, ...]:
    """Materialize one dispositioned pointer-output fact per proven key."""
    return tuple(
        TerminalPointerOutputFact8616(
            address=grouped[key][0],
            base_value=grouped[key][1],
            disposition=(
                TerminalPointerOutputDisposition8616.MUST_WRITE
                if key in must_write
                else TerminalPointerOutputDisposition8616.CONDITIONAL
            ),
            store_sites=tuple(
                sorted(grouped[key][2], key=lambda site: (site.block_addr, site.instr_index))
            ),
            terminal_block_addrs=terminals,
            definitely_written_terminal_block_addrs=definite_terminals[key],
        )
        for key in keys
    )


def collect_terminal_pointer_output_evidence_8616(
    project: object,
    artifact: SSAFunctionArtifact,
) -> TerminalPointerOutputEvidence8616:
    """Classify stable versioned DS/ES pointer ranges over every return path."""
    all_candidates = [
        (block.addr, instr_index, instruction)
        for block in artifact.blocks
        for instr_index, instruction in enumerate(block.instrs)
        if _pointer_store_8616(block.addr, instr_index, instruction) is not None
    ]
    if not all_candidates:
        return TerminalPointerOutputEvidence8616(
            artifact.function_addr, (), None, TerminalPointerOutputStats8616()
        )
    reachable, successors, failure = _reachable_blocks_8616(artifact)
    if reachable is None or successors is None:
        if failure is None:
            raise RuntimeError("incomplete pointer-output CFG refusal")
        return _refused_8616(artifact, failure, len(all_candidates))

    grouped, all_stores, pointer_sites = _grouped_pointer_sites_8616(artifact, reachable)
    if not grouped:
        return TerminalPointerOutputEvidence8616(
            artifact.function_addr, (), None, TerminalPointerOutputStats8616()
        )
    keys = tuple(sorted(grouped, key=lambda key: (key[0].value, *key[1:])))
    for block_addr, instr_index, instruction in all_stores:
        if (block_addr, instr_index) in pointer_sites:
            continue
        if _store_may_alias_candidates_8616(instruction, keys):
            return _refused_8616(
                artifact, TerminalPointerOutputFailure8616.ALIAS_CONFLICT, len(keys), len(keys)
            )
    solved = _must_write_keys_8616(artifact, reachable, successors, frozenset(keys))
    if solved is None:
        return _refused_8616(
            artifact, TerminalPointerOutputFailure8616.CFG_INCOMPLETE, len(keys), len(keys)
        )
    must_write, terminals, definite_terminals = solved
    if any(not _terminal_is_return_8616(project, address) for address in terminals):
        return _refused_8616(
            artifact, TerminalPointerOutputFailure8616.TERMINAL_NOT_RETURN, len(keys), len(keys)
        )
    facts = _pointer_output_facts_8616(grouped, keys, must_write, terminals, definite_terminals)
    count = len(facts)
    return TerminalPointerOutputEvidence8616(
        artifact.function_addr,
        facts,
        None,
        TerminalPointerOutputStats8616(count, count, count, count),
    )


__all__ = ["collect_terminal_pointer_output_evidence_8616"]
