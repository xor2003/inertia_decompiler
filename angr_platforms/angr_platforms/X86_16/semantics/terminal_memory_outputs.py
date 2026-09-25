"""Classify exact direct segmented storage reaching every function return.

Layer: Semantics.
Responsibility: prove whether each stable direct DS/ES store is definitely
written on every entry-reachable return path while retaining all store sites.
Consumes typed function SSA and structured instruction decoding. This module
does not create Alias identities, choose C types, mutate prototypes, or render C.
Indirect, indexed, or incompletely connected memory effects remain explicitly
outside this direct-storage proof and do not erase independently proven direct
stores. Exact overlapping or possibly aliasing ranges remain separate Semantics
facts; Alias and interprocedural Lowering own their storage relationships.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import Any, cast

from angr.errors import SimEngineError, SimTranslationError

from ..frontend_instruction_reachability import decoded_block_instructions_8616
from ..ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace
from ..ir.ssa_function import SSAFunctionArtifact
from .terminal_memory_output_contracts import (
    MemoryOutputKey8616,
    TerminalMemoryOutputDisposition8616,
    TerminalMemoryOutputEvidence8616,
    TerminalMemoryOutputFact8616,
    TerminalMemoryOutputFailure8616,
    TerminalMemoryOutputStats8616,
    TerminalMemoryStoreSite8616,
)


def _stable_direct_address_8616(address: object) -> bool:
    """Return whether one address is a stable base-free DS/ES word."""
    return (
        isinstance(address, IRAddress)
        and address.space in {MemSpace.DS, MemSpace.ES}
        and not address.base
        and address.status is AddressStatus.STABLE
    )


def _width_coherent_value_8616(address: object, value: object, instruction: IRInstr) -> bool:
    """Return whether one STORE value's width matches its address and site."""
    return (
        isinstance(address, IRAddress)
        and isinstance(value, IRValue)
        and address.size > 0
        and address.size == instruction.size
        and address.size == value.size
        and instruction.addr is not None
    )


def _direct_store_8616(
    block_addr: int,
    instr_index: int,
    instruction: IRInstr,
) -> tuple[MemoryOutputKey8616, IRAddress, TerminalMemoryStoreSite8616] | None:
    """Return one width-coherent stable direct DS/ES STORE."""
    if instruction.op != "STORE" or len(instruction.args) < 2:
        return None
    address, value = instruction.args[:2]
    if not _stable_direct_address_8616(address) or not _width_coherent_value_8616(
        address, value, instruction
    ):
        return None
    key = (address.space, address.offset, address.size)
    return key, address, TerminalMemoryStoreSite8616(block_addr, instr_index, instruction.addr)


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
    failure: TerminalMemoryOutputFailure8616,
    raw_count: int,
    normalized_count: int = 0,
) -> TerminalMemoryOutputEvidence8616:
    """Build one atomic refusal without publishing partial output facts."""
    return TerminalMemoryOutputEvidence8616(
        function_addr=artifact.function_addr,
        facts=(),
        failure=failure,
        stats=TerminalMemoryOutputStats8616(
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
    TerminalMemoryOutputFailure8616 | None,
]:
    """Return the closed entry-reachable SSA block set."""
    blocks = {block.addr: block for block in artifact.blocks}
    if artifact.function_addr not in blocks:
        return None, None, TerminalMemoryOutputFailure8616.ENTRY_BLOCK_MISSING
    if set(artifact.predecessor_map) != set(blocks):
        return None, None, TerminalMemoryOutputFailure8616.CFG_INCOMPLETE
    successors: dict[int, set[int]] = {address: set() for address in blocks}
    for successor, predecessors in artifact.predecessor_map.items():
        if any(predecessor not in blocks for predecessor in predecessors):
            return None, None, TerminalMemoryOutputFailure8616.CFG_INCOMPLETE
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
    return reachable, {address: frozenset(values) for address, values in successors.items()}, None


def _must_write_keys_8616(
    artifact: SSAFunctionArtifact,
    reachable: set[int],
    successors: dict[int, frozenset[int]],
    candidate_keys: frozenset[MemoryOutputKey8616],
) -> tuple[
    frozenset[MemoryOutputKey8616],
    tuple[int, ...],
    dict[MemoryOutputKey8616, tuple[int, ...]],
] | None:
    """Solve definite direct stores to every terminal over the exact SSA CFG."""
    blocks = {block.addr: block for block in artifact.blocks if block.addr in reachable}
    predecessors = {
        address: {predecessor for predecessor in artifact.predecessor_map[address] if predecessor in reachable}
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
            direct[0]
            for index, instruction in enumerate(block.instrs)
            if (direct := _direct_store_8616(block.addr, index, instruction)) is not None
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
                new_in: frozenset[MemoryOutputKey8616] = frozenset()
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


def _grouped_store_sites_8616(
    artifact: SSAFunctionArtifact,
    reachable: set[int],
) -> dict[MemoryOutputKey8616, tuple[IRAddress, list[TerminalMemoryStoreSite8616]]]:
    """Group proven direct-store sites by output key over reachable blocks."""
    grouped: dict[MemoryOutputKey8616, tuple[IRAddress, list[TerminalMemoryStoreSite8616]]] = {}
    for block in artifact.blocks:
        if block.addr not in reachable:
            continue
        for instr_index, instruction in enumerate(block.instrs):
            if instruction.op != "STORE":
                continue
            direct = _direct_store_8616(block.addr, instr_index, instruction)
            if direct is None:
                continue
            key, address, site = direct
            stored = grouped.setdefault(key, (address, []))
            stored[1].append(site)
    return grouped


def _memory_output_facts_8616(
    grouped: dict[MemoryOutputKey8616, tuple[IRAddress, list[TerminalMemoryStoreSite8616]]],
    keys: tuple[MemoryOutputKey8616, ...],
    must_write: frozenset[MemoryOutputKey8616],
    terminals: tuple[int, ...],
    definite_terminals: dict[MemoryOutputKey8616, tuple[int, ...]],
) -> tuple[TerminalMemoryOutputFact8616, ...]:
    """Materialize one dispositioned output fact per proven key."""
    return tuple(
        TerminalMemoryOutputFact8616(
            address=grouped[key][0],
            disposition=(
                TerminalMemoryOutputDisposition8616.MUST_WRITE
                if key in must_write
                else TerminalMemoryOutputDisposition8616.CONDITIONAL
            ),
            store_sites=tuple(sorted(grouped[key][1], key=lambda site: (site.block_addr, site.instr_index))),
            terminal_block_addrs=terminals,
            definitely_written_terminal_block_addrs=definite_terminals[key],
        )
        for key in keys
    )


def collect_terminal_memory_output_evidence_8616(
    project: object,
    artifact: SSAFunctionArtifact,
) -> TerminalMemoryOutputEvidence8616:
    """Classify stable direct DS/ES ranges over every exact return path."""
    all_direct: list[tuple[int, int, IRInstr]] = []
    for block in artifact.blocks:
        all_direct.extend(
            (block.addr, instr_index, instruction)
            for instr_index, instruction in enumerate(block.instrs)
            if _direct_store_8616(block.addr, instr_index, instruction) is not None
        )
    if not all_direct:
        return TerminalMemoryOutputEvidence8616(
            artifact.function_addr, (), None, TerminalMemoryOutputStats8616()
        )
    reachable, successors, failure = _reachable_blocks_8616(artifact)
    if reachable is None or successors is None:
        if failure is None:
            raise RuntimeError("incomplete memory-output CFG refusal")
        return _refused_8616(artifact, failure, len(all_direct))

    grouped = _grouped_store_sites_8616(artifact, reachable)
    if not grouped:
        return TerminalMemoryOutputEvidence8616(
            artifact.function_addr, (), None, TerminalMemoryOutputStats8616()
        )
    keys = tuple(sorted(grouped, key=lambda item: (item[0].value, item[1], item[2])))
    solved = _must_write_keys_8616(artifact, reachable, successors, frozenset(keys))
    if solved is None:
        return _refused_8616(
            artifact, TerminalMemoryOutputFailure8616.CFG_INCOMPLETE, len(keys), len(keys)
        )
    must_write, terminals, definite_terminals = solved
    if any(not _terminal_is_return_8616(project, address) for address in terminals):
        return _refused_8616(
            artifact, TerminalMemoryOutputFailure8616.TERMINAL_NOT_RETURN, len(keys), len(keys)
        )
    facts = _memory_output_facts_8616(grouped, keys, must_write, terminals, definite_terminals)
    count = len(facts)
    return TerminalMemoryOutputEvidence8616(
        artifact.function_addr,
        facts,
        None,
        TerminalMemoryOutputStats8616(count, count, count, count),
    )
