"""Transfer returned pointer carriers through one typed caller SSA block.

Layer: Types/Lowering.
Responsibility: carry exact full-word register identities through semantic MOV
aliases and recognize stable segmented LOAD or STORE address use in one block.
Consumes alias, widening, and typed facts.
Consumes Alias-owned register domains and typed IR/SSA facts. This module does
not traverse CFG edges, join phi inputs, infer arithmetic aliases, mutate
codegen, or inspect Structuring output.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..alias.domains import (
    AX,
    FULL16,
    DomainKey,
    register_domain_for_name,
    register_view_for_name,
)
from ..caller_return_use_contracts import CallerReturnUseFact8616
from ..ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from ..ir.logical_memory_register_transfer_contracts import LogicalMemoryRegisterTransferKind8616
from ..ir.ssa import SSABlock
from ..widening.stack_word_register_transfers import (
    StackWordRegisterTransfer8616,
    StackWordStorageVersion8616,
)
from .interprocedural_storage_return_type_contracts import (
    ReturnPointerAliasStep8616,
    ReturnPointerCfgEdge8616,
    ReturnPointerPhiEvidence8616,
    ReturnPointerUseEvidence8616,
)

__all__ = [
    "PointerBlockScan8616",
    "PointerCarrier8616",
    "append_unique_pointer_proofs_8616",
    "full_word_pointer_domain_8616",
    "pointer_witness_seed_values_8616",
    "scan_pointer_carriers_in_block_8616",
]

_ValueKey8616 = tuple[MemSpace, str | None, int, int, int | None]


@dataclass(frozen=True, slots=True)
class PointerCarrier8616:
    """One exact call-output-derived register carrier and its proof path."""

    value: IRValue
    aliases: tuple[ReturnPointerAliasStep8616, ...] = ()
    cfg_edges: tuple[ReturnPointerCfgEdge8616, ...] = ()
    phis: tuple[ReturnPointerPhiEvidence8616, ...] = ()
    stack_transfers: tuple[StackWordRegisterTransfer8616, ...] = ()


@dataclass(slots=True)
class PointerBlockScan8616:
    """Output carriers and refusal observations from one block scan."""

    carriers: dict[DomainKey, PointerCarrier8616]
    stack_carriers: dict[StackWordStorageVersion8616, PointerCarrier8616]
    evidence: ReturnPointerUseEvidence8616 | None = None
    saw_unknown_address: bool = False
    saw_ambiguous_address: bool = False
    saw_alias_clobber: bool = False


def append_unique_pointer_proofs_8616[ProofT](
    values: tuple[ProofT, ...],
    additions: tuple[ProofT, ...],
) -> tuple[ProofT, ...]:
    """Append equal proof records once while preserving deterministic order."""
    merged = list(values)
    for addition in additions:
        if addition not in merged:
            merged.append(addition)
    return tuple(merged)


def full_word_pointer_domain_8616(value: IRValue) -> DomainKey | None:
    """Return Alias-owned full-word register identity for a typed value."""
    if value.space is not MemSpace.REG or value.size != 2:
        return None
    if register_view_for_name(value.name) != FULL16:
        return None
    return register_domain_for_name(value.name)


def pointer_witness_seed_values_8616(
    block: SSABlock,
    witness: int,
) -> tuple[IRValue, ...]:
    """Return exact AX-domain reads performed by one witnessed instruction."""
    values: list[IRValue] = []
    for instruction in block.instrs:
        if instruction.addr != witness:
            continue
        for argument in instruction.args:
            if (
                isinstance(argument, IRValue)
                and full_word_pointer_domain_8616(argument) == AX
                and isinstance(argument.version, int)
                and argument not in values
            ):
                values.append(argument)
    return tuple(values)


def _value_key_8616(value: IRValue) -> _ValueKey8616:
    """Return exact block-local SSA identity for one typed value."""
    return (value.space, value.name, value.offset, value.size, value.version)


def _copy_source_8616(
    instruction: IRInstr,
    tainted: dict[_ValueKey8616, PointerCarrier8616],
    live: dict[DomainKey, PointerCarrier8616],
    entry_domains: set[DomainKey],
) -> tuple[IRValue, PointerCarrier8616] | None:
    """Resolve one exact tainted source of an equal-width semantic MOV."""
    destination = instruction.dst
    if (
        instruction.op != "MOV"
        or destination is None
        or len(instruction.args) != 1
        or not isinstance(instruction.args[0], IRValue)
    ):
        return None
    source = instruction.args[0]
    if source.expr is not None or source.size != 2 or destination.size != source.size:
        return None
    carrier = tainted.get(_value_key_8616(source))
    source_domain = full_word_pointer_domain_8616(source)
    if carrier is None and source.version == 0 and source_domain in entry_domains:
        carrier = live.get(source_domain)
    return None if carrier is None else (source, carrier)


def _address_uses_8616(instruction: IRInstr) -> tuple[IRAddress, ...]:
    """Return typed memory addresses consumed by a LOAD or STORE."""
    if instruction.op not in {"LOAD", "STORE"}:
        return ()
    return tuple(argument for argument in instruction.args if isinstance(argument, IRAddress))


def _address_carrier_8616(
    address: IRAddress,
    live: dict[DomainKey, PointerCarrier8616],
) -> tuple[PointerCarrier8616 | None, str | None, bool, bool]:
    """Classify exact, ambiguous, and unknown use of a live pointer carrier."""
    live_names = tuple(
        name for name in address.base if (domain := register_domain_for_name(name)) is not None and domain in live
    )
    if not live_names:
        return None, None, False, False
    if len(address.base) != 1 or len(live_names) != 1:
        return None, None, True, False
    if (
        address.status is not AddressStatus.STABLE
        or address.segment_origin is not SegmentOrigin.PROVEN
        or address.space not in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
        or address.size <= 0
    ):
        return None, None, False, True
    name = live_names[0]
    domain = register_domain_for_name(name)
    if domain is None:
        return None, None, False, True
    return live[domain], name, False, False


def _apply_stack_transfers_8616(
    transfers: tuple[StackWordRegisterTransfer8616, ...],
    live: dict[DomainKey, PointerCarrier8616],
    stack_live: dict[StackWordStorageVersion8616, PointerCarrier8616],
) -> bool:
    """Apply Alias-versioned spills and reloads at one machine instruction."""
    saw_clobber = False
    for transfer in transfers:
        register = transfer.source.register
        domain = full_word_pointer_domain_8616(register)
        if domain is None or not transfer.complete:
            continue
        key = transfer.storage_version
        if transfer.source.kind is LogicalMemoryRegisterTransferKind8616.SPILL:
            carrier = live.get(domain)
            if carrier is None:
                continue
            if carrier.value != register:
                saw_clobber = True
                continue
            stack_live[key] = PointerCarrier8616(
                value=carrier.value,
                aliases=carrier.aliases,
                cfg_edges=carrier.cfg_edges,
                phis=carrier.phis,
                stack_transfers=append_unique_pointer_proofs_8616(
                    carrier.stack_transfers,
                    (transfer,),
                ),
            )
            continue
        carrier = stack_live.get(key)
        if carrier is None:
            continue
        live[domain] = PointerCarrier8616(
            value=register,
            aliases=carrier.aliases,
            cfg_edges=carrier.cfg_edges,
            phis=carrier.phis,
            stack_transfers=append_unique_pointer_proofs_8616(
                carrier.stack_transfers,
                (transfer,),
            ),
        )
    return saw_clobber


@dataclass(slots=True)
class _PointerBlockScanState8616:
    """Mutable carrier-propagation state for one block scan."""

    block: SSABlock
    live: dict[DomainKey, PointerCarrier8616]
    stack_live: dict[StackWordStorageVersion8616, PointerCarrier8616]
    entry_domains: set[DomainKey]
    tainted: dict[_ValueKey8616, PointerCarrier8616]
    saw_unknown: bool = False
    saw_ambiguous: bool = False
    saw_clobber: bool = False

    def deref_evidence(
        self,
        instruction: IRInstr,
        instr_addr: int,
        fact: CallerReturnUseFact8616,
        witness: int,
    ) -> ReturnPointerUseEvidence8616 | None:
        """Return complete dereference evidence for one instruction or None."""
        for address in _address_uses_8616(instruction):
            carrier, name, ambiguous, unknown = _address_carrier_8616(address, self.live)
            self.saw_ambiguous = self.saw_ambiguous or ambiguous
            self.saw_unknown = self.saw_unknown or unknown
            if carrier is not None and name is not None:
                evidence = ReturnPointerUseEvidence8616(
                    caller_addr=fact.caller_addr,
                    callsite_addr=fact.callsite_addr,
                    witness_instruction_addr=witness,
                    dereference_instruction_addr=instr_addr,
                    carrier_register=name,
                    address=address,
                    aliases=carrier.aliases,
                    cfg_edges=carrier.cfg_edges,
                    phis=carrier.phis,
                    stack_transfers=carrier.stack_transfers,
                )
                if evidence.complete:
                    return evidence
                self.saw_unknown = True
        return None

    def apply_copy(
        self,
        instr_index: int,
        instruction: IRInstr,
        instr_addr: int | None,
    ) -> None:
        """Propagate one exact carrier through a proven register copy."""
        destination = instruction.dst
        copy = (
            None
            if not isinstance(instr_addr, int)
            else _copy_source_8616(instruction, self.tainted, self.live, self.entry_domains)
        )
        destination_domain = (
            None if destination is None else full_word_pointer_domain_8616(destination)
        )
        if destination_domain is not None:
            self.entry_domains.discard(destination_domain)
            if destination_domain in self.live and copy is None:
                self.saw_clobber = True
            self.live.pop(destination_domain, None)
        if (
            destination is not None
            and copy is not None
            and isinstance(destination.version, int)
            and isinstance(instr_addr, int)
        ):
            source, source_carrier = copy
            alias = ReturnPointerAliasStep8616(
                block_addr=self.block.addr,
                instr_index=instr_index,
                instr_addr=instr_addr,
                source=source,
                target=destination,
            )
            carrier = PointerCarrier8616(
                value=destination,
                aliases=append_unique_pointer_proofs_8616(source_carrier.aliases, (alias,)),
                cfg_edges=source_carrier.cfg_edges,
                phis=source_carrier.phis,
                stack_transfers=source_carrier.stack_transfers,
            )
            self.tainted[_value_key_8616(destination)] = carrier
            if destination_domain is not None:
                self.live[destination_domain] = carrier

    def apply_transfers(
        self,
        instr_index: int,
        instr_addr: int | None,
        stack_transfers_by_instruction: dict[int, tuple[StackWordRegisterTransfer8616, ...]],
    ) -> None:
        """Apply stack-transfer clobbers between adjacent addressed instructions."""
        next_addr = (
            self.block.instrs[instr_index + 1].addr
            if instr_index + 1 < len(self.block.instrs)
            else None
        )
        if isinstance(instr_addr, int) and next_addr != instr_addr:
            transfer_clobber = _apply_stack_transfers_8616(
                stack_transfers_by_instruction.get(instr_addr, ()),
                self.live,
                self.stack_live,
            )
            self.saw_clobber = self.saw_clobber or transfer_clobber


def scan_pointer_carriers_in_block_8616(
    block: SSABlock,
    fact: CallerReturnUseFact8616,
    entry_carriers: dict[DomainKey, PointerCarrier8616],
    entry_stack_carriers: dict[StackWordStorageVersion8616, PointerCarrier8616],
    stack_transfers_by_instruction: dict[int, tuple[StackWordRegisterTransfer8616, ...]],
    start_index: int,
    witness: int,
) -> PointerBlockScan8616:
    """Propagate exact carriers through one block from a proven entry state."""
    live = dict(entry_carriers)
    state = _PointerBlockScanState8616(
        block=block,
        live=live,
        stack_live=dict(entry_stack_carriers),
        entry_domains=set(live),
        tainted={_value_key_8616(carrier.value): carrier for carrier in live.values()},
    )

    for instr_index in range(start_index, len(block.instrs)):
        instruction = block.instrs[instr_index]
        instr_addr = instruction.addr
        if isinstance(instr_addr, int):
            evidence = state.deref_evidence(instruction, instr_addr, fact, witness)
            if evidence is not None:
                return PointerBlockScan8616(
                    carriers=state.live,
                    stack_carriers=state.stack_live,
                    evidence=evidence,
                )
        state.apply_copy(instr_index, instruction, instr_addr)
        state.apply_transfers(instr_index, instr_addr, stack_transfers_by_instruction)
    return PointerBlockScan8616(
        carriers=state.live,
        stack_carriers=state.stack_live,
        saw_unknown_address=state.saw_unknown,
        saw_ambiguous_address=state.saw_ambiguous,
        saw_alias_clobber=state.saw_clobber,
    )
