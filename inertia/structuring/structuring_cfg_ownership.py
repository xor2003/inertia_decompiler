"""Ownership/refusal layer over CFG snapshots.

Layer: Structuring.
Responsibility: derive explicit ownership and refusal records from structuring CFG snapshots.
Forbidden: grouping unrelated entries, rewriting control flow, or repairing generated C.

This module turns raw region connectivity into a typed ownership surface with
explicit refusal reasons for shared or disconnected regions.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.structuring.structuring_cfg_snapshot import CFGSnapshot, build_cfg_snapshot


@dataclass(frozen=True, order=True, slots=True)
class CFGInstructionSite8616:
    """One exact instruction occurrence in a pre-join CFG block."""

    block_addr: int
    ins_addr: int


class CFGInstructionReachability8616(StrEnum):
    """Typed result of proving execution order between exact instruction sites."""

    REACHES = "reaches"
    DOES_NOT_REACH = "does_not_reach"
    OWNER_MISSING = "owner_missing"
    OWNER_AMBIGUOUS = "owner_ambiguous"
    ORDER_CONFLICT = "order_conflict"


@dataclass(frozen=True, slots=True)
class CFGOwnershipRecord:
    """Ownership/refusal state for one CFG region."""

    region_id: int
    ownership_kind: str
    refusal_reason: str | None
    predecessor_count: int
    successor_count: int
    reachable_from_entry: bool


@dataclass(frozen=True, slots=True)
class CFGOwnershipArtifact:
    """Typed ownership surface built from a CFG snapshot."""

    snapshot: CFGSnapshot
    records: tuple[CFGOwnershipRecord, ...]
    shared_region_ids: tuple[int, ...]
    entry_fragment_region_ids: tuple[int, ...]

    def instruction_sites(self, ins_addr: int) -> tuple[CFGInstructionSite8616, ...]:
        """Return deterministic exact block/instruction sites recorded for one address."""
        sites = {
            CFGInstructionSite8616(block_addr=node.block_addr, ins_addr=ins_addr)
            for node in self.snapshot.nodes
            if node.block_addr is not None and ins_addr in node.statement_ins_addrs
        }
        return tuple(sorted(sites))

    def instruction_owner_region_id(
        self,
        site: CFGInstructionSite8616,
    ) -> int | CFGInstructionReachability8616:
        """Resolve one exact site to a unique CFG region or a typed refusal."""
        owners = tuple(
            node
            for node in self.snapshot.nodes
            if node.block_addr == site.block_addr and site.ins_addr in node.statement_ins_addrs
        )
        if not owners:
            return CFGInstructionReachability8616.OWNER_MISSING
        if len(owners) != 1:
            return CFGInstructionReachability8616.OWNER_AMBIGUOUS
        owner = owners[0]
        if sum(node.region_id == owner.region_id for node in self.snapshot.nodes) != 1:
            return CFGInstructionReachability8616.OWNER_AMBIGUOUS
        return owner.region_id

    def instruction_reachability(
        self,
        source_site: CFGInstructionSite8616,
        target_site: CFGInstructionSite8616,
    ) -> CFGInstructionReachability8616:
        """Prove whether one exact instruction site can execute before another."""
        source_owner = self.instruction_owner_region_id(source_site)
        if isinstance(source_owner, CFGInstructionReachability8616):
            return source_owner
        target_owner = self.instruction_owner_region_id(target_site)
        if isinstance(target_owner, CFGInstructionReachability8616):
            return target_owner

        if source_owner == target_owner:
            if source_site.ins_addr > target_site.ins_addr:
                return CFGInstructionReachability8616.ORDER_CONFLICT
            return CFGInstructionReachability8616.REACHES
        return self._region_reachability(source_owner, target_owner)

    def _region_reachability(
        self,
        source_region_id: int,
        target_region_id: int,
    ) -> CFGInstructionReachability8616:
        """Traverse the immutable snapshot after validating unique region identities."""
        nodes_by_id = {node.region_id: node for node in self.snapshot.nodes}
        if len(nodes_by_id) != len(self.snapshot.nodes):
            return CFGInstructionReachability8616.OWNER_AMBIGUOUS
        if source_region_id not in nodes_by_id or target_region_id not in nodes_by_id:
            return CFGInstructionReachability8616.OWNER_MISSING

        pending = [source_region_id]
        visited: set[int] = set()
        while pending:
            region_id = pending.pop()
            if region_id in visited:
                continue
            visited.add(region_id)
            for successor_id in nodes_by_id[region_id].successor_ids:
                if successor_id == target_region_id:
                    return CFGInstructionReachability8616.REACHES
                if successor_id in nodes_by_id and successor_id not in visited:
                    pending.append(successor_id)
        return CFGInstructionReachability8616.DOES_NOT_REACH

    def summary_line(self) -> str:
        """Compact deterministic summary for diagnostics."""
        return (
            f"cfg_ownership regions={len(self.records)} shared={len(self.shared_region_ids)} "
            f"entry_fragments={len(self.entry_fragment_region_ids)}"
        )

    def to_dict(self) -> dict[str, object]:
        """Stable serialization for reports and artifacts."""
        return {
            "snapshot": self.snapshot.to_dict(),
            "shared_region_ids": [hex(region_id) for region_id in self.shared_region_ids],
            "entry_fragment_region_ids": [hex(region_id) for region_id in self.entry_fragment_region_ids],
            "records": [
                {
                    "region_id": hex(record.region_id),
                    "ownership_kind": record.ownership_kind,
                    "refusal_reason": record.refusal_reason,
                    "predecessor_count": record.predecessor_count,
                    "successor_count": record.successor_count,
                }
                for record in self.records
            ],
        }


def build_cfg_ownership_artifact(codegen: object) -> CFGOwnershipArtifact | None:
    """Build the ownership/refusal surface for structuring CFGs."""
    snapshot = build_cfg_snapshot(codegen)
    if snapshot is None:
        return None

    records: list[CFGOwnershipRecord] = []
    shared_region_ids: list[int] = []
    entry_fragment_region_ids: list[int] = []
    reachable_by_id = {item.region_id: item.reachable_from_entry for item in snapshot.nodes}

    for node in snapshot.nodes:
        predecessor_count = len(node.predecessor_ids)
        successor_count = len(node.successor_ids)
        if node.region_id == snapshot.entry_region_id:
            ownership_kind = "entry"
            refusal_reason = None
        elif not node.reachable_from_entry and predecessor_count == 0:
            ownership_kind = "entry_fragment"
            refusal_reason = "disconnected_from_entry"
            entry_fragment_region_ids.append(node.region_id)
        elif not node.reachable_from_entry:
            ownership_kind = "shared_owner"
            refusal_reason = "mixed_reachability_predecessors"
            shared_region_ids.append(node.region_id)
        elif predecessor_count == 0:
            ownership_kind = "entry_fragment"
            refusal_reason = "disconnected_from_entry"
            entry_fragment_region_ids.append(node.region_id)
        elif predecessor_count == 1:
            ownership_kind = "single_owner"
            refusal_reason = None
        else:
            ownership_kind = "shared_owner"
            predecessor_reachability = {reachable_by_id.get(region_id, False) for region_id in node.predecessor_ids}
            if len(predecessor_reachability) > 1:
                refusal_reason = "mixed_reachability_predecessors"
            else:
                refusal_reason = "multiple_predecessors"
            shared_region_ids.append(node.region_id)

        records.append(
            CFGOwnershipRecord(
                region_id=node.region_id,
                ownership_kind=ownership_kind,
                refusal_reason=refusal_reason,
                predecessor_count=predecessor_count,
                successor_count=successor_count,
                reachable_from_entry=node.reachable_from_entry,
            )
        )

    return CFGOwnershipArtifact(
        snapshot=snapshot,
        records=tuple(records),
        shared_region_ids=tuple(shared_region_ids),
        entry_fragment_region_ids=tuple(entry_fragment_region_ids),
    )
