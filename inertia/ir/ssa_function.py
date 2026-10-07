"""Build function-level SSA artifacts and phi nodes over typed IR.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .core import IRFunctionArtifact, IRRefusal, IRValue, MemSpace
from .function_condition_artifact import IRFunctionConditionArtifact8616
from .logical_memory_contracts import IRLogicalMemoryArtifact8616
from .ssa import SSABlock, _version_key, build_x86_16_block_local_ssa
from .ssa_memory import build_x86_16_function_memory_ssa
from .ssa_memory_contracts import (
    SSACallStackEffectSite8616,
    SSAMemoryAccess8616,
    SSAMemoryBinding8616,
    SSAMemoryOverlap8616,
    SSAMemoryPhiNode8616,
    SSAMemoryStats8616,
)

_MIN_PHI_INPUTS_8616 = 2

__all__ = [
    "SSACallStackEffectSite8616",
    "SSAFunctionArtifact",
    "SSAIncomingValue",
    "SSAMemoryAccess8616",
    "SSAMemoryBinding8616",
    "SSAMemoryOverlap8616",
    "SSAMemoryPhiNode8616",
    "SSAMemoryStats8616",
    "SSAPhiNode",
    "build_x86_16_function_ssa",
    "build_x86_16_ir_predecessor_map",
]


@dataclass(frozen=True, slots=True)
class SSAIncomingValue:
    """Incoming SSA value from one predecessor block."""

    source_block_addr: int
    value: IRValue

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "source_block_addr": self.source_block_addr,
            "value": self.value.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class SSAPhiNode:
    """Phi node for a typed IR value with multiple predecessor definitions."""

    block_addr: int
    key: tuple[str, str | None, int]
    target: IRValue
    incoming: tuple[SSAIncomingValue, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "block_addr": self.block_addr,
            "key": list(self.key),
            "target": self.target.to_dict(),
            "incoming": [item.to_dict() for item in self.incoming],
        }


@dataclass(frozen=True, slots=True)
class SSAFunctionArtifact:
    """Function-level SSA artifact over typed IR blocks and phi nodes."""

    function_addr: int
    blocks: tuple[SSABlock, ...]
    phi_nodes: tuple[SSAPhiNode, ...] = ()
    memory_bindings: tuple[SSAMemoryBinding8616, ...] = ()
    memory_accesses: tuple[SSAMemoryAccess8616, ...] = ()
    memory_phi_nodes: tuple[SSAMemoryPhiNode8616, ...] = ()
    memory_overlaps: tuple[SSAMemoryOverlap8616, ...] = ()
    memory_call_effects: tuple[SSACallStackEffectSite8616, ...] = ()
    memory_refusals: tuple[IRRefusal, ...] = ()
    memory_stats: SSAMemoryStats8616 = SSAMemoryStats8616()  # noqa: RUF009
    predecessor_map: dict[int, tuple[int, ...]] = field(default_factory=dict)
    summary: dict[str, object] = field(default_factory=dict)
    logical_memory: IRLogicalMemoryArtifact8616 | None = None
    condition_evidence: IRFunctionConditionArtifact8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addr": self.function_addr,
            "blocks": [block.to_dict() for block in self.blocks],
            "phi_nodes": [phi.to_dict() for phi in self.phi_nodes],
            "memory_bindings": [binding.to_dict() for binding in self.memory_bindings],
            "memory_accesses": [access.to_dict() for access in self.memory_accesses],
            "memory_phi_nodes": [phi.to_dict() for phi in self.memory_phi_nodes],
            "memory_overlaps": [overlap.to_dict() for overlap in self.memory_overlaps],
            "memory_call_effects": [effect.to_dict() for effect in self.memory_call_effects],
            "memory_refusals": [refusal.to_dict() for refusal in self.memory_refusals],
            "memory_stats": {
                "raw_fact_count": self.memory_stats.raw_fact_count,
                "normalized_fact_count": self.memory_stats.normalized_fact_count,
                "classified_fact_count": self.memory_stats.classified_fact_count,
                "materialized_count": self.memory_stats.materialized_count,
                "failure_count": self.memory_stats.failure_count,
            },
            "predecessor_map": {
                hex(addr): [hex(pred) for pred in preds] for addr, preds in sorted(self.predecessor_map.items())
            },
            "summary": dict(self.summary),
            "logical_memory": (
                None if self.logical_memory is None else self.logical_memory.to_dict()
            ),
            "condition_evidence": (
                None
                if self.condition_evidence is None
                else self.condition_evidence.to_dict()
            ),
        }


def _value_key(value: IRValue) -> tuple[str, str | None, int] | None:
    """Use the same storage identity for block definitions and function joins."""
    if value.space in {MemSpace.CONST, MemSpace.UNKNOWN}:
        return None
    return _version_key(value)


def _block_exit_versions(block: SSABlock) -> dict[tuple[str, str | None, int], IRValue]:
    exit_versions: dict[tuple[str, str | None, int], IRValue] = {}
    for binding in block.bindings:
        key = _value_key(binding.target)
        if key is None:
            continue
        exit_versions[key] = binding.target
    return exit_versions


def build_x86_16_ir_predecessor_map(artifact: IRFunctionArtifact) -> dict[int, tuple[int, ...]]:
    """Derive deterministic in-function predecessors from typed IR CFG edges."""
    block_addrs = {block.addr for block in artifact.blocks}
    pred_map: dict[int, set[int]] = {block.addr: set() for block in artifact.blocks}
    for block in artifact.blocks:
        for succ in block.successor_addrs:
            if succ in block_addrs:
                pred_map.setdefault(succ, set()).add(block.addr)
    return {addr: tuple(sorted(preds)) for addr, preds in sorted(pred_map.items())}


def _distinct_incoming_values(values: tuple[SSAIncomingValue, ...]) -> bool:
    seen = {
        (
            item.source_block_addr,
            item.value.space.value,
            item.value.name,
            item.value.offset,
            item.value.const,
            item.value.version,
        )
        for item in values
    }
    return len(seen) > 1


def _make_phi_target(
    block_addr: int, key: tuple[str, str | None, int], incoming: tuple[SSAIncomingValue, ...]
) -> IRValue:
    max_version = max((item.value.version or 0) for item in incoming)
    return IRValue(
        space=MemSpace(key[0]),
        name=key[1],
        offset=key[2],
        size=max((item.value.size for item in incoming), default=0),
        version=max_version + 1,
        expr=("phi", hex(block_addr)),
    )


def build_x86_16_function_ssa(artifact: IRFunctionArtifact) -> SSAFunctionArtifact:
    """Build function-level SSA and phi-node facts from typed IR CFG edges."""

    def _impl() -> SSAFunctionArtifact:
        local_blocks = tuple(build_x86_16_block_local_ssa(block) for block in artifact.blocks)
        pred_map = build_x86_16_ir_predecessor_map(artifact)
        memory_ssa = build_x86_16_function_memory_ssa(
            artifact.function_addr,
            local_blocks,
            pred_map,
            artifact.logical_memory,
        )
        local_blocks = memory_ssa.blocks
        local_by_addr = {block.addr: block for block in local_blocks}
        exits_by_addr = {block.addr: _block_exit_versions(block) for block in local_blocks}
        phi_nodes: list[SSAPhiNode] = []

        for block_addr, preds in pred_map.items():
            if len(preds) < _MIN_PHI_INPUTS_8616:
                continue
            candidate_keys = sorted({key for pred in preds for key in exits_by_addr.get(pred, {})})
            for key in candidate_keys:
                incoming = tuple(
                    SSAIncomingValue(source_block_addr=pred, value=exits_by_addr[pred][key])
                    for pred in preds
                    if key in exits_by_addr.get(pred, {})
                )
                if len(incoming) < _MIN_PHI_INPUTS_8616 or not _distinct_incoming_values(incoming):
                    continue
                phi_nodes.append(
                    SSAPhiNode(
                        block_addr=block_addr,
                        key=key,
                        target=_make_phi_target(block_addr, key, incoming),
                        incoming=tuple(sorted(incoming, key=lambda item: item.source_block_addr)),
                    )
                )

        summary: dict[str, object] = {
            "block_count": len(local_blocks),
            "phi_node_count": len(phi_nodes),
            "join_block_count": sum(1 for preds in pred_map.values() if len(preds) > 1),
            "memory_binding_count": len(memory_ssa.bindings),
            "memory_access_count": len(memory_ssa.accesses),
            "memory_phi_node_count": len(memory_ssa.phi_nodes),
            "memory_overlap_count": len(memory_ssa.overlaps),
            "memory_call_effect_count": len(memory_ssa.call_effects),
            "memory_refusal_count": len(memory_ssa.refusals),
        }
        return SSAFunctionArtifact(
            function_addr=artifact.function_addr,
            blocks=tuple(sorted(local_by_addr.values(), key=lambda block: block.addr)),
            phi_nodes=tuple(sorted(phi_nodes, key=lambda node: (node.block_addr, node.key))),
            memory_bindings=memory_ssa.bindings,
            memory_accesses=memory_ssa.accesses,
            memory_phi_nodes=memory_ssa.phi_nodes,
            memory_overlaps=memory_ssa.overlaps,
            memory_call_effects=memory_ssa.call_effects,
            memory_refusals=memory_ssa.refusals,
            memory_stats=memory_ssa.stats,
            predecessor_map=pred_map,
            summary=summary,
            logical_memory=memory_ssa.logical_memory,
            condition_evidence=artifact.condition_evidence,
        )

    return _impl()
