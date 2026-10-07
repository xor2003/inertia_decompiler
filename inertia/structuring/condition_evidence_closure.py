"""Classify final structured-condition evidence closure.

Layer: Structuring.
Responsibility: require every exact typed ConditionIR identity to have a final
structured AST owner, including JCCs consumed by proven composite predicates.
Do not infer branch meaning from rendered C, variable names, or flag equations.

Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CIfElse

from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

from .condition_chain_provenance import condition_chain_provenance_8616

type ConditionEvidenceKey8616 = tuple[int, int]


class _TaggedNode8616(Protocol):
    """Third-party structured AST tag surface used at this boundary."""

    tags: dict[str, object]


@dataclass(frozen=True, slots=True)
class ConditionEvidenceClosure8616:
    """Identity-based closure result for final structured conditions."""

    required_keys: frozenset[ConditionEvidenceKey8616]
    materialized_keys: frozenset[ConditionEvidenceKey8616]
    unresolved_branch_owners: frozenset[int]

    @property
    def complete(self) -> bool:
        """Return whether every typed condition has a final proven owner."""
        return (
            self.required_keys <= self.materialized_keys
            and not self.unresolved_branch_owners
        )


def _condition_key_8616(condition: ConditionIR) -> ConditionEvidenceKey8616 | None:
    """Return one exact JCC/block identity when both coordinates exist."""
    if not isinstance(condition.src_insn, int) or not isinstance(
        condition.block_addr,
        int,
    ):
        return None
    return condition.src_insn, condition.block_addr


def _tags_8616(node: object) -> dict[str, object]:
    """Read third-party AST tags without assigning semantic defaults."""
    try:
        tags = cast(_TaggedNode8616, node).tags
    except AttributeError:
        return {}
    return tags if isinstance(tags, dict) else {}


def _tagged_key_8616(tags: Mapping[str, object]) -> ConditionEvidenceKey8616 | None:
    """Return one exact condition identity carried by AST tags."""
    loop_key = tags.get("inertia_typed_loop_condition_key_8616")
    if (
        isinstance(loop_key, tuple)
        and len(loop_key) == 2
        and all(isinstance(item, int) for item in loop_key)
    ):
        return cast(ConditionEvidenceKey8616, loop_key)
    if not (
        tags.get("inertia_structuring_condition_cfg_materialized_8616") is True
        or tags.get("inertia_typed_loop_condition_bound_8616") is True
    ):
        return None
    instruction_addr = tags.get("ins_addr")
    block_addr = tags.get("vex_block_addr")
    if isinstance(instruction_addr, int) and isinstance(block_addr, int):
        return instruction_addr, block_addr
    return None


def _binary_cfg_owner_8616(
    node: CIfElse,
    successors: Mapping[int, tuple[int, ...]],
) -> int | None:
    """Return the exact two-successor CFG owner of one structured if node."""
    candidates: list[int] = []
    for tagged in (node, *(condition for condition, _body in node.condition_and_nodes)):
        tags = _tags_8616(tagged)
        for name in ("vex_block_addr", "ins_addr"):
            address = tags.get(name)
            if isinstance(address, int) and address not in candidates:
                candidates.append(address)
    owners = tuple(address for address in candidates if len(successors.get(address, ())) == 2)
    return owners[0] if len(owners) == 1 else None


def classify_condition_evidence_closure_8616(
    root: object,
    typed_conditions: tuple[ConditionIR, ...],
    successors: Mapping[int, tuple[int, ...]],
) -> ConditionEvidenceClosure8616:
    """Classify typed condition coverage and unresolved real CFG branches."""
    required_keys = frozenset(
        key
        for condition in typed_conditions
        if (key := _condition_key_8616(condition)) is not None
    )
    materialized_keys: set[ConditionEvidenceKey8616] = set()
    unresolved_owners: set[int] = set()
    required_blocks = {block_addr for _instruction_addr, block_addr in required_keys}
    keys_by_instruction: dict[int, set[ConditionEvidenceKey8616]] = {}
    for key in required_keys:
        keys_by_instruction.setdefault(key[0], set()).add(key)
    for node in _iter_c_nodes_deep_8616(root):
        key = _tagged_key_8616(_tags_8616(node))
        if key is not None:
            materialized_keys.add(key)
        provenance = condition_chain_provenance_8616(node)
        if provenance is not None:
            for instruction_addr in provenance.jcc_addrs:
                candidates = keys_by_instruction.get(instruction_addr, set())
                if len(candidates) == 1:
                    materialized_keys.update(candidates)
        if not isinstance(node, CIfElse):
            continue
        owner = _binary_cfg_owner_8616(node, successors)
        if owner is not None and owner not in required_blocks:
            unresolved_owners.add(owner)
    return ConditionEvidenceClosure8616(
        required_keys=required_keys,
        materialized_keys=frozenset(materialized_keys),
        unresolved_branch_owners=frozenset(unresolved_owners),
    )
