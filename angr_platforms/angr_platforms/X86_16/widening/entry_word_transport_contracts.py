"""Typed contracts for cross-block entry-word value transport.

Layer: Widening.
Responsibility: own the immutable verdict/refusal/fact contracts emitted by
``entry_word_transport.prove_entry_word_transport_8616``. A transport fact is
value-only provenance: one canonical entry-stack-word register definition
carried unchanged to one selected later 16-bit MOV destination across an
acyclic CFG cone. It is never a return, frame, callee-closure, pointer, or
whole-function claim. Consumes alias-proven storage identity and the canonical
word proof by object identity only.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..ir.core import IRFunctionArtifact, MemSpace
from .entry_stack_word_value_contracts import EntryStackWordProof8616


class EntryWordTransportVerdict8616(StrEnum):
    """Aggregate verdict for one targeted word-transport proof."""

    PROVEN = "proven"
    REFUSED = "refused"


class EntryWordTransportScope8616(StrEnum):
    """The conditional CFG scope for which the value relation is established.

    Unknown/off-cone exits are not proved unable to reenter the selected site.
    A whole-function consumer needs independent frontier closure evidence.
    """

    KNOWN_ACYCLIC_TARGET_CONE = "known_acyclic_target_cone"


class EntryWordTransportRefusalKind8616(StrEnum):
    """Typed reasons a targeted word transport or its provenance was refused.

    ``MISSING_BRANCH_TARGET`` marks a typed control target absent from the
    block's recorded successors; ``POST_CONTROL_DATA_WRITE`` and
    ``UNTRACKED_IP_WRITE`` mark post-control writes that only the fallthrough
    executes, so they cannot describe the taken edge.
    """

    CROSS_ARTIFACT_PROOF = "cross_artifact_proof"
    STALE_WORD_PROOF = "stale_word_proof"
    SEED_NOT_PROVEN = "seed_not_proven"
    SEED_NOT_FULL_WORD_REGISTER = "seed_not_full_word_register"
    SEED_OUTSIDE_ENTRY = "seed_outside_entry"
    MISSING_ENTRY_BLOCK = "missing_entry_block"
    AMBIGUOUS_BLOCK_ADDR = "ambiguous_block_addr"
    MISSING_TARGET_BLOCK = "missing_target_block"
    UNREACHABLE_TARGET = "unreachable_target"
    CFG_CYCLE = "cfg_cycle"
    BAD_TARGET_INDEX = "bad_target_index"
    NON_SCALAR_TARGET = "non_scalar_target"
    UNSUPPORTED_TARGET_WIDTH = "unsupported_target_width"
    UNSUPPORTED_OPERAND = "unsupported_operand"
    UNSEEDED_PREDECESSOR = "unseeded_predecessor"
    DIVERGENT_INCOMING_WORD = "divergent_incoming_word"
    WORD_CLOBBERED = "word_clobbered"
    UNKNOWN_EFFECT = "unknown_effect"
    DUPLICATE_TMP_PRODUCER = "duplicate_tmp_producer"
    STALE_TMP_VERSION = "stale_tmp_version"
    MISSING_BRANCH_TARGET = "missing_branch_target"
    POST_CONTROL_DATA_WRITE = "post_control_data_write"
    UNTRACKED_IP_WRITE = "untracked_ip_write"


@dataclass(frozen=True, slots=True)
class EntryWordSite8616:
    """One exact block/instruction site inside the transport cone."""

    block_addr: int
    instr_index: int
    instruction_addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this site deterministically."""
        return {
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
            "instruction_addr": self.instruction_addr,
        }


@dataclass(frozen=True, slots=True)
class EntryWordTransport8616:
    """One proven transport of the captured immutable word to a MOV destination.

    ``source`` is the seed definition site; ``target`` the selected MOV site;
    ``traversed_blocks`` the evaluated cone blocks; ``retained_exits`` the
    off-target CFG exits kept open — explicitly never closure evidence.
    """

    source: EntryWordSite8616
    target: EntryWordSite8616
    seed_register: str
    target_space: MemSpace
    target_tmp: int | None
    target_name: str | None
    target_version: int | None
    traversed_blocks: tuple[int, ...]
    retained_exits: tuple[int, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize this fact deterministically; identity stays object-bound."""
        return {
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "seed_register": self.seed_register,
            "target_space": self.target_space.value,
            "target_tmp": self.target_tmp,
            "target_name": self.target_name,
            "target_version": self.target_version,
            "traversed_blocks": list(self.traversed_blocks),
            "retained_exits": list(self.retained_exits),
        }


@dataclass(frozen=True, slots=True)
class EntryWordTransportRefusal8616:
    """One typed refusal against the targeted transport proof."""

    kind: EntryWordTransportRefusalKind8616
    detail: str
    block_addr: int | None = None
    instr_index: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this refusal deterministically."""
        return {
            "kind": self.kind.value,
            "detail": self.detail,
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
        }


@dataclass(frozen=True, slots=True)
class EntryWordTraversalStats8616:
    """Instruction observations, separate from the selected relation census.

    Observing a closed instruction effect does not materialize a word fact.
    Every retained diagnostic reason remains counted even when several reasons
    refuse the same single requested relation.
    """

    observed_instruction_count: int = 0
    closed_effect_count: int = 0
    refusal_count: int = 0

    def to_dict(self) -> dict[str, int]:
        """Serialize the unchanged instruction/refusal observations."""
        return {
            "observed_instruction_count": self.observed_instruction_count,
            "closed_effect_count": self.closed_effect_count,
            "refusal_count": self.refusal_count,
        }


@dataclass(frozen=True, slots=True)
class EntryWordTransportProof8616:
    """Closed-count result of one targeted entry-word transport proof.

    ``artifact`` and ``word_proof`` are retained by object identity; equal
    addresses or serialization are never proof of source ownership. All five
    evidence counters describe one requested relation, not its instructions.
    ``traversal`` preserves the independent instruction and refusal census.
    Materialization counts a proven word relation, never an emitted-C body.
    """

    artifact: IRFunctionArtifact = field(compare=False)
    word_proof: EntryStackWordProof8616 = field(compare=False)
    verdict: EntryWordTransportVerdict8616 = EntryWordTransportVerdict8616.REFUSED
    scope: EntryWordTransportScope8616 = EntryWordTransportScope8616.KNOWN_ACYCLIC_TARGET_CONE
    fact: EntryWordTransport8616 | None = None
    refusals: tuple[EntryWordTransportRefusal8616, ...] = ()
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    traversal: EntryWordTraversalStats8616 = EntryWordTraversalStats8616()

    def to_dict(self) -> dict[str, object]:
        """Serialize counts, fact, and refusals deterministically."""
        return {
            "verdict": self.verdict.value,
            "execution_scope": self.scope.value,
            "whole_frontier_closed": False,
            "function_addr": self.artifact.function_addr,
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
            "traversal": self.traversal.to_dict(),
            "fact": None if self.fact is None else self.fact.to_dict(),
            "refusals": [refusal.to_dict() for refusal in self.refusals],
        }
