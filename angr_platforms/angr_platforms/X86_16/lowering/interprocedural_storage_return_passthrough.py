"""Materialize exact deferred return pass-through trials.

Layer: Types/Lowering.
Responsibility: join one recursive caller-return fact, Semantics-owned terminal
path proof, and the exact SSA CALL identity without choosing output storage or
type. SCC resolution is the only permitted consumer that may complete it.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from ..call_target_identity import x86_16_call_targets_equivalent_8616
from ..caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallsiteReturnUseKind8616,
)
from ..ir import IRInstr, IRValue, MemSpace
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
)
from ..semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)
from ..semantics.terminal_return_passthrough import (
    TerminalReturnPassThroughEvidence8616,
    collect_terminal_return_passthrough_evidence_8616,
)
from .interprocedural_storage_caller_context import CallerSSAContext8616
from .interprocedural_storage_contracts import StorageTrialStats8616
from .interprocedural_storage_return_defs import call_candidates_at_address_8616
from .interprocedural_storage_return_passthrough_contracts import (
    ReturnPassThroughTrial8616,
    ReturnPassThroughTrialFailure8616,
)

__all__ = [
    "ReturnPassThroughTrialResult8616",
    "materialize_return_passthrough_trial_8616",
]


@dataclass(frozen=True, slots=True)
class ReturnPassThroughTrialResult8616:
    """One exact deferred trial or an atomic typed refusal."""

    trial: ReturnPassThroughTrial8616 | None
    failure: ReturnPassThroughTrialFailure8616 | None
    semantic_evidence: TerminalReturnPassThroughEvidence8616 | None
    ssa_failure: FunctionSSAArtifactFailure8616 | None
    stats: StorageTrialStats8616

    @property
    def complete(self) -> bool:
        """Return whether one semantic fact became one complete deferred trial."""
        return (
            self.trial is not None
            and self.trial.is_complete
            and self.failure is None
            and self.ssa_failure is None
            and self.semantic_evidence is not None
            and self.semantic_evidence.complete
            and self.stats.complete
        )


class _FunctionManager8616(Protocol):
    """Third-party function lookup needed at the Lowering boundary."""

    def function(self, *, addr: int, create: bool) -> object | None:
        """Return one exact existing function without creating a guess."""


class _ProjectKnowledgeBase8616(Protocol):
    """Third-party knowledge-base fields required for caller lookup."""

    functions: _FunctionManager8616


class _ProjectSurface8616(Protocol):
    """Third-party project fields required for caller lookup."""

    kb: _ProjectKnowledgeBase8616


def _refused_result_8616(
    failure: ReturnPassThroughTrialFailure8616,
    *,
    semantic_evidence: TerminalReturnPassThroughEvidence8616 | None = None,
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None,
    normalized: bool = False,
) -> ReturnPassThroughTrialResult8616:
    """Build one atomic refusal with its upstream evidence retained."""
    return ReturnPassThroughTrialResult8616(
        trial=None,
        failure=failure,
        semantic_evidence=semantic_evidence,
        ssa_failure=ssa_failure,
        stats=StorageTrialStats8616(
            raw_fact_count=1,
            normalized_fact_count=int(normalized),
            failure_count=1,
        ),
    )


def _semantic_passthrough_gate_8616(
    caller_project: object | None,
    caller_function: object,
    fact: CallerReturnUseFact8616,
) -> TerminalReturnPassThroughEvidence8616 | ReturnPassThroughTrialResult8616:
    """Collect the unique semantic passthrough fact or a typed refusal."""
    semantic_evidence = collect_terminal_return_passthrough_evidence_8616(
        caller_project,
        caller_function,
        (fact.callsite_addr,),
    )
    if not semantic_evidence.complete or len(semantic_evidence.facts) != 1:
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.SEMANTIC_EVIDENCE_REFUSED,
            semantic_evidence=semantic_evidence,
        )
    semantic_fact = semantic_evidence.facts[0]
    if (
        semantic_fact.caller_addr != fact.caller_addr
        or semantic_fact.callsite_addr != fact.callsite_addr
    ):
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.SEMANTIC_FACT_CONFLICT,
            semantic_evidence=semantic_evidence,
            normalized=True,
        )
    if semantic_fact.return_instruction_addr != fact.witness_instruction_addr:
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.RETURN_WITNESS_CONFLICT,
            semantic_evidence=semantic_evidence,
            normalized=True,
        )
    return semantic_evidence


def _callsite_call_gate_8616(
    caller_project: object | None,
    caller_function: object,
    fact: CallerReturnUseFact8616,
    semantic_evidence: TerminalReturnPassThroughEvidence8616,
) -> tuple[int, int, IRInstr] | ReturnPassThroughTrialResult8616:
    """Return the single typed CALL at the callsite or a typed refusal."""
    ssa = semantic_function_ssa_artifact_at_address_8616(
        caller_project, fact.caller_addr, function=caller_function
    )
    artifact = ssa.artifact
    if artifact is None:
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.CALLER_SSA_UNAVAILABLE,
            semantic_evidence=semantic_evidence,
            ssa_failure=ssa.failure,
            normalized=True,
        )
    if artifact.function_addr != fact.caller_addr:
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.FUNCTION_IDENTITY_CONFLICT,
            semantic_evidence=semantic_evidence,
            normalized=True,
        )
    candidates = call_candidates_at_address_8616(artifact, fact.callsite_addr)
    if not candidates:
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.CALLSITE_NOT_FOUND,
            semantic_evidence=semantic_evidence,
            normalized=True,
        )
    if len(candidates) != 1:
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.CALLSITE_CONFLICT,
            semantic_evidence=semantic_evidence,
            normalized=True,
        )
    block_addr, instr_index, instruction = candidates[0]
    if len(instruction.args) != 1 or not isinstance(instruction.args[0], IRValue):
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.CALL_TARGET_UNKNOWN,
            semantic_evidence=semantic_evidence,
            normalized=True,
        )
    return block_addr, instr_index, instruction


def materialize_return_passthrough_trial_8616(
    project: object,
    callee_addr: int,
    fact: CallerReturnUseFact8616,
    accepted_target_addrs: tuple[int, ...],
    caller_context: CallerSSAContext8616 | None = None,
) -> ReturnPassThroughTrialResult8616:
    """Join one proven recursive return path to its exact typed SSA CALL."""
    if (
        fact.kind is not CallsiteReturnUseKind8616.FUNCTION_RETURN
        or not fact.excluded_recursive_passthrough
    ):
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.RETURN_FACT_NOT_PASSTHROUGH,
        )
    caller_project = project if caller_context is None else caller_context.evidence_project
    caller_function = None if caller_context is None else caller_context.caller_function
    if caller_function is None and caller_project is not None:
        try:
            caller_function = cast(_ProjectSurface8616, caller_project).kb.functions.function(
                addr=fact.caller_addr, create=False
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            caller_function = None
    if caller_function is None:
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.CALLER_FUNCTION_UNAVAILABLE,
        )
    gate = _semantic_passthrough_gate_8616(caller_project, caller_function, fact)
    if isinstance(gate, ReturnPassThroughTrialResult8616):
        return gate
    semantic_evidence = gate
    semantic_fact = semantic_evidence.facts[0]

    call_gate = _callsite_call_gate_8616(
        caller_project, caller_function, fact, semantic_evidence
    )
    if isinstance(call_gate, ReturnPassThroughTrialResult8616):
        return call_gate
    block_addr, instr_index, instruction = call_gate
    target = instruction.args[0]
    if target.space is not MemSpace.CONST or not isinstance(target.const, int):
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.CALL_TARGET_UNKNOWN,
            semantic_evidence=semantic_evidence,
            normalized=True,
        )
    targets = frozenset((callee_addr, *accepted_target_addrs))
    target_matches = any(
        x86_16_call_targets_equivalent_8616(caller_project, target.const, accepted)
        for accepted in targets
    )
    semantic_target_matches = x86_16_call_targets_equivalent_8616(
        caller_project, semantic_fact.target_addr, target.const
    )
    if not target_matches or not semantic_target_matches:
        return _refused_result_8616(
            ReturnPassThroughTrialFailure8616.CALL_TARGET_CONFLICT,
            semantic_evidence=semantic_evidence,
            normalized=True,
        )
    trial = ReturnPassThroughTrial8616(
        callee_addr=callee_addr,
        caller_addr=fact.caller_addr,
        callsite_addr=fact.callsite_addr,
        target_addr=target.const,
        return_instruction_addr=semantic_fact.return_instruction_addr,
        path_block_addrs=semantic_fact.path_block_addrs,
        call_block_addr=block_addr,
        call_instr_index=instr_index,
    )
    return ReturnPassThroughTrialResult8616(
        trial=trial,
        failure=None,
        semantic_evidence=semantic_evidence,
        ssa_failure=None,
        stats=StorageTrialStats8616(1, 1, 1, 1),
    )
