"""Layer: IR.

Responsibility: retain typed outcomes and five-stage accounting for modular
stack-argument use evidence without inferring source-language signedness.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .logical_memory_contracts import IRLogicalMemoryAccessKey8616


class ModularArgumentUseVerdict8616(Enum):
    """Whether one exact stack input has a closed modular return use."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class ModularReturnRegister8616(Enum):
    """One word carrier whose exact bit-pattern use reaches a return."""

    AX = "ax"
    DX = "dx"


class ModularArgumentUseFailure8616(Enum):
    """Typed reason that the proposed sign-insensitive use is not proven."""

    FUNCTION_IDENTITY_CONFLICT = "function_identity_conflict"
    CFG_NOT_CLOSED = "cfg_not_closed"
    INPUT_ACCESS_UNKNOWN = "input_access_unknown"
    CALL_EFFECT_UNKNOWN = "call_effect_unknown"
    SSA_DEFINITION_UNKNOWN = "ssa_definition_unknown"
    SIGN_DEPENDENT_OPERATION = "sign_dependent_operation"
    UNSUPPORTED_USE = "unsupported_use"
    RETURN_FLOW_UNKNOWN = "return_flow_unknown"


@dataclass(frozen=True, slots=True)
class ModularArgumentUseStats8616:
    """Account for the one requested input-use proof without hidden success."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class ModularArgumentUseResult8616:
    """Closed bit-pattern use evidence or an explicit typed refusal."""

    verdict: ModularArgumentUseVerdict8616
    failure: ModularArgumentUseFailure8616 | None
    stats: ModularArgumentUseStats8616
    input_access_key: IRLogicalMemoryAccessKey8616 | None = None
    return_instruction_addr: int | None = None


__all__ = [
    "ModularArgumentUseFailure8616",
    "ModularArgumentUseResult8616",
    "ModularArgumentUseStats8616",
    "ModularArgumentUseVerdict8616",
    "ModularReturnRegister8616",
]
