# cython: language_level=3, infer_types=True
"""Typed return and storage-effect contracts for proven calls.

Layer: Semantics.
Responsibility: represent value ranges and segmented storage effects already
proven for one call; runtime-name lookup is one optional evidence source.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Forbidden: treating names as proof of target identity, materializing C
expressions, performing lowering/structuring, or accepting rendered-C text as
evidence.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import Enum

from inertia.ir.core import IRAddress
import dataclasses

__all__ = [
    "CallContractEvidenceKind8616",
    "IntegerValueRange8616",
    "RuntimeCallReturnContract8616",
    "RuntimeCallSemanticId8616",
    "runtime_call_return_contract_8616",
]


class RuntimeCallSemanticId8616(Enum):
    """Runtime-call identities with semantics used by the x86-16 pipeline."""

    C_RAND = "c_rand"


class CallContractEvidenceKind8616(Enum):
    """Evidence classes that may prove one call contract."""

    IDENTIFIED_RUNTIME = "identified_runtime"
    DECODED_BINARY = "decoded_binary"


@dataclasses.dataclass(frozen=True, )
class IntegerValueRange8616:
    """Inclusive integer range proven for one semantic value."""

    minimum: cython.longlong
    maximum: int | None

    @property
    def is_nonnegative(self) -> cython.bint:
        """Return whether every value in this range is nonnegative."""
        return self.minimum >= 0


@dataclasses.dataclass(frozen=True, )
class RuntimeCallReturnContract8616:
    """Typed return-value and storage-effect contract for one proven call.

    The historical class name remains stable for serialized lowering facts.
    ``semantic_id`` is absent for contracts proved directly from anonymous
    binary code.
    """

    semantic_id: RuntimeCallSemanticId8616 | None
    value_range: IntegerValueRange8616
    preserves_caller_storage: cython.bint
    evidence_kind: CallContractEvidenceKind8616 = (
        CallContractEvidenceKind8616.IDENTIFIED_RUNTIME
    )
    exact_memory_writes: tuple[IRAddress, ...] = ()
    has_unknown_memory_writes: cython.bint = False

    def preserves_address(self, address: IRAddress) -> cython.bint:
        """Return whether this contract proves one exact address unchanged."""
        write: object
        if self.preserves_caller_storage:
            return True
        if self.has_unknown_memory_writes or address.size <= 0:
            return False
        for write in self.exact_memory_writes:
            if (
                write.space is address.space
                and write.size > 0
                and write.offset < address.offset + address.size
                and address.offset < write.offset + write.size
            ):
                return False
        return True


_RUNTIME_RETURN_CONTRACTS_8616 = {
    "rand": RuntimeCallReturnContract8616(
        semantic_id=RuntimeCallSemanticId8616.C_RAND,
        value_range=IntegerValueRange8616(minimum=0, maximum=None),
        preserves_caller_storage=True,
    ),
}


@cython.ccall
def runtime_call_return_contract_8616(
    canonical_name: object,
) -> RuntimeCallReturnContract8616 | None:
    """Return semantics for a call identity resolved by binary/runtime evidence.

    This lookup does not identify a call target. Callers must first resolve the
    binary target to a canonical runtime identity. Unknown identities remain
    unproved.
    """
    if not isinstance(canonical_name, str):
        return None
    normalized = canonical_name.strip().lower().lstrip("_")
    if not normalized:
        return None
    return _RUNTIME_RETURN_CONTRACTS_8616.get(normalized)
