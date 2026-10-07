"""Bind emitted generated C to its completed acceptance proof.

Layer: CLI/fallback/reporting.
Responsibility: verify that the payload selected for cache, file, or stdout
emission is byte-identical to both the validated and compiler-checked payload.
Forbidden: decompiler semantics, rendered-C inference, or proof regeneration.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class AcceptedPayloadWorkResult8616(Protocol):
    """Read-only accepted-result surface; verification must not rewrite proofs."""

    @property
    def payload(self) -> str:
        """Return the exact generated C selected for emission."""
        ...

    @property
    def validated_payload_hash(self) -> str | None:
        """Return the hash independently recorded by semantic validation."""
        ...

    @property
    def gcc_checked_payload_hash(self) -> str | None:
        """Return the hash independently recorded by the compiler check."""
        ...


class AcceptedPayloadIntegrityVerdict8616(StrEnum):
    """Typed identity result for an accepted generated-C payload."""

    PASSED = "passed"
    EMPTY_PAYLOAD = "empty_payload"
    MISSING_VALIDATED_HASH = "missing_validated_hash"
    MISSING_COMPILER_HASH = "missing_compiler_hash"
    VALIDATED_PAYLOAD_MISMATCH = "validated_payload_mismatch"
    COMPILER_PAYLOAD_MISMATCH = "compiler_payload_mismatch"


@dataclass(frozen=True, slots=True)
class AcceptedPayloadIntegrity8616:
    """Closed payload-identity proof immediately before C emission."""

    verdict: AcceptedPayloadIntegrityVerdict8616
    payload_hash: str | None

    @property
    def passed(self) -> bool:
        """Return whether both acceptance hashes identify the current payload."""
        return self.verdict is AcceptedPayloadIntegrityVerdict8616.PASSED

    def diagnostic(self) -> str:
        """Return a stable diagnostic without exposing generated C text."""
        return f"accepted generated-C payload integrity={self.verdict.value}"


def verify_accepted_payload_integrity_8616(
    payload: str,
    *,
    validated_payload_hash: str | None,
    gcc_checked_payload_hash: str | None,
) -> AcceptedPayloadIntegrity8616:
    """Verify one payload against both independently recorded acceptance hashes."""
    if not payload.strip():
        return AcceptedPayloadIntegrity8616(
            AcceptedPayloadIntegrityVerdict8616.EMPTY_PAYLOAD,
            None,
        )
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if not validated_payload_hash:
        verdict = AcceptedPayloadIntegrityVerdict8616.MISSING_VALIDATED_HASH
    elif not gcc_checked_payload_hash:
        verdict = AcceptedPayloadIntegrityVerdict8616.MISSING_COMPILER_HASH
    elif validated_payload_hash != payload_hash:
        verdict = AcceptedPayloadIntegrityVerdict8616.VALIDATED_PAYLOAD_MISMATCH
    elif gcc_checked_payload_hash != payload_hash:
        verdict = AcceptedPayloadIntegrityVerdict8616.COMPILER_PAYLOAD_MISMATCH
    else:
        verdict = AcceptedPayloadIntegrityVerdict8616.PASSED
    return AcceptedPayloadIntegrity8616(verdict, payload_hash)


def verify_function_work_result_payload_integrity_8616(
    result: AcceptedPayloadWorkResult8616,
) -> AcceptedPayloadIntegrity8616:
    """Verify the accepted-payload identity carried by one owned work result."""
    return verify_accepted_payload_integrity_8616(
        result.payload,
        validated_payload_hash=result.validated_payload_hash,
        gcc_checked_payload_hash=result.gcc_checked_payload_hash,
    )
