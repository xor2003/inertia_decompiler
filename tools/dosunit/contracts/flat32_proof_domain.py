"""Caller-declared entry-ESP interval premise for flat32 call proofs.

Layer: dosunit proof input domain.
Responsibility: own the typed, validated, caller-supplied ``esp`` interval
that bounds the stack window a composed flat32 function is proved under.
The premise is strictly an assumption: it is never derived from an image,
never defaulted, and every verdict produced under it must be published as
``conditional`` with the exact interval serialized.

The interval binds only the TOP-LEVEL caller entry ``esp`` input.  Callee
summaries are composed once over unconstrained callee entry inputs and
reused at every callsite, so a nested return proof runs over a different
``esp`` input — the nested caller's entry ``esp``, shifted by that caller's
push sequence.  No constant-width transport of the root interval into that
frame exists inside the shared callee composition, so nested return proofs
always run premise-free; a nested callee that needs the premise refuses on
exactly the same evidence as it would with no domain declared.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

UINT32_MAX: int = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class Flat32ProofDomain:
    """Closed unsigned interval premise on the composed entry ``esp`` input.

    ``esp_min``/``esp_max`` are inclusive bounds on the value of ``esp`` at
    the TOP-LEVEL function entry.  The domain never constrains callee-entry
    ``esp`` inputs, which are related to the root ``esp`` by each callsite's
    push sequence; consumers must attach :meth:`constraints` only where the
    free ``esp`` input denotes the declared root entry frame.
    """

    esp_min: int
    esp_max: int

    def __post_init__(self) -> None:
        """Reject non-integer, Boolean, out-of-word and empty intervals."""
        for bound in (self.esp_min, self.esp_max):
            if type(bound) is not int:
                raise ValueError("flat32 proof domain bounds must be plain integers")
        if not 0 <= self.esp_min <= self.esp_max <= UINT32_MAX:
            raise ValueError("flat32 proof domain requires a nonempty uint32 interval")

    def constraints(self) -> list[dict[str, Any]]:
        """Serialize the premise for the SSA ``input_constraints`` channel."""
        return [
            {
                "name": "esp",
                "kind": "unsigned_range",
                "min": self.esp_min,
                "max": self.esp_max,
            }
        ]

    def assumption_document(self) -> dict[str, Any]:
        """Serialize the premise as an explicit unproved-assumption payload."""
        return {
            "kind": "caller_supplied_entry_esp_domain",
            "proved": False,
            "provenance": "caller_supplied_domain",
            "input": "esp",
            "interval": {"min": hex(self.esp_min), "max": hex(self.esp_max)},
            "scope": (
                "top-level entry esp is assumed to lie in the declared closed unsigned "
                "interval for the whole proof; the interval is caller-supplied evidence, "
                "not derived from the image, and is never transported onto nested callee "
                "entry frames whose esp is shifted by the caller's pushes"
            ),
        }
