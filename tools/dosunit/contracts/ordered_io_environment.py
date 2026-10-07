"""Declared ordered-I/O environment contract for binary proof lanes.

Layer: dosunit machine-model contracts.
Responsibility: own the single typed, content-bound declaration under which
decoded scalar port I/O may be admitted into a machine-state comparison.
The contract binds the lane architecture, the admitted width and effect
domains, the covered scalar instruction forms and VEX dirty helpers, the
ordered event relation, and an explicit caller premise.  A model name alone
never proves behavior: admission still requires every decoded binary effect
to be covered by the modeled event semantics and every lifted event to be
retained in the ordered ``io`` state that both sides compare in full.

The premise is strictly an assumption — "both executables observe identical
responses for an identical ordered event history" — not a claim of universal
real-device equivalence.  Missing, malformed or incompatible bindings refuse;
there is no default environment.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from capstone.x86_const import X86_INS_IN, X86_INS_OUT

from tools.dosunit.contracts.binary_environment import EnvironmentEffect
from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.contracts.proof_contracts import Architecture

ORDERED_IO_SCHEMA: Final[str] = "dosunit.ordered_io.v1"
ORDERED_IO_MODEL: Final[str] = "ordered_scalar_port_io"
ORDERED_IO_VERSION: Final[str] = "v1"
#: Exact public identity string a caller must declare to bind the canonical
#: model.  Any other model/version spelling is an incompatible binding and
#: refuses at intake.
ORDERED_IO_MODEL_IDENTITY: Final[str] = "dosunit.ordered_io.scalar_in_out.v1"
ORDERED_IO_PREMISE_NAME: Final[str] = "unproved_ordered_io_environment"

_SUPPORTED_ARCHITECTURES: Final[frozenset[Architecture]] = frozenset(
    {Architecture.REAL16, Architecture.FLAT32}
)
_SUPPORTED_WIDTHS: Final[frozenset[int]] = frozenset({8, 16, 32})
_SUPPORTED_EFFECTS: Final[frozenset[EnvironmentEffect]] = frozenset(
    {EnvironmentEffect.PORT_READ, EnvironmentEffect.PORT_WRITE}
)
#: Scalar port forms only.  String forms (INS*/OUTS*) decode as port effects
#: but are never covered: they carry an implicit counted memory relation the
#: declared event semantics do not model.
_SUPPORTED_INSTRUCTIONS: Final[frozenset[int]] = frozenset({X86_INS_IN, X86_INS_OUT})
#: Direction is bound to the scalar form: an IN cannot stand for a PORT_WRITE
#: event and an OUT cannot stand for a PORT_READ, even when a declared subset
#: contains both set members independently.
_INSTRUCTION_EFFECT: Final[dict[int, EnvironmentEffect]] = {
    X86_INS_IN: EnvironmentEffect.PORT_READ,
    X86_INS_OUT: EnvironmentEffect.PORT_WRITE,
}
_SUPPORTED_HELPERS: Final[frozenset[str]] = frozenset(
    {"x86g_dirtyhelper_IN", "x86g_dirtyhelper_OUT"}
)


def _checked_frozenset(
    name: str,
    value: object,
    supported: frozenset[Any],
    element_type: type,
) -> frozenset[Any]:
    """Require a nonempty frozenset of ``element_type`` inside the domain.

    The element check is separate from the subset check: ``StrEnum`` members
    compare and hash equal to their string values, so a raw string could
    otherwise alias a declared effect without being one.
    """
    if not isinstance(value, frozenset) or not value or not value <= supported:
        raise ValueError(f"ordered-io contract {name} must be a nonempty subset of the supported domain")
    if not all(isinstance(item, element_type) for item in value):
        raise ValueError(f"ordered-io contract {name} contains an element of the wrong type")
    return value


@dataclass(frozen=True, slots=True)
class OrderedIoContract:
    """One typed declared ordered-I/O environment relation.

    ``model``/``version`` identify the relation; the remaining fields are its
    full semantic content — lane architecture, admitted scalar widths, covered
    effects, scalar instruction forms and lifted dirty helpers.  Sealed reports
    bind :meth:`to_document`, so two declarations that differ in any content
    field produce different contract identities even when names agree.
    """

    architecture: Architecture
    model: str
    version: str
    widths: frozenset[int]
    effects: frozenset[EnvironmentEffect]
    scalar_instruction_ids: frozenset[int]
    dirty_helpers: frozenset[str]

    def __post_init__(self) -> None:
        """Reject malformed or unsupported contract content; fail closed."""
        if not isinstance(self.architecture, Architecture) or self.architecture not in _SUPPORTED_ARCHITECTURES:
            raise ValueError("ordered-io contract requires a supported lane architecture")
        if self.model != ORDERED_IO_MODEL or self.version != ORDERED_IO_VERSION:
            raise ValueError("ordered-io contract model/version is not the declared relation")
        object.__setattr__(self, "widths", _checked_frozenset("widths", self.widths, _SUPPORTED_WIDTHS, int))
        object.__setattr__(
            self, "effects", _checked_frozenset("effects", self.effects, _SUPPORTED_EFFECTS, EnvironmentEffect)
        )
        object.__setattr__(
            self, "scalar_instruction_ids",
            _checked_frozenset(
                "scalar_instruction_ids", self.scalar_instruction_ids, _SUPPORTED_INSTRUCTIONS, int
            ),
        )
        object.__setattr__(
            self, "dirty_helpers",
            _checked_frozenset("dirty_helpers", self.dirty_helpers, _SUPPORTED_HELPERS, str),
        )

    def covers_event(self, effect: EnvironmentEffect, instruction_id: int, width_bits: int | None) -> bool:
        """Return True when one decoded instruction event is modeled.

        Only scalar IN/OUT instruction identities with a decoded scalar width
        inside the declared domain are covered; string forms, unknown widths
        and unmodeled directions are not.  The effect must be the direction
        the instruction performs — set membership alone cannot alias IN for
        a write or OUT for a read.
        """
        return (
            isinstance(effect, EnvironmentEffect)
            and effect in self.effects
            and isinstance(instruction_id, int)
            and instruction_id in self.scalar_instruction_ids
            and _INSTRUCTION_EFFECT.get(instruction_id) == effect
            and isinstance(width_bits, int)
            and width_bits in self.widths
        )

    def covers_helper(self, name: str) -> bool:
        """Return True when a lifted VEX dirty helper is a modeled I/O event."""
        return name in self.dirty_helpers

    def validate_for(self, architecture: Architecture) -> OrderedIoContract:
        """Bind the contract to a lane or refuse an incompatible identity."""
        if self.architecture is not architecture:
            raise ValueError(
                f"ordered-io contract architecture {self.architecture.value} "
                f"does not match lane {architecture.value}"
            )
        return self

    def to_document(self) -> dict[str, Any]:
        """Serialize the complete contract deterministically for sealing."""
        return {
            "schema": ORDERED_IO_SCHEMA,
            "model": self.model,
            "version": self.version,
            "identity": ORDERED_IO_MODEL_IDENTITY,
            "architecture": self.architecture.value,
            "widths": sorted(self.widths),
            "effects": sorted(effect.value for effect in self.effects),
            "scalar_instruction_ids": sorted(self.scalar_instruction_ids),
            "dirty_helpers": sorted(self.dirty_helpers),
            "relation": "ordered_io_events",
        }

    def identity_digest(self) -> str:
        """Content digest of the declared relation for premise binding."""
        return hashlib.sha256(canonical_json_bytes(self.to_document())).hexdigest()

    def premise_document(self) -> dict[str, Any]:
        """Serialize the explicit caller premise bound into verdicts.

        The premise is unproved by construction: it asserts that identical
        ordered event histories receive identical environment responses on
        both sides.  It does not claim equivalence of the real devices.
        """
        return {
            "kind": "declared_ordered_io_environment",
            "proved": False,
            "provenance": "caller_declared_contract",
            "model": self.to_document(),
            "relation_identity": self.identity_digest(),
            "scope": (
                "every decoded scalar port IN/OUT event is retained in order in the "
                "compared io state, including reads whose returned value is dead; both "
                "sides are assumed to receive identical responses for the identical "
                "ordered event history — an explicit caller premise, not a universal "
                "device-equivalence claim"
            ),
        }


def declared_ordered_io(architecture: Architecture) -> OrderedIoContract:
    """Construct the canonical declared scalar port-I/O contract for a lane."""
    return OrderedIoContract(
        architecture=architecture,
        model=ORDERED_IO_MODEL,
        version=ORDERED_IO_VERSION,
        widths=frozenset(_SUPPORTED_WIDTHS),
        effects=frozenset(_SUPPORTED_EFFECTS),
        scalar_instruction_ids=frozenset(_SUPPORTED_INSTRUCTIONS),
        dirty_helpers=frozenset(_SUPPORTED_HELPERS),
    )


def parse_ordered_io_identity(value: object, architecture: Architecture) -> OrderedIoContract:
    """Bind a caller-declared model identity or refuse the malformed binding.

    Only the exact canonical model identity is admitted: the declaration names
    a typed in-code relation whose content is sealed into the proof contract,
    so a version, architecture or name mismatch cannot alias the real model.
    """
    if value != ORDERED_IO_MODEL_IDENTITY:
        raise ValueError(
            f"unsupported ordered-io environment binding: {value!r} "
            f"(expected {ORDERED_IO_MODEL_IDENTITY!r})"
        )
    return declared_ordered_io(architecture).validate_for(architecture)


def premise_identity(premise: object) -> str | None:
    """Return the relation identity recorded in an assumption payload."""
    if not isinstance(premise, Mapping):
        return None
    value = premise.get("relation_identity")
    return value if isinstance(value, str) else None
