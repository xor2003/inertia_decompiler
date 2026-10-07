"""Layer: Recovery/reporting.

Responsibility: project already-published recovery metadata into typed confidence evidence.
Forbidden: fabricating evidence counts, upgrading refused facts, or creating proof.

Producer schema (optional attachments on third-party angr codegen objects):

- ``type_structure_merging.apply_x86_16_structure_field_merging`` publishes
  ``codegen._inertia_struct_merging_*``: an ``_applied`` flag, the
  ``StorageObjectBridge`` itself, ``_member_facts``/``_array_facts``/
  ``_struct_facts``/``_refusal_facts`` dictionaries, a ``_typed_ir_facts``
  candidate dictionary, a ``_stats`` counter dictionary, and an ``_error``
  string on failure.
- ``type_array_matching.apply_x86_16_array_expression_matching`` publishes
  ``codegen._inertia_array_matching_*``: an ``_applied`` flag, the bridge,
  ``_lowerable_arrays``/``_refused_arrays`` dictionaries, ``_typed_ir_candidates``
  and ``_string_candidates`` dictionaries, a ``_stats`` dictionary, and an
  ``_error`` string on failure.
- ``segmented_memory_reasoning`` publishes ``codegen._inertia_segmented_memory_*``:
  an ``_applied`` flag, a bucketed ``_summary`` dictionary
  (``stable``/``over_associated``/``unknown`` mapping segment-register names to
  ``space``/``classification``/``confidence``/``evidence_count``/``known_values``
  entries), a ``_lowering`` policy dictionary, a ``_stats`` dictionary, and an
  ``_error`` string on failure.

Legacy ``cfunc._struct_recovery_info`` / ``cfunc._array_recovery_info`` /
``cfunc._segmented_memory_info`` attachments have no in-repo publishers. They
are still read here so external plugins that attach real owned record objects
keep working, but every payload is validated with ``isinstance`` against the
owned record types before any field is read; unvalidated payloads are recorded
in the channel's ``malformed`` tuple instead of being trusted.

Producer payloads are projected only while their channel is healthy
(``_applied`` true and no ``_error``). Payloads retained under an ERROR or
ABSENT producer state are stale: they are named in ``malformed`` and never
reach ``items``, so they cannot silently create ordinary confidence markers.
Individual entries are validated against the exact producer contract — key
shape, required keys, field types/widths, non-empty cardinality, and
key/value coherence — before contributing an item; anything else is named in
``malformed`` and contributes nothing.

Dynamic boundary: every attribute read on a third-party codegen/cfunc object
happens inside this module. Absent evidence yields an explicit ABSENT channel
status; unexpected exceptions propagate to the caller instead of being
converted into defaults.

Package ownership contract (canonical inertia/structuring package):
Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from inertia.cli.cli_storage_objects import StorageObjectRefusal
from inertia.ir.core import MemSpace, SegmentOrigin
from inertia.lowering.segmented_memory_reasoning import SegmentAssociation, SegmentAssociationAnalyzer, SegmentRegister
from inertia.lowering.type_array_matching import ArrayExpressionMatcher, ArrayRecoveryInfo
from inertia.lowering.type_storage_object_bridge import SegmentedStorageFact, StorageObjectBridgeFact
from inertia.lowering.type_structure_merging import StructField, StructRecoveryInfo, StructType, StructureFieldMerger

__all__ = [
    "ArrayEvidenceItem",
    "ConfidenceEvidence",
    "EvidenceChannel",
    "EvidenceRefusal",
    "EvidenceStatus",
    "SegmentEvidenceItem",
    "StructEvidenceItem",
    "load_confidence_evidence",
]


class EvidenceStatus(Enum):
    """Availability of one producer evidence channel."""

    ABSENT = "absent"  # Producer never ran or published nothing
    PRESENT = "present"  # Producer ran and its published payload validated
    ERROR = "error"  # Producer recorded a failure reason


@dataclass(frozen=True, slots=True)
class EvidenceRefusal:
    """Typed refusal fact reported by a producer for one object."""

    identity: str
    reason: str


@dataclass(frozen=True, slots=True)
class StructEvidenceItem:
    """One struct/object candidate projected from producer or legacy evidence."""

    identity: str
    source: str  # "storage_object" | "typed_ir" | "legacy"
    evidence_count: int
    evidence_basis: str  # What the count measures, e.g. "candidate field offset"
    segmented_allowed: bool
    refusal_reason: str | None = None  # Producer refusal verdict, when present


@dataclass(frozen=True, slots=True)
class ArrayEvidenceItem:
    """One array candidate projected from producer or legacy evidence."""

    identity: str
    source: str  # "storage_object" | "typed_ir" | "string_effect" | "legacy"
    evidence_count: int
    evidence_basis: str  # What the count measures, e.g. "access pattern"


@dataclass(frozen=True, slots=True)
class SegmentEvidenceItem:
    """One segment association projected from producer or legacy evidence."""

    segment: str
    bucket: str  # "stable" | "over_associated" | "unknown"
    classification: str
    stability: float
    evidence_count: int
    detail: str


@dataclass(frozen=True, slots=True)
class EvidenceChannel[ItemT]:
    """Validated projection of one producer evidence channel.

    ``status`` is ABSENT when no producer ran and no validated evidence
    exists, ERROR when the producer recorded a failure, and PRESENT when the
    producer applied or validated (legacy) evidence was read. ``items`` only
    ever contains entries validated against the current producer schema
    (or isinstance-validated legacy owned records); producer payloads retained
    under an ERROR or ABSENT state are named in ``malformed`` instead.
    ``malformed`` names every payload that failed validation or was retained
    under a non-healthy producer state; those payloads contribute no items
    and are never replaced by defaults.
    """

    status: EvidenceStatus
    items: tuple[ItemT, ...] = ()
    refusals: tuple[EvidenceRefusal, ...] = ()
    error: str | None = None
    malformed: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ConfidenceEvidence:
    """Complete projected recovery evidence for one confidence report."""

    structs: EvidenceChannel[StructEvidenceItem]
    arrays: EvidenceChannel[ArrayEvidenceItem]
    segments: EvidenceChannel[SegmentEvidenceItem]


def _applied_flag_8616(codegen: object, name: str, malformed: list[str]) -> bool:
    """Read a producer ``_applied`` flag at the dynamic codegen boundary."""
    value = getattr(codegen, name, None)
    if value is None:
        return False
    if not isinstance(value, bool):
        # A non-boolean applied flag is malformed producer state, not evidence.
        malformed.append(name)
        return False
    return value


def _error_string_8616(codegen: object, name: str) -> str | None:
    """Read a producer ``_error`` diagnostic at the dynamic codegen boundary."""
    value = getattr(codegen, name, None)
    return value if isinstance(value, str) and value else None


def _channel_status_8616(applied: bool, error: str | None, has_items: bool) -> EvidenceStatus:
    """Derive the channel status from producer state and validated evidence."""
    if error is not None:
        return EvidenceStatus.ERROR
    return EvidenceStatus.PRESENT if applied or has_items else EvidenceStatus.ABSENT


def _mapping_or_malformed_8616(
    value: object,
    name: str,
    malformed: list[str],
) -> dict[object, object]:
    """Validate a producer dictionary attachment at the dynamic codegen boundary."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        malformed.append(name)
        return {}
    return value


def _producer_payload_8616(
    codegen: object,
    name: str,
    usable: bool,
    status_label: str,
    malformed: list[str],
) -> dict[object, object]:
    """Read one producer mapping, refusing retained payloads of a failed channel.

    A non-empty mapping on a channel whose producer never applied or recorded
    an error is stale state: it is named in ``malformed`` and contributes no
    items rather than silently fabricating confidence markers. An empty
    mapping carries no evidence and needs no diagnosis.
    """
    # Dynamic codegen boundary: optional producer metadata on angr codegen objects.
    value = getattr(codegen, name, None)
    mapping = _mapping_or_malformed_8616(value, name, malformed)
    if usable or not mapping:
        return mapping
    malformed.append(f"{name} (retained under producer status {status_label})")
    return {}


def _is_plain_int_8616(value: object) -> bool:
    """Return whether a value is an int, excluding bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def _str_tuple_8616(value: object, min_len: int) -> tuple[str, ...] | None:
    """Return the value as a tuple of >= ``min_len`` strings, else None."""
    if (
        isinstance(value, (tuple, list))
        and len(value) >= min_len
        and all(isinstance(part, str) for part in value)
    ):
        return tuple(value)
    return None


def _int_tuple_8616(value: object, min_len: int) -> tuple[int, ...] | None:
    """Return the value as a tuple of >= ``min_len`` ints (no bool), else None."""
    if (
        isinstance(value, (tuple, list))
        and len(value) >= min_len
        and all(_is_plain_int_8616(part) for part in value)
    ):
        return tuple(value)
    return None


def _positive_count_8616(value: object) -> int | None:
    """Return the value as a positive plain int (bool excluded), else None."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    return None


def _unit_probability_8616(value: object) -> float | None:
    """Return the value as a finite [0, 1] probability (bool excluded), else None."""
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0.0 <= float(value) <= 1.0
    ):
        return float(value)
    return None


# Published value vocabularies, mirroring the current producers. Producer keys
# and fields are enum ``.value``/``.name`` strings, so these sets define the
# space each published payload may legitimately occupy.
_MEM_SPACE_VALUES_8616: frozenset[str] = frozenset(space.value for space in MemSpace)
_SEGMENT_ORIGIN_VALUES_8616: frozenset[str] = frozenset(origin.value for origin in SegmentOrigin)
_SEGMENT_REGISTER_NAMES_8616: frozenset[str] = frozenset(SegmentRegister.__members__)
_STRING_CANDIDATE_ROLES_8616: frozenset[str] = frozenset({"source", "destination"})

# Producer bucket for each classification, mirroring
# SegmentAssociationAnalyzer.summarize: single/const -> stable,
# over_associated -> over_associated, otherwise -> unknown.
_SEGMENT_CLASSIFICATION_BUCKET_8616: dict[str, str] = {
    "single": "stable",
    "const": "stable",
    "over_associated": "over_associated",
    "unknown": "unknown",
}


def _render_key_part_8616(part: object) -> str:
    """Render one key component, flattening nested tuples deterministically."""
    if isinstance(part, tuple):
        return ":".join(_render_key_part_8616(item) for item in part)
    return str(part)


def _base_key_identity_8616(base_key: object) -> str:
    """Render a deterministic identity for a storage-object base key."""
    rendered = _render_key_part_8616(base_key)
    return rendered if rendered else "<empty-base>"


def _typed_candidate_identity_8616(key: object) -> str:
    """Render a deterministic identity for a typed IR candidate key."""
    rendered = _render_key_part_8616(key)
    return rendered if rendered else "<empty-key>"


def _bridge_struct_items_8616(
    facts: dict[object, object],
    malformed: list[str],
) -> list[StructEvidenceItem]:
    """Project validated storage-object member facts into struct evidence items."""
    items: list[StructEvidenceItem] = []
    for base_key, fact in facts.items():
        if (
            not isinstance(fact, StorageObjectBridgeFact)
            or fact.object_kind != "member"  # producer member_facts carry only member kind
            or _int_tuple_8616(fact.candidate_offsets, 0) is None
            or not isinstance(fact.segmented_memory, SegmentedStorageFact)
        ):
            malformed.append(f"member_facts[{base_key!r}]")
            continue
        identity = _base_key_identity_8616(fact.base_key)
        items.append(
            StructEvidenceItem(
                identity=identity,
                source="storage_object",
                evidence_count=len(fact.candidate_offsets),
                evidence_basis="candidate field offset",
                segmented_allowed=fact.segmented_memory.allow_object_lowering,
                refusal_reason=fact.segmented_memory.refusal_reason(),
            )
        )
    return items


def _bridge_refusals_8616(
    refusals: dict[object, object],
    malformed: list[str],
) -> list[EvidenceRefusal]:
    """Project validated storage-object refusals into typed refusal facts."""
    items: list[EvidenceRefusal] = []
    for base_key, refusal in refusals.items():
        if not isinstance(refusal, StorageObjectRefusal):
            malformed.append(f"refusal_facts[{base_key!r}]")
            continue
        items.append(
            EvidenceRefusal(
                identity=_base_key_identity_8616(refusal.base_key),
                reason=refusal.reason,
            )
        )
    return items


def _typed_ir_struct_candidate_offsets_8616(
    key: object, candidate: object
) -> tuple[int, ...] | None:
    """Return a candidate's validated offsets, or None when it is off-contract.

    ``type_structure_merging._typed_ir_struct_candidates`` publishes
    ``(space: MemSpace value, base: tuple[str, ...])`` keys and dict values
    with ``space``, ``base`` (non-empty, key-identical), ``candidate_offsets``
    (>= 2 ints — the producer requires at least two offsets), non-empty
    ``candidate_widths`` ints, and ``has_phi_evidence`` set to True.
    """
    if not isinstance(key, tuple) or len(key) != 2 or not isinstance(candidate, dict):
        return None
    key_space, key_base = key
    key_base_tuple = _str_tuple_8616(key_base, 1)
    base = _str_tuple_8616(candidate.get("base"), 1)
    offsets = _int_tuple_8616(candidate.get("candidate_offsets"), 2)
    if not (
        isinstance(key_space, str)
        and key_space in _MEM_SPACE_VALUES_8616
        and key_base_tuple is not None
        and candidate.get("space") == key_space
        and base == key_base_tuple
        and offsets is not None
        and _int_tuple_8616(candidate.get("candidate_widths"), 1) is not None
        and candidate.get("has_phi_evidence") is True
    ):
        return None
    return offsets


def _typed_ir_struct_items_8616(
    candidates: dict[object, object],
    malformed: list[str],
) -> list[StructEvidenceItem]:
    """Project typed IR field-offset candidates into struct evidence items."""
    items: list[StructEvidenceItem] = []
    for key, candidate in candidates.items():
        offsets = _typed_ir_struct_candidate_offsets_8616(key, candidate)
        if offsets is None:
            malformed.append(f"typed_ir_facts[{key!r}]")
            continue
        items.append(
            StructEvidenceItem(
                identity=_typed_candidate_identity_8616(key),
                source="typed_ir",
                evidence_count=len(offsets),
                evidence_basis="candidate field offset",
                segmented_allowed=True,
            )
        )
    return items


def _functions_from_fields_8616(fields: dict[int, StructField]) -> int:
    """Count distinct functions recorded on an owned struct type's fields."""
    functions: set[str] = set()
    for struct_field in fields.values():
        functions.update(struct_field.functions)
    return len(functions)


def _legacy_struct_items_8616(legacy: object, malformed: list[str]) -> list[StructEvidenceItem]:
    """Project a validated legacy ``_struct_recovery_info`` attachment into items."""
    if legacy is None:
        return []
    items: list[StructEvidenceItem] = []
    if isinstance(legacy, (StructRecoveryInfo, StructType)):
        items.append(
            StructEvidenceItem(
                identity=legacy.name,
                source="legacy",
                evidence_count=_functions_from_fields_8616(legacy.fields),
                evidence_basis="function use",
                segmented_allowed=True,
            )
        )
    elif isinstance(legacy, StructureFieldMerger):
        for name, struct_type in legacy.structs.items():
            if not isinstance(struct_type, StructType):
                malformed.append(f"_struct_recovery_info.structs[{name!r}]")
                continue
            items.append(
                StructEvidenceItem(
                    identity=struct_type.name,
                    source="legacy",
                    evidence_count=_functions_from_fields_8616(struct_type.fields),
                    evidence_basis="function use",
                    segmented_allowed=True,
                )
            )
    else:
        malformed.append("_struct_recovery_info")
    return items


def _project_struct_channel_8616(codegen: object, cfunc: object | None) -> EvidenceChannel[StructEvidenceItem]:
    """Project struct-merging producer metadata into typed struct evidence."""
    malformed: list[str] = []
    applied = _applied_flag_8616(codegen, "_inertia_struct_merging_applied", malformed)
    error = _error_string_8616(codegen, "_inertia_struct_merging_error")
    usable = applied and error is None
    status_label = "error" if error is not None else "absent"

    # Dynamic codegen boundary: optional struct-merging attachments on angr codegen.
    items = _bridge_struct_items_8616(
        _producer_payload_8616(
            codegen, "_inertia_struct_merging_member_facts", usable, status_label, malformed
        ),
        malformed,
    )
    items.extend(
        _typed_ir_struct_items_8616(
            _producer_payload_8616(
                codegen, "_inertia_struct_merging_typed_ir_facts", usable, status_label, malformed
            ),
            malformed,
        )
    )
    refusals = _bridge_refusals_8616(
        _producer_payload_8616(
            codegen, "_inertia_struct_merging_refusal_facts", usable, status_label, malformed
        ),
        malformed,
    )
    # Dynamic cfunc boundary: optional legacy attachment on the structured C function.
    items.extend(_legacy_struct_items_8616(getattr(cfunc, "_struct_recovery_info", None), malformed))

    items.sort(key=lambda item: (item.source, item.identity))
    refusals.sort(key=lambda refusal: refusal.identity)
    return EvidenceChannel(
        status=_channel_status_8616(applied, error, bool(items)),
        items=tuple(items),
        refusals=tuple(refusals),
        error=error,
        malformed=tuple(malformed),
    )


def _bridge_array_items_8616(
    facts: dict[object, object],
    refusals: list[EvidenceRefusal],
    malformed: list[str],
) -> list[ArrayEvidenceItem]:
    """Project validated lowerable array bridge facts into array evidence items.

    The producer publishes ``lowerable_arrays`` already filtered by
    ``bridge.allows_object_lowering``. A fact in that map that carries a
    segmented-memory refusal (``allow_object_lowering`` not true) is stale or
    contradictory metadata: it is projected as a refusal — never as an
    ordinary item — and the inconsistent placement is named in ``malformed``.
    """
    items: list[ArrayEvidenceItem] = []
    for base_key, fact in facts.items():
        if (
            not isinstance(fact, StorageObjectBridgeFact)
            or fact.object_kind != "array"  # producer array_facts carry only array kind
            or _int_tuple_8616(fact.candidate_offsets, 0) is None
            or not isinstance(fact.segmented_memory, SegmentedStorageFact)
        ):
            malformed.append(f"lowerable_arrays[{base_key!r}]")
            continue
        if fact.segmented_memory.allow_object_lowering is not True:
            reason = (
                fact.segmented_memory.refusal_reason()
                or fact.segmented_memory.reason
                or "object lowering refused"
            )
            refusals.append(
                EvidenceRefusal(identity=_base_key_identity_8616(fact.base_key), reason=reason)
            )
            malformed.append(f"lowerable_arrays[{base_key!r}]")
            continue
        items.append(
            ArrayEvidenceItem(
                identity=_base_key_identity_8616(fact.base_key),
                source="storage_object",
                evidence_count=len(fact.candidate_offsets),
                evidence_basis="candidate element offset",
            )
        )
    return items


def _typed_ir_array_candidate_valid_8616(key: object, candidate: dict[object, object]) -> bool:
    """Validate one typed IR array candidate against the producer contract.

    ``type_array_matching._typed_ir_array_candidates`` publishes
    ``(space: MemSpace value, base: tuple[str, ...] (>= 2), element_size: int)``
    keys and dict values carrying the key-identical ``space``/``base``/
    ``element_size`` fields plus ``has_phi_index`` set to True.
    """
    if not isinstance(key, tuple) or len(key) != 3:
        return False
    key_space, key_base, key_size = key
    key_base_tuple = _str_tuple_8616(key_base, 2)
    base = _str_tuple_8616(candidate.get("base"), 2)
    element_size = candidate.get("element_size")
    return (
        isinstance(key_space, str)
        and key_space in _MEM_SPACE_VALUES_8616
        and key_base_tuple is not None
        and _is_plain_int_8616(key_size)
        and key_size >= 0
        and candidate.get("space") == key_space
        and base == key_base_tuple
        and _is_plain_int_8616(element_size)
        and element_size == key_size
        and candidate.get("has_phi_index") is True
    )


def _string_array_candidate_valid_8616(key: object, candidate: dict[object, object]) -> bool:
    """Validate one string-effect array candidate against the producer contract.

    ``type_array_matching._typed_string_array_candidates`` publishes the same
    key shape (base non-empty) and dict values carrying the key-identical
    ``space``/``base``/``element_size`` fields plus ``has_string_effect`` True,
    ``segment_origin`` (a SegmentOrigin value), non-empty ``string_family``
    and ``repeat_kind`` strings, and ``role`` in {"source", "destination"}.
    """
    if not isinstance(key, tuple) or len(key) != 3:
        return False
    key_space, key_base, key_size = key
    key_base_tuple = _str_tuple_8616(key_base, 1)
    base = _str_tuple_8616(candidate.get("base"), 1)
    element_size = candidate.get("element_size")
    segment_origin = candidate.get("segment_origin")
    return (
        isinstance(key_space, str)
        and key_space in _MEM_SPACE_VALUES_8616
        and key_base_tuple is not None
        and _is_plain_int_8616(key_size)
        and key_size >= 0
        and candidate.get("space") == key_space
        and base == key_base_tuple
        and _is_plain_int_8616(element_size)
        and element_size == key_size
        and candidate.get("has_string_effect") is True
        and isinstance(segment_origin, str)
        and segment_origin in _SEGMENT_ORIGIN_VALUES_8616
        and isinstance(candidate.get("string_family"), str)
        and bool(candidate.get("string_family"))
        and isinstance(candidate.get("repeat_kind"), str)
        and bool(candidate.get("repeat_kind"))
        and isinstance(candidate.get("role"), str)
        and candidate.get("role") in _STRING_CANDIDATE_ROLES_8616
    )


def _typed_candidate_array_items_8616(
    candidates: dict[object, object],
    source: str,
    field: str,
    malformed: list[str],
) -> list[ArrayEvidenceItem]:
    """Project typed IR or string-effect array candidates into evidence items."""
    items: list[ArrayEvidenceItem] = []
    for key, candidate in candidates.items():
        valid = isinstance(candidate, dict) and (
            _typed_ir_array_candidate_valid_8616(key, candidate)
            if source == "typed_ir"
            else _string_array_candidate_valid_8616(key, candidate)
        )
        if not valid:
            malformed.append(f"{field}[{key!r}]")
            continue
        items.append(
            ArrayEvidenceItem(
                identity=_typed_candidate_identity_8616(key),
                source=source,
                evidence_count=1,
                evidence_basis="typed IR candidate" if source == "typed_ir" else "string-effect record",
            )
        )
    return items


def _refused_array_refusals_8616(
    refused: dict[object, object],
    malformed: list[str],
) -> list[EvidenceRefusal]:
    """Project validated refused-array reasons into typed refusal facts."""
    items: list[EvidenceRefusal] = []
    for base_key, reason in refused.items():
        if reason is not None and not isinstance(reason, str):
            malformed.append(f"refused_arrays[{base_key!r}]")
            continue
        items.append(
            EvidenceRefusal(
                identity=_base_key_identity_8616(base_key),
                reason=reason if isinstance(reason, str) and reason else "refusal reason not published",
            )
        )
    return items


def _legacy_array_items_8616(legacy: object, malformed: list[str]) -> list[ArrayEvidenceItem]:
    """Project a validated legacy ``_array_recovery_info`` attachment into items."""
    if legacy is None:
        return []
    infos: list[ArrayRecoveryInfo] = []
    if isinstance(legacy, ArrayRecoveryInfo):
        infos = [legacy]
    elif isinstance(legacy, ArrayExpressionMatcher):
        infos_dict = legacy.array_infos
        for name, info in infos_dict.items():
            if not isinstance(info, ArrayRecoveryInfo):
                malformed.append(f"_array_recovery_info.array_infos[{name!r}]")
                continue
            infos.append(info)
    elif isinstance(legacy, dict):
        for name, info in legacy.items():
            if not isinstance(info, ArrayRecoveryInfo):
                malformed.append(f"_array_recovery_info[{name!r}]")
                continue
            infos.append(info)
    else:
        malformed.append("_array_recovery_info")
        return []
    return [
        ArrayEvidenceItem(
            identity=info.array_name,
            source="legacy",
            evidence_count=len(info.access_patterns),
            evidence_basis="access pattern",
        )
        for info in infos
    ]


def _project_array_channel_8616(codegen: object, cfunc: object | None) -> EvidenceChannel[ArrayEvidenceItem]:
    """Project array-matching producer metadata into typed array evidence."""
    malformed: list[str] = []
    applied = _applied_flag_8616(codegen, "_inertia_array_matching_applied", malformed)
    error = _error_string_8616(codegen, "_inertia_array_matching_error")
    usable = applied and error is None
    status_label = "error" if error is not None else "absent"

    refusals: list[EvidenceRefusal] = []
    # Dynamic codegen boundary: optional array-matching attachments on angr codegen.
    items = _bridge_array_items_8616(
        _producer_payload_8616(
            codegen, "_inertia_array_matching_lowerable_arrays", usable, status_label, malformed
        ),
        refusals,
        malformed,
    )
    items.extend(
        _typed_candidate_array_items_8616(
            _producer_payload_8616(
                codegen, "_inertia_array_matching_typed_ir_candidates", usable, status_label, malformed
            ),
            "typed_ir",
            "typed_ir_candidates",
            malformed,
        )
    )
    items.extend(
        _typed_candidate_array_items_8616(
            _producer_payload_8616(
                codegen, "_inertia_array_matching_string_candidates", usable, status_label, malformed
            ),
            "string_effect",
            "string_candidates",
            malformed,
        )
    )
    refusals.extend(
        _refused_array_refusals_8616(
            _producer_payload_8616(
                codegen, "_inertia_array_matching_refused_arrays", usable, status_label, malformed
            ),
            malformed,
        )
    )
    # Dynamic cfunc boundary: optional legacy attachment on the structured C function.
    items.extend(_legacy_array_items_8616(getattr(cfunc, "_array_recovery_info", None), malformed))

    items.sort(key=lambda item: (item.source, item.identity))
    refusals.sort(key=lambda refusal: refusal.identity)
    return EvidenceChannel(
        status=_channel_status_8616(applied, error, bool(items)),
        items=tuple(items),
        refusals=tuple(refusals),
        error=error,
        malformed=tuple(malformed),
    )


_SEGMENT_SUMMARY_BUCKETS_8616: tuple[str, ...] = ("stable", "over_associated", "unknown")


def _summary_segment_items_8616(
    summary: object,
    malformed: list[str],
) -> list[SegmentEvidenceItem]:
    """Project the published segmented-memory summary into segment evidence items."""
    if summary is None:
        return []
    if not isinstance(summary, dict):
        malformed.append("_inertia_segmented_memory_summary")
        return []
    items: list[SegmentEvidenceItem] = []
    for key in summary:
        if key not in _SEGMENT_SUMMARY_BUCKETS_8616:
            # Current producers publish exactly the three known buckets.
            malformed.append(f"_inertia_segmented_memory_summary[{key!r}]")
    for bucket in _SEGMENT_SUMMARY_BUCKETS_8616:
        entries = summary.get(bucket)
        if entries is None:
            continue
        if not isinstance(entries, dict):
            malformed.append(f"_inertia_segmented_memory_summary[{bucket!r}]")
            continue
        for segment_name, entry in entries.items():
            item = _summary_segment_item_8616(bucket, segment_name, entry, malformed)
            if item is not None:
                items.append(item)
    return items


def _summary_segment_item_8616(
    bucket: str,
    segment_name: object,
    entry: object,
    malformed: list[str],
) -> SegmentEvidenceItem | None:
    """Validate one segmented-memory summary entry into a segment evidence item.

    Producer contract (``SegmentAssociationAnalyzer.summarize``): keys are
    ``SegmentRegister`` names; each entry carries ``space`` (non-empty str),
    ``classification`` in {"single", "const", "over_associated", "unknown"}
    coherent with its bucket, ``confidence`` a finite float in [0, 1],
    ``evidence_count`` a positive int (zero-count entries are never
    published), and ``known_values`` a tuple of ints.
    """
    label = f"_inertia_segmented_memory_summary[{bucket!r}][{segment_name!r}]"
    if not isinstance(segment_name, str) or segment_name not in _SEGMENT_REGISTER_NAMES_8616:
        malformed.append(label)
        return None
    if not isinstance(entry, dict):
        malformed.append(label)
        return None
    classification = entry.get("classification")
    stability = _unit_probability_8616(entry.get("confidence"))
    evidence_count = _positive_count_8616(entry.get("evidence_count"))
    space = entry.get("space")
    known_values = _int_tuple_8616(entry.get("known_values"), 0)
    if not isinstance(classification, str) or _SEGMENT_CLASSIFICATION_BUCKET_8616.get(classification) != bucket:
        malformed.append(label)
        return None
    if (
        stability is None
        or evidence_count is None
        or not isinstance(space, str)
        or not space
        or known_values is None
    ):
        malformed.append(label)
        return None
    return SegmentEvidenceItem(
        segment=segment_name,
        bucket=bucket,
        classification=classification,
        stability=stability,
        evidence_count=evidence_count,
        detail=f"{segment_name}→{space} [{classification}]",
    )


def _legacy_segment_bucket_8616(classification: str) -> str:
    """Map a legacy segment-association classification onto a summary bucket."""
    if classification in {"single", "const"}:
        return "stable"
    if classification == "over_associated":
        return "over_associated"
    return "unknown"


def _legacy_segment_item_8616(assoc: SegmentAssociation) -> SegmentEvidenceItem:
    """Project one owned legacy segment association into a segment evidence item."""
    segment = assoc.segment_reg.name if isinstance(assoc.segment_reg, SegmentRegister) else str(assoc.segment_reg)
    classification = assoc.classification
    return SegmentEvidenceItem(
        segment=segment,
        bucket=_legacy_segment_bucket_8616(classification),
        classification=classification,
        stability=assoc.stability,
        evidence_count=assoc.evidence_count,
        detail=f"{segment}→{assoc.associated_space} [{classification}]",
    )


def _validated_segment_mapping_8616(
    entries: Iterable[tuple[object, object]],
    label: str,
    malformed: list[str],
) -> list[SegmentAssociation]:
    """Validate legacy (key, association) pairs into owned associations."""
    associations: list[SegmentAssociation] = []
    for key, assoc in entries:
        if not isinstance(assoc, SegmentAssociation):
            malformed.append(f"{label}[{key!r}]")
            continue
        associations.append(assoc)
    return associations


def _legacy_segment_associations_8616(legacy: object, malformed: list[str]) -> list[SegmentAssociation]:
    """Validate a legacy ``_segmented_memory_info`` payload into associations."""
    if isinstance(legacy, SegmentAssociation):
        return [legacy]
    if isinstance(legacy, SegmentAssociationAnalyzer):
        return _validated_segment_mapping_8616(
            legacy.associations.items(), "_segmented_memory_info.associations", malformed
        )
    if isinstance(legacy, dict):
        return _validated_segment_mapping_8616(legacy.items(), "_segmented_memory_info", malformed)
    if isinstance(legacy, (list, tuple)):
        associations: list[SegmentAssociation] = []
        for index, assoc in enumerate(legacy):
            if not isinstance(assoc, SegmentAssociation):
                malformed.append(f"_segmented_memory_info[{index}]")
                continue
            associations.append(assoc)
        return associations
    malformed.append("_segmented_memory_info")
    return []


def _legacy_segment_items_8616(legacy: object, malformed: list[str]) -> list[SegmentEvidenceItem]:
    """Project a validated legacy ``_segmented_memory_info`` attachment into items."""
    if legacy is None:
        return []
    return [
        _legacy_segment_item_8616(assoc)
        for assoc in _legacy_segment_associations_8616(legacy, malformed)
    ]


def _project_segment_channel_8616(codegen: object, cfunc: object | None) -> EvidenceChannel[SegmentEvidenceItem]:
    """Project segmented-memory producer metadata into typed segment evidence."""
    malformed: list[str] = []
    applied = _applied_flag_8616(codegen, "_inertia_segmented_memory_applied", malformed)
    error = _error_string_8616(codegen, "_inertia_segmented_memory_error")
    usable = applied and error is None
    status_label = "error" if error is not None else "absent"

    # Dynamic codegen boundary: optional segmented-memory attachments on angr codegen.
    items = _summary_segment_items_8616(
        _producer_payload_8616(
            codegen, "_inertia_segmented_memory_summary", usable, status_label, malformed
        ),
        malformed,
    )
    # Dynamic cfunc boundary: optional legacy attachment on the structured C function.
    items.extend(_legacy_segment_items_8616(getattr(cfunc, "_segmented_memory_info", None), malformed))

    items.sort(key=lambda item: (item.segment, item.bucket))
    return EvidenceChannel(
        status=_channel_status_8616(applied, error, bool(items)),
        items=tuple(items),
        error=error,
        malformed=tuple(malformed),
    )


def load_confidence_evidence(codegen: object, cfunc: object | None) -> ConfidenceEvidence:
    """Project all published producer metadata into typed confidence evidence.

    Args:
        codegen: Third-party angr codegen object carrying optional producer
            ``_inertia_*`` metadata attachments.
        cfunc: Optional structured C function carrying optional legacy
            ``_*_recovery_info`` attachments.

    Returns:
        Typed evidence channels. Absent producers yield ABSENT channels and
        malformed payloads are named in each channel's ``malformed`` tuple;
        neither is replaced by fabricated defaults.

    Raises:
        Any unexpected exception raised by third-party attribute access
        propagates unchanged; only absent/malformed evidence is tolerated.
    """
    return ConfidenceEvidence(
        structs=_project_struct_channel_8616(codegen, cfunc),
        arrays=_project_array_channel_8616(codegen, cfunc),
        segments=_project_segment_channel_8616(codegen, cfunc),
    )
