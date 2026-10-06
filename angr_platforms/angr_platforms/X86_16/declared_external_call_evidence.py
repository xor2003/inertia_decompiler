"""Bind optional declared external-call segment relations to exact evidence.

Layer: Frontend.
Responsibility: parse explicit caller-supplied external-call declarations,
admit them only when they bind to the exact current input image, an exact
caller byte range and digest, an exact decoded direct CALL coordinate, an
exact registered synthetic-stub target, and an exact near/far call distance.
The single admitted relation is ``DS_after == DS_before`` on normal return.
The module also owns the immutable replayable consumption receipt that IR
segment-state transfer produces when it consumes an admitted declaration.
Forbidden: inferring effects from names, placeholder bytes, rendered C, or
ABI defaults; admitting a real callee body; or authorizing memory, general-
register, flag, or return-value semantics.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, Protocol, cast

from .synthetic_call_stub_evidence import is_synthetic_call_stub_8616

__all__ = (
    "DECLARED_EXTERNAL_CALL_EFFECT_SCHEMA_8616",
    "DeclaredCallAdmission8616",
    "DeclaredCallAdmissionFailure8616",
    "DeclaredCallAssumption8616",
    "DeclaredCallEffectConsumption8616",
    "DeclaredExternalCallAdmissionError8616",
    "DeclaredExternalCallRegistry8616",
    "DeclaredExternalCallRelation8616",
    "DeclaredExternalCallSpec8616",
    "admit_declared_external_call_files_8616",
    "declared_call_effect_consumption_from_record_8616",
    "declared_external_call_registry_8616",
)

DECLARED_EXTERNAL_CALL_EFFECT_SCHEMA_8616: int = 1
_DECLARED_CALL_SITE_RECORD_SCHEMA_8616: int = 1
_HEX_DIGEST_LENGTH_8616: int = 64
_MAX_DECLARED_CALL_EFFECT_FILES_8616: int = 16
_MAX_DECLARED_CALLS_PER_FILE_8616: int = 256


class DeclaredExternalCallRelation8616(StrEnum):
    """Enumerated relations an external-call declaration may assert."""

    DS_PRESERVED_ON_RETURN = "ds_preserved_on_return"


class DeclaredCallAssumption8616(StrEnum):
    """Typed assumption recorded when a declaration is consumed."""

    DECLARED_EXTERNAL_CALL_EFFECT = "DECLARED_EXTERNAL_CALL_EFFECT"


class DeclaredCallAdmissionFailure8616(StrEnum):
    """Stable typed reasons a declaration cannot bind the current evidence."""

    SCHEMA_UNSUPPORTED = "schema_unsupported"
    FIELD_MALFORMED = "field_malformed"
    RELATION_MISSING = "relation_missing"
    RELATION_UNSUPPORTED = "relation_unsupported"
    IMAGE_DIGEST_MISMATCH = "image_digest_mismatch"
    CALLER_RANGE_INVALID = "caller_range_invalid"
    CALLER_DIGEST_MISMATCH = "caller_digest_mismatch"
    CALLSITE_OUT_OF_CALLER = "callsite_out_of_caller"
    CALLSITE_NOT_DECODED_CALL = "callsite_not_decoded_call"
    DISTANCE_MISMATCH = "distance_mismatch"
    TARGET_MISMATCH = "target_mismatch"
    TARGET_NOT_SYNTHETIC_STUB = "target_not_synthetic_stub"
    DUPLICATE_CALLSITE = "duplicate_callsite"
    CONTRADICTORY_DECLARATION = "contradictory_declaration"


class DeclaredExternalCallAdmissionError8616(ValueError):
    """A declaration file or binding refused under the typed contract."""

    def __init__(self, failure: DeclaredCallAdmissionFailure8616, detail: str) -> None:
        """Retain the typed failure and a human-readable detail."""
        super().__init__(f"declared external-call admission refused: {failure.value}: {detail}")
        self.failure = failure
        self.detail = detail


@dataclass(frozen=True, slots=True)
class DeclaredExternalCallSpec8616:
    """One parsed declaration before it binds to the current image."""

    caller_start: int
    caller_end: int
    caller_sha256: str
    callsite_addr: int
    target_addr: int
    is_far: bool
    relations: frozenset[DeclaredExternalCallRelation8616]
    label: str | None = None


@dataclass(frozen=True, slots=True)
class DeclaredCallAdmission8616:
    """A declaration bound to the exact current image, caller, site and target.

    ``caller_addr`` is the caller function address the declaration binds;
    ``declaration_sha256`` is the canonical digest of the complete bound
    binding so consumed receipts carry replayable identity, not a name.

    ``image_base`` and ``image_size`` retain the exact loaded-image window
    the declaration bound, and ``project`` is the exact in-process project
    object whose loader, declaration registry, stub registry, and IR-artifact
    registry must still authenticate this admission at consumption. Both are
    local object identity only: ``project`` is excluded from equality and
    ``repr`` and is never reconstructed from serialized fields. An admission
    minted without them (``None``) cannot authorize consumption.
    """

    image_sha256: str
    caller_addr: int
    caller_end: int
    caller_sha256: str
    callsite_addr: int
    target_addr: int
    is_far: bool
    retained_registers: tuple[str, ...]
    declaration_sha256: str
    label: str | None = None
    image_base: int | None = None
    image_size: int | None = None
    project: object | None = field(default=None, compare=False, repr=False)

    def binds_callsite(self, function_addr: int, callsite_addr: int) -> bool:
        """Return whether this admission authorizes exactly one CALL site."""
        return self.caller_addr == function_addr and self.callsite_addr == callsite_addr


@dataclass(frozen=True, slots=True)
class DeclaredCallEffectConsumption8616:
    """Immutable replayable receipt for one consumed declared call boundary.

    The receipt carries the full admission binding — declaration digest,
    image digest, caller range digest, callsite, target and distance — so
    serialized results can revalidate that the identical contract produced
    the claimed segment retention. It never asserts a numeric DS value.
    """

    assumption: DeclaredCallAssumption8616
    declaration_sha256: str
    image_sha256: str
    caller_addr: int
    caller_sha256: str
    callsite_addr: int
    target_addr: int
    is_far: bool
    retained_registers: tuple[str, ...]

    @classmethod
    def from_admission_8616(
        cls,
        admission: DeclaredCallAdmission8616,
    ) -> DeclaredCallEffectConsumption8616:
        """Record the conditional assumption consumed at one bound CALL."""
        return cls(
            assumption=DeclaredCallAssumption8616.DECLARED_EXTERNAL_CALL_EFFECT,
            declaration_sha256=admission.declaration_sha256,
            image_sha256=admission.image_sha256,
            caller_addr=admission.caller_addr,
            caller_sha256=admission.caller_sha256,
            callsite_addr=admission.callsite_addr,
            target_addr=admission.target_addr,
            is_far=admission.is_far,
            retained_registers=admission.retained_registers,
        )

    def binds_callsite(self, function_addr: int, callsite_addr: int) -> bool:
        """Return whether this receipt describes one exact call boundary."""
        return self.caller_addr == function_addr and self.callsite_addr == callsite_addr

    def to_record(self) -> dict[str, object]:
        """Serialize the receipt into a deterministic strict record."""
        return {
            "schema": _DECLARED_CALL_SITE_RECORD_SCHEMA_8616,
            "assumption": self.assumption.value,
            "declaration_sha256": self.declaration_sha256,
            "image_sha256": self.image_sha256,
            "caller_addr": self.caller_addr,
            "caller_sha256": self.caller_sha256,
            "callsite_addr": self.callsite_addr,
            "target_addr": self.target_addr,
            "is_far": self.is_far,
            "retained_registers": list(self.retained_registers),
        }


@dataclass(frozen=True, slots=True)
class DeclaredExternalCallRegistry8616:
    """Closed set of admitted declarations plus their evidence census."""

    admissions: tuple[DeclaredCallAdmission8616, ...]
    image_sha256: str
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    def admissions_for_function_8616(
        self,
        function_addr: int,
    ) -> tuple[DeclaredCallAdmission8616, ...]:
        """Return admissions bound to one exact caller function address."""
        return tuple(
            admission for admission in self.admissions if admission.caller_addr == function_addr
        )

    @property
    def closes_evidence(self) -> bool:
        """Return whether every supplied declaration was admitted exactly once."""
        return (
            self.raw_fact_count == self.normalized_fact_count == len(self.admissions)
            and self.classified_fact_count == self.materialized_count == len(self.admissions)
            and self.failure_count == 0
        )


class _DeclaredExternalCallOwner8616(Protocol):
    """Owned project field carrying admitted external-call declarations."""

    _inertia_declared_external_call_registry_8616: DeclaredExternalCallRegistry8616


class _LoaderMemorySurface8616(Protocol):
    """Third-party loader memory API used for exact mapped bytes."""

    def load(self, address: int, size: int) -> bytes:
        """Read a mapped byte range or raise for an unmapped address."""
        ...


class _LoaderSurface8616(Protocol):
    """Third-party loader boundary for exact loaded-image bytes."""

    memory: _LoaderMemorySurface8616


class _ProjectLoaderBoundary8616(Protocol):
    """Minimal third-party project view for whole-image byte identity."""

    loader: _LoaderSurface8616


def _loaded_image_equals_8616(project: object, image_base: int, image_code: bytes) -> bool:
    """Return whether the entire currently loaded image equals ``image_code``.

    The whole supplied window — caller bytes and synthetic stub bytes alike —
    must match the bytes mapped in the project's loader. An unmapped or
    malformed loader surface refuses rather than guessing.
    """
    boundary = cast(_ProjectLoaderBoundary8616, project)
    try:
        loaded = bytes(boundary.loader.memory.load(image_base, len(image_code)))
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    return loaded == image_code


def declared_external_call_registry_8616(
    owner: object,
) -> DeclaredExternalCallRegistry8616 | None:
    """Read the typed declaration registry from a project boundary."""
    try:
        registry = cast(
            _DeclaredExternalCallOwner8616, owner
        )._inertia_declared_external_call_registry_8616
    except AttributeError:
        return None
    return registry if isinstance(registry, DeclaredExternalCallRegistry8616) else None


def _fail_8616(failure: DeclaredCallAdmissionFailure8616, detail: str) -> NoReturn:
    """Raise the typed admission refusal."""
    raise DeclaredExternalCallAdmissionError8616(failure, detail)


def _hex_digest_8616(value: object, *, field_name: str) -> str:
    """Parse one exact lowercase hex SHA-256 field."""
    if (
        not isinstance(value, str)
        or len(value) != _HEX_DIGEST_LENGTH_8616
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            f"{field_name} must be a lowercase sha256 hex digest",
        )
    return value


def _nonnegative_int_8616(value: object, *, field_name: str) -> int:
    """Parse one strict nonnegative integer from int or 0x-prefixed text."""
    if isinstance(value, bool):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            f"{field_name} must be an integer",
        )
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError:
            _fail_8616(
                DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
                f"{field_name} must be an integer",
            )
    else:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            f"{field_name} must be an integer",
        )
    if parsed < 0:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            f"{field_name} must be nonnegative",
        )
    return parsed


def _relations_8616(value: object) -> frozenset[DeclaredExternalCallRelation8616]:
    """Parse and admit only the enumerated DS-preservation relation set."""
    if not isinstance(value, list):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            "relations must be a list",
        )
    relations: set[DeclaredExternalCallRelation8616] = set()
    for item in value:
        try:
            relations.add(DeclaredExternalCallRelation8616(item))
        except ValueError:
            _fail_8616(
                DeclaredCallAdmissionFailure8616.RELATION_UNSUPPORTED,
                f"unsupported segment relation {item!r}",
            )
    if DeclaredExternalCallRelation8616.DS_PRESERVED_ON_RETURN not in relations:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.RELATION_MISSING,
            "relations must enumerate ds_preserved_on_return",
        )
    if len(relations) != 1:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.RELATION_UNSUPPORTED,
            "only ds_preserved_on_return is admitted",
        )
    return frozenset(relations)


def _spec_from_record_8616(record: object) -> DeclaredExternalCallSpec8616:
    """Parse one declaration entry under the strict schema."""
    if not isinstance(record, dict):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            "declaration entry must be an object",
        )
    label = record.get("label")
    if label is not None and not isinstance(label, str):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            "label must be a string",
        )
    is_far = record.get("is_far")
    if not isinstance(is_far, bool):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            "is_far must be a boolean naming the exact call distance",
        )
    return DeclaredExternalCallSpec8616(
        caller_start=_nonnegative_int_8616(record.get("caller_start"), field_name="caller_start"),
        caller_end=_nonnegative_int_8616(record.get("caller_end"), field_name="caller_end"),
        caller_sha256=_hex_digest_8616(record.get("caller_sha256"), field_name="caller_sha256"),
        callsite_addr=_nonnegative_int_8616(record.get("callsite_addr"), field_name="callsite_addr"),
        target_addr=_nonnegative_int_8616(record.get("target_addr"), field_name="target_addr"),
        is_far=is_far,
        relations=_relations_8616(record.get("relations")),
        label=label if isinstance(label, str) else None,
    )


def _specs_from_file_8616(
    path: Path,
) -> tuple[str, tuple[DeclaredExternalCallSpec8616, ...]]:
    """Parse one declaration file into its image digest and strict specs."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            f"cannot parse {path}: {exc}",
        )
    if (
        not isinstance(document, dict)
        or type(document.get("schema")) is not int
        or document.get("schema") != DECLARED_EXTERNAL_CALL_EFFECT_SCHEMA_8616
    ):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.SCHEMA_UNSUPPORTED,
            f"{path} does not carry schema {DECLARED_EXTERNAL_CALL_EFFECT_SCHEMA_8616}",
        )
    declared_image_sha256 = _hex_digest_8616(
        document.get("image_sha256"), field_name="image_sha256"
    )
    raw_declarations = document.get("declarations")
    if not isinstance(raw_declarations, list) or len(raw_declarations) > (
        _MAX_DECLARED_CALLS_PER_FILE_8616
    ):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            "declarations must be a bounded list",
        )
    return declared_image_sha256, tuple(
        _spec_from_record_8616(item) for item in raw_declarations
    )


def _decoded_call_target_8616(
    image_code: bytes,
    image_base: int,
    callsite_addr: int,
) -> tuple[bool, int, int] | None:
    """Decode one direct CALL at ``callsite_addr``; refuse anything else.

    Returns ``(is_far, target_addr, instruction_size)`` for a bare ``E8``
    near or ``9A`` far direct call whose operand resolves to an address
    inside or adjacent to the image; ``None`` when the bytes are not an
    unprefixed direct CALL.
    """
    offset = callsite_addr - image_base
    if offset < 0 or offset >= len(image_code):
        return None
    opcode = image_code[offset]
    if opcode == 0xE8:
        if offset + 3 > len(image_code):
            return None
        displacement = int.from_bytes(image_code[offset + 1 : offset + 3], "little", signed=True)
        return False, callsite_addr + 3 + displacement, 3
    if opcode == 0x9A:
        if offset + 5 > len(image_code):
            return None
        target_offset = int.from_bytes(image_code[offset + 1 : offset + 3], "little")
        target_segment = int.from_bytes(image_code[offset + 3 : offset + 5], "little")
        return True, target_segment * 16 + target_offset, 5
    return None


def _declaration_digest_8616(
    image_sha256: str,
    spec: DeclaredExternalCallSpec8616,
) -> str:
    """Compute the canonical digest of one fully bound declaration."""
    canonical = "|".join(
        (
            image_sha256,
            hex(spec.caller_start),
            hex(spec.caller_end),
            spec.caller_sha256,
            hex(spec.callsite_addr),
            hex(spec.target_addr),
            "far" if spec.is_far else "near",
            *(relation.value for relation in sorted(spec.relations)),
        )
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _admit_one_8616(
    project: object,
    spec: DeclaredExternalCallSpec8616,
    *,
    image_code: bytes,
    image_base: int,
    image_sha256: str,
) -> DeclaredCallAdmission8616:
    """Bind one parsed declaration to exact current image and stub evidence."""
    if not spec.caller_start <= spec.callsite_addr < spec.caller_end:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.CALLSITE_OUT_OF_CALLER,
            f"callsite {spec.callsite_addr:#x} is outside caller "
            f"[{spec.caller_start:#x}, {spec.caller_end:#x})",
        )
    caller_offset_start = spec.caller_start - image_base
    caller_offset_end = spec.caller_end - image_base
    if not (0 <= caller_offset_start < caller_offset_end <= len(image_code)):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.CALLER_RANGE_INVALID,
            f"caller range [{spec.caller_start:#x}, {spec.caller_end:#x}) "
            "is outside the input image",
        )
    caller_digest = hashlib.sha256(image_code[caller_offset_start:caller_offset_end]).hexdigest()
    if caller_digest != spec.caller_sha256:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.CALLER_DIGEST_MISMATCH,
            "caller byte digest does not match the current image",
        )
    decoded = _decoded_call_target_8616(image_code, image_base, spec.callsite_addr)
    if decoded is None:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.CALLSITE_NOT_DECODED_CALL,
            f"no direct CALL decodes at callsite {spec.callsite_addr:#x}",
        )
    decoded_is_far, decoded_target, decoded_size = decoded
    if spec.callsite_addr + decoded_size > spec.caller_end:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.CALLSITE_OUT_OF_CALLER,
            f"callsite {spec.callsite_addr:#x} CALL extends past caller end "
            f"{spec.caller_end:#x}; the caller range must contain the entire "
            "CALL instruction",
        )
    if decoded_is_far != spec.is_far:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.DISTANCE_MISMATCH,
            f"callsite {spec.callsite_addr:#x} decodes "
            f"{'far' if decoded_is_far else 'near'}, not the declared distance",
        )
    if decoded_target != spec.target_addr:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.TARGET_MISMATCH,
            f"callsite {spec.callsite_addr:#x} decodes to "
            f"{decoded_target:#x}, not declared target {spec.target_addr:#x}",
        )
    if not is_synthetic_call_stub_8616(project, spec.target_addr):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.TARGET_NOT_SYNTHETIC_STUB,
            f"target {spec.target_addr:#x} is not a registered synthetic "
            "external stub; a real callee body can never be masked",
        )
    return DeclaredCallAdmission8616(
        image_sha256=image_sha256,
        caller_addr=spec.caller_start,
        caller_end=spec.caller_end,
        caller_sha256=spec.caller_sha256,
        callsite_addr=spec.callsite_addr,
        target_addr=spec.target_addr,
        is_far=spec.is_far,
        retained_registers=("ds",),
        declaration_sha256=_declaration_digest_8616(image_sha256, spec),
        label=spec.label,
        image_base=image_base,
        image_size=len(image_code),
        project=project,
    )


def admit_declared_external_call_files_8616(
    project: object,
    *,
    image_code: bytes,
    image_base: int,
    paths: tuple[Path, ...],
) -> DeclaredExternalCallRegistry8616 | None:
    """Parse and admit optional declared external-call segment relations.

    Every supplied declaration must bind the exact current image bytes, an
    exact caller byte range and digest, an exact decoded direct CALL
    coordinate, an exact registered synthetic-stub target, and the exact
    near/far distance. Any malformed, stale, duplicated, contradictory, or
    unbound declaration refuses the whole input rather than weakening it.
    ``None`` is returned when no declaration input was supplied at all.
    """
    if not paths:
        return None
    if len(paths) > _MAX_DECLARED_CALL_EFFECT_FILES_8616:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            "too many declaration files",
        )
    if not isinstance(image_code, bytes) or type(image_base) is not int or image_base < 0:
        _fail_8616(
            DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
            "image_code must be bytes and image_base a nonnegative integer",
        )
    parsed = tuple(_specs_from_file_8616(path) for path in paths)
    specs = tuple(spec for _digest, file_specs in parsed for spec in file_specs)
    image_sha256 = hashlib.sha256(image_code).hexdigest()
    if any(digest != image_sha256 for digest, _file_specs in parsed):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.IMAGE_DIGEST_MISMATCH,
            "declaration image digest does not match the current input image",
        )
    if not _loaded_image_equals_8616(project, image_base, image_code):
        _fail_8616(
            DeclaredCallAdmissionFailure8616.IMAGE_DIGEST_MISMATCH,
            "the currently loaded image bytes differ from the supplied image",
        )
    admissions: list[DeclaredCallAdmission8616] = []
    seen_callsites: dict[int, DeclaredCallAdmission8616] = {}
    for spec in specs:
        admission = _admit_one_8616(
            project,
            spec,
            image_code=image_code,
            image_base=image_base,
            image_sha256=image_sha256,
        )
        existing = seen_callsites.get(admission.callsite_addr)
        if existing is not None:
            _fail_8616(
                DeclaredCallAdmissionFailure8616.DUPLICATE_CALLSITE
                if existing == admission
                else DeclaredCallAdmissionFailure8616.CONTRADICTORY_DECLARATION,
                f"callsite {admission.callsite_addr:#x} is declared more than once",
            )
        seen_callsites[admission.callsite_addr] = admission
        admissions.append(admission)
    registry = DeclaredExternalCallRegistry8616(
        admissions=tuple(admissions),
        image_sha256=image_sha256,
        raw_fact_count=len(specs),
        normalized_fact_count=len(specs),
        classified_fact_count=len(admissions),
        materialized_count=len(admissions),
        failure_count=0,
    )
    cast(
        _DeclaredExternalCallOwner8616, project
    )._inertia_declared_external_call_registry_8616 = registry
    return registry


def declared_call_effect_consumption_from_record_8616(
    record: object,
) -> DeclaredCallEffectConsumption8616:
    """Validate one serialized consumption receipt strictly."""
    if (
        not isinstance(record, dict)
        or type(record.get("schema")) is not int
        or record.get("schema") != _DECLARED_CALL_SITE_RECORD_SCHEMA_8616
    ):
        raise ValueError("declared call consumption has an unsupported schema")
    assumption = record.get("assumption")
    if assumption != DeclaredCallAssumption8616.DECLARED_EXTERNAL_CALL_EFFECT.value:
        raise ValueError("declared call consumption carries an unknown assumption")
    retained = record.get("retained_registers")
    if (
        not isinstance(retained, list)
        or any(item not in {"ds"} for item in retained)
        or tuple(retained) != tuple(sorted(set(retained)))
        or not retained
    ):
        raise ValueError("declared call consumption has invalid retained registers")
    is_far = record.get("is_far")
    if not isinstance(is_far, bool):
        raise ValueError("declared call consumption has invalid call distance")
    return DeclaredCallEffectConsumption8616(
        assumption=DeclaredCallAssumption8616.DECLARED_EXTERNAL_CALL_EFFECT,
        declaration_sha256=_hex_digest_8616(
            record.get("declaration_sha256"), field_name="declaration_sha256"
        ),
        image_sha256=_hex_digest_8616(record.get("image_sha256"), field_name="image_sha256"),
        caller_addr=_nonnegative_int_8616(record.get("caller_addr"), field_name="caller_addr"),
        caller_sha256=_hex_digest_8616(record.get("caller_sha256"), field_name="caller_sha256"),
        callsite_addr=_nonnegative_int_8616(
            record.get("callsite_addr"), field_name="callsite_addr"
        ),
        target_addr=_nonnegative_int_8616(record.get("target_addr"), field_name="target_addr"),
        is_far=is_far,
        retained_registers=tuple(retained),
    )
