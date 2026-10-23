"""Explicit source-bound declared input for scoped real16 intake.

Layer: dosunit program intake.
Responsibility: authenticate one ``inertia.real16_declared_input.v1``
document — the SHA-256 of the exact retained MZ source bytes, an embedded
``dosunit.real16_program_environment.v1`` manifest parsed only through the
canonical manifest owner, and an explicit list of declared INT21 service
sites — then mint the ``ProgramBoot`` and ``DeclaredInterruptService8616``
records the scoped invocation source binds. ``content_sha256`` binds the
raw declaration document bytes the record was minted from, so equal source
under changed declared registers or policies never shares that identity;
source authenticity itself stays with ``ProgramBoot`` and the root
``source_sha256`` check. Supplied ``caller_addr``/``callsite_addr``
coordinates are caller declarations, not a site proof: the native census
re-authenticates each relation against proven site state, the live IVT and
the declared environment digest. This wrapper runs no inventory scan, mints
no inventory or bootstrap cycle, and invents no DOS semantics. Whole-program
intake admits no replay projection: a nonempty oracle or candidate
code-range list in the embedded manifest refuses. Every malformed field,
source mismatch, replay scope or adapter refusal raises ``ValueError``
before any boot or service record is minted; nothing is dropped or
defaulted.

Optional ``function_entries`` carry explicit conditional application-entry
specifications through the canonical frontend decoder and admission owner.
They bind this same source, load and environment but assert no boot reachability.

"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from inertia.frontend.real16_vector_response8616 import INT21_GET_VECTOR_8616, INT21_SET_VECTOR_8616
from inertia.frontend.x86_16.declared_entry_document import parse_declared_function_entry_spec_8616
from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredFunctionEntryAdmission8616,
    DeclaredFunctionEntryRefusal8616,
    admit_declared_function_entry_8616,
)
from inertia.frontend.x86_16.mz_invocation_source import mz_invocation_source_8616
from inertia.ir.real16_declared_interrupt8616 import (
    DeclaredInterruptRefusal8616,
    DeclaredInterruptService8616,
    declared_environment_digest_8616,
)
from tools.dosunit.reporting.real16_program_manifest import parse_program_manifest
from tools.dosunit.runtime.real16_declared_invocation8616 import (
    declared_int21_resize_service_8616,
    declared_int21_vector_service_8616,
    declared_int21_version_service_8616,
)
from tools.dosunit.runtime.real16_program_boot import (
    ProgramBoot,
    ProgramEnvironment,
    program_from_mz_bytes,
)

__all__ = [
    "DECLARED_INPUT_SCHEMA_8616",
    "DeclaredReal16Input8616",
    "DeclaredServiceKind8616",
    "parse_declared_real16_input_8616",
    "read_declared_real16_input_8616",
]

DECLARED_INPUT_SCHEMA_8616: str = "inertia.real16_declared_input.v1"

_DECLARED_INPUT_FIELDS_8616: frozenset[str] = frozenset(
    {"schema", "source_sha256", "program", "services"}
)
_DECLARED_SERVICE_FIELDS_8616: frozenset[str] = frozenset(
    {"kind", "caller_addr", "callsite_addr"}
)
# Declared site coordinates are physical addresses inside the real-mode
# 20-bit conventional domain; wider or Boolean values are malformed.
_DECLARED_ADDRESS_LIMIT_8616: int = 0xFFFFF

# ``content_sha256`` must be the exact lowercase hexadecimal form
# ``hashlib.sha256(...).hexdigest()`` emits — 64 digits, no prefixes.
_SHA256_HEX_LENGTH_8616: int = 64
_SHA256_HEX_DIGITS_8616: frozenset[str] = frozenset("0123456789abcdef")


def _is_sha256_hex_8616(value: object) -> bool:
    """Return whether ``value`` is an exact lowercase SHA-256 hex digest."""
    return (
        type(value) is str
        and len(value) == _SHA256_HEX_LENGTH_8616
        and all(character in _SHA256_HEX_DIGITS_8616 for character in value)
    )


class DeclaredServiceKind8616(StrEnum):
    """Explicit INT21 service kinds; vector numbers bind proven AL at consumption."""

    VERSION = "version"
    RESIZE = "resize"
    VECTOR_QUERY = "vector_query"
    VECTOR_UPDATE = "vector_update"


@dataclass(frozen=True, slots=True)
class DeclaredReal16Input8616:
    """One authenticated boot with service relations and conditional entries.

    ``boot`` is the ``program_from_mz_bytes`` contract over the exact
    retained source bytes under the document's declared environment;
    ``services`` are the adapter-minted declared relations in document
    order; ``content_sha256`` is the SHA-256 of the raw declaration
    document bytes the record was minted from, so changed declared state
    under identical source bytes carries a different identity. Source
    authenticity stays with ``ProgramBoot`` and the root ``source_sha256``
    check — this field never re-binds the source. Every service record must
    bind the digest of this boot's own declared environment, and no
    ``(kind, site)`` pair may repeat — the record cannot publish a
    foreign-environment relation.
    ``function_entries`` holds source/load/environment-bound frontend admissions
    with unique entry addresses; these premises grant no startup path proof.
    """

    boot: ProgramBoot
    services: tuple[DeclaredInterruptService8616, ...]
    content_sha256: str
    function_entries: tuple[DeclaredFunctionEntryAdmission8616, ...] = ()

    def __post_init__(self) -> None:
        """Require typed fields bound to the declared environment evidence."""
        if type(self.boot) is not ProgramBoot:
            raise ValueError("declared input requires a typed ProgramBoot")
        if type(self.services) is not tuple or not all(
            type(service) is DeclaredInterruptService8616
            for service in self.services
        ):
            raise ValueError(
                "declared services must be typed DeclaredInterruptService8616 records"
            )
        if not _is_sha256_hex_8616(self.content_sha256):
            raise ValueError(
                "declared input content_sha256 must be a SHA-256 hex digest"
            )
        if self.services:
            digest = declared_environment_digest_8616(self.boot.environment)
            if type(digest) is not str or any(
                service.environment_sha256 != digest for service in self.services
            ):
                raise ValueError(
                    "declared services must bind this boot's environment digest"
                )
        sites = [
            (
                service.caller_addr,
                service.callsite_addr,
                service.vector,
                service.function,
                service.selector,
            )
            for service in self.services
        ]
        if len(sites) != len(set(sites)):
            raise ValueError("declared services must not repeat a kind at one site")
        _validate_function_entries_8616(self.boot, self.function_entries)


def _validate_function_entries_8616(
    boot: ProgramBoot, entries: tuple[DeclaredFunctionEntryAdmission8616, ...],
) -> None:
    """Keep function premises source/environment bound and unambiguous."""
    if type(entries) is not tuple:
        raise ValueError("function entries must be an immutable tuple")
    if not entries:
        return
    digest = declared_environment_digest_8616(boot.environment)
    for entry in entries:
        if (
            type(entry) is not DeclaredFunctionEntryAdmission8616
            or not entry.complete or entry.source != boot.source
            or entry.environment_sha256 != digest
            or entry.spec.load_segment != boot.image.load_segment
        ):
            raise ValueError("function entry must bind the declared source, load and environment")
    heads = [entry.entry_linear for entry in entries]
    if len(heads) != len(set(heads)):
        raise ValueError("function entries must not repeat an entry address")


def _function_entry_declarations_8616(
    document: object, boot: ProgramBoot,
) -> tuple[DeclaredFunctionEntryAdmission8616, ...]:
    """Admit explicitly supplied entry specs through their canonical owner."""
    if not isinstance(document, list):
        raise ValueError("function_entries must be a list")
    module = mz_invocation_source_8616(boot.source, boot.image.load_segment).module
    digest = declared_environment_digest_8616(boot.environment)
    if not isinstance(digest, str):
        raise ValueError("function entries require a declared environment digest")
    entries: list[DeclaredFunctionEntryAdmission8616] = []
    for item in document:
        admission = admit_declared_function_entry_8616(
            parse_declared_function_entry_spec_8616(item), source=boot.source,
            loaded_module=module, environment_sha256=digest,
        )
        if isinstance(admission, DeclaredFunctionEntryRefusal8616):
            raise ValueError(f"function entry refused: {admission.reason.value}: {admission.detail}")
        entries.append(admission)
    return tuple(entries)


@dataclass(frozen=True, slots=True)
class _DeclaredServiceSite8616:
    """One validated declared service site before adapter minting."""

    kind: DeclaredServiceKind8616
    caller_addr: int
    callsite_addr: int


def _object_8616(value: object, keys: frozenset[str], name: str) -> dict[str, object]:
    """Require a named JSON object with exactly the declared members."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name}: expected an object")
    if set(value) != keys:
        raise ValueError(f"{name}: expected exactly {sorted(keys)}")
    return value


def _site_address_8616(value: object, name: str) -> int:
    """Read one explicit physical address inside the real-mode 20-bit domain."""
    if type(value) is not int:
        raise ValueError(f"{name}: expected an integer")
    if not 0 <= value <= _DECLARED_ADDRESS_LIMIT_8616:
        raise ValueError(f"{name}: outside the real-mode physical domain")
    return value


def _service_declarations_8616(
    value: object,
) -> tuple[_DeclaredServiceSite8616, ...]:
    """Validate the explicit service-site list before any record is minted.

    Each item declares exactly ``kind``, ``caller_addr`` and
    ``callsite_addr``; kinds are the admitted enum values and addresses are
    integers inside the 20-bit physical domain — bools, strings and
    out-of-range values are malformed. A repeated ``(kind, caller, site)``
    refuses; version and resize at the same site remain distinct
    declarations because the native consumer re-checks the proven AH/AL
    selectors.
    """
    if not isinstance(value, list):
        raise ValueError("services: expected a list")
    declarations: list[_DeclaredServiceSite8616] = []
    for raw in value:
        item = _object_8616(raw, _DECLARED_SERVICE_FIELDS_8616, "service")
        kind_text = item["kind"]
        if not isinstance(kind_text, str):
            raise ValueError("service kind must be version, resize, vector_query or vector_update")
        try:
            kind = DeclaredServiceKind8616(kind_text)
        except ValueError as error:
            raise ValueError("service kind must be version, resize, vector_query or vector_update") from error
        declarations.append(
            _DeclaredServiceSite8616(
                kind=kind,
                caller_addr=_site_address_8616(item["caller_addr"], "caller_addr"),
                callsite_addr=_site_address_8616(
                    item["callsite_addr"], "callsite_addr"
                ),
            )
        )
    identity = [
        (site.kind, site.caller_addr, site.callsite_addr) for site in declarations
    ]
    if len(identity) != len(set(identity)):
        raise ValueError("services must not repeat a kind at one declared site")
    return tuple(declarations)


def _mint_declared_service_8616(
    environment: ProgramEnvironment,
    site: _DeclaredServiceSite8616,
) -> DeclaredInterruptService8616:
    """Mint one declared relation through its canonical adapter.

    Authentication stays with the dosunit adapter: a typed
    ``DeclaredInterruptRefusal8616`` becomes a ``ValueError`` naming the
    refusal reason — never a dropped entry or a defaulted record.
    """
    mint: Callable[
        ..., DeclaredInterruptService8616 | DeclaredInterruptRefusal8616
    ]
    if site.kind in (DeclaredServiceKind8616.VECTOR_QUERY, DeclaredServiceKind8616.VECTOR_UPDATE):
        function = (
            INT21_GET_VECTOR_8616
            if site.kind is DeclaredServiceKind8616.VECTOR_QUERY
            else INT21_SET_VECTOR_8616
        )
        minted = declared_int21_vector_service_8616(
            environment, caller_addr=site.caller_addr,
            callsite_addr=site.callsite_addr, function=function,
        )
    else:
        mint = (
            declared_int21_version_service_8616
            if site.kind is DeclaredServiceKind8616.VERSION
            else declared_int21_resize_service_8616
        )
        minted = mint(
            environment,
            caller_addr=site.caller_addr,
            callsite_addr=site.callsite_addr,
        )
    if isinstance(minted, DeclaredInterruptRefusal8616):
        raise ValueError(
            f"declared {site.kind.value} service at {site.callsite_addr:#06x} "
            f"refused: {minted.value}"
        )
    return minted


def parse_declared_real16_input_8616(
    document: object,
    source: bytes,
    content_sha256: str,
) -> DeclaredReal16Input8616:
    """Authenticate one declared-input document against exact source bytes.

    Ordering keeps the earliest dishonesty first: the root must carry
    ``schema``, ``source_sha256``, ``program`` and ``services``, optionally
    ``function_entries`` with explicit source-bound function premises;
    ``source_sha256`` must equal the SHA-256 of the passed ``source`` bytes;
    ``content_sha256`` is the declaration-file digest the reader supplies —
    the parser authenticates its exact hexadecimal shape, never its bytes,
    because the parsed document no longer carries the raw file encoding;
    the embedded manifest parses only through ``parse_program_manifest``
    and must carry no oracle/candidate code ranges — replay projections are
    not program intake. Only then does ``program_from_mz_bytes`` own the
    boot and each declared site mint through its canonical adapter.
    """
    fields = _DECLARED_INPUT_FIELDS_8616
    if isinstance(document, dict) and "function_entries" in document:
        fields = fields | {"function_entries"}
    root = _object_8616(document, fields, "declared input")
    if root["schema"] != DECLARED_INPUT_SCHEMA_8616:
        raise ValueError("unsupported declared-input schema")
    if type(source) is not bytes:
        raise ValueError("declared input requires the exact source bytes")
    actual = hashlib.sha256(source).hexdigest()
    if not _is_sha256_hex_8616(content_sha256):
        raise ValueError("declared input content_sha256 must be a SHA-256 hex digest")
    declared_digest = root["source_sha256"]
    if type(declared_digest) is not str or declared_digest != actual:
        raise ValueError("declared input source_sha256 does not match the source bytes")
    manifest = parse_program_manifest(root["program"])
    if manifest.oracle_code_ranges or manifest.candidate_code_ranges:
        raise ValueError("declared whole-program input admits no replay code ranges")
    sites = _service_declarations_8616(root["services"])
    boot = program_from_mz_bytes(source, manifest.environment)
    services = tuple(
        _mint_declared_service_8616(manifest.environment, site) for site in sites
    )
    return DeclaredReal16Input8616(
        boot=boot, services=services, content_sha256=content_sha256,
        function_entries=_function_entry_declarations_8616(root["function_entries"], boot)
        if "function_entries" in root else (),
    )


def read_declared_real16_input_8616(
    path: Path,
    source: bytes,
) -> DeclaredReal16Input8616:
    """Read, parse and authenticate one declared-input document from disk.

    ``path`` names the ``inertia.real16_declared_input.v1`` JSON document;
    ``source`` is the exact retained MZ byte stream the document binds.
    The raw file bytes are read once: their digest becomes
    ``content_sha256`` and their JSON becomes the parsed document, so a
    whitespace-only rewrite still changes the declared-input identity.
    Filesystem failures propagate as ``OSError``; an unreadable JSON
    document or any refused field raises ``ValueError`` with its cause.
    """
    if type(source) is not bytes:
        raise ValueError("declared input requires the exact source bytes")
    raw = path.read_bytes()
    try:
        document: object = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"declared input {path}: invalid JSON document") from error
    return parse_declared_real16_input_8616(
        document, source, hashlib.sha256(raw).hexdigest()
    )
