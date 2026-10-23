"""Source-bound declared-input intake: parser, binding and refusal controls.

Layer: tests.
Responsibility: prove the ``inertia.real16_declared_input.v1`` wrapper binds
the exact MZ source bytes before minting, delegates program parsing to the
canonical manifest owner, refuses replay-scope code ranges and malformed or
duplicate service declarations, converts every adapter refusal into a
``ValueError`` naming the reason, and preserves the declared full-width
register file unchanged in the minted boot.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from inertia.ir.real16_declared_interrupt8616 import (
    DeclaredInterruptService8616,
    declared_environment_digest_8616,
)
from tools.dosunit.catalog.real16_declared_input import (
    DECLARED_INPUT_SCHEMA_8616,
    DeclaredReal16Input8616,
    parse_declared_real16_input_8616,
    read_declared_real16_input_8616,
)
from tools.dosunit.reporting.real16_program_manifest import parse_program_manifest
from tools.dosunit.runtime.real16_declared_invocation8616 import (
    declared_int21_version_service_8616,
)
from tools.dosunit.runtime.real16_program_boot import ProgramBoot
from tools.dosunit.runtime.real16_program_vectors import DOS_VECTOR, vector_bytes
from tools.dosunit.runtime.real16_program_version import VersionPolicy
from tools.dosunit.runtime.real16_replay_model import SegOffset
from tools.dosunit.tests.test_real16_program_replay import environment, mz

DOS_ENTRY = {"segment": 0x54, "offset": 0x21}
VERSION_POLICY = {"major": 3, "minor": 30, "oem": 0x42, "serial24": 0x123456}
RESIZE_MCB = "5a9201009f0000b24b56314b50523047"
EXIT_PROGRAM = bytes.fromhex("b8004ccd21")  # mov ax,4c00; int 21h
DEFAULT_CALLER = 0x10100  # image base for the psp 0x1000 environment
DEFAULT_CALLSITE = 0x10103  # the int 21h instruction inside EXIT_PROGRAM
RESIZE_CALLER = 0x1100  # image base for the psp 0x0100 resize environment
RESIZE_CALLSITE = 0x1103


DOS_ENTRY_COORDINATE = SegOffset(0x54, 0x21)


def _ivt(dos_entry: SegOffset = DOS_ENTRY_COORDINATE) -> bytes:
    """Supply the complete 1024-byte IVT with the declared DOS entry at 0x21."""
    table = bytearray(1024)
    table[DOS_VECTOR * 4:DOS_VECTOR * 4 + 4] = vector_bytes(dos_entry)
    return bytes(table)


def _environment_fields(
    *,
    version: bool = True,
    resize: bool = False,
    vectors: bool = True,
    psp_segment: int = 0x1000,
    allocation: bytes | None = None,
    registers: dict | None = None,
    ivt: bytes | None = None,
    dos_entry: tuple[int, int] = (0x54, 0x21),
) -> dict:
    """Build the manifest environment fields for one declared input."""
    base = environment()
    fields: dict = {
        "psp_segment": psp_segment,
        "allocation_hex": (base.allocation if allocation is None else allocation).hex(),
        "registers": dict(base.registers) if registers is None else registers,
        "fs": 0,
        "gs": 0,
        "extra_memory": [
            {
                "segment": 0,
                "offset": 0,
                "data_hex": (
                    _ivt(SegOffset(*dos_entry)) if ivt is None else ivt
                ).hex(),
            }
        ],
    }
    if vectors:
        fields["dos_vectors"] = {
            "dos_entry": {"segment": dos_entry[0], "offset": dos_entry[1]}
        }
    if version:
        fields["dos_version"] = dict(VERSION_POLICY)
    if resize:
        fields["dos_resize"] = {
            "profile": "kvikdos_single_tail",
            "segment": 0x100,
            "mcb_hex": RESIZE_MCB,
        }
    return fields


def _resize_environment_fields(**overrides: object) -> dict:
    """Build the native tail-block environment for resize declarations."""
    options: dict = {"psp_segment": 0x100, "allocation": bytes(0x9F000), "resize": True}
    options.update(overrides)
    return _environment_fields(**options)


def _service(
    kind: str = "version",
    caller_addr: int = DEFAULT_CALLER,
    callsite_addr: int = DEFAULT_CALLSITE,
) -> dict:
    """One explicit service-site declaration."""
    return {"kind": kind, "caller_addr": caller_addr, "callsite_addr": callsite_addr}


def _document(
    source: bytes,
    environment_fields: dict | None = None,
    services: list | None = None,
) -> dict:
    """Build the complete declared-input document over ``source`` bytes."""
    return {
        "schema": DECLARED_INPUT_SCHEMA_8616,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "program": {
            "schema": "dosunit.real16_program_environment.v1",
            "environment": (
                _environment_fields()
                if environment_fields is None
                else environment_fields
            ),
        },
        "services": [] if services is None else services,
    }


def _resize_mz(code: bytes = EXIT_PROGRAM) -> bytes:
    """Emit the MZ whose loader grant admits the complete native tail arena."""
    image = bytearray(mz(code))
    image[12:14] = b"\xff\xff"
    return bytes(image)


def _sha(source: bytes) -> str:
    """Digest the exact passed bytes."""
    return hashlib.sha256(source).hexdigest()


def _document_with_function_entry():
    from dataclasses import replace

    from inertia.frontend.x86_16.declared_function_entry import DeclaredEntryReturn8616
    from inertia.frontend.x86_16.mz_invocation_source import mz_invocation_source_8616
    from tests.frontend.test_declared_function_entry import make_spec

    source = mz(EXIT_PROGRAM)
    document = _document(source)
    boot = parse_declared_real16_input_8616(document, source, _sha(source)).boot
    projection = mz_invocation_source_8616(source, boot.image.load_segment)
    base = boot.image.load_segment * 16
    spec = make_spec()
    spec = replace(
        spec, source_sha256=_sha(source), relocated_sha256=_sha(projection.module),
        load_segment=boot.image.load_segment, entry_segment=boot.image.load_segment,
        entry_offset=0, range_start=base, range_end=base + len(EXIT_PROGRAM),
        native_sha256=_sha(projection.module[:len(EXIT_PROGRAM)]),
        environment_sha256=declared_environment_digest_8616(boot.environment),
        return_boundary=DeclaredEntryReturn8616(
            spec.return_boundary.kind, boot.image.load_segment, spec.return_boundary.offset,
        ),
    )
    document["function_entries"] = [spec.to_dict()]
    return source, document, spec


def test_declared_document_preserves_authenticated_function_entry():
    source, document, spec = _document_with_function_entry()
    result = parse_declared_real16_input_8616(document, source, _sha(source))
    assert len(result.function_entries) == 1
    admission = result.function_entries[0]
    assert admission.complete and admission.spec == spec
    assert admission.source == source == result.boot.source
    assert admission.environment_sha256 == declared_environment_digest_8616(result.boot.environment)


@pytest.mark.parametrize("mutation", ["source", "environment", "frame", "duplicate", "shape"])
def test_invalid_function_entry_document_never_falls_back_to_boot(mutation):
    source, document, _ = _document_with_function_entry()
    entry = document["function_entries"][0]
    if mutation == "source":
        entry["source_sha256"] = "0" * 64
    elif mutation == "environment":
        entry["environment_sha256"] = "0" * 64
    elif mutation == "frame":
        entry["memory"] = []
    elif mutation == "duplicate":
        document["function_entries"].append(entry)
    else:
        document["function_entries"] = {}
    with pytest.raises(ValueError):
        parse_declared_real16_input_8616(document, source, _sha(source))


def _content_sha(document: object) -> str:
    """Digest the serialized declaration bytes the tests write to disk."""
    return hashlib.sha256(json.dumps(document).encode()).hexdigest()


def _parse(document: object, source: bytes) -> DeclaredReal16Input8616:
    """Parse with the declaration-file digest for ``document``."""
    return parse_declared_real16_input_8616(
        document, source, _content_sha(document)
    )


def test_version_declaration_mints_bound_boot_and_service() -> None:
    source = mz(EXIT_PROGRAM)
    document = _document(source, services=[_service()])
    declaration = _parse(document, source)
    assert declaration.content_sha256 == _content_sha(document)
    assert declaration.content_sha256 != _sha(source)
    assert declaration.boot.source == source
    assert declaration.boot.entry == SegOffset(0x1010, 0)
    assert declaration.boot.image.load_segment == 0x1010
    assert declaration.boot.image.code_scope == "whole_image"
    assert declaration.boot.environment.version_policy == VersionPolicy(
        3, 30, 0x42, 0x123456
    )
    (service,) = declaration.services
    assert (service.caller_addr, service.callsite_addr) == (
        DEFAULT_CALLER, DEFAULT_CALLSITE,
    )
    assert (service.vector, service.function, service.selector) == (0x21, 0x30, 0)
    assert service.answer_ax == 0x1E03  # (minor<<8)|major for the declared version
    assert service.ivt_slot_bytes == vector_bytes(SegOffset(0x54, 0x21))
    digest = declared_environment_digest_8616(declaration.boot.environment)
    assert type(digest) is str and service.environment_sha256 == digest


def test_read_mints_the_same_declaration_from_disk(tmp_path: Path) -> None:
    source = mz(EXIT_PROGRAM)
    document = _document(source, services=[_service()])
    path = tmp_path / "input.json"
    path.write_text(json.dumps(document))
    from_file = read_declared_real16_input_8616(path, source)
    assert from_file == _parse(document, source)


def test_resize_declaration_mints_allocator_relation() -> None:
    source = _resize_mz()
    declaration = _parse(
        _document(
            source,
            _resize_environment_fields(),
            [_service("resize", RESIZE_CALLER, RESIZE_CALLSITE)],
        ),
        source,
    )
    (service,) = declaration.services
    assert (service.vector, service.function) == (0x21, 0x4A)
    assert service.selector is None and service.answer_ax is None
    assert service.resize is not None
    assert service.resize.block_segment == 0x100
    assert service.resize.metadata_linear == (0x100 - 1) << 4
    assert service.resize.metadata.hex() == RESIZE_MCB
    assert declaration.boot.entry == SegOffset(0x110, 0)


def test_version_and_resize_may_share_one_callsite() -> None:
    """Distinct kinds at one site stay distinct declarations: the census
    re-checks proven AH/AL before admitting either relation."""
    source = _resize_mz()
    declaration = _parse(
        _document(
            source,
            _resize_environment_fields(),
            [
                _service("version", RESIZE_CALLER, RESIZE_CALLSITE),
                _service("resize", RESIZE_CALLER, RESIZE_CALLSITE),
            ],
        ),
        source,
    )
    assert [service.function for service in declaration.services] == [0x30, 0x4A]
    assert {service.callsite_addr for service in declaration.services} == {
        RESIZE_CALLSITE
    }


def test_empty_service_list_is_allowed() -> None:
    source = mz(EXIT_PROGRAM)
    declaration = _parse(_document(source), source)
    assert declaration.services == ()
    assert declaration.boot.environment.version_policy is not None


def test_source_sha256_binds_the_exact_passed_bytes() -> None:
    source = mz(EXIT_PROGRAM)
    document = _document(source, services=[_service()])
    document["source_sha256"] = _sha(b"a different binary")
    with pytest.raises(ValueError, match="source_sha256"):
        _parse(document, source)
    for bad_source in (b"", "MZ", None, bytearray(source)):
        with pytest.raises(ValueError):
            parse_declared_real16_input_8616(document, bad_source, "0" * 64)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "digest",
    ["0" * 63, "0" * 65, "g" * 64, "0x" + "0" * 62, "F" * 64, 64, None],
)
def test_content_sha256_requires_an_exact_sha256_hex_digest(digest) -> None:
    source = mz(EXIT_PROGRAM)
    with pytest.raises(ValueError, match="content_sha256"):
        parse_declared_real16_input_8616(_document(source), source, digest)


def test_parse_admits_the_callers_declaration_file_digest() -> None:
    """Parse authenticates the digest shape; only read() binds file bytes."""
    source = mz(EXIT_PROGRAM)
    declaration = parse_declared_real16_input_8616(
        _document(source), source, _sha(b"some raw declaration file")
    )
    assert declaration.content_sha256 == _sha(b"some raw declaration file")


def test_content_sha256_binds_declaration_bytes_not_source(tmp_path: Path) -> None:
    """Same source under changed declared state must mint a new identity."""
    source = mz(EXIT_PROGRAM)
    registers = dict(environment().registers)
    first_fields = _environment_fields(registers=dict(registers, eax=1))
    second_fields = _environment_fields(registers=dict(registers, eax=2))
    first, second = _document(source, first_fields), _document(source, second_fields)
    assert first["source_sha256"] == second["source_sha256"] == _sha(source)
    left, right = tmp_path / "first.json", tmp_path / "second.json"
    left.write_text(json.dumps(first))
    right.write_text(json.dumps(second))
    declared_left = read_declared_real16_input_8616(left, source)
    declared_right = read_declared_real16_input_8616(right, source)
    assert declared_left.content_sha256 == _sha(left.read_bytes())
    assert declared_right.content_sha256 == _sha(right.read_bytes())
    assert declared_left.content_sha256 != declared_right.content_sha256
    assert declared_left.boot.source == declared_right.boot.source == source
    assert declared_left.boot != declared_right.boot
    # A whitespace-only rewrite keeps one parsed document but a new identity.
    right.write_text(json.dumps(second, indent=2))
    rewritten = read_declared_real16_input_8616(right, source)
    assert rewritten.content_sha256 != declared_right.content_sha256
    assert (rewritten.boot, rewritten.services) == (
        declared_right.boot, declared_right.services,
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(schema="dosunit.real16_program_environment.v1"),
        lambda d: d.pop("services"),
        lambda d: d.pop("program"),
        lambda d: d.update(extra=1),
    ],
    ids=["wrong schema", "missing services", "missing program", "extra field"],
)
def test_root_fields_and_schema_are_exact(mutate) -> None:
    source = mz(EXIT_PROGRAM)
    document = _document(source)
    mutate(document)
    with pytest.raises(ValueError):
        _parse(document, source)
    for non_object in (["schema"], "declaration", 5, None):
        with pytest.raises(ValueError):
            _parse(non_object, source)


def test_embedded_manifest_refusals_propagate() -> None:
    source = mz(EXIT_PROGRAM)
    document = _document(source)
    document["program"]["schema"] = "inertia.real16_declared_input.v1"
    with pytest.raises(ValueError, match="manifest schema"):
        _parse(document, source)
    document = _document(source)
    del document["program"]["environment"]["allocation_hex"]
    with pytest.raises(ValueError, match="allocation_hex"):
        _parse(document, source)
    for bad_program in ({"schema": "dosunit.real16_program_environment.v1"}, 5, "env"):
        document = _document(source)
        document["program"] = bad_program
        with pytest.raises(ValueError):
            _parse(document, source)


@pytest.mark.parametrize("side", ["oracle_code_ranges", "candidate_code_ranges"])
def test_replay_code_ranges_refuse(side: str) -> None:
    source = mz(EXIT_PROGRAM)
    document = _document(source)
    document["program"][side] = [{"address": DEFAULT_CALLER, "size": 1}]
    with pytest.raises(ValueError, match="code ranges"):
        _parse(document, source)


@pytest.mark.parametrize(
    "item",
    [
        {},
        {"kind": "version", "caller_addr": DEFAULT_CALLER},
        {"kind": "version", "caller_addr": DEFAULT_CALLER,
         "callsite_addr": DEFAULT_CALLSITE, "note": 1},
        {"kind": 0x30, "caller_addr": DEFAULT_CALLER, "callsite_addr": DEFAULT_CALLSITE},
        {"kind": "reboot", "caller_addr": DEFAULT_CALLER, "callsite_addr": DEFAULT_CALLSITE},
        {"kind": "version", "caller_addr": True, "callsite_addr": DEFAULT_CALLSITE},
        {"kind": "version", "caller_addr": DEFAULT_CALLER, "callsite_addr": False},
        {"kind": "version", "caller_addr": -1, "callsite_addr": DEFAULT_CALLSITE},
        {"kind": "version", "caller_addr": DEFAULT_CALLER, "callsite_addr": 0x100000},
        {"kind": "version", "caller_addr": "0x10100", "callsite_addr": DEFAULT_CALLSITE},
        {"kind": "version", "caller_addr": float(DEFAULT_CALLER), "callsite_addr": DEFAULT_CALLSITE},
        "version",
        [DEFAULT_CALLER, DEFAULT_CALLSITE],
    ],
)
def test_service_items_require_exact_typed_fields(item: object) -> None:
    source = mz(EXIT_PROGRAM)
    with pytest.raises(ValueError):
        _parse(_document(source, services=[item]), source)


def test_duplicate_kind_at_one_site_refuses() -> None:
    source = mz(EXIT_PROGRAM)
    document = _document(
        source, services=[_service(), dict(_service())]
    )
    with pytest.raises(ValueError, match="repeat"):
        _parse(document, source)


@pytest.mark.parametrize(
    ("fields", "service"),
    [
        (_environment_fields(version=False), _service()),
        (_environment_fields(vectors=False), _service()),
        (_resize_environment_fields(resize=False), _service("resize", RESIZE_CALLER, RESIZE_CALLSITE)),
    ],
    ids=["no version policy", "no vector policy", "no resize policy"],
)
def test_missing_policies_refuse_with_typed_reason(
    fields: dict, service: dict
) -> None:
    source = _resize_mz() if fields["psp_segment"] == 0x100 else mz(EXIT_PROGRAM)
    with pytest.raises(ValueError, match="declared_service_environment_incomplete"):
        _parse(_document(source, fields, [service]), source)


def test_forged_ivt_slot_refuses() -> None:
    """IVT bytes that do not encode the declared DOS entry are dishonest."""
    source = mz(EXIT_PROGRAM)
    forged = _ivt(SegOffset(0x55, 0x21))
    with pytest.raises(ValueError, match="declared_service_ivt_mismatch"):
        _parse(
            _document(source, _environment_fields(ivt=forged), [_service()]),
            source,
        )
    missing = bytes(1024)  # IVT supplied but the DOS slot stays zero
    with pytest.raises(ValueError, match="declared_service_ivt_mismatch"):
        _parse(
            _document(source, _environment_fields(ivt=missing), [_service()]),
            source,
        )


def test_dos_entry_inside_the_arena_is_an_owned_handler() -> None:
    source = mz(EXIT_PROGRAM)
    owned = (0x1000, 0)  # linear 0x10000 lies inside the declared arena
    with pytest.raises(ValueError, match="declared_service_owned_handler"):
        _parse(
            _document(
                source, _environment_fields(dos_entry=owned), [_service()]
            ),
            source,
        )


def test_malformed_fields_refuse_before_boot_mint() -> None:
    """A non-MZ source still reports the earliest structural dishonesty."""
    foreign = b"not an mz image"
    document = _document(
        foreign,
        services=[{"kind": "reboot", "caller_addr": 0, "callsite_addr": 0}],
    )
    with pytest.raises(ValueError, match="service kind must be version, resize, vector_query or vector_update"):
        _parse(document, foreign)
    document = _document(foreign)
    document["source_sha256"] = _sha(b"other")
    with pytest.raises(ValueError, match="source_sha256"):
        _parse(document, foreign)
    with pytest.raises(ValueError, match="MZ"):
        _parse(_document(foreign), foreign)


def test_declared_fullwidth_registers_pass_through_unchanged() -> None:
    source = mz(EXIT_PROGRAM)
    registers = {
        "eax": 0x12345678,
        "ebx": 0x9ABCDEF0,
        "ecx": 0x01234567,
        "edx": 0xDEADBEEF,
        "esi": 0xFEDCBA98,
        "edi": 0x13579BDF,
        "ebp": 0x2468ACE0,
        "esp": 0,
        "eflags": 0xFFFFFFFF,
    }
    declaration = _parse(
        _document(
            source,
            _environment_fields(registers=registers),
            [_service()],
        ),
        source,
    )
    assert dict(declaration.boot.environment.registers) == registers
    # The header SS:SP stays authoritative over the declared esp low half.
    assert dict(declaration.boot.initial_registers())["esp"] == (
        declaration.boot.stack.offset
    )
    # A truncated register file cannot mint a declared environment.
    truncated = dict(registers, eax=0x123456789)
    with pytest.raises(ValueError):
        _parse(
            _document(source, _environment_fields(registers=truncated), []),
            source,
        )


def test_record_rejects_stale_or_foreign_evidence() -> None:
    source = mz(EXIT_PROGRAM)
    declaration = _parse(_document(source, services=[_service()]), source)
    boot, (service,) = declaration.boot, declaration.services
    with pytest.raises(ValueError, match="content_sha256"):
        DeclaredReal16Input8616(
            boot=boot, services=(), content_sha256="not-a-digest"
        )
    with pytest.raises(ValueError, match="typed DeclaredInterruptService8616"):
        DeclaredReal16Input8616(
            boot=boot,
            services=(service, object()),  # type: ignore[arg-type]
            content_sha256=declaration.content_sha256,
        )
    with pytest.raises(ValueError, match="typed ProgramBoot"):
        DeclaredReal16Input8616(
            boot=object(),  # type: ignore[arg-type]
            services=(),
            content_sha256=declaration.content_sha256,
        )
    # A relation minted under a different declared environment is foreign.
    foreign_environment = parse_program_manifest(
        {
            "schema": "dosunit.real16_program_environment.v1",
            "environment": _environment_fields(version=True)
            | {"dos_version": dict(VERSION_POLICY, minor=31)},
        }
    ).environment
    foreign = declared_int21_version_service_8616(
        foreign_environment,
        caller_addr=DEFAULT_CALLER,
        callsite_addr=DEFAULT_CALLSITE,
    )
    assert isinstance(foreign, DeclaredInterruptService8616)
    with pytest.raises(ValueError, match="environment digest"):
        DeclaredReal16Input8616(
            boot=boot,
            services=(foreign,),
            content_sha256=declaration.content_sha256,
        )
    twin = declared_int21_version_service_8616(
        boot.environment,
        caller_addr=DEFAULT_CALLER,
        callsite_addr=DEFAULT_CALLSITE,
    )
    with pytest.raises(ValueError, match="repeat"):
        DeclaredReal16Input8616(
            boot=boot,
            services=(service, twin),
            content_sha256=declaration.content_sha256,
        )
    assert type(boot) is ProgramBoot


def test_read_requires_a_real_json_document(tmp_path: Path) -> None:
    source = mz(EXIT_PROGRAM)
    with pytest.raises(OSError):
        read_declared_real16_input_8616(tmp_path / "absent.json", source)
    path = tmp_path / "input.json"
    path.write_bytes(b"{ not json")
    with pytest.raises(ValueError, match="invalid JSON"):
        read_declared_real16_input_8616(path, source)
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(ValueError, match="invalid JSON"):
        read_declared_real16_input_8616(path, source)
    path.write_text(json.dumps(["schema", "source_sha256"]))
    with pytest.raises(ValueError, match="expected an object"):
        read_declared_real16_input_8616(path, source)
    with pytest.raises(ValueError, match="exact source bytes"):
        read_declared_real16_input_8616(path, "not-bytes")  # type: ignore[arg-type]
