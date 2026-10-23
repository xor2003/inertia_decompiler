"""Executable checks for the declared function-entry contract.

Layer: Frontend contract tests.
Responsibility: prove admission binds exact MZ source identity, the
recomputed relocated module, the native range digest, the declared
environment digest, strict register/frame constraints, and revalidatable
``.complete`` — with real MZ bytes whose header entry differs from the
declared function entry. Assertions bind typed refusals and explicit
fields only; no name matching.
"""

from __future__ import annotations

import dataclasses
import hashlib

from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredEntryFailure8616,
    DeclaredEntryMemory8616,
    DeclaredEntryReturn8616,
    DeclaredEntryReturnKind8616,
    DeclaredFunctionEntryAdmission8616,
    DeclaredFunctionEntryRefusal8616,
    DeclaredFunctionEntrySpec8616,
    admit_declared_function_entry_8616,
    revalidate_declared_function_entry_8616,
)
from inertia.frontend.x86_16.mz_invocation_source import (
    mz_invocation_source_8616,
)

LOAD_SEGMENT = 0x1000
MODULE_BASE = LOAD_SEGMENT * 16
IMAGE = bytes(range(256))
RANGE = (MODULE_BASE + 0x40, MODULE_BASE + 0x80)
ENTRY = (0x1004, 0x0000)  # entry_linear 0x10040, inside RANGE, != header entry
STACK = (0x2000, 0x0100)
FRAME_LINEAR = STACK[0] * 16 + STACK[1]
ENVIRONMENT = hashlib.sha256(b"declared-env").hexdigest()


def _mz(image: bytes, *, entry_cs: int = 0, entry_ip: int = 0) -> bytes:
    """Build a minimal genuine MZ whose header entry is offset 0."""
    header_size = 2 * 16
    exe_size = header_size + len(image)
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = (exe_size % 512).to_bytes(2, "little")
    header[0x04:0x06] = ((exe_size + 511) // 512).to_bytes(2, "little")
    header[0x06:0x08] = (0).to_bytes(2, "little")
    header[0x08:0x0A] = (2).to_bytes(2, "little")
    header[0x0A:0x0C] = (0x10).to_bytes(2, "little")
    header[0x0C:0x0E] = (0x20).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0020).to_bytes(2, "little")
    header[0x10:0x12] = (0x0800).to_bytes(2, "little")
    header[0x12:0x14] = (0).to_bytes(2, "little")
    header[0x14:0x16] = entry_ip.to_bytes(2, "little")
    header[0x16:0x18] = entry_cs.to_bytes(2, "little")
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    return bytes(header) + image


SOURCE = _mz(IMAGE)
MODULE = mz_invocation_source_8616(SOURCE, LOAD_SEGMENT).module
NATIVE = MODULE[RANGE[0] - MODULE_BASE : RANGE[1] - MODULE_BASE]


def make_spec(**overrides: object) -> DeclaredFunctionEntrySpec8616:
    """A valid near-frame spec; callers override one field at a time."""
    fields: dict[str, object] = {
        "version": 1,
        "source_sha256": hashlib.sha256(SOURCE).hexdigest(),
        "relocated_sha256": hashlib.sha256(MODULE).hexdigest(),
        "load_segment": LOAD_SEGMENT,
        "entry_segment": ENTRY[0],
        "entry_offset": ENTRY[1],
        "range_start": RANGE[0],
        "range_end": RANGE[1],
        "native_sha256": hashlib.sha256(NATIVE).hexdigest(),
        "environment_sha256": ENVIRONMENT,
        "use_environment_memory": True,
        "registers": (("ss", STACK[0]), ("sp", STACK[1])),
        "memory": (DeclaredEntryMemory8616(FRAME_LINEAR, (0x1200).to_bytes(2, "little")),),
        "return_boundary": DeclaredEntryReturn8616(
            DeclaredEntryReturnKind8616.NEAR, ENTRY[0], 0x1200
        ),
    }
    fields.update(overrides)
    return DeclaredFunctionEntrySpec8616(**fields)  # type: ignore[arg-type]


def admit(
    spec: DeclaredFunctionEntrySpec8616, **kwargs: object
) -> DeclaredFunctionEntryAdmission8616 | DeclaredFunctionEntryRefusal8616:
    """Admit with the genuine source/module/environment unless overridden."""
    inputs = {"source": SOURCE, "loaded_module": MODULE, "environment_sha256": ENVIRONMENT}
    inputs.update(kwargs)
    return admit_declared_function_entry_8616(spec, **inputs)


def test_valid_near_admission_binds_exact_identity() -> None:
    """Near spec admits; retained inputs and digests are exact."""
    result = admit(make_spec())
    assert isinstance(result, DeclaredFunctionEntryAdmission8616)
    assert result.complete
    assert result.entry_linear == ENTRY[0] * 16 + ENTRY[1] == RANGE[0]
    assert result.source == SOURCE and result.loaded_module == MODULE
    assert result.environment_sha256 == ENVIRONMENT
    # Header-derived entry (0x10000) differs from the declared function entry.
    assert mz_invocation_source_8616(SOURCE, LOAD_SEGMENT).entry_linear != result.entry_linear
    assert admit(make_spec()).declaration_sha256 == result.declaration_sha256


def test_valid_far_admission() -> None:
    """Far boundary admits a cross-segment return target."""
    boundary = DeclaredEntryReturn8616(DeclaredEntryReturnKind8616.FAR, 0x3000, 0x4000)
    frame = DeclaredEntryMemory8616(FRAME_LINEAR, (0x4000).to_bytes(2, "little") + (0x3000).to_bytes(2, "little"))
    result = admit(make_spec(memory=(frame,), return_boundary=boundary))
    assert isinstance(result, DeclaredFunctionEntryAdmission8616) and result.complete


def test_omitted_optional_registers_remain_absent() -> None:
    """Only declared ss/sp exist; no zero/ABI defaults are inferred."""
    result = admit(make_spec())
    assert isinstance(result, DeclaredFunctionEntryAdmission8616)
    assert result.spec.registers == (("ss", STACK[0]), ("sp", STACK[1]))


def test_environment_baseline_false_retained_and_bound() -> None:
    """use_environment_memory=False admits; altered env digest refuses."""
    result = admit(make_spec(use_environment_memory=False))
    assert isinstance(result, DeclaredFunctionEntryAdmission8616)
    assert result.spec.use_environment_memory is False
    other = admit(make_spec(), environment_sha256=hashlib.sha256(b"other").hexdigest())
    assert isinstance(other, DeclaredFunctionEntryRefusal8616)
    assert other.reason is DeclaredEntryFailure8616.ENVIRONMENT_MISMATCH


def test_altered_source_module_digests_and_ranges_refuse() -> None:
    """Mutated source bytes, module bytes, digests, ranges, entries refuse."""
    mutated_source = bytes([SOURCE[0] ^ 0x01]) + SOURCE[1:]
    cases = (
        (make_spec(), {"source": mutated_source}, DeclaredEntryFailure8616.SOURCE_MISMATCH),
        (make_spec(), {"loaded_module": bytes([MODULE[0] ^ 0x01]) + MODULE[1:]},
         DeclaredEntryFailure8616.MODULE_MISMATCH),
        (make_spec(source_sha256="0" * 64), {}, DeclaredEntryFailure8616.SOURCE_MISMATCH),
        (make_spec(relocated_sha256="0" * 64), {}, DeclaredEntryFailure8616.MODULE_MISMATCH),
        (make_spec(native_sha256="0" * 64), {}, DeclaredEntryFailure8616.NATIVE_DIGEST_MISMATCH),
        (make_spec(load_segment=0x1001), {},
         DeclaredEntryFailure8616.NATIVE_DIGEST_MISMATCH),
        (make_spec(range_end=MODULE_BASE + len(MODULE) + 0x100), {},
         DeclaredEntryFailure8616.RANGE_INVALID),
        (make_spec(entry_offset=0x0100), {}, DeclaredEntryFailure8616.ENTRY_INVALID),
        (make_spec(entry_segment=True), {}, DeclaredEntryFailure8616.ENTRY_INVALID),
        (make_spec(version=2), {}, DeclaredEntryFailure8616.VERSION_UNSUPPORTED),
        (make_spec(native_sha256="AB"), {}, DeclaredEntryFailure8616.DIGEST_MALFORMED),
        ("not-a-spec", {}, DeclaredEntryFailure8616.SPEC_MALFORMED),
    )
    for spec, inputs, reason in cases:
        result = admit(spec, **inputs)  # type: ignore[arg-type]
        assert isinstance(result, DeclaredFunctionEntryRefusal8616)
        assert result.reason is reason, (reason, result)


def test_register_constraints_strict() -> None:
    """Duplicate, unknown, cs/ip, bool, out-of-word, missing ss/sp refuse."""
    base = (("ss", STACK[0]), ("sp", STACK[1]))
    cases = (
        (*base, ("ax", 0), ("ax", 1)),  # duplicate
        (*base, ("ah", 0)),  # unknown
        (*base, ("cs", ENTRY[0])),  # entry-owned
        (*base, ("ip", 0)),
        (*base, ("ax", True)),  # bool masquerade
        (*base, ("ax", 0x10000)),  # out of word
        (*base, ("AX", 0)),  # not lowercase
        (("ss", STACK[0]),),  # missing sp
        (("sp", STACK[1]),),  # missing ss
    )
    for registers in cases:
        result = admit(make_spec(registers=registers))
        assert isinstance(result, DeclaredFunctionEntryRefusal8616)
        assert result.reason is DeclaredEntryFailure8616.REGISTER_INVALID


def test_memory_spans_strict() -> None:
    """Empty, unbounded, overlapping, and native-altering spans refuse."""
    good = DeclaredEntryMemory8616(FRAME_LINEAR, (0x1200).to_bytes(2, "little"))
    cases = (
        (good, DeclaredEntryMemory8616(0x30000, b"")),
        (DeclaredEntryMemory8616(0x100000 - 1, b"\x00\x00"), good),
        (good, DeclaredEntryMemory8616(FRAME_LINEAR, b"\x00\x12")),
        (good, DeclaredEntryMemory8616(FRAME_LINEAR + 1, b"\x34\x56")),
    )
    for memory in cases:
        result = admit(make_spec(memory=memory))
        assert isinstance(result, DeclaredFunctionEntryRefusal8616)
        assert result.reason is DeclaredEntryFailure8616.MEMORY_INVALID
    altered = DeclaredEntryMemory8616(RANGE[0], b"\xFF" * 4)
    result = admit(make_spec(memory=(good, altered)))
    assert isinstance(result, DeclaredFunctionEntryRefusal8616)
    assert result.reason is DeclaredEntryFailure8616.MEMORY_ALTERS_NATIVE
    identical = DeclaredEntryMemory8616(RANGE[0], NATIVE[:4])
    assert isinstance(admit(make_spec(memory=(good, identical))),
                    DeclaredFunctionEntryAdmission8616)


def test_frame_and_return_boundary_strict() -> None:
    """Missing/wrong frame bytes, wrap, code alias, bad kind refuse."""
    default_memory = make_spec().memory
    cases = (
        # No declared span covers the frame.
        ({}, (), DeclaredEntryFailure8616.FRAME_UNDECLARED),
        # Wrong frame bytes at the right address.
        ({}, (DeclaredEntryMemory8616(FRAME_LINEAR, b"\x34\x12"),),
         DeclaredEntryFailure8616.FRAME_UNDECLARED),
        # SP wrap: 0xFFFF + 2 leaves the 64K stack window.
        ({"registers": (("ss", STACK[0]), ("sp", 0xFFFF))}, None,
         DeclaredEntryFailure8616.FRAME_INVALID),
        # Frame inside the native range.
        ({"registers": (("ss", RANGE[0] // 16), ("sp", RANGE[0] % 16))}, None,
         DeclaredEntryFailure8616.FRAME_INVALID),
        # Near return with a foreign CS.
        ({"return_boundary": DeclaredEntryReturn8616(
            DeclaredEntryReturnKind8616.NEAR, 0x9999, 0x1200)}, None,
         DeclaredEntryFailure8616.RETURN_INVALID),
        # Untyped return kind.
        ({"return_boundary": DeclaredEntryReturn8616("near", ENTRY[0], 0x1200)},  # type: ignore[arg-type]
         None, DeclaredEntryFailure8616.RETURN_INVALID),
    )
    for overrides, memory, reason in cases:
        spec = make_spec(
            memory=default_memory if memory is None else memory, **overrides
        )
        result = admit(spec)
        assert isinstance(result, DeclaredFunctionEntryRefusal8616)
        assert result.reason is reason, (reason, result)


def test_forged_or_stale_admission_never_completes() -> None:
    """Directly constructed or mutated admissions revalidate to False."""
    real = admit(make_spec())
    assert isinstance(real, DeclaredFunctionEntryAdmission8616)
    forged = DeclaredFunctionEntryAdmission8616(
        spec=real.spec,
        source=SOURCE,
        loaded_module=MODULE,
        environment_sha256=ENVIRONMENT,
        declaration_sha256="0" * 64,
    )
    assert not forged.complete
    stale = dataclasses.replace(
        real, spec=dataclasses.replace(real.spec, entry_offset=real.spec.entry_offset + 2)
    )
    assert not stale.complete
    assert not dataclasses.replace(real, source=SOURCE + b"\x00").complete


def test_constraint_containers_are_immutable_and_malformed_inputs_refuse() -> None:
    """Mutable or missing containers never enter the retained premise."""
    for field in ("registers", "memory"):
        for malformed in (None, [], {}, "unknown"):
            result = admit(make_spec(**{field: malformed}))
            assert isinstance(result, DeclaredFunctionEntryRefusal8616)
            assert result.reason is DeclaredEntryFailure8616.SPEC_MALFORMED


def test_explicit_revalidation_binds_current_inputs_and_complete_spec() -> None:
    """Retained consistency does not authorize changed live input identities."""
    result = admit(make_spec(use_environment_memory=False))
    assert isinstance(result, DeclaredFunctionEntryAdmission8616)
    current = {"source": SOURCE, "loaded_module": MODULE, "environment_sha256": ENVIRONMENT}
    assert revalidate_declared_function_entry_8616(result, **current)
    for key, value in (
        ("source", SOURCE + b"\0"),
        ("loaded_module", MODULE + b"\0"),
        ("environment_sha256", "0" * 64),
    ):
        assert not revalidate_declared_function_entry_8616(result, **(current | {key: value}))
    changed = dataclasses.replace(result, spec=dataclasses.replace(result.spec, use_environment_memory=True))
    assert not revalidate_declared_function_entry_8616(changed, **current)
    receipt = result.to_dict()
    assert receipt["spec"] == result.spec.to_dict()
    assert receipt["assumption"] == "declared_function_entry"
    assert receipt["declaration_sha256"] == result.declaration_sha256


def test_function_range_cannot_cross_fetch_segment_window() -> None:
    """Linear module membership alone cannot admit a wrapped CS fetch range."""
    image = bytes(0x10010)
    source = _mz(image)
    projection = mz_invocation_source_8616(source, LOAD_SEGMENT)
    start, end = MODULE_BASE + 0xFFF0, MODULE_BASE + 0x10010
    spec = make_spec(
        source_sha256=hashlib.sha256(source).hexdigest(),
        relocated_sha256=hashlib.sha256(projection.module).hexdigest(),
        native_sha256=hashlib.sha256(projection.module[0xFFF0:0x10010]).hexdigest(),
        range_start=start, range_end=end, entry_segment=LOAD_SEGMENT, entry_offset=0xFFF0,
    )
    result = admit(spec, source=source, loaded_module=projection.module)
    assert isinstance(result, DeclaredFunctionEntryRefusal8616)
    assert result.reason is DeclaredEntryFailure8616.ENTRY_INVALID


def test_far_return_target_must_remain_inside_real_mode_memory() -> None:
    """Two individually valid words cannot authorize a beyond1MiB target."""
    boundary = DeclaredEntryReturn8616(DeclaredEntryReturnKind8616.FAR, 0xFFFF, 0xFFFF)
    result = admit(make_spec(return_boundary=boundary))
    assert isinstance(result, DeclaredFunctionEntryRefusal8616)
    assert result.reason is DeclaredEntryFailure8616.RETURN_INVALID


def test_identical_partial_native_overlap_compares_only_intersection() -> None:
    """Declared bytes beyond the native range do not change its shared bytes."""
    overlay = DeclaredEntryMemory8616(RANGE[1] - 2, NATIVE[-2:] + b"data")
    result = admit(make_spec(memory=(*make_spec().memory, overlay)))
    assert isinstance(result, DeclaredFunctionEntryAdmission8616)
    mutated = dataclasses.replace(overlay, data=b"\xff\xffdata")
    result = admit(make_spec(memory=(*make_spec().memory, mutated)))
    assert isinstance(result, DeclaredFunctionEntryRefusal8616)
    assert result.reason is DeclaredEntryFailure8616.MEMORY_ALTERS_NATIVE
