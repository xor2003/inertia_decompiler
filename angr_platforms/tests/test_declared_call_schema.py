"""Declared-call schema boundary controls reviewed from Devin."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.declared_external_call_evidence import (
    DeclaredCallAdmissionFailure8616,
    DeclaredCallEffectConsumption8616,
    declared_call_effect_consumption_from_record_8616,
)
from angr_platforms.X86_16.synthetic_call_stub_evidence import (
    record_synthetic_call_stubs_8616,
)
from x86_16_declared_admission_fixture import (
    _MAX_DECLARED_CALLS_PER_FILE,
    _NEAR_ENTRIES,
    BASE,
    _admit,
    _declaration,
    _document,
    _image_and_targets,
    _project,
    _refuse,
    _stage,
    _write,
)


@pytest.mark.parametrize(
    "field,value",
    [
        ("caller_start", True),
        ("caller_start", -1),
        ("caller_start", "zzz"),
        ("caller_start", 1.5),
        ("caller_end", "0x"),
        ("caller_end", None),
        ("callsite_addr", -4),
        ("callsite_addr", [1]),
        ("target_addr", None),
        ("target_addr", -0x1000),
        ("is_far", 1),
        ("is_far", "yes"),
        ("is_far", None),
        ("label", 7),
        ("caller_sha256", "A" * 64),
        ("caller_sha256", "0" * 63),
        ("caller_sha256", 5),
        ("relations", "ds_preserved_on_return"),
        ("relations", None),
        ("relations", 3),
    ],
)
def test_malformed_declaration_fields_refuse(
    tmp_path: Path, field: str, value: object
) -> None:
    """Each entry field enforces its exact declared type."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(image, is_far=False, target=target, overrides={field: value})
    path = _write(tmp_path, _document(image, [entry]))
    _refuse(DeclaredCallAdmissionFailure8616.FIELD_MALFORMED, project, image, (path,))


def test_declaration_entry_must_be_an_object(tmp_path: Path) -> None:
    """Non-object declaration entries refuse rather than being skipped."""
    image, (_target,) = _image_and_targets(_NEAR_ENTRIES)
    path = _write(tmp_path, _document(image, ["call it", 3]))
    _refuse(
        DeclaredCallAdmissionFailure8616.FIELD_MALFORMED, SimpleNamespace(), image, (path,)
    )


def test_declarations_must_be_a_bounded_list(tmp_path: Path) -> None:
    """The declarations member must be a list within the per-file bound."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    document = _document(image, [_declaration(image, is_far=False, target=target)])
    document["declarations"] = {"callsite": BASE}
    path = _write(tmp_path, document)
    _refuse(
        DeclaredCallAdmissionFailure8616.FIELD_MALFORMED, SimpleNamespace(), image, (path,)
    )

    oversized = _document(image, [{}] * (_MAX_DECLARED_CALLS_PER_FILE + 1))
    path = _write(tmp_path, oversized, name="oversized.json")
    _refuse(
        DeclaredCallAdmissionFailure8616.FIELD_MALFORMED, SimpleNamespace(), image, (path,)
    )


@pytest.mark.parametrize(
    "relations,failure",
    [
        ([], DeclaredCallAdmissionFailure8616.RELATION_MISSING),
        (["ds_preserved_on_return", "es_preserved_on_return"], DeclaredCallAdmissionFailure8616.RELATION_UNSUPPORTED),
        (["bogus_relation"], DeclaredCallAdmissionFailure8616.RELATION_UNSUPPORTED),
    ],
)
def test_relation_set_is_closed(
    tmp_path: Path, relations: list[object], failure: DeclaredCallAdmissionFailure8616
) -> None:
    """Only the enumerated DS-preservation relation may be declared."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(
        image, is_far=False, target=target, overrides={"relations": relations}
    )
    path = _write(tmp_path, _document(image, [entry]))
    _refuse(failure, project, image, (path,))


def test_repeated_relation_in_list_still_binds(tmp_path: Path) -> None:
    """A duplicated supported relation normalizes to the single relation."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(
        image,
        is_far=False,
        target=target,
        overrides={
            "relations": ["ds_preserved_on_return", "ds_preserved_on_return"]
        },
    )
    path = _write(tmp_path, _document(image, [entry]))
    registry = _admit(project, image, (path,))
    assert registry is not None and registry.closes_evidence


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", 2),
        ("assumption", "INFERRED_EFFECT"),
        ("retained_registers", []),
        ("retained_registers", ["es"]),
        ("retained_registers", ["ds", "ds"]),
        ("retained_registers", ["ds", "cs"]),
        ("retained_registers", "ds"),
        ("is_far", "near"),
        ("declaration_sha256", "Z" * 64),
        ("caller_addr", -1),
    ],
)
def test_consumption_record_strict_parse(tmp_path: Path, field: str, value: object) -> None:
    """The serialized receipt parser refuses each corrupted field."""
    project, image, _target, path = _stage(tmp_path)
    registry = _admit(project, image, (path,))
    assert registry is not None
    receipt = DeclaredCallEffectConsumption8616.from_admission_8616(registry.admissions[0])
    record = receipt.to_record()
    record[field] = value
    with pytest.raises(ValueError):
        declared_call_effect_consumption_from_record_8616(record)


@pytest.mark.parametrize("schema", [True, 1.0])
def test_consumption_record_schema_requires_exact_integer(tmp_path: Path, schema: object) -> None:
    """A serialized receipt with ``"schema": true`` is not schema 1."""
    project, image, _target, path = _stage(tmp_path)
    registry = _admit(project, image, (path,))
    assert registry is not None
    receipt = DeclaredCallEffectConsumption8616.from_admission_8616(registry.admissions[0])
    record = receipt.to_record()
    record["schema"] = schema
    with pytest.raises(ValueError):
        declared_call_effect_consumption_from_record_8616(record)

