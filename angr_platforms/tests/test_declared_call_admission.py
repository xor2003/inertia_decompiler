"""Declared-call admission boundary controls reviewed from Devin."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.declared_external_call_evidence import (
    DeclaredCallAdmissionFailure8616,
    DeclaredCallEffectConsumption8616,
    declared_call_effect_consumption_from_record_8616,
    declared_external_call_registry_8616,
)
from angr_platforms.X86_16.synthetic_call_stub_evidence import (
    record_synthetic_call_stubs_8616,
)
from x86_16_declared_admission_fixture import (
    _MAX_DECLARED_CALL_EFFECT_FILES,
    _NEAR_ENTRIES,
    _TWO_CALL_ENTRIES,
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


def test_exact_declaration_admits_closed_registry(tmp_path: Path) -> None:
    """An exactly bound near declaration mints a closed replayable registry."""
    project, image, _target, path = _stage(tmp_path)
    registry = _admit(project, image, (path,))
    assert registry is not None and registry.closes_evidence
    assert declared_external_call_registry_8616(project) is registry
    (admission,) = registry.admissions
    assert admission.binds_callsite(BASE, BASE)
    assert not admission.binds_callsite(BASE, BASE + 1)
    assert not admission.binds_callsite(BASE + 1, BASE)
    assert admission.image_sha256 == hashlib.sha256(image).hexdigest()
    assert admission.image_base == BASE and admission.image_size == len(image)
    assert admission.project is project
    assert admission.retained_registers == ("ds",)
    assert len(admission.declaration_sha256) == 64
    receipt = DeclaredCallEffectConsumption8616.from_admission_8616(admission)
    assert declared_call_effect_consumption_from_record_8616(receipt.to_record()) == receipt


def test_exact_far_declaration_admits(tmp_path: Path) -> None:
    """A far declaration binds the decoded 9A pointer and distance exactly."""
    project, image, target, path = _stage(tmp_path, is_far=True)
    registry = _admit(project, image, (path,))
    assert registry is not None and registry.closes_evidence
    admission = registry.admissions[0]
    assert admission.is_far and admission.target_addr == target


def test_no_declaration_input_supplies_no_authority() -> None:
    """An empty path set mints nothing and leaves no registry on the owner."""
    project = SimpleNamespace()
    assert _admit(project, b"", ()) is None
    assert declared_external_call_registry_8616(project) is None


def test_empty_declaration_list_closes_without_admissions(tmp_path: Path) -> None:
    """A supplied-but-empty declaration list yields a closed empty registry."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    path = _write(tmp_path, _document(image, []))
    registry = _admit(project, image, (path,))
    assert registry is not None and registry.closes_evidence
    assert registry.admissions == ()
    assert registry.failure_count == 0


def test_distinct_callsites_across_files_admit(tmp_path: Path) -> None:
    """Two files each binding a distinct decoded CALL admit independently."""
    image, targets = _image_and_targets(_TWO_CALL_ENTRIES)
    assert len(targets) == 2
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset(targets))
    first = _write(
        tmp_path,
        _document(
            image,
            [
                _declaration(
                    image, is_far=False, target=targets[0], caller_end=BASE + 4
                )
            ],
        ),
        name="first.json",
    )
    second = _write(
        tmp_path,
        _document(
            image,
            [
                _declaration(
                    image,
                    is_far=False,
                    target=targets[1],
                    callsite_addr=BASE + 4,
                    caller_start=BASE + 4,
                    caller_end=BASE + 8,
                )
            ],
        ),
        name="second.json",
    )
    registry = _admit(project, image, (first, second))
    assert registry is not None and registry.closes_evidence
    assert len(registry.admissions) == 2
    assert len(registry.admissions_for_function_8616(BASE)) == 1
    assert len(registry.admissions_for_function_8616(BASE + 4)) == 1
    assert registry.admissions_for_function_8616(BASE + 1) == ()


def test_too_many_declaration_files_refuses(tmp_path: Path) -> None:
    """More than the bounded file count refuses before any file is read."""
    paths = tuple(
        tmp_path / f"missing-{index}.json"
        for index in range(_MAX_DECLARED_CALL_EFFECT_FILES + 1)
    )
    _refuse(DeclaredCallAdmissionFailure8616.FIELD_MALFORMED, SimpleNamespace(), b"", paths)


@pytest.mark.parametrize(
    "image_code,image_base",
    [
        ("not-bytes", BASE),
        (None, BASE),
        (b"", True),
        (b"", -1),
        (b"", 1.5),
    ],
)
def test_image_inputs_are_strictly_typed(
    tmp_path: Path, image_code: object, image_base: object
) -> None:
    """The image byte string and base address refuse non-exact types."""
    path = _write(tmp_path, _document(b"", []))
    _refuse(
        DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
        SimpleNamespace(),
        image_code,  # type: ignore[arg-type]
        (path,),
        image_base=image_base,  # type: ignore[arg-type]
    )


def test_unreadable_or_unparseable_file_refuses(tmp_path: Path) -> None:
    """A missing path or non-JSON content refuses as malformed input."""
    _refuse(
        DeclaredCallAdmissionFailure8616.FIELD_MALFORMED,
        SimpleNamespace(),
        b"",
        (tmp_path / "absent.json",),
    )
    bad = _write(tmp_path, "{not json")
    _refuse(
        DeclaredCallAdmissionFailure8616.FIELD_MALFORMED, SimpleNamespace(), b"", (bad,)
    )


@pytest.mark.parametrize("document", [[], "text", 3, {"schema": 2}, {"schema": "1"}, {}])
def test_unsupported_schema_refuses(tmp_path: Path, document: object) -> None:
    """Non-object documents and wrong schema versions refuse before fields."""
    path = _write(tmp_path, json.dumps(document))
    _refuse(
        DeclaredCallAdmissionFailure8616.SCHEMA_UNSUPPORTED, SimpleNamespace(), b"", (path,)
    )


@pytest.mark.parametrize("schema", [True, 1.0])
def test_schema_requires_exact_integer_one(tmp_path: Path, schema: object) -> None:
    """JSON ``true``/``1.0`` are not the integer schema version 1."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    document = _document(image, [_declaration(image, is_far=False, target=target)])
    document["schema"] = schema
    path = _write(tmp_path, document)
    _refuse(DeclaredCallAdmissionFailure8616.SCHEMA_UNSUPPORTED, project, image, (path,))


@pytest.mark.parametrize(
    "digest",
    ["A" * 64, "0" * 63, "0" * 65, "g" * 64, 1, None],
)
def test_malformed_image_digest_field_refuses(tmp_path: Path, digest: object) -> None:
    """The file-level image digest must be one lowercase sha256 hex string."""
    document = _document(b"", [])
    document["image_sha256"] = digest
    path = _write(tmp_path, document)
    _refuse(DeclaredCallAdmissionFailure8616.FIELD_MALFORMED, SimpleNamespace(), b"", (path,))


def test_stale_image_digest_refuses(tmp_path: Path) -> None:
    """A declaration minted for other bytes cannot bind the current image."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    document = _document(image, [_declaration(image, is_far=False, target=target)])
    document["image_sha256"] = hashlib.sha256(image + b"\x00").hexdigest()
    path = _write(tmp_path, document)
    _refuse(
        DeclaredCallAdmissionFailure8616.IMAGE_DIGEST_MISMATCH,
        SimpleNamespace(),
        image,
        (path,),
    )


def test_loaded_image_must_equal_supplied_bytes(tmp_path: Path) -> None:
    """The mapped loader bytes must equal the supplied image, not a guess."""
    project, image, _target, path = _stage(tmp_path)
    project.loader.memory.store(BASE, bytes([image[0] ^ 0xFF]))
    _refuse(DeclaredCallAdmissionFailure8616.IMAGE_DIGEST_MISMATCH, project, image, (path,))

    project, image, _target, path = _stage(tmp_path)
    _refuse(
        DeclaredCallAdmissionFailure8616.IMAGE_DIGEST_MISMATCH,
        SimpleNamespace(),
        image,
        (path,),
    )
    del project.loader
    _refuse(DeclaredCallAdmissionFailure8616.IMAGE_DIGEST_MISMATCH, project, image, (path,))

