"""Declared-call binding boundary controls reviewed from Devin."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from inertia.frontend.x86_16.declared_external_call_evidence import (
    DeclaredCallAdmissionFailure8616,
    declared_external_call_registry_8616,
)
from inertia.frontend.x86_16.synthetic_call_stub_evidence import (
    record_synthetic_call_stubs_8616,
)
from tests.integration.x86_16_declared_admission_fixture import (
    _FAR_ENTRIES,
    _NEAR_ENTRIES,
    BASE,
    _declaration,
    _document,
    _image_and_targets,
    _project,
    _refuse,
    _write,
)


@pytest.mark.parametrize(
    "caller_start,caller_end",
    [(BASE + 1, BASE + 4), (BASE, BASE), (BASE + 4, BASE + 5)],
)
def test_callsite_must_be_inside_caller_range(
    tmp_path: Path, caller_start: int, caller_end: int
) -> None:
    """A callsite outside its declared caller range refuses outright."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(
        image,
        is_far=False,
        target=target,
        caller_start=caller_start,
        caller_end=caller_end,
    )
    path = _write(tmp_path, _document(image, [entry]))
    _refuse(DeclaredCallAdmissionFailure8616.CALLSITE_OUT_OF_CALLER, project, image, (path,))


@pytest.mark.parametrize(
    "caller_start,caller_end",
    [(BASE - 0x10, BASE + 4), (BASE, BASE + 0x100), (BASE + 8, BASE + 9)],
)
def test_caller_range_must_be_inside_image(
    tmp_path: Path, caller_start: int, caller_end: int
) -> None:
    """The declared caller byte range must lie inside the supplied image."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(
        image,
        is_far=False,
        target=target,
        callsite_addr=BASE + 8 if caller_start == BASE + 8 else BASE,
        caller_start=caller_start,
        caller_end=caller_end,
    )
    path = _write(tmp_path, _document(image, [entry]))
    _refuse(DeclaredCallAdmissionFailure8616.CALLER_RANGE_INVALID, project, image, (path,))


def test_caller_digest_must_match_image_bytes(tmp_path: Path) -> None:
    """A well-formed but wrong caller digest refuses as stale evidence."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(
        image, is_far=False, target=target, overrides={"caller_sha256": "f" * 64}
    )
    path = _write(tmp_path, _document(image, [entry]))
    _refuse(DeclaredCallAdmissionFailure8616.CALLER_DIGEST_MISMATCH, project, image, (path,))


def test_callsite_must_decode_a_direct_call(tmp_path: Path) -> None:
    """Bytes at the declared callsite that are not a bare CALL refuse."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(
        image, is_far=False, target=target, callsite_addr=BASE + 3
    )
    path = _write(tmp_path, _document(image, [entry]))
    _refuse(
        DeclaredCallAdmissionFailure8616.CALLSITE_NOT_DECODED_CALL, project, image, (path,)
    )

    truncated = bytes.fromhex("e802")
    project = _project(truncated)
    entry = _declaration(truncated, is_far=False, target=target)
    path = _write(tmp_path, _document(truncated, [entry]), name="truncated.json")
    _refuse(
        DeclaredCallAdmissionFailure8616.CALLSITE_NOT_DECODED_CALL,
        project,
        truncated,
        (path,),
    )


def test_whole_call_must_fit_inside_caller_range(tmp_path: Path) -> None:
    """A caller range truncating the CALL instruction refuses."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(
        image, is_far=False, target=target, caller_end=BASE + 2
    )
    path = _write(tmp_path, _document(image, [entry]))
    refusal = _refuse(
        DeclaredCallAdmissionFailure8616.CALLSITE_OUT_OF_CALLER, project, image, (path,)
    )
    assert "entire" in refusal.detail


@pytest.mark.parametrize("is_far", [False, True])
def test_declared_distance_must_match_decoded_call(tmp_path: Path, is_far: bool) -> None:
    """The declared near/far distance must equal the decoded CALL kind."""
    image, (target,) = _image_and_targets(_FAR_ENTRIES if is_far else _NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(image, is_far=not is_far, target=target)
    path = _write(tmp_path, _document(image, [entry]))
    _refuse(DeclaredCallAdmissionFailure8616.DISTANCE_MISMATCH, project, image, (path,))


def test_declared_target_must_match_decoded_call(tmp_path: Path) -> None:
    """The declared callee address must equal the decoded CALL operand."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(image, is_far=False, target=target + 1)
    path = _write(tmp_path, _document(image, [entry]))
    _refuse(DeclaredCallAdmissionFailure8616.TARGET_MISMATCH, project, image, (path,))


def test_real_callee_cannot_be_masked_by_declaration(tmp_path: Path) -> None:
    """Only a registered synthetic stub target may carry the relation."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    entry = _declaration(image, is_far=False, target=target)
    path = _write(tmp_path, _document(image, [entry]))
    _refuse(
        DeclaredCallAdmissionFailure8616.TARGET_NOT_SYNTHETIC_STUB,
        project,
        image,
        (path,),
    )

    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target + 1}))
    _refuse(
        DeclaredCallAdmissionFailure8616.TARGET_NOT_SYNTHETIC_STUB,
        project,
        image,
        (path,),
    )

    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target, -1}))
    _refuse(
        DeclaredCallAdmissionFailure8616.TARGET_NOT_SYNTHETIC_STUB,
        project,
        image,
        (path,),
    )


def test_duplicate_callsite_declaration_refuses(tmp_path: Path) -> None:
    """The same callsite declared twice, in one file or two, refuses."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(image, is_far=False, target=target)
    path = _write(tmp_path, _document(image, [entry, dict(entry)]))
    _refuse(DeclaredCallAdmissionFailure8616.DUPLICATE_CALLSITE, project, image, (path,))

    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    second = _write(tmp_path, _document(image, [dict(entry)]), name="second.json")
    _refuse(
        DeclaredCallAdmissionFailure8616.DUPLICATE_CALLSITE, project, image, (path, second)
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"label": "other-label"},
        {"caller_end": BASE + 4},
    ],
)
def test_contradictory_callsite_declaration_refuses(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    """The same callsite carrying a different bound binding contradicts."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    first = _declaration(image, is_far=False, target=target)
    second_overrides = dict(overrides)
    if "caller_end" in second_overrides:
        end = int(second_overrides["caller_end"])
        second_overrides["caller_sha256"] = hashlib.sha256(
            image[: end - BASE]
        ).hexdigest()
    second = _declaration(
        image, is_far=False, target=target, overrides=second_overrides
    )
    path = _write(tmp_path, _document(image, [first, second]))
    _refuse(
        DeclaredCallAdmissionFailure8616.CONTRADICTORY_DECLARATION,
        project,
        image,
        (path,),
    )


def test_refused_admission_leaves_no_registry(tmp_path: Path) -> None:
    """A refused input must not mint partial authority on the project."""
    image, (target,) = _image_and_targets(_NEAR_ENTRIES)
    project = _project(image)
    record_synthetic_call_stubs_8616(project, frozenset({target}))
    entry = _declaration(image, is_far=False, target=target + 1)
    path = _write(tmp_path, _document(image, [entry]))
    _refuse(DeclaredCallAdmissionFailure8616.TARGET_MISMATCH, project, image, (path,))
    assert declared_external_call_registry_8616(project) is None

