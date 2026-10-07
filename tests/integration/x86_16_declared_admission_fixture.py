"""Admission-boundary corruption controls for declared external-call evidence.

Layer: Tests.
Responsibility: prove the frontend admission owner refuses malformed, stale,
unbound, duplicated, or contradictory declaration input with its typed
failure, and that only an exactly bound declaration mints a closed registry
on the project. Every control exercises the real imported implementation
against a real blob project; consumption-time authentication of minted
admissions is covered by ``test_x86_16_declared_call_consumption.py`` and is
not duplicated here.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.frontend.x86_16.cod_analysis_image import build_cod_analysis_image_8616
from inertia.frontend.x86_16.declared_external_call_evidence import (
    DeclaredCallAdmissionFailure8616,
    DeclaredExternalCallAdmissionError8616,
    admit_declared_external_call_files_8616,
)
from inertia.frontend.x86_16.synthetic_call_stub_evidence import (
    record_synthetic_call_stubs_8616,
)

BASE = 0x1000
_NEAR_CALL_SIZE = 3
_FAR_CALL_SIZE = 5
_MAX_DECLARED_CALL_EFFECT_FILES = 16
_MAX_DECLARED_CALLS_PER_FILE = 256

_NEAR_ENTRIES = [
    {"offset": 0, "bytes": bytes.fromhex("e80000"), "text": "call declared_external"},
    {"offset": 3, "bytes": b"\xc3", "text": "ret"},
]
_FAR_ENTRIES = [
    {"offset": 0, "bytes": bytes.fromhex("9a00000000"), "text": "call far ptr declared_external"},
    {"offset": 5, "bytes": b"\xcb", "text": "retf"},
]
_TWO_CALL_ENTRIES = [
    {"offset": 0, "bytes": bytes.fromhex("e80000"), "text": "call first_external"},
    {"offset": 3, "bytes": b"\xc3", "text": "ret"},
    {"offset": 4, "bytes": bytes.fromhex("e80000"), "text": "call second_external"},
    {"offset": 7, "bytes": b"\xc3", "text": "ret"},
]


def _project(image: bytes) -> angr.Project:
    """Build one real blob project exposing the exact loader memory surface."""
    return angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": BASE,
            "entry_point": BASE,
        },
        auto_load_libs=False,
        simos="DOS",
    )


def _image_and_targets(entries: list[dict[str, object]]) -> tuple[bytes, tuple[int, ...]]:
    """Build one COD analysis image and return its bytes and stub addresses."""
    image = build_cod_analysis_image_8616(entries)
    targets = tuple(BASE + offset for offset in sorted(image.call_target_offsets))
    return image.code, targets


def _declaration(
    image: bytes,
    *,
    is_far: bool,
    target: int,
    callsite_addr: int = BASE,
    caller_start: int = BASE,
    caller_end: int | None = None,
    overrides: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build one valid declaration entry; overrides corrupt single fields."""
    end = caller_end if caller_end is not None else BASE + len(image)
    entry: dict[str, object] = {
        "caller_start": caller_start,
        "caller_end": end,
        "caller_sha256": hashlib.sha256(
            image[caller_start - BASE : end - BASE]
        ).hexdigest(),
        "callsite_addr": callsite_addr,
        "target_addr": target,
        "is_far": is_far,
        "relations": ["ds_preserved_on_return"],
        "label": "declared-external",
    }
    if overrides:
        entry.update(overrides)
    return entry


def _document(image: bytes, declarations: list[object]) -> dict[str, object]:
    """Build one valid declaration document carrying the supplied entries."""
    return {
        "schema": 1,
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "declarations": declarations,
    }


def _write(tmp_path: Path, document: object, name: str = "declared.json") -> Path:
    """Persist one declaration document under ``tmp_path``."""
    path = tmp_path / name
    path.write_text(
        document if isinstance(document, str) else json.dumps(document),
        encoding="utf-8",
    )
    return path


def _stage(
    tmp_path: Path,
    *,
    is_far: bool = False,
    register_stub: bool = True,
) -> tuple[angr.Project, bytes, int, Path]:
    """Mint a real project, image, registered stub and valid declaration file."""
    image, (target,) = _image_and_targets(_FAR_ENTRIES if is_far else _NEAR_ENTRIES)
    project = _project(image)
    if register_stub:
        record_synthetic_call_stubs_8616(project, frozenset({target}))
    path = _write(tmp_path, _document(image, [_declaration(image, is_far=is_far, target=target)]))
    return project, image, target, path


def _admit(
    project: object,
    image: bytes,
    paths: tuple[Path, ...],
    *,
    image_base: int = BASE,
) -> object:
    """Run the real admission boundary."""
    return admit_declared_external_call_files_8616(
        project, image_code=image, image_base=image_base, paths=paths
    )


def _refuse(
    failure: DeclaredCallAdmissionFailure8616,
    project: object,
    image: bytes,
    paths: tuple[Path, ...],
    *,
    image_base: int = BASE,
) -> DeclaredExternalCallAdmissionError8616:
    """Assert the boundary refuses with exactly one typed failure."""
    with pytest.raises(DeclaredExternalCallAdmissionError8616) as caught:
        _admit(project, image, paths, image_base=image_base)
    assert caught.value.failure is failure
    return caught.value


