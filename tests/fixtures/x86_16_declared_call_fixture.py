"""Shared native fixture for declared external-call consumer controls.

Layer: Tests.
Responsibility: mint a real frontend admission bound to exact image bytes and
materialize the matching native IR block so each control corrupts exactly one
authority instead of fabricating success.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import angr

import inertia.frontend.x86_16.lift_86_16 as lift_86_16
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.cod_analysis_image import build_cod_analysis_image_8616
from inertia.frontend.x86_16.declared_external_call_evidence import (
    DeclaredCallAdmission8616,
    admit_declared_external_call_files_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.frontend.x86_16.synthetic_call_stub_evidence import (
    record_synthetic_call_stubs_8616,
)
from inertia.ir.core import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
)
from inertia.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from inertia.ir.function_readiness_contracts import (
    function_artifact_body_digest_8616,
    observed_function_source_revision_8616,
    record_function_build_attestation_8616,
)
from inertia.ir.vex_import import _block_to_ir

BASE = 0x1000

NativeConsumption = tuple[
    angr.Project, IRBlock, IRInstr, IRFunctionArtifact, DeclaredCallAdmission8616, bytes
]


def _declaration_file(tmp_path: Path, image: bytes, target: int, *, is_far: bool, call_size: int) -> Path:
    """Write one strict declaration file binding the exact supplied image."""
    caller = image[: call_size + 1]
    document = {
        "schema": 1,
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "declarations": [
            {
                "caller_start": BASE,
                "caller_end": BASE + len(caller),
                "caller_sha256": hashlib.sha256(caller).hexdigest(),
                "callsite_addr": BASE,
                "target_addr": target,
                "is_far": is_far,
                "relations": ["ds_preserved_on_return"],
                "label": "declared-external",
            }
        ],
    }
    path = tmp_path / "declared.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def world(tmp_path: Path, *, is_far: bool = False) -> NativeConsumption:
    """Mint a real frontend admission and consume it on a real native block."""
    assert lift_86_16.__file__.endswith(".so")
    if is_far:
        entries = [
            {"offset": 0, "bytes": bytes.fromhex("9a00000000"), "text": "call far ptr far_external"},
            {"offset": 5, "bytes": b"\xcb", "text": "retf"},
        ]
        call_size = 5
    else:
        entries = [
            {"offset": 0, "bytes": bytes.fromhex("e80000"), "text": "call arbitrary_external"},
            {"offset": 3, "bytes": b"\xc3", "text": "ret"},
        ]
        call_size = 3
    image = build_cod_analysis_image_8616(entries)
    project = angr.Project(
        io.BytesIO(image.code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": BASE,
            "entry_point": BASE,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    targets = frozenset(BASE + offset for offset in image.call_target_offsets)
    record_synthetic_call_stubs_8616(project, targets)
    declaration = _declaration_file(tmp_path, image.code, min(targets), is_far=is_far, call_size=call_size)
    registry = admit_declared_external_call_files_8616(
        project, image_code=image.code, image_base=BASE, paths=(declaration,)
    )
    assert registry is not None and registry.closes_evidence and len(registry.admissions) == 1
    admission = registry.admissions[0]
    block, _transport, _terminal = _block_to_ir(project.factory.block(BASE, opt_level=0))
    call = next(i for i in block.instrs if i.op == "CALL")
    boundary = exact_function_range_boundary_8616(project, BASE, admission.caller_end)
    assert boundary is not None
    revision = observed_function_source_revision_8616(project, BASE, boundary=boundary)
    assert revision is not None
    artifact = IRFunctionArtifact(BASE, (block,), source_revision=revision)
    digest = function_artifact_body_digest_8616(artifact)
    assert digest is not None
    record_function_build_attestation_8616(
        project,
        BASE,
        digest,
        revision,
        "x86_16_vex_ir",
        boundary=boundary,
    )
    assert publish_function_ir_artifact_8616(project, artifact).artifact is artifact
    return project, block, call, artifact, admission, image.code
