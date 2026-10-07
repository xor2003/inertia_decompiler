"""Static intake must address the actual caller/frame dependency, not only RET."""

from pathlib import Path

import pytest
import tests.frontend.test_x86_16_mz_static_invocation as worker
import inertia.ir.entry_domain_call_preservation as consumer
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    registered_function_ir_artifact_8616,
)


def test_header_intake_supplies_decoded_edge_for_pending_return_callee(tmp_path: Path) -> None:
    """An authenticated caller CALL exists before proving the callee's return."""
    base = worker.BASE
    callee = base + 0x20
    root = base + 0x60
    # pop cx; jmp cx: a near return requiring the transporting CALL premise.
    body = bytes.fromhex("59 ff e1")
    caller = b"\xe8" + ((callee - root - 3) & 0xffff).to_bytes(2, "little") + b"\xc3"
    image = worker._build_image(((callee, body), (root, caller)))
    mz = worker._build_mz(image, entry_ip=root-base)
    project = worker._make_project(mz, tmp_path, root)
    source = worker._source(project)
    assert source is not None, project._inertia_mz_static_invocation_install_8616
    rows = source.callsite_index.for_target(callee)
    assert len(rows) == 1
    assert rows[0].callsite_addr == root


@pytest.mark.parametrize("corrupted", [False, True])
def test_automatic_header_source_resolves_only_valid_pending_return(tmp_path: Path, corrupted: bool) -> None:
    """The installed caller edge reaches real callee resolution without publication."""
    base = worker.BASE
    callee, root = base + 0x20, base + 0x60
    body = bytes.fromhex("59 ff e2" if corrupted else "59 ff e1")
    caller = b"\xe8" + ((callee - root - 3) & 0xffff).to_bytes(2, "little") + b"\xc3"
    image = worker._build_image(((callee, body), (root, caller)))
    mz = worker._build_mz(image, entry_ip=root-base)
    project = worker._make_project(mz, tmp_path, root)
    source = worker._source(project)
    assert source is not None
    row, = source.callsite_index.for_target(callee)
    resolved = consumer._callee_artifact_and_boundary_8616(project, callee, row)
    if corrupted:
        assert resolved is None
    else:
        assert resolved is not None
        artifact, boundary = resolved
        assert boundary.near_return_continuations is not None
        assert any(
            refusal.kind == "near_return_continuation_pending"
            for block in artifact.blocks for refusal in block.refusals
        )
    registered = registered_function_ir_artifact_8616(project, callee)
    assert registered.verdict is not FunctionIRArtifactVerdict8616.PROVEN
