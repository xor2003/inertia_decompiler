"""Native controls for declared external-call consumption authentication.

A minted admission authorizes DS retention at one exact CALL only while the
current project still authenticates it: closed declaration registry holding
the identical object, identical registered artifact/block/instruction
membership, unchanged whole-image bytes, stub membership, and the shared
exact native call binding. Every negative corrupts one authority.
"""

from __future__ import annotations

import io
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import (
    IRFunctionArtifact,
    IRInstr,
    SegmentOrigin,
)
from inertia.ir.segment_contract import SegmentFunctionContract
from inertia.ir.segment_state import apply_x86_16_segment_state_artifact
from inertia.ir.segment_state_transfer import (
    SegmentValueKind8616,
    architectural_live_in_state,
    declared_call_effect_at_instruction_8616,
    transfer_block_with_instruction_states,
)
from inertia.semantics.segment_function_summary import SegmentFunctionSummary8616

from inertia.frontend.x86_16.declared_external_call_evidence import (
    DeclaredExternalCallRegistry8616,
    declared_external_call_registry_8616,
)
from inertia.frontend.x86_16.synthetic_call_stub_evidence import (
    SyntheticCallStubRegistry8616,
)
from tests.fixtures.x86_16_declared_call_fixture import BASE, world


def test_declared_consumption_authenticates_native_near_call(tmp_path: Path) -> None:
    """A minted admission retains only DS across its one exact native CALL."""
    _project, block, call, artifact, admission, _image = world(tmp_path)
    consumed = declared_call_effect_at_instruction_8616(
        artifact, block, call, (admission,)
    )
    assert consumed is admission
    entry = {"ds": architectural_live_in_state("ds"), "ss": architectural_live_in_state("ss")}
    state, _entries, _exits = transfer_block_with_instruction_states(
        block, entry, source_artifact=artifact, declared_call_effects=(admission,)
    )
    assert state["ds"].source == "ds" and state["ds"].origin is SegmentOrigin.PROVEN
    assert state["ss"].value_kind is SegmentValueKind8616.CALL_BOUNDARY


def test_far_declaration_without_native_theorem_refuses(tmp_path: Path) -> None:
    """A native far CALL stays unsupported until its full binding is proved."""
    _project, block, call, artifact, admission, _image = world(tmp_path, is_far=True)
    assert call.args[0].space.name == "CONST" and call.args[0].const == admission.target_addr
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (admission,)) is None


def test_far_consumption_rejects_unbound_native_origin(tmp_path: Path) -> None:
    """Declared far effects need current native IR provenance."""
    _project, block, call, artifact, admission, _image = world(tmp_path, is_far=True)
    object.__setattr__(call, "origin", None)
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (admission,)) is None


def test_consumption_rejects_wrong_target(tmp_path: Path) -> None:
    """A foreign admission object or mutated call target cannot authorize."""
    project, block, call, artifact, admission, _image = world(tmp_path)
    other_stub = replace(admission, target_addr=admission.target_addr + 1)
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (other_stub,)) is None
    # Repointing the E8 displacement at a different address refuses too.
    project.loader.memory.store(BASE + 1, b"\xff\x7f")
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (admission,)) is None


def test_consumption_rejects_foreign_instruction_and_block(tmp_path: Path) -> None:
    """Equal-but-not-identical CALL objects or foreign blocks refuse."""
    _project, block, call, artifact, admission, _image = world(tmp_path)
    identical_value_foreign_object = replace(call)
    assert declared_call_effect_at_instruction_8616(
        artifact, block, identical_value_foreign_object, (admission,)
    ) is None
    foreign_block = replace(block)
    assert declared_call_effect_at_instruction_8616(
        artifact, foreign_block, call, (admission,)
    ) is None
    nonmember = IRInstr("CALL", None, call.args, addr=call.addr)
    assert declared_call_effect_at_instruction_8616(
        artifact, block, nonmember, (admission,)
    ) is None


def test_consumption_rejects_stale_source(tmp_path: Path) -> None:
    """Mutating any caller byte after minting refuses consumption."""
    project, block, call, artifact, admission, image = world(tmp_path)
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (admission,)) is admission
    project.loader.memory.store(BASE + 3, bytes([image[3] ^ 0xFF]))
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (admission,)) is None


def test_consumption_rejects_changed_stub_bytes(tmp_path: Path) -> None:
    """Mutating stub bytes or evicting stub membership refuses consumption."""
    project, block, call, artifact, admission, _image = world(tmp_path)
    project.loader.memory.store(admission.target_addr, b"\xcb")
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (admission,)) is None

    project, block, call, artifact, admission, _image = world(tmp_path)
    empty = SyntheticCallStubRegistry8616(
        addresses=frozenset(),
        raw_fact_count=0,
        normalized_fact_count=0,
        classified_fact_count=0,
        materialized_count=0,
        failure_count=0,
    )
    project._inertia_synthetic_call_stub_registry_8616 = empty
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (admission,)) is None


def test_consumption_rejects_cross_project_or_copied_admission(tmp_path: Path) -> None:
    """A copied object or a foreign project's admission cannot authorize."""
    _project, block, call, artifact, admission, image = world(tmp_path)
    copied = replace(admission)
    assert copied == admission and copied is not admission
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (copied,)) is None

    other = angr.Project(
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
    foreign = replace(admission, project=other)
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (foreign,)) is None


def test_consumption_rejects_mismatched_registry_or_artifact(tmp_path: Path) -> None:
    """Non-member, unclosed, or missing registry and foreign artifacts refuse."""
    project, block, call, artifact, admission, _image = world(tmp_path)

    unregistered = IRFunctionArtifact(BASE, (block,))
    assert declared_call_effect_at_instruction_8616(
        unregistered, block, call, (admission,)
    ) is None

    registry = declared_external_call_registry_8616(project)
    assert registry is not None
    missing = replace(registry, admissions=())
    assert not missing.closes_evidence
    project._inertia_declared_external_call_registry_8616 = missing
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (admission,)) is None

    unclosed = DeclaredExternalCallRegistry8616(
        admissions=(admission,),
        image_sha256=admission.image_sha256,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=1,
    )
    assert not unclosed.closes_evidence
    project._inertia_declared_external_call_registry_8616 = unclosed
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (admission,)) is None

    del project._inertia_declared_external_call_registry_8616
    assert declared_call_effect_at_instruction_8616(artifact, block, call, (admission,)) is None


def test_defaults_without_declarations_unchanged(tmp_path: Path) -> None:
    """Absent or empty declarations keep the CALL boundary unknown."""
    _project, block, call, artifact, _admission, _image = world(tmp_path)
    assert declared_call_effect_at_instruction_8616(artifact, block, call, ()) is None
    entry = {"ds": architectural_live_in_state("ds")}
    state, _entries, _exits = transfer_block_with_instruction_states(
        block, entry, source_artifact=artifact
    )
    assert state["ds"].value_kind is SegmentValueKind8616.CALL_BOUNDARY
    assert state["ds"].origin is SegmentOrigin.UNKNOWN


def test_native_apply_publishes_and_revokes_receipts(tmp_path: Path) -> None:
    """Current native consumption reaches both summaries; revocation clears both."""
    project, _block, _call, artifact, _admission, _image = world(tmp_path)
    summary = SegmentFunctionSummary8616(BASE, SegmentFunctionContract(function_addr=BASE))
    boundary = SimpleNamespace(
        _inertia_vex_ir_artifact=artifact,
        _inertia_segment_function_summary_8616=summary,
    )
    project._inertia_segment_function_summaries_8616 = {BASE: summary}
    apply_x86_16_segment_state_artifact(project, boundary)
    receipts = boundary._inertia_segment_state_artifact.declared_call_consumptions
    assert len(receipts) == 1
    assert boundary._inertia_segment_function_summary_8616.declared_call_consumptions == receipts
    assert project._inertia_segment_function_summaries_8616[BASE].declared_call_consumptions == receipts
    project._inertia_declared_external_call_registry_8616 = None
    apply_x86_16_segment_state_artifact(project, boundary)
    assert boundary._inertia_segment_state_artifact.declared_call_consumptions == ()
    assert boundary._inertia_segment_function_summary_8616.declared_call_consumptions == ()
    assert project._inertia_segment_function_summaries_8616[BASE].declared_call_consumptions == ()
