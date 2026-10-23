"""Data-only IR cache boundaries for live function lifecycle authority."""

import base64
import hashlib
import pickle
from dataclasses import replace

import pytest

from inertia.cli.function_ir_ssa_cache_codec import (
    FunctionIRSSABundle8616,
    function_ir_ssa_bundle_from_record_8616,
    function_ir_ssa_bundle_record_8616,
)
from inertia.ir.core import IRBlock
from inertia.ir.function_artifact import IRFunctionArtifact
from inertia.ir.function_lifecycle import (
    FunctionStageEvidence8616,
    FunctionStageReadiness8616,
    FunctionStageVerdict8616,
)
from inertia.ir.function_readiness_contracts import (
    FUNCTION_LIFECYCLE_STAGES_8616,
    FunctionLifecycleStage8616,
    function_artifact_body_digest_8616,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa

pytestmark = pytest.mark.decompiler


class _RuntimeOnly:
    def __reduce__(self) -> object:
        raise AssertionError("live producer objects must never enter an IR cache")


def _bundle() -> FunctionIRSSABundle8616:
    artifact = IRFunctionArtifact(0x1000, blocks=(IRBlock(0x1000),))
    return FunctionIRSSABundle8616(artifact, build_x86_16_function_ssa(artifact))


def _checked_lifecycle(bundle: FunctionIRSSABundle8616) -> None:
    for stage in FUNCTION_LIFECYCLE_STAGES_8616:
        bundle.ir.lifecycle.state.observe(FunctionStageReadiness8616(
            0x1000, stage, FunctionStageVerdict8616.CURRENT,
        ))


def test_live_publications_are_not_pickled_or_restored() -> None:
    """A live backend object is excluded while raw IR still round-trips."""
    bundle = _bundle()
    bundle.ir.lifecycle.state.record(FunctionStageEvidence8616(
        FunctionLifecycleStage8616.REWRITE, None, ("output",), (), "runtime",
        live_outputs=(_RuntimeOnly(),),
    ))
    _checked_lifecycle(bundle)
    record = function_ir_ssa_bundle_record_8616(bundle)
    restored = function_ir_ssa_bundle_from_record_8616(record, 0x1000)
    assert restored.ir.lifecycle is restored.ssa.lifecycle
    assert restored.ir.lifecycle.state.maturity is None
    assert not restored.ir.lifecycle.state.publications
    assert bundle.ir.lifecycle.state.maturity is FunctionLifecycleStage8616.REWRITE
    assert bundle.ir.lifecycle.state.publications
    assert function_artifact_body_digest_8616(restored.ir) == function_artifact_body_digest_8616(bundle.ir)


def test_forged_serialized_maturity_is_discarded_on_decode() -> None:
    """A valid payload digest cannot turn serialized verdicts into live proof."""
    bundle = _bundle()
    record = function_ir_ssa_bundle_record_8616(bundle)
    _checked_lifecycle(bundle)
    forged = replace(bundle.ir, lifecycle_stage=FunctionLifecycleStage8616.REWRITE)
    payload = pickle.dumps(forged, protocol=5)
    record["payload"] = base64.b64encode(payload).decode("ascii")
    record["payload_sha256"] = hashlib.sha256(payload).hexdigest()
    restored = function_ir_ssa_bundle_from_record_8616(record, 0x1000)
    assert not restored.ir.lifecycle.state.evaluations
    assert restored.ssa.lifecycle.state.maturity is None
    assert restored.ir.lifecycle_stage is FunctionLifecycleStage8616.IR
    assert restored.ssa.lifecycle_stage is FunctionLifecycleStage8616.IR


def test_runtime_maturity_changes_neither_body_identity_nor_cached_ir() -> None:
    """Mutable consumer observations cannot change exact consumed-body identity."""
    bundle = _bundle()
    body = function_artifact_body_digest_8616(bundle.ir)
    first = function_ir_ssa_bundle_record_8616(bundle)
    _checked_lifecycle(bundle)
    assert function_artifact_body_digest_8616(bundle.ir) == body
    assert function_ir_ssa_bundle_record_8616(bundle) == first


def test_ir_and_ssa_share_the_same_function_state() -> None:
    """A built SSA projection must expose the raw owner's current refusal view."""
    bundle = _bundle()
    assert bundle.ir.lifecycle is bundle.ssa.lifecycle
    _checked_lifecycle(bundle)
    assert bundle.ir.to_dict()["lifecycle"] == bundle.ssa.to_dict()["lifecycle"]
