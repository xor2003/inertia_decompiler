"""Parent review controls for source freshness and complete intake receipts."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from tools.dosunit.tests.test_binary_callee_intake import _image, _lower, _request
from tools.dosunit.tests.test_dosunit_tool import _edge_function

import tools.dosunit.catalog.binary_callee_intake as I
import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.catalog.binary_callee_discovery import DiscoveryBudget, DiscoveryRefusal, discover_uncatalogued_leaves
from tools.dosunit.reporting.flat32_proof_report import loaded_image_identity
from tools.dosunit.compare.real16_call_frames import CallFrameKind


def _fixture(tmp_path):
    """Lower the real caller before injecting a failed probe boundary."""
    return _lower(tmp_path, _image(), [_edge_function("demo.exe:caller", "caller", offset=0x200, size=7)], "review")


@pytest.mark.parametrize("missing", ["statements", "size"])
def test_intake_refuses_missing_probe_ir_evidence(tmp_path, monkeypatch, missing):
    """Absent VEX exit/size evidence must not default to a complete leaf."""
    project, document = _fixture(tmp_path)
    original = S._lift_vex_block_cached
    invoked = False

    def incomplete_probe(**kwargs):
        nonlocal invoked
        lifted = original(**kwargs)
        if invoked:
            return lifted
        invoked = True
        fields = {"jumpkind": lifted.irsb.jumpkind, "statements": lifted.irsb.statements, "size": lifted.irsb.size}
        fields.pop(missing)
        return replace(lifted, irsb=SimpleNamespace(**fields))

    monkeypatch.setattr(S, "_lift_vex_block_cached", incomplete_probe)
    result = I.intake_uncatalogued_leaf(_request(project, document))
    assert result.status is I.IntakeStatus.REFUSED
    assert result.refusal.reason is I.IntakeRefusalReason.BODY_LIFT_FAILED


@pytest.mark.parametrize("mutation", ["file", "loaded_image"])
def test_intake_rechecks_full_source_identity_before_receipt(tmp_path, monkeypatch, mutation):
    """Changing unrelated source bytes still invalidates an image-bound receipt."""
    project, document = _fixture(tmp_path)
    original = I._lower_leaf

    def changed_source(*args, **kwargs):
        parts = original(*args, **kwargs)
        if mutation == "file":
            path = Path(document["exe"])
            path.write_bytes(path.read_bytes() + b"\x00")
        else:
            project.loader.memory.store(0x1280, b"\x01")
        return parts

    monkeypatch.setattr(I, "_lower_leaf", changed_source)
    result = I.intake_uncatalogued_leaf(_request(project, document))
    assert result.status is I.IntakeStatus.REFUSED
    assert result.refusal.reason is I.IntakeRefusalReason.SOURCE_CHANGED


def test_intake_receipt_retains_loaded_model_domain_and_shared_counters(tmp_path):
    """All admitted projections carry the same concrete image/domain evidence."""
    project, document = _fixture(tmp_path)
    result = I.intake_uncatalogued_leaf(_request(project, document))
    assert result.status is I.IntakeStatus.ADMITTED
    receipt = result.receipt
    assert receipt.loaded_image == loaded_image_identity(project)
    assert len(receipt.semantic_sha256) == 64
    assert receipt.selector_domain.linear_entry == receipt.body.target_linear
    assert receipt.call_site.frame_kind is CallFrameKind.NEAR16
    assert result.counters.failure_count == 0
    assert result.counters.raw_fact_count == result.counters.materialized_count > 0


@pytest.mark.parametrize("budget,reason", [
    (DiscoveryBudget(max_requests=0), DiscoveryRefusal.REQUEST_LIMIT),
    (DiscoveryBudget(max_elapsed_ms=0), DiscoveryRefusal.DEADLINE),
])
def test_discovery_exhaustion_keeps_missing_callee_and_failure_visible(tmp_path, budget, reason):
    """An exhausted intake cannot materialize a guessed body or drop its refusal."""
    project, document = _fixture(tmp_path)
    original_parts = tuple(document["functions"])
    report = discover_uncatalogued_leaves(
        project, document, root_ids=frozenset({"demo.exe:caller"}),
        leaf_budget=I.IntakeBudget(), budget=budget,
    )
    assert tuple(document["functions"]) == original_parts
    assert report["attempted"] == 0
    assert report["requests"][0]["reason"] == reason.value
    assert report["counters"]["failure_count"] == 1
    assert report["counters"]["classified_fact_count"] == report["counters"]["materialized_count"] == 1
