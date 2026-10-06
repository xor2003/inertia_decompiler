"""
Tests for confidence_and_assumptions module (Phase 4.1).

Tests confidence level assignment, marker tracking, function reports,
and integration with decompiler output.
"""

import types

import pytest
from angr_platforms.X86_16.confidence_and_assumptions import (
    ConfidenceLevel,
    ConfidenceMarker,
    ConfidenceTracker,
    FunctionConfidenceReport,
    ScanConfidenceSummary,
    apply_x86_16_confidence_and_assumptions,
    build_function_with_confidence_markers,
)
from angr_platforms.X86_16.confidence_evidence import (
    EvidenceStatus,
    load_confidence_evidence,
)
from angr_platforms.X86_16.segmented_memory_reasoning import (
    SegmentAssociation,
    SegmentRegister,
)
from angr_platforms.X86_16.type_array_matching import ArrayRecoveryInfo
from angr_platforms.X86_16.type_storage_object_bridge import (
    SegmentedStorageFact,
    StorageObjectBridgeFact,
)
from angr_platforms.X86_16.type_structure_merging import (
    StructField,
    StructRecoveryInfo,
    StructType,
)

from inertia_decompiler.cli_storage_objects import StorageObjectRefusal


class TestConfidenceLevel:
    """Test confidence level enum."""

    def test_enum_values(self) -> None:
        """Test confidence level enum has expected values."""
        assert ConfidenceLevel.HIGH.value == "HIGH"
        assert ConfidenceLevel.MEDIUM.value == "MEDIUM"
        assert ConfidenceLevel.LOW.value == "LOW"

    def test_enum_ordering(self) -> None:
        """Test confidence levels are distinct."""
        assert ConfidenceLevel.HIGH != ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.MEDIUM != ConfidenceLevel.LOW
        assert ConfidenceLevel.HIGH != ConfidenceLevel.LOW


class TestConfidenceMarker:
    """Test confidence marker creation."""

    def test_marker_creation_basic(self) -> None:
        """Test basic marker creation."""
        marker = ConfidenceMarker(
            fact_kind="struct",
            fact_detail="struct Person",
            confidence=ConfidenceLevel.HIGH,
            evidence_count=3,
        )
        assert marker.fact_kind == "struct"
        assert marker.fact_detail == "struct Person"
        assert marker.confidence == ConfidenceLevel.HIGH
        assert marker.evidence_count == 3
        assert marker.reason is None

    def test_marker_with_reason(self) -> None:
        """Test marker with reason."""
        marker = ConfidenceMarker(
            fact_kind="array",
            fact_detail="array buffer[256]",
            confidence=ConfidenceLevel.MEDIUM,
            evidence_count=2,
            reason="detected from 2 access patterns",
        )
        assert marker.reason == "detected from 2 access patterns"

    def test_marker_immutable(self) -> None:
        """Test marker is immutable (frozen)."""
        marker = ConfidenceMarker(
            fact_kind="pointer",
            fact_detail="ptr_t",
            confidence=ConfidenceLevel.HIGH,
            evidence_count=1,
        )
        with pytest.raises(AttributeError):
            marker.fact_kind = "changed"


class TestConfidenceTracker:
    """Test confidence tracker aggregation."""

    def test_tracker_creation(self) -> None:
        """Test tracker creation."""
        tracker = ConfidenceTracker()
        assert tracker.total_count() == 0
        assert tracker.high_count() == 0
        assert tracker.medium_count() == 0
        assert tracker.low_count() == 0

    def test_add_single_marker(self) -> None:
        """Test adding single marker."""
        tracker = ConfidenceTracker()
        tracker.add_marker(
            fact_kind="struct",
            fact_detail="struct Point",
            confidence=ConfidenceLevel.HIGH,
            evidence_count=5,
        )
        assert tracker.total_count() == 1
        assert tracker.high_count() == 1
        assert tracker.medium_count() == 0
        assert tracker.low_count() == 0

    def test_add_multiple_markers(self) -> None:
        """Test adding multiple markers."""
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "struct A", ConfidenceLevel.HIGH, evidence_count=3)
        tracker.add_marker("array", "array buf", ConfidenceLevel.MEDIUM, evidence_count=2)
        tracker.add_marker("pointer", "ptr field", ConfidenceLevel.LOW, evidence_count=1)
        assert tracker.total_count() == 3
        assert tracker.high_count() == 1
        assert tracker.medium_count() == 1
        assert tracker.low_count() == 1

    def test_count_only_relevant_confidence(self) -> None:
        """Test counting per confidence level."""
        tracker = ConfidenceTracker()
        for _ in range(4):
            tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        for _ in range(3):
            tracker.add_marker("array", "a", ConfidenceLevel.MEDIUM, evidence_count=1)
        for _ in range(2):
            tracker.add_marker("pointer", "p", ConfidenceLevel.LOW, evidence_count=1)
        assert tracker.high_count() == 4
        assert tracker.medium_count() == 3
        assert tracker.low_count() == 2
        assert tracker.total_count() == 9

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "struct X", ConfidenceLevel.HIGH, evidence_count=2)
        tracker.add_marker("array", "array Y", ConfidenceLevel.LOW, evidence_count=1)
        d = tracker.to_dict()
        assert d["high_count"] == 1
        assert d["medium_count"] == 0
        assert d["low_count"] == 1
        assert d["total_count"] == 2
        assert len(d["markers"]) == 2


class TestFunctionConfidenceReport:
    """Test function confidence reports."""

    def test_report_creation(self) -> None:
        """Test report creation."""
        tracker = ConfidenceTracker()
        report = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="main",
            confidence_tracker=tracker,
        )
        assert report.func_addr == 0x1000
        assert report.func_name == "main"
        assert len(report.assumptions) == 0
        assert len(report.critical_unknowns) == 0

    def test_add_assumption(self) -> None:
        """Test adding assumptions."""
        tracker = ConfidenceTracker()
        report = FunctionConfidenceReport(
            func_addr=0x2000,
            func_name="process",
            confidence_tracker=tracker,
        )
        report.add_assumption("unresolved indirect target at 0x2100")
        report.add_assumption("guessed helper signature for DOS function")
        assert len(report.assumptions) == 2

    def test_add_critical_unknown(self) -> None:
        """Test adding critical unknowns."""
        tracker = ConfidenceTracker()
        report = FunctionConfidenceReport(
            func_addr=0x3000,
            func_name="data_handler",
            confidence_tracker=tracker,
        )
        report.add_critical_unknown("uncertain far pointer to DS:0x4000")
        assert len(report.critical_unknowns) == 1

    def test_overall_confidence_high(self) -> None:
        """Test overall confidence HIGH."""
        tracker = ConfidenceTracker()
        for _ in range(8):
            tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        tracker.add_marker("array", "a", ConfidenceLevel.MEDIUM, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="func",
            confidence_tracker=tracker,
        )
        assert report.overall_confidence() == ConfidenceLevel.HIGH

    def test_overall_confidence_medium(self) -> None:
        """Test overall confidence MEDIUM."""
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        tracker.add_marker("array", "a", ConfidenceLevel.MEDIUM, evidence_count=1)
        tracker.add_marker("pointer", "p", ConfidenceLevel.MEDIUM, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x2000,
            func_name="func",
            confidence_tracker=tracker,
        )
        assert report.overall_confidence() == ConfidenceLevel.MEDIUM

    def test_overall_confidence_low_from_low_markers(self) -> None:
        """Test overall confidence LOW from low markers."""
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        for _ in range(4):
            tracker.add_marker("pointer", "p", ConfidenceLevel.LOW, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x3000,
            func_name="func",
            confidence_tracker=tracker,
        )
        assert report.overall_confidence() == ConfidenceLevel.LOW

    def test_overall_confidence_low_from_critical_unknowns(self) -> None:
        """Test overall confidence LOW from critical unknowns."""
        tracker = ConfidenceTracker()
        for _ in range(5):
            tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x4000,
            func_name="func",
            confidence_tracker=tracker,
        )
        report.add_critical_unknown("cannot resolve target")
        assert report.overall_confidence() == ConfidenceLevel.LOW

    def test_comment_header_generation(self) -> None:
        """Test comment header generation."""
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        tracker.add_marker("array", "a", ConfidenceLevel.HIGH, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="process",
            confidence_tracker=tracker,
        )
        report.add_assumption("assumption 1")
        header = report.comment_header()
        assert "// process @ 0x1000" in header
        assert "// Confidence: HIGH" in header
        assert "// Evidence: 2 HIGH, 0 MEDIUM, 0 LOW" in header
        assert "// Assumptions: 1 recorded" in header

    def test_comment_header_with_critical_unknowns(self) -> None:
        """Test comment header with critical unknowns."""
        tracker = ConfidenceTracker()
        report = FunctionConfidenceReport(
            func_addr=0x2000,
            func_name="unknown_func",
            confidence_tracker=tracker,
        )
        report.add_critical_unknown("issue 1")
        header = report.comment_header()
        assert "// ⚠️ CRITICAL UNKNOWNS:" in header
        assert "issue 1" in header

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="func",
            confidence_tracker=tracker,
        )
        report.add_assumption("assumption 1")
        d = report.to_dict()
        assert d["func_name"] == "func"
        assert d["func_addr"] == "0x1000"
        assert d["overall_confidence"] == "HIGH"
        assert d["assumptions_count"] == 1


class TestScanConfidenceSummary:
    """Test scan-wide confidence summary."""

    def test_summary_creation(self) -> None:
        """Test summary creation."""
        summary = ScanConfidenceSummary()
        assert summary.total_functions == 0
        assert summary.high_confidence_count == 0
        assert summary.high_confidence_ratio() == 0.0

    def test_add_high_confidence_function(self) -> None:
        """Test adding high-confidence function."""
        tracker = ConfidenceTracker()
        for _ in range(5):
            tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="func1",
            confidence_tracker=tracker,
        )
        summary = ScanConfidenceSummary()
        summary.add_function_report(report)
        assert summary.total_functions == 1
        assert summary.high_confidence_count == 1
        assert summary.high_confidence_ratio() == 1.0

    def test_add_mixed_functions(self) -> None:
        """Test adding functions with mixed confidence."""
        summary = ScanConfidenceSummary()
        # Add high-confidence function
        t1 = ConfidenceTracker()
        for _ in range(4):
            t1.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        r1 = FunctionConfidenceReport(func_addr=0x1000, func_name="f1", confidence_tracker=t1)
        summary.add_function_report(r1)
        # Add low-confidence function
        t2 = ConfidenceTracker()
        for _ in range(4):
            t2.add_marker("pointer", "p", ConfidenceLevel.LOW, evidence_count=1)
        r2 = FunctionConfidenceReport(func_addr=0x2000, func_name="f2", confidence_tracker=t2)
        summary.add_function_report(r2)
        assert summary.total_functions == 2
        assert summary.high_confidence_count == 1
        assert summary.low_confidence_count == 1
        assert summary.high_confidence_ratio() == 0.5

    def test_scan_classification_strong(self) -> None:
        """Test scan classified as STRONG."""
        summary = ScanConfidenceSummary()
        for _ in range(10):
            t = ConfidenceTracker()
            for _ in range(3):
                t.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
            r = FunctionConfidenceReport(
                func_addr=0x1000 + _,
                func_name=f"f{_}",
                confidence_tracker=t,
            )
            summary.add_function_report(r)
        assert summary.scan_classification() == "strong"

    def test_scan_classification_weak(self) -> None:
        """Test scan classified as WEAK."""
        summary = ScanConfidenceSummary()
        t = ConfidenceTracker()
        for _ in range(3):
            t.add_marker("pointer", "p", ConfidenceLevel.LOW, evidence_count=1)
        r = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="f",
            confidence_tracker=t,
        )
        r.add_critical_unknown("issue")
        summary.add_function_report(r)
        assert summary.scan_classification() == "weak"

    def test_scan_classification_partial(self) -> None:
        """Test scan classified as PARTIAL."""
        summary = ScanConfidenceSummary()
        t = ConfidenceTracker()
        t.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        t.add_marker("array", "a", ConfidenceLevel.MEDIUM, evidence_count=1)
        r = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="f",
            confidence_tracker=t,
        )
        summary.add_function_report(r)
        assert summary.scan_classification() == "partial"

    def test_add_assumptions_and_unknowns_to_summary(self) -> None:
        """Test that summary tracks assumptions and unknowns."""
        summary = ScanConfidenceSummary()
        t = ConfidenceTracker()
        t.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        r = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="f",
            confidence_tracker=t,
        )
        r.add_assumption("assumption1")
        r.add_assumption("assumption2")
        r.add_critical_unknown("unknown1")
        summary.add_function_report(r)
        assert summary.total_assumptions == 2
        assert summary.total_critical_unknowns == 1

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        summary = ScanConfidenceSummary()
        t = ConfidenceTracker()
        t.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        r = FunctionConfidenceReport(
            func_addr=0x1000,
            func_name="f",
            confidence_tracker=t,
        )
        summary.add_function_report(r)
        d = summary.to_dict()
        assert d["total_functions"] == 1
        assert d["high_confidence_count"] == 1
        assert d["scan_classification"] == "strong"


class TestIntegration:
    """Test integration with decompiler passes."""

    def test_apply_pass_basic(self) -> None:
        """Test applying confidence pass to mock codegen."""

        class MockCFunc:
            addr = 0x1000
            name = "test_func"
            _struct_recovery_info = None
            _array_recovery_info = None
            _segmented_memory_info = None

        class MockCodegen:
            cfunc = MockCFunc()

        codegen = MockCodegen()
        result = apply_x86_16_confidence_and_assumptions(codegen)
        assert result is False
        assert hasattr(codegen.cfunc, "_recovery_metadata")

    def test_apply_pass_with_none_cfunc(self) -> None:
        """Test applying pass with None cfunc."""

        class MockCodegen:
            cfunc = None

        codegen = MockCodegen()
        result = apply_x86_16_confidence_and_assumptions(codegen)
        assert result is False  # Should not crash or mark structuring changed

    def test_build_function_with_markers(self) -> None:
        """Test building function with markers."""

        class MockCFunc:
            addr = 0x2000
            name = "marked_func"

        cfunc = MockCFunc()
        tracker = ConfidenceTracker()
        tracker.add_marker("struct", "s", ConfidenceLevel.HIGH, evidence_count=1)
        report = FunctionConfidenceReport(
            func_addr=0x2000,
            func_name="marked_func",
            confidence_tracker=tracker,
        )
        result = build_function_with_confidence_markers(cfunc, report)
        assert result is True
        assert hasattr(cfunc, "_recovery_metadata")
        assert cfunc._recovery_metadata["confidence_report"] == report

    def test_empty_tracker_confidence(self) -> None:
        """Test confidence with empty tracker."""
        tracker = ConfidenceTracker()
        report = FunctionConfidenceReport(
            func_addr=0x3000,
            func_name="empty_func",
            confidence_tracker=tracker,
        )
        # Empty tracker should default to MEDIUM
        assert report.overall_confidence() == ConfidenceLevel.MEDIUM


def _allowed_segmented_fact() -> SegmentedStorageFact:
    """Build a segmented-storage fact that permits object lowering."""
    return SegmentedStorageFact(
        segment_register="DS",
        classification="const",
        associated_space="data",
        allow_linear_lowering=True,
        allow_object_lowering=True,
        reason="constant segment value",
    )


def _member_fact(base_key: tuple[object, ...], offsets: tuple[int, ...]) -> StorageObjectBridgeFact:
    """Build a storage-object bridge fact of member kind."""
    return StorageObjectBridgeFact(
        base_key=base_key,
        object_kind="member",
        candidate_offsets=offsets,
        primary_member_offset=offsets[0] if offsets else None,
        segmented_memory=_allowed_segmented_fact(),
    )


def _array_fact(base_key: tuple[object, ...], offsets: tuple[int, ...]) -> StorageObjectBridgeFact:
    """Build a storage-object bridge fact of array kind."""
    return StorageObjectBridgeFact(
        base_key=base_key,
        object_kind="array",
        candidate_offsets=offsets,
        primary_member_offset=offsets[0] if offsets else None,
        segmented_memory=_allowed_segmented_fact(),
    )


def _report_for(codegen: object) -> FunctionConfidenceReport:
    """Run the confidence pass and return the attached function report."""
    assert apply_x86_16_confidence_and_assumptions(codegen) is False
    return codegen.cfunc._recovery_metadata["confidence_report"]


class TestProducerEvidenceProjection:
    """Test the typed producer-evidence projection and marker contract."""

    def test_absent_producer_evidence_yields_no_markers(self) -> None:
        """Codegen without producer metadata must not fabricate markers."""
        codegen = types.SimpleNamespace(
            cfunc=types.SimpleNamespace(addr=0x1000, name="func_absent")
        )
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.structs.status == EvidenceStatus.ABSENT
        assert evidence.arrays.status == EvidenceStatus.ABSENT
        assert evidence.segments.status == EvidenceStatus.ABSENT
        report = _report_for(codegen)
        assert report.confidence_tracker.total_count() == 0
        assert report.assumptions == []

    def test_struct_markers_from_typed_producer(self) -> None:
        """Published struct-merging facts produce markers from real evidence."""
        codegen = types.SimpleNamespace(
            cfunc=types.SimpleNamespace(addr=0x1000, name="func_structs")
        )
        codegen._inertia_struct_merging_applied = True
        codegen._inertia_struct_merging_member_facts = {
            ("ds", "obj_a"): _member_fact(("ds", "obj_a"), (0, 2, 4)),
        }
        codegen._inertia_struct_merging_typed_ir_facts = {
            ("ds", ("v1", "v2")): {
                "space": "ds",
                "base": ("v1", "v2"),
                "candidate_offsets": (0, 2),
                "candidate_widths": (2,),
                "has_phi_evidence": True,
            },
        }
        codegen._inertia_struct_merging_refusal_facts = {
            ("es", "obj_b"): StorageObjectRefusal(
                base_key=("es", "obj_b"), reason="insufficient field evidence"
            ),
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.structs.status == EvidenceStatus.PRESENT
        assert len(evidence.structs.items) == 2
        assert len(evidence.structs.refusals) == 1
        report = _report_for(codegen)
        tracker = report.confidence_tracker
        assert tracker.total_count() == 3
        assert tracker.high_count() == 2  # 3 member offsets + 2 typed IR offsets
        assert tracker.medium_count() == 0
        assert tracker.low_count() == 1  # refusal stays LOW
        refusal_marker = next(m for m in tracker.markers if "refused" in m.fact_detail)
        assert refusal_marker.confidence == ConfidenceLevel.LOW
        assert "insufficient field evidence" in (refusal_marker.reason or "")

    def test_array_markers_from_typed_producer(self) -> None:
        """Published array-matching facts produce markers from real evidence."""
        codegen = types.SimpleNamespace(
            cfunc=types.SimpleNamespace(addr=0x2000, name="func_arrays")
        )
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_lowerable_arrays = {
            ("ds", "buf"): _array_fact(("ds", "buf"), (0, 2, 4, 6)),
        }
        codegen._inertia_array_matching_typed_ir_candidates = {
            ("ds", ("idx", "base"), 2): {
                "space": "ds",
                "base": ("idx", "base"),
                "element_size": 2,
                "has_phi_index": True,
            },
        }
        codegen._inertia_array_matching_refused_arrays = {
            ("es", "tab"): "over-associated segment",
        }
        report = _report_for(codegen)
        tracker = report.confidence_tracker
        assert tracker.total_count() == 3
        assert tracker.high_count() == 1  # 4 candidate offsets >= 3
        assert tracker.medium_count() == 1  # typed IR candidate
        assert tracker.low_count() == 1  # refused array stays LOW
        refused = next(m for m in tracker.markers if "refused" in m.fact_detail)
        assert "over-associated segment" in (refused.reason or "")

    def test_segment_markers_from_published_summary(self) -> None:
        """Published segmented-memory summary drives segment markers."""
        codegen = types.SimpleNamespace(
            cfunc=types.SimpleNamespace(addr=0x3000, name="func_segments")
        )
        codegen._inertia_segmented_memory_applied = True
        codegen._inertia_segmented_memory_summary = {
            "stable": {
                "DS": {
                    "space": "data",
                    "classification": "const",
                    "confidence": 0.9,
                    "evidence_count": 5,
                    "known_values": (0x1234,),
                }
            },
            "over_associated": {
                "ES": {
                    "space": "data",
                    "classification": "over_associated",
                    "confidence": 0.3,
                    "evidence_count": 7,
                    "known_values": (),
                }
            },
            "unknown": {},
        }
        report = _report_for(codegen)
        tracker = report.confidence_tracker
        assert tracker.total_count() == 2
        ds_marker = next(m for m in tracker.markers if "DS" in m.fact_detail)
        es_marker = next(m for m in tracker.markers if "ES" in m.fact_detail)
        assert ds_marker.confidence == ConfidenceLevel.HIGH
        assert ds_marker.evidence_count == 5
        assert es_marker.confidence == ConfidenceLevel.LOW
        assert es_marker.evidence_count == 7

    def test_malformed_evidence_named_not_fabricated(self) -> None:
        """Malformed producer payloads are recorded, never defaulted."""
        codegen = types.SimpleNamespace(
            cfunc=types.SimpleNamespace(addr=0x4000, name="func_malformed")
        )
        codegen._inertia_struct_merging_applied = True
        codegen._inertia_struct_merging_member_facts = "not-a-dict"
        codegen._inertia_struct_merging_typed_ir_facts = {
            ("ds", ("v1",)): {"unexpected": "shape"},
        }
        codegen._inertia_segmented_memory_applied = True
        codegen._inertia_segmented_memory_summary = {
            "stable": {"DS": {"classification": 42}},
        }
        codegen.cfunc._struct_recovery_info = {"structs": [object()]}
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert "_inertia_struct_merging_member_facts" in evidence.structs.malformed
        assert "_struct_recovery_info" in evidence.structs.malformed
        assert evidence.segments.malformed
        report = _report_for(codegen)
        assert report.confidence_tracker.total_count() == 0
        assert any("malformed" in assumption for assumption in report.assumptions)

    def test_producer_error_recorded_as_assumption(self) -> None:
        """A producer-recorded error surfaces as an explicit assumption."""
        codegen = types.SimpleNamespace(
            cfunc=types.SimpleNamespace(addr=0x5000, name="func_error")
        )
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_error = "bridge construction failed"
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.arrays.status == EvidenceStatus.ERROR
        assert evidence.arrays.error == "bridge construction failed"
        report = _report_for(codegen)
        assert any(
            "bridge construction failed" in assumption for assumption in report.assumptions
        )

    def test_legacy_struct_attachment_validated(self) -> None:
        """Owned legacy record types still produce markers from real fields."""
        struct_type = StructType(
            name="point",
            struct_id=0,
            fields={
                0: StructField(
                    name="x",
                    offset=0,
                    width=16,
                    field_type="int",
                    access_count=3,
                    functions={"f1", "f2"},
                )
            },
        )
        codegen = types.SimpleNamespace(
            cfunc=types.SimpleNamespace(addr=0x6000, name="func_legacy")
        )
        codegen.cfunc._struct_recovery_info = StructRecoveryInfo(struct_type)
        report = _report_for(codegen)
        tracker = report.confidence_tracker
        assert tracker.total_count() == 1
        marker = tracker.markers[0]
        assert marker.fact_detail == "struct point"
        assert marker.evidence_count == 2
        assert marker.confidence == ConfidenceLevel.HIGH

    def test_legacy_array_and_segment_attachments_validated(self) -> None:
        """Owned legacy array/segment records produce markers from real fields."""
        array_info = ArrayRecoveryInfo(
            array_name="buf",
            base_ptr="bp-8",
            element_type="int",
            element_width=16,
            element_stride=2,
            access_patterns={"a[i]", "a[i+1]", "a[i+2]"},
            confidence=0.8,
        )
        assoc = SegmentAssociation(
            segment_reg=SegmentRegister.SS,
            associated_space="stack",
            classification="single",
            stability=0.7,
            evidence_count=4,
        )
        codegen = types.SimpleNamespace(
            cfunc=types.SimpleNamespace(addr=0x7000, name="func_legacy2")
        )
        codegen.cfunc._array_recovery_info = array_info
        codegen.cfunc._segmented_memory_info = {"ss": assoc}
        report = _report_for(codegen)
        tracker = report.confidence_tracker
        array_marker = next(m for m in tracker.markers if m.fact_kind == "array")
        segment_marker = next(m for m in tracker.markers if m.fact_kind == "segmented_memory")
        assert array_marker.evidence_count == 3
        assert array_marker.confidence == ConfidenceLevel.HIGH
        assert "SS" in segment_marker.fact_detail
        assert segment_marker.evidence_count == 4
        assert segment_marker.confidence == ConfidenceLevel.MEDIUM

    def test_unexpected_cfunc_exception_propagates(self) -> None:
        """Unexpected third-party boundary errors propagate, not defaulted."""

        class ExplodingCodegen:
            @property
            def cfunc(self) -> object:
                raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            apply_x86_16_confidence_and_assumptions(ExplodingCodegen())

    def test_unexpected_evidence_exception_propagates(self) -> None:
        """A validated record raising on access propagates through the pass."""

        class ExplodingSegmented(SegmentedStorageFact):
            """SegmentedStorageFact instance whose field access raises."""

            @property
            def allow_object_lowering(self) -> bool:
                raise RuntimeError("segmented boom")

            @property
            def refusal_reason(self) -> object:
                raise RuntimeError("segmented boom")

        codegen = types.SimpleNamespace(
            cfunc=types.SimpleNamespace(addr=0x8000, name="func_explode")
        )
        codegen._inertia_struct_merging_applied = True
        codegen._inertia_struct_merging_member_facts = {
            ("ds", "x"): StorageObjectBridgeFact(
                base_key=("ds", "x"),
                object_kind="member",
                candidate_offsets=(0,),
                primary_member_offset=0,
                segmented_memory=ExplodingSegmented.__new__(ExplodingSegmented),
            ),
        }
        with pytest.raises(RuntimeError, match="segmented boom"):
            apply_x86_16_confidence_and_assumptions(codegen)

    def test_projection_deterministic_ordering(self) -> None:
        """Projected items are sorted deterministically by source and identity."""
        codegen = types.SimpleNamespace(
            cfunc=types.SimpleNamespace(addr=0x9000, name="func_order")
        )
        codegen._inertia_struct_merging_applied = True
        codegen._inertia_struct_merging_member_facts = {
            ("ds", "b"): _member_fact(("ds", "b"), (0,)),
            ("ds", "a"): _member_fact(("ds", "a"), (0,)),
        }
        codegen._inertia_struct_merging_typed_ir_facts = {
            ("ds", ("x",)): {
                "space": "ds",
                "base": ("x",),
                "candidate_offsets": (0, 2),
                "candidate_widths": (2,),
                "has_phi_evidence": True,
            },
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        identities = [item.identity for item in evidence.structs.items]
        assert identities == ["ds:a", "ds:b", "ds:x"]


def _staged_codegen(name: str, addr: int = 0x9100) -> types.SimpleNamespace:
    """Build a minimal codegen/cfunc pair for staged producer-evidence tests."""
    return types.SimpleNamespace(cfunc=types.SimpleNamespace(addr=addr, name=name))


def _refused_segmented_fact() -> SegmentedStorageFact:
    """Build a segmented-storage fact that refuses object lowering."""
    return SegmentedStorageFact(
        segment_register="DS",
        classification="unknown",
        associated_space="data",
        allow_linear_lowering=False,
        allow_object_lowering=False,
        reason="unstable segment association",
    )


class TestProducerContractValidation:
    """Parent-review counterexamples: entries must satisfy real producer contracts."""

    def test_empty_typed_ir_candidate_dict_is_malformed(self) -> None:
        """Repro: ``{'empty': {}}`` must not emit an evidence_count=1 marker."""
        codegen = _staged_codegen("func_empty_candidate")
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_typed_ir_candidates = {"empty": {}}
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.arrays.items == ()
        assert "typed_ir_candidates['empty']" in evidence.arrays.malformed
        report = _report_for(codegen)
        assert all(
            marker.fact_kind != "array" for marker in report.confidence_tracker.markers
        )
        assert any("typed_ir_candidates" in a for a in report.assumptions)

    def test_empty_string_candidate_dict_is_malformed(self) -> None:
        """String-effect candidates follow the same contract: ``{}`` is not evidence."""
        codegen = _staged_codegen("func_empty_string_candidate")
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_string_candidates = {"empty": {}}
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.arrays.items == ()
        assert "string_candidates['empty']" in evidence.arrays.malformed

    def test_typed_ir_candidate_requires_producer_fields(self) -> None:
        """Typed IR candidates require space/base/element_size/has_phi_index coherence."""
        codegen = _staged_codegen("func_typed_ir_shape")
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_typed_ir_candidates = {
            ("ds", ("idx", "base"), 2): {
                "space": "ds",
                "base": ("idx", "base"),
                "element_size": 2,
                "has_phi_index": True,
            },
            ("ds", ("short",), 1): {
                "space": "ds",
                "base": ("short",),  # producer requires >= 2 base components
                "element_size": 1,
                "has_phi_index": True,
            },
            ("ds", ("noflag", "base"), 1): {
                "space": "ds",
                "base": ("noflag", "base"),
                "element_size": 1,
            },
            "not-a-tuple-key": {
                "space": "ds",
                "base": ("a", "b"),
                "element_size": 1,
                "has_phi_index": True,
            },
            ("ds", ("mismatched", "base"), 4): {
                "space": "ds",
                "base": ("idx", "base"),  # key/value coherence is producer contract
                "element_size": 4,
                "has_phi_index": True,
            },
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert len(evidence.arrays.items) == 1
        assert evidence.arrays.items[0].source == "typed_ir"
        assert len(evidence.arrays.malformed) == 4

    def test_string_candidate_requires_producer_fields(self) -> None:
        """String candidates require the published role/origin/family contract."""
        codegen = _staged_codegen("func_string_shape")
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_string_candidates = {
            ("ds", ("si",), 1): {
                "space": "ds",
                "base": ("si",),
                "element_size": 1,
                "has_string_effect": True,
                "segment_origin": "proven",
                "string_family": "movs",
                "repeat_kind": "rep",
                "role": "source",
            },
            ("es", ("di",), 1): {
                "space": "es",
                "base": ("di",),
                "element_size": 1,
                "has_string_effect": True,
                "segment_origin": "proven",
                "string_family": "movs",
                "repeat_kind": "rep",
                "role": "middle",  # producer only emits source/destination
            },
            ("ss", ("di",), 2): {
                "space": "ss",
                "base": ("di",),
                "element_size": 2,
                "has_string_effect": True,
                # missing segment_origin/string_family/repeat_kind/role
            },
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert len(evidence.arrays.items) == 1
        assert evidence.arrays.items[0].source == "string_effect"
        assert len(evidence.arrays.malformed) == 2

    def test_struct_typed_ir_fact_contract(self) -> None:
        """Struct typed-IR facts need >=2 int offsets, widths, and phi evidence."""
        codegen = _staged_codegen("func_struct_typed")
        codegen._inertia_struct_merging_applied = True
        codegen._inertia_struct_merging_typed_ir_facts = {
            ("ds", ("v1", "v2")): {
                "space": "ds",
                "base": ("v1", "v2"),
                "candidate_offsets": (0, 2, 4),
                "candidate_widths": (2,),
                "has_phi_evidence": True,
            },
            ("ds", ("v3",)): {
                "space": "ds",
                "base": ("v3",),
                "candidate_offsets": (0,),  # producer requires >= 2 offsets
                "candidate_widths": (2,),
                "has_phi_evidence": True,
            },
            ("ds", ("v4",)): {
                "space": "ds",
                "base": ("v4",),
                "candidate_offsets": (0, "wide"),  # non-int offset
                "candidate_widths": (2,),
                "has_phi_evidence": True,
            },
            ("ds", ("v5",)): {"candidate_offsets": (0, 2)},  # missing producer keys
            "scalar-key": {
                "space": "ds",
                "base": ("v6",),
                "candidate_offsets": (0, 2),
                "candidate_widths": (2,),
                "has_phi_evidence": True,
            },
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert len(evidence.structs.items) == 1
        assert evidence.structs.items[0].evidence_count == 3
        assert len(evidence.structs.malformed) == 4

    def test_segment_entry_rejects_out_of_range_numbers(self) -> None:
        """Repro: confidence=2.0 / evidence_count=-4 must not emit a marker."""
        codegen = _staged_codegen("func_segment_numbers")
        codegen._inertia_segmented_memory_applied = True
        codegen._inertia_segmented_memory_summary = {
            "stable": {
                "DS": {
                    "space": "data",
                    "classification": "stable",  # also not a producer classification
                    "confidence": 2.0,
                    "evidence_count": -4,
                }
            }
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.segments.items == ()
        assert evidence.segments.malformed == (
            "_inertia_segmented_memory_summary['stable']['DS']",
        )
        report = _report_for(codegen)
        assert all(
            marker.fact_kind != "segmented_memory"
            for marker in report.confidence_tracker.markers
        )
        assert any("segmented memory" in a for a in report.assumptions)

    def test_segment_entry_numeric_and_coherence_bounds(self) -> None:
        """Entries require finite confidence in [0,1], count >= 1, coherent bucket."""
        codegen = _staged_codegen("func_segment_bounds")
        codegen._inertia_segmented_memory_applied = True
        codegen._inertia_segmented_memory_summary = {
            "stable": {
                "DS": {
                    "space": "data",
                    "classification": "const",
                    "confidence": 0.9,
                    "evidence_count": 5,
                    "known_values": (0x1234,),
                },
                "CS": {
                    "space": "code",
                    "classification": "single",
                    "confidence": float("nan"),
                    "evidence_count": 3,
                    "known_values": (),
                },
            },
            "over_associated": {
                "ES": {
                    "space": "data",
                    "classification": "over_associated",
                    "confidence": True,  # bool is not a probability
                    "evidence_count": 2,
                    "known_values": (),
                },
            },
            "unknown": {
                "SS": {
                    "space": "stack",
                    "classification": "unknown",
                    "confidence": 0.2,
                    "evidence_count": 0,  # producer skips zero-count entries
                    "known_values": (),
                },
                "FS": {
                    "space": "unknown",
                    "classification": "single",  # incoherent: single -> stable bucket
                    "confidence": 0.9,
                    "evidence_count": 4,
                    "known_values": (),
                },
                "QQ": {
                    "space": "data",
                    "classification": "unknown",
                    "confidence": 0.2,
                    "evidence_count": 3,
                    "known_values": (),
                },
                "GS": {
                    "space": 123,  # non-str space
                    "classification": "unknown",
                    "confidence": 0.2,
                    "evidence_count": 3,
                    "known_values": (),
                },
            },
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert len(evidence.segments.items) == 1
        assert evidence.segments.items[0].segment == "DS"
        assert len(evidence.segments.malformed) == 6

    def test_refused_fact_in_lowerable_map_is_not_upgraded(self) -> None:
        """A refused bridge fact must not become an ordinary high-confidence marker."""
        codegen = _staged_codegen("func_refused_lowerable")
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_lowerable_arrays = {
            ("ds", "buf"): StorageObjectBridgeFact(
                base_key=("ds", "buf"),
                object_kind="array",
                candidate_offsets=(0, 2, 4, 6),
                primary_member_offset=0,
                segmented_memory=_refused_segmented_fact(),
            ),
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.arrays.items == ()
        assert len(evidence.arrays.refusals) == 1
        assert "unstable segment association" in evidence.arrays.refusals[0].reason
        assert "lowerable_arrays[('ds', 'buf')]" in evidence.arrays.malformed
        report = _report_for(codegen)
        tracker = report.confidence_tracker
        assert tracker.high_count() == 0
        assert tracker.medium_count() == 0
        refused = next(m for m in tracker.markers if "refused" in m.fact_detail)
        assert refused.confidence == ConfidenceLevel.LOW

    def test_wrong_object_kind_in_bridge_maps_is_malformed(self) -> None:
        """Producer maps carry fixed kinds; foreign kinds are stale metadata."""
        codegen = _staged_codegen("func_kind_mismatch")
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_lowerable_arrays = {
            ("ds", "member_in_array_map"): _member_fact(("ds", "member_in_array_map"), (0, 2)),
        }
        codegen._inertia_struct_merging_applied = True
        codegen._inertia_struct_merging_member_facts = {
            ("ds", "array_in_member_map"): _array_fact(("ds", "array_in_member_map"), (0, 2)),
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.arrays.items == ()
        assert evidence.structs.items == ()
        assert evidence.arrays.malformed
        assert evidence.structs.malformed

    def test_error_status_retained_payloads_emit_no_ordinary_markers(self) -> None:
        """Producer ERROR + retained payloads: named, no high-confidence markers."""
        codegen = _staged_codegen("func_error_retained")
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_error = "loop rewrite failed"
        codegen._inertia_array_matching_lowerable_arrays = {
            ("ds", "buf"): _array_fact(("ds", "buf"), (0, 2, 4, 6)),
        }
        codegen._inertia_array_matching_typed_ir_candidates = {
            ("ds", ("idx", "base"), 2): {
                "space": "ds",
                "base": ("idx", "base"),
                "element_size": 2,
                "has_phi_index": True,
            },
        }
        codegen._inertia_array_matching_refused_arrays = {
            ("es", "tab"): "over-associated segment",
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.arrays.status == EvidenceStatus.ERROR
        assert evidence.arrays.items == ()
        assert evidence.arrays.refusals == ()
        assert evidence.arrays.malformed  # retained payloads are named
        report = _report_for(codegen)
        tracker = report.confidence_tracker
        assert all(marker.fact_kind != "array" for marker in tracker.markers)
        assert any("loop rewrite failed" in a for a in report.assumptions)

    def test_absent_status_retained_payloads_emit_no_markers(self) -> None:
        """No applied flag + retained payloads: ABSENT, payloads named, no markers."""
        codegen = _staged_codegen("func_absent_retained")
        codegen._inertia_array_matching_typed_ir_candidates = {
            ("ds", ("idx", "base"), 2): {
                "space": "ds",
                "base": ("idx", "base"),
                "element_size": 2,
                "has_phi_index": True,
            },
        }
        codegen._inertia_segmented_memory_summary = {
            "stable": {
                "DS": {
                    "space": "data",
                    "classification": "const",
                    "confidence": 0.9,
                    "evidence_count": 5,
                    "known_values": (0x1234,),
                }
            }
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.arrays.status == EvidenceStatus.ABSENT
        assert evidence.arrays.items == ()
        assert evidence.segments.status == EvidenceStatus.ABSENT
        assert evidence.segments.items == ()
        assert evidence.arrays.malformed
        assert evidence.segments.malformed
        report = _report_for(codegen)
        assert report.confidence_tracker.total_count() == 0

    def test_error_status_retained_struct_and_segment_payloads(self) -> None:
        """The retained-payload rule applies to every producer channel."""
        codegen = _staged_codegen("func_error_all_channels")
        codegen._inertia_struct_merging_applied = True
        codegen._inertia_struct_merging_error = "bridge failed"
        codegen._inertia_struct_merging_member_facts = {
            ("ds", "obj"): _member_fact(("ds", "obj"), (0, 2, 4)),
        }
        codegen._inertia_segmented_memory_applied = True
        codegen._inertia_segmented_memory_error = "analysis failed"
        codegen._inertia_segmented_memory_summary = {
            "stable": {
                "DS": {
                    "space": "data",
                    "classification": "const",
                    "confidence": 0.9,
                    "evidence_count": 5,
                    "known_values": (),
                }
            }
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.structs.status == EvidenceStatus.ERROR
        assert evidence.structs.items == ()
        assert evidence.segments.status == EvidenceStatus.ERROR
        assert evidence.segments.items == ()
        report = _report_for(codegen)
        assert report.confidence_tracker.total_count() == 0
        assert any("bridge failed" in a for a in report.assumptions)
        assert any("analysis failed" in a for a in report.assumptions)

    def test_valid_producer_payloads_still_emit_markers(self) -> None:
        """Fully valid current-schema payloads keep producing real markers."""
        codegen = _staged_codegen("func_valid_all")
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_lowerable_arrays = {
            ("ds", "buf"): _array_fact(("ds", "buf"), (0, 2, 4, 6)),
        }
        codegen._inertia_array_matching_typed_ir_candidates = {
            ("ds", ("idx", "base"), 2): {
                "space": "ds",
                "base": ("idx", "base"),
                "element_size": 2,
                "has_phi_index": True,
            },
        }
        codegen._inertia_array_matching_string_candidates = {
            ("ds", ("si",), 1): {
                "space": "ds",
                "base": ("si",),
                "element_size": 1,
                "has_string_effect": True,
                "segment_origin": "proven",
                "string_family": "movs",
                "repeat_kind": "rep",
                "role": "source",
            },
        }
        codegen._inertia_segmented_memory_applied = True
        codegen._inertia_segmented_memory_summary = {
            "stable": {
                "DS": {
                    "space": "data",
                    "classification": "const",
                    "confidence": 0.9,
                    "evidence_count": 5,
                    "known_values": (0x1234,),
                }
            },
            "over_associated": {},
            "unknown": {},
        }
        evidence = load_confidence_evidence(codegen, codegen.cfunc)
        assert evidence.arrays.items  # all three valid array candidates projected
        assert len(evidence.arrays.items) == 3
        assert len(evidence.segments.items) == 1
        report = _report_for(codegen)
        tracker = report.confidence_tracker
        assert tracker.high_count() >= 1  # 4-offset array fact + const DS stability
        assert tracker.low_count() == 0


@pytest.mark.parametrize('role', [[], {}, ['source']])
def test_unhashable_string_role_is_malformed(role: object) -> None:
    """Malformed plugin fields produce diagnostics rather than crashing reporting."""
    payload = {
        'space': 'ds', 'base': ('si',), 'element_size': 1,
        'has_string_effect': True, 'segment_origin': 'proven',
        'string_family': 'movs', 'repeat_kind': 'rep', 'role': role,
    }
    codegen = types.SimpleNamespace(
        _inertia_array_matching_applied=True,
        _inertia_array_matching_string_candidates={('ds', ('si',), 1): payload},
    )
    channel = load_confidence_evidence(codegen, None).arrays
    assert not channel.items
    assert len(channel.malformed) == 1
