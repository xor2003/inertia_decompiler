"""Layer: IR tests.

Responsibility: require the frozen bitfield main's complete entry preparation
under the production request limits. This prerequisite does not establish the
later generated-C, same-toolchain rebuild or whole-program round trip.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from inertia.cli.real16_declared_project import build_declared_project_8616
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.ir.declared_entry_pipeline import (
    _declared_source_8616,
    _function_entry_for_head_8616,
    _prepare_native_entry_8616,
)
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import declared_entry_dependency_traversal_scope_8616
from tools.dosunit.catalog.real16_declared_input import read_declared_real16_input_8616

_ROOT = Path(__file__).resolve().parents[2]
_BINARY = _ROOT / ".cache/bitfield-route/original-dosbox/BITNBR.EXE"
_DECLARED = _ROOT / ".cache/bitfield-route/main-declared-input.json"
_HEAD = 0x1D43

pytestmark = [
    pytest.mark.decompiler,
    pytest.mark.skipif(
        not (_BINARY.is_file() and _DECLARED.is_file()),
        reason="frozen bitfield main corpus not staged",
    ),
]


def test_frozen_bitfield_main_preparation_closes_in_production_budget() -> None:
    """All main CALLs and full invocation must close in one unchanged request."""
    apply_x86_16_bootstrap()
    declaration = read_declared_real16_input_8616(_DECLARED, _BINARY.read_bytes())
    project = build_declared_project_8616(
        _BINARY, _DECLARED, force_blob=False,
        base_addr=declaration.boot.image.load_segment,
        entry_point=declaration.boot.entry.linear(),
    )
    deadline = time.monotonic() + 25.0
    # Production runs this operation under declared_entry_dependency_traversal_scope_8616
    # (128k census units / 25k selector-batch units); the generic 20k scope is not the
    # production budget for declared-entry preparation.
    with native_import_request_8616(), declared_entry_dependency_traversal_scope_8616() as ledger:
        ledger.census_deadline = deadline
        with direct_evidence_deadline_scope_8616(project, deadline):
            source = _declared_source_8616(project, _HEAD)
            assert source is not None
            admission = _function_entry_for_head_8616(source, _HEAD)
            assert admission is not None
            prepared = _prepare_native_entry_8616(project, source, admission)
            assert prepared.source is source
            assert prepared.admission is admission
            assert prepared.view.failure is None
        assert ledger.census_work_units <= ledger.census_work_limit
