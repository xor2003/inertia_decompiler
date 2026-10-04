"""Parent native acceptance of the scoped import transport API.

Layer: tests.
Responsibility: compare saved-before universal/census products and authenticate
the new explicit view against actual MZ bytes, independently supplied entries
and retained original source identities.
"""
from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import test_x86_16_scoped_native_inputs as native
from angr_platforms.X86_16.ir import real16_invocation_domain as domain
from angr_platforms.X86_16.ir import vex_import as importer
from test_x86_16_scoped_native_inputs import _view, world  # noqa: F401


def test_native_raw_products_receipt(world: tuple) -> None:  # noqa: F811
    """Retain complete original-format products for cross-process parity."""
    _boot, project, _sb, stub, _index, boundary, artifact = world
    census = domain.real16_native_census_import_8616(project, boundary)
    assert census is not None
    assert any(block.refusals for block in artifact.blocks)
    receipt = {'stub': stub.to_dict(), 'caller': artifact.to_dict(), 'census': census.to_dict()}
    destination = os.environ.get('IMPORT_RECEIPT')
    if destination:
        Path(destination).write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')


def test_native_explicit_scoped_import_keeps_source_identity(world: tuple) -> None:  # noqa: F811
    """Build the view through the public staged API, using an independent entry."""
    old_view, scope, artifact = _view(world)
    project = old_view.boundary.project
    boundary = old_view.boundary
    bundle = importer.raw_x86_16_import_bundle_for_artifact_8616(project, boundary, artifact)
    assert bundle is not None
    assert bundle.artifact is artifact
    records = native._records(project, artifact, boundary)
    view = importer.prove_scoped_x86_16_ir_function_view_8616(
        project, bundle, boundary, invocation_scope=scope, call_preservations=records,
    )
    assert view.source_artifact is artifact
    assert not view.complete
    assert view.complete_for(scope), view.to_dict()
    assert not view.complete_for(replace(scope, boot=object()))
    missing = importer.prove_scoped_x86_16_ir_function_view_8616(
        project, bundle, boundary, invocation_scope=None, call_preservations=records,
    )
    assert not missing.complete_for(scope)
    assert any(block.refusals for block in artifact.blocks)
