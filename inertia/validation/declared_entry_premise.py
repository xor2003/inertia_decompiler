"""Layer: Validation.

Responsibility: transport a checked conditional entry without replaying during reporting.
The serialized receipt is diagnostic evidence, never authority to mint an IR scope.
Dynamic boundary: reads third-party angr/codegen attachments through getattr.
Owns canonical equivalence checking and validation diagnostics
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import IRFunctionArtifact
from inertia.ir.near_call_jump_scope import NearCallJumpScope8616
from inertia.ir.real16_invocation_domain import DeclaredFunctionEntryLink8616, Real16InvocationKind8616
from inertia.ir.scoped_function_ir_view import ScopedFunctionIRView8616
from inertia.ir.segment_state import SegmentStateArtifact
from inertia.ir.source_graph_binding import canonical_source_graph_8616
from inertia.ir.ssa_function import SSAFunctionArtifact


class EntryPremiseStatus8616(StrEnum):
    """Whether a collected scope supplies a checked conditional premise."""

    CONDITIONAL = 'conditional'
    REFUSED = 'refused'


class EntryPremiseAuthority8616(StrEnum):
    """Distinct authority retained by a conditional native-entry receipt."""

    NATIVE_NEAR_CALL = 'native_near_call'


@dataclass(frozen=True, slots=True)
class EntryPremiseReceipt8616:
    """Immutable canonical projection of one freshly authenticated scope."""

    status: EntryPremiseStatus8616
    payload_json: str
    digest: str

    def to_dict(self) -> dict[str, object]:
        """Serialize detached data; this operation performs no proof replay."""
        return {'status': self.status.value, 'payload': json.loads(self.payload_json), 'sha256': self.digest}


def _receipt(status: EntryPremiseStatus8616, payload: dict[str, object]) -> EntryPremiseReceipt8616:
    """Freeze deterministic projection bytes for comparison and cache identity."""
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return EntryPremiseReceipt8616(status, encoded, hashlib.sha256(encoded.encode()).hexdigest())


def _codegen_source_bound_8616(project: object, codegen: object, state: SegmentStateArtifact) -> bool:
    """Bind native IR or its authenticated, private call-Semantics projection."""
    from inertia.semantics.call_stack_effect_pipeline import CallSemanticProjection8616

    # Current codegen attachments are the third-party boundary; owned contracts
    # below are inspected directly, never reconstructed from diagnostic JSON.
    current = getattr(codegen, '_inertia_vex_ir_artifact', None)
    projection = getattr(codegen, '_inertia_call_semantic_projection_8616', None)
    if current is state.source_artifact and projection is None:
        return True
    if not isinstance(projection, CallSemanticProjection8616) or projection.scoped_input is None:
        return False
    current_ssa = getattr(codegen, '_inertia_vex_ir_function_ssa', None)
    context = projection.scoped_input
    return bool(
        isinstance(current, IRFunctionArtifact) and isinstance(current_ssa, SSAFunctionArtifact)
        and projection.source_ir is state.source_artifact
        and context.project is project
        and context.scope is (state.near_call_scope or state.invocation_scope)
        and context.view is state.scoped_view
        and projection.matches_codegen(current, current_ssa) and projection.complete
    )


def collect_entry_premise_8616(project: object, codegen: object) -> EntryPremiseReceipt8616 | None:
    """Authenticate attached scoped state once; never discover ambient declarations."""
    # Codegen is the dynamic third-party AST boundary.
    state = getattr(codegen, '_inertia_segment_state_artifact', None)
    refused = _receipt(EntryPremiseStatus8616.REFUSED, {'reason': 'entry_scope_unbound'})
    if state is None:
        return None
    if not isinstance(state, SegmentStateArtifact):
        return refused
    if state.near_call_scope is not None:
        return _collect_near_call_premise_8616(project, codegen, state)
    scope = state.invocation_scope
    view = state.scoped_view
    if scope is None and view is None:
        return refused if state.summary.get('scoped_view_bound') else None
    if scope is None or not isinstance(view, ScopedFunctionIRView8616):
        return refused
    if scope.kind is not Real16InvocationKind8616.DECLARED_FUNCTION_ENTRY:
        # Other scoped authorities are not silently converted to unconditional evidence.
        return refused
    link = scope.chain
    if not isinstance(link, DeclaredFunctionEntryLink8616):
        return refused
    # Read the third-party codegen attachment at this dynamic boundary.
    if (scope.project is not project or state.source_artifact is not link.artifact
            or not _codegen_source_bound_8616(project, codegen, state)
            or view.source_artifact is not link.artifact or not view.complete_for(scope)):
        return refused
    payload: dict[str, object] = {
        'declaration': link.admission.to_dict(),
        'domain': {
            'kind': scope.kind.value, 'source_sha256': scope.source_sha256,
            'callsite_addr': scope.callsite_addr,
            'entry_segment': scope.entry_segment, 'entry_offset': scope.entry_offset,
            'stack_segment': scope.stack_segment, 'stack_offset': scope.stack_offset,
            'minimum_selector': scope.minimum_selector, 'maximum_selector': scope.maximum_selector,
            'path_block_addrs': list(scope.path_block_addrs),
            'assumptions': [item.value for item in scope.assumptions],
        },
        'boundary': {'start': link.boundary.addr, 'size': link.boundary.size},
    }
    return _receipt(EntryPremiseStatus8616.CONDITIONAL, payload)


def _collect_near_call_premise_8616(
    project: object, codegen: object, state: SegmentStateArtifact,
) -> EntryPremiseReceipt8616:
    """Retain a native incoming-edge premise without claiming caller discharge.

    Raw input or a replayed private call-Semantics projection must retain
    the identical native source, scoped view and incoming-edge premise.
    """
    refused = _receipt(EntryPremiseStatus8616.REFUSED, {'reason': 'near_call_scope_unbound'})
    scope = state.near_call_scope
    view = state.scoped_view
    if (
        type(scope) is not NearCallJumpScope8616
        or state.invocation_scope is not None
        or type(view) is not ScopedFunctionIRView8616
        or scope.project is not project
        or state.source_artifact is not scope.artifact
    ):
        return refused
    if (
        view.source_artifact is not scope.artifact
        or view.near_call_scope is not scope
        or not _codegen_source_bound_8616(project, codegen, state)
        or not view.complete_for(scope)
    ):
        return refused
    artifact = scope.artifact
    if not isinstance(artifact, IRFunctionArtifact):
        return refused
    source = canonical_source_graph_8616(artifact.function_addr, artifact.blocks)
    return _receipt(EntryPremiseStatus8616.CONDITIONAL, {
        'authority': EntryPremiseAuthority8616.NATIVE_NEAR_CALL.value,
        'near_call': scope.context.to_dict(),
        'call_encoding': scope.context.call_encoding.hex(),
        'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'boundary': {'start': view.boundary.addr, 'size': view.boundary.size},
    })


def valid_entry_premise_projection_8616(value: object) -> bool:
    """Detect damaged diagnostic receipts without treating JSON as proof authority."""
    if not isinstance(value, dict) or value.get('status') != EntryPremiseStatus8616.CONDITIONAL:
        return False
    payload = value.get('payload')
    if not isinstance(payload, dict):
        return False
    if payload.get('authority') == EntryPremiseAuthority8616.NATIVE_NEAR_CALL:
        if not isinstance(payload.get('near_call'), dict):
            return False
    elif not isinstance(payload.get('declaration'), dict):
        return False
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return value.get('sha256') == hashlib.sha256(encoded.encode()).hexdigest()


def entry_premise_cache_identity_8616(codegen: object) -> dict[str, object] | None:
    """Project retained bindings cheaply; cache identity never authenticates them."""
    # Third-party codegen attachment boundary, not an owned contract.
    state = getattr(codegen, '_inertia_segment_state_artifact', None)
    if not isinstance(state, SegmentStateArtifact):
        return None
    if state.near_call_scope is not None:
        view = state.scoped_view
        return {
            'authority': EntryPremiseAuthority8616.NATIVE_NEAR_CALL.value,
            'scope': state.near_call_scope.to_dict(),
            'source_addr': state.source_artifact.function_addr if state.source_artifact else None,
            'view_bound': state.scoped_view is not None,
            'view_scope_bound': (
                isinstance(view, ScopedFunctionIRView8616)
                and view.near_call_scope is state.near_call_scope
            ),
            'source_bound': state.source_artifact is state.near_call_scope.artifact,
            'mixed_scope': state.invocation_scope is not None,
        }
    scope = state.invocation_scope
    view = state.scoped_view
    if scope is None and view is None:
        return None
    result: dict[str, object] = {
        'source_addr': state.source_artifact.function_addr if state.source_artifact else None,
        'view_bound': view is not None,
    }
    if scope is None:
        result['missing_scope'] = True
        return result
    result['domain'] = {
        'kind': scope.kind.value, 'source': scope.source_sha256,
        'entry': [scope.entry_segment, scope.entry_offset],
        'stack': [scope.stack_segment, scope.stack_offset],
        'callsite': scope.callsite_addr, 'range': [scope.minimum_selector, scope.maximum_selector],
        'failure': scope.failure.value if scope.failure else None,
        'path': list(scope.path_block_addrs),
    }
    if isinstance(scope.chain, DeclaredFunctionEntryLink8616):
        result['declaration'] = scope.chain.admission.to_dict()
    return result
