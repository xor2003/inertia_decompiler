"""Layer: dosunit recursive proposal content identity (staging).

Responsibility: seal all admitted joint effects and dispatch metadata so mutable
term dictionaries cannot transfer a completed prerequisite to a new proposal.
Callers must admit and bound terms before serialization; a digest grants no proof.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointSystem
from tools.dosunit.register_state_relations import MachineState


def joint_proposal_hash(system: JointSystem, bootstrap: tuple[MachineState, MachineState]) -> str:
    """Bind every owned proposal field, including complete native term trees.

    Node names distinguish manifest entries only. They provide no executable
    correspondence or semantic evidence; the independent decoder owns that.
    Serialization follows bounded admission at both production and consumption.
    """
    document = {
        "version": "complete-joint-proposal-v1",
        "contract": system.contract.to_document(),
        "root": system.root.key(),
        "members": [member.value for member in system.members],
        "required_outputs": system.required_outputs,
        "external_dependencies": [member.value for member in system.external_dependencies],
        "expected_nodes": [node.key() for node in system.expected_nodes],
        "initial_state": system.initial_state,
        "control_field": system.control_field,
        "component_ranges": system.component_ranges,
        "environment_scope": ({"members": [member.value for member in system.environment_scope.members],
                               "original_hash": system.environment_scope.original_hash,
                               "candidate_hash": system.environment_scope.candidate_hash,
                               "provenance": system.environment_scope.provenance}
                              if system.environment_scope is not None else None),
        "bootstrap": bootstrap,
        "steps": [{"node": step.node.key(), "original_address": step.original_address,
                   "candidate_address": step.candidate_address, "original_hash": step.original_hash,
                   "candidate_hash": step.candidate_hash, "kind": step.kind.value,
                   "original": step.original, "candidate": step.candidate,
                   "successors": [node.key() for node in step.successors],
                   "callee": step.callee.key() if step.callee is not None else None,
                   "continuation": step.continuation.key() if step.continuation is not None else None,
                   "original_control": (step.original_control.to_document()
                                        if step.original_control is not None else None),
                   "candidate_control": (step.candidate_control.to_document()
                                         if step.candidate_control is not None else None)}
                  for step in system.steps],
    }
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def control_view_model_hash() -> str:
    """Seal the real16 control-boundary, declared-target and resolver owners.

    A proved control view produced under one revision of the proof or
    resolver owners must not be consumed after those owners change; binding
    the owner sources keeps stale projections a typed refusal.
    """
    parent = Path(__file__).resolve().parent.parent
    paths = (parent / "real16_control_boundary.py", parent / "real16_control_targets.py",
             parent / "straightline_ssa.py", Path(__file__).with_name("recursive_static_control.py"))
    values = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()
