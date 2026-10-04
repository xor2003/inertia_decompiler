"""Layer: test support for binary-derived per-call return bindings.

Responsibility: construct two reachable recursive CALL sites from actual MZ
bytes and deliberately swap their metadata without changing any native effect.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from recursive_proof_fixtures.entry_domain_inputs import _document
from recursive_proof_fixtures.image_bound_inputs import Inputs, _proposal
from recursive_proof_fixtures.real16_joint_system import build_real16_joint_system
from tools.dosunit import straightline_ssa as S
from tools.dosunit.real16_call_contracts import initial_state
from tools.dosunit.real16_call_evidence import group_functions
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import bind_real16_mz
from tools.dosunit.recursive_proofs.loaded_byte_relation import propose_loaded_byte_relation
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import prove_loaded_byte_relation
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointStepKind, JointSystem

TWO_CALL_CODE: bytes = bytes.fromhex("e30d4985c07405e8f6ffeb03e8f1ffc3")


def make_two_call_inputs(tmp_path: Path) -> Inputs:
    """Derive every state and request from two independently loaded MZ files.

    JCXZ exits at zero. Otherwise CX decreases and AX chooses between two
    recursive calls, whose saved fallthroughs are distinct admitted heads.
    Both paths are statically reachable; swapping the two continuation labels
    leaves the global continuation set and reachable manifest unchanged.
    """
    documents = tuple(_document(tmp_path, TWO_CALL_CODE, tag) for tag in ("left", "right"))
    system = build_real16_joint_system(*documents, "recursive")
    loads = tuple(bind_real16_mz(Path(document["exe"]).read_bytes(), load_segment=0x100)
                  for document in documents)
    initialized = prove_loaded_byte_relation(propose_loaded_byte_relation(*(load.binding.snapshot for load in loads)))
    groups = tuple(group_functions(document) for document in documents)
    bootstrap = tuple(S._compose_block_outputs(group["bootstrap"].blocks[0],
        group["bootstrap"].blocks[0]["outputs"], initial_state()) for group in groups)
    requests = []
    for side in range(2):
        rows = tuple(_proposal(loads[side], step.original_address if side == 0 else step.candidate_address,
                               step.original if side == 0 else step.candidate) for step in system.steps)
        requests.append((*rows, _proposal(loads[side], loads[side].binding.entry, bootstrap[side])))
    return Inputs(system, (loads[0], loads[1]), initialized, (bootstrap[0], bootstrap[1]),
                  (requests[0], requests[1]))


def swap_declared_continuations(system: JointSystem) -> JointSystem:
    """Corrupt only per-call metadata while retaining its admitted global set."""
    calls = tuple(step for step in system.steps if step.kind is JointStepKind.CALL)
    assert len(calls) == 2 and calls[0].continuation != calls[1].continuation
    replacements = {calls[0].node: calls[1].continuation, calls[1].node: calls[0].continuation}
    steps = tuple(replace(step, continuation=replacements[step.node]) if step.node in replacements
                  else step for step in system.steps)
    return replace(system, steps=steps)
