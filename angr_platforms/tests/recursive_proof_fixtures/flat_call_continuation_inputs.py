"""Layer: test support for both native flat32 driver seams.

Responsibility: propose a single self-recursive component from actual lifted
i386 blocks; production admission and native proofs validate the proposal.
This fixture supplies no executable-loader or whole-binary theorem.
"""
from __future__ import annotations

import hashlib
import time

import angr

from tools.dosunit import straightline_ssa as S
from tools.dosunit.flat32_call_contracts import (
    CallCompositionLimits,
    _ComposeSession,
    _initial_state,
    _LiftedBlock,
    _register_widths,
)
from tools.dosunit.flat32_call_lowering import _lift_block
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import Architecture, ContractIdentity
from tools.dosunit.recursive_proofs.recursive_call_components import FunctionId
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointNodeId,
    JointStepKind,
    JointStepPair,
    JointSystem,
)
from tools.dosunit.register_state_relations import MachineState

FLAT_BASE: int = 0x100000
TWO_FLAT_CALLS: bytes = bytes.fromhex("e3114985c07407e8f4ffffffeb05e8edffffffc3")


def _rows(session: _ComposeSession, size: int) -> dict[int, tuple[_LiftedBlock, MachineState, JointStepKind]]:
    """Walk decoded successor/fallthrough heads under a single bounded budget."""
    deadline = time.monotonic() + 20
    pending = {FLAT_BASE}
    rows = {}
    kinds = {"Ijk_Boring": JointStepKind.BRANCH, "Ijk_Call": JointStepKind.CALL, "Ijk_Ret": JointStepKind.RETURN}
    while pending:
        assert time.monotonic() < deadline
        address = min(pending)
        pending.remove(address)
        if address in rows:
            continue
        assert FLAT_BASE <= address < FLAT_BASE + size
        block = _lift_block(session, FLAT_BASE, address, FLAT_BASE + size)
        kind = kinds[block.irsb.jumpkind]
        state = S._compose_block_outputs(block.part, block.part["outputs"], _initial_state(session.reg_widths),
                                          compose_stats={"deadline": deadline})
        rows[address] = (block, state, kind)
        if kind is JointStepKind.CALL:
            assert block.call_target == FLAT_BASE and block.fallthrough is not None
            pending.add(block.fallthrough)
        elif kind is JointStepKind.BRANCH:
            pending.update(block.successors)
    return rows


def make_flat_two_call_system() -> JointSystem:
    """Retain full native states from the currently installed MSC8/BC5 adapter."""
    code = TWO_FLAT_CALLS
    projects = tuple(angr.load_shellcode(code, arch="x86", load_address=FLAT_BASE) for _ in range(2))
    sessions = tuple(_ComposeSession(project, {FLAT_BASE: len(code)}, {}, CallCompositionLimits(), _register_widths())
                     for project in projects)
    native = tuple(_rows(session, len(code)) for session in sessions)
    assert set(native[0]) == set(native[1])
    member = FunctionId("native-flat-fixture")
    root = JointNodeId(member, 0)
    steps = []
    image_hash = hashlib.sha256(code).hexdigest()
    for address in sorted(native[0]):
        left, original, kind = native[0][address]
        right, candidate, candidate_kind = native[1][address]
        assert candidate_kind is kind and left.successors == right.successors
        callee, continuation = None, None
        if kind is JointStepKind.CALL:
            assert left.fallthrough is not None and right.fallthrough == left.fallthrough
            callee = root
            continuation = JointNodeId(member, left.fallthrough - FLAT_BASE)
            successors = (callee,)
        else:
            successors = tuple(JointNodeId(member, target - FLAT_BASE) for target in sorted(set(left.successors)))
        steps.append(JointStepPair(JointNodeId(member, address - FLAT_BASE), address, address, image_hash,
            image_hash, kind, original, candidate, successors, callee, continuation))
    initial = _initial_state(sessions[0].reg_widths)
    initial["ip"] = {"op": "input", "name": "ip", "width": 32}
    semantic_hash = hashlib.sha256(canonical_json_bytes(tuple((step.original, step.candidate) for step in steps))).hexdigest()
    contract = ContractIdentity(Architecture.FLAT32, image_hash, image_hash, semantic_hash,
        hashlib.sha256(b"native-flat32-fixture-model").hexdigest(), hashlib.sha256(b"strict-near32-frame").hexdigest())
    return JointSystem(contract, root, (member,), tuple(steps), tuple(sorted(initial)),
        expected_nodes=tuple(step.node for step in steps), initial_state=initial,
        control_field="ip", component_ranges=((FLAT_BASE, FLAT_BASE + len(code)),))
