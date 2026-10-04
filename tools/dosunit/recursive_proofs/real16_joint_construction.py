"""Layer: dosunit binary-derived joint recursive proposal construction.

Responsibility: consume two sealed lowered full-state documents and a requested
root, require complete matching reachable call graphs with exactly one closed
direct near16 recursive component, and retain every paired atomic transition as
actual composed block effects with binary-derived dispatch. Catalog, mapping
and graph metadata propose correspondence only: differing layouts, external
dependencies, missing targets and non-near16 frames stay typed refusals, and no
constructed ``JointSystem`` grants equality or proof status. An optional
caller-declared ``Real16EnvironmentScope`` is bound into the proposal; it is a
premise, never a byte-proved fact.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from tools.dosunit import straightline_ssa as S
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import Architecture, ContractIdentity
from tools.dosunit.real16_call_contracts import FunctionCtx, initial_state
from tools.dosunit.real16_call_evidence import block_source, group_functions
from tools.dosunit.real16_call_frames import CallFrameKind
from tools.dosunit.real16_call_graph_admission import (
    AdmissionLimits,
    AdmissionReport,
    AdmissionVerdict,
    CallSiteRecord,
    admit_call_graph,
)
from tools.dosunit.recursive_proofs.recursive_call_components import CallComponent, FunctionId
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointNodeId,
    JointReason,
    JointStepKind,
    JointStepPair,
    JointSystem,
    Real16EnvironmentScope,
)


def build_real16_joint_system(
    original: dict[str, Any],
    candidate: dict[str, Any],
    root: str,
    *,
    timeout_ms: int = 20000,
    environment_scope: Real16EnvironmentScope | None = None,
) -> JointSystem:
    """Build a same-coordinate joint proposal for one closed near16 component.

    Full reachable graph admission and actual frame decoding are required on
    both sides. Differing layouts, external components and operand32/mixed
    frames remain explicit refusals of this first relation. Physical model
    closure is deliberately left for the joint checker, never inferred here.
    ``environment_scope`` is a caller-declared typed premise content-bound to
    both executable identities; it becomes part of the proposal identity and
    keeps the environment obligation visibly conditional downstream.
    """
    if environment_scope is not None and not isinstance(environment_scope, Real16EnvironmentScope):
        raise ValueError("joint environment scope must be a typed declared premise")
    deadline = time.monotonic() + max(timeout_ms, 0) / 1000
    reports = []
    for document in (original, candidate):
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise JointRefusal(JointReason.DEADLINE, "joint construction deadline exceeded")
        reports.append(admit_call_graph(document, root, limits=AdmissionLimits(deadline_ms=remaining)))
    component = _admitted_component(reports)
    left = reports[0]
    if left.root is None:
        raise ValueError("admitted root must retain its function identity")
    groups = (group_functions(original), group_functions(candidate))
    sites = [{JointNodeId(site.caller, site.delta): site for site in report.sites} for report in reports]
    steps = []
    ranges = []
    for member in component.members:
        a, b = (group[member.value] for group in groups)
        if a.entry_linear != b.entry_linear or a.body_size != b.body_size or set(a.blocks) != set(b.blocks):
            raise JointRefusal(JointReason.LAYOUT, "native block layout differs; identity relation cannot apply")
        ranges.append((a.entry_linear, a.entry_linear + a.body_size))
        for delta in sorted(a.blocks):
            steps.append(_pair_step(member, a, b, delta, sites, deadline))
    semantic_hash = hashlib.sha256(canonical_json_bytes([original, candidate])).hexdigest()
    contract = ContractIdentity(Architecture.REAL16, _image_hash(original), _image_hash(candidate),
                                semantic_hash, hashlib.sha256(b"real16-native-ssa-joint-v1").hexdigest(),
                                hashlib.sha256(b"strict-full-state-near16-v1").hexdigest())
    expected = tuple(JointNodeId(member, delta) for member in component.members
                     for delta in sorted(groups[0][member.value].blocks))
    return JointSystem(contract, JointNodeId(left.root, 0), component.members, tuple(steps),
                       tuple(sorted(initial_state())), expected_nodes=expected,
                       initial_state=initial_state(), component_ranges=tuple(ranges),
                       environment_scope=environment_scope)


def _admitted_component(reports: list[AdmissionReport]) -> CallComponent:
    """Require complete matching graphs with one closed recursive component."""
    left, right = reports
    if left.verdict is not AdmissionVerdict.ADMITTED or right.verdict is not AdmissionVerdict.ADMITTED:
        raise JointRefusal(JointReason.ADMISSION, "both reachable graphs must be complete")
    if left.root is None or left.graph is None or left.analysis is None:
        raise JointRefusal(JointReason.ADMISSION, "complete original graph evidence missing")
    if right.root is None or right.graph is None or right.analysis is None:
        raise JointRefusal(JointReason.ADMISSION, "complete candidate graph evidence missing")
    if left.root != right.root or left.graph != right.graph:
        raise JointRefusal(JointReason.ADMISSION, "both complete reachable call graphs must match")
    component_key = left.analysis.component_key_of(left.root)
    component = next(item for item in left.analysis.components if item.key == component_key)
    if not component.recursive:
        raise JointRefusal(JointReason.COMPONENT, "joint recursive proposal requires a recursive component")
    if set(component.members) != set(left.graph.vertices):
        raise JointRefusal(JointReason.EXTERNAL, "external component dependencies are not yet jointly discharged")
    for report in reports:
        if any(site.frame is not CallFrameKind.NEAR16 for site in report.sites):
            raise JointRefusal(JointReason.LAYOUT, "operand32 or mixed frames require a separate relation")
    return component


def _pair_step(member: FunctionId, a: FunctionCtx, b: FunctionCtx, delta: int,
               sites: list[dict[JointNodeId, CallSiteRecord]], deadline: float) -> JointStepPair:
    """Retain both actual block effects and exact binary-derived dispatch."""
    node = JointNodeId(member, delta)
    states = [_effect(ctx, delta, deadline) for ctx in (a, b)]
    jumpkind = block_source(a.blocks[delta]).get("jumpkind")
    if block_source(b.blocks[delta]).get("jumpkind") != jumpkind:
        raise JointRefusal(JointReason.DISPATCH, "paired atomic transition kinds differ")
    successors: tuple[JointNodeId, ...] = ()
    callee, continuation = None, None
    if jumpkind == "Ijk_Call":
        if len(sites) != 2 or any(node not in table for table in sites):
            raise JointRefusal(JointReason.MANIFEST, f"CALL lacks admitted site evidence: {node.key()}")
        ls, rs = (table[node] for table in sites)
        if (ls.callee != rs.callee or ls.fall_delta != rs.fall_delta
                or ls.callee is None or ls.fall_delta is None):
            raise JointRefusal(JointReason.DISPATCH, "CALL target/continuation mismatch")
        kind = JointStepKind.CALL
        callee, continuation = JointNodeId(ls.callee, 0), JointNodeId(member, ls.fall_delta)
        successors = (callee,)
    elif jumpkind == "Ijk_Ret":
        kind = JointStepKind.RETURN
    elif jumpkind == "Ijk_Boring":
        kind = JointStepKind.BRANCH
        declared = S._direct_successor_delta_set(a.blocks[delta])
        if declared != S._direct_successor_delta_set(b.blocks[delta]):
            raise JointRefusal(JointReason.DISPATCH, "branch successor sets differ")
        successors = tuple(JointNodeId(member, target) for target in sorted(declared))
    else:
        raise JointRefusal(JointReason.DISPATCH, "atomic transition has unsupported control kind")
    return JointStepPair(node, a.entry_linear + delta, b.entry_linear + delta,
                         a.body_sha256, b.body_sha256, kind, states[0], states[1],
                         successors, callee, continuation)


def _effect(ctx: FunctionCtx, delta: int, deadline: float) -> dict[str, dict[str, Any]]:
    """Compose actual block outputs from a fresh cutpoint without callee state."""
    block = ctx.blocks[delta]
    state: dict[str, dict[str, Any]] = S._compose_block_outputs(
        block, block["outputs"], initial_state(), compose_stats={"deadline": deadline})
    return state


def _image_hash(document: dict[str, Any]) -> str:
    """Bind the proposal to actual complete executable file bytes."""
    path = document.get("exe")
    if not isinstance(path, str):
        raise JointRefusal(JointReason.ADMISSION, "executable file identity missing")
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
