"""Layer: dosunit independently bound code-prefix preservation (staging).

Responsibility: scope each complete fetched span and check every raw native
store prefix against its fetched byte manifest under consumed entry-domain
evidence. Retain reads for subsequent fault/address proofs; this theorem grants
no control correspondence, recursive or binary equivalence.
"""
from __future__ import annotations

import hashlib
import io
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import angr
import pyvex
import z3

from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import initial_state, materialize_function
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load, ImageBindingRefusal
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.real16_code_byte_oracle import (
    CodeByteProjectionProof,
    prove_physical_byte_projection,
)
from tools.dosunit.recursive_proofs.real16_entry_domain import Real16ScalarDomain
from tools.dosunit.recursive_proofs.real16_fetch_scope import (
    FetchScopeReason,
    Real16FetchScope,
    check_real16_fetch_scope,
    fetch_scope_model_hash,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainReason,
    ImageBoundReal16Domain,
    image_bound_domain_model_hash,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import (
    BoundDomainConsumption,
    consume_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_loader_arch import real16_loader_arch
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBlockRequest,
    _BindingRun,
    _block_bytes,
    _NativeRefusal,
)
from tools.dosunit.recursive_proofs.real16_native_memory_access import (
    NativeAccessKind,
    NativeAccessLimits,
    NativeAccessReport,
    collect_native_memory_accesses,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointSystem
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import _state_exprs
from tools.dosunit.register_state_relations import MachineState


class CodePrefixReason(StrEnum):
    """Typed closure or the exact boundary retaining an unproved obligation."""

    PRESERVED = "bound_native_code_prefixes_preserved"
    RECEIPT = "code_prefix_prerequisites_refused"
    SOURCE = "code_prefix_independent_decode_refused"
    ACCESS = "code_prefix_raw_access_ledger_incomplete"
    FETCH = "code_prefix_fetch_geometry_unproved"
    COUNTERMODEL = "code_prefix_physical_byte_countermodel"
    UNKNOWN = "code_prefix_solver_unknown"
    MODEL = "code_prefix_model_changed"
    DEADLINE = "code_prefix_original_deadline_exhausted"
    RESOURCE = "code_prefix_work_budget_exhausted"


@dataclass(frozen=True, slots=True)
class CodePrefixBlock:
    """Exact byte provenance, all raw accesses and every store-prefix result."""

    side: int
    address: int
    size: int
    byte_hash: str
    accesses: NativeAccessReport
    projections: tuple[CodeByteProjectionProof, ...]
    fetch_scope: Real16FetchScope
    protected_ranges: tuple[tuple[int, int], ...] = ()

    @property
    def complete(self) -> bool:
        """Require all prefixes, including an identity witness for a read-only block."""
        count = max(1, sum(row.kind is NativeAccessKind.WRITE for row in self.accesses.facts))
        scoped = (self.fetch_scope.complete and self.fetch_scope.address == self.address
                  and self.fetch_scope.size == self.size)
        return (self.accesses.complete and scoped and bool(self.protected_ranges) and len(self.projections) == count
                and all(row.status is ProofStatus.PROVED and row.counters.failure_count == 0
                        for row in self.projections))


@dataclass(frozen=True, slots=True)
class Real16CodePrefixProof:
    """Source/domain-bound local code stability, with physical outcomes still open."""

    status: ProofStatus
    reason: CodePrefixReason
    model_hash: str
    blocks: tuple[CodePrefixBlock, ...]
    consumers: tuple[BoundDomainConsumption, ...]
    counters: FactCounters
    detail: str = ""
    proposal_hash: str = ""
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]] | None = None
    receipt: ImageBoundReal16Domain | None = None

    @property
    def binary_equivalence_proved(self) -> bool:
        """Code stability does not discharge addresses, faults, events or observers."""
        return False


def code_prefix_model_hash() -> str:
    """Seal the raw collector, algebra, binder and all consumed domain owners."""
    digest = hashlib.sha256(image_bound_domain_model_hash().encode("ascii"))
    digest.update(fetch_scope_model_hash().encode("ascii"))
    stage = Path(__file__).parent
    for name in (Path(__file__).name, "real16_native_memory_access.py", "real16_code_byte_oracle.py",
                 "real16_loader_arch.py"):
        digest.update(name.encode("ascii"))
        digest.update((stage / name).read_bytes())
    return digest.hexdigest()


def _memory_document(memory: S.SsaExpr) -> dict[str, Any]:
    """Materialize a raw prefix using the authoritative SSA versioning owner."""
    state = S._IrsbLowerState(S._initial_reg_versions(), memory, S.SsaExpr("mem_input", 0, name="io"),
                             memory_touched=True)
    result = S._materialize_irsb_outputs(state, {}, max_assignments_per_function=4096)
    if isinstance(result, S.LowerFailure):
        raise result
    outputs, assignments = result
    return {"inputs": S._input_items(S._collect_inputs((memory,))),
            "outputs": outputs, "assignments": assignments}


def check_native_code_prefixes(accesses: NativeAccessReport, entry: MachineState,
                              ranges: tuple[tuple[int, int], ...],
                              domain: Real16ScalarDomain | None, *, deadline: float,
                              ) -> tuple[CodeByteProjectionProof, ...]:
    """Check every collected write against block-entry memory, never net memory.

    This local helper cannot grant source provenance. The bound producer supplies
    fresh raw accesses and the consumed complete fetched-byte ranges. Entry has
    concrete loader fields only for the bootstrap; other blocks use the proven
    scalar predicate. All other registers and background bytes remain arbitrary.
    """
    NativeAccessLimits(deadline)
    if not accesses.complete or not ranges:
        return ()
    before = materialize_function("code-prefix:entry", entry)
    index = z3.BitVec("bound_code_prefix_arbitrary_byte", 32)
    fetched = z3.Or(*(z3.And(z3.UGE(index, start), z3.ULT(index, start + size))
                     for start, size in ranges))
    writes = tuple(row.memory_after for row in accesses.facts if row.kind is NativeAccessKind.WRITE)
    memories = writes or (S.SsaExpr("mem_input", 0, name="mem"),)
    results: list[CodeByteProjectionProof] = []
    for memory in memories:
        if time.monotonic() >= deadline:
            raise TimeoutError("original code-prefix deadline exhausted")
        document = _memory_document(memory)
        composed = S._compose_block_outputs(document, document["outputs"], entry,
                                            compose_stats={"deadline": deadline})
        post = dict(entry)
        post["memory"] = composed["memory"]
        inputs = S._z3_inputs(before, materialize_function("code-prefix:post", post), z3)
        pre_terms, post_terms = _state_exprs(entry, inputs), _state_exprs(post, inputs)
        premise = cast(z3.BoolRef, fetched if domain is None else z3.And(fetched, domain.predicate(pre_terms)))
        results.append(prove_physical_byte_projection(cast(z3.ArrayRef, pre_terms["memory"]),
                       cast(z3.ArrayRef, post_terms["memory"]), index, premise, deadline=deadline))
        if results[-1].status is not ProofStatus.PROVED:
            break
    return tuple(results)


@dataclass(slots=True)
class _PrefixRun:
    """One original deadline and closed block denominator for both binaries."""

    receipt: ImageBoundReal16Domain
    system: JointSystem
    loads: tuple[BoundReal16Load, BoundReal16Load]
    initialized: LoadedRelationProof
    bootstrap: tuple[MachineState, MachineState]
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]]
    limits: LoadedRelationLimits
    blocks: list[CodePrefixBlock] = field(default_factory=list)
    model: str = ""
    fixed: int = 0
    proposal: str = ""
    consumers: list[BoundDomainConsumption] = field(default_factory=list)

    def consume(self) -> CodePrefixReason | None:
        """Require the actual complete source/domain manifest before and after work."""
        self.limits.check_time()
        outcome = consume_image_bound_real16_domain(self.receipt, self.system, self.loads, self.initialized,
                    self.bootstrap, self.requests, timeout_ms=2**31 - 1, limits=self.limits)
        self.consumers.append(outcome)
        if outcome.complete:
            return None
        return CodePrefixReason.DEADLINE if outcome.reason is BoundDomainReason.DEADLINE else CodePrefixReason.RECEIPT

    def report(self, reason: CodePrefixReason, detail: str = "") -> Real16CodePrefixProof:
        """Keep missing blocks and every failed raw/prefix sub-obligation visible."""
        count = 3 + 2 * (len(self.system.steps) + 1)
        done = self.fixed + sum(row.complete for row in self.blocks)
        status = ProofStatus.PROVED if reason is CodePrefixReason.PRESERVED and done == count else ProofStatus.UNKNOWN
        if (any(p.status is ProofStatus.COUNTEREXAMPLE for row in self.blocks for p in row.projections)
                or any(row.fetch_scope.status is ProofStatus.COUNTEREXAMPLE for row in self.blocks)):
            status = ProofStatus.COUNTEREXAMPLE
        if not detail and self.consumers:
            detail = self.consumers[-1].detail
        return Real16CodePrefixProof(status, reason, self.model, tuple(self.blocks), tuple(self.consumers),
                                    FactCounters(count, count, count, self.fixed + len(self.blocks), count - done), detail,
                                    self.proposal, self.requests, self.receipt)


def _entry(load: BoundReal16Load, address: int, scalar: Real16ScalarDomain,
           ) -> tuple[MachineState, Real16ScalarDomain | None]:
    """Derive bootstrap constants from the actual load, without narrowing other inputs."""
    entry = initial_state()
    if address != load.binding.entry:
        return entry, scalar
    for name, value in load.binding.entry_registers:
        if name != "ip":
            entry[name] = {"op": "const", "width": 16, "value": hex(value)}
    entry["control_ip"] = {"op": "const", "width": 32, "value": hex(load.binding.entry)}
    return entry, None


def _decoded_prefix_block(run: _PrefixRun, side: int, project: angr.Project, row: NativeBlockRequest,
                          scalar: Real16ScalarDomain) -> CodePrefixReason | None:
    """Independently lift one immutable request and close its full raw ledger."""
    load, rows = run.loads[side], run.requests[side]
    data = _block_bytes(_BindingRun(load, rows, run.limits), row)
    remaining = int((run.limits.deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise TimeoutError("original native code-prefix lift deadline exhausted")
    with S._timeout_alarm(remaining, message="independent raw code-prefix lift deadline"):
        irsb = project.factory.block(row.address, byte_string=data, size=row.size, opt_level=0).vex
        if not isinstance(irsb, pyvex.IRSB) or irsb.size != row.size or irsb.jumpkind == "Ijk_NoDecode":
            return CodePrefixReason.SOURCE
        accesses = collect_native_memory_accesses(irsb, NativeAccessLimits(run.limits.deadline))
        entry, domain = _entry(load, row.address, scalar)
        fetch_scope = check_real16_fetch_scope(row.address, row.size, entry, domain,
                                               deadline=run.limits.deadline)
        ranges = tuple((item.address, item.size) for item in rows)
        projections = (check_native_code_prefixes(accesses, entry, ranges, domain, deadline=run.limits.deadline)
                       if fetch_scope.complete else ())
    block = CodePrefixBlock(side, row.address, row.size, hashlib.sha256(data).hexdigest(), accesses,
                            projections, fetch_scope, ranges)
    run.blocks.append(block)
    if not accesses.complete:
        return CodePrefixReason.ACCESS
    if not fetch_scope.complete:
        if fetch_scope.reason is FetchScopeReason.DEADLINE:
            return CodePrefixReason.DEADLINE
        return (CodePrefixReason.COUNTERMODEL if fetch_scope.status is ProofStatus.COUNTEREXAMPLE
                else CodePrefixReason.FETCH)
    if not block.complete:
        return (CodePrefixReason.COUNTERMODEL if any(p.status is ProofStatus.COUNTEREXAMPLE for p in projections)
                else CodePrefixReason.UNKNOWN)
    return None


def _bound_prefixes(run: _PrefixRun) -> CodePrefixReason:
    """Freshly decode every consumed request and retain all ordered accesses."""
    consumed = run.consume()
    if consumed is not None:
        return consumed
    run.fixed += 1
    run.model = code_prefix_model_hash()
    run.proposal = joint_proposal_hash(run.system, run.bootstrap)
    scalar = run.receipt.domain
    if scalar is None:
        return CodePrefixReason.RECEIPT
    for side, (load, rows) in enumerate(zip(run.loads, run.requests, strict=True)):
        run.limits.check_time()
        if len(load.image.chunks) != 1:
            return CodePrefixReason.SOURCE
        address, image = load.image.chunks[0]
        remaining = int((run.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise TimeoutError("original code-prefix project creation deadline exhausted")
        with S._timeout_alarm(remaining, message="independent code-prefix project creation deadline"):
            project = angr.Project(io.BytesIO(image),
                        main_opts={"backend": "blob", "arch": real16_loader_arch(), "base_addr": address,
                                   "entry_point": load.binding.entry}, auto_load_libs=False)
        for row in rows:
            run.limits.check_time()
            reason = _decoded_prefix_block(run, side, project, row, scalar.domain)
            if reason is not None:
                return reason
    consumed = run.consume()
    if consumed is not None:
        return consumed
    run.fixed += 1
    if run.model != code_prefix_model_hash():
        return CodePrefixReason.MODEL
    run.limits.check_time()
    run.fixed += 1
    return CodePrefixReason.PRESERVED


def prove_real16_code_prefixes(receipt: ImageBoundReal16Domain, system: JointSystem,
    loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
    bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    *, timeout_ms: int = 15000, limits: LoadedRelationLimits | None = None) -> Real16CodePrefixProof:
    """Prove bound fetched-byte stability at every actual native store prefix."""
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("code-prefix proof requires a nonnegative finite millisecond budget")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _PrefixRun(receipt, system, loads, initialized, bootstrap, requests, replace(selected, deadline=deadline))
    reason, detail = CodePrefixReason.UNKNOWN, ""
    try:
        reason = _bound_prefixes(run)
    except TimeoutError as refusal:
        reason, detail = CodePrefixReason.DEADLINE, str(refusal)
    except LoadedRelationRefusal as refusal:
        reason = CodePrefixReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE else CodePrefixReason.RESOURCE
        detail = str(refusal)
    except (ImageBindingRefusal, _NativeRefusal) as refusal:
        reason, detail = CodePrefixReason.SOURCE, str(refusal)
    except (S.LowerFailure, RecursionError) as refusal:
        reason, detail = CodePrefixReason.RESOURCE, str(refusal)
    except (angr.errors.SimEngineError, pyvex.errors.PyVEXError) as refusal:
        reason, detail = CodePrefixReason.SOURCE, str(refusal)
    return run.report(reason, detail)
