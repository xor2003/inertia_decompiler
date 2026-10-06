"""Public real-mode binary-to-binary semantic proof wrapper.

Layer: dosunit public comparator driver.
Responsibility: lower fresh real16 SSA evidence for an original and a
candidate executable under sealed binary/semantic provenance, run the bounded
SSA/Z3 comparator over the full modeled machine state, and evaluate one
whole-function proof obligation per requested function through the shared
typed ledger. Per-part backend passes never become whole-function proof:
only a complete leaf block covering the declared body, a closed whole-region
equality result, or complete direct-call inlining may discharge an obligation. Catalog and
mapping documents propose entry/body correspondence only; missing requested
functions, stale provenance, aborted runs, unproved callees and
candidate-only reachable code all stay in the denominator and cannot pass.
"""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Sequence
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

from tools.dosunit import ssa_provenance, straightline_ssa
from tools.dosunit.binary_callee_discovery import DiscoveryBudget, discover_uncatalogued_leaves, discovery_root_ids
from tools.dosunit.binary_callee_intake import IntakeBudget
from tools.dosunit.binary_environment import (
    EnvironmentScan,
    active_ordered_io,
    part_io_events,
    scan_lowered_parts,
    scoped_ordered_io,
)
from tools.dosunit.binary_initial_state import compare_initial_images
from tools.dosunit.flat32_proof_report import loaded_image_identity
from tools.dosunit.model import DosUnitError, canonical_json_bytes, load_json, stable_id, write_json
from tools.dosunit.ordered_io_environment import (
    ORDERED_IO_PREMISE_NAME,
    OrderedIoContract,
    parse_ordered_io_identity,
)
from tools.dosunit.proof_contracts import (
    Architecture,
    ContractIdentity,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ProofStatus,
    report_to_document,
)
from tools.dosunit.proof_obligations import evaluate_obligations
from tools.dosunit.proof_public_domain import common_image_bits, real16_public_domain
from tools.dosunit.real16_call_contracts import Real16CallLimits
from tools.dosunit.real16_macro_retry import retry_whole_function_with_macro as retry_whole_function
from tools.dosunit.real16_proof_evidence import (
    _compare_index,
    _function_evidence,
    _group_parts,
    _mapped_candidate_keys,
    _requested_obligations,
)
from tools.dosunit.real16_recursive_compare import (
    Real16RecursiveRequest,
    RecursiveCompareOutcome,
    prove_recursive_compare,
)
from tools.dosunit.ssa_selection import selected_catalog_indices

REPORT_SCHEMA: str = "dosunit.binary16_compare.v1"
NON_PROVED_FAILURE: int = 1


def _digest(value: object) -> str:
    """Hash a deterministic JSON contract description."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _input_domain(io_model: OrderedIoContract | None = None) -> dict[str, Any]:
    """Declare the exact machine/environment contract this proof is bound to.

    A declared ordered-I/O environment relation replaces the closed-world
    ``environment`` clause: the sealed digest then binds the full typed
    contract content, so bound and unbound proofs cannot share an identity.
    """
    domain: dict[str, Any] = {
        "machine": "16-bit real-mode segmented x86 integer-functional VEX semantics",
        "state": "all modeled registers, 386 high halves, segment/flags/control registers and touched memory",
        "code_entry": "all CS aliases with 0 <= loaded_entry - 16*CS <= 0xffff; full 32-bit loaded control",
        "segmentation": "physical-address segmentation and aliasing exactly as modeled by the dosunit lifter",
        "instruction_memory": "immutable executable bytes; self-modifying code is outside scope",
        "faults": "fault-free model; exception/trap paths are refusals",
        "environment": "no interrupts, device I/O or operating-system effects",
        "initial_data": "shared arbitrary memory at function entry; executable-seeded memory requires its own relation",
    }
    if io_model is not None:
        domain["environment"] = "declared ordered scalar port-I/O relation (caller premise)"
        domain["ordered_io_environment"] = io_model.to_document()
    return domain


def _resolve_io_model(
    binding: OrderedIoContract | str | None,
) -> OrderedIoContract | None:
    """Bind a caller-declared ordered-I/O contract to this lane or refuse.

    A contract object is bound by architecture; an identity string is bound
    by exact model identity.  Any other shape — dicts, unknown names, wrong
    architecture — is an incompatible binding and refuses.
    """
    if binding is None:
        return None
    try:
        if isinstance(binding, OrderedIoContract):
            return binding.validate_for(Architecture.REAL16)
        return parse_ordered_io_identity(binding, Architecture.REAL16)
    except ValueError as exc:
        raise DosUnitError(str(exc)) from exc


def _bind_io_premise(
    row: ObligationEvidence, function_id: str, io_model: OrderedIoContract | None,
    document: dict[str, Any], backend: object,
) -> ObligationEvidence:
    """Mark a discharged row conditional when it consumed the I/O premise.

    Consumption is binary-derived: the admitted function's own parts record
    ordered port events, or the call-composition backend recorded the
    consumed environment premise for its transitive callees.  With no
    binding, or when no covered event existed in the closure, the row keeps
    its status; otherwise PROVED is weakened to CONDITIONAL with the premise
    assumption recorded.
    """
    if io_model is None or row.status not in (ProofStatus.PROVED, ProofStatus.CONDITIONAL):
        return row
    consumed = any(
        part_io_events(part) for part in _group_parts(document).get(function_id, [])
    )
    consumed = consumed or (
        isinstance(backend, dict) and bool(backend.get("environment"))
    )
    if not consumed:
        return row
    assumptions = tuple(
        dict.fromkeys([*row.assumptions, ORDERED_IO_PREMISE_NAME])
    )
    return replace(
        row,
        status=ProofStatus.CONDITIONAL,
        reason="ordered_io_environment_premise",
        assumptions=assumptions,
    )


def _recursive_evidence(
    evidence: list[ObligationEvidence],
    *,
    recursive: Real16RecursiveRequest | None,
    required: list[Obligation],
    documents: dict[str, dict[str, Any]],
    digests: dict[str, str],
    images: dict[str, dict[str, Any]],
    admissible: bool,
) -> tuple[list[ObligationEvidence], RecursiveCompareOutcome | None]:
    """Retain a separate initialized-component result without member promotion.

    The recursive attempt is opt-in and runs under its own typed request
    budget; a stale or aborted run cannot even attempt it. The joint's root
    entry/frame domain has no checked implication to arbitrary-entry member
    obligations. Preserve their contracts, dependencies and statuses exactly;
    the recursive_joint report exposes the component and its declared scope.
    """
    if recursive is None or not admissible:
        return evidence, None
    outcome = prove_recursive_compare(
        documents=documents,
        digests=digests,
        images=images,
        roots=[obligation.id.key for obligation in required],
        request=recursive,
    )
    return evidence, outcome


def _recursive_document(
    recursive: Real16RecursiveRequest | None, outcome: RecursiveCompareOutcome | None
) -> dict[str, Any] | None:
    """Report the retained recursive state; absent request means no field."""
    if recursive is None:
        return None
    if outcome is None:
        return {
            "schema": "dosunit.binary16_compare.recursive_joint.v1",
            "attempted": False,
            "status": ProofStatus.UNKNOWN.value,
            "reason": "run_not_fresh_or_aborted",
        }
    document: dict[str, Any] = outcome.to_document()
    return document


def _candidate_selection_keys(
    resolved: dict[str, dict[str, Any]], mapping: dict[str, Any] | None,
) -> frozenset[str]:
    """Preserve explicit mapping alternatives and implicit cross-module names."""
    candidate_intake_keys = frozenset(
        key for entry in resolved.values()
        for key in _mapped_candidate_keys(str(entry["id"]), entry, mapping)
    )
    if mapping is None:
        candidate_intake_keys |= frozenset(
            str(name) for entry in resolved.values() for name in entry.get("names", [])
        )
    return candidate_intake_keys


def compare_binary16(
    oracle_exe: Path,
    candidate_exe: Path,
    oracle_catalog: dict[str, Any],
    candidate_catalog: dict[str, Any],
    *,
    mapping: dict[str, Any] | None = None,
    selected: Sequence[str] = (),
    solver_timeout_ms: int = 60000,
    max_solver_assignments: int = 0,
    max_solver_inputs: int = 0,
    max_solver_memory_stores: int = 32,
    semantic_proof_passes: int = 2,
    max_region_loop_unroll: int = 2,
    max_blocks_per_function: int = 1000,
    max_insns_per_function: int = 256,
    max_ssa_assignments: int = 0,
    scan_limit: int = 0x1000,
    max_lift_block_ms: int = 10000,
    max_function_ms: int = 60000,
    max_rss_mb: int = 0,
    recursive: Real16RecursiveRequest | None = None,
    ordered_io_environment: OrderedIoContract | str | None = None,
    reuse_identical_lowering: bool = True,
) -> dict[str, Any]:
    """Compare two real-mode executables and return a sealed proof report.

    Both binaries are lowered fresh with checked provenance, compared over the
    full modeled state, then evaluated as one obligation per requested oracle
    function; the report status is PROVED only when every required function is
    discharged by leaf-complete or closed whole-region evidence.
    Identical paths, catalogs and fresh identities share one invocation-local
    lowering through independent deep copies; every side retains its seal,
    environment scan and full proof gates. The report records that reuse.

    ``reuse_identical_lowering`` is a diagnostic parity control. The default
    ``True`` keeps the in-invocation deepcopy reuse above; ``False`` recomputes
    the candidate lowering from the same sealed inputs, so a parity run can
    prove the reuse path never changes verdicts or dependency evidence. The
    mode is reported as ``lowering_reuse_mode`` and the per-side outcome stays
    in ``lowering_reuse``; neither semantic dependency identities nor any
    dischargeable-fact machinery are affected.

    ``recursive`` is a typed opt-in: when supplied, requested oracle function
    keys are tried as roots for the image-bound recursive joint checker over
    the same sealed documents and executable identities. The recursive_joint
    field retains that component result and its declared assumptions separately;
    it cannot discharge ordinary arbitrary-entry function obligations.

    ``ordered_io_environment`` binds the declared ordered scalar port-I/O
    environment contract: covered decoded IN/OUT events are admitted under
    its explicit premise, every discharged row that consumed the premise is
    CONDITIONAL rather than PROVED, and uncovered effects still refuse. A
    malformed or incompatible binding raises ``DosUnitError`` before any
    lowering; the default ``None`` preserves the closed-environment gate.
    """
    io_model = _resolve_io_model(ordered_io_environment)
    ambient_io = active_ordered_io()
    if ambient_io is not None and ambient_io != io_model:
        raise DosUnitError("public ordered-io declaration conflicts with ambient binding")
    if io_model is not None and recursive is not None:
        # The recursive joint is a separate opt-in component proof whose own
        # premise discipline has no declared relation to the ordered-I/O
        # binding; combining them would publish an unscoped premise.
        raise DosUnitError(
            "ordered-io environment binding cannot combine with the recursive joint proof"
        )
    with scoped_ordered_io(io_model):
        return _compare_binary16(
            oracle_exe,
            candidate_exe,
            oracle_catalog,
            candidate_catalog,
            mapping=mapping,
            selected=selected,
            solver_timeout_ms=solver_timeout_ms,
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
            semantic_proof_passes=semantic_proof_passes,
            max_region_loop_unroll=max_region_loop_unroll,
            max_blocks_per_function=max_blocks_per_function,
            max_insns_per_function=max_insns_per_function,
            max_ssa_assignments=max_ssa_assignments,
            scan_limit=scan_limit,
            max_lift_block_ms=max_lift_block_ms,
            max_function_ms=max_function_ms,
            max_rss_mb=max_rss_mb,
            recursive=recursive,
            io_model=io_model,
            reuse_identical_lowering=reuse_identical_lowering,
        )


def _compare_binary16(
    oracle_exe: Path,
    candidate_exe: Path,
    oracle_catalog: dict[str, Any],
    candidate_catalog: dict[str, Any],
    *,
    mapping: dict[str, Any] | None = None,
    selected: Sequence[str] = (),
    solver_timeout_ms: int = 60000,
    max_solver_assignments: int = 0,
    max_solver_inputs: int = 0,
    max_solver_memory_stores: int = 32,
    semantic_proof_passes: int = 2,
    max_region_loop_unroll: int = 2,
    max_blocks_per_function: int = 1000,
    max_insns_per_function: int = 256,
    max_ssa_assignments: int = 0,
    scan_limit: int = 0x1000,
    max_lift_block_ms: int = 10000,
    max_function_ms: int = 60000,
    max_rss_mb: int = 0,
    recursive: Real16RecursiveRequest | None = None,
    io_model: OrderedIoContract | None = None,
    reuse_identical_lowering: bool = True,
) -> dict[str, Any]:
    """Evaluate the sealed comparison body under an already-bound environment.

    ``io_model`` is the resolved ordered-I/O contract; the caller has
    installed it ambiently so unowned intake and lowering gates see the
    identical binding, and it is additionally threaded explicitly through
    the owned scan, composition and report seams. ``reuse_identical_lowering``
    selects whether an eligible candidate may deepcopy this invocation's
    sealed oracle document; ``False`` lowers the candidate independently.
    """
    digests = {
        side: hashlib.sha256(path.read_bytes()).hexdigest()
        for side, path in (("oracle", oracle_exe), ("candidate", candidate_exe))
    }
    required, resolved = _requested_obligations(oracle_catalog, selected)
    intake_roots = frozenset(str(entry["id"]) for entry in resolved.values())
    candidate_intake_keys = _candidate_selection_keys(resolved, mapping)
    selection_roots = {"oracle": intake_roots, "candidate": candidate_intake_keys}
    images: dict[str, Any] = {}
    documents: dict[str, dict[str, Any]] = {}
    environment: dict[str, EnvironmentScan] = {}
    oracle_identity: ssa_provenance.LoweringIdentity | None = None
    lowering_reuse = {"oracle": False, "candidate": False}
    for side, exe, catalog in (
        ("oracle", oracle_exe, oracle_catalog),
        ("candidate", candidate_exe, candidate_catalog),
    ):
        # Shared in-package lifter seam; tests monkeypatch this attribute.
        project = straightline_ssa._load_lifter_project(exe)
        images[side] = loaded_image_identity(project)
        identity = ssa_provenance.begin_lowering(exe)
        reuse_oracle = (
            reuse_identical_lowering
            and side == "candidate" and exe == oracle_exe
            and catalog == oracle_catalog and identity == oracle_identity
            and selected_catalog_indices(catalog.get("functions", []), selection_roots["oracle"])
            == selected_catalog_indices(catalog.get("functions", []), selection_roots["candidate"])
        )
        if reuse_oracle:
            # Reuse only this invocation's sealed evidence. Independent nested
            # state and the identity guard prevent stale or cross-side evidence.
            document = deepcopy(documents["oracle"])
            lowering_reuse[side] = True
        else:
            document = straightline_ssa.lower_straightline_ssa_document(
                exe_path=exe,
                functions_catalog=catalog,
                output_regs=straightline_ssa.INTERNAL_STATE_REGS,
                max_blocks_per_function=max_blocks_per_function,
                max_insns_per_function=max_insns_per_function,
                max_assignments_per_function=max_ssa_assignments,
                scan_limit=scan_limit,
                cache_dir=None,
                max_lift_block_ms=max_lift_block_ms,
                max_function_ms=max_function_ms,
                lifter_project=project,
                selected_roots=selection_roots[side] if selected else None,
            )
            discover_uncatalogued_leaves(
                project, document,
                root_ids=discovery_root_ids(document, intake_roots if side == "oracle" else candidate_intake_keys),
                leaf_budget=IntakeBudget(
                    max_body_bytes=min(scan_limit, 0x100),
                    max_instructions=min(max_insns_per_function, 32),
                    max_assignments_per_function=max_ssa_assignments,
                    max_lift_block_ms=min(max_lift_block_ms, 10000) if max_lift_block_ms > 0 else 10000,
                ),
                budget=DiscoveryBudget(
                    max_elapsed_ms=min(max_function_ms, 60000) if max_function_ms > 0 else 60000,
                ),
            )
        ssa_provenance.seal_lowering(document, exe, identity)
        if side == "oracle":
            oracle_identity = identity
        # The seal just checked binary/source freshness. Full artifact checks
        # belong after comparison and again after retries, where their results
        # gate admission. An immediate check here was discarded before use.
        documents[side] = document
        environment[side] = scan_lowered_parts(
            project, document.get("functions", []), io_model=io_model
        )
    compare = straightline_ssa.compare_ssa_documents(
        oracle=documents["oracle"],
        candidate=documents["candidate"],
        mapping_document=mapping,
        include_unmapped=True,
        timeout_ms=solver_timeout_ms,
        max_solver_assignments=max_solver_assignments,
        max_solver_inputs=max_solver_inputs,
        max_solver_memory_stores=max_solver_memory_stores,
        semantic_proof_passes=semantic_proof_passes,
        enable_region_equality=True,
        enable_connectivity=True,
        max_region_loop_unroll=max_region_loop_unroll,
        max_rss_mb=max_rss_mb,
    )
    semantic = {
        side: {
            field: documents[side].get("provenance", {}).get(field)
            for field in ("semantic_sha256", "model", "packages")
        }
        for side in ("oracle", "candidate")
    }
    public_domain = real16_public_domain(
        registers=straightline_ssa.INTERNAL_STATE_REGS,
        image_bits=common_image_bits(images),
        ordered_io=io_model,
    )
    domain_document = public_domain.to_document()
    contract = ContractIdentity(
        Architecture.REAL16,
        digests["oracle"],
        digests["candidate"],
        _digest(semantic),
        _digest({"loaded_images": images, "input_domain": _input_domain(io_model)}),
        _digest(
            {
                "scope": "whole_requested_function",
                "state": [*straightline_ssa.INTERNAL_STATE_REGS, "memory"],
                "oracle_catalog": oracle_catalog,
                "candidate_catalog": candidate_catalog,
                "mapping": mapping,
                "domain": domain_document,
            }
        ),
    )
    provenance = {side: ssa_provenance.checked_provenance(document)
                  for side, document in documents.items()}
    fresh = all(item.get("complete") and item.get("binary_sha256") == digests[side]
                for side, item in provenance.items())
    environment_admitted = all(scan.complete and not scan.requires_contract
                               for scan in environment.values())
    aborted = any(
        isinstance(section, dict) and section.get("aborted")
        for section in (compare, compare.get("summary"), compare.get("region_equality"), compare.get("connectivity"))
    )
    index = _compare_index(compare, documents["oracle"], documents["candidate"])
    evidence: list[ObligationEvidence] = []
    call_results: dict[str, dict[str, Any]] = {}
    # The ambient ordered-I/O binding installed by the public wrapper scopes
    # this obligation evaluation so unowned retry intermediaries inherit the
    # identical typed model rather than a silently different admission.
    for obligation in required:
        oracle_entry = resolved.get(obligation.id.key)
        if oracle_entry is None:
            continue
        if not fresh or aborted or not environment_admitted:
            reason = ("compare_aborted" if aborted else "stale_provenance" if not fresh
                      else "external_environment_contract_required")
            row = ObligationEvidence(
                id=obligation.id,
                contract=contract,
                status=ProofStatus.UNKNOWN,
                reason=reason,
                counters=FactCounters(1, 1, 1, 1, 1),
            )
        else:
            row = _function_evidence(obligation, oracle_entry, contract, index, mapping)
            if row.status is ProofStatus.UNKNOWN:
                retry = retry_whole_function(
                    obligation, oracle_entry, contract, documents["oracle"], documents["candidate"], mapping,
                    timeout_ms=solver_timeout_ms,
                    limits=Real16CallLimits(
                        max_solver_assignments=max_solver_assignments,
                        max_solver_inputs=max_solver_inputs,
                        max_solver_memory_stores=max_solver_memory_stores,
                    ),
                )
                if retry is not None:
                    row = retry.evidence
                    call_results[obligation.id.key] = retry.backend
        row = _bind_io_premise(
            row,
            str(oracle_entry.get("id") or obligation.id.key),
            io_model,
            documents["oracle"],
            call_results.get(obligation.id.key),
        )
        evidence.append(row)
    evidence, recursive_outcome = _recursive_evidence(
        evidence, recursive=recursive, required=required,
        documents=documents, digests=digests, images=images,
        admissible=fresh and not aborted,
    )
    provenance = {side: ssa_provenance.checked_provenance(document)
                  for side, document in documents.items()}
    if not all(item.get("complete") and item.get("binary_sha256") == digests[side]
               for side, item in provenance.items()):
        evidence = [replace(row, status=ProofStatus.UNKNOWN, reason="stale_provenance",
                            counters=FactCounters(1, 1, 1, 1, 1)) for row in evidence]
    evaluated = evaluate_obligations(contract, required, evidence)
    proof = report_to_document(evaluated)
    return {
        "schema": REPORT_SCHEMA,
        "status": proof["status"],
        "proof": proof,
        "proof_scope": "requested_functions_over_shared_input_memory",
        "initial_image_relation": compare_initial_images(images["oracle"], images["candidate"]).to_document(
            evaluated.status,
        ),
        "requested_functions": [obligation.id.key for obligation in required],
        "inputs": {
            side: {"path": str(path.resolve()), "sha256": digests[side], "image": images[side]}
            for side, path in (("oracle", oracle_exe), ("candidate", candidate_exe))
        },
        "provenance": provenance,
        "input_domain": _input_domain(io_model),
        "ordered_io_environment": (
            {
                "premise": io_model.premise_document(),
                "relation_identity": io_model.identity_digest(),
            }
            if io_model is not None else None
        ),
        "proof_domain": domain_document,
        "recursive_joint": _recursive_document(recursive, recursive_outcome),
        "lowering": {side: documents[side].get("counters") for side in ("oracle", "candidate")},
        "lowering_reuse_mode": "enabled" if reuse_identical_lowering else "bypassed",
        "lowering_reuse": lowering_reuse,
        "callee_intake": {side: document.get("binary_callee_intake") for side, document in documents.items()},
        "backend": {
            "function_proofs": call_results,
            "direct_calls": call_results,
            **{
            key: compare.get(key)
            for key in (
                "summary",
                "results",
                "region_equality",
                "connectivity",
                "external_parts",
                "candidate_only_parts",
            )
            },
        },
    }


def add_binary16_parser(subparsers: Any) -> argparse.ArgumentParser:  # noqa: ANN401
    """Attach the ``compare-binary16`` subcommand to a dosunit/z3func subparser set."""
    parser: argparse.ArgumentParser = subparsers.add_parser(
        "compare-binary16",
        help="Prove real-mode binary-to-binary function equivalence with fresh sealed SSA evidence",
    )
    parser.add_argument("--oracle-exe", required=True)
    parser.add_argument("--candidate-exe", required=True)
    parser.add_argument("--oracle-functions", required=True, help="Oracle functions-catalog JSON")
    parser.add_argument("--candidate-functions", required=True, help="Candidate functions-catalog JSON")
    parser.add_argument("--mapping", help="Optional candidate mapping JSON (correspondence only)")
    parser.add_argument("--select", default="", help="Comma-separated function names/ids to prove")
    parser.add_argument("--solver-timeout-ms", type=int, default=60000)
    parser.add_argument("--max-solver-assignments", type=int, default=0)
    parser.add_argument("--max-solver-inputs", type=int, default=0)
    parser.add_argument("--max-solver-memory-stores", type=int, default=32)
    parser.add_argument("--semantic-proof-passes", type=int, default=2)
    parser.add_argument("--max-region-loop-unroll", type=int, default=2)
    parser.add_argument("--max-blocks-per-function", type=int, default=1000)
    parser.add_argument("--max-insns-per-function", type=int, default=256)
    parser.add_argument("--max-ssa-assignments", type=int, default=0)
    parser.add_argument("--scan-limit", type=lambda value: int(value, 0), default=0x1000)
    parser.add_argument("--max-lift-block-ms", type=int, default=10000)
    parser.add_argument("--max-function-ms", type=int, default=60000)
    parser.add_argument("--max-rss-mb", type=int, default=0)
    parser.add_argument("--recursive", action="store_true",
                        help="Attempt the image-bound recursive joint proof for selected roots")
    parser.add_argument("--recursive-timeout-ms", type=int, default=240000,
                        help="Shared deadline for admission, binding and both recursive proof stages")
    parser.add_argument("--recursive-closed-machine", action="store_true",
                        help="Declare the closed-machine premise bound to both executables (visible assumption)")
    parser.add_argument("--ordered-io-environment", metavar="MODEL_ID",
                        help="Bind the declared ordered scalar port-I/O environment contract "
                             "(model identity dosunit.ordered_io.scalar_in_out.v1; results stay conditional)")
    parser.add_argument("--no-lowering-reuse", dest="reuse_identical_lowering",
                        action="store_false", default=True,
                        help="Diagnostic parity control: recompute the candidate lowering "
                             "instead of reusing an identical in-invocation oracle document")
    parser.add_argument("--out", required=True)
    parser.set_defaults(func=cmd_compare_binary16)
    return parser


def cmd_compare_binary16(args: argparse.Namespace) -> int:
    """Run the bounded binary16 comparison and write the sealed proof report."""
    mapping = load_json(Path(args.mapping)) if args.mapping else None
    if mapping is not None and mapping.get("schema") != "dosunit.mapping.v1":
        raise DosUnitError("mapping document schema must be dosunit.mapping.v1")
    report = compare_binary16(
        Path(args.oracle_exe),
        Path(args.candidate_exe),
        load_json(Path(args.oracle_functions)),
        load_json(Path(args.candidate_functions)),
        mapping=mapping,
        selected=tuple(str(args.select or "").split(",")),
        solver_timeout_ms=args.solver_timeout_ms,
        max_solver_assignments=args.max_solver_assignments,
        max_solver_inputs=args.max_solver_inputs,
        max_solver_memory_stores=args.max_solver_memory_stores,
        semantic_proof_passes=args.semantic_proof_passes,
        max_region_loop_unroll=args.max_region_loop_unroll,
        max_blocks_per_function=args.max_blocks_per_function,
        max_insns_per_function=args.max_insns_per_function,
        max_ssa_assignments=args.max_ssa_assignments,
        scan_limit=args.scan_limit,
        max_lift_block_ms=args.max_lift_block_ms,
        max_function_ms=args.max_function_ms,
        max_rss_mb=args.max_rss_mb,
        recursive=(
            Real16RecursiveRequest(
                timeout_ms=args.recursive_timeout_ms,
                closed_machine=args.recursive_closed_machine,
                provenance="compare-binary16-cli",
            )
            if args.recursive else None
        ),
        ordered_io_environment=args.ordered_io_environment,
        reuse_identical_lowering=args.reuse_identical_lowering,
    )
    report["id"] = stable_id("binary16-compare", {key: value for key, value in report.items() if key != "id"})
    write_json(Path(args.out), report)
    return 0 if report["status"] == ProofStatus.PROVED.value else 1
