"""Bind flat32 backend evidence to immutable inputs and explicit proof scope.

Layer: dosunit proof reporting.
Responsibility: share checked obligation accounting across staged i386 drivers,
retaining raw diagnostics and refusing changed inputs or inconsistent evidence.
"""

from __future__ import annotations

import argparse
import hashlib
from collections import Counter
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.dosunit.binary_initial_state import compare_initial_images
from tools.dosunit.model import canonical_json_bytes, write_json
from tools.dosunit.proof_contracts import Architecture, ContractIdentity, legacy_status_for, report_to_document
from tools.dosunit.proof_projection import project_backend_report
from tools.dosunit.proof_public_domain import common_image_bits, flat32_declared_outputs, flat32_public_domain

if TYPE_CHECKING:
    import angr

MODEL_VERSION: str = 'flat32.integer-functional.v1'


def _digest(value: object) -> str:
    """Hash a deterministic JSON contract description."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _semantic_sources(driver: Path) -> dict[str, str]:
    """Fingerprint the actual staged driver and shared proof owners."""
    shared = Path(__file__).parent
    paths = [driver, *[driver.parent / name for name in (
        'flat32_adapter.py', 'flat32_cfg.py', 'flat32_region.py', 'flat32_verdict.py',
    )], *[shared / name for name in (
        'straightline_ssa.py', 'proof_contracts.py', 'proof_obligations.py',
        'proof_serialization.py', 'proof_projection.py', 'flat32_proof_report.py',
    )]]
    # Conservatively seal every owned Python dependency, including helpers
    # imported indirectly by SSA, relation owners, or frontend lifting. A fixed
    # hand-maintained list omitted arithmetic helpers and accepted stale proofs.
    # Sorted paths make additions, removals and content changes reproducible.
    owned = set(paths)
    owned.update(shared.rglob('*.py'))
    owned.update(driver.parent.rglob('*.py'))
    frontend = shared.parents[1] / 'angr_platforms' / 'angr_platforms'
    if frontend.is_dir():
        owned.update(frontend.rglob('*.py'))
    # Repository imports enter through the outer shim; installed layouts may
    # have only the inner entry point. Seal whichever entry points exist.
    outer_entry = frontend.parent / '__init__.py'
    if outer_entry.is_file():
        owned.add(outer_entry)
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(owned)}


def _mapped_run_records(address: int, parts: list[bytes]) -> tuple[bytes, ...]:
    """Hash a contiguous mapped span independently of CLE backer boundaries."""
    header = address.to_bytes(8, 'little') + sum(len(part) for part in parts).to_bytes(8, 'little')
    return (header, *parts)


def loaded_image_identity(project: angr.Project) -> dict[str, Any]:
    """Fingerprint mapped CLE bytes and the loader's address contract.

    CLE is a dynamic third-party boundary; memory backers are read directly
    from the exact project consumed by the comparison.
    """
    digest = hashlib.sha256()
    byte_count = 0
    run_start: int | None = None
    run_parts: list[bytes] = []
    end = 0
    for address, data in sorted(project.loader.memory.backers(), key=lambda item: item[0]):
        blob = bytes(data)
        if not blob:
            continue
        if run_start is not None and address < end:
            raise ValueError("overlapping mapped backers cannot establish an image identity")
        if run_start is not None and address != end:
            for record in _mapped_run_records(run_start, run_parts):
                digest.update(record)
            run_parts = []
            run_start = None
        if run_start is None:
            run_start = int(address)
        run_parts.append(blob)
        end = address + len(blob)
        byte_count += len(blob)
    if run_start is not None:
        for record in _mapped_run_records(run_start, run_parts):
            digest.update(record)
    main = project.loader.main_object
    return {'sha256': digest.hexdigest(), 'byte_count': byte_count,
            'architecture': project.arch.name, 'width': project.arch.bits,
            'loader': type(main).__qualname__, 'mapped_base': main.mapped_base,
            'linked_base': main.linked_base, 'entry': project.entry}


def _checked_rows(raw: dict[str, Any], proof: dict[str, Any]) -> list[dict[str, Any]]:
    """Retain diagnostics while replacing any unjustified legacy success."""
    index: dict[str, list[dict[str, Any]]] = {}
    raw_rows = raw.get('results')
    for row in raw_rows if isinstance(raw_rows, list) else []:
        function = row.get('function') if isinstance(row, dict) else None
        if isinstance(function, dict) and isinstance(function.get('name'), str):
            index.setdefault(function['name'], []).append(row)
    results: list[dict[str, Any]] = []
    from tools.dosunit.proof_contracts import ProofStatus

    for verdict in proof['verdicts']:
        name = verdict['id']['key']
        candidates = index.get(name, [])
        checked_row: dict[str, Any] = dict(candidates[0]) if len(candidates) == 1 else {'function': {'id': f'oracle:{name}', 'name': name}}
        status = legacy_status_for(ProofStatus(verdict['status']))
        if checked_row.get('status') != status:
            checked_row.update(backend_status=checked_row.get('status'), backend_reason=checked_row.get('reason'),
                       status=status, reason=verdict['reason'])
        results.append(checked_row)
    return results


def run_bound_comparison(
    comparison: Callable[[argparse.Namespace], dict[str, Any]], args: argparse.Namespace, driver: Path,
) -> dict[str, Any]:
    """Run one comparison and seal exactly its declared function obligations.

    A caller-declared ``entry_esp_range`` premise is serialized into the sealed
    input domain before the comparison runs, so the contract identity binds the
    exact interval; per-verdict assumption payloads stay on the result rows.

    A declared ``ordered_io_environment`` binding is likewise resolved before
    the comparison, installed ambiently across it — so every intake, lowering
    and composition gate inside owned and unowned seams observes the identical
    typed model — and sealed into the domain digest. Missing binding preserves
    the closed-environment default; malformed or incompatible bindings refuse.
    An existing ambient binding must match this explicit public declaration,
    including its absence, so executed premises and the sealed domain agree.
    Internal retry scopes may still inherit an already declared binding.
    """
    from tools.dosunit.binary_environment import active_ordered_io, scoped_ordered_io
    from tools.dosunit.flat32_proof_domain_cli import entry_domain_from_args, ordered_io_from_args

    entry_domain = entry_domain_from_args(args)
    io_model = ordered_io_from_args(args)
    ambient_io = active_ordered_io()
    if ambient_io is not None and ambient_io != io_model:
        raise ValueError("public ordered-io declaration conflicts with ambient binding")
    sources = _semantic_sources(driver)
    paths = {'oracle': args.oracle_exe, 'candidate': args.candidate_exe}
    digests = {side: hashlib.sha256(path.read_bytes()).hexdigest() for side, path in paths.items()}
    with scoped_ordered_io(io_model):
        raw = comparison(args)
    if sources != _semantic_sources(driver):
        raise RuntimeError('comparator sources changed during the proof; evidence cannot be sealed')
    if any(hashlib.sha256(path.read_bytes()).hexdigest() != digests[side] for side, path in paths.items()):
        raise RuntimeError('binary changed during the proof; evidence cannot be sealed')
    names = raw.get('requested_functions')
    if not isinstance(names, list) or not all(isinstance(name, str) and name for name in names):
        raise RuntimeError('comparison did not retain its requested-function manifest')
    abi = raw.get('proof_contract', {})
    domain: dict[str, Any] = {
        'machine': 'flat i386 integer-functional VEX semantics',
        'instruction_memory': 'immutable executable bytes; data writes do not alias executable ranges',
        'faults': 'only admitted fault-free memory accesses; exception edges refuse',
        'environment': 'no undeclared interrupts, operating-system services or asynchronous events',
        'initial_data': 'shared unconstrained flat byte array and declared register relation',
    }
    if entry_domain is not None:
        # Seal the exact declared interval into the model hash so otherwise
        # identical runs under a different premise cannot share identity.
        domain['entry_esp_premise'] = entry_domain.assumption_document()
    if io_model is not None:
        # Seal the declared ordered-I/O relation identity and full contract
        # content into the model hash; bound and unbound runs can never
        # share a sealed obligation identity.
        domain['environment'] = 'declared ordered scalar port-I/O relation (caller premise)'
        domain['ordered_io_environment'] = io_model.to_document()
    # A supplied backend output declaration must be well-formed and
    # consistent across both raw keys; only an omitted declaration falls back
    # to the caller's --output-regs list, published as caller-declared.
    declared_outputs, output_source = flat32_declared_outputs(abi, args.output_regs)
    public_domain = flat32_public_domain(
        outputs=declared_outputs,
        register_source=output_source,
        image_bits=common_image_bits(raw.get('loaded_images') or {}),
        premise=domain.get('entry_esp_premise'),
        ordered_io=io_model,
    )
    domain_document = public_domain.to_document()
    contract = ContractIdentity(
        Architecture.FLAT32, digests['oracle'], digests['candidate'], _digest(sources),
        _digest({'version': MODEL_VERSION, 'scope': abi, 'domain': domain, 'loaded_images': raw.get('loaded_images'),
                 'packages': {name: version(name) for name in ('angr', 'cle', 'pyvex', 'z3-solver')}}),
        _digest({'scope': 'whole_requested_function', 'mode': args.mode, 'outputs': args.output_regs,
                 'function_ranges': raw.get('function_ranges'), 'domain': domain_document}),
    )
    evaluated = project_backend_report(contract, tuple(names), raw)
    proof = report_to_document(evaluated)
    results = _checked_rows(raw, proof)
    counts = Counter(row['status'] for row in results)
    raw_summary = raw.get('summary')
    summary = {**(raw_summary if isinstance(raw_summary, dict) else {}), 'total': len(results),
               **{status: counts[status] for status in ('passed', 'failed', 'refused', 'conditional')}}
    report = {**raw, 'summary': summary, 'results': results, 'proof_evidence': proof,
              'inputs': {side: {'path': str(path.resolve()), 'sha256': digests[side]} for side, path in paths.items()},
              'semantic_sources': sources, 'input_domain': domain, 'proof_domain': domain_document}
    image_reports = raw.get('loaded_images')
    image_reports = image_reports if isinstance(image_reports, dict) else {}
    report['proof_scope'] = 'requested_functions_over_shared_input_memory'
    report['initial_image_relation'] = compare_initial_images(
        image_reports.get('oracle'), image_reports.get('candidate'),
    ).to_document(evaluated.status)
    if raw.get('results') != results:
        report['backend_results'] = raw.get('results')
    write_json(args.out_dir / 'compare.json', report)
    return report
