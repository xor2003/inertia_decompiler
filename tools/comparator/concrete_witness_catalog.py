"""Layer: comparator concrete refutation intake.

Responsibility: bind explicit shared vectors to catalog-derived native function
ranges and retain completed integer counterexamples beside the original refusal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.comparator.table_checks import read_pe_bytes
from tools.dosunit.compare.flat32_concrete_witness import ConcreteFunction, compare_concrete_witness
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.reporting.flat32_proof_domain_cli import entry_domain_from_args
from tools.dosunit.reporting.flat32_replay_cli import parse_replay_vector
from tools.dosunit.runtime.flat32_replay_model import ReplayVector


@dataclass(frozen=True)
class ConcreteWitnessCatalog:
    """Immutable intake identity with bounded per-function test inputs."""

    path: Path
    digest: str
    vectors: dict[str, tuple[tuple[str, ReplayVector], ...]]
    entry_domain: Flat32ProofDomain | None


def prepare_concrete_catalog(args: argparse.Namespace) -> ConcreteWitnessCatalog | None:
    """Validate opt-in inputs before starting the ordinary function comparison."""
    options = vars(args)  # Third-party argparse boundary, including older programmatic callers.
    path = options.get('concrete_counterexample_vectors')
    if path is None:
        return None
    if (args.mode != 'matched-cfg' or args.normalize_globals
            or any(options.get(key) is not None for key in ('abi_observation_catalog', 'external_call_catalog'))):
        raise ValueError('concrete counterexamples require literal matched-cfg without ABI/external catalogs')
    if 'eax' not in {part.strip() for part in args.output_regs.split(',')}:
        raise ValueError('concrete counterexamples require full EAX observation')
    source = Path(path).resolve()
    raw = source.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError('concrete witness catalog exceeds 1 MiB')
    document = json.loads(raw)
    if (not isinstance(document, dict) or set(document) != {'schema', 'functions'}
            or document['schema'] != 'dosunit.flat32_concrete_witnesses.v1'
            or not isinstance(document['functions'], dict) or not 1 <= len(document['functions']) <= 512):
        raise ValueError('invalid concrete witness catalog')
    domain = entry_domain_from_args(args)
    vectors = {name: _function_vectors(name, items, domain) for name, items in document['functions'].items()}
    return ConcreteWitnessCatalog(source, hashlib.sha256(raw).hexdigest(), vectors, domain)


def _function_vectors(
    name: str, items: object, domain: Flat32ProofDomain | None,
) -> tuple[tuple[str, ReplayVector], ...]:
    """Reject ambiguous vector identity, extra entry overrides and out-of-domain ESP."""
    if not isinstance(name, str) or not name or not isinstance(items, list) or not 1 <= len(items) <= 16:
        raise ValueError('concrete function requires 1..16 named vectors')
    result: list[tuple[str, ReplayVector]] = []
    seen: set[str] = set()
    for item in items:
        if (not isinstance(item, dict) or not {'id', 'registers'} <= item.keys()
                or not item.keys() <= {'id', 'registers', 'memory', 'mappings', 'observations'}):
            raise ValueError('invalid concrete vector fields; entries come from function catalogs')
        ident = item['id']
        if not isinstance(ident, str) or not ident or ident in seen:
            raise ValueError('concrete vector IDs must be nonempty and unique within each function')
        seen.add(ident)
        vector = parse_replay_vector(item)
        esp = dict(vector.registers).get('esp')
        if esp is None or (domain is not None and not domain.esp_min <= esp <= domain.esp_max):
            raise ValueError('concrete vector ESP is missing or outside the declared entry domain')
        result.append((ident, vector))
    return tuple(result)


def attach_concrete_catalog(
    report: dict[str, Any], catalog: ConcreteWitnessCatalog,
    original: bytes, candidate: bytes, eligible_names: set[str],
) -> None:
    """Reexecute immutable PE slices; promote only an eligible original refusal."""
    if hashlib.sha256(catalog.path.read_bytes()).hexdigest() != catalog.digest:
        raise RuntimeError('concrete witness catalog changed during comparison')
    ranges = report['function_ranges']
    unknown = catalog.vectors.keys() - ranges['oracle'].keys()
    if unknown:
        raise ValueError(f'unknown concrete witness functions: {sorted(unknown)}')
    report.setdefault('auxiliary_inputs', {})['concrete_counterexample_vectors'] = {
        'path': str(catalog.path), 'sha256': catalog.digest,
    }
    image_hashes = [hashlib.sha256(image).hexdigest() for image in (original, candidate)]
    for row in report['results']:
        name = row['function']['name']
        if (row['status'] != 'refused' or name not in eligible_names or name not in catalog.vectors
                or name not in ranges['candidate']):
            continue
        functions = []
        for side, image in (('oracle', original), ('candidate', candidate)):
            entry, size = ranges[side][name]
            functions.append(ConcreteFunction(entry, read_pe_bytes(image, entry, size, executable=True)))
        attempts = []
        for ident, vector in catalog.vectors[name]:
            evidence: dict[str, Any]
            try:
                evidence = compare_concrete_witness(functions[0], functions[1], vector)
            except ValueError as error:
                evidence = {'status': 'refused', 'reason': 'concrete_vector_not_admitted', 'detail': str(error)}
            evidence.update(vector_id=ident, image_sha256=image_hashes)
            if catalog.entry_domain is not None:
                evidence['entry_domain'] = catalog.entry_domain.assumption_document()
            attempts.append(evidence)
            if evidence['status'] == 'failed':
                previous = dict(row)
                row.update(status='failed', reason=evidence['reason'], backend_status='failed',
                           proof_scope='complete_function', proof_method='bounded_integer_execution_counterexample',
                           strict_function_result=previous)
                break
        row['concrete_counterexamples'] = attempts
