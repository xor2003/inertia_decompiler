"""Bind flat32 backend evidence to immutable inputs and explicit proof scope.

Layer: dosunit proof reporting.
Responsibility: share checked obligation accounting across staged i386 drivers,
retaining raw diagnostics and refusing changed inputs or inconsistent evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from collections import Counter
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.dosunit.contracts.binary_initial_state import compare_initial_images
from tools.dosunit.contracts.model import canonical_json_bytes, write_json
from tools.dosunit.contracts.proof_contracts import (
    Architecture,
    ContractIdentity,
    legacy_status_for,
    report_to_document,
)
from tools.dosunit.reporting.proof_projection import project_backend_report
from tools.dosunit.reporting.proof_public_domain import common_image_bits, flat32_declared_outputs, flat32_public_domain

if TYPE_CHECKING:
    import angr

MODEL_VERSION: str = 'flat32.integer-functional.v1'


def _digest(value: object) -> str:
    """Hash a deterministic JSON contract description."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _semantic_sources(driver: Path) -> dict[str, str]:
    """Fingerprint the actual staged driver and shared proof owners."""
    shared = Path(__file__).resolve().parents[1]
    paths = [driver, *[driver.parent / name for name in (
        'flat32_adapter.py', 'flat32_cfg.py', 'flat32_region.py', 'flat32_verdict.py',
    )], *[shared / name for name in (
        'compare/straightline_ssa.py', 'contracts/proof_contracts.py',
        'contracts/proof_obligations.py', 'reporting/proof_serialization.py',
        'reporting/proof_projection.py', 'reporting/flat32_proof_report.py',
    )]]
    # Conservatively seal every owned Python dependency, including helpers
    # imported indirectly by SSA, relation owners, or frontend lifting. A fixed
    # hand-maintained list omitted arithmetic helpers and accepted stale proofs.
    # Sorted paths make additions, removals and content changes reproducible.
    owned = {path for path in paths if path.is_file()}
    owned.update(shared.rglob('*.py'))
    owned.update((shared.parent / 'comparator').rglob('*.py'))
    owned.update(driver.parent.rglob('*.py'))
    owned.update((shared.parents[1] / 'inertia').rglob('*.py'))
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(owned)}


def _auxiliary_input_bindings(args: argparse.Namespace) -> dict[str, dict[str, str]]:
    """Snapshot an explicit LINK-map input at the public argparse boundary.

    Older third-party driver namespaces omit this opt-in field. Its absence
    preserves the existing binary-only contract; a supplied path must exist.
    """
    # Dynamic third-party argparse boundary: older driver namespaces omit this opt-in field.
    supplied = getattr(args, 'candidate_link_map', None)
    if supplied is None:
        return {}
    path = Path(supplied).resolve()
    return {'candidate_link_map': {
        'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
    }}


def _verify_auxiliary_inputs(
    bindings: dict[str, dict[str, str]], raw: dict[str, Any],
) -> None:
    """Refuse drift or a backend that consumed a different auxiliary identity."""
    reported = raw.get('auxiliary_inputs')
    for name, binding in bindings.items():
        if hashlib.sha256(Path(binding['path']).read_bytes()).hexdigest() != binding['sha256']:
            raise RuntimeError('auxiliary input changed during the proof; evidence cannot be sealed')
        evidence = reported.get(name) if isinstance(reported, dict) else None
        if not isinstance(evidence, dict) or evidence.get('sha256') != binding['sha256']:
            raise RuntimeError('backend auxiliary input identity differs; evidence cannot be sealed')


def _extra_input_domain(
    auxiliary_inputs: dict[str, dict[str, str]], retry_cap: int | None,
) -> dict[str, Any]:
    """Describe explicitly bound auxiliary inputs and the unchanged retry budget."""
    extra: dict[str, Any] = {}
    if auxiliary_inputs:
        extra['auxiliary_inputs'] = auxiliary_inputs
    if retry_cap is not None:
        extra['call_block_retry_policy'] = {
            'initial_cap': 64, 'retry_cap': retry_cap,
            'deadline': 'same absolute retry deadline', 'other_limits': 'unchanged',
        }
    return extra


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


_PE32_BORLAND_SECTIONS = frozenset({b'CODE', b'DATA', b'BSS', b'.tls'})
_PE32_GNU_SECTIONS = frozenset(
    {b'.CRT', b'.pdata', b'.eh_fram', b'.debug_info', b'.debug_abbrev'})
_PE32_WATCOM_SECTIONS = frozenset({b'AUTO', b'CONST', b'CONST2', b'_DATA', b'_BSS'})
_GCC_COMMENT = re.compile(rb'GCC: \(([^)]*)\) ([0-9][0-9A-Za-z.\-]*)')


def _pe32_producer(path: Path, head: bytes) -> dict[str, Any]:
    """Classify a PE32 image's producing toolchain from loader evidence.

    Borland TLINK32 writes uppercase CODE/DATA/BSS section names and stamps
    optional-header linker version 2.x; MSVC link.exe leaves the 'DanS...Rich'
    compid header and lowercase .text/.data; MinGW GCC adds .CRT/.pdata/.eh_fram
    or debug_* sections; Watcom wlink uses AUTO/CONST/_BSS segment-class names.
    """
    import pefile

    pe = pefile.PE(str(path))
    section_names = [bytes(sec.Name).rstrip(b'\x00') for sec in pe.sections]
    rich = b'DanS' in head[:8192] and b'Rich' in head[:8192]
    borland = bool(_PE32_BORLAND_SECTIONS.intersection(section_names))
    gnu = bool(_PE32_GNU_SECTIONS.intersection(section_names))
    watcom = bool(_PE32_WATCOM_SECTIONS.intersection(section_names)) and not borland
    evidence: list[str] = []
    if rich:
        evidence.append('rich-header(DanS)')
    if borland:
        names = b','.join(sorted(_PE32_BORLAND_SECTIONS.intersection(section_names))).decode('latin1')
        evidence.append(f'borland-sections({names})')
    if gnu:
        names = b','.join(sorted(_PE32_GNU_SECTIONS.intersection(section_names))).decode('latin1')
        evidence.append(f'gnu-sections({names})')
    if watcom:
        evidence.append('watcom-sections')
    if borland and not rich:
        producer = 'borland-tlink'
    elif rich:
        producer = 'msvc-link'
    elif gnu:
        producer = 'gnu-mingw'
    elif watcom:
        producer = 'watcom-wlink'
    else:
        producer = 'unknown'
    opt = pe.OPTIONAL_HEADER
    return {
        'producer': producer, 'format': 'pe32',
        'linker_version': f'{opt.MajorLinkerVersion}.{opt.MinorLinkerVersion}',
        'sections': [name.decode('latin1') for name in section_names],
        'evidence': evidence,
    }


def _elf_producer(path: Path) -> dict[str, Any]:
    """Classify an ELF image's producing toolchain from marker evidence."""
    raw = path.read_bytes()
    ei_class = raw[4] if len(raw) > 4 else 0
    comment = _GCC_COMMENT.search(raw)
    evidence: list[str] = []
    if comment:
        evidence.append(f"comment({comment.group(0).decode('latin1')})")
    if b'.note.ABI-tag' in raw or b'.note.gnu.property' in raw:
        evidence.append('gnu-note-sections')
    if b'cosmopolitan' in raw.lower() or b'Actually Portable' in raw:
        evidence.append('cosmopolitan-ape')
    if comment:
        producer = 'gcc'
        tool = f"gcc {comment.group(2).decode('latin1')}"
    elif evidence:
        producer = 'gnu-or-cosmopolitan'
        tool = 'unknown'
    else:
        producer = 'unknown'
        tool = 'unknown'
    return {
        'producer': producer, 'format': f'elf{64 if ei_class == 2 else 32}',
        'toolchain': tool, 'evidence': evidence,
    }


def image_producer(path: Path) -> dict[str, Any]:
    """Fingerprint the producing toolchain of a compared binary image.

    Report-layer evidence only: the result never feeds a verdict.  It exists
    so a cross-producer comparison surfaces as an explicit warning — frame
    shape, register-width cleanup and prologue conventions differ across
    toolchains, so a same-compiler/same-flags candidate is the meaningful
    equivalence target.
    """
    head = path.read_bytes()[:65536]
    if head[:2] == b'MZ' and len(head) >= 0x40:
        pe_offset = int.from_bytes(head[0x3C:0x40], 'little')
        if head[pe_offset:pe_offset + 4] == b'PE\x00\x00':
            return _pe32_producer(path, head)
        return {'producer': 'unknown', 'format': 'mz-non-pe',
                'evidence': ['mz-without-pe-signature']}
    if head[:4] == b'\x7fELF':
        return _elf_producer(path)
    return {'producer': 'unknown', 'format': 'unrecognized',
            'evidence': ['no-mz-pe-or-elf-magic']}


def producer_warning(oracle: dict[str, Any], candidate: dict[str, Any]) -> str | None:
    """Return the comparability warning for a producer pair, if any."""
    known = {'borland-tlink', 'msvc-link', 'gnu-mingw', 'watcom-wlink', 'gcc'}
    oprod = oracle.get('producer', 'unknown')
    cprod = candidate.get('producer', 'unknown')
    if oprod in known and cprod in known and oprod != cprod:
        return (
            f'producer mismatch: oracle={oprod} candidate={cprod} — binaries built by '
            'different toolchains; frame/register-width/codegen differences '
            'will dominate observed deltas. Build the candidate with the '
            'same compiler and matching flags for a meaningful comparison.')
    if (oprod == cprod and oprod in known
            and oracle.get('linker_version') != candidate.get('linker_version')):
        return (
            f"linker-version mismatch inside producer {oprod}: oracle={oracle.get('linker_version')} "
            f"candidate={candidate.get('linker_version')} — matching compiler and linker flags/versions "
            'improve provability.')
    return None


def _checked_rows(raw: dict[str, Any], proof: dict[str, Any]) -> list[dict[str, Any]]:
    """Retain diagnostics while replacing any unjustified legacy success."""
    index: dict[str, list[dict[str, Any]]] = {}
    raw_rows = raw.get('results')
    for row in raw_rows if isinstance(raw_rows, list) else []:
        function = row.get('function') if isinstance(row, dict) else None
        if isinstance(function, dict) and isinstance(function.get('name'), str):
            index.setdefault(function['name'], []).append(row)
    results: list[dict[str, Any]] = []
    from tools.dosunit.contracts.proof_contracts import ProofStatus

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
    from tools.dosunit.compare.flat32_proof_retry import call_block_retry_cap
    from tools.dosunit.contracts.binary_environment import active_ordered_io, scoped_ordered_io
    from tools.dosunit.reporting.flat32_proof_domain_cli import entry_domain_from_args, ordered_io_from_args

    entry_domain = entry_domain_from_args(args)
    retry_cap = call_block_retry_cap(args)
    io_model = ordered_io_from_args(args)
    ambient_io = active_ordered_io()
    if ambient_io is not None and ambient_io != io_model:
        raise ValueError("public ordered-io declaration conflicts with ambient binding")
    sources = _semantic_sources(driver)
    auxiliary_inputs = _auxiliary_input_bindings(args)
    paths = {'oracle': args.oracle_exe, 'candidate': args.candidate_exe}
    digests = {side: hashlib.sha256(path.read_bytes()).hexdigest() for side, path in paths.items()}
    with scoped_ordered_io(io_model):
        raw = comparison(args)
    if sources != _semantic_sources(driver):
        raise RuntimeError('comparator sources changed during the proof; evidence cannot be sealed')
    if any(hashlib.sha256(path.read_bytes()).hexdigest() != digests[side] for side, path in paths.items()):
        raise RuntimeError('binary changed during the proof; evidence cannot be sealed')
    _verify_auxiliary_inputs(auxiliary_inputs, raw)
    if call_block_retry_cap(args) != retry_cap:
        raise RuntimeError('block retry policy changed during the proof; evidence cannot be sealed')
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
    domain.update(_extra_input_domain(auxiliary_inputs, retry_cap))
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
    producers = {side: image_producer(path) for side, path in paths.items()}
    report['image_producers'] = producers
    warning = producer_warning(producers['oracle'], producers['candidate'])
    if warning is not None:
        report['producer_warning'] = warning
        sys.stderr.write(f'producer warning: {warning}\n')
    report['proof_scope'] = 'requested_functions_over_shared_input_memory'
    report['initial_image_relation'] = compare_initial_images(
        image_reports.get('oracle'), image_reports.get('candidate'),
    ).to_document(evaluated.status)
    if raw.get('results') != results:
        report['backend_results'] = raw.get('results')
    write_json(args.out_dir / 'compare.json', report)
    return report
