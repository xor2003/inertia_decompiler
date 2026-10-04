"""Public command boundary for independent flat32 differential execution.

Layer: dosunit CLI/execution reporting.
Responsibility: validate concrete vector manifests, execute linked images and
publish tested observations separately from semantic proof verdicts.
"""

from __future__ import annotations

import argparse
import hashlib
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from tools.dosunit.model import DosUnitError, load_json, write_json

if TYPE_CHECKING:
    from tools.dosunit.flat32_memory_permissions import DeclaredRegion
    from tools.dosunit.flat32_replay import ReplayImage, ReplayResult, ReplayVector


def add_replay_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register a concrete execution lane shared by dosunit and z3func."""
    parser = subparsers.add_parser('replay-flat32', help='Execute declared vectors on both i386 binaries; test evidence only')
    parser.add_argument('--oracle-exe', required=True, type=Path)
    parser.add_argument('--candidate-exe', required=True, type=Path)
    parser.add_argument('--vectors', required=True, type=Path)
    parser.add_argument('--instruction-limit', type=int, default=100000)
    parser.add_argument('--out', required=True, type=Path)
    parser.set_defaults(func=cmd_replay_flat32)


def _u32(value: object, field: str) -> int:
    """Parse an explicit i386 value at the JSON boundary, rejecting truncation."""
    if type(value) is int:
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as error:
            raise DosUnitError(f'{field}: invalid integer {value!r}') from error
    else:
        raise DosUnitError(f'{field}: expected integer or hexadecimal string')
    if not 0 <= parsed < 2**32:
        raise DosUnitError(f'{field}: value is outside the i386 domain')
    return parsed


def _memory_patches(raw: object) -> tuple[tuple[int, bytes], ...]:
    """Read explicit concrete memory bytes without guessing pointer relations."""
    if not isinstance(raw, list):
        raise DosUnitError('vector.memory must be a list')
    result: list[tuple[int, bytes]] = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get('bytes'), str):
            raise DosUnitError('memory patch requires address and hexadecimal bytes')
        try:
            data = bytes.fromhex(item['bytes'])
        except ValueError as error:
            raise DosUnitError('memory patch has invalid hexadecimal bytes') from error
        if not data:
            raise DosUnitError('memory patch cannot be empty')
        result.append((_u32(item.get('address'), 'memory.address'), data))
    return tuple(result)


def _scratch_mappings(raw: object) -> tuple[DeclaredRegion, ...]:
    """Parse explicit data-only caller mappings; observations grant no access."""
    from tools.dosunit.flat32_memory_permissions import DeclaredAccess, DeclaredRegion, MappingOrigin

    if not isinstance(raw, list):
        raise DosUnitError('vector.mappings must be a list')
    result: list[DeclaredRegion] = []
    accesses = {'read': DeclaredAccess.READ, 'write': DeclaredAccess.WRITE}
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get('access'), list):
            raise DosUnitError('scratch mapping requires address, size and an access list')
        access = DeclaredAccess.NONE
        for name in item['access']:
            if not isinstance(name, str) or name not in accesses:
                raise DosUnitError('scratch access must name read or write')
            access |= accesses[name]
        result.append(DeclaredRegion(_u32(item.get('address'), 'mapping.address'),
                                    _u32(item.get('size'), 'mapping.size'), access, MappingOrigin.VECTOR))
    return tuple(result)


def _vector(raw: dict[str, object]) -> ReplayVector:
    """Convert one checked JSON vector to the owned execution contract."""
    from tools.dosunit.flat32_replay import MemoryRange, ReplayVector

    registers = raw.get('registers')
    if not isinstance(registers, dict) or not all(isinstance(name, str) for name in registers):
        raise DosUnitError('vector.registers must be an object')
    values = tuple((name, _u32(value, f'registers.{name}')) for name, value in sorted(registers.items()))
    observed = raw.get('observations', [])
    if not isinstance(observed, list):
        raise DosUnitError('vector.observations must be a list')
    ranges: list[MemoryRange] = []
    for item in observed:
        if not isinstance(item, dict):
            raise DosUnitError('memory observation requires address and size')
        ranges.append(MemoryRange(_u32(item.get('address'), 'observation.address'),
                                  _u32(item.get('size'), 'observation.size')))
    return ReplayVector(values, _memory_patches(raw.get('memory', [])), tuple(ranges),
                        _scratch_mappings(raw.get('mappings', [])))


def _image(path: Path) -> ReplayImage:
    """Load an actual linked executable through CLE and snapshot its bytes."""
    import angr
    from cle.errors import CLEError

    from tools.dosunit.flat32_replay import image_from_project

    try:
        project = angr.Project(str(path), auto_load_libs=False)
        return image_from_project(project)
    except (CLEError, OSError, ValueError) as error:
        raise DosUnitError(f'flat32 replay cannot load {path}: {error}') from error


def _result_document(result: ReplayResult) -> dict[str, object]:
    """Serialize actual observations without promoting them to a proof."""
    return {
        'status': result.status.value, 'detail': result.detail, 'instructions': result.instructions,
        'registers': dict(result.registers),
        'requested_observations': [{'address': hex(region.address), 'size': region.size}
                                   for region in result.requested_observations],
        'observations': [{'address': hex(row.address), 'size': row.size, 'status': row.status.value,
                          'bytes': row.data.hex(), 'origins': [origin.value for origin in row.origins]}
                         for row in result.observations],
        'pages': [{'address': hex(page.address), 'access': int(page.access),
                   'origins': [origin.value for origin in page.origins]} for page in result.pages],
        'writes': [{'address': hex(address), 'bytes': data.hex()} for address, data in result.writes],
    }


def _checked_vectors(document: object) -> list[dict[str, object]]:
    """Reject empty, ambiguous or malformed selections before loading binaries."""
    raw = document.get('vectors') if isinstance(document, dict) else None
    if not isinstance(raw, list) or not raw:
        raise DosUnitError('flat32 replay needs a nonempty vectors list')
    checked: list[dict[str, object]] = []
    ids: set[str] = set()
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id']:
            raise DosUnitError('every flat32 vector requires a nonempty id')
        if item['id'] in ids:
            raise DosUnitError('duplicate flat32 vector id')
        ids.add(item['id'])
        checked.append(item)
    return checked


def cmd_replay_flat32(args: argparse.Namespace) -> int:
    """Run the selected vectors and return 0/1/2 for agreement/mismatch/gaps."""
    try:
        from tools.dosunit.flat32_replay import DEFAULT_OBSERVABLES, compare_replays, replay
    except ImportError as error:
        raise DosUnitError(f'flat32 execution backend unavailable: {error}') from error
    vectors = _checked_vectors(load_json(args.vectors))
    if args.instruction_limit <= 0:
        raise DosUnitError('flat32 instruction limit must be positive')
    paths: tuple[Path, Path] = args.oracle_exe, args.candidate_exe
    digests = tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in paths)
    images = tuple(_image(path) for path in paths)
    rows: list[dict[str, object]] = []
    for item in vectors:
        vector = _vector(item)
        try:
            left = replay(images[0], _u32(item.get('oracle_entry'), 'oracle_entry'), vector,
                          instruction_limit=args.instruction_limit)
            right = replay(images[1], _u32(item.get('candidate_entry'), 'candidate_entry'), vector,
                           instruction_limit=args.instruction_limit)
        except ValueError as error:
            raise DosUnitError(f'vector {item["id"]}: {error}') from error
        agreement = compare_replays(left, right)
        rows.append({'id': item['id'], 'status': agreement.value,
                     'oracle': _result_document(left), 'candidate': _result_document(right)})
    if any(hashlib.sha256(path.read_bytes()).hexdigest() != digest for path, digest in zip(paths, digests, strict=True)):
        raise DosUnitError('binary changed during flat32 replay')
    counts = Counter(row['status'] for row in rows)
    summary = {'total': len(rows), **{status: counts[status] for status in ('agreed', 'mismatched', 'incomplete')}}
    document = {
        'schema': 'dosunit.flat32_replay.v1', 'proof_status': 'not_established_by_execution',
        'summary': summary, 'results': rows, 'observables': list(DEFAULT_OBSERVABLES),
        'scope': 'declared integer vectors; full integer/control/segment state, strict flat addresses and observed writes',
        'inputs': {side: {'path': str(path), 'sha256': digest}
                   for side, path, digest in zip(('oracle', 'candidate'), paths, digests, strict=True)},
    }
    write_json(args.out, document)
    if counts['mismatched']:
        return 1
    return 2 if counts['incomplete'] else 0
