"""Public command boundary for independent real16 differential execution.

Layer: dosunit CLI/execution reporting.
Responsibility: orchestrate the checked manifest (owned by
``real16_replay_manifest``), relocated MZ image loading, per-vector fresh-guest
execution and the tested-observation report. Admission is a checked contract:
no frames, pointers, registers or observable sets are guessed, and concrete
agreement is test evidence, never a proof. The whole manifest parses before
any binary is read, so malformed selections never produce partial reports.
Each selected executable is read exactly once into an immutable snapshot;
the loaded image, its published file fingerprint and the post-execution
stability digest all derive from those same bytes, so a transient mid-run
change cannot slip an altered image past the mutation check.

"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from tools.dosunit.model import DosUnitError, load_json, write_json

if TYPE_CHECKING:
    from tools.dosunit.real16_replay_manifest import Real16Manifest
    from tools.dosunit.real16_replay_model import LinearRange, Real16Image


def add_replay16_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register a segmented concrete execution lane for dosunit."""
    parser = subparsers.add_parser(
        "replay-real16",
        help="Execute declared segmented vectors on both MZ binaries; test evidence only",
    )
    parser.add_argument("--oracle-exe", required=True, type=Path)
    parser.add_argument("--candidate-exe", required=True, type=Path)
    parser.add_argument("--vectors", required=True, type=Path)
    parser.add_argument("--instruction-limit", type=int, default=100000)
    parser.add_argument("--out", required=True, type=Path)
    parser.set_defaults(func=cmd_replay_real16)


def _read_bytes(path: Path, what: str) -> bytes:
    """Read input bytes, carrying the filesystem cause into DosUnitError."""
    try:
        return path.read_bytes()
    except OSError as error:
        raise DosUnitError(f"real16 replay cannot read {what} {path}: {error}") from error


def _manifest(path: Path) -> Real16Manifest:
    """Load and fully check the vector selection before any execution."""
    from tools.dosunit.real16_replay_manifest import parse_manifest

    try:
        document = load_json(path)
    except OSError as error:
        raise DosUnitError(f"real16 replay cannot read vectors {path}: {error}") from error
    return parse_manifest(document)


def _image(
    data: bytes,
    path: Path,
    load_segment: int,
    code_ranges: tuple[LinearRange, ...] | None,
) -> Real16Image:
    """Relocate one snapshotted MZ executable under the declared segment/ranges.

    ``data`` must be the single snapshot read of ``path``; ``path`` is kept
    only so load failures name the input file in their error cause.
    """
    from tools.dosunit.real16_mz_load import image_from_mz_bytes

    try:
        return image_from_mz_bytes(
            data,
            load_segment=load_segment,
            code_ranges=code_ranges or (),
        )
    except ValueError as error:
        raise DosUnitError(f"real16 replay cannot load {path}: {error}") from error


def cmd_replay_real16(args: argparse.Namespace) -> int:
    """Run the selected vectors and return 0/1/2 for agreement/mismatch/gaps."""
    try:
        from tools.dosunit.real16_replay import compare_executions, replay
        from tools.dosunit.real16_replay_model import (
            DEFAULT_OBSERVABLES,
            Real16Agreement,
            Real16ReplayPolicy,
        )
        from tools.dosunit.real16_replay_report import (
            Real16ReplayRow,
            replay16_report_document,
        )
    except ImportError as error:
        raise DosUnitError(f"real16 execution backend unavailable: {error}") from error
    if args.instruction_limit <= 0:
        raise DosUnitError("real16 instruction limit must be positive")
    manifest = _manifest(args.vectors)
    paths: tuple[Path, Path] = (args.oracle_exe, args.candidate_exe)
    snapshots = tuple(_read_bytes(path, "binary") for path in paths)
    images = (
        _image(snapshots[0], paths[0], manifest.oracle_load_segment, manifest.oracle_code_ranges),
        _image(snapshots[1], paths[1], manifest.candidate_load_segment, manifest.candidate_code_ranges),
    )
    # The image's file fingerprint is the authoritative digest of the exact
    # bytes that were relocated and will be executed; the post-run check
    # verifies the on-disk files still hash to it.
    digests = (images[0].file_sha256, images[1].file_sha256)
    policy = Real16ReplayPolicy()
    rows: list[Real16ReplayRow] = []
    agreements: list[Real16Agreement] = []
    for selected in manifest.vectors:
        try:
            left = replay(
                images[0], selected.oracle_entry, selected.vector,
                policy=policy, instruction_limit=args.instruction_limit,
            )
            right = replay(
                images[1], selected.candidate_entry, selected.vector,
                policy=policy, instruction_limit=args.instruction_limit,
            )
            comparison = compare_executions(
                left, right,
                observables=(
                    selected.observables
                    if selected.observables is not None
                    else DEFAULT_OBSERVABLES
                ),
            )
        except ValueError as error:
            raise DosUnitError(f"vector {selected.vector_id}: {error}") from error
        agreements.append(comparison.agreement)
        rows.append(Real16ReplayRow(
            selected.vector_id, comparison, left, right,
            selected.vector, selected.oracle_entry, selected.candidate_entry,
            declared_observables=selected.observables is not None,
        ))
    if any(
        hashlib.sha256(_read_bytes(path, "binary")).hexdigest() != digest
        for path, digest in zip(paths, digests, strict=True)
    ):
        raise DosUnitError("binary changed during real16 replay")
    document_out = replay16_report_document(
        oracle_path=paths[0],
        candidate_path=paths[1],
        oracle_image=images[0],
        candidate_image=images[1],
        rows=rows,
        policy=policy,
        instruction_limit=args.instruction_limit,
    )
    try:
        write_json(args.out, document_out)
    except OSError as error:
        raise DosUnitError(f"real16 replay cannot write report {args.out}: {error}") from error
    if all(agreement is Real16Agreement.AGREED for agreement in agreements):
        return 0
    if any(agreement is Real16Agreement.MISMATCHED for agreement in agreements):
        return 1
    return 2
