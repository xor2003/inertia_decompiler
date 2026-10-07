"""Layer: optional disassembly CLI.

Responsibility: run the imported ada_script pipeline with shared library naming
and isolated output, retaining raw signature provenance before ASM/LST rendering.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
from enum import StrEnum
from pathlib import Path

from inertia.cli.default_signature_catalog import default_signature_catalog_path
from tools.ada_script.contracts import DatabaseView
from tools.ada_script.map_writer import write_map
from tools.ada_script.signatures import apply_signatures

LOGGER: logging.Logger = logging.getLogger(__name__)


class AsmCodeEncoding(StrEnum):
    """Select exact original instruction bytes or readable mnemonic rendering."""

    EXACT = "exact"
    MNEMONIC = "mnemonic"


def build_parser() -> argparse.ArgumentParser:
    """Preserve standalone options and add explicit catalog/output controls."""
    parser = argparse.ArgumentParser(description="Ada Script: annotated DOS disassembly with Inertia library signatures")
    parser.add_argument("binary", type=Path)
    parser.add_argument("-s", "--idc-script", type=Path)
    parser.add_argument("-r", "--runtime", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("analysis.md"))
    parser.add_argument("--work-dir", type=Path, default=Path.cwd())
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--classify", action="store_true")
    parser.add_argument("--xrefs", action="store_true")
    parser.add_argument("--backend", choices=("capstone", "rizin"), default="capstone")
    parser.add_argument("--asm-code-encoding", type=AsmCodeEncoding,
                        choices=tuple(AsmCodeEncoding), default=AsmCodeEncoding.EXACT,
                        help="exact preserves original instruction encodings; mnemonic favors readable code "
                             "and may not assemble or reproduce the original bytes")
    parser.add_argument("--signature-catalog", type=Path, action="append", default=[],
                        help="PAT catalog; repeat to combine. Default: Inertia's repository library catalog")
    parser.add_argument("--no-signatures", action="store_true")
    parser.add_argument("--pat-backend", choices=("python_regex", "hyperscan", "auto"), default="python_regex")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0+inertia")
    return parser


def _apply_inputs(args: argparse.Namespace, db: DatabaseView) -> None:
    """Apply upstream IDC and runtime inputs before proposing signature names."""
    if args.idc_script is not None:
        try:
            from tools.ada_script.idc_engine import parse_idc

            script = parse_idc(args.idc_script.read_text(), db, strict=True)
        except SyntaxError as exc:
            raise ValueError(f"IDC parse failed: {args.idc_script}") from exc
        if script is None:
            raise ValueError(f"IDC parse failed: {args.idc_script}")
        script.insert_to_db()
    if args.runtime is not None:
        trace = json.loads(args.runtime.read_text())
        meta = trace.get("Meta") if isinstance(trace, dict) else None
        load_segment = meta.get("DosboxLoadSeg") if isinstance(meta, dict) else None
        if type(load_segment) is not int or not 0 <= load_segment <= 0xFFFF:
            raise ValueError(f"Runtime trace requires Meta.DosboxLoadSeg: {args.runtime}")
        from tools.ada_script.runtime_info import load_runtime_json

        load_runtime_json(str(args.runtime), db)


def _catalogs(args: argparse.Namespace) -> tuple[Path, ...]:
    """Explicit catalogs override automatic library discovery; disable wins."""
    if args.no_signatures:
        return ()
    if args.signature_catalog:
        return tuple(args.signature_catalog)
    default = default_signature_catalog_path()
    return () if default is None else (default,)


def _require_dos_mz_image(binary: bytes) -> None:
    """Refuse extended payloads whose MZ bytes are only a launcher stub."""
    if binary[:2] != b"MZ":
        raise ValueError("Ada Script requires a DOS MZ executable")
    if len(binary) < 64:
        return
    payload_offset = int.from_bytes(binary[0x3C:0x40], "little")
    if 64 <= payload_offset <= len(binary) - 4:
        signature = binary[payload_offset:payload_offset + 4]
        if signature == b"PE\0\0" or signature[:2] in {b"NE", b"LE", b"LX"}:
            raise ValueError(f"Unsupported extended executable format at {payload_offset:#x}")


def _run_pipeline(args: argparse.Namespace) -> None:
    """Run the qualified ADA analyzer modules with optional backend dependencies."""
    from tools.ada_script.analysis_backend import AnalysisOptions
    from tools.ada_script.mz_parser import MZParser
    from tools.ada_script.output_generator import OutputGenerator

    binary = args.binary.read_bytes()
    _require_dos_mz_image(binary)
    db: DatabaseView = MZParser(binary).parse()
    try:
        db.binary = binary
        _apply_inputs(args, db)
        report = apply_signatures(db.conn, image=binary[db.header_size:db.header_size + db.image_size],
                                  base=db.image_base, catalogs=_catalogs(args),
                                  cache_dir=args.work_dir / "signature-cache", backend=args.pat_backend,
                                  enabled=not args.no_signatures)
        report.write(args.work_dir / "signatures.json")
        options = AnalysisOptions(args.full, args.classify, args.xrefs)
        if args.backend == "capstone":
            from tools.ada_script.capstone_backend import CapstoneBackend

            analyzer = CapstoneBackend(binary, db, options)
        else:
            from tools.ada_script.rizin_backend import RizinBackend

            analyzer = RizinBackend(binary, db, options)
        analyzer.analyze()
        generator = OutputGenerator(db, args.binary.name)
        generator.generate_lst(str(args.work_dir / f"{args.binary.stem}.lst"))
        generator.generate_asm(str(args.work_dir / f"{args.binary.stem}.asm"),
                               exact_code_bytes=args.asm_code_encoding is AsmCodeEncoding.EXACT)
        routine_count = write_map(db, args.work_dir / f"{args.binary.stem}.map")
        LOGGER.info("MAP written: %s (%d routines)", args.work_dir / f"{args.binary.stem}.map",
                    routine_count)
        counts = {table: db.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in ("instructions", "functions")}
        args.output.write_text(f"# Ada Script: {args.binary.name}\n\n"
                               f"Instructions: {counts['instructions']}\n\nFunctions: {counts['functions']}\n\n"
                               f"Library names applied: {report.named_count}; conflicts: {report.failure_count}.\n\n"
                               "Signature evidence: signatures.json and analysis.db/signature_matches.\n")
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    """Run in an explicit workdir; preserve causes of genuine pipeline errors."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    args.binary = args.binary.resolve()
    if not args.binary.is_file():
        LOGGER.error("Binary not found: %s", args.binary)
        return 1
    args.work_dir = args.work_dir.resolve()
    args.signature_catalog = [path.resolve() for path in args.signature_catalog]
    args.idc_script = None if args.idc_script is None else args.idc_script.resolve()
    args.runtime = None if args.runtime is None else args.runtime.resolve()
    args.output = args.output if args.output.is_absolute() else args.work_dir / args.output
    args.work_dir.mkdir(parents=True, exist_ok=True)
    previous = Path.cwd()
    try:
        os.chdir(args.work_dir)
        _run_pipeline(args)
    except (OSError, ValueError, sqlite3.Error):
        LOGGER.exception("Ada Script pipeline failed")
        return 1
    finally:
        os.chdir(previous)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
