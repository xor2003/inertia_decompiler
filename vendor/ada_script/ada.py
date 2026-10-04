#!/usr/bin/env python3
"""
Ada Script: Full Binary Analysis Pipeline
Integrates MZ parsing, IDC application, emulation analysis, and output generation (.lst/.asm).
Flags drive optional steps: --full (functions/CFG), --classify (entropy-based), --xrefs (cross-refs).
"""

import argparse
import logging
import sys
from pathlib import Path

from analysis_backend import AnalysisOptions
from idc_engine import parse_idc

# Module imports for pipeline
from mz_parser import MZParser
from output_generator import OutputGenerator


def main():
    parser = argparse.ArgumentParser(description="Full Binary Analysis Pipeline.")
    parser.add_argument("binary", nargs='?', help="Path to binary file (e.g., .exe)")
    parser.add_argument("-s", "--idc-script", help="IDC script to apply")
    parser.add_argument("-r", "--runtime",
                        help="libdosbox run-time info .json (execution coverage, "
                             "segment values, data accesses)")
    parser.add_argument("-o", "--output", default="analysis.md", help="MD report (default: analysis.md)")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    parser.add_argument("--full", action="store_true", help="Full analysis (functions, CFG)")
    parser.add_argument("--classify", action="store_true", help="Classify code/data")
    parser.add_argument("--xrefs", action="store_true", help="Compute cross-references")
    parser.add_argument(
        "--backend",
        choices=["capstone", "rizin"],
        default="capstone",
        help="Disassembly/analysis backend (default: capstone)",
    )
    parser.add_argument('--version', action='version', version='%(prog)s 0.1.0')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.binary is None:
        parser.print_help()
        sys.exit(1)

    binary_path = Path(args.binary)
    if not binary_path.exists():
        logging.error(f"Binary not found: {binary_path}")
        sys.exit(1)

    logging.info(f"Starting analysis of {binary_path.name} (debug: {args.debug})")

    try:
        # Load binary
        with open(binary_path, 'rb') as f:
            binary = f.read()
        logging.info(f"Loaded binary: {binary_path.name} ({len(binary)} bytes)")

        # Step 1: MZ Parsing
        mz_parser = MZParser(binary)
        db = mz_parser.parse()
        db.binary = binary  # needed by analyzers/generator for byte reads
        logging.info("MZ parsing complete")

        # Step 2: Apply IDC (if provided) and insert to DB
        if args.idc_script:
            idc_path = Path(args.idc_script)
            if idc_path.exists():
                with open(idc_path, 'r') as f:
                    idc_content = f.read()
                script = parse_idc(idc_content, db, strict=args.debug)  # Strict if debug for better errors
                if script is None or (len(script.functions) == 0 and len(script.variables) == 0 and len(script.includes) == 0 and len(script.defines) == 0):
                    logging.error(f"IDC parse failed for {idc_path}: empty or None script")
                    sys.exit(1)
                logging.info(f"IDC applied: {script}")
                script.insert_to_db()
            else:
                logging.warning(f"IDC not found: {idc_path}")

        # Step 2b: Apply libdosbox run-time info (if provided)
        if args.runtime:
            rt_path = Path(args.runtime)
            if rt_path.exists():
                from runtime_info import load_runtime_json
                load_runtime_json(str(rt_path), db)
            else:
                logging.warning(f"Run-time info not found: {rt_path}")

        # Step 3: Analysis backend (disasm, classify, functions, xrefs)
        options = AnalysisOptions(full=args.full, classify=args.classify, xrefs=args.xrefs)
        if args.backend == "rizin":
            from rizin_backend import RizinBackend
            analyzer = RizinBackend(binary, db, options)
        else:
            # without IDC info, try rizin procedure discovery first
            nfuncs = db.conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
            if nfuncs == 0:
                try:
                    from rizin_backend import discover_functions
                    discover_functions(binary, db)
                except Exception as exc:
                    logging.info(f"Rizin discovery unavailable ({exc}); "
                                 "falling back to capstone recursive descent")
            from capstone_backend import CapstoneBackend
            analyzer = CapstoneBackend(binary, db, options)
        analyzer.analyze()

        # Step 4: Generate Outputs
        generator = OutputGenerator(db, binary_path.name)
        stem = binary_path.stem
        lst_file = f"{stem}.lst"
        generator.generate_lst(lst_file)

        # Generate .asm (label-aware, same rendering as lst)
        asm_file = f"{stem}.asm"
        generator.generate_asm(asm_file)

        # Step 5: MD Report (query DB)
        conn = db.conn
        num_insts = conn.execute("SELECT COUNT(*) FROM instructions").fetchone()[0]
        num_funcs = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
        coverage = conn.execute("SELECT value FROM stats WHERE key='code_coverage'").fetchone()
        coverage = coverage[0] if coverage else 0
        funcs = conn.execute("SELECT start, name FROM functions LIMIT 10").fetchall()
        comments = conn.execute("SELECT addr, comment FROM comments LIMIT 5").fetchall()

        with open(args.output, "w") as f:
            f.write("# Binary Analysis Report\n")
            f.write(f"## File: {binary_path.name} ({len(binary)} bytes)\n")
            f.write("### Summary\n")
            f.write(f"- Instructions: {num_insts}\n")
            f.write(f"- Functions: {num_funcs}\n")
            f.write(f"- Coverage: {coverage:.1f}%\n")
            f.write("### Functions (Top 10)\n")
            f.writelines(f"- {hex(start)}: {name}\n" for start, name in funcs)
            f.write("### Comments (Top 5)\n")
            f.writelines(f"- {hex(addr)}: {text}\n" for addr, text in comments)
            f.write(f"### Outputs\n- LST: {lst_file}\n- ASM: {asm_file}\n")

        logging.info(f"Pipeline complete. MD: {args.output}, LST: {lst_file}, ASM: {asm_file}")

    except Exception:
        logging.exception("Pipeline failed")
        sys.exit(1)
    finally:
        if 'db' in locals():
            db.close()

if __name__ == "__main__":
    main()
