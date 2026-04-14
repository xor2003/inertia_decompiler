# Inertia Decompiler

Inertia is an angr-based decompiler workspace focused on 16-bit x86 real-mode binaries.

Project priorities:

- correctness first
- readability second
- recompilable output where practical

This repo is not aiming to be a source-shaped transpiler. When evidence is weak, it prefers explicit low-level C, visible assumptions, and honest fallback modes.

## Killer Features

- **Real-mode x86 support in angr**: in-tree `x86-16` arch, lifter, SimOS, DOS MZ loader, and DOS NE loader
- **Decompiler CLI that works on real DOS inputs**: whole-binary or single-function recovery from `.COM`, `.EXE`, raw blobs, and `.COD`
- **Sidecar-aware recovery**: `.COD`, `.LST`, `.MAP`, CodeView, and TDINFO metadata improve labels, ranges, and emitted C
- **Evidence-backed fallback modes**: timeouts and lift failures stay visible instead of being silently replaced with guessed output
- **Peer-EXE catalog borrowing**: sibling executables can donate labels only when function bytes match exactly across the full claimed span
- **Library signature support**: import `.pat`, OMF `.obj`, and OMF `.lib` into a deduplicated PAT catalog
- **Tail validation**: semantic checks on late pipeline output instead of trusting cleanup blindly
- **Batch corpus tooling**: decompile whole `.COD` trees into sibling `.dec` outputs with bounded workers and validation baselines
- **Integrated debugger utilities**: angr-backed DOS debugging through GDB RSP and a Textual TUI

## Supported inputs

### Executables and blobs

| Input | Status | Notes |
|---|---|---|
| `.COM` | supported | blob-loaded with DOS SimOS |
| `.EXE` DOS MZ | supported | in-tree loader with relocations |
| `.EXE` 16-bit NE | smoke-level supported | loaded through `dos_ne` backend |
| `.BIN` / `.RAW` | supported | blob loading |
| `.COD` | supported | can be loaded as a blob or sliced by `--proc` |

### Metadata and symbol sources

| Source | Usage |
|---|---|
| `.COD` listings | procedure slicing, local naming, source-backed annotations |
| `.LST` listings | labels, ranges, segment-aware metadata |
| `.MAP` files | code/data layout and public symbol recovery |
| CodeView NB00 / NB02 / NB04 | symbol/type/debug metadata when embedded |
| TDINFO | Borland/Turbo Debugger symbol metadata |
| `.pat` / OMF `.obj` / OMF `.lib` | library signature matching via deduplicated PAT catalogs |
| peer `.EXE` siblings | exact-match catalog borrowing, reported as `peer_exe` evidence |

## CLI

The main entrypoints are:

- `./decompile.py`
- `python -m inertia_decompiler.cli`
- installed script: `decompile-x86-16`

`decompile.py` re-execs into `./.venv/bin/python` when that virtualenv exists, so local runs stay on the repo interpreter by default.

Basic usage:

```bash
./decompile.py examples/snake.EXE
./decompile.py angr_platforms/x16_samples/ICOMDO.COM
./decompile.py examples/BENCHMUL.BIN --blob --base-addr 0x1000 --entry-point 0x1000
./decompile.py LIFE.EXE --addr 0x11423 --timeout 30
./decompile.py cod/DOSFUNC.COD --proc _dos_free --proc-kind NEAR --timeout 10
```

Current CLI options:

- `--addr` decompile one function by address
- `--blob` force blob loading
- `--base-addr` and `--entry-point` control blob/COM layout
- `--show-asm` print the first lifted block before C
- `--proc` and `--proc-kind` extract one procedure from a `.COD`
- `--timeout` bound analysis time
- `--window` bound CFG recovery near a target address
- `--max-memory-mb` set a best-effort address-space cap
- `--max-functions` cap whole-binary output volume
- `--api-style` choose helper naming style: `modern`, `dos`, `raw`, `pseudo`, `service`, `msc`, `compiler`
- `--pat-backend` choose PAT matcher backend: `hyperscan` or `python_regex`
- `--signature-catalog` load a deduplicated PAT catalog

## Output model

The x86-16 recovery pipeline is organized around:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

Control-flow structuring and confidence/assumption reporting are explicit parts of the current pipeline, not late cosmetic cleanup.

When recovery fails or times out, the CLI reports that directly and may emit one of several evidence-backed fallbacks, including:

- partial-timeout C
- sidecar-slice C
- peer-sidecar C
- trivial sidecar C
- non-optimized fallback C
- string-intrinsic fallback C
- assembly fallback
- lift-break probes

Tail-validation summaries are emitted for semantic guardrails instead of treating late-stage rewrites as automatically trusted.

## Install

The repo is tested against the angr stack pinned in [pyproject.toml](/home/xor/vextest/pyproject.toml).

Recommended local setup:

```bash
git submodule update --init --recursive
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
python -m pip install -e ".[test]"
```

If you are working on the in-tree `angr_platforms` package directly, reinstall after submodule updates so the root environment and editable package stay aligned.

## Signature catalogs

To build one deduplicated PAT catalog from `.pat`, `.obj`, and `.lib` inputs:

```bash
python scripts/build_signature_catalog.py signature_catalogs/ QLINK/ --output signature_catalogs/local.pat
```

That catalog can then be used during decompilation:

```bash
./decompile.py your_binary.exe --signature-catalog signature_catalogs/local.pat
```

## Batch `.COD` runs

To decompile a whole `.COD` corpus into sibling `.dec` files:

```bash
python scripts/decompile_cod_dir.py cod --timeout 20 --max-memory-mb 1024
```

Useful filters:

- `--cod-file <name-or-path>` limit to one or more listings
- `--proc-name <name>` limit to one or more procedures
- `--skip-existing` avoid overwriting existing `.dec`
- `--write-tail-validation-baseline` persist the current changed-set baseline

## Sample corpus

The repo includes a small x86-16 corpus under [angr_platforms/x16_samples/README.md](/home/xor/vextest/angr_platforms/x16_samples/README.md).

Typical sample flow:

```bash
./angr_platforms/scripts/build_x16_samples.sh
./.venv/bin/python -m pytest -q angr_platforms/tests/test_x86_16_sample_matrix.py
./decompile.py angr_platforms/x16_samples/IMOD.EXE
./decompile.py angr_platforms/x16_samples/IMOD.COD --proc _main
```

## Debugging tools

The repo also carries debugger utilities built around angr simulation, GDB RSP, and Textual:

```bash
python -m inertia_decompiler.debug_dos LIFE.EXE --port 1234
python -m inertia_decompiler.gdb_tui --host 127.0.0.1 --port 1234 --arch x86_16
```

## Layout

Main code:

- [inertia_decompiler/cli.py](/home/xor/vextest/inertia_decompiler/cli.py): root decompiler CLI
- [inertia_decompiler/project_loading.py](/home/xor/vextest/inertia_decompiler/project_loading.py): loader selection, blob setup, packed-EXE handling
- [inertia_decompiler/sidecar_metadata.py](/home/xor/vextest/inertia_decompiler/sidecar_metadata.py): sidecar/debug metadata loading
- [inertia_decompiler/tail_validation.py](/home/xor/vextest/inertia_decompiler/tail_validation.py): validation routing and reporting
- [angr_platforms/angr_platforms/X86_16](/home/xor/vextest/angr_platforms/angr_platforms/X86_16): x86-16 platform, loaders, and analysis support

## Focused tests

Good starting points:

```bash
./.venv/bin/python -m pytest -q \
  angr_platforms/tests/test_x86_16_smoketest.py \
  angr_platforms/tests/test_x86_16_cli.py \
  angr_platforms/tests/test_x86_16_cod_samples.py \
  angr_platforms/tests/test_x86_16_dos_mz_loader.py \
  angr_platforms/tests/test_x86_16_dos_ne_loader.py \
  angr_platforms/tests/test_x86_16_sample_matrix.py \
  angr_platforms/tests/test_x86_16_tail_validation.py
```

For wider x86-16 coverage, the test suite also includes dedicated files for structuring, aliasing, widening, segmented memory, string instructions, recovery artifacts, helper modeling, confidence reporting, corpus scans, and validation manifests under [angr_platforms/tests](/home/xor/vextest/angr_platforms/tests).
