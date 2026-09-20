# Inertia Decompiler

Inertia Decompiler is a toolchain for decompiling and comparing 16-bit and
32-bit real-mode DOS programs. It supports the DOS segmented-memory model and
processes real-mode `.EXE`, `.COM`, and assembly listings from DOS-era
toolchains.

Inertia Decompiler uses a dual-license model. Community use is available under
the GNU Affero General Public License, version 3 or any later version. A separate
commercial license is available for organizations that need rights outside the
AGPL's conditions. See [License](#license).

Correctness comes before pretty C. When evidence is weak, the tools prefer low-level output, visible refusals, or explicit fallback reports over guessed source.

## Why Inertia For DOS

Inertia focuses on the results that matter when restoring a DOS program:

- **More of the program becomes C.** The goal is to recover every function
  instead of silently omitting difficult functions or leaving most of the
  program as an assembly listing.
- **The C is checked against the executable.** Recovered conditions, calls,
  return values, and memory changes are validated. Code that looks cleaner but
  changes the program's behavior is rejected.
- **The output is intended to compile.** Inertia can generate portable C or C
  suitable for Microsoft C on DOS. It checks for common decompiler failures such
  as wrong function arguments, incompatible pointer types, missing declarations,
  and invalid assignments.
- **The output is easier to understand.** Proven stack locations become
  arguments and local variables, branches become meaningful conditions, and
  repeated memory layouts can become arrays or structures. When a readable
  interpretation cannot be proved, Inertia keeps a lower-level representation
  instead of inventing one.
- **Stripped executables are first-class inputs.** Debug files and original
  source are not required. When old `.COD`, `.LST`, `.MAP`, CodeView, or TDInfo
  files are available, they can restore useful names and source locations.
- **Library code creates less noise.** Signatures from old DOS compilers,
  object files, and libraries help identify runtime and library functions so the
  report stays focused on the program's own code.
- **You can test whether a rebuild still behaves like the original.** Included
  comparison tools can run both versions and compare function results, changed
  memory, and other externally visible behavior.
- **Uncertain output is clearly marked.** Timeouts, incomplete recovery, failed
  validation, and fallback output remain visible. A plausible-looking function
  is not presented as trustworthy C without supporting evidence.

No decompiler can reconstruct every original name, type, or source construct
from machine code. Inertia is designed for cases where complete, recompilable,
behaviorally checked C is more useful than attractive but unverified pseudocode.

## Install

PKLITE-packed MZ inputs use the optional native [Deark](https://github.com/jsummers/deark)
decoder (`deark` on PATH or `INERTIA_DEARK_PATH`). Function catalog recovery has
its own `--catalog-timeout` budget, defaulting to 60 seconds. See
[catalog, unpacking and DOS-tool setup](reference/pr1-adoption.md) for limitations
and installation hints. Required compiler checks are not silently skipped.

The repo is tested against the angr stack pinned in [pyproject.toml](pyproject.toml).

```bash
git submodule update --init --recursive
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
python -m pip install -e ".[test]"
```

The root `./decompile.py` wrapper re-execs through `./.venv/bin/python` when that virtualenv exists.

## Decompile

Main entry points:

- `./decompile.py`
- `python -m inertia_decompiler.cli`
- installed script: `decompile-x86-16`

Common runs:

```bash
./decompile.py PROGRAM.EXE
./decompile.py PROGRAM.COM
./decompile.py PROGRAM.EXE --addr 0x11423 --timeout 30
./decompile.py LISTING.COD --proc _main --proc-kind NEAR
./decompile.py blob.bin --blob --base-addr 0x1000 --entry-point 0x1000
```

Useful options:

- `--addr ADDR`: decompile one function by linear address.
- `--proc NAME`: extract one procedure from a `.COD` listing.
- `--max-functions N`: cap whole-binary output.
- `--timeout SEC`: bound analysis for a function or run.
- `--window BYTES`: bound CFG recovery around a target address.
- `--c-target portable-flat|msc-dos`: choose generated C target helpers.
- `--api-style modern|dos|raw|pseudo|service|msc|compiler`: choose helper naming style.
- `--show-asm`: print the first lifted block before C.
- `--trace-c-stages`: print labeled generated-C snapshots.
- `--dump-layers --dump-layer-dir DIR`: write per-stage C artifacts.
- `--function-discovery-backend auto|angr|rizin|hybrid`: choose whole-binary discovery.
- `--signature-catalog PATH`: apply a PAT catalog built from `.pat`, `.obj`, and `.lib`.
- `-q` or `INERTIA_BRIEF=1`: reduce progress and diagnostics.

Tail validation can be enabled for decompiler correctness checks:

```bash
INERTIA_ENABLE_TAIL_VALIDATION=1 ./decompile.py SORTDEMO.EXE
```

When a run is slow, capture compact telemetry:

```bash
INERTIA_OTEL_SPANS=1 \
INERTIA_OTEL_SPAN_FILE=angr_platforms/.cache/otel.trace.txt \
./decompile.py PROGRAM.EXE --addr 0x11423
```

See [reference/telemetry.md](reference/telemetry.md) for trace formats and OTLP export.

## Inputs And Sidecars

Supported executable inputs:

- `.COM`
- DOS MZ `.EXE`
- 16-bit NE `.EXE` at smoke level
- `.BIN` / `.RAW` blobs
- `.COD` listings as direct procedure inputs

Metadata sidecars are optional but useful:

- `.COD` and `.LST`: procedure ranges, labels, local names, and source-backed hints.
- `.MAP`: public symbols and layout.
- CodeView NB00/NB02/NB04/NB08/NB09: debug names, procedures, stack variables, source files, line maps, type names, and member records where supported.
- TDInfo: Borland/Turbo Debugger symbols, stack/register/constant symbols, compact type descriptors, structs, unions, and enums.
- `.pat`, `.obj`, `.lib`: library signature matching.

Inspect embedded debug metadata directly:

```bash
./dump_debug_info.py PROGRAM.EXE
```

More format detail lives in [CODEVIEW_SUPPORT.md](CODEVIEW_SUPPORT.md), [DOS_COMPILER_SUPPORT.md](DOS_COMPILER_SUPPORT.md), [NE_WIN16_SUPPORT.md](NE_WIN16_SUPPORT.md), and [NE_LOADER_INTEGRATION_VERIFIED.md](NE_LOADER_INTEGRATION_VERIFIED.md).

## 80386 Real-Mode Frontend

The x86-16 frontend supports i386 programs running in real mode, including
32-bit general-purpose registers, FS and GS, and 32-bit operand and address
forms. Memory retains the DOS segmented model: segment registers select distinct
address spaces and 16-bit or 32-bit offsets are interpreted within the active
segment.

## Signature Catalogs

Build one deduplicated catalog from FLAIR `.pat`, OMF `.obj`, and OMF `.lib` inputs:

```bash
python scripts/build_signature_catalog.py signature_catalogs/ QLINK/ \
  --output signature_catalogs/local.pat
```

Use it during decompilation:

```bash
./decompile.py PROGRAM.EXE --signature-catalog signature_catalogs/local.pat
```

Build a shareable all-compilers bundle when the local compiler archive exists:

```bash
python scripts/build_compiler_catalog_bundle.py
```

Report likely compiler/runtime matches for a binary:

```bash
python scripts/report_compiler_matches.py PROGRAM.EXE \
  --catalog signature_catalogs/all_compilers_catalog_bundle.zip
```

Add `--compilers-only` for a short ranked compiler list.

## MS C Compiler And Flag Diagnostics

The compiler matcher can also score likely Microsoft C 5.1 flag combinations when profile data is available:

```bash
python scripts/build_msc51_flag_profiles.py \
  --cod-dir deep \
  --output signature_catalogs/msc51_flag_profiles.json

python scripts/report_compiler_matches.py PROGRAM.EXE \
  --catalog signature_catalogs/all_compilers_catalog_bundle.zip \
  --detect-flags-msc51 \
  --msc51-flag-profiles signature_catalogs/msc51_flag_profiles.json
```

The decompiler also has an internal MS C 5.1 local-variable hash diagnostic. It checks whether recovered local names and BP offsets fit the compiler's 16-bucket allocation pattern; this is used as evidence, not as a source of guessed names.

## Z3 Function Comparator

`./z3func.py` is the main static and concrete function-comparison tool. `./dosunit.py` exposes the same flow for compatibility.

Typical static SSA comparison:

```bash
./z3func.py discover --exe original.exe --map original.map --out /tmp/orig.functions.json
./z3func.py discover --exe rebuilt.exe --map rebuilt.map --out /tmp/rebuilt.functions.json

./z3func.py make-mapping \
  --oracle-functions /tmp/orig.functions.json \
  --candidate-functions /tmp/rebuilt.functions.json \
  --out /tmp/mapping.json

./z3func.py ssa \
  --exe original.exe \
  --functions /tmp/orig.functions.json \
  --cache-dir .cache/dosunit \
  --out /tmp/orig.ssa.json

./z3func.py ssa \
  --exe rebuilt.exe \
  --functions /tmp/rebuilt.functions.json \
  --cache-dir .cache/dosunit \
  --out /tmp/rebuilt.ssa.json

./z3func.py compare-ssa \
  --oracle-ssa /tmp/orig.ssa.json \
  --candidate-ssa /tmp/rebuilt.ssa.json \
  --mapping /tmp/mapping.json \
  --out /tmp/ssa.results.json

./z3func.py report-failures \
  --results /tmp/ssa.results.json \
  --out /tmp/ssa.failures.md
```

For large programs, prefer the batched comparator:

```bash
./z3func.py compare-ssa-batched \
  --oracle-ssa /tmp/orig.ssa.json \
  --candidate-ssa /tmp/rebuilt.ssa.json \
  --oracle-index-ssa /tmp/orig.ssa.json \
  --candidate-index-ssa /tmp/rebuilt.ssa.json \
  --mapping /tmp/mapping.json \
  --out-dir /tmp/ssa-batches \
  --out /tmp/ssa-batches/aggregate.json
```

Other useful comparator subcommands:

- `complexity`: classify which functions are good bounded-Z3 targets.
- `regions` / `compare-regions`: compare lifter-backed operand/effect summaries.
- `compare-ssa-abi`: prove ABI-visible equivalence from an ABI manifest.
- `gen-vectors`, `record-oracle`, `compare`: concrete-vector comparison through the runtime backend.
- `compare-data`: compare loaded MZ data ranges after relocation.
- `summarize`: print result rollups.

## Debugger

Start an angr-backed DOS GDB remote server:

```bash
python -m inertia_decompiler.debug_dos PROGRAM.EXE --host 127.0.0.1 --port 1234
```

Connect with the Textual TUI:

```bash
python -m inertia_decompiler.gdb_tui --host 127.0.0.1 --port 1234 --arch x86_16
```

The debugger exposes 16-bit registers, segment registers, flags, memory, breakpoints, and stepping through the GDB remote protocol.

## Batch And Corpus Tools

Decompile a `.COD` corpus into sibling `.dec` files:

```bash
python scripts/decompile_cod_dir.py cod --timeout 20 --max-memory-mb 1024
```

Useful filters include `--cod-file`, `--proc-name`, `--skip-existing`, and `--write-tail-validation-baseline`.

Compare discovery engines:

```bash
python scripts/compare_discovery_backends.py PROGRAM.EXE \
  --backends all \
  --json-output /tmp/discovery.json
```

Run the legacy curated check (full validation package):

```bash
make decompiler-check PYTHON=./.venv/bin/python
```

For routine development work, use the hard gate:

```bash
make quality-dev PYTHON=./.venv/bin/python
```

Run the MS C tiny pipeline examples:

```bash
make test-pipeline PYTHON=./.venv/bin/python
```

Optional native speedups are available for selected pure-Python modules:

```bash
python -m pip install ".[mypyc]"
python scripts/build_mypyc.py build_ext --inplace
```

If `mypyc` is unavailable, normal `.py` execution is unchanged.

Optimization changes must not reduce semantic quality.
Use the quality gate before enabling any speed-up path:

```bash
make decomp-opt-regression-suite PYTHON=./.venv/bin/python
DECOMP_OPT_REGRESSION_ARGS="--max-functions 20 --timeout 45 -q" \
  make decomp-opt-regression-thread PYTHON=./.venv/bin/python
```

The gate compares pure-Python decompilation to the optimized path and fails unless:

- both runs validate (`validation=passed`)
- no functions are lost
- no quality metrics regress

## How It Works

### Decompiler

The core pipeline is:

```text
IR -> Alias -> Widening -> Types -> Structuring -> Rewrite
```

The frontend loads DOS real-mode programs through the in-tree x86-16 angr platform, loader, lifter, SimOS, and sidecar parsers. Recovery tries to prove storage identity first, then widen split byte/word values, recover typed memory and stack objects, structure control flow, and finally perform cleanup-only C rewrites.

Generated C targets either portable flat helpers or MS C DOS helpers. Segmented memory is represented through helpers such as `SEG_U8`, `SEG_U16`, `SEG_PTR`, and `MK_FP`; raw `(seg << 4) + off` arithmetic is an internal execution detail, not normal output.

Tail validation compares semantic effects after late-stage cleanup. Validation failures are reported as failures rather than silently converted into prettier C.

### Z3 Comparator

`z3func.py ssa` lifts bounded VEX or AIL regions into compact SSA. The comparator observes ABI-selected registers, stack effects, memory stores, direct control-flow successors, direct calls, and optional composed acyclic regions.

`compare-ssa` first applies cheap equivalence checks such as byte-identical code, compact-SSA equality, mapped direct-call targets, and proven region facts. It then asks Z3 for a counterexample where observable outputs differ. Unsupported helpers, hard guarded memory, oversized slices, symbolic loop paths beyond the bound, and unknown call effects become structured refusals.

`compare-ssa-batched` runs the same proof in child processes with full SSA indexes available for call-target lookup, keeping whole-program comparisons memory-bounded.

### Function Signatures

Function signature evidence comes from callsite materialization, stack-push recovery, sidecar/debug metadata, known helper/runtime models, library signature matches, and ABI manifests. The decompiler uses that evidence to distinguish near/far calls, stack arguments, register returns, preserved/clobbered registers, and pointer-vs-value argument classes.

When exact signatures are not proven, output should keep an honest fallback prototype instead of filling guessed arguments or rewriting call bodies late.

### `.OBJ` / `.LIB` Signature Parsing

The signature pipeline accepts existing FLAIR `.pat` files and Microsoft OMF `.obj` / `.lib` inputs.

For OMF inputs, the parser extracts module blobs, public names, fixup references, segment bytes, module lengths, tail bytes, source path, and compiler provenance. Each module is converted to PAT-style pattern data, then `signature_catalog.py` deduplicates modules by pattern bytes, length, public names, referenced names, and tail bytes.

At match time, the loaded binary image is scanned with either the portable Python regex backend or Hyperscan when available. Matches become code labels, code ranges, library-function classifications, and probable compiler names. Unsupported archive formats are detected defensively and skipped instead of crashing.

## Internal Contributor Notes

Contributor and agent-specific rules are intentionally not in this README. See [AGENTS.md](AGENTS.md), [reference/agent-rules.md](reference/agent-rules.md), [reference/decompiler-fix-plan.md](reference/decompiler-fix-plan.md), and the other files under [reference/](reference/).

## License

Original Inertia Decompiler code and documentation are available under either:

- the [GNU Affero General Public License v3.0 or later](LICENSE); or
- a separate written [commercial license](COMMERCIAL-LICENSE.md).

The AGPL permits commercial use. The separate commercial license is for users
who need additional proprietary-use rights or separately agreed support terms.

Third-party components, dependencies, test binaries, corpora, research
material, and other separately licensed content are not automatically covered
by either Inertia license. Review [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
before redistribution.

Contributions require the
[Inertia Decompiler Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md)
so the project can preserve both licensing options.
