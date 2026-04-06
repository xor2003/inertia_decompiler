# Inertia Decompiler

Inertia decompiler provides support for decompiling 16-bit x86 real mode binaries using the angr framework, with custom agents for architecture, lifting, and simulation.

## Project overview

Inertia is an angr-based decompiler focused on readable, evidence-driven C for real-mode x86 binaries.

The project priorities are:

- correctness first
- readability second
- recompilable output where practical

The project is not aiming to become a transpiler.

## Features

- **DOS MZ loader** — In-tree loader with relocation handling instead of treating every sample like a flat blob
- **DOS/BIOS interrupt modeling** — Turns `int 0x21` and friends into synthetic helper calls
- **Far-call-aware CFG** — Extended CFG analysis that stays narrow without losing obvious callees
- **COD and LST sidecar ingestion** — Names, procedure slicing, and evidence-backed annotations from compiler output
- **Confidence and assumption reporting** — Uncertain recovery is visible instead of hidden
- **Recompilable-subset ratchet** — Focus on producing output that can round-trip back to working code
- **Region-based structuring pipeline** — Loops, ifs, gotos, and future switch recovery
- **Corpus-first harnessing** — Regressions, bounded scans, and real-binary progress tracking
- **FLAIR pattern extraction** — Library function identification from `.lib` and `.obj` inputs
- **CodeView NB00 debug info** — Symbol and type recovery from CodeView debug sections
- **Turbo Debugger TDINFO parsing** — Symbol extraction from Borland debug formats
- **Peer-EXE catalog borrowing** — Exact byte-identical sibling executables can donate function catalogs when native sidecars are absent

## Supported Formats

### Binary formats

| Format | Description | Loading method |
|--------|-------------|----------------|
| `.COM` | DOS COM files (raw executable, loads at 0x100) | `backend="blob"` or `simos="DOS"` |
| `.EXE` | DOS MZ executables with relocations | DOS MZ loader |
| `.EXE` (NE) | 16-bit Windows New Executable files | DOS NE loader (smoke-level support) |
| `.BIN` | Raw binary blobs | `angr.load_shellcode()` |
| OMF `.OBJ` | Object Module Format object files | FLAIR pattern extraction |
| OMF `.LIB` | Object Module Format libraries | FLAIR pattern extraction |

### Sidecar/debug formats

| Format | Description | Usage |
|--------|-------------|-------|
| `.COD` | Microsoft compiler assembly listings | Procedure metadata, call names, source correlation |
| `.LST` | Assembler listing files | Labels, procedures, symbols, segments |
| CodeView NB00 | CodeView debug information | Symbol names, types, code/data classification |
| TDINFO | Turbo Debugger debug information | Symbol tables, code labels |
| `.MAP` | Linker map files | Segment ranges, symbol addresses |

### Architecture modes

| Mode | Status | Description |
|------|--------|-------------|
| Real mode (16-bit) | Supported | Primary target — full x86 real-mode semantics |
| Real mode (32-bit) | Planned | 32-bit operands and addressing in real mode (operand-size override) |
| Unreal mode | Planned | 32-bit segment limits via descriptor tricks while staying in real mode |
| MZ/NE | Smoke-level supported | New Executable format (16-bit Windows) |
| Protected mode (32-bit) | Not planned | Outside scope — focus is real-mode DOS |

## Why This Repo Is Interesting

This is not just "angr pointed at 16-bit DOS." The repo already contains several pieces that are unusual enough to be fun to work on:

- custom `x86-16` architecture, lifter, and `SimOS` support for real-mode binaries
- in-tree DOS MZ loader with relocation handling instead of treating every sample like a flat blob
- bounded recovery windows and timeout-aware fallback paths for scan-safe decompilation
- DOS and BIOS interrupt modeling that turns `int 0x21`/friends into synthetic helper calls
- far-call-aware CFG extension so recovery can stay narrow without losing obvious callees
- `COD` and `LST` sidecar ingestion for names, procedure slicing, and evidence-backed annotations
- exact-span peer executable matching so stripped sibling builds can reuse verified function catalogs without guessing
- explicit `confidence` and `assumption` reporting so uncertain recovery is visible instead of hidden
- a recompilable-subset ratchet, not just “pretty pseudocode”
- an in-progress region-based structuring pipeline for loops, ifs, gotos, and future switch recovery
- corpus-first harnessing for regressions, bounded scans, and real-binary progress tracking

If you like decompilers that try to be honest about segmented memory, calling conventions, and uncertain evidence, this codebase already has real architecture to extend.

## Decompiler Shape

The current x86-16 decompiler is organized around the recovery pipeline:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

Recent work made two parts explicit:

- `control-flow structuring` now has its own stage instead of living inside late cleanup.
- `confidence` and `assumption` reporting now travel through scan and milestone outputs so the decompiler can say what is recovered, what is uncertain, and what is still unresolved.

## x86-16 platform map

The main x86-16 implementation lives under [`angr_platforms/angr_platforms/X86_16`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16).

Key modules:

- Arch: [`arch_86_16.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/arch_86_16.py)
- Lifter: [`lift_86_16.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lift_86_16.py)
- Instructions: [`instr_base.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/instr_base.py), [`instr16.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/instr16.py)
- Runtime/core: [`emulator.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/emulator.py), [`processor.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/processor.py)
- SimOS: [`simos_86_16.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/simos_86_16.py)
- Hardware helpers: [`memory.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/memory.py), [`io.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/io.py), [`interrupt.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/interrupt.py)

AIL lifting and decompilation use the in-tree x86-16 platform; this is the main supported path for the real-mode work in this repo.

Quick smoke example:

```python
import angr
import angr_platforms.X86_16

binary = b'\xb8\x01\x00\x05\x02\x00\xc3'  # MOV AX,1; ADD AX,2; RET
p = angr.Project(binary, backend="blob", arch="X86_16")
cfg = p.analyses.CFG()
decomp = p.analyses.Decompiler(target_addr=0x0)
print(decomp.code)
```

## TODO
- Unreal mode support

## Requirements
You will need:
1. [angr-platforms](https://github.com/xor2003/angr-platforms)
2. [patched angr](https://github.com/xor2003/angr)

Use a fresh Python virtual environment. The current checked setup is working
with Python 3.14.x. The package metadata supports Python 3.10+, but the
recommended path for this repo is to keep the project isolated in `.venv`.

From a fresh clone:

```bash
git submodule update --init --recursive
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e ./angr_platforms[test]
```

If you already have a working `.venv`, re-run the last two commands after a
submodule update so the root environment and `angr_platforms` stay in sync.

Quick verification:

```bash
python -m pytest -q tests/test_x86_16_smoketest.py tests/test_x86_16_cod_samples.py
```

## Usage

For a COM file (e.g., `simple.com`), import the x86-16 platform once before creating the project:
```python
import angr
import angr_platforms.X86_16  # registers the custom x86-16 platform

project = angr.Project(
    "angr_platforms/test_programs/x86_16/simple.com",
    main_opts={"backend": "blob", "arch": "X86_16"},
    auto_load_libs=False,
    simos="DOS",
)
cfg = project.analyses.CFGFast(start_at_entry=False, function_starts=[0], normalize=True)
func = cfg.functions[0]
decomp = project.analyses.Decompiler(func, cfg=cfg)
print(decomp.codegen.text)
```

For raw blobs, use `angr.load_shellcode(...)` with the x86-16 architecture object:

```python
import angr
import angr_platforms.X86_16  # registers the custom x86-16 platform
from angr_platforms.X86_16.arch_86_16 import Arch86_16

binary = b'\xb8\x01\x00\x05\x02\x00\xc3'
project = angr.load_shellcode(
    binary,
    arch=Arch86_16(),
    start_offset=0x1000,
    load_address=0x1000,
    selfmodifying_code=False,
    rebase_granularity=0x1000,
)
cfg = project.analyses.CFGFast(normalize=True)
func = cfg.functions[0x1000]
decomp = project.analyses.Decompiler(func, cfg=cfg)
print(decomp.codegen.text)
```

Note: import `angr_platforms.X86_16` before constructing the project so the custom agents are registered. For COM files or other headerless binaries that you want to load from a file path, use `main_opts={"backend": "blob", "arch": "X86_16"}`. For raw blobs, prefer `angr.load_shellcode(...)` as shown above.

For legacy script usage:
```bash
./decompile.py test.bin
```

When native sidecars such as `.COD`, `.LST`, `.MAP`, or embedded debug info are absent, Inertia can also reuse function labels/ranges from a nearby sibling executable in the same family only when the bytes at the same function entry and across the full claimed function span match exactly. This peer-derived evidence is reported as `peer_exe` and is kept separate from native sidecar sources.

## Project docs and current status

**Main roadmap** (deterministic, actionable):
- [`GLOBAL_PLAN3.md`](/home/xor/vextest/GLOBAL_PLAN3.md) — **Active roadmap** (4 phases, deterministic DoD, PC reasoning assistant)
  - For forward planning and architecture decisions
- [`PLAN.md`](/home/xor/vextest/PLAN.md) — **Immediate fixes** (4 regression items, see completed + in-progress)
  - Completed first, then follow GLOBAL_PLAN3 phases

**Reference docs** (philosophical, not action items):
- [`AGENTS.md`](/home/xor/vextest/AGENTS.md) — Operating rules and architecture constraints (read first)
- [`GLOBAL_PLAN.md`](/home/xor/vextest/GLOBAL_PLAN.md) — Architectural thinking (historical reference)
- [`GLOBAL_PLAN2.md`](/home/xor/vextest/GLOBAL_PLAN2.md) — Pre-implementation roadmap (historical reference)

**Implementation docs**:
- [`angr_platforms/docs/dream_decompiler_execution_plan.md`](/home/xor/vextest/angr_platforms/docs/dream_decompiler_execution_plan.md)
- [`angr_platforms/docs/x86_16_80286_real_mode_coverage.md`](/home/xor/vextest/angr_platforms/docs/x86_16_80286_real_mode_coverage.md)
- [`angr_platforms/docs/x86_16_mnemonic_coverage.md`](/home/xor/vextest/angr_platforms/docs/x86_16_mnemonic_coverage.md)
- [`angr_platforms/docs/x86_16_reference_priority.md`](/home/xor/vextest/angr_platforms/docs/x86_16_reference_priority.md)

Focused x86-16 tests:

- [`angr_platforms/tests/test_x86_16_smoketest.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_smoketest.py)
- [`angr_platforms/tests/test_x86_16_cod_samples.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_cod_samples.py)
- [`angr_platforms/tests/test_x86_16_dos_mz_loader.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_dos_mz_loader.py)
- [`angr_platforms/tests/test_x86_16_sample_matrix.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_sample_matrix.py)
- [`angr_platforms/tests/test_x86_16_runtime_samples.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_runtime_samples.py)
- [`angr_platforms/tests/test_x86_16_compare_semantics.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_compare_semantics.py)
- [`angr_platforms/tests/test_x86_16_cli.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_cli.py)

Focused commands:

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q tests/test_x86_16_smoketest.py tests/test_x86_16_cod_samples.py tests/test_x86_16_dos_mz_loader.py tests/test_x86_16_sample_matrix.py tests/test_x86_16_runtime_samples.py
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python scripts/scan_cod_dir.py ../cod --mode scan-safe --timeout-sec 5 --max-memory-mb 1024
```

## Failure Handling

When recovery fails, prefer an honest fallback over silence:

- If the lifter crashes or lifting breaks, dump assembly around the first failing address and investigate the lifter.
- If the decompiler times out, emit a non-optimized decompilation fallback before dropping to raw assembly, then investigate the timeout.
- If the decompiler crashes, report the failure clearly, preserve the best available assembly or non-optimized output, and investigate the crash instead of masking it.


## x86-16 Quick Start

This repo includes an in-tree real-mode DOS sample corpus under `x16_samples/`.

- Decompile a DOS executable directly from the repo root with:
  - `./decompile.py your_binary.exe`
- Decompile a `.COM` sample the same way:
  - `./decompile.py your_binary.com`
- For raw blobs, use:
  - `./decompile.py --blob your_binary.bin`
- If recovery is slow, pass a larger timeout or a concrete function start:
  - `./decompile.py your_binary.exe --timeout 60`
  - `./decompile.py your_binary.exe --addr 0x1146`
- To keep analysis bounded on large or awkward binaries, you can also tune:
  - `./decompile.py your_binary.exe --window 0x400`
  - `./decompile.py your_binary.exe --max-memory-mb 1024`

- Build or rebuild the sample matrix with `./scripts/build_x16_samples.sh`
- Run the focused x86-16 regression suite with:
  - `../.venv/bin/python -m pytest -q tests/test_x86_16_smoketest.py tests/test_x86_16_cod_samples.py tests/test_x86_16_dos_mz_loader.py tests/test_x86_16_sample_matrix.py`
- Run just the real-binary corpus coverage with:
  - `../.venv/bin/python -m pytest -q tests/test_x86_16_sample_matrix.py`

The sample rebuild uses the DOS toolchain from `/home/xor/games/f15se2-re` by default. If your toolchain checkout lives somewhere else, set `X16_TOOLCHAIN_ROOT=/path/to/f15se2-re`.

For repository operating rules and architecture constraints, see [`AGENTS.md`](/home/xor/vextest/AGENTS.md). For harness behavior and knobs, see [`meta_harness/README.md`](/home/xor/vextest/meta_harness/README.md).
