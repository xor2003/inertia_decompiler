# DOS game reconstruction: C, assembly, tools and order

Use one workflow with three independent validation results: instruction
matching, concrete execution agreement, and symbolic equivalence. None is a
replacement for the others. This guide organizes the existing tools; it does
not claim every backend or target has passed an execution test.

For the relationship between `ada_script`, Inertia, `masm2c` and libdosbox,
including 386 instructions in real mode and a staged integration plan, see
[DOS game toolchain integration](dos-game-toolchain-integration.md).

## 1. Identify and preserve the original

Keep an immutable executable, SHA-256, file size, metadata and build provenance.
Identify the actual code format and CPU mode before choosing a loader: an MZ
prefix alone does not distinguish DOS real-mode code from a PE or extender stub.
Record packing, overlays, relocation information, entry point and data layout.
Keep unpacked working images separate from the original and record their origin.

Useful tools: `sha256sum`, `file`, a format-aware header reader, `mzhdr` for
supported DOS MZ images, and an emulator/debugger when unpacking is necessary.
Compiler banners identify the product, not necessarily its build compiler.

## 2. Recover a function catalog and contracts

First collect initial observations by running the original in libdosbox batch
mode: executed instructions, segment values, memory access widths and targets.
Feed this evidence to ada_script, Inertia and the masm2c preparation workflow.
See the integration guide for collection profiles and artifact checks.

Use Inertia together with Ghidra and Reko for complementary analysis, plus
existing IDA analysis where available. Names, MAP/LST/COD sidecars and
compiler/library signatures are optional evidence; semantics must come from
binary instructions and their effects.

For each function record original and candidate addresses, bounds, CPU mode,
calling convention, arguments, return values, preserved registers, stack
behavior, memory observables and external effects. In 16-bit DOS, retain
segment:offset identity and near/far distinctions.

`dosunit discover` produces catalogs; `make-mapping` connects the two catalogs.
`regions` and `complexity` help prioritize and diagnose functions. A matching
name establishes a proposed correspondence, not equivalence.

## 3. Reconstruct and build a candidate

Recover C incrementally; retain unsupported routines in assembly if the target
build supports mixed C/ASM. Preserve a runnable candidate at each milestone.

For instruction matching, reproduce the compiler, options, memory model,
calling convention, assembler, linker and runtime library as closely as
evidence permits. The same compiler alone does not guarantee identical SSA.
For semantic comparison, structurally different code can still be equivalent.

Keep `.obj`, MAP and listings as build/diagnostic artifacts. The current
comparison workflows below operate on linked loadable images (then derived
SSA), not raw OMF objects. This is a loader limitation, not a Z3 requirement:
Z3 consumes formulas. Linking also resolves symbols and relocations.

## 4. Validate each rebuilt function

| Order | Tool | Question answered | Limit of the evidence |
| --- | --- | --- | --- |
| 1 | Compiler diagnostics and C unit tests | Does the C compile and satisfy explicit examples? | Successful compilation and handwritten expectations do not establish equivalence. |
| 2 | `mzdiff` from mzretools | Does supported DOS machine code match instruction by instruction despite layout changes? | Structural evidence; use strict settings and retain exclusions/options. |
| 3 | `dosunit ssa` + `compare-ssa` or the flat32 adapter | Are modeled outputs equal for all admitted inputs in the completed proof obligation? | Only the recorded model, assumptions and supported control flow are covered. |
| 4 | `dosunit record-oracle` + `compare` | Do original and candidate produce the same declared observations for identical concrete inputs? | Agreement on tested vectors, not every input. |
| 5 | DOSBox/runtime integration scenarios | Does the whole rebuilt program behave correctly with files, interrupts, devices and real workloads? | Scenario evidence; essential even when selected functions are proved. |

Repeat these checks as functions change; do not wait for the entire program.
Run SSA/Z3 before the concrete dosunit lane, then replay realizable
counterexamples and test refused functions as well as proved ones. Use leaf
proofs before attempting callers. Do not enable
callee composition unless the selected adapter supports its ABI and call model.

For an explicit initialized-MZ state, the separate
[`replay-program16` lane](real16-program-execution.md) uses header startup and
typed DOS termination without a synthetic function frame. Its current
explicit file, output, memory and supported DOS/BIOS policies are documented
with that lane. Named observations cover declared scenarios; they do not replace
whole-program files/device/runtime integration tests.

### Instruction matching: mzretools

Upstream documents MZ/8086 support, layout-aware instruction matching in
`mzdiff`, maps from `mzmap`, and data-segment comparison via `--data`.
Its documented scope excludes COM and newer CPUs. Check any local fork's
actual support before applying it to a different target. Options such as
`--loose`, `--idiff`, and instruction skipping are diagnostic aids, not strict
acceptance settings. See the [upstream documentation](https://github.com/neuviemeporte/mzretools).

Local checkout: `/home/xor/games/f19ru/F19/mzretools/`; built utilities are in
`build/`, including `mzdiff`, `mzmap`, `mzhdr`, `mzdup`, `mzptr` and `mzsig`.
`version.txt` records `1.0.20`. Use these explicit paths; they were not on PATH
in the earlier inventory. Their presence was checked, but no comparison was
run for this documentation update.

### Concrete tests: dosunit and ordinary unit tests

Maintain readable C tests for intent and edge cases. Also obtain expected
outputs by executing the original binary; avoid relying exclusively on
handwritten expectations. Use boundary inputs, branch cases and realistic
pointer/memory states. `gen-vectors` can generate inputs; `import-libdosbox`
can import runtime evidence. Neither replaces oracle execution.

The local CLI exposes `libkvikdos` and `kvikdos` execution backends, plus a
fixture backend. A fixture result tests the harness; it is not evidence that
the actual DOS executable ran. Confirm backend availability with a smoke test.
Reset state between vectors. Capture all declared outputs, including memory
and stack effects; do not ignore mismatching fields merely to obtain PASS.

### Symbolic tests: SSA/Z3

SSA lowering and comparison are part of dosunit, not an unrelated test system.
Keep complete per-function obligations, assumptions, refused cases and solver
counterexamples. A proof is conditional on correct lifting and the chosen
ABI/memory/environment model. Replay realizable counterexamples through the
original and candidate before calling a modeled mismatch a decompilation bug.

Timeout, unsupported operation and incomplete loop/call reasoning mean no
proof. Input generation, a few loop iterations or matching SSA fragments do
not establish whole-function equivalence. Record tested, proved, conditional,
failed and refused coverage separately.

For scalar port I/O, both public comparator tracks expose
`--ordered-io-environment dosunit.ordered_io.scalar_in_out.v1`. This is an
explicit environment assumption: identical ordered event histories receive
identical responses. Returning callees propagate it, and affected proofs stay
conditional. Reads whose values are discarded still count as events. It does
not model arbitrary devices or services; unsupported effects remain refusals.
Keep these symbolic assumptions separate from concrete replay results.

For initialized bounded programs, `compare-terminal16` and
`compare-terminal32` compare complete modeled terminal state, memory and ordered
service events. The real16 lane admits declared DOS-version and BIOS-video
queries; the PE32 lane binds declared synthetic services through actual import
directories and IAT routes. Both support bounded divide-error outcomes under an
explicit no-handler premise. Equality remains conditional, with execution
reported separately. See the [terminal-service contract](dosunit-execution-spec.md#79-symbolic-terminal-service-comparison)
and the [real16](real16-program-execution.md#symbolic-terminal-comparison) /
[PE32](pe32-program-execution.md#symbolic-terminal-comparison) commands.

## 5. Whole-program acceptance

Compare initialized data as well as code (`dosunit compare-data`, or supported
`mzdiff --data`). Validate entry/startup code, linker layout, CRT behavior,
overlays, interrupts and external resources in integration tests.

For a compiler suite, include source-to-object differential tests and separately
exercise LINK on object/library fixtures and CL on command-line/driver scenarios.
Matching objects on a corpus is useful behavioral evidence, not a proof of every
compiler function. Full self-hosting additionally requires runnable linked tools.

## Local entry points and verified command surface

Run from `/home/xor/vextest` with `.venv/bin/python dosunit.py`.
The following help commands were checked on 2026-09-26:

```sh
PYTHON_JIT=1 .venv/bin/python dosunit.py --help
PYTHON_JIT=1 .venv/bin/python dosunit.py discover --help
PYTHON_JIT=1 .venv/bin/python dosunit.py make-mapping --help
PYTHON_JIT=1 .venv/bin/python dosunit.py record-oracle --help
PYTHON_JIT=1 .venv/bin/python dosunit.py compare --help
PYTHON_JIT=1 .venv/bin/python dosunit.py ssa --help
PYTHON_JIT=1 .venv/bin/python dosunit.py compare-ssa --help
```

Use `summarize` and `report-failures` to review artifacts. `compare-ssa-batched`
provides a process-batched comparison command; inspect its help for budgets.
See [the execution specification](dosunit-execution-spec.md) for contracts;
it contains both design requirements and command documentation, so use current
CLI help rather than assuming all planned behavior is available.

`dosbox` resolved to `/usr/bin/dosbox` in this session. `mzdiff`, `mzmap`,
`mzhdr`, `dosbox-x` and `kvikdos` did not resolve on PATH; that does not establish
whether local checkouts/builds exist. No emulator execution was performed for
this documentation update.

## The MSC v8 compiler reconstruction is a separate format branch

For the original PE32 compiler executables versus rebuilt ELF32/PE32 tools,
use the [flat32 adapter](../artifacts/msc8-z3cmp32/README.md), not the default
16-bit dosunit SSA ABI or an 8086 MZ instruction comparison of the DOS stub.
The adapter supports complete leaves, matched CFGs, bounded acyclic regions,
direct-call composition and admitted loop relations. `auto` selects bounded
retries; it never turns a finite unrolling into a loop proof. Recursive component
reports and finite indirect targets retain their explicit admission contracts.
Global relocation and environment-dependent results remain conditional.
Unsupported calls, CFG relations or effects still refuse; inspect each report's
scope and assumptions rather than inferring coverage from its selected mode.

Keep two experiments separate:

1. Original compiler executable versus reconstructed compiler executable:
   function-level PE32/ELF32 comparison, including LINK and CL where supported.
2. Original and reconstructed compilers processing the same C inputs:
   compare produced objects, then linked programs and runtime behavior.

16-bit output objects are not 32-bit candidates for experiment 1. Their code
mode also does not identify the compiler used to build the original tools.

## Suggested artifact layout per reconstruction project

```text
original/       immutable binaries and hashes
analysis/       catalogs, maps, disassembly, ABI contracts
src/            reconstructed C and retained assembly
build/          objects, linked candidates, exact build commands
tests/unit/     readable C regression tests
tests/vectors/  concrete states and recorded original outputs
reports/asm/    instruction and initialized-data comparisons
reports/run/    concrete differential and integration results
reports/z3/     SSA, mappings, assumptions, verdicts, counterexamples
```

Track one row per function with independent build, instruction-match,
concrete-test and symbolic-proof status. Keep the full function count visible;
unmapped and refused functions must not disappear from the denominator.

### Binary preservation checkpoint

After rebuilding, compare immutable original and rebuilt executables through
the binary behavior proof commands in [the execution specification](dosunit-execution-spec.md#binary-behavior-proof-commands).
Keep the complete requested-function manifest and both image hashes with the
report. A proof under a declared function/machine model and concrete scenario
replay are independent acceptance evidence; an unproved call, loop, mapping or
external effect prevents claiming unchanged whole-binary behavior. Decompiler
tail validation remains a separate required checkpoint.

Retain `initial_image_relation` as well as the function verdict. A shared-memory
function proof cannot establish equivalence when an executable changes an
initialized global. Missing or different loaded-image identities leave the
initialized-memory relation unproved, including possible reads of changed
instruction bytes as data. Only identity is currently discharged automatically;
startup and environment scenarios still require their own evidence.

Finite loop proofs can use binary-derived register permutations and invertible
modular affine relations at interior cutpoints. The solver checks initiation,
preservation and final observations, including flags and memory; a proposed
relation or a few agreeing executions cannot discharge those obligations.
Rotated guards can use a complete finite region cover with checked internal
progress. Stack-slot changes can use invertible byte permutations plus separately
proved saved-byte invariants. Entry initiation, continuation preservation and
complete final memory equality remain required; failed synthesis or budget
exhaustion stays unknown. These function proofs do not establish initialized
image, startup or environment equivalence.
