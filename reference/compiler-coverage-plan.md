# Small DOS C Programs: Decompiler Round Trips

Status (2026-10-06): first16 fixtures are frozen, and both small-model profiles
verify against the reviewed private runner snapshot. Devin deadline, timeout
classification and detached-process cleanup changes have parent review and
focused evidence: **210 passed** across result (45), profile/runner (120) and
IR/Alias deadline (45) cohorts. New deadline-owner gate enrollment is checked.
A synchronized detached-child replay returned at 1.01s for a 1s timeout and
kept partial output; cleanup uses bounded 0.5s drain/wait allowances.
The retained source-free `cmp_i16` static probe still reached its outer 88s
timeout before the decompilation banner; cooperative checks do not preempt an
individual expensive operation. No end-to-end speedup or new semantic acceptance
is claimed. The parent sandbox has no `/dev/kvm`. A newly measured explicit private DOSBox
route removes that execution blocker: five real exit controls (0, 1, 5, 127,
255) recovered exact guest status, and fresh MS5.1/Borland3.1 small/large
compile/link/run probes produced byte-identical retained EXEs and expected exit255.
The private alternate registry is
`.cache/compiler-coverage/dosbox-parent-probes-20261006/toolchains-dosbox.json`;
default/frozen KvikDOS registries are preserved. Adapter review/checks are in
progress; this runner evidence is not decompiler acceptance. The slow source-free
analysis remains the next blocker. Acceptance remains **0/16**.
Review receipts/logs: `.cache/compiler-coverage/parent-review-20261006/`.
User purpose clarified, 2026-10-06. This is the active plan.
The sixteen round trips below are a starter batch, not the completion boundary.

## Objective And Limits

Build a systematic corpus of small C examples that exposes missing decompiler
support across language constructs and compiler-emitted structures. Large
programs such as SORTDEMO and unrelated random sources combine too many causes,
make repair slow and leave coverage accidental. Existing working tiny examples
are the foundation; new examples must fill a named gap or interaction.

Use **Microsoft C 5.1 and Borland C++ 3.1**, targeting **16-bit real-mode DOS,
C mode**. Start with small model; retain the original plan's targeted large-model
near/far ABI subset without duplicating the entire corpus. Decompile without
source-assisted semantic recovery, rebuild generated C with the same compiler/
configuration, and compare behavior. Fix the small failing witnesses at their
owning layers; whole-game repairs are not prerequisites.

After the MS/Borland corpus is accepted, run the required final Watcom 11.0b
16-bit phase below. It adds a third compiler lane, not another language corpus.

Both compiler directories exist under `/home/xor/inertia_player/dos_compilers/`.
Verify exact versions, flags, target bitness and compile/link/run availability
before freezing the batch. Do not silently substitute MS C 6, another Borland
version or a 32-bit target. Borland 3.1 is a representative choice, not a claim
of measured market-share leadership. The original Wolfenstein 3D release
[documents Borland 3.0/3.1 support](https://github.com/id-Software/wolf3d).

FPU, handwritten assembly, unpacking, protected mode and Ghidra/Reko parity remain
outside this plan. No exhaustive claim over all C programs or every optimizer
output is possible. Define finite required feature/output families and selected
compiler configurations, record missing coverage and preserve regressions.

## Coverage Matrix Is The Deliverable

Reuse the original variation inventory in `examples/compiler_coverage/pilot.json`.
Its historical `admitted`/`later` lists and old compiler profile are inventory,
not a completed coverage claim or permission to leave required families untested.
Map existing tiny fixtures before writing code; freeze exact obligations and
explicit exclusions for the finite pilot, then add gap-driven examples in batches.

| Family | C inputs and interactions to inventory | Binary/output evidence to check |
| --- | --- | --- |
| Values | Byte/word/long signedness, promotions, casts, arithmetic, shifts, Boolean conditions | Extension/truncation, multiword carry/compare/shift, flags and materialized conditions |
| Storage | Scalars, arrays including multidimensional, pointer aliases, globals/static state, structs/unions/bitfields | Field layout, strides, overlapping reads/writes, partial updates and preserved neighbors |
| Calls | Direct/indirect, nested arguments, scalar/pointer/aggregate arguments and returns, variadic and bounded recursive patterns | Stack/register transport, hidden result storage where emitted, cleanup, call-live state and target recovery |
| Flow | If/else, short circuit, switch, for/while/do, nested loops, break/continue/goto/early return | Branch chains, jump tables when emitted, joins, backedges and loop-carried values |
| DOS model/ABI | Small near code/data plus targeted large far calls/data/pointer transport | Segment:offset state, near/far returns, pointer width and segment preservation |
| Optimization | Representative verified configurations on selected witnesses | Folded versus runtime expressions, strength reduction, shared expressions, register/spill changes |
| Boundaries | Matched library calls and compiler-generated helpers used by these cases | Preserved call arguments/results/effects; no silent application-function exclusion |

Track language-feature coverage separately from emitted-pattern coverage and
compiler/configuration coverage. Each required matrix cell needs an identified
small source, defined input/output contract, compiler flags/model, actual binary
mechanism, round-trip verdict and evidence location. If a switch compiles to
comparisons it covers comparisons, not a jump table. If a construct disappears
under optimization, it is not an emitted witness. Select constants/runtime inputs
and verified configurations to obtain missing patterns; do not count source text.

Use the original 32–64-source pilot as a planning budget, counting reused sources,
not a quota or guarantee that every obligation fits. Freeze the actual source and
compiler/model selection before expansion; avoid a full Cartesian product.
If coverage cannot fit, report the exact missing cells and proposed budget/scope
change. Do not mark them covered, silently remove them or replace difficult cases.
Csmith supplies bounded interaction discovery; it cannot replace this matrix.

For a failure found in a large program, extract a small defined-behavior witness
for the missing construct/interaction. Confirm it reproduces the same semantic
failure before using it as the regression. Preserve the original failure as
evidence, but do not make whole-SORTDEMO repair the development loop.

## First Batch To Freeze (Not Full Coverage)

| Source ID | Required behavior | Configurations |
| --- | --- | --- |
| word_comparisons | Existing `compare16.c`: signed/unsigned comparisons, extreme values and unsigned wrap | MS C 5.1 small; Borland 3.1 small |
| array_pointer_writes | Existing `pointer_memory.c`: indexed writes, same-object alias, overlapping copies and pointer returns | Same two |
| branches_loops | Existing `simple_control.c`: conditions, loop-carried state and grouped switch cases/default | Same two |
| call_composition | Existing `function_pointers.c`: direct/indirect calls and nested arguments live across calls | Same two |
| struct_value_abi | Small mixed-width struct passed and returned by value, assigned to another object; check fields and unchanged caller input | Same two |
| bitfield_neighbors | Adjacent unsigned-int bitfields: assign/update one field while preserving neighbors and an ordinary member | Same two |
| multidim_alias | Small two-dimensional array passed as pointer-to-row; variable row/column indexing and same-array alias store/readback | Same two |
| csmith_seed2 | Pinned generated interactions with observable checksum/state | Same two |

Explicit scope revision following the user's existing-tiny-test correction:
four existing regression sources + three directed gap probes + one Csmith source
= eight sources, sixteen compiler/case pairs. The old five-source proposal was
not executed or frozen; no failed case is removed by this revision. Report the
subtotals separately: baseline N/8, directed additions N/6, Csmith N/2. Historical
tiny successes are useful regression evidence, not new-construction progress.

The three additions come from the original plan's structure ABI, bitfield and
multidimensional-array obligations. Direct inspection of `msc6_constructs/`
found ordinary struct-pointer access, scalar mixed-width arithmetic, globals,
loops and callbacks already represented; do not duplicate those as new coverage.
Before creating files, check existing fixture/runner mappings for an equivalent
probe and reuse it if present. Keep each addition to one interaction and 1–3
application functions, with a tiny deterministic input set.

For struct ABI, compare named fields, not padding; do not prescribe a hidden
return-pointer convention—the binary establishes it. For bitfields, use explicit
`unsigned int`, in-range values and a compiler probe for layout; never assume
matching packing across compilers. Each rebuilt binary is compared with its own
compiler's original. For multidimensional arrays, keep accesses within bounds,
use correct pointer-to-array types, and require both aliasing and disjoint cases.
Add matching negative controls: corrupt a returned struct field, clear a neighbor
bitfield, or change a row stride/store destination; each must be detected.
Other inventory items enter subsequent explicitly frozen coverage batches;
their admission and completion must be visible in the matrix.

These four sources already live in `examples/msc6_constructs/` and are selected
by `examples/compiler_coverage/pilot.json`; reuse their existing IDs, bodies and
checks. Do not create four equivalent new fixtures or a second runner. The old
pilot profile is MS C 6 small (`/Od /AS`), not evidence of MS C 5.1/Borland
acceptance. Add separate compiler profiles without overwriting historical ones.

The existing MS tiny-model lane and `examples/build_msc6_tiny/` remain useful
baseline evidence. Reuse source/runner infrastructure, but rebuild under each
new small-model compiler profile: tiny and small have different image/segment
contracts. Neither old tiny results nor existing build files establish new passes.
Preserve existing success exit255 instead of imposing the Csmith exit0 convention.

Freeze source hashes, inputs, observations and emitted-mechanism evidence before
repairs. Existing sources may contain more than three application functions;
keep all reachable application bodies and checks rather than splitting them
or dropping indirect calls to meet an artificial size limit. Use 1–3 functions
as a guideline only for genuinely missing new probes. Keep arrays/loops bounded.
An optimized-away construct is not a binary witness. Undefined
behavior, uninitialized/padding bytes and host-integer assumptions are not oracles.

Retain Csmith seed **2**, user fork branch `ms-c-dos`, revision
`35e702de01e158bc948a2024d0e187c1803d1ebb`, exact build/options and generated C.
Historical generated-source SHA-256:
`353845463705795ea0822c0ecaf5f956828405507d956d661e2fa124a4d66939`.
Verify retained artifacts; do not invent fresh equivalent evidence. Preserve
original failures when minimizing. Never replace a failing admitted seed or
source with an easier one, or drop a compiler to obtain a green denominator.

### Source-Informed Construct Selection

Bounded source review, 2026-10-06: the following two external reconstructed
compiler files informed the four directed cases. They are patched Hex-Rays
output with guessed types and host-x86-32 conventions, not original C source,
correctness oracles or proof of what the older DOS compilers will emit.

- Borland source: `/home/xor/inertia_player/dos_compilers/Borland C++ v5.02/BC5/BIN/rebuild/gen/BCC.c`.
  `fold_compare` (line 28521) branches on type/range/signedness;
  `make_bool` (line 28445) constructs explicit truth comparisons;
  `parse_decl_specifiers` (line 11949) combines repeated dispatch, grouped cases
  and short-circuit conditions. These inform the existing comparison/control cases.
- Microsoft source: `/home/xor/inertia_player/dos_compilers/Microsoft C v8/BIN/rebuild/gen/Q23.c`.
  `nibble_set` (line 3985) performs read/modify/write with masks and shifts;
  `page_cell_ref`/`page_cell_get` (lines 3911/3947) combine traversal
  and indexed fields; `rd_rec` (line 2139) copies words through an output pointer;
  `hash_walk_buckets` (line 3703) keeps traversal state live across a callback.
  These motivate masked updates, record/alias addressing and call-live state.

First map these patterns onto the existing fixtures. Additional nearby examples
already include `mixwidth.c`, `compare32.c`, `loops_jumps.c` and
`medium_structs.c`; consult them before adding code. Masks/nibble writes, mixed
widths and record fields are gap candidates, not automatic batch expansion.
Propose any missing-obligation extension before source freeze; preserve existing
checks and the first batch's eight-source/two-compiler denominator. Missing
required cells belong in the next declared batch, not silent changes to this one.
For a genuinely missing probe, write clean C89; do not copy raw casts,
numeric compiler opcodes, LOBYTE/LOWORD pseudo-assignments, guessed uninitialized
locals, calling-convention artifacts or suspicious pointer arithmetic. Use
unsigned operands for shifts, counts below width, and in-range signed arithmetic.
Exercise byte boundaries 127/128/255 and word boundaries 32767/32768/65535 via
appropriate typed inputs; check unsigned long carry across 65535 without signed
overflow. Do not assume
plain-char signedness or negative right-shift behavior is portable. Preserve
mask neighbors and alias readback as explicit observations, not only checksums.

Use runtime inputs to keep the target operation present, then inspect emitted
binary/IR evidence. Source presence alone is insufficient. The inspected BCC
folding/CSE machinery reinforces that rule; it is not a reason to add a compiler
exhaustive optimization matrix. Keep this batch's sixteen-case denominator and
existing bounds; later targeted configurations must fill a recorded output gap.
The existing `function_pointers.c` callback checks stay in call_composition;
do not defer or delete behavior already present in the selected source.
Additional C callback/recursion witnesses come from the coverage matrix, not a
port of these compilers. Their paged allocator, C++ types/exceptions and FPU do
not become mandatory implementations by appearing in these reference sources.

## Acceptance For Each Round Trip

`C → compile/link → original EXE → decompile → generated C → rebuilt EXE → compare`

1. Original compiles and executes under the frozen contract. Source expectations
   separately check compiler/harness correctness.
2. Every selected non-library application function is accounted for and emitted.
   Source/COD/listings cannot supply semantic answers or repair recovered bodies,
   arguments or types. Optional names/bounds remain diagnostic evidence only.
3. Semantic validation passes; required calls and value/pointer arguments survive.
   Generated C rebuilds without manual semantic repair or deletion of live code.
   Existing function-fix and tail-validation contracts remain in force.
4. Original/rebuilt termination, returns, output/checksum and declared memory
   observations match on frozen boundary/alias/branch inputs.
5. Reports separate symbolic validation from concrete execution. A checksum match
   is not all-input equivalence. Unknown/refusal/timeout never becomes success.
   Every frozen batch row remains accounted for, including blocked/failed rows;
   the first batch has sixteen.

Deliberately corrupt return, store and branch behavior on both compiler lanes;
the comparator/harness must detect each mutation. These negative controls
supplement the sixteen positive round trips and are mandatory acceptance evidence.

### Csmith Runtime Boundary

The historical seed-2 build emitted two application functions plus 67 runtime
helpers: `--max-funcs 1` did not bound linked runtime size. Establish this boundary
before another campaign. Use verified binary-signature matching, retain library
call ABI/effects and record matched addresses/provenance. No name-only exclusions
or source-membership shortcuts. Unmatched bodies remain accounted for and must
be analyzed or reported as blocking. Only dependencies of the frozen cases are
in scope; this is not a universal runtime-library recovery project.

## Execution And Completion

| Step | Required deliverable |
| --- | --- |
| 1. Probe and map | Both compiler probes; exact flags/libraries/backend/models; map existing tiny fixtures to required input/output obligations and freeze the finite coverage matrix |
| 2a. Freeze first batch | Sixteen-row manifest with sources, inputs, observations and budgets; record which matrix cells it does and does not cover |
| 2. Run the baseline | All sixteen attempted once; original/generated/rebuilt artifacts where available; typed per-stage failures/timings; corruption controls and timeout cleanup verified |
| 3. Repair one failure family | Retained reproducer, owning-layer fix, focused red/green, scoped lint/types and affected neighbors; rerun affected frozen cases without weakening acceptance |
| 4. Accept the batch | All sixteen complete round trips pass; negative controls detect corruption; reproducible rerun evidence and affected regressions pass; publish exclusions |
| 5. Fill named gaps | Subsequent small frozen batches from the matrix, reusing fixtures and adding only missing mechanisms/interactions; targeted large-model and configuration witnesses |
| 6. Accept MS/Borland corpus | Every required matrix cell has an accepted emitted witness under its selected MS/Borland configurations; all admitted cases and negative controls pass; missing/excluded cells and limits published |
| 7. Validate Watcom 16-bit | Reuse the corpus with installed Watcom 11.0b; prove its compiler/runtime profile, preserve independent ABI/layout evidence and pass the same applicable round-trip and corruption obligations |

Reuse `tools/compiler_toolchain/build_msc6_examples.py`, the compiler-coverage suite/manifest and
Csmith adapters. Extend their compiler boundary rather than build a second
pipeline. Existing `compiler-coverage-csmith` is a starting point, not evidence
of support for both requested compilers. Deliver documented commands for the
batch, compiler/case selection and failed-case reruns. Keep durable manifests,
fixtures and regressions in the repository; raw run artifacts in fresh directories.

Freeze stage/case/batch wall and memory limits before baseline. The existing Make
case default is 600 seconds; inspect actual limits and do not increase them to
turn failures green. Record source/toolchain/runtime/options/environment and
implementation identities. Reuse unchanged evidence only when relevant inputs
match; do not repeat the entire batch for documentation or unrelated edits.
Run Python/pytest at nice 10 with `PYTHON_JIT=1`, deterministic seeds and at most
six aggregate test workers. Begin external round trips serially; increase only
with measured resource evidence, at most two heavy jobs. Timeouts must stop owned
descendants and preserve partial artifacts. No endless seed campaigns.

Focused regression and changed-file lint are the development loop. Frozen-case
round trips and affected shared-owner tests are integration checks. Broad release/
PR gates are separate: record unrelated failures without making them milestone
blockers. Regressions caused by this work remain blockers. KVM-backed DOS execution
tests carry `requires_kvm`; static/Z3 tests do not. Missing execution is blocked
evidence, never an accepted case or permission to silently substitute backends.

**Runner operational** means batches execute with complete failure accounting
and passing corruption/timeout controls. **First batch accepted** means its
sixteen round trips pass. **Plan complete** means the required finite coverage
matrix and all admitted batch cases are accepted, including emitted-mechanism
witnesses and the final Watcom lane, not merely the initial sixteen results.
MS/Borland acceptance is a separate checkpoint and is not postponed by starting
Watcom early. Unit-test counts establish
none of these on their own. Report covered/required cells separately for language,
output and compiler/model configuration; also accepted cases per batch, exact
blocking families, next bounded action, time and peak memory.

Current state (2026-10-07): all 36 source entries are present or retained and
hash-pinned; this does not establish emitted coverage. Verified primary DOSBox
profiles exist in the private probe registry. One of sixteen first-batch cases
has been attempted: MS C 5.1 word comparisons compiles/runs the original, but
decompilation still times out at the unchanged 120-second limit. Acceptance is
0/16; the other fifteen baseline attempts and full matrix acceptance remain open.
See `compiler-coverage-matrix.md` and `../PROGRESS.md` for current evidence.
Historical results are not automatically current acceptance. If a blocker
requires a substantial new subsystem, report the concrete dependency and leave
its case open; do not silently expand or weaken the plan. Large-program repair
queues and unrelated gates stay separate. Required missing constructs remain
visible obligations even when a simpler smoke batch passes.

## Final Phase: Watcom C/C++ 11.0b, 16-bit DOS

Selected installation:
`/home/xor/inertia_player/dos_compilers/Watcom C++ v11b/`.
This is the preferred installed candidate because it provides the 11.0 B-level
fixes and the 16-bit C compiler, linker and DOS runtimes together. This is a
selection rationale, not an assertion that it is fastest or universally best.
Local inspection found `binw/wcc.exe`, `binw/wcl.exe`, `binw/wlink.exe`, and
`lib286/dos/clibs.lib`/`clibl.lib`. The installation's `readme.txt` identifies
`wcc` as the 16-bit x86 C compiler and `wcc386` as the 32-bit compiler. No live
compile/link/run probe has yet established usability in the current environment.

1. Start only after the MS/Borland corpus checkpoint. Pin compiler/linker/library
   hashes, actual version, host runner, target, flags and environment. Use WCC
   (or WCL driving WCC), explicitly targeting 16-bit real-mode DOS. Do not use
   WCC386, DOS/4GW or a 32-bit extender. Compiler-host bitness is not target
   bitness: verify actual emitted objects and linked executable behavior.
2. Compile/link/run a small-model probe, then reuse the eight starter sources
   as eight additional Watcom round trips. Extend to the same admitted corpus
   and targeted large-model witnesses through frozen selections. Keep existing
   MS/Borland receipts and denominators unchanged; report Watcom separately.
3. Probe and record actual argument registers/stack use, preserved registers,
   multiword returns, struct return transport, near/far control and packing.
   Preserve the selected Watcom ABI instead of forcing every case to MS-style
   cdecl merely to avoid a decompiler limitation. Additional ABI options need a
   named coverage obligation, not an exhaustive configuration matrix. The
   [Open Watcom guide](https://open-watcom.github.io/open-watcom-1.9/cguide.html)
   is supplemental documentation; installed 11.0b binaries/probes determine
   this lane's exact behavior.
4. Compare each Watcom original with its own rebuilt output. Across compilers,
   compare only explicitly portable source observations; do not demand identical
   assembly, layout, padding, checksums over representations or calling conventions.
   Account for compiler-specific helpers with the same library boundary rules.
5. Acceptance requires every applicable admitted Watcom case, emitted-pattern
   witness and negative control to pass at the frozen budgets. Compiler errors,
   unsupported ABI recovery and runtime failures remain explicit open cases;
   they are not success or permission to silently drop a difficult construct.
   Fix only defects exposed by this lane and their affected regressions. Reuse
   unchanged primary-lane evidence; rerun relevant checks for shared-owner edits.

No further compiler release is added automatically. Watcom adds portability and
ABI/code-generation diversity to the same systematic small-example corpus;
it does not reopen whole-game repair or unrelated repository-wide gate work.
