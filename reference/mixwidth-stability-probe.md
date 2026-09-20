# Mixed-Width Linked-Binary Probe

## Purpose

Stability/correctness probe inspired by the mixed int/long comparison in
`/home/xor/nndecomp/msex/f14/src/TEST.C`. The independently written fixture
`examples/msc6_constructs/mixwidth.c` uses a parameterized function, eight
boundary checks and an explicit success exit code. It avoids the original's
out-of-range signed conversion and implicit return. No external source tree
was modified. Existing compare16/compare32 fixtures compare equal-width
operands; this fixture adds signed widening across the call boundary.

## Reproduce

```sh
PYTHON_JIT=1 PYTHONHASHSEED=0 .venv/bin/python scripts/build_msc6_examples.py \
  --only-constructs mixwidth --out-dir .cache/mixwidth-msc6 \
  --kvikdos /home/xor/kvikdos/kvikdos \
  --msc6-root '/home/xor/inertia_player/dos_compilers/Microsoft C v6ax' \
  --decompile-timeout 30 --decompile-run-timeout 120
```

The existing builder uses `/Od`; it retains C, OBJ, linked EXE, MAP and COD.
It does not treat this linked executable as an unrelocated COD blob.

## Observed September 20

- Original MS C 6 build and kvikdos execution pass: exit 255 after eight checks.
- Main-function decompilation fails; total decompiler lane time 45.65 seconds.
  Generated output uses assembly fallback. Recompilation/behavior acceptance
  does not pass. Report: `.cache/mixwidth-msc6/report.json`.
- Whole-tail checks reject missing calls at rebased callsites 0x10af, 0x10cd,
  0x10e7, duplicate final callsites 0x1035 and 0x1053, and missing branch surfaces.
  These diagnostics are symptoms, not yet a proven root cause.
- Isolated linked helper at 0x10010, with `--no-alternate-source-c`, exits zero
  and reports `validation=passed`. Artifacts: `.cache/mixwidth-function.c` and
  `.cache/mixwidth-function.log`. Its generated body was not yet independently
  recompiled/executed, so do not claim full helper equivalence.

The initial builder invocation permits its existing alternate-source candidate
lane; no resulting candidate was accepted. That lane cannot establish a
binary-only recovery claim. Use `--no-alternate-source-c` for root-cause probes.

## Next Repair

The first root cause is now isolated and repaired provisionally at the
Structuring symbolic-conversion boundary. angr names opaque ITE expressions by
their repr; embedded calls at different instruction addresses have the same
repr. They intern to one symbolic variable, and the reverse map loses callsite
identity before Inertia's structuring prime even starts. The reduced regression
failed before the patch (one failure, five passes).

`structuring/symbolic_ite.py` preserves opaque values by original object identity
with deterministic per-processor names and strong source references. It does
not infer equality from rendering or reconstruct calls later. Repeated use of
one object reuses its symbol. The existing scoped condition-processor adapter
delegates ITE conversion to this owner. Distinct-call, width and reverse-map
tests pass; 67 focused structuring tests pass in 7.77 seconds. The module is
enrolled in typed/Ruff/ownership gates and its tests already run in the routine
pipeline. Scoped mypy and types/docs pass; the legacy structuring stage retains
16 complexity findings. `quality-fast` remains blocked by global lint debt
(`.cache/mixwidth-quality-fast.log`); its mypyc import smoke passes 39 modules.

Rejected experiment: recursively converting ITE to symbolic `If` prevents the
collision but angr cannot reverse-convert BV `If`. That implementation was
removed; do not repeat it without implementing and testing the complete
bidirectional contract.

After the identity patch, a direct helper/main probe preserves eight separate
calls and their distinct argument values. Main eventually returns C via the
sidecar-slice lane with `validation=passed` and clean whole-tail validation;
earlier attempts still report branch-surface mismatches. This is not evidence
that every recovery lane now passes. Artifacts:
`.cache/mixwidth-main-repaired2.{c,log}`.

The original build command rerun with output `.cache/mixwidth-msc6-after`
reports original build/run passing and decompilation passing (24.43 seconds),
but generated-C compilation fails. `STDINT.H` incorrectly redeclares `size_t`
as unsigned long and `ptrdiff_t` as int32_t, conflicting with MS C's `STDDEF.H`
definitions (unsigned int and int). The linker then reports missing OBJ; that
is secondary to the C2086 compiler errors. Fix the toolchain compatibility
header owner, not generated C. The similar shim in
`scripts/compare_msc6_ssa_examples.py` also needs coherent ownership.

Remaining: repair/retest the header contract, compile all required generated
functions, execute the rebuilt fixture, inspect remaining branch-evidence
refusals, and run the routine pipeline before claiming semantic completion.
Do not add a source-backed body replacement or weaken the required call and
control-flow checks. This remains a failing end-to-end development reproducer.

## Header Repair And Complete-Function Gate

The header contract is now repaired in `scripts/msc6_compat_headers.py`.
Both build and SSA tooling delegate to it. `size_t`/`ptrdiff_t` are imported
from the target's `<stddef.h>`, not redefined by the fixed-width shim.
Four tests failed before the fix (both owners, both include orders); all 60
header/builder tests now pass in 7.68 seconds. The target-sized test header
deliberately uses 16-bit types, avoiding a false pass from host-sized typedefs.
New-module Ruff, mypy and types/docs pass. Explicit-package-bases mypy also
passes both legacy consumers; Make's typing target omits the legacy SSA tool,
so that direct check is additional evidence. The two legacy consumers retain
14 complexity/condition findings. Tests are enrolled in Make, ownership and
the routine pipeline. The global pipeline has not yet been rerun.

MS C rerun in `.cache/mixwidth-msc6-headers` compiles generated main without
C2086 errors. Linking fails because main-only mode omits `_compare_mixed`.
Identifier-truncation and long/short conversion warnings remain visible; no
warning suppression or generated-source rewrite was added.

Rerunning the builder with `--decompile-mode functions
--decompile-max-functions 0` selects exactly the two application functions.
Artifact: `.cache/mixwidth-msc6-all/report.json`. Original build/run passes;
the 56.10-second decompiler attempt accepts only one of two functions and
returns 2. Main retains eight branch-condition missing-surface failures, and
the program-layout report has 11 failures. This is stronger evidence than
the successful single-function sidecar fallback: whole-program acceptance
remains false. Next: trace main's branch-origin/evidence loss in the normal
whole-binary path, preserving calls and keeping validation blocking.

DoD: main and helper generate C with passed validation, every original call
survives with correct argument classes, rebuilt DOS code passes the same eight
checks and exit status, and a focused regression detects the original defect.
Failure: accepting assembly fallback, lost/duplicated calls, source replacement,
or an exit-code match without complete function coverage.

## Call-Condition Binding Investigation

The bound-call Boolean adapter now retains existing equality comparisons with
nonzero constants through Boolean wrappers. Four new regression cases failed
before that extension; the adapter, call-return and branch-validation tests
pass together (54 tests, 7.64 seconds). Scoped Ruff, mypy and types/docs pass.
This is not sufficient to accept the linked fixture:
`.cache/mixwidth-msc6-bound/report.json` still accepts only one of two functions
after 56.71 seconds, with eight missing branch surfaces.

A read-only diagnostic probe completed at 06:36 local time on September 20.
Artifacts: `.cache/mixwidth-target-probe.{c,log}` and
`.cache/mixwidth-branch-1.json` through `-6.json`. It captures the actual
in-process analysis using an isolated cache, without changing validation or
generated output. The rebased attempt has eight raw and normalized call-return
conditions, zero classified/materialized conditions and eight failures. The
later full-address fallback has eight materialized conditions and no binding
failures. Thus upstream return-use evidence is present; this is not wholesale
loss of branch-origin tags.

The target matcher in `structuring/call_return_conditions.py` requires an
attached angr `callee_func`. The rebased calls have no such object: initially
they carry numeric `CConstant` targets, later projected names retain numeric
`inertia_target_addr_8616` tags. The diagnostic observes zero target matches
for all eight calls. A name by itself must remain insufficient evidence.

Next bounded repair: match retained numeric call-target evidence through the
canonical address owner, with tests for rebasing, absent callee objects and
conflicting target evidence. Preserve the exact existing call and arguments;
do not synthesize a replacement call. Then recheck the typed producer contract:
MS C uses DEC/INC on AX before some zero tests, so a comparison with 1 or -1
must retain that producer meaning rather than be certified as a raw AX-zero
test. The diagnostic still reports invalid-fingerprint cleanup refusals on six
branches before a validated fallback. Do not silence these refusals.

No whole-program compilation/behavior success or green routine pipeline is
claimed by this checkpoint. Use the same linked MS C 6/kvikdos fixture to close
the evidence loop before adding another example family.

## Numeric Target Binding Repair

The matcher now consumes numeric constants, raw integer targets, retained
numeric target tags and attached callee addresses through the existing
canonical target owner. Every available identity must agree; names alone,
indirect expressions and conflicting identities refuse a match. It returns
the existing call objects without reconstructing arguments. This is a small
local extension in the existing Structuring owner, not semantic recovery in
postprocess or CLI.

Six regression cases failed before this change. The expanded focused set now
passes 68 tests in 10.65 seconds, including rebased targets, detached callees,
conflict/name-only refusal and full condition-binder integration. Tests are in
the already-enrolled bound-call regression module. Mypy, types/docs, test Ruff
and diff checks pass. Production Ruff reports two pre-existing complexity
findings in other functions; the changed matcher has no finding. Graph tools
remain unavailable (transport closed); evidence is direct source and runtime.

The linked rerun in `.cache/mixwidth-msc6-target/report.json` completed in
61.68 seconds. Original build and execution pass (exit 255). Decompilation
still fails, with no successful generated recompilation or execution. The
normal attempt reports structuring stable and postprocess failed; six
nonzero call-result comparisons have invalid branch fingerprints. This
replaces the earlier eight missing-surface failures but is not acceptance.
Next: reconcile typed INC/DEC producer semantics with the condition validation
projection, preserving branch direction and refusing unsupported producers.
The routine pipeline remains unverified for this change.

## Result-Zero Input Proof

`ir/condition_zero_input.py` now proves the input value producing zero for a
typed word INC/DEC. It requires the exact producer operation, unit amount,
register identity/width and post-update operand binding. It does not delete
updates or flag effects. Branch validation consumes this proof for an already
bound call-return condition; CFG validation retains branch-polarity ownership.
No rendered-C matching or postprocess semantic repair was added.

The two positive regression cases failed before the change. The focused set
passes 63 tests in 7.19 seconds, including refusal controls and exhaustive
65,536-value checks of both word updates and zero/nonzero conditions. The new
test is enrolled in Make, routine pipeline and ownership. Mypy and types/docs
pass. Ruff reports three existing findings elsewhere in branch validation;
the new IR module and tests are clean.

The two-function linked rerun in `.cache/mixwidth-msc6-zero/report.json` now
reports `decompile_ok=true`, both functions emitted, `validation=passed`, clean
whole-tail validation and no assembly fallback. Decompilation took 16.89
seconds versus the preceding failed attempt's 61.68 seconds; these are not
controlled performance repeats. The builder retains its alternate-source
candidate option, so this run alone is not a binary-only acceptance claim.

End-to-end acceptance is still false: MS C reports duplicate `inertia_gp_dword`
and `inertia_gp_lane` declarations in the prepared translation unit. Original
execution still exits 255, but generated code has not linked or executed.
The builder's saved `.dec.txt` is already C89-prepared output, not raw stdout.
It contains the guarded portable runtime header plus preprocessed, unguarded
runtime typedefs selecting host `unsigned int`. Direct source tracing finds
`generated_translation_unit_assembly._preprocess_payload` uses host GCC and
serializes the resulting AST, while the MS C builder prepends the portable
header afterward. Verify this interaction with a minimal export regression
next; preserve the coherent register ABI and target-dependent integer widths
rather than suppressing compiler diagnostics or rewriting function semantics.

## Checkpoint Gates

- `quality-fast`: failed on global Ruff debt. Compiled import smoke passed
  39 mypyc modules; this is not a globally green quality gate.
- `test-pipeline`: exit 0, all three selected lanes passed, none skipped or
  timed out. Main focused lane: 6,097 tests passed in 310.02 seconds. QuickC
  fixture lane: 38.78 seconds. MS C tiny full pipeline: 89.62 seconds. The
  preceding Make contract gate also passed 268 tests; do not add these counts
  together as unique tests because scopes can overlap.
- Slowest main-lane tests: SORTD InitMenu 93.21 seconds, binary ESC exit 69.62
  seconds, InitBars 59.95 seconds. SetGear passed in 29.87 seconds; its earlier
  intermittent timeout is not proven permanently eliminated.
- Logs: `.cache/mixwidth-zero-quality-fast.log`,
  `.cache/mixwidth-zero-test-pipeline.log`. Structured lane report:
  `angr_platforms/.cache/test_pipeline/summary.json` (overwritten by future runs).

The existing tiny lane's green result does not cover the new linked mixed-width
fixture end to end; its declaration/export failure above remains blocking.

## Portable Runtime Export Repair

Whole-file export now marks the exact authoritative runtime header with
preprocessor source locations. Its parsed declarations still participate in
conflict detection, but output retains the portable guarded header rather than
serializing host-selected runtime typedefs a second time. This is export
packaging in `generated_translation_unit_assembly.py`, not a function-body or
semantic repair. Arbitrary headers are not inferred from declaration names.

One regression failed before the change. The 55-test focused set passes in
6.65 seconds, including strict C89 compilation/execution proving a low-word
write preserves the upper register word, repeated header inclusion and retained
conflict reporting. The existing assembler test module is already enrolled in
routine gates. Mypy, types/docs and test Ruff pass; the assembler retains one
complexity finding (16 > 10). Graph transport remains unavailable, so evidence
comes from exact source and executable checks.

`.cache/mixwidth-msc6-export/report.json`: both functions decompile with passed
validation in 15.54 seconds. MS C now compiles the generated translation unit
with zero errors. Identifier-truncation and two long/short argument-conversion
warnings remain recorded. Linking fails on CRT's unresolved `_main`: the
generated entry function has its numeric name, and the fixture builder has not
bound that function to its executable entry harness. No generated execution
result exists yet. Do not rename functions based on guessed semantics or
replace the generated main body; establish the fixture entry from exact binary
and optional label evidence, then add only the required harness invocation.

The preceding green routine pipeline predates this export patch. Its result
must not be presented as verification of the updated export path; rerun broad
gates after closing the fixture entry/rebuild contract.

## Linked Entry And Round Trip

`scripts/msc6_entrypoint.py` now inspects generated declarations with the
existing C parser. Given the fixture's same-build `main` address, it appends
only `int main(void) { return (int)sub_<address>(); }` when exactly one matching
zero-argument integer definition exists. It preserves the complete generated
source, reuses an existing main, and refuses missing/ambiguous address or
signature evidence. This is explicit executable harness binding, not decompiler
naming recovery or replacement of main's checks. The builder records the typed
binding status and selected symbol in its report.

The linked run `.cache/mixwidth-msc6-entry/report.json` passes original build/run,
two-function validated decompilation, generated MS C compilation/linking and
kvikdos execution. Both original and rebuilt executables return 255 after all
eight checks. Binding selected `sub_10065`. Decompilation was 3.49 seconds with
existing caches; no controlled performance improvement is claimed. The
builder's existing alternate-source candidate option and same-build labels
remain enabled, so this is not sidecar-free proof.

Eight entry tests and the surrounding builder/pipeline set pass: 114 tests in
8.37 seconds. Two ordering-sensitive lane-status tests now select the intended
fixture by name; the explicit inventory expectation includes `mixwidth`.
The new helper has typed/docs/Ruff/ownership and routine test enrollment.
Scoped mypy passes both helper and builder. The legacy builder retains 12
complexity/condition findings; none were suppressed. `mixwidth` is now part of
`MSC6_TINY_CONSTRUCTS`, so subsequent routine gates exercise the full round trip.
The broad checkpoint now passes: `test-pipeline` exits 0 with all three lanes
passed and no skips/timeouts. Main pytest: 6,107 passed in 294.98 seconds;
QuickC: 35.69 seconds; MS C tiny: 106.22 seconds, including the newly enrolled
`mixwidth` returning 255. Log: `.cache/mixwidth-entry-test-pipeline.log`.
`quality-fast` remains blocked by global Ruff debt, while the 39-module mypyc
import smoke passes. Its log is `.cache/mixwidth-entry-quality-fast.log`.
These results do not discharge the portable-host correctness blocker below.

## Portable-Host Correctness Blocker

Historical failure; the Types/Lowering repair and current acceptance are in
[the portability repair report](mixwidth-portability-repair.md).

An independent execution of the same prepared generated C under host GCC
exposes a remaining error despite the successful MS C round trip:

```sh
gcc -x c -std=c89 -O0 -fsanitize=undefined \
  .cache/mixwidth-msc6-entry/DMIXW01.C \
  .cache/mixwidth-msc6-entry/INERTIA.C -o .cache/mixwidth-host-check
.cache/mixwidth-host-check
```

Compilation succeeds; execution returns 3, the fixture's third check, rather
than 255. No UBSan diagnostic is emitted. The generated helper compares signed
`arg_8` directly with unsigned-word `arg_4` in its low-word comparison. MS C's
16-bit integer promotions and GCC's 32-bit promotions differ for these operands.
The equal negative boundary therefore needs its proven unsigned low-word view,
independently of the argument's signed uses in high-word/sign-extension logic.

Next investigation belongs in Types/Lowering, not the harness or rendered C.
Existing owners are `lowering/condition_operand_views.py` and
`lowering/semantic_cast.py`; the former can omit an identity cast based on the
current declaration. Determine whether later declaration refinement or another
materialization path loses the required view before choosing a fix. The exact
cause of that omission is not yet proven. Add a compiled-host regression and
repeat both GCC and MS C behavior checks. Do not change expected exit status,
remove the negative boundary, or cast every use of the signed argument globally.

This was a correctness blocker, not readability debt. MS C success alone was
insufficient; retain both compiler execution oracles when extending the cohort.
