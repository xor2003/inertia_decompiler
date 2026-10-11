# Small DOS C Programs: Decompiler Round Trips

Current acceptance (2026-10-10): **0/16 starter, 0/118 matrix**. Preserve
all corpus requirements and the Watcom phase below. Focused tests, original-only
builds and conditional exports are not completed round trips.

## Immediate deliverable

Current work order: finish the **ordinary, source-free BITNBR round trip**.
The declared-route optimization checkpoints further below are retained evidence,
not the active queue. Do not resume their performance work unless an ordinary
case failure establishes that dependency. All original matrix/Watcom obligations
and acceptance criteria remain unchanged.

Ordinary application output is now **3/4 functions**: sub_1ce2, sub_1d04 and
sub_1d12 each exit0 with `validation=passed`. sub_1ce2 C exactly matches the
previous2048/2048 replayed payload; sub_1d04 now has an unsigned-byte pointer,
compiles with GCC Werror and passes512/512 fresh native/host comparisons.
Receipts and hashes: `.cache/bitfield-ordinary-leaves/RESULT.md`.
This is function output accounting, not3/4 of whole-program acceptance.
Fresh ordinary sub_1d04 CLI exits0 with `validation=passed`; its output hash
matches the payload compiled/linked with frozen BC31-small and executed in
DOS with512 concrete data/ESI-preservation checks and exit0. A separate
mask254->252 corruption builds but exits1 with256 detected failures.
Evidence: `.cache/one-function-current/RESULT.md`. This is one function's
validated C and concrete DOS round trip, not whole-case or all-input binary
equivalence acceptance; all batch denominators remain unchanged.

Precise ordinary-main blocker: six terminal jumps retain selector-window
refusals because `entry_jump_domain_call_on_path` cannot consume a preservation
proof at CALL0x1d97. The root census covers23 blocks; all four call-preservation
records have `entry_domain_call_callee_unresolved`, an entry and binding but no
callee artifact. Parent subsequently inspected each retained binding: all four
already refuse `selector_window_unproved`. The resolver deliberately does not
start callee closure after this failure; `CALLEE_UNRESOLVED` is secondary, not
evidence of a broken importer. Standalone imports of all three callees succeed.
That source is now checked: static MZ intake is INSTALLED, its inventory is
READY (14 materialized boundaries, no pending targets), and the startup caller
at0x1b78 is indexed. The ordinary boot premise instead refuses
`declared_service_unproven` at INT21h/AH=30h, instruction0x1a2a. The current
crossing requires proven AH/AL and an explicit environment-bound service
relation; ordinary header intake supplies no such relation. A raw-only probe's
`coverage_unbound` is expected for this refusal-free startup surface, not the
ordinary route's failure. Evidence: `.cache/main-intake-review/RESULT.md` and
`caller.jsonl`. Do not repeat intake/import/cache investigations or raise timeouts.
Next review a local selector proof or an explicit modeled-environment boundary;
do not silently inject a DOS answer or relabel a conditional premise as passed.
Do not assume CS from the load address, change jump destinations or suppress validation.
Typed proof ledger: `.cache/main-jump-domain/proof-01-0x1d43.json`.
Full binding evidence and parent correction: `.cache/main-binding-diagnostic/`.

### Bounded implementation: modular near-call entry context

The next implementation uses the incoming CALL's own fetch condition, not a
DOS-startup reachability claim. For BITNBR, fetching the word near CALL at0x1b78
establishes a selector interval that maps its destination to main0x1d43 for
every admitted selector. If main preserves CS, that interval also fixes its
four outgoing call destinations. This is conditional on that exact entry edge;
it does not establish arbitrary entry into main or whole-program reachability.

1. Derive a typed selector-window projection from the existing authenticated
   near-call-frame premise and exact decoded word-CALL coordinates. Check full
   instruction fetch extent, target invariance, width and physical bounds.
   Projection is geometry data; it grants no native-image or semantic authority.
2. Bind consumption to the current native caller bytes, retained row/index,
   exact callee artifact/boundary and required entry edge. Reuse existing
   segment-effect/CFG proof to establish CS preservation; unknown effects,
   changed CS, unmatched calls and stale surfaces remain refusals.
3. Carry this scope through target binding, call preservation, jump admission,
   application and validation. It must never enter the universal registry or
   satisfy a context-free consumer. Discharge the entry condition at a proved
   matching caller; otherwise retain an explicit conditional result. Do not
   manufacture a full-state invocation receipt from selector geometry.
   Implement **outgoing CALL binding and conditional CS preservation first**.
   BITNBR's six pending jumps all target0x1da3 inside main0x1d43: the existing
   root-fetch window already establishes their target geometry. Their blocker
   is the unproved CALL on the path, not missing jump-window arithmetic.
   Preserve the existing jump theorem; extend its scope transport only when
   the conditional call records are ready to consume. Use a tiny real native
   fixture with an incoming CALL, a root calling an earlier callee, and a
   universally CS-preserving callee. Do not substitute a backward jump below
   the root as the primary reproducer of this failure family.
4. Tests must reject forged coordinates, changed width/bytes/index, foreign
   caller scope, CS interference and wrapped destinations. Verify interval
   arithmetic independently with symbolic16-bit IP semantics. The actual
   ordinary CLI and round trip remain the acceptance checks after integration.

Feasibility evidence: a private, explicitly conditional predicate experiment
removes all6 main jump refusals and closes all4 existing callee-segment records
in1.12seconds (`.cache/call-entry-selector/feasibility.json`). This is NOT an
accepted proof or implementation: the experiment does not transport the scope.
Its products must not be reused as ordinary evidence. The staged geometry helper
and its14 tests are now reviewed (`.cache/call-entry-selector/REPORT.md`);
parent corrected typing and reran lint/MyPy/tests. The geometry is now promoted
to `inertia/frontend/x86_16/near_call_selector_window.py`. An independent
bit-vector regression (`tests/frontend/test_near_call_selector_symbolic.py`)
passes30 native E8 address/displacement cases, including64KiB fetch and return-IP
boundaries. A separate symbolic calculation proves fetch-interval exactness and
target invariance for all below1MiB word-CALL coordinates; both counterexample
queries are unsatisfiable (`.cache/call-entry-native/geometry-universal.json`).
Native-byte binding is implemented in `near_call_entry_context.py` and parent
reviewed. The57-test cohort passes, including three parent regressions that
failed before fixing expiry and changed CALL bytes during native replay.
Scoped lint, MyPy, Pyright and startup architecture checks pass. A real BITNBR
probe binds and consumes CALL0x1b78 -> main0x1d43 with interval[0,439] using
unchanged production functions, in0.0144s after project loading. Evidence:
`.cache/call-entry-native/REPORT.md` and `bitnbr.json`. This remains conditional
entry evidence, not main acceptance. IR scope transport and caller discharge
remain outstanding.
Keep the production validator unchanged until the scope reaches every consumer
above.

The experiment exposed a separate native-import defect: a recovered graph
merged target0x1da3 into its predecessor, leaving the native census incomplete.
VEX import now restores block splits through the existing authenticated frontend
boundary transport. A15-byte regression fails before and passes after; the
113-test focused cohort passes. Ordinary score still exits0/validation=passed
with identical generated C. Main's conditional diagnostic restores23 blocks
and6 jump admissions, then reaches its60s timeout; it is not main acceptance.
Evidence/gate limits: `.cache/native-interior-target/RESULT.md`. Next integrate
the reviewed call-entry scope; only then diagnose any remaining full-pipeline
timeout with stage/stack evidence. No budget increase or repeated blind rerun.

**Normal single-function emission now succeeds.** A fresh ordinary CLI run for
BITNBR `0x1d12..0x1d43`, with load segment `--base-addr 0x1a2` and without
`--real16-declared-input`, exits0 and reports `validation=passed`; structuring
and postprocess snapshots are both stable. Its accepted C is byte-identical
to the fresh payload already recompiled/tested below (SHA256 `4a0360e0…8bda897a`).
No status, premise or validator was patched. The explicit declared-input mode
deliberately selected a conditional domain; its result did not establish that
ordinary recovery was blocked. Source review confirms the word arithmetic
return and pointer input agree with `flags_score`; the source body has no calls
to lose. Original-to-rebuilt Z3 remains limited to its stated entry/frame
domain; CLI tail validation is a separate observation, not a universal ABI proof.
Evidence: `.cache/score-entry-next/ordinary.log` and
`ordinary-generated/00001d12-sub_1d12.c`. The first unscoped attempt used the
default load segment and therefore selected an unmapped address; it is not a
semantic failure. Next obtain an ordinary baseline for the remaining application
functions before assuming that declared-entry/CRT work blocks the whole case.
Complete-case acceptance remains **0/16, 0/118**.

The next ordinary `main` baseline is now measured: `0x1d43..0x1e54`, same
load segment, no declared input, unchanged60s function budget, exits4 with
`validation_failed` (not timeout). Four calls have unknown calling conventions.
The first hard failure is `Semantics source IR contains retained refusals`
at `inertia/semantics/call_stack_effect_pipeline.py:apply_x86_16_call_stack_effects_8616`.
Later76 uninitialized-read reports and `ss << 4` leakage are downstream symptoms;
do not repair rendered C or suppress these guards. No accepted main C is emitted.
Next extract the exception's typed `details.refusals` and fix that earliest
call/import owner before revisiting entry-proof optimization. Evidence:
`.cache/bitfield-ordinary-main/run.log`; tail diagnostic path is recorded there.

Fresh single-function checkpoint: the ordinary CLI regenerated BITNBR score
into `.cache/score-fixture/fresh-generated/conditional/00001d12-sub_1d12.c`
(exit5, conditional). This new payload explicitly captures `tmp_1`; it differs
from the frozen witness below. GCC Werror compilation and12288 original-byte
replays pass. Frozen BC31 `-Od -ms` compilation/linking of the unchanged payload
and DOSBox execution pass402/402 cases (guest exit0). The fresh candidate is
233bytes with one real shift-helper call, versus249bytes/two calls before.
The same scoped symbolic obligations, root CS and physical return checks pass
on the newly extracted candidate/helper bytes (3.41s pytest total), using a
private copy of the permanent test with only fixture location/call count changed.
Receipts: `.cache/score-fixture/fresh-dos/receipt.json`, `fresh-replay.json`,
`fresh-symbolic.log`. This is an actual fresh decompile/build/run/check chain,
still under explicit entry/runtime/private-storage premises; it is not complete
ABI validation or whole-case acceptance. Do not widen its claim to `passed`.
The permanent fixture now contains this fresh233-byte candidate and the
unchanged fresh C; all3 mutation offsets were checked against its instructions.
All4 permanent tests pass in5.73s, and the old partial-Put liveness implementation
still fails the positive AX proof in a private process. Thus the durable
regression covers the current payload, not just the older compiler artifact.

The isolated score witness is now a permanent regression at
`tools/dosunit/tests/test_generated_bitfield_function.py`, with frozen original,
candidate and helper slices plus unchanged generated C under `tests/data/bitfield_score/`
in the same component. Parent independently verified full artifact hashes,
all slices and relocation non-overlap. Four tests pass: scoped symbolic
observations (including root CS and full-width return control) and three actual
instruction mutation counterexamples. Restoring only the old liveness function
in a private test process makes the positive AX proof fail; live source is never
replaced. Scoped iteration lint passes. This protects a real compiled witness,
but does not replace fresh CLI regeneration or discharge entry/private-storage
premises. Acceptance remains **0/16, 0/118**.

Current function checkpoint (2026-10-10): a real VEX-to-SSA liveness defect
was isolated and fixed. A byte write incorrectly killed the whole word's
previous definition: `mov al,[...]; mov ah,0` lost the AL load. Partial writes
now retain the previous version for untouched bits. The frozen old function
fails17/18 new binary regressions; the corrected partial-write/call-composition
cohort passes45/45. Tests cover all four byte-addressable word registers and
both write orders, word-to-byte updates, and a changed-memory-load negative.
The regression is enrolled in the SSA component and routine pipeline.
The broader static dosunit module passes211 tests (5 KVM cases deliberately
deselected); iteration lint passes. Direct MyPy retains187 baseline diagnostics
in the legacy owner, verified with a process-local shadow preimage; no new
diagnostic beyond shifted line references. No whole-project gate is claimed.

The exact native counterexample input `00010101` gives513 in Unicorn and
VEX execution, versus257 in the old SSA model. After the fix the diagnostic
`.cache/score-abi-audit/symbolic.py` proves all9 selected observations:
AX, SP, BP, SI, DI, ESI-high, both runtime ESI halves and memory outside the
explicit fixture-private footprint. It composes both real helper calls and
proves their returns/CS. No default budget increased. This is symbolic for
arbitrary input bytes/register values within the recorded fixed entry and
storage relation, not just finite replay. Receipt: `symbolic.json` in that
directory. It is not complete ABI/flags validation, caller reachability, or
public-contract integration; conditional export and full0/16 acceptance remain.
The final diagnostic on reviewed sources completes in3.56seconds. The
misleading `uninterpreted_x86_flags` label on its old counterexample was a
second defect: exhausting1024 traversal steps invented helper evidence.
The bounded scanner now distinguishes actual helper evidence from incomplete
coverage and deduplicates shared compounds. Parent review corrected Devin's
queued-sibling cycle handling; malformed/cyclic references remain refusals.
Final combined regression rerun239passed/5KVMdeselected,36.30seconds; lint
and new-helper MyPy pass. One earlier run had an unexplained transient refusal
in the existing shifted-callee region-proof test (passes alone and on rerun).
Retain that limitation; do not call the earlier run successful.

Next: integrate an evidence-backed input/output correspondence, including
private-storage ownership/disjointness and every required observable, into
the existing proof contract. Do not infer private storage merely from extra
candidate stores or bypass resource gates by renaming the memory output.
The diagnostic's fixed fixture allocation is an explicit premise, not a
general recovery rule. The declared-entry premise remains until discharged.

Current bounded task: finish BITNBR `sub_1d12` before further optimization
or expanding recovery to `main`. Keep its declared-entry premise explicit;
do not obtain `validation=passed` by stripping that premise. Audit the existing
original-to-rebuilt binary comparison against the generated GP runtime and
the actual function ABI. Tail-transform preservation and finite replay are
separate evidence from original-to-generated symbolic equivalence.
Private host-adapter fault-injection controls in
`.cache/score-negative-controls/result.json` detect return corruption (6/6),
input writes (6/6), and conditional return corruption (3/6); unchanged payload
has 0/6 mismatches. These are six-vector host controls around the unchanged C,
not DOS mutation controls or completion of the two-compiler negative controls.
The same fault classes now have frozen BC31/DOSBox adapter controls:
`.cache/score-dos-negative/result.json`. Each run compiles the identical
generated payload: unchanged402/402pass, return corruption402/402detected,
input write402/402detected, conditional-return corruption201/402detected.
All guest exit codes agree with the harness failures. The unchanged rebuilt
EXE is byte-identical to the earlier DOS evidence. These remain isolated
harness-injected faults, not mutations inside a recovered body or completion
of both compiler lanes. Four compile/run checks took23.08seconds total.
The candidate-only call admission defect is fixed: the public comparator now
invokes existing complete call composition when either selected root has CALLs.
It previously inspected only the oracle. Real BITNBR now inlines both Borland
`N_LXURSH@` calls and proves both return targets and CS preservation. No new
near/far helper semantics were needed. Default comparison still refuses at
46 memory stores versus the unchanged limit of32. An isolated diagnostic with
limit64 reaches a full-machine-state counterexample (BX, DI, memory), not a
proof under the decompiler's declared entry / runtime-state correspondence.
Do not hide those effects or equate that unrestricted obligation with C ABI
equivalence. Evidence: `.cache/candidate-call-retry/production-report.json`
and `probe-64-report.json`; the latter is diagnostic process-local admission.
Next obligation: bind the actual declared function inputs and runtime-state
correspondence, using existing contracts where possible, before claiming
original-to-generated equivalence. Frozen compiler profile remains unchanged.

Binary correspondence diagnostic (2026-10-10):
`.cache/score-abi-audit/replay.py` executes both hash-pinned MZ binaries in
Unicorn, including the candidate's actual shift helper. All1024 seeded cases
pass with varied32-bit GP inputs and four input bytes. It checks AX, input
preservation, physical EBP/ESI/EDI, candidate runtime ESI, SP and return;
all observed writes are recorded. Oracle writes three stack words; candidate
writes ten stack words and the two runtime lanes EAX/ESI. This is finite
evidence at fixed, distinct valid DS/pointer coordinates, not a symbolic frame
proof or entry-premise discharge. Receipt: `.cache/score-abi-audit/replay.json`.
The same diagnostic mutates actual candidate instructions in private emulator
memory (original files unchanged): return add-to-sub is detected64/64,
unexpected input-store64/64, removed input bit38/64. Each mutation checks its
original bytes, invalidates Unicorn's translated-code cache, and is restored
before the next control. These strengthen the isolated binary checks; they do
not complete the two-compiler corpus negative-control requirement.
Do not equate every final runtime lane with the original physical register:
the C return carries AX, while the runtime EAX lane can hold an intermediate.
The next proof must state that output correspondence explicitly and prove
memory outside admitted private storage is preserved. Private storage must
be disjoint from user objects and escaped pointers; observed write addresses
alone cannot establish that for all inputs. Keep the declared-entry premise
and conditional verdict until separately discharged. No main/optimization
expansion is required for this isolated function obligation.

Follow-up checkpoint (2026-10-10): the generated `sub_1d12` was built
unchanged with the frozen Borland 3.1 small-model/DOSBox profile. Devin's
isolated DOS harness matched 402 native-derived results, preserved input bytes
and ESI, and exited 0. Parent reviewed the harness and byte/hash bindings, then
independently reran the built DOS EXE: 402/402, exit 0. Evidence:
`.cache/score-dos-review/` and `.cache/score-dos-parent/result.json`.
This closes the isolated concrete DOS build/run check, not whole-case or
unconditional symbolic acceptance; the native oracle and rebuilt fixture use
their respective valid DS/near-pointer coordinates.

BITNBR `0x1ce2..0x1d04` now also exports conditional C, but its first concrete
check exposed 2000/2048 mismatches. GP lowering created correct temporary
captures; virtual-expression cleanup then replaced captured memory reads with
reads of already-updated architectural state. Cleanup now refuses unversioned
`SimMemoryVariable` reads instead of deleting those captures. Two compiled-C
regressions failed before the fix; 47 focused simplifier/GP tests pass afterward.
The new regression is enrolled in the canonical component's routine tests.
Scoped lint passes; all 17 scoped MyPy errors reproduce on the preimage.
Fresh unchanged C compiles with GCC Werror and matches 2048/2048 native memory
results, preserving ESI. Artifact:
`.cache/add-level-replay/fixed-generated/conditional/00001ce2-sub_1ce2.c`;
before/after receipts: `.cache/add-level-replay/{result,fixed-result}.json`.
`main`, complete-case rebuilding and full acceptance remain open.
No SORTDEMO or broad pipeline run was made. Acceptance remains 0/16 and 0/118.

Latest focused checkpoint (2026-10-10): BITNBR `0x1d12..0x1d43` now has
fresh generated C in `.cache/score-return-fix/unsigned-final-generated/conditional/00001d12-sub_1d12.c`.
The inferred byte pointer explicitly renders unsigned, and address-label
normalization preserves required semantic casts. Both defects have failing
before/passing after controls. Focused cohort: 87 passed; scoped iteration
lint passed. Scoped MyPy has the same 58 diagnostics as the shadow preimage,
with no added/removed messages. No broad pipeline or SORTDEMO run was made.
GCC C11 `-Wall -Wextra -Werror` compilation passed. Under the declared fixed
DS/SS/pointer, 12,288 native-vs-C scalar/input checks passed; UBSan and expected
return checks passed for all 65,536 tag values with the other fields zero.
The host harness uses one guest-memory array biased to preserve the declared
near-pointer encoding; it asserts that mapping before calling unchanged C.
This remains **conditional**, not `validation=passed`: it does not establish
all-state equivalence, flags/stack scratch or a DOS round trip. Keep acceptance
at 0/16 and 0/118. Finish this function's acceptance before broad optimization.
Evidence: `unsigned-final-{native,tests,lint,replay,sanitizer}.log` and the
matching JSON/harness files in `.cache/score-return-fix/`.

Current user priority: finish one small generated function before further
optimization. Fresh normal CLI emission of BITNBR `0x1d04..0x1d12` produces
the unchanged conditional C payload (exit 5). GCC C11 compilation with the
emitted runtime header passes `-Wall -Wextra -Werror`. A bounded comparison
executes the original, hash-checked 14 bytes in Unicorn against the compiled
generated C: 512 cases cover all 256 values of the affected byte and two
neighbor patterns; six data bytes and full ESI agree. Oracle BP, SP and near
return are also checked. Changing the native mask from `0xfe` to `0xfc` is
detected at byte value 2. This is concrete evidence with fixed valid DS/SS and
pointer, not all-state equivalence: flags and stack scratch are not compared.
Transformation validation remains conditional on the declared function entry;
there is no DOS rebuild or whole-case acceptance. Evidence and reproducible
replay: `.cache/one-function-delivery/`. Next establish the function's ABI and
remaining validation obligations, then advance to the other application
functions; do not resume general performance work first.

The next application function `0x1d12..0x1d43` now has a fresh focused
normal-CLI baseline: exit 4, `validation_failed` (not timeout). Structuring is
conditional; postprocess refuses an uninitialized virtual-carrier read
(`tmp_id-1:size1:root.stmt1.stmt2`). Partial C also contains an invalid
address-of arithmetic expression in the return. No accepted C artifact is
exported. Next bounded repair: identify the typed producer/consumer responsible
for this function's scalar return and carrier definition, preserve the failing
validation control, and fix the earliest semantic owner. Do not repair rendered
C or weaken the guard. Full log: `.cache/one-function-delivery/score.log`;
the diagnostic detail artifact path is recorded there.

One producer/consumer defect is now repaired: terminal return-type lowering
looked only in `project.kb`, while direct codegen retains its function in the
analysis KB. It now consumes the existing `codegen_function_8616` owner without
mutating the default KB. The native diagnostic previously logged
`function=False` despite complete AX evidence. A real recovered-function
regression failed before this fix; the final focused cohort has17passed.
Scoped lint, MyPy and startup architecture checks pass. Fresh BITNBR rerun still
exits4 with the same validation failure and invalid return expression: this
owner fix is not function acceptance. Evidence: `.cache/score-return-fix/`.
Continue at typed return-expression construction; do not suppress the guard.

Early return-width transport is now implemented. Native ReturnMaker received
a guessed `char` prototype and selected AL despite complete terminal AX
evidence. `native_terminal_return_values.py` now asks the existing typed
return owner to refine that guessed byte before native return construction
and SSA. Explicit prototypes, AL-only and unknown-storage cases remain
unchanged; the guessed status and typed evidence counts are retained. A focused
boundary regression first failed; final ownership/return cohort32passed, with
scoped lint/MyPy and startup architecture checks passing before the native run.
That run removed the invalid pointer dereference and uninitialized-carrier
failure: both transformation stages are conditional, and the return is now
unsigned short arithmetic. It still exits4 because portable GCC rejects
`inertia_si = arg_4` (pointer assigned to integer without a cast). Thus there
is still no accepted second-function artifact or completed round trip.
Evidence: `.cache/score-return-fix/early-native.log` and `early-final-tests.log`.
Next fix the existing pointer-storage projection at the GP write boundary;
do not insert casts in rendered C. Concrete replay is still required after
compilation succeeds, particularly for the remaining DX/stack reload effects.

Pointer projection diagnosis: GP lowering initially receives an integer
temporary, then typed argument substitution replaces its value with a pointer.
A new canonical GP-write refresh consumes the existing pointer-storage bridge
before validation (not in rendering). Its regression failed first;46focused
GP tests and scoped lint pass. Scoped MyPy retains one `no-any-return` at
`gp_register_state.py:337`, reproduced on the pre-change source via shadow-file;
the introduced return boundary is explicitly typed. Actual CLI still exits4:
validation rejects a later simplification and restores `tmp_0 = arg_4`, so the
pointer-to-integer failure now resides in the scalar temporary assignment.
Next fix that earlier typed storage conversion rather than adding rendering
casts or suppressing rollback. Evidence: `pointer-fixed-native.log` in the
score-return-fix directory.

Independent concrete diagnostic found an actual scalar-result mismatch:
four zero input bytes give native AX0 but generated return256; armed-byte1
gives256 on both. The diagnostic compiled unchanged partial C while allowing
the already-known pointer-conversion warning; it is not accepted compilation
or proof. The final `dx_2 = SEG_U16(SS,SP)` overwrites the previously loaded
field. Original bytes are hash-checked. Preserve this mismatch as a repair
target; conditional transformation validation did not detect it. Evidence:
`.cache/score-return-fix/score-diagnostic-replay.json`. Devin has a bounded
read-only task on the GP stack restore/reload owners; no production changes
are authorized for that worker.

Scalar temporary storage conversion now consumes the existing pointer bridge
for exact16/32-bit integer temporaries after argument substitution. Width
mismatches and pointer destinations are retained.70focused tests, scoped lint
and startup architecture pass;55MyPy diagnostics in the existing segmented
owner reproduce on its pre-change shadow source, with no new messages.
Fresh CLI exports the second function as conditional (exit5); its unchanged
C also compiles with GCC `-Wall -Wextra -Werror`. Generated artifact:
`.cache/score-return-fix/scalar-fixed-generated/conditional/00001d12-sub_1d12.c`.
The concrete0→256mismatch remains in this successfully compiled artifact
(`score-current-replay.json`), so this is not function acceptance.

Constructor tracing pinpoints the bad insertion:
`ir_segmented_load_carriers._materialize_identity_assignment_8616` inserts a
register8/identity`ir_8` assignment from a logical reload tagged0x1d2c.
Exact native disassembly confirms0x1d2c is POP DX, followed by ADD AX,DX and
MOV DL,[SI+1] at0x1d2f. The inserted late reload must not overwrite the newer
DX version. Investigate the physical-register/SSA-version binding and insertion
point, not an epilogue POP or renderer repair. Trace:
`.cache/score-return-fix/reload-trace.jsonl`. Devin's bounded read-only run
timed out without a patch; its epilogue hypothesis was not adopted.

The spurious DX reload is repaired. Missing-assignment reconstruction now
retains every existing SSA definition, including multi-origin, missing-origin
and equal-origin tags; origin addresses are not execution-order proof. An
existing definition cannot be overwritten by a guessed physical-register
reload. Three focused controls failed before the fix; the carrier cohort is
14passed, scoped lint and MyPy pass. Fresh CLI exits5/conditional and removes
the late DX overwrite. Generated C compiles with GCC `-Wall -Wextra -Werror`.
4096 concrete native-vs-generated comparisons agree: all256 first-byte values,
second-byte0/1/254/255 and tag0/0x234/0x8000/0xffff, under fixed DS/SS/pointer.
Input bytes are preserved; this does not establish flags, stack-scratch,
all-state equivalence or a DOS round trip. Artifact:
`.cache/score-return-fix/ssa-fixed-generated/conditional/00001d12-sub_1d12.c`;
reproducer `replay-score.py`, result `score-ssa-replay.json` in the same work
directory. Existing definition handling deliberately leaves uncertain
dominance/invalid def-use paths to validation rather than repairing by address.
Next application function is0x1ce2..0x1d04; main and whole-case acceptance stay
open. Continue with small function emission before general optimization.

Do not overstate the4096 replay matches: a further UBSan run of that same
generated score C fails on input00000080 with `left shift of negative value
-128`. The high-byte expression needs unsigned widening before shifting;
casting only the shifted result is insufficient. This remains a correctness
blocker despite concrete scalar-result matches. Reproducer and log:
`.cache/score-return-fix/score-sanitizer.c` and `score-sanitizer.log`.
The third-function baseline0x1ce2..0x1d04 also exits4 and retains partial C;
see `add-level-native.log`. Finish the score function's signed-byte conversion
before expanding to that next repair. No whole-case acceptance is claimed.

User priority: produce C from the binary before spending further iterations on
entry-proof budget tuning. An unproved entry premise must not authorize scoped
pruning, entry-state substitution, universal publication or validation success.
Investigate a typed unproved intake that preserves the complete raw graph and
allows ordinary conservative decompilation with visible refused validation.
Generated C alone is not a completed round trip; all acceptance requirements
below remain. Cython pure-Python compilation is for measured runtime hotspots,
not a workaround for the logical work-unit limit.

Finish `bitfield_neighbors@bc31-small` from its unchanged source. The frozen
original compile/link/run returns 255. Authenticated libdosbox entry capture and
explicit compiler context are in `.cache/bitfield-route/`. DOSBox is explicitly
selected. KVM availability is an environment/namespace property: static SSA
analysis does not require KVM, and no specific KVM API level is claimed without
fresh verification. The current kvikdos generation `3d75` has fresh
compile/link/run probes for all four MSC5.1/Borland3.1 small/large profiles.
Borland explicitly selects host DPMI `off`; MS retains `auto`. All four EXE
hashes and observations match the prior probes. Actual typed build/runtime
owners reproduce the frozen bitfield EXE exactly, with exit 255, in
approximately 0.10s. This is original-only reproduction evidence — it is not
decompiler acceptance — and the DOSBox entry declaration remains DOSBox-bound.
Never silently exchange runners or environment evidence. Receipts:
`.cache/native-runner-allprofiles-verified/` and
`.cache/kvikdos-profile-mode/native-bitfield-v2/`.

Ordinary first-case round-trip command, after semantic sources are frozen and
main preparation passes (no declared-entry input):

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 .venv/bin/python -m tools.compiler_toolchain \
  --manifest examples/compiler_coverage/first16.json \
  --case bitfield_neighbors@bc31-small \
  --profile-evidence .cache/bc31-first-acceptance/toolchains.json \
  --out-dir .cache/compiler-coverage/bitfield-ordinary-reviewed-r1
```

Use a fresh output directory. The selected registry currently verifies and
explicitly uses DOSBox. This execution profile does not by itself grant an
interrupt-service proof premise to static analysis. Do not use
`.cache/bitfield-route/toolchains-frozen.json`: its probe-evidence hash no longer
matches. The default registry selects kvikdos and is a distinct execution
profile. All34 pinned source/catalog inputs across the16 starter cases were
rechecked and match; this establishes input integrity only.

The 14-byte application function at 0x1d04 exports declared-entry conditional
C+JSON (exit 5) and compiles as portable C; this is a conditional export, not a
round trip. Alias-proven GP restoration consumes the existing pointer storage
bridge. Main 0x1d43..0x1e54 remains unproved; no DOS rebuild or whole-case
acceptance follows. Negative address controls must retain refusal for narrowed
references/physical pointers, signed selectors, word-scaled references and
pointee casts that change displacement units. Evidence:
`.cache/bitfield-gp-restore/`, `.cache/bitfield-pointer-fix/`.

## Blocking mechanism and next action

The selector invariant is promoted to canonical owners:
`inertia/ir/declared_selector_invariant.py`, its control/native effect helpers,
and frontend instruction-fetch/control geometry. The pipeline retains the
identical declared root link. Conditional CALL records are separate from full
invocation evidence; actual caller CS, universal callee segment closure and
ordinary callee GP/SP/memory/return simulation remain required. Weak evidence
cannot authorize universal publication or prefix replay.

Parent integration cohort: **142 passed**, one warning, 46.84s; existing CALL
regressions:17passed,1warning/16.18s. Startup
architecture and scoped lint passed. Three new authority controls first failed
for post-native-callback module mutation, exhausted shared work and expired
shared deadline, then passed after consumer fixes. This is focused evidence,
not first-case acceptance. Logs: `.cache/selector-parent-integrated-tests.log`,
`.cache/selector-canonical-authority-red-plain.log`.

Current frozen parent measurement (2026-10-10): selector certificate
**0→8110** units. Immutable native graph facts are integrated; final seals
traverse current IR once, while keeping original and fresh-native comparisons.
The shared fresh batch admits all four CALL projections at **18885 units**.
Collector final callee/CALL reconciliation still exhausts the unchanged20000
limit. Reviewed caller-position reconciliation reduces its attempted ledger
from21732 to20948 before full invocation. Some final checks stop on exhaustion,
so20948 is not the complete required work. The fresh final probe reproduces
the refusal in2.39s with stable source hashes; this is not a controlled timing
gain. Evidence: `.cache/collector-final-work/parent-main-final.log`.

Native review: a new boundary-metadata serializer hid list/tuple changes.
Removed it, preserving prior detached metadata behavior. Parent reproduced the
negative red and green; all243 focused controls, scoped lint and MyPy passed.
Immutable graph facts remain exact and deeply immutable. No budget/deadline
increase; selector accounting charges the one actual final current-IR walk.

Next: measure and remove duplicate final callee/CALL work. Four provisional
records snapshot callee facts costing732,537,346,732 units; final caller-block
checks now reserve463,100,60,165. These are measured preparation-derived costs,
not completed post-exhaustion checks. Repeated callee7442 still receives fresh
boundary wrappers, preventing exact-identity sharing. Preserve fresh geometry,
source authority, caller membership and late mutation refusal; do not cache a
successful verdict or drop required evidence. Full invocation and the actual
DOS round trip remain unproved.

The callee state-map census has no repeated mutable containers to deduplicate:
callee7442 costs332 graph rows+400 metadata entries;7394 costs263+274;
7428 costs198+148. A visited-container memo leaves those counts unchanged.
Evidence: `.cache/collector-final-work/callee-cost-baseline.log`. Do not pursue
that shortcut or reduce its charges without removing actual traversal.

The reviewed survey/recording fusion retains every native instruction head,
STORE, CALL, control, selector and unknown effect; raw IR is kept in full.
Original snapshots survive callbacks and repeated selector seeds. Thirty
static/mutation controls and scoped lint/MyPy passed. This is prerequisite
evidence, not first-case acceptance. No budget or deadline was increased.

The callback-laundering defects found by review are repaired: capture graphs,
boundaries, certificate selectors and projections before the first callback,
then reconcile original and fresh native facts after every callback. Controls
reject coordinated projection/certificate changes, altered native imports and
late mutation of survey-omitted ordinary rows.

### Current bounded specification: caller membership reconciliation

Owners: `inertia/ir/declared_selector_call_preservation.py` collects the CALL
obligations; `entry_domain_call_preservation.py` binds caller membership;
`inertia/semantics/direct_near_call_target_binding.py` seals pending operands.
Retain typed operation-local block/instruction positions before callbacks.
Any replacement for a membership scan must check the exact artifact, block,
instruction, current stream and slot, plus all existing coordinates, native
authority and certificate conditions. Removal, replacement, reordering,
foreign ownership and late mutation must refuse. Public standalone consumers
continue to authenticate fresh evidence; no successful verdict is cached.

Separate membership cost from the pending canonical source-graph pass:
eliminating a membership scan does not eliminate graph authentication or its
charge. Preserve full field/provenance and malformed-graph checks. Charge actual
visited rows and metadata; retain the 20000-unit/25s request unchanged.

Acceptance: focused red/green traversal and adversarial controls; current
collector, selector-batch and pending-binding regressions; scoped lint/types;
then a source-stable complete main probe. A partial cost reduction is not main
preparation or first-case acceptance. Callee sharing is a separate measured
follow-up, not permission to expand this slice.

This slice is implemented and parent-reviewed against saved dirty preimages.
Six focused controls first produced4failures/2passes; final affected cohort:
132passed,1warning. Scoped lint passed. Scoped MyPy has45errors, all reproduced
on the saved preimages; no new diagnostic messages. Nine wider test failures
also reproduce on those preimages and remain unresolved outside this slice.
Required position fields are supplied by updated test fixtures; production
does not weaken its contracts to accommodate mocks. Evidence:
`.cache/collector-final-work/`.

The raw decoded-callee census experiment is complete without production edits:
collector19894, then full-entry proof attempted21746 and refused. Parent
measured54 additional native census rows whose traversal must also be charged.
This is not first-case acceptance or a finished optimization. Evidence:
`.cache/callee-census-reuse/report.md`, `.cache/callee-census-parent/count.log`.

Next bounded task follows the user priority above: find why an unproved declared
entry aborts before C generation and exercise a conservative full-graph route.
Owners are `declared_entry_pipeline.py`, its VEX attachment consumer and Clinic
conversion consumer. Required typed outcome distinguishes proved scoped intake
from unproved full-graph intake. Both retain native provenance and malformed
input errors; only the proved outcome can prune. Preserve declarations and
report non-proof explicitly rather than silently falling back. Diagnosis is
recorded in `.cache/decompile-before-proof/`: declared main has22 raw blocks,
1808IR instructions,4CALLs and6 unresolved control obligations. No C was emitted.
The ordinary-path probe without declarations did not recover main; removing
declarations is not an acceptable workaround.

Typed unproved intake is implemented in the shared tree; integration remains
open. Saved dirty preimages and logs live in
`.cache/unproved-entry-implementation/`. Parent review found and repaired a
downstream universal-publication leak: unproved entries now retain raw IR/SSA
without constructing a semantic projection. Two focused publication controls
failed before that repair. Premise status is constructor-independent and exposed
in function diagnostics. Invalid declarations, changed native input and failed
boot replay remain errors. Resource-limited proof returns typed non-proof,
without authorizing pruning or renewing its budget.

Current focused cohort:70passed/27.49s; scoped iteration lint and startup
architecture checks passed. Scoped MyPy reports three `no-any-return` errors
in `vex_import.py`, reproduced with all six saved preimages via shadow files.
This does not establish emitted C or first-case acceptance. The first parent emission
probe exposed a diagnostic defect (synthetic empty function followed by another
CFG pass). A clean, explicitly seeded CFG probe instead reports main unrecovered.
The normal `decompile.py` CLI does recover main and enters decompilation; use
that invocation rather than treating the isolated helper probe as authoritative.
Its60s run exits3 with `status=timeout`, no generated function C, and uncollected
tail validation. Evidence: `parent-current-cli.log` in the directory above.
The same-budget sampled CLI run also exits3/status=timeout. Its actual fork
worker reaches postprocessing: samples include angr reaching-definitions,
recursive `c_ast_utils._walk`, and `tail_validation_generation_atoms._dataclass_atom`.
Two rejected optimization passes were restored, preserving their validation
failures. Evidence: `parent-cli-stacks.log`; all five10s samples belong to the
real decompilation worker (some JIT frames lack line numbers). Next: measure
repeated AST/validation traversals on this path before choosing an optimization;
the remaining timeout is not solely entry-domain preparation. Do not increase timeout or claim the
typed-intake unit cohort establishes complete emission. The historical DOSBox
compiler profile also fails its frozen-profile identity check; the normal CLI
run is diagnostic under current configuration, not acceptance under that profile.
SORTDEMO must not be executed at this time (user instruction).

Measured priority update: parent phase instrumentation recorded62 completed
postprocess passes totaling11.395s: validation5.664s, snapshot setup1.608s,
cycle gates0.847s. Therefore cycle-check optimization is not the primary lever.
External20Hz py-spy recorded1421 samples (zero sampling errors, lag warnings):
619 sampled stacks include Clinic, and400 of those include
`frontend/x86_16/load_propagation.py:refuse_reordered_loads_8616`. Many samples
are temporary Assignment construction and repeated `has_load_expr` traversal.
These are sampling counts under profiler overhead, not a controlled speedup.
Artifacts: `.cache/ast-pass-profile/cli-stacks.raw`, `events.jsonl`.

The load-propagation guard optimization is implemented and parent-reviewed:
direct expression walking avoids synthetic Assignments; identity reuse lasts
one invocation; reverse-index ordering lookup avoids copying block prefixes.
Store/SideEffect barriers, nearest definitions and missing-evidence refusals
remain unchanged. Parent rejected Devin's all-prefix cache:300 adjacent uses
regressed17ms→530ms and5.7KB→2.3MB in its measured run. The replacement visits
300 statements rather than copying90000 prefix elements. Both performance
controls fail against the saved preimage. Mutation and nested-load controls
cover per-invocation reuse, calls, ITE and embedded statements.

Saved BITNBR workload:1941 replacements, nine paired samples, median17.03ms
before /6.91ms after, identical mappings and evidence counts. This is local
performance evidence, not end-to-end acceptance. Focused guard/stack cohort:
73passed; iteration lint and scoped production MyPy pass. Two previously
failing integration cases lacked explicit stack-compatibility installation;
the tests now enable the production hook. No production weakening was needed.
Preimages and logs: `.cache/load-propagation-speed/`. Devin was stopped after
its reviewable patch; parent repaired the ordering regression and finished
checks. The earlier cycle/atom workers made no production changes.

The same60s normal BITNBR CLI still exits3/status=timeout, with no generated C
and uncollected tail validation (`parent-cli-after.log`). Neither first-case
acceptance nor whole-function speedup is established. Next bounded diagnostic:
sample the actual worker on the final reviewed sources to locate the remaining
timeout; keep limits fixed and do not execute SORTDEMO.
The final-source sampled CLI (`parent-final-cli.log`, exit3) reaches structuring
and postprocessing but still times out. Actual worker stacks include composite
pretest condition materialization via `c_ast_utils._iter_c_nodes_deep_8616`,
its recursive `_walk`, and `structured_ast_generation._fields/_object_value`.
Scoped Pyright also passes. Next work should bound and reduce these repeated
AST traversals, preserving shared-node/cycle and mutation semantics; do not
restart the rejected all-prefix guard optimization or raise the deadline.

The generation-builder experiment is closed without production optimization.
Devin's per-type dispatch cache changed digest bytes for two dynamic boundary
instances sharing one Python type but different `isinstance` classifications.
Parent reproduced that mismatch, rejected the patch and retained a regression
in the existing direct-stack reload test module. A smaller buffer-only patch
preserved the digest on5212 native AST nodes, but twelve alternating paired
samples gave only1.039x CPU speedup (0.1070s→0.1032s median). It was also removed;
do not repeat these approaches without a stronger measured opportunity.
The original builder source is restored exactly. Focused final cohort29passed;
the new dispatch control fails against the rejected worker builder. Scoped
iteration lint passed. Artifacts/preimages: `.cache/ast-generation-speed/`.
Full cProfile instrumentation
prevented recovery from completing and produced no builder measurements; discard
that run as a hotspot measurement. Lightweight timing also did not reach the
builder under concurrent external decompiler/indexer load (recovery55s versus
earlier~20s). No source regression or improvement follows from those timeouts.

Compiler-context obstruction is resolved independently: the sole serialized
profile difference was the added `kvikdos_dpmi_mode="auto"` field. Removing
only that field from the current resolved profile exactly reproduces the old
profile hash; evidence bytes, DOSBox backends, flags and verified tools match.
The canonical `FrozenCompilerContext.create` and `.resolve` now validate a new
`.cache/bc31-dosbox-unblock/compiler-context-current.json`; the old context is
preserved. Explicit wrapper: `run-current-profile-cli.py` in that directory.
Use this DOSBox-bound context for further diagnostics; no runner substitution
or fingerprint bypass occurred. This is not generated-C or round-trip evidence.
The refreshed-context CLI (`current-profile-cli.log`) passes profile admission
but still exits3/status=timeout at60s, no C and uncollected tail validation.
Its last full worker stack identifies GP version capture during the structuring
suffix: `gp_register_versions._plans` via `gp_register_state` and
`_replay_structuring_gp_state_after_late_cleanup_8616`. Source inspection shows
whole-root occurrence, owner and scope scans repeated per candidate identity.
Next bounded Devin slice owns that planner and its existing tests only:
share occurrence counts and owner/group census within one planning invocation,
preserve shared-edge multiplicity, lazy cycle failures, dominance, call clobbers,
pointer projection and exact counters. No persistent prefix maps or cross-call
reuse. Preimages/prompt/logs: `.cache/gp-version-scan-speed/` and
`.cache/devin-prompts/gp-version-scan-speed.md`. Parent must review measurable
gain and semantic controls before another current-profile CLI.

The subsequent actual-worker diagnostic bounds this opportunity:21completed
GP capture calls total2.037s, including one1.544s call with91156 occurrence
visits. The whole request still exits3 at the unchanged60s budget, with no C
and uncollected validation. Thus the planner is not the dominant explanation
for the timeout; do not describe its optimization as the whole-case unblock.
Evidence: `.cache/gp-version-scan-speed/events.jsonl` and `baseline-cli.log`.
Next measurement records coarse core/priming/postprocess/pass-validation wall
and CPU boundaries directly in the actual worker, without global profiling.
Use `measure_stages.py` in that directory; preserve the current compiler
context, request limits and the prohibition on executing SORTDEMO.

Coarse stage evidence now localizes the remaining work: the first stage probe
spent39.08s wall/38.96s CPU in core decompilation, then3.12s collecting the
validation baseline. A second probe (with Devin's provisional GP patch loaded)
spent42.88s/42.79s in core, including24.07s semantic priming:17.14s prefix and
2.73s suffix. VEX-IR preparation accounts for5.08s within priming. These are
inclusive diagnostic spans, not additive totals or a controlled before/after
comparison. Both requests still exit3/timeout. Further optimization should
target measured priming owners instead of assuming host contention or GP
capture explains the whole delay. Artifacts: `stage-events.jsonl`,
`core-events.jsonl` and corresponding CLI logs in the same diagnostic directory.

GP planner slice is implemented and parent-reviewed. Whole-root occurrence and
owner inventories are invocation-local; per-statement counts preserve shared
edge multiplicity. Parent review caught quadratic retained subtree histograms
in the initial Devin patch. A nested40-scope regression failed on that patch;
the final implementation limits retained identity entries to twice the root's
distinct identity count and recomputes after eviction. No state survives AST
mutation. Final focused GP cohort36passed; iteration lint and scoped MyPy exit0.
The saved-preimage differential reports identical plans/stats/digests/refusals,
median33.69ms→11.16ms (3.02x) on its small synthetic fixture; traced peaks round
to0.02→0.03MB. These figures are not a whole-function speedup. Parent artifacts:
`nested-red.log`, `parent-green.log`, `parent-bench.log`, `parent-lint.log`,
`parent-mypy.log`. Remaining acceptance is unchanged:0/16 and0/118.

Final finer-grained diagnostic on the reviewed planner also exits3/timeout,
without accepted C. Inclusive spans: core35.63s CPU35.59s; structuring semantic
priming16.56s (prefix10.61s, suffix2.45s); structuring passes6.01s; initial
VEX-IR preparation3.27s; condition cleanup1.51s; later validation summary2.60s.
The differing diagnostic scopes/runs do not establish an end-to-end gain.
Next bounded task: inspect repeated priming/lowering and condition-refresh
work using `owners-events.jsonl`, identify an exact unchanged-input duplicate
before eliminating it, and preserve all final semantic/validation consumers.
No raised deadline, skipped validation or new global cache. Corresponding
terminal log: `owners-cli.log` in `.cache/gp-version-scan-speed/`.

### Current bounded specification: Clinic to codegen entry handoff

Low-overhead50Hz `py-spy --subprocesses` collected3708 samples without sampling
errors;1949 include the core-decompile frame.507core samples (26.0%) include
`prepare_declared_entry_pipeline_8616`;259 (13.3%) include immutable source-graph
capture. These are inclusive sample shares, not additive timing totals.
The decompiler still reports timeout; py-spy's supervisor exits1 with
`No child process` after writing the samples, so its status is not a successful
decompilation receipt. Raw profile and terminal log:
`.cache/condition-cleanup-speed/bitnbr-samples.txt`, `sampled-cli.log`.

Observed wiring: Clinic's conversion prepares and retains an entry record;
structuring attaches that same Clinic to `codegen._clinic`, but final IR
preparation only consults the codegen's own retained record. Investigate explicit
transport of the authenticated **unproved** input, without rerunning the failed
optional premise proof. This is a pipeline handoff, not a project/address cache.

Requirements:
- Same project, function head, exact native boundary, boot and declaration;
  current native bytes and retained raw graph must still authenticate through
  canonical contracts. Identity/address alone is insufficient.
- Preserve `UNKNOWN_REFUSE`, complete raw effects and diagnostics. No scoped
  pruning, substitutions, universal publication or validation success follows.
- Missing Clinic keeps ordinary preparation. Changed/foreign/forged inputs
  preserve hard failure or the existing honest re-preparation path. Keep the
  proven-entry route unchanged in this bounded slice.
- Focused negative controls must cover native/declaration/raw-graph mutation,
  foreign project/head and removed authority. A valid transfer performs native
  preparation once across Clinic and codegen; then verify actual BITNBR at60s.

Devin owns the IR entry owner and existing unproved-entry tests, with saved
preimages under `.cache/entry-handoff-speed/`. A separate Devin owns only
condition materialization and its tests under `.cache/condition-cleanup-speed/`.
Both require parent review and measured evidence; neither is plan acceptance.

Parent completed the independently reviewed composite-pretest early admission:
fewer than two typed conditions cannot yield any composite raw candidate, so
return all-zero statistics without walking AST. With sufficient facts retain
deep traversal, including loops nested inside expression-owned statements.
Two no-scan controls failed before; final cohort15passed, iteration lint and
scoped production MyPy passed. This removes provably fruitless work but is not
measured first-case progress or a reason to weaken missing-evidence reporting.

Performance evidence: diagnostic-only work limits50000 and100000 still refuse
scoped CFG construction in4.31s and6.50s respectively; production limits were
not changed. Instrumented profile shows53 source-graph encoder preparations
taking8.61s cumulatively within25.07s main preparation. The isolated Devin
experiment in `.cache/source-graph-cython/` is complete: pure-Python-syntax
Cython annotations reduced median canonical encoding from0.172s to0.144s and
graph capture from0.153s to0.118s across nine warm samples. Canonical bytes and
four malformed/cyclic-input refusals matched; interpreted annotated source
also matched. This is kernel evidence only; no production integration or
end-to-end speedup is established. Its `status=prepared` diagnostic means a
preparation call returned, not that its entry premise was proved. Review the
returned typed record before treating any preparation result as proof.

After the collector genuinely fits, measure full invocation. If repeated
internal CALL admissions dominate, use typed provisional CALL obligations and
one final fresh synchronous batch before any successful domain or feasibility
pruning escapes. Preserve callee GP/SP/memory/return simulation and failure
priorities; selector preservation alone is not a complete invocation theorem.
No positive-proof cache, renewed deadline or budget increase is permitted.
Review and the complete main regression are required before the round trip.

Acceptance is still **0/16 starter, 0/118 matrix**. Main preparation must become
a genuine full invocation proof before emitted C, same-toolchain rebuild and
whole-case behavior comparison can establish the first completed case.
The direct prerequisite regression is now
`tests/ir/test_declared_main_budget.py`: complete main preparation within the
unchanged25s/20000-unit request, without KVM. Baseline red reproduced
`PipelineHardError` at the real entry-domain phase (1failed/5.27s); scoped lint
passed. After the CALL changes, run this test before the round-trip command.
Keep it in the bounded proof lane at integration; it is not a broad-unit worker
benchmark. Do not replace its required complete preparation with a partial
selector certificate.

## Retained mechanisms and enrolled controls

These integrated mechanisms remain in force; their obligations are not relaxed
by the staged work above.

- Discarded-snapshot omission in the invocation, edge-feasibility and
  repeated-store owners: the exact terminal CALL may be excluded only at the
  selected stop, with no requested cut and fresh canonical producer identity.
  Foreign LOAD/STORE/memory/call observers retain replay; ordinary fixpoint
  effects and all five counters remain mandatory.
  (`.cache/parent-root-load-final/`)
- Terminal native selection copies only the consumed prefix of the explicit
  root stop block; every returned row stays deeply detached; whole-block
  consumers retain full binding or freshly upgrade the selection.
  (`.cache/native-prefix-copy/`)
- Caller scalar-prefix fusion binds native rows while transferring the scalar
  prefix into private state, then binds the complete suffix before any CALL
  executes; provenance, late-mismatch rollback, counters and resource-failure
  priority are mandatory. (`.cache/caller-prefix-report.md`,
  `.cache/caller-prefix-native/`)
- `entry_call_pool_advice` selects replay work only: READ replays, UNUSED
  skips the eligibility scan, UNKNOWN keeps it; only a fresh UNUSED receipt
  authorizes sharing. (`.cache/replay-advice-*/`)
- One-pass eligibility gate collects owner/other-CALL blocks in one charged
  walk plus one canonical predecessor closure. (`.cache/entry-pool-gate/`)
- Flag-ownership fix: sessions bind to the source project and complete
  instruction ownership; foreign helpers use local decoder evidence; cache
  keys bind the effective policy. (`.cache/flag-owner-fix/`,
  `.cache/native-effect-boundary/`)
- Deferred caller-range interval selection inside the existing interval-query
  walk, only when the query runs. (`.cache/flag-owner-next/caller-range-native-deferred/`)
- Tuple-dispatch registry: exact built-in entry tuples and direct lookup with
  no mutable backing store; fresh seals bind lookup aliases and registry
  identities. (`.cache/tuple-dispatch/`)
- Block-local dead-TMP normalization and predicate-width propagation before the
  common native surface; every deletion keeps typed evidence and closed stage
  counts. (`.cache/flag-owner-next/`, `.cache/post-normalization-cost/`)
- Identity-bound CFG cut witness `inertia/ir/real16_prefix_cut.py`; write
  footprint guard `_feasibility_code_unmodified_8616`; routine controls in
  `tests/ir/test_sparse_code_write_guard.py`.
- Private opt-in transcript capture/enrollment and terminal-CALL continuation
  remain unarmed by default; payloads are data only and grant no
  completion/reuse authority. (`.cache/prefix-transcript-owner/`,
  `.cache/prefix-enrollment/`, `.cache/prefix-resume-current/`,
  `.cache/prefix-absorbing-implementation/`)

## Rejected experiments — do not repeat

- Record/scratch row loans and public object-token borrowing: a rebound
  call-effect handler poisoned the cached MOV row.
  (`.cache/scratch-native-parent-review/`, `.cache/scratch-native-parent-fixed/`)
- Discarding private-call replay: all expensive interior calls are selected;
  unselected calls are already terminal-exempt, and skipping simulation changes
  failure priority and callback multiplicity.
- Copy-transfer wrapper: a custom fetch could self-assert ownership.
  (`.cache/native-projection-transfer/REJECTED.md`)
- Reducing collected CALLs leaves later reachable calls unproved under the
  whole-region theorem.
- Finished-premise caching yielded zero real hits and was removed; never cache
  refusals as positive proof.
- Fresh-native unretained import; producer seal-only reduction (≤1562 units,
  still >20,000; flag summaries already cover that owner).
  (`.cache/native-fresh-experiment/`)
- Branch-snapshot fusion and pure-prefix reuse as case fixes; native equality
  receipts cannot remove importer copying; frozen-node mutation controls forbid
  identity-only reuse across callbacks.
  (`.cache/branch-snapshot-fusion/APPLICABILITY.md`)
- Identity-only `MappingProxyType` dispatch seal: mutable backing dictionary
  can escape through overloaded equality/union. (`.cache/registry-cost-review/`)
- CJMP/fixpoint snapshot skip and the REP snapshot experiment: later callbacks
  and code-manifest growth can invalidate earlier proof/write guards.
- Upfront caller-range preparation (regressed the primary late scope
  26032→26208) and eager scratch register/memory-copy deferral (≤117 units,
  too small). (`.cache/flag-owner-next/`)
- Enabling detached transcript payload copying by default: its 1672-row
  capture costs 10,102 units against a 545-unit margin.
- The pure-Python-syntax Cython encoder probe is not integrated.
  (`.cache/cython-source-graph/`)
- Census/work budget increases, renewed timeouts on retries, and any raising of
  the 20,000-unit cap or 25s deadline remain rejected, not active deliverables.

## Shared invariants for bounded optimization work

- Work on one smallest failing real function before corpus expansion. Keep one
  owner on the semantic defect and another on its measured bottleneck, with
  explicit disjoint ownership. Each cycle needs exact diagnosis, focused
  red/green and a native result. Reuse unchanged successful checks; run broad
  gates at integration boundaries. A repeated diagnostic needs a new question
  and a verified actual-worker observer. Frozen sources, compiler context,
  budgets and owned subprocess cleanup are mandatory during
  provenance-sensitive runs.
- Reduce repeated work without changing budgets, typed verdicts or freshness:
  synchronous factory consumers may inspect the exact just-derived result under
  the same accounting/depth/work/deadline admission; operation-local
  native/CFG/capture projections require current
  project/function/source/entry/Alias/configuration/producer bindings and
  detached copies; proof/discharge/finalization rerun; bounds remain 4
  records/256 blocks; caller work is shared only through dependent facts under
  existing proof owners with separate callsite/register/memory states.
- Measure actual work in the uncached worker: derivations/lifts/preparations,
  changed-input refusals, wall/CPU/contention/memory. Report the five
  evidence-loop counts. Overlapping test counts are never summed; diagnostic
  counters are not closed proof accounting; phase values that overlap nested
  derivations are not a disjoint whole-request profile.
- Charged-work reductions are not wall-time speedups and neither is acceptance.
  Unit-test/control counts never establish case acceptance. Supervisor-measured
  times only; before/after claims need identical source/input/context hashes on
  frozen sources.
- Preserve typed cause/function/stage/budget before fallback; refuse before
  expensive inputs when work exceeds the existing limit; owned typed contracts
  for mocks; frozen actual-case evidence for any optimization claim; exact
  source/module/load/environment/compiler/payload bindings for cross-run
  artifacts; explicit pinned runner context for execution; shared
  active-domain/depth/work/deadline admission before any producer; each phase
  retains its own premise/status so conditional/refused never merges into
  stable acceptance.
- Never clear raw refusals, lower work charges, or weaken freshness to force
  admission. Unknown raw effects remain code, never universal proof. Remove
  only demonstrably redundant verification, with measured benefit required
  before claiming speed.

## Scope and open acceptance obligations

All 36 source entries are present/retained and hash-pinned; all 16 baseline
originals compile and meet runtime contracts. These are original-only facts.
MS C 5.1 signed bitfields and automatic array initializers remain compiler
obligations; do not change sources/flags to hide them. Fresh unchanged-source
MS C 5.10 probes reproduce five C2073 initializer errors (no object) and three
C4014 bitfield warnings followed by exit 2 instead of 255. Evidence:
`.cache/msc51-original-obligation/compile-receipt.json`. No compatible spelling
or exclusion is verified. Manifests/profiles/receipts are owned by
`compiler-coverage-matrix.md`, `examples/compiler_coverage/` and
`../PROGRESS.md`. Entry capture belongs to
`tools/compiler_toolchain/capture_real16_entry.py`. Service/allocator policies
are explicit measured declarations. DOSBox and kvikdos evidence are distinct:
resolve an explicitly pinned available runner, never substitute it silently.
The prior broad pipeline was red with incomplete attribution; focused checks do
not discharge it. Recheck at integration, keeping unrelated failures separate.
Full CRT recovery is not a corpus deliverable. The existing signature filter
already excludes matched library bodies and retains application bodies. Do not
build another filter or recover CRT merely to emit application C. Calls remain
external only with authenticated ABI/effects; names/extent alone prove neither
preservation, memory effects nor termination. Unresolved required effects
block.

## Source-free conditional application boundary

Function validation may be conditional on explicit typed entry premises; all
consumers must bind the same premise. Use the existing
`--real16-declared-input` loading path and frontend admissions, not a parallel
registry or MZ-entry rewrite. Bind original MZ/relocated module/load/function
entry+extent/native digest, environment digest, known register lanes/memory
spans and near/far return frame. Omitted lanes stay unknown. Loaded code
authenticates decoding, not unchanged writable globals: baseline data requires
explicit `use_environment_memory`. Otherwise only declared spans/observed
writes supply data knowledge. Services cannot reacquire undeclared initial
IVT/metadata assumptions.

Initialized contents and address authority are separate. With environment
contents disabled, freshly authenticated environment/image ranges may authorize
reading bytes proved written by the native census. They supply no initial byte
values: absent, unknown, tainted or out-of-range writes remain unknown. The
memory owner must retain this distinction in typed contracts and descendants.
Acceptance controls require known stack-write transport without a baseline,
unchanged refusal for unwritten module data, malformed/outside ranges and stale
source/environment rejection. The first CMP16 call must transport its return
value from those native writes before another whole-case run is justified.

Replay rechecks live native bytes, source/environment/declaration and exact
artifact/boundary identity; normal bounded census proves local effects. Retain
scope through raw IR, Semantics, Alias/SSA, scoped private Clinic partitions,
segment state, validation/cache keys and persisted snapshots. Original function
CFG remains unchanged; private control projections require current
authenticated partition/context and all-or-nothing edges. Refresh consumed
scopes explicitly; foreign/changed/detached evidence refuses rather than
falling back unscoped. Identity views require complete source-bound coverage
with no pending calls, candidates or refusals.

Near-callee entry and its eventual return theorem are separate: entry-only
binding authenticates exact caller prefix/native CALL/index/callee head while
chain seed proves CS/stack/memory. Keep unfinished return candidates visible
and unconsumed; ordinary links keep existing edge checks, explicit stale edges
refuse. Never relabel caller scope as callee scope or weaken raw/final native
equality. Known effects can refine feasible edges only through source-bound
consumers; unknown/refused effects retain edges. Early and post-simulation
authentication, whole fetched-code write guards, detached scratch ledgers and
budgets stay intact. Declared interrupts consume current IVT/frame/memory
effects, including vector query/update/query; unsupported handlers/selectors/
frame aliases refuse.

Conditional C still runs final quality/recompilation/payload-integrity checks.
Its companion receipt binds exact emitted SHA256 and premise. Exit 5 /
acceptedFalse and merge hold remain; it never enters unconditional accepted
caches. Missing/damaged/different premise or failed compilation/payload binding
remains failure. Complete-case consumer requires all selected functions exactly
once at final attempts, coherent source/load/environment bindings, fresh
payload/validation/compiler hashes, and original/rebuilt runs pinned to the
same compiler context and declared observations. Missing main or arbitrary
self-signed conditional JSON cannot pass. Freeze the original
observation/expectation contract bytes independently of current proof status;
changed expectations refuse. Per-function declaration entry and range start
must equal that selected function address; differing legitimate register
domains remain allowed. Concrete native behavior stays separate from symbolic
conditions.

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

Historical results are not automatically current acceptance. If a blocker
requires a substantial new subsystem, report the concrete dependency and leave
its case open; do not silently expand or weaken the plan. Large-program repair
queues and unrelated gates stay separate. Required missing constructs remain
visible obligations even when a simpler smoke batch passes.

## Staged Analysis: Raw Facts Before Deep Proof

Use existing source-bound raw intake, invocation census and scoped discharge.
Raw pending artifacts never enter the universal proven-function registry.

1. **Collect:** decode/lift exact source-bound instruction/effect facts once per
   analysis context; retain unresolved edges/typed reasons. Raw boot intake binds
   authenticated MZ state, project/artifact/boundary and current byte evidence.
2. **Propagate:** local SSA/Alias/control facts before recursive caller demands;
   deterministic dependency order, revisit only changed proof inputs, separate
   unknown/proven facts and retain the five evidence-loop counts.
3. **Close:** fixed point or existing request budget; deeper proofs only for
   required unresolved dependencies. Full source/evidence context, never address
   alone, governs any allowed reuse. Exhaustion stays unresolved.

Initial CS does not prove preservation. Census live calls/stores/interrupts/
selectors. Do not fabricate complete coverage, delete unknown edges, create a
parallel scheduler or renew budgets on identical retries. Native/decoded/image
bytes must agree. Both ordinary/raw imports stop lifts and finishing on expiry;
partial collected blocks remain diagnostics. Changes must reject foreign source/
artifact/boundary, unsupported selector/effects and code-writing stores. Retain
the selector-wrap leaf control: no calls does not authorize skipping entry proof.
Measure imports/dependency retries/time/memory on the frozen actual case.

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
