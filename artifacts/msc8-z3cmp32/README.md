# MSC v8 flat32 SSA comparison

This is a staged PE32 comparison driver with isolated adapter modules. It uses
`/home/xor/vextest/tools/dosunit` SSA/Z3. The rebuild directory is read-only in
this session; run this copy directly.

The current candidate can be the VC1.1-built PE32 image under
`rebuild/out/msc32/`, with its corresponding `.lst` boundary file. The ELF32
path remains available in leaf and matched-CFG modes. Region mode is PE32-only.

## Install the staged patch

The actual Git root is `dos_compilers`, so the subdirectory prefix is required:

```sh
git -C /home/xor/inertia_player/dos_compilers apply \
  --directory='Microsoft C v8/BIN/rebuild' \
  /home/xor/vextest/artifacts/msc8-z3cmp32/rebuild.patch
```

This historical patch predates region mode. Run this staged copy for region
comparison; do not use the patch to install the region implementation.

## Run

```sh
PY=/home/xor/vextest/.venv/bin/python
BIN='/home/xor/inertia_player/dos_compilers/Microsoft C v8/BIN'
DRIVER=/home/xor/vextest/artifacts/msc8-z3cmp32/z3cmp32.py

PYTHON_JIT=1 "$PY" "$DRIVER" \
  --oracle-exe "$BIN/C13216.EXE" --oracle-lst "$BIN/C13216.EXE.lst" \
  --candidate-exe "$BIN/rebuild/out/C13216.exe" \
  --functions sub_27320 --out-dir /home/xor/vextest/.cache/msc8-hash
```

For the current PE32 candidate, provide its function boundary listing:

```sh
PYTHON_JIT=1 "$PY" "$DRIVER" \
  --oracle-exe "$BIN/C23216.EXE" --oracle-lst "$BIN/C23216.EXE.lst" \
  --candidate-exe "$BIN/rebuild/out/msc32/C23216.exe" \
  --candidate-lst "$BIN/rebuild/out/msc32/C23216.lst" \
  --mode auto --functions sub_1D300,sub_222D0,sub_24FD0 \
  --out-dir /home/xor/vextest/.cache/msc8-selfhost
```

Function names in the two catalogs must identify corresponding functions.
A matching compiler can make SSA and CFGs match, but names or compiler identity
alone never constitute a proof. Use `--all-mapped` instead of `--functions` to
account for every mapped `sub_*`; unsupported bodies remain explicit refusals.
Q23's Phar Lap container is outside this PE32/ELF32 loader.

## Proof contracts

Both staged MSC8 and BC5 drivers accept `--entry-esp-range MIN:MAX` in
`region`, `auto`, and `matched-cfg` modes for PE32-to-PE32 comparison. Bounds
are inclusive unsigned 32-bit integers; hexadecimal syntax is accepted. For
example, `--entry-esp-range 0x7f000:0x80000` declares a hypothetical root-entry
stack interval. It does not establish where Windows placed the stack.

The option has no default. Call compositions relying on the declared interval
remain **conditional**, retaining the interval in their assumptions and sealed
`input_domain`. Changing the interval changes the proof contract identity.
Nested frames do not inherit a root ESP premise. Leaf mode, DOS-only MZ images,
PE32+ images and non-i386 candidates reject this option.

Shared call-composition guards count distinct expression dictionaries rather
than repeated references to the same subexpression. Outbound slots, longest
container paths and cycles are separately bounded; budget exhaustion remains
a refusal. This removes artificial DAG overcounting without assuming missing
callee, region-boundary or environment proofs.

* `leaf` accepts only complete single-block near-return functions. It retains
  all VEX statements, handles partial GPR writes at their actual 32-bit width,
  and checks all 32 bits of the return target. `.lst` `endp` is inclusive of
  its last instruction, whose byte length is decoded from the binary.
* `matched-cfg` builds a closed bijection between reachable blocks. Each internal
  edge compares every modeled GPR, lazy flag field, segment register, direction
  flag, and the entire memory array, plus a canonical 32-bit successor token.
  Every corresponding block must pass. This is induction over matching graphs,
  including cycles; no loop-unroll bound is treated as a proof. Shape changes,
  indirect jumps, calls, exception edges, and effects after conditional exits
  refuse in this initial lane; the shared retries below may discharge them.
  A mismatched edge or changed loop body fails the regression controls.
* `region` composes every reachable path of a bounded, acyclic PE32 function
  through full-width linear successor addresses, then compares the return and
  memory effects with dosunit Z3. It can prove equal behavior across different
  CFG shapes. Calls, loops, indirect edges, incomplete scans, and exhausted
  budgets refuse in this initial lane. Shared retries can discharge supported
  calls and loops. The defaults cap each side at 64 blocks, 128 block
  compositions, 12,000 expression nodes, 64 solver inputs, and 128 memory
  stores. A SAT result involving uninterpreted lazy flags remains a refusal.
* `auto` runs `region` first and retries its loop refusals with the
  matched-CFG induction. The retry caps each CFG at eight blocks and Z3 at
  250 ms per block. A refused retry leaves the original loop refusal in place;
  a concrete mismatch is reported as `failed` for review. In the C23216
  PE32-to-PE32 sample, this proves `sub_1D300`, `sub_222D0`, and `sub_24FD0`,
  which `region` refused. This mode still requires literal data addresses.
* Returns observe EAX, EDX, ESP, preserved GPRs, segments, direction flag and the
  full return target by default. `--output-regs eax,esp` can declare a narrower
  return-value ABI explicitly. Preserved registers and return control remain
  checked. EDX mismatches under the default contract do not automatically mean
  a C function returning only EAX is wrong.
* Memory is the same unconstrained flat byte array on both sides. Stack writes
  remain observable. Floating point, MMU validity and asynchronous effects are
  outside this integer functional model. Explicit VEX exception paths refuse.
* Default 32-bit `ENTER iw,ib` uses a PyVEX fallback with ordered stack pushes,
  nesting-display reads and unchanged flags. Native differential controls cover
  allocations, masked nesting levels and overlapping stack/frame addresses.
  Override-prefixed forms remain unsupported by this fallback.
* `x86g_calculate_condition` has exact bitvector semantics for x86 SUB byte,
  word and dword comparisons and LOGIC zero/nonzero tests when the condition
  and VEX operation are constants. Other known pure lazy-flag helpers remain
  uninterpreted. A SAT mismatch involving one of those remains a refusal.
  Unknown helpers refuse. No broad exception fallback converts errors into proofs.
* `--normalize-globals` is optional in leaf and matched-CFG modes. It records candidate-to-oracle
  constant relocation using defined candidate data aliases and exact matching
  original `.lst` labels, with mapped original addresses. This produces a distinct **`conditional` verdict for the relocated SSA**, not a proof of pointer alias correspondence,
  initialized data, or arbitrary address-valued integers. Review `globals.json`.
  Matched-CFG induction checks every edge under the same explicit map and
  requires complete binary environment coverage. Refused normalized CFGs
  retry checked call composition under the same constant map. Calls require
  complete helper bodies and proved returns; these retries do not run strict
  fallback comparisons with a different relation or discard existing
  conditional CFG proofs.
  Acyclic roots without CALL instructions also publish when composition
  carries complete-function scope and both images' native coverage; a
  cutpoint counterexample or incomplete scan cannot stand in for that scope.
  Region/auto modes still require literal addresses. Inferred
  16-bit layout heuristics and binary-equality shortcuts are disabled.
* Non-leaf modes also retry incomplete evidence through the shared flat32
  call composer, closed CFG reblocking, checked call-loop induction and
  macro-step induction. A cyclic composition also reaches the checked
  loop lane when its transitions contain REP summaries without CALLs; raw
  conditional-exit lowering failures do not suppress that induction attempt.
  Direct acyclic callees use
  their actual binary effects; the composer proves the full saved return
  target before continuing. Unconditional statically resolved transfers to
  declared foreign entries also compose the destination's full effects,
  preserving the existing return slot without adding a CALL push. Tail chains
  share the depth and expression limits and have a 32-transfer cap; call and
  tail work is reserved before nested composition. Interior, undeclared,
  conditional outside edges and cycles still refuse. Reports retain
  `oracle_tail_transfers`, `candidate_tail_transfers` and `tail_sites`; tail-only
  premise-dependent proofs receive the same environment checks as calls.
  Paired IDA `START/END OF FUNCTION CHUNK` declarations add separate executable
  dependency envelopes for known owners. They do not enlarge the parent range
  or the original-function denominator. Transfers into those chunks must pass
  the same native tail/body/return checks; malformed or overlapping declarations
  are rejected, and missing or non-code chunks cannot authorize a transfer.
  Each image contributes helpers independently of the root mapping. Supply
  `--candidate-code-map PATH` to include verified LINK public/static code
  symbols omitted by the candidate listing. Header identity, code-segment
  coordinates and executable extents must match the image, and the map digest
  is sealed. This option neither normalizes data nor assumes helper behavior.
  Finite indirect calls compose every admitted target's validated body and
  prove complete target coverage. Unknown or incomplete targets, ordinary
  recursive dependencies, unproved return-slot preservation and exhausted
  limits refuse. `--recursive` separately reports an image-bound component
  proof with explicit premises; it does not discharge ordinary function rows.
  See the [execution specification](../../reference/dosunit-execution-spec.md#710-pe32-public-recursive-component-reports)
  for its access-domain contract. Strict memory includes stack
  stores. Refused retries remain in `additional_proof_attempts`; their
  `calls.return_proof_failure` retains the comparison side, CALL instruction
  address (`callsite`), owning block (`call_block`), callee, continuation and
  solver countermodel or non-result. A countermodel needs independent replay
  before it is described as an observed binary mismatch.

Reports now use `msc8.z3cmp32.v2`. A `passed` verdict requires exactly one
identified passing record for every obligation, with consistent backend counters.
Missing, duplicate, unknown, misidentified, unexpected or aborted evidence refuses.
The raw backend report is retained for diagnosis. A relocation-dependent result
is `conditional`, is counted separately, and never satisfies a proof obligation.

Exit codes: `0` means a nonempty selection with every requested function proved;
`1` means at least one mismatch; `2` means incomplete, refused or conditional. Missing names,
failed lowerings, timeouts and zero comparisons cannot produce exit 0.

Artifacts include input catalogs, mapping, both SSA documents, raw comparator
results, and one result per requested function. CFG runs retain both SSA graphs
and every block comparison in `<function>.cfg.json`. When loading a saved leaf
SSA document directly through dosunit, restore `_constant_normalization` JSON
keys to integers; the driver builds that private runtime map itself.

A focused VC1.1 PE32 run of 80 previously branch-refused C23216 functions
proved three: `sub_1E600`, `sub_22680` and `sub_26D50`. The other 77 refused
under the fixed budgets, chiefly due to calls and loops. Four flag-helper
refusals were later rechecked with exact SUB/LOGIC semantics: two became
counterexample verdicts, one still refused due an abstract helper, and one
timed out at 3 seconds. The counterexamples require source and relocation
triage; they are not automatically decompiled-C defects. This is a sampled
result, not a coverage estimate for the full refusal class.

## Declared scalar port I/O

Both bundled PE32 drivers and `z3func.py compare-binary16` accept
`--ordered-io-environment dosunit.ordered_io.scalar_in_out.v1`. This explicitly
assumes identical environment responses to identical ordered scalar IN/OUT
histories; it does not prove real-device equivalence. Supported widths are
8, 16 and 32 bits. Reads remain observable even if their values are overwritten.
Returning callees propagate the premise into their callers.

A proof consuming this declaration is `conditional`, with
`unproved_ordered_io_environment` and the complete architecture-specific model
sealed into its report. Omitting the option preserves environment refusals.
Unsupported services, string I/O, missing retained event evidence and budget
exhaustion still refuse. Malformed, wrong-architecture or conflicting ambient
declarations reject before proof work. Real16 cannot combine this declaration
with initialized recursive joint proofs.

## Verification and remaining work

See `RESULTS.md` for the measured batch and corpus results. Run the complete standalone gate with
`make -C /home/xor/vextest/artifacts/msc8-z3cmp32 check` (after installation:
`make -f tools/Makefile.z3cmp32 check` from rebuild). It includes Ruff, Pyright,
and both test modules. The focused pytest
suite exercises real VEX/Z3 with changed-code controls, partial-register writes,
CCalls, full-width returns, refusals, and relocated cyclic CFGs:

```sh
PYTHON_JIT=1 /home/xor/vextest/.venv/bin/python -m pytest \
  /home/xor/vextest/artifacts/msc8-z3cmp32/test_z3cmp32.py \
  /home/xor/vextest/artifacts/msc8-z3cmp32/test_proof_verdicts.py \
  -n 7 --tb=short --durations=5 -q
```

The function-fix acceptance goal is not complete for `sub_26870`, `sub_2B0F0`,
or `sub_1D216`: the first two have call paths, and the latter has an explicit
VEX division-exception edge. No reconstructed C was changed to accommodate the
comparison. Different CFGs and callee composition remain implementation work.


Concrete replay diagnostics: the shared `replay-flat32` command reports
`differences.registers`, `differences.observed_memory` (both final byte
strings), and `differences.written_memory`. Written memory means coalesced
final bytes at written addresses, not store order. Incomplete comparisons
have `differences: null`. These diagnostics do not promote execution
agreement to proof or automatically replace an SSA comparator refusal.


Bounded root refutation accepts repeated
`--counterexample-memory-byte 0xADDRESS` together with
`--find-return-counterexamples`. It compares those byte addresses in the
same symbolic input-memory domain, after both paths execute RET to the
original caller slot. A concrete byte difference can replace a refusal with
`root_return_memory_counterexample`; the strict result remains embedded.
Unobserved differences, clipped paths, or bounded agreement do not prove
equivalence. Existing literal matched-CFG/no-ABI-catalog restrictions apply.


Memory-byte refutation unfolds at most three visits per block on a path,
with depth12 and the existing total visit/time/node caps. It uses valid VEX
direction encodings (+1 or -1) and requires both paths to return to the original
caller slot. Observed bytes may overlap stack frames when ESP is unrestricted;
such a strict-memory counterexample does not establish an ABI-visible defect.
An explicit entry-ESP domain is honored. Bounded non-discovery is never proof.


The bounded memory refuter can now pass byte-admitted default REP instructions
when the composed ECX is zero. This exact branch preserves every register,
flag and memory byte; nonzero-count branches remain clipped. Prefixes before
REP use the common native boundary scanner. Fixed ESP excludes overlap of the
observed address with the immediate frame, but does not constrain arbitrary
source/destination pointer arguments or establish an ABI-valid input domain.


Root counterexamples now request `solver_result.counterexample_memory`.
Each named input array has a status. A `complete` 32-bit byte model contains
`default_byte` for all addresses and ordered `stores` overrides; unsupported
array forms or exhausted serialization bounds provide no partial replay image.
The ordinary SSA comparison path does not request this serialization.
Model completeness is evidence about the solver input, not by itself a claim
of valid ABI pointers or successful native replay. The replay harness replaces
the root caller return slot with its sentinel, which must be accounted for
when reconstructing a concrete vector.


`CL-reviewed-abi.json` is an opt-in catalog of explicitly conditional
scalar observations for the MS C CL original/rebuild comparison. Pass it via
`--abi-observation-catalog`; it is never selected by default. `sub_19123`
uses a void-return premise and no private-stack exclusion. `sub_1CC77`
uses a 32-bit return and 32-byte post-return private-stack lifetime premise.
`sub_1F890` (`get_heap`) uses a 32-bit return and exactly four private bytes:
the CALL-pushed continuation below entry ESP. All memory reads, call effects,
preserved registers, caller return slot and memory outside the declared
post-return cells remain observed. These declarations are assumptions, not
recovered universal ABI proofs; escaped pointers into excluded cells invalidate
the lifetime premise. Normalization, external-call contracts and any entry-ESP
domain remain separate published premises.

The catalog also includes `error_map`, `seh_probe`, `map_control_word`,
`fd_handle` and `fd_set_textmode`. The two descriptor-table functions declare
that the DWORD at canonical original address `0x27fe0` is in `0..64` at root
entry, with respectively four and eight private stack bytes. Both PE initializers
contain 64, but that alone does not establish the live-entry invariant. These
two proofs additionally use the explicit ESP interval `0x7f000:0x80000` and
relocation map. All descriptor argument values remain allowed, including invalid
descriptors; no argument is restricted to a sample set.

An optional `entry_memory_ranges` list encodes these value premises, for example
`[{"address": 163808, "width": 32, "min": 0, "max": 64}]`.
Addresses are canonical original-memory coordinates; predicate constants do not
undergo code/data relocation. Widths 8, 16 and 32 are supported. Bounds constrain
only initial memory: later writes and reads retain their full semantics. Empty
combined domains cannot produce a proof. Root premises are not assumed at
arbitrary loop cutpoints. Successful results remain `conditional` and publish
the full predicate. This mechanism is distinct from inferring table bounds from
an executable initializer.

Native v63 acceptance: both descriptor functions are conditional, with zero
refusals; isolated candidate mutations changing errno 9 to 10 and errno 22 to 23
both fail under exactly the same premises. Receipts are
`.cache/ssa-capability-audit/CL-fd-abi-v63-receipt.json` and
`CL-fd-abi-mutant-v63-receipt.json` in the same directory.

Native `get_heap` evidence: both binaries execute CALL, store EAX to the
corresponding `hHeap` global, then RET. With the catalog the complete root
comparison is conditional; strict full-memory comparison retains its refusal.
An independently mutated copy of the rebuilt PE, changing only the store
destination to the neighboring global, is not proved under the same catalog
(`opaque_external_call_countermodel`). This negative control does not claim
a concrete implementation-specific counterexample for the abstract API.
Run/evidence commands are in `.cache/devin-x87/getheap-abi-command.json` and
`.cache/ssa-capability-audit/CL-getheap-abi-receipt.json`; the mutation receipt
is `CL-getheap-mutated-global-receipt.json` in the same directory.

The companion `CL-reviewed-external.json` contains only the two API contracts
needed by these three roots: GetSystemTime writes its 16-byte output region;
GetProcessHeap reads/writes no guest memory under the declared API model.
Use both catalogs together. The checked native replay command is recorded in
`.cache/devin-x87/reviewed-minimal-command.json` (entry ESP domain
`0x7f000:0x80000`, explicit global/code normalization). Its final receipt
`.cache/ssa-capability-audit/CL-reviewed-minimal-receipt.json` records
3 conditional,0 refused,0 failed,1853 verified provenance paths. This is a
three-function cohort, not the full CL or seven-stage coverage result.


ABI catalogs optionally accept `stack_disjoint_buffers`, for example
`[{"argument_index": 0, "size_bytes": 2}]`. Argument zero is the DWORD pointer
loaded from **root entry** memory at ESP+4. The declared buffer must be
disjoint from `[entry_esp-private_stack_bytes, entry_esp)` with modulo32
addressing. This is an explicit input assumption, not inferred pointer
validity. Fixed sizes1..65536 and argument indices0..31 are supported.
The existing post-return private-stack lifetime assumption remains separate.
Execution loads/stores, return values, saved registers and public memory are
unchanged. The shared solver enforces the predicate and rejects empty/unknown
domains; predicate constants are architectural offsets, never code-relocated.
Predicates are attached only after complete root composition and are not
transported to callee inputs or arbitrary loop cutpoints. They therefore do
not repair refusals that occur before root composition completes.

`C13216-reviewed-abi.json` and `C1XX3216-reviewed-abi.json` declare this
two-byte argument-zero buffer and a12-byte private frame for their respective
print_2_digits roots. Both actual native comparisons are conditional under
these declarations plus the existing relocation map. Without the buffer
premise both retain observable saved-register differences under unrestricted
stack overlap. The permanent catalogs are hash-identical copies of the
input catalogs verified in `.cache/ssa-capability-audit/buffer-domain-acceptance.json`.


### Explicit unread external memory (heap_free, checkpoint148)

External catalogs accept `read_excluded_memory_ranges`: ordered, disjoint,
inclusive uint32 intervals, each at most 8192 bytes. This is a caller-supplied
noninterference premise, NOT inferred Windows behavior. It only removes those
bytes from opaque call dependencies. ABI arguments and return control still
come from actual memory. Write preservation is separately declared through
`preserved_memory_ranges`; neither premise implies the other.

SSA uses the exact law P(Store(M,a,v)) = P(M) inside an unread interval and
Store(P(M),a,v) outside it. The base P is uninterpreted: the exact projection
is one allowed interpretation, so this is a conservative overapproximation,
not a claim that the external implementation was recovered. This avoids
quantified Lambda arguments and materializing thousands of zero stores.

CL `sub_1D600` (heap_free) additionally assumes a 32-bit return observation,
20 private bytes below root ESP, and for HeapFree alone: no external reads
of [0x7efec,0x7ffff] except explicit ABI arguments, and no writes to
[0x7efec,0x80003]. These fixed ranges cover the union of native private frames
under the existing explicit root ESP domain [0x7f000,0x80000]. They also impose
stronger restrictions than one concrete 20-byte frame; they remain visible
conditional premises. Native original/candidate frames use 20/16 bytes.
No global unconditional coverage is claimed. Removing either memory premise
or changing the candidate HeapFree flags argument is rejected.

For the historical full-CL cohort, use the derived external catalog
`.cache/devin-x87/CL-reviewed-external148.json` with the canonical ABI catalog;
it retains every prior root from the full94 environment. Do not substitute
the small canonical external catalog for that entire cohort.


### con_close observation contract (checkpoint151)

CL `sub_20FE0` now declares a 32-bit return observation and 8 private bytes
below entry ESP. Native original and rebuilt functions each push one handle
and a return address for their sequential CloseHandle calls. The existing
explicit CloseHandle external contract is reused; no additional unread or
preserved-memory interval is added. The ordinary entry-domain and layout
normalization premises remain conditional. Native original/candidate proof
passes; mutating candidate CMP EAX,-1 to CMP EAX,0 produces an external-history
countermodel. The two other checkpoint149 ABI/read-frame proposals remain
unaccepted. Reports are `.cache/ssa-capability-audit/CL-peer-loop150-*.json.gz`.


### Module symbol lookup observation contract (checkpoint178)

CL sub_1D55D observes a 32-bit return and 12 private stack bytes.
GetModuleHandleA and GetProcAddress explicitly exclude reads in
[0x7eff4,0x7ffff] and preserve writes in [0x7eff4,0x80003]. These ranges
cover the union of frames over the declared entry ESP interval, and are
unproved environmental premises, not facts derived from Windows APIs.
Exact unread projection now commutes through array choices and closed
pointwise Lambda choices; no new return-address literal normalization is used.
Native checkpoint177 proves the root conditionally (18.3s); checkpoint176
hit the composition deadline, so timing robustness is not claimed.
Two code mutants refuse on budget; concrete replay172 independently shows
original/rebuilt EAX=0 and return mutant EAX=1. No SMT countermodel is claimed.
The full external cohort catalog is CL-external174-minimal.json under
.cache/devin-x87; keep these conditional results separate from unconditional ones.

### Fixed delimiter string (checkpoint194)

CL `sub_17F16` observes a 32-bit return with 20 private stack bytes and
explicitly assumes the four entry-memory bytes at original address 0x25880
are `5c 3a 2f 00`. The mapped rebuilt address is 0x36880; both PE images
contain those bytes. Image contents do not establish live entry memory: this
remains a caller-supplied conditional premise. The needle remains unrestricted.
The existing finite-loop executor specializes the strrchr-like callee from
these bytes. Flat32 nonempty SCAS/CMPS summaries now discard incoming
arithmetic flags while preserving direction and the zero-count state.
Original/rebuilt proof is conditional; changing candidate INC EAX at 0x121dd
to DEC EAX yields an observable EAX counterexample. The frozen 37-root scan
cohort gained only this function: 1 conditional, 2 failed, 34 refused.
Evidence: `.cache/ssa-capability-audit/CL-repeat193`, `CL-repeat193-mutant`,
and `CL-repeat195-class`. These are subset results, not a new full-PE count.

### Reconverging option updates (checkpoint199)

CL `sub_19AAE` (`option_dfl`) has an explicit void-return observation and
eight post-return private stack bytes. The original has no stack frame;
the rebuilt entry subtracts four bytes and saves EBX, then restores ESP.
The rebuilt C declares an int result but leaves it uninitialized on one path;
strict and 32-bit-return comparisons remain failed. The new conditional proof
applies only when the return is not observed and the eight stack bytes are
private. Option-table callers discard the callback result, but a universal
caller audit is not claimed. All globals and memory outside that frame remain
observed. Mutating the rebuilt store at 0x13ea0 from byte1 to byte2 fails.

The comparator now selects its existing exact DAG composition for closed
acyclic regions with reconverging branches before path enumeration duplicates
their stores. It retains the existing work, term, store and deadline caps.
With the same ABI premise, the old code refuses this root on the store gate;
the new code proves it conditionally. Evidence: CL-dag198-frame-before,
CL-dag198-frame, and CL-dag198-mutant under .cache/ssa-capability-audit.


### Discovered callback entry cells (checkpoint205)

CL `HandlerRoutine` is conditionally proved with a 32-bit return and four
private post-return stack bytes. The proof explicitly assumes zero DWORDs
at original entry-memory addresses 0x27e70 and 0x27e74 and rebuilt addresses
0x38e70 and 0x38e74. PE bytes supply proposed values, not proof of live memory.
Every consumed cell must be proved preserved from the anchored root entry
to its read; arbitrary loop cutpoints cannot acquire these entry assumptions.
Unknown aliases, writes and unmapped targets retain their refusals.

Retries restore partial evidence without refunding executed work. The loop
consumer carries the function entry explicitly. The frozen stage204 suite
passed 224 tests, including negative cutpoint and external-evidence controls.
The 31-root class completed exactly once with no audit problems: one
conditional proof (HandlerRoutine), 30 refusals. The final stage204 candidate
mutation from zero to 0x1beef refuses on an unmapped call target (5.5s).
Evidence: `.cache/ssa-capability-audit/CL-indirect201`,
`CL-indirect205-mutant`, and `CL-indirect204-class`. These subset results
do not replace the last whole-CL or seven-PE coverage figures.


### Bounded descriptor table (checkpoint210)

CL `sub_1FC90` (`fd_close`) is conditionally proved with a 32-bit return,
20 private post-return stack bytes, and a caller-declared unsigned entry-memory
range 0..64 for the DWORD at original address 0x27fe0 (rebuilt 0x38fe0). Both
images initialize it to 64; this is not proof of its runtime invariant. The
descriptor argument remains unrestricted, so invalid descriptors still take
the error path. The original maximum call frame is two saved registers plus
two SetStdHandle arguments and its return address (20 bytes); the rebuilt
frame uses 16 bytes. Internal reads and return checks remain observed.

The minimal external catalog assumes SetStdHandle returns normally, preserves
program memory and import bindings, and has two callee-cleaned arguments.
Its arguments, return-dependent behavior and ordered external effects are
still modeled. Existing relocation and entry-ESP assumptions remain explicit.
Private-stack projection alone does not prove this root (fdclose207 reports
an EAX countermodel); adding the table bound proves it in 7.2s, and the
minimal external catalog replay proves it in 7.1s.

The isolated mutant changes the rebuilt table store at 0x19a95 from -1 to -2.
The memory equality lemma finds a counterexample; the overall result remains
refused as opaque_external_call_countermodel, never passed. Evidence:
`.cache/ssa-capability-audit/CL-fdclose207`, `CL-fdlimit208`,
`CL-fdlimit208-mutant`, `CL-fdclose210-minimal`, and the final minimal-catalog
negative replay `CL-fdclose210-mutant` (6.4s, memory counterexample).

All 13 original functions directly referencing the table limit were checked
once in `CL-fdlimit209-class`: 3 conditional, 10 refused, zero audit problems.
Only fd_close gains versus full179. For roots without a prior ABI contract,
this diagnostic class retained both EAX and EDX and excluded no stack bytes.
Only the fd_close catalog entries are promoted. No new whole-PE percentage
is inferred from this subset. Remaining work: prove the table-limit invariant
from initialization and all writes, or continue publishing it as a premise.


### Descriptor flush (checkpoint212)

CL `sub_1FB00` (`fd_flush`) is conditionally proved with the same entry table
limit 0..64 at 0x27fe0, a 32-bit return and 16 private post-return stack bytes.
The original maximum stack footprint includes its EBP save, the fd_handle
argument, call return address and fd_handle EBP save (16 bytes). The ABI
observation changes only completed-root outputs; nested frame reads remain
checked. Minimal external contracts cover only FlushFileBuffers and
GetLastError, with unchanged program memory, preserved import bindings,
callee cleanup and normal return assumed. Calls and external history remain
observable. The source declaration returns DWORD.

Evidence: `CL-fdpair211` proves fd_flush but still refuses fd_bind with a
memory counterexample. `CL-fdflush212-minimal` independently proves fd_flush
with only its two external contracts (15.8s). `CL-fdflush212-mutant` changes
the errno store at rebuilt 0x1996b from 9 to 8: the memory equality lemma
finds a counterexample (10.2s), overall refused opaque_external_call_countermodel.
These reports are under `.cache/ssa-capability-audit`. Only fd_flush entries
are promoted; the fd_bind frame proposal and broader class catalog remain
diagnostic. The previous 13-root class sweep plus this focused pair are
separate measurements, not a new whole-PE total.


### Confirmed fd_bind width defect (checkpoint215; no coverage gain)

The actual rebuilt CL `sub_1FBE0` is not accepted. Original instruction 0x1fc45
stores a DWORD HANDLE to hFile[1]; rebuilt 0x199ee stores only BL to 0x3902c.
Generated C declares `extern _UNKNOWN unk_2802C`, and defs.h defines _UNKNOWN
as char. The assignment therefore truncates the handle. A concrete replay
with fd=1 and handle=0x1000 yields original table value0x1000 versus rebuilt
0xffffff00, with identical external calls and EAX=0. Four of five selected
handle values differ. The replay explicitly stubs SetStdHandle as a normal
return1 with callee cleanup8 and preserved memory; it is not an unrestricted
execution proof. Image hashes and cases: `.cache/devin-x87/fdbind215-concrete.json`.

A persistent generator repair is recorded in
`.cache/devin-x87/fdbind215-source-fix.patch`: the exact declaration becomes
HANDLE. The repair is now applied to rebuild/patch.py and gen/CL.c; its targeted
declaration transform was checked, and the generated source exactly matches
the source used by the isolated Microsoft rebuild.
The canonical PE remains unchanged. A byte-patched
width control is diagnostic only and must never count as actual rebuilt coverage.
It exposed another issue: the normalization map lacks0x3902c->0x2802c although
the original listing contains an anonymous data row at that address. Separate
private-label controls CL-fdbind216-* isolate this missing correspondence from
the genuine width defect. Neither arbitrary address guessing nor suppression
of memory outputs is a valid repair. A subsequent isolated actual Microsoft rebuild and proof are recorded below;
canonical PE replacement and general alias intake remain separate steps.


### Actual fd_bind Microsoft rebuild (checkpoint218)

The isolated tree `.cache/devin-x87/msc217-rebuild` builds the corrected
declaration using the real Microsoft CL/C13232/C23232 toolchain: 260 objects
compiled and linked successfully. The resulting 2MiB PE differs from the
canonical candidate in 28 bytes, including link metadata and register
allocation. At 0x199ee it now writes a DWORD from ESI; this was inspected in
the compiled image, not assumed from the earlier opcode-patch control.
`build-inputs.json` and `build-result.json` bind source and image hashes.

`CL-fdbind218-real-rebuild` proves the original function against this actual
new PE conditionally in 7.4s. It uses the explicit alias claim at0x2802c,
32-bit return,24 private stack bytes, table limit0..64 and declared external
contracts. The unchanged BYTE-writing candidate with that same alias still
fails the memory lemma (`CL-fdbind216-alias-only`); thus the alias does not
hide the width defect. This new-image result is separate from the current
canonical-image coverage. The canonical rebuilt PE has not been replaced.


### Combined CL audit (checkpoint220)

The revalidated full213/recovery219 evidence covers304 of305 original CL
functions:3 unconditional,80 conditional,5 failed,216 refused. sub_20020 has
no sealed result after a900s batch timeout and is kept separately unresolved.
Thus83/305 functions have proofs (27.2%), six more than full179; the audit
is incomplete and this is not seven-PE coverage. The isolated corrected
MSC217 candidate is excluded from these counts. Machine-readable provenance:
`.cache/ssa-capability-audit/CL-combined220.json`.

The subsequent HANDLE source fix changed gen/CL.c, also a global-alias input.
Historical reports retain their original hashes. The exact old file is
archived in promotion220-rebuild-source-before/gen/CL.c;
global-alias220-source-transition.json verifies identical629externnames and
837address annotations consumed by the alias parser. The combiner checks
that historical input version, unchanged binaries/comparator/catalogs,
commands, report and CFG archive hashes, and duplicate/missing roots. It
does not silently replace old input hashes with current ones.


`memory_op` (`sub_1A15C`) declares a 32-bit scalar return and four private
post-return stack bytes. Both native bodies push/pop EDI; the rebuilt body
uses EDX as scratch, while the original preserves its incoming value. The
32-bit return observation therefore excludes EDX but retains EAX, preserved
registers, all reads and memory outside the completed private frame. Native
original/rebuilt checks pass conditionally; changing the rebuilt clearing
count from 1000 DWORDs to 999 fails on memory. This does not prove the two
callers or discharge the ABI, stack-lifetime, relocation or entry-ESP premises.


`option_grp2` (`sub_19C1F`) uses an explicit void-callback observation with
no private-stack exclusion. The original bypass path does not assign EAX;
the option-table dispatch sites do not use the callback return value. This
is a scoped calling-convention premise, not a guarantee for arbitrary callers
that inspect EAX. All memory remains observed. The actual rebuilt PE passes
conditionally, while changing its option-flag store from one to zero fails
on memory. The four neighboring option handlers pass in the same class run;
only this root is a new proof. The persistent `CL_sub_19C1F.c` hand override now emits a `void` signature
and removes the former uninitialized result. A regression covers both entry
paths and all flag writes; the actual MS C rebuild also passes the conditional
comparison. The ABI premise remains explicit.
