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
* `x86g_calculate_condition` has exact bitvector semantics for x86 SUB byte,
  word and dword comparisons and LOGIC zero/nonzero tests when the condition
  and VEX operation are constants. Other known pure lazy-flag helpers remain
  uninterpreted. A SAT mismatch involving one of those remains a refusal.
  Unknown helpers refuse. No broad exception fallback converts errors into proofs.
* `--normalize-globals` is optional in leaf mode. It records candidate-to-oracle
  constant relocation using defined candidate data aliases and exact matching
  original `.lst` labels, with mapped original addresses. This produces a distinct **`conditional` verdict for the relocated SSA**, not a proof of pointer alias correspondence,
  initialized data, or arbitrary address-valued integers. Review `globals.json`.
  It is not enabled in the unnormalized batch or matched-CFG mode. Inferred
  16-bit layout heuristics and binary-equality shortcuts are disabled.
* Non-leaf modes also retry incomplete evidence through the shared flat32
  call composer, closed CFG reblocking, checked call-loop induction and
  macro-step induction. Direct acyclic callees use
  their actual binary effects; the composer proves the full saved return
  target before continuing. Unconditional statically resolved transfers to
  declared foreign entries also compose the destination's full effects,
  preserving the existing return slot without adding a CALL push. Tail chains
  share the depth and expression limits and have a 32-transfer cap; call and
  tail work is reserved before nested composition. Interior, undeclared,
  conditional outside edges and cycles still refuse. Reports retain
  `oracle_tail_transfers`, `candidate_tail_transfers` and `tail_sites`; tail-only
  premise-dependent proofs receive the same environment checks as calls.
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
