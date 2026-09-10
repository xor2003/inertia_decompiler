# Native Stack Tracker Width Investigation

## Status And Evidence

Initial investigation checkpoint, 2026-09-10. No complete tracker repair or
function acceptance is claimed. This follows the lifted-integer-constant repair, not a replacement
for it. The current InitMenu observation produced byte-identical C with
SHA-256 `285df6de1eedddb129b89e186823ca24bcb3648d8411ecee9e4950ca411277f5`.
It reports `validation=passed` and clean whole-tail validation; the previously
recorded final bookkeeping assertion and strict-GCC failure remain unresolved.

The base `Arch86_16` reports bits=16, bytes=2, SP=(16,2), ESP=(16,4).
The actual InitMenu Clinic worker reports bits=32, bytes=2, and the register
name at SP's offset is ESP. This distinction is material: inspecting only a
fresh architecture instance missed the worker's analysis domain.

Native angr's `Clinic._track_stack_pointers` seeds `OffsetVal` with a `Register`
whose width is `arch.bits`. `StackPointerTracker._get_register` instead selects
the storage register width from `register_names`/`registers`. Its VEX resolver
does not retain the Get width and evaluates Add/Sub with `OffsetVal` arithmetic;
that arithmetic wraps at the seed register width, not the VEX operation width.

Observed InitMenu offsets after successive instructions include:

| Instruction address in active slice | Instruction | SP before | SP after |
| --- | --- | ---: | ---: |
| 0x1000 | PUSH BP | 0 | 4294967294 |
| 0x1010 | PUSH CS | 4294967288 | 65526 |
| 0x101c | PUSH CS | 65524 | 131058 |

The last row demonstrates that the valid 16-bit bit pattern 0xfffe is added
as positive 65534 in the wider tracker domain. `inconsistent_for(sp)` returns
false despite this defect. CFG join consistency is not a width-correctness
oracle. Whole-tail validation likewise does not independently certify these
native analysis facts merely because the resulting C passes its checks.

## Controlled Counterexample

Six isolated blob analyses used two byte sequences and three combinations of
architecture width and explicit initial Register width. All processes exited
successfully. No installed module or shared cache was changed.

- `55 0e 50 83c402 c3` (PUSH BP; PUSH CS; PUSH AX; ADD SP,2; RET):
  the 16/16 and 32/16 domains agree on offsets
  65534,65532,65530,65532,65534. The 32/32 domain instead starts at 4294967294.
- `66 81 c4 00 00 01 00 c3` (ADD ESP,0x10000; RET):
  the 32/32 domain retains the first offset 65536; both domains seeded with
  16-bit Registers produce zero. Therefore globally narrowing tracker seeds
  would lose a genuine full-width register update. It is not an accepted fix.

Reproduction used `PYTHON_JIT=1 PYTHONHASHSEED=0`, `angr.Project` with a blob
at 0x1000, `Arch86_16`, explicit `arch.bits`, and native StackPointerTracker
single-block mode with `cross_insn_opt=False` and
`initial_reg_values={sp: OffsetVal(Register(sp, seed_bits), 0)}`.
Read instruction results through `offset_before` and `offset_after`.
Temporary scripts: `/tmp/inertia-stack-width-matrix.py` and
`/tmp/inertia-initmenu-spt.py`; function artifacts:
`/tmp/inertia-initmenu-spt-width.{c,log}`. These are diagnostics, not recovery.

## Repair Order

1. Introduce instruction-width-aware SP/ESP projections at the native-analysis
   boundary, consuming owned typed register/stack evidence where available.
   Reason: a register storage offset alone cannot distinguish its subviews.
   DoD: raw-code tests cover both sequences above, full ESP observations after
   narrow updates, wrapping, unknown writes, and CFG joins; low-SP arithmetic
   is correct without erasing high ESP effects. Definition of failure:
   globally narrow arch/register widths, mask every result, or treat ambiguous
   full-register values as proven low-word offsets.
2. Correct returning-call stack effects using the existing typed return-frame
   evidence, including accepted PUSH CS/near-CALL sequences.
   Reason: the observed CALL leaves SP unchanged after PUSH CS; native default
   return adjustment adds only `arch.bytes`. This is separate from width drift.
   Native tracking may additionally apply calling-convention argument cleanup;
   a bridge must account for that existing adjustment or refuse the correction.
   DoD: exact near/far and operand-width cases agree with binary return effects,
   cleanup is counted once, unknown callees remain unknown. Definition of
   failure: callee names, address proximity, or a blanket extra pop as proof.
3. Re-run unchanged InitMenu acceptance and strict C compilation, then routine
   quality and full-roundtrip gates after implementation.
   Reason: correct tracker numbers alone do not prove coherent consumers.
   DoD: validation passes, calls/argument classes survive, required acceptance
   passes, and tests plus scoped Ruff/MyPy/Pyright are green. Definition of
   failure: delete live bookkeeping without evidence or weaken assertions.

The function observation ended at 02:36:57 CEST; the isolated matrix was
verified by 02:38:35 CEST. These are observation anchors, not total effort or
an ETA. Existing 3,233-test routine results are not a fresh full-suite audit.

## Signed Delta Preservation

The frontend register-update boundary still has the signed Python delta before
encoding it as a VEX bit pattern. `Processor.update_gpreg` now emits a typed
subtraction for a known negative delta, rather than adding its unsigned bit
pattern. Positive and symbolic deltas retain addition. Concrete execution,
register widths, byte-safe memory access and high-register preservation are
unchanged. This small producer normalization avoids adding tracker machinery
for an increment direction that the producer already knows.

Reason: preserve available signed-displacement evidence before integer encoding
loses its direction. DoD: focused raw-IR and mixed-PUSH tracker regressions
pass; concrete and lifted execution preserve upper ESP and wrapped stack bytes;
routine gates pass. Definition of failure: narrow the architecture, alter
full-width updates, infer a signed delta from an arbitrary runtime value, or
claim this makes the general native tracker subview-safe.

Twenty-four regression cases were added to the existing routine-admitted
lifted-integer test module. The corrected baseline fixture reproduced five
failures and 35 passes in 8.06 seconds before the production edit. The final
focused run passes 71 cases, including six lifted PUSH execution cases at
wrapping boundaries; InitMenu still fails its unchanged assertion at line 1663
(52.91 seconds total, 44.26 seconds for that function). The behavior harness
after that assertion was not reached.

The after-probe now tracks PUSH CS at 0x1010 as 4294967288 -> 4294967286 and
at 0x101c as 4294967284 -> 4294967282. No architecture width was changed.
Final C is byte-identical to the baseline hash above; validation still passes,
but strict GCC remains red. No generated-C quality improvement is claimed.
The return-segment adjustment and general subview-safe tracker remain open.

Scoped Ruff and production MyPy pass; Pyright passes on production and tests.
A separate strict MyPy invocation on tests with silent imported modules reports
untyped pytest decorators; it is not the configured production typing gate.
All touched test functions nevertheless retain explicit type annotations.
Routine `quality-fast test-pipeline` exited zero. Fast passes 3,257 tests in
139.36 seconds (eight warnings); default passes 3,257 in 124.63 seconds pytest
/ 125.049 seconds lane (seven warnings). All three executable quality guards
pass. QuickC passes in 47.093 seconds; all seven MS C tiny full roundtrips pass
in 63.236 seconds, each with return code zero. The default unit lane remains
over budget. This is not a refreshed full-repository audit.

The corrected baseline run ended at 02:44:16 CEST. The combined gate started
at 02:47:38, last wrote its log at 02:55:36, and terminal exit zero was verified
by 02:55:58 (8m20s observation window, including polling). Investigation and
the initial fixture correction preceded these anchors; no total-effort or
remaining-goal estimate is inferred from them.
Logs: `/tmp/inertia-signed-register-delta-before.log`,
`/tmp/inertia-signed-delta-acceptance.log`, `/tmp/inertia-signed-delta-gates.log`;
probe artifacts: `/tmp/inertia-signed-delta-initmenu.{c,log}`.

## Return-Segment Tracker Experiment

A temporary native-tracker experiment classified 19 decoded returning calls,
accepted 12 through the existing far-return proof, and applied 12 additional
two-byte return-segment pops. It refused native callee-cleanup conventions
rather than risk double counting. The first attempt found no candidates because
the rebased function lacks native call-return metadata; the corrected probe
used decoded fallthrough addresses present in the function's block inventory.
This was a bounded diagnostic, not a new production recovery path.

SP after the CALL at 0x1011 changed from 4294967286 to 4294967288 as intended.
Nevertheless, generated C retained the exact baseline SHA-256 above and
validation passed. Do not install this experiment merely to claim an InitMenu
fix: it does not resolve the current output blocker. The general tracker
correctness debt remains open, while output work proceeds to the independent
[strict-C rendering blocker](p0-c-render-parentheses.md).

Artifacts: `/tmp/inertia-return-tracker-probe.{py,c,log}`. The temporary wrappers
restore native methods in a finally block and are not installed in production.
