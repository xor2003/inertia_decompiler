# Lifted Integer Bit Patterns (2026-09-10)

## Root Cause And Repair

The native-stage probe found oversized SP subtraction operands before SSA,
not in C rendering. Eight such assignments survived the return-frame boundary.
For example, the PUSH at active-project address 0x106a produced
`reg16<16> = (t34 Sub 65538<16>)`. This address is diagnostic only.

A one-instruction PUSH DS lift then isolated the earlier fault: its VEX
integer constant was `(Ity_I16, -2)`, not the bit pattern 0xfffe. The full
frontend's `Processor.constant` passed Python integers directly to PyVEX's
constant constructor. Native conversion and simplification exposed the
malformed constant as the oversized subtraction. The optimized frontend and
full instruction path must obey the same finite-width constant contract.

The fix belongs in Frontend/runtime, before VEX and native AIL consumption.
`Processor.constant` now uses PyVEX's integer-type and width APIs to encode
lifted integers modulo their declared width. Concrete signed arithmetic and
floating constants retain their previous values. No caller-effect ownership,
stack wrapping policy, execution-memory method, SSA liveness or rewrite rule
changed. The frontend change is one import and two normalization lines in
the existing owner, not another late cleanup pass.

## Acceptance

- Reason: finite-width constants must carry valid bit patterns so downstream
  analyses do not interpret malformed Python values as oversized stack deltas.
- DoD: negative and overflowing integer inputs normalize at 1/8/16/32/64 bits;
  concrete and floating values remain unchanged; representative word/dword
  PUSH forms emit bounded constants; execution and numeric-SP regressions,
  scoped lint/types and routine/default gates pass.
- Definition of failure: malformed lifted constants survive, concrete or
  floating arithmetic changes, upper ESP or live stack effects are lost, tests
  are weakened, or this repair is presented as complete InitMenu acceptance.

Twenty-two new cases are admitted to Make, the default pipeline and the
existing symbolic frontend ownership rule. Before the fix: 21 failed and one
passed, seven warnings, 8.13 seconds. After: 78 focused tests pass, including
direction-flag execution and compiled-C numeric SP/upper-ESP comparisons.
The additional unchanged InitMenu acceptance test still fails at its final
SP-bookkeeping assertion: 78 passed, one failed, seven warnings, 59.14 seconds.
Its earlier validation and call/argument assertions pass. The behavioral
harness following the failed assertion is not reached.

Ruff `check --fix`, scoped MyPy and Pyright pass. The first broad gate exposed
the IR projection gap below; `/tmp/inertia-lifted-constants-gates.log` is a
failed gate, not a passing result. No full-suite claim is made.

## IR Projection Follow-Up

The first fast gate reports 3,216 passed and one failed in 141.60 seconds.
The existing real-VEX segment save/restore test still proves DS restoration,
but receives stack offsets 65534/65535 instead of -2/-1. The test is unchanged.

The VEX-to-IR importer folded an unsigned constant directly into
`IRValue.offset`. That is a register-relative displacement, not an absolute
integer constant. `ir/vex_integer_displacement.py` now owns its signed modular
canonicalization, used by the importer's register-plus/minus-constant cases.
It requires an exact matching integer operation width; unknown sizes, mismatched
widths and noninteger operations are left untouched. Alias receives coherent
relative offsets without a special segment-restore exception.

Thirteen initial importer cases plus the existing segment test fail before
repair (14 failures, 8.20 seconds). The first rerun passes all 72 selected
tests in 8.95 seconds. Three further refusal cases cover absent, mismatched and
noninteger width evidence. The final 16 importer cases are routine alongside
the 22 frontend cases. Tests also equate signed and unsigned constant inputs
and cover accumulated displacement wrapping. Scoped lint/types pass.

Reason: every owned projection must agree after canonicalizing VEX bit patterns.
DoD: the unchanged segment restoration test and importer equivalence/refusal
cases pass, followed by numeric-SP, function acceptance and routine gates.
Definition of failure: restore malformed VEX constants, change the expected
stack offsets to conceal the inconsistency, guess an operation width, or move
relative-value interpretation into Alias, cleanup or CLI.

Final focused run: 85 passed, one failed, seven warnings, 59.55 seconds.
Only the unchanged InitMenu final bookkeeping assertion fails; the preceding
validation and call/argument checks pass. Final scoped Ruff/MyPy/Pyright pass.
The combined `quality-fast test-pipeline` command exits 0: fast passes 3,233
tests in 139.18 seconds (eight warnings), all executable guards pass, and
default passes 3,233 tests in 122.86 seconds pytest / 123.285 seconds lane
(seven warnings). QuickC passes in 47.092 seconds and all seven MS C tiny
full roundtrips pass in 61.958 seconds. The default unit lane remains over
budget. Log: `/tmp/inertia-canonical-constant-final-gates.log`.
This supersedes the failed routine gate, not the failing function acceptance
or the outstanding full-repository audit.

## Function Evidence And Remaining Work

The after-probe records zero `65538` terms throughout its captured native AIL
stages, versus 20 before constant propagation and eight immediately before
SSA in the baseline probe. This is bounded diagnostic evidence, not a new
rendered-text recovery rule. The baseline probe preserved byte-identical C;
both probes run with isolated decompilation caches and observation-only hooks.

The frontend-only after-probe retains validation=passed and clean whole-tail
validation. Its C
now contains ordinary two-byte stack steps instead of the oversized terms.
SHA-256: `285df6de1eedddb129b89e186823ca24bcb3648d8411ecee9e4950ca411277f5`.
Strict GCC on that artifact still reports 20 parenthesization errors. Caller argument pushes,
cleanup and SP/BP bookkeeping remain the next ownership problem; correcting
constant representation is not evidence that those effects may be erased.

Artifacts: `/tmp/inertia-initmenu-native-stages.{c,log}` (baseline),
`/tmp/inertia-canonical-initmenu.{c,log}` (after),
`/tmp/inertia-canonical-initmenu-gcc.log`, and
`/tmp/inertia-lifted-constants-{before,after,pyright}.log`.
Temporary observation hooks are not installed in production.

Recorded log-creation anchors: baseline regression 02:03:58 CEST; focused
after-run 02:04:41, with 59.14 seconds pytest time. These are command windows,
not an estimate of total active coding time or remaining plan duration.
The IR regression baseline log was created at 02:14:01 CEST; its first passing
rerun at 02:14:51. The final gate log was created at 02:17:38, and terminal
exit 0 was verified by 02:26:57: a 9m19s observation window including polling.
Baseline-regression log creation through final verification spans 22m59s,
including implementation, probes, failed/passing tests and waits. Earlier
root-cause investigation is outside that interval.
