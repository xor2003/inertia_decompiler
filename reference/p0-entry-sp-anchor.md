# Entry-SP Anchor Candidate: Rejected

## Latest Verdict (2026-09-09)

The candidate described below is withdrawn, not accepted. `quality-fast` failed
four tests (3,081 passed, seven warnings, 134.17s). Focused reproduction failed
the same four in 12.79s; a diagnostic-only restoration of the previous resolver
passed all four in 12.01s. Logs:
`/tmp/inertia-stack-anchor-quality-fast.log`,
`/tmp/inertia-stack-anchor-smoke-{before,baseline}.log`.

Affected tests: ENTER local stack, explicit local type, BP displacement
annotation, and explicit local name in `test_x86_16_smoketest.py`. Whole-tail
validation reported an uninitialized BP-2 read. Do not weaken those tests.

The earlier inference was too broad: the frame delta is proven, but a generic
unbound Reference does not prove entry-SP coordinate provenance. The previous
segmented-chain expectation was restored, not reclassified as obsolete.
The resolver again respects its coordinate registry without unconditional
rebasing. New paired tests distinguish explicitly bound entry-SP variables
from unbound legacy variables in a function with the same proven frame.

Next task: carry native stack-anchor coordinate provenance from the AIL/SSA
boundary into the typed coordinate owner, then consume that proof in Lowering.
Reason: prevent accidental saved-frame/local aliasing without shifting genuine
BP locals. DoD: both byteops and the four smoke regressions pass, required calls
survive, whole-tail validation passes, generated C recompiles and the default
pipeline passes. Failure: inferred domain from Reference shape or frame delta
alone, adjusted test expectations without evidence, or suppressed validation.

The remaining sections are historical candidate evidence, not current success.

### Withdrawal Verification

- `quality-fast`: exit 0; 3,087 tests, seven warnings, 133.22s; configured
  static checks and executable guards pass.
- Default `test-pipeline`: exit 2; unit lane 3,087 passed in 116.97s; QuickC
  passes; MSC6 5/7. `scalar_types_io` still fails C2065 for `inertia_ebp`;
  `function_pointers` still fails L2029 for ESP/EBP. No accepted byteops fix.
- Logs: `/tmp/inertia-stack-anchor-withdrawal-{quality-fast,test-pipeline}.log`.
- Ruff `check --fix` and `git diff --check` pass for this withdrawal.

### Scoped Deduplication Audit

The current `/home/xor/pytest_deduplicate/pytest_deduplicate.py` explicitly
rejects xdist; it cannot aggregate worker coverage. Coverage was installed
under `/tmp/inertia-dedup-deps`, leaving the project environment unchanged.
The stack-address test module ran serially with `PYTHON_JIT=1`, hash seed 0,
and explicit source scopes for stack-address and variable-coordinate owners.
Result: 7 passed, one warning, 3.71s; collector errors empty. This is a scoped
audit, not a full-suite redundancy assessment or a stability/mutation audit.

One identical-coverage pair shares 45 arcs: bound offsets -2 and 0, approximately
2ms each. Keep both: their expected coordinates differ (0 versus 2), exercising
zero and nonzero projected results. Coverage equality alone cannot justify
deletion, and the potential time saving is negligible. No tests were removed.
Artifacts: `/tmp/inertia-stack-coordinate-dedup.{json,log}`.

## Root Cause (2026-09-09)

Fresh in-process Clinic observations show correct saved-BP execution slices:
the entry instruction writes two bytes at SP-2 and SP-1. Native stack SSA
subsequently expresses the base as a reference to an entry-SP anchor. No
instruction byte was lost, and replacing byte-safe execution or introducing
word-store reconstruction was not justified by this evidence.

Lowering already owns `machine_bp_offset_for_entry_sp_anchor_8616`, which
consumes the proven frame delta and refuses already-projected variables. But
`_stack_offset_from_expr_8616` did not consult it for `Reference` expressions.
A later segmented-access fallback used it only if the raw displacement lacked
storage evidence. Thus an unrelated BP-2 local could match an entry-SP-2 saved
frame byte, despite the existing proof that this address is BP+0.

The main stack-address resolver now consumes the existing anchor projection
before ordinary variable-coordinate fallback. Registered variable ownership and
unknown-frame behavior remain unchanged. This is a missing Types/Lowering
consumer, not new semantics in Rewrite, nor a reason to weaken frame-use guards.

## Regression Evidence

Two direct consumer cases fail before repair: entry-SP anchors -2 and 0 resolve
without the proven +2 translation. Before: 2 failed, 3 passed, 8.04s.
After, the coordinate/direct-width/segmented-stack group passes **115 tests**,
seven dependency warnings, 9.98s. One older expectation was corrected: a chain
adding +2 then -2 preserves entry-SP -10, corresponding to machine BP -8, not
entry-SP -12. The test now checks both coordinate domains. Ruff passes.
The stack-address test module is admitted to the routine pytest and Ruff lists.

Fresh `byteops_unsigned` output no longer contains the spurious EBP-to-`a`
assignment or the EBP external declaration. Decompilation exits 0 with
`validation=passed` and clean whole-tail validation. Generated C compiles and
returns the expected `0xC000` at both GCC -O0 and -O2 without supplying any
runtime register variable. Existing byte-safe frontend methods were not changed.

The displayed `b` comment at offset -6 is not independently evidence of a wrong
slot: the observed registry maps its entry-SP -6 to machine BP -4, as required.
Do not interpret native variable-offset comments as machine-BP proof.

Logs and artifacts:
`/tmp/inertia-stack-anchor-consumer-{before,after,verified}.log`,
`/tmp/inertia-native-stack-ssa-probe.{c,log}`,
`/tmp/inertia-stack-anchor-byteops.{c,log}`.
The broad fast gate is running; default pipeline acceptance is still pending.
Do not call the MSC6 construct fixed until its recompilation and DOS exit-code
checks pass, including the other functions in `scalar_types_io`.

## Acceptance

Reason: one address must retain its proven coordinate domain before storage
selection. DoD: exact anchor/refusal tests, saved-frame/local separation,
compiled behavior, call preservation, tail validation and routine gates agree.
Definition of failure: selecting an unrelated slot by numerical coincidence,
double-projecting registered storage, changing numeric stack values, deleting
unknown effects, or passing a synthetic register definition to conceal the bug.
