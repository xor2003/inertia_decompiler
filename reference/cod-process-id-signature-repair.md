# Process-ID Stub Signature Repair

## Input Qualification And Root Cause

The two DOSFUNC.COD procedures are empty source stubs, not working DOS API
wrappers. Rows 828-834 and 841-848 contain only `push bp; pop bp; ret`. There is
no interrupt and no computed return value. Their source declarations claim
non-void results, but the source bodies do not implement them. Do not invent
process-ID behavior from the names or copy an imagined implementation.

The production layer dump `.cache/process-id-layers/` establishes the failure:
structured codegen emits a void function with a bare return; helper-call text
formatting replaces that signature with a name-selected non-void declaration.
The resulting C falls through without a value and GCC correctly rejects it.
The late text rewrite occurs after the evidence underlying the clean tail
verdict, explaining why that verdict did not catch this invalid signature.

## Repair And Tests

Retired `_rewrite_known_helper_signature_text` as a compatibility no-op, matching
the existing source-header alignment boundary. Deleted its rendered-header,
argument-renaming and name-specific return-pruning logic. Known helper ABI
metadata remains available to typed recovery owners; a label alone cannot
authorize changing an already rendered function interface.

- Three negative controls failed before removal. They cover both process-ID
  names and ERROR without the authoritative-codegen flag. All 99 tests in the
  text-processing module pass afterward (8.60 seconds).
- Four existing live process-helper tests now require exit zero and the typed
  void output rather than accepting exit 4 or requiring invalid source headers.
  All four pass (14.15 seconds).
- Both fresh CLI runs exit zero with `validation=passed`, clean whole-tail
  checks and accepted portable-flat C compilation. Artifacts:
  `.cache/process-{get,set}-fixed.{c,log}`.
- Focused mypy and mandatory types/docs checks pass. Ruff reports 61 remaining
  legacy findings across touched files; its one automatic fix removed the now
  unused prototype-parser import. Diagnostics were not suppressed.
- The routine pipeline passed: 6,132 main-lane tests in 308.08 seconds, QuickC
  fixtures in 35.416 seconds, all eight MS C tiny examples in 118.658 seconds.
  Logs: `.cache/cod-helper-{pipeline,quality}.log`. Quality remains blocked by
  legacy lint findings; this is not a whole-repository green claim.
- After that run started, the six signature controls and one two-case live
  process-helper test were explicitly enrolled in the routine pipeline. The
  enrollment and pipeline contracts were checked separately: 58 tests passed
  in 16.29 seconds (`.cache/cod-helper-enrollment.log`). Do not count these as
  extra distinct tests on top of the broad run: the sets overlap. The enlarged
  combined selection was not rerun as a whole. Pipeline Ruff, mypy and types/docs
  checks pass. The duplicate live regression group remains outside the routine
  selection.

DoD: rendered interfaces remain identical to their typed input regardless of
helper name, both real stubs validate and compile, mandatory live tests reject
the previous failure, and the routine pipeline does not regress. Failure:
inventing a DOS call or return value, suppressing return-type errors, or restoring
name-based signature/body rewriting to satisfy obsolete source-header tests.

This repairs decompiler output, not the original source stubs. It does not prove
unobserved caller return-register behavior or linked-program equivalence.
Graph tools remained unavailable; conclusions use exact source and layer dumps.
