# COD Function Extent Repair

## Root Cause

September 20 follow-up: `_dos_resize` still lacked both source return paths
after its unrelated stream-pointer substitution was repaired.

The constructed fixture preserves all 135 body bytes and appends five external
call stubs. Independent CFGFast on these exact bytes recovers the epilogue at
0x1083 and its RET at 0x1086. Production entry recovery instead accepts its
first fast 128-byte window. The last decoded SUB ends at 0x1081; the resulting
region cuts off the jump and shared epilogue. Production reports returning=False
and Clinic contains no Return statements. This is not late return deletion.

A read-only worker probe confirmed the actual production graph, not just a
parent-process hook. The initial parent-only hook did not execute inside the
clean worker and was not used as negative evidence. Saved observations:
`.cache/dos-resize-worker-probe.log`, `.cache/dos-resize-return.log` and
`.cache/dos-resize-return-layers/`.

## Repair

The COD fixture transport now supplies its exact body end, excluding appended
synthetic callees, through the existing exact-region request field. Named-entry
recovery no longer ignores an explicit region in favor of a guessed fast window.
The region also survives the fallback for projects without loader extent data.

This is input-boundary and recovery orchestration, not semantic recovery in the
CLI: no return expression, argument, source type or body is synthesized. Existing
binary/CFG/IR return analysis receives the complete function and recovers its
values. Ordinary requests without exact bounds retain their current behavior.

## Evidence And Remaining Work

- The existing boundary-forwarding test now covers named/unnamed entries with
  and without exact bounds. Two exact-bound cases failed before, all four pass
  afterward; all 19 extent-repair tests pass in 7.60 seconds.
- Production output now contains `return rout.x.bx;` and `return 0;`.
  Artifacts: `.cache/dos-resize-full-extent.{c,log}` and layer snapshots in
  `.cache/dos-resize-full-extent-layers/`.
- The function still exits 4: missing FILE declaration and an incompatible
  ERROR format pointer remain. Do not declare the entire function fixed.
- The routine pipeline passes all three lanes: 6,131 main-lane tests in
  307.99 seconds, QuickC fixtures in 39.996 seconds, and all eight MS C tiny
  examples in 111.436 seconds. This is not a whole-repository pytest run.
- Focused mypy and mandatory types/docs checks pass for both changed modules.
  `quality-fast` remains blocked by lint debt; direct Ruff reports 90 findings
  across the touched files. No diagnostics were suppressed. Evidence:
  `.cache/cod-extent-{pipeline,quality,mypy,types,ruff}.log`.

DoD for this sub-repair: exact bounds reach recovery, both original returns
survive in the production reproducer, focused and routine regressions pass,
and remaining failures remain visible. Failure: using source text to manufacture
returns, widening past the known body into synthetic callees, or accepting a
smaller heuristic window in place of explicit bounds.

The general fast-window path for inputs without authoritative bounds is not
proved complete by this repair and still needs a truncation audit. The COD
fixture is not an original linked program; semantic validation compares pipeline
stages and cannot alone prove correspondence to the source listing.
