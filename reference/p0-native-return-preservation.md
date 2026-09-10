# Native Return Expression Preservation

## Root Cause (2026-09-09)

The return-expression trace identifies an early compatibility rewrite:
`MakeTypecastsImplicit`'s Inertia hook replaces a present native dereference
expression with `_infer_x86_16_c_return_value_from_ax_8616`. Its stack lookup
uses alternate offsets and name/size preferences and can choose a saved-frame
byte instead of the local supplying AX. A dereference is not a missing return.

The hook now infers only when the current return expression is absent and the
result is not proven unused. Native expressions remain available to the normal
IR/SSA/typed pipeline. No new C-body, signature or call repair is introduced.

## Evidence

- New binary regression records compatibility inference calls for an existing
  native stack return: one failure before the guard change (11.55s).
- After: 73 return/smoke tests pass (27.95s). Scoped Ruff --fix, MyPy and Pyright
  pass. The regression is admitted to routine Make and pipeline lists.
- Combined diagnostic native-anchor experiment: all four previously failing
  smoke cases pass (22.49s). Fresh byteops contains no EBP reference, exits 0,
  validates cleanly and compiles/runs to 0xC000 under GCC -O0 and -O2 without
  supplying any runtime register variable.
- The provenance mechanism is still diagnostic-only under /tmp. Production
  native-anchor publication/consumption is not implemented or accepted yet.
- Combined `quality-fast` exits 0: 3,101 tests pass (170.07s), configured
  checks and three executable guards pass. This is not a whole-repository
  test result.
- Combined default pipeline exits 2: 3,101 unit tests pass (124.15s; lane
  124.629s), QuickC passes (43.275s), MSC6 remains 5/7 (64.787s).
  `scalar_types_io` still emits undefined EBP; `function_pointers` still has
  unresolved ESP/EBP at link time. Pointer argument-class warnings in
  `pick_ptr` remain visible. These are the same observed failures as before.
  Reports: `angr_platforms/.cache/test_pipeline/summary.json` and
  `examples/build_msc6_tiny/report.json` (mutable latest-run artifacts).
- Logs: `/tmp/inertia-return-expression-preservation-{before,after,mypy,pyright}.log`;
  `/tmp/inertia-anchor-return-probe.log`;
  `/tmp/inertia-anchor-return-preserved-smoke.log`;
  `/tmp/inertia-anchor-integrated-byteops.{c,log}`.

## Acceptance And Next Step

Update: [native anchor provenance](p0-native-stack-anchor.md) is now integrated
and passes focused tests and the fresh compiled byteops check. The diagnostic
only status above describes the earlier prerequisite checkpoint. Combined
broad-gate acceptance for the new integration remains pending.

Reason: existing native expressions must not be replaced by a guessed C lookup.
DoD: present expressions survive, missing-return handling stays covered, return
semantics and scoped/full gates agree. Quality-fast passes; the default
pipeline still fails its MSC6 lane, so overall acceptance remains open.
Failure: substitute an offset/name-selected local for a present expression,
hide changed/uncollected validation, or claim the diagnostic hook is deployed.

Next: publish typed native entry-SP anchor provenance at the SSA rewriting
boundary and consume only that explicit proof in Lowering. Keep untagged legacy
references unchanged; do not restore unconditional reference rebasing. Test
publication, refusal, codegen-tag preservation, frame completeness and clones;
then rerun the four smoke cases, byteops, strict compilation and MSC6 pipeline.
