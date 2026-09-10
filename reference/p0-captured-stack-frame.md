# Captured SP Frame Proof

## Root Cause (2026-09-09)

The anchor-provenance experiment exposed an independent upstream error:
`ENTER 2,0` had a PROVEN frame delta of -4, although BP is set to entry-SP -2
before local allocation. ENTER allocations 0, 2 and 16 all reproduced it.

IR preserves a register-shaped value plus `source_tmp`, identifying the earlier
VEX read/expression. The compact frame-analysis path treated that value as a
fresh read of the current SP and added its already-accounted displacement
again. A saved SP expression is not interchangeable with a current register.

`analysis/stack_frame_ir.py` now uses the compact direct-read path only when
`source_tmp is None`. Captured values use the existing block-local SSA affine
trace, which follows the actual read before subsequent writes. No new semantic
recovery is added to Lowering, Rewrite or CLI; frontend byte execution is intact.

## Evidence

- Before: three new binary ENTER frame tests fail; 12 pass (8.22s).
- After: 80 frame/address/smoke tests pass (18.48s), including the four failures
  that rejected unconditional anchor conversion. Tests use `pytest -n 7`.
- Scoped Ruff `check --fix`, MyPy and Pyright pass.
- Fresh isolated `byteops_unsigned` still retains its EBP assignment, although
  decompilation exits 0 with `validation=passed` and clean whole-tail validation.
  This frame repair is not a claim that byteops or the MSC6 lane is fixed.
- `quality-fast`: exit 0; 3,090 tests pass (138.88s), seven dependency warnings,
  configured checks and all three executable quality guards pass.
- Default pipeline: exit 2; unit 3,090 passed (122.30s), QuickC passes, MSC6
  5/7. The same scalar_types_io undefined-EBP compilation and function_pointers
  unresolved-ESP/EBP linkage failures remain. No full-suite pass is claimed.
- Logs: `/tmp/inertia-frame-captured-sp-{quality-fast,test-pipeline}.log` and
  `/tmp/inertia-frame-captured-sp-{before,after,mypy,pyright}.log`;
  fresh C and diagnostics: `/tmp/inertia-frame-captured-sp-byteops.{c,log}`.

## Acceptance And Next Work

Reason: every stack-coordinate consumer depends on the frame delta being true.
DoD: binary frame tests, existing coordinate/smoke tests, scoped static checks,
quality-fast and the default compiler pipeline agree. Quality-fast is green;
default pipeline acceptance remains open because of the two existing failures.
Failure: double-counting an earlier SP update, accepting unknown captured
provenance, changing frontend execution, or hiding a validation/rebuild failure.

The rejected anchor experiment remains diagnostic-only under `/tmp`. Its native
SSA tag survived C lowering, but four smoke tests failed while the frame delta
was wrong. Re-evaluate only after this frame fix; do not assume tagging alone
solves all storage-coordinate problems or revive unconditional rebasing.
