# Rewrite Byte Joins And Storage Bindings

Timing: first probe at 01:08:34 +02:00 on 2026-09-12; gate results recorded
at 01:22 +02:00. Approximately 14 minutes elapsed, including focused and broad
gate waits. Architecture validation also passes.

## Evidence

After fixing intra-instruction SP propagation, a diagnostic `__fimemset` run
with pruning disabled retained ES's saved bytes but restored from a distinct
two-byte `SimStackVariable` whose C type was `SimTypeChar`. This produced an
unbound duplicate local and lost the high byte.

`_promote_direct_stack_cvariable` was investigated and ruled out for this
failure: its six observed calls only handled byte arguments and changed no
types. Do not repeat that hypothesis without new evidence.

An instrumented `CVariable` constructor identified the actual creator:
`decompiler_postprocess_simplify._materialize_joined_word_expr_8616`. It made
new stack/memory word objects in Rewrite while copying the low byte's type,
without rebinding stores. It could also fall back to physical adjacency when
Alias state was absent. Logs: `/home/xor/.cache/fim-stack-promotion-census.log`
and `/home/xor/.cache/fim-restore-creation.log`.

## Change

Remove that stack/memory recovery from Rewrite. Keep the original byte join;
do not invent a wide object, change its type, or repair its stores here.
Existing register-view joins remain unchanged. Actual wide memory storage
must be materialized and bound in Lowering from earlier evidence.

Two compiled-C regressions cover separate stack and global byte bindings and
nonzero high bytes. Both failed before the change and pass afterward. Two old
tests requiring new Rewrite-owned storage now require original binding
preservation. Existing word arithmetic and register Alias tests still pass.

## Acceptance Status

- Focused run: 51 passed, one known `__fimemset` failure, 22.42s.
- MyPy passes for the edited owner. Ruff still reports legacy findings in the
  large module and old tests; no suppressions or weakened thresholds added.
- Routine pipeline: 268 early contracts passed; 4,326 pytest tests passed and
  one failed in 270.00s; both external lanes passed, including MS C round trips.
- `quality-fast` remains red on global Ruff; 39-module mypyc smoke passes.
- `__fimemset` is not fixed: production save/restore pruning still loses ES/EDI
  preservation. Whole-suite and expanded acceptance remain open.

Logs: `/home/xor/.cache/fim-rewrite-word-{before,focused,mypy,quality,pipeline}.log`.
