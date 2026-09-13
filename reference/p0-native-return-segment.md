# Native Return Segment Coherence

## Root Cause

Step 9 investigation on 2026-09-12, after the 18:31 checkpoint. The native
tracker probe completed before implementation; final gate results were
collected by 18:59 +02:00. Active engineering and gate-wait time were not
separately measured.

The sidecar-free InitBars binary uses `PUSH CS; CALL near` to invoke a callee
with a far return. The native tracker accounted for the near CALL's return IP
but not the separately pushed CS consumed by RETF. Consequently its caller SP
stayed two bytes too low after the call. At the final SI POP it reported
entry-SP -126 instead of -124. Correctly placed saves at -124/-123 were read
through a different, uninitialized byte pair; another saved pair became dead.
The resulting C was rejected by the initialization gate, not just cosmetically
different from the source.

The observation came from the real native tracker used during decompilation,
not a reconstructed offset calculation. Before the far-return call, the trace
shows argument pushes, then the CS push, CALL and caller ADD SP,4. The latter
restores arguments but cannot compensate for an unmodeled CS pop.

## Correct Owners

`semantics/call_return_segment.py` already proves exact adjacent PUSH CS/near
CALL effects and checks a complete callee return census. Its typed frame now
exposes the additional return bytes only for a successfully proven frame.
Unknown/mixed returns, incompatible widths, explicit cleanup and incomplete
prefix effects do not gain this adjustment. No helper name is used as proof.

The native compatibility adapter in `stack_tracker_return_segment.py` consumes
that proof after angr's ordinary CALL transfer. The existing installer also
retains the allocation adapter. Native lookup is restricted to its current
CFG block, avoiding a repeated whole-function prefix scan.

The pre-Alias call-stack pipeline collects the same frame facts and publishes
the extra pop in `IRCallStackEffect8616.net_stack_delta`. Native coordinates
and Alias's IR input therefore do not develop competing stack models. No
storage offset is repaired in Lowering or Rewrite, and no live save is deleted
to satisfy the validator.

## Acceptance

Reason: a lost machine return slot shifts every later SP-relative access,
making correct register saves look dead and their restores uninitialized.

DoD: the exact far-return prefix consumes its CS slot in both native tracking
and typed IR effects; an ordinary near-return call keeps CS as an argument;
caller-cleaned arguments remain independent; the original InitBars regression
passes without weakened assertions and external roundtrips stay green.

Definition of failure: inferring RETF from PUSH CS alone, adding the pop twice,
accepting unsupported widths/cleanup, fixing only one stack representation,
or bypassing the initialization/semantic gates.

Evidence:

- Fail-first native controls: 2 failed / 1 passed in 14.31s. Both complete
  far-return variants lost the CS slot; the near-return control was correct.
- Final related tests: 67 passed, 7 dependency warnings, in 11.44s under
  `pytest -n 7`. Coverage includes multiple far endpoints, near-return refusal,
  caller-cleaned arguments, and scoped/full return-proof agreement.
- The original three SORTD regressions: InitBars passes; RunMenu and InitMenu
  still fail. All original assertions are retained.
- Scoped MyPy passes for five changed production owners. New native adapter
  and regression Ruff pass. Existing Semantics lint debt remains visible.
- Full architecture checks pass. `quality-fast` remains red on global lint
  debt; its 39-module compiled-import smoke passes.
- Default pipeline: 268 preliminary tests pass; curated lane 4,716 passed and
  2 failed in 275.32s. QuickC passes; MS C tiny remains 7/7.
- Lane walls: curated 275.93s, QuickC 46.93s, MS C 100.09s. These are warm-cache
  acceptance timings, not a controlled speedup claim.
- The curated lane has 8 warnings, including the multithreaded-fork warning
  from `fork_timeout.py`. It is not suppressed.

New source/tests are enrolled in Make, the default pipeline, ownership mapping
and architecture promotion. Full collection and expanded acceptance are not
refreshed; Step 9 remains open.

## Remaining Work

RunMenu still reports missing register definitions, a branch-predicate mismatch
and missing ESC switch-exit evidence. Its def-use count fell from 30 to 26 but
it is not accepted. InitMenu still reports four uninitialized stack reads, now
at different offsets; trace its remaining call/frame transitions rather than
assuming they share the already-fixed cause.

Temporary evidence under `/home/xor/.cache`: `initbars-native-sp.log`,
`return-segment-native-before.log`, `return-segment-final-focused.log`,
`return-segment-sortd-tests.log`, `return-segment-mypy.log`,
`return-segment-quality.log`, `return-segment-architecture.log`, and
`return-segment-pipeline.log`. Diagnostic hooks are not part of production.

## InitMenu Follow-Up: Native Callee Cleanup

2026-09-12 19:07 +02:00: two fresh private-cache diagnostic runs completed.
No production semantics changed during this investigation. The prior
far-return-prefix hypothesis does not explain the remaining drift: observed
PUSH CS/near CALL pairs now consume their separately pushed return segments.

The native trace instead isolates the first persistent eight-byte drift at
callsite `0x10133`, targeting `0x1143a`. Four argument words lower SP from
entry-SP -24 to -32. Native CALL transfer leaves it at -32. The canonical
`callee_return_evidence_8616` producer reports complete binary evidence:
88 raw/normalized/classified/materialized facts, zero failures, consistent
near 16-bit returns with eight bytes of cleanup. Thus the returning caller
should resume at -24. Subsequent argument cleanup does not repair this loss;
the final SI POP sees -32 instead of its saved slot at -24.

The installed angr native tracker derives optional callee cleanup from a
calling convention and prototype argument locations, not this binary proof.
The allocation and return-segment adapters do not currently bridge this
additional obligation. This identifies the next repair at the native
Frontend compatibility boundary, consuming authoritative Semantics evidence;
it is not a reason to shift stack objects in Lowering.

Next acceptance obligations:

- Fail-first native controls for binary-proven immediate cleanup without a
  prototype, ordinary zero cleanup, and incomplete/mixed return evidence.
- Reconcile cleanup already performed by angr rather than adding it twice;
  cover a convention/prototype that already accounts for the same cleanup.
- Verify the pre-Alias call-stack projection consumes the same cleanup fact.
- Re-run the original InitMenu regression without weakening initialization,
  call-preservation, compilation or tail-validation requirements.

DoD: both stack projections reflect the proven callee argument pop exactly
once, InitMenu passes its original acceptance, and refusal controls preserve
uncertainty. Failure: prototype/name guessing, double cleanup, offset repair
in Lowering, or treating the diagnostic process exit code as acceptance.

Both diagnostic processes exited zero, but their worker reports retain
failed postprocess validation and uninitialized stack reads. InitMenu is
therefore still not fixed. Logs: `/home/xor/.cache/initmenu-native-sp.log`
and `/home/xor/.cache/initmenu-cleanup.log`; the latter records the complete
callee cleanup census. No full-suite result was refreshed in this follow-up.

### Cleanup Adapter Checkpoint

2026-09-12 19:20 +02:00: the native compatibility adapter now consumes the
complete near/16-bit cleanup proof. It subtracts the cleanup projection the
installed angr backend already derives from its first eligible callee's
convention/prototype, then applies the proven amount. This backend-specific
reconciliation is not a new semantic inference. Unknown or mixed binary
returns retain existing behavior; no new cleanup is guessed. Far-return
cleanup remains outside this added adapter's scope.

The pre-Alias owner already uses terminal cleanup through callsite summaries:
`callsite_summary._callee_stack_cleanup_bytes_8616` consumes the canonical
terminal evidence, and `semantics/call_stack_effects.py` publishes callee
cleanup as net delta when no caller cleanup instruction owns it. No second
IR cleanup implementation was added.

- Fail-first native tests: 1 failed / 9 passed, 8.31s.
- Related native/allocation/IR tests: 36 passed, 15.43s. Added cases cover
  immediate cleanup, zero cleanup, existing prototype cleanup reconciliation,
  contradictory prototype cleanup, mixed returns and unresolved exits.
- Scoped Ruff `--fix` and MyPy pass for the two production adapters.
- Full architecture check passes. Global quality-fast remains red on lint
  debt; the 39-module compiled-import smoke passes.
- Default pipeline: 268 preliminary passes; 4,722 curated passes / 2 failures
  in 276.73s. QuickC passes (48.52s); all seven MS C round trips pass (95.41s).
  These timings are not a controlled optimization experiment.

InitMenu's original regression still fails, but no longer at uninitialized
register-save reads: both structuring and postprocess report stable validation.
Strict GCC now rejects the DI restore's `(unsigned char)ach` expression.
Generated C uses the buffer object as a saved-register byte. Its declaration
is labeled BP-0x14, while the original listing uses BP-18 for the buffer.
That discrepancy guides the next storage-coordinate investigation; it is not
permission to shift objects or add a cast in Rewrite. The original regression
and compilation checks remain unchanged. InitMenu is not accepted yet.

Logs: `/home/xor/.cache/native-cleanup-{before,focused,initmenu,mypy,quality,architecture,pipeline}.log`.
The final MyPy rerun passed directly after correcting an explicit backend
integer conversion; the earlier MyPy log retains that resolved diagnostic.
All gate sessions are terminal. Full collection/expanded acceptance remain
unrefreshed, and RunMenu remains the other curated failure.

### Coordinate Collision Investigation

Fresh private-cache InitMenu probes identify aggregate materialization and
coordinate-registry invalidation, rather than a necessary pointer cast, as
the next repair surface. Production source was unchanged during these probes.

The first aggregate fact is correct: machine BP-18, 16-byte partition ending
at BP-2, backed by entry-SP -20. At the same time the saved DI low byte is a
different variable at machine BP-20 with a one-byte exact projection. Both
identities coexist correctly in the initial registry. A later observation
shows all local projections gone; following aggregate replay, the DI byte
declaration disappears while the buffer remains.

`stack_memory_ssa.py` calls `reset_local_stack_coordinate_projections_8616`
whenever it has any candidates. That reset drops every negative-BP
STACK_STORAGE projection, not only the ranges the current replay replaces.
Both saved-byte coordinates and aggregate coordinates use that producer.
The subsequent aggregate restore can therefore encounter unrelated raw-BP
and entry-SP variables with equal numeric offsets but lost provenance.

Next task: make replay invalidation range-scoped, preserving unrelated live
coordinate owners and refusing ambiguous overlapping replacements. Add a
regression with an unrelated replay candidate plus colliding numeric buffer
and saved-byte coordinates, then check the original InitMenu regression.
Do not globally preserve stale coordinates, infer identity from names, or
repair this with an emitted-C cast. The full scope and acceptance of Step 9
are unchanged.

Evidence: `/home/xor/.cache/initmenu-array.log` records the type publisher;
`/home/xor/.cache/initmenu-array-coordinates.log` records exact variable and
registry snapshots. Both diagnostic sessions completed. This is root-cause
evidence, not a completed coordinate fix or refreshed test-suite result.

### Scoped Replay Checkpoint

The reset now requires explicit machine-BP ranges supplied by the current
stack-memory SSA candidates. It removes exact replacement ranges only and
preserves unrelated local, argument and call-output projections. Partial
overlaps are not silently treated as ownership of a whole older object.
This repairs the reset's overly broad invalidation contract, but does not
close InitMenu's compiler failure.

Focused coordinate/call-output/stack-memory tests: 32 passed in 10.91s.
The new equal-numeric-offset regression rejects an injected old whole-local
reset at the saved-byte preservation assertion. Scoped MyPy passes. Ruff
passes for the reset owner and regression; stack_memory_ssa.py retains four
reported legacy complexity/magic-value findings. quality-fast remains red.

The unchanged InitMenu regression still fails strict GCC on the same buffer
pointer cast (65.78s including pytest startup). A fresh diagnostic run proves
the saved-byte exact projections now survive replay, yet the invalid final
expression remains. Therefore the earlier description of reset invalidation
as the complete cause was too strong: it was a demonstrated independent loss
of provenance, not the sole cause of the substitution. Later selection or
replacement of the saved-byte expression still needs investigation. Watching
direct CVariable.variable reassignment did not observe the bad replacement;
new expression construction or child replacement remains a candidate.

Logs: `/home/xor/.cache/scoped-coordinate-{focused,old-behavior,initmenu,mypy,quality}.log`,
`/home/xor/.cache/initmenu-coordinate-reset.log` and
`/home/xor/.cache/initmenu-variable-swap.log`. All sessions are terminal.
The full default/expanded/complete-suite gates were not refreshed for this
patch; no function fix or Step 9 completion is claimed.

### InitMenu Canonical-View Acceptance

2026-09-12 20:00 +02:00 checkpoint. The exact regression path now passes.
Several earlier diagnostic probes explicitly ignored local sidecars, unlike
the failing exact-slice regression. Their provenance observations remain
useful, but they did not establish the cause of that exact compiler failure.
The final probe matched the regression's discovered slice and reproduced
its 379-byte input and invalid cast before locating the construction site.

The actual bad cast was constructed by
`lowering/stack_lowering_impl.py::_canonicalize_stack_cvar_expr`. For a scalar
variable it found the authoritative machine-BP projection, but returned it
only when it differed from the current CVariable. When already canonical,
it continued into raw-offset fallback and could select the buffer sharing
the same numeric entry-SP offset. The enclosing semantic cast then rendered
that buffer pointer as a saved register byte.

The fix returns any authoritative exact projection, including the existing
node. It changes no storage proof, pointer cast, signature or rendered text.
Reason: canonicalization must be idempotent and must not discard stronger
coordinate evidence in favor of a numeric fallback. DoD: a proven current
node never reaches raw lookup, InitMenu passes validation/compilation and
its source-behavior oracle, and external roundtrips remain green. Failure:
merely casting the wrong buffer, dropping saves/restores, or weakening tail
validation to accept the collision.

Evidence:

- Fail-first generic regression reaches the forbidden raw lookup; after the
  one-condition correction, 28 related bounded tests pass.
- InitMenu reaches clean semantic/compilation acceptance. Its remaining
  formatting assertion now permits the redundant unsigned-short cast only
  when the loop variable is already declared unsigned short.
- The behavior harness declares explicit SI/DI state and now checks both
  complete register values survive, in addition to all original pause-guard
  output checks. The final focused InitMenu regression passes in 8.68s
  using cached decompilation; the preceding fresh run was 66.10s for the
  call and had already passed validation and strict generated-C compilation.
- Default pipeline: 4,724 passed / 2 failed in 225.49s. InitMenu passes.
  RunMenu remains failing; the other failure is the frontend two-INC
  condition test (`ne` versus expected `nonzero`). Its entire 21-test file
  passes separately in 7.63s. This is unresolved order/intermittency evidence,
  not permission to suppress it or call the curated lane green.
- QuickC passes (36.50s); MS C tiny roundtrips pass (98.27s).
- Architecture and scoped MyPy pass. Ruff reports 26 existing findings in
  the large stack-lowering owner; regression/helper Ruff passes. Global
  quality-fast remains red. Full collection/expanded gates are unrefreshed.

Logs: `/home/xor/.cache/canonical-stack-{before,after,initmenu-accepted,frontend-isolated,pipeline,quality,architecture,mypy,ruff}.log`.
The decisive diagnostic is `/home/xor/.cache/initmenu-cast-array.log`.
All sessions are terminal. Step 9 remains open for RunMenu, the intermittent
frontend test, global quality and complete acceptance.
