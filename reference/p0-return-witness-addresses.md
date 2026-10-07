# Return Witness Address Checkpoint

## Scope And Reason

Types/Lowering must materialize return trials only from exact instruction
identities. The scalar witness resolver could match an absent caller witness
to an addressless SSA instruction (`None == None`) and construct a
`StorageUseEvidence8616` with `instr_addr=None`. This is a reproduced boundary
defect, not evidence that ordinary SORTD input reaches it: upstream
classification may already refuse the incomplete caller fact.

The resolver now requires a concrete instruction address. Pointer alias-step
construction makes its existing address prerequisite explicit. Split-return
classification consumes the validated, typed Alias-domain mapping instead of
re-deriving optional domains. Split witness evidence retains the checked
producer after exact instruction-address equality. No semantic recovery was
added to Rewrite, postprocess, or CLI.

## Acceptance And Failure

- DoD: absent addresses refuse; zero remains a valid address; duplicate
  witnesses remain conflicts; exact witnesses retain their instruction index.
- DoD: AX/DX and DX/AX storage orders both retain correct per-piece uses.
- DoD: scoped Ruff `--fix`, MyPy, Pyright, architecture checks, and the default
  DOS pipeline pass. New tests remain in the routine pipeline and ownership map.
- Failure: publish incomplete evidence, guess an address/domain, reorder
  physical outputs, suppress typing diagnostics, or regress DOS round trips.

## Measured Evidence

- Before: one failing address regression and five passing controls. The failed
  case constructed evidence with `instr_addr=None`.
- After: 85 focused return/storage tests pass; the final repeat took 23.23s
  alongside broad gates. All reported individual durations were below 1s.
- Pipeline/ownership/Make inventory: 118 passed in 6.39s.
- Scoped Ruff, MyPy, Pyright and startup architecture checks pass.
- Changed non-test types/docs ratchet and ownership validation pass.
- Default pipeline: 2,556 unit tests passed in 146.48s; QuickC and all seven
  MS C tiny compile/run/decompile/recompile/run cases passed. Three lanes
  passed, none failed, skipped, or timed out.
- Global `quality-fast` remains red: 11 MyPy errors, previously 14. Remaining
  owners are segmented-load carriers, callsite prototype declarations, and
  the postprocess-stage compatibility bridge. No full-suite closure is claimed.
- `quality-dev` also remains red: its selected MyPy scope reports `Any` returns
  at `inertia/cli/cache.py:255` and `callsite_summary_codec.py:237`.
  Its downstream checks did not run; this is not a successful development gate.

Logs: `/tmp/inertia-return-witness-{before,tests,admission,mypy,pyright,quality,architecture,pipeline,dev,types}.log`.

## Timing

Reproducer baseline completed 2026-09-09 00:27:02 +02:00. Implementation and
focused verification were completed before 00:31 +02:00. The default pipeline
finished before 00:32:43 +02:00, within 5m41s of the baseline checkpoint.
This excludes earlier investigation and is not an estimate for remaining P0.
