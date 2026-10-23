# Instruction semantics

The instruction semantics, flag analysis, call effects, carry/borrow evidence,
and terminal-return analyses live here. Implementations retain their existing
interfaces and behavior. Historical `X86_16/semantics/` module paths are aliases
to these owners.

`scoped_callee_stack_effects.py` binds one physical decoded near CALL to an
Alias `ScopedCalleeStackPointerResult8616`: `complete_for(caller_scope,
callee_scope)` and `return_sp_delta_for(caller_scope, callee_scope)` require
the offered caller scope to share the retained chain parent's provenance and
the offered callee scope to share the retained body scope's provenance, with
the physical binding and body proof re-read on every projection. The result
never publishes a context-free displacement; `CalleeStackCallResult8616` and
`IRCallStackCoordinates8616.net_sp_delta` stay universal-only. Native controls
live in `tests/semantics/test_scoped_callee_stack_effects.py`.

Private tests live in `tests/semantics/`. Tests involving lowering, widening,
validation or full decompilation move with those layers or shared integration
coverage. The IR and other layers still use their existing owners during the
remaining file moves.

## Repeated comparison flag liveness

`DecodedStatusFlagInstruction8616.repeat_prefix` preserves the decoder's REP
metadata. Repeated SCAS/CMPS may execute zero iterations, so their flag writes
are not definite overwrites and cannot alone make an earlier flag definition
dead. Ordinary non-repeated comparisons retain their definite overwrite set.
This contract belongs to `status_flag_liveness.py`, before lifting suppresses
writes. Native decoder controls live in
`tests/semantics/test_x86_16_status_flag_liveness.py`; zero-count binary equality
is mandatory in `tools/dosunit/tests/test_real16_repeat_summary_contract.py`.

Native lifting must restrict decoded lookahead to the same `max_inst` window
that will be lifted. An instruction outside that window cannot justify killing
an earlier flag definition. `Lifter86_16.decode` enforces the boundary before
Gymrat supplies its future-instruction list; the bounded-SHL/XOR regression in
`test_x86_16_status_flag_liveness.py` checks the emitted native flag write.
