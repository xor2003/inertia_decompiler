# Scoped near-return continuation

`X86_16/frontend_near_return_continuation.py` proves from decoded instruction
facts that an indirect jump transfers to the incoming near-call return word.
The caller premise retains an exact indexed direct-call row and target. Its
decoded operand width must prove a word return address; far calls, wide near
calls, missing width facts, stale rows and foreign targets refuse.
Capstone `CS_ERR_DETAIL` is missing decoded evidence, including during wrapper
inspection and premise freshness checks; it refuses rather than crashing.
Other Capstone failures propagate with their original exception identity.

For a callee shared by several callers, the callsite-driven import carries the
actual resolved edge. Its caller/callsite/target coordinates and decoded
instruction address, extent and bytes must match one retained source-index row;
the bytes must also match current mapped memory. Distinct decoded row objects
are allowed, but matching coordinates alone cannot authorize a premise. A
context-free request still requires a unique source row. This transport does
not install invocation authority or discharge an unresolved backward tail.

Static MZ project loading retains a deferred request built from the source
bytes and declared load paragraph. On demand, `mz_static_boot.py` authenticates
only header CS:IP/SS:SP; GP registers, DS/ES, flags and environment remain
unknown. `mz_static_intake.py` checks the relocated module against mapped bytes
before installing the source. This path needs no KVM or runtime trace.

The invocation inventory may retain closed caller surfaces while a discovered
callee remains unresolved. Such evidence has `PARTIAL_CALLER_EVIDENCE` status,
explicit `pending_targets`, and `ready=False`. Admission requires reconciled
counts, zero failures and consistent status/obligations; an index alone is not
authority. Closed and pending heads share the boundary budget, checked before
another decode. Caller-edge evidence can supply a return-frame premise without
claiming that the callee or the transitive corpus is complete. Explicit roots
still require closure. The declared-environment adapter still requires READY.

Deferred intake refuses re-entry and clears its active state on exceptions.
Cached authentication refusals bind retained source and mapped evidence;
inventory refusals are not cached by image identity alone. The ordinary project
load does not scan a transitive call graph. None of this discharges an unresolved
error tail or creates universal callee authority.

The bounded dataflow tracks register provenance, stack-relative slots, overlap
of writes with the return word, CS/SS preservation and intervening effects.
Unknown effects, clobbered carriers, unproved paths and budget exhaustion keep
their typed refusal. A proved normal path cannot erase a failing sibling tail.

`X86_16/ir/near_return_continuation_view.py` owns conditional consumption.
The raw imported artifact retains its JMP and pending refusal; universal
publication and coverage remain refused. Only an independently authenticated
invocation scope crossing the identical call row/index and owning the exact
callee artifact/boundary may project RET. Native rederivation and source
revocation remain mandatory. The view requires a nonempty proved census and
an exact integer evidence ledger `(N, N, N, N, 0)` at consumption.

A body carrying both continuation and selector-window obligations requires
both proofs. `X86_16/ir/scoped_control_obligations.py` composes the existing
owners: continuation evidence defines an intermediate control surface, then
the entry-jump proof discharges selector obligations on that surface. Both
must bind to the same native source and independently authenticated consuming
scope. Every marker remains counted; missing, foreign or stale evidence and
unrelated refusals prevent complete coverage. Raw IR remains unchanged and
unavailable to context-free consumers. Projection must reauthenticate both
proofs, including the continuation census, before exposing effective edges.

Coverage, segment state and effect closure retain this scope. Their context-free
`complete` stays false; `complete_for(scope)` reauthenticates. The projection
changes the control classification only; preceding register, stack and memory
effects remain the imported binary effects. Rewrite does not recover semantics.

The quick frame-width controls are in the normal contract pipeline. Decoded
continuation, actual-MZ scope, corruption and revocation controls run in the
serial `test-scoped-ir-native` lane, also required by `test-pipeline-expanded`.
These are static proof tests and do not require KVM. They do not establish that
an original compiler/game function is fixed: applicable tail validation,
call-preservation, shape and recompilation acceptance remain required.
