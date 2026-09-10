# Exact Stack Arithmetic Producer Links

## Reason And Ownership

The final InitMenu arithmetic retains exact producer tags, but consumers need
to distinguish a producer from its physical SP write. The IR module
`ir/stack_pointer_provenance.py` now snapshots that direct native AIL dataflow
relationship at the existing pre-SSA boundary, after proven CALL frames have
been consumed. It reuses source tags rather than introducing a cross-SSA
propagation system or deriving identities from rendered C.

Each immutable link retains the instruction/block/producer/write identity,
physical register offset, arithmetic width, operation, constant operand and
separate CFG occurrence. Different blocks or statement positions are not merged
merely because they share original source tags. The Clinic owns one typed
`_inertia_stack_pointer_provenance_8616` artifact for that graph.

These are dataflow facts, not proof that the arithmetic is a stack argument,
that its input is a passive SP value, or that its effect may be removed.
Materialized counters here mean published IR links, not deleted instructions.
Argument/storage ownership and complete live-use checks remain separate work.

## Acceptance

DoD: preserve exact non-adjacent producer/write indices; keep 16/32-bit widths
and duplicated CFG occurrences; refuse missing/mismatched source keys,
unsupported widths and nonconstant updates without mutating the graph; publish
after CALL-frame consumption; expose a closed census; cover the observed
InitMenu arithmetic and preserve generated C and validation.

Definition of failure: use an index increment heuristic, merge occurrences by
source address, guess argument ownership, treat a published link as DCE proof,
change runtime register effects, or report unchanged C as an InitMenu fix.

The initial missing-module test run failed collection. The first implemented
run exposed five faulty test corruptions: native AIL accessors return copies,
and native tag conversion normalizes booleans to integers. Fixtures now replace
expressions explicitly; invalid raw key types are tested directly at the key
reader. No production rejection rule was loosened to pass those fixtures.

The final focused run has 29 passes and the unchanged InitMenu bookkeeping
failure, seven warnings, 52.57 seconds total (43.36 seconds InitMenu). Seventeen
new tests cover this artifact and its stage wiring, with the existing twelve
CALL-frame tests also passing. All are included in routine test selection.
Scoped Ruff `check --fix`, MyPy and Pyright pass; Pyright reports zero diagnostics.

## Live Evidence

The verified stage observer records raw=67, normalized=66, classified=66,
materialized=66, failure=1. Its 66 links cover all 60 distinct arithmetic
producer keys observed in the final ten SP/BP assignments. The remaining
unsupported SP assignment is retained; no deletion consumer is installed.

Generated C is byte-identical to the prior baseline, SHA-256
`4a41e50d2e9dd5a85c438df8fee336b5c679ccfe28483c2677cacb87ca01ae3f`,
with `validation=passed` and clean whole-tail validation. The unchanged InitMenu
test still stops before its compiled behavior harness.

The fast quality gate exited zero: 3,313 tests passed with eight warnings in
137.11 seconds, and all three executable quality guards passed. The slowest
tests were the sidecar-free RunMenu Escape regression (54.62 seconds), InitBars
stack-array regression (54.10 seconds), and indexed-address parity inventory
(34.32 seconds). The known threaded-fork warning remains visible alongside
the dependency warnings. This is not a controlled performance comparison.
The default external pipeline was last
verified at the preceding typed-declaration checkpoint; no refreshed full-suite
or completed semantic-function claim is made here.

Logs: `/tmp/inertia-stack-provenance-{live,acceptance,quality,pyright-final,mypy-final}.log`.
The live C is `/tmp/inertia-stack-provenance-live.c`. Temporary observers are
not installed in production. Focused acceptance was observed terminal before
the fast quality gate started. The gate log spans 04:30:12 to 04:34:15 CEST
on 2026-09-10 (4m03s including checks/waits); terminal exit zero was verified
afterward. This is not total active implementation time or a remaining-goal ETA.
