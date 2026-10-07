# Handoff: comparator loop invariants and indirect calls

The active plan and acceptance ledger are now
[Comparator plan: loop invariants and indirect calls](comparator-coverage-progress.md).
Status: planned, **0/6 milestones accepted**. Start at LI0; do not start a full
corpus sweep or count existing controls as new coverage gains.

Work in `/home/xor/vextest`. Read `AGENTS.md`, `reference/agent-execution.md`,
the active plan, `reference/dosunit-execution-spec.md`, and the applicable
`reference/devin-handoff.md` before execution. Use codebase-memory with coverage
checks and targeted source verification. Preserve concurrent edits and retained
proof receipts; use private regular-file snapshots for before/after evidence.

Scope: real16 MZ and PE32-to-PE32 equivalence; bounded single-loop invariant
proofs and closed finite indirect calls, then their composition. Extend existing
proof owners. Preserve ELF compatibility, mandatory Cython lifting, full state,
segmented memory, typed verdicts and source/contract provenance. No reconstructed
C edits, decompiler M0–M7 expansion, differing recursive-layout redesign, or
increased default proof budgets.

Use RTK, nice10/JIT1, at most six test slots/two heavy proof jobs. Static
comparator work requires no KVM. Workers run focused tests/lint; parent reviews
exact deltas, actual-image corruption controls and measured corpus transitions.
Use the plan's finite proposal/refinement and stop rules. No proof gain means
diagnosis, not milestone acceptance.
