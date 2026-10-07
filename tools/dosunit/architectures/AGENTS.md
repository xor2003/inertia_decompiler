# Architecture owner

Read the root guidance and this directory's README. Own architecture effects
here; pure contracts stay in `../contracts/` and proof verdicts stay with their
comparison owner. Supply state explicitly and keep register/control/input
projections coherent. Preserve unsupported-operation refusals.

Run scoped `lint-iteration` and the contract-boundary tests at nice 10. Changes
to effects require the matching terminal/call/recursive proof controls, with
existing proof/resource budgets. Import moves also require legacy identity,
model-seal and isolated wheel checks.
