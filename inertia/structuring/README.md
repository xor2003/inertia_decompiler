# Structuring

This layer consumes proven IR, alias and condition facts to structure branches,
loops, switches and returns. Stage orchestration lives in
`decompiler_structuring_stage.py`; import these canonical owners directly.
Private regressions live in `tests/structuring/`.

A pass may declare an owning applicability check. It must inspect the current
typed AST afresh and return false only when it proves that the pass has no work;
unknown input remains applicable. A skipped pass preserves its zero-work
diagnostics. Applicable passes retain their before/after validation, and final
function validation remains mandatory. `INERTIA_VALIDATE_ALL_STRUCTURING_PASSES=1`
also runs proven inapplicable passes for diagnostic coverage.

Condition CFG consumers resolve codegen's authenticated retained Function through
`inertia.ir.vex_import.codegen_function_8616`. Native analysis can own a private
knowledge base; an empty or same-address default project entry must not replace
its graph. Foreign ownership fails loudly. Missing or ambiguous evidence cannot
authorize a branch replacement.

Source-instruction tags identify a condition's origin, but do not establish the
orientation of its structured true arm. Preserve polarity through proven operand
identity or exclusive CFG target ownership. Width and signed operand views remain
Lowering-owned; Structuring must consume those views without guessing or moving
semantic repair into Rewrite. Validation and original-versus-generated execution
are separate acceptance evidence.
