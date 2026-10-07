# Stored Call-Return Contract

## Ownership

Lowering joins one exact `ConditionIR`, a closed callsite return-storage
summary, and one stable `SS:BP+offset` identity in
`X86_16/lowering/call_return_stack_conditions.py`. It refuses unknown,
conflicting, incomplete, or non-stack evidence.

Structuring consumes that contract in
`X86_16/structuring/stored_call_return_early_exit.py`. It may replace empty
terminal return placeholders and flatten a proven continuation. It must not
rediscover the call, storage identity, condition polarity, or return value.

Validation consumes the same contract through
`X86_16/validation_call_return_storage.py`. The contextual condition and the
observed-location census therefore use one storage identity rather than an AST
register carrier whose alias can drift after a later assignment.

## Acceptance

The contract is accepted only when all of the following hold:

- the callsite summary proves one exact return store
- the typed branch condition consumes that store and has an exact target
- the structured condition uses the same stable stack variable
- both terminal return expressions are proven from typed effects
- materialization closes all five evidence counters
- tail validation passes with no semantic call or memory-effect loss

Any missing or conflicting fact keeps the original AST. Repeated Structuring
execution must be idempotent and report `already_materialized` without moving
or duplicating continuation effects.

## Required Tests

- `tests.validation.test_x86_16_validation_call_return_storage.py` covers storage identity,
  condition polarity, observed locations, and refusal cases.
- `test_x86_16_stored_call_return_early_exit.py` covers both terminal returns,
  continuation effects, refusal cases, and idempotence.
- the `_dos_loadProgram` COD and CLI regressions require `return err`,
  `return 0`, word stores through `cs[0]` and `ss[0]`, no high-byte duplicate
  stores, and `validation=passed`.
