# SSA operator interpretation

`z3_ops.py` owns interpretation of operators over supplied Z3 terms,
including integer widths, byte-array memory effects and summary functions.
It does not import Z3 until a caller supplies the backend module.

Document constant normalization, solver admission, deadlines and verdict
policy remain outside this owner. Lazy x86 flag semantics use the existing
authoritative condition contract. Preserve unsupported-operation refusals;
do not approximate unsupported behavior to obtain equality.

Legacy engine helper imports alias these exact objects during migration.
Boundary controls cover import isolation, legacy identities, 16/32-bit
memory roundtrips and deliberately corrupted stores.

`translation.py` owns serialized term and assignment translation through
`TranslationContext`. Each context explicitly carries its document, inputs,
assignment index, memo cache, backend and constant-normalization policy.
Different output normalization domains require separate caches. The legacy
engine translation entry points construct this context; operator recursion
no longer imports or calls back into the engine.

`composition.py` owns block-output substitution, exact named scalar/array
binding, shared-DAG equality and guarded state merging. Existing deadline
checks remain at the same work boundaries. Keep comparison caches scoped to
live terms; the merge owner pins compared roots to prevent recycled identities.

`materialization.py` owns deterministic serialized assignment references,
shared-term memoization and input discovery through references. Neither module
imports the engine, architecture setup or a solver. Legacy engine helpers alias
these owners. Array `mem` binds program `memory`; other arrays bind their exact
names, and unbound arrays remain explicit inputs. A missing assignment or
expired deadline retains its existing refusal.

`identity.py` owns literal SSA and machine-code identity admission over an
explicit `ComparisonPolicy`. It has no backend or engine dependency. With
explicit-only comparison, normalization maps require solving even if raw
expressions or machine-code hashes match. The legacy engine helpers alias
these exact functions. Layout inference and proof orchestration remain in
the engine; their per-invocation policy comes from `../contracts/comparison.py`.
