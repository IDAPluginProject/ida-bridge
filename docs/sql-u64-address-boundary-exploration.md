# SQL u64 and address boundary note

This is a research note, not user-facing documentation. Keep it only to preserve the reasoning behind the current policy.

## Problem

IDA uses 64-bit addresses and other `u64` values. SQLite `INTEGER` is signed 64-bit. APSW follows SQLite's signed `int64` boundary.

This matters for high-half addresses such as `0xfffffe0007004000` and affects:
- table columns
- views
- scalar function inputs and outputs
- JSON transport
- any computed SQL expression involving address-like values

The original symptom was `OverflowError` on direct reads such as `db_info`, `funcs`, `names`, and `segments`. The real problem is broader: how to keep a normal SQLite experience while handling values that do not fit in signed `INTEGER` semantics.

## Hard constraints

These are the facts worth remembering.

### SQLite

- `INTEGER` is signed 64-bit.
- There is no normal unsigned-64 SQLite integer mode.
- Oversized integer literals do not become unsigned integers.
- SQL expressions over address-like values use signed semantics once they enter SQLite as `INTEGER`.

Examples:
- `0x8000000000000000` is signed min `INTEGER`
- `0xfffffe0007004000` is a negative `INTEGER`
- decimal literals above signed 64-bit range become floating-point (`REAL`), not exact integers

### APSW

- Python `int` binds through SQLite signed `int64` APIs.
- Values above `0x7fffffffffffffff` do not bind as `INTEGER`; they raise `OverflowError`.
- Result integers come back through signed `int64` APIs as well.

### Consequence

There is no real design where we "just pass uint64 through SQLite integers" unchanged.

## Current policy

Use signed boundary encoding at the SQLite layer, then repair representation where provenance is known.

In practice:
- address-like and `u64` values cross the SQLite boundary using signed `INTEGER` reinterpretation
- known address-like columns and known address-returning scalar results decode back to normal unsigned Python ints after query execution
- JSON transport renders registered address-like columns as `0x...` strings
- address inputs must be SQLite `INTEGER` values, typically unquoted hex literals

Why this policy won:
- keeps normal SQLite queries working for common cases
- preserves direct table/view access patterns
- avoids inventing a custom side-channel result protocol
- fits the project rule: behave like SQLite as much as possible

## Limits of the policy

Post-query decoding can change representation, not SQLite semantics.

That means it cannot fix:
- arithmetic semantics
- ordering semantics
- aggregate semantics
- comparisons inside computed expressions

Known weak spots:
- computed expressions such as `start_ea + 0`
- aggregates such as `max(start_ea)`
- aliased or otherwise provenance-losing expressions

Once provenance is lost, SQLite has already evaluated the expression using signed semantics.

## Alternatives explored

### Hex text everywhere

Pros:
- exact value preserved
- user-facing addresses always look familiar
- no integer overflow at the boundary

Cons:
- breaks normal numeric SQL
- range queries, ordering, joins, and arithmetic become unnatural
- pushes too much custom knowledge onto the agent

Rejected.

### Custom side-channel metadata or richer result envelope

Pros:
- could preserve more provenance

Cons:
- fights normal SQLite expectations
- increases protocol complexity
- easy for agents to ignore or misuse

Rejected.

### Value-based heuristics

Example: "convert negative ints back to unsigned if they look like addresses."

Cons:
- ambiguous
- breaks signed values that are legitimately negative
- hard to make coherent across tables, views, and functions

Rejected.

### Special-case only the originally failing table

Cons:
- not a real design
- the boundary affects many tables, views, and scalars, not just `db_info`

Rejected.

## What is still worth remembering

- This is not a formatting bug. It is a SQLite/APSW type-boundary problem.
- `idasql` also ended up with a hybrid approach, which is additional evidence that pure SQLite integers are not enough for all address surfaces.
- The important distinction is between:
  - SQL semantics inside SQLite
  - representation after query execution
- Any future revisit should start by deciding whether the project still prefers SQLite-native behavior over perfect `u64` fidelity in every expression.

## Future revisit questions

If this area becomes painful again, the first questions to ask are:
- Are direct table/view reads still the dominant use case?
- Are agents actually blocked by signed semantics in computed expressions?
- Is the pain large enough to justify a less SQLite-like contract?
- Do we want a separate contract for addresses, or is the current hybrid still the best tradeoff?
