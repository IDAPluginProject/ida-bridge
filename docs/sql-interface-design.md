# SQL interface design

This file keeps the durable SQL contract and design rules.

## Model

The SQL layer is APSW SQLite virtual tables backed by IDA APIs.

Entry points:
- `ida-bridge exec <target> --sql "..."`
- `ida-bridge exec-idb --idb /path/to.i64 --sql "..."`
- `idb.sql(query)` inside the exec environment

## Column metadata

Each table declares a `CREATE TABLE` schema plus `COLUMN_SPECS`, which holds a `ColumnSpec` only for columns needing non-default metadata. Four flags:

- `hex`: render the value as `0x...` in JSON transport
- `u64`: carry the value across the SQLite boundary as reinterpreted signed `INTEGER`
- `rowid`: SQLite's rowid comes from this column
- `writable`: assignment is allowed; every unmarked column rejects it

`apply_schema_specs` derives the runtime metadata from those declarations and attaches it to the table and cursor classes.

This declarative layer is ours, not SQLite's. One declaration site drives transport, row identity, and write enforcement.

## SQL contract

Supported surface:
- normal SQLite queries via APSW: `SELECT`, `WHERE`, joins, subqueries, aggregates, CTEs, window functions, `ORDER BY`, `LIMIT`
- read access across IDA-backed virtual tables
- limited writes where explicitly supported

Result format:
- `{"columns": [...], "rows": [...]}` and nothing else -- no warnings field, no side channel
- A single SQL execution returns one result set. Multi-statement SQL may contain only one row-producing statement; the rest must be non-result statements.
- Row-producing statements include `SELECT`, row-returning `PRAGMA`, `RETURNING`, `EXPLAIN`, and `VALUES`.

Transport rule:
- results over the transport row cap raise an error
- use `LIMIT` in SQL; no silent truncation

## Discovery

The surface should be discoverable with normal SQLite tools:
- `SELECT name FROM sqlite_master WHERE type IN ('table', 'view')`
- `PRAGMA table_info(<table>)`
- `SELECT name, signature, description FROM sql_functions` for scalar functions

Do not require custom registries or side channels to discover the schema.

## Address and u64 boundary

SQLite `INTEGER` is signed 64-bit, while IDA addresses are unsigned 64-bit.

Current policy:
- `u64` values cross the SQLite boundary using signed `INTEGER` reinterpretation
- columns and scalar results marked `u64` decode back to normal unsigned Python ints after query execution
- inputs for `u64` columns and functions must be SQLite `INTEGER` values, typically unquoted `0x...` literals

What works well:
- direct table/view address columns
- known scalar outputs
- common read queries over schema-provided address columns

Known limit:
- computed expressions can lose address provenance inside SQLite
- once that happens, SQLite has already used signed semantics for ordering, comparison, arithmetic, and aggregates

See `docs/sql-u64-address-boundary-exploration.md` for the research note behind this policy.

## Hex presentation

Columns marked `hex` render as `0x...` strings in JSON transport. This is a presentation rule only: it does not change SQL comparison, ordering, arithmetic, or filtering semantics.

## Row identity (rowid)

Every SQLite row has a signed 64-bit `rowid`. `UPDATE` and `DELETE` locate a row by it; `SELECT` does not depend on it.

### SQLite

A normal table stores rows in a B-tree keyed by rowid -- either an auto-assigned hidden value or an `INTEGER PRIMARY KEY` column aliased to it.

A virtual table has no B-tree; the module is the storage and supplies the rowid itself. Declared columns and the rowid are independent: SQLite has no automatic column-to-rowid alias for virtual tables.

### APSW

APSW maps the SQLite virtual-table hooks to Python methods:

- `Cursor.Rowid()` returns the rowid of the row the cursor is on.
- `UpdateChangeRow(old_rowid, new_rowid, fields)`, `UpdateDeleteRow(rowid)`, and `UpdateInsertRow(new_rowid, fields)` receive writes.

For an `UPDATE`, SQLite first finds matching rows (`Filter`/`Column`/`Rowid`), then calls `UpdateChangeRow` with the old rowid and one entry per declared column. The handler uses the rowid to know which row to change.

### Our tables

A table supplies its rowid one of three ways:

- Designate a column with `ColumnSpec(rowid=True)`; `BaseCursor.Rowid()` then returns that column's value (`names.address`, for example).
- Override `Rowid()` to pack a composite identity into one integer through `sql/rowid.py`, decoded back in the write handler (`comments` packs the repeatable flag alongside the address).
- Provide nothing. `BaseCursor` hands out a sequential counter (`0, 1, 2, ...`) as rows stream.

Invariant: a writable table uses the first or second form, because its write handler must map the rowid back to a real target. The sequential-counter form carries no usable identity, so tables that rely on it are read-only.

u64 note: the rowid is signed, but addresses are unsigned 64-bit. Column-rowid tables boundary-encode the value through `encode_sql_u64` so high addresses survive.

### Packing a composite rowid

A composite rowid carries a base value (usually an address) plus a small payload in the base value's high bits. That works only because a real address has uniform high bits -- zeros for userspace, ones for kernel -- so the borrowed bits are redundant and the decoder regenerates them by sign extension.

Pack through `sql/rowid.py`, never a hand-written shift: it raises on a value whose high bits are not uniform and on a payload too wide for its field, both of which would otherwise corrupt silently. Size a payload to its domain -- a flag gets one bit -- and give an unbounded counter a generous budget. Each table documents its width beside the constant.

## Write support

A column is writable only where `COLUMN_SPECS` marks it `writable=True`; grep for `writable=True` to see the current surface rather than maintaining a list here.

### The rule

For an existing row, identity comes from the rowid, never from `fields`. Decode it from the rowid argument, or derive it from what the rowid pins (for example, a decompiler comment's containing function from its `ea`). `fields` carries only new column data.

### Why

A declared column is not a rowid alias, so assigning an identity column does not move the row -- the assigned value rides through in `fields`. A handler that reads identity from `fields` applies the write to that value instead of the row SQLite matched, silently retargeting it.

### Adding write support to a table

Precondition: the table's rowid carries full identity (rowid section, mechanism 1 or 2), packed through `sql/rowid.py` when composite. Without that there is nothing for a write to address.

1. Mark each mutated column `writable=True` in `COLUMN_SPECS`. Leave every other column unmarked.
2. In `UpdateChangeRow` and `UpdateDeleteRow`, derive identity from the rowid argument -- `decode_sql_u64` for a u64 rowid, `unpack_rowid` for a composite one, or derive a pinned value (for example, `func_ea` from `ea` via the containing function). Do not read identity from `fields`.
3. Call `reject_readonly_update(self, fields)` first.
4. Read new values for writable columns from `fields` and apply them.
5. In `UpdateInsertRow`, read identity from `fields`: there is no prior row.

### What the machinery enforces

Declaring writable columns is the whole contract. During an update, every unmarked column -- data or identity -- reports as `apsw.no_change` unless the user assigned it, and `reject_readonly_update` raises on any assignment. Identity and read-only columns therefore reject writes with no per-table guard.

### Tests

Every writable table needs two kinds of coverage: that assigning any non-writable column raises, identity included, and that each writable column's write actually lands. The first generalizes across tables (`TestNonWritableColumnsReject`); the second does not.

## Pushdown policy

A table that cannot afford a full scan declares a required constraint and raises a SQL error when it is missing, rather than silently scanning the world. The error names the constraint to add, so the fix travels with the failure.

Every other table expresses relative cost through `estimatedCost` in `BestIndex`, pricing unconstrained plans high enough that the planner prefers a constrained path.

## Schema design

Design tables, columns, and scalar functions so common RE tasks are obvious: find callers, resolve containing functions, trace data flow, identify string usage, map addresses to names.

Assume an agent sees only `sqlite_master` and `PRAGMA table_info`, so obvious queries must work without repo-specific docs.

If a common task requires creative SQL (range joins, correlated subqueries, multi-step workarounds), add the missing column, function, or table instead.

Add new SQL surfaces from observed agent needs, not speculative coverage. Get the read schema right before adding write support to the same tables.

## Bitmask columns and flag scalars

When a table exposes a native IDA bitmask, prefer:
- one raw `INTEGER` bitmask column
- one scalar per domain, such as `func_flag(name)`

Query pattern:
- `WHERE flags & func_flag('thunk') != 0`

Why this pattern:
- avoids a boolean column for every flag
- avoids magic-number masks in queries
- keeps the schema stable as new flags appear
- lets invalid names fail loudly instead of silently misquerying

## Scalar naming

- Lookup at an address: suffix `_at` (e.g., `name_at`, `disasm_at`).
- Memory read at an address: prefix `read_` (e.g., `read_u32`, `read_cstr`).
- Flag/constant to string: suffix `_flag` (e.g., `func_flag`, `udm_flag`).
- Requires IDA GUI: prefix `ui_` (e.g., `ui_open_disasm`).
- Mutation: prefix with verb (e.g., `set_type`, `mark_cfunc_dirty`).
- Pure transforms (no address, deterministic): bare name (e.g., `hex`, `demangle`).

## Design rules

- Match SQLite semantics; prefer APSW behavior over custom bridge behavior.
- Before adding custom SQL behavior, ask whether standard SQLite already expresses it. Question anything not discoverable from the schema or normal SQLite conventions.
- Optional data returns `NULL` when unavailable: enrichment columns and lookup scalars.
- Required data raises rather than returning `NULL`: required columns, table contracts, query preconditions, invalid typed inputs, and vocabulary scalars given an unknown name.
- Expose atomic columns, not JSON blobs in cells.
- Put ownership and routing policy in the bridge, not in the SQL layer.
