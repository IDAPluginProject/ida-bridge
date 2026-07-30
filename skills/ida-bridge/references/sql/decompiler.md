# SQL decompiler reference

Decompiler output, decompiler comments, lvars, function signatures, and decompiler cache behavior.

### funcs

- Exact lookup pushdown: `start_ea = <ea>` and `name = '<exact name>'`.
- Broad scans materialize expensive columns lazily. `count(*)` and scans over `start_ea`, `name`, `size`, `end_ea`, `flags`, and `type_source` are much cheaper than scans selecting `prototype`, comments, `return_type`, `arg_count`, or `calling_conv` across the whole table.
- `name`, `prototype`, `comment`, `rpt_comment`, `flags` are writable via UPDATE. All other columns are read-only; assigning one in an UPDATE raises.
- Setting `prototype` to NULL clears the stored type. Setting to a C declaration applies it via `apply_cdecl`. Name and prototype changes invalidate the decompiler cache.
- `flags`: raw `func_t.flags` bitmask. Query with `func_flag()` scalar.
- `type_source`: who stored the prototype:
  - NULL -- no stored type. Transient: flips to `"hexrays"` on first decompilation.
  - `"ida"` -- auto-analysis guess.
  - `"hexrays"` -- decompiler inference (stored automatically on decompilation).
  - `"user/til"` -- user-applied or type library match.
- `prototype`, `return_type`, `arg_count`, `calling_conv`: all NULL when no type is stored (`type_source IS NULL`). Populated from `ida_nalt.get_tinfo` (stored types only, not guesses).

### pseudocode

Interleaved decompiler output: code lines and comment lines in rendering order.

Columns: `n` (sort key, 1-based sequential), `type` (`code` or `comment`), `func_ea`, `line` (code text or comment text), `ea` (ctree address, NULL for signature/blank lines), `placement` (NULL for code rows, placement name for comment rows), `valid_placements` (comma-separated valid placements for code rows, NULL for comment rows), `is_orphan` (NULL for code rows, 0/1 for comment rows).

Pushdown (required): `func_ea` EQ decompiles a function and returns all rows. `ea` EQ resolves the containing function, decompiles, and returns only rows matching that ea.

`valid_placements` on code rows lists placement names valid for commenting that line (e.g., `semi,block1`). Use these values as `placement` when inserting comments. Common values: `semi` (trailing comment after statement), `block1` (standalone line before the item), `block2` (standalone line after the item), `curly1`/`curly2` (opening/closing brace), `brace2` (closing paren of condition), `else`, `do`, `arg1`..`arg64` (between call arguments).

Write support (comment rows only; code rows are read-only):
- INSERT: `INSERT INTO pseudocode (func_ea, ea, placement, line) VALUES (...)`. All four required.
- UPDATE: change `line` (text), `ea`, or `placement`.
- DELETE: remove a comment.

Validation: INSERT/UPDATE validates that the comment renders (IDA `used` flag). On failure, the error reports which placements would work for that ea.

Examples:
```sql
-- Read pseudocode with interleaved comments
SELECT n, type, line, ea, placement, valid_placements FROM pseudocode WHERE func_ea = 0x100003F40

-- Add a trailing comment
INSERT INTO pseudocode (func_ea, ea, placement, line)
VALUES (0x100003F40, 0x100003F60, 'semi', 'buffer overflow check')

-- Add a block comment before a line
INSERT INTO pseudocode (func_ea, ea, placement, line)
VALUES (0x100003F40, 0x100003F60, 'block1', 'validation section')

-- Check for orphaned comments after retyping
SELECT ea, line FROM pseudocode
WHERE func_ea = 0x100003F40 AND type = 'comment' AND is_orphan = 1

-- Update comment text
UPDATE pseudocode SET line = 'new text'
WHERE func_ea = 0x100003F40 AND ea = 0x100003F60 AND placement = 'semi'

-- Delete a comment
DELETE FROM pseudocode
WHERE func_ea = 0x100003F40 AND ea = 0x100003F60 AND placement = 'semi'
```

### ctree_lvars

Decompiler local variables for a function. One row per lvar (arguments, locals, result vars).

- `func_ea`: function address (pushdown key).
- `idx`: lvar index within the function (0-based).
- `name`: variable name (may be auto-generated).
- `type`: C type string.
- `comment`: user lvar comment, or NULL. Hex-Rays may render generated storage annotations in pseudocode declarations, such as registers, stack offsets, `BYREF`, or `MAPDST`.
- `size`: variable size in bytes.
- `is_arg`: 1 if this is a function argument.
- `is_result`: 1 if this is the return value variable.
- `is_stk_var`: 1 if stack-allocated.
- `is_reg_var`: 1 if register-allocated.
- `stkoff`: stack offset (only for stack variables), or NULL.

Pushdown (required): `func_ea` EQ. Decompiles the function and returns all lvars.

Write support via UPDATE:
- For non-argument, non-result locals, `name`, `type`, and `comment` are writable.
- For argument and result rows, only `comment` is writable through `ctree_lvars`; name/type changes raise. Change argument names/types, return type, calling convention, or parameter lists through `funcs.prototype`.
- `type` accepts C type strings (e.g., `int`, `char *`, `struct foo *`) or named types.
- Name, type, and comment can be set together in a single UPDATE on non-argument, non-result locals (applied atomically).
- Changes use `modify_user_lvar_info` and persist across decompilations when IDA accepts the lvar edit.
- Name-only and comment-only UPDATEs are index-stable: sequential UPDATEs to different lvars in the same function are safe without re-querying.
- Caution: type changes trigger re-decompilation, which can reassign lvar indices. After updating a variable's type, re-query the table before modifying other variables in the same function.

Examples:
```sql
-- List all local variables of a function
SELECT name, type, is_arg FROM ctree_lvars WHERE func_ea = 0x100003F40

-- Rename a non-argument, non-result local variable
UPDATE ctree_lvars SET name = 'buffer' WHERE func_ea = 0x100003F40 AND idx = 3

-- Retype a non-argument, non-result local variable
UPDATE ctree_lvars SET type = 'struct ioctl_data *' WHERE func_ea = 0x100003F40 AND idx = 3
```

### decompile

`decompile(ea)`: decompile the function containing ea, return full pseudocode text as a single string. Returns NULL if ea is NULL, no function at ea, or decompilation fails. Raises if the Hex-Rays decompiler is not available.

Side effects: decompilation populates struct member xrefs (stroff), stores type info on the function, and propagates types. Use for mass-decompile to build up the type xref graph.

Examples:
```sql
-- Decompile a single function
SELECT decompile(0x100003F40)

-- Find functions whose pseudocode mentions a pattern
SELECT name, start_ea FROM funcs WHERE decompile(start_ea) LIKE '%decrypt%'

-- Mass decompile to populate type xrefs, discard text
SELECT COUNT(decompile(start_ea)) FROM funcs WHERE name LIKE '%handler%'

-- Decompile all callers of a function
SELECT caller_name, decompile(caller_func) FROM callers WHERE func_addr = 0x100001000
```

### Decompiler cache

`mark_cfunc_dirty(ea)`: invalidate the cached decompiler result for the function containing ea. Returns 1. Raises if ea is NULL or not within a function, so a bulk call fails on the first orphan ea. Use after modifying types, globals, or callee signatures that affect a function's pseudocode.

```sql
-- Flush one function's decompiler cache
SELECT mark_cfunc_dirty(0x100001000)

-- Flush all functions that reference a struct after editing it
SELECT mark_cfunc_dirty(from_ea) FROM xrefs WHERE to_ea = 0x100004000
```
