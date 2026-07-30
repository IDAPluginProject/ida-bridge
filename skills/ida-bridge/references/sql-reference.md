# SQL reference

The SQL reference is split by concept. For schema, use `PRAGMA table_info(<table>)` and `SELECT name, sql FROM sqlite_master`. For scalar functions, `SELECT name, signature, description FROM sql_functions`.

- `sql/decompiler.md`: `funcs`, `pseudocode`, `ctree_lvars`, `decompile`, and `mark_cfunc_dirty`.
- `sql/disassembly.md`: `instructions`, `heads`, `blocks`, `cfg_edges`, `xrefs`, item `comments`, `callers`, and `callees`.
- `sql/types.md`: local types, struct/union members, enums, function type args, `set_type`, `type_at`, `parse_type`, and `parse_types`.
- `sql/data.md`: `names`, `entries`, `strings`, `string_refs`, `bin_search`, and memory-read scalars.
- `sql/ui.md`: `ui_open_disasm`, `ui_open_pseudocode`, and `ui_get_selection`.
