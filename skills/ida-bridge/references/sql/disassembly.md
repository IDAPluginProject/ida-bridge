# SQL disassembly reference

Instruction-level evidence, item maps, control flow, xrefs, and item comments.

### instructions

- Pushdown strongly recommended: `address` EQ, `func_ea` EQ, or `address` range. Full scan walks every head in every segment.

### heads

- Pushdown strongly recommended: `address` EQ, `func_ea` EQ, `segment` EQ, or `address` range. Full scan walks every head in every segment.
- `type`: item classification -- `code`, `data`, `string`, `struct`, `align`, `unknown`.
- Row fields are resolved on demand. `count(*)` and `SELECT address ...` avoid `size`, flags/type classification, segment-name lookup, and containing-function lookup.
- `segment`: pre-computed segment name when segment pushdown or full-segment iteration already knows it. Otherwise resolved lazily per row. Pushdown on segment EQ scopes the scan.
- `func_ea`: containing function start EA. NULL when not in any function -- the orphan code signal. Selecting it still triggers a containing-function lookup per row.
- Undefined bytes (not item starts) are not returned by heads. Gaps between consecutive heads indicate undefined regions.

### blocks

- Pushdown required: `func_ea` EQ (raises if unconstrained).
- Basic blocks per function. Columns: `func_ea`, `start_ea`, `end_ea`, `size`.
- Derived from IDA's FlowChart with FC_NOEXT (excludes synthetic external-call nodes, includes all function chunks including inlined tail chunks).
- Return blocks (no outgoing edges) are included. Empty result means the function doesn't exist.

### cfg_edges

- Pushdown required: `func_ea` EQ (raises if unconstrained).
- Control flow graph edges. Columns: `func_ea`, `src_block`, `dst_block`, `edge_type`.
- `src_block` / `dst_block` are block start_ea values (join with `blocks.start_ea`).
- `edge_type`:
  - `flow`: single successor (unconditional fall-through or branch).
  - `true`: first successor of a conditional branch (IDA convention: branch taken).
  - `false`: second successor of a conditional branch (fall-through).
  - `switch`: any successor of a 3+ way branch.
- Return blocks produce zero outgoing edges.
- Composable with `blocks` and `instructions` for per-block analysis:
  `SELECT i.* FROM blocks b JOIN instructions i ON i.func_ea = b.func_ea AND i.address >= b.start_ea AND i.address < b.end_ea WHERE b.func_ea = 0x...`

### xrefs

- Pushdown strongly recommended: `to_ea` EQ, `from_ea` EQ, or `from_func` EQ.
- `from_func`: start EA of the function containing `from_ea`. 0 when `from_ea` is outside any function.
- `is_code`: 1 for a code reference (cref), 0 for a data reference (dref).
- `type`: raw IDA xref type code.
  - code (`is_code = 1`): `16` call far, `17` call near, `18` jump far, `19` jump near, `21` ordinary flow.
  - data (`is_code = 0`): `1` offset, `2` write, `3` read, `4` text, `5` informational, `6` enum member.
  - Call edges are `16`/`17`; the `callers`/`callees` views pre-filter to them.
- `type_name`: readable form of `type` (`offset`, `write`, `read`, `text`, `info`, `enum`, `call`, `jump`, `flow`); `NULL` for unmapped codes. `call`/`jump` cover both far and near; raw `type` splits them (`16`/`18` far = intersegment, `17`/`19` near = intrasegment).
- `to_ea` (and `from_ea`, when the ref's source is a struct member) may be a type or member tid in the unmapped type-id space (`0xff...`) rather than an address; `name_at`/`segment_at` are NULL there. Resolve with `tid_name()` and see `sql/types.md` Member xrefs.

### comments

Item-level comments (disassembly comments). Function comments use `funcs.comment` / `funcs.rpt_comment`; decompiler comments use `pseudocode.comment`.

Columns: `address`, `text`, `repeatable`.

- `address`: EA of the commented item.
- `text`: comment text.
- `repeatable`: 0 for regular comment, 1 for repeatable comment.

Pushdown: `address` EQ. Full scan allowed but walks all heads.

Write support:
- INSERT: `INSERT INTO comments (address, text, repeatable) VALUES (0x..., 'text', 0)`.
- UPDATE: `UPDATE comments SET text = '...' WHERE address = 0x... AND repeatable = 0`.
- DELETE: `DELETE FROM comments WHERE address = 0x... AND repeatable = 0`.
- Setting text to empty string clears the comment.

### callers and callees

- `callers` / `callees`: filter to call xref types only (`fl_CF`, `fl_CN`), excluding flow and jump refs. Pushdown: `func_addr` maps to `xrefs.to_ea` (callers) or `xrefs.from_func` (callees).
