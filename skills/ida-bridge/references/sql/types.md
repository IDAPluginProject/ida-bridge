# SQL types reference

Local types, struct/union members, enums, function type args, and type application/parsing scalars.

### types

All local types in the IDB's type library.

- `ordinal`: type ordinal in the local type library (1-based, stable within a session).
- `tid`: IDA type ID for the local type. Useful for type xrefs and IDA-native lookups.
- `name`: type name. Empty string for anonymous types.
- `kind`: type classification: `struct`, `union`, `enum`, `func`, `ptr`, `array`, `bitfield`, `typedef`, `other`. Resolved kinds win for common categories, so typedef aliases to struct/union/enum/func/ptr/array/bitfield keep that resolved kind.
- `size`: size in bytes. NULL for forward declarations or types with no meaningful size.
- `alignment`: effective struct/union alignment in bytes. NULL for non-UDT types. Fixed-layout structs (`is_fixed = 1`) report alignment 1 because IDA does not recalculate layout for them.
- `unpadded_size`: struct/union size before trailing padding. NULL for non-UDT types.
- `member_count`: number of members for structs/unions and enums. NULL for other types.
- `is_typedef`: 1 if the row is a typedef alias, 0 otherwise. Use with `kind` to distinguish `typedef struct foo bar_t` from a non-alias struct.
- `is_forward_decl`: 1 if forward declaration, 0 otherwise.
- `is_fixed`: 1 if the struct has fixed layout (IDA will not recalculate size or member positions on mutations), 0 otherwise. Only meaningful for structs (always 0 for unions, enums, etc.).
- `definition`: compact single-type declaration/definition from IDA's local-type printer. Forward declarations preserve the declared name (`struct foo;`), not IDA's lossy `struct;` fallback.
- `resolved_name`: final typedef target name for aliases when it differs from the row itself, else NULL.
- `resolved_ordinal`: final typedef target ordinal for aliases when it differs from the row itself, else NULL.
- `source`: type-library source marker. Currently always `local`.
- Full scan table, no pushdown needed.

UPDATE support:
- `name`: rename a type. Empty string is not supported. Typedef ordinals are resolved to the real type before writing.
- `size`: set explicit struct size in bytes. Only works on fixed structs (`is_fixed = 1`). New size must be >= unpadded content size (all members must fit). Use to grow or shrink a struct.
- `is_fixed`: set to 1 to mark a struct as fixed-layout (preserves size and offsets on member mutations). Set to 0 to unfix (IDA will immediately recalculate size and alignment). Only works on structs (not unions).

DELETE support: remove a type from the local library.
- Uses `del_numbered_type`. References to the deleted type from applied types or other type definitions are not automatically cleaned up.

INSERT support: create an empty struct, union, or enum.
- Required: `name`.
- Optional: `kind` (`'struct'`, `'union'`, `'enum'`; defaults to `'struct'`).
- Rejects if a type with the given name already exists.
- Returns the allocated ordinal. Populate members via INSERT into `types_struct_members` or `types_enum_values`.
- New structs are created with fixed layout (`is_fixed = 1`) so size is preserved on member mutations.

### types_struct_members

Struct/union field details. One row per `udm_t` member in each UDT.

- `type_ordinal`: parent type ordinal (FK to `types.ordinal`).
- `type_name`: parent type name (denormalized, avoids JOIN for common queries).
- `member_index`: 0-based position within the UDT.
- `member_name`: field name.
- `offset`: byte offset (`offset_bits // 8`).
- `offset_bits`: raw bit offset from `udm_t.offset`. Use for bitfield precision.
- `size`: byte size (`size_bits // 8`).
- `size_bits`: raw bit size from `udm_t.size`. Use for bitfield precision.
- `member_type`: rendered type string (e.g., `int`, `char *`, `my_struct *`).
- `is_bitfield`: 1 if the member is a bitfield, 0 otherwise.
- `tafld_bits`: raw `udm_t.tafld_bits` bitmask. Query with `udm_flag(name)` scalar.
- `comment`: member comment, or NULL.
- `tid`: member type ID. Usable as an xref target address -- join with `xrefs.to_ea` to find code that accesses this field (see Member xrefs below).

Pushdown (recommended): `type_ordinal` EQ or `type_name` EQ. Full scan allowed but walks all UDTs.

Write support via UPDATE:
- `member_name`: rename a field. Setting it to empty string is not supported.
- `member_type`: change the field type. Value is a C type string (e.g., `int`, `char *`, `struct foo *`). May change member size and struct layout.
- `comment`: set or clear the field comment. `NULL` and empty string clear it.
- Other columns are read-only for UPDATE; assigning one raises.

INSERT support: add a member to a struct/union.
- Required: (`type_ordinal` or `type_name`), `member_name`, `member_type`, `offset` (bytes).
- `member_type` is a C type string (e.g., `int`, `char *`, `uint32_t`).
- Typedef ordinals are resolved to the real type before writing.

DELETE support: remove a member.
- Typedef ordinals are resolved to the real type before writing.

Bitmask pattern for `tafld_bits`: `WHERE tafld_bits & udm_flag('baseclass') != 0` selects C++ base-class members. Valid flag names: `baseclass`, `bytil`, `gap`, `method`, `regcmt`, `retaddr`, `savregs`, `unaligned`, `vftable`, `virtbase`.

Enums, forward declarations, and non-UDT types return no rows.

Member xrefs: references from code addresses to member tids. They appear where IDA applies a struct offset to a disassembly operand, or where a decompiler plugin records member accesses from decompiled code. Resolve a tid back to its name with `tid_name(tid)`. Query pattern:
```sql
-- Which functions access field msgh_remote_port?
SELECT x.from_ea, x.from_func, name_at(x.from_func) as func_name
FROM types_struct_members m
JOIN xrefs x ON x.to_ea = m.tid
WHERE m.type_name = 'mach_msg_header_t' AND m.member_name = 'msgh_remote_port'

-- All member accesses across a struct, grouped by function
SELECT m.member_name, x.from_func, name_at(x.from_func) as func_name
FROM types_struct_members m
JOIN xrefs x ON x.to_ea = m.tid
WHERE m.type_name = 'mach_msg_header_t'
```
Note: member xrefs only exist where a struct offset was applied in disassembly or a decompiler plugin recorded accesses from decompiled code. A freshly analyzed binary without type work returns empty until types are propagated.

### types_enum_values

Enum constant details. One row per `edm_t` value in each enum type.

- `type_ordinal`: parent enum ordinal (FK to `types.ordinal`).
- `type_name`: parent enum name (denormalized).
- `value_index`: 0-based position within the enum.
- `value_name`: constant name.
- `value`: integer value (unsigned 64-bit via u64 boundary encoding, hex-formatted in transport).
- `comment`: constant comment, or NULL.
- `tid`: enum constant type ID. Usable as an xref target address -- join with `xrefs.to_ea` to find code that references this enum constant.

Pushdown (recommended): `type_ordinal` EQ or `type_name` EQ. Full scan allowed but walks all enums.

Write support via UPDATE:
- `value_name`: rename a constant. Setting it to empty string is not supported.
- `value`: change the integer value.
- `comment`: set or clear the constant comment. `NULL` and empty string clear it.
- Other columns are read-only for UPDATE; assigning one raises.

INSERT support: add a constant to an enum.
- Required: (`type_ordinal` or `type_name`), `value_name`, `value`.
- Typedef ordinals are resolved to the real type before writing.

DELETE support: remove a constant.
- Typedef ordinals are resolved to the real type before writing.

Structs, unions, forward declarations, and non-enum types return no rows.

### types_func_args

Function type parameter and return type details. One row per argument plus one row for the return type. Handles both function types and function pointer types (dereferences the pointer automatically).

- `type_ordinal`: parent function type ordinal (FK to `types.ordinal`).
- `type_name`: parent function type name (denormalized).
- `arg_index`: -1 for the return type, 0+ for parameters.
- `arg_name`: parameter name, or `(return)` for the return type row.
- `arg_type`: type as a C declaration string.
- `calling_conv`: calling convention name (e.g. `cdecl`, `fastcall`, `thiscall`). Only set on the return type row (`arg_index = -1`); NULL on parameter rows.

Pushdown (recommended): `type_ordinal` EQ or `type_name` EQ. Full scan allowed but walks all function types.

Read-only.

Non-function types return no rows.

Examples:
```sql
-- Get all parameters of a function type
SELECT arg_index, arg_name, arg_type FROM types_func_args
WHERE type_name = 'my_callback_t' AND arg_index >= 0

-- Get return type and calling convention
SELECT arg_type, calling_conv FROM types_func_args
WHERE type_name = 'my_callback_t' AND arg_index = -1
```

### Type application scalars

`set_type(ea, decl)`: apply a C type declaration at any address -- functions, globals, data. Returns 1 on success. `set_type(ea, NULL)` clears the type info at the address.

`type_at(ea)`: return the C type string applied at ea, or NULL if no type is set.

Examples:
```sql
-- Apply a struct type to a global
SELECT set_type(0x100004000, 'struct dispatch_table')

-- Set a function prototype
SELECT set_type(0x100001000, 'int init(int argc, char **argv)')

-- Read back the applied type
SELECT type_at(0x100004000)

-- Clear type info
SELECT set_type(0x100004000, NULL)
```

### Type parsing scalars

`parse_type(decl_text)`: parse a single C type declaration, save to local types. Returns the ordinal. If a type with the same name exists, it is replaced. Structs are marked fixed-layout automatically.

`parse_type(decl_text, parser_name)`: parse using a named parser (e.g., `'idaclang'`). Returns the ordinal.

`parse_types(decl_text)`: parse multiple C declarations (structs, enums, typedefs) into local types using IDA's built-in parser. Returns a JSON array of `[{"ordinal": N, "name": "..."}]` for each new or modified type. Structs are marked fixed-layout automatically.

`parse_types(decl_text, parser_name)`: same, but use a named parser (e.g., `'idaclang'` for C++/ObjC support).

Do not use anonymous typedef declarations like `typedef struct { ... } name;`; use named declarations like `struct name { ... };` instead. Anonymous typedefs make IDA create an anonymous struct plus a typedef.

Examples:
```sql
-- Create a struct from a C declaration
SELECT parse_type('struct ioctl_data { uint32_t cmd; uint64_t addr; size_t len; };')

-- Replace an existing type (same name)
SELECT parse_type('struct ioctl_data { uint32_t cmd; uint64_t addr; size_t len; void *buf; };')

-- Batch create multiple types
SELECT parse_types('struct point { int x; int y; }; enum color { RED, GREEN, BLUE };')
```
