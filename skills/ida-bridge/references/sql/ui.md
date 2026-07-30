# SQL UI reference

GUI-only SQL functions for navigating IDA and reading the active UI selection.

### UI functions

`ui_open_disasm(ea)`: navigate disassembly to ea, bring IDA to front. Returns 1.

`ui_open_pseudocode(ea)`: open pseudocode for the containing function. If ea is a line-level address (from the pseudocode table's `ea` column), scrolls to that line. Returns 1. Composable: `SELECT ui_open_pseudocode(ea) FROM pseudocode WHERE line LIKE '%pattern%'`.

`ui_get_selection()`: read the active view's selection. Returns a JSON string:
- Pseudocode: `{"view":"pseudocode", "func_ea":"0x...", "from_line":N, "to_line":N, "lines":[...]}` (line numbers are 1-based, matching IDA UI and pseudocode table).
- Disassembly: `{"view":"disasm", "from_ea":"0x...", "to_ea":"0x...", "lines":["0xADDR: INSN", ...]}`.
- Returns NULL if nothing is selected; raises on an unsupported view type or no GUI.
