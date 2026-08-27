# IDA Bridge

Bridge between agents and IDA Pro.
Execute IDAPython and SQL queries against live IDA databases.
Supports UI IDA (plugin) and headless idalib.
Designed to be driven by AI agents.

Agent skill and references: `skills/ida-bridge/`.

## Prerequisites

- IDA Pro >= 9.0
- macOS or Windows
- [ida-docs](https://github.com/cellebrite-labs/ida-docs) agent skill (for agent-authored IDAPython)
- [ida-setup](https://github.com/cellebrite-labs/ida-setup) (macOS only; automates the manual setup below)

## Installation

```bash
# clone repo
git clone https://github.com/cellebrite-labs/ida-bridge.git
cd ida-bridge

# install ida-bridge cli
uv tool install -e .

# install ida-bridge plugin into IDA Python venv (macOS)
ida-setup plugin install -e .

# install pi agent skills
pi install .
pi install https://github.com/cellebrite-labs/ida-docs
```

On Windows, skip `ida-setup` and follow [Windows setup](#windows-setup).

## Manual setup

On macOS, `ida-setup` is the easy mode: it sets up a venv in `~/.idapro/venv` and makes IDA use it.
The same venv is used for IDA UI and IDA headless and everything just works.
On Windows the same four pieces apply, but every step is manual.

1. host CLI, so the agent can run `ida-bridge` commands
2. agent skills, so the agent can operate ida-bridge and verify current IDA APIs
3. IDA UI plugin, so IDA UI is reachable
4. IDA headless, so the headless runner can import both `idapro` and `ida_bridge`

### Host CLI

This one is straightforward. Editable install: `uv tool install -e .` (or `pip install -e .`).

Validate by running `ida-bridge server status`, it's supposed to say server is not running.

### Agent skills

For manual skill installation, clone both repositories and symlink their skill directories:

```bash
# pi, codex
ln -s /path/to/ida-bridge/skills/ida-bridge ~/.agents/skills/
ln -s /path/to/ida-docs/skills/ida-docs ~/.agents/skills/

# claude code
ln -s /path/to/ida-bridge/skills/ida-bridge ~/.claude/skills/
ln -s /path/to/ida-docs/skills/ida-docs ~/.claude/skills/
```

Validate: run the agent and tell it to start ida-bridge server, it's supposed to run `ida-bridge server start`.

### IDA UI plugin

Symlink the plugin file into IDA: `ln -s repo/src/ida_bridge/ida_bridge_plugin.py ~/.idapro/plugins/`.
Install `ida_bridge` into the python environment IDA uses (`idapyswitch`, bundled with IDA, controls which one that is): `<IDA UI python> -m pip install -e .`.

Validate by running `import ida_bridge` in python console inside IDA.
Restart IDA and check that you see a log line with `[ida-bridge]` in the output window.

### IDA headless (idalib)

ida-bridge contains a runner that uses `idalib` to implement headless interaction with IDA.
The runner needs to import and use both `ida_bridge` and `idapro` (idalib package).
Hence when running headless runner, it has to know which python to use.

By default it uses `~/.idapro/venv/bin/python3` on macOS and `~/.idapro/venv/Scripts/python.exe` on Windows.
Having a single venv to be used by headless and IDA UI is convenient to reuse packages/plugins, etc.
You can point the runner to a different python with `--python` argument when running `exec-idb` or `start-idalib`.

IDA installation comes with a pre-bundled `idapro` package and `py-activate-idalib.py`.
- install `idapro` package in the python you are going to use with the runner
- run `py-activate-idalib.py`
Refer to IDA documentation for details.

This same python also needs `ida_bridge` itself: `<IDA headless python> -m pip install -e .`.

Validate by running: `ida-bridge supervisor start-idalib --idb path/to/idb`.
On success it prints client id, idb path, PID and log path.
On failure log path is printed, check it out for troubleshooting.

## Windows setup

`ida-setup` is macOS-only. On Windows, set up the four pieces by hand. PowerShell:

IDA's per-user directory is `%APPDATA%\Hex-Rays\IDA Pro\` (the Windows equivalent of `~/.idapro/` for plugins and `ida-config.json`). The headless venv still defaults to `~/.idapro/venv` so the same layout works on both platforms.

1. **Host CLI**

```powershell
uv tool install -e .
# or: py -m pip install -e .
```

Validate: `ida-bridge server status` says the server is not running.

2. **Headless venv** — one Python that can import both `idapro` and `ida_bridge`:

```powershell
python -m venv "$env:USERPROFILE\.idapro\venv"
& "$env:USERPROFILE\.idapro\venv\Scripts\python.exe" -m pip install pydantic websocket-client apsw
& "$env:USERPROFILE\.idapro\venv\Scripts\python.exe" -m pip install -e .
```

Install the `idapro` package that ships with IDA (see `idalib\python\` in the IDA install), then run `py-activate-idalib.py` once so that Python can find IDA. `IDADIR` can point at a non-default install directory.

Validate: with the bridge running (`ida-bridge server start`), `ida-bridge supervisor start-idalib --idb <path>.i64` prints a `client_id`.

3. **UI plugin**

- Install `pydantic`, `websocket-client`, and `ida_bridge` into the Python IDA uses (`idapyswitch` selects it).
- Copy `src\ida_bridge\ida_bridge_plugin.py` to `%APPDATA%\Hex-Rays\IDA Pro\plugins\`. Windows cannot symlink into that tree without Developer Mode; a copy is enough.

Validate: `import ida_bridge` in IDA's Python console, then restart IDA and look for `[ida-bridge]` in the Output window.

4. **start-ui** — `supervisor start-ui` auto-detects the newest `ida.exe` under Program Files (or `IDADIR`). Override with `--ida "C:\Program Files\IDA Professional 9.x\ida.exe"`.

Notes:

- Launching `~\.idapro\venv\Scripts\python.exe` shows two Python processes. That is CPython's venv redirector; the child is the real interpreter. `supervisor stop` kills the tree.
- Logs default to `%LOCALAPPDATA%\ida-bridge\logs`. `IDA_BRIDGE_LOG_DIR` overrides on every platform.
- `supervisor stop` still prefers the bridge `quit` RPC. The OS fallback is `TerminateProcess` (Windows has no SIGTERM).

## How it works

The bridge server must be running first: `ida-bridge server start`.
When IDA opens an IDB -- UI or headless -- it connects to the bridge server automatically.

The CLI gives agents control over connected instances:
- `ida-bridge list` -- see which IDAs are connected and which IDBs they have open
- `ida-bridge exec` -- execute IDAPython or SQL on a specific IDA instance
- `ida-bridge supervisor start-idalib` / `start-ui` -- launch new IDA instances
- `ida-bridge supervisor stop` / `save` -- stop or save IDA instances

This lets an agent discover available targets, run queries or code against them, and manage their lifecycle -- all through CLI.

## Agent usage

The ida-bridge skill (`skills/ida-bridge/SKILL.md`) contains the operational knowledge: command patterns, SQL schema, session management, and pitfalls.

When SQL cannot express an operation, ida-bridge tells the agent to load `ida-docs` before writing IDAPython. ida-docs checks the current IDA 9.x API against the official SDK instead of relying on stale model knowledge.

You can ask the agent to:
- open an IDB or create one from a binary
- search strings, find callers, trace cross-references
- annotate functions, set types, rename variables
- decompile and analyze specific functions
- query anything in the IDB through SQL

The agent handles the CLI invocations, session lifecycle, and SQL/IDAPython choice on its own. You describe the RE task; it drives IDA.

## One-shot vs persistent

Most of the work happens iteratively via `exec` against running IDA instance -- exploring a binary, building annotations over time, etc.

`exec-idb` is available for one-off queries, quick probes, or create-and-save flows.
It is fire-and-forget: start IDA, run code or SQL, exit (`--save` if needed).

## Runtime and sessions

`exec` is stateless by default: each request gets a fresh Python environment. Use this for independent SQL and IDAPython probes.

Use `exec --stateful --session-id <sid>` only when later calls need variables, imports, or helpers from earlier calls. A stateful exec claims the target exec environment for that session. The same session reuses the environment; other sessions and stateless execs are rejected until ownership is released, taken over, expires, or the IDA instance reconnects.

Use `reset <target> --session-id <sid>` to clear a stateful environment while keeping ownership. Use `reset <target> --session-id <sid> --release` when finished. Use `reset <target> --session-id <new-sid> --takeover` to intentionally replace another owner.

## Why SQL

Agents have outdated knowledge of the IDAPython API. They write IDAPython for IDA 8.x.
This wastes time on repeated failures and risks corrupting the database.

The SQL interface sidesteps this: agents write standard SQL, which is converted to correct IDAPython calls internally.
Agents are already fluent with SQL -- no new skills to learn, no IDA API to get wrong.

Example: `SELECT name, start_ea FROM funcs WHERE name LIKE '%auth%' LIMIT 10`

ida-bridge's SQL interface follows the IDA-over-SQL approach created by Elias Bachaalany ([@allthingsida](https://github.com/allthingsida) / [@0xeb](https://github.com/0xeb)) in [idasql](https://github.com/allthingsida/idasql) and the [libxsql](https://github.com/0xeb/libxsql) family.
We studied his design while building ours.
Credit for establishing SQL as a reverse-engineering interface for IDA is his.

## Execution modes

A single `exec` call can combine multiple modes:
- `--sql` -- runs first, results available to subsequent code
- `-f` -- uploads and runs files in order; can specify multiple
- `-c` -- inline code, runs last

Execution order is `--sql` -> `-f` (in order) -> `-c`.
Results carry between parts, so you can query with SQL, process with a file, and finalize with inline code.

In stateless execs, files passed with `-f` are available only within that request. In stateful execs, functions and variables they define remain available to later calls in the same session.

## DYLD cache single-module IDBs

Apple's dyld shared cache bundles hundreds of system libraries together.
To analyze a single library, IDA needs to extract it during IDB creation.

Pass the cache as `--input`, the target image as `--dyld-module`, and an output path as `--out-idb`:

`ida-bridge supervisor start-idalib --input /path/to/dyld_shared_cache_arm64e --out-idb /tmp/Foundation.i64 --dyld-module /System/Library/Frameworks/Foundation.framework/Foundation`

One-shot create-and-save:

`ida-bridge exec-idb --input /path/to/dyld_shared_cache_arm64e --out-idb /tmp/Foundation.i64 --dyld-module /System/Library/Frameworks/Foundation.framework/Foundation --save`

Headless only (idalib). UI IDA handles dyld module selection through its own GUI.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IDA_BRIDGE_HOST` | `127.0.0.1` | bridge server bind host and client default host |
| `IDA_BRIDGE_PORT` | `8765` | bridge server bind port and client default port |
| `IDA_BRIDGE_WS_MAX_SIZE` | `67108864` | max incoming websocket message size in bytes |
| `IDA_BRIDGE_LOG_FILE` | `~/Library/Logs/ida-bridge/server.log` (macOS) / `%LOCALAPPDATA%\ida-bridge\logs\server.log` (Windows) | structured server log (rotated); raw stdout/stderr go to the sibling `server.out` |
| `IDA_BRIDGE_LOG_MAX_BYTES` | `10485760` | log rotation threshold in bytes |
| `IDA_BRIDGE_LOG_BACKUP_COUNT` | `3` | number of rotated log files to keep |
| `IDA_BRIDGE_LOG_DIR` | `~/Library/Logs/ida-bridge` (macOS) / `%LOCALAPPDATA%\ida-bridge\logs` (Windows) | base directory for all bridge logs (server log + per-instance launch logs `idaui-<pid>.log` / `idalib-<pid>.log`) |
| `IDA_BRIDGE_LOG_KEEP` | `30` | dead per-instance logs retained per kind (live instances always kept) |
| `IDA_BRIDGE_LOG_PRUNE_INTERVAL_S` | `3600` | how often the server sweeps dead per-instance logs |
| `IDA_BRIDGE_STATEFUL_TTL_S` | `3600` | seconds before idle stateful ownership expires |

## Docs

- `docs/protocol.md` -- wire contract
- `docs/arch.md` -- architecture and ownership of concerns
- `docs/testing.md` -- test layout and fixture model
- `docs/sql-interface-design.md` -- SQL contract and boundaries

## Testing

```bash
# All tests
uv run --group test pytest -q tests/

# Unit + integration only
uv run --group test pytest -q tests/unit tests/integration

# E2E only (default fixture set)
uv run --group test pytest -q tests/e2e

# E2E including heavy fixtures (idbs/heavy/)
uv run --group test pytest -q tests/e2e --e2e-heavy
```

## Development

When changing code:
- bridge/server changes: restart the bridge server
- UI/plugin-side changes: restart IDA
- idalib-side changes: restart the runner

Hot reload is not supported.
