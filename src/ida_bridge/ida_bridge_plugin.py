"""IDA Bridge UI plugin.

This plugin runs inside UI IDA and connects to the local ida-bridge server.

Behavior:
- Zero-config: connect to the default bridge URL.
- Works for both supervisor-started and human-started IDA.
- Connect after the database is initialized (so metadata like idb_path is correct).
- Retry connecting in the background (handled by ida_bridge.ida_client).

Client identity:
- UI IDA instances use: idaui-<PID>

The websocket client, protocol handshake, request queue, and executor live in
`ida_bridge.ida_client`.
"""

import ida_kernwin
import idaapi
import idc


def _deps_ok() -> bool:
    try:
        import pydantic  # noqa: F401
        import websocket  # noqa: F401

        return True
    except Exception as exc:
        ida_kernwin.msg("[ida-bridge] missing python deps (pydantic, websocket-client)\n")
        ida_kernwin.msg(
            "[ida-bridge] fix: use the ida-setup skill and ask it to install pydantic + websocket-client into IDA's python.\n"
        )
        ida_kernwin.msg(
            "[ida-bridge] or if you have the ida-setup tool: ida-setup --python ida pip install --upgrade pydantic websocket-client\n"
        )
        ida_kernwin.msg(f"[ida-bridge] import error: {exc}\n")
        return False


class _UIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin: "IDABridgePlugin"):
        super().__init__()
        self._plugin = plugin

    def database_inited(self, is_new_database: int, idc_script: str) -> None:
        # DB is ready; it is now safe to collect idb_path/input_file metadata.
        self._plugin._on_database_ready()

    def database_closed(self) -> None:
        self._plugin._on_database_closed()

    def ready_to_run(self) -> None:
        # Covers cases where the plugin is loaded after the DB is already open.
        if idc.get_idb_path():
            self._plugin._on_database_ready()


class IDABridgePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX

    comment = "IDA Bridge plugin"
    help = "Connect UI IDA to ida-bridge"

    wanted_name = "IDA Bridge"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self._client = None
        self._hooks: _UIHooks | None = None

    def init(self):
        # idalib_runner manages its own connection; skip the UI plugin.
        if "idapro" in __import__("sys").modules:
            return idaapi.PLUGIN_SKIP

        if not _deps_ok():
            return idaapi.PLUGIN_SKIP

        # Import only after deps check (so missing deps doesn't crash plugin load).
        from ida_bridge.ida_client import IDAClient

        # Do not connect here; wait for database_inited().
        self._client = IDAClient()

        self._hooks = _UIHooks(self)
        self._hooks.hook()

        ida_kernwin.msg("[ida-bridge] plugin loaded\n")
        return idaapi.PLUGIN_KEEP

    def term(self):
        try:
            if self._hooks:
                self._hooks.unhook()
        finally:
            self._hooks = None

        try:
            if self._client:
                self._client.disconnect()
        finally:
            self._client = None

    def run(self, arg):
        # Manual entrypoint (Plugin menu): attempt connection if DB is ready.
        self._on_database_ready()

    def _on_database_ready(self) -> None:
        if not self._client:
            return

        # Avoid connecting in "no database" state.
        if not idc.get_idb_path():
            return

        self._client.connect()

    def _on_database_closed(self) -> None:
        if not self._client:
            return

        # Symmetry with database_inited(): disconnect when the DB goes away.
        self._client.disconnect()
        ida_kernwin.msg("[ida-bridge] database closed; disconnected\n")


def PLUGIN_ENTRY():
    return IDABridgePlugin()
