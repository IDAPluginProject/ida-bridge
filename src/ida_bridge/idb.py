"""IDB helper namespace injected into the exec environment as ``idb``."""

from . import sql as _sql
from .sql import QueryResult


class Idb:
    """Convenience helpers available to agent code as ``idb.*``.

    Lifecycle:
        idb.save()  -- persist the current IDB to disk.
        idb.quit()  -- request graceful shutdown (checked after exec completes).
    """

    def __init__(self) -> None:
        self._quit_requested = False

    @property
    def quit_requested(self) -> bool:
        return self._quit_requested

    def sql(self, query: str) -> QueryResult:
        """Run a SQL query against the IDB tables."""
        return _sql.sql(query)

    def save(self) -> bool:
        """Save the IDB. Returns True if the database was written."""
        import ida_loader
        import idc

        return bool(ida_loader.save_database(idc.get_idb_path(), 0))

    def quit(self) -> dict[str, bool]:
        """Request graceful shutdown.

        The runtime exits after the current exec completes.

        Returns a small dict so callers can safely assign to ``_result_``.
        """
        self._quit_requested = True
        return {"ok": True}
