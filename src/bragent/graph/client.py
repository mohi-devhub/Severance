"""FalkorDB connection and read/write helpers.

The active graph is held in a contextvar so a dry-run can redirect every query
to a throwaway copy without threading a graph handle through each call.
"""

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from falkordb import FalkorDB

from bragent.config import settings

_db: FalkorDB | None = None
_active: ContextVar[str | None] = ContextVar("active_graph", default=None)


def db() -> FalkorDB:
    global _db
    if _db is None:
        _db = FalkorDB(host=settings.falkor_host, port=settings.falkor_port)
    return _db


def graph_name() -> str:
    return _active.get() or settings.graph_name


def run_ro(cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Read-only query (GRAPH.RO_QUERY) on the active graph; rows as dicts."""
    res = db().select_graph(graph_name()).ro_query(cypher, params)
    cols = [h[1] for h in res.header]
    return [dict(zip(cols, row, strict=True)) for row in res.result_set]


def run_rw(cypher: str, params: dict[str, Any] | None = None):
    """Read-write query on the active graph. Seeder and edge deletion only."""
    return db().select_graph(graph_name()).query(cypher, params)


def copy_graph(src: str, dst: str) -> None:
    db().connection.execute_command("GRAPH.COPY", src, dst)


def drop_graph(name: str) -> None:
    if name in db().list_graphs():
        db().select_graph(name).delete()


@contextmanager
def graph_copy() -> Iterator[str]:
    """Server-side copy of the active graph; queries inside the block hit the copy."""
    src = graph_name()
    name = f"{src}_dryrun_{uuid.uuid4().hex[:8]}"
    copy_graph(src, name)
    token = _active.set(name)
    try:
        yield name
    finally:
        _active.reset(token)
        drop_graph(name)


@contextmanager
def use_graph(name: str) -> Iterator[None]:
    token = _active.set(name)
    try:
        yield
    finally:
        _active.reset(token)
