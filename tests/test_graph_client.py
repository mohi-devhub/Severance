from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from redis.exceptions import ResponseError

from bragent.graph import client


def test_copy_waits_for_background_save(monkeypatch):
    execute = Mock(side_effect=[ResponseError("GRAPH.COPY failed, could not fork"), None])
    pause = Mock()
    monkeypatch.setattr(
        client, "db", lambda: SimpleNamespace(connection=SimpleNamespace(execute_command=execute))
    )
    monkeypatch.setattr(client.time, "sleep", pause)
    client.copy_graph("source", "copy")
    assert execute.call_count == 2
    execute.assert_called_with("GRAPH.COPY", "source", "copy")
    pause.assert_called_once_with(0.1)


@pytest.mark.parametrize(
    "detail,calls", [("GRAPH.COPY failed, could not fork", 10), ("unknown command", 1)]
)
def test_copy_retries_are_bounded_and_specific(monkeypatch, detail, calls):
    execute = Mock(side_effect=ResponseError(detail))
    monkeypatch.setattr(
        client, "db", lambda: SimpleNamespace(connection=SimpleNamespace(execute_command=execute))
    )
    monkeypatch.setattr(client.time, "sleep", lambda _: None)
    with pytest.raises(ResponseError, match=detail):
        client.copy_graph("source", "copy")
    assert execute.call_count == calls
