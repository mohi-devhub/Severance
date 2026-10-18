import asyncio

import pytest
from claude_agent_sdk import ResultMessage

from severance.agent import runner, tools
from severance.models import Finding


@pytest.mark.parametrize("transport_error", [False, True])
def test_agent_failure_is_audited_and_session_is_reset(monkeypatch, tmp_path, transport_error):
    monkeypatch.setattr(runner.settings, "audit_dir", str(tmp_path))
    monkeypatch.setattr(runner, "options", lambda: None)

    class FailedClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def query(self, prompt):
            pass

        async def receive_response(self):
            if transport_error:
                raise RuntimeError("connection lost")
            yield ResultMessage(
                subtype="success",
                is_error=True,
                result="rate limited",
                duration_ms=0,
                duration_api_ms=0,
                num_turns=1,
                session_id="test",
            )

    monkeypatch.setattr(runner, "ClaudeSDKClient", FailedClient)
    result = asyncio.run(
        runner.run(
            Finding(
                id="test",
                kind="public_write",
                resource_name="bucket",
                description="test finding",
            )
        )
    )
    assert not result.success and not result.applied
    assert result.error == ("RuntimeError: connection lost" if transport_error else "rate limited")
    assert result.records[-1]["step"] == "run_end"
    assert result.records[-1]["error"] == result.error
    with pytest.raises(LookupError):
        tools._session.get()
