import pytest
from typer.testing import CliRunner

from severance.cli.main import app

pytestmark = pytest.mark.graph
cli = CliRunner()


def test_seed_and_stats():
    out = cli.invoke(app, ["seed", "escalation_chain"])
    assert out.exit_code == 0 and "nodes" in out.output
    out = cli.invoke(app, ["graph-stats"])
    assert out.exit_code == 0 and "top brokers" in out.output


def test_investigate_needs_one_source():
    assert cli.invoke(app, ["investigate"]).exit_code != 0


def test_noninteractive_investigation_rejects_by_default(monkeypatch):
    from severance.agent import runner, tools

    async def fake_run(finding, *, approver, **kwargs):
        assert approver is tools.reject_all
        return runner.RunResult(
            run_id="test",
            audit_path="audit/test.jsonl",
            final_text="rejected",
            success=True,
            applied=False,
            records=[],
        )

    monkeypatch.setattr(runner, "run", fake_run)
    result = cli.invoke(app, ["investigate", "--scenario", "public_bucket"])
    assert result.exit_code == 0
    assert "approval defaults to rejection" in result.output
