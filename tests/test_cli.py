import pytest
from typer.testing import CliRunner

from bragent.cli.main import app

pytestmark = pytest.mark.graph
cli = CliRunner()


def test_seed_and_stats():
    out = cli.invoke(app, ["seed", "escalation_chain"])
    assert out.exit_code == 0 and "nodes" in out.output
    out = cli.invoke(app, ["graph-stats"])
    assert out.exit_code == 0 and "top brokers" in out.output


def test_investigate_needs_one_source():
    assert cli.invoke(app, ["investigate"]).exit_code != 0
