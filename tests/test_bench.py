"""Benchmark failure isolation, durable progress and honest aggregation."""

import asyncio
import json
from types import SimpleNamespace

import pytest
from claude_agent_sdk import ResultMessage
from typer.testing import CliRunner

from severance import bench
from severance.cli.main import app
from severance.models import EdgeRef


@pytest.fixture
def baseline_graph(monkeypatch):
    truth = SimpleNamespace(
        expected_external_path_ids=["ext", "target"],
        expected_fix_edge=EdgeRef(from_id="ext", type="CAN_ASSUME", to_id="target"),
        finding=SimpleNamespace(description="Synthetic test finding"),
        target_resource_id="target",
        node_count=2,
        edge_count=1,
    )
    answer = {
        "path": truth.expected_external_path_ids,
        "fix_edge": truth.expected_fix_edge.model_dump(),
    }
    monkeypatch.setattr(bench, "SCENARIOS", {"first": None, "second": None})
    monkeypatch.setattr(bench, "seed", lambda *a, **kw: truth)
    monkeypatch.setattr(
        bench, "_graph_text", lambda: ("nodes", "edges", {("ext", "CAN_ASSUME", "target")})
    )
    monkeypatch.setattr(
        bench, "engine_answer", lambda t: {"path": answer["path"], "fix": answer["fix_edge"]}
    )
    return json.dumps(answer)


def test_failed_call_does_not_cancel_peers_or_later_scenarios(
    monkeypatch, tmp_path, baseline_graph
):
    calls = 0

    async def ask(prompt):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("session limit")
        await asyncio.sleep(0)
        return baseline_graph

    monkeypatch.setattr(bench, "_ask", ask)
    path = tmp_path / "baseline_scale10.runs.json"
    rows = bench.baseline(3, 10, checkpoint=path, log=lambda _: None)
    assert calls == 6
    assert rows[1]["failed_runs"] == 1
    assert rows[1]["path_acc"] == pytest.approx(2 / 3)
    assert rows[1]["stability"] == pytest.approx(2 / 3)
    assert rows[1]["hallucination_rate"] == 0
    assert rows[1]["modal_answer"] is not None
    assert rows[3]["failed_runs"] == 0
    saved = json.loads(path.read_text())
    assert "session limit" in saved["scenarios"]["first"]["runs"]["0"]["error"]
    assert json.loads((tmp_path / "baseline_scale10.json").read_text()) == rows
    assert "1/3" in (tmp_path / "baseline_scale10.md").read_text()


def test_interrupted_scenario_resumes_without_repeating_saved_calls(
    monkeypatch, tmp_path, baseline_graph
):
    calls = 0

    async def interrupted(prompt):
        nonlocal calls
        calls += 1
        if calls == 1:
            return baseline_graph
        await asyncio.sleep(0)
        raise asyncio.CancelledError

    path = tmp_path / "baseline_scale10.runs.json"
    monkeypatch.setattr(bench, "_ask", interrupted)
    with pytest.raises(asyncio.CancelledError):
        bench.baseline(3, 10, checkpoint=path, log=lambda _: None)
    saved = json.loads(path.read_text())
    assert len(saved["scenarios"]["first"]["runs"]) == 1
    calls = 0

    async def resumed(prompt):
        nonlocal calls
        calls += 1
        return baseline_graph

    monkeypatch.setattr(bench, "_ask", resumed)
    rows = bench.baseline(3, 10, checkpoint=path, resume=True, log=lambda _: None)
    assert calls == 5  # two missing calls, then three for the second scenario
    assert all(r["path_acc"] == 1 for r in rows)
    bench.baseline(3, 10, checkpoint=path, resume=True, log=lambda _: None)
    assert calls == 5  # a fully saved benchmark makes no more Claude calls


def test_resume_rejects_changed_options_or_prompt(monkeypatch, tmp_path, baseline_graph):
    async def ask(prompt):
        return baseline_graph

    monkeypatch.setattr(bench, "_ask", ask)
    path = tmp_path / "baseline_scale10.runs.json"
    bench.baseline(1, 10, checkpoint=path, log=lambda _: None)
    with pytest.raises(ValueError, match="run count differs"):
        bench.baseline(2, 10, checkpoint=path, resume=True)
    monkeypatch.setattr(bench, "_BASELINE_PROMPT", "changed prompt")
    with pytest.raises(ValueError, match="graph or prompt changed"):
        bench.baseline(1, 10, checkpoint=path, resume=True)
    with pytest.raises(ValueError, match="No baseline checkpoint"):
        bench.baseline(1, 10, checkpoint=tmp_path / "absent.json", resume=True)


def test_scale_specific_outputs_preserve_small_baseline(monkeypatch, tmp_path, baseline_graph):
    from contextlib import nullcontext

    async def ask(prompt):
        return baseline_graph

    old = {"baseline.json": "original JSON", "baseline.md": "original Markdown"}
    for name, text in old.items():
        (tmp_path / name).write_text(text)
    monkeypatch.setattr(bench, "RESULTS", tmp_path)
    monkeypatch.setattr(bench, "_ask", ask)
    monkeypatch.setattr(bench, "use_graph", lambda name: nullcontext())
    monkeypatch.setattr(bench, "correctness", lambda: [])
    monkeypatch.setattr(
        bench,
        "scale",
        lambda: [{"nodes": 2, "edges": 1, "find_reachers_ms": 1, "shortest_external_path_ms": 1}],
    )
    monkeypatch.setattr(bench, "_plot", lambda *args: None)
    monkeypatch.setattr(bench.queries, "drop_graph", lambda name: None)
    bench.run_all(1, 10, log=lambda _: None)
    assert all((tmp_path / name).read_text() == text for name, text in old.items())
    assert len(json.loads((tmp_path / "baseline_scale10.json").read_text())) == 4
    assert (tmp_path / "baseline_scale10.runs.json").exists()


@pytest.mark.parametrize(
    "text",
    [
        "limit reached",
        "{}",
        '{"path":42,"fix_edge":[]}',
        '{"path":[{}],"fix_edge":{}}',
        "{broken JSON}",
    ],
)
def test_invalid_answer_is_a_failure_not_a_hallucinated_edge(monkeypatch, baseline_graph, text):
    async def ask(prompt):
        return text

    monkeypatch.setattr(bench, "_ask", ask)
    rows = bench.baseline(2, log=lambda _: None)
    for row in rows[1::2]:
        assert row["failed_runs"] == 2
        assert row["path_acc"] == row["fix_acc"] == row["stability"] == 0
        assert row["hallucination_rate"] is None
        assert row["modal_answer"] is None
    assert "—" in bench.baseline_md(rows)


def test_unparseable_modal_answer_after_valid_first_run(monkeypatch, baseline_graph):
    calls = 0

    async def ask(prompt):
        nonlocal calls
        calls += 1
        return baseline_graph if calls % 3 == 1 else "unparseable"

    monkeypatch.setattr(bench, "_ask", ask)
    rows = bench.baseline(3, log=lambda _: None)
    assert rows[1]["modal_answer"] == [
        json.loads(baseline_graph)["path"],
        json.loads(baseline_graph)["fix_edge"],
    ]
    assert rows[1]["failed_runs"] == 2


@pytest.mark.parametrize("subtype,is_error", [("success", True), ("error_max_turns", False)])
def test_sdk_error_result_is_a_failed_call(monkeypatch, subtype, is_error):
    async def query(**kwargs):
        yield ResultMessage(
            subtype=subtype,
            is_error=is_error,
            result="session limit",
            duration_ms=0,
            duration_api_ms=0,
            num_turns=1,
            session_id="test",
        )

    monkeypatch.setattr("claude_agent_sdk.query", query)
    with pytest.raises(RuntimeError, match="session limit"):
        asyncio.run(bench._ask("prompt"))


def test_empty_sdk_response_is_a_failed_call(monkeypatch):
    async def query(**kwargs):
        if False:
            yield None

    monkeypatch.setattr("claude_agent_sdk.query", query)
    with pytest.raises(RuntimeError, match="no result"):
        asyncio.run(bench._ask("prompt"))


def test_sdk_receives_key_from_settings(monkeypatch, baseline_graph):
    monkeypatch.setattr(bench.settings, "anthropic_api_key", "test-key")

    async def query(*, prompt, options):
        assert options.env == {"ANTHROPIC_API_KEY": "test-key"}
        yield ResultMessage(
            subtype="success",
            is_error=False,
            result=baseline_graph,
            duration_ms=0,
            duration_api_ms=0,
            num_turns=1,
            session_id="test",
        )

    monkeypatch.setattr("claude_agent_sdk.query", query)
    assert asyncio.run(bench._ask("prompt")) == baseline_graph


@pytest.mark.parametrize(
    "args", [["--llm-runs", "-1"], ["--baseline-scale", "0"], ["--resume", "--llm-runs", "0"]]
)
def test_cli_rejects_invalid_benchmark_options(args):
    result = CliRunner().invoke(app, ["benchmark", *args])
    assert result.exit_code == 2


@pytest.mark.graph
@pytest.mark.parametrize("scenario", list(bench.SCENARIOS))
def test_scale10_engine_matches_planted_truth(scenario):
    from severance.graph.client import use_graph

    with use_graph("iam_test_bench_scale10"):
        try:
            truth = bench.seed(scenario, scale=10)
            answer = bench.engine_answer(truth)
            assert answer["path"] == truth.expected_external_path_ids
            assert answer["fix"] == truth.expected_fix_edge.model_dump()
        finally:
            bench.queries.drop_graph("iam_test_bench_scale10")
