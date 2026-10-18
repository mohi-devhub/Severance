"""Benchmark suite (docs/05, docs/10) → results/.

A. correctness of the deterministic engine on every scenario
B. engine vs a tool-less LLM given the same graph as raw text
C. query latency vs graph size
"""

import asyncio
import csv
import hashlib
import json
import re
import statistics
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from bragent.config import settings
from bragent.graph import queries
from bragent.graph.client import run_ro, use_graph
from bragent.graph.seeder import SCENARIOS, ScenarioTruth, seed
from bragent.remediation import dryrun, planner

RESULTS = Path("results")
BENCH_GRAPH = "iam_bench"


def _ok(b: bool) -> str:
    return "✓" if b else "✗"


# ── A. correctness ─────────────────────────────────────────────────────────────


def engine_answer(t: ScenarioTruth) -> dict[str, Any]:
    path = queries.shortest_external_path(t.target_resource_id)
    plan = planner.choose(t.target_resource_id)
    return {
        "path": path.ids if path else [],
        "fix": plan.edge.model_dump() if plan else None,
        "plan": plan,
    }


def correctness() -> list[dict[str, Any]]:
    rows = []
    for name in SCENARIOS:
        t = seed(name)
        a = engine_answer(t)
        dr = dryrun.simulate(a["plan"])
        rows.append(
            {
                "scenario": name,
                "found_external_path": a["path"] == t.expected_external_path_ids,
                "chose_root_cause_fix": a["fix"] == t.expected_fix_edge.model_dump(),
                "external_reachers_after": dr.after.external_reacher_count,
                "collateral": len(dr.collateral),
            }
        )
    return rows


def correctness_md(rows: list[dict]) -> str:
    out = [
        "| scenario | found external path | chose root-cause fix | external reachers after "
        "| collateral |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        out.append(
            f"| {r['scenario']} | {_ok(r['found_external_path'])} | "
            f"{_ok(r['chose_root_cause_fix'])} | {r['external_reachers_after']} "
            f"| {r['collateral']} |"
        )
    return "\n".join(out)


# ── B. engine vs tool-less LLM ─────────────────────────────────────────────────

_BASELINE_PROMPT = """\
You are given a cloud IAM graph as raw text. Answer from the text alone.

Reach semantics: a principal reaches a resource via a directed path
Principal (-MEMBER_OF-> group)* (-HAS_ROLE-> or -CAN_ASSUME-> Role)(-CAN_ASSUME-> Role)*
-GRANTS-> Policy -PERMITS-> Action -TARGETS-> Resource.
Principals of kind "external" are untrusted.

Finding: {finding}
Target resource id: {target}

Nodes (id | label | kind/type/trust | sensitivity):
{nodes}

Edges (from -[TYPE]-> to):
{edges}

Tasks:
1. The shortest directed path (fewest edges) from any external principal to the target,
   as the ordered list of node ids.
2. The single edge to delete that removes all external access to the target while keeping
   every internal principal's access. If several do, prefer the edge touching the most
   load-bearing role/policy (highest betweenness centrality), then the one closest to the
   misconfiguration (CAN_ASSUME into a broad-trust role > GRANTS > MEMBER_OF > HAS_ROLE >
   CAN_ASSUME > PERMITS > TARGETS).

Reply with only a JSON object:
{{"path": ["id", ...], "fix_edge": {{"from_id": "...", "type": "...", "to_id": "..."}}}}
"""


def _graph_text() -> tuple[str, str, set[tuple[str, str, str]]]:
    nodes = run_ro(
        "MATCH (n) RETURN n.id AS id, labels(n)[0] AS label, "
        "coalesce(n.kind, n.type, n.trust, '') AS kind, coalesce(n.sensitivity, '') AS sens "
        "ORDER BY id"
    )
    edges = run_ro(
        "MATCH (a)-[e]->(b) RETURN a.id AS f, type(e) AS t, b.id AS to ORDER BY f, t, to"
    )
    node_txt = "\n".join(f"{n['id']} | {n['label']} | {n['kind']} | {n['sens']}" for n in nodes)
    edge_txt = "\n".join(f"{e['f']} -[{e['t']}]-> {e['to']}" for e in edges)
    return node_txt, edge_txt, {(e["f"], e["t"], e["to"]) for e in edges}


async def _ask(prompt: str) -> str:
    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

    opts = ClaudeAgentOptions(
        tools=[],
        setting_sources=[],
        model=settings.model,
        max_turns=1,
        env={"ANTHROPIC_API_KEY": settings.anthropic_api_key} if settings.anthropic_api_key else {},
    )
    text = ""
    error = None
    async for msg in query(prompt=prompt, options=opts):
        if isinstance(msg, ResultMessage):
            if msg.is_error or msg.subtype != "success":
                detail = "; ".join(msg.errors or []) or msg.result or msg.subtype
                error = f"Claude call failed: {detail}"
            text = msg.result or ""
    if error:
        raise RuntimeError(error)
    if not text.strip():
        raise RuntimeError("Claude call returned no result")
    return text


def _parse(text: str) -> dict[str, Any] | None:
    m = re.search(r"\{.*\}", text, re.S)
    try:
        ans = json.loads(m.group(0)) if m else None
    except json.JSONDecodeError:
        return None
    if not isinstance(ans, dict):
        return None
    path, fix = ans.get("path"), ans.get("fix_edge")
    if not isinstance(path, list) or not path or not all(isinstance(n, str) for n in path):
        return None
    if not isinstance(fix, dict) or not all(
        isinstance(fix.get(k), str) and fix[k] for k in ("from_id", "type", "to_id")
    ):
        return None
    return ans


def _score(ans: dict | None, t: ScenarioTruth, edges: set[tuple]) -> dict[str, Any]:
    if not ans:
        return {"path_ok": False, "fix_ok": False, "hallucinated": False, "key": None}
    path = ans.get("path") or []
    fix = ans.get("fix_edge") or {}
    fix_t = (fix.get("from_id"), fix.get("type"), fix.get("to_id"))
    path_edges_known = all(
        any(
            (a, ty, b) in edges
            for ty in ("MEMBER_OF", "HAS_ROLE", "CAN_ASSUME", "GRANTS", "PERMITS", "TARGETS")
        )
        for a, b in zip(path, path[1:], strict=False)
    )
    return {
        "path_ok": path == t.expected_external_path_ids,
        "fix_ok": fix == t.expected_fix_edge.model_dump(),
        "hallucinated": not path_edges_known or fix_t not in edges,
        "key": json.dumps([path, fix], sort_keys=True),
    }


async def _baseline_runs(
    prompt: str,
    runs: int,
    completed: dict[int, dict] | None = None,
    on_result: Callable[[int, dict], None] | None = None,
) -> list[dict]:
    """Isolate call failures and checkpoint each completion before waiting for peers."""
    limit = asyncio.Semaphore(4)
    results = dict(completed or {})

    async def one(index: int) -> None:
        async with limit:
            try:
                text = await _ask(prompt)
                result = {"text": text, "error": None if _parse(text) else "Invalid answer JSON"}
            except Exception as exc:
                result = {"text": "", "error": f"{type(exc).__name__}: {exc}"}
            results[index] = result
            if on_result:
                on_result(index, result)

    await asyncio.gather(*(one(i) for i in range(runs) if i not in results))
    return [results[i] for i in range(runs)]


def _write_json(path: Path, data: Any) -> None:
    """Replace atomically so an interrupted write leaves the last checkpoint readable."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(path)


def _baseline_summary(name: str, cond: str, scores: list[dict], **metadata) -> dict:
    runs = len(scores)
    valid = [s for s in scores if s["key"] is not None]
    modal = Counter(s["key"] for s in valid).most_common(1)
    return {
        "scenario": name,
        "condition": cond,
        **metadata,
        "runs": runs,
        "failed_runs": runs - len(valid),
        "path_acc": sum(s["path_ok"] for s in scores) / runs,
        "fix_acc": sum(s["fix_ok"] for s in scores) / runs,
        "stability": modal[0][1] / runs if modal else 0.0,
        "hallucination_rate": sum(s["hallucinated"] for s in valid) / len(valid) if valid else None,
        "modal_answer": json.loads(modal[0][0]) if modal else None,
    }


def baseline(
    runs: int,
    graph_scale: int = 1,
    *,
    checkpoint: Path | None = None,
    resume: bool = False,
    log=print,
) -> list[dict[str, Any]]:
    if runs < 1 or graph_scale < 1:
        raise ValueError("runs and graph_scale must be positive")
    metadata = {"version": 1, "model": settings.model, "graph_scale": graph_scale, "runs": runs}
    state = {"metadata": metadata, "scenarios": {}}
    if resume:
        if checkpoint is None or not checkpoint.exists():
            raise ValueError("No baseline checkpoint exists to resume")
        state = json.loads(checkpoint.read_text())
        if state["metadata"] != metadata:
            raise ValueError(
                "Checkpoint model, scale or run count differs; use the original options"
            )
    elif checkpoint:
        _write_json(checkpoint, state)
    rows = []
    for name in SCENARIOS:
        t = seed(name, scale=graph_scale)
        node_txt, edge_txt, edges = _graph_text()
        engine = [
            _score({"path": a["path"], "fix_edge": a["fix"]}, t, edges)
            for a in (engine_answer(t) for _ in range(runs))
        ]
        prompt = _BASELINE_PROMPT.format(
            finding=t.finding.description,
            target=t.target_resource_id,
            nodes=node_txt,
            edges=edge_txt,
        )
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        scenario = state["scenarios"].setdefault(name, {"prompt_sha256": digest, "runs": {}})
        if scenario["prompt_sha256"] != digest:
            raise ValueError(f"{name}: graph or prompt changed since the checkpoint")
        completed = {int(i): result for i, result in scenario["runs"].items()}
        log(f"  {name}: {t.node_count} nodes, {t.edge_count} edges; {len(completed)}/{runs} saved")

        def save(index: int, result: dict, *, scenario=scenario, name=name) -> None:
            scenario["runs"][str(index)] = result
            if checkpoint:
                _write_json(checkpoint, state)
            status = f"FAILED: {result['error']}" if result["error"] else "ok"
            log(f"    {name} run {index + 1}/{runs}: {status}")

        answers = asyncio.run(_baseline_runs(prompt, runs, completed, save))
        llm = [_score(None if a["error"] else _parse(a["text"]), t, edges) for a in answers]
        for cond, scores in (("engine", engine), ("llm_no_tools", llm)):
            rows.append(
                _baseline_summary(
                    name,
                    cond,
                    scores,
                    model=settings.model,
                    graph_scale=graph_scale,
                    nodes=t.node_count,
                    edges=t.edge_count,
                )
            )
        if checkpoint:
            summary = checkpoint.with_name(checkpoint.name.removesuffix(".runs.json") + ".json")
            _write_json(summary, rows)
            summary.with_suffix(".md").write_text(baseline_md(rows) + "\n")
    return rows


def baseline_md(rows: list[dict]) -> str:
    out = [
        "| scenario | condition | exact path | fix edge | same answer across runs "
        "| hallucinated edges | failed runs |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        hallucinations = r["hallucination_rate"]
        hall = f"{hallucinations:.0%}" if hallucinations is not None else "—"
        out.append(
            f"| {r['scenario']} | {r['condition']} | {r['path_acc']:.0%} | {r['fix_acc']:.0%} "
            f"| {r['stability']:.0%} | {hall} | {r.get('failed_runs', 0)}/{r['runs']} |"
        )
    return "\n".join(out) + (
        "\n\nAccuracy and stability use all attempted runs; failures count as misses. "
        "Hallucinated-edge rate uses valid answers only (— if none)."
    )


# ── C. scale ───────────────────────────────────────────────────────────────────


def _timed(fn, *args, reps: int = 5) -> float:
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn(*args)
        samples.append((time.perf_counter() - t0) * 1000)
    return statistics.median(samples)


def scale(scales: tuple[int, ...] = (2, 20, 200)) -> list[dict[str, Any]]:
    rows = []
    for s in scales:
        t = seed("escalation_chain", scale=s)
        assert queries.shortest_external_path(t.target_resource_id).ids == (
            t.expected_external_path_ids
        )
        rows.append(
            {
                "nodes": t.node_count,
                "edges": t.edge_count,
                "find_reachers_ms": _timed(queries.find_reachers, t.target_resource_id),
                "shortest_external_path_ms": _timed(
                    queries.shortest_external_path, t.target_resource_id
                ),
            }
        )
    return rows


def _plot(rows: list[dict], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(6, 3.5))
    n = [r["nodes"] for r in rows]
    ax.plot(n, [r["find_reachers_ms"] for r in rows], "o-", label="find_reachers")
    ax.plot(n, [r["shortest_external_path_ms"] for r in rows], "s-", label="shortest_external_path")
    ax.set_xscale("log")
    ax.set_xlabel("graph nodes")
    ax.set_ylabel("median latency (ms)")
    ax.set_title("Query latency vs graph size (FalkorDB)")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=150)


# ── entry point ────────────────────────────────────────────────────────────────


def run_all(llm_runs: int, baseline_scale: int = 1, log=print, *, resume: bool = False) -> Path:
    RESULTS.mkdir(exist_ok=True)
    with use_graph(BENCH_GRAPH):
        try:
            log("A. correctness …")
            a = correctness()
            (RESULTS / "correctness.json").write_text(json.dumps(a, indent=2))
            (RESULTS / "correctness.md").write_text(correctness_md(a) + "\n")
            log(correctness_md(a))

            if llm_runs:
                log(
                    f"B. engine vs tool-less LLM ({llm_runs} runs/scenario, "
                    f"scale {baseline_scale}) …"
                )
                stem = "baseline" if baseline_scale == 1 else f"baseline_scale{baseline_scale}"
                b = baseline(
                    llm_runs,
                    baseline_scale,
                    checkpoint=RESULTS / f"{stem}.runs.json",
                    resume=resume,
                    log=log,
                )
                _write_json(RESULTS / f"{stem}.json", b)
                (RESULTS / f"{stem}.md").write_text(baseline_md(b) + "\n")
                log(baseline_md(b))

            log("C. scale …")
            c = scale()
            with (RESULTS / "scale.csv").open("w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(c[0]), lineterminator="\n")
                w.writeheader()
                w.writerows(c)
            _plot(c, RESULTS / "scale.png")
            for r in c:
                log(
                    f"  {r['nodes']:>6} nodes: find_reachers {r['find_reachers_ms']:.1f} ms, "
                    f"shortest_external_path {r['shortest_external_path_ms']:.1f} ms"
                )
        finally:
            queries.drop_graph(BENCH_GRAPH)
    return RESULTS
