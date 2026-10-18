"""`severance` CLI: operator interface and demo driver (docs/08)."""

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from severance.audit.log import summary
from severance.graph import queries
from severance.graph.seeder import SCENARIOS, seed
from severance.models import Approval, DryRunResult, Finding, RemediationPlan

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Severance: graph-backed cloud IAM investigation and remediation.",
)
console = Console()


# ── rendering ──────────────────────────────────────────────────────────────────


def chain(path: dict) -> str:
    nodes, edges = path["nodes"], path["edges"]
    first = nodes[0]
    out = f"[bold red]{first['name']}[/]({first['kind'] or first['label']})"
    for edge, n in zip(edges, nodes[1:], strict=True):
        out += f" [dim]─{edge}→[/] [bold]{n['name']}[/]"
    return out


def _hops(h: int | None) -> str:
    return "∞" if h is None else str(h)


def before_after(before: dict, after: dict, closed: int, collateral: list[str]) -> Table:
    t = Table(box=None, show_header=True, header_style="bold")
    t.add_column("")
    t.add_column("before", justify="right")
    t.add_column("", justify="center")
    t.add_column("after", justify="right")
    t.add_column("")
    ok = "[green]✓[/]"
    ext_ok = ok if after["external_reachers"] == 0 else "[red]✗[/]"
    hops_ok = ok if after["shortest_external_hops"] is None else "[red]✗[/]"
    t.add_row("reachers", str(before["reachers"]), "→", str(after["reachers"]), "")
    t.add_row(
        "external reachers",
        str(before["external_reachers"]),
        "→",
        str(after["external_reachers"]),
        ext_ok,
    )
    t.add_row(
        "shortest external hops",
        _hops(before["shortest_external_hops"]),
        "→",
        _hops(after["shortest_external_hops"]),
        hops_ok,
    )
    t.add_row("severity", f"{before['severity']:g}", "→", f"{after['severity']:g}", "")
    t.add_row("paths closed", str(closed), "", "", "")
    t.add_row(
        "collateral (legit lost)",
        str(len(collateral)),
        "",
        "",
        ok if not collateral else f"[red]✗ {', '.join(collateral)}[/]",
    )
    return t


def render_result(name: str, p: dict[str, Any]) -> None:
    """Render each tool's deterministic payload as it arrives."""
    if name == "get_finding_context":
        r, f = p["resource"], p["finding"]
        console.print(
            f"▶ Finding: [bold]{f['kind']}[/] on [bold]{r['name']}[/] "
            f"({r['type']}, sensitivity={r['sensitivity']})"
        )
    elif name == "find_reachers":
        t = Table(title=f"WHO CAN REACH ({p['reacher_count']} principals)", title_justify="left")
        for col in ("principal", "kind", "hops", "via"):
            t.add_column(col)
        for r in p["reachers"]:
            style = "bold red" if r["kind"] == "external" else ""
            t.add_row(
                r["principal"]["name"],
                r["kind"],
                str(r["hops"]),
                ", ".join(r["via_actions"]),
                style=style,
            )
        console.print(t)
    elif name == "shortest_escalation_path":
        if p["primary"] is None:
            console.print("[green]No external principal reaches this resource.[/]")
            return
        n_entry = len(p["entry_points"])
        console.print(
            f"\n[bold]SHORTEST EXTERNAL PATH[/] (blast radius = {p['hops']} hops, "
            f"{n_entry} external entry point{'s' if n_entry != 1 else ''})"
        )
        console.print("  " + chain(p["primary"]))
    elif name == "rank_brokers" and p["brokers"]:
        top = p["brokers"][0]["node"]
        console.print(
            f"\n[bold]LOAD-BEARING NODE[/] (betweenness): [bold yellow]{top['name']}[/] "
            f"({top['label'].lower()}, {p['brokers'][0]['score']:g})"
        )
        for b in p["brokers"][1:]:
            console.print(f"  [dim]{b['node']['name']} ({b['node']['label']}) {b['score']:g}[/]")
    elif name == "propose_remediation" and p.get("plan_id"):
        console.print(f"\n[bold]PROPOSED FIX:[/] [cyan]{p['action']}[/] — {p['rationale']}")
    elif name == "simulate_remediation":
        console.print("\n[bold]DRY-RUN[/] (on graph copy)")
        console.print(
            before_after(p["before"], p["after"], len(p["paths_closed"]), p["collateral"])
        )
    elif name == "apply_remediation":
        console.print("[bold green]✓ Applied to live graph.[/]")


def interactive_approver(plan: RemediationPlan, dr: DryRunResult) -> Approval:
    body = [f"[cyan]{plan.action}[/]: {plan.rationale}"]
    if plan.justifying_paths:
        body.append("justifying path: " + chain(plan.justifying_paths[0].model_dump()))
    if dr.collateral:
        body.append(
            f"[bold red]⚠ this also removes legit access for: {', '.join(dr.collateral)}[/]"
        )
    if plan.alternatives:
        alt = plan.alternatives[0]
        body.append(f"[dim]equally good alternative: {alt.from_id} -{alt.type}-> {alt.to_id}[/]")
    console.print(Panel("\n".join(body), title="APPROVAL REQUIRED", border_style="yellow"))
    console.print(
        before_after(summary(dr.before), summary(dr.after), len(dr.paths_closed), dr.collateral)
    )
    ok = Confirm.ask("Approve this remediation?", default=False)
    note = Prompt.ask("Note (optional)", default="")
    return Approval(approved=ok, approver="operator", note=note)


def auto_approver(plan: RemediationPlan, dr: DryRunResult) -> Approval:
    console.print("Approve this remediation? \\[y/N]: [bold]y[/] [dim](--auto-approve)[/]")
    return Approval(approved=True, approver="auto-approve", note="demo auto-approval")


def _investigate(finding: Finding, auto_approve: bool, verbose: bool) -> None:
    from severance.agent import runner

    console.print("▶ Investigating with the agent …")

    def on_text(text: str) -> None:
        if verbose:
            console.print(f"[dim italic]agent: {text}[/]")

    approver = auto_approver if auto_approve else interactive_approver
    if not auto_approve and not sys.stdin.isatty():
        from severance.agent.tools import reject_all

        approver = reject_all
        console.print("Non-interactive input: remediation approval defaults to rejection.")

    res = asyncio.run(
        runner.run(
            finding,
            approver=approver,
            on_text=on_text,
            on_result=render_result,
        )
    )
    console.print()
    if res.final_text:
        console.print(Panel(res.final_text, title="agent summary", border_style="dim"))
    if res.applied:
        console.print(f"[green]✓ Applied.[/] Audit record: {res.audit_path}")
    else:
        console.print(f"No changes made. Investigation logged: {res.audit_path}")
    if not res.success:
        console.print("[red]agent run did not complete successfully[/]")
        if res.error:
            console.print(res.error, markup=False)
        raise typer.Exit(1)


# ── commands ───────────────────────────────────────────────────────────────────


@app.command()
def up() -> None:
    """Start FalkorDB (docker compose up -d)."""
    subprocess.run(["docker", "compose", "up", "-d"], check=True)


@app.command("seed")
def seed_cmd(scenario: str = typer.Argument(..., help=" | ".join(SCENARIOS))) -> None:
    """Wipe the graph and seed a scenario."""
    truth = seed(scenario)
    console.print(f"✓ {scenario}: {truth.node_count} nodes, {truth.edge_count} edges")


@app.command("graph-stats")
def graph_stats() -> None:
    """Node/edge counts and the top global brokers."""
    c = queries.graph_counts()
    console.print(f"{c['nodes']} nodes, {c['edges']} edges")
    t = Table(title="top brokers (betweenness)")
    for col in ("label", "name", "score"):
        t.add_column(col)
    for b in queries.rank_brokers(10):
        t.add_row(b.node.label, b.node.name, f"{b.score:g}")
    console.print(t)


@app.command()
def investigate(
    scenario: str = typer.Option(None, help="seed this scenario and use its finding"),
    finding: str = typer.Option(None, help="finding JSON (uses the current graph)"),
    finding_file: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    auto_approve: bool = typer.Option(False, help="approve without prompting (recordings)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="show agent commentary"),
) -> None:
    """Run the agent on a finding."""
    if sum(bool(value) for value in (scenario, finding, finding_file)) != 1:
        raise typer.BadParameter("pass exactly one of --scenario, --finding, or --finding-file")
    if scenario:
        f = seed(scenario).finding
    else:
        data = json.loads(finding_file.read_text() if finding_file else finding)
        data.setdefault("id", f"find-{int(time.time())}")
        f = Finding(**data)
    _investigate(f, auto_approve, verbose)


@app.command()
def demo(auto_approve: bool = typer.Option(True, help="auto-walk the approval")) -> None:
    """Seed escalation_chain and run the full loop."""
    console.print("▶ Seeding scenario: escalation_chain …", end=" ")
    truth = seed("escalation_chain")
    console.print(f"[green]✓[/] {truth.node_count} nodes, {truth.edge_count} edges")
    _investigate(truth.finding, auto_approve, verbose=False)


@app.command()
def benchmark(
    llm_runs: int = typer.Option(10, min=0, help="tool-less LLM runs per scenario (0 = skip)"),
    baseline_scale: int = typer.Option(
        1, min=1, help="decoy-org multiplier for the baseline graph"
    ),
    resume: bool = typer.Option(False, help="resume saved baseline calls with matching options"),
) -> None:
    """Correctness table, engine vs tool-less LLM, and the scale plot → results/."""
    from severance.bench import run_all

    if resume and not llm_runs:
        raise typer.BadParameter("--resume requires --llm-runs greater than zero")
    try:
        out = run_all(llm_runs, baseline_scale, log=console.print, resume=resume)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[green]✓[/] results written to {out}/")


@app.command("import-iam")
def import_iam(
    snapshot: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    action: str = typer.Option(..., help="one concrete action, e.g. s3:PutObject"),
    resource_arn: str = typer.Option(..., help="one concrete resource ARN"),
    untrusted_arn: str = typer.Option(..., help="snapshot user/role assumed compromised"),
    graph: str = typer.Option("iam_import", help="destination; must be empty"),
    output: Annotated[Path, typer.Option(help="finding/report file prefix")] = Path(
        "results/iam_import"
    ),
) -> None:
    """Import a focused offline identity-policy projection; never contacts AWS."""
    from severance.graph.client import db, use_graph
    from severance.graph.iam_import import load_projection

    try:
        projection = load_projection(snapshot, action, resource_arn, untrusted_arn)
        with use_graph(graph):
            if graph in db().list_graphs() and queries.graph_counts()["nodes"]:
                raise ValueError(f"graph {graph!r} is not empty; choose a new --graph name")
            projection.write()
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    output.parent.mkdir(parents=True, exist_ok=True)
    output.with_suffix(".finding.json").write_text(
        projection.finding.model_dump_json(indent=2) + "\n"
    )
    output.with_suffix(".report.json").write_text(json.dumps(projection.report, indent=2) + "\n")
    console.print(
        f"Imported {projection.report['nodes']} nodes, {projection.report['edges']} edges"
    )
    console.print(f"Untrusted identity policy decision: {projection.report['untrusted_decision']}")
    console.print("Offline projection only. Unknown identities excluded. No AWS changes.")
    console.print(f"Report: {output.with_suffix('.report.json')}")
    console.print(f"Finding: {output.with_suffix('.finding.json')} (GRAPH_NAME={graph})")


@app.command("benchmark-public")
def benchmark_public(
    agent_runs: int = typer.Option(1, min=0, max=10, help="paid agent calls per case; 0 skips"),
    engine_runs: int = typer.Option(5, min=1, help="deterministic repetitions per case"),
    output: Annotated[Path, typer.Option()] = Path("results/public_iam"),
) -> None:
    """Benchmark the pinned public Cloudsplaining snapshot, with per-call checkpoints."""
    from severance.public_bench import run

    result = run(agent_runs=agent_runs, engine_runs=engine_runs, output=output, log=console.print)
    console.print(f"Results: {output.with_suffix('.md')}")
    if not result:
        raise typer.Exit(1)


@app.command()
def reset() -> None:
    """Delete everything in the graph."""
    queries.wipe()
    console.print("✓ graph wiped")


if __name__ == "__main__":
    app()
