"""Render publication charts from recorded results; no DB or LLM calls.

Run from the repository root with `python -m severance.plots` or `make charts`.
"""

import csv
import hashlib
import json
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import PercentFormatter  # noqa: E402

RESULTS = Path("results")
OUTPUT = RESULTS / "charts"
BG, INK, MUTED, GRID = "#FAF9F6", "#202923", "#646D65", "#DADDD5"
GREEN, ORANGE = "#16836C", "#E5743C"


def _style():
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11,
            "figure.facecolor": BG,
            "axes.facecolor": BG,
            "text.color": INK,
            "axes.labelcolor": INK,
            "axes.edgecolor": INK,
            "xtick.color": MUTED,
            "ytick.color": INK,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.spines.left": False,
            "axes.spines.bottom": False,
            "axes.axisbelow": True,
            "svg.fonttype": "none",
            "svg.hashsalt": "severance",
        }
    )


def _frame(fig, title, subtitle, footer):
    fig.text(
        0.055, 0.957, "SEVERANCE  /  BENCHMARKS", fontsize=10, color=GREEN, weight="bold", va="top"
    )
    fig.text(0.055, 0.91, title, fontsize=23, weight="bold", va="top")
    fig.text(0.055, 0.852, subtitle, fontsize=11, color=MUTED, va="top")
    fig.text(0.055, 0.061, footer, fontsize=9.5, color=MUTED, va="top", linespacing=1.6)
    fig.text(0.945, 0.957, "RECORDED 2026-10-18", fontsize=9, color=MUTED, ha="right", va="top")


def _save(fig, name):
    for extension in ("png", "svg"):
        kwargs = {"dpi": 200} if extension == "png" else {"metadata": {"Date": None}}
        fig.savefig(OUTPUT / f"{name}.{extension}", facecolor=BG, **kwargs)
    plt.close(fig)


def baseline_chart():
    rows = json.loads((RESULTS / "baseline_scale10.json").read_text())
    names = list(dict.fromkeys(r["scenario"] for r in rows))
    labels = ["Public\nbucket", "Escalation\nchain", "Broker\npolicy", "Exposed\nsecret"]
    if names != ["public_bucket", "escalation_chain", "broker_policy", "exposed_secret"]:
        raise ValueError("Unexpected scenario order; update the chart labels")
    fig, axes = plt.subplots(1, 2, figsize=(14.4, 8.2))
    fig.subplots_adjust(left=0.075, right=0.95, top=0.68, bottom=0.23, wspace=0.2)
    _frame(
        fig,
        "Path finding and fix selection are different tasks",
        "Seeded graphs: 479–485 nodes  ·  10 attempts per scenario and condition  ·  "
        "40 tool-less Sonnet 5.5 calls",
        "Fix agreement checks the declared edge-ranking policy. Alternative LLM cuts also "
        "closed target access with zero internal collateral.\n"
        "Engine bars repeat deterministic code; they are not full-agent runs. "
        "Source: results/baseline_scale10.json",
    )
    x = list(range(len(names)))
    for ax, metric, title in zip(
        axes,
        ("path_acc", "fix_acc"),
        ("Exact shortest-path match", "Exact expected-fix agreement"),
        strict=True,
    ):
        ax.set_title(title, loc="left", fontsize=14, weight="bold", pad=17)
        ax.set_ylim(0, 117)
        ax.set_yticks([0, 25, 50, 75, 100])
        ax.yaxis.set_major_formatter(PercentFormatter(100))
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.tick_params(length=0, pad=9)
        ax.set_xticks(x, labels)
        for offset, condition, color, label in (
            (-0.19, "engine", GREEN, "Deterministic engine"),
            (0.19, "llm_no_tools", ORANGE, "Tool-less Sonnet 5.5"),
        ):
            values = [
                next(
                    r[metric] * 100
                    for r in rows
                    if r["scenario"] == name and r["condition"] == condition
                )
                for name in names
            ]
            bars = ax.bar(
                [v + offset for v in x],
                values,
                width=0.32,
                color=color,
                edgecolor=INK,
                linewidth=0.7,
                label=label,
            )
            ax.bar_label(
                bars, labels=[f"{v:g}%" for v in values], padding=6, fontsize=11, weight="bold"
            )
            for xi, value in zip(x, values, strict=True):
                if value == 0:
                    ax.plot(
                        xi + offset,
                        0,
                        "_",
                        color=color,
                        markersize=17,
                        markeredgewidth=3,
                        clip_on=False,
                    )
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper left",
        bbox_to_anchor=(0.067, 0.79),
        frameon=False,
        ncol=2,
        fontsize=11,
    )
    _save(fig, "baseline_comparison")
    return rows


def public_chart():
    state = json.loads((RESULTS / "public_iam.json").read_text())
    if not state.get("completed_at"):
        raise ValueError("Public benchmark is incomplete")
    labels = {
        "role_write": "EC2 role · S3 write",
        "group_write": "Group · S3 write",
        "group_acl": "Group · object ACL",
        "role_write_rejected": "Approval rejected",
        "explicit_deny": "Deny in one policy",
        "split_policy_deny": "Deny across policies",
    }
    data = []
    for name, case in state["cases"].items():
        runs = case["agent"]
        if len(runs) != 1 or not runs[0]["passed"]:
            raise ValueError("This figure requires the final one-agent-run-per-case benchmark")
        run = runs[0]
        results = run["tool_results"]
        simulation = results.get("simulate_remediation")
        before = (
            simulation["before"]["external_reachers"]
            if simulation
            else results["find_reachers"]["external_reacher_count"]
        )
        if run["run"]["applied"]:
            after = results["apply_remediation"]["blast_radius_now"]["external_reachers"]
        else:
            unchanged = run["checks"].get("rejection_preserves_graph") or run["checks"].get(
                "no_false_positive_mutation"
            )
            if not unchanged:
                raise ValueError("Missing evidence that the unmodified graph was preserved")
            after = before
        data.append(
            {
                "case": name,
                "before": before,
                "after": after,
                "elapsed_s": run["elapsed_s"],
                "agent_passed": run["passed"],
                "engine_passes": sum(r["passed"] for r in case["engine"]),
                "engine_runs": len(case["engine"]),
                "median_path_ms": statistics.median(r["path_ms"] for r in case["engine"]),
            }
        )

    fig, axes = plt.subplots(1, 2, figsize=(14.4, 8.5), sharey=True)
    fig.subplots_adjust(left=0.235, right=0.94, top=0.72, bottom=0.23, wspace=0.25)
    _frame(
        fig,
        "Six public-input workflows, verified end to end",
        "Cloudsplaining example  ·  30/30 engine evaluations  ·  6/6 live MCP-agent calls  ·  "
        "Sonnet 5.5",
        "Rejected approval intentionally preserves access. Deny controls start and end at zero. "
        "Positive fixes have zero supported-principal collateral.\n"
        "One live call per case; durations are single observations. Offline identity-policy "
        "projections, not production accuracy. Source: results/public_iam.json",
    )
    y = list(range(len(data)))
    left, right = axes
    for ax in axes:
        ax.grid(axis="x", color=GRID, linewidth=0.8)
        ax.tick_params(length=0, pad=10)
    left.set_title(
        "Untrusted reachers in the active graph", loc="left", fontsize=13, weight="bold", pad=39
    )
    for delta, key, color, label in (
        (-0.17, "before", ORANGE, "Before"),
        (0.17, "after", GREEN, "After actual decision"),
    ):
        bars = left.barh(
            [v + delta for v in y],
            [r[key] for r in data],
            height=0.27,
            color=color,
            edgecolor=INK,
            linewidth=0.6,
            label=label,
        )
        left.bar_label(bars, padding=6, fontsize=11, weight="bold")
    left.set_xlim(0, 1.4)
    left.set_xticks([0, 1])
    left.set_xlabel("Modeled principals", labelpad=14)
    left.set_yticks(y, [labels[r["case"]] for r in data])
    left.invert_yaxis()
    left.legend(
        loc="lower left",
        bbox_to_anchor=(-0.02, 1.005),
        frameon=False,
        ncol=2,
        fontsize=9.5,
        handlelength=1.1,
        columnspacing=1.1,
    )
    right.set_title("Full live-agent investigation", loc="left", fontsize=13, weight="bold", pad=39)
    bars = right.barh(
        y, [r["elapsed_s"] for r in data], height=0.52, color=GREEN, edgecolor=INK, linewidth=0.6
    )
    right.bar_label(
        bars,
        labels=[f"{r['elapsed_s']:.1f}s · PASS" for r in data],
        padding=7,
        fontsize=10,
        weight="bold",
    )
    right.set_xlim(0, max(r["elapsed_s"] for r in data) * 1.45)
    right.set_xlabel("Elapsed time (seconds)", labelpad=14)
    _save(fig, "public_workflows")
    return data


def scale_chart():
    with (RESULTS / "scale.csv").open() as f:
        data = [{k: float(v) for k, v in row.items()} for row in csv.DictReader(f)]
    fig, ax = plt.subplots(figsize=(14.4, 8.2))
    fig.subplots_adjust(left=0.105, right=0.93, top=0.72, bottom=0.24)
    _frame(
        fig,
        "Query latency as the seeded graph grows",
        "Median of 5 recorded measurements per point  ·  113 to 9,421 nodes  ·  "
        "Graph size on a logarithmic axis",
        "Best-case topology: added decoy components stay disconnected from the target. "
        "This does not measure dense or highly connected graphs.\n"
        "Source: results/scale.csv  ·  Query time only; no LLM, planner or end-to-end "
        "agent latency is included.",
    )
    x = [r["nodes"] for r in data]
    for key, label, color, marker in (
        ("find_reachers_ms", "Find reachers", GREEN, "o"),
        ("shortest_external_path_ms", "Shortest external path", ORANGE, "s"),
    ):
        values = [r[key] for r in data]
        ax.plot(
            x,
            values,
            color=color,
            linewidth=2.5,
            marker=marker,
            markersize=10,
            markeredgecolor=INK,
            markeredgewidth=0.9,
            label=label,
        )
        for row, xi, yi in zip(data, x, values, strict=True):
            other = row[
                "shortest_external_path_ms" if key == "find_reachers_ms" else "find_reachers_ms"
            ]
            offset = 15 if yi >= other else -22
            ax.annotate(
                f"{yi:.2f} ms",
                (xi, yi),
                xytext=(0, offset),
                textcoords="offset points",
                ha="center",
                fontsize=11,
                weight="bold",
            )
    ax.set_xscale("log")
    ax.set_xticks(x, [f"{int(v):,}" for v in x])
    ax.minorticks_off()
    ax.set_ylim(0, 0.85)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8])
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.tick_params(length=0, pad=12)
    ax.set_xlabel("Graph nodes (log scale)", labelpad=16)
    ax.set_ylabel("Median query latency (ms)", labelpad=15)
    ax.legend(loc="upper left", frameon=False, ncol=2)
    _save(fig, "query_scaling")
    return data


def main():
    _style()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    data = {
        "baseline": baseline_chart(),
        "public_workflows": public_chart(),
        "query_scaling": scale_chart(),
    }
    data["source_sha256"] = {
        name: hashlib.sha256((RESULTS / name).read_bytes()).hexdigest()
        for name in ("baseline_scale10.json", "public_iam.json", "scale.csv")
    }
    (OUTPUT / "chart_data.json").write_text(json.dumps(data, indent=2) + "\n")
    print(f"Wrote 3 charts as PNG + SVG, plus source data, to {OUTPUT}/")


if __name__ == "__main__":
    main()
