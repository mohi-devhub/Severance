# Benchmark figures

Run `make charts` from the repository root after installing the `bench` extra
(`uv sync --locked --all-extras`). Plotting reads saved artifacts only: it does not
connect to FalkorDB or call an LLM. Implementation: [plots.py](../../src/severance/plots.py).

Every chart is exported as a high-resolution PNG and an SVG:

| Figure | Source | What it measures |
|---|---|---|
| [Path/fix bars](baseline_comparison.png) · [SVG](baseline_comparison.svg) | [baseline_scale10.json](../baseline_scale10.json) | Exact shortest-path and expected-fix agreement over 10 attempts per scenario/condition. Engine repetitions are deterministic; 40 calls use tool-less Sonnet 5.5. |
| [Public workflows](public_workflows.png) · [SVG](public_workflows.svg) | [public_iam.json](../public_iam.json) | Active-graph untrusted reachers before/after the actual decision and one full-agent duration per case. Approved writes close access, rejection preserves it, and deny controls remain at zero. |
| [Query scaling](query_scaling.png) · [SVG](query_scaling.svg) | [scale.csv](../scale.csv) | Median query latency over five measurements at each of three seeded graph sizes. Node count uses a logarithmic axis. |

[chart_data.json](chart_data.json) contains the plotted data and SHA-256 checksums
of all three input files. Original benchmark artifacts are unchanged.

Fix agreement evaluates the declared ranking policy. The alternative baseline cuts
also closed target access without internal collateral. Public-workflow results
cover a small external example fixture, not production accuracy; unknown identities
are excluded from the supported projection. Live-agent timings have one observation
per case. Scale results use disconnected decoys and measure query time, not planner
or full-agent time. No cost measurements were recorded or inferred.
