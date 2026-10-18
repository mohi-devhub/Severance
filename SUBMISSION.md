# Graph Hacks submission notes

**Project:** BlastRadius Agent (repository: Severance)

**Team:** pied-piper

**Track:** Track 01 — Agents That Act on Connected Data

## Project description

BlastRadius Agent investigates synthetic cloud IAM security findings using FalkorDB as
its operational context. A Claude agent selects typed MCP tools to find external
reachers, trace multi-hop privilege-escalation paths, and rank load-bearing roles and
policies. A deterministic planner evaluates candidate edge cuts on server-side graph
copies. The chosen fix is simulated, presented for approval, and applied only with a
single-use consent token. Every plan and mutation records its justifying graph path
and measured before/after effects in an append-only audit trail.

FalkorDB supplies the decisions: removing it removes reachability analysis, shortest
paths, broker ranking, dry-runs, and remediation. The project uses synthetic data only.

## Submission assets

| Requirement | Location |
|---|---|
| Source repository | https://github.com/mohi-devhub/Severance |
| Track, setup, architecture, graph model and essential Cypher | [README](README.md) |
| Working demo video | [90-second MP4](demo/blastradius-demo.mp4) |
| Original terminal output | [Transcript](demo/transcript.txt) and [timestamped capture](demo/capture.json) |
| Exact investigation and mutation evidence | [Recorded audit](demo/audit.jsonl) and [summary](demo/evidence.json) |
| Larger baseline, model and raw answers | [Report](results/baseline_scale10.md), [metrics](results/baseline_scale10.json), [checkpoint](results/baseline_scale10.runs.json) |
| Repeatable build and CI | `uv.lock`, pinned Docker image, [workflow](.github/workflows/ci.yml) |
| AI coding disclosure | README → Scope and AI assistance |

The video is an annotated replay of an actual Sonnet 5.5 CLI run, with playback
stretched for readability and no audio. The real capture lasted about 24 seconds.
It explicitly uses the synthetic demo's auto-approval. Normal investigations ask a
human to approve, and non-interactive input rejects by default. Its source composition
and rebuilding instructions are in [demo/README.md](demo/README.md).

## What has been verified

- 86 deterministic tests passed against both the existing database and a fresh
  container using the pinned FalkorDB image.
- Two real Sonnet agent tests passed: approve and apply; reject and preserve the graph.
- Ruff lint and formatting checks passed.
- Source distribution and wheel built; a clean environment installed the wheel,
  loaded its system prompt and MCP server, and ran the CLI help.
- The 40-call scale-10 baseline completed without call failures. Sonnet found all
  expected paths; its exact fix-edge accuracy was 67.5%, versus 100% for the engine.
  Alternative fix edges still closed the exposure; the metric checks edge ranking.
- Video layout, runtime, motion and text contrast were checked before rendering.

## Before submitting on the event website

The repository is **private by the team leader's explicit choice**. The
[official rules](https://www.wemakedevs.org/hackathons/falkordb/rules) require a
**public source repository**, a demo video, setup and graph-model documentation,
essential queries/algorithms, named tracks, and disclosure of AI assistance.
The README and local setup satisfy the documentation/deployment requirements.

1. Change repository visibility to public when the team leader is ready.
2. Upload `demo/blastradius-demo.mp4` to the submission form or a video host the form accepts.
3. Enter the source link and **Track 01 — Agents That Act on Connected Data**.
4. Include the AI assistance disclosure; review the demo and be prepared to explain
   the graph schema, queries, ranking policy, approval gate and benchmark limitations.
5. Confirm team membership before submitting; the event page says it cannot be changed afterward.

The advertised deadline is October 18, 2026, 11:59 PM IST. Repository publication,
video hosting and form submission are not performed by this preparation step.
