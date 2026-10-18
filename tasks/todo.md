# Severance build

- [x] Phase 0 scaffolding (FalkorDB on host port 6380; 6379 taken by local redis)
- [x] Phase 1 graph layer: client, schema, queries, seeder (GRAPH.COPY verified on v4.22.1)
- [x] Phase 2 scoring
- [x] Phase 3 planner (4/4 expected_fix_edge)
- [x] Phase 4 dry-run, token-gated apply, audit
- [x] Phase 5 agent + tools (e2e approve/reject pass against real Claude)
- [x] Phase 6 CLI + demo (38s end to end)
- [x] Phase 7 benchmark + README

## Review
- 86 deterministic tests pass against the existing DB and a fresh pinned FalkorDB container;
  2 live Sonnet agent e2e tests pass. Ruff lint and formatting pass.
- Scale-10 baseline completed: 10 calls/scenario, 40 total; Sonnet 5.5 found all paths,
  matched 27/40 expected fix edges, and hallucinated no edges. Small-graph results preserved.
- Failed calls are recorded independently; atomic per-call checkpoints support --resume.
- CI, dependency lock, pinned multi-platform database image, health checks, wheel smoke test,
  graph-model/query docs, Track 01 evidence, and AI assistance disclosure are implemented.
- The project, Python package and CLI are named Severance (`severance`).
- The public repository is accessible without authentication. The README maps the graph
  and explains where FalkorDB supplies the agent's decisions; it contains no demo section.
- Video recording/editing and submission through the event form remain with the project owner.

## Public IAM snapshot follow-up

- [x] Vendor the unchanged Cloudsplaining snapshot with pinned revision, checksum and license.
- [x] Add scoped IAM import, explicit compromised-identity assumptions, deny/unknown handling.
- [x] Add public snapshot engine/MCP-agent benchmark and preserve early lookup-error runs.
- [x] Verify 113 deterministic tests, lint/format and wheel/source build.
- [x] Add source-derived expectations, import commands, graph mapping and measured results.
- Final public-snapshot run passes 30/30 engine evaluations and 6/6 full-agent calls,
  without tool errors; approved writes, rejection and explicit-deny controls all match.
