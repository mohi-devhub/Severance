# Severance — Graph Hacks submission notes

**Project:** Severance

**Team:** pied-piper

**Track:** Track 01 — Agents That Act on Connected Data

## Project description

Severance investigates seeded IAM findings and imports a public AWS IAM example snapshot
using FalkorDB as its
operational context. A Claude agent selects typed MCP tools to find external
reachers, trace multi-hop privilege-escalation paths, and rank load-bearing roles
and policies. A deterministic planner evaluates candidate edge cuts on server-side
graph copies. The chosen fix is simulated, presented for approval, and applied only
with a single-use consent token. Plans and mutations record the justifying graph
path and measured before/after effects in an append-only audit trail.

FalkorDB supplies the decisions: removing it removes reachability analysis,
shortest paths, broker ranking, dry-runs, and remediation. Public imports assess a
supported identity-policy subset for one permission request; they do not claim complete
AWS effective-permission analysis. All changes remain inside FalkorDB.

## Non-video submission requirements

| Requirement | Status and evidence |
|---|---|
| Public source repository | [mohi-devhub/Severance](https://github.com/mohi-devhub/Severance), verified accessible without authentication. |
| README graph map | [Node properties, all six relationships, and a diagram](README.md#graph-data-model) showing external escalation and legitimate internal access. |
| Graph queries and algorithms | [Essential Cypher](README.md#queries-that-drive-the-agent) and [implementation](src/severance/graph/queries.py): read-only traversals, `algo.SPpaths`, seeded `algo.betweenness`, and graph copies. |
| FalkorDB central to decisions | [Track 01 evidence](README.md#track-01-evidence), [planner](src/severance/remediation/planner.py), [dry-run](src/severance/remediation/dryrun.py), and [approval gate](src/severance/remediation/apply.py). |
| Complete local setup | [README setup](README.md#run-it), `uv.lock`, and a pinned, health-checked multi-platform FalkorDB image. |
| Named track and AI disclosure | README explicitly identifies Track 01 and [discloses AI assistance](README.md#scope-and-ai-assistance). |
| Reproducible checks | [GitHub Actions](.github/workflows/ci.yml) runs lint, formatting, deterministic graph tests, and package builds. |

## Verification

- 113 deterministic tests pass, including public-input paths, exact fixes, deny precedence,
  unknown handling and compound resource-name normalization. The original 86-test suite
  also passed against a clean pinned database container.
- Two real Sonnet agent tests passed: approve and apply; reject and preserve the graph.
- Ruff lint and formatting checks passed.
- Source and wheel packages build; an isolated environment can install the wheel and
  load its system prompt, MCP server and CLI.
- The 40-call scale-10 baseline completed without call failures. Sonnet found all
  expected paths; its exact fix-edge accuracy was 67.5%, versus 100% for the engine.
  Alternative cuts also closed exposure; this metric checks the declared edge ranking.
  [Report](results/baseline_scale10.md), [metrics](results/baseline_scale10.json), and
  [raw answers](results/baseline_scale10.runs.json) are included.

- Public-snapshot benchmark: 30/30 engine evaluations and 6/6 real Sonnet MCP-agent
  investigations pass, including rejection and two explicit-deny controls.
- Public snapshot provenance, source-derived expectations and scoped import semantics are
  documented in [datasets/cloudsplaining](datasets/cloudsplaining/README.md). The full-agent
  benchmark and raw evidence are in [public_iam.md](results/public_iam.md) and
  [public_iam.json](results/public_iam.json). Earlier lookup-error runs are retained.

## Event submission

The [official rules](https://www.wemakedevs.org/hackathons/falkordb/rules) require public
source, graph-model and setup documentation, essential queries or algorithms, named
tracks, disclosure of AI assistance, and a working demonstration.

Video recording and editing are handled by the project owner and are outside this
update. Submit the source link, select **Track 01**, and provide the owner's working
demonstration in the event form. Review the graph schema, queries, ranking policy,
approval gate and benchmark limitations so the team can explain the implementation.

The advertised deadline is October 18, 2026, 11:59 PM IST. Form submission and
certificate retrieval from the participant profile are handled by the project owner.
