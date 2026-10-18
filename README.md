# BlastRadius Agent

**Given a cloud security finding, this agent traces every path an untrusted identity could walk
to the exposed resource. It then picks the one load-bearing edge to cut, proves the fix on a copy
of the graph, and only then asks a human to approve it.**

The LLM plans and explains. Every path, count and score comes from a graph query.

```
$ bragent demo
▶ Seeding scenario: escalation_chain … ✓ 64 nodes, 71 edges
▶ Finding: overly_permissive on prod-db (database, sensitivity=critical)

SHORTEST EXTERNAL PATH (blast radius = 6 hops, 1 external entry point)
  guest(external) ─CAN_ASSUME→ build-role ─CAN_ASSUME→ deploy-role ─CAN_ASSUME→
  admin-role ─GRANTS→ IAMFullAccess ─PERMITS→ iam:AttachRolePolicy ─TARGETS→ prod-db

LOAD-BEARING NODE (betweenness): admin-role (role, 77)

PROPOSED FIX: detach_policy — Detach policy IAMFullAccess from role admin-role.

DRY-RUN (on graph copy)
                          before     after
 reachers                      4  →      3
 external reachers             1  →      0  ✓
 shortest external hops        6  →      ∞  ✓
 severity                     18  →     12
 paths closed                  1
 collateral (legit lost)       0            ✓
Approve this remediation? [y/N]: y
✓ Applied to live graph.  Audit: audit/run-041dd4.jsonl
```

A scanner says *"prod-db is reachable."* This agent shows the 6-hop chain from a guest identity
and the one policy that chain depends on. It also proves, before you approve anything, that
detaching that policy closes the path and leaves every legitimate user's access intact.

## Benchmark

`make bench` writes everything below to `results/`.

**A. Correctness of the deterministic engine.** All four seeded scenarios pass on every column.

| scenario | found external path | chose root-cause fix | external reachers after | collateral |
|---|---|---|---|---|
| public_bucket | ✓ | ✓ | 0 | 0 |
| escalation_chain | ✓ | ✓ (deep pivot, not hop 1) | 0 | 0 |
| broker_policy | ✓ | ✓ | 0 | 0 |
| exposed_secret | ✓ | ✓ | 0 | 0 |

**B. Engine vs. the same model with no tools.** The baseline gets the raw node and edge list in
its prompt, plus the same objective and tie-break rule. Results are from 3 runs per scenario
(`--llm-runs 3`), on graphs of about 65 nodes.

| scenario | condition | exact path | fix edge | same answer across runs | hallucinated edges |
|---|---|---|---|---|---|
| public_bucket | engine | 100% | 100% | 100% | 0% |
| public_bucket | llm_no_tools | 100% | 100% | 100% | 0% |
| escalation_chain | engine | 100% | 100% | 100% | 0% |
| escalation_chain | llm_no_tools | 100% | **0%** | 100% | 0% |
| broker_policy | engine | 100% | 100% | 100% | 0% |
| broker_policy | llm_no_tools | 100% | 100% | 100% | 0% |
| exposed_secret | engine | 100% | 100% | 100% | 0% |
| exposed_secret | llm_no_tools | 100% | 100% | 100% | 0% |

At this size the tool-less model reads the graph well: it found every exact path and invented no
edges. On the 6-hop `escalation_chain` it consistently cut `deploy-role -CAN_ASSUME-> admin-role`
instead of the policy. That edge is the engine's own runner-up: it closes the path too and ties on
broker score, but ranks lower on specificity. To see how the gap changes with graph size, run
`bragent benchmark --baseline-scale 10`, which gives about 500 nodes.

**C. Scale.** This is the median latency over 5 runs on `escalation_chain`, with the decoy org
scaled up.

| nodes | edges | find_reachers | shortest_external_path |
|---|---|---|---|
| 113 | 128 | 0.9 ms | 0.6 ms |
| 963 | 1,096 | 0.6 ms | 0.7 ms |
| 9,421 | 10,748 | 0.7 ms | 1.0 ms |

![scale](results/scale.png)

Both queries start from an indexed node and walk outward, so their cost follows the size of the
reachable neighbourhood, not the whole graph. The seeded decoys never connect to the target, so
this measures that best case.

## How it stays safe: the four invariants

1. **Determinism over vibes.** Reachability, paths and scores come from Cypher and plain Python.
   Tools return JSON that the model reads, and the model never computes a number itself.
2. **No silent mutation.** A fix is first measured on a server-side `GRAPH.COPY`. Applying it
   needs a single-use token that is minted only when the human approves, and the token is bound
   to a hash of that exact edge. Plans and dry-runs stay in server-side session state, keyed by
   `plan_id`, so the model can't hand back an edited plan or fake before/after numbers.
3. **Everything is auditable.** `audit/<run_id>.jsonl` gets a record for every tool call, plan,
   dry-run, approval and apply. Records for a plan or a mutation must carry the justifying path,
   or the log refuses to write them.
4. **Synthetic only.** The seeder plants known vulnerabilities, so the tests can assert exact
   paths and fix edges. There is no cloud SDK and no live account.

The approval token is there to make applying without approval structurally impossible. It is not
meant to be cryptographically strong. Non-interactive runs reject by default.

## Severity formula

```
severity = w_sens · sensitivity_weight     (low=1, medium=2, high=3, critical=4)
         + w_ext  · min(external_reachers, CAP)
         + w_prox · max(0, MAX_HOPS − shortest_external_hops)   (0 if no external path)
```

The defaults are `w_sens=3, w_ext=2, w_prox=2, CAP=10, MAX_HOPS=8`, and all of them can be set in
`config.py` or `.env`.

## How the planner picks the edge

The candidates are the edges on at least one shortest external path. The planner cuts each one
on a graph copy and ranks them by these keys, in order:

1. fewest external reachers left
2. most shortest external paths closed
3. least collateral (internal principals that lose access)
4. highest broker score (betweenness of a Role or Policy endpoint on the path)
5. specificity: `CAN_ASSUME` into a broad-trust role, then `GRANTS`, `MEMBER_OF`,
   `HAS_ROLE`/`CAN_ASSUME`, `PERMITS`, `TARGETS`
6. edge id, as a stable final tie-break

Keys 4 and 5 are what make `escalation_chain` and `broker_policy` choose the deep broker, where
the naive "cut hop 1" answer is wrong. If the runner-up ties on keys 1–3, the approval prompt
shows it as an alternative.

## Architecture

```
cli/main.py ─ typer + rich: investigate · demo · seed · graph-stats · benchmark · reset
     │
agent/runner.py ─ Claude Agent SDK loop, approver injected per run
agent/tools.py  ─ 9 typed tools → in-process MCP server ("iam"), per-call audit
     │
     ├── graph/       client (RO/RW, GRAPH.COPY context), schema, queries, seeder
     ├── scoring/     escalation paths, blast radius, severity
     ├── remediation/ planner · dryrun · token-gated apply
     └── audit/       append-only JSONL
     │
FalkorDB (Docker)
```

The agent calls the tools in this order: `get_finding_context` → `find_reachers` →
`shortest_escalation_path` → `rank_brokers` → `propose_remediation` → `simulate_remediation` →
`request_approval` → `apply_remediation` → `write_audit`.

## Run it

```bash
uv venv -p 3.11 .venv && uv pip install -p .venv -e '.[dev,bench]'
cp .env.example .env            # FalkorDB on host port 6380
make up                          # docker compose up -d
make demo                        # seed escalation_chain + full loop (auto-approve)
.venv/bin/bragent investigate --scenario broker_policy    # real y/N prompt
make test                        # agent e2e runs only with ANTHROPIC_API_KEY or BRAGENT_RUN_AGENT=1
make bench
```

The agent authenticates through the Claude Agent SDK, using either `ANTHROPIC_API_KEY` or a
logged-in Claude Code.

## Implementation notes

- **Action nodes are scoped per resource** (`id = "s3:PutObject@res-prod-artifacts"`). With one
  global node per action string, any policy that permits `s3:GetObject` would appear to reach
  every bucket.
- **Paths come from `algo.SPpaths` with `pathCount: 0`, run per external principal.** On this
  FalkorDB build (v4.22), `shortestPath()` is only allowed in `WITH`/`RETURN`. SPpaths gives every
  shortest path in one call, and ties are broken by node ids.
- **Betweenness is seeded and sampled at 10× the node count.** `algo.betweenness` samples source
  nodes with replacement. A 1× sample sometimes missed the only external source entirely.
- **The var-length hop bound is inlined** as a range-checked int (2–8). FalkorDB can't take it as
  a parameter.
- **Tools take a `plan_id`, not a plan payload** (see invariant 2).
