"""Reproducible external-fixture correctness and full MCP-agent benchmark."""

import asyncio
import hashlib
import json
import statistics
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from severance.agent import runner
from severance.agent.prompts import SYSTEM_PROMPT, render_finding_prompt
from severance.bench import _write_json
from severance.config import settings
from severance.graph import queries
from severance.graph.client import drop_graph, use_graph
from severance.graph.iam_import import load_projection
from severance.models import Approval
from severance.remediation import dryrun, planner

DATASET = Path("datasets/cloudsplaining/example.json")
COMMIT = "f2ed0ba2ddf6457143203d46971c91ba236b6597"
RESOURCE = "arn:aws:s3:::mybucket/example.txt"
ROLE = "arn:aws:iam::012345678901:role/OverprivilegedEC2"
USER = "arn:aws:iam::200611803367:user/privesc-sre-user"
GROUP = "arn:aws:iam::200611803367:group/privesc-sre-group"
GROUP_POLICY = "arn:aws:iam::200611803367:policy/privesc-sre-admin-policy"
ROLE_POLICY = "arn:aws:iam::012345678901:policy/InsecurePolicy"

# Expectations are manually derived from the pinned input documents, not the
# engine's output. Dataset notes explain the corresponding source statements.
CASES = [
    {
        "name": "role_write",
        "arn": ROLE,
        "action": "s3:PutObject",
        "approve": True,
        "path_prefix": [f"session:{ROLE}", ROLE, ROLE_POLICY],
        "fix": {"from_id": ROLE, "type": "GRANTS", "to_id": ROLE_POLICY},
    },
    {
        "name": "group_write",
        "arn": USER,
        "action": "s3:PutObject",
        "approve": True,
        "path_prefix": [USER, GROUP, f"permissions:{GROUP}", GROUP_POLICY],
        "fix": {"from_id": USER, "type": "MEMBER_OF", "to_id": GROUP},
    },
    {
        "name": "group_acl",
        "arn": USER,
        "action": "s3:PutObjectAcl",
        "approve": True,
        "path_prefix": [USER, GROUP, f"permissions:{GROUP}", GROUP_POLICY],
        "fix": {"from_id": USER, "type": "MEMBER_OF", "to_id": GROUP},
    },
    {
        "name": "role_write_rejected",
        "arn": ROLE,
        "action": "s3:PutObject",
        "approve": False,
        "path_prefix": [f"session:{ROLE}", ROLE, ROLE_POLICY],
        "fix": {"from_id": ROLE, "type": "GRANTS", "to_id": ROLE_POLICY},
    },
    {
        "name": "explicit_deny",
        "arn": "arn:aws:iam::200611803367:user/fp1-allow-and-deny-user",
        "action": "iam:CreateAccessKey",
        "approve": False,
        "path_prefix": [],
        "fix": None,
    },
    {
        "name": "split_policy_deny",
        "arn": "arn:aws:iam::200611803367:user/fp2-allow-and-deny-multiple-policies-user",
        "action": "s3:PutObject",
        "approve": False,
        "path_prefix": [],
        "fix": None,
    },
]


def _projection(case):
    resource = case["arn"] if case["action"].startswith("iam:") else RESOURCE
    return load_projection(DATASET, case["action"], resource, case["arn"])


def _expected_path(case, target):
    return case["path_prefix"] + [f"{case['action']}@{target}", target] if case["fix"] else []


def _engine(case, projection):
    start = time.perf_counter()
    path = queries.shortest_external_path(projection.target_id)
    path_ms = (time.perf_counter() - start) * 1000
    start = time.perf_counter()
    plan = planner.choose(projection.target_id)
    planner_ms = (time.perf_counter() - start) * 1000
    checks = {
        "exact_path": (path.ids if path else []) == _expected_path(case, projection.target_id),
        "exact_fix": (plan.edge.model_dump() if plan else None) == case["fix"],
    }
    dr = dryrun.simulate(plan) if plan else None
    if dr:
        checks.update(
            closes_exposure=dr.after.external_reacher_count == 0,
            preserves_supported_callers=not dr.collateral,
        )
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "path": path.ids if path else [],
        "fix": plan.edge.model_dump() if plan else None,
        "path_ms": path_ms,
        "planner_ms": planner_ms,
        "external_before": dr.before.external_reacher_count if dr else 0,
        "external_after_simulation": dr.after.external_reacher_count if dr else 0,
        "collateral": dr.collateral if dr else [],
    }


def _redact(value):
    if isinstance(value, dict):
        return {k: "[redacted]" if k == "token" else _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str) and settings.anthropic_api_key:
        return value.replace(settings.anthropic_api_key, "[redacted]")
    return value


async def _agent(case, projection):
    counts = queries.graph_counts()
    before = [r.model_dump() for r in queries.find_reachers(projection.target_id)]
    observed = {}
    start = time.perf_counter()
    result = await asyncio.wait_for(
        runner.run(
            projection.finding,
            approver=lambda plan, dr: Approval(
                approved=case["approve"],
                approver="public-benchmark",
                note="explicit offline benchmark decision",
            ),
            on_result=lambda name, payload: observed.__setitem__(name, payload),
        ),
        timeout=180,
    )
    elapsed = time.perf_counter() - start
    after = [r.model_dump() for r in queries.find_reachers(projection.target_id)]
    steps = [r["step"] for r in result.records]
    tool_calls = [r for r in result.records if r["step"] == "tool_call"]
    checks = {
        "sdk_success": result.success,
        "audit_written": "write_audit" in steps,
        "no_tool_errors": all(not r["is_error"] for r in tool_calls),
    }
    path = observed.get("shortest_escalation_path", {}).get("primary")
    checks["exact_path"] = ([n["id"] for n in path["nodes"]] if path else []) == (
        _expected_path(case, projection.target_id)
    )
    if case["fix"]:
        proposal = observed.get("propose_remediation", {})
        sim = observed.get("simulate_remediation", {})
        checks.update(
            exact_fix=proposal.get("edge") == case["fix"],
            closes_exposure=sim.get("after", {}).get("external_reachers") == 0,
            preserves_supported_callers=sim.get("collateral") == [],
            approval_respected=result.applied == case["approve"]
            and any(
                r["step"] == "request_approval" and r.get("approved") == case["approve"]
                for r in result.records
            ),
        )
        if case["approve"]:
            checks["post_apply_no_untrusted_reacher"] = not any(
                r["kind"] == "external" for r in after
            )
            checks["exactly_one_edge_deleted"] = queries.graph_counts() == {
                "nodes": counts["nodes"],
                "edges": counts["edges"] - 1,
            }
        else:
            checks["rejection_preserves_graph"] = (
                queries.graph_counts() == counts and after == before
            )
    else:
        checks["no_false_positive_mutation"] = (
            not result.applied
            and (queries.graph_counts() == counts and after == before)
            and "propose_remediation" not in steps
            and "request_approval" not in steps
        )
    return _redact(
        {
            "passed": all(checks.values()),
            "checks": checks,
            "elapsed_s": elapsed,
            "error": result.error,
            "run": result.model_dump(),
            "tool_results": observed,
        }
    )


def report_md(state):
    lines = [
        "# Public IAM snapshot benchmark",
        "",
        f"Model: `{state['model']}`. Started: {state['started_at']}.",
        "",
        f"Source: Cloudsplaining `example.json`, commit `{COMMIT}`.",
        f"SHA-256: `{state['source_sha256']}`.",
        "",
        "Offline identity-policy projections; manually specified compromised identities.",
        "These are external example fixtures, not production accounts or live AWS checks.",
        "",
        "| case | graph nodes / edges | engine passes | agent passes | hops | "
        "external before → simulated after | collateral | median path ms | median planner ms |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, case in state["cases"].items():
        engines, agents = case["engine"], case["agent"]
        latest = next((r for r in engines if "path" in r), {})
        source = case["import"]
        lines.append(
            f"| {name} | {source['nodes']} / {source['edges']} | "
            f"{sum(r['passed'] for r in engines)}/{len(engines)} | "
            f"{sum(r['passed'] for r in agents)}/{len(agents)} | "
            f"{len(latest.get('path', [])) - 1 if latest.get('path') else 'none'} | "
            f"{latest.get('external_before', '—')} → "
            f"{latest.get('external_after_simulation', '—')} | "
            f"{len(latest.get('collateral', []))} | "
            f"{statistics.median(r['path_ms'] for r in engines if 'path_ms' in r):.3f} | "
            f"{statistics.median(r['planner_ms'] for r in engines if 'planner_ms' in r):.3f} |"
        )
    lines += [
        "",
        "Each engine repetition checks an independently specified exact path/fix and "
        "dry-run effects. Each agent run imports a fresh graph and uses the real MCP loop.",
        "Approved cases must delete exactly one graph edge and close untrusted reachability; "
        "rejection and explicit-deny controls must leave the graph unchanged.",
        "",
        "Full per-call checks, raw agent summaries, tool outputs, redacted audit records, "
        "import coverage and unknown identities are in the companion JSON.",
        "",
        "Limitations: one action/resource request per projection; no role-trust transitions, "
        "resource policies, SCPs/RCPs or session policies. Relevant conditions, negations, "
        "policy variables, missing documents and permissions boundaries produce unknown. "
        "Unknown identities are excluded, never counted as proven denies. "
        "Collateral covers other supported callers of the assessed permission only. "
        "No AWS mutation. This is a small fixture benchmark, not a production accuracy estimate.",
    ]
    return "\n".join(lines) + "\n"


def run(agent_runs=1, engine_runs=5, output=Path("results/public_iam"), log=print):
    output.parent.mkdir(parents=True, exist_ok=True)
    provenance = json.loads(DATASET.with_name("provenance.json").read_text())
    checksum = hashlib.sha256(DATASET.read_bytes()).hexdigest()
    if checksum != provenance["sha256"] or provenance["commit"] != COMMIT:
        raise ValueError("Public benchmark input does not match the pinned dataset provenance")
    state = {
        "benchmark_id": uuid.uuid4().hex[:12],
        "source_commit": COMMIT,
        "source_sha256": checksum,
        "model": settings.model,
        "started_at": datetime.now(UTC).isoformat(),
        "engine_runs_per_case": engine_runs,
        "agent_runs_per_case": agent_runs,
        "cases": {},
    }

    def save():
        _write_json(output.with_suffix(".json"), state)
        if all(c["engine"] for c in state["cases"].values()):
            output.with_suffix(".md").write_text(report_md(state))

    save()
    for case in CASES:
        projection = _projection(case)
        row = {
            "definition": case,
            "finding": projection.finding.model_dump(),
            "prompt_sha256": hashlib.sha256(
                (SYSTEM_PROMPT + render_finding_prompt(projection.finding)).encode()
            ).hexdigest(),
            "import": projection.report,
            "engine": [],
            "agent": [],
        }
        state["cases"][case["name"]] = row
        graph = f"iam_public_bench_{state['benchmark_id']}_{case['name']}"
        try:
            with use_graph(graph):
                projection.write()
                for _ in range(engine_runs):
                    row["engine"].append(_engine(case, projection))
                    save()
                log(
                    f"{case['name']}: engine "
                    f"{sum(r['passed'] for r in row['engine'])}/{engine_runs}"
                )
                for index in range(agent_runs):
                    projection.write()
                    try:
                        result = asyncio.run(_agent(case, projection))
                    except Exception as exc:
                        result = _redact({"passed": False, "error": f"{type(exc).__name__}: {exc}"})
                    row["agent"].append(result)
                    save()
                    log(
                        f"  agent {index + 1}/{agent_runs}: "
                        f"{'PASS' if result['passed'] else 'FAIL'} {result.get('error') or ''}"
                    )
        finally:
            drop_graph(graph)
    state["completed_at"] = datetime.now(UTC).isoformat()
    save()
    return all(
        r["passed"]
        for c in state["cases"].values()
        for group in ("engine", "agent")
        for r in c[group]
    )
