"""The nine tools the model can call, as an in-process MCP server (docs/06).

Each tool is a thin typed skin over graph/, scoring/, remediation/ and audit/.
Plans and dry-runs live in server-side session state and are referenced by
`plan_id`: the model never hands back a plan or a dry-run it could have edited,
so the approver always sees numbers that came from a query.
"""

import json
import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from typing import Any

from claude_agent_sdk import create_sdk_mcp_server, tool

from severance.audit.log import AuditLog, plan_fields, summary
from severance.graph import queries
from severance.models import Approval, DryRunResult, Finding, RemediationPlan
from severance.remediation import apply, dryrun, planner
from severance.scoring import blast_radius
from severance.scoring.paths import escalation_paths, exploit_node_ids

Approver = Callable[[RemediationPlan, DryRunResult], Approval]


@dataclass
class Session:
    finding: Finding
    approver: Approver
    log: AuditLog
    plans: dict[str, RemediationPlan] = field(default_factory=dict)
    dryruns: dict[str, DryRunResult] = field(default_factory=dict)
    approvals: dict[str, Approval] = field(default_factory=dict)
    on_result: Callable[[str, Any], None] | None = None  # CLI rendering hook


_session: ContextVar[Session] = ContextVar("session")


def start_session(session: Session):
    return _session.set(session)


def reject_all(plan: RemediationPlan, dr: DryRunResult) -> Approval:
    """Fail-safe approver for non-interactive runs: never auto-approve a mutation."""
    return Approval(approved=False, approver="non-interactive", note="default reject")


class ToolError(Exception):
    """An expected failure the model should see and react to."""


def _ok(payload: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, default=str)}]}


def _audited(name: str):
    """Wrap a handler: JSON in/out, errors → is_error, and an audit record per call."""

    def deco(fn: Callable[[Session, dict], Any]) -> Callable[[dict], Awaitable[dict]]:
        @wraps(fn)
        async def handler(args: dict[str, Any]) -> dict[str, Any]:
            s = _session.get()
            try:
                payload = fn(s, args)
            except (ToolError, LookupError, ValueError) as e:
                s.log.record("tool_call", tool=name, inputs=args, is_error=True, error=str(e))
                return {"content": [{"type": "text", "text": f"error: {e}"}], "is_error": True}
            s.log.record("tool_call", tool=name, inputs=args, is_error=False)
            if s.on_result:
                s.on_result(name, payload)
            return _ok(payload)

        return handler

    return deco


def _plan(s: Session, plan_id: str) -> RemediationPlan:
    if plan_id not in s.plans:
        raise ToolError(f"unknown plan_id {plan_id!r}; call propose_remediation first")
    return s.plans[plan_id]


@_audited("get_finding_context")
def _get_finding_context(s: Session, args: dict) -> dict:
    res = queries.get_resource_by_name(args["resource_name"])
    if res is None:
        raise ToolError(f"no resource named {args['resource_name']!r} in the graph")
    s.log.resource = res.name
    return {
        "finding": s.finding.model_dump(),
        "resource": res.model_dump(),
        "question": f"Which identities can reach {res.name} ({res.type}, "
        f"sensitivity={res.sensitivity}), and how could an untrusted one get there?",
    }


@_audited("find_reachers")
def _find_reachers(s: Session, args: dict) -> dict:
    reachers = queries.find_reachers(args["resource_id"], maxlen=args["max_hops"])
    return {
        "reacher_count": len(reachers),
        "external_reacher_count": sum(r.kind == "external" for r in reachers),
        "reachers": [r.model_dump() for r in reachers],
    }


@_audited("shortest_escalation_path")
def _shortest_escalation_path(s: Session, args: dict) -> dict:
    primary, paths = escalation_paths(args["resource_id"])
    if primary is None:
        return {"primary": None, "message": "no external principal reaches this resource"}
    return {
        "primary": primary.model_dump(),
        "primary_rendered": primary.cypher_render(),
        "hops": primary.length,
        "entry_points": [p.cypher_render() for p in paths],
    }


@_audited("rank_brokers")
def _rank_brokers(s: Session, args: dict) -> dict:
    _, paths = escalation_paths(args["resource_id"])
    on_path = exploit_node_ids(paths)
    if not on_path:
        return {"brokers": [], "message": "no external paths; nothing to rank"}
    return {"brokers": [b.model_dump() for b in queries.rank_brokers(5, on_path)]}


@_audited("propose_remediation")
def _propose_remediation(s: Session, args: dict) -> dict:
    plan = planner.choose(args["resource_id"])
    if plan is None:
        s.log.record("propose_remediation_none", result="no_external_blast_radius")
        return {"plan_id": None, "message": "no external blast radius; nothing to remediate"}
    plan_id = f"plan-{uuid.uuid4().hex[:6]}"
    s.plans[plan_id] = plan
    s.log.record(
        "propose_remediation", plan_id=plan_id, rationale=plan.rationale, **plan_fields(plan)
    )
    return {"plan_id": plan_id, **plan.model_dump()}


@_audited("simulate_remediation")
def _simulate_remediation(s: Session, args: dict) -> dict:
    plan = _plan(s, args["plan_id"])
    dr = dryrun.simulate(plan)
    s.dryruns[args["plan_id"]] = dr
    s.log.record("simulate_remediation", plan_id=args["plan_id"], **plan_fields(plan, dr))
    return {
        "plan_id": args["plan_id"],
        "before": summary(dr.before),
        "after": summary(dr.after),
        "paths_closed": [p.cypher_render() for p in dr.paths_closed],
        "collateral": dr.collateral,
    }


@_audited("request_approval")
def _request_approval(s: Session, args: dict) -> dict:
    plan = _plan(s, args["plan_id"])
    dr = s.dryruns.get(args["plan_id"])
    if dr is None:
        raise ToolError("call simulate_remediation for this plan before requesting approval")
    approval = s.approver(plan, dr)
    previous = s.approvals.get(args["plan_id"])
    if previous:
        apply.revoke_token(previous.token)
    if approval.approved:
        approval.token = apply.issue_token(plan)
    s.approvals[args["plan_id"]] = approval
    s.log.record(
        "request_approval",
        plan_id=args["plan_id"],
        approved=approval.approved,
        approved_by=approval.approver,
        approval_note=approval.note,
        result="approved" if approval.approved else "rejected",
    )
    return approval.model_dump()


@_audited("apply_remediation")
def _apply_remediation(s: Session, args: dict) -> dict:
    plan = _plan(s, args["plan_id"])
    out = apply.apply(plan, args["token"], s.log, s.dryruns.get(args["plan_id"]))
    if out["result"] != "applied":
        raise ToolError(f"apply {out['result']}: no change made to the live graph")
    out["blast_radius_now"] = summary(blast_radius.compute(plan.resource_id))
    return out


@_audited("write_audit")
def _write_audit(s: Session, args: dict) -> dict:
    fields: dict[str, Any] = {"summary": args["summary"]}
    if s.plans:
        fields["justifying_path"] = plan_fields(list(s.plans.values())[-1])["justifying_path"]
    s.log.record("write_audit", **fields)
    return {"ok": True, "audit_file": str(s.log.path)}


TOOLS = [
    tool(
        "get_finding_context",
        "Resolve the finding's resource by name. Call first; returns the resource id, type "
        "and sensitivity used by every other tool.",
        {"resource_name": str},
    )(_get_finding_context),
    tool(
        "find_reachers",
        "List every principal that can reach a resource, with hop count and the actions "
        "they'd use. Deterministic graph query; never guess reachability.",
        {"resource_id": str, "max_hops": int},
    )(_find_reachers),
    tool(
        "shortest_escalation_path",
        "Shortest path any external (untrusted) principal can walk to the resource, plus "
        "every external entry point.",
        {"resource_id": str},
    )(_shortest_escalation_path),
    tool(
        "rank_brokers",
        "Rank the roles/policies on external paths by betweenness centrality: which node "
        "is load-bearing for the exploit.",
        {"resource_id": str},
    )(_rank_brokers),
    tool(
        "propose_remediation",
        "Deterministically pick the single edge to cut and return a plan with a plan_id "
        "and the justifying paths.",
        {"resource_id": str},
    )(_propose_remediation),
    tool(
        "simulate_remediation",
        "Dry-run a plan on a copy of the graph; returns before/after blast radius, paths "
        "closed and collateral. Never touches the live graph.",
        {"plan_id": str},
    )(_simulate_remediation),
    tool(
        "request_approval",
        "Ask the human operator to approve a simulated plan. Returns approved, approver, "
        "note and, only if approved, the token apply_remediation needs.",
        {"plan_id": str},
    )(_request_approval),
    tool(
        "apply_remediation",
        "Apply an approved plan to the live graph. Requires the token from "
        "request_approval; refuses without it.",
        {"plan_id": str, "token": str},
    )(_apply_remediation),
    tool(
        "write_audit",
        "Append a final summary record to the audit log; the justifying path is attached "
        "automatically. Call once at the end of every investigation.",
        {"summary": str},
    )(_write_audit),
]

TOOL_NAMES = [f"mcp__iam__{t.name}" for t in TOOLS]


def server():
    return create_sdk_mcp_server(name="iam", version="1.0.0", tools=TOOLS)
