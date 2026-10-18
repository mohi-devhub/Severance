"""Drive the tool layer in the agent's order without an LLM (scripted 'model')."""

import asyncio
import json

import pytest

from severance.agent import tools
from severance.audit.log import AuditLog
from severance.graph import queries
from severance.models import Approval

pytestmark = pytest.mark.graph
BY_NAME = {t.name: t.handler for t in tools.TOOLS}


def call(name, **args):
    out = asyncio.run(BY_NAME[name](args))
    return out.get("is_error", False), json.loads(
        out["content"][0]["text"].removeprefix("error: ")
    ) if not out.get("is_error") else out["content"][0]["text"]


def _session(truth, approve: bool):
    def approver(plan, dr):
        return Approval(approved=approve, approver="test", note="stub")

    log = AuditLog(finding_id=truth.finding.id, resource=truth.finding.resource_name)
    return tools.start_session(tools.Session(finding=truth.finding, approver=approver, log=log))


@pytest.mark.parametrize("seeded", ["escalation_chain"], indirect=True)
def test_scripted_happy_path(seeded):
    tok = _session(seeded, approve=True)
    _, ctx = call("get_finding_context", resource_name="prod-db")
    rid = ctx["resource"]["id"]
    _, reach = call("find_reachers", resource_id=rid, max_hops=6)
    assert reach["external_reacher_count"] == 1
    _, path = call("shortest_escalation_path", resource_id=rid)
    assert [n["id"] for n in path["primary"]["nodes"]] == seeded.expected_external_path_ids
    _, plan = call("propose_remediation", resource_id=rid)
    pid = plan["plan_id"]

    err, msg = call("request_approval", plan_id=pid)
    assert err and "simulate_remediation" in msg  # dry-run is mandatory before approval

    _, dr = call("simulate_remediation", plan_id=pid)
    assert dr["after"]["external_reachers"] == 0 and dr["collateral"] == []
    err, _ = call("apply_remediation", plan_id=pid, token="forged")
    assert err and queries.edge_exists(seeded.expected_fix_edge)

    _, appr = call("request_approval", plan_id=pid)
    _, applied = call("apply_remediation", plan_id=pid, token=appr["token"])
    assert applied["result"] == "applied" and applied["blast_radius_now"]["external_reachers"] == 0
    call("write_audit", summary="fixed")
    log = tools._session.get().log
    tools._session.reset(tok)

    steps = [r["step"] for r in log.records()]
    assert {"propose_remediation", "simulate_remediation", "request_approval"} <= set(steps)
    assert [r["result"] for r in log.records() if r["step"] == "apply_remediation"] == [
        "refused",
        "applied",
    ]
    final = [r for r in log.records() if r["step"] == "write_audit"]
    assert final[0]["justifying_path"] == seeded.expected_external_path_ids


@pytest.mark.parametrize("seeded", ["broker_policy"], indirect=True)
def test_scripted_reject(seeded):
    tok = _session(seeded, approve=False)
    before = queries.graph_counts()
    _, plan = call("propose_remediation", resource_id=seeded.target_resource_id)
    call("simulate_remediation", plan_id=plan["plan_id"])
    _, appr = call("request_approval", plan_id=plan["plan_id"])
    assert appr == {"approved": False, "approver": "test", "note": "stub", "token": ""}
    err, _ = call("apply_remediation", plan_id=plan["plan_id"], token="")
    tools._session.reset(tok)
    assert err and queries.graph_counts() == before


@pytest.mark.parametrize("seeded", ["public_bucket"], indirect=True)
def test_unknown_resource_is_error(seeded):
    tok = _session(seeded, approve=False)
    err, msg = call("get_finding_context", resource_name="nope")
    tools._session.reset(tok)
    assert err and "nope" in msg


@pytest.mark.parametrize("seeded", ["public_bucket"], indirect=True)
def test_rejection_revokes_previous_consent(seeded):
    tok = _session(seeded, approve=True)
    try:
        _, plan = call("propose_remediation", resource_id=seeded.target_resource_id)
        pid = plan["plan_id"]
        call("simulate_remediation", plan_id=pid)
        _, approval = call("request_approval", plan_id=pid)
        tools._session.get().approver = tools.reject_all
        _, rejected = call("request_approval", plan_id=pid)
        assert not rejected["approved"]
        err, _ = call("apply_remediation", plan_id=pid, token=approval["token"])
        assert err and queries.edge_exists(seeded.expected_fix_edge)
    finally:
        tools._session.reset(tok)
