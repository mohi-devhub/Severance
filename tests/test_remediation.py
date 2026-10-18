import pytest
from conftest import ALL_SCENARIOS

from severance.models import EdgeRef
from severance.remediation import planner

graph = pytest.mark.graph


def _c(edge_type, ext=0, closed=1, coll=(), broker=0.0, spec=0, f="a", t="b"):
    return planner.Candidate(
        edge=EdgeRef(from_id=f, type=edge_type, to_id=t),
        external_after=ext,
        closed=closed,
        collateral=list(coll),
        broker=broker,
        specificity=spec,
    )


def test_sort_key_order():
    leaves_ext = _c("GRANTS", ext=1, broker=99)
    lossy = _c("GRANTS", coll=["svc"], broker=99)
    weak_broker = _c("CAN_ASSUME", broker=1, spec=5)
    strong = _c("GRANTS", broker=9, spec=4)
    ranked = sorted([leaves_ext, lossy, weak_broker, strong], key=planner.sort_key)
    assert ranked == [strong, weak_broker, lossy, leaves_ext]


def test_specificity():
    assert planner.specificity(EdgeRef(from_id="a", type="CAN_ASSUME", to_id="b"), "broad") == 5
    assert planner.specificity(EdgeRef(from_id="a", type="CAN_ASSUME", to_id="b"), "internal") == 2
    assert planner.specificity(EdgeRef(from_id="a", type="TARGETS", to_id="b"), None) == 0


@graph
@pytest.mark.parametrize("seeded", ALL_SCENARIOS, indirect=True)
def test_planner(seeded):
    plan = planner.choose(seeded.target_resource_id)
    assert plan.edge == seeded.expected_fix_edge
    assert plan.justifying_paths[0].ids == seeded.expected_external_path_ids


@graph
@pytest.mark.parametrize("seeded", ["escalation_chain", "broker_policy"], indirect=True)
def test_planner_not_hop1(seeded):
    ids = seeded.expected_external_path_ids
    plan = planner.choose(seeded.target_resource_id)
    assert (plan.edge.from_id, plan.edge.to_id) != (ids[0], ids[1])


@graph
def test_planner_no_external_path():
    from severance.graph import queries
    from severance.graph.seeder import seed

    t = seed("public_bucket")
    queries.delete_edge(t.expected_fix_edge)
    assert planner.choose(t.target_resource_id) is None


def _plan_and_dryrun(t):
    from severance.remediation import dryrun

    plan = planner.choose(t.target_resource_id)
    return plan, dryrun.simulate(plan)


def _snapshot(t):
    from severance.graph import queries

    return queries.graph_counts(), [
        r.principal.id for r in queries.find_reachers(t.target_resource_id)
    ]


@graph
@pytest.mark.parametrize("seeded", ALL_SCENARIOS, indirect=True)
def test_dryrun(seeded):
    before = _snapshot(seeded)
    plan, dr = _plan_and_dryrun(seeded)
    assert dr.before.external_reacher_count >= 1
    assert dr.after.external_reacher_count == 0 and dr.after.shortest_external_hops is None
    assert dr.collateral == []
    assert [p.ids for p in dr.paths_closed] == [seeded.expected_external_path_ids]
    assert set(seeded.legit_reachers_after_fix) <= set(dr.after.internal_reacher_ids)
    assert _snapshot(seeded) == before  # live graph untouched


@graph
@pytest.mark.parametrize("seeded", ["escalation_chain"], indirect=True)
def test_apply_without_token_refuses(seeded):
    from severance.audit.log import AuditLog
    from severance.remediation import apply

    before = _snapshot(seeded)
    plan, dr = _plan_and_dryrun(seeded)
    log = AuditLog()
    assert apply.apply(plan, "forged", log, dr)["result"] == "refused"
    other = plan.model_copy(
        update={"edge": seeded.expected_fix_edge.model_copy(update={"to_id": "x"})}
    )
    assert apply.apply(plan, apply.issue_token(other), log, dr)["result"] == "refused"
    assert _snapshot(seeded) == before
    assert [r["result"] for r in log.records()] == ["refused", "refused"]


@graph
@pytest.mark.parametrize("seeded", ["escalation_chain"], indirect=True)
def test_apply_with_token_deletes_exactly_the_edge(seeded):
    from severance.audit.log import AuditLog
    from severance.graph import queries
    from severance.remediation import apply

    counts = queries.graph_counts()
    plan, dr = _plan_and_dryrun(seeded)
    log = AuditLog()
    token = apply.issue_token(plan)
    assert apply.apply(plan, token, log, dr) == {"result": "applied", "deleted": 1}
    assert queries.graph_counts() == {"nodes": counts["nodes"], "edges": counts["edges"] - 1}
    assert not queries.edge_exists(seeded.expected_fix_edge)
    assert queries.shortest_external_path(seeded.target_resource_id) is None
    assert apply.apply(plan, token, log, dr)["result"] == "refused"  # single use

    rec = log.records()[0]
    assert rec["result"] == "applied"
    assert rec["justifying_path"] == seeded.expected_external_path_ids
    assert rec["edge"] == seeded.expected_fix_edge.model_dump()
    assert rec["blast_radius_before"]["external_reachers"] == dr.before.external_reacher_count
    assert rec["blast_radius_after"] == {
        "reachers": dr.after.reacher_count,
        "external_reachers": 0,
        "shortest_external_hops": None,
        "severity": dr.after.severity,
    }


@graph
@pytest.mark.parametrize("seeded", ["public_bucket"], indirect=True)
def test_stale_apply_aborts(seeded):
    from severance.audit.log import AuditLog
    from severance.graph import queries
    from severance.remediation import apply

    plan, dr = _plan_and_dryrun(seeded)
    queries.delete_edge(plan.edge)  # graph drifts after the dry-run
    log = AuditLog()
    assert apply.apply(plan, apply.issue_token(plan), log, dr)["result"] == "stale_aborted"
    assert log.records()[0]["result"] == "stale_aborted"


def test_audit_refuses_unjustified_mutation():
    from severance.audit.log import AuditLog

    with pytest.raises(ValueError):
        AuditLog().record("apply_remediation", result="applied", justifying_path=[])
