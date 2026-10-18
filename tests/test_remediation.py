import pytest
from conftest import ALL_SCENARIOS

from bragent.models import EdgeRef
from bragent.remediation import planner

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
    from bragent.graph import queries
    from bragent.graph.seeder import seed

    t = seed("public_bucket")
    queries.delete_edge(t.expected_fix_edge)
    assert planner.choose(t.target_resource_id) is None
