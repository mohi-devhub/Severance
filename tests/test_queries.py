import pytest
from conftest import ALL_SCENARIOS

from bragent.graph import queries as q
from bragent.models import EdgeRef

pytestmark = pytest.mark.graph


@pytest.mark.parametrize("seeded", ["escalation_chain"], indirect=True)
def test_find_reachers_escalation(seeded):
    r = q.find_reachers(seeded.target_resource_id)
    assert r[0].principal.id == "ext-guest"
    assert r[0].hops == len(seeded.expected_external_path_ids) - 1 == 6
    assert "iam:AttachRolePolicy" in r[0].via_actions
    assert sum(x.kind == "external" for x in r) == 1


def test_get_resource_by_name():
    seed_truth = __import__("bragent.graph.seeder", fromlist=["seed"]).seed("escalation_chain")
    res = q.get_resource_by_name("prod-db")
    assert res.id == seed_truth.target_resource_id and res.sensitivity == "critical"
    assert q.get_resource_by_name("nope") is None


@pytest.mark.parametrize("seeded", ALL_SCENARIOS, indirect=True)
def test_shortest_external_path_exact(seeded):
    p = q.shortest_external_path(seeded.target_resource_id)
    assert p.ids == seeded.expected_external_path_ids


@pytest.mark.parametrize("seeded", ALL_SCENARIOS, indirect=True)
def test_broker_in_top3(seeded):
    paths = q.all_shortest_external_paths(seeded.target_resource_id)
    on = {n.id for p in paths for n in p.nodes if n.label in ("Role", "Policy")}
    top = [b.node.id for b in q.rank_brokers(3, on)]
    assert seeded.expected_broker_id in top


@pytest.mark.parametrize("seeded", ["escalation_chain"], indirect=True)
def test_path_edges(seeded):
    edges = q.path_edges("ext-guest", seeded.target_resource_id)
    assert seeded.expected_fix_edge in edges and len(edges) == 6


def test_maxlen_validated():
    with pytest.raises(ValueError):
        q.find_reachers("x", maxlen=99)


@pytest.mark.parametrize("seeded", ["escalation_chain"], indirect=True)
def test_delete_edge_rejects_unknown_type(seeded):
    with pytest.raises(ValueError):
        q.delete_edge(EdgeRef.model_construct(from_id="a", type="DROP", to_id="b"))
