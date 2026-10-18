import pytest
from conftest import ALL_SCENARIOS

from severance.graph import queries as q
from severance.graph.client import graph_copy
from severance.graph.seeder import seed

pytestmark = pytest.mark.graph


@pytest.mark.parametrize("seeded", ALL_SCENARIOS, indirect=True)
def test_counts_match_declared(seeded):
    assert q.graph_counts() == {"nodes": seeded.node_count, "edges": seeded.edge_count}


@pytest.mark.parametrize("name", ALL_SCENARIOS)
def test_idempotent(name):
    a = seed(name)
    first = q.graph_counts(), [r.principal.id for r in q.find_reachers(a.target_resource_id)]
    seed(name)
    assert (
        q.graph_counts(),
        [r.principal.id for r in q.find_reachers(a.target_resource_id)],
    ) == first


@pytest.mark.parametrize("seeded", ALL_SCENARIOS, indirect=True)
def test_planted_path_is_connected(seeded):
    ids = seeded.expected_external_path_ids
    for f, t in zip(ids, ids[1:], strict=False):
        rows = q.run_ro("MATCH ({id: $f})-[e]->({id: $t}) RETURN count(e) AS c", {"f": f, "t": t})
        assert rows[0]["c"] == 1, (f, t)
    reachers = {r.principal.id: r for r in q.find_reachers(seeded.target_resource_id)}
    assert reachers[ids[0]].kind == "external"


@pytest.mark.parametrize("seeded", ALL_SCENARIOS, indirect=True)
def test_fix_edge_cuts_external_keeps_legit(seeded):
    with graph_copy():
        assert q.delete_edge(seeded.expected_fix_edge) == 1
        reachers = q.find_reachers(seeded.target_resource_id)
        assert not [r for r in reachers if r.kind == "external"]
        assert set(seeded.legit_reachers_after_fix) <= {r.principal.id for r in reachers}
    assert q.edge_exists(seeded.expected_fix_edge)  # copy only
