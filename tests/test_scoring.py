"""Pure-function scoring tests: canned rows, no DB."""

from severance.models import BlastRadius, GraphPath, NodeRef, Reacher
from severance.scoring import blast_radius as br
from severance.scoring.paths import exploit_node_ids


def _r(pid: str, kind: str, hops: int) -> Reacher:
    return Reacher(
        principal=NodeRef(id=pid, label="Principal", name=pid, kind=kind),
        kind=kind,
        hops=hops,
        via_actions=["s3:PutObject"],
    )


def _path() -> GraphPath:
    nodes = [
        NodeRef(id="ext", label="Principal", name="anon", kind="external"),
        NodeRef(id="role", label="Role", name="ci"),
        NodeRef(id="pol", label="Policy", name="P"),
        NodeRef(id="act", label="Action", name="s3:PutObject"),
        NodeRef(id="res", label="Resource", name="bucket", kind="bucket"),
    ]
    return GraphPath(nodes=nodes, edges=["CAN_ASSUME", "GRANTS", "PERMITS", "TARGETS"], length=4)


def test_proximity():
    assert br.proximity(None) == 0
    assert br.proximity(2) == 6
    assert br.proximity(12) == 0


def test_severity_hand_computed():
    # 3*4 (critical) + 2*min(3,10) + 2*(8-4) = 12 + 6 + 8
    assert br.severity("critical", 3, 4) == 26
    # 3*1 + 2*10 (capped) + 0
    assert br.severity("low", 50, None) == 23


def test_build_blast_radius():
    reachers = [_r("ext", "external", 4), _r("svc", "service", 4), _r("u", "user", 5)]
    b = br.build(reachers, _path(), [], "high")
    assert (b.reacher_count, b.external_reacher_count, b.shortest_external_hops) == (3, 1, 4)
    assert b.severity == 3 * 3 + 2 * 1 + 2 * 4
    assert b.internal_reacher_ids == ["svc", "u"]


def test_build_no_external():
    b = br.build([_r("svc", "service", 4)], None, [], "medium")
    assert b.external_reacher_count == 0 and b.shortest_external_hops is None
    assert b.severity == 6


def test_collateral_only_internal_losses():
    def b(ids):
        return BlastRadius(
            reacher_count=len(ids),
            external_reacher_count=0,
            shortest_external_path=None,
            shortest_external_hops=None,
            top_brokers=[],
            internal_reacher_ids=ids,
        )

    assert br.collateral(b(["svc", "u"]), b(["u"])) == ["svc"]


def test_exploit_node_ids():
    assert exploit_node_ids([_path()]) == {"role", "pol"}


def test_render():
    assert _path().cypher_render().startswith("(anon:external) -[CAN_ASSUME]-> (ci:Role)")
