"""Every Cypher query the system runs, as named functions with typed returns.

All data goes in through params. The only inlined values are code constants
(labels, edge types) and the range-checked hop bound, which FalkorDB cannot take
as a parameter in a var-length pattern (docs/04 §2).
"""

from bragent.config import settings
from bragent.graph.client import copy_graph, drop_graph, run_ro, run_rw  # noqa: F401
from bragent.graph.schema import REACH_EDGES
from bragent.models import EDGE_TYPES, Broker, EdgeRef, GraphPath, NodeRef, Reacher, ResourceRow

_NODE = "[n.id, labels(n)[0], coalesce(n.name, n.id), coalesce(n.kind, n.type, n.trust)]"


def _maxlen(maxlen: int) -> int:
    if not isinstance(maxlen, int) or not 2 <= maxlen <= 8:
        raise ValueError(f"maxlen must be an int in [2, 8], got {maxlen!r}")
    return maxlen


def _path(nodes: list[list], edges: list[str]) -> GraphPath:
    refs = [NodeRef(id=i, label=lab, name=name, kind=kind) for i, lab, name, kind in nodes]
    return GraphPath(nodes=refs, edges=edges, length=len(edges))


def get_resource_by_name(name: str) -> ResourceRow | None:
    rows = run_ro(
        "MATCH (r:Resource {name: $name}) "
        "RETURN r.id AS id, r.name AS name, r.type AS type, r.sensitivity AS sensitivity",
        {"name": name},
    )
    return ResourceRow(**rows[0]) if rows else None


def get_resource(resource_id: str) -> ResourceRow | None:
    rows = run_ro(
        "MATCH (r:Resource {id: $id}) "
        "RETURN r.id AS id, r.name AS name, r.type AS type, r.sensitivity AS sensitivity",
        {"id": resource_id},
    )
    return ResourceRow(**rows[0]) if rows else None


def find_reachers(resource_id: str, maxlen: int = settings.max_hops) -> list[Reacher]:
    """Every principal with a reach-spine path to the resource.

    `hops` is the full path length to the resource: the identity segment plus
    the fixed GRANTS -> PERMITS -> TARGETS tail (3 edges).
    """
    rows = run_ro(
        "MATCH (res:Resource {id: $rid})<-[:TARGETS]-(act:Action)"
        "<-[:PERMITS]-(:Policy)<-[:GRANTS]-(role:Role) "
        f"MATCH path = (p:Principal)-[:MEMBER_OF|HAS_ROLE|CAN_ASSUME*1..{_maxlen(maxlen)}]->(role) "
        "RETURN p.id AS id, p.name AS name, p.kind AS kind, "
        "min(length(path)) + 3 AS hops, collect(DISTINCT act.name) AS via_actions",
        {"rid": resource_id},
    )
    reachers = [
        Reacher(
            principal=NodeRef(id=r["id"], label="Principal", name=r["name"], kind=r["kind"]),
            kind=r["kind"],
            hops=r["hops"],
            via_actions=sorted(r["via_actions"]),
        )
        for r in rows
    ]
    return sorted(reachers, key=lambda r: (r.kind != "external", r.hops, r.principal.id))


def all_shortest_external_paths(resource_id: str) -> list[GraphPath]:
    """Every shortest path from each external principal to the resource (algo.SPpaths)."""
    rows = run_ro(
        "MATCH (ext:Principal {kind: 'external'}), (res:Resource {id: $rid}) "
        "CALL algo.SPpaths({sourceNode: ext, targetNode: res, relTypes: $rel_types, "
        "relDirection: 'outgoing', pathCount: 0}) "
        "YIELD path "
        f"RETURN [n IN nodes(path) | {_NODE}] AS nodes, "
        "[r IN relationships(path) | type(r)] AS edges",
        {"rid": resource_id, "rel_types": REACH_EDGES},
    )
    paths = [_path(r["nodes"], r["edges"]) for r in rows]
    return sorted(paths, key=lambda p: (p.length, p.ids))


def shortest_external_path(resource_id: str) -> GraphPath | None:
    """The fewest-hop path any external principal has to the resource (ties: by node ids)."""
    paths = all_shortest_external_paths(resource_id)
    return paths[0] if paths else None


def path_edges(external_id: str, resource_id: str) -> list[EdgeRef]:
    """Edges on the shortest paths from one external principal to the resource."""
    seen: dict[tuple, EdgeRef] = {}
    for p in all_shortest_external_paths(resource_id):
        if p.nodes[0].id == external_id:
            for e in p.edge_refs():
                seen.setdefault((e.from_id, e.type, e.to_id), e)
    return list(seen.values())


def rank_brokers(limit: int = 10, only_ids: set[str] | None = None) -> list[Broker]:
    """Betweenness over the reach subgraph, seeded → reproducible.

    algo.betweenness samples source nodes with replacement; 10x the node count makes
    a missed source unlikely (a 1x sample left the only external source unsampled).
    With `only_ids`, keep just those nodes (e.g. Roles/Policies on external paths).
    """
    # ponytail: O(10n·m); fine to ~10^3 nodes, pass an explicit sample size if it bites
    n = 10 * run_ro("MATCH (n) RETURN count(n) AS n")[0]["n"]
    rows = run_ro(
        "CALL algo.betweenness({relationshipTypes: $rel_types, samplingSize: $n, "
        "samplingSeed: 1337}) YIELD node, score "
        "WITH node AS n, score "
        f"RETURN {_NODE} AS node, score",
        {"rel_types": REACH_EDGES, "n": max(n, 1)},
    )
    brokers = [
        Broker(node=NodeRef(id=i, label=lab, name=name, kind=kind), score=r["score"])
        for r in rows
        for i, lab, name, kind in [r["node"]]
        if only_ids is None or i in only_ids
    ]
    return sorted(brokers, key=lambda b: (-b.score, b.node.id))[:limit]


def edge_exists(edge: EdgeRef) -> bool:
    rows = run_ro(
        "MATCH (a {id: $f})-[rel]->(b {id: $t}) WHERE type(rel) = $ty RETURN count(rel) AS c",
        {"f": edge.from_id, "t": edge.to_id, "ty": edge.type},
    )
    return rows[0]["c"] > 0


def delete_edge(edge: EdgeRef) -> int:
    """Delete one typed edge on the active graph. RW: dry-run copies and approved apply only."""
    if edge.type not in EDGE_TYPES:
        raise ValueError(f"unknown edge type {edge.type!r}")
    res = run_rw(
        "MATCH (a {id: $f})-[rel]->(b {id: $t}) WHERE type(rel) = $ty DELETE rel",
        {"f": edge.from_id, "t": edge.to_id, "ty": edge.type},
    )
    return int(res.relationships_deleted)


def graph_counts() -> dict[str, int]:
    nodes = run_ro("MATCH (n) RETURN count(n) AS c")[0]["c"]
    edges = run_ro("MATCH ()-[e]->() RETURN count(e) AS c")[0]["c"]
    return {"nodes": nodes, "edges": edges}


def wipe() -> None:
    run_rw("MATCH (n) DETACH DELETE n")
