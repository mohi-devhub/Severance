"""Choose the single edge to cut (docs/07).

Candidates are the edges on at least one shortest external path. Each is cut on
a throwaway graph copy and scored; the sort key below is the whole policy:

    1. fewest external reachers left          (does it actually close the exposure?)
    2. most shortest external paths closed
    3. least collateral (internal principals that lose access)
    4. highest broker score                   (load-bearing Role/Policy endpoint)
    5. highest specificity                    (closest to the misconfiguration)
    6. edge ids                               (stable final tie-break)
"""

from pydantic import BaseModel

from severance.graph import queries
from severance.graph.client import graph_copy
from severance.models import BlastRadius, EdgeRef, GraphPath, RemediationPlan
from severance.scoring import blast_radius
from severance.scoring.paths import escalation_paths, exploit_node_ids

ACTION_FOR_EDGE = {
    "CAN_ASSUME": "revoke_assume",
    "GRANTS": "detach_policy",
    "MEMBER_OF": "remove_member",
    "HAS_ROLE": "revoke_assume",
    "PERMITS": "restrict_action",
    "TARGETS": "restrict_action",
}
_SPECIFICITY = {"GRANTS": 4, "MEMBER_OF": 3, "HAS_ROLE": 2, "CAN_ASSUME": 2, "PERMITS": 1}


class Candidate(BaseModel):
    edge: EdgeRef
    external_after: int
    closed: int
    collateral: list[str]
    broker: float
    specificity: int


def candidate_edges(paths: list[GraphPath]) -> list[EdgeRef]:
    seen: dict[tuple, EdgeRef] = {}
    for p in paths:
        for e in p.edge_refs():
            seen.setdefault((e.from_id, e.type, e.to_id), e)
    return list(seen.values())


def specificity(edge: EdgeRef, to_trust: str | None) -> int:
    """CAN_ASSUME into a broad-trust role is the misconfiguration itself → highest."""
    if edge.type == "CAN_ASSUME" and to_trust == "broad":
        return 5
    return _SPECIFICITY.get(edge.type, 0)


def sort_key(c: Candidate) -> tuple:
    e = c.edge
    return (
        c.external_after,
        -c.closed,
        len(c.collateral),
        -c.broker,
        -c.specificity,
        (e.from_id, e.type, e.to_id),
    )


def score_candidates(resource_id: str) -> tuple[BlastRadius, list[GraphPath], list[Candidate]]:
    """Before-metrics, the external paths, and every candidate scored + sorted best first."""
    before = blast_radius.compute(resource_id, broker_limit=100)
    _, paths = escalation_paths(resource_id)
    broker = {b.node.id: b.score for b in before.top_brokers}
    trust = {n.id: n.kind for p in paths for n in p.nodes if n.label == "Role"}
    on_path = exploit_node_ids(paths)
    out = []
    for edge in candidate_edges(paths):
        with graph_copy():
            queries.delete_edge(edge)
            after = blast_radius.build(queries.find_reachers(resource_id), None, [], "low")
        out.append(
            Candidate(
                edge=edge,
                external_after=after.external_reacher_count,
                closed=sum(edge in p.edge_refs() for p in paths),
                collateral=blast_radius.collateral(before, after),
                broker=max(
                    (broker.get(n, 0.0) for n in (edge.from_id, edge.to_id) if n in on_path),
                    default=0.0,
                ),
                specificity=specificity(edge, trust.get(edge.to_id)),
            )
        )
    return before, paths, sorted(out, key=sort_key)


def _phrase(edge: EdgeRef, names: dict[str, str]) -> str:
    a, b = names.get(edge.from_id, edge.from_id), names.get(edge.to_id, edge.to_id)
    return {
        "CAN_ASSUME": f"Revoke assume-role: {a} can no longer assume {b}",
        "HAS_ROLE": f"Revoke role: {a} no longer holds {b}",
        "GRANTS": f"Detach policy {b} from role {a}",
        "MEMBER_OF": f"Remove {a} from group {b}",
        "PERMITS": f"Remove {b} from policy {a}",
        "TARGETS": f"Remove {b} from action {a}",
    }[edge.type]


def choose(resource_id: str) -> RemediationPlan | None:
    """The plan to cut, or None when no external principal reaches the resource."""
    before, paths, ranked = score_candidates(resource_id)
    if not ranked:
        return None
    best = ranked[0]
    names = {n.id: n.name for p in paths for n in p.nodes}
    closing = [p for p in paths if best.edge in p.edge_refs()]
    tie = sort_key(best)[:3]
    alternatives = [c.edge for c in ranked[1:2] if sort_key(c)[:3] == tie]
    rationale = (
        f"{_phrase(best.edge, names)}. Closes {best.closed} of {len(paths)} shortest "
        f"external path(s); {best.external_after} external reacher(s) remain; "
        f"collateral {len(best.collateral)}; broker score {best.broker:g}."
    )
    return RemediationPlan(
        action=ACTION_FOR_EDGE[best.edge.type],
        edge=best.edge,
        resource_id=resource_id,
        rationale=rationale,
        justifying_paths=closing,
        alternatives=alternatives,
    )
