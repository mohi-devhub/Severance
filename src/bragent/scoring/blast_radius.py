"""Blast-radius metric and severity formula (docs/05). Pure over query results."""

from bragent.config import settings
from bragent.graph import queries
from bragent.models import BlastRadius, Broker, GraphPath, Reacher
from bragent.scoring.paths import escalation_paths, exploit_node_ids

SENSITIVITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def proximity(hops: int | None, max_hops: int = settings.prox_max_hops) -> int:
    return 0 if hops is None else max(0, max_hops - hops)


def severity(sensitivity: str, external_reachers: int, shortest_hops: int | None) -> float:
    """w_sens·sens + w_ext·min(ext, CAP) + w_prox·proximity(hops)."""
    s = settings
    return (
        s.w_sens * SENSITIVITY_WEIGHT[sensitivity]
        + s.w_ext * min(external_reachers, s.ext_cap)
        + s.w_prox * proximity(shortest_hops, s.prox_max_hops)
    )


def build(
    reachers: list[Reacher],
    shortest: GraphPath | None,
    brokers: list[Broker],
    sensitivity: str,
) -> BlastRadius:
    ext = sum(r.kind == "external" for r in reachers)
    hops = shortest.length if shortest else None
    return BlastRadius(
        reacher_count=len(reachers),
        external_reacher_count=ext,
        shortest_external_path=shortest,
        shortest_external_hops=hops,
        top_brokers=brokers,
        internal_reacher_ids=[r.principal.id for r in reachers if r.kind != "external"],
        severity=severity(sensitivity, ext, hops),
    )


def collateral(before: BlastRadius, after: BlastRadius) -> list[str]:
    """Internal principals that reached before and no longer do."""
    return sorted(set(before.internal_reacher_ids) - set(after.internal_reacher_ids))


def compute(resource_id: str, broker_limit: int = 5) -> BlastRadius:
    """BlastRadius for a resource on the active graph."""
    res = queries.get_resource(resource_id)
    if res is None:
        raise LookupError(f"no resource {resource_id!r}")
    reachers = queries.find_reachers(resource_id)
    shortest, paths = escalation_paths(resource_id)
    on_path = exploit_node_ids(paths)
    brokers = queries.rank_brokers(broker_limit, on_path) if on_path else []
    return build(reachers, shortest, brokers, res.sensitivity)
