"""Measure a plan on a throwaway copy of the graph; the live graph is never touched."""

from severance.graph import queries
from severance.graph.client import graph_copy
from severance.models import DryRunResult, RemediationPlan
from severance.scoring import blast_radius
from severance.scoring.paths import escalation_paths


def simulate(plan: RemediationPlan) -> DryRunResult:
    rid = plan.resource_id
    before = blast_radius.compute(rid)
    _, before_paths = escalation_paths(rid)
    with graph_copy():
        if queries.delete_edge(plan.edge) == 0:
            raise LookupError(f"edge {plan.edge.model_dump()} not in graph")
        after = blast_radius.compute(rid)
        _, after_paths = escalation_paths(rid)
    remaining = {tuple(p.ids) for p in after_paths}
    return DryRunResult(
        before=before,
        after=after,
        paths_closed=[p for p in before_paths if tuple(p.ids) not in remaining],
        collateral=blast_radius.collateral(before, after),
    )
