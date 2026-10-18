"""Escalation paths: the primary (shortest) path and every external entry point."""

from bragent.graph import queries
from bragent.models import GraphPath

BROKER_LABELS = ("Role", "Policy")


def escalation_paths(resource_id: str) -> tuple[GraphPath | None, list[GraphPath]]:
    """(primary shortest external path, all shortest external paths)."""
    paths = queries.all_shortest_external_paths(resource_id)
    return (paths[0] if paths else None), paths


def exploit_node_ids(paths: list[GraphPath]) -> set[str]:
    """Roles/Policies on at least one external path: the broker candidates."""
    return {n.id for p in paths for n in p.nodes if n.label in BROKER_LABELS}
