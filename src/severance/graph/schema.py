"""Labels, edge types and index DDL."""

from severance.graph.client import run_rw

LABELS = ("Principal", "Role", "Policy", "Action", "Resource")
REACH_EDGES = ["MEMBER_OF", "HAS_ROLE", "CAN_ASSUME", "GRANTS", "PERMITS", "TARGETS"]

INDEXES = [f"CREATE INDEX FOR (n:{label}) ON (n.id)" for label in LABELS] + [
    "CREATE INDEX FOR (n:Resource) ON (n.name)"
]


def ensure_indexes() -> None:
    for ddl in INDEXES:
        try:
            run_rw(ddl)
        except Exception as e:  # FalkorDB errors on an existing index
            if "already indexed" not in str(e):
                raise
