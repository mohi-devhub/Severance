import pytest

from bragent.config import settings

settings.graph_name = "iam_test"
settings.audit_dir = "audit/test"


def _db_up() -> bool:
    try:
        from bragent.graph.client import db

        return db().connection.ping()
    except Exception:
        return False


def pytest_collection_modifyitems(config, items):
    if not _db_up():
        skip = pytest.mark.skip(reason="FalkorDB not reachable")
        for item in items:
            if "graph" in item.keywords:
                item.add_marker(skip)


@pytest.fixture
def seeded(request):
    """Seed the test graph with a scenario (param = scenario name) → ScenarioTruth."""
    from bragent.graph.seeder import seed

    return seed(request.param)


ALL_SCENARIOS = ["public_bucket", "escalation_chain", "broker_policy", "exposed_secret"]
