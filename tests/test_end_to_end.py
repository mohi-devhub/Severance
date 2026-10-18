"""Full agent loop through the Claude Agent SDK. Needs the Claude API.

Runs when ANTHROPIC_API_KEY is set or BRAGENT_RUN_AGENT=1 (e.g. a logged-in Claude Code).
"""

import asyncio
import os

import pytest

from bragent.agent import runner
from bragent.graph import queries
from bragent.models import Approval

pytestmark = [
    pytest.mark.graph,
    pytest.mark.agent,
    pytest.mark.skipif(
        not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("BRAGENT_RUN_AGENT")),
        reason="no Claude API credentials",
    ),
]


def _approver(ok: bool):
    return lambda plan, dr: Approval(approved=ok, approver="test-stub", note="e2e")


def _numbers_match_graph(records, truth):
    """No fabricated numbers: every audited before-number matches a direct query on a reseed."""
    from bragent.graph.seeder import seed
    from bragent.scoring import blast_radius

    seed(truth.name)
    direct = blast_radius.compute(truth.target_resource_id)
    for r in records:
        if "blast_radius_before" in r:
            b = r["blast_radius_before"]
            assert b["reachers"] == direct.reacher_count
            assert b["external_reachers"] == direct.external_reacher_count
            assert b["shortest_external_hops"] == direct.shortest_external_hops


@pytest.mark.parametrize("seeded", ["escalation_chain"], indirect=True)
def test_agent_auto_approve(seeded):
    res = asyncio.run(runner.run(seeded.finding, approver=_approver(True)))
    assert res.success and res.applied
    assert queries.find_reachers(seeded.target_resource_id)
    assert not [r for r in queries.find_reachers(seeded.target_resource_id) if r.kind == "external"]
    applied = [
        r for r in res.records if r["step"] == "apply_remediation" and r["result"] == "applied"
    ]
    assert applied[0]["edge"] == seeded.expected_fix_edge.model_dump()
    assert applied[0]["justifying_path"] == seeded.expected_external_path_ids
    _numbers_match_graph(res.records, seeded)


@pytest.mark.parametrize("seeded", ["escalation_chain"], indirect=True)
def test_rejected_approval_no_mutation(seeded):
    counts = queries.graph_counts()
    reach = [r.principal.id for r in queries.find_reachers(seeded.target_resource_id)]
    res = asyncio.run(runner.run(seeded.finding, approver=_approver(False)))
    assert not res.applied
    assert queries.graph_counts() == counts
    assert [r.principal.id for r in queries.find_reachers(seeded.target_resource_id)] == reach
    assert any(r.get("result") == "rejected" for r in res.records)
