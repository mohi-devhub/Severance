"""Live-graph mutation, gated on an approval token bound to the exact plan.

Tokens are single-use uuids held in process memory and keyed to a hash of the
plan's edge + resource. Their job is to make "apply without approval"
structurally impossible, not to be cryptographically serious.
"""

import hashlib
import uuid
from typing import Any, Literal

from bragent.audit.log import AuditLog, plan_fields
from bragent.graph import queries
from bragent.models import DryRunResult, RemediationPlan

_issued: dict[str, str] = {}

Result = Literal["applied", "refused", "stale_aborted"]


def _plan_key(plan: RemediationPlan) -> str:
    return hashlib.sha256(f"{plan.resource_id}|{plan.edge.model_dump_json()}".encode()).hexdigest()


def issue_token(plan: RemediationPlan) -> str:
    """Mint a token for an approved plan. Only the approval path calls this."""
    token = uuid.uuid4().hex
    _issued[token] = _plan_key(plan)
    return token


def apply(
    plan: RemediationPlan,
    token: str,
    log: AuditLog,
    dryrun: DryRunResult | None = None,
) -> dict[str, Any]:
    fields = plan_fields(plan, dryrun)
    if _issued.get(token) != _plan_key(plan):
        log.record("apply_remediation", result="refused", reason="no valid token", **fields)
        return {"result": "refused", "deleted": 0}
    del _issued[token]
    deleted = queries.delete_edge(plan.edge)
    result: Result = "applied" if deleted else "stale_aborted"
    log.record("apply_remediation", result=result, deleted=deleted, **fields)
    return {"result": result, "deleted": deleted}
