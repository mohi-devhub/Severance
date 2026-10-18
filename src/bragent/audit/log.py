"""Append-only JSONL audit log, one file per run (docs/07)."""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bragent.config import settings
from bragent.models import BlastRadius, DryRunResult, RemediationPlan

# steps that describe or perform a mutation must carry the path that justified them
JUSTIFIED_STEPS = {"propose_remediation", "apply_remediation"}


def summary(b: BlastRadius) -> dict[str, Any]:
    return {
        "reachers": b.reacher_count,
        "external_reachers": b.external_reacher_count,
        "shortest_external_hops": b.shortest_external_hops,
        "severity": b.severity,
    }


def plan_fields(plan: RemediationPlan, dryrun: DryRunResult | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "action": plan.action,
        "edge": plan.edge.model_dump(),
        "justifying_path": plan.justifying_paths[0].ids if plan.justifying_paths else [],
    }
    if dryrun:
        out["blast_radius_before"] = summary(dryrun.before)
        out["blast_radius_after"] = summary(dryrun.after)
        out["collateral"] = dryrun.collateral
    return out


class AuditLog:
    def __init__(self, run_id: str | None = None, finding_id: str = "", resource: str = ""):
        self.run_id = run_id or f"run-{uuid.uuid4().hex[:6]}"
        self.finding_id = finding_id
        self.resource = resource
        self.path = Path(settings.audit_dir) / f"{self.run_id}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, step: str, **fields: Any) -> dict[str, Any]:
        if step in JUSTIFIED_STEPS and not fields.get("justifying_path"):
            raise ValueError(f"audit: {step} record without a justifying_path")
        rec = {
            "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "run_id": self.run_id,
            "step": step,
            "finding_id": self.finding_id,
            "resource": self.resource,
            **fields,
        }
        with self.path.open("a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        return rec

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines()]
