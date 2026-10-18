"""Import an action/resource projection of an AWS account-authorization snapshot.

This is identity-policy analysis, not an AWS effective-permissions simulator.
Role sessions and untrusted identity selection are explicit assessment assumptions.
Trust policies, resource policies, SCPs and session policies are not inferred.
"""

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from severance.graph import queries
from severance.graph.builder import GraphBuilder
from severance.graph.schema import ensure_indexes
from severance.models import Finding


def _list(value):
    return value if isinstance(value, list) else [value]


def _document(value: dict | str) -> dict:
    return value if isinstance(value, dict) else json.loads(unquote(value))


def _matches(pattern: str, value: str, *, ignore_case: bool = False) -> bool:
    # IAM supports * and ?, but not the [] character classes in fnmatch.
    pattern = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(pattern, value, re.I if ignore_case else 0) is not None


def policy_decision(document: dict, action: str, resource: str) -> str:
    """allow/deny/unknown/implicit_deny for the supported identity-policy subset."""
    allow, unknown = False, False
    for statement in _list(document.get("Statement", [])):
        actions = _list(statement.get("Action", []))
        resources = _list(statement.get("Resource", []))
        if "NotAction" not in statement and not any(
            _matches(a, action, ignore_case=True) for a in actions
        ):
            continue
        variable = any("${" in r for r in resources)
        if (
            not variable
            and "NotResource" not in statement
            and not any(_matches(r, resource) for r in resources)
        ):
            continue
        if variable or any(
            key in statement
            for key in ("Condition", "NotAction", "NotResource", "Principal", "NotPrincipal")
        ):
            unknown = True
            continue
        if statement.get("Effect") == "Deny":
            return "deny"
        if statement.get("Effect") == "Allow":
            allow = True
        else:
            unknown = True
    return "unknown" if unknown else "allow" if allow else "implicit_deny"


@dataclass
class Projection:
    builder: GraphBuilder
    finding: Finding
    target_id: str
    report: dict

    def write(self) -> dict:
        """Replace the active graph only after the entire import has validated."""
        queries.wipe()
        ensure_indexes()
        self.builder.write()
        return self.report


def project(snapshot: dict, action: str, resource_arn: str, untrusted_arn: str) -> Projection:
    """Project one permission request; preserve source ARNs and policy provenance.

    Users/groups have an explicit permission-carrier Role to fit the existing
    GRANTS spine. A session Principal represents each role, without inventing a
    trust relationship. An imported internal identity may be marked untrusted
    to model a compromised identity; it is not evidence of anonymous access.
    """
    if not action or any(c in action for c in "*?$") or ":" not in action:
        raise ValueError("action must be one concrete service:Action")
    if not resource_arn.startswith("arn:") or any(c in resource_arn for c in "*?$"):
        raise ValueError("resource must be a concrete ARN (use an example object key)")
    for key in ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"):
        if key not in snapshot or not isinstance(snapshot[key], list):
            raise ValueError(f"snapshot must contain a {key} list")
    if snapshot.get("IsTruncated") or snapshot.get("NextToken"):
        raise ValueError("snapshot is paginated/incomplete; export every page before importing")
    entities = {
        e["Arn"]: (kind, e)
        for key, kind in (
            ("UserDetailList", "user"),
            ("GroupDetailList", "group"),
            ("RoleDetailList", "role"),
        )
        for e in snapshot[key]
    }
    if untrusted_arn not in entities or entities[untrusted_arn][0] == "group":
        raise ValueError("untrusted ARN must identify a user or role in the snapshot")
    groups = {e["GroupName"]: e["Arn"] for e in snapshot["GroupDetailList"]}
    b = GraphBuilder()
    documents, names = {}, {}
    for policy in snapshot["Policies"]:
        versions = [
            v
            for v in policy.get("PolicyVersionList", [])
            if v.get("VersionId") == policy.get("DefaultVersionId")
        ]
        if len(versions) == 1:
            documents[policy["Arn"]] = _document(versions[0]["Document"])
            names[policy["Arn"]] = policy["PolicyName"]

    attached, missing = {}, {}
    for arn, (kind, entity) in entities.items():
        ids = [p["PolicyArn"] for p in entity.get("AttachedManagedPolicies", [])]
        for inline in entity.get(f"{kind.title()}PolicyList", []):
            pid = f"{arn}#inline/{inline['PolicyName']}"
            ids.append(pid)
            documents[pid] = _document(inline["PolicyDocument"])
            names[pid] = inline["PolicyName"]
        attached[arn] = ids
        missing[arn] = [pid for pid in ids if pid not in documents]

    decisions = {pid: policy_decision(doc, action, resource_arn) for pid, doc in documents.items()}
    outcomes = {}
    for arn, (kind, entity) in entities.items():
        inherited = []
        missing_groups = []
        if kind == "user":
            for group_name in entity.get("GroupList", []):
                if group_name in groups:
                    inherited.append(groups[group_name])
                else:
                    missing_groups.append(group_name)
        ids = sorted(set(attached[arn] + [p for g in inherited for p in attached[g]]))
        absent = sorted(set(missing[arn] + [p for g in inherited for p in missing[g]]))
        states = [decisions[pid] for pid in ids if pid in decisions]
        reasons = []
        if "deny" in states:
            state = "deny"
        elif entity.get("PermissionsBoundary") or absent or missing_groups or "unknown" in states:
            state = "unknown"
            if entity.get("PermissionsBoundary"):
                reasons.append("permissions boundary is not evaluated")
            if absent:
                reasons.append("missing policy documents")
            if missing_groups:
                reasons.append("missing group definitions")
            if "unknown" in states:
                reasons.append("relevant unsupported statement (conditions/negations/variables)")
        else:
            state = "allow" if "allow" in states else "implicit_deny"
        outcomes[arn] = {
            "decision": state,
            "reasons": reasons,
            "allow_policies": [p for p in ids if decisions.get(p) == "allow"],
            "missing_policies": absent,
            "inherited_groups": inherited,
        }

    if outcomes[untrusted_arn]["decision"] == "unknown":
        raise ValueError(
            "untrusted identity cannot be assessed: "
            + "; ".join(outcomes[untrusted_arn]["reasons"])
        )

    digest = hashlib.sha256(f"{action}\n{resource_arn}".encode()).hexdigest()[:16]
    target_id = f"permission:{digest}"
    target_name = f"{action} on {resource_arn}"
    b.resource(target_id, target_name, "permission_request", "high")
    aid = b.action(action, target_id, "write" if action.lower() != "s3:getobject" else "read")
    for pid, name in names.items():
        b.policy(pid, name, managed="#inline/" not in pid)
        if decisions[pid] == "allow":
            b.edge(pid, "PERMITS", aid, source_policy=pid)
    for arn, (kind, entity) in entities.items():
        name = entity[f"{kind.title()}Name"]
        carrier = arn if kind == "role" else f"permissions:{arn}"
        b.role(carrier, name if kind == "role" else f"{name} permissions")
        principal = f"session:{arn}" if kind == "role" else arn
        b.principal(
            principal,
            f"{name} session" if kind == "role" else name,
            "external" if arn == untrusted_arn else "service" if kind == "role" else kind,
        )
        if outcomes[arn]["decision"] != "allow":
            continue  # unresolved/denied identities never acquire a positive reach path
        b.edge(
            principal,
            "HAS_ROLE",
            carrier,
            source_arn=arn,
            mapping="role session" if kind == "role" else "identity permission carrier",
        )
        for pid in attached[arn]:
            if decisions.get(pid) == "allow":
                b.edge(carrier, "GRANTS", pid, source_arn=arn, source_policy=pid)
    for arn, (kind, _entity) in entities.items():
        if kind == "user" and outcomes[arn]["decision"] == "allow":
            for group in outcomes[arn]["inherited_groups"]:
                if outcomes[group]["decision"] == "allow":
                    b.edge(arn, "MEMBER_OF", group, source_arn=arn)

    report = {
        "source_counts": {
            k: len(snapshot[k])
            for k in ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")
        },
        "action": action,
        "resource_arn": resource_arn,
        "untrusted_arn": untrusted_arn,
        "untrusted_decision": outcomes[untrusted_arn]["decision"],
        "nodes": b.node_count,
        "edges": len(b.edges),
        "decision_counts": dict(Counter(o["decision"] for o in outcomes.values())),
        "identities": outcomes,
        "assumptions": [
            "Untrusted identity is an operator-selected compromised user or role session.",
            "Target is a concrete permission request, not evidence that a resource exists.",
            "Only identity policies are evaluated; "
            "no resource policies, SCPs/RCPs or session policies.",
            "Role trust/AssumeRole transitions are not imported or inferred.",
            "Unknown identities are excluded; counts cover the supported projection only.",
            "Permission carriers and role sessions are explicit schema adapters.",
            "Applying changes only FalkorDB, never AWS.",
        ],
    }
    finding = Finding(
        id=f"import-{digest}",
        kind="overly_permissive",
        resource_name=target_name,
        description=f"Assess {action} for an explicitly assumed compromised identity "
        f"{untrusted_arn}. "
        "This is an offline identity-policy projection, not verified live AWS access. "
        "Any remediation applies to the FalkorDB model only; unknown identities are excluded.",
    )
    return Projection(b, finding, target_id, report)


def load_projection(path: Path, action: str, resource_arn: str, untrusted_arn: str) -> Projection:
    raw = path.read_bytes()
    projection = project(json.loads(raw), action, resource_arn, untrusted_arn)
    projection.report["source_sha256"] = hashlib.sha256(raw).hexdigest()
    return projection
