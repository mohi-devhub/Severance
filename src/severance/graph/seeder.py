"""Synthetic cloud generator with planted, known vulnerabilities (docs/03).

Each scenario = deterministic decoy org + one planted exploit, plus a
`ScenarioTruth` that tests and the benchmark assert against.

Action nodes are scoped per resource (`id = "<action>@<resource_id>"`, `name` is
the bare action string). With one global node per action string, any policy
permitting `s3:GetObject` would appear to reach every bucket.
"""

import random
from collections.abc import Callable

from pydantic import BaseModel

from severance.graph.builder import GraphBuilder as _Builder
from severance.graph.queries import wipe
from severance.graph.schema import ensure_indexes
from severance.models import EdgeRef, Finding

_ACTIONS = {
    "bucket": [("s3:GetObject", "read"), ("s3:PutObject", "write")],
    "database": [("rds:Describe", "read"), ("rds:ExecuteStatement", "write")],
    "cluster": [("eks:DescribeCluster", "read"), ("eks:AccessKubernetesApi", "admin")],
    "secret": [("secretsmanager:DescribeSecret", "read")],
    "queue": [("sqs:ReceiveMessage", "read"), ("sqs:SendMessage", "write")],
}
_SENS = ["low", "medium", "high", "critical"]


class ScenarioTruth(BaseModel):
    name: str
    finding: Finding
    target_resource_id: str
    expected_external_path_ids: list[str]
    expected_fix_edge: EdgeRef
    legit_reachers_after_fix: list[str]
    expected_broker_id: str
    node_count: int
    edge_count: int


def _baseline(b: _Builder, rng: random.Random, scale: int) -> None:
    """Plausible decoy org, wired only among itself so planted truth stays exact."""
    res = []
    for i in range(6 * scale):
        rtype = rng.choice(list(_ACTIONS))
        res.append(
            (b.resource(f"res-d{i:04d}", f"{rtype}-{i:04d}", rtype, rng.choice(_SENS)), rtype)
        )
    pols = []
    for i in range(6 * scale):
        pid = b.policy(f"pol-d{i:04d}", f"DecoyPolicy{i:04d}", managed=rng.random() < 0.6)
        for rid, rtype in rng.sample(res, 2):
            name, access = rng.choice(_ACTIONS[rtype])
            b.edge(pid, "PERMITS", b.action(name, rid, access))
        pols.append(pid)
    roles = []
    for i in range(5 * scale):
        rid = b.role(f"role-d{i:04d}", f"decoy-role-{i:04d}")
        for pid in rng.sample(pols, 2):
            b.edge(rid, "GRANTS", pid)
        roles.append(rid)
    for i in range(1, len(roles)):  # a few assume chains, acyclic (lower → higher index)
        if rng.random() < 0.3:
            b.edge(roles[rng.randrange(i)], "CAN_ASSUME", roles[i])
    groups = []
    for i in range(3 * scale):
        gid = b.principal(f"grp-d{i:04d}", f"team-{i:04d}", "group")
        b.edge(gid, "HAS_ROLE", rng.choice(roles))
        groups.append(gid)
    for i in range(20 * scale):
        if rng.random() < 0.2:
            sid = b.principal(f"svc-d{i:04d}", f"service-{i:04d}", "service")
            b.edge(sid, "HAS_ROLE", rng.choice(roles))
        else:
            uid = b.principal(f"u-d{i:04d}", f"user-{i:04d}", "user")
            b.edge(uid, "MEMBER_OF", rng.choice(groups))
    # an external with harmless reach (decoy resources only)
    b.edge(b.principal("ext-d-partner", "partner-readonly", "external"), "HAS_ROLE", roles[0])


def _public_bucket(b: _Builder) -> dict:
    res = b.resource("res-prod-artifacts", "prod-artifacts", "bucket", "high")
    ci = b.role("role-ci", "ci-deployer", trust="broad")
    pol = b.policy("pol-ci-deploy", "CIDeployAccess", managed=False)
    put = b.action("s3:PutObject", res, "write")
    b.edge(ci, "GRANTS", pol)
    b.edge(pol, "PERMITS", put)
    anon = b.principal("ext-anon", "anon", "external")
    b.edge(anon, "CAN_ASSUME", ci)
    svc = b.principal("svc-ci", "ci-runner", "service")
    b.edge(svc, "HAS_ROLE", ci)
    reader = b.role("role-artifacts-reader", "artifacts-reader")
    rpol = b.policy("pol-artifacts-read", "ArtifactsReadOnly")
    b.edge(reader, "GRANTS", rpol)
    b.edge(rpol, "PERMITS", b.action("s3:GetObject", res, "read"))
    grp = b.principal("grp-data-eng", "data-eng", "group")
    b.edge(grp, "HAS_ROLE", reader)
    for i in range(3):
        b.edge(b.principal(f"u-de-{i}", f"data-eng-{i}", "user"), "MEMBER_OF", grp)
    return dict(
        finding=Finding(
            id="find-public-bucket",
            kind="public_write",
            resource_name="prod-artifacts",
            description="Public write access on S3 bucket prod-artifacts.",
        ),
        target=res,
        path=[anon, ci, pol, put, res],
        fix=EdgeRef(from_id=anon, type="CAN_ASSUME", to_id=ci),
        legit=[svc, grp, "u-de-0", "u-de-1", "u-de-2"],
        broker=pol,
    )


def _escalation_chain(b: _Builder) -> dict:
    db = b.resource("res-prod-db", "prod-db", "database", "critical")
    logs = b.resource("res-audit-logs", "audit-logs", "bucket", "medium")
    guest = b.principal("ext-guest", "guest", "external")
    build = b.role("role-build", "build-role")
    deploy = b.role("role-deploy", "deploy-role")
    admin = b.role("role-admin", "admin-role")
    iam = b.policy("pol-iam-full", "IAMFullAccess")
    attach = b.action("iam:AttachRolePolicy", db, "admin")
    b.edge(guest, "CAN_ASSUME", build)
    b.edge(build, "CAN_ASSUME", deploy)
    b.edge(deploy, "CAN_ASSUME", admin)
    b.edge(admin, "GRANTS", iam)
    b.edge(iam, "PERMITS", attach)
    ops = b.policy("pol-admin-ops", "AdminOps")
    b.edge(admin, "GRANTS", ops)
    b.edge(ops, "PERMITS", b.action("s3:GetObject", logs, "read"))
    b.edge(ops, "PERMITS", b.action("s3:PutObject", logs, "write"))
    # legitimate DBAs reach prod-db through their own role, not the escalation chain
    dba = b.role("role-dba", "dba-role")
    rds = b.policy("pol-rds-rw", "RDSReadWrite")
    b.edge(dba, "GRANTS", rds)
    b.edge(rds, "PERMITS", b.action("rds:ExecuteStatement", db, "write"))
    grp = b.principal("grp-dba", "dba-team", "group")
    b.edge(grp, "HAS_ROLE", dba)
    for name in ("alice", "bob"):
        uid = b.principal(f"u-{name}", name, "user")
        b.edge(uid, "MEMBER_OF", grp)
        b.edge(uid, "HAS_ROLE", admin)
    return dict(
        finding=Finding(
            id="find-escalation-chain",
            kind="overly_permissive",
            resource_name="prod-db",
            description="Guest identity can escalate to admin on database prod-db.",
        ),
        target=db,
        path=[guest, build, deploy, admin, iam, attach, db],
        fix=EdgeRef(from_id=admin, type="GRANTS", to_id=iam),
        legit=[grp, "u-alice", "u-bob"],
        broker=iam,
    )


def _broker_policy(b: _Builder) -> dict:
    db = b.resource("res-customer-db", "customer-db", "database", "critical")
    shared = b.policy("pol-db-shared", "SharedDBReadWrite")
    exe = b.action("rds:ExecuteStatement", db, "write")
    b.edge(shared, "PERMITS", exe)
    legit = []
    for rname in ("app", "analytics", "reporting"):
        rid = b.role(f"role-{rname}", f"{rname}-role")
        b.edge(rid, "GRANTS", shared)
        svc = b.principal(f"svc-{rname}", f"{rname}-service", "service")
        b.edge(svc, "HAS_ROLE", rid)
        legit.append(svc)
    grp = b.principal("grp-analysts", "analysts", "group")
    b.edge(grp, "HAS_ROLE", "role-analytics")
    legit.append(grp)
    for i in range(4):
        uid = b.principal(f"u-analyst-{i}", f"analyst-{i}", "user")
        b.edge(uid, "MEMBER_OF", grp)
        legit.append(uid)
    # the sandbox role is meant to be externally assumable; the bug is that it carries
    # the shared DB policy
    sandbox = b.role("role-sandbox", "sandbox-role", trust="broad")
    sbx_bucket = b.resource("res-sandbox", "vendor-sandbox", "bucket", "low")
    sbx_pol = b.policy("pol-sandbox", "SandboxBucketAccess")
    b.edge(sandbox, "GRANTS", sbx_pol)
    b.edge(sbx_pol, "PERMITS", b.action("s3:PutObject", sbx_bucket, "write"))
    b.edge(sandbox, "GRANTS", shared)
    vendor = b.principal("ext-vendor", "vendor-federated", "external")
    b.edge(vendor, "CAN_ASSUME", sandbox)
    return dict(
        finding=Finding(
            id="find-broker-policy",
            kind="overly_permissive",
            resource_name="customer-db",
            description="Over-shared managed policy grants write on critical customer-db.",
        ),
        target=db,
        path=[vendor, sandbox, shared, exe, db],
        fix=EdgeRef(from_id=sandbox, type="GRANTS", to_id=shared),
        legit=legit,
        broker=shared,
    )


def _exposed_secret(b: _Builder) -> dict:
    secret = b.resource("res-cluster-creds", "prod-cluster-creds", "secret", "critical")
    cluster = b.resource("res-prod-k8s", "prod-k8s", "cluster", "critical")
    batch = b.role("role-batch", "batch-service-role")
    pol = b.policy("pol-batch-secrets", "BatchSecretsRead")
    get = b.action("secretsmanager:GetSecretValue", secret, "read")
    b.edge(batch, "GRANTS", pol)
    b.edge(pol, "PERMITS", get)
    svc = b.principal("svc-batch", "batch-runner", "service")
    b.edge(svc, "HAS_ROLE", batch)
    ops = b.principal("grp-ops", "ops-team", "group")
    b.edge(ops, "HAS_ROLE", batch)
    users = []
    for i in range(3):
        uid = b.principal(f"u-ops-{i}", f"ops-{i}", "user")
        b.edge(uid, "MEMBER_OF", ops)
        users.append(uid)
    contractor = b.principal("ext-contractor", "contractor", "external")
    b.edge(contractor, "MEMBER_OF", ops)
    # the secret's payload: credentials for the prod cluster, used by a separate admin role
    k8s = b.role("role-k8s-admin", "k8s-admin")
    kpol = b.policy("pol-k8s-admin", "EKSAdmin")
    b.edge(k8s, "GRANTS", kpol)
    b.edge(kpol, "PERMITS", b.action("eks:AccessKubernetesApi", cluster, "admin"))
    b.edge(svc, "HAS_ROLE", k8s)
    return dict(
        finding=Finding(
            id="find-exposed-secret",
            kind="exposed_secret",
            resource_name="prod-cluster-creds",
            description="Secret prod-cluster-creds (unlocks prod-k8s) is readable from outside.",
        ),
        target=secret,
        path=[contractor, ops, batch, pol, get, secret],
        fix=EdgeRef(from_id=contractor, type="MEMBER_OF", to_id=ops),
        legit=[svc, ops, *users],
        broker=batch,
    )


SCENARIOS: dict[str, Callable[[_Builder], dict]] = {
    "public_bucket": _public_bucket,
    "escalation_chain": _escalation_chain,
    "broker_policy": _broker_policy,
    "exposed_secret": _exposed_secret,
}


def seed(scenario: str, seed: int = 1337, scale: int = 1) -> ScenarioTruth:
    """Wipe the active graph and rebuild `scenario`. Deterministic and idempotent."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; choose from {list(SCENARIOS)}")
    b = _Builder()
    _baseline(b, random.Random(seed), scale)
    planted = SCENARIOS[scenario](b)
    wipe()
    ensure_indexes()
    b.write()
    return ScenarioTruth(
        name=scenario,
        finding=planted["finding"],
        target_resource_id=planted["target"],
        expected_external_path_ids=planted["path"],
        expected_fix_edge=planted["fix"],
        legit_reachers_after_fix=planted["legit"],
        expected_broker_id=planted["broker"],
        node_count=b.node_count,
        edge_count=len(b.edges),
    )
