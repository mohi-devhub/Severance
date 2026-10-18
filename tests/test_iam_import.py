import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from severance.graph import queries
from severance.graph.client import drop_graph, use_graph
from severance.graph.iam_import import policy_decision, project
from severance.public_bench import CASES, DATASET, _engine, _projection


@pytest.mark.parametrize(
    ("statement", "decision"),
    [
        ({"Effect": "Allow", "Action": "S3:put*", "Resource": "*"}, "allow"),
        ({"Effect": "Deny", "Action": "*", "Resource": "*"}, "deny"),
        ({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}, "implicit_deny"),
        (
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::other/*"},
            "implicit_deny",
        ),
        ({"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {}}, "unknown"),
        ({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}, "unknown"),
        ({"Effect": "Deny", "Action": "*", "NotResource": "arn:aws:s3:::other/*"}, "unknown"),
        (
            {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::${aws:username}/*"},
            "unknown",
        ),
    ],
)
def test_policy_subset(statement, decision):
    assert (
        policy_decision(
            {"Statement": statement}, "s3:PutObject", "arn:aws:s3:::mybucket/example.txt"
        )
        == decision
    )


def test_known_deny_overrides_conditional_allow():
    assert (
        policy_decision(
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {}},
                    {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
                ]
            },
            "s3:PutObject",
            "arn:aws:s3:::mybucket/example.txt",
        )
        == "deny"
    )


@pytest.fixture
def snapshot():
    return {
        "UserDetailList": [
            {
                "Arn": "arn:aws:iam::123456789012:user/test",
                "UserName": "test",
                "GroupList": ["team"],
                "AttachedManagedPolicies": [],
            }
        ],
        "GroupDetailList": [
            {
                "Arn": "arn:aws:iam::123456789012:group/team",
                "GroupName": "team",
                "AttachedManagedPolicies": [{"PolicyArn": "policy"}],
            }
        ],
        "RoleDetailList": [],
        "Policies": [
            {
                "Arn": "policy",
                "PolicyName": "policy",
                "DefaultVersionId": "v2",
                "PolicyVersionList": [
                    {
                        "VersionId": "v1",
                        "Document": {
                            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
                        },
                    },
                    {
                        "VersionId": "v2",
                        "Document": {
                            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
                        },
                    },
                ],
            }
        ],
    }


def _project(snapshot):
    return project(
        snapshot,
        "s3:PutObject",
        "arn:aws:s3:::mybucket/example.txt",
        snapshot["UserDetailList"][0]["Arn"],
    )


def test_group_inheritance_and_default_version(snapshot):
    assert _project(snapshot).report["untrusted_decision"] == "allow"


def test_user_deny_overrides_inherited_allow(snapshot):
    snapshot["UserDetailList"][0]["UserPolicyList"] = [
        {
            "PolicyName": "deny",
            "PolicyDocument": {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
        }
    ]
    p = _project(snapshot)
    assert p.report["untrusted_decision"] == "deny"
    user = snapshot["UserDetailList"][0]["Arn"]
    assert not [edge for edge in p.builder.edges if edge[0] == user]


@pytest.mark.parametrize("problem", ["boundary", "missing_policy", "missing_group", "condition"])
def test_unknown_identity_is_rejected(snapshot, problem):
    user = snapshot["UserDetailList"][0]
    if problem == "boundary":
        user["PermissionsBoundary"] = {"PermissionsBoundaryArn": "boundary"}
    elif problem == "missing_policy":
        user["AttachedManagedPolicies"] = [{"PolicyArn": "missing"}]
    elif problem == "missing_group":
        user["GroupList"].append("missing")
    else:
        snapshot["Policies"][0]["PolicyVersionList"][1]["Document"]["Statement"][0][
            "Condition"
        ] = {}
    with pytest.raises(ValueError, match="cannot be assessed"):
        _project(snapshot)


def test_partial_snapshot_rejected(snapshot):
    snapshot["IsTruncated"] = True
    with pytest.raises(ValueError, match="incomplete"):
        _project(snapshot)


def test_source_checksum():
    provenance = json.loads(DATASET.with_name("provenance.json").read_text())
    assert hashlib.sha256(DATASET.read_bytes()).hexdigest() == provenance["sha256"]


@pytest.mark.graph
@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_public_snapshot_paths_fixes_and_dryruns(case):
    p = _projection(copy.deepcopy(case))
    with use_graph("iam_public_test"):
        try:
            p.write()
            before = queries.graph_counts()
            result = _engine(case, p)
            assert result["passed"], result
            assert queries.graph_counts() == before
        finally:
            drop_graph("iam_public_test")


@pytest.mark.graph
def test_concurrent_benchmarks_keep_independent_graphs(tmp_path, monkeypatch):
    from severance import public_bench

    monkeypatch.setattr(public_bench, "CASES", CASES[:1])

    def bench(index):
        path = tmp_path / f"parallel-{index}"
        assert public_bench.run(agent_runs=0, engine_runs=1, output=path, log=lambda _: None)
        return json.loads(path.with_suffix(".json").read_text())["benchmark_id"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(bench, range(2)))
    assert len(set(ids)) == 2
