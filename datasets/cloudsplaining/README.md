# Public IAM input and assessment cases

`example.json` is the unmodified example account-authorization file from
[Salesforce Cloudsplaining](https://github.com/salesforce/cloudsplaining/blob/f2ed0ba2ddf6457143203d46971c91ba236b6597/examples/files/example.json).
It contains 44 users, 5 groups, 78 roles, and 84 managed policies, plus inline
policies. The fixture combines training/example account data with historical
dates; it is not a verified production-account export or a current inventory.

The exact revision, SHA-256 and retrieval date are in [provenance.json](provenance.json).
The upstream BSD 3-Clause copyright and redistribution terms are retained in
[LICENSE](LICENSE). Source content is unchanged; findings and compromised-identity
assumptions are supplied separately by Severance.

## Independently specified expectations

The assertions in [public_bench.py](../../src/severance/public_bench.py) are derived
from these source records, before running the engine:

- **role_write:** `OverprivilegedEC2` attaches `InsecurePolicy`. Its default version
  allows `s3:PutObject` and `s3:PutObjectAcl` on `*`. Assume a session of this role
  is compromised. Detaching this policy closes the assessed write permission;
  the role's separate inline `SupYo` policy grants read, not write. The session
  adapter gives a four-edge explanation.
- **group_write / group_acl:** `privesc-sre-user` belongs to `privesc-sre-group`,
  which attaches `privesc-sre-admin-policy`. That policy allows `s3:*` on `*`.
  Assume this user is compromised. Removing this user's membership closes the
  assessed permission while preserving other supported callers. These paths
  span five edges, including the group's permission-carrier adapter.
- **role_write_rejected:** Same finding as role_write, but the approval callback
  rejects the change. Graph counts and all target reachers must remain unchanged.
- **explicit_deny:** `fp1-allow-and-deny-user` attaches `fp1-allow-and-deny`, whose
  default version both allows and denies `iam:*`. `iam:CreateAccessKey` must have
  no positive path and must produce no remediation or approval request.
- **split_policy_deny:** `fp2-allow-and-deny-multiple-policies-user` attaches both
  `fp2-allow-all` and `deny-all`. The latter's explicit deny must override the
  former's allow; no positive S3 write path or mutation is permitted.

The concrete request `arn:aws:s3:::mybucket/example.txt` instantiates the
`arn:aws:s3:::mybucket/*` pattern already present in the example's `NotYourPolicy`.
It does not assert that the bucket or object exists. The IAM control assesses the
user ARN already present in the snapshot.

## Import semantics and limits

Each import projects **one concrete action/resource permission request** from the
whole snapshot into FalkorDB. ARNs remain node IDs. Managed policies use only
`DefaultVersionId`; inline IDs include their owning ARN. User/group policy
attachments pass through an explicitly labeled permission-carrier `Role`. A
role-session `Principal` represents an assumed session of each source role.
These are schema adapters, not additional AWS roles, trusts, or policies.

The policy evaluator supports unconditional identity-policy allows and explicit
denies, wildcard actions/resources, and user group inheritance. Applicable
conditions, NotAction/NotResource, variables, boundaries, missing groups or missing
policy documents produce **unknown**. An unknown selected untrusted identity
aborts the import. Other unknown identities are listed in the report and omitted
from positive paths. A known explicit deny still takes precedence.

Role trust and assume-role transitions are not inferred. Resource policies,
SCPs/RCPs, session policies, cross-account authorization, service-specific resource
validation, and actual resource existence are outside this projection. Positive
paths mean identity-policy grants in the supported subset, not verified effective
AWS access. Collateral measures loss of the single assessed permission among
other supported identities; it does not measure all workloads or permissions.

See AWS's [policy evaluation documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
for the broader authorization model. Every remediation here changes only the
FalkorDB model. No AWS credentials, deployment, or AWS mutation is involved.
