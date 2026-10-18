# Public IAM snapshot benchmark

Model: `claude-sonnet-5-5`. Started: 2026-10-18T11:44:56.219847+00:00.

Source: Cloudsplaining `example.json`, commit `f2ed0ba2ddf6457143203d46971c91ba236b6597`.
SHA-256: `fb6f8b80e967606462ca189912996fc0e66b26c3f34a06514512d7d6e5bda610`.

Offline identity-policy projections; manually specified compromised identities.
These are external example fixtures, not production accounts or live AWS checks.

| case | graph nodes / edges | engine passes | agent passes | hops | external before → simulated after | collateral | median path ms | median planner ms |
|---|---|---|---|---|---|---|---|---|
| role_write | 379 / 43 | 5/5 | 1/1 | 4 | 1 → 0 | 0 | 0.816 | 622.301 |
| group_write | 379 / 43 | 5/5 | 1/1 | 5 | 1 → 0 | 0 | 1.475 | 512.315 |
| group_acl | 379 / 47 | 5/5 | 1/1 | 5 | 1 → 0 | 0 | 1.865 | 509.559 |
| role_write_rejected | 379 / 43 | 5/5 | 1/1 | 4 | 1 → 0 | 0 | 2.786 | 400.225 |
| explicit_deny | 379 / 40 | 5/5 | 1/1 | none | 0 → 0 | 0 | 0.379 | 1.634 |
| split_policy_deny | 379 / 43 | 5/5 | 1/1 | none | 0 → 0 | 0 | 0.547 | 1.863 |

Each engine repetition checks an independently specified exact path/fix and dry-run effects. Each agent run imports a fresh graph and uses the real MCP loop.
Approved cases must delete exactly one graph edge and close untrusted reachability; rejection and explicit-deny controls must leave the graph unchanged.

Full per-call checks, raw agent summaries, tool outputs, redacted audit records, import coverage and unknown identities are in the companion JSON.

Limitations: one action/resource request per projection; no role-trust transitions, resource policies, SCPs/RCPs or session policies. Relevant conditions, negations, policy variables, missing documents and permissions boundaries produce unknown. Unknown identities are excluded, never counted as proven denies. Collateral covers other supported callers of the assessed permission only. No AWS mutation. This is a small fixture benchmark, not a production accuracy estimate.
