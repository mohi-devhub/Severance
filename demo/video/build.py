"""Build the seek-safe demo composition from captured CLI/audit evidence."""

import json
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
capture = json.loads((HERE.parent / "capture.json").read_text())
audit = [json.loads(line) for line in (HERE.parent / "audit.jsonl").read_text().splitlines()]
started = datetime.fromisoformat(capture["started_at"])
plan = next(r for r in audit if r["step"] == "propose_remediation")
applied = next(r for r in audit if r["step"] == "apply_remediation" and r["result"] == "applied")
run_end = audit[-1]
assert run_end["success"] and run_end["applied"]

steps = [
    ("get_finding_context", "Resolve finding"),
    ("find_reachers", "Query reachability"),
    ("shortest_escalation_path", "Trace shortest paths"),
    ("rank_brokers", "Rank load-bearing nodes"),
    ("propose_remediation", "Choose a graph-based fix"),
    ("simulate_remediation", "Prove it on a copy"),
    ("request_approval", "Request consent"),
    ("apply_remediation", "Apply the approved edge"),
    ("write_audit", "Save the evidence"),
]
frames = [
    {
        "at": 0,
        "text": "A guest can escalate to admin on prod-db.\n\n"
        "The agent must find the path, prove a fix, and obtain approval.\n\n"
        "All IAM data in this demo is synthetic.\n\n$ " + capture["command"],
    }
]
output = "$ " + capture["command"] + "\n"
for event in capture["events"]:
    output += event["text"]
    frames.append(
        {
            "at": round(8 + event["at"] / capture["duration_seconds"] * 60, 3),
            "text": "\n".join(output.splitlines()[-25:]),
        }
    )
evidence = {
    "source": "demo/audit.jsonl",
    "run_id": run_end["run_id"],
    "model": capture["model"],
    "chosen_edge": plan["edge"],
    "justifying_path": plan["justifying_path"],
    "before": applied["blast_radius_before"],
    "after": applied["blast_radius_after"],
    "collateral": applied["collateral"],
    "result": applied["result"],
}
evidence_text = (
    "RECORDED AUDIT EVIDENCE\n\n"
    f"Source: {evidence['source']}\nRun: {evidence['run_id']}\nModel: {evidence['model']}\n\n"
    f"Edge removed: {plan['edge']['from_id']} -{plan['edge']['type']}-> {plan['edge']['to_id']}\n\n"
    f"External reachers: {applied['blast_radius_before']['external_reachers']} -> "
    f"{applied['blast_radius_after']['external_reachers']}\n"
    f"Total reachers: {applied['blast_radius_before']['reachers']} -> "
    f"{applied['blast_radius_after']['reachers']}\n"
    f"Severity: {applied['blast_radius_before']['severity']:g} -> "
    f"{applied['blast_radius_after']['severity']:g}\n"
    f"Internal principals losing access: {len(applied['collateral'])}\n\n"
    "Result: applied to the synthetic graph.\n"
    "Consent: explicit demo auto-approval.\n\n"
    "Source code, real transcript, raw audit and benchmark results are in the repository."
)
frames.append({"at": 70, "text": evidence_text})
tool_cues = []
for record in audit:
    if record["step"] == "tool_call" and not record["is_error"]:
        elapsed = (datetime.fromisoformat(record["ts"]) - started).total_seconds()
        tool_cues.append(
            {"at": max(8, 8 + elapsed / capture["duration_seconds"] * 60), "tool": record["tool"]}
        )

template = (HERE / "template.html.in").read_text()
step_html = "".join(
    f'<div class="step" id="step-{i}"><p class="step-label">{i + 1:02d} / {label}</p>'
    f'<p class="step-tool">{name}</p></div>'
    for i, (name, label) in enumerate(steps)
)
html = template.replace("__STEPS__", step_html)
html = html.replace("__FRAMES__", json.dumps(frames, ensure_ascii=False).replace("</", "<\\/"))
html = html.replace("__CUES__", json.dumps(tool_cues))
html = html.replace("__STEP_NAMES__", json.dumps([s[0] for s in steps]))
(HERE / "index.html").write_text(html)
(HERE.parent / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
print("Built a 90-second composition from the recorded CLI and audit.")
