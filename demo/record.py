"""Capture the real CLI and its audit trail for the submission demo.

Run from the repository root: .venv/bin/python demo/record.py
This makes one paid agent investigation, auto-approves only the synthetic demo,
and uses its own iam_demo graph. It never reads or prints credentials.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from severance.config import settings

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "demo"


def main() -> None:
    started = datetime.now(UTC)
    clock = time.monotonic()
    events = []
    env = {
        **os.environ,
        "GRAPH_NAME": "iam_demo",
        "AUDIT_DIR": "audit/demo",
        "COLUMNS": "110",
        "NO_COLOR": "1",
        "PYTHONUNBUFFERED": "1",
    }
    with tempfile.TemporaryFile(mode="w+") as stderr:
        process = subprocess.Popen(
            [sys.executable, "-m", "severance.cli.main", "demo"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            bufsize=1,
        )
        for line in process.stdout:
            print(line, end="", flush=True)
            events.append({"at": round(time.monotonic() - clock, 3), "text": line})
        if process.wait() != 0:
            raise RuntimeError("Demo failed; inspect the terminal output and audit/demo/")
    transcript = "".join(e["text"] for e in events)
    match = re.search(r"Audit record: (audit/demo/[^\s]+\.jsonl)", transcript)
    if not match:
        raise RuntimeError("Demo did not return an audit path")
    records = [json.loads(line) for line in (ROOT / match[1]).read_text().splitlines()]
    assert any(r["step"] == "apply_remediation" and r["result"] == "applied" for r in records)
    assert records[-1]["step"] == "run_end" and records[-1]["success"]
    for record in records:
        if "token" in record.get("inputs", {}):
            record["inputs"]["token"] = "REDACTED_SINGLE_USE_TOKEN"
    # Preserve all content; trim terminal-only right padding for source control.
    (OUT / "transcript.txt").write_text(
        "\n".join(line.rstrip() for line in transcript.splitlines()) + "\n"
    )
    (OUT / "audit.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    capture = {
        "kind": "actual_cli_capture",
        "started_at": started.isoformat(),
        "model": settings.model,
        "command": "GRAPH_NAME=iam_demo .venv/bin/severance demo",
        "approval": "Explicit demo auto-approval on synthetic data",
        "duration_seconds": round(time.monotonic() - clock, 3),
        "events": events,
    }
    (OUT / "capture.json").write_text(json.dumps(capture, indent=2) + "\n")
    print("Saved demo/transcript.txt, demo/capture.json and demo/audit.jsonl")


if __name__ == "__main__":
    main()
