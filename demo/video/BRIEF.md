---
workflow: general-video
flow: automation
storyboard: no
message: "A graph-backed agent proves its security fix before it applies it."
destination: hackathon-submission
aspect: 1920x1080
language: en
audience: Graph Hacks Track 01 judges
length: 90s
---

## Intent

Produce the working-project demo required by the hackathon rules, within the user's
instruction to make the project submission-ready. One terminal view replays a real
Sonnet investigation; a side rail identifies its actual MCP calls. The graph supplies
the path, ranking, dry-run and applied result. End on observed before/after evidence.

## Assets

- ../capture.json — timestamped real CLI output, recorded with demo/record.py.
- ../audit.jsonl — the same run's audit trail; single-use approval token redacted.
- ../transcript.txt — complete original terminal output.

## Notes

Autonomous production follows the user's instruction to finish all necessary work.
16:9, English captions, readable monospace, deliberate silence. Playback timing may
be stretched for readability and must be labelled as a replay. Synthetic data and
demo auto-approval must remain visible. No generated results, voice, logos or music.
The source-code repository remains private as explicitly requested.
