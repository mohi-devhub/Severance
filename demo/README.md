# Recorded working demo

[Watch the 90-second demo](blastradius-demo.mp4).

The video is a silent, annotated replay of a real `claude-sonnet-5-5` agent run,
recorded on October 18, 2026. Timing is stretched for readability. It shows the
working CLI, the actual MCP calls, graph-derived path and broker ranking,
`GRAPH.COPY` dry-run, explicit demo consent, application, and final audit evidence.

The agent performed the investigation in about 24 seconds on a synthetic graph
with 64 nodes and 71 edges. The exact timings are in [capture.json](capture.json).
The terminal output is in [transcript.txt](transcript.txt), with trailing terminal
padding removed; the capture retains the original events. Its [audit](audit.jsonl)
retains every recorded step; only the consumed single-use approval token is redacted.
[evidence.json](evidence.json) extracts the original path, edge, and measured effects.

The demo uses its own `iam_demo` graph. It makes no cloud API calls. The approval
shown is the CLI's explicit demo auto-approval, not an interactive human decision.
The application also has live approve/reject integration tests for the MCP loop.

## Re-record the application

From the repository root, with FalkorDB running and a configured Claude key/model:

```bash
.venv/bin/python demo/record.py
.venv/bin/python demo/video/build.py
```

Recording runs one paid agent investigation and updates the transcript, capture,
and redacted audit. Building reads those files and regenerates the composition and
evidence summary without calling a model.

## Rebuild the video

Requires Node.js 22+, FFmpeg, and a Chromium browser supported by HyperFrames.
The core Python application does not depend on these video tools.

```bash
cd demo/video
npm run check -- --strict
npm run dev
# After reviewing the preview:
npm run render -- --quality delivery --fps 24 --output ../blastradius-demo.mp4
```

The composition pins HyperFrames 0.8.171 in `package.json`. Its fonts are embedded
by the compiler at build time. It uses one paused, seek-safe timeline; no model,
network API, clock, or randomness supplies the rendered terminal state.

The terminal layout and discrete-output approach adapt HyperFrames'
`code-terminal-run` registry component. The original component is retained under
`video/compositions/components/` as a reference. The composition contains actual
recorded output, rather than the component's sample build-tool text.
