"""The Claude Agent SDK loop with the approval callback wired in (docs/06)."""

from collections.abc import Callable
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
)
from pydantic import BaseModel

from bragent.agent import tools
from bragent.agent.prompts import render_finding_prompt, write_prompt_file
from bragent.audit.log import AuditLog
from bragent.config import settings
from bragent.models import Finding


class RunResult(BaseModel):
    run_id: str
    audit_path: str
    final_text: str
    success: bool
    applied: bool
    records: list[dict[str, Any]]


def options() -> ClaudeAgentOptions:
    return ClaudeAgentOptions(
        system_prompt={"type": "file", "path": str(write_prompt_file())},
        mcp_servers={"iam": tools.server()},
        tools=[],  # no built-in tools: only the iam server
        allowed_tools=tools.TOOL_NAMES,
        strict_mcp_config=True,
        setting_sources=[],  # don't inherit the operator's Claude Code settings/hooks
        model=settings.model,
        max_turns=24,
    )


async def run(
    finding: Finding,
    approver: tools.Approver = tools.reject_all,
    on_text: Callable[[str], None] | None = None,
    on_result: Callable[[str, Any], None] | None = None,
) -> RunResult:
    log = AuditLog(finding_id=finding.id, resource=finding.resource_name)
    log.record("triage", finding=finding.model_dump())
    token = tools.start_session(
        tools.Session(finding=finding, approver=approver, log=log, on_result=on_result)
    )
    final, success = "", False
    try:
        async with ClaudeSDKClient(options=options()) as client:
            await client.query(render_finding_prompt(finding))
            async for msg in client.receive_response():
                if isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, TextBlock) and on_text:
                            on_text(block.text)
                elif isinstance(msg, ResultMessage):
                    success = msg.subtype == "success"
                    final = msg.result or ""
    finally:
        tools._session.reset(token)
    records = log.records()
    applied = any(
        r["step"] == "apply_remediation" and r.get("result") == "applied" for r in records
    )
    log.record("run_end", success=success, applied=applied)
    return RunResult(
        run_id=log.run_id,
        audit_path=str(log.path),
        final_text=final,
        success=success,
        applied=applied,
        records=log.records(),
    )
