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
from bragent.agent.prompts import SYSTEM_PROMPT, render_finding_prompt
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
    error: str | None = None


def options() -> ClaudeAgentOptions:
    return ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        mcp_servers={"iam": tools.server()},
        tools=[],  # no built-in tools: only the iam server
        allowed_tools=tools.TOOL_NAMES,
        strict_mcp_config=True,
        setting_sources=[],  # don't inherit the operator's Claude Code settings/hooks
        model=settings.model,
        env={"ANTHROPIC_API_KEY": settings.anthropic_api_key} if settings.anthropic_api_key else {},
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
    session = tools.Session(finding=finding, approver=approver, log=log, on_result=on_result)
    token = tools.start_session(session)
    final, success = "", False
    error = None
    try:
        async with ClaudeSDKClient(options=options()) as client:
            await client.query(render_finding_prompt(finding))
            async for msg in client.receive_response():
                if isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, TextBlock) and on_text:
                            on_text(block.text)
                elif isinstance(msg, ResultMessage):
                    success = msg.subtype == "success" and not msg.is_error
                    final = msg.result or ""
                    if not success:
                        error = "; ".join(msg.errors or []) or final or msg.subtype
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        success = False
    finally:
        for approval in session.approvals.values():
            tools.apply.revoke_token(approval.token)
        tools._session.reset(token)
        applied = any(
            r["step"] == "apply_remediation" and r.get("result") == "applied" for r in log.records()
        )
        log.record("run_end", success=success, applied=applied, error=error)
    return RunResult(
        run_id=log.run_id,
        audit_path=str(log.path),
        final_text=final,
        success=success,
        applied=applied,
        records=log.records(),
        error=error,
    )
