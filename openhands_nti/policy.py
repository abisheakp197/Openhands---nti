"""Mapping from OpenHands tools to NTI capabilities.

The guardrail signs and authorizes every action against a capability name. This
module centralizes the default mapping so the same capability vocabulary is used
by the delegation chain, the engine grants, and the receipts.
"""

from __future__ import annotations

from collections.abc import Callable

# OpenHands tool name -> NTI capability. Extend via ``tool_capabilities``.
DEFAULT_TOOL_CAPABILITIES: dict[str, str] = {
    "bash": "shell.execute",
    "terminal": "shell.execute",
    "execute_bash": "shell.execute",
    "str_replace_editor": "file.write",
    "file_editor": "file.write",
    "apply_patch": "file.write",
    "browser": "web.fetch",
    "browser_use": "web.fetch",
    "fetch": "web.fetch",
    "web_search": "web.fetch",
    "think": "agent.think",
    "finish": "agent.finish",
    "task_tracker": "agent.plan",
    "invoke_skill": "agent.skill",
}


def capability_for(
    tool_name: str,
    overrides: dict[str, str] | None = None,
    resolver: Callable[[str], str] | None = None,
) -> str:
    """Resolve the capability a tool requires.

    Precedence: ``resolver`` > ``overrides`` > :data:`DEFAULT_TOOL_CAPABILITIES`
    > ``"tool.<name>"``.
    """
    if resolver is not None:
        return resolver(tool_name)
    if overrides and tool_name in overrides:
        return overrides[tool_name]
    return DEFAULT_TOOL_CAPABILITIES.get(tool_name, f"tool.{tool_name}")
