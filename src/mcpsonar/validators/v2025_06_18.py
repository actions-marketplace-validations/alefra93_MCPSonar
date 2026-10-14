"""Validator for MCP spec version 2025-06-18.

Adds structured tool output (``outputSchema``) and tool ``title``s; removes JSON-RPC
batching. None of that changes what a healthy tools server must provide, so the rules
match 2025-11-25.

Kept as its own file (not a subclass) so each version's rules can evolve independently.
"""

from __future__ import annotations

from mcp.types import InitializeResult, Tool

from .base import BaseValidator, register


class V20250618Validator(BaseValidator):
    spec_version = "2025-06-18"

    def validate(self, init: InitializeResult, tools: list[Tool]) -> list[str]:
        issues: list[str] = []

        if init.capabilities is None or init.capabilities.tools is None:
            issues.append("server does not advertise the 'tools' capability")

        for tool in tools:
            if tool.inputSchema is None:
                issues.append(f"tool '{tool.name}' is missing inputSchema")

        return issues


register(V20250618Validator())
