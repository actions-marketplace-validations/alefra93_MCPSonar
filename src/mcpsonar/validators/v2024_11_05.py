"""Validator for MCP spec version 2024-11-05.

The first public spec (HTTP+SSE transport). A tools server must already advertise the
``tools`` capability and give every tool an ``inputSchema``.

Kept as its own file (not a subclass) so each version's rules can evolve independently.
"""

from __future__ import annotations

from mcp.types import InitializeResult, Tool

from .base import BaseValidator, register


class V20241105Validator(BaseValidator):
    spec_version = "2024-11-05"

    def validate(self, init: InitializeResult, tools: list[Tool]) -> list[str]:
        issues: list[str] = []

        if init.capabilities is None or init.capabilities.tools is None:
            issues.append("server does not advertise the 'tools' capability")

        for tool in tools:
            if tool.inputSchema is None:
                issues.append(f"tool '{tool.name}' is missing inputSchema")

        return issues


register(V20241105Validator())
