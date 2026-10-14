"""Tool-definition fingerprints and diffs — the basis of rug-pull detection.

An MCP server can change what its tools *say* at any time: a description that was harmless
yesterday can carry hidden instructions for the LLM today, or an input schema can quietly
grow a new ``notes`` parameter used to exfiltrate context. Clients typically approve a tool
once and never look again.

mcpsonar pins every tool's definition on first sight (the *baseline*) and diffs each later
``tools/list`` against the last one it saw. This module is pure: it only normalizes, hashes
and compares; persistence and policy live in :mod:`mcpsonar.monitor`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal

from mcp.types import Tool

#: The parts of a tool definition that are pinned. ``_meta``/``icons``/``execution`` are left
#: out on purpose: they are presentation/runtime hints that may legitimately vary per call.
PINNED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")

ChangeKind = Literal["added", "removed", "changed"]


def normalize_tool(tool: Tool | dict[str, Any]) -> dict[str, Any]:
    """Reduce a tool to its pinned fields as plain JSON-able data (absent fields dropped)."""
    data = tool if isinstance(tool, dict) else tool.model_dump(mode="json", by_alias=True)
    return {k: data[k] for k in PINNED_FIELDS if data.get(k) is not None}


def fingerprint(definition: dict[str, Any]) -> str:
    """Stable SHA-256 of a normalized definition (key order independent)."""
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class ToolChange:
    """One difference between two tool listings."""

    kind: ChangeKind
    tool: str
    fields: list[str] = field(default_factory=list)  # which pinned fields differ ("changed")
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None

    def summary(self) -> str:
        if self.kind == "changed":
            return f"{self.tool}: {', '.join(self.fields)} changed"
        return f"{self.tool}: {self.kind}"


def diff_tools(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> list[ToolChange]:
    """Compare two ``{tool name: normalized definition}`` maps. Sorted by tool name."""
    changes: list[ToolChange] = []
    for name in sorted(before.keys() | after.keys()):
        old, new = before.get(name), after.get(name)
        if old is None:
            changes.append(ToolChange("added", name, after=new))
        elif new is None:
            changes.append(ToolChange("removed", name, before=old))
        elif fingerprint(old) != fingerprint(new):
            fields = [f for f in PINNED_FIELDS if old.get(f) != new.get(f)]
            changes.append(ToolChange("changed", name, fields=fields, before=old, after=new))
    return changes


def index_tools(tools: list[Tool] | list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """``{name: normalized definition}`` for a tools/list result."""
    out: dict[str, dict[str, Any]] = {}
    for tool in tools:
        norm = normalize_tool(tool)
        out[norm["name"]] = norm
    return out
