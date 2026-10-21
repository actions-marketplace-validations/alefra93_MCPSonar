"""Response drift: a probed tool that still answers, but differently.

Only tools explicitly configured as probes are watched — never responses to anything else.
What is kept between checks is a *shape*, never the response itself:

* ``is_error`` — whether the call returned an error result;
* ``content`` — the types of the content items, in order (``text``, ``image``, ...);
* ``structured`` — the structure of ``structuredContent``: key names and value *types*
  (``{"temp": "number", "unit": "string"}``), never values;
* ``size`` — the order of magnitude of the payload (log2 of its length);
* ``hash`` — only in ``drift: hash`` mode: SHA-256 of the canonicalized response, minus the
  fields listed in ``drift_ignore`` (timestamps, random ids). For deterministic probes.

A size change counts only when it is at least 8× (3 binary orders of magnitude): responses
that vary a little in length are not drift.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

SIZE_TOLERANCE = 3  # log2 buckets: 2**3 = 8x


def _type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def structure(value: Any, depth: int = 0) -> Any:
    """Key names and types of a JSON value, recursively (lists: the first item's shape)."""
    if depth > 8:
        return _type(value)
    if isinstance(value, dict):
        return {k: structure(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [structure(value[0], depth + 1)] if value else []
    return _type(value)


def _strip(value: Any, ignore: set[str]) -> Any:
    if isinstance(value, dict):
        return {k: _strip(v, ignore) for k, v in sorted(value.items()) if k not in ignore}
    if isinstance(value, list):
        return [_strip(v, ignore) for v in value]
    return value


def shape_of(result: Any, mode: str = "shape", ignore: list[str] | None = None) -> dict[str, Any]:
    """The comparable shape of a ``CallToolResult`` (any object with ``content`` /
    ``structured_content`` / ``is_error``)."""
    content = list(getattr(result, "content", None) or [])
    structured = getattr(result, "structured_content", None)
    texts = [getattr(c, "text", "") or "" for c in content]
    size = sum(len(t) for t in texts) + (len(json.dumps(structured)) if structured else 0)
    shape: dict[str, Any] = {
        "is_error": bool(getattr(result, "is_error", False)),
        "content": [getattr(c, "type", type(c).__name__) for c in content][:20],
        "structured": structure(structured) if structured is not None else None,
        "size": int(math.log2(size + 1)),
    }
    if mode == "hash":
        skip = set(ignore or [])
        canonical = json.dumps(
            {"text": texts, "structured": _strip(structured, skip)},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str,
        )
        shape["hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return shape


def _paths(value: Any, prefix: str = "") -> dict[str, str]:
    """``{"a.b": "number", ...}`` for every leaf of a structure."""
    if isinstance(value, dict):
        out: dict[str, str] = {}
        for k, v in value.items():
            out.update(_paths(v, f"{prefix}.{k}" if prefix else k))
        return out or {prefix or "(root)": "object"}
    if isinstance(value, list):
        return _paths(value[0], f"{prefix}[]") if value else {f"{prefix}[]": "empty"}
    return {prefix or "(root)": str(value)}


def compare(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Human-readable reasons why ``new`` drifted from ``old`` (empty: no drift)."""
    reasons: list[str] = []
    if old.get("is_error") != new.get("is_error"):
        reasons.append("now returns an error result" if new.get("is_error")
                       else "no longer returns an error result")
    if old.get("content") != new.get("content"):
        reasons.append(f"content types {old.get('content')} → {new.get('content')}")
    if old.get("structured") != new.get("structured"):
        before, after = _paths(old.get("structured")), _paths(new.get("structured"))
        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        retyped = sorted(p for p in set(before) & set(after) if before[p] != after[p])
        parts = ([f"+{p}" for p in added] + [f"-{p}" for p in removed]
                 + [f"{p}: {before[p]}→{after[p]}" for p in retyped])
        reasons.append("structure changed (" + ", ".join(parts[:8])
                       + (", …" if len(parts) > 8 else "") + ")" if parts
                       else "structure changed")
    if abs(old.get("size", 0) - new.get("size", 0)) >= SIZE_TOLERANCE:
        factor = 2 ** abs(new.get("size", 0) - old.get("size", 0))
        reasons.append(f"payload ~{factor}x {'larger' if new['size'] > old['size'] else 'smaller'}")
    if "hash" in old and "hash" in new and old["hash"] != new["hash"] and not reasons:
        reasons.append("response content changed (hash mode)")
    return reasons
