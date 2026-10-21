"""Response drift: a probed tool that still answers, but differently.

The fixture's ``weather`` tool answers according to a variant file the test rewrites between
checks, so each case runs the real pipeline (engine → monitor → storage) end to end.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mcpsonar.drift import compare, shape_of, structure
from mcpsonar.models import ServerConfig, ToolProbe
from mcpsonar.monitor import process_check
from mcpsonar.storage import Storage

FIXTURE = Path(__file__).parent / "fixtures" / "scripted_server.py"


@pytest.fixture
async def storage(tmp_path):
    s = await Storage.open(tmp_path / "m.db")
    yield s
    await s.close()


def _cfg(variant_file: Path, **probe) -> ServerConfig:
    return ServerConfig(
        transport="stdio", command=sys.executable,
        args=[str(FIXTURE), "respond", str(variant_file)],
        tools_to_test=[ToolProbe(name="weather", **probe)],
        on_tool_change="ignore",
    )


async def _check(storage, cfg, variant_file: Path, variant: str):
    variant_file.write_text(variant, encoding="utf-8")
    event = await process_check(storage, "s", cfg)
    return [a.detail for a in event.anomalies if a.kind == "response_drift"]


async def test_first_answer_is_the_reference_and_same_shape_is_quiet(storage, tmp_path):
    vf = tmp_path / "variant"
    cfg = _cfg(vf)
    assert await _check(storage, cfg, vf, "a") == []
    assert await _check(storage, cfg, vf, "a") == []
    assert "weather" in await storage.get_probe_shapes("s")


async def test_added_field_is_reported_once_then_becomes_the_reference(storage, tmp_path):
    vf = tmp_path / "variant"
    cfg = _cfg(vf)
    await _check(storage, cfg, vf, "a")
    (drift,) = await _check(storage, cfg, vf, "b")
    assert drift.startswith("weather: structure changed") and "+wind" in drift
    assert await _check(storage, cfg, vf, "b") == []  # reported once


async def test_error_result_is_drift(storage, tmp_path):
    vf = tmp_path / "variant"
    cfg = _cfg(vf)
    await _check(storage, cfg, vf, "a")
    (drift,) = await _check(storage, cfg, vf, "err")
    assert "now returns an error result" in drift


async def test_values_only_change_is_not_drift_in_shape_mode(storage, tmp_path):
    vf = tmp_path / "variant"
    cfg = _cfg(vf)
    await _check(storage, cfg, vf, "a")
    assert await _check(storage, cfg, vf, "a2") == []


async def test_hash_mode_sees_values_and_honours_drift_ignore(storage, tmp_path):
    vf = tmp_path / "variant"
    await _check(storage, _cfg(vf, drift="hash"), vf, "a")
    (drift,) = await _check(storage, _cfg(vf, drift="hash"), vf, "a2")
    assert "response content changed (hash mode)" in drift

    other = tmp_path / "other"
    cfg = _cfg(other, drift="hash", drift_ignore=["temp", "unit"])
    other.write_text("a", encoding="utf-8")
    first = await process_check(storage, "t", cfg)
    other.write_text("a2", encoding="utf-8")
    second = await process_check(storage, "t", cfg)
    assert not [a for a in first.anomalies + second.anomalies if a.kind == "response_drift"]


async def test_size_jump_is_drift(storage, tmp_path):
    vf = tmp_path / "variant"
    cfg = _cfg(vf)
    await _check(storage, cfg, vf, "err")
    (drift,) = await _check(storage, cfg, vf, "big")
    assert "larger" in drift and "no longer returns an error result" in drift


async def test_drift_off_stores_nothing(storage, tmp_path):
    vf = tmp_path / "variant"
    cfg = _cfg(vf, drift="off")
    await _check(storage, cfg, vf, "a")
    assert await _check(storage, cfg, vf, "b") == []
    assert await storage.get_probe_shapes("s") == {}


async def test_no_response_content_is_persisted(storage, tmp_path):
    vf = tmp_path / "variant"
    await _check(storage, _cfg(vf, drift="hash"), vf, "a")
    (shape,) = (await storage.get_probe_shapes("s")).values()
    assert set(shape) == {"is_error", "content", "structured", "size", "hash"}
    assert len(shape.pop("hash")) == 64  # a digest, not the content
    stored = json.dumps(shape)
    assert "sunny" not in stored and "21" not in stored and '"C"' not in stored


async def test_delete_server_removes_shapes(storage, tmp_path):
    vf = tmp_path / "variant"
    await _check(storage, _cfg(vf), vf, "a")
    await storage.delete_server("s")
    assert await storage.get_probe_shapes("s") == {}


# ---- pure functions --------------------------------------------------------------- #
class _Text:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _Result:
    def __init__(self, text="", structured=None, is_error=False):
        self.content = [_Text(text)]
        self.structured_content = structured
        self.is_error = is_error


def test_structure_keeps_types_never_values():
    assert structure({"b": [1, 2], "a": {"x": None, "y": True}}) == {
        "a": {"x": "null", "y": "boolean"}, "b": ["number"]}


def test_retyped_and_removed_fields_are_named():
    old = shape_of(_Result(structured={"temp": 21, "unit": "C"}))
    new = shape_of(_Result(structured={"temp": "21"}))
    (reason,) = compare(old, new)
    assert "-unit" in reason and "temp: number→string" in reason


def test_small_size_changes_are_tolerated():
    assert compare(shape_of(_Result("x" * 100)), shape_of(_Result("x" * 400))) == []
    assert compare(shape_of(_Result("x" * 100)), shape_of(_Result("x" * 1000))) != []


def test_hash_ignores_listed_fields_anywhere():
    a = shape_of(_Result(structured={"v": 1, "meta": {"ts": 1}}), "hash", ["ts"])
    b = shape_of(_Result(structured={"v": 1, "meta": {"ts": 2}}), "hash", ["ts"])
    c = shape_of(_Result(structured={"v": 2, "meta": {"ts": 2}}), "hash", ["ts"])
    assert a["hash"] == b["hash"] != c["hash"]
