from __future__ import annotations

import io
import json
import struct
from pathlib import Path

import pytest

from intake_gatekeeper import asar


def _archive(header: object, body: bytes = b"") -> bytes:
    text = json.dumps(header).encode()
    padded = text + b"\x00" * (-len(text) % 4)
    pickle = struct.pack("<Ii", 4 + len(padded), len(text)) + padded
    return struct.pack("<II", 4, len(pickle)) + pickle + body


def _read(data: bytes) -> tuple[dict[str, object], int]:
    return asar.read_header(io.BytesIO(data), len(data), 1024 * 1024)


def test_reads_archive_built_by_official_tool(demo_asar: Path) -> None:
    size = demo_asar.stat().st_size
    with demo_asar.open("rb") as handle:
        header, start = asar.read_header(handle, size, 1024 * 1024)
        entries = [e for e in asar.iter_entries(header, 100) if isinstance(e, asar.AsarEntry)]
        paths = sorted(entry.path for entry in entries)
        assert paths == [
            "dist/settings.min.js",
            "main.js",
            "node_modules/@demo/ui-kit/package.json",
            "node_modules/lodash/index.js",
            "node_modules/lodash/package.json",
            "node_modules/minimist/package.json",
            "package.json",
            "preload.js",
        ]
        manifest = next(entry for entry in entries if entry.path == "package.json")
        data = json.loads(asar.read_entry(handle, start, size, manifest))
    assert data["name"] == "intake-demo-app"


def test_round_trip_synthetic_archive() -> None:
    body = b"hello"
    header = {"files": {"a.txt": {"offset": "0", "size": 5}}}
    data = _archive(header, body)
    parsed, start = _read(data)
    (entry,) = list(asar.iter_entries(parsed, 10))
    assert isinstance(entry, asar.AsarEntry)
    assert asar.read_entry(io.BytesIO(data), start, len(data), entry) == body


@pytest.mark.parametrize(
    "data",
    [
        b"",
        struct.pack("<II", 5, 10),
        struct.pack("<II", 4, 10_000),
        _archive(["not", "an", "object"]),
    ],
)
def test_rejects_malformed_headers(data: bytes) -> None:
    with pytest.raises(asar.AsarError):
        _read(data)


def test_header_size_limit() -> None:
    data = _archive({"files": {"x": {"offset": "0", "size": 0}}})
    with pytest.raises(asar.AsarError, match="limit"):
        asar.read_header(io.BytesIO(data), len(data), 8)


def test_unsafe_names_and_bad_offsets_are_reported_not_followed() -> None:
    header = {
        "files": {
            "..": {"offset": "0", "size": 1},
            "a/b": {"offset": "0", "size": 1},
            "neg": {"offset": "0", "size": -1},
            "num": {"offset": 0, "size": 1},
            "link": {"link": "../../etc/passwd"},
            "ok": {"offset": "0", "size": 1},
        }
    }
    results = list(asar.iter_entries(header, 10))
    entries = [r for r in results if isinstance(r, asar.AsarEntry)]
    problems = [r for r in results if isinstance(r, str)]
    assert [e.path for e in entries] == ["ok"]
    assert len(problems) == 4


def test_entry_outside_archive_is_rejected() -> None:
    data = _archive({"files": {"big": {"offset": "0", "size": 999}}})
    parsed, start = _read(data)
    (entry,) = list(asar.iter_entries(parsed, 10))
    assert isinstance(entry, asar.AsarEntry)
    with pytest.raises(asar.AsarError, match="outside"):
        asar.read_entry(io.BytesIO(data), start, len(data), entry)


def test_entry_limit() -> None:
    files = {f"f{i}": {"offset": "0", "size": 0} for i in range(5)}
    results = list(asar.iter_entries({"files": files}, 3))
    assert sum(isinstance(r, asar.AsarEntry) for r in results) == 3
    assert results[-1] == "entry limit of 3 reached"
