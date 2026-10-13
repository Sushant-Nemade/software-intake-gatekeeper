"""Decode the module information that the Go linker embeds in executables (Go 1.18+)."""

from __future__ import annotations

import mmap
import re
from dataclasses import dataclass, field

Bytes = bytes | mmap.mmap

MAGIC = b"\xff Go buildinf:"
_HEADER_SIZE = 32
_FLAG_INLINE = 0x2
_MAX_VERSION = 1024
_MAX_MODINFO = 16 * 1024 * 1024
_MAX_CANDIDATES = 32
_GO_RELEASE = re.compile(r"^go(\d+)\.(\d+)(?:\.(\d+))?$")


@dataclass(frozen=True)
class GoModule:
    path: str
    version: str
    replace_path: str | None = None
    replace_version: str | None = None


@dataclass
class GoBuildInfo:
    go_version: str
    path: str = ""
    main: GoModule | None = None
    deps: list[GoModule] = field(default_factory=list)
    settings: dict[str, str] = field(default_factory=dict)


class LegacyGoBinary(Exception):
    """Raised when only a pre-Go 1.18 pointer-format header is present."""


def _uvarint(data: Bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for index in range(10):
        if pos + index >= len(data):
            raise ValueError("truncated varint")
        byte = data[pos + index]
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos + index + 1
        shift += 7
    raise ValueError("varint overflow")


def _string(data: Bytes, pos: int, limit: int) -> tuple[bytes, int]:
    length, pos = _uvarint(data, pos)
    if length > limit or pos + length > len(data):
        raise ValueError("string length out of range")
    return data[pos : pos + length], pos + length


def _module(fields: list[str]) -> GoModule:
    if len(fields) not in (2, 3):
        raise ValueError("expected 2 or 3 module columns")
    return GoModule(path=fields[0], version=fields[1])


def parse_modinfo(go_version: str, modinfo: str) -> GoBuildInfo:
    info = GoBuildInfo(go_version=go_version)
    last: int | None = None
    for line in modinfo.split("\n"):
        if line.startswith("path\t"):
            info.path = line[5:]
        elif line.startswith("mod\t"):
            info.main = _module(line[4:].split("\t"))
            last = -1
        elif line.startswith("dep\t"):
            info.deps.append(_module(line[4:].split("\t")))
            last = len(info.deps) - 1
        elif line.startswith("=>\t"):
            fields = line[3:].split("\t")
            if len(fields) != 3 or last is None:
                raise ValueError("malformed replacement line")
            target = info.main if last == -1 else info.deps[last]
            if target is None:
                raise ValueError("replacement without module")
            replaced = GoModule(target.path, target.version, fields[0], fields[1])
            if last == -1:
                info.main = replaced
            else:
                info.deps[last] = replaced
            last = None
        elif line.startswith("build\t"):
            key, separator, value = line[6:].partition("=")
            if separator and key and not key.startswith(('"', "`")):
                info.settings[key] = value
    return info


def read_buildinfo(data: Bytes) -> GoBuildInfo | None:
    """Return build info, None when the data is not a Go binary, or raise LegacyGoBinary."""
    saw_legacy = False
    start = 0
    for _ in range(_MAX_CANDIDATES):
        index = data.find(MAGIC, start)
        if index < 0:
            break
        start = index + 1
        if index + _HEADER_SIZE > len(data):
            break
        flags = data[index + 15]
        if not flags & _FLAG_INLINE:
            saw_legacy = True
            continue
        try:
            raw_version, pos = _string(data, index + _HEADER_SIZE, _MAX_VERSION)
            raw_modinfo, _ = _string(data, pos, _MAX_MODINFO)
            version = raw_version.decode("utf-8")
            # Strip the 16-byte binary sentinels framing the module text, as debug/buildinfo does.
            if len(raw_modinfo) >= 33 and raw_modinfo[-17] == 0x0A:
                modinfo = raw_modinfo[16:-16].decode("utf-8")
            else:
                modinfo = ""
        except (ValueError, UnicodeDecodeError):
            continue
        if not version.startswith(("go", "devel")):
            continue
        try:
            return parse_modinfo(version, modinfo)
        except ValueError:
            continue
    if saw_legacy:
        raise LegacyGoBinary("Go binary built before Go 1.18; module list not decoded")
    return None


def stdlib_version(go_version: str) -> str | None:
    """Map 'go1.21.3' (optionally with ' X:...' suffix) to OSV's '1.21.3'; None if not a release."""
    match = _GO_RELEASE.match(go_version.split(" ", 1)[0])
    if match is None:
        return None
    major, minor, patch = match.groups()
    return f"{major}.{minor}.{patch or 0}"
