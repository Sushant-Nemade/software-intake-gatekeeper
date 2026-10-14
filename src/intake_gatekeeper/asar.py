"""Read-only ASAR archive reader that never extracts files to disk."""

from __future__ import annotations

import json
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from intake_gatekeeper.model import GatekeeperError

_MAX_DEPTH = 64


class AsarError(GatekeeperError):
    pass


@dataclass(frozen=True)
class AsarEntry:
    path: str
    offset: int
    size: int
    unpacked: bool


def _u32(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<I", data, at)[0])


def read_header(handle: BinaryIO, archive_size: int, max_header_bytes: int) -> tuple[dict[str, object], int]:
    """Return the parsed header and the absolute offset where file contents start."""
    prefix = handle.read(8)
    if len(prefix) != 8 or _u32(prefix, 0) != 4:
        raise AsarError("not an ASAR archive (missing size pickle)")
    header_pickle_size = _u32(prefix, 4)
    if header_pickle_size < 8 or header_pickle_size > archive_size - 8:
        raise AsarError("ASAR header size exceeds the archive size")
    if header_pickle_size > max_header_bytes:
        raise AsarError(f"ASAR header is larger than the {max_header_bytes} byte limit")
    pickle = handle.read(header_pickle_size)
    if len(pickle) != header_pickle_size:
        raise AsarError("truncated ASAR header")
    payload_size = _u32(pickle, 0)
    string_size = struct.unpack_from("<i", pickle, 4)[0]
    if payload_size > header_pickle_size - 4 or not 0 <= string_size <= payload_size - 4:
        raise AsarError("corrupt ASAR header pickle")
    try:
        header = json.loads(pickle[8 : 8 + string_size].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AsarError(f"ASAR header is not valid JSON: {error}") from None
    if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
        raise AsarError("ASAR header has no root 'files' object")
    return header, 8 + header_pickle_size


def iter_entries(header: dict[str, object], max_entries: int) -> Iterator[AsarEntry | str]:
    """Yield file entries, or a problem description for entries that were skipped."""
    stack: list[tuple[str, dict[str, object], int]] = [("", header, 0)]
    emitted = 0
    while stack:
        prefix, node, depth = stack.pop()
        files = node.get("files")
        if not isinstance(files, dict):
            continue
        for name in sorted(files):
            child = files[name]
            if (
                not isinstance(name, str)
                or name in ("", ".", "..")
                or "/" in name
                or "\\" in name
                or "\x00" in name
            ):
                yield f"unsafe entry name {name!r} under '{prefix or '/'}'"
                continue
            path = f"{prefix}{name}"
            if not isinstance(child, dict):
                yield f"malformed entry '{path}'"
                continue
            if "files" in child:
                if depth + 1 >= _MAX_DEPTH:
                    yield f"directory nesting limit reached at '{path}'"
                    continue
                stack.append((path + "/", child, depth + 1))
                continue
            if "link" in child:
                continue
            emitted += 1
            if emitted > max_entries:
                yield f"entry limit of {max_entries} reached"
                return
            unpacked = child.get("unpacked") is True
            size = child.get("size")
            offset = child.get("offset", "0" if unpacked else None)
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or not isinstance(offset, str)
                or not offset.isdigit()
            ):
                yield f"entry '{path}' has an invalid offset or size"
                continue
            yield AsarEntry(path=path, offset=int(offset), size=size, unpacked=unpacked)


def read_entry(handle: BinaryIO, data_start: int, archive_size: int, entry: AsarEntry) -> bytes:
    start = data_start + entry.offset
    if start + entry.size > archive_size:
        raise AsarError(f"entry '{entry.path}' points outside the archive")
    handle.seek(start)
    data = handle.read(entry.size)
    if len(data) != entry.size:
        raise AsarError(f"entry '{entry.path}' is truncated")
    return data
