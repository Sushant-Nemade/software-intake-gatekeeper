from __future__ import annotations

import mmap
from pathlib import Path

import pytest
from conftest import go_version_m

from intake_gatekeeper import golang

_START = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6"
_END = b"\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2"


def _uvarint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _blob(version: str, modinfo: str, flags: int = 0x2) -> bytes:
    framed = _START + modinfo.encode() + _END
    header = golang.MAGIC + bytes([8, flags]) + b"\x00" * 16
    return (
        b"\x00" * 64
        + header
        + _uvarint(len(version))
        + version.encode()
        + _uvarint(len(framed))
        + framed
    )


MODINFO = (
    "path\texample.com/tool\n"
    "mod\texample.com/tool\tv1.4.0\th1:abc=\n"
    "dep\tgolang.org/x/net\tv0.17.0\th1:def=\n"
    "dep\tgithub.com/old/lib\tv1.0.0\th1:ghi=\n"
    "=>\tgithub.com/new/lib\tv1.2.0\th1:jkl=\n"
    "dep\tgithub.com/local/lib\tv0.0.0\n"
    "=>\t../lib\t\t\n"
    "build\tGOOS=linux\n"
)


def test_parses_inline_buildinfo_with_replacements() -> None:
    info = golang.read_buildinfo(_blob("go1.21.3", MODINFO))
    assert info is not None
    assert info.go_version == "go1.21.3"
    assert info.main == golang.GoModule("example.com/tool", "v1.4.0")
    assert info.deps[0] == golang.GoModule("golang.org/x/net", "v0.17.0")
    assert info.deps[1] == golang.GoModule(
        "github.com/old/lib", "v1.0.0", "github.com/new/lib", "v1.2.0"
    )
    assert info.deps[2].replace_path == "../lib"
    assert info.deps[2].replace_version == ""
    assert info.settings == {"GOOS": "linux"}


def test_skips_magic_literal_without_valid_blob() -> None:
    decoy = golang.MAGIC + b"\x08\x02" + b"\x00" * 16 + b"\xff\xff\xff"
    data = decoy + _blob("go1.22.0", MODINFO)
    info = golang.read_buildinfo(data)
    assert info is not None and info.go_version == "go1.22.0"


def test_not_a_go_binary() -> None:
    assert golang.read_buildinfo(b"MZ" + b"\x00" * 200) is None


def test_legacy_pointer_format_is_reported() -> None:
    with pytest.raises(golang.LegacyGoBinary):
        golang.read_buildinfo(_blob("go1.16", MODINFO, flags=0x0))


def test_truncated_varint_is_ignored() -> None:
    data = golang.MAGIC + b"\x08\x02" + b"\x00" * 16 + b"\x80\x80"
    assert golang.read_buildinfo(data) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("go1.21.3", "1.21.3"),
        ("go1.20", "1.20.0"),
        ("go1.22.1 X:boringcrypto", "1.22.1"),
        ("go1.23rc1", None),
        ("devel go1.24-abc", None),
    ],
)
def test_stdlib_version(raw: str, expected: str | None) -> None:
    assert golang.stdlib_version(raw) == expected


def _expected_from_go(path: Path) -> tuple[str, list[tuple[str, str]]]:
    lines = go_version_m(path).splitlines()
    version = lines[0].rsplit(": ", 1)[1].strip()
    deps = [
        (fields[1], fields[2])
        for fields in (line.strip().split("\t") for line in lines[1:])
        if fields[0] == "dep"
    ]
    return version, deps


@pytest.mark.parametrize("label", ["pe", "elf", "macho"])
def test_matches_go_version_m_on_real_binaries(go_binaries: dict[str, Path], label: str) -> None:
    path = go_binaries[label]
    expected_version, expected_deps = _expected_from_go(path)
    with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        info = golang.read_buildinfo(data)
    assert info is not None
    assert info.go_version == expected_version
    assert [(dep.path, dep.version) for dep in info.deps] == expected_deps
    assert ("golang.org/x/text", "v0.3.7") in expected_deps
