"""Static Electron checks: fuse wire, runtime version and risky BrowserWindow preferences."""

from __future__ import annotations

import re
from dataclasses import dataclass

from intake_gatekeeper.golang import Bytes
from intake_gatekeeper.model import Location, clean_text

SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
FUSE_NAMES = (
    "RunAsNode",
    "EnableCookieEncryption",
    "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments",
    "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar",
    "LoadBrowserProcessSpecificV8Snapshot",
    "GrantFileProtocolExtraPrivileges",
    "WasmTrapHandlers",
)
_STATES = {0x30: "disabled", 0x31: "enabled", 0x72: "removed"}
# (fuse, risky state, rule id)
FUSE_RULES = (
    ("RunAsNode", "enabled", "EGK-FUSE-RUN-AS-NODE"),
    ("EnableCookieEncryption", "disabled", "EGK-FUSE-COOKIE-ENCRYPTION-OFF"),
    ("EnableNodeOptionsEnvironmentVariable", "enabled", "EGK-FUSE-NODE-OPTIONS"),
    ("EnableNodeCliInspectArguments", "enabled", "EGK-FUSE-NODE-INSPECT"),
    ("EnableEmbeddedAsarIntegrityValidation", "disabled", "EGK-FUSE-ASAR-INTEGRITY-OFF"),
    ("OnlyLoadAppFromAsar", "disabled", "EGK-FUSE-LOAD-OUTSIDE-ASAR"),
    ("GrantFileProtocolExtraPrivileges", "enabled", "EGK-FUSE-FILE-PROTOCOL-PRIVILEGES"),
)
_VERSION_PREFIX = b"Electron/"
_VERSION = re.compile(
    rb"Electron/(\d{1,3}\.\d{1,4}\.\d{1,4}(?:-(?:alpha|beta|nightly)\.[0-9.]{1,20})?)"
)
_MAX_VERSION_PROBES = 4096

_TRUE = r"(?:true|!0|1)\b"
_FALSE = r"(?:false|!1|0)\b"


def _key(name: str) -> str:
    # Patterns start with a literal so re can use its fast substring search; see _boundary().
    return rf"{name}[\"']?\s*(?::|=(?!=))\s*"


JS_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("EGK-JS-NODE-INTEGRATION", "nodeIntegration", re.compile(_key("nodeIntegration") + _TRUE)),
    (
        "EGK-JS-CONTEXT-ISOLATION-OFF",
        "contextIsolation",
        re.compile(_key("contextIsolation") + _FALSE),
    ),
    ("EGK-JS-WEB-SECURITY-OFF", "webSecurity", re.compile(_key("webSecurity") + _FALSE)),
    (
        "EGK-JS-INSECURE-CONTENT",
        "allowRunningInsecureContent",
        re.compile(_key("allowRunningInsecureContent") + _TRUE),
    ),
    (
        "EGK-JS-NODE-INTEGRATION-EXTENDED",
        "nodeIntegrationIn",
        re.compile(_key("nodeIntegrationIn(?:SubFrames|Worker)") + _TRUE),
    ),
    ("EGK-JS-REMOTE-MODULE", "enableRemoteModule", re.compile(_key("enableRemoteModule") + _TRUE)),
    ("EGK-JS-WEBVIEW-TAG", "webviewTag", re.compile(_key("webviewTag") + _TRUE)),
    (
        "EGK-JS-EXPERIMENTAL-FEATURES",
        "experimentalFeatures",
        re.compile(_key("experimentalFeatures") + _TRUE),
    ),
    ("EGK-JS-OPEN-EXTERNAL", "openExternal", re.compile(r"shell\s*\.\s*openExternal\s*\(")),
)
_WEB_PREFERENCES = re.compile(r"webPreferences")
_SANDBOX_OFF = re.compile(_key("sandbox") + _FALSE)
_WEB_PREFERENCES_WINDOW = 1200
MAX_MATCHES_PER_RULE = 10


def _boundary(text: str, start: int) -> bool:
    """True when the match is not the tail of a longer identifier (an opening quote is skipped)."""
    before = start - 1
    if before >= 0 and text[before] in "\"'":
        before -= 1
    return before < 0 or not (text[before].isalnum() or text[before] in "_$")


@dataclass(frozen=True)
class FuseWire:
    offset: int
    version: int
    states: dict[str, str]
    raw: str


def read_fuse_wires(data: Bytes, limit: int = 4) -> list[FuseWire]:
    wires: list[FuseWire] = []
    start = 0
    while len(wires) < limit:
        index = data.find(SENTINEL, start)
        if index < 0:
            break
        start = index + 1
        header = index + len(SENTINEL)
        if header + 2 > len(data):
            break
        version = data[header]
        length = data[header + 1]
        wire = data[header + 2 : header + 2 + length]
        states: dict[str, str] = {}
        for position, value in enumerate(wire):
            name = FUSE_NAMES[position] if position < len(FUSE_NAMES) else f"Fuse{position}"
            states[name] = _STATES.get(value, f"unknown(0x{value:02x})")
        raw = "".join(chr(value) if 0x20 < value < 0x7F else "?" for value in wire)
        wires.append(FuseWire(offset=index, version=version, states=states, raw=raw))
    return wires


def find_electron_versions(data: Bytes) -> list[str]:
    versions: set[str] = set()
    start = 0
    for _ in range(_MAX_VERSION_PROBES):
        index = data.find(_VERSION_PREFIX, start)
        if index < 0:
            break
        start = index + 1
        match = _VERSION.match(data[index : index + 64])
        if match:
            versions.add(match.group(1).decode("ascii"))
    return sorted(versions)


def _locate(text: str, path: str, start: int, end: int) -> Location:
    line = text.count("\n", 0, start) + 1
    column = start - (text.rfind("\n", 0, start) + 1) + 1
    snippet = clean_text(" ".join(text[max(0, start - 40) : end + 40].split()), 160)
    return Location(path=path, line=line, column=column, snippet=snippet)


def scan_javascript(text: str, path: str) -> list[tuple[str, Location]]:
    hits: list[tuple[str, Location]] = []
    for rule_id, keyword, pattern in JS_RULES:
        if keyword not in text:
            continue
        count = 0
        for match in pattern.finditer(text):
            if not _boundary(text, match.start()):
                continue
            count += 1
            if count > MAX_MATCHES_PER_RULE:
                break
            hits.append((rule_id, _locate(text, path, match.start(), match.end())))
    if "sandbox" not in text:
        return hits
    sandbox_hits: set[int] = set()
    for preferences in _WEB_PREFERENCES.finditer(text):
        window = text[preferences.end() : preferences.end() + _WEB_PREFERENCES_WINDOW]
        sandbox = next(
            (m for m in _SANDBOX_OFF.finditer(window) if _boundary(window, m.start())), None
        )
        if sandbox is None:
            continue
        absolute = preferences.end() + sandbox.start()
        if absolute in sandbox_hits or len(sandbox_hits) >= MAX_MATCHES_PER_RULE:
            continue
        sandbox_hits.add(absolute)
        end = preferences.end() + sandbox.end()
        hits.append(("EGK-JS-SANDBOX-OFF", _locate(text, path, absolute, end)))
    return hits
