from __future__ import annotations

import build_demo
import pytest

from intake_gatekeeper import electron


def _rules(text: str) -> list[str]:
    return [rule for rule, _ in electron.scan_javascript(text, "main.js")]


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        ("webPreferences: { nodeIntegration: true }", "EGK-JS-NODE-INTEGRATION"),
        ('{"nodeIntegration":!0}', "EGK-JS-NODE-INTEGRATION"),
        ("prefs.nodeIntegration = true;", "EGK-JS-NODE-INTEGRATION"),
        ("{contextIsolation:!1}", "EGK-JS-CONTEXT-ISOLATION-OFF"),
        ("{ webSecurity: false }", "EGK-JS-WEB-SECURITY-OFF"),
        ("{allowRunningInsecureContent:true}", "EGK-JS-INSECURE-CONTENT"),
        ("{nodeIntegrationInWorker: true}", "EGK-JS-NODE-INTEGRATION-EXTENDED"),
        ("{enableRemoteModule:!0}", "EGK-JS-REMOTE-MODULE"),
        ("{webviewTag: true}", "EGK-JS-WEBVIEW-TAG"),
        ("{experimentalFeatures:true}", "EGK-JS-EXPERIMENTAL-FEATURES"),
        ("electron.shell.openExternal(url)", "EGK-JS-OPEN-EXTERNAL"),
        ("new BrowserWindow({webPreferences:{preload:p,sandbox:!1}})", "EGK-JS-SANDBOX-OFF"),
    ],
)
def test_detects_risky_preferences(source: str, rule: str) -> None:
    assert _rules(source) == [rule]


@pytest.mark.parametrize(
    "source",
    [
        "{ nodeIntegration: false, contextIsolation: true, sandbox: true }",
        "if (options.nodeIntegration == true) {}",
        "{ myNodeIntegration: true }",
        "{ nodeIntegration: 10 }",
        "iframe.sandbox = false",
        "{ sandbox: false }",
    ],
)
def test_safe_or_unrelated_code_is_quiet(source: str) -> None:
    assert _rules(source) == []


def test_locations_report_line_column_and_snippet() -> None:
    text = "const a = 1;\nconst w = new BrowserWindow({\n  webPreferences: { nodeIntegration: true }\n});"
    ((rule, location),) = electron.scan_javascript(text, "src/main.js")
    assert rule == "EGK-JS-NODE-INTEGRATION"
    assert (location.path, location.line, location.column) == ("src/main.js", 3, 21)
    assert location.snippet is not None and "nodeIntegration: true" in location.snippet


def test_matches_per_rule_are_capped() -> None:
    text = "{nodeIntegration:true}\n" * 50
    assert len(_rules(text)) == electron.MAX_MATCHES_PER_RULE


def test_reads_fuse_wire_and_version() -> None:
    data = build_demo.electron_stand_in("28.0.0", b"10r1")
    (wire,) = electron.read_fuse_wires(data)
    assert wire.version == 1
    assert wire.states == {
        "RunAsNode": "enabled",
        "EnableCookieEncryption": "disabled",
        "EnableNodeOptionsEnvironmentVariable": "removed",
        "EnableNodeCliInspectArguments": "enabled",
    }
    assert electron.find_electron_versions(data) == ["28.0.0"]


def test_unknown_fuse_values_and_extra_fuses_are_labelled() -> None:
    data = build_demo.electron_stand_in(wire=b"1" * 9 + b"Z")
    (wire,) = electron.read_fuse_wires(data)
    assert wire.states["WasmTrapHandlers"] == "enabled"
    assert wire.states["Fuse9"] == "unknown(0x5a)"


def test_no_sentinel_means_no_electron() -> None:
    assert electron.read_fuse_wires(b"MZ" + b"\x00" * 100) == []
    assert electron.find_electron_versions(b"Electron/abc") == []
