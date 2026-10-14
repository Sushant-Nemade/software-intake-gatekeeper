from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import build_demo
import httpx
import pytest

from intake_gatekeeper import cli, output
from intake_gatekeeper.diff import compare
from intake_gatekeeper.engine import run_scan
from intake_gatekeeper.model import Decision
from intake_gatekeeper.osv import OsvClient
from intake_gatekeeper.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
UPDATE_DEMO = ROOT / "examples" / "update-demo"
NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
OFFLINE = Policy(require_vulnerability_lookup=False)
VULNERABLE = {
    ("npm", "axios", "0.21.1"): "GHSA-cph5-m8f7-6c5x",
    ("npm", "lodash", "4.17.15"): "GHSA-p6mc-m468-83gw",
}


def _osv(_url: str = "") -> OsvClient:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            results = []
            for query in queries:
                key = (query["package"]["ecosystem"], query["package"]["name"], query["version"])
                vuln = VULNERABLE.get(key)
                results.append({"vulns": [{"id": vuln}]} if vuln else {})
            return httpx.Response(200, json={"results": results})
        vuln_id = request.url.path.rsplit("/", 1)[1]
        return httpx.Response(
            200,
            json={"id": vuln_id, "summary": f"Advisory {vuln_id}", "database_specific": {"severity": "HIGH"}},
        )

    return OsvClient(client=httpx.Client(transport=httpx.MockTransport(handle)))


def _scan(path: Path, osv: OsvClient | None = None, policy: Policy = OFFLINE):  # type: ignore[no-untyped-def]
    return run_scan(path, policy, osv, now=NOW)


def test_update_demo_with_vulnerability_lookup() -> None:
    diff = compare(_scan(UPDATE_DEMO / "v1", _osv()), _scan(UPDATE_DEMO / "v2", _osv()), Policy())
    assert diff.decision is Decision.REJECT
    new_ids = {f.rule_id for f in diff.new_findings}
    resolved_ids = {f.rule_id for f in diff.resolved_findings}
    assert new_ids == {"GHSA-cph5-m8f7-6c5x"}
    assert resolved_ids == {"GHSA-p6mc-m468-83gw", "EGK-JS-NODE-INTEGRATION"}
    changes = {(c.name, c.kind, c.old, c.new) for c in diff.components}
    assert changes == {("axios", "added", (), ("0.21.1",)), ("lodash", "changed", ("4.17.15",), ("4.17.21",))}
    assert diff.endpoints_added == ["collect.metrics-collector.example"]
    assert diff.endpoints_removed == []
    assert diff.binaries_added == ["resources/app/node_modules/fast-native/build/Release/addon.node"]
    assert any("network endpoint" in reason for reason in diff.reasons)


def test_identical_versions_are_approved(tmp_path: Path) -> None:
    copy = tmp_path / "same"
    shutil.copytree(UPDATE_DEMO / "v1", copy)
    diff = compare(_scan(UPDATE_DEMO / "v1"), _scan(copy), OFFLINE)
    assert diff.decision is Decision.APPROVE
    assert diff.new_findings == [] and diff.components == [] and diff.persisting_findings == 1


def test_only_resolutions_are_approved(tmp_path: Path) -> None:
    fixed = tmp_path / "fixed"
    shutil.copytree(UPDATE_DEMO / "v1", fixed)
    (fixed / "resources/app/main.js").write_text(
        'fetch("https://api.update-demo.example/v1/status");\n', encoding="utf-8"
    )
    diff = compare(_scan(UPDATE_DEMO / "v1"), _scan(fixed), OFFLINE)
    assert diff.decision is Decision.APPROVE
    assert "1 finding(s) resolved" in diff.reasons[0]


def test_electron_upgrade_and_weakened_fuse(tmp_path: Path) -> None:
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "app.exe").write_bytes(build_demo.electron_stand_in("30.0.0", b"00110001"))
    (new / "app.exe").write_bytes(build_demo.electron_stand_in("31.1.0", b"10110001"))
    diff = compare(_scan(old), _scan(new), OFFLINE)
    assert diff.electron_versions == ("30.0.0", "31.1.0")
    (change,) = diff.fuse_changes
    assert (change.fuse, change.old, change.new, change.weakened) == (
        "RunAsNode",
        "disabled",
        "enabled",
        True,
    )
    assert diff.binaries_changed == ["app.exe"]
    assert {f.rule_id for f in diff.new_findings} == {"EGK-FUSE-RUN-AS-NODE"}
    assert diff.decision is Decision.REVIEW
    assert any("weakened" in reason for reason in diff.reasons)


def test_blocking_gaps_in_new_version_need_review(tmp_path: Path) -> None:
    diff = compare(_scan(UPDATE_DEMO / "v1"), _scan(UPDATE_DEMO / "v1", policy=Policy()), Policy())
    assert diff.decision is Decision.REVIEW
    assert any("lookup-disabled" in reason for reason in diff.reasons)


def test_diff_outputs(tmp_path: Path) -> None:
    diff = compare(_scan(UPDATE_DEMO / "v1", _osv()), _scan(UPDATE_DEMO / "v2", _osv()), Policy())
    document = json.loads(output.to_diff_json(diff))
    assert document["schema"] == "software-intake-gatekeeper/diff/v1"
    assert document["decision"]["value"] == "reject"
    assert document["endpoints"]["added"] == ["collect.metrics-collector.example"]
    assert document["reports"]["new"]["binaries"][0]["kind"] == "native"
    sarif = json.loads(output.diff_sarif(diff))
    assert [r["ruleId"] for r in sarif["runs"][0]["results"]] == ["GHSA-cph5-m8f7-6c5x"]
    markdown = output.to_diff_markdown(diff)
    assert "update check: **REJECT**" in markdown
    assert "`collect.metrics-collector.example`" in markdown


def test_cli_diff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    out = tmp_path / "out"
    args = [
        "diff",
        "examples/update-demo/v1",
        "examples/update-demo/v2",
        "--osv",
        "--json",
        str(out / "d.json"),
        "--markdown",
        str(out / "d.md"),
        "--sarif",
        str(out / "d.sarif"),
        "--cyclonedx",
        str(out / "sbom.json"),
        "-q",
    ]
    assert cli.main(args, osv_factory=_osv) == cli.EXIT_GATE
    assert sorted(p.name for p in out.iterdir()) == ["d.json", "d.md", "d.sarif", "sbom.json"]
    sarif = json.loads((out / "d.sarif").read_text(encoding="utf-8"))
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("examples/update-demo/v2/")
    assert cli.main([*args, "--fail-on", "never"], osv_factory=_osv) == cli.EXIT_OK
    assert cli.main(["diff", "examples/update-demo/v1", "missing-dir"]) == cli.EXIT_USAGE


def test_endpoints_ignore_namespaces_and_local_hosts() -> None:
    from intake_gatekeeper.electron import find_endpoints

    text = (
        'xmlns="http://www.w3.org/2000/svg" a="https://api.vendor.example/x" b="http://localhost:3000" '
        'c="http://127.0.0.1/" d="wss://socket.vendor.example" e="https://cdn.vendor.example."'
    )
    assert find_endpoints(text) == {"api.vendor.example", "socket.vendor.example", "cdn.vendor.example"}


def test_endpoints_skip_urls_in_comments_and_prose() -> None:
    from intake_gatekeeper.electron import find_endpoints

    text = (
        "/*! lib v1 | (c) https://license-host.example */\n"
        "// see https://docs.example/issue\n"
        'throw new Error("Read https://help.example/x");\n'
        "fetch('https://api.vendor.example/v1'); new WebSocket(`wss://live.vendor.example/s`);\n"
    )
    assert find_endpoints(text) == {"api.vendor.example", "live.vendor.example"}


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (
            "resources/app.asar!/out/renderer/assets/index-Cz8Eo_n9.js",
            "resources/app.asar!/out/renderer/assets/index-*.js",
        ),
        ("dist/main.3f2a1b9c.js", "dist/main.*.js"),
        ("dist/vendors-chunk.0a1b2c3d4e5f.css", "dist/vendors-chunk.*.css"),
        ("resources/app/main.js", "resources/app/main.js"),
        ("out/index-renderer.js", "out/index-renderer.js"),
        ("out/polyfills-es2015.js", "out/polyfills-es2015.js"),
        ("index-Cz8Eo_n9.js", "index-*.js"),
    ],
)
def test_stable_path_ignores_content_hashes(path: str, expected: str) -> None:
    from intake_gatekeeper.diff import stable_path

    assert stable_path(path) == expected


def test_renamed_bundle_keeps_findings_persisting(tmp_path: Path) -> None:
    code = "new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n"
    old, new = tmp_path / "old" / "assets", tmp_path / "new" / "assets"
    old.mkdir(parents=True)
    new.mkdir(parents=True)
    (old / "index-BBEVtY79.js").write_text(code, encoding="utf-8")
    (new / "index-Cz8Eo_n9.js").write_text(code, encoding="utf-8")
    diff = compare(_scan(old.parent), _scan(new.parent), OFFLINE)
    assert diff.new_findings == [] and diff.resolved_findings == []
    assert diff.persisting_findings == 1
    assert diff.decision is Decision.APPROVE
