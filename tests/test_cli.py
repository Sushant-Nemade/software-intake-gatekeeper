from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from intake_gatekeeper import cli
from intake_gatekeeper.osv import OsvClient


def _offline_osv(_url: str) -> OsvClient:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [{} for _ in queries]})
        return httpx.Response(404)

    return OsvClient(client=httpx.Client(transport=httpx.MockTransport(handle)))


def test_scan_writes_all_reports(demo_target: Path, tmp_path: Path) -> None:
    out = tmp_path / "reports"
    code = cli.main(
        [
            "scan",
            str(demo_target),
            "--osv",
            "--json",
            str(out / "r.json"),
            "--sarif",
            str(out / "r.sarif"),
            "--cyclonedx",
            str(out / "r.cdx.json"),
            "--markdown",
            str(out / "r.md"),
            "-q",
        ],
        osv_factory=_offline_osv,
    )
    assert code == cli.EXIT_GATE
    assert sorted(p.name for p in out.iterdir()) == ["r.cdx.json", "r.json", "r.md", "r.sarif"]
    assert json.loads((out / "r.json").read_text(encoding="utf-8"))["vulnerability_lookup"] == "osv"


@pytest.mark.parametrize(("fail_on", "expected"), [("never", 0), ("reject", 1), ("review", 1)])
def test_fail_on(demo_target: Path, fail_on: str, expected: int) -> None:
    assert cli.main(["scan", str(demo_target), "--fail-on", fail_on, "-q"]) == expected


def test_sarif_paths_are_relative_to_working_directory(
    demo_target: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(demo_target.parent)
    sarif = tmp_path / "r.sarif"
    cli.main(["scan", demo_target.name, "--sarif", str(sarif), "--fail-on", "never", "-q"])
    uris = {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
    }
    assert "demo/resources/app.asar!/main.js" in uris
    assert all(uri.startswith("demo/") for uri in uris)


def test_sarif_paths_stay_target_relative_outside_working_directory(
    demo_target: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    sarif = tmp_path / "r.sarif"
    asar = demo_target / "resources" / "app.asar"
    cli.main(["scan", str(asar), "--sarif", str(sarif), "--fail-on", "never", "-q"])
    results = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
    assert {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results} >= {
        "app.asar!/main.js"
    }


def test_lookup_disabled_cannot_approve(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "App.deps.json").write_text(
        json.dumps({"libraries": {"Serilog/2.10.0": {"type": "package"}}}), encoding="utf-8"
    )
    assert cli.main(["scan", str(tmp_path), "--fail-on", "review"]) == cli.EXIT_GATE
    assert "lookup-disabled" in capsys.readouterr().out
    assert (
        cli.main(
            ["scan", str(tmp_path), "--osv", "--fail-on", "review", "-q"], osv_factory=_offline_osv
        )
        == cli.EXIT_OK
    )


def test_policy_can_relax_lookup_requirement(tmp_path: Path) -> None:
    (tmp_path / "App.deps.json").write_text(
        json.dumps({"libraries": {"Serilog/2.10.0": {"type": "package"}}}), encoding="utf-8"
    )
    policy = tmp_path / "policy.toml"
    policy.write_text("[gate]\nrequire_vulnerability_lookup = false\n", encoding="utf-8")
    assert (
        cli.main(["scan", str(tmp_path), "--policy", str(policy), "--fail-on", "review", "-q"]) == 0
    )


def test_empty_directory_is_not_approved(tmp_path: Path) -> None:
    assert cli.main(["scan", str(tmp_path), "--fail-on", "review", "-q"]) == cli.EXIT_GATE


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "missing-target-xyz"],
        ["scan", ".", "--osv", "--osv-url", "http://osv.example"],
        ["scan", ".", "--policy", "missing-policy.toml"],
        ["scan", ".", "--max-files", "0"],
    ],
)
def test_usage_errors_exit_2(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(args) == cli.EXIT_USAGE
    assert "error:" in capsys.readouterr().err


def test_rules_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["rules"]) == 0
    assert "EGK-FUSE-RUN-AS-NODE" in capsys.readouterr().out
