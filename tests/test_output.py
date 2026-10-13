from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from intake_gatekeeper import output
from intake_gatekeeper.engine import run_scan
from intake_gatekeeper.model import Finding, Location, Report, Severity, Vulnerability
from intake_gatekeeper.policy import Policy

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


def _report(target: Path) -> Report:
    report = run_scan(target, Policy(), None, now=NOW)
    vulnerability = Vulnerability(
        "GHSA-p6mc-m468-83gw",
        ("CVE-2020-8203",),
        "Prototype pollution in lodash",
        Severity.HIGH,
        "GHSA-p6mc-m468-83gw database severity",
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",),
        ("4.17.19",),
        "4.17.19",
    )
    report.inventory.findings.append(
        Finding(
            "GHSA-p6mc-m468-83gw",
            Severity.HIGH,
            "lodash 4.17.15: Prototype pollution",
            "m",
            Location("resources/app.asar!/node_modules/lodash/package.json"),
            "pkg:npm/lodash@4.17.15",
            vulnerability,
            waiver_reason="Accepted for test.",
        )
    )
    return report


def test_cyclonedx_is_schema_valid(demo_target: Path) -> None:
    document = output.to_cyclonedx(_report(demo_target))
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(document) is None
    parsed = json.loads(document)
    assert parsed["vulnerabilities"][0]["affects"] == [{"ref": "pkg:npm/lodash@4.17.15"}]
    assert {c["purl"] for c in parsed["components"]} >= {"pkg:npm/%40demo/ui-kit@2.0.1"}


def test_cyclonedx_serial_is_deterministic(demo_target: Path) -> None:
    first = json.loads(output.to_cyclonedx(_report(demo_target)))["serialNumber"]
    second = json.loads(output.to_cyclonedx(_report(demo_target)))["serialNumber"]
    assert first == second and first.startswith("urn:uuid:")


def test_sarif_structure(demo_target: Path) -> None:
    sarif = json.loads(output.to_sarif(_report(demo_target)))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert " " not in uri and "\\" not in uri
    waived = [r for r in run["results"] if r["ruleId"] == "GHSA-p6mc-m468-83gw"]
    assert waived[0]["suppressions"][0]["justification"] == "Accepted for test."
    node = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "EGK-JS-NODE-INTEGRATION")
    assert node["properties"]["security-severity"] == "8.0"


def test_json_report_round_trip(demo_target: Path) -> None:
    document = json.loads(output.to_json(_report(demo_target)))
    assert document["schema"] == "software-intake-gatekeeper/report/v1"
    assert document["decision"]["value"] == "reject"
    assert document["summary"]["waived_findings"] == 1
    assert document["electron"][0]["fuses"]["RunAsNode"] == "enabled"


def test_untrusted_text_cannot_inject_markdown_or_terminal_codes(demo_target: Path) -> None:
    report = _report(demo_target)
    report.target = "evil`](https://x.invalid)<img src=x>|\x1b[31m"
    report.inventory.findings.insert(
        0,
        Finding(
            "EGK-JS-NODE-INTEGRATION",
            Severity.HIGH,
            "![track](https://x.invalid/p.png) | <script>",
            "m",
            Location("a|b`c\u202e.js", 1, 1),
        ),
    )
    markdown = output.to_markdown(report)
    assert "![track]" not in markdown
    assert "<script>" not in markdown
    assert "\\<script\\>" in markdown
    # Untrusted values outside tables are confined to a single code span.
    assert "`evil'](https://x.invalid)<img src=x>\u00a6[31m`" in markdown
    assert "\x1b" not in markdown and "\u202e" not in markdown
    text = output.to_text(report)
    assert "\x1b" not in text and "\u202e" not in text


def test_write_atomic_replaces_file(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "out.json"
    output.write_atomic(target, "one")
    output.write_atomic(target, "two")
    assert target.read_text(encoding="utf-8") == "two"
    assert [p.name for p in target.parent.iterdir()] == ["out.json"]
