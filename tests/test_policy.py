from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from intake_gatekeeper.model import Decision, Finding, Gap, Severity, Vulnerability
from intake_gatekeeper.policy import (
    Policy,
    PolicyError,
    Waiver,
    apply_policy,
    decide,
    load_policy,
)

TODAY = date(2026, 10, 14)


def _finding(rule: str = "EGK-JS-WEBVIEW-TAG", severity: Severity = Severity.LOW) -> Finding:
    return Finding(rule, severity, "t", "m")


def _vuln_finding() -> Finding:
    vulnerability = Vulnerability(
        "GHSA-p6mc-m468-83gw", ("CVE-2020-8203",), "s", Severity.HIGH, "x", (), ("4.17.19",)
    )
    return Finding(
        "GHSA-p6mc-m468-83gw",
        Severity.HIGH,
        "t",
        "m",
        component_purl="pkg:npm/lodash@4.17.15",
        vulnerability=vulnerability,
    )


def _policy(tmp_path: Path, text: str) -> Policy:
    path = tmp_path / "policy.toml"
    path.write_text(text, encoding="utf-8")
    return load_policy(path)


def test_defaults() -> None:
    policy = load_policy(None)
    assert policy.reject_at is Severity.HIGH and policy.review_at is Severity.LOW


def test_shipped_example_policy_loads() -> None:
    policy = load_policy(Path(__file__).parents[1] / "examples" / "intake-policy.toml")
    assert policy.severity_overrides == {"EGK-FUSE-RUN-AS-NODE": Severity.HIGH}
    assert policy.waivers[0].component == "pkg:npm/lodash@4.17.15"


def test_full_policy(tmp_path: Path) -> None:
    policy = _policy(
        tmp_path,
        """
version = 1
[gate]
reject_at = "critical"
review_at = "medium"
unrated_vulnerability = "high"
require_vulnerability_lookup = false
[rules]
disabled = ["EGK-JS-OPEN-EXTERNAL"]
severity = { "EGK-FUSE-RUN-AS-NODE" = "low" }
[[waivers]]
id = "CVE-2020-8203"
component = "pkg:npm/lodash@4.17.15"
reason = "Only trusted input reaches lodash in this app."
expires = 2026-12-31
""",
    )
    assert policy.reject_at is Severity.CRITICAL
    assert policy.unrated_vulnerability is Severity.HIGH
    assert policy.disabled_rules == {"EGK-JS-OPEN-EXTERNAL"}
    assert policy.severity_overrides == {"EGK-FUSE-RUN-AS-NODE": Severity.LOW}
    assert policy.waivers[0].expires == date(2026, 12, 31)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("unknown = 1", "unknown top-level"),
        ("version = 2", "version"),
        ("[gate]\nreject_at = 'severe'", "unknown severity"),
        ("[gate]\nreject_at = 'low'\nreview_at = 'high'", "must not be higher"),
        ("[gate]\ntypo = 1", "unknown keys"),
        ("[rules]\ndisabled = ['EGK-NOPE']", "unknown rule"),
        ("[[waivers]]\nid = 'X'\nreason = 'short'\nexpires = 2026-12-31", "reason"),
        ("[[waivers]]\nid = 'X'\nreason = 'long enough reason'\nexpires = '2026-12-31'", "date"),
        (
            "[[waivers]]\nid = 'X'\nreason = 'long enough reason'\nexpires = 2026-12-31T00:00:00",
            "date",
        ),
        (
            "[[waivers]]\nid='X'\nreason='long enough reason'\nexpires=2026-12-31\n"
            "component='lodash'",
            "package URL",
        ),
        ("not toml [", "invalid policy TOML"),
    ],
)
def test_invalid_policies(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        _policy(tmp_path, text)


def test_waiver_by_alias_and_component() -> None:
    waiver = Waiver(
        "CVE-2020-8203", "Reviewed and not reachable.", date(2026, 12, 31), "pkg:npm/lodash@4.17.15"
    )
    policy = Policy(waivers=(waiver,))
    findings, gaps = apply_policy([_vuln_finding()], policy, TODAY)
    assert findings[0].waived
    assert gaps == []
    assert decide(findings, [], policy)[0] is Decision.APPROVE


def test_waiver_for_another_component_does_not_apply() -> None:
    waiver = Waiver(
        "CVE-2020-8203", "Reviewed and not reachable.", date(2026, 12, 31), "pkg:npm/lodash@4.17.21"
    )
    findings, gaps = apply_policy([_vuln_finding()], Policy(waivers=(waiver,)), TODAY)
    assert not findings[0].waived
    assert [gap.code for gap in gaps] == ["waiver-unused"]


def test_expired_and_unused_waivers_are_reported() -> None:
    policy = Policy(
        waivers=(
            Waiver("GHSA-p6mc-m468-83gw", "Old acceptance of risk.", date(2026, 1, 1)),
            Waiver("GHSA-none", "Nothing matches this one.", date(2027, 1, 1)),
        )
    )
    findings, gaps = apply_policy([_vuln_finding()], policy, TODAY)
    assert not findings[0].waived
    assert [gap.code for gap in gaps] == ["waiver-expired", "waiver-unused"]
    assert all(not gap.blocking for gap in gaps)


def test_disabled_rules_and_overrides() -> None:
    policy = Policy(
        disabled_rules=frozenset({"EGK-JS-OPEN-EXTERNAL"}),
        severity_overrides={"EGK-JS-WEBVIEW-TAG": Severity.CRITICAL},
    )
    findings, _ = apply_policy(
        [_finding("EGK-JS-OPEN-EXTERNAL", Severity.INFO), _finding()], policy, TODAY
    )
    assert [(f.rule_id, f.severity) for f in findings] == [
        ("EGK-JS-WEBVIEW-TAG", Severity.CRITICAL)
    ]


@pytest.mark.parametrize(
    ("findings", "gaps", "expected"),
    [
        ([], [], Decision.APPROVE),
        ([_finding(severity=Severity.INFO)], [], Decision.APPROVE),
        ([_finding(severity=Severity.LOW)], [], Decision.REVIEW),
        ([_finding(severity=Severity.HIGH)], [], Decision.REJECT),
        ([], [Gap("lookup-disabled", "x")], Decision.REVIEW),
        ([], [Gap("links-skipped", "x", blocking=False)], Decision.APPROVE),
        ([_finding(severity=Severity.CRITICAL)], [Gap("x", "y")], Decision.REJECT),
    ],
)
def test_decision_matrix(findings: list[Finding], gaps: list[Gap], expected: Decision) -> None:
    decision, reasons = decide(findings, gaps, Policy())
    assert decision is expected
    assert reasons
