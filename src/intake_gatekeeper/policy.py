"""Policy loading, waivers and the approve/review/reject decision."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from intake_gatekeeper.model import Decision, Finding, Gap, GatekeeperError, Severity
from intake_gatekeeper.rules import RULES


class PolicyError(GatekeeperError):
    pass


@dataclass(frozen=True)
class Waiver:
    id: str
    reason: str
    expires: date
    component: str | None = None

    def matches(self, finding: Finding) -> bool:
        if self.id not in finding.identifiers:
            return False
        return self.component is None or self.component == finding.component_purl


@dataclass(frozen=True)
class Policy:
    reject_at: Severity = Severity.HIGH
    review_at: Severity = Severity.LOW
    unrated_vulnerability: Severity = Severity.MEDIUM
    require_vulnerability_lookup: bool = True
    disabled_rules: frozenset[str] = frozenset()
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    waivers: tuple[Waiver, ...] = ()


def _table(data: dict[str, Any], key: str, allowed: set[str]) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise PolicyError(f"[{key}] must be a table")
    unknown = set(value) - allowed
    if unknown:
        raise PolicyError(f"unknown keys in [{key}]: {', '.join(sorted(unknown))}")
    return value


def _severity(value: object, name: str) -> Severity:
    if not isinstance(value, str):
        raise PolicyError(f"{name} must be a severity string")
    try:
        return Severity.parse(value)
    except ValueError as error:
        raise PolicyError(f"{name}: {error}") from None


def load_policy(path: Path | None) -> Policy:
    if path is None:
        return Policy()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise PolicyError(f"cannot read policy {path}: {error.strerror}") from None
    except tomllib.TOMLDecodeError as error:
        raise PolicyError(f"invalid policy TOML: {error}") from None
    unknown = set(data) - {"version", "gate", "rules", "waivers"}
    if unknown:
        raise PolicyError(f"unknown top-level keys: {', '.join(sorted(unknown))}")
    if data.get("version", 1) != 1:
        raise PolicyError("unsupported policy version (expected 1)")

    gate = _table(
        data,
        "gate",
        {"reject_at", "review_at", "unrated_vulnerability", "require_vulnerability_lookup"},
    )
    defaults = Policy()
    reject_at = _severity(gate.get("reject_at", defaults.reject_at.label), "gate.reject_at")
    review_at = _severity(gate.get("review_at", defaults.review_at.label), "gate.review_at")
    if review_at > reject_at:
        raise PolicyError("gate.review_at must not be higher than gate.reject_at")
    unrated = _severity(
        gate.get("unrated_vulnerability", defaults.unrated_vulnerability.label),
        "gate.unrated_vulnerability",
    )
    require_lookup = gate.get("require_vulnerability_lookup", True)
    if not isinstance(require_lookup, bool):
        raise PolicyError("gate.require_vulnerability_lookup must be true or false")

    rules = _table(data, "rules", {"disabled", "severity"})
    disabled = rules.get("disabled", [])
    if not isinstance(disabled, list) or not all(isinstance(item, str) for item in disabled):
        raise PolicyError("rules.disabled must be a list of rule ids")
    unknown_rules = set(disabled) - set(RULES)
    if unknown_rules:
        raise PolicyError(f"unknown rule ids in rules.disabled: {', '.join(sorted(unknown_rules))}")
    overrides_raw = rules.get("severity", {})
    if not isinstance(overrides_raw, dict):
        raise PolicyError("[rules.severity] must be a table")
    overrides = {
        str(key): _severity(value, f"rules.severity.{key}") for key, value in overrides_raw.items()
    }

    waivers_raw = data.get("waivers", [])
    if not isinstance(waivers_raw, list):
        raise PolicyError("waivers must be an array of tables ([[waivers]])")
    waivers: list[Waiver] = []
    for index, item in enumerate(waivers_raw, start=1):
        if not isinstance(item, dict):
            raise PolicyError(f"waiver {index} must be a table")
        extra = set(item) - {"id", "reason", "expires", "component"}
        if extra:
            raise PolicyError(f"waiver {index}: unknown keys {', '.join(sorted(extra))}")
        waiver_id, reason, expires = item.get("id"), item.get("reason"), item.get("expires")
        component = item.get("component")
        if not isinstance(waiver_id, str) or not waiver_id.strip():
            raise PolicyError(f"waiver {index}: 'id' is required")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            raise PolicyError(f"waiver {index}: 'reason' must explain the decision (10+ chars)")
        if not isinstance(expires, date) or hasattr(expires, "hour"):
            raise PolicyError(f"waiver {index}: 'expires' must be a TOML date like 2026-12-31")
        if component is not None and not (
            isinstance(component, str) and component.startswith("pkg:")
        ):
            raise PolicyError(f"waiver {index}: 'component' must be a package URL")
        waivers.append(Waiver(waiver_id.strip(), reason.strip(), expires, component))

    return Policy(
        reject_at=reject_at,
        review_at=review_at,
        unrated_vulnerability=unrated,
        require_vulnerability_lookup=require_lookup,
        disabled_rules=frozenset(disabled),
        severity_overrides=overrides,
        waivers=tuple(waivers),
    )


def apply_policy(
    findings: list[Finding], policy: Policy, today: date
) -> tuple[list[Finding], list[Gap]]:
    gaps: list[Gap] = []
    kept: list[Finding] = []
    used: set[int] = set()
    for finding in findings:
        if finding.rule_id in policy.disabled_rules:
            continue
        for identifier in finding.identifiers:
            if identifier in policy.severity_overrides:
                finding.severity = policy.severity_overrides[identifier]
                break
        for index, waiver in enumerate(policy.waivers):
            if waiver.matches(finding):
                used.add(index)
                if waiver.expires >= today:
                    finding.waiver_reason = f"{waiver.reason} (expires {waiver.expires})"
                    break
        kept.append(finding)
    for index, waiver in enumerate(policy.waivers):
        if waiver.expires < today:
            gaps.append(
                Gap(
                    "waiver-expired",
                    f"Waiver for {waiver.id} expired on {waiver.expires}.",
                    blocking=False,
                )
            )
        elif index not in used:
            gaps.append(
                Gap("waiver-unused", f"Waiver for {waiver.id} matched no finding.", blocking=False)
            )
    return kept, gaps


def decide(findings: list[Finding], gaps: list[Gap], policy: Policy) -> tuple[Decision, list[str]]:
    active = [finding for finding in findings if not finding.waived]
    at_reject = [f for f in active if f.severity >= policy.reject_at]
    at_review = [f for f in active if policy.review_at <= f.severity < policy.reject_at]
    blocking = [gap for gap in gaps if gap.blocking]
    reasons: list[str] = []
    if at_reject:
        reasons.append(f"{len(at_reject)} finding(s) at or above {policy.reject_at.label}.")
    if at_review:
        reasons.append(
            f"{len(at_review)} finding(s) between {policy.review_at.label} and "
            f"{policy.reject_at.label}."
        )
    if blocking:
        reasons.append(
            f"{len(blocking)} coverage gap(s): "
            + "; ".join(sorted({g.code for g in blocking}))
            + "."
        )
    if at_reject:
        return Decision.REJECT, reasons
    if at_review or blocking:
        return Decision.REVIEW, reasons
    return Decision.APPROVE, ["No unwaived findings and no blocking coverage gaps."]
