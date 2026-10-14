"""Opt-in smoke test against the public OSV.dev API (set INTAKE_LIVE_OSV=1)."""

from __future__ import annotations

import os

import pytest

from intake_gatekeeper.model import Component
from intake_gatekeeper.osv import OsvClient

pytestmark = pytest.mark.skipif(os.environ.get("INTAKE_LIVE_OSV") != "1", reason="live OSV test is opt-in")


def test_known_advisories_are_returned() -> None:
    text = Component("Go", "golang.org/x/text", "v0.3.7")
    newtonsoft = Component("NuGet", "Newtonsoft.Json", "12.0.1")
    client = OsvClient()
    try:
        result = client.lookup([text, newtonsoft])
    finally:
        client.close()
    assert result.gaps == []
    text_ids = {v.id for v in result.vulnerabilities[text.key]}
    assert "GHSA-69ch-w2m2-3vjp" in text_ids
    assert all(v.id != "GO-2022-1059" for v in result.vulnerabilities[text.key])
    (newtonsoft_vuln,) = result.vulnerabilities[newtonsoft.key]
    assert newtonsoft_vuln.id == "GHSA-5crp-9r3c-p9vr"
    assert newtonsoft_vuln.nearest_fix == "13.0.1"
