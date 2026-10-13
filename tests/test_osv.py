from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from intake_gatekeeper.model import Component, GatekeeperError, Severity
from intake_gatekeeper.osv import OsvClient, validate_base_url

Handler = Callable[[httpx.Request], httpx.Response]

TEXT = Component("Go", "golang.org/x/text", "v0.3.7")
LODASH = Component("npm", "lodash", "4.17.15")
LOCAL = Component("npm", "app", "1.0.0", queryable=False)

RECORDS: dict[str, dict[str, Any]] = {
    "GHSA-69ch-w2m2-3vjp": {
        "id": "GHSA-69ch-w2m2-3vjp",
        "aliases": ["CVE-2022-32149", "GO-2022-1059"],
        "summary": "Denial of service via crafted Accept-Language header",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "golang.org/x/text"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.3.8"}]}],
            }
        ],
    },
    "GO-2022-1059": {
        "id": "GO-2022-1059",
        "aliases": ["CVE-2022-32149", "GHSA-69ch-w2m2-3vjp"],
        "summary": "Denial of service in golang.org/x/text/language",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "golang.org/x/text"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.3.8"}]}],
            }
        ],
    },
    "GO-2099-0001": {
        "id": "GO-2099-0001",
        "aliases": ["GHSA-aaaa-bbbb-cccc"],
        "details": "Synthetic advisory without summary.\nSecond line.",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "golang.org/x/text"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.39.0"}]}
                ],
            }
        ],
    },
    "GHSA-aaaa-bbbb-cccc": {
        "id": "GHSA-aaaa-bbbb-cccc",
        "summary": "Linked advisory",
        "database_specific": {"severity": "MODERATE"},
    },
    "GHSA-p6mc-m468-83gw": {
        "id": "GHSA-p6mc-m468-83gw",
        "summary": "Prototype pollution in lodash",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "3.7.0"}, {"fixed": "4.17.19"}]}
                ],
            }
        ],
    },
    "GHSA-withdrawn": {"id": "GHSA-withdrawn", "withdrawn": "2024-01-01T00:00:00Z"},
}
BATCH = {
    "golang.org/x/text": ["GHSA-69ch-w2m2-3vjp", "GO-2022-1059", "GO-2099-0001"],
    "lodash": ["GHSA-p6mc-m468-83gw", "GHSA-withdrawn"],
}


def _server(log: list[httpx.Request], fail: dict[str, list[int]] | None = None) -> Handler:
    fail = fail or {}

    def handle(request: httpx.Request) -> httpx.Response:
        log.append(request)
        statuses = fail.get(request.url.path)
        if statuses:
            return httpx.Response(statuses.pop(0), headers={"Retry-After": "0"})
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            results = [
                {"vulns": [{"id": i} for i in BATCH.get(q["package"]["name"], [])]} for q in queries
            ]
            return httpx.Response(200, json={"results": results})
        vuln_id = request.url.path.rsplit("/", 1)[1]
        if vuln_id in RECORDS:
            return httpx.Response(200, json=RECORDS[vuln_id])
        return httpx.Response(404, json={"message": "not found"})

    return handle


def _client(handler: Handler) -> OsvClient:
    return OsvClient(
        client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None
    )


def test_lookup_groups_aliases_and_resolves_severity() -> None:
    log: list[httpx.Request] = []
    result = _client(_server(log)).lookup([TEXT, LODASH, LOCAL])
    assert result.gaps == []
    assert result.queried == 2
    sent = json.loads(log[0].content)["queries"]
    assert sent == [
        {"package": {"name": "golang.org/x/text", "ecosystem": "Go"}, "version": "v0.3.7"},
        {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.15"},
    ]
    text = result.vulnerabilities[TEXT.key]
    assert [v.id for v in text] == ["GHSA-69ch-w2m2-3vjp", "GO-2099-0001"]
    merged, linked = text
    assert set(merged.aliases) == {"CVE-2022-32149", "GO-2022-1059"}
    assert merged.severity is Severity.HIGH
    assert merged.fixed_versions == ("0.3.8",)
    assert merged.nearest_fix == "0.3.8"
    assert merged.cvss_vectors[0].startswith("CVSS:3.1/")
    assert linked.severity is Severity.MEDIUM
    assert linked.severity_source == "GHSA-aaaa-bbbb-cccc database severity"
    assert linked.summary == "Synthetic advisory without summary."
    (lodash,) = result.vulnerabilities[LODASH.key]
    assert lodash.id == "GHSA-p6mc-m468-83gw"
    assert LOCAL.key not in result.vulnerabilities


def test_retries_transient_errors() -> None:
    log: list[httpx.Request] = []
    result = _client(_server(log, {"/v1/querybatch": [503, 429]})).lookup([LODASH])
    assert result.gaps == []
    assert [r.url.path for r in log[:3]] == ["/v1/querybatch"] * 3


def test_persistent_failure_is_a_blocking_gap() -> None:
    log: list[httpx.Request] = []
    result = _client(_server(log, {"/v1/querybatch": [500] * 4})).lookup([LODASH])
    assert result.vulnerabilities == {}
    (gap,) = result.gaps
    assert gap.code == "osv-error" and gap.blocking
    assert len(log) == 4


def test_client_errors_are_not_retried() -> None:
    log: list[httpx.Request] = []
    result = _client(_server(log, {"/v1/querybatch": [400]})).lookup([LODASH])
    assert result.gaps[0].code == "osv-error"
    assert len(log) == 1


def test_mismatched_batch_response_is_rejected() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": []})

    result = _client(handle).lookup([LODASH])
    assert "does not match" in result.gaps[0].message


def test_pagination_follows_tokens() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={
                    "results": [{"vulns": [{"id": "GHSA-p6mc-m468-83gw"}], "next_page_token": "t"}]
                },
            )
        if request.url.path == "/v1/query":
            assert json.loads(request.content)["page_token"] == "t"
            return httpx.Response(200, json={"vulns": [{"id": "GHSA-withdrawn"}]})
        return httpx.Response(200, json=RECORDS[request.url.path.rsplit("/", 1)[1]])

    result = _client(handle).lookup([LODASH])
    assert [v.id for v in result.vulnerabilities[LODASH.key]] == ["GHSA-p6mc-m468-83gw"]


def test_no_queryable_components_makes_no_requests() -> None:
    log: list[httpx.Request] = []
    result = _client(_server(log)).lookup([LOCAL])
    assert log == [] and result.queried == 0


@pytest.mark.parametrize(
    "url",
    ["http://api.osv.dev", "ftp://x", "https://user@api.osv.dev", "https://api.osv.dev/?q=1"],
)
def test_rejects_unsafe_base_urls(url: str) -> None:
    with pytest.raises(GatekeeperError):
        validate_base_url(url)


def test_allows_https_and_local_http() -> None:
    assert validate_base_url("https://api.osv.dev/") == "https://api.osv.dev"
    assert validate_base_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
