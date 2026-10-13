"""Bounded, privacy-aware client for the public OSV.dev vulnerability API."""

from __future__ import annotations

import ssl
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
import truststore

from intake_gatekeeper import __version__
from intake_gatekeeper.model import (
    Component,
    Gap,
    GatekeeperError,
    Severity,
    Vulnerability,
    nearest_fix,
    sort_versions,
)

DEFAULT_URL = "https://api.osv.dev"
_BATCH_SIZE = 1000
_MAX_PAGES = 10
_RETRY_STATUS = {429, 500, 502, 503, 504}


class OsvError(Exception):
    pass


@dataclass
class LookupResult:
    vulnerabilities: dict[tuple[str, str, str], list[Vulnerability]] = field(default_factory=dict)
    gaps: list[Gap] = field(default_factory=list)
    queried: int = 0


def validate_base_url(url: str) -> str:
    parts = urlsplit(url)
    local = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise GatekeeperError("OSV URL must use https (http is allowed only for localhost)")
    if not parts.hostname or parts.query or parts.fragment or parts.username:
        raise GatekeeperError("OSV URL must be a plain origin such as https://api.osv.dev")
    return url.rstrip("/")


def default_http_client(timeout: float) -> httpx.Client:
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    return httpx.Client(
        verify=context,
        timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
        follow_redirects=False,
        headers={"User-Agent": f"software-intake-gatekeeper/{__version__}"},
    )


class OsvClient:
    def __init__(
        self,
        base_url: str = DEFAULT_URL,
        client: httpx.Client | None = None,
        timeout: float = 20.0,
        max_details: int = 3000,
        workers: int = 6,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._base = validate_base_url(base_url)
        self._client = client or default_http_client(timeout)
        self._max_details = max_details
        self._workers = workers
        self._sleep = sleep

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        delay = 1.0
        last_error = "no response"
        for attempt in range(4):
            if attempt:
                self._sleep(delay)
                delay *= 2
            try:
                response = self._client.request(method, self._base + path, json=body)
            except httpx.HTTPError as error:
                last_error = type(error).__name__
                continue
            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError:
                    raise OsvError(f"OSV returned invalid JSON for {path}") from None
            if response.status_code == 404 and method == "GET":
                return None
            last_error = f"HTTP {response.status_code}"
            if response.status_code not in _RETRY_STATUS:
                break
            retry_after = response.headers.get("Retry-After", "")
            if retry_after.isdigit():
                delay = min(float(retry_after), 10.0)
        raise OsvError(f"OSV request {method} {path} failed: {last_error}")

    def _ids_for(self, components: list[Component]) -> list[set[str]]:
        found: list[set[str]] = [set() for _ in components]
        for start in range(0, len(components), _BATCH_SIZE):
            chunk = components[start : start + _BATCH_SIZE]
            queries = [_query(component) for component in chunk]
            payload = self._request("POST", "/v1/querybatch", {"queries": queries})
            results = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(results, list) or len(results) != len(chunk):
                raise OsvError("OSV batch response does not match the query count")
            for offset, result in enumerate(results):
                ids = found[start + offset]
                if not isinstance(result, dict):
                    raise OsvError("OSV batch result is not an object")
                ids.update(_ids(result.get("vulns")))
                token = result.get("next_page_token")
                pages = 0
                while isinstance(token, str) and token and pages < _MAX_PAGES:
                    pages += 1
                    page = self._request(
                        "POST", "/v1/query", {**queries[offset], "page_token": token}
                    )
                    if not isinstance(page, dict):
                        raise OsvError("OSV page response is not an object")
                    ids.update(_ids(page.get("vulns")))
                    token = page.get("next_page_token")
                if isinstance(token, str) and token:
                    raise OsvError("OSV result exceeded the page limit")
        return found

    def _details(self, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        unique = sorted(set(ids))
        if len(unique) > self._max_details:
            raise OsvError(f"more than {self._max_details} advisories; raise the limit")

        def fetch(vuln_id: str) -> tuple[str, Any]:
            return vuln_id, self._request("GET", f"/v1/vulns/{quote(vuln_id, safe='')}")

        records: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            for vuln_id, record in pool.map(fetch, unique):
                if isinstance(record, dict) and record.get("id") == vuln_id:
                    records[vuln_id] = record
        return records

    def lookup(self, components: list[Component]) -> LookupResult:
        queryable = [component for component in components if component.queryable]
        result = LookupResult(queried=len(queryable))
        if not queryable:
            return result
        try:
            per_component = self._ids_for(queryable)
            records = self._details(set[str]().union(*per_component))
            missing_severity = {
                alias
                for record in records.values()
                if _own_severity(record) is None
                for alias in _strings(record.get("aliases"))
                if alias.startswith("GHSA-") and alias not in records
            }
            records.update(self._details(missing_severity))
        except OsvError as error:
            result.gaps.append(Gap("osv-error", f"Vulnerability lookup incomplete: {error}."))
            return result
        for component, ids in zip(queryable, per_component, strict=True):
            vulns = _group(component, [records[i] for i in sorted(ids) if i in records], records)
            if vulns:
                result.vulnerabilities[component.key] = vulns
            if len(ids - records.keys()) > 0:
                result.gaps.append(
                    Gap("osv-error", "Some advisories could not be retrieved.", component.purl)
                )
        return result


def _query(component: Component) -> dict[str, Any]:
    return {
        "package": {"name": component.name, "ecosystem": component.ecosystem},
        "version": component.version,
    }


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _ids(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {
        item["id"] for item in value if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _own_severity(record: dict[str, Any]) -> Severity | None:
    specific = record.get("database_specific")
    if isinstance(specific, dict) and isinstance(specific.get("severity"), str):
        try:
            return Severity.parse(specific["severity"])
        except ValueError:
            return None
    return None


def _fixed_versions(component: Component, record: dict[str, Any]) -> set[str]:
    fixed: set[str] = set()
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict):
            continue
        if package.get("ecosystem") != component.ecosystem:
            continue
        if str(package.get("name", "")).casefold() != component.name.casefold():
            continue
        for range_ in affected.get("ranges") or []:
            if not isinstance(range_, dict) or range_.get("type") == "GIT":
                continue
            for event in range_.get("events") or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.add(event["fixed"])
    return fixed


def _group(
    component: Component, records: list[dict[str, Any]], all_records: dict[str, dict[str, Any]]
) -> list[Vulnerability]:
    active = [record for record in records if not record.get("withdrawn")]
    parent: dict[str, str] = {}

    def find(item: str) -> str:
        while parent.setdefault(item, item) != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    by_id = {record["id"]: record for record in active}
    for record in active:
        for alias in _strings(record.get("aliases")):
            if alias in by_id:
                parent[find(alias)] = find(record["id"])
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in active:
        groups.setdefault(find(record["id"]), []).append(record)

    vulnerabilities: list[Vulnerability] = []
    for members in groups.values():
        ids = sorted(record["id"] for record in members)
        primary = next((i for i in ids if i.startswith("GHSA-")), ids[0])
        aliases = sorted(
            {alias for record in members for alias in _strings(record.get("aliases"))} | set(ids)
        )
        aliases.remove(primary)
        severity: Severity | None = None
        source = "unrated"
        for record in members:
            rated = _own_severity(record)
            if rated is not None and (severity is None or rated > severity):
                severity, source = rated, f"{record['id']} database severity"
        if severity is None:
            for alias in aliases:
                linked = all_records.get(alias)
                rated = _own_severity(linked) if linked else None
                if rated is not None and (severity is None or rated > severity):
                    severity, source = rated, f"{alias} database severity"
        vectors = sorted(
            {
                str(item["score"])
                for record in members
                for item in record.get("severity") or []
                if isinstance(item, dict) and isinstance(item.get("score"), str)
            }
        )
        summary = next(
            (str(r["summary"]) for r in members if r["id"] == primary and r.get("summary")), ""
        ) or next((str(r["summary"]) for r in members if r.get("summary")), "")
        if not summary:
            details = next((str(r["details"]) for r in members if r.get("details")), "")
            summary = details.strip().split("\n", 1)[0][:200]
        fixed: set[str] = set()
        for record in members:
            fixed |= _fixed_versions(component, record)
        fixed_versions = sort_versions(fixed)
        vulnerabilities.append(
            Vulnerability(
                id=primary,
                aliases=tuple(aliases),
                summary=summary or "No summary provided.",
                severity=severity,
                severity_source=source,
                cvss_vectors=tuple(vectors),
                fixed_versions=fixed_versions,
                nearest_fix=nearest_fix(component.version, fixed_versions),
            )
        )
    vulnerabilities.sort(key=lambda v: (-(v.severity if v.severity is not None else -1), v.id))
    return vulnerabilities
