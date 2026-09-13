"""Fail closed on current OSV matches for the exact public PyPI lock graph.

Sends package names/versions only. No application imports, installs or secrets.
Provenance and the live 72-hour gate remain separate required checks.
"""
from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from tools.check_dependency_policy import _reviewed_ca_context, check_trust_bundle

ROOT = Path(__file__).resolve().parents[1]
URL = "https://api.osv.dev/v1/querybatch"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("OSV redirects are forbidden")


def locked_packages(lock: dict) -> list[tuple[str, str]]:
    packages = []
    for item in lock["package"]:
        if item.get("source") == {"virtual": "."}:
            continue
        if item.get("source") != {"registry": "https://pypi.org/simple"}:
            raise ValueError("Only reviewed PyPI registry packages may be queried")
        name, version = item["name"], item["version"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            raise ValueError("Invalid package name")
        if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", version):
            raise ValueError("Invalid package version")
        packages.append((name, version))
    if not packages or len(packages) > 1000 or len(set(packages)) != len(packages):
        raise ValueError("Invalid lock query size or duplicate package")
    return packages


def advisory_matches(packages: list[tuple[str, str]], payload: object) -> list[str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("Malformed OSV result")
    results = payload["results"]
    if len(results) != len(packages):
        raise ValueError("OSV did not answer every package query")
    matches = []
    for (name, version), result in zip(packages, results):
        if not isinstance(result, dict) or set(result) - {"vulns", "next_page_token"}:
            raise ValueError("Malformed OSV package result")
        if result.get("next_page_token"):
            raise ValueError("Incomplete paginated OSV result requires review")
        vulns = result.get("vulns", [])
        if not isinstance(vulns, list):
            raise ValueError("Malformed OSV vulnerability list")
        for vuln in vulns:
            identifier = vuln.get("id") if isinstance(vuln, dict) else None
            if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", identifier):
                raise ValueError("Invalid advisory identifier")
            matches.append(f"{name}=={version}: {identifier}")
    return matches


def main() -> int:
    packages = locked_packages(tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8")))
    body = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in packages]}
    context = _reviewed_ca_context(check_trust_bundle())
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirects())
    request = Request(URL, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "Accept": "application/json"})
    with opener.open(request, timeout=30) as response:
        if response.status != 200 or response.geturl() != URL:
            raise ValueError("Unexpected OSV status or destination")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("OSV response exceeded the size limit")
    matches = advisory_matches(packages, json.loads(raw))
    if matches:
        print("Advisory check FAILED:\n" + "\n".join(matches))
        return 1
    print(f"Advisory check OK: {len(packages)} locked packages, no current OSV matches")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, AssertionError):
        print("Advisory check FAILED: authoritative complete verification unavailable", file=sys.stderr)
        raise SystemExit(1)
