"""Offline-cached OSV.dev, CISA KEV, and FIRST EPSS advisory feed manager.

Security boundary:
  - `sync_advisory_cache()` is strictly opt-in via `vulnbox sync-advisories` and fetches
    vulnerability metadata from OSV.dev, CISA KEV, and FIRST EPSS into a local JSON cache.
  - `load_offline_osv_advisories()` and `load_offline_enrichment()` are 100% offline/air-gapped
    and never open network sockets during `vulnbox scan` or `vulnbox remediate`.
"""

from __future__ import annotations

import json
import os
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnbox.analyzers.lockfiles import (
    InstalledPackage,
    parse_node_dependencies,
    parse_python_dependencies,
)

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"

# Curated baseline EPSS/KEV enrichment for offline built-in advisories when no live cache exists
BUILTIN_KEV_CVES: frozenset[str] = frozenset(
    {
        "CVE-2020-14343",
    }
)
BUILTIN_EPSS_SCORES: dict[str, dict[str, float]] = {
    "CVE-2020-14343": {"epss": 0.912, "percentile": 0.996},
    "CVE-2023-45803": {"epss": 0.041, "percentile": 0.721},
    "CVE-2021-23337": {"epss": 0.348, "percentile": 0.968},
    "CVE-2021-44906": {"epss": 0.164, "percentile": 0.955},
    "CVE-2024-29041": {"epss": 0.019, "percentile": 0.584},
}


def default_advisory_cache_dir() -> Path:
    env_dir = os.environ.get("VULNBOX_ADVISORY_CACHE")
    if env_dir:
        return Path(env_dir).expanduser().resolve()
    return (Path.home() / ".cache" / "vulnbox" / "advisories").resolve()


def _http_json(url: str, body: dict[str, Any] | None = None, timeout: int = 20) -> Any:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"User-Agent": "VulnBox-AdvisorySync/0.1", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _osv_severity_to_vulnbox(vuln: dict[str, Any]) -> str:
    db_spec = vuln.get("database_specific") or {}
    raw = str(db_spec.get("severity") or "").upper()
    if raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return raw.lower()
    if raw == "MODERATE":
        return "medium"
    for sev in vuln.get("severity") or []:
        score_str = str(sev.get("score") or "")
        try:
            score = float(score_str)
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
        except ValueError:
            continue
    return "high"


def normalize_osv_record(
    vuln: dict[str, Any],
    ecosystem: str,
    package_name: str,
) -> dict[str, Any] | None:
    """Convert a raw OSV.dev vulnerability JSON entry into a VulnBox Advisory dict."""
    aliases = [str(a) for a in (vuln.get("aliases") or [])]
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
    advisory_id = cve_id or str(vuln.get("id") or "")
    if not advisory_id:
        return None

    fixed_version = ""
    vulnerable_symbols: list[str] = []
    target_eco = "PyPI" if ecosystem == "python" else "npm"

    for aff in vuln.get("affected") or []:
        pkg_info = aff.get("package") or {}
        if str(pkg_info.get("ecosystem") or "").lower() != target_eco.lower():
            continue
        if str(pkg_info.get("name") or "").lower() != package_name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    fixed_version = str(ev["fixed"])
        eco_spec = aff.get("ecosystem_specific") or {}
        for imp in eco_spec.get("imports") or []:
            if isinstance(imp, dict):
                for sym in imp.get("symbols") or []:
                    vulnerable_symbols.append(str(sym))

    if not fixed_version:
        return None

    db_spec = vuln.get("database_specific") or {}
    cwes = db_spec.get("cwe_ids") or []
    cwe_id = str(cwes[0]) if cwes else "CWE-1104"
    title = str(vuln.get("summary") or f"{package_name} vulnerability {advisory_id}")[:140]

    return {
        "advisory_id": advisory_id,
        "ecosystem": ecosystem,
        "package": package_name.lower(),
        "affected_below": fixed_version,
        "fixed_version": fixed_version,
        "severity": _osv_severity_to_vulnbox(vuln),
        "cwe_id": cwe_id,
        "title": title,
        "imports": [package_name.lower().replace("-", "_")],
        "vulnerable_symbols": sorted(set(vulnerable_symbols)),
        "aliases": aliases,
    }


def sync_advisory_cache(
    repo_path: Path | None = None,
    cache_dir: Path | None = None,
    include_kev: bool = True,
    include_epss: bool = True,
) -> dict[str, Any]:
    """Fetch OSV.dev advisories (for repo dependencies), CISA KEV, and FIRST EPSS offline cache."""
    cdir = Path(cache_dir or default_advisory_cache_dir()).resolve()
    cdir.mkdir(parents=True, exist_ok=True)

    advisories: list[dict[str, Any]] = []
    seen_ids: set[tuple[str, str, str]] = set()
    cve_ids_for_epss: set[str] = set(BUILTIN_EPSS_SCORES)

    # Preserve existing cached advisories so multiple repos accumulate offline coverage
    osv_cache_file = cdir / "osv_cache.json"
    if osv_cache_file.is_file():
        try:
            existing = json.loads(osv_cache_file.read_text(encoding="utf-8"))
            for item in existing.get("advisories") or []:
                key = (
                    str(item.get("advisory_id", "")),
                    str(item.get("ecosystem", "")),
                    str(item.get("package", "")),
                )
                if key not in seen_ids:
                    seen_ids.add(key)
                    advisories.append(item)
                    if key[0].startswith("CVE-"):
                        cve_ids_for_epss.add(key[0])
        except (OSError, json.JSONDecodeError):
            pass

    queried_packages = 0
    if repo_path is not None:
        pkgs: list[InstalledPackage] = [
            *parse_python_dependencies(repo_path),
            *parse_node_dependencies(repo_path),
        ]
        # Deduplicate queries by (ecosystem, name, clean_version)
        unique_pkgs: list[InstalledPackage] = []
        seen_q: set[tuple[str, str, str]] = set()
        for p in pkgs:
            clean_v = p.version.strip().lstrip("^~>=<v")
            qk = (p.ecosystem, p.name, clean_v)
            if clean_v and qk not in seen_q:
                seen_q.add(qk)
                unique_pkgs.append(p)

        queried_packages = len(unique_pkgs)
        for start in range(0, len(unique_pkgs), 100):
            batch = unique_pkgs[start : start + 100]
            queries = [
                {
                    "package": {
                        "name": p.name,
                        "ecosystem": "PyPI" if p.ecosystem == "python" else "npm",
                    },
                    "version": p.version.strip().lstrip("^~>=<v"),
                }
                for p in batch
            ]
            resp = _http_json(OSV_QUERYBATCH_URL, body={"queries": queries})
            results = resp.get("results") or []
            for pkg, res in zip(batch, results, strict=False):
                for stub in (res.get("vulns") or [])[:25]:
                    vid = stub.get("id")
                    if not vid:
                        continue
                    try:
                        full_vuln = _http_json(f"{OSV_VULN_URL}{vid}")
                    except Exception:
                        continue
                    norm = normalize_osv_record(full_vuln, pkg.ecosystem, pkg.name)
                    if norm is None:
                        continue
                    key = (norm["advisory_id"], norm["ecosystem"], norm["package"])
                    if key not in seen_ids:
                        seen_ids.add(key)
                        advisories.append(norm)
                        if norm["advisory_id"].startswith("CVE-"):
                            cve_ids_for_epss.add(norm["advisory_id"])

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    osv_cache_file.write_text(
        json.dumps({"updated_at": now, "advisories": advisories}, indent=2) + "\n",
        encoding="utf-8",
    )

    kev_count = 0
    if include_kev:
        kev_data = _http_json(CISA_KEV_URL)
        kev_cves = sorted(
            {
                str(v.get("cveID"))
                for v in (kev_data.get("vulnerabilities") or [])
                if v.get("cveID")
            }
        )
        kev_count = len(kev_cves)
        (cdir / "kev_cache.json").write_text(
            json.dumps({"updated_at": now, "cves": kev_cves}, indent=2) + "\n",
            encoding="utf-8",
        )

    epss_count = 0
    if include_epss and cve_ids_for_epss:
        epss_map: dict[str, dict[str, float]] = {}
        sorted_cves = sorted(cve_ids_for_epss)
        for start in range(0, len(sorted_cves), 80):
            chunk = ",".join(sorted_cves[start : start + 80])
            epss_resp = _http_json(f"{FIRST_EPSS_URL}?cve={chunk}")
            for row in epss_resp.get("data") or []:
                cid = str(row.get("cve") or "")
                if cid:
                    try:
                        epss_map[cid] = {
                            "epss": round(float(row.get("epss", 0.0)), 5),
                            "percentile": round(float(row.get("percentile", 0.0)), 5),
                        }
                    except (TypeError, ValueError):
                        pass
        epss_count = len(epss_map)
        (cdir / "epss_cache.json").write_text(
            json.dumps({"updated_at": now, "scores": epss_map}, indent=2) + "\n",
            encoding="utf-8",
        )

    return {
        "cache_dir": str(cdir),
        "queried_packages": queried_packages,
        "osv_advisories_cached": len(advisories),
        "kev_cves_cached": kev_count,
        "epss_scores_cached": epss_count,
        "updated_at": now,
    }


def load_offline_osv_advisories(cache_dir: Path | None = None) -> list[dict[str, Any]]:
    """Read locally cached OSV advisories with zero network calls."""
    cdir = Path(cache_dir or default_advisory_cache_dir())
    osv_file = cdir / "osv_cache.json"
    if not osv_file.is_file():
        return []
    try:
        data = json.loads(osv_file.read_text(encoding="utf-8"))
        items = data.get("advisories")
        return items if isinstance(items, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def load_offline_enrichment(
    cache_dir: Path | None = None,
) -> tuple[set[str], dict[str, dict[str, float]]]:
    """Return offline `(cisa_kev_cves, epss_scores_map)` merging bundled defaults + local cache."""
    kev_set: set[str] = set(BUILTIN_KEV_CVES)
    epss_map: dict[str, dict[str, float]] = {k: dict(v) for k, v in BUILTIN_EPSS_SCORES.items()}

    cdir = Path(cache_dir or default_advisory_cache_dir())
    kev_file = cdir / "kev_cache.json"
    if kev_file.is_file():
        try:
            data = json.loads(kev_file.read_text(encoding="utf-8"))
            for cid in data.get("cves") or []:
                if isinstance(cid, str):
                    kev_set.add(cid)
        except (OSError, json.JSONDecodeError):
            pass

    epss_file = cdir / "epss_cache.json"
    if epss_file.is_file():
        try:
            data = json.loads(epss_file.read_text(encoding="utf-8"))
            scores = data.get("scores") or {}
            if isinstance(scores, dict):
                for cid, entry in scores.items():
                    if isinstance(entry, dict) and "epss" in entry:
                        epss_map[str(cid)] = {
                            "epss": float(entry.get("epss", 0.0)),
                            "percentile": float(entry.get("percentile", 0.0)),
                        }
        except (OSError, json.JSONDecodeError):
            pass

    return kev_set, epss_map
