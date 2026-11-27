"""Offline-cached OSV.dev, CISA KEV, and FIRST EPSS advisory feed manager.

Security boundary:
  - `sync_advisory_cache()` is strictly opt-in via `vulnbox sync-advisories` and fetches
    vulnerability metadata from OSV.dev, CISA KEV, and FIRST EPSS into a local JSON cache.
  - `load_offline_osv_advisories()` and `load_offline_enrichment()` are 100% offline/air-gapped
    and never open network sockets during `vulnbox scan` or `vulnbox remediate`.
"""

from __future__ import annotations

import json
import math
import os
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnbox.analyzers.lockfiles import (
    InstalledPackage,
    parse_go_mod,
    parse_node_dependencies,
    parse_python_dependencies,
)

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"

# Well-known PyPI distribution -> top-level Python import module mappings where
# `package.replace("-", "_")` does NOT match the actual runtime import name.
PYPI_IMPORT_ALIASES: dict[str, list[str]] = {
    "pyyaml": ["yaml"],
    "pillow": ["PIL"],
    "beautifulsoup4": ["bs4"],
    "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"],
    "opencv-python-headless": ["cv2"],
    "opencv-contrib-python": ["cv2"],
    "python-dateutil": ["dateutil"],
    "python-jose": ["jose"],
    "pyjwt": ["jwt"],
    "python-dotenv": ["dotenv"],
    "pycryptodome": ["Crypto"],
    "pycryptodomex": ["Cryptodome"],
    "attrs": ["attr", "attrs"],
    "msgpack-python": ["msgpack"],
    "pyopenssl": ["OpenSSL"],
    "python-multipart": ["multipart", "python_multipart"],
    "python-magic": ["magic"],
    "psycopg2-binary": ["psycopg2"],
    "mysqlclient": ["MySQLdb"],
    "ruamel.yaml": ["ruamel"],
    "google-auth": ["google"],
    "protobuf": ["google"],
    "pynacl": ["nacl"],
    "pypdf2": ["PyPDF2"],
    "pymupdf": ["fitz"],
    "pycryptodome-test-vectors": ["Cryptodome"],
    "django": ["django"],
    "flask": ["flask"],
    "fastapi": ["fastapi"],
}

# CVSS v3.0 / v3.1 metric weights (FIRST CVSS v3.1 specification)
_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def compute_cvss_v3_base_score(vector: str) -> float | None:
    """Compute exact FIRST CVSS v3.0 / v3.1 base score from a CVSS vector string."""
    v = vector.strip()
    if not v.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics: dict[str, str] = {}
    for part in v.split("/")[1:]:
        if ":" in part:
            k, val = part.split(":", 1)
            metrics[k.upper()] = val.upper()
    try:
        av = _CVSS3_AV[metrics["AV"]]
        ac = _CVSS3_AC[metrics["AC"]]
        scope = metrics["S"]
        pr = (_CVSS3_PR_C if scope == "C" else _CVSS3_PR_U)[metrics["PR"]]
        ui = _CVSS3_UI[metrics["UI"]]
        c = _CVSS3_CIA[metrics["C"]]
        i = _CVSS3_CIA[metrics["I"]]
        a = _CVSS3_CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * iss
    elif scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        return None

    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (
        min(impact + exploitability, 10.0)
        if scope == "U"
        else min(1.08 * (impact + exploitability), 10.0)
    )
    # FIRST CVSS v3.1 Roundup(x): round up to 1 decimal place
    return math.ceil(round(raw * 100_000) / 10_000) / 10.0


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _resolve_python_imports(package_name: str) -> list[str]:
    low = package_name.lower()
    if low in PYPI_IMPORT_ALIASES:
        return list(PYPI_IMPORT_ALIASES[low])
    base = low.replace("-", "_").replace(".", "_")
    return [base]

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

    best_score: float | None = None
    for sev in vuln.get("severity") or []:
        score_str = str(sev.get("score") or "").strip()
        if not score_str:
            continue
        computed = compute_cvss_v3_base_score(score_str)
        if computed is None:
            try:
                computed = float(score_str)
            except ValueError:
                computed = None
        if computed is not None and (best_score is None or computed > best_score):
            best_score = computed

    if best_score is not None:
        return _score_to_severity(best_score)
    return "medium"


def normalize_osv_record(
    vuln: dict[str, Any],
    ecosystem: str,
    package_name: str,
) -> dict[str, Any] | None:
    """Convert a raw OSV.dev vulnerability JSON entry into a VulnBox Advisory dict.

    Preserves full multi-branch `affected_ranges` (`introduced` / `fixed` / `last_affected`),
    PyPI distribution-to-import aliases, and Go/PyPI ecosystem_specific symbol paths.
    """
    aliases = [str(a) for a in (vuln.get("aliases") or [])]
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
    advisory_id = cve_id or str(vuln.get("id") or "")
    if not advisory_id:
        return None

    affected_ranges: list[dict[str, str]] = []
    vulnerable_symbols: list[str] = []
    go_import_paths: list[str] = []
    eco_map = {"python": "PyPI", "node": "npm", "go": "Go"}
    target_eco = eco_map.get(ecosystem.lower(), ecosystem)

    for aff in vuln.get("affected") or []:
        pkg_info = aff.get("package") or {}
        if str(pkg_info.get("ecosystem") or "").lower() != target_eco.lower():
            continue
        if str(pkg_info.get("name") or "").lower() != package_name.lower():
            continue
        for rng in aff.get("ranges") or []:
            cur_intro = "0"
            for ev in rng.get("events") or []:
                if not isinstance(ev, dict):
                    continue
                if ev.get("introduced") is not None:
                    cur_intro = str(ev["introduced"])
                elif ev.get("fixed"):
                    affected_ranges.append({"introduced": cur_intro, "fixed": str(ev["fixed"])})
                    cur_intro = "0"
                elif ev.get("last_affected"):
                    affected_ranges.append(
                        {"introduced": cur_intro, "last_affected": str(ev["last_affected"])}
                    )
                    cur_intro = "0"
            # Open-ended introduced range with no fix yet
            if cur_intro != "0" and not any(r.get("introduced") == cur_intro for r in affected_ranges):
                affected_ranges.append({"introduced": cur_intro})

        eco_spec = aff.get("ecosystem_specific") or {}
        for imp in eco_spec.get("imports") or []:
            if isinstance(imp, dict):
                imp_path = imp.get("path")
                if isinstance(imp_path, str) and imp_path:
                    go_import_paths.append(imp_path)
                for sym in imp.get("symbols") or []:
                    vulnerable_symbols.append(str(sym))

    fixed_versions = [r["fixed"] for r in affected_ranges if r.get("fixed")]
    if not affected_ranges:
        return None
    fallback_fixed = fixed_versions[-1] if fixed_versions else ""

    db_spec = vuln.get("database_specific") or {}
    cwes = db_spec.get("cwe_ids") or []
    cwe_id = str(cwes[0]) if cwes else "CWE-1104"
    title = str(vuln.get("summary") or f"{package_name} vulnerability {advisory_id}")[:140]

    if ecosystem == "python":
        imports = _resolve_python_imports(package_name)
    elif ecosystem == "go":
        imports = sorted(set(go_import_paths)) or [package_name]
    else:
        imports = [package_name.lower()]

    return {
        "advisory_id": advisory_id,
        "ecosystem": ecosystem,
        "package": package_name if ecosystem == "go" else package_name.lower(),
        "affected_below": fallback_fixed,
        "fixed_version": fallback_fixed,
        "affected_ranges": affected_ranges,
        "severity": _osv_severity_to_vulnbox(vuln),
        "cwe_id": cwe_id,
        "title": title,
        "imports": imports,
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
    queried_pkg_keys: set[tuple[str, str]] = set()
    fresh_advisories: list[dict[str, Any]] = []
    fresh_seen: set[tuple[str, str, str]] = set()

    if repo_path is not None:
        pkgs: list[InstalledPackage] = [
            *parse_python_dependencies(repo_path),
            *parse_node_dependencies(repo_path),
            *parse_go_mod(repo_path),
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
                queried_pkg_keys.add((p.ecosystem, p.name.lower()))

        eco_query_map = {"python": "PyPI", "node": "npm", "go": "Go"}
        queried_packages = len(unique_pkgs)
        for start in range(0, len(unique_pkgs), 100):
            batch = unique_pkgs[start : start + 100]
            queries = [
                {
                    "package": {
                        "name": p.name,
                        "ecosystem": eco_query_map.get(p.ecosystem, p.ecosystem),
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
                    key = (norm["advisory_id"], norm["ecosystem"], norm["package"].lower())
                    if key not in fresh_seen:
                        fresh_seen.add(key)
                        fresh_advisories.append(norm)
                        if norm["advisory_id"].startswith("CVE-"):
                            cve_ids_for_epss.add(norm["advisory_id"])

        # Evict stale cached advisories for any (ecosystem, package) freshly queried in this sync
        advisories = [
            item
            for item in advisories
            if (str(item.get("ecosystem", "")), str(item.get("package", "")).lower())
            not in queried_pkg_keys
        ]
        advisories.extend(fresh_advisories)

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
