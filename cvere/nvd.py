"""NVD interaction: CVE records, CPE resolution, CPE -> CVE matching."""
from __future__ import annotations

import difflib
import os
import sys
import urllib.parse

from .models import Service, Vuln
from .net import Http, HttpError
from .util import norm_tokens

NVD_API = "https://services.nvd.nist.gov/rest/json"
CVSS_KEYS = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
CVSS_LABEL = {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}


class Nvd:
    def __init__(self, http: Http, api_key: str | None = None, max_cves: int = 1000, verbose: bool = False):
        self.http = http
        self.api_key = api_key or os.environ.get("NVD_API_KEY") or ""
        self.max_cves = max_cves
        self.verbose = verbose
        # NVD allows 5 requests / 30 s anonymous, 50 / 30 s with a key.
        self.interval = 0.7 if self.api_key else 6.2

    # -- low level --------------------------------------------------------
    def _get(self, path: str, params: dict, ttl: float):
        url = f"{NVD_API}/{path}?" + urllib.parse.urlencode(params)
        headers = {"apiKey": self.api_key} if self.api_key else None
        return self.http.get_json(url, ttl=ttl, headers=headers, rate=("services.nvd.nist.gov", self.interval))

    # -- single CVE -------------------------------------------------------
    def cve(self, cve_id: str) -> Vuln | None:
        data = self._get("cves/2.0", {"cveId": cve_id}, ttl=86400)
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return None
        return self._parse(vulns[0])

    # -- CPE --------------------------------------------------------------
    def cpe_candidates(self, keyword: str, limit: int = 5, want: str | None = None) -> list[tuple[str, float]]:
        """Search the CPE dictionary and rank vendor:product pairs against `want`."""
        data = self._get("cpes/2.0", {"keywordSearch": keyword, "resultsPerPage": 200}, ttl=7 * 86400)
        tokens = norm_tokens(want or keyword)
        if not tokens:
            return []
        scored: dict[str, tuple[str, float]] = {}
        for prod in data.get("products") or []:
            cpe = prod.get("cpe") or {}
            name = cpe.get("cpeName") or ""
            if not name.startswith("cpe:2.3:") or cpe.get("deprecated"):
                continue
            f = name.split(":")
            if len(f) < 5:
                continue
            part, vendor, product = f[2], f[3], f[4]
            if part not in ("a", "o"):
                continue
            score = _match_score(tokens, vendor, product)
            if score <= 0:
                continue
            if part == "o":
                score -= 0.2
            key = f"{part}:{vendor}:{product}"
            best = scored.get(key)
            if best is None or score > best[1]:
                scored[key] = (name, score)
        ranked = sorted(scored.values(), key=lambda x: -x[1])
        return ranked[:limit]

    @staticmethod
    def with_version(cpe_name: str, version: str | None) -> str:
        f = cpe_name.split(":")
        while len(f) < 13:
            f.append("*")
        if version:
            f[5] = version
        else:
            f[5] = f[5] or "*"
        return ":".join(f[:13])

    # -- CPE -> CVEs ------------------------------------------------------
    def cves_for_cpe(self, cpe_name: str, results_per_page: int = 2000) -> list[Vuln]:
        out: list[Vuln] = []
        start = 0
        while True:
            data = self._get(
                "cves/2.0",
                {
                    "virtualMatchString": cpe_name,
                    "resultsPerPage": results_per_page,
                    "startIndex": start,
                },
                ttl=12 * 3600,
            )
            total = data.get("totalResults", 0)
            batch = data.get("vulnerabilities") or []
            out.extend(self._parse(v) for v in batch)
            start += len(batch)
            if not batch or start >= total or len(out) >= self.max_cves:
                break
            if self.verbose:
                print(f"  ... {start}/{total} CVEs for {cpe_name}", file=sys.stderr)
        return out[: self.max_cves]

    # -- parsing ----------------------------------------------------------
    def _parse(self, item: dict) -> Vuln:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "?")
        desc = ""
        for d in cve.get("descriptions") or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        metrics = cve.get("metrics") or {}
        score = None
        version = ""
        vector = ""
        for key in CVSS_KEYS:
            entries = metrics.get(key) or []
            if not entries:
                continue
            primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = primary.get("cvssData") or {}
            score = data.get("baseScore")
            version = CVSS_LABEL[key]
            vector = data.get("vectorString", "")
            if score is not None:
                break
        cwe: list[str] = []
        for w in cve.get("weaknesses") or []:
            for d in w.get("description") or []:
                v = d.get("value", "")
                if v and v not in cwe and v not in ("NVD-CWE-Other", "NVD-CWE-noinfo"):
                    cwe.append(v)
        refs = [r.get("url", "") for r in cve.get("references") or [] if r.get("url")]
        return Vuln(
            cve_id=cve_id,
            description=desc,
            cvss=float(score) if score is not None else None,
            cvss_version=version,
            cvss_vector=vector,
            cwe=cwe,
            published=(cve.get("published") or "")[:10],
            last_modified=(cve.get("lastModified") or "")[:10],
            status=cve.get("vulnStatus") or "",
            references=refs,
        )


# --------------------------------------------------------------------------- resolution

ALIASES: list[tuple[str, list[str]]] = [
    ("apache httpd", ["cpe:2.3:a:apache:http_server"]),
    ("apache http server", ["cpe:2.3:a:apache:http_server"]),
    ("httpd", ["cpe:2.3:a:apache:http_server"]),
    ("nginx", ["cpe:2.3:a:f5:nginx", "cpe:2.3:a:nginx:nginx"]),
    ("openssh", ["cpe:2.3:a:openbsd:openssh"]),
    ("dropbear", ["cpe:2.3:a:dropbear_ssh_project:dropbear_ssh"]),
    ("microsoft iis httpd", ["cpe:2.3:a:microsoft:internet_information_services"]),
    ("microsoft httpapi", ["cpe:2.3:a:microsoft:httpapi"]),
    ("tomcat", ["cpe:2.3:a:apache:tomcat"]),
    ("jetty", ["cpe:2.3:a:eclipse:jetty"]),
    ("log4j", ["cpe:2.3:a:apache:log4j"]),
    ("struts", ["cpe:2.3:a:apache:struts"]),
    ("vsftpd", ["cpe:2.3:a:vsftpd:vsftpd"]),
    ("proftpd", ["cpe:2.3:a:proftpd:proftpd"]),
    ("pure-ftpd", ["cpe:2.3:a:pure-ftpd:pure-ftpd"]),
    ("exim", ["cpe:2.3:a:exim:exim"]),
    ("postfix", ["cpe:2.3:a:postfix:postfix"]),
    ("dovecot", ["cpe:2.3:a:dovecot:dovecot"]),
    ("openssl", ["cpe:2.3:a:openssl:openssl"]),
    ("samba", ["cpe:2.3:a:samba:samba"]),
    ("dnsmasq", ["cpe:2.3:a:thekelleys:dnsmasq"]),
    ("lighttpd", ["cpe:2.3:a:lighttpd:lighttpd"]),
    ("mysql", ["cpe:2.3:a:oracle:mysql", "cpe:2.3:a:mysql:mysql"]),
    ("mariadb", ["cpe:2.3:a:mariadb:mariadb"]),
    ("postgresql", ["cpe:2.3:a:postgresql:postgresql"]),
    ("redis", ["cpe:2.3:a:redis:redis"]),
    ("mongodb", ["cpe:2.3:a:mongodb:mongodb"]),
    ("elasticsearch", ["cpe:2.3:a:elastic:elasticsearch"]),
    ("rabbitmq", ["cpe:2.3:a:vmware:rabbitmq", "cpe:2.3:a:pivotal_software:rabbitmq"]),
    ("php", ["cpe:2.3:a:php:php"]),
    ("jenkins", ["cpe:2.3:a:jenkins:jenkins"]),
    ("wordpress", ["cpe:2.3:a:wordpress:wordpress"]),
    ("drupal", ["cpe:2.3:a:drupal:drupal"]),
    ("jira", ["cpe:2.3:a:atlassian:jira"]),
    ("confluence", ["cpe:2.3:a:atlassian:confluence"]),
    ("gitlab", ["cpe:2.3:a:gitlab:gitlab"]),
    ("splunk", ["cpe:2.3:a:splunk:splunk"]),
    ("weblogic", ["cpe:2.3:a:oracle:weblogic_server"]),
    ("struts2", ["cpe:2.3:a:apache:struts"]),
    ("proxy server", ["cpe:2.3:a:squid-cache:squid"]),
]

STOPWORDS = {"http", "https", "server", "service", "daemon", "the", "key", "value", "store",
             "store.", "open", "secure", "linux", "unix", "protocol", "unknown"}


def _match_score(tokens: list[str], vendor: str, product: str) -> float:
    """How well a CPE vendor:product pair matches the tokens of an nmap banner."""
    fields = [vendor.replace("_", " "), product.replace("_", " "), vendor.replace("_", ""), product.replace("_", "")]
    hay = " ".join(fields).lower()
    hit = 0.0
    for t in tokens:
        if len(t) <= 2 or t in STOPWORDS:
            continue
        if t in hay:
            hit += 1.0
        else:
            best = max(
                (difflib.SequenceMatcher(None, t, w).ratio() for w in hay.replace("-", " ").split()),
                default=0.0,
            )
            if best >= 0.72:
                hit += best * 0.85
    meaningful = [t for t in tokens if len(t) > 2 and t not in STOPWORDS]
    if not meaningful:
        return 0.0
    score = hit / len(meaningful)
    if meaningful[0] in hay:
        score += 0.4
    return score


def alias_hints(product: str) -> list[str]:
    text = (product or "").lower()
    out: list[str] = []
    for key, cpes in ALIASES:
        if key in text:
            for c in cpes:
                if c not in out:
                    out.append(c)
    return out


def _cpe_key(cpe: str) -> tuple[str, str, str]:
    f = cpe.split(":")
    while len(f) < 5:
        f.append("")
    return (f[2], f[3], f[4])


def resolve_cpes(nvd: Nvd, service: Service, limit: int = 2) -> list[str]:
    """Ordered CPE candidates for a service: nmap's own CPEs, then aliases, then keyword search."""
    out: list[str] = []
    seen: set[tuple[str, str, str]] = set()

    def add(cpe: str) -> None:
        key = _cpe_key(cpe)
        if key in seen or not cpe.startswith("cpe:2.3:"):
            return
        seen.add(key)
        out.append(cpe)

    # 1. what nmap itself detected (application CPEs first - OS CPEs pull in kernel CVEs)
    nmap_cpes = [c for c in service.cpes if c.split(":")[2:3] == ["a"]] or list(service.cpes)
    for c in nmap_cpes:
        f = c.split(":")
        if len(f) >= 6 and f[5] in ("*", "-", "") and service.version:
            c = nvd.with_version(c, service.version)
        add(c)

    # 2. built-in vendor/product aliases (nmap names rarely equal CPE names)
    for c in alias_hints(service.product or service.name):
        add(nvd.with_version(c, service.version or None))

    # 3. live CPE dictionary search, only when the above is thin
    if len(out) < limit:
        product = service.product or service.name
        tokens = [t for t in norm_tokens(product) if len(t) > 2 and t not in STOPWORDS]
        strategies = [product]
        if tokens:
            strategies += [max(tokens, key=len), tokens[0], " ".join(tokens[:2])]
        for kw in dict.fromkeys(x for x in strategies if x):
            try:
                found = nvd.cpe_candidates(kw, limit=limit + 2, want=product)
            except HttpError:
                break
            for name, score in found:
                add(nvd.with_version(name, service.version or None))
                if score >= 0.8:
                    break
            if len(out) >= limit:
                break
    return out[: max(limit, 2) + 2]


def cpe_attempts(nvd: Nvd, service: Service, limit: int = 2, max_attempts: int = 4) -> list[str]:
    """CPE strings to try, ordered: best vendor:product first, exact version then trimmed."""
    from .util import version_candidates

    bases = resolve_cpes(nvd, service, limit=limit)
    versions = version_candidates(service.version)
    if not versions:
        return list(dict.fromkeys(bases))[:max_attempts]
    attempts: list[str] = []
    for base in bases:
        f = base.split(":")
        while len(f) < 13:
            f.append("*")
        f[5] = "*"
        stripped = ":".join(f[:13])
        for v in versions[:2]:
            attempts.append(nvd.with_version(stripped, v))
    return list(dict.fromkeys(attempts))[:max_attempts]
