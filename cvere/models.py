"""Plain dataclasses shared across CVEre."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Service:
    """One service discovered by an nmap version scan (or typed by hand)."""

    host: str = "?"
    port: str = "?"
    proto: str = "tcp"
    name: str = ""            # nmap service name, e.g. http
    product: str = ""         # e.g. Apache httpd
    version: str = ""         # e.g. 2.4.49
    extrainfo: str = ""       # e.g. (Ubuntu) OpenSSL/1.1.1f
    cpes: list[str] = field(default_factory=list)
    tunnel: str = ""          # ssl when nmap says ssl/http
    resolved: list[str] = field(default_factory=list)   # CPE actually used for the lookup

    def label(self) -> str:
        bits = " ".join(x for x in (self.product or self.name, self.version) if x)
        where = f"{self.host}:{self.port}" if self.port != "?" else self.host
        return f"{bits or 'unknown service'} @ {where}/{self.proto}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "proto": self.proto,
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "cpe": list(self.cpes),
            "cpe_used": list(self.resolved),
        }


@dataclass
class Finding:
    """A public exploit / PoC hit from one source."""

    source: str
    url: str
    title: str = ""
    kind: str = "poc"          # poc | template | module | writeup | advisory
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "url": self.url, "title": self.title, "kind": self.kind, "meta": self.meta}


@dataclass
class Vuln:
    cve_id: str
    description: str = ""
    cvss: float | None = None
    cvss_version: str = ""
    cvss_vector: str = ""
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_info: dict[str, Any] = field(default_factory=dict)
    cwe: list[str] = field(default_factory=list)
    published: str = ""
    last_modified: str = ""
    status: str = ""
    references: list[str] = field(default_factory=list)
    matched: list[str] = field(default_factory=list)   # which services matched
    findings: list[Finding] = field(default_factory=list)
    source_errors: dict[str, str] = field(default_factory=dict)

    # -- derived ----------------------------------------------------------
    @property
    def severity(self) -> str:
        from .util import severity_for

        return severity_for(self.cvss)

    @property
    def poc_count(self) -> int:
        return len(self.findings)

    def sources_hit(self) -> list[str]:
        seen: list[str] = []
        for f in self.findings:
            if f.source not in seen:
                seen.append(f.source)
        return seen

    def sort_key(self) -> tuple:
        return (
            -(self.cvss or 0.0),
            -(self.epss or 0.0),
            -len(self.findings),
            self.cve_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss": self.cvss,
            "cvss_version": self.cvss_version,
            "cvss_vector": self.cvss_vector,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "kev": self.kev,
            "kev_info": self.kev_info,
            "cwe": self.cwe,
            "published": self.published,
            "last_modified": self.last_modified,
            "status": self.status,
            "description": self.description,
            "references": self.references,
            "matched": self.matched,
            "poc_count": self.poc_count,
            "sources": self.sources_hit(),
            "findings": [f.to_dict() for f in self.findings],
            "source_errors": self.source_errors,
        }
