"""Exploit intelligence enrichment: EPSS scores and the CISA KEV catalog."""
from __future__ import annotations

import urllib.parse

from .net import Http, HttpError

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class Enricher:
    def __init__(self, http: Http, verbose: bool = False):
        self.http = http
        self.verbose = verbose
        self._kev: dict[str, dict] | None = None

    # -- EPSS -------------------------------------------------------------
    def epss(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        """Return {cve: (epss, percentile)} for up to 100 CVEs per call."""
        out: dict[str, tuple[float, float]] = {}
        for i in range(0, len(cve_ids), 100):
            chunk = cve_ids[i: i + 100]
            url = EPSS_API + "?cve=" + urllib.parse.quote(",".join(chunk))
            try:
                data = self.http.get_json(url, ttl=12 * 3600)
            except HttpError:
                continue
            for row in data.get("data") or []:
                try:
                    out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
                except (KeyError, TypeError, ValueError):
                    continue
        return out

    # -- KEV --------------------------------------------------------------
    def kev_catalog(self) -> dict[str, dict]:
        if self._kev is not None:
            return self._kev
        catalog: dict[str, dict] = {}
        try:
            data = self.http.get_json(KEV_URL, ttl=24 * 3600)
            for v in data.get("vulnerabilities") or []:
                cve = v.get("cveID")
                if cve:
                    catalog[cve] = {
                        "vendor": v.get("vendorProject", ""),
                        "product": v.get("product", ""),
                        "name": v.get("vulnerabilityName", ""),
                        "dateAdded": v.get("dateAdded", ""),
                        "dueDate": v.get("dueDate", ""),
                        "ransomware": v.get("knownRansomwareCampaignUse", ""),
                        "required_action": v.get("requiredAction", ""),
                    }
        except HttpError:
            pass
        self._kev = catalog
        return catalog
