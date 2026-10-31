# Changelog

## 1.0.0

First release.

- **Input**: CVE IDs, nmap XML/normal/grepable output (file or stdin), pasted service banners.
- **Service → CVE mapping**: nmap CPEs, a built-in vendor/product alias table, fuzzy CPE-dictionary
  search, version fallbacks (`8.2p1` → `8.2`) and per-service `--top` ranking.
- **Sources (9 by default)**: PoC-in-GitHub, Exploit-DB, Metasploit, nuclei-templates, HackerOne
  Hacktivity, Vulhub, CVEsLab, awesome-cve-poc, trickest/cve; opt-in GitHub repo search.
- **Risk context**: NVD CVSS 4.0/3.1/3.0/2.0, CWE, FIRST EPSS, CISA KEV.
- **Output**: colour console, `--json`, `--md`, standalone `--html` report.
- **Operational**: gzip HTTP cache with per-source TTL, `--offline`, rate limiting, per-source
  failure isolation, exit codes for CI (`--fail-on`).
- **Docs**: `docs/ECOSYSTEM.md` — taxonomy of the public PoC ecosystem and the coverage matrix.
- 37 offline unit tests, no third-party dependencies.
