# Changelog

## 1.0.2

- **Python 3.9-3.11 compatibility.** 1.0.1 introduced two PEP 701 constructs that only 3.12+ accepts
  and broke the 3.9/3.10/3.11 CI jobs:
  - a nested same-quote f-string (`f"...{paint(f"{sev:<22}", ...)}..."`)
  - backslash escapes inside f-string *expressions* (`{paint(' \u00b7 '.join(...))}`)

  Both are gone; the affected characters (`, `, ..., flags, rules) now come from module-level
  constants in `cvere/util.py`. Verified with real 3.9.25 / 3.10.22 / 3.11.18 / 3.13.16 interpreters,
  not just syntax guesswork.
- Two guard tests (`TestCompatibility`) fail on either pattern, so it cannot regress silently.
- 44 offline unit tests.

## 1.0.1

- **Console output is now terminal-width aware.** The summary row used to be a fixed ~131 columns,
  which wrapped into garbage on a 100-column terminal (and the findings table lost its alignment).
  Narrow terminals (< 118 cols) switch to a two-line layout, every column is measured rather than
  estimated, and long description tokens are hard-wrapped.
- New `--width N` flag to force a width; `COLUMNS` is honoured.
- The logo drops its tagline when the terminal is too narrow to hold it.
- Progress lines on stderr switched from dim grey to cyan - the grey was near-invisible on dark
  themes.
- Long URLs are deliberately never truncated, so copy/paste keeps working.
- 41 offline unit tests, including width-regression tests at 60/70/80/100/118/120/140/200 columns.

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
