# The public PoC ecosystem — background and source taxonomy

> **Why this document exists.** CVEre is only as good as the sources it queries. This is the
> landscape note that drives the source list: which tiers of the public Proof-of-Concept
> ecosystem exist, what each one actually contains, how it is discovered and ingested, and how it
> maps onto a `--sources` value in this tool. Section 7 is the coverage matrix — what CVEre
> implements, and what it deliberately does not.

## 1. Ecosystem architecture and primary sources

Security research around CVEs depends on the rapid availability and empirical validation of
Proof-of-Concept exploit code. A PoC turns theoretical risk into a practical, verifiable
demonstration of a vulnerability, and is a direct input to patch prioritisation, exposure
management and detection engineering.

Public PoCs are fragmented across automated code aggregators, curated vulnerability archives,
machine-executable scanning frameworks, bug-bounty disclosure feeds, and cold-storage archival
mirrors. Understanding where PoC code lives means looking at both **primary hosting environments**
and the **secondary automation pipelines** that index, preserve and score them.

| Ecosystem tier | Primary repositories & platforms | Core artifact formats | Ingestion & discovery | Operational utility |
|---|---|---|---|---|
| Automated GitHub aggregators | `trickest/cve`, `0xMarcio/pocindex`, Exploit-Index | Structured Markdown indices, Python/Go/C scripts | GitHub Search API crawling, regex content matching, ffuf fuzzing | Rapid discovery of newly released public exploits |
| Traditional exploit archives | Exploit-DB, Packet Storm, 0day.today | Standalone exploit scripts, advisories, shellcode binaries | Direct researcher submission, vendor advisory monitoring | Historical reference, legacy vulnerability analysis |
| Executable scan frameworks | ProjectDiscovery nuclei-templates, Rapid7 Metasploit | Executable YAML templates, Ruby modules | Open-source PRs, dedicated research commits | Continuous scanning, non-destructive verification |
| Bug bounty disclosure feeds | HackerOne Hacktivity, Bugcrowd CrowdStream, Huntr | Markdown writeups, raw cURL, HTTP traces | Public disclosure releases, unauthenticated APIs | Real-world attack-chain analysis, root-cause depth |
| Containerised research labs | `SecuriTrust/CVEsLab`, `exploitintel/eip-pocs-and-cves`, Vulhub | Dockerfiles, compose files, setup scripts | Version-controlled repo updates | Dynamic call-chain testing in isolated environments |
| Archival resilience systems | `HORKimhab/poc-cve-collection`, Internet Archive | Encrypted ZIP archives, Wayback snapshots | GitHub Actions pipelines, cryptographic archiving | Long-term preservation of deleted/taken-down repos |

## 2. Automated GitHub aggregators and repository indices

GitHub is the central publication point for independent researchers. Because of the daily volume of
new repositories, analysts rely on aggregation projects that continuously monitor GitHub repos,
Gists and public forums to build centralised indices.

Aggregation pipelines ingest authoritative identifiers from the CVE Project (`cvelistV5`) and
cross-reference them against newly created repositories using specialised search tooling such as
`find-gh-poc`. To find functional PoC material in linked external pages they use content discovery
tools such as `ffuf` with targeted regular expressions:

```regex
(?i)[^a-z0-9]+(poc|proof of concept|proof[-_]of[-_]concept)[^a-z0-9]+
```

Harvested links are validated to filter spam, empty forks and false positives against maintained
exclusion lists (`blacklist.txt`) before being committed to public index files.

| Aggregator repository | Maintainer | Structure | Contextual risk metadata |
|---|---|---|---|
| `trickest/cve` | Trickest | Annual tree `YYYY/CVE-YYYY-XXXX.md` of collected reference links | HackerOne report links, shields.io version badges |
| `0xMarcio/pocindex` | 0xMarcio | Real-time searchable database across multiple code hosts | CVSS, EPSS, CISA KEV status |
| Exploit-Index | securewithumer | Offline aggregator over vulnerability feeds | Exploit-DB, Nuclei, Metasploit, KEV metrics |
| Awesome-CVE-POC-Index | hackthacker-sec | Hand-curated, organised by CVE and red-team domain | Validated, high-impact pentest exploits |
| `awesome-cve-poc` | qazbnm456 | Categorised PoC repository | Historical coverage of high-profile infrastructure bugs |
| `eip-pocs-and-cves` | exploitintel | CVE index with writeups and lab dependencies | Severity ratings, containerised research packages |

`trickest/cve` is one of the largest public aggregators, indexing hundreds of thousands of PoC
references organised into per-CVE Markdown files with description metadata, external references and
known HackerOne disclosures. `0xMarcio/pocindex` continuously indexes tens of thousands of
repositories and contextualises each exploit with EPSS probability and CISA KEV status.

## 3. Traditional exploit archives and public mailing lists

Before social coding platforms dominated, research was centralised in curated archives and public
mailing lists. They remain relevant because they host standalone exploit scripts, whitepapers and
verified shellcode **on their own infrastructure**, independent of code-hosting provider policy.

**Packet Storm** (`packetstorm.news`) has archived information-security material for over 25 years,
hosting files directly rather than linking out. Entries follow a `SOFTWARE_AFFECTED VERSION
FLAW_TYPE` naming convention and carry `PSS-` identifiers alongside CVE identifiers, author
attribution and cryptographic checksums. Source code is served unedited so defenders can audit a
payload for backdoors before running it.

**Exploit-DB**, maintained by Offensive Security, is a curated archive of public exploits with
`EDB-ID` numbers. Submissions are validated by technical editors and organised by target platform
(Linux, Windows, hardware firmware) and exploitation class (RCE, SQLi, LPE). Its structured data
feeds vulnerability management tooling and commercial threat intelligence.

Complementing static archives are historical mailing lists — **Full Disclosure**, **Bugtraq** and
**SecurityFocus** — which capture early disclosures, unformatted researcher notes and inline script
attachments that often precede formal CVE assignment, making them useful for legacy and zero-day
variants.

## 4. Bug bounty platforms and public disclosure streams

Disclosed bug bounty reports are a major source of production-tested PoC logic: once a report is
disclosed after remediation, the technical submission — narrative, HTTP request traces, parameter
manipulation, reproduction commands — becomes public.

**HackerOne Hacktivity** is the primary feed. Disclosed reports contain complete reproduction
steps, vulnerable endpoint parameters, boundary constraints and functional cURL commands that act
as inline PoCs. Intelligence platforms ingest it through unauthenticated GraphQL, storing records
under `H1-` identifiers to map findings to CVEs, CWEs and bounty amounts.

**Bugcrowd CrowdStream** is the parallel opt-in disclosure feed. For open-source and AI components,
**Huntr** publishes vendor-validated reports with reproduction scripts and confirmed CVSS vectors.

## 5. Executable scan frameworks, containerised labs and patch analysis

Vulnerability intelligence is shifting from static text toward machine-executable templates and
reproducible lab environments.

| Platform / tool | Repository | Operational mechanism | Technical application |
|---|---|---|---|
| Nuclei templates | `projectdiscovery/nuclei-templates` | Community YAML templates with HTTP/DNS/TCP matchers | Non-destructive automated scanning at scale |
| Metasploit Framework | `rapid7/metasploit-framework` | Standardised Ruby exploit modules | Exploit execution, pentesting, payload delivery |
| Containerised CVE labs | `SecuriTrust/CVEsLab`, Vulhub | Pre-configured Docker Compose environments | Safe reproduction and blue-team rule validation |
| Research packages | `exploitintel/eip-pocs-and-cves` | PoC code paired with lab setup files | Dynamic testing of complex call chains |
| Patch mining | `xmoezzz/cve-patch` | Parses upstream commit diffs | Reverse-engineering fixes to derive PoC mechanics |

`nuclei-templates` contains thousands of YAML templates organised by CVE year (e.g.
`http/cves/2024/CVE-2024-8911.yaml`). Rather than exploiting a system, templates translate PoC
mechanics into request headers, payload parameters and response matchers — safe exposure
verification at enterprise scale.

Vulhub, CVEsLab and the eip packages package vulnerable software with working exploit triggers, so
blue teams can observe dynamic call chains, test payload variants and validate detections without
touching production. Patch-mining utilities such as `cve-patch` let researchers diff vendor
commits and derive PoC mechanics when no explicit exploit code has been published.

## 6. Archival resilience, EPSS dynamics and intelligence synthesis

The PoC landscape is subject to **code ephemerality**: copyright takedowns, terms-of-service
enforcement, author self-deletion, or malicious alteration where working code is swapped for a
backdoored payload.

Preservation projects such as `HORKimhab/poc-cve-collection` run continuous archival workflows:
GitHub Actions pipelines watch PoC discovery feeds, pull new repositories, package the trees into
AES-256-CBC encrypted ZIP archives and mirror them to cold storage including the Internet Archive,
creating a record that survives the original takedown.

PoC availability also changes the risk model itself. EPSS weighs it as a heavily weighted input:

```
P(exploitation) = f( CVSS base metrics, CWE category, public PoC availability,
                    CISA KEV listing, ... )
```

When a functional script is indexed, the EPSS probability rises, reflecting a higher likelihood of
weaponisation and exploitation within 30 days. That frequently triggers automated scanning by
threat actors and shortens time-to-exploit for unpatched systems. Modern workflows therefore move
past static CVSS and prioritise on **present PoC availability, EPSS acceleration and verified KEV
listing**.

## 7. How CVEre covers this taxonomy

`cvere --list-sources` prints the live list. Tier mapping:

| Tier from above | CVEre source | Status | Notes |
|---|---|---|---|
| GitHub aggregators | `poc-in-github` | **live** | per-CVE repo index with stars/dates, one API call |
| GitHub aggregators | `trickest` | **live** | parses the per-CVE Markdown into PoC/exploit/writeup links |
| GitHub aggregators | `github-search` | **live, opt-in** | live GitHub repo search; needs `GITHUB_TOKEN` for sane rate limits |
| Traditional archives | `exploitdb` | **live** | per-CVE JSON search endpoint; id, author, platform, date |
| Executable frameworks | `nuclei` | **live** | template index (ID → path → raw YAML), severity included |
| Executable frameworks | `metasploit` | **live** | module metadata index; module rank and disclosure date |
| Bug bounty feeds | `hackerone` | **live** | public Hacktivity GraphQL, filtered on `cve_ids` |
| Containerised labs | `vulhub` | **live** | repo tree indexed once per run, matched on `CVE-…` path segments |
| Containerised labs | `cveslab` | **live** | same mechanism, small repo |
| Curated indices | `awesome-cve-poc` | **live** | same mechanism, historical coverage |
| Risk context | `nvd`, EPSS, CISA KEV | **live** | always on; CVSS 4.0/3.1/3.0/2.0, EPSS, KEV metadata |
| Traditional archives | Packet Storm | *not implemented* | `packetstorm.news` sits behind a JavaScript proof-of-work wall; scraping it needs a browser. Links still surface via `trickest`. |
| Traditional archives | 0day.today | *not implemented* | Cloudflare-protected, and heavy on paywalled content |
| Bug bounty feeds | Bugcrowd CrowdStream, Huntr | *not implemented* | no stable unauthenticated API for per-CVE lookup |
| Aggregator sites | `pocindex`, Exploit-Index | *not implemented* | site-level aggregators whose underlying sources (GitHub, nuclei, Exploit-DB, Metasploit) CVEre already queries directly |
| Research packages | `exploitintel/eip-pocs-and-cves` | *not implemented* | 49k-file tree makes a per-CVE index expensive; content overlaps Vulhub/CVEsLab |
| Patch analysis | `cve-patch` | *out of scope* | derives PoCs from vendor diffs; not a lookup source |
| Archival | Internet Archive, `poc-cve-collection` | *out of scope* | preservation layer, not a discovery feed |

Two design consequences follow from the taxonomy:

1. **Multi-source or nothing.** No single source is complete, and any one of them can disappear.
   CVEre runs 9 sources by default and isolates failures per source, so a dead feed degrades the
   answer instead of breaking it.
2. **Presence is a signal, not a verdict.** A PoC hit means "attention", not "confirmed
   exploitable" — the ranking combines CVSS, EPSS and KEV precisely because availability alone
   overstates risk for some classes and understates it for others.

## 8. Practical pipeline

A defensible prioritisation loop, in the order this tool supports it:

1. **Inventory** — `nmap -sV`, map to CPE, resolve to CVEs (NVD).
2. **Filter** — drop `< CVSS 7` noise, keep `--kev` and `--poc-only` for the short list.
3. **Verify** — reproduce in a containerised lab (Vulhub/CVEsLab) or fire a nuclei template;
   never against production.
4. **Detect** — turn the template into a detection rule and validate it against the lab.
5. **Prioritise** — weight present PoC availability, EPSS acceleration and KEV listing over raw
   CVSS.
6. **Preserve** — archive the PoC and its metadata; links rot and repositories vanish.

---

*Landscape synthesis compiled for the CVEre project; source-tier descriptions reflect the
ecosystem as documented by the respective projects. See [`../README.md`](../README.md) for the
tool itself.*
