# CVEre

**Feed it an nmap version scan or a CVE ID → get the public PoCs, exploit code and exploit intel for every CVE that matches.**

CVEre is a **zero-dependency** Python CLI. It maps services to CVEs through the NVD CPE
dictionary, then hunts the public PoC ecosystem — GitHub aggregators, Exploit-DB, Metasploit,
nuclei, HackerOne disclosures, containerised labs — and ranks every hit by CVSS, EPSS and CISA KEV.

Background on *why* these sources: [`docs/ECOSYSTEM.md`](docs/ECOSYSTEM.md) — a taxonomy of the
public PoC ecosystem and how CVEre covers each tier.

```
 █████ ██   ██ ██████ ██  ██  ████
██     ██   ██ ██     ██ ██  ██  ██
██     ██   ██ █████  ████   █████     nmap / CVE  ->  public PoC, exploits & exploit intel
██      ██ ██  ██     ██     ██
 █████   ███   ██████ ██      ████     v1.0.0 - 9 sources
```

---

## Why

`nmap -sV` tells you `Apache httpd 2.4.49`. It does not tell you that there are 44 public PoCs,
a Metasploit scanner module, a nuclei template, three Exploit-DB entries, and that two of the
matching CVEs are in CISA KEV with a 100% EPSS. CVEre does, in one command.

```console
$ cvere examples/scan.xml --top 4 --poc-only
services scanned
  · OpenSSH 8.2p1 @ web01.lab.local:22/tcp          cpe:2.3:a:openbsd:openssh:8.2p1
  · Apache httpd 2.4.49 @ web01.lab.local:80/tcp    cpe:2.3:a:apache:http_server:2.4.49
  · MySQL 5.7.31 @ web01.lab.local:3306/tcp         cpe:2.3:a:oracle:mysql:5.7.31
  · Redis key-value store 6.0.9 @ 10.10.14.22:6379  cpe:2.3:a:redis:redis:6.0.9
  · Jetty 9.4.43 @ 10.10.14.22:8080/tcp             cpe:2.3:a:eclipse:jetty:9.4.43

13 CVE(s) with data, ranked by CVSS
  CVE-2025-49844  CRITICAL    9.9  EPSS  82.6%  Redis is an open source, in-memory database…  31 PoC
  CVE-2021-41773  CRITICAL    9.8  EPSS 100.0%  A flaw was found in a change made to path…     KEV 44 PoC
  CVE-2021-42013  CRITICAL    9.8  EPSS 100.0%  It was found that the fix for CVE-2021-41…     KEV 46 PoC
  CVE-2021-44790  CRITICAL    9.8  EPSS  96.8%  A carefully crafted request body can cause…   23 PoC

──────────────────────────────────────────────────────────────────────────────────────────
CVE-2021-41773  CRITICAL 9.8 (CVSS 3.1)   EPSS 100.0%   ⚑ CISA KEV
  matched: Apache httpd 2.4.49 @ web01.lab.local:80/tcp
  published 2021-10-05 · CWE-22 · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  KEV: Apache HTTP Server Path Traversal Vulnerability added 2021-11-03 · ransomware: Known
  [poc-in-github] 20 hit(s)
    thehackersbrain/CVE-2021-41773                    https://github.com/thehackersbrain/CVE-2021-41773 (★51)
    theLSA/apache-httpd-path-traversal-checker        https://github.com/theLSA/apache-httpd-path-traversal-checker (★7)
  [exploitdb] 2 hit(s)
    Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution
                                                      https://www.exploit-db.com/exploits/50383 (2021-10-06)
  [metasploit] 1 hit(s)
    Apache 2.4.49/2.4.50 Traversal RCE scanner        https://github.com/rapid7/…/apache_normalize_path.rb (normal)
  [nuclei] 1 hit(s)
    Apache 2.4.49 - Path Traversal and Remote Code Execution
                                                      https://raw.githubusercontent.com/…/CVE-2021-41773.yaml (high)
  [hackerone] 2 hit(s)
    Internet Bug Bounty — Path Traversal and Remote Code Execution…
                                                      https://hackerone.com/reports/1400238 (Critical 2021-11-19)
  [vulhub] 1 hit(s)
    Vulhub lab: httpd/CVE-2021-41773                   https://github.com/vulhub/vulhub/blob/master/httpd/CVE-2021-41773/README.md
```

## Install

No dependencies — Python 3.9+ and the standard library.

```bash
git clone <this repo> && cd cvere
python3 -m venv .venv && . .venv/bin/activate
pip install -e .          # gives you the `cvere` command
# …or just run it in place, no install at all:
python3 -m cvere --help
./bin/cvere CVE-2021-44228
```

Optional but recommended: a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
(drops the NVD rate limit from 5 to 50 requests per 30 s):

```bash
export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

## Usage

```bash
# 1. Straight CVE lookup
cvere CVE-2021-44228
cvere CVE-2021-44228 CVE-2021-41773 CVE-2022-22965

# 2. nmap output, any flavour (XML, normal, grepable) — auto-detected
cvere examples/scan.xml
cvere -n scan.gnmap --min-cvss 7
nmap -sV -oX - 10.0.0.0/24 | cvere -            # straight from the pipe

# 3. A banner you pasted from somewhere
cvere --service "Apache httpd 2.4.49" --service "OpenSSH 8.2p1"

# 4. Only what is actually exploitable, with reports
cvere -n scan.xml --poc-only --min-cvss 7 --json out.json --html report.html --md report.md
```

### Filters and behaviour

| flag | meaning |
|---|---|
| `--min-cvss 7` | drop CVEs below this score |
| `--poc-only` (alias `--exploited`) | keep only CVEs with at least one public PoC/exploit |
| `--kev` | keep only CVEs in CISA KEV |
| `--top N` | investigate the top N CVEs per service (default 15) — the guard against a 1000-CVE product |
| `--sort cvss\|epss` | ranking used before PoC harvesting (default cvss) |
| `--sources a,b` | restrict sources (see below) |
| `--limit N` | max hits kept per source per CVE (default 20) |
| `--no-banner` / `--logo` | hide the logo banner / print it and exit |

### Exit codes

`0` nothing found · `1` at least one CVE with a public PoC · `2` usage/network error.
Change with `--fail-on cve|poc|never` — handy in CI:

```bash
nmap -sV -oX - "$TARGET" | cvere - --poc-only --min-cvss 9 || echo "critical, exploitable stuff on $TARGET"
```

## Sources

Nine sources run by default, one is opt-in. `cvere --list-sources` prints the live list.

| source | tier | what it gives | auth |
|---|---|---|---|
| `poc-in-github` | GitHub aggregator | repos indexed per CVE, stars, dates | none |
| `trickest` | GitHub aggregator | [trickest/cve](https://github.com/trickest/cve) curated PoC/exploit/writeup links | none |
| `exploitdb` | traditional archive | Exploit-DB entries: id, author, platform, date | none |
| `metasploit` | executable framework | Metasploit modules + rank (excellent/great/…) | none |
| `nuclei` | executable framework | [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) detection templates | none |
| `hackerone` | bug bounty feed | disclosed Hacktivity reports (public GraphQL), severity, bounty | none |
| `vulhub` | containerised lab | Vulhub docker lab for the CVE | none |
| `cveslab` | containerised lab | SecuriTrust/CVEsLab reproduction lab | none |
| `awesome-cve-poc` | curated index | qazbnm456/awesome-cve-poc entries | none |
| `github-search` | live search | GitHub repository search | `GITHUB_TOKEN`, **off by default** |
| `nvd`, EPSS, KEV | metadata | CVE record, CVSS 4.0/3.1/3.0/2.0, CWE, EPSS, KEV | optional NVD key |

Sources that cannot be scripted honestly are documented rather than faked — Packet Storm (JS
proof-of-work wall), 0day.today (Cloudflare), Bugcrowd CrowdStream and Huntr (no per-CVE public
API). See §7 of [`docs/ECOSYSTEM.md`](docs/ECOSYSTEM.md) for the full coverage matrix.

Duplicate hits are collapsed: one row per repo/exploit/lab, with `meta.also_in` recording the
other sources that listed it.

## How nmap becomes CVEs

1. **Parse** — XML (`-oX`), normal (`-oN`) and grepable (`-oG`) output, plus pasted banner strings.
   Product, version, extra info and tunnel (`ssl/http`) are extracted per port.
2. **CPE resolution**, in order of preference:
   1. the `<cpe>` nmap itself detected (`cpe:/a:apache:http_server:2.4.49`);
   2. a built-in alias table for names NVD spells differently (`Apache httpd` → `apache:http_server`,
      `MySQL` → `oracle:mysql`, `Redis key-value store` → `redis:redis`, …);
   3. a live CPE-dictionary search scored by token overlap + string similarity against the banner.
3. **Version matching** — `virtualMatchString` on the versioned CPE. Banner versions rarely match CPE
   versions exactly (`8.2p1` vs `8.2`), so a few *safer* variants are tried (`8.2p1` → `8.2`, `1.3.1a` →
   `1.3.1`) — never a shortened numeric version, which would produce false positives.
   If the first candidate returns nothing, the next vendor/product candidate is tried.
4. **Enrich & rank** — EPSS + KEV, then the top N per service by CVSS/EPSS get the PoC hunt.

Wrong CPEs are the main source of noise: if a service's product name is unusual, pass
`--service "Vendor Product 1.2.3"` (or fix the nmap banner) and check the `cpe_used` field in the
JSON output to see what was actually matched.

## Outputs

* **console** — colour when attached to a tty, `--no-color`/`NO_COLOR` respected; logo banner is
  suppressed by `-q`/`--no-banner` (and always skipped when stdout is not a tty)
* `--json FILE` — everything (services, CVEs, EPSS, KEV, findings with metadata); `-` for stdout
* `--md FILE` — copy-paste-into-a-ticket report
* `--html FILE` — standalone dark-mode report, no external assets, safe to email

## Caching & politeness

Everything is cached under `~/.cache/cvere` (override with `--cache-dir`), gzip-compressed:
NVD CVE records 24 h, CPE dictionary 7 d, PoC sources 12 h, Metasploit index 7 d.
`--offline` uses the cache only (great for air-gapped retros), `--refresh` bypasses it,
`--clear-cache` wipes it.

NVD is rate limited to the published 5 req / 30 s anonymously (50 with a key) and each host gets its
own limiter. Sources run in parallel (`--threads`, default 6) and a failing source never kills the run —
errors land in `source_errors` per CVE.

## Extending

Add a function to `cvere/sources.py` that returns `Finding` objects and register it:

```python
def packetstorm(ctx: Ctx, cve: str) -> list[Finding]:
    data = ctx.http.get_json(f"https://example/api?cve={cve}", ttl=12 * 3600)
    return [Finding(source="packetstorm", url=r["url"], title=r["title"], kind="exploit") for r in data]

ADAPTERS["packetstorm"] = (packetstorm, "Packet Storm exploits")
```

That's it — `--sources packetstorm` now works. Repos that carry the CVE id in a *path*
(`vulhub/CVE-…/`, `CVE-…/README.md`) need no adapter at all: add a spec to `REPO_INDEXES` and the
generic indexer handles it in one cached request per run. `ctx.http` handles caching, retries and rate
limiting; `kind` is one of `poc | exploit | module | template | writeup | advisory | reference`
and controls ordering.

## Tests

```bash
python3 -m unittest discover -s tests -v   # 37 tests, fully offline
```

## Caveats — read this

* **PoC links are unvetted third-party code.** CVEre reports where things are, it does not validate
  that a repo works or is safe to run. Clone and read before executing anything, ever.
* CPE matching is heuristic. NVD also lags reality: a 2019 banner can be affected by a 2026 CVE
  whose advisory text says "before 10.4", and that is exactly what `--top` is for.
* Version ranges NVD expresses as wildcard CPEs with `versionStartIncluding` are matched by NVD
  itself, not by CVEre; a *missing* CVE is more likely a bad CPE guess than a true negative.
* Use it only against systems you are authorised to assess. Public PoCs are for defenders,
  CTF players and pentesters with a scope document — not for the other thing.
