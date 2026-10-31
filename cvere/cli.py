"""CVEre command line interface."""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import os
import re
import sys
import time

from . import logo, nmap as nmap_parser
from .enrich import Enricher
from .models import Service, Vuln
from .net import Http, HttpError, OfflineMiss, default_cache_dir
from .nvd import Nvd, cpe_attempts
from .report import build_payload, render_console, to_html, to_json, to_markdown
from .sources import ADAPTERS, DEFAULT_SOURCES, Ctx, run_sources
from .util import Paint, severity_for

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
VERSION = "1.0.0"

TAGLINE = "nmap / CVE  \u2192  public PoC, exploits & exploit intel"


# --------------------------------------------------------------------------- arguments

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cvere",
        description="CVEre — feed it a CVE ID or an nmap version scan, get public PoCs, "
                    "exploits and exploit-intel for the matching CVEs.",
        epilog="examples:\n"
               "  cvere CVE-2021-44228\n"
               "  cvere -n scan.xml --min-cvss 7 --html report.html\n"
               "  nmap -sV -oX - 10.0.0.0/24 | cvere -\n"
               "  cvere --service 'Apache httpd 2.4.49'\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("input", nargs="*", metavar="CVE|FILE|-",
                   help="CVE ID(s), an nmap output file (XML/normal/grepable), or - for stdin")
    p.add_argument("-n", "--nmap", metavar="FILE", help="nmap output file to parse")
    p.add_argument("-s", "--service", action="append", default=[], metavar="BANNER",
                   help="service banner to look up, e.g. 'OpenSSH 8.2p1' (repeatable)")

    g = p.add_argument_group("filtering")
    g.add_argument("--min-cvss", type=float, default=0.0, help="drop CVEs below this CVSS score")
    g.add_argument("--top", type=int, default=15, help="max CVEs to investigate per service (default 15)")
    g.add_argument("--sort", choices=["cvss", "epss"], default="cvss", help="pre-PoC ranking (default cvss)")
    g.add_argument("--kev", action="store_true", help="only CVEs in CISA KEV")
    g.add_argument("--poc-only", "--exploited", dest="poc_only", action="store_true",
                   help="only CVEs that have at least one public PoC/exploit")

    g = p.add_argument_group("sources")
    g.add_argument("--sources", default=",".join(DEFAULT_SOURCES),
                   help=f"comma separated subset of: {', '.join(ADAPTERS)} (default all but github-search)")
    g.add_argument("--limit", type=int, default=20, help="max results kept per source per CVE (default 20)")
    g.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""),
                   help="GitHub token (enables higher rate limits / github-search)")
    g.add_argument("--list-sources", action="store_true", help="list available sources and exit")

    g = p.add_argument_group("output")
    g.add_argument("--json", metavar="FILE", help="write JSON report ('-' for stdout)")
    g.add_argument("--md", metavar="FILE", help="write Markdown report")
    g.add_argument("--html", metavar="FILE", help="write standalone HTML report")
    g.add_argument("--refs", type=int, default=0, metavar="N", help="show N NVD reference URLs per CVE")
    g.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    g.add_argument("--no-banner", action="store_true", help="don't print the logo banner")
    g.add_argument("--logo", action="store_true", help="print the logo and exit")
    g.add_argument("-q", "--quiet", action="store_true", help="no progress output on stderr")
    g.add_argument("-v", "--verbose", action="store_true", help="extra diagnostics")

    g = p.add_argument_group("network")
    g.add_argument("--nvd-key", default=os.environ.get("NVD_API_KEY", ""),
                   help="NVD API key (50 req/30s instead of 5) — env NVD_API_KEY")
    g.add_argument("--cache-dir", default=default_cache_dir(), help="cache directory")
    g.add_argument("--offline", action="store_true", help="use only cached responses")
    g.add_argument("--refresh", action="store_true", help="ignore cached responses")
    g.add_argument("--clear-cache", action="store_true", help="delete the cache and exit")
    g.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds")
    g.add_argument("--threads", type=int, default=6, help="parallel source lookups (default 6)")
    g.add_argument("--nvd-cpe-limit", type=int, default=2,
                   help="max CPE candidates tried per service (default 2)")
    g.add_argument("--fail-on", choices=["poc", "cve", "never"], default="poc",
                   help="exit 1 when this is found (default: poc)")
    p.add_argument("--version", action="version", version=f"cvere {VERSION}")
    return p


# --------------------------------------------------------------------------- helpers

class Log:
    def __init__(self, quiet: bool, verbose: bool, paint: Paint):
        self.quiet = quiet
        self.verbose = verbose
        self.paint = paint
        self.t0 = time.time()

    def __call__(self, msg: str) -> None:
        if not self.quiet:
            print(self.paint(msg, "grey"), file=sys.stderr, flush=True)

    def debug(self, msg: str) -> None:
        if self.verbose:
            print(self.paint(msg, "grey"), file=sys.stderr, flush=True)


def _read_input_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def gather_inputs(args) -> tuple[list[str], list[Service]]:
    cves: list[str] = []
    services: list[Service] = []
    paths: list[str] = list(args.input)
    if args.nmap:
        paths.append(args.nmap)

    for item in paths:
        if item == "-" and not sys.stdin.isatty():
            services.extend(nmap_parser.parse(_read_input_text("-")))
            continue
        if os.path.exists(item):
            services.extend(nmap_parser.parse(_read_input_text(item)))
            continue
        if CVE_RE.match(item.strip()):
            cves.append(item.strip().upper())
            continue
        if "/" in item or " " in item:
            services.extend(nmap_parser.parse_service_line(item))
            continue
        raise ValueError(f"'{item}' is not a CVE ID, an existing file, or a service banner")
    for banner in args.service:
        services.extend(nmap_parser.parse_service_line(banner))
    return list(dict.fromkeys(cves)), nmap_parser.dedupe(services)


def collect_from_services(nvd: Nvd, services: list[Service], args, log: Log, paint: Paint) -> dict[str, Vuln]:
    found: dict[str, Vuln] = {}
    per_service: dict[str, list[str]] = {}
    for svc in services:
        cpes = cpe_attempts(nvd, svc, limit=args.nvd_cpe_limit, max_attempts=max(3, args.nvd_cpe_limit * 2))
        if not cpes:
            log(f"  ! {svc.label()}: could not resolve a CPE (try --service with vendor name)")
            continue
        svc.resolved = cpes
        log(f"  → {svc.label()}  [{', '.join(':'.join(c.split(':')[3:5]) for c in cpes)}]")
        hits: list[str] = []
        for cpe in cpes:
            try:
                vulns = nvd.cves_for_cpe(cpe)
            except (HttpError, OfflineMiss) as e:
                log(f"  ! NVD lookup failed for {cpe}: {e}")
                continue
            log(f"     {':'.join(cpe.split(':')[3:6])}: {len(vulns)} CVE(s)")
            if not vulns and not hits:
                # wrong vendor guess - keep the first candidate that actually matches
                continue
            for v in vulns:
                hits.append(v.cve_id)
                existing = found.get(v.cve_id)
                if existing:
                    if svc.label() not in existing.matched:
                        existing.matched.append(svc.label())
                else:
                    v.matched = [svc.label()]
                    found[v.cve_id] = v
            if hits:
                svc.resolved = [cpe]  # remember the CPE that actually matched
                break
        per_service[svc.label()] = hits

    # keep a per-service top-N so huge products stay manageable
    keep: set[str] = set()
    for label, ids in per_service.items():
        ranked = sorted({i for i in ids}, key=lambda i: _rank(found[i], args.sort))
        keep.update(ranked[: args.top])
    if len(found) > len(keep):
        log(f"  · keeping top {args.top} per service: {len(keep)} of {len(found)} CVEs (raise with --top)")
    return {k: v for k, v in found.items() if k in keep}


def _rank(v: Vuln, sort: str) -> tuple:
    if sort == "epss":
        return (-(v.epss or 0.0), -(v.cvss or 0.0), v.cve_id)
    return (-(v.cvss or 0.0), -(v.epss or 0.0), v.cve_id)


def apply_filters(vulns: list[Vuln], args) -> list[Vuln]:
    out = []
    for v in vulns:
        if v.cvss is not None and v.cvss < args.min_cvss:
            continue
        if args.kev and not v.kev:
            continue
        if args.poc_only and not v.findings:
            continue
        out.append(v)
    return out


def _write(path: str, text: str, log: Log) -> None:
    if path == "-":
        print(text)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    log(f"  wrote {path} ({len(text)} bytes)")


# --------------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paint = Paint(enabled=False if args.no_color else None)

    if args.clear_cache:
        import shutil

        shutil.rmtree(args.cache_dir, ignore_errors=True)
        print(f"cache cleared: {args.cache_dir}")
        return 0

    if args.logo:
        print(logo.render(paint, VERSION, len(ADAPTERS)))
        return 0

    if args.list_sources:
        print("available sources:")
        for name, (_, desc) in ADAPTERS.items():
            print(f"  {name:<14} {desc}")
        return 0

    sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    unknown = [s for s in sources if s not in ADAPTERS]
    if unknown:
        print(f"cvere: unknown source(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    log = Log(args.quiet, args.verbose, paint)
    if not (args.quiet or args.no_banner):
        print(logo.render(paint, VERSION, len(sources), TAGLINE) + "\n", file=sys.stderr)

    try:
        cves, services = gather_inputs(args)
    except (ValueError, OSError) as e:
        print(f"cvere: {e}", file=sys.stderr)
        return 2
    if not cves and not services:
        build_parser().print_usage(sys.stderr)
        print("cvere: give me a CVE ID, an nmap scan, or --service", file=sys.stderr)
        return 2

    t0 = time.time()
    http = Http(cache_dir=args.cache_dir, timeout=args.timeout, offline=args.offline,
                refresh=args.refresh, verbose=args.verbose)
    nvd = Nvd(http, api_key=args.nvd_key, verbose=args.verbose)
    enricher = Enricher(http, verbose=args.verbose)

    try:
        # ---- 1. which CVEs?
        found: dict[str, Vuln] = {}
        if services:
            log(f"[1/4] resolving {len(services)} service(s) to CVEs via NVD")
            found.update(collect_from_services(nvd, services, args, log, paint))
        for cve in cves:
            if cve in found:
                continue
            log(f"[1/4] fetching {cve} from NVD")
            try:
                v = nvd.cve(cve)
            except (HttpError, OfflineMiss) as e:
                log(f"  ! {cve}: {e}")
                v = None
            found[cve] = v or Vuln(cve_id=cve)

        vulns = list(found.values())

        # ---- 2. exploit intel
        if vulns:
            log(f"[2/4] EPSS + CISA KEV for {len(vulns)} CVE(s)")
            try:
                epss = enricher.epss([v.cve_id for v in vulns])
            except Exception:  # noqa: BLE001
                epss = {}
            try:
                kev = enricher.kev_catalog()
            except Exception:  # noqa: BLE001
                kev = {}
            for v in vulns:
                if v.cve_id in epss:
                    v.epss, v.epss_percentile = epss[v.cve_id]
                if v.cve_id in kev:
                    v.kev = True
                    v.kev_info = kev[v.cve_id]

        # ---- 3. rank / trim, then hunt PoCs
        vulns.sort(key=lambda v: _rank(v, args.sort))

        ctx = Ctx(http, limit=args.limit, verbose=args.verbose, github_token=args.github_token)
        if vulns:
            log(f"[3/4] hunting public PoCs from {len(sources)} source(s) for {len(vulns)} CVE(s)")
        with futures.ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
            jobs = {pool.submit(run_sources, ctx, v.cve_id, sources): v for v in vulns}
            done = 0
            for fut in futures.as_completed(jobs):
                v = jobs[fut]
                findings, errors = fut.result()
                v.findings = findings
                v.source_errors = errors
                done += 1
                hits = len({f.source for f in findings})
                log(f"  [{done}/{len(vulns)}] {v.cve_id}  {len(findings):>3} hit(s) / {hits} source(s)")
    except OfflineMiss as e:
        print(f"cvere: offline and no cached response for {e.url}", file=sys.stderr)
        return 2

    # ---- 4. filter + report
    vulns = [v for v in vulns if not (args.kev and not v.kev)]
    before = len(vulns)
    vulns = apply_filters(vulns, args)
    if before != len(vulns):
        log(f"  · {before - len(vulns)} CVE(s) filtered out")

    vulns.sort(key=lambda v: v.sort_key())

    # when the machine-readable report goes to stdout, keep it parseable
    if args.json == "-":
        log("  (console output suppressed: --json - writes JSON to stdout)")
    else:
        print(render_console(vulns, services, paint, verbose=args.verbose, show_refs=args.refs), end="")

    elapsed = time.time() - t0
    payload = build_payload(vulns, services, sources, elapsed)
    if args.json:
        _write(args.json, to_json(payload), log)
    if args.md:
        _write(args.md, to_markdown(payload), log)
    if args.html:
        _write(args.html, to_html(payload), log)

    with_poc = [v for v in vulns if v.findings]
    summary = (f"{len(vulns)} CVE(s) · {len(with_poc)} with public PoC · "
               f"{sum(1 for v in vulns if v.kev)} in KEV · {elapsed:.1f}s")
    if not args.quiet:
        print(paint(summary, "grey"), file=sys.stderr)
        if http.stats["miss"] or http.stats["hit"]:
            log(f"  http: {http.stats['hit']} cache hits, {http.stats['miss']} fetched, "
                f"{http.stats['bytes'] / 1e6:.1f} MB")

    if args.fail_on == "never":
        return 0
    if args.fail_on == "cve":
        return 1 if vulns else 0
    return 1 if with_poc else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
