"""Rendering: console (ANSI), JSON, Markdown and a standalone HTML report."""
from __future__ import annotations

import html
import json
import time
from typing import Any

from .models import Service, Vuln
from .util import SEVERITY_STYLE, Paint, fmt_epss, fmt_score, severity_badge, severity_for, truncate

SOURCE_ICON = {
    "poc-in-github": "github",
    "trickest": "trickest",
    "nuclei": "nuclei",
    "exploitdb": "exploitdb",
    "metasploit": "metasploit",
    "github-search": "github",
}


# --------------------------------------------------------------------------- console

def _rule(paint: Paint, width: int = 92) -> str:
    return paint("─" * width, "grey")


def render_console(vulns: list[Vuln], services: list[Service], paint: Paint, verbose: bool = False,
                   show_refs: int = 0) -> str:
    out: list[str] = []
    if services:
        out.append(paint("services scanned", "bold"))
        for s in services:
            used = s.resolved[0] if s.resolved else (s.cpes[0] if s.cpes else "")
            cpe = f"  {paint(used, 'grey')}" if used else ""
            out.append(f"  · {s.label()}{cpe}")
        out.append("")

    if not vulns:
        out.append(paint("No matching CVEs found.", "bgreen"))
        return "\n".join(out)

    # ---- summary table
    width_id = max(len(v.cve_id) for v in vulns)
    out.append(paint(f"{len(vulns)} CVE(s) with data, ranked by CVSS", "bold"))
    for v in vulns:
        sev = severity_for(v.cvss)
        badge = paint(f"{sev:<22}", *SEVERITY_STYLE.get(sev, ("grey",)))
        flags = []
        if v.kev:
            flags.append(paint("KEV", "bred", "bold"))
        n_poc = sum(1 for f in v.findings if f.kind in ("poc", "exploit", "template", "module"))
        if n_poc:
            flags.append(paint(f"{n_poc} PoC", "bgreen"))
        flagstr = " ".join(flags)
        title = truncate(_headline(v), 58)
        out.append(
            f"  {paint(v.cve_id.ljust(width_id), 'bold')}  {badge} {fmt_score(v.cvss):>4}  "
            f"EPSS {fmt_epss(v.epss):>6}  {title:<58} {flagstr}"
        )
    out.append("")

    # ---- detail
    for v in vulns:
        out.append(_rule(paint))
        out.append(f"{paint(v.cve_id, 'bold', 'bcyan')}  {severity_badge(v.cvss, paint)} {fmt_score(v.cvss)}"
                   f"{paint(' (CVSS ' + v.cvss_version + ')', 'grey') if v.cvss_version else ''}"
                   f"   EPSS {fmt_epss(v.epss)}"
                   + (f"   {paint('⚑ CISA KEV', 'bred', 'bold')}" if v.kev else ""))
        if v.matched:
            out.append(f"  {paint('matched:', 'grey')} {', '.join(v.matched)}")
        meta = []
        if v.published:
            meta.append(f"published {v.published}")
        if v.cwe:
            meta.append(", ".join(v.cwe[:3]))
        if v.cvss_vector and len(v.cvss_vector) <= 64:
            meta.append(v.cvss_vector)
        if meta:
            out.append(f"  {paint(' · '.join(meta), 'grey')}")
        if v.kev:
            k = v.kev_info
            out.append(f"  {paint('KEV:', 'bred')} {k.get('name','')} added {k.get('dateAdded','')}"
                       f" · ransomware: {k.get('ransomware','Unknown')}")
        if v.description:
            out.append("  " + _wrap(v.description, 100, indent="  "))

        if v.findings:
            by_source: dict[str, list] = {}
            for f in v.findings:
                by_source.setdefault(f.source, []).append(f)
            order = sorted(by_source.items(), key=lambda kv: (-len(kv[1]), kv[0]))
            for source, items in order:
                out.append(f"  {paint(f'[{source}]', 'bblue')} {paint(str(len(items)) + ' hit(s)', 'grey')}")
                for f in items[:8]:
                    out.append(_finding_line(f, paint))
                if len(items) > 8:
                    out.append(f"    {paint(f'… {len(items) - 8} more (JSON/MD report has all)', 'grey')}")
        elif v.source_errors:
            out.append(f"  {paint('no public PoC found', 'yellow')}")
        else:
            out.append(f"  {paint('no public PoC found', 'grey')}")

        if v.source_errors and verbose:
            for src, err in v.source_errors.items():
                out.append(f"  {paint('! ' + src + ': ' + err, 'grey')}")
        if show_refs and v.references:
            out.append(f"  {paint('references:', 'grey')}")
            for r in v.references[:show_refs]:
                out.append(f"    {paint(r, 'cyan')}")
        out.append("")

    return "\n".join(out).rstrip() + "\n"


def _finding_line(f, paint: Paint) -> str:
    extra = []
    if f.meta.get("stars"):
        extra.append(f"★{f.meta['stars']}")
    if f.meta.get("rank"):
        extra.append(str(f.meta["rank"]))
    if f.meta.get("severity"):
        extra.append(str(f.meta["severity"]))
    if f.meta.get("date"):
        extra.append(str(f.meta["date"]))
    if f.meta.get("also_in"):
        extra.append("also " + "/".join(f.meta["also_in"]))
    tag = paint("(" + " ".join(extra) + ")", "grey") if extra else ""
    title = (f.title or "").strip()
    if not title or title.startswith("http"):
        return f"    {paint(f.url, 'cyan')} {tag}".rstrip()
    return f"    {truncate(title, 64):<64} {paint(f.url, 'cyan')} {tag}".rstrip()


def _headline(v: Vuln) -> str:
    if not v.description:
        return ""
    first = v.description.split(". ")[0]
    return first if len(first) < 160 else first[:157] + "…"


def _wrap(text: str, width: int, indent: str = "") -> str:
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return ("\n" + indent).join(lines[:6] + (["…"] if len(lines) > 6 else []))


# --------------------------------------------------------------------------- data

def build_payload(vulns: list[Vuln], services: list[Service], sources: list[str], elapsed: float) -> dict[str, Any]:
    return {
        "tool": "cvere",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(elapsed, 2),
        "sources": sources,
        "services": [s.to_dict() for s in services],
        "stats": {
            "cves": len(vulns),
            "with_poc": sum(1 for v in vulns if v.findings),
            "kev": sum(1 for v in vulns if v.kev),
            "critical": sum(1 for v in vulns if v.severity == "CRITICAL"),
            "high": sum(1 for v in vulns if v.severity == "HIGH"),
        },
        "vulnerabilities": [v.to_dict() for v in vulns],
    }


def to_json(payload: dict) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- markdown

def to_markdown(payload: dict) -> str:
    s = payload["stats"]
    lines = [
        "# CVEre report",
        "",
        f"Generated {payload['generated']} · {s['cves']} CVEs · {s['with_poc']} with public PoC · "
        f"{s['kev']} in CISA KEV",
        "",
    ]
    if payload["services"]:
        lines += ["## Services", "", "| host | port | service | banner | CPE |", "|---|---|---|---|---|"]
        for svc in payload["services"]:
            banner = " ".join(x for x in (svc["product"], svc["version"]) if x)
            lines.append(
                f"| {svc['host']} | {svc['port']}/{svc['proto']} | {svc['name']} | {banner} | "
                f"{(svc.get('cpe_used') or svc['cpe'] or ['-'])[0]} |"
            )
        lines.append("")
    lines += ["## Findings", "", "| CVE | Severity | CVSS | EPSS | KEV | PoCs | Sources |", "|---|---|---|---|---|---|---|"]
    for v in payload["vulnerabilities"]:
        lines.append(
            f"| [{v['cve_id']}](https://nvd.nist.gov/vuln/detail/{v['cve_id']}) | {v['severity']} | "
            f"{v['cvss'] if v['cvss'] is not None else '-'} | "
            f"{(str(round(v['epss']*100, 1)) + '%') if v['epss'] is not None else '-'} | "
            f"{'yes' if v['kev'] else '-'} | {v['poc_count']} | {', '.join(v['sources']) or '-'} |"
        )
    lines.append("")
    for v in payload["vulnerabilities"]:
        lines += [f"### {v['cve_id']} — {v['severity']} {v['cvss'] if v['cvss'] is not None else ''}".strip(), ""]
        if v["matched"]:
            lines += [f"*Matched on:* {', '.join(v['matched'])}", ""]
        if v["description"]:
            lines += [v["description"][:700], ""]
        if v["kev"]:
            k = v["kev_info"]
            lines += [f"> **CISA KEV** — {k.get('name','')} (added {k.get('dateAdded','')})", ""]
        if v["findings"]:
            lines += ["| Source | What | Link |", "|---|---|---|"]
            for f in v["findings"]:
                lines.append(f"| {f['source']} | {f['title'].replace('|', '/')[:90]} | {f['url']} |")
            lines.append("")
        else:
            lines += ["_No public PoC found._", ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- html

SEV_COLOR = {"CRITICAL": "#ff4d6d", "HIGH": "#ff8f3f", "MEDIUM": "#ffd166", "LOW": "#9ad1a0",
             "NONE": "#8a8f98", "UNKNOWN": "#8a8f98"}


def to_html(payload: dict) -> str:
    e = html.escape
    s = payload["stats"]
    cards = []
    for v in payload["vulnerabilities"]:
        color = SEV_COLOR.get(v["severity"], "#8a8f98")
        badges = [f'<span class="badge" style="background:{color}22;color:{color};border:1px solid {color}55">{v["severity"]}</span>']
        if v["kev"]:
            badges.append('<span class="badge" style="background:#ff4d6d22;color:#ff4d6d;border:1px solid #ff4d6d55">CISA KEV</span>')
        if v["poc_count"]:
            badges.append(f'<span class="badge" style="background:#4ade8022;color:#4ade80;border:1px solid #4ade8055">{v["poc_count"]} PoC</span>')
        rows = []
        for f in v["findings"]:
            meta = " · ".join(str(f["meta"][k]) for k in ("stars", "rank", "severity", "date") if f["meta"].get(k))
            rows.append(
                f'<li><a href="{e(f["url"])}" target="_blank" rel="noopener">{e(f["title"][:110])}</a>'
                f'<span class="src">{e(f["source"])}</span>'
                f'{f"<span class=meta>{e(meta)}</span>" if meta else ""}</li>'
            )
        findings = f'<ul class="findings">{"".join(rows)}</ul>' if rows else '<p class="none">No public PoC found.</p>'
        matched = f'<div class="matched">matched: {e(", ".join(v["matched"]))}</div>' if v["matched"] else ""
        cards.append(f"""
      <article class="card" style="border-left-color:{color}">
        <header>
          <a class="cve" href="https://nvd.nist.gov/vuln/detail/{e(v['cve_id'])}" target="_blank" rel="noopener">{e(v['cve_id'])}</a>
          <span class="score" style="color:{color}">{v['cvss'] if v['cvss'] is not None else '-'}</span>
          {"".join(badges)}
          <span class="stats">EPSS {f"{v['epss']*100:.1f}%" if v['epss'] is not None else '-'}
            {f"· published {e(v['published'])}" if v['published'] else ""}</span>
        </header>
        {matched}
        <p class="desc">{e(v['description'][:600])}</p>
        {findings}
      </article>""")
    svc_rows = "".join(
        f"<tr><td>{e(sv['host'])}</td><td>{e(sv['port'])}/{e(sv['proto'])}</td><td>{e(sv['name'])}</td>"
        f"<td>{e(' '.join(x for x in (sv['product'], sv['version']) if x))}</td>"
        f"<td class='mono'>{e((sv.get('cpe_used') or sv['cpe'] or ['-'])[0])}</td></tr>"
        for sv in payload["services"]
    )
    services = (
        f"<h2>Scanned services</h2><table><thead><tr><th>host</th><th>port</th><th>service</th>"
        f"<th>banner</th><th>CPE</th></tr></thead><tbody>{svc_rows}</tbody></table>"
        if svc_rows else ""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CVEre report — {s['cves']} CVEs</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:40px 20px; background:#0b0d12; color:#e6e8ee;
         font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
  .wrap {{ max-width:1040px; margin:0 auto; }}
  h1 {{ font-size:26px; margin:0 0 4px; letter-spacing:-.02em; }}
  h1 span {{ color:#7c8cff; }}
  .sub {{ color:#8a8f98; font-size:13px; margin-bottom:26px; }}
  .kpis {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:28px; }}
  .kpi {{ flex:1 1 130px; background:#12151d; border:1px solid #1e2230; border-radius:12px; padding:14px 16px; }}
  .kpi b {{ display:block; font-size:24px; line-height:1.15; }}
  .kpi small {{ color:#8a8f98; text-transform:uppercase; letter-spacing:.08em; font-size:10.5px; }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.1em; color:#8a8f98; margin:34px 0 12px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; background:#12151d;
           border:1px solid #1e2230; border-radius:12px; overflow:hidden; }}
  th {{ text-align:left; padding:9px 12px; background:#161a24; color:#9aa1ae; font-weight:600; font-size:11px;
        text-transform:uppercase; letter-spacing:.07em; }}
  td {{ padding:9px 12px; border-top:1px solid #1a1e29; vertical-align:top; }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:#9aa1ae; }}
  .card {{ background:#12151d; border:1px solid #1e2230; border-left:4px solid #7c8cff;
           border-radius:12px; padding:16px 18px; margin-bottom:14px; }}
  .card header {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
  .cve {{ font:600 16px ui-monospace,Menlo,monospace; color:#c8d0ff; text-decoration:none; }}
  .cve:hover {{ text-decoration:underline; }}
  .score {{ font:700 20px ui-monospace,Menlo,monospace; }}
  .badge {{ font-size:10.5px; padding:2px 8px; border-radius:99px; text-transform:uppercase; letter-spacing:.06em; }}
  .stats {{ margin-left:auto; color:#8a8f98; font-size:12px; }}
  .matched {{ color:#8a8f98; font-size:12px; margin:6px 0 0; }}
  .desc {{ color:#b9c0cc; font-size:12.8px; margin:10px 0 6px; }}
  .findings {{ list-style:none; padding:0; margin:8px 0 0; }}
  .findings li {{ padding:5px 0; border-top:1px solid #1a1e29; font-size:12.8px; }}
  .findings a {{ color:#8fb8ff; text-decoration:none; }}
  .findings a:hover {{ text-decoration:underline; }}
  .src {{ font-size:10px; color:#7c8cff; border:1px solid #7c8cff44; border-radius:99px; padding:1px 6px; margin-left:8px;
          text-transform:uppercase; letter-spacing:.05em; }}
  .meta {{ color:#6b7280; font-size:11px; margin-left:8px; }}
  .none {{ color:#ffd166; font-size:12.5px; }}
  footer {{ color:#5c6270; font-size:11.5px; margin-top:36px; text-align:center; }}
</style></head>
<body><div class="wrap">
  <h1>CVE<span>re</span> report</h1>
  <div class="sub">Generated {e(payload['generated'])} · sources: {e(', '.join(payload['sources']))}
    · {payload['elapsed_seconds']}s</div>
  <div class="kpis">
    <div class="kpi"><b>{s['cves']}</b><small>CVEs</small></div>
    <div class="kpi"><b style="color:#ff4d6d">{s['critical']}</b><small>critical</small></div>
    <div class="kpi"><b style="color:#ff8f3f">{s['high']}</b><small>high</small></div>
    <div class="kpi"><b style="color:#4ade80">{s['with_poc']}</b><small>with public PoC</small></div>
    <div class="kpi"><b style="color:#ff4d6d">{s['kev']}</b><small>in CISA KEV</small></div>
  </div>
  {services}
  <h2>Vulnerabilities</h2>
  {"".join(cards) if cards else "<p class='none'>No matching CVEs.</p>"}
  <footer>CVEre · data from NVD, FIRST EPSS, CISA KEV, PoC-in-GitHub, trickest/cve, nuclei-templates,
    Exploit-DB, Metasploit Framework</footer>
</div></body></html>
"""
