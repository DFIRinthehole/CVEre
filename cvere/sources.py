"""Public PoC / exploit sources.

Every adapter returns a list of :class:`~cvere.models.Finding`.  All of them are
wrapped so a single failing source never kills a run.
"""
from __future__ import annotations

import html
import json
import re
import sys
import threading
from typing import Callable

from .models import Finding
from .net import Http, HttpError, q

POCAPI = "https://poc-in-github.motikan2010.net/api/v1/?cve_id="
TRICKEST = "https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve}.md"
NUCLEI_INDEX = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
NUCLEI_RAW = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/{path}"
EDB_SEARCH = "https://www.exploit-db.com/search?cve={short}"
EDB_EXPLOIT = "https://www.exploit-db.com/exploits/{id}"
MSF_INDEX = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
H1_GRAPHQL = "https://hackerone.com/graphql"
JSDELIVR = "https://data.jsdelivr.com/v1/packages/gh/{repo}@{branch}?structure=flat"
GH_TREE = "https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
GH_BLOB = "https://github.com/{repo}/blob/{branch}/{path}"
GH_SEARCH = "https://api.github.com/search/repositories?q={q}&sort=stars&order=desc&per_page={n}"

KIND_ORDER = ["poc", "exploit", "module", "template", "lab", "writeup", "advisory", "reference"]

MSF_RANKS = {0: "manual", 100: "low", 200: "average", 300: "normal", 400: "good", 500: "great", 600: "excellent"}


class Ctx:
    """Shared state for adapters (http client, caches, knobs)."""

    def __init__(self, http: Http, limit: int = 20, verbose: bool = False, github_token: str = ""):
        self.http = http
        self.limit = limit
        self.verbose = verbose
        self.github_token = github_token
        self._lock = threading.Lock()
        self._nuclei: dict[str, dict] | None = None
        self._msf: dict[str, list[dict]] | None = None
        self._repos: dict[str, list[str]] = {}

    def note(self, msg: str) -> None:
        if self.verbose:
            print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- poc-in-github

def poc_in_github(ctx: Ctx, cve: str) -> list[Finding]:
    data = ctx.http.get_json(POCAPI + q(cve), ttl=12 * 3600, allow_status=(404,))
    pocs = (data or {}).get("pocs") or []
    pocs.sort(key=lambda p: -int(p.get("stargazers_count") or 0))
    out = []
    for p in pocs[: ctx.limit]:
        url = p.get("html_url") or ""
        if not url:
            continue
        out.append(
            Finding(
                source="poc-in-github",
                url=url,
                title=p.get("full_name") or p.get("name") or "",
                kind="poc",
                meta={
                    "stars": int(p.get("stargazers_count") or 0),
                    "description": (p.get("description") or "")[:300],
                    "created": (p.get("created_at") or "")[:10],
                    "pushed": (p.get("pushed_at") or "")[:10],
                },
            )
        )
    return out


# --------------------------------------------------------------------------- trickest/cve

TRICKEST_LINK = re.compile(r"\[([^\]]*)\]\((https?://[^)\s]+)\)")
TRICKEST_BARE = re.compile(r"(?<!\()(https?://[^\s)\]>]+)")
# badge images, tracker pixels and similar noise that trickest embeds in its tables
NOISE_URL = re.compile(
    r"(img\.shields\.io|shields\.io|badge|visitor\.badge|github\.com/.*/(blob|tree)/.*\.(png|jpg|svg))",
    re.I,
)
# aggregator / index repos: they mention every CVE, they are not PoCs
AGGREGATOR = re.compile(
    r"github\.com/(arpsyndicate|nomi-sec|trickest|fkie-cad|0day404|0x7n6|scmanjarrez|"
    r"nmmapper|vulnerscom|edoardottt|cybermon|unknown)($|/)",
    re.I,
)
FILE_EXT = {"html", "htm", "php", "md", "txt", "yaml", "yml", "rb", "py", "sh", "go", "java",
            "json", "pdf", "zip", "js", "asp", "aspx", "jsp", "c", "cpp", "pl"}
EXT_GLUE = re.compile(r"(\.[a-z0-9]{1,5})([A-Z][A-Za-z0-9]*)$")


def clean_url(link: str) -> str:
    """Trim junk glued onto a bare URL by sloppy markdown tables."""
    m = EXT_GLUE.search(link)
    if m and m.group(1)[1:].lower() in FILE_EXT:
        return link[: m.start()] + m.group(1)
    return link
SECTION_KIND = [
    ("github", "poc"),
    ("exploit", "exploit"),
    ("nuclei", "template"),
    ("metasploit", "module"),
    ("writeup", "writeup"),
    ("blog", "writeup"),
    ("analysis", "writeup"),
    ("advisory", "advisory"),
]


def _kind_for_section(section: str) -> str:
    s = section.lower()
    for key, kind in SECTION_KIND:
        if key in s:
            return kind
    return "reference"


def trickest(ctx: Ctx, cve: str) -> list[Finding]:
    year = cve.split("-")[1]
    url = TRICKEST.format(year=year, cve=cve.upper())
    try:
        text = ctx.http.get(url, ttl=12 * 3600, allow_status=(404,)).text
    except HttpError:
        return []
    if not text or "404: Not Found" in text[:100]:
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    section = ""
    for line in text.splitlines():
        if line.startswith("#"):
            section = line.lstrip("#").strip()
            continue
        links = TRICKEST_LINK.findall(line)
        if not links:
            links = [(u, u) for u in TRICKEST_BARE.findall(line)]
        for title, link in links:
            link = clean_url(link.rstrip(".,;"))
            if link in seen or NOISE_URL.search(link) or AGGREGATOR.search(link):
                continue
            if link.rstrip("/") in (url, url[:-1]):
                continue
            # collapse many files from one repo into one hit
            key = link
            m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)", link)
            if m:
                key = f"{m.group(1)}/{m.group(2)}".lower()
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    source="trickest",
                    url=link,
                    title=(title or "").strip()[:160] or link,
                    kind=_kind_for_section(section),
                    meta={"section": section} if section else {},
                )
            )
            if len(findings) >= ctx.limit * 3:
                break
    findings.sort(key=lambda f: KIND_ORDER.index(f.kind) if f.kind in KIND_ORDER else 9)
    return findings[: ctx.limit]


# --------------------------------------------------------------------------- nuclei

def _nuclei_index(ctx: Ctx) -> dict[str, dict]:
    with ctx._lock:
        if ctx._nuclei is not None:
            return ctx._nuclei
    ctx.note("  · downloading nuclei-templates index (~2 MB, cached 24h)")
    index: dict[str, dict] = {}
    try:
        text = ctx.http.get(NUCLEI_INDEX, ttl=24 * 3600).text
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            cid = (rec.get("ID") or "").upper()
            if not cid.startswith("CVE-"):
                continue
            index.setdefault(cid, {
                "path": rec.get("file_path", ""),
                "name": (rec.get("Info") or {}).get("Name", ""),
                "severity": (rec.get("Info") or {}).get("Severity", ""),
            })
    except HttpError as e:
        ctx.note(f"  ! nuclei index: {e}")
    with ctx._lock:
        ctx._nuclei = index
    return index


def nuclei(ctx: Ctx, cve: str) -> list[Finding]:
    rec = _nuclei_index(ctx).get(cve.upper())
    if not rec:
        return []
    path = rec["path"]
    return [
        Finding(
            source="nuclei",
            url=NUCLEI_RAW.format(path=path),
            title=rec.get("name") or path,
            kind="template",
            meta={"severity": rec.get("severity", ""), "path": path,
                  "web": f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{path}"},
        )
    ]


# --------------------------------------------------------------------------- exploit-db

def exploitdb(ctx: Ctx, cve: str) -> list[Finding]:
    short = cve.split("-", 1)[1]  # 2021-44228
    url = EDB_SEARCH.format(short=short)
    data = ctx.http.get_json(
        url,
        ttl=12 * 3600,
        headers={"X-Requested-With": "XMLHttpRequest", "Referer": "https://www.exploit-db.com/"},
        rate=("www.exploit-db.com", 1.0),
        allow_status=(404,),
    )
    out = []
    for row in (data or {}).get("data") or []:
        eid = str(row.get("id") or "")
        desc = row.get("description")
        if isinstance(desc, list):
            desc = desc[-1] if desc else ""
        out.append(
            Finding(
                source="exploitdb",
                url=EDB_EXPLOIT.format(id=eid),
                title=html.unescape(str(desc or f"EDB-{eid}")),
                kind="exploit",
                meta={
                    "id": eid,
                    "type": (row.get("type") or {}).get("display", ""),
                    "platform": (row.get("platform") or {}).get("platform", ""),
                    "author": (row.get("author") or {}).get("name", ""),
                    "date": row.get("date_published", ""),
                    "verified": bool(row.get("verified")),
                },
            )
        )
    return out[: ctx.limit]


# --------------------------------------------------------------------------- metasploit

def _msf_index(ctx: Ctx) -> dict[str, list[dict]]:
    with ctx._lock:
        if ctx._msf is not None:
            return ctx._msf
    ctx.note("  · downloading metasploit module index (~11 MB, cached 7d)")
    index: dict[str, list[dict]] = {}
    try:
        data = ctx.http.get_json(MSF_INDEX, ttl=7 * 86400)
        for key, mod in data.items():
            for ref in mod.get("references") or []:
                if isinstance(ref, str) and ref.upper().startswith("CVE-"):
                    index.setdefault(ref.upper(), []).append({
                        "fullname": mod.get("fullname") or key,
                        "name": mod.get("name", ""),
                        "rank": MSF_RANKS.get(mod.get("rank"), str(mod.get("rank", ""))),
                        "type": mod.get("type", ""),
                        "date": mod.get("disclosure_date", ""),
                        "path": mod.get("path", ""),
                    })
    except HttpError as e:
        ctx.note(f"  ! metasploit index: {e}")
    with ctx._lock:
        ctx._msf = index
    return index


def metasploit(ctx: Ctx, cve: str) -> list[Finding]:
    mods = _msf_index(ctx).get(cve.upper()) or []
    mods.sort(key=lambda m: m.get("date") or "", reverse=True)
    out = []
    for m in mods[: ctx.limit]:
        full = m["fullname"]
        # module files live at modules/<type>/<rest>.rb
        typ = m.get("type") or full.split("/")[0]
        rel = full.split("/", 1)[1] if "/" in full else full
        url = f"https://github.com/rapid7/metasploit-framework/blob/master/modules/{typ}/{rel}.rb"
        out.append(
            Finding(
                source="metasploit",
                url=url,
                title=m.get("name") or full,
                kind="module",
                meta={"fullname": full, "rank": m.get("rank", ""), "date": m.get("date", ""), "type": typ},
            )
        )
    return out


# --------------------------------------------------------------------------- github search

def github_search(ctx: Ctx, cve: str) -> list[Finding]:
    headers = {"Accept": "application/vnd.github+json"}
    if ctx.github_token:
        headers["Authorization"] = f"Bearer {ctx.github_token}"
    url = GH_SEARCH.format(q=q(f'"{cve}" in:name,description'), n=ctx.limit)
    data = ctx.http.get_json(
        url, ttl=12 * 3600, headers=headers, rate=("api.github.com", 1.0 if ctx.github_token else 6.5)
    )
    out = []
    for r in (data or {}).get("items") or []:
        out.append(
            Finding(
                source="github-search",
                url=r.get("html_url", ""),
                title=r.get("full_name", ""),
                kind="poc",
                meta={
                    "stars": r.get("stargazers_count", 0),
                    "description": (r.get("description") or "")[:300],
                    "pushed": (r.get("pushed_at") or "")[:10],
                },
            )
        )
    return out


# --------------------------------------------------------------------------- hackerone

H1_QUERY = """query($q: String!, $n: Int!) {
  search(index: CompleteHacktivityReportIndex, query_string: $q, first: $n) {
    total_count
    nodes {
      __typename
      ... on HacktivityDocument {
        _id
        cve_ids
        severity_rating
        disclosed_at
        total_awarded_amount
        report { title url }
        team { handle name }
      }
    }
  }
}"""


def hackerone(ctx: Ctx, cve: str) -> list[Finding]:
    """Disclosed HackerOne reports - they usually carry real reproduction steps / curl PoCs."""
    data = ctx.http.post_json(
        H1_GRAPHQL,
        {"query": H1_QUERY, "variables": {"q": cve, "n": 40}},
        ttl=12 * 3600,
        rate=("hackerone.com", 1.0),
    )
    nodes = (((data or {}).get("data") or {}).get("search") or {}).get("nodes") or []
    out: list[Finding] = []
    for node in nodes:
        if node.get("__typename") != "HacktivityDocument":
            continue
        title = (node.get("report") or {}).get("title") or ""
        cve_ids = [c.upper() for c in (node.get("cve_ids") or [])]
        if cve not in cve_ids and cve.lower() not in title.lower():
            continue
        url = (node.get("report") or {}).get("url") or f"https://hackerone.com/reports/{node.get('_id')}"
        team = (node.get("team") or {}).get("name") or (node.get("team") or {}).get("handle") or ""
        out.append(
            Finding(
                source="hackerone",
                url=url,
                title=f"{team} — {title}".strip(" —")[:160],
                kind="poc",
                meta={
                    "severity": node.get("severity_rating") or "",
                    "date": (node.get("disclosed_at") or "")[:10],
                    "bounty": node.get("total_awarded_amount") or 0,
                    "id": node.get("_id") or "",
                },
            )
        )
    return out[: ctx.limit]


# --------------------------------------------------------------------------- repo indexes
# Lab/index repos carry the CVE id in the path, so one flat file listing per repo answers
# "is there anything here for this CVE?" for every CVE in the run.

REPO_INDEXES: dict[str, dict[str, str]] = {
    "vulhub": {"repo": "vulhub/vulhub", "branch": "master", "kind": "lab", "label": "Vulhub lab"},
    "cveslab": {"repo": "SecuriTrust/CVEsLab", "branch": "main", "kind": "lab", "label": "CVEsLab lab"},
    "awesome-cve-poc": {"repo": "qazbnm456/awesome-cve-poc", "branch": "master", "kind": "poc",
                        "label": "awesome-cve-poc entry"},
}


def _repo_paths(ctx: Ctx, repo: str, branch: str) -> list[str]:
    """Flat list of every blob path in a GitHub repo (jsdelivr first, GitHub tree API fallback)."""
    key = f"{repo}@{branch}"
    with ctx._lock:
        if key in ctx._repos:
            return ctx._repos[key]
    paths: list[str] | None = None
    try:
        data = ctx.http.get_json(JSDELIVR.format(repo=repo, branch=branch), ttl=7 * 86400)
        paths = [f["name"].lstrip("/") for f in data.get("files") or []]
    except HttpError:
        paths = None
    if not paths:
        headers = {}
        if ctx.github_token:
            headers["Authorization"] = f"Bearer {ctx.github_token}"
        ctx.note(f"  · downloading {repo} file index via GitHub API (cached 7d)")
        data = ctx.http.get_json(
            GH_TREE.format(repo=repo, branch=branch),
            ttl=7 * 86400,
            headers=headers,
            rate=("api.github.com", 1.0 if ctx.github_token else 2.0),
        )
        paths = [n["path"] for n in data.get("tree") or [] if n.get("type") == "blob"]
    with ctx._lock:
        ctx._repos[key] = paths
    return paths


def _repo_index(ctx: Ctx, cve: str, name: str) -> list[Finding]:
    spec = REPO_INDEXES[name]
    paths = _repo_paths(ctx, spec["repo"], spec["branch"])
    exact = re.compile(rf"(^|/){re.escape(cve)}(/|\.|$)", re.I)
    hits = [p for p in paths if exact.search(p)]
    if not hits:
        return []
    # collapse every file of a CVE directory into one entry, README.md first
    def pref(path: str) -> int:
        name = path.rsplit("/", 1)[-1].lower()
        return {("readme.md",): 0}.get((name,), 1 if name.startswith("readme") else 2)

    dirs: dict[str, str] = {}
    for path in hits:
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        if parent not in dirs or pref(path) < pref(dirs[parent]):
            dirs[parent] = path
    out: list[Finding] = []
    for parent, path in sorted(dirs.items()):
        out.append(
            Finding(
                source=name,
                url=GH_BLOB.format(repo=spec["repo"], branch=spec["branch"], path=path),
                title=f"{spec['label']}: {parent or path}"[:160],
                kind=spec["kind"],
                meta={"path": path, "repo": spec["repo"]},
            )
        )
    return out[: ctx.limit]


def vulhub(ctx: Ctx, cve: str) -> list[Finding]:
    return _repo_index(ctx, cve, "vulhub")


def cveslab(ctx: Ctx, cve: str) -> list[Finding]:
    return _repo_index(ctx, cve, "cveslab")


def awesome_cve_poc(ctx: Ctx, cve: str) -> list[Finding]:
    return _repo_index(ctx, cve, "awesome-cve-poc")


# --------------------------------------------------------------------------- registry

ADAPTERS: dict[str, tuple[Callable[[Ctx, str], list[Finding]], str]] = {
    "poc-in-github": (poc_in_github, "2000+ GitHub repos indexed per CVE (motikan2010 API)"),
    "trickest": (trickest, "trickest/cve curated PoC + exploit lists"),
    "nuclei": (nuclei, "ProjectDiscovery nuclei templates"),
    "exploitdb": (exploitdb, "Exploit-DB entries"),
    "metasploit": (metasploit, "Metasploit Framework modules"),
    "hackerone": (hackerone, "disclosed HackerOne reports (Hacktivity, public GraphQL)"),
    "vulhub": (vulhub, "Vulhub docker labs for the CVE"),
    "cveslab": (cveslab, "SecuriTrust/CVEsLab reproduction labs"),
    "awesome-cve-poc": (awesome_cve_poc, "qazbnm456/awesome-cve-poc curated entries"),
    "github-search": (github_search, "live GitHub repository search (rate limited)"),
}

DEFAULT_SOURCES = [
    "poc-in-github", "exploitdb", "metasploit", "nuclei", "hackerone",
    "vulhub", "cveslab", "awesome-cve-poc", "trickest",
]


GH_REPO = re.compile(r"https?://github\.com/([^/]+)/([^/#?\s]+)", re.I)
SOURCE_PRIORITY = [
    "poc-in-github", "exploitdb", "metasploit", "nuclei", "hackerone",
    "vulhub", "cveslab", "awesome-cve-poc", "trickest", "github-search",
]


def canonical(url: str) -> str:
    """Collapse URLs that point at the same thing (repo, EDB entry, ...)."""
    m = GH_REPO.match(url)
    if m:
        repo = m.group(2)
        if repo.endswith(".git"):
            repo = repo[:-4]
        return f"github/{m.group(1)}/{repo}".lower()
    u = url.split("?")[0].rstrip("/")
    return u.replace("http://", "https://").lower()


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """One entry per target repo/exploit, with cross-source hits noted in meta."""
    rank = {name: i for i, name in enumerate(SOURCE_PRIORITY)}
    ordered = sorted(findings, key=lambda f: rank.get(f.source, 99))
    seen: dict[str, Finding] = {}
    out: list[Finding] = []
    for f in ordered:
        key = canonical(f.url)
        if key in seen:
            also = seen[key].meta.setdefault("also_in", [])
            if f.source != seen[key].source and f.source not in also:
                also.append(f.source)
            continue
        seen[key] = f
        out.append(f)
    return out


def run_sources(ctx: Ctx, cve: str, names: list[str]) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    errors: dict[str, str] = {}
    for name in names:
        fn = ADAPTERS.get(name, (None, ""))[0]
        if fn is None:
            errors[name] = "unknown source"
            continue
        try:
            findings.extend(fn(ctx, cve))
        except HttpError as e:
            errors[name] = f"HTTP {e.status}" if e.status else "network error"
        except Exception as e:  # noqa: BLE001 - source isolation on purpose
            errors[name] = f"{type(e).__name__}: {e}"
    return dedupe_findings(findings), errors
