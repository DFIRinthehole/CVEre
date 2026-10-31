"""Offline unit tests — no network required.  Run: python3 -m unittest discover -s tests -v"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cvere import nmap as nmap_parser
from cvere.models import Finding, Service, Vuln
from cvere.net import Http, HttpError, OfflineMiss
from cvere.report import build_payload, render_console, to_html, to_json, to_markdown
from cvere.logo import LOGO, plain, render
from cvere.sources import Ctx, canonical, clean_url, dedupe_findings, run_sources
from cvere.util import Paint, severity_for, truncate, version_candidates

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.join(os.path.dirname(HERE), "examples")

NORMAL_SCAN = """Nmap scan report for web01.lab.local (10.10.14.7)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1k)
8080/tcp open  ssl/http Jetty 9.4.43 (Apache Tomcat)
9000/tcp closed http     nginx
"""

GREPABLE = ("Host: 10.10.14.7 (web01)\tPorts: 80/open/tcp//http//Apache httpd 2.4.49 ((Unix))/, "
            "22/open/tcp//ssh//OpenSSH 8.2p1/\tIgnored State: filtered (998)\n")


class TestVersions(unittest.TestCase):
    def test_candidates(self):
        self.assertEqual(version_candidates("2.4.49"), ["2.4.49"])
        self.assertEqual(version_candidates("8.2p1"), ["8.2p1", "8.2"])
        self.assertIn("1.3.1", version_candidates("1.3.1a"))
        self.assertEqual(version_candidates(""), [])
        self.assertEqual(version_candidates(None), [])

    def test_never_invents_shorter_versions(self):
        # trimming "2.4.49" to "2.4.4" would match the wrong CPE
        self.assertNotIn("2.4.4", version_candidates("2.4.49"))

    def test_severity(self):
        self.assertEqual(severity_for(9.8), "CRITICAL")
        self.assertEqual(severity_for(7.0), "HIGH")
        self.assertEqual(severity_for(4.0), "MEDIUM")
        self.assertEqual(severity_for(0.1), "LOW")
        self.assertEqual(severity_for(None), "UNKNOWN")

    def test_truncate(self):
        self.assertEqual(truncate("abcdef", 4), "abc…")
        self.assertEqual(truncate("abc", 10), "abc")


class TestNmap(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(nmap_parser.detect_format("<nmaprun></nmaprun>"), "xml")
        self.assertEqual(nmap_parser.detect_format(GREPABLE), "grepable")
        self.assertEqual(nmap_parser.detect_format(NORMAL_SCAN), "normal")

    def test_normal(self):
        svcs = nmap_parser.parse(NORMAL_SCAN)
        self.assertEqual(len(svcs), 3)          # closed port skipped
        ssh, http, jetty = svcs
        self.assertEqual((ssh.product, ssh.version), ("OpenSSH", "8.2p1"))
        self.assertEqual((http.product, http.version), ("Apache httpd", "2.4.49"))
        self.assertEqual(jetty.tunnel, "ssl")
        self.assertEqual(jetty.name, "http")
        self.assertEqual(ssh.host, "web01.lab.local")

    def test_grepable(self):
        svcs = nmap_parser.parse(GREPABLE)
        self.assertEqual(len(svcs), 2)
        self.assertEqual(svcs[0].port, "80")
        self.assertEqual(svcs[0].version, "2.4.49")

    def test_xml_fixture(self):
        with open(os.path.join(EXAMPLES, "scan.xml"), encoding="utf-8") as fh:
            svcs = nmap_parser.parse(fh.read())
        self.assertEqual(len(svcs), 5)
        apache = next(s for s in svcs if "Apache" in s.product)
        self.assertEqual(apache.cpes, ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"])
        self.assertEqual(len(apache.cpes[0].split(":")), 13)

    def test_text_fixture_matches_xml(self):
        with open(os.path.join(EXAMPLES, "scan.txt"), encoding="utf-8") as fh:
            txt = nmap_parser.parse(fh.read())
        self.assertEqual(len(txt), 5)
        apache = next(s for s in txt if "Apache" in s.product)
        self.assertEqual((apache.product, apache.version), ("Apache httpd", "2.4.49"))

    def test_pasted_banner(self):
        svc = nmap_parser.parse_service_line("nginx 1.18.0 (Ubuntu)")[0]
        self.assertEqual((svc.product, svc.version), ("nginx", "1.18.0"))
        svc = nmap_parser.parse_service_line("443/tcp open ssl/https nginx 1.18.0")[0]
        self.assertEqual((svc.port, svc.name, svc.version), ("443", "https", "1.18.0"))

    def test_dedupe(self):
        a = Service(host="h", port="80", product="Apache httpd", version="2.4.49")
        b = Service(host="h", port="80", product="apache httpd", version="2.4.49")
        self.assertEqual(len(nmap_parser.dedupe([a, b])), 1)

    def test_split_banner(self):
        product, version, extra = nmap_parser.split_banner("Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1k)")
        self.assertEqual((product, version), ("Apache httpd", "2.4.49"))
        self.assertIn("OpenSSL", extra)


class TestSources(unittest.TestCase):
    def test_canonical(self):
        self.assertEqual(canonical("https://github.com/Foo/Bar/tree/main/x"),
                         canonical("https://github.com/foo/bar"))
        self.assertEqual(canonical("http://www.exploit-db.com/exploits/1/"),
                         "https://www.exploit-db.com/exploits/1")

    def test_clean_url(self):
        self.assertEqual(clean_url("https://w4ke.info/2025/10/29/funky-chunks-2.htmlJetty"),
                         "https://w4ke.info/2025/10/29/funky-chunks-2.html")
        self.assertEqual(clean_url("https://w4ke.info/post"), "https://w4ke.info/post")

    def test_dedupe_prefers_richer_source(self):
        a = Finding(source="trickest", url="https://github.com/x/y", title="x/y")
        b = Finding(source="poc-in-github", url="https://github.com/x/y", title="x/y", meta={"stars": 5})
        out = dedupe_findings([a, b])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].source, "poc-in-github")
        self.assertEqual(out[0].meta["also_in"], ["trickest"])

    def test_metasploit_modules_are_not_collapsed(self):
        # many modules live in one repo: they must stay distinct
        mods = [Finding(source="metasploit", url=f"https://github.com/rapid7/metasploit-framework/blob/master/modules/exploit/x{i}.rb",
                        title=f"Module {i}") for i in range(3)]
        self.assertEqual(len(dedupe_findings(mods)), 3)

    def test_repo_level_sources_still_collapse(self):
        links = [Finding(source="trickest", url="https://github.com/a/b/blob/main/poc.py"),
                 Finding(source="trickest", url="https://github.com/a/b/tree/main/other")]
        self.assertEqual(len(dedupe_findings(links)), 1)

    def test_unknown_source_is_reported(self):
        ctx = Ctx(Http(cache_dir=tempfile.mkdtemp()), limit=5)
        findings, errors = run_sources(ctx, "CVE-2020-0001", ["nope"])
        self.assertEqual(findings, [])
        self.assertIn("unknown source", errors["nope"])


class StubHttp(Http):
    """Serves canned responses; anything else raises like a 404."""

    def __init__(self, mapping):
        super().__init__(cache_dir=tempfile.mkdtemp())
        self.mapping = mapping

    def get(self, url, **kw):
        from cvere.net import Resp

        for frag, body in self.mapping.items():
            if frag in url:
                return Resp(url, 200, body.encode(), True)
        raise HttpError(url, 404)

    def post_json(self, url, payload, **kw):
        import json as _json

        for frag, body in self.mapping.items():
            if frag in url:
                return _json.loads(body) if isinstance(body, str) else body
        raise HttpError(url, 404)


class TestAdapters(unittest.TestCase):
    def test_trickest_parsing(self):
        md = """# CVE-2021-99999
## Description
### Github PoCs
- [repo one](https://github.com/a/b)
- https://github.com/a/b/tree/main/files
- https://github.com/c/d.htmlGlued
- [badge](https://img.shields.io/static/v1?label=x)
### Exploits
- [Packet Storm](http://packetstormsecurity.com/files/1/x.html)
"""
        ctx = Ctx(StubHttp({"trickest/cve": md}), limit=10)
        found, errors = run_sources(ctx, "CVE-2021-99999", ["trickest"])
        urls = [f.url for f in found]
        self.assertIn("https://github.com/a/b", urls)
        self.assertTrue(any(u.endswith("d.html") for u in urls))
        self.assertFalse(any("shields.io" in u for u in urls))
        self.assertEqual(len([u for u in urls if "github.com/a/b" in u]), 1)  # collapsed
        self.assertEqual(found[0].kind, "poc")

    def test_nuclei_template(self):
        index = json.dumps({"ID": "CVE-2021-44228", "Info": {"Name": "Log4j", "Severity": "critical"},
                            "file_path": "http/cves/2021/CVE-2021-44228.yaml"})
        ctx = Ctx(StubHttp({"nuclei-templates": index + "\n"}), limit=5)
        found, _ = run_sources(ctx, "CVE-2021-44228", ["nuclei"])
        self.assertEqual(len(found), 1)
        self.assertIn("CVE-2021-44228.yaml", found[0].url)
        self.assertEqual(found[0].meta["severity"], "critical")


class TestNewAdapters(unittest.TestCase):
    """HackerOne GraphQL, and the generic vh-style repo indexer."""

    def test_hackerone_filters_by_cve(self):
        payload = {"data": {"search": {"total_count": 2, "nodes": [
            {"__typename": "HacktivityDocument", "_id": "1", "cve_ids": ["CVE-2021-44228"],
             "severity_rating": "Critical", "disclosed_at": "2022-01-02", "total_awarded_amount": 5000,
             "report": {"title": "Log4j RCE", "url": "https://hackerone.com/reports/1"},
             "team": {"name": "Acme", "handle": "acme"}},
            {"__typename": "HacktivityDocument", "_id": "2", "cve_ids": [],
             "report": {"title": "Unrelated report", "url": "https://hackerone.com/reports/2"},
             "team": {"name": "Other", "handle": "other"}},
        ]}}}
        ctx = Ctx(StubHttp({"hackerone.com/graphql": payload}), limit=10)
        found, errors = run_sources(ctx, "CVE-2021-44228", ["hackerone"])
        self.assertEqual(errors, {})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].url, "https://hackerone.com/reports/1")
        self.assertEqual(found[0].meta["bounty"], 5000)
        self.assertIn("Acme", found[0].title)

    def test_repo_index_collapses_directory(self):
        files = [{"name": "/log4j/CVE-2021-44228/1.png"},
                 {"name": "/log4j/CVE-2021-44228/README.zh-cn.md"},
                 {"name": "/log4j/CVE-2021-44228/README.md"},
                 {"name": "/log4j/CVE-2021-44228-other/README.md"},
                 {"name": "/httpd/CVE-2021-41773/README.md"}]
        ctx = Ctx(StubHttp({"data.jsdelivr.com": json.dumps({"files": files})}), limit=10)
        found, _ = run_sources(ctx, "CVE-2021-44228", ["vulhub"])
        self.assertEqual(len(found), 1)                     # one entry for the CVE directory
        self.assertTrue(found[0].url.endswith("log4j/CVE-2021-44228/README.md"))
        self.assertEqual(found[0].kind, "lab")

    def test_repo_index_falls_back_to_github_tree(self):
        tree = {"tree": [{"path": "CVE-2017-0199.md", "type": "blob"}]}
        ctx = Ctx(StubHttp({"git/trees": json.dumps(tree)}), limit=10)
        found, _ = run_sources(ctx, "CVE-2017-0199", ["awesome-cve-poc"])
        self.assertEqual(len(found), 1)
        self.assertIn("CVE-2017-0199.md", found[0].url)

    def test_repo_index_no_hit(self):
        ctx = Ctx(StubHttp({"data.jsdelivr.com": json.dumps({"files": [{"name": "/x/y.md"}]})}), limit=10)
        found, errors = run_sources(ctx, "CVE-2020-99999", ["vulhub"])
        self.assertEqual((found, errors), ([], {}))

    def test_all_default_sources_are_registered(self):
        from cvere.sources import ADAPTERS, DEFAULT_SOURCES

        for name in DEFAULT_SOURCES:
            self.assertIn(name, ADAPTERS)


class TestLogo(unittest.TestCase):
    def test_render(self):
        out = render(Paint(enabled=False), "1.0.0", 9)
        self.assertEqual(len(out.splitlines()), 5)
        self.assertIn("public PoC", out)
        self.assertIn("v1.0.0", out)
        self.assertIn("9 sources", out)

    def test_rows_same_width(self):
        widths = {len(line) for line in plain().splitlines()}
        self.assertEqual(len(widths), 1)

    def test_colour_codes_only_when_enabled(self):
        self.assertNotIn("\033", render(Paint(enabled=False), "1.0.0", 3))
        self.assertIn("\033", render(Paint(enabled=True), "1.0.0", 3))


class TestNet(unittest.TestCase):
    def test_cache_roundtrip(self):
        d = tempfile.mkdtemp()
        h = Http(cache_dir=d)
        from cvere.net import Resp

        resp = Resp("https://x/y", 200, b'{"a":1}', False)
        h._write(h._path("https://x/y"), resp.status, resp.body)
        again = Http(cache_dir=d).get("https://x/y")
        self.assertEqual(again.json(), {"a": 1})
        self.assertTrue(again.cached)

    def test_offline_miss(self):
        h = Http(cache_dir=tempfile.mkdtemp(), offline=True)
        with self.assertRaises(OfflineMiss):
            h.get("https://example.invalid/nope")


class TestReport(unittest.TestCase):
    def make(self):
        v = Vuln(cve_id="CVE-2021-44228", description="Log4j RCE. Bad.", cvss=10.0, cvss_version="3.1",
                 epss=0.99, kev=True, kev_info={"name": "Log4j", "dateAdded": "2021-12-10"},
                 published="2021-12-10", matched=["Apache httpd 2.4.49 @ h:80/tcp"])
        v.findings = [Finding(source="exploitdb", url="https://www.exploit-db.com/exploits/50592",
                              title="Apache Log4j 2 - RCE", meta={"id": "50592"})]
        return v

    def test_console(self):
        out = render_console([self.make()], [Service(product="Apache httpd", version="2.4.49")],
                             Paint(enabled=False))
        self.assertIn("CVE-2021-44228", out)
        self.assertIn("CRITICAL", out)
        self.assertIn("exploit-db", out)
        self.assertIn("50592", out)

    def test_payload_and_formats(self):
        payload = build_payload([self.make()], [], ["exploitdb"], 1.0)
        self.assertEqual(payload["stats"]["with_poc"], 1)
        self.assertEqual(payload["stats"]["kev"], 1)
        self.assertIn("CVE-2021-44228", to_json(payload))
        md = to_markdown(payload)
        self.assertIn("| CRITICAL | 10.0 | 99.0% | yes | 1 | exploitdb |", md)
        html_out = to_html(payload)
        self.assertIn("<!doctype html>", html_out)
        self.assertIn("exploit-db", html_out)

    def test_html_escapes(self):
        v = self.make()
        v.description = "<script>alert(1)</script>"
        out = to_html(build_payload([v], [], [], 0))
        self.assertNotIn("<script>alert(1)</script>", out)


class TestCli(unittest.TestCase):
    def test_gather_inputs(self):
        from cvere.cli import gather_inputs

        args = argparse.Namespace(input=["cve-2021-44228", os.path.join(EXAMPLES, "scan.txt")],
                                  nmap=None, service=["Apache httpd 2.4.49"])
        cves, services = gather_inputs(args)
        self.assertEqual(cves, ["CVE-2021-44228"])
        self.assertEqual(len(services), 6)   # 5 from the file + 1 pasted banner

    def test_filters(self):
        from cvere.cli import apply_filters

        good = Vuln("CVE-1", cvss=9.8)
        good.findings = [Finding("exploitdb", "http://x")]
        low = Vuln("CVE-2", cvss=3.0)
        args = argparse.Namespace(min_cvss=7.0, kev=False, poc_only=False)
        self.assertEqual([v.cve_id for v in apply_filters([good, low], args)], ["CVE-1"])
        args = argparse.Namespace(min_cvss=0.0, kev=False, poc_only=True)
        self.assertEqual([v.cve_id for v in apply_filters([good, low], args)], ["CVE-1"])

    def test_list_sources(self):
        from cvere.cli import main

        self.assertEqual(main(["--list-sources"]), 0)

    def test_usage_error(self):
        from cvere.cli import main

        self.assertEqual(main([]), 2)
        self.assertEqual(main(["!!not-a-cve!!"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
