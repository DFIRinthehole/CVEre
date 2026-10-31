"""Parse nmap output (XML / normal / grepable) into Service objects.

Also accepts a bare ``product version`` string typed by hand.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Iterable

from .models import Service

VERSION_TOKEN = re.compile(r"^v?\d+(?:\.\d+)+")
LOOSE_VERSION = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)*(?:[a-z]\d*|p\d+)?)", re.I)


# --------------------------------------------------------------------------- helpers

def split_banner(banner: str) -> tuple[str, str, str]:
    """Split a free-text version banner into (product, version, extrainfo).

    ``Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1k)`` -> ("Apache httpd", "2.4.49", ...)
    """
    banner = (banner or "").strip()
    if not banner:
        return "", "", ""
    extra = ""
    m = re.search(r"\(\(?.*", banner)
    if m and m.start() > 0:
        extra = m.group(0).strip()
        banner = banner[: m.start()].strip()
    parts = banner.split()
    for i, tok in enumerate(parts):
        if VERSION_TOKEN.match(tok):
            product = " ".join(parts[:i]).strip()
            version = tok.lstrip("vV")
            rest = " ".join(parts[i + 1:]).strip()
            if rest:
                extra = (extra + " " + rest).strip()
            return product, version, extra
    # no token starting with a digit -> try a looser scan
    m = LOOSE_VERSION.search(banner)
    if m:
        return banner[: m.start()].strip(), m.group(1), banner[m.end():].strip()
    return banner, "", extra


def _service_from_fields(host: str, port: str, proto: str, service: str, banner: str) -> Service | None:
    service = (service or "").strip()
    tunnel = ""
    if "/" in service:
        tunnel, _, service = service.partition("/")
    product, version, extra = split_banner(banner)
    if not (product or service):
        return None
    if not product:
        product = service
    return Service(
        host=host,
        port=port,
        proto=proto or "tcp",
        name=service,
        product=product,
        version=version,
        extrainfo=extra,
        tunnel=tunnel,
    )


# --------------------------------------------------------------------------- XML

def _norm_cpe(cpe: str) -> str:
    cpe = cpe.strip()
    if cpe.startswith("cpe:/"):
        body = cpe[5:]
        fields = body.split(":")
        while len(fields) < 11:
            fields.append("*")
        fields = [f if f else "*" for f in fields]
        return "cpe:2.3:" + ":".join(fields)
    return cpe


def parse_xml(text: str) -> list[Service]:
    root = ET.fromstring(text)
    out: list[Service] = []
    for host in root.iter("host"):
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr") or ""
                break
        if not addr:
            fallback = host.find("address")
            addr = (fallback.get("addr") if fallback is not None else None) or "?"
        hostnames = [h.get("name") for h in host.findall("./hostnames/hostname") if h.get("name")]
        label = hostnames[0] if hostnames else addr
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is not None and state.get("state") not in (None, "open", "open|filtered"):
                continue
            svc = port.find("service")
            if svc is None:
                continue
            portid = port.get("portid", "?")
            proto = port.get("protocol", "tcp")
            product = svc.get("product", "")
            version = svc.get("version", "")
            extra = svc.get("extrainfo", "")
            name = svc.get("name", "")
            tunnel = svc.get("tunnel", "")
            cpes = [c.text.strip() for c in svc.findall("cpe") if c.text]
            if not (product or name):
                continue
            if not product:
                product = name
            out.append(
                Service(
                    host=label,
                    port=portid,
                    proto=proto,
                    name=name,
                    product=product,
                    version=version,
                    extrainfo=extra,
                    cpes=[_norm_cpe(c) for c in cpes],
                    tunnel=tunnel,
                )
            )
        # nmap may also drop cpes on the host level (rare)
    return out


# --------------------------------------------------------------------------- normal

REPORT_RE = re.compile(r"^Nmap scan report for\s+(.+?)\s*$")
PORT_RE = re.compile(r"^(\d+)/(tcp|udp|sctp)\s+(open\|filtered|open|filtered|unfiltered)\s+(\S+)\s*(.*)$")


def parse_normal(text: str) -> list[Service]:
    out: list[Service] = []
    host = "?"
    for raw in text.splitlines():
        line = raw.rstrip()
        m = REPORT_RE.match(line)
        if m:
            target = m.group(1)
            host = target.split()[0] if target.split() else target
            continue
        if line.startswith("|") or line.startswith("MAC Address") or not line.strip():
            continue
        m = PORT_RE.match(line.strip())
        if m:
            port, proto, state, service, banner = m.groups()
            if state not in ("open", "open|filtered"):
                continue
            svc = _service_from_fields(host, port, proto, service, banner)
            if svc:
                out.append(svc)
    if not out:
        # last resort: plain "product version" lines
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "|", "Nmap", "Starting", "Host", "PORT", "MAC")):
                continue
            svc = _service_from_fields("?", "?", "tcp", "", line)
            if svc and svc.version:
                out.append(svc)
    return out


# --------------------------------------------------------------------------- grepable

GREP_HOST = re.compile(r"^Host:\s+(\S+)\s*(?:\((.*?)\))?")
GREP_PORT = re.compile(r"Ports:\s*(.*?)\t?(?:Ignored State|OS:|Seq Index|IP ID|$)")


def parse_grepable(text: str) -> list[Service]:
    out: list[Service] = []
    for line in text.splitlines():
        m = GREP_HOST.match(line)
        if not m:
            continue
        host = (m.group(2) or m.group(1) or "?").strip()
        pm = re.search(r"Ports:(.*?)(?:\t(?:Ignored State|OS|Seq Index|IP ID|Status):|$)", line)
        if not pm:
            continue
        for entry in pm.group(1).split(","):
            entry = entry.strip()
            if not entry:
                continue
            f = entry.split("/")
            if len(f) < 5:
                continue
            port, state, proto, _owner, service = f[0], f[1], f[2], f[3], f[4]
            banner = f[6] if len(f) > 6 else (f[5] if len(f) > 5 else "")
            if state not in ("open", "open|filtered"):
                continue
            svc = _service_from_fields(host, port, proto, service, banner)
            if svc:
                out.append(svc)
    return out


# --------------------------------------------------------------------------- entry points

def detect_format(text: str) -> str:
    head = text.lstrip()[:4000]
    if head.startswith("<?xml") or "<nmaprun" in head:
        return "xml"
    if re.search(r"^Host:\s+\S+", text[:8000], re.M):
        return "grepable"
    return "normal"


def parse(text: str) -> list[Service]:
    fmt = detect_format(text)
    if fmt == "xml":
        return parse_xml(text)
    if fmt == "grepable":
        services = parse_grepable(text)
        if services:
            return services
    return parse_normal(text)


def parse_service_line(line: str) -> list[Service]:
    """Parse a pasted ``product version`` / ``port/service`` line."""
    line = line.strip()
    m = PORT_RE.match(line)
    if m:
        port, proto, state, service, banner = m.groups()
        svc = _service_from_fields("?", port, proto, service, banner)
        return [svc] if svc else []
    svc = _service_from_fields("?", "?", "tcp", "", line)
    return [svc] if svc else []


def dedupe(services: Iterable[Service]) -> list[Service]:
    seen: set[tuple] = set()
    out: list[Service] = []
    for s in services:
        key = (s.host, s.port, s.proto, s.product.lower(), s.version.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out
