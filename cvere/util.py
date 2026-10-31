"""Small helpers: colour, versions, text."""
from __future__ import annotations

import os
import re
import sys

# --------------------------------------------------------------------------- colour

RESET = "\033[0m"


class Paint:
    """ANSI colours that disable themselves when not a tty / NO_COLOR set."""

    CODES = {
        "bold": "1",
        "dim": "2",
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "white": "37",
        "grey": "90",
        "bred": "91",
        "bgreen": "92",
        "byellow": "93",
        "bblue": "94",
        "bmagenta": "95",
        "bcyan": "96",
    }

    def __init__(self, enabled: bool | None = None):
        if enabled is None:
            enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        codes = ";".join(self.CODES[s] for s in styles if s in self.CODES)
        return f"\033[{codes}m{text}{RESET}" if codes else text


SEVERITY_STYLE = {
    "CRITICAL": ("bred", "bold"),
    "HIGH": ("red",),
    "MEDIUM": ("byellow",),
    "LOW": ("yellow",),
    "NONE": ("grey",),
    "UNKNOWN": ("grey",),
}


def severity_for(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def severity_badge(score: float | None, paint: Paint) -> str:
    sev = severity_for(score)
    return paint(sev, *SEVERITY_STYLE.get(sev, ("grey",)))


# --------------------------------------------------------------------------- versions

_VER_RE = re.compile(r"\d+(?:\.\d+)*[A-Za-z0-9._-]*")


def version_candidates(version: str | None) -> list[str]:
    """Return plausible CPE version strings for an nmap version banner.

    nmap reports things like ``8.2p1``, ``2.4.49``, ``1.3.1a``, ``7.4.17 (Ubuntu)``
    while CPE dictionaries usually only carry ``8.2``/``2.4.49``.  We try the raw
    value first, then progressively trimmed variants.
    """
    if not version:
        return []
    v = version.strip()
    v = re.sub(r"\(.*?\)", "", v).strip()
    v = v.split()[0] if v.split() else v
    out: list[str] = []

    def add(x: str) -> None:
        if x and x not in out:
            out.append(x)

    add(v)
    # 8.2p1 -> 8.2p / 8.2 ; 1.2.3-ubuntu -> 1.2.3
    add(re.split(r"[-~+]", v)[0])
    m = re.match(r"^(\d+(?:\.\d+)*)", v)
    if m:
        add(m.group(1))
    # letters glued to the number, e.g. 2.4.49a -> 2.4.49
    stripped = re.sub(r"[A-Za-z]+$", "", v)
    add(stripped)
    return [x for x in out if x]


def norm_tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if t]


def truncate(text: str, width: int) -> str:
    text = " ".join((text or "").split())
    if width <= 1 or len(text) <= width:
        return text
    return text[: width - 1].rstrip() + "\u2026"


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}GB"


def fmt_epss(epss: float | None) -> str:
    return "-" if epss is None else f"{epss * 100:.1f}%"


def fmt_score(score: float | None) -> str:
    return "-" if score is None else f"{score:.1f}"
