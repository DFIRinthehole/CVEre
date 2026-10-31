"""The CVEre wordmark."""
from __future__ import annotations

from .util import Paint

# "CVEre" in a custom 6-wide x 5-row block face
_GLYPHS = [
    [" █████", "██   ██", "██████", "██  ██", " ████ "],   # C V E r e
    ["██    ", "██   ██", "██    ", "██ ██ ", "██  ██"],
    ["██    ", "██   ██", "█████ ", "████  ", "█████ "],
    ["██    ", " ██ ██ ", "██    ", "██    ", "██    "],
    [" █████", "  ███  ", "██████", "██    ", " ████ "],
]

LOGO = [" ".join(row[i] for i in range(5)) for row in _GLYPHS]

GRADIENT = ["bcyan", "cyan", "bblue", "blue", "bmagenta"]


def render(paint: Paint, version: str = "", sources: int = 0, subtitle: str = "") -> str:
    """Colourised wordmark plus a tagline block."""
    lines = [paint(line, GRADIENT[min(i, len(GRADIENT) - 1)], "bold") for i, line in enumerate(LOGO)]
    tag = subtitle or "nmap / CVE  \u2192  public PoC, exploits & exploit intel"
    meta_bits = [f"v{version}" if version else "", f"{sources} sources" if sources else ""]
    meta = " \u00b7 ".join(b for b in meta_bits if b)
    pad = "  "
    lines[2] = lines[2] + pad + paint(tag, "bold")
    if meta:
        lines[4] = lines[4] + pad + paint(meta, "grey")
    return "\n".join(lines)


def plain() -> str:
    return "\n".join(LOGO)
