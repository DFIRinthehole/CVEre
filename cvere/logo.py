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


def render(paint: Paint, version: str = "", sources: int = 0, subtitle: str = "", width: int | None = None) -> str:
    """Colourised wordmark plus a tagline block.

    The tagline is only attached when it actually fits the terminal, otherwise a narrow window
    wraps it and the banner turns into confetti.
    """
    from .util import term_width

    width = width or term_width()
    lines = [paint(line, GRADIENT[min(i, len(GRADIENT) - 1)], "bold") for i, line in enumerate(LOGO)]
    tag = subtitle or "nmap / CVE  \u2192  public PoC, exploits & exploit intel"
    meta_bits = [f"v{version}" if version else "", f"{sources} sources" if sources else ""]
    meta = " \u00b7 ".join(b for b in meta_bits if b)
    pad = "  "
    logo_w = max(len(x) for x in LOGO)
    if logo_w + len(pad) + len(tag) <= width:
        lines[2] = lines[2] + pad + paint(tag, "bold")
        if meta:
            lines[4] = lines[4] + pad + paint(meta, "grey")
    elif meta and logo_w + len(pad) + len(meta) <= width:
        lines[4] = lines[4] + pad + paint(meta, "grey")
    return "\n".join(lines)


def plain() -> str:
    return "\n".join(LOGO)
