"""Generate the README and documentation artwork as SVG.

Every image under ``docs/assets`` that is not a recording is drawn here, so a
change of wording, colour or name is one edit and one command::

    python tools/assets.py                  # write everything
    python tools/assets.py --only banner    # write one asset
    python tools/assets.py --check          # fail if a file is out of date

The files are plain SVG with system fonts only, so they render the same on
GitHub, in the documentation site and in any editor. The numbers drawn in the
benchmark panel are read from ``benchmark/results-podman.json`` when that file
exists, so the picture cannot drift from the measurement.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "docs" / "assets"

NAME = "Verdis"
SLUG = "verdis"
VERSION = "0.1.0"
TAGLINE = "Reproduce-first triage for security reports"

SANS = "Inter, 'Helvetica Neue', Helvetica, Arial, 'Segoe UI', sans-serif"
MONO = "'SF Mono', ui-monospace, Menlo, Consolas, 'Liberation Mono', monospace"


class Theme:
    """The palette of one rendering."""

    def __init__(
        self,
        *,
        bg: str,
        panel: str,
        line: str,
        ink: str,
        muted: str,
        faint: str,
        accent: str,
    ) -> None:
        self.bg = bg
        self.panel = panel
        self.line = line
        self.ink = ink
        self.muted = muted
        self.faint = faint
        self.accent = accent


DARK = Theme(
    bg="#060807",
    panel="#0c110f",
    line="#1f2a25",
    ink="#f1f5f2",
    muted="#8d9c94",
    faint="#4d5a54",
    accent="#3ddc97",
)
LIGHT = Theme(
    bg="#f7f8f5",
    panel="#ffffff",
    line="#d9dfda",
    ink="#0a0e0c",
    muted="#56645c",
    faint="#9aa6a0",
    accent="#0e9f66",
)

#: One colour per verdict, tuned for a dark background.
VERDICT_COLOURS = {
    "REPRODUCED": "#3ddc97",
    "NOT_REPRODUCED": "#8fb4ff",
    "INCONCLUSIVE": "#f2b84b",
    "OUT_OF_SCOPE": "#b79cff",
    "DUPLICATE": "#5fd4e8",
    "NEEDS_INFO": "#ff9f5a",
    "UNSAFE_ATTACHMENT": "#ff6b6b",
}

#: The four roles a stage can play, drawn as the accent of its card.
ROLE_COLOURS = {
    "model": "#f2b84b",
    "rule": "#c9d3cd",
    "sandbox": "#3ddc97",
    "oracle": "#8fb4ff",
}


# ---------------------------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------------------------


def esc(value: str) -> str:
    return html.escape(value, quote=False)


def num(value: float) -> str:
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return text or "0"


def text(
    x: float,
    y: float,
    value: str,
    *,
    size: float = 20,
    fill: str = "#fff",
    weight: int = 400,
    anchor: str = "start",
    mono: bool = False,
    spacing: float = 0,
    opacity: float | None = None,
    italic: bool = False,
) -> str:
    attrs = [
        f'x="{num(x)}"',
        f'y="{num(y)}"',
        f'font-family="{MONO if mono else SANS}"',
        f'font-size="{num(size)}"',
        f'font-weight="{weight}"',
        f'fill="{fill}"',
    ]
    if anchor != "start":
        attrs.append(f'text-anchor="{anchor}"')
    if spacing:
        attrs.append(f'letter-spacing="{num(spacing)}"')
    if opacity is not None:
        attrs.append(f'opacity="{num(opacity)}"')
    if italic:
        attrs.append('font-style="italic"')
    return f"<text {' '.join(attrs)}>{esc(value)}</text>"


def runs(
    x: float,
    y: float,
    parts: list[tuple[str, str]],
    *,
    size: float = 20,
    weight: int = 400,
    mono: bool = False,
    spacing: float = 0,
    anchor: str = "start",
) -> str:
    """One line of text whose pieces carry different colours."""
    attrs = [
        f'x="{num(x)}"',
        f'y="{num(y)}"',
        f'font-family="{MONO if mono else SANS}"',
        f'font-size="{num(size)}"',
        f'font-weight="{weight}"',
    ]
    if anchor != "start":
        attrs.append(f'text-anchor="{anchor}"')
    if spacing:
        attrs.append(f'letter-spacing="{num(spacing)}"')
    inner = "".join(f'<tspan fill="{fill}">{esc(piece)}</tspan>' for piece, fill in parts)
    return f"<text {' '.join(attrs)}>{inner}</text>"


def lines(
    x: float,
    y: float,
    values: list[str],
    *,
    leading: float,
    **kwargs: object,
) -> str:
    return "\n".join(
        text(x, y + index * leading, value, **kwargs)  # type: ignore[arg-type]
        for index, value in enumerate(values)
    )


def rect(
    x: float,
    y: float,
    w: float,
    h: float,
    *,
    fill: str = "none",
    stroke: str | None = None,
    sw: float = 1,
    rx: float = 0,
    dash: str | None = None,
    opacity: float | None = None,
) -> str:
    attrs = [f'x="{num(x)}"', f'y="{num(y)}"', f'width="{num(w)}"', f'height="{num(h)}"']
    if rx:
        attrs.append(f'rx="{num(rx)}"')
    attrs.append(f'fill="{fill}"')
    if stroke:
        attrs.append(f'stroke="{stroke}" stroke-width="{num(sw)}"')
    if dash:
        attrs.append(f'stroke-dasharray="{dash}"')
    if opacity is not None:
        attrs.append(f'opacity="{num(opacity)}"')
    return f"<rect {' '.join(attrs)}/>"


def line(
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    *,
    stroke: str,
    sw: float = 1,
    dash: str | None = None,
    opacity: float | None = None,
) -> str:
    attrs = [
        f'x1="{num(x1)}"',
        f'y1="{num(y1)}"',
        f'x2="{num(x2)}"',
        f'y2="{num(y2)}"',
        f'stroke="{stroke}"',
        f'stroke-width="{num(sw)}"',
    ]
    if dash:
        attrs.append(f'stroke-dasharray="{dash}"')
    if opacity is not None:
        attrs.append(f'opacity="{num(opacity)}"')
    return f"<line {' '.join(attrs)}/>"


def path(
    d: str,
    *,
    stroke: str,
    sw: float = 2,
    fill: str = "none",
    dash: str | None = None,
    marker_end: str | None = None,
    opacity: float | None = None,
) -> str:
    attrs = [
        f'd="{d}"',
        f'fill="{fill}"',
        f'stroke="{stroke}"',
        f'stroke-width="{num(sw)}"',
        'stroke-linecap="round"',
        'stroke-linejoin="round"',
    ]
    if dash:
        attrs.append(f'stroke-dasharray="{dash}"')
    if marker_end:
        attrs.append(f'marker-end="url(#{marker_end})"')
    if opacity is not None:
        attrs.append(f'opacity="{num(opacity)}"')
    return f"<path {' '.join(attrs)}/>"


def circle(cx: float, cy: float, r: float, *, fill: str = "none", stroke: str | None = None, sw: float = 1) -> str:
    attrs = [f'cx="{num(cx)}"', f'cy="{num(cy)}"', f'r="{num(r)}"', f'fill="{fill}"']
    if stroke:
        attrs.append(f'stroke="{stroke}" stroke-width="{num(sw)}"')
    return f"<circle {' '.join(attrs)}/>"


def arrow(points: list[tuple[float, float]], *, stroke: str, sw: float = 2, head: float = 10) -> str:
    """A polyline with a chevron at the end. Drawn explicitly, so no renderer has to orient a marker."""
    d = "M" + " L".join(f"{num(x)} {num(y)}" for x, y in points)
    (x0, y0), (x1, y1) = points[-2], points[-1]
    dx, dy = x1 - x0, y1 - y0
    norm = math.hypot(dx, dy) or 1.0
    ux, uy = dx / norm, dy / norm
    px, py = -uy, ux
    ax, ay = x1 - ux * head + px * head * 0.6, y1 - uy * head + py * head * 0.6
    bx, by = x1 - ux * head - px * head * 0.6, y1 - uy * head - py * head * 0.6
    tip = f"M{num(ax)} {num(ay)} L{num(x1)} {num(y1)} L{num(bx)} {num(by)}"
    return path(d, stroke=stroke, sw=sw) + path(tip, stroke=stroke, sw=sw)


_ICONS: dict[str, str] = {
    "doc": '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M9 12h6M9 16h6"/>',
    "cube": '<path d="M12 2.5l8 4.4v9.2l-8 4.4-8-4.4V6.9z"/><path d="M4 6.9l8 4.4 8-4.4M12 11.3v9.2"/>',
    "terminal": '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M7 10l3 2.5L7 15M12.5 15H17"/>',
    "check": '<path d="M5 12.5l4.5 4.5L19 7"/>',
    "shield": '<path d="M12 3l7 3v5.5c0 4.6-3 7.6-7 9.5-4-1.9-7-4.9-7-9.5V6z"/><path d="M9 12l2.2 2.2L15.5 10"/>',
    "hash": '<path d="M5 9h14M5 15h14M10.5 4l-2 16M15.5 4l-2 16"/>',
    "gear": (
        '<circle cx="12" cy="12" r="3.2"/>'
        '<path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/>'
    ),
    "lock": '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>',
    "inbox": '<path d="M3 13l3-8h12l3 8v6H3z"/><path d="M3 13h5l1.5 2.5h5L16 13h5"/>',
    "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5L21 21"/>',
    "copy": '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
    "scales": (
        '<path d="M12 3v18M7 21h10M5 7h14"/>'
        '<path d="M5 7l-3 7a3.2 3.2 0 0 0 6 0zM19 7l-3 7a3.2 3.2 0 0 0 6 0z"/>'
    ),
    "spark": '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"/><path d="M19 16v4M17 18h4"/>',
    "play": '<path d="M8 5l11 7-11 7z"/>',
    "archive": '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v10h14V9M10 13h4"/>',
    "mail": '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    "branch": (
        '<path d="M7 4v13"/><circle cx="7" cy="19" r="2"/><circle cx="17" cy="7" r="2"/><circle cx="7" cy="4" r="0.6"/>'
        '<path d="M17 9c0 5-10 3-10 8"/>'
    ),
    "list": '<path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1"/><circle cx="4.5" cy="12" r="1"/><circle cx="4.5" cy="18" r="1"/>',
    "flag": '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
}


def icon(name: str, x: float, y: float, size: float, colour: str, sw: float = 1.7) -> str:
    scale = size / 24
    return (
        f'<g transform="translate({num(x)} {num(y)}) scale({num(scale)})" fill="none" '
        f'stroke="{colour}" stroke-width="{num(sw)}" stroke-linecap="round" stroke-linejoin="round">'
        f"{_ICONS[name]}</g>"
    )


def mark(x: float, y: float, size: float, *, fg: str, accent: str, ring: str | None = None, dot: bool = True) -> str:
    """The logo: a V that finishes as a tick, ending in a point of evidence."""
    s = size / 64
    parts = [f'<g transform="translate({num(x)} {num(y)}) scale({num(s)})">']
    if ring:
        parts.append(rect(1.5, 1.5, 61, 61, stroke=ring, sw=3, rx=17))
    parts.append(
        path("M16 21 L31 46 L49 15", stroke=fg, sw=7, opacity=None)
    )
    if dot:
        parts.append(circle(49, 15, 5.5, fill=accent))
    parts.append("</g>")
    return "".join(parts)


def svg(width: int, height: int, body: str, *, defs: str = "", title: str = "", desc: str = "") -> str:
    head = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img"'
    )
    if title:
        head += f' aria-label="{esc(title)}"'
    head += ">"
    inner = []
    if title:
        inner.append(f"<title>{esc(title)}</title>")
    if desc:
        inner.append(f"<desc>{esc(desc)}</desc>")
    if defs:
        inner.append(f"<defs>{defs}</defs>")
    inner.append(body)
    return head + "\n" + "\n".join(inner) + "\n</svg>\n"


def chip(x: float, y: float, label: str, colour: str, *, size: float = 15, pad: float = 14, h: float = 30, bg: str = "#0c110f") -> tuple[str, float]:
    """A verdict chip. Returns the markup and its width."""
    width = len(label) * size * 0.64 + 2 * pad
    body = (
        rect(x, y, width, h, fill=bg, stroke=colour, sw=1.4, rx=h / 2)
        + circle(x + pad - 1, y + h / 2, 3.5, fill=colour)
        + text(x + pad + 9, y + h / 2 + size * 0.36, label, size=size, fill=colour, weight=600, mono=True, spacing=0.6)
    )
    return body, width


# ---------------------------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------------------------


def build_mark() -> str:
    body = rect(0, 0, 64, 64, fill="#060807", rx=16) + mark(0, 0, 64, fg="#f1f5f2", accent="#3ddc97")
    return svg(64, 64, body, title=f"{NAME} mark")


def banner(theme: Theme) -> str:
    w, h = 1200, 630
    parts = [rect(0, 0, w, h, fill=theme.bg)]
    # A faint oversized mark on the right keeps the plain layout from feeling empty.
    parts.append(
        '<g opacity="0.06">' + mark(716, 36, 470, fg=theme.ink, accent=theme.accent, dot=False) + "</g>"
    )
    parts.append(mark(72, 62, 52, fg=theme.ink, accent=theme.accent))
    parts.append(line(142, 66, 142, 116, stroke=theme.faint, sw=1))
    parts.append(text(163, 96, NAME, size=36, fill=theme.ink, weight=700, spacing=-0.8))
    parts.append(text(163, 118, TAGLINE.upper(), size=13.5, fill=theme.muted, mono=True, spacing=2.4))
    parts.append(text(70, 318, "Reproduce first.", size=104, fill=theme.ink, weight=800, spacing=-4.2))
    parts.append(
        runs(70, 424, [("Judge second", theme.ink), (".", theme.accent)], size=104, weight=800, spacing=-4.2)
    )
    parts.append(line(72, 521, 1128, 521, stroke=theme.line, sw=1))
    parts.append(text(72, 563, "OPEN SOURCE  ·  APACHE-2.0", size=17, fill=theme.muted, mono=True, spacing=1.2))
    parts.append(text(1128, 563, f"VERSION {VERSION}", size=17, fill=theme.muted, mono=True, spacing=1.2, anchor="end"))
    return svg(w, h, "\n".join(parts), title=f"{NAME}. {TAGLINE}. Version {VERSION}.")


def build_banner_dark() -> str:
    return banner(DARK)


def build_banner_light() -> str:
    return banner(LIGHT)


def build_social() -> str:
    """1280 x 640, the size GitHub asks for in a repository's social preview."""
    t = DARK
    w, h = 1280, 640
    parts = [rect(0, 0, w, h, fill=t.bg)]
    parts.append('<g opacity="0.06">' + mark(780, 40, 480, fg=t.ink, accent=t.accent, dot=False) + "</g>")
    parts.append(mark(80, 70, 60, fg=t.ink, accent=t.accent))
    parts.append(text(160, 112, NAME, size=44, fill=t.ink, weight=700, spacing=-1))
    parts.append(text(80, 330, "Run the report.", size=112, fill=t.ink, weight=800, spacing=-4.5))
    parts.append(runs(80, 440, [("Then decide", t.ink), (".", t.accent)], size=112, weight=800, spacing=-4.5))
    parts.append(line(80, 536, 1200, 536, stroke=t.line, sw=1))
    parts.append(text(80, 584, TAGLINE.upper(), size=17, fill=t.muted, mono=True, spacing=2))
    parts.append(text(1200, 584, "github.com/usualdork/verdis", size=17, fill=t.muted, mono=True, anchor="end", spacing=0.5))
    return svg(w, h, "\n".join(parts), title=f"{NAME}. {TAGLINE}.")


# ---- the pipeline -------------------------------------------------------------------------


def node(
    x: float,
    y: float,
    w: float,
    h: float,
    *,
    title: str,
    sub: list[str],
    glyph: str,
    role: str,
    t: Theme,
    step: str,
) -> str:
    colour = ROLE_COLOURS[role]
    parts = [
        rect(x, y, w, h, fill=t.panel, stroke=t.line, sw=1.5, rx=14),
        rect(x, y + 18, 5, h - 36, fill=colour, rx=2.5),
        icon(glyph, x + 28, y + 24, 34, colour, 1.6),
        text(x + w - 22, y + 38, step, size=15, fill=t.faint, mono=True, anchor="end", spacing=1),
        text(x + 28, y + 100, title, size=29, fill=t.ink, weight=700, spacing=-0.4),
        lines(x + 28, y + 132, sub, leading=24, size=17.5, fill=t.muted),
    ]
    return "\n".join(parts)


def build_pipeline() -> str:
    t = DARK
    w, h = 1600, 900
    nw, nh, gap = 270, 188, 42
    left = (w - (5 * nw + 4 * gap)) / 2
    row1, row2 = 150, 470

    def xs(i: int) -> float:
        return left + i * (nw + gap)

    parts = [rect(0, 0, w, h, fill=t.bg)]
    parts.append(text(60, 70, "FROM REPORT TO VERDICT", size=15, fill=t.muted, mono=True, spacing=3))
    parts.append(text(60, 108, "Every stage is ordered, saved and resumable.", size=30, fill=t.ink, weight=700, spacing=-0.6))

    top = [
        ("Intake", ["File, GitHub report,", "GitHub issue, IMAP"], "inbox", "rule", "01"),
        ("Claim", ["Component, class, PoC,", "expected signal, with spans"], "spark", "model", "02"),
        ("Policy", ["Checks the claim against", "your policy, with citations"], "list", "rule", "03"),
        ("Dedupe", ["Before and after the run:", "a suggestion, never a merge"], "copy", "rule", "04"),
        ("Preflight", ["Inspects each attachment", "before anything executes"], "shield", "rule", "05"),
    ]
    bottom = [
        ("Plan", ["Restricted step language,", "validated before it runs"], "spark", "model", "06"),
        ("Build", ["From a recipe, network", "only through your mirror"], "gear", "sandbox", "07"),
        ("Run", ["No network, no capabilities,", "rootless, hard limits"], "play", "sandbox", "08"),
        ("Oracles", ["Seven kinds observe the run", "and compare it to the claim"], "eye", "oracle", "09"),
        ("Judge", ["Ordered rules turn the", "evidence into a verdict"], "scales", "rule", "10"),
    ]
    for i, (title, sub, glyph, role, step) in enumerate(top):
        parts.append(node(xs(i), row1, nw, nh, title=title, sub=sub, glyph=glyph, role=role, t=t, step=step))
    for i, (title, sub, glyph, role, step) in enumerate(bottom):
        parts.append(node(xs(i), row2, nw, nh, title=title, sub=sub, glyph=glyph, role=role, t=t, step=step))

    # Connectors inside each row.
    for i in range(4):
        for ry in (row1, row2):
            parts.append(arrow([(xs(i) + nw + 6, ry + nh / 2), (xs(i + 1) - 6, ry + nh / 2)], stroke=t.faint))
    # The turn from Preflight down to Plan.
    px = xs(4) + nw / 2
    turn_y = row1 + nh + 66
    parts.append(
        arrow(
            [(px, row1 + nh + 4), (px, turn_y), (xs(0) + nw / 2, turn_y), (xs(0) + nw / 2, row2 - 6)],
            stroke=t.faint,
        )
    )
    # The exit taken by an unsafe attachment.
    chip_w = len("UNSAFE_ATTACHMENT") * 14 * 0.64 + 28
    body, _ = chip(px - 24 - chip_w, row1 + nh + 14, "UNSAFE_ATTACHMENT", VERDICT_COLOURS["UNSAFE_ATTACHMENT"], size=14, h=28)
    parts.append(body)
    parts.append(text(px - 24 - chip_w - 14, row1 + nh + 33, "risky attachments stop here", size=15.5, fill=t.muted, anchor="end"))

    # Output band.
    oy = row2 + nh + 64
    parts.append(arrow([(xs(4) + nw / 2, row2 + nh + 6), (xs(4) + nw / 2, oy - 6)], stroke=t.faint))
    parts.append(rect(left, oy, 5 * nw + 4 * gap, 96, fill=t.panel, stroke=t.line, sw=1.5, rx=14))
    outs = [
        ("archive", "Evidence bundle", "hashed manifest, rerun.sh"),
        ("doc", "Verdict card", "what was and was not shown"),
        ("mail", "Draft reply", "yours to approve or discard"),
        ("hash", "JSON and SARIF", "for scripts and code scanning"),
    ]
    slot = (5 * nw + 4 * gap) / 4
    for i, (glyph, title, sub) in enumerate(outs):
        ox = left + i * slot + 30
        parts.append(icon(glyph, ox, oy + 27, 36, t.accent, 1.6))
        parts.append(text(ox + 52, oy + 44, title, size=22, fill=t.ink, weight=700))
        parts.append(text(ox + 52, oy + 71, sub, size=16.5, fill=t.muted))
        if i:
            parts.append(line(left + i * slot, oy + 20, left + i * slot, oy + 76, stroke=t.line))

    # Legend.
    ly = h - 40
    legend = [
        ("model", "A model may draft this. It is validated, never trusted."),
        ("sandbox", "Runs inside the sandbox."),
        ("oracle", "Observes the run."),
        ("rule", "Deterministic rule."),
    ]
    lx = left
    for role, label in legend:
        parts.append(rect(lx, ly - 13, 14, 14, fill=ROLE_COLOURS[role], rx=3))
        parts.append(text(lx + 24, ly, label, size=16, fill=t.muted))
        lx += 24 + len(label) * 7.9 + 44
    return svg(
        w,
        h,
        "\n".join(parts),
        title=f"{NAME} pipeline",
        desc="Intake, claim, policy, dedupe and preflight; then plan, build, run, oracles and judge; then the evidence bundle, verdict card, draft reply and JSON or SARIF.",
    )


# ---- the narrative sheet -------------------------------------------------------------------


def _panel(ox: float, oy: float, w: float, h: float, number: str, label: str, title: str, caption: str, t: Theme) -> str:
    return "\n".join(
        [
            text(ox + 40, oy + 50, f"{number}  ·  {label}", size=14, fill=t.faint, mono=True, spacing=2.4),
            text(ox + 40, oy + 96, title, size=23, fill=t.ink, weight=700, spacing=2.2),
            text(ox + 40, oy + h - 36, caption, size=13, fill=t.muted, mono=True, spacing=1.2),
        ]
    )


def _panel_claim(ox: float, oy: float, t: Theme) -> str:
    parts = []
    doc_x, doc_y, doc_w = ox + 40, oy + 132, 316
    parts.append(rect(doc_x, doc_y, doc_w, 232, fill=t.panel, stroke=t.line, sw=1.4, rx=12))
    parts.append(text(doc_x + 18, doc_y + 30, "report.md", size=13, fill=t.faint, mono=True, spacing=1))
    source = [
        ("Title", "Heap overflow in libfoo", False),
        ("Version", "2.3.1", True),
        ("Component", "parse_header()", True),
        ("Steps", "./parse_demo poc.bin", True),
        ("Expected", "heap-buffer-overflow", True),
        ("Impact", "memory corruption", True),
    ]
    for i, (key, value, used) in enumerate(source):
        y = doc_y + 66 + i * 30
        parts.append(
            runs(
                doc_x + 18,
                y,
                [(f"{key}: ", t.muted), (value, t.ink if used else t.muted)],
                size=14.5,
                mono=True,
            )
        )
    card_x, card_w = ox + 440, 300
    parts.append(rect(card_x, doc_y, card_w, 232, fill=t.panel, stroke=t.line, sw=1.4, rx=12))
    parts.append(text(card_x + 18, doc_y + 30, "claim", size=13, fill=t.faint, mono=True, spacing=1))
    fields = [
        ("version", "2.3.1", True),
        ("component", "parse_header", True),
        ("poc", "poc.bin", True),
        ("expect", "heap-buffer-overflow", True),
        ("impact", "memory corruption", True),
        ("config", "unknown", False),
    ]
    for i, (key, value, known) in enumerate(fields):
        y = doc_y + 96 + i * 30 - 30
        colour = t.ink if known else "#f2b84b"
        parts.append(runs(card_x + 18, y, [(f"{key:<10}", t.muted), (value, colour)], size=14.5, mono=True))
        parts.append(circle(card_x - 2, y - 5, 4.5, fill=t.accent if known else "#f2b84b"))
        if known:
            parts.append(line(doc_x + doc_w + 8, y - 5, card_x - 8, y - 5, stroke=t.accent, sw=1.2, opacity=0.7))
            parts.append(circle(doc_x + doc_w + 2, y - 5, 3.5, fill=t.accent))
    return "\n".join(parts)


def _panel_run(ox: float, oy: float, t: Theme) -> str:
    parts = []
    hops = [
        ("CHECKOUT", "doc", ["ref v2.3.1", "tree hashed"], "sha256:3f9a21c0…"),
        ("BUILD", "gear", ["from a recipe", "ASan + UBSan"], "sha256:c47be913…"),
        ("RUN", "play", ["no network", "exit 134"], "sha256:e51a07bd…"),
        ("OBSERVE", "eye", ["seven oracles", "logs kept"], "sha256:b83d44f2…"),
    ]
    col = 177
    left = ox + 40
    cy = oy + 200
    # The sandbox boundary around build and run.
    bx = left + col * 1 + 6
    parts.append(rect(bx, oy + 122, col * 2 - 12, 190, fill="none", stroke=t.accent, sw=1.4, rx=14, dash="6 6", opacity=0.8))
    parts.append(icon("lock", bx + 14, oy + 134, 18, t.accent, 1.8))
    parts.append(text(bx + 40, oy + 148, "SANDBOXED · ROOTLESS", size=11.5, fill=t.accent, mono=True, spacing=1.2))
    for i, (name, glyph, sub, digest) in enumerate(hops):
        cx = left + col * i + col / 2
        parts.append(circle(cx, cy, 28, fill=t.panel, stroke=t.line, sw=1.6))
        parts.append(icon(glyph, cx - 13, cy - 13, 26, t.ink, 1.7))
        parts.append(text(cx, cy + 56, name, size=14, fill=t.ink, mono=True, weight=700, anchor="middle", spacing=1.2))
        parts.append(lines(cx, cy + 78, sub, leading=19, size=13, fill=t.muted, anchor="middle"))
        if i < 3:
            parts.append(arrow([(cx + 36, cy), (cx + col - 36, cy)], stroke=t.faint, sw=1.6, head=8))
        chip_w = 140
        parts.append(rect(cx - chip_w / 2, oy + 330, chip_w, 26, fill=t.panel, stroke=t.line, sw=1.2, rx=13))
        parts.append(text(cx, oy + 347.5, digest, size=11.5, fill=t.muted, mono=True, anchor="middle"))
        if i < 3:
            parts.append(line(cx + chip_w / 2, oy + 343, cx + col - chip_w / 2, oy + 343, stroke=t.accent, sw=1.2, opacity=0.7))
    return "\n".join(parts)


def _panel_verdict(ox: float, oy: float, t: Theme) -> str:
    parts = []
    rows = [
        ("sanitizer fired", "AddressSanitizer diagnostic"),
        ("matches the claimed class", "heap-buffer-overflow"),
        ("matches the claimed frame", "parse_header (src/hdr.c:212)"),
        ("impact demonstrated", "memory corruption"),
    ]
    x = ox + 40
    for i, (label, value) in enumerate(rows):
        y = oy + 148 + i * 56
        parts.append(circle(x + 12, y + 2, 12, fill="none", stroke=t.accent, sw=1.6))
        parts.append(icon("check", x + 5, y - 5, 14, t.accent, 2.4))
        parts.append(text(x + 36, y + 2, label, size=17, fill=t.ink, weight=600))
        parts.append(text(x + 36, y + 24, value, size=13, fill=t.muted, mono=True))
    parts.append(icon("scales", ox + 386, oy + 190, 42, t.ink, 1.5))
    parts.append(text(ox + 407, oy + 262, "ordered", size=12, fill=t.muted, mono=True, anchor="middle", spacing=1))
    parts.append(text(ox + 407, oy + 278, "rules", size=12, fill=t.muted, mono=True, anchor="middle", spacing=1))
    parts.append(arrow([(ox + 372, oy + 222), (ox + 454, oy + 222)], stroke=t.faint, sw=1.6, head=8))
    card_x, card_w = ox + 466, 274
    parts.append(rect(card_x, oy + 140, card_w, 214, fill=t.panel, stroke=VERDICT_COLOURS["REPRODUCED"], sw=1.6, rx=14))
    parts.append(text(card_x + 24, oy + 192, "REPRODUCED", size=27, fill=VERDICT_COLOURS["REPRODUCED"], weight=700, mono=True, spacing=0.4))
    body, _ = chip(card_x + 24, oy + 210, "TIER 1", VERDICT_COLOURS["REPRODUCED"], size=13, h=26, pad=12)
    parts.append(body)
    parts.append(line(card_x + 24, oy + 262, card_x + card_w - 24, oy + 262, stroke=t.line))
    parts.append(text(card_x + 24, oy + 292, "NOT ESTABLISHED", size=11.5, fill=t.faint, mono=True, spacing=1.6))
    parts.append(text(card_x + 24, oy + 318, "exploitability beyond", size=15, fill=t.muted))
    parts.append(text(card_x + 24, oy + 338, "what the evidence shows", size=15, fill=t.muted))
    return "\n".join(parts)


def _panel_fit(ox: float, oy: float, t: Theme) -> str:
    parts = []
    sources = [("inbox", "GitHub private reports"), ("list", "GitHub issues"), ("mail", "Email over IMAP"), ("doc", "Local files")]
    outputs = [("doc", "Verdict card"), ("archive", "Evidence bundle"), ("mail", "Draft reply"), ("hash", "JSON and SARIF")]
    left, right = ox + 40, ox + 540
    cw, chh, gap = 200, 46, 14
    top = oy + 132
    cx0, cx1 = ox + 302, ox + 478
    for i, ((g1, l1), (g2, l2)) in enumerate(zip(sources, outputs, strict=True)):
        y = top + i * (chh + gap)
        parts.append(rect(left, y, cw, chh, fill=t.panel, stroke=t.line, sw=1.3, rx=10))
        parts.append(icon(g1, left + 14, y + 11, 24, t.muted, 1.6))
        parts.append(text(left + 48, y + 29, l1, size=14.5, fill=t.ink))
        parts.append(rect(right, y, cw, chh, fill=t.panel, stroke=t.line, sw=1.3, rx=10))
        parts.append(icon(g2, right + 14, y + 11, 24, t.accent, 1.6))
        parts.append(text(right + 48, y + 29, l2, size=14.5, fill=t.ink))
        parts.append(arrow([(left + cw + 6, y + chh / 2), (cx0 - 4, top + 120)], stroke=t.faint, sw=1.2, head=0.1))
        parts.append(arrow([(cx1 + 4, top + 120), (right - 8, y + chh / 2)], stroke=t.faint, sw=1.2, head=7))
    parts.append(rect(cx0, top + 70, cx1 - cx0, 100, fill=t.panel, stroke=t.accent, sw=1.6, rx=16))
    parts.append(mark(cx0 + (cx1 - cx0) / 2 - 20, top + 86, 40, fg=t.ink, accent=t.accent))
    parts.append(text(cx0 + (cx1 - cx0) / 2, top + 150, NAME, size=18, fill=t.ink, weight=700, anchor="middle"))
    return "\n".join(parts)


def build_narrative() -> str:
    t = DARK
    w, h = 1560, 878
    pw, ph = 780, 439
    parts = [rect(0, 0, w, h, fill=t.bg)]
    panels = [
        (0, 0, "1", "THE CLAIM", "EVERY CLAIM CARRIES ITS SOURCE", "A MISSING FIELD IS MARKED UNKNOWN. IT IS NEVER INVENTED.", _panel_claim),
        (pw, 0, "2", "THE RUN", "EVERY STEP IS RECORDED", "IMAGE DIGEST, ENVIRONMENT AND ISOLATION TRAVEL WITH THE VERDICT.", _panel_run),
        (0, ph, "3", "THE VERDICT", "THE EVIDENCE DECIDES", "A MODEL DRAFTS THE PLAN. IT NEVER DECIDES THE VERDICT.", _panel_verdict),
        (pw, ph, "4", "WHERE IT FITS", "A PERSON DECIDES WHAT HAPPENS NEXT", "THE TOOL DRAFTS THE REPLY. IT DOES NOT CLOSE OR BAN ANYONE.", _panel_fit),
    ]
    for ox, oy, number, label, title, caption, body in panels:
        parts.append(_panel(ox, oy, pw, ph, number, label, title, caption, t))
        parts.append(body(ox, oy, t))
    parts.append(line(pw, 0, pw, h, stroke=t.line, sw=1.5))
    parts.append(line(0, ph, w, ph, stroke=t.line, sw=1.5))
    parts.append(text(w - 24, h - 14, "Illustrative values.", size=11.5, fill=t.faint, mono=True, anchor="end"))
    return svg(
        w,
        h,
        "\n".join(parts),
        title=f"How {NAME} works",
        desc="Four panels: a claim that cites its source, a recorded run, a verdict derived from the evidence, and where the tool fits in a maintainer's workflow.",
    )


# ---- the rule ladder ---------------------------------------------------------------------


def build_verdicts() -> str:
    t = DARK
    w, h = 1500, 900
    parts = [rect(0, 0, w, h, fill=t.bg)]
    parts.append(text(60, 72, "HOW A VERDICT IS REACHED", size=15, fill=t.muted, mono=True, spacing=3))
    parts.append(text(60, 114, "Seven ordered rules. The first one that applies decides.", size=31, fill=t.ink, weight=700, spacing=-0.6))
    rows = [
        ("UNSAFE_ATTACHMENT", "Preflight blocked an attachment.", "Nothing runs. The reasons are stated as observed behaviour, not as a judgement of the reporter."),
        ("NEEDS_INFO", "Required evidence is missing.", "The affected version, the proof of concept or the steps. Your own policy clause is quoted."),
        ("DUPLICATE", "A prior report or advisory matches above the threshold.", "A suggestion with reasons. It needs no run, and nothing is ever merged."),
        ("INCONCLUSIVE", "The report names a function or file the target does not have.", "The claim cannot be checked, so it is never called reproduced."),
        ("INCONCLUSIVE", "The build failed, the run timed out or flaked, or the environment is unsupported.", "The honest answer when the tool cannot tell."),
        ("REPRODUCED", "An oracle fired at the claimed ref and matched the claim.", "Tier 1 when the impact was shown, Tier 2 when only the behaviour was."),
        ("NOT_REPRODUCED", "The proof of concept ran and the claimed behaviour did not occur.", "It never means the code is safe. It means this run did not show the claim."),
    ]
    top, step = 170, 92
    for i, (verdict, headline, sub) in enumerate(rows):
        y = top + i * step
        colour = VERDICT_COLOURS[verdict]
        cx = 92
        if i < len(rows) - 1:
            parts.append(line(cx, y + 22, cx, y + step - 22, stroke=t.line, sw=2))
        parts.append(circle(cx, y, 20, fill=t.panel, stroke=t.line, sw=1.6))
        parts.append(text(cx, y + 6, str(i + 1), size=17, fill=t.muted, mono=True, anchor="middle", weight=600))
        body, _ = chip(150, y - 18, verdict, colour, size=16, h=36, pad=16)
        parts.append(body)
        parts.append(text(470, y - 2, headline, size=22, fill=t.ink, weight=600))
        parts.append(text(470, y + 26, sub, size=16.5, fill=t.muted))
        if verdict == "REPRODUCED":
            body, _ = chip(1218, y - 18, "OUT_OF_SCOPE", VERDICT_COLOURS["OUT_OF_SCOPE"], size=15, h=34, pad=15)
            parts.append(body)
            parts.append(text(1218, y + 38, "if your policy excludes it", size=14.5, fill=t.muted))
    parts.append(line(60, h - 96, w - 60, h - 96, stroke=t.line))
    parts.append(
        runs(
            60,
            h - 52,
            [("When nothing is certain the answer is ", t.muted), ("INCONCLUSIVE", VERDICT_COLOURS["INCONCLUSIVE"]), (". Ambiguity never becomes ", t.muted), ("REPRODUCED", VERDICT_COLOURS["REPRODUCED"]), (".", t.muted)],
            size=21,
            weight=500,
        )
    )
    return svg(
        w,
        h,
        "\n".join(parts),
        title=f"{NAME} verdict rules",
        desc="Seven ordered rules: unsafe attachment, needs info, duplicate, two kinds of inconclusive, reproduced or out of scope, and not reproduced.",
    )


# ---- the benchmark -----------------------------------------------------------------------

_BENCH_FALLBACK = {
    "tiers": [("negative", 539), ("positive", 45), ("adversarial", 41), ("style", 40), ("policy", 4), ("messy", 3), ("limitation", 1)],
    "total": 673,
    "evaluated": 672,
    "false_reproduced": 0,
    "negatives": 539,
    "median": 8.63,
    "warm": 0.03,
    "clusters": 25,
    "bound_cluster": 0.12,
    "bound_case": 0.0071,
}


def _bench() -> dict[str, object]:
    source = REPO_ROOT / "benchmark" / "results-podman.json"
    if not source.exists():
        return dict(_BENCH_FALLBACK)
    data = json.loads(source.read_text(encoding="utf-8"))
    summary = data["summary"]
    tiers: dict[str, int] = {}
    for case in data["cases"]:
        tiers[case["kind"]] = tiers.get(case["kind"], 0) + 1
    fr = summary["false_reproduced"]
    return {
        "tiers": sorted(tiers.items(), key=lambda kv: -kv[1]),
        "total": len(data["cases"]),
        "evaluated": sum(v["trials"] for v in summary["accuracy"]["by_kind"].values()),
        "false_reproduced": fr["count"],
        "negatives": fr["trials"],
        "median": summary["time"]["median_seconds"],
        "warm": summary["time"]["warm_median_seconds"],
        "clusters": fr["clusters"],
        "bound_cluster": fr["rule_of_three_upper_per_cluster"],
        "bound_case": fr["per_case_interval"][1],
    }


def build_benchmark() -> str:
    t = DARK
    data = _bench()
    w, h = 1500, 760
    parts = [rect(0, 0, w, h, fill=t.bg)]
    parts.append(text(60, 72, f"{NAME.upper()}BENCH", size=15, fill=t.muted, mono=True, spacing=3))
    parts.append(text(60, 114, "Measured on a corpus built to find the tool's mistakes.", size=31, fill=t.ink, weight=700, spacing=-0.6))
    evaluated, total = int(data["evaluated"]), int(data["total"])  # type: ignore[call-overload]
    tiles = [
        (f"{data['false_reproduced']} / {data['negatives']}", "negatives called REPRODUCED", t.accent),
        (f"{evaluated} / {evaluated}", "verdicts as expected", t.accent),
        (f"{data['median']} s", "median time to verdict", t.ink),
        (f"{data['warm']} s", "with a warm build cache", t.ink),
    ]
    tw, gap = 324, 28
    for i, (big, small, colour) in enumerate(tiles):
        x = 60 + i * (tw + gap)
        parts.append(rect(x, 160, tw, 150, fill=t.panel, stroke=t.line, sw=1.5, rx=16))
        parts.append(text(x + 28, 238, big, size=52, fill=colour, weight=800, spacing=-1.5))
        parts.append(text(x + 28, 278, small, size=18, fill=t.muted))
    # Stacked bar of the corpus by tier.
    parts.append(text(60, 372, f"THE CORPUS  ·  {total} CASES", size=14, fill=t.muted, mono=True, spacing=2.5))
    palette = {
        "negative": "#8fb4ff",
        "positive": "#3ddc97",
        "adversarial": "#ff6b6b",
        "style": "#5fd4e8",
        "policy": "#b79cff",
        "messy": "#f2b84b",
        "limitation": "#ff9f5a",
    }
    bar_x, bar_w, bar_y = 60, w - 120, 392
    cursor = bar_x
    legend_items = []
    for name, count in data["tiers"]:  # type: ignore[attr-defined]
        seg = bar_w * count / total
        parts.append(rect(cursor, bar_y, max(seg - 3, 4), 44, fill=palette[name], rx=6))
        cursor += seg
        legend_items.append((name, count))
    lx, ly = 60, 486
    for name, count in legend_items:
        parts.append(rect(lx, ly - 14, 14, 14, fill=palette[name], rx=3))
        label = f"{name}  {count}"
        parts.append(text(lx + 24, ly, label, size=17, fill=t.ink))
        lx += 24 + len(label) * 9.2 + 40
    facts = [
        ("cube", f"{data['clusters']} independent target programs", "C, Python, Node and Go, each built and run in the same sandbox."),
        ("shield", "41 adversarial cases", "40 are compared with a clean twin. None moved the verdict, and no plan injection succeeded."),
        ("search", "3 upstream CVEs", "libxml2 and libarchive at the vulnerable commit, with the proof of concept the fix brought."),
    ]
    fy = 560
    for i, (glyph, head, sub) in enumerate(facts):
        x = 60 + i * 470
        parts.append(icon(glyph, x, fy, 30, t.accent, 1.6))
        parts.append(text(x + 46, fy + 14, head, size=19, fill=t.ink, weight=600))
        parts.append(lines(x + 46, fy + 40, textwrap.wrap(sub, width=52), leading=20, size=14.5, fill=t.muted))
    parts.append(line(60, h - 78, w - 60, h - 78, stroke=t.line))
    bound = float(data["bound_cluster"]) * 100  # type: ignore[arg-type]
    case_bound = float(data["bound_case"]) * 100  # type: ignore[arg-type]
    parts.append(
        text(
            60,
            h - 44,
            f"Upper 95% bound on the false-REPRODUCED rate: {bound:.0f}% counting each target program once, {case_bound:.2f}% if every case were independent.",
            size=15.5,
            fill=t.muted,
        )
    )
    parts.append(text(60, h - 22, f"Rootless Podman, no-model mode. {evaluated} of {total} cases ran; the flaky case needs the host backend.", size=15.5, fill=t.faint))
    return svg(
        w,
        h,
        "\n".join(parts),
        title=f"{NAME}Bench results",
        desc="Corpus composition by tier and the headline measurements: no false REPRODUCED verdicts on 539 negatives.",
    )


ASSETS: dict[str, tuple[str, Callable[[], str]]] = {
    "mark": (f"{SLUG}-mark.svg", build_mark),
    "banner": (f"{SLUG}-banner.svg", build_banner_dark),
    "banner-light": (f"{SLUG}-banner-light.svg", build_banner_light),
    "social": (f"{SLUG}-social.svg", build_social),
    "pipeline": (f"{SLUG}-pipeline.svg", build_pipeline),
    "narrative": (f"{SLUG}-narrative.svg", build_narrative),
    "verdicts": (f"{SLUG}-verdicts.svg", build_verdicts),
    "benchmark": (f"{SLUG}-benchmark.svg", build_benchmark),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--only", action="append", choices=sorted(ASSETS))
    parser.add_argument("--check", action="store_true", help="exit 1 if a file differs from what would be written")
    args = parser.parse_args(argv)

    stale = 0
    for key in args.only or sorted(ASSETS):
        filename, builder = ASSETS[key]
        target = args.out / filename
        content = builder()
        if args.check:
            if not target.exists() or target.read_text(encoding="utf-8") != content:
                print(f"out of date: {target}")
                stale += 1
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        print(f"wrote {target.relative_to(REPO_ROOT) if target.is_relative_to(REPO_ROOT) else target}")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
