"""Make the README's terminal recording.

The recording is a real run: the tool triages the example report in
``examples/demo`` and the output is captured. The capture is then drawn
as an animated SVG, so the README shows the tool working rather than a
picture of it.

Usage::

    python tools/recording.py --out docs/assets/verdis-demo.svg
"""

from __future__ import annotations

import argparse
import html
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The colours of a dark terminal.
BACKGROUND = "#0d1117"
CHROME = "#161b22"
TEXT = "#e6edf3"
PROMPT = "#7ee787"
DIM = "#8b949e"

CHAR_WIDTH = 8.4
#: Longest line drawn; longer ones wrap, so the image stays readable when scaled.
WRAP_AT = 100
LINE_HEIGHT = 21
PADDING = 18
TITLE_BAR = 34


def capture(repo: Path, home: Path) -> list[str]:
    """Run the demo and return the lines it printed."""
    command = [
        sys.executable,
        "-m",
        "verdis",
        "triage",
        str(repo / "report.md"),
        "--repo",
        str(repo / "target"),
        "--sandbox",
        "local",
    ]
    # A fresh home, so the recording shows a first triage and not a
    # duplicate of the last one.
    env = dict(os.environ)
    env["VERDIS_HOME"] = str(home)
    result = subprocess.run(
        command,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        env=env,
    )
    output = (result.stdout + result.stderr).rstrip("\n")
    # The recording shows where a bundle lands, not where this run
    # happened to put it.
    output = output.replace(str(home), "~/.local/share/verdis")
    lines: list[str] = []
    for raw in output.splitlines():
        raw = raw.rstrip()
        if len(raw) <= WRAP_AT:
            lines.append(raw)
            continue
        indent = len(raw) - len(raw.lstrip())
        lines.extend(
            textwrap.wrap(
                raw,
                width=WRAP_AT,
                subsequent_indent=" " * (indent + 2),
                break_long_words=False,
                break_on_hyphens=False,
            )
        )
    # The banner is the command a reader would have typed.
    banner = "$ verdis triage examples/demo/report.md --repo examples/demo/target"
    return [banner, *lines]


def _escape(text: str) -> str:
    return html.escape(text, quote=False)


def build_svg(lines: list[str], *, seconds: float = 25.0) -> str:
    """Draw the capture as an animated SVG.

    Each line fades in in turn, so the recording plays back as the run
    happened. The whole thing is one file: no fonts, no scripts and no
    network.
    """
    step = seconds / max(len(lines), 1)
    width = max(720, int(max((len(line) for line in lines), default=40) * CHAR_WIDTH) + 2 * PADDING)
    height = TITLE_BAR + PADDING * 2 + LINE_HEIGHT * len(lines)

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="A terminal recording of Verdis triaging a report">',
        f"<style>text{{font-family:'Menlo','DejaVu Sans Mono',monospace;font-size:13px;"
        f"fill:{TEXT};white-space:pre}}</style>",
        f'<rect width="{width}" height="{height}" rx="10" fill="{BACKGROUND}"/>',
        f'<rect width="{width}" height="{TITLE_BAR}" rx="10" fill="{CHROME}"/>',
        f'<rect y="{TITLE_BAR - 10}" width="{width}" height="10" fill="{CHROME}"/>',
        '<circle cx="18" cy="17" r="5" fill="#ff5f56"/>',
        '<circle cx="36" cy="17" r="5" fill="#ffbd2e"/>',
        '<circle cx="54" cy="17" r="5" fill="#27c93f"/>',
        f'<text x="{width / 2}" y="21" fill="{DIM}" font-size="12" text-anchor="middle" '
        f"font-family='Menlo,monospace'>verdis — reproduce first, judge second</text>",
    ]

    for index, line in enumerate(lines):
        y = TITLE_BAR + PADDING + index * LINE_HEIGHT
        colour = PROMPT if line.startswith("$") else TEXT
        begin = round(index * step, 2)
        parts.append(
            f'<text x="{PADDING}" y="{y}" fill="{colour}" opacity="0">'
            f'<animate attributeName="opacity" from="0" to="1" begin="{begin}s" '
            f'dur="0.25s" fill="freeze"/>{_escape(line)}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=str(REPO_ROOT / "docs" / "assets" / "verdis-demo.svg"),
        help="where the recording is written",
    )
    parser.add_argument(
        "--seconds",
        type=float,
        default=25.0,
        help="how long the recording plays for",
    )
    parser.add_argument(
        "--demo",
        default=str(REPO_ROOT / "examples" / "demo"),
        help="the demo project to record",
    )
    args = parser.parse_args(argv)

    home = Path(tempfile.mkdtemp(prefix="verdis-recording-"))
    lines = capture(Path(args.demo), home)
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(build_svg(lines, seconds=args.seconds), encoding="utf-8")
    print(f"wrote {target} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
