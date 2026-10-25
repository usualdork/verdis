#!/usr/bin/env python3
"""Reconnaissance: which upstream projects can the corpus actually use?

For each candidate the script clones the repository, looks for the
commits that fixed a given CVE, and reports what the fix added. A fix
that adds a test file usually adds the proof of concept with it, which
is what the corpus needs: a real input, from upstream, that crashes the
vulnerable version and not the fixed one.

Usage::

    python benchmark/corpus/recon.py --cve CVE-2016-3945
    python benchmark/corpus/recon.py --project libtiff
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

#: The upstream projects the corpus draws on, with the CVEs that are
#: worth trying for each. The URL is the one the project publishes.
PROJECTS: dict[str, dict[str, object]] = {
    "giflib": {
        "url": "https://sourceforge.net/p/giflib/code/ci/master/tree/",
        "mirror": "https://github.com/mattdesl/giflib.git",
        "cves": ["CVE-2018-5711"],
    },
    "pcre": {
        "url": "https://github.com/PCRE2Project/pcre.git",
        "mirror": "https://sourceforge.net/p/pcre/code/ci/HEAD/tree/",
        "cves": ["CVE-2015-2326", "CVE-2015-8384", "CVE-2015-8386"],
    },
    "wavpack": {
        "url": "https://github.com/dbry/WavPack.git",
        "cves": [
            "CVE-2018-10536",
            "CVE-2018-10537",
            "CVE-2018-10538",
            "CVE-2018-10539",
            "CVE-2018-10540",
        ],
    },
    "libwebp": {
        "url": "https://github.com/webmproject/libwebp.git",
        "cves": [
            "CVE-2018-25009",
            "CVE-2018-25010",
            "CVE-2018-25011",
            "CVE-2018-25012",
            "CVE-2018-25013",
        ],
    },
    "xz": {
        "url": "https://github.com/tukaani-project/xz.git",
        "cves": ["CVE-2016-9840", "CVE-2016-9841"],
    },
    "bzip2": {
        "url": "https://gitlab.com/bzip2/bzip2.git",
        "cves": ["CVE-2019-12900"],
    },
    "libexif": {
        "url": "https://github.com/libexif/libexif.git",
        "cves": ["CVE-2016-6328"],
    },
    "libtiff": {
        "url": "https://gitlab.com/libtiff/libtiff.git",
        "cves": [
            "CVE-2016-3945",
            "CVE-2016-3990",
            "CVE-2016-3991",
            "CVE-2016-5314",
            "CVE-2016-5315",
            "CVE-2016-5316",
            "CVE-2016-5317",
            "CVE-2017-9935",
            "CVE-2017-9936",
            "CVE-2017-11613",
        ],
    },
    "libarchive": {
        "url": "https://github.com/libarchive/libarchive.git",
        "cves": [
            "CVE-2016-4302",
            "CVE-2020-36148",
            "CVE-2020-36149",
        ],
    },
    "libxml2": {
        "url": "https://gitlab.gnome.org/GNOME/libxml2.git",
        "mirror": "https://github.com/GNOME/libxml2.git",
        "cves": [
            "CVE-2016-1834",
            "CVE-2016-4658",
            "CVE-2017-9047",
            "CVE-2017-9048",
            "CVE-2017-9049",
            "CVE-2017-9050",
        ],
    },
}


def _run(args: list[str], *, cwd: Path | None = None, timeout: int = 900) -> str:
    result = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )
    return result.stdout + result.stderr


def clone(project: str, spec: dict[str, object], workdir: Path) -> Path | None:
    """Clone a project, trying its published URL and then a mirror."""
    destination = workdir / project
    if destination.exists():
        return destination
    urls = [str(spec["url"])]
    if spec.get("mirror"):
        urls.append(str(spec["mirror"]))
    for url in urls:
        output = _run(
            ["git", "clone", "--quiet", url, str(destination)], timeout=1200
        )
        if destination.exists() and (destination / ".git").exists():
            return destination
        print(f"    {url} failed: {output.strip()[:160]}")
    return None


def find_fixes(repo: Path, cve: str) -> list[str]:
    """The commits that mention a CVE."""
    output = _run(
        ["git", "log", "--all", "--format=%H%x09%s", f"--grep={cve}", "-i"],
        cwd=repo,
    )
    commits: list[str] = []
    for line in output.splitlines():
        if "\t" not in line:
            continue
        commit, subject = line.split("\t", 1)
        if cve.upper() in subject.upper():
            commits.append(commit)
    return commits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve", default="")
    parser.add_argument("--project", default="")
    parser.add_argument("--workdir", default=str(Path.home() / ".cache" / "verdis-upstream"))
    parser.add_argument("--json", default="")
    args = parser.parse_args(argv)

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    report: list[dict[str, object]] = []
    for project, spec in PROJECTS.items():
        if args.project and project != args.project:
            continue
        cves = [args.cve] if args.cve else list(spec["cves"])  # type: ignore[arg-type]
        print(f"== {project}")
        repo = clone(project, spec, workdir)
        if repo is None:
            print("    could not clone")
            report.append({"project": project, "cloned": False})
            continue
        for cve in cves:
            commits = find_fixes(repo, cve)
            print(f"    {cve}: {len(commits)} commit(s) mention it")
            for commit in commits[:2]:
                files = _run(
                    ["git", "show", "--name-only", "--format=", commit], cwd=repo
                )
                added = [
                    line
                    for line in files.splitlines()
                    if line.strip() and not line.startswith("commit")
                ][:8]
                subject = _run(
                    ["git", "log", "-1", "--format=%s", commit], cwd=repo
                ).strip()
                print(f"      {commit[:10]} {subject}")
                for name in added:
                    print(f"        {name}")
                report.append(
                    {
                        "project": project,
                        "cve": cve,
                        "commit": commit,
                        "subject": subject,
                        "files": added,
                    }
                )
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
