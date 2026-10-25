# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-25

### Added

- The optional REA preflight plugin is wired in: the preflight loads it
  by path (`preflight.rea_plugin`), uses it for ELF, PE and Mach-O
  files, and carries on without it when it cannot run.
- The base image carries Python, Node and Go, so the four languages the
  PRD names can be built and run in the same sandbox. The corpus has a
  Python, a Node and a Go target, each verified in a container.
- The output oracle can fire from a report: the heuristics read a stated
  expected output or exit code, the RRS block may carry a regex or an
  exit code, and the plan carries both.
- The benchmark measures the warm-cache median and checks the "zero
  sandbox-conformance failures" threshold, so all seven thresholds of
  section 13.3 are measured rather than asserted.
- The conformance suite writes its own report, which the benchmark reads.
- The release workflow publishes the images to GHCR with their digests,
  signs the checksums with a keyless key and points the Action's `v1`
  tag at the release.
- The docs site is built and published by CI.
- The README shows a real run, replayed as an animated SVG.
- Discoverability: `CITATION.cff`, an `llms.txt` served from the docs site,
  and Open Graph, Twitter card and schema.org metadata for the docs pages.
- `tools/assets.py` draws the artwork in the README and the docs (banner,
  pipeline, how-it-works sheet, verdict rules and benchmark panel); the
  benchmark panel reads its numbers from the results file. `make assets`
  redraws it.

### Fixed

- `.gitignore` ignored every directory called `build`, which kept the
  `build` package out of the repository. The pattern is now anchored to
  the repository root.
- The Action's `action.yml` sits at the repository root, so
  `uses: usualdork/verdis@v1` resolves, and the release workflow builds the
  tool image from the repository root, where its `COPY` paths exist.
- The dev extras install `types-PyYAML`, so `mypy src` passes on a clean
  install.
- The benchmark documents agree with the results file: 673 cases, of which
  672 ran in the container and one flaky case is skipped.
- A proof of concept whose command is not in the sandbox is now
  INCONCLUSIVE. It used to be reported as NOT_REPRODUCED, which claimed
  a negative result the run never produced.
- The build stage has a writable home, so a toolchain that keeps its
  cache there (Go, npm, cargo) can build.
- The reported impact of an output, property or differential oracle is no
  longer called a crash or code execution: those oracles show a
  behaviour, not a class of impact.

### Earlier

- The full triage pipeline: intake, claim extraction, policy check,
  dedupe, attachment preflight, planning, build, run, oracles, judgment
  and reporting.
- Seven verdicts with deterministic, documented decision rules
  (`src/verdis/judge/rules.py`).
- All seven oracle types: crash, sanitizer, exception, canary, differential,
  property and output.
- The restricted plan language and its allowlist validator.
- `.verdis/policy.yml` with citations, and derivation of hints from
  `SECURITY.md` and `THREAT_MODEL.md`.
- Two-pass deduplication against the local store and published advisories.
- Attachment preflight: archives, scripts and binaries, with a risk score
  and quarantine.
- The Reproducible Report Spec v0.1: parsing, emission and a model-free
  triage path.
- Evidence bundles with a hashed manifest, a `rerun.sh` and
  `verdis bundle verify`.
- Draft replies for every verdict.
- The CLI: `triage`, `preflight`, `inbox`, `show`, `rerun`, `recipe`,
  `policy`, `bundle verify` and `doctor`.
- Sandbox backends: rootless Podman, Docker, and a development-only local
  backend that is explicitly not a security boundary.
- A model provider abstraction with OpenAI-compatible, Anthropic and
  Ollama providers, plus a first-class no-LLM mode.
- The GitHub Action, in shadow, comment and label modes.
- Published JSON schemas for every object in the data model.
- The VerdisBench harness and a first set of cases.
- The test suite: unit, golden, property, conformance, adversarial and
  end-to-end.

[Unreleased]: https://github.com/usualdork/verdis/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/usualdork/verdis/releases/tag/v0.1.0
