# Contributing to Verdis

Thanks for helping. This document is short on purpose.

## The shape of the project

Verdis has one rule that shapes everything else:

> An LLM proposes, the sandbox disposes.

Models read prose and draft plans. **They never decide a verdict.** Whether
a bug reproduced is decided by observable oracles — sanitizer output,
crashes, canary files, differential runs — and by deterministic rules that
are written down in `src/verdis/judge/rules.py`.

If a change lets a model's opinion influence a verdict, it will not be
merged.

## Getting set up

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

You need Python 3.12 or later. A container runtime (Podman or Docker) is
needed for the container-backed tests; without one, those tests skip and
the development backend is used instead.

## Running the tests

```bash
pytest                        # everything
pytest tests/unit             # fast
pytest tests/property         # hypothesis
pytest tests/conformance      # the sandbox conformance suite
pytest tests/adversarial      # the injection suite
pytest -m "not slow"          # skip the slow ones
```

The suites are a release gate:

- the **conformance suite** must have zero failures on both profiles;
- the **adversarial suite** must have zero successful plan injections;
- the **benchmark** must keep a false-`REPRODUCED` rate at or below 1%
  and a definitive-verdict rate of at least 85% on positives.

## Style

```bash
ruff check src tests
ruff format src tests
mypy src
```

Typed code, small modules, and a docstring that says *why* rather than
*what*. Comments that restate the code are noise.

## Adding things

| You want to add | Where it goes | What it must satisfy |
| --- | --- | --- |
| A new oracle | `src/verdis/oracles/` | Deterministic, no model, states what it observed. |
| A new sandbox backend | `src/verdis/sandbox/` | Passes the conformance suite. |
| A new intake adapter | `src/verdis/intake/` | Normalises into the same `Report`. |
| A new model provider | `src/verdis/extract/providers.py` | Schema-constrained outputs, temperature 0, a token budget. |
| A build recipe | `recipes/` | A `recipe.yml` plus a test that it builds. |
| An emitter | `src/verdis/emit/` | Never states more than the evidence supports. |

Anything that plugs into the core ships with a conformance test kit, so a
third party can extend Verdis without patching it.

## Commits and pull requests

- One logical change per pull request.
- Say what problem you are solving, not which files you touched.
- Include a test that fails without your change.
- Sign off your commits (`git commit -s`) — the project uses the DCO.

## Reporting security issues

Please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

The [Contributor Covenant](https://www.contributor-covenant.org/) applies.
See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
