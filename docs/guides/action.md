# The GitHub Action

The action triages a report and, depending on the mode, does nothing,
posts a comment or applies a label.

## The snippet

```yaml
name: Verdis triage
on:
  issues:
    types: [opened, labeled]

jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@v4
      - uses: usualdork/verdis@v1
        with:
          mode: comment
          sandbox: default
          model-provider: none
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## The inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `mode` | `shadow` | `shadow`, `comment` or `label`. |
| `sandbox` | `default` | `default` or `hardened`. |
| `model-provider` | `none` | `none`, `openai`, `anthropic` or `ollama`. |
| `budget-tokens` | `20000` | the token budget per report. |
| `report-path` | `$VERDIS_REPORT` | the report to triage. |
| `label` | `verdis:triage` | the label applied in `label` mode. |

## The outputs

| Output | Meaning |
| --- | --- |
| `verdict` | the verdict. |
| `tier` | `tier1` or `tier2`, for `REPRODUCED`. |
| `bundle-path` | where the evidence bundle was written. |

## The guarantees

- The action requests the minimum permissions it needs.
- **The token is never passed into the sandbox.** The run stage has no
  network and no secrets; the token is used only to post a comment or
  apply a label, after the verdict exists.
- The action never closes an issue, never labels one invalid and never
  bans anybody.
- A non-definitive verdict does not fail the workflow. An inconclusive
  run is information, not a build failure.

## How the sandbox is reached

The action is a composite action, not a container action, and that is
deliberate. The proof of concept has to run inside a sandbox, and the
sandbox is a container runtime. A container action would have to carry
a runtime of its own — rootless Podman inside an unprivileged
container — and could not use the runner's. A composite action runs on
the runner, where Docker already is, so the proof of concept runs in a
container the runner owns.

The tool never pulls an image at run time: the bits that ran have to be
the ones the maintainer pinned. The action fetches the sandbox image
explicitly, before the triage, and a workflow that wants to pin it
should set `VERDIS_BASE_IMAGE` to a digest.

```yaml
      - uses: usualdork/verdis@v1
        env:
          VERDIS_BASE_IMAGE: ghcr.io/usualdork/verdis/base@sha256:...
```

## Shadow mode first

Run in `shadow` mode for a month before you let it comment. Shadow mode
writes verdicts and bundles and posts nothing. The point is to build
trust in the verdicts, and to find the cases where the tool needs a
recipe before it needs a maintainer.
