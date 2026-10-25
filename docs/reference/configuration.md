# Configuration

## `.verdis/config.yml`

```yaml
mode: shadow             # shadow | comment | label
sandbox: default         # default | hardened
llm:
  provider: none         # none | openai | openai-compatible | anthropic | ollama
  model: ''
  base_url: ''
  budget_tokens: 20000
  redaction: true
actions:
  post_comment: false
  apply_labels: false
  auto_close: false      # never on by default
  auto_reply_needs_info: false
dedupe:
  threshold: 0.82
  stop_on_duplicate: false
advisories:
  lookup: false           # opt in to published advisory lookups
preflight:
  threshold: 45
build:
  cache_dir: ''
  cache_max_bytes: 2147483648
  mirror_proxy: ''         # the proxy the build stage may reach
run:
  timeout: 60
  build_timeout: 900
  repeats: 3
  comparison_ref: ''
  report_budget_seconds: 900
work_dir: ''                # where the scratch directories go
base_image: ''             # the image to build and run in, by digest
build:
  cache_dir: ''
  mirror_proxy: ''          # the proxy the build stage may reach
```

### The fields

| Field | Default | Meaning |
| --- | --- | --- |
| `mode` | `shadow` | `shadow` logs only, `comment` posts a comment, `label` applies a label. |
| `sandbox` | `default` | `default`, `hardened`, `podman`, `docker` or `local`. `local` is a development convenience with no isolation. |
| `llm.provider` | `none` | which model provider to use. `none` is a first-class mode. |
| `llm.budget_tokens` | `20000` | the token budget per report. |
| `llm.redaction` | `true` | redact emails and secrets before any external call. |
| `actions.auto_close` | `false` | ignored: the tool never closes a report. |
| `actions.auto_reply_needs_info` | `false` | send `NEEDS_INFO` replies without asking. |
| `dedupe.threshold` | `0.82` | the similarity above which a match is a duplicate. |
| `dedupe.stop_on_duplicate` | `false` | skip the run when the pre-pass finds a strong match. |
| `advisories.lookup` | `false` | look published advisories up (OSV). Off by default: it is the only part of the tool that tells a third party what the project is. |
| `preflight.threshold` | `45` | the risk score above which an attachment is quarantined. |
| `preflight.rea_plugin` | `''` | the optional REA preflight plugin, by path. It is only used for ELF, PE and Mach-O files, and only when it can run inside the sandbox. |
| `base_image` | `''` | the image the build and run stages use. A digest pins the exact bits that ran, which a tag does not (PRD 11.2). The environment variable `VERDIS_BASE_IMAGE` sets it too. |
| `build.cache_dir` | `''` | where build outputs are cached. |
| `build.mirror_proxy` | `''` | the proxy the **build** stage may reach. Without one the build stage has no network either, so the build and the run are equally isolated. |
| `build.mirror_proxy` | `''` | the proxy the **build** stage may reach. The run stage never has a network. |
| `run.timeout` | `60` | the wall-clock limit for one run. |
| `run.repeats` | `3` | how many times the PoC is run, to detect flakiness. |
| `run.comparison_ref` | `''` | a default comparison ref, such as `main`. |
| `run.report_budget_seconds` | `900` | the wall-clock budget for one report. |
| `work_dir` | `''` | where the scratch directories go. The system temporary directory by default. |

## The work directory

The tool copies the target source, stages the PoC artifacts and builds in
a scratch directory before it runs anything. Those directories have to be
visible to the container runtime, and a runtime that is not on the same
machine — a VM, a remote daemon — can only bind-mount the paths it shares
with the host.

On Linux the system temporary directory always works. On macOS with a
Docker VM, it does not: the shared path is the one under your home
directory. Set `work_dir` (or `VERDIS_WORK_DIR`) to a shared path when
the runtime is remote.

```yaml
work_dir: ~/.cache/verdis
```

## Environment variables

| Variable | Meaning |
| --- | --- |
| `VERDIS_HOME` | where the store and the evidence live. |
| `GITHUB_TOKEN` | used by the GitHub intake and the action. |
| `VERDIS_IMAP_PASSWORD` | used by the IMAP intake. |
| `VERDIS_SANDBOX` | the backend used by `rerun.sh`. |
| `VERDIS_WORK_DIR` | where the scratch directories go. See below. |
| `VERDIS_REPO` | the repository used by `rerun.sh`. |

## The defaults are conservative

`auto_close` cannot be turned on: the tool never closes a report. The
configuration loader ignores it and says so.

`mode` defaults to `shadow`: the tool does not post anything until you
have decided you trust it.
